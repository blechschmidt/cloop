package jira

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
	"unicode"
)

// The cursor is where a listing stands, between List calls and across syncs.
//
// A listing is a pass over the issues the source's query matches whose last
// change is at or after the pass's Since, newest change first. The first pass
// has no Since and lists everything. A pass ends at its last page; the newest
// change it saw, Top, less overlap, becomes the next pass's Since — so a sync
// reads what changed since the last one, and the query a pass pages through
// is one query from its first page to its last.
//
// Since is written into the query as milliseconds since the epoch, which JQL
// reads as an instant: a written date and time would be read in the time zone
// of the account the source signs in as, and be off by its offset.
//
// Newest first, because an issue changed while a pass pages through moves to
// the front, where the pass has been: on Data Center, whose pages are offsets,
// the pages behind it only shift by one, so at worst an issue is listed twice —
// never skipped — and the one that moved is newer than this pass's Top, so the
// next pass lists it. What could make an offset page skip an issue is one
// leaving the query's results — deleted, or changed out of scope — ahead of
// the page; so a Data Center page is asked for from a few issues before where
// the last one ended, and skips the ones it already listed (Tail). overlap
// covers an issue whose change reaches the site's search index after a pass
// read past it: Jira Cloud's search is eventually consistent.
const overlap = 15 * time.Minute

// cursorPrefix marks this connector's cursors, and their version.
const cursorPrefix = "jr1."

// Cursor bounds: what a cursor that decodes may hold.
const (
	maxTokenBytes = 4096
	maxTail       = 64
	maxStart      = 10_000_000
)

// cursor is a listing's position. Times are Unix milliseconds, 0 for none.
type cursor struct {
	// Mid reports a pass under way: its first page has been listed.
	Mid bool `json:"m,omitempty"`
	// Since is how far back the pass lists; 0 lists everything.
	Since int64 `json:"since,omitempty"`
	// Top is the newest change the pass has listed.
	Top int64 `json:"top,omitempty"`
	// Token is the Cloud site's nextPageToken for the pass's next page.
	Token string `json:"t,omitempty"`
	// Start is the Data Center site's startAt for the pass's next page, and
	// Tail the ids of the issues ending the last page, which that page
	// repeats.
	Start int      `json:"st,omitempty"`
	Tail  []string `json:"tail,omitempty"`
	// Web is where the pass's issues are read, for a Cloud site reached
	// through the API gateway.
	Web string `json:"w,omitempty"`
}

// decodeCursor reads a cursor. One that does not decode — a cursor of another
// version, or none — starts a pass from the beginning: listing everything
// again costs time, never an issue.
func decodeCursor(s string) cursor {
	var c cursor
	raw, ok := strings.CutPrefix(s, cursorPrefix)
	if !ok {
		return cursor{}
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &c) != nil {
		return cursor{}
	}
	c.Since, c.Top = max(c.Since, 0), max(c.Top, 0)
	if !c.Mid || len(c.Token) > maxTokenBytes || strings.IndexFunc(c.Token, unicode.IsControl) >= 0 ||
		c.Start < 0 || c.Start > maxStart || len(c.Tail) > maxTail {
		// Not a position this connector wrote: the pass begins again, from
		// how far back it was to begin.
		return cursor{Since: c.Since}
	}
	for _, id := range c.Tail {
		if !issueIDPattern.MatchString(id) {
			c.Tail = nil
			break
		}
	}
	return c
}

// encode writes the cursor for the framework to store.
func (c cursor) encode() string {
	b, err := json.Marshal(c)
	if err != nil {
		// Only ints, bools and strings: unreachable, and a fresh pass is the
		// safe reading of it.
		return ""
	}
	return cursorPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// saw records a change at t as seen by the pass. A change dated more than a
// day past now — an import that set it, a site clock gone wrong — is not let
// set how far back the next pass begins, or the passes after it would see
// nothing until the clock caught up.
func (c *cursor) saw(t, now time.Time) {
	if t.IsZero() || t.After(now.Add(24*time.Hour)) {
		return
	}
	if ms := t.UnixMilli(); ms > c.Top {
		c.Top = ms
	}
}

// end ends the pass: the next one lists back to the newest change this one
// saw, less overlap. A pass that saw nothing leaves the bound where it was.
func (c cursor) end() cursor {
	next := cursor{Since: c.Since}
	if c.Top > 0 {
		next.Since = max(c.Top-overlap.Milliseconds(), 1)
	}
	return next
}
