package confluence

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// The cursor is where a listing stands, between List calls and across syncs.
//
// A listing is a pass over each of the source's streams in turn — a Cloud
// space-scoped source's pages and its blog posts, any other source's one CQL
// search — newest change first. A stream's pass lists back to its Since: the
// newest change the stream's previous pass saw, less overlap. The first pass
// has no Since and lists everything. A pass ends, for a stream, at the first
// document older than Since or at the stream's last page; its newest change,
// Top, becomes the next pass's Since.
//
// Newest first, because a document changed while a pass pages through moves
// to the front, where the pass has been: the pages behind it only shift by
// one, so at worst a document is listed twice — never skipped — and the one
// that moved is newer than this pass's Top, so the next pass lists it.
// overlap covers a document whose change reaches a search index after a pass
// read past it.
const overlap = 10 * time.Minute

// cursorPrefix marks this connector's cursors, and their version.
const cursorPrefix = "cf1."

// cursor is a listing's position. Times are Unix nanoseconds, 0 for none.
type cursor struct {
	// Stream is the stream the pass is in.
	Stream int `json:"s,omitempty"`
	// Next is the site's link to the stream's next page, below the API root;
	// empty at the stream's first page.
	Next string `json:"n,omitempty"`
	// Since is, per stream, how far back the pass lists; 0 lists it all.
	Since []int64 `json:"since,omitempty"`
	// Top is, per stream, the newest change the pass has listed.
	Top []int64 `json:"top,omitempty"`
	// Spaces are what the pass resolved the configured space keys to.
	Spaces []spaceRef `json:"sp,omitempty"`
}

// spaceRef is a space a pass resolved: its id (Cloud) and key.
type spaceRef struct {
	ID  string `json:"i,omitempty"`
	Key string `json:"k"`
}

// decodeCursor reads a cursor for a source with streams streams. One that
// does not decode — a cursor of another version, or none — starts a pass from
// the beginning: listing everything again costs time, never a document.
func decodeCursor(s string, streams int) cursor {
	var c cursor
	if raw, ok := strings.CutPrefix(s, cursorPrefix); ok {
		if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
			if json.Unmarshal(b, &c) != nil {
				c = cursor{}
			}
		}
	}
	if c.Stream < 0 || c.Stream >= streams {
		c.Stream, c.Next = 0, ""
	}
	if c.Next != "" && !strings.HasPrefix(c.Next, "/") {
		c.Next = ""
	}
	c.Since = fit(c.Since, streams)
	c.Top = fit(c.Top, streams)
	return c
}

// fit returns v with exactly n entries.
func fit(v []int64, n int) []int64 {
	out := make([]int64, n)
	copy(out, v)
	for i := range out {
		if out[i] < 0 {
			out[i] = 0
		}
	}
	return out
}

// encode writes the cursor for the framework to store.
func (c cursor) encode() string {
	b, err := json.Marshal(c)
	if err != nil {
		// Only ints and strings: unreachable, and a fresh pass is the safe
		// reading of it.
		return ""
	}
	return cursorPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// since returns stream i's lower bound.
func (c cursor) since(i int) time.Time { return fromNanos(c.Since[i]) }

// saw records a change at t as seen by stream i's pass.
func (c *cursor) saw(i int, t time.Time) {
	if n := t.UnixNano(); !t.IsZero() && n > c.Top[i] {
		c.Top[i] = n
	}
}

// endStream ends stream i's pass: its next pass lists back to the newest
// change this one saw, less overlap. A pass that saw nothing leaves the bound
// where it was.
func (c *cursor) endStream(i int) {
	if c.Top[i] > 0 {
		c.Since[i] = max(c.Top[i]-int64(overlap), 1)
	}
	c.Top[i] = 0
	c.Next = ""
}

func fromNanos(n int64) time.Time {
	if n <= 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}
