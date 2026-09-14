// Package telemetry is the model for browser-side diagnostic events that the
// hub collects so a front-end defect can be debugged from the outside (Task
// 20251).
//
// # Why this exists
//
// The hub already logged uncaught JavaScript exceptions: the error boundary
// POSTs to /api/client-error and the structured logger writes a line. That
// covers the case where the page throws, and it covers nothing else.
//
// The front-end defects this project actually spends tasks on do not throw.
// "Swiping right selects the first item once and then stops" (Task 20242),
// "the refresh resets the view" (20237), "there is no button to add a task"
// (20243) — each of those was a silent behavioural failure on a Meta Ray-Ban
// Display, a device with no developer tools, no console, no network inspector
// and no way for a wearer to report anything beyond a sentence of prose. Every
// one of them was diagnosed by building a simulator of the device and guessing
// until the guess reproduced the prose. That is an expensive way to find out
// which branch ran.
//
// So the unit of collection here is not the exception. It is the breadcrumb:
// an ordered trail of what the page did — the gesture it received, the view it
// opened, the request it issued and the status that came back — with errors as
// one kind of entry among several. A trail answers "the cursor never moved
// past the first row" directly, because the gesture events are in it and the
// focus-change events are not.
//
// # Trust
//
// Every field originates in a browser and none of it is trusted. The package
// therefore treats normalization as the whole of its job: kinds outside the
// known set collapse to KindNote, strings are clamped to fixed budgets, and
// Scrub strips credentials before anything is stored. The last is not
// hypothetical — the glasses link carries its bearer token in the page URL, so
// an unscrubbed `url` field would copy a live credential out of a URL bar and
// into a database table that a different permission can read.
//
// Stdlib-only, so both pkg/statedb and pkg/ui can depend on it without either
// depending on the other.
package telemetry

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Source names the front end an event came from. Kept to a closed set because
// it is the first filter a reader applies ("show me the glasses") and a
// free-text field would let a caller invent a spelling nobody searches for.
type Source string

const (
	// SourceDashboard is the full browser dashboard.
	SourceDashboard Source = "dashboard"
	// SourceGlasses is the heads-up display page served at /glasses.
	SourceGlasses Source = "glasses"
)

// Valid reports whether s is a known source.
func (s Source) Valid() bool {
	return s == SourceDashboard || s == SourceGlasses
}

// Kind classifies an event. The set is closed for the same reason Source is,
// and deliberately small: a reader scanning a trail under time pressure needs
// to recognise every kind on sight.
type Kind string

const (
	// KindError is an uncaught exception.
	KindError Kind = "error"
	// KindRejection is an unhandled promise rejection.
	KindRejection Kind = "rejection"
	// KindGesture is an input the page received — a key, a swipe, a pinch, a
	// click on a control. The kind that makes a silent failure legible: if the
	// trail shows four gestures and one view change, the page ignored three.
	KindGesture Kind = "gesture"
	// KindView is a screen or tab the page opened.
	KindView Kind = "view"
	// KindFetch is a completed request the page issued, recorded whether it
	// succeeded or not so a trail shows both "the call never happened" and
	// "the call came back 403".
	KindFetch Kind = "fetch"
	// KindLifecycle is a page-level transition: load, visibility change,
	// WebSocket connect or drop, the terminal dead-link state.
	KindLifecycle Kind = "lifecycle"
	// KindNote is anything a caller wants recorded that is none of the above,
	// and the landing place for a kind this build does not recognise.
	KindNote Kind = "note"
)

// Kinds lists every known kind, in the order a UI should offer them.
var Kinds = []Kind{KindError, KindRejection, KindGesture, KindView, KindFetch, KindLifecycle, KindNote}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	for _, known := range Kinds {
		if k == known {
			return true
		}
	}
	return false
}

// Field budgets. Generous enough for a real stack trace, small enough that the
// worst case of MaxBatchEvents events is a bounded write.
const (
	// MaxMessage bounds the human-readable summary.
	MaxMessage = 2 * 1024
	// MaxStack bounds a stack trace. The largest field by design: a truncated
	// stack is often a useless stack.
	MaxStack = 8 * 1024
	// MaxURL bounds a location or request URL.
	MaxURL = 1024
	// MaxDetail bounds the free-form structured detail blob.
	MaxDetail = 4 * 1024
	// MaxShort bounds the small identifying fields (session, view, kind
	// overflow, user agent).
	MaxShort = 256
	// MaxBatchEvents is the most events one POST may carry. A page that
	// generates more than this between flushes is looping, and the right
	// response to a loop is to drop the excess rather than to store it.
	MaxBatchEvents = 64
)

// Event is one recorded moment in a browser session.
//
// Two timestamps, because neither alone is sufficient. At is the hub's clock
// and is the only one worth sorting different sessions by. ClientMillis is the
// page's own clock, which is what gives the gaps *within* a session their
// meaning — and which on a wearable is routinely wrong in absolute terms, so
// it is stored as the page reported it and never used as an ordering key.
type Event struct {
	ID      int64     `json:"id,omitempty"`
	At      time.Time `json:"at"`
	Source  Source    `json:"source"`
	Kind    Kind      `json:"kind"`
	Session string    `json:"session"`

	// Seq is the page's own counter for this session. It is the ordering key a
	// reader should trust: events are batched, batches race, and two events
	// written in the same millisecond are indistinguishable by any clock. A
	// gap in Seq is itself a finding — it means a batch was dropped in flight.
	Seq int64 `json:"seq"`

	// ClientMillis is Date.now() as the page saw it. Zero when unreported.
	ClientMillis int64 `json:"client_millis,omitempty"`

	Message string `json:"message,omitempty"`
	Stack   string `json:"stack,omitempty"`
	URL     string `json:"url,omitempty"`

	// View is the tab, screen or route the page was showing. The field that
	// turns "it broke" into "it broke on the task list".
	View string `json:"view,omitempty"`

	// Detail is a small JSON object the page attached, already serialised.
	// Free-form on purpose: the useful detail for a gesture (which key, which
	// cursor index) has nothing in common with the useful detail for a fetch
	// (which status, how many milliseconds), and a schema covering both would
	// be mostly empty columns.
	Detail string `json:"detail,omitempty"`

	// Server-observed context. Never client-supplied — a page that sent its
	// own Actor would be asserting an identity rather than reporting one.
	UserAgent string `json:"user_agent,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Release   string `json:"release,omitempty"`
}

// Batch is the wire shape of one POST. The session and source are named once
// per batch rather than per event because they are constant for the page's
// whole lifetime, and repeating them 64 times would be most of the payload.
type Batch struct {
	Source  string      `json:"source"`
	Session string      `json:"session"`
	Release string      `json:"release"`
	Events  []WireEvent `json:"events"`
}

// WireEvent is one event as a browser sends it.
type WireEvent struct {
	Kind         string `json:"kind"`
	Seq          int64  `json:"seq"`
	ClientMillis int64  `json:"ts"`
	Message      string `json:"message"`
	Stack        string `json:"stack"`
	URL          string `json:"url"`
	View         string `json:"view"`
	Detail       string `json:"detail"`
}

// Context is everything the server knows about a batch that the batch itself
// must not be allowed to claim.
type Context struct {
	Source    Source
	At        time.Time
	UserAgent string
	ClientIP  string
	Actor     string
}

// Normalize converts a decoded batch into storable events.
//
// Total, by construction: every reachable input produces a valid slice rather
// than an error. Telemetry that refuses malformed input is telemetry that goes
// silent exactly when the page is malfunctioning, which is the only time it is
// worth having. Unusable input is clamped, relabelled or dropped per-event,
// and the rest of the batch still lands.
//
// ctx.Source wins over the batch's own claim: the route a batch arrived on
// knows which front end sent it, and the payload does not get a vote.
func Normalize(b Batch, ctx Context) []Event {
	if len(b.Events) == 0 {
		return nil
	}
	if len(b.Events) > MaxBatchEvents {
		b.Events = b.Events[:MaxBatchEvents]
	}

	src := ctx.Source
	if !src.Valid() {
		// Only reachable if a caller builds a Context by hand; the routes all
		// pin it. Fall back to the batch's claim, then to dashboard.
		src = Source(strings.TrimSpace(b.Source))
		if !src.Valid() {
			src = SourceDashboard
		}
	}
	at := ctx.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	at = at.UTC()

	session := sanitizeToken(b.Session, MaxShort)
	release := sanitizeToken(b.Release, MaxShort)
	ua := clamp(sanitizeLine(ctx.UserAgent), MaxShort)

	out := make([]Event, 0, len(b.Events))
	for _, we := range b.Events {
		kind := Kind(strings.TrimSpace(strings.ToLower(we.Kind)))
		if !kind.Valid() {
			// Relabelled rather than dropped: an unrecognised kind is usually
			// a newer page talking to an older hub, and the message is still
			// worth reading.
			kind = KindNote
		}
		ev := Event{
			At:           at,
			Source:       src,
			Kind:         kind,
			Session:      session,
			Seq:          we.Seq,
			ClientMillis: we.ClientMillis,
			Message:      clamp(Scrub(sanitizeLine(we.Message)), MaxMessage),
			Stack:        clamp(Scrub(sanitizeText(we.Stack)), MaxStack),
			URL:          clamp(Scrub(sanitizeLine(we.URL)), MaxURL),
			View:         clamp(sanitizeLine(we.View), MaxShort),
			Detail:       clamp(Scrub(sanitizeText(we.Detail)), MaxDetail),
			UserAgent:    ua,
			ClientIP:     ctx.ClientIP,
			Actor:        ctx.Actor,
			Release:      release,
		}
		if ev.Seq < 0 {
			ev.Seq = 0
		}
		if ev.ClientMillis < 0 {
			ev.ClientMillis = 0
		}
		if ev.Message == "" && ev.Stack == "" && ev.URL == "" && ev.Detail == "" {
			// Nothing legible survived normalization. Storing it would cost a
			// row and tell a reader only that something happened.
			continue
		}
		out = append(out, ev)
	}
	return out
}

// credentialPrefixes are the literal credential shapes cloop mints. Matched as
// substrings anywhere in a field, not just in query strings: a stack trace or
// an error message can quote a whole URL, and a message like `401 for
// cloop_pat_ab_cd` is exactly the kind of thing a page helpfully reports.
var credentialPrefixes = []string{
	"cloop_pat_",
	"cloop_glasses_",
}

// sensitiveParams are query-string keys whose values never belong in storage.
// Matched case-insensitively against the key only, so a URL *path* containing
// the word "token" survives intact.
var sensitiveParams = []string{
	"token", "access_token", "id_token", "refresh_token",
	"secret", "client_secret", "password", "passwd", "pwd",
	"api_key", "apikey", "key", "code", "sig", "signature",
	"authorization", "auth", "session", "sid",
}

// Scrub removes credential material from a free-text field.
//
// The load-bearing case is the glasses link. Its token is delivered in the
// page URL — `/glasses?token=cloop_glasses_…` — which means `location.href`,
// the natural value for an event's URL field, is a live credential valid for
// thirty days. The page lifts it out of the URL on load, but a trail is
// recorded from many places and one of them will eventually capture the
// original. Scrubbing at ingest is the boundary that holds regardless.
//
// Deliberately conservative: it over-redacts rather than reasoning about
// whether a particular `key=` is sensitive. A redacted field a human can ask
// about is recoverable; a leaked credential in a table is not.
func Scrub(s string) string {
	if s == "" {
		return s
	}
	s = scrubQueryParams(s)
	s = scrubBearer(s)
	s = scrubPrefixed(s)
	return s
}

// scrubQueryParams replaces the value of any sensitive key in a `k=v` pair.
// Operates on raw text rather than a parsed URL because the input is often not
// a URL at all — it may be a sentence that contains one, or a stack frame.
func scrubQueryParams(s string) string {
	if !strings.ContainsAny(s, "=") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			b.WriteString(s[i:])
			break
		}
		eq += i
		// Walk back over the key: the run of key-ish bytes immediately before
		// the '='.
		ks := eq
		for ks > i && isParamKeyByte(s[ks-1]) {
			ks--
		}
		key := strings.ToLower(s[ks:eq])
		b.WriteString(s[i:eq])
		if !matchesSensitiveParam(key) {
			b.WriteByte('=')
			i = eq + 1
			continue
		}
		// Consume the value: up to the next delimiter.
		ve := eq + 1
		for ve < len(s) && !isParamValueTerminator(s[ve]) {
			ve++
		}
		if ve == eq+1 {
			// Empty value — nothing to hide, and rewriting it to REDACTED
			// would invent information.
			b.WriteByte('=')
			i = eq + 1
			continue
		}
		b.WriteString("=[redacted]")
		i = ve
	}
	return b.String()
}

func matchesSensitiveParam(key string) bool {
	if key == "" {
		return false
	}
	for _, k := range sensitiveParams {
		if key == k {
			return true
		}
	}
	return false
}

func isParamKeyByte(c byte) bool {
	return c == '_' || c == '-' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// isParamValueTerminator reports whether c ends a query-parameter value. The
// set includes whitespace and quotes so a URL embedded in prose or in JSON
// stops at the right place.
func isParamValueTerminator(c byte) bool {
	switch c {
	case '&', '#', ' ', '\t', '\n', '\r', '"', '\'', '<', '>', ')', ']', '}', ',', ';':
		return true
	}
	return false
}

// scrubBearer redacts the credential in an Authorization-style value.
func scrubBearer(s string) string {
	const marker = "bearer "
	lower := strings.ToLower(s)
	idx := strings.Index(lower, marker)
	if idx < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for {
		rel := strings.Index(strings.ToLower(s[i:]), marker)
		if rel < 0 {
			b.WriteString(s[i:])
			break
		}
		start := i + rel + len(marker)
		b.WriteString(s[i:start])
		end := start
		for end < len(s) && !isSpaceOrQuote(s[end]) {
			end++
		}
		if end == start {
			i = start
			continue
		}
		b.WriteString("[redacted]")
		i = end
	}
	return b.String()
}

func isSpaceOrQuote(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', ',', ';':
		return true
	}
	return false
}

// scrubPrefixed redacts any run that begins with a cloop credential prefix,
// wherever it appears.
func scrubPrefixed(s string) string {
	for _, prefix := range credentialPrefixes {
		for {
			idx := strings.Index(s, prefix)
			if idx < 0 {
				break
			}
			end := idx + len(prefix)
			for end < len(s) && isCredentialByte(s[end]) {
				end++
			}
			s = s[:idx] + "[redacted]" + s[end:]
		}
	}
	return s
}

func isCredentialByte(c byte) bool {
	return c == '_' || c == '-' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// sanitizeLine strips control characters, including newlines, and collapses
// surrounding space. For fields that are one line by nature — a message, a
// URL, a view name — so that a hostile value cannot forge extra lines in a
// log reader or a terminal.
func sanitizeLine(s string) string {
	return strings.TrimSpace(stripControl(s, false))
}

// sanitizeText is sanitizeLine but keeps newlines and tabs, for the fields
// whose whole value is their multi-line shape: stack traces and JSON detail.
func sanitizeText(s string) string {
	return strings.TrimSpace(stripControl(s, true))
}

// sanitizeToken keeps only the bytes an identifier may contain. Applied to the
// session id and release string, which are used as query filters and shown in
// a table, and which a browser supplies.
func sanitizeToken(s string, max int) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		if isCredentialByte(c) || c == '.' || c == ':' || c == '+' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// stripControl removes C0/C7 control characters and invalid UTF-8. Invalid
// UTF-8 matters because these strings end up in JSON responses and in a SQLite
// TEXT column, and a malformed sequence can fail the encode for the whole
// batch — one bad byte from one page silencing the rest of the trail.
func stripControl(s string, keepWhitespace bool) string {
	needsWork := !utf8.ValidString(s)
	if !needsWork {
		for _, r := range s {
			if isStrippable(r, keepWhitespace) {
				needsWork = true
				break
			}
		}
	}
	if !needsWork {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		if isStrippable(r, keepWhitespace) {
			// Replaced with a space rather than dropped so words on either
			// side of a stripped newline do not fuse into one token.
			if !keepWhitespace {
				b.WriteByte(' ')
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isStrippable(r rune, keepWhitespace bool) bool {
	if keepWhitespace && (r == '\n' || r == '\t' || r == '\r') {
		return false
	}
	return r == 0 || unicode.IsControl(r)
}

// clamp truncates to max bytes on a rune boundary, marking the cut so a reader
// knows the value is partial rather than assuming the page sent it that way.
func clamp(s string, max int) string {
	if len(s) <= max {
		return s
	}
	const marker = "…[truncated]"
	if max <= len(marker) {
		return s[:max]
	}
	cut := max - len(marker)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + marker
}
