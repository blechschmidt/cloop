package telemetry

import (
	"strings"
	"testing"
	"time"
)

// TestScrub_RedactsTheGlassesLink is the case this package exists to prevent.
//
// The display-glasses credential is delivered in the page URL and is valid for
// thirty days. location.href is the obvious value for an event's URL field, so
// without scrubbing the first trail a wearer produces copies a live bearer
// token into a table that audit.read can list.
func TestScrub_RedactsTheGlassesLink(t *testing.T) {
	t.Parallel()

	const live = "cloop_glasses_7f3a_2b91ccd04e5f"
	in := "https://hub.example.com/glasses?token=" + live

	got := Scrub(in)

	if strings.Contains(got, live) {
		t.Fatalf("Scrub left the credential in place: %q\n"+
			"a glasses link survives thirty days; storing one turns read access "+
			"to the telemetry table into a working session on someone's account", got)
	}
	if !strings.Contains(got, "/glasses") {
		t.Errorf("Scrub(%q) = %q — the path was destroyed along with the "+
			"credential, and the path is the part worth reading", in, got)
	}
}

func TestScrub(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		absent  []string
		present []string
	}{
		{
			name:    "query token",
			in:      "/api/glasses/tasks?project_idx=2&token=abc123xyz&page=3",
			absent:  []string{"abc123xyz"},
			present: []string{"project_idx=2", "page=3"},
		},
		{
			name:    "authorization header quoted in a message",
			in:      `request failed, headers {"Authorization":"Bearer eyJhbGciOi.J9.sig"}`,
			absent:  []string{"eyJhbGciOi.J9.sig"},
			present: []string{"request failed"},
		},
		{
			name:    "personal access token anywhere in prose",
			in:      "401 while calling with cloop_pat_9f2e_deadbeefcafe, retrying",
			absent:  []string{"deadbeefcafe", "cloop_pat_9f2e"},
			present: []string{"401 while calling with", "retrying"},
		},
		{
			name:    "several sensitive params in one url",
			in:      "https://h/cb?code=abc&state=xyz&id_token=zzz",
			absent:  []string{"code=abc", "id_token=zzz"},
			present: []string{"state=xyz"},
		},
		{
			name: "a path segment that merely contains the word token",
			in:   "/api/tokens/list?page=1",
			// Nothing to redact: `token` appears in the path, not as a
			// parameter key. Over-redaction here would hide which endpoint
			// failed, which is the whole content of the event.
			present: []string{"/api/tokens/list", "page=1"},
		},
		{
			name:    "empty value is left alone",
			in:      "/x?token=&next=/home",
			present: []string{"token=", "next=/home"},
			absent:  []string{"[redacted]"},
		},
		{
			name:    "case insensitive key and scheme",
			in:      "/x?TOKEN=SEKRIT&ok=1",
			absent:  []string{"SEKRIT"},
			present: []string{"ok=1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Scrub(tc.in)
			for _, s := range tc.absent {
				if strings.Contains(got, s) {
					t.Errorf("Scrub(%q) = %q — still contains %q", tc.in, got, s)
				}
			}
			for _, s := range tc.present {
				if !strings.Contains(got, s) {
					t.Errorf("Scrub(%q) = %q — lost %q, which is not a credential",
						tc.in, got, s)
				}
			}
		})
	}
}

// TestScrub_Terminates guards the rewrite loops. scrubPrefixed replaces a match
// with text of its own and re-searches from the start; if the replacement ever
// contained a prefix it looks for, the loop would never end.
func TestScrub_Terminates(t *testing.T) {
	t.Parallel()

	done := make(chan string, 1)
	go func() {
		done <- Scrub(strings.Repeat("cloop_pat_aaaa bearer bbbb tok=cc ", 200))
	}()
	select {
	case got := <-done:
		if strings.Contains(got, "cloop_pat_aaaa") {
			t.Errorf("credential survived: %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Scrub did not terminate — a replacement re-matched its own pattern")
	}
}

func ctxFor(src Source) Context {
	return Context{
		Source:    src,
		At:        time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC),
		UserAgent: "Mozilla/5.0 (glasses)",
		ClientIP:  "10.0.0.9",
		Actor:     "aiden@example.com",
	}
}

// TestNormalize_IsTotal states the package's central contract: no reachable
// input makes normalization fail. Telemetry that rejects malformed input goes
// silent exactly when the page is malfunctioning.
func TestNormalize_IsTotal(t *testing.T) {
	t.Parallel()

	batches := []Batch{
		{},
		{Events: []WireEvent{{}}},
		{Source: "../../etc", Session: "'; DROP TABLE telemetry_events--",
			Events: []WireEvent{{Kind: "\x00\x01", Message: "x"}}},
		{Events: []WireEvent{{Kind: "error", Seq: -5, ClientMillis: -1, Message: "m"}}},
		{Events: []WireEvent{{Kind: "error", Message: string([]byte{0xff, 0xfe, 'h', 'i'})}}},
	}
	for i, b := range batches {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("batch %d panicked: %v", i, r)
				}
			}()
			for _, ev := range Normalize(b, ctxFor(SourceGlasses)) {
				if !ev.Kind.Valid() {
					t.Errorf("batch %d produced invalid kind %q", i, ev.Kind)
				}
				if !ev.Source.Valid() {
					t.Errorf("batch %d produced invalid source %q", i, ev.Source)
				}
				if ev.Seq < 0 || ev.ClientMillis < 0 {
					t.Errorf("batch %d produced negative counter", i)
				}
			}
		}()
	}
}

// TestNormalize_SourceComesFromTheRouteNotThePayload: the ingest path knows
// which front end is talking. A batch claiming otherwise must not be believed,
// or a dashboard could file events into the glasses trail.
func TestNormalize_SourceComesFromTheRouteNotThePayload(t *testing.T) {
	t.Parallel()

	evs := Normalize(Batch{
		Source: "dashboard",
		Events: []WireEvent{{Kind: "gesture", Message: "swipe"}},
	}, ctxFor(SourceGlasses))

	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	if evs[0].Source != SourceGlasses {
		t.Errorf("Source = %q, want %q — the payload overrode the route",
			evs[0].Source, SourceGlasses)
	}
}

// TestNormalize_ServerContextIsNotClientSupplied: a page reports, it does not
// assert. Identity and address are stamped by the hub.
func TestNormalize_ServerContextIsNotClientSupplied(t *testing.T) {
	t.Parallel()

	ctx := ctxFor(SourceDashboard)
	evs := Normalize(Batch{Events: []WireEvent{{Kind: "note", Message: "hi"}}}, ctx)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	if evs[0].Actor != ctx.Actor || evs[0].ClientIP != ctx.ClientIP {
		t.Errorf("actor/ip = %q/%q, want %q/%q",
			evs[0].Actor, evs[0].ClientIP, ctx.Actor, ctx.ClientIP)
	}
	if !evs[0].At.Equal(ctx.At) {
		t.Errorf("At = %v, want the server clock %v", evs[0].At, ctx.At)
	}
}

func TestNormalize_UnknownKindBecomesNote(t *testing.T) {
	t.Parallel()

	evs := Normalize(Batch{Events: []WireEvent{
		{Kind: "telepathy", Message: "from a newer page"},
	}}, ctxFor(SourceDashboard))

	if len(evs) != 1 {
		t.Fatalf("an unrecognised kind was dropped; a newer page talking to an "+
			"older hub must still be readable (got %d events)", len(evs))
	}
	if evs[0].Kind != KindNote {
		t.Errorf("Kind = %q, want %q", evs[0].Kind, KindNote)
	}
}

func TestNormalize_DropsEventsWithNothingLegible(t *testing.T) {
	t.Parallel()

	evs := Normalize(Batch{Events: []WireEvent{
		{Kind: "gesture", View: "tasks"}, // view only — no content
		{Kind: "gesture", Message: "\x00\x00"},
		{Kind: "gesture", Message: "swipe-right"},
	}}, ctxFor(SourceGlasses))

	if len(evs) != 1 {
		t.Fatalf("got %d events, want only the one carrying content", len(evs))
	}
	if evs[0].Message != "swipe-right" {
		t.Errorf("kept the wrong event: %q", evs[0].Message)
	}
}

func TestNormalize_CapsBatchSize(t *testing.T) {
	t.Parallel()

	var wire []WireEvent
	for i := 0; i < MaxBatchEvents*4; i++ {
		wire = append(wire, WireEvent{Kind: "note", Message: "m"})
	}
	if got := len(Normalize(Batch{Events: wire}, ctxFor(SourceDashboard))); got > MaxBatchEvents {
		t.Errorf("accepted %d events, want at most %d", got, MaxBatchEvents)
	}
}

func TestNormalize_ClampsFields(t *testing.T) {
	t.Parallel()

	evs := Normalize(Batch{Events: []WireEvent{{
		Kind:    "error",
		Message: strings.Repeat("m", MaxMessage*3),
		Stack:   strings.Repeat("s", MaxStack*3),
		URL:     strings.Repeat("u", MaxURL*3),
		Detail:  strings.Repeat("d", MaxDetail*3),
	}}}, ctxFor(SourceDashboard))

	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	e := evs[0]
	for _, c := range []struct {
		name string
		got  string
		max  int
	}{
		{"Message", e.Message, MaxMessage},
		{"Stack", e.Stack, MaxStack},
		{"URL", e.URL, MaxURL},
		{"Detail", e.Detail, MaxDetail},
	} {
		if len(c.got) > c.max {
			t.Errorf("%s is %d bytes, want at most %d", c.name, len(c.got), c.max)
		}
		if !strings.Contains(c.got, "truncated") {
			t.Errorf("%s was cut without a marker — a reader cannot tell a "+
				"clipped value from one the page sent that way", c.name)
		}
	}
}

// TestNormalize_StripsControlCharacters: these strings reach a terminal (the
// CLI reader) and a JSON response. A value that can forge a newline can forge
// a log line.
func TestNormalize_StripsControlCharacters(t *testing.T) {
	t.Parallel()

	evs := Normalize(Batch{Events: []WireEvent{{
		Kind:    "note",
		Message: "before\n2026-01-01 FAKE LOG LINE\rafter\x1b[31m",
		Stack:   "frame one\nframe two", // newlines are the point of a stack
	}}}, ctxFor(SourceDashboard))

	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	if strings.ContainsAny(evs[0].Message, "\n\r\x1b") {
		t.Errorf("Message kept a control character: %q", evs[0].Message)
	}
	if !strings.Contains(evs[0].Stack, "\n") {
		t.Errorf("Stack lost its newlines (%q) — a one-line stack trace is "+
			"unreadable", evs[0].Stack)
	}
}

// TestNormalize_ScrubsEveryFreeTextField: it is not enough to scrub the URL.
// A rejected fetch reports its URL inside the message, and a stack frame
// carries the script URL it came from.
func TestNormalize_ScrubsEveryFreeTextField(t *testing.T) {
	t.Parallel()

	const live = "cloop_glasses_aa_bb"
	evs := Normalize(Batch{
		Session: "s1",
		Events: []WireEvent{{
			Kind:    "fetch",
			Message: "GET /glasses?token=" + live + " failed",
			Stack:   "at load (/glasses?token=" + live + ":1:1)",
			URL:     "/glasses?token=" + live,
			Detail:  `{"href":"/glasses?token=` + live + `"}`,
		}},
	}, ctxFor(SourceGlasses))

	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	e := evs[0]
	for _, f := range []struct{ name, val string }{
		{"Message", e.Message}, {"Stack", e.Stack},
		{"URL", e.URL}, {"Detail", e.Detail},
	} {
		if strings.Contains(f.val, live) {
			t.Errorf("%s carries a live credential: %q", f.name, f.val)
		}
	}
}

func TestSanitizeToken(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"abc123":                    "abc123",
		"  spaced  ":                "spaced",
		"'; DROP TABLE x--":         "DROPTABLEx--",
		"<script>alert(1)</script>": "scriptalert1script",
		"a.b:c+d":                   "a.b:c+d",
	}
	for in, want := range cases {
		if got := sanitizeToken(in, MaxShort); got != want {
			t.Errorf("sanitizeToken(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeToken(strings.Repeat("a", MaxShort*2), MaxShort); len(got) != MaxShort {
		t.Errorf("sanitizeToken did not bound length: got %d", len(got))
	}
}
