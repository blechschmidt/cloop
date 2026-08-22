package auditexport

// Golden-fixture tests for the three export formats (Task 20167).
//
// Export formats are a contract with software nobody here controls: a SIEM
// parser, a spreadsheet, someone's jq pipeline. Golden files are the right
// shape of test for that, because they fail on *any* change to the bytes —
// including the well-intentioned ones that would silently break a downstream
// consumer. Regenerate deliberately with:
//
//	go test ./pkg/auditexport/ -update

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

var updateGolden = flag.Bool("update", false, "update golden files")

// fixtureEvents is a fixed, deterministic set spanning the shapes the
// formatters have to handle: several severities, an empty entity id, a
// payload containing the characters each format has to escape, and the
// genesis prev_hash.
func fixtureEvents() []Event {
	ts := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	zero := strings.Repeat("0", 64)
	h := func(b byte) string { return strings.Repeat(string(b), 64) }

	return []Event{
		{
			ID: 1, Timestamp: ts, Actor: "system",
			EventType: "state.save", EntityType: "plan", EntityID: "",
			Payload:  `{"goal":"ship the thing","task_count":3}`,
			PrevHash: zero, RowHash: h('a'),
		},
		{
			ID: 2, Timestamp: ts.Add(90 * time.Second), Actor: "alice@example.com",
			EventType: "task.delete", EntityType: "task", EntityID: "42",
			Payload:  `{"id":42}`,
			PrevHash: h('a'), RowHash: h('b'),
		},
		{
			ID: 3, Timestamp: ts.Add(5 * time.Minute), Actor: "alice@example.com",
			EventType: "executor.enroll", EntityType: "executor", EntityID: "edge-1",
			Payload:  `{"name":"edge one","workdir_root":"/srv/work"}`,
			PrevHash: h('b'), RowHash: h('c'),
		},
		{
			ID: 4, Timestamp: ts.Add(6 * time.Minute), Actor: "bob@example.com",
			EventType: "authz.denied", EntityType: "permission", EntityID: "run.start",
			Payload:  `{"outcome":"denied","role":"viewer"}`,
			PrevHash: h('c'), RowHash: h('d'),
		},
		{
			// The escaping torture case: a pipe (special in the CEF header),
			// an equals sign (special in the CEF extension), a backslash
			// (special in both), a newline, and a quote (special in CSV).
			ID: 5, Timestamp: ts.Add(7 * time.Minute), Actor: `weird|user=name`,
			EventType: "config.set", EntityType: "config", EntityID: "",
			Payload:  "{\"note\":\"a|b=c\\\\d\\ne\\\"f\"}",
			PrevHash: h('d'), RowHash: h('e'),
		},
	}
}

func goldenPath(name string) string {
	return filepath.Join("testdata", name)
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := goldenPath(name)

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		t.Logf("updated golden file: %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden file missing (%s) — run: go test ./pkg/auditexport/ -update", path)
	}
	if string(want) != got {
		gotLines, wantLines := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
			var g, w string
			if i < len(gotLines) {
				g = gotLines[i]
			}
			if i < len(wantLines) {
				w = wantLines[i]
			}
			if g != w {
				t.Fatalf("%s differs at line %d:\n  got:  %s\n  want: %s", name, i+1, g, w)
			}
		}
		t.Fatalf("%s differs from golden", name)
	}
}

func writeToString(t *testing.T, events []Event, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, events, opts); err != nil {
		t.Fatalf("Write(%s): %v", opts.Format, err)
	}
	return buf.String()
}

func TestGoldenJSONL(t *testing.T) {
	got := writeToString(t, fixtureEvents(), Options{Format: FormatJSONL})
	assertGolden(t, "trail.jsonl", got)
}

func TestGoldenCSV(t *testing.T) {
	got := writeToString(t, fixtureEvents(), Options{Format: FormatCSV})
	assertGolden(t, "trail.csv", got)
}

func TestGoldenCEF(t *testing.T) {
	// Pin the version so the golden does not move with the build stamp.
	got := writeToString(t, fixtureEvents(), Options{Format: FormatCEF, ProductVersion: "1.2.3"})
	assertGolden(t, "trail.cef", got)
}

// ── Format invariants ───────────────────────────────────────────────────────
//
// The goldens pin the exact bytes; these assert the properties a consumer
// actually depends on, so a deliberate golden update cannot silently break
// parseability.

func TestJSONLIsOneParseableObjectPerLine(t *testing.T) {
	events := fixtureEvents()
	out := writeToString(t, events, Options{Format: FormatJSONL})

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != len(events) {
		t.Fatalf("got %d lines, want %d", len(lines), len(events))
	}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", i+1, err, line)
		}
		if rec["row_hash"] == "" || rec["prev_hash"] == "" {
			t.Errorf("line %d dropped a hash — an export without them cannot be re-verified", i+1)
		}
	}
	// The payload must arrive as structured JSON, not a quoted string, so a
	// consumer can index into it.
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if _, ok := first["payload"].(map[string]any); !ok {
		t.Errorf("payload = %T, want an embedded JSON object", first["payload"])
	}
}

func TestJSONLWrapsNonJSONPayloadAsString(t *testing.T) {
	events := []Event{{
		ID: 1, Timestamp: time.Unix(0, 0).UTC(), Actor: "system",
		EventType: "task.upsert", Payload: "not json at all",
	}}
	out := writeToString(t, events, Options{Format: FormatJSONL})

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
		t.Fatalf("a malformed payload broke the whole line: %v\n%s", err, out)
	}
	if got, ok := rec["payload"].(string); !ok || got != "not json at all" {
		t.Errorf("payload = %#v, want the raw text preserved as a string", rec["payload"])
	}
}

func TestCSVRoundTripsThroughAParser(t *testing.T) {
	events := fixtureEvents()
	out := writeToString(t, events, Options{Format: FormatCSV})

	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("csv does not parse: %v", err)
	}
	if len(records) != len(events)+1 {
		t.Fatalf("got %d records (incl. header), want %d", len(records), len(events)+1)
	}
	if got := strings.Join(records[0], ","); got != strings.Join(csvHeader, ",") {
		t.Errorf("header = %q, want %q", got, strings.Join(csvHeader, ","))
	}
	// The torture row survives quoting intact: pipes, equals signs,
	// backslashes and quotes all come back byte-identical.
	last := records[len(records)-1]
	want := events[len(events)-1]
	if last[2] != want.Actor {
		t.Errorf("actor = %q, want %q — pipes and equals must survive verbatim", last[2], want.Actor)
	}
	if last[6] != want.Payload {
		t.Errorf("payload did not round-trip:\n  got:  %q\n  want: %q", last[6], want.Payload)
	}
	if last[8] != want.RowHash {
		t.Errorf("row_hash = %q, want %q", last[8], want.RowHash)
	}
}

// TestCSVQuotesEmbeddedNewlines covers the field shape that breaks naive
// line-splitting consumers. Payloads are normally JSON (newlines escaped),
// but the column is free text and a malformed row must not corrupt the file.
func TestCSVQuotesEmbeddedNewlines(t *testing.T) {
	events := []Event{{
		ID: 1, Timestamp: time.Unix(0, 0).UTC(), Actor: "u",
		EventType: "task.upsert", EntityType: "task", EntityID: "1",
		Payload: "line one\nline two,with comma\nand a \" quote",
	}}
	out := writeToString(t, events, Options{Format: FormatCSV})

	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("csv with an embedded newline does not parse: %v\n%s", err, out)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want header + 1 (the newline must not split the row)", len(records))
	}
	if records[1][6] != events[0].Payload {
		t.Errorf("payload did not round-trip:\n  got:  %q\n  want: %q", records[1][6], events[0].Payload)
	}
}

func TestCEFHeaderEscaping(t *testing.T) {
	events := []Event{{
		ID: 1, Timestamp: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		Actor: "someone", EventType: `weird|type\with`, EntityType: "task", EntityID: "1",
	}}
	out := strings.TrimSpace(writeToString(t, events, Options{Format: FormatCEF, ProductVersion: "1.0"}))

	// A CEF header is exactly seven pipe-delimited fields before the
	// extension; unescaped pipes in a field would produce more.
	head := out
	if i := strings.Index(out, "rt="); i > 0 {
		head = out[:i]
	}
	if strings.Count(head, `\|`) < 2 {
		t.Errorf("pipes in header fields were not escaped: %s", head)
	}
	if !strings.Contains(head, `\\`) {
		t.Errorf("backslash in a header field was not escaped: %s", head)
	}
	if !strings.HasPrefix(out, "CEF:0|cloop|cloop|1.0|") {
		t.Errorf("header prefix = %q, want the vendor/product/version triple", out[:40])
	}
}

func TestCEFExtensionEscaping(t *testing.T) {
	events := []Event{{
		ID: 1, Timestamp: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		Actor: "u", EventType: "config.set", EntityType: "config",
		Payload: "a=b\nc\\d",
	}}
	out := strings.TrimSpace(writeToString(t, events, Options{Format: FormatCEF, ProductVersion: "1.0"}))

	if strings.Count(out, "\n") != 0 {
		t.Errorf("a record must stay on one line, got:\n%s", out)
	}
	if !strings.Contains(out, `\n`) {
		t.Errorf("embedded newline was not escaped to \\n: %s", out)
	}
	// The payload's own '=' must be escaped so it cannot be mistaken for a
	// key/value separator; the real separators must not be.
	if !strings.Contains(out, `a\=b`) {
		t.Errorf("'=' inside a value was not escaped: %s", out)
	}
	if !strings.Contains(out, "cs4Label=payload") {
		t.Errorf("custom string label missing — an unlabelled cs4 is meaningless: %s", out)
	}
}

func TestCEFSeverityRanking(t *testing.T) {
	cases := []struct {
		eventType string
		want      int
	}{
		{"authz.denied", 8},
		{"secret.lease", 7},
		{"egress.grant", 7},
		{"executor.enroll", 6},
		{"config.set", 5},
		{"authz.granted", 4},
		{"task.delete", 4},
		{"task.upsert", 2},
		{"state.save", 2},
		{"step.append", 1},
		{"something.new", 3},
	}
	for _, tc := range cases {
		if got := severityFor(Event{EventType: tc.eventType}); got != tc.want {
			t.Errorf("severityFor(%q) = %d, want %d", tc.eventType, got, tc.want)
		}
	}
}

func TestCEFTruncatesLongPayloads(t *testing.T) {
	long := strings.Repeat("x", 10_000)
	events := []Event{{
		ID: 1, Timestamp: time.Unix(0, 0).UTC(), Actor: "u",
		EventType: "step.append", EntityType: "step", Payload: long,
	}}
	out := writeToString(t, events, Options{Format: FormatCEF, MaxPayloadBytes: 128})

	if len(out) > 1024 {
		t.Errorf("record is %d bytes; truncation did not apply", len(out))
	}
	if !strings.Contains(out, "truncated") {
		t.Errorf("a clipped payload must say so, got: %s", out)
	}
}

func TestParseFormat(t *testing.T) {
	ok := map[string]Format{
		"jsonl": FormatJSONL, "JSONL": FormatJSONL, "json": FormatJSONL,
		"ndjson": FormatJSONL, "": FormatJSONL,
		"csv": FormatCSV, "CSV": FormatCSV,
		"cef": FormatCEF, " cef ": FormatCEF,
	}
	for in, want := range ok {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("ParseFormat(\"xml\") should fail")
	} else if !strings.Contains(err.Error(), "jsonl") {
		t.Errorf("error should list the valid formats, got: %v", err)
	}
}

func TestWriteRejectsUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, fixtureEvents(), Options{Format: Format("xml")}); err == nil {
		t.Error("Write should reject an unknown format rather than writing nothing silently")
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize(fixtureEvents(), FormatCEF)
	if s.Events != 5 || s.FirstID != 1 || s.LastID != 5 {
		t.Errorf("got %+v, want 5 events spanning ids 1–5", s)
	}
	if len(s.Actors) != 4 {
		t.Errorf("Actors = %v, want the 4 distinct actors", s.Actors)
	}
	if len(s.EventTypes) != 5 {
		t.Errorf("EventTypes = %v, want 5 distinct types", s.EventTypes)
	}
	// Empty input must not panic or report a bogus range.
	if empty := Summarize(nil, FormatCSV); empty.Events != 0 || empty.FirstID != 0 {
		t.Errorf("Summarize(nil) = %+v, want a zero summary", empty)
	}
}

// TestEventTypeAliasesStatedbType guards the re-export: if statedb.AuditEvent
// gains a field, this file is where the formatters need updating.
func TestEventTypeAliasesStatedbType(t *testing.T) {
	var ev Event = statedb.AuditEvent{ID: 7}
	if ev.ID != 7 {
		t.Fatal("Event must alias statedb.AuditEvent")
	}
}
