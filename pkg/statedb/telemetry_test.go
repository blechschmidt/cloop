package statedb

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/telemetry"
)

func telEvent(session string, seq int64, kind telemetry.Kind, msg string) telemetry.Event {
	return telemetry.Event{
		At:      time.Now().UTC(),
		Source:  telemetry.SourceGlasses,
		Kind:    kind,
		Session: session,
		Seq:     seq,
		Message: msg,
	}
}

func TestAppendAndQueryTelemetry(t *testing.T) {
	db := openTestDB(t)

	if err := db.AppendTelemetry(nil); err != nil {
		t.Fatalf("empty append should be a no-op: %v", err)
	}

	batch := []telemetry.Event{
		telEvent("s1", 1, telemetry.KindLifecycle, "load"),
		telEvent("s1", 2, telemetry.KindGesture, "swipe-right"),
		telEvent("s1", 3, telemetry.KindError, "boom"),
	}
	if err := db.AppendTelemetry(batch); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, total, err := db.QueryTelemetry(TelemetryFilter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 3 || len(got) != 3 {
		t.Fatalf("got %d rows (total %d), want 3", len(got), total)
	}
	// Newest first: a reader opening the panel wants the most recent thing
	// that happened, not the oldest thing still retained.
	if got[0].Seq != 3 {
		t.Errorf("first row seq = %d, want 3 (newest first)", got[0].Seq)
	}
	if got[0].Kind != telemetry.KindError || got[0].Message != "boom" {
		t.Errorf("round trip lost content: %+v", got[0])
	}
	if got[0].Source != telemetry.SourceGlasses {
		t.Errorf("source = %q, want glasses", got[0].Source)
	}
}

func TestQueryTelemetry_Filters(t *testing.T) {
	db := openTestDB(t)

	evs := []telemetry.Event{
		telEvent("s1", 1, telemetry.KindGesture, "swipe on /api/glasses/tasks"),
		telEvent("s1", 2, telemetry.KindError, "TypeError in tasks"),
		telEvent("s2", 1, telemetry.KindGesture, "swipe elsewhere"),
	}
	evs[2].Source = telemetry.SourceDashboard
	if err := db.AppendTelemetry(evs); err != nil {
		t.Fatalf("append: %v", err)
	}

	cases := []struct {
		name string
		f    TelemetryFilter
		want int
	}{
		{"by source", TelemetryFilter{Source: "glasses"}, 2},
		{"by kind", TelemetryFilter{Kind: "error"}, 1},
		{"by session", TelemetryFilter{Session: "s2"}, 1},
		{"by search", TelemetryFilter{Search: "swipe"}, 2},
		{"combined", TelemetryFilter{Source: "glasses", Kind: "gesture"}, 1},
		{"no match", TelemetryFilter{Session: "nope"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, total, err := db.QueryTelemetry(tc.f)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if len(rows) != tc.want || total != tc.want {
				t.Errorf("got %d rows (total %d), want %d", len(rows), total, tc.want)
			}
		})
	}
}

// TestQueryTelemetry_SearchTreatsWildcardsLiterally: the search box takes
// whatever a reader types, and URLs are full of percent-encoding. A search for
// "%2F" must not become a wildcard that matches the whole table.
func TestQueryTelemetry_SearchTreatsWildcardsLiterally(t *testing.T) {
	db := openTestDB(t)

	if err := db.AppendTelemetry([]telemetry.Event{
		telEvent("s1", 1, telemetry.KindFetch, "GET /a%2Fb"),
		telEvent("s1", 2, telemetry.KindFetch, "GET /plain"),
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	rows, _, err := db.QueryTelemetry(TelemetryFilter{Search: "%"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("searching for %q matched %d rows, want 1 — the term was "+
			"interpreted as a LIKE wildcard instead of a literal", "%", len(rows))
	}
}

func TestQueryTelemetry_Paging(t *testing.T) {
	db := openTestDB(t)

	var evs []telemetry.Event
	for i := 1; i <= 25; i++ {
		evs = append(evs, telEvent("s1", int64(i), telemetry.KindNote, fmt.Sprintf("e%d", i)))
	}
	if err := db.AppendTelemetry(evs); err != nil {
		t.Fatalf("append: %v", err)
	}

	first, total, err := db.QueryTelemetry(TelemetryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 25 || len(first) != 10 {
		t.Fatalf("page one: %d rows, total %d; want 10/25", len(first), total)
	}
	second, _, err := db.QueryTelemetry(TelemetryFilter{Limit: 10, Offset: 10})
	if err != nil {
		t.Fatalf("query page two: %v", err)
	}
	if len(second) != 10 {
		t.Fatalf("page two: %d rows, want 10", len(second))
	}
	if first[0].ID == second[0].ID {
		t.Error("offset had no effect — page two repeats page one")
	}

	// A caller asking for more than the cap gets the cap, not an error: a
	// reader who types a big number should see a big page, not a failure.
	capped, _, err := db.QueryTelemetry(TelemetryFilter{Limit: TelemetryMaxLimit * 10})
	if err != nil {
		t.Fatalf("query with oversized limit: %v", err)
	}
	if len(capped) > TelemetryMaxLimit {
		t.Errorf("returned %d rows, want at most %d", len(capped), TelemetryMaxLimit)
	}
}

func TestListTelemetrySessions(t *testing.T) {
	db := openTestDB(t)

	older := time.Now().UTC().Add(-time.Hour)
	evs := []telemetry.Event{
		{At: older, Source: telemetry.SourceGlasses, Kind: telemetry.KindLifecycle,
			Session: "s1", Seq: 1, Message: "load", UserAgent: "GlassOS/1", Actor: "a@b.c"},
		{At: older.Add(time.Minute), Source: telemetry.SourceGlasses, Kind: telemetry.KindError,
			Session: "s1", Seq: 2, Message: "boom", UserAgent: "GlassOS/1", Actor: "a@b.c"},
		{At: time.Now().UTC(), Source: telemetry.SourceDashboard, Kind: telemetry.KindView,
			Session: "s2", Seq: 1, Message: "tasks", UserAgent: "Firefox"},
	}
	if err := db.AppendTelemetry(evs); err != nil {
		t.Fatalf("append: %v", err)
	}

	all, err := db.ListTelemetrySessions("", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d sessions, want 2", len(all))
	}
	// Most recently active first: an investigation starts from "what just
	// happened", not from the oldest session still retained.
	if all[0].Session != "s2" {
		t.Errorf("first session = %q, want s2 (most recent activity first)", all[0].Session)
	}

	var s1 TelemetrySession
	for _, s := range all {
		if s.Session == "s1" {
			s1 = s
		}
	}
	if s1.Events != 2 || s1.Errors != 1 {
		t.Errorf("s1 rolled up to %d events / %d errors, want 2/1", s1.Events, s1.Errors)
	}
	if s1.UserAgent != "GlassOS/1" || s1.Actor != "a@b.c" {
		t.Errorf("s1 lost its correlated context: %+v", s1)
	}
	if !s1.LastSeen.After(s1.FirstSeen) {
		t.Errorf("s1 first/last = %v/%v — the span collapsed", s1.FirstSeen, s1.LastSeen)
	}

	only, err := db.ListTelemetrySessions("glasses", 0)
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(only) != 1 || only[0].Session != "s1" {
		t.Errorf("source filter returned %+v, want only s1", only)
	}
}

// TestAppendTelemetry_EnforcesRowCeiling is the bound that matters most: ingest
// is a public endpoint, so the table must be self-limiting on the write path
// and not depend on a janitor that runs hourly.
func TestAppendTelemetry_EnforcesRowCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("writes TelemetryMaxRows rows")
	}
	db := openTestDB(t)

	// Push well past the ceiling plus its slack.
	const batchSize = 500
	total := TelemetryMaxRows + telemetryTrimSlack*2
	for written := 0; written < total; written += batchSize {
		var evs []telemetry.Event
		for i := 0; i < batchSize; i++ {
			evs = append(evs, telEvent("flood", int64(written+i), telemetry.KindNote, "x"))
		}
		if err := db.AppendTelemetry(evs); err != nil {
			t.Fatalf("append at %d: %v", written, err)
		}
	}

	var count int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM telemetry_events`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count > TelemetryMaxRows+telemetryTrimSlack {
		t.Errorf("table holds %d rows, want at most %d — an unauthenticated "+
			"endpoint can grow it without bound",
			count, TelemetryMaxRows+telemetryTrimSlack)
	}

	// The newest events must be the survivors; retention that dropped the
	// most recent trail would defeat the purpose.
	rows, _, err := db.QueryTelemetry(TelemetryFilter{Limit: 1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 || rows[0].Seq < int64(TelemetryMaxRows) {
		t.Errorf("newest surviving seq = %v, want a recent one — the trim kept "+
			"the wrong end of the table", rows)
	}
}

func TestPruneTelemetry(t *testing.T) {
	db := openTestDB(t)

	old := telEvent("s1", 1, telemetry.KindNote, "ancient")
	old.At = time.Now().UTC().Add(-48 * time.Hour)
	fresh := telEvent("s1", 2, telemetry.KindNote, "recent")
	if err := db.AppendTelemetry([]telemetry.Event{old, fresh}); err != nil {
		t.Fatalf("append: %v", err)
	}

	n, err := db.PruneTelemetry(time.Now().UTC().Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d rows, want 1", n)
	}
	rows, _, err := db.QueryTelemetry(TelemetryFilter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 || rows[0].Message != "recent" {
		t.Errorf("prune kept the wrong rows: %+v", rows)
	}
}

// TestAppendTelemetry_StoresHostileStringsVerbatim: normalization is
// pkg/telemetry's job, and storage must not add a second, divergent opinion.
// What it must do is bind every value as a parameter.
func TestAppendTelemetry_StoresHostileStringsVerbatim(t *testing.T) {
	db := openTestDB(t)

	nasty := `'; DROP TABLE telemetry_events; --`
	if err := db.AppendTelemetry([]telemetry.Event{
		telEvent(nasty, 1, telemetry.KindNote, nasty),
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	rows, _, err := db.QueryTelemetry(TelemetryFilter{})
	if err != nil {
		t.Fatalf("query — the table is probably gone: %v", err)
	}
	if len(rows) != 1 || rows[0].Message != nasty {
		t.Errorf("got %+v, want the string stored verbatim", rows)
	}
	if !strings.Contains(rows[0].Session, "DROP") {
		t.Errorf("session = %q, want it stored as given", rows[0].Session)
	}
}
