package statedb

// Tests for the journal feed (Task 20384): the order a step and an event
// sharing a timestamp take, that every way of paging — places down, cursors up,
// positions — returns each row exactly once in one order, and that a page is a
// seek on the index rather than a scan of the journal.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// journal is a test's handle on a fresh database's steps and events.
type journal struct {
	t    *testing.T
	db   *DB
	step int
	// rows is every row written, for the order the feed must have.
	rows []written
}

type written struct {
	name  string
	at    time.Time
	event bool
	key   int64
}

func newJournal(t *testing.T) *journal {
	t.Helper()
	return &journal{t: t, db: openFresh(t)}
}

// addStep records the next step, finished at at. It returns the row's name.
func (j *journal) addStep(at time.Time, output string) string {
	j.t.Helper()
	n := j.step
	j.step++
	if err := j.db.AppendStep(StepRow{Step: n, Task: fmt.Sprintf("Task %d", n), Output: output, Duration: "1s", Time: at}); err != nil {
		j.t.Fatalf("AppendStep %d: %v", n, err)
	}
	name := fmt.Sprintf("s%d", n)
	j.rows = append(j.rows, written{name: name, at: at, key: int64(n)})
	return name
}

// addEvent records an event that happened at at. It returns the row's name.
func (j *journal) addEvent(at time.Time, details string) string {
	j.t.Helper()
	if err := j.db.RecordEvent(EventRow{Timestamp: at, Type: EventTaskDone, TaskID: 1, Step: NoStep, Message: "done", Details: details}); err != nil {
		j.t.Fatalf("RecordEvent: %v", err)
	}
	var id int64
	if err := j.db.conn.QueryRow(`SELECT MAX(id) FROM events`).Scan(&id); err != nil {
		j.t.Fatal(err)
	}
	name := fmt.Sprintf("e%d", id)
	j.rows = append(j.rows, written{name: name, at: at, event: true, key: id})
	return name
}

// wantOrder is the feed's order worked out from what was written, the way
// the description in history.go puts it rather than the way the code does:
// newest instant first (to the millisecond), an event above a step at the same
// instant, and within one table the later-written first. An unreadable or zero
// time is the oldest there is.
func (j *journal) wantOrder() []string {
	rows := append([]written(nil), j.rows...)
	ms := func(w written) int64 {
		if w.at.IsZero() {
			return -1 << 62
		}
		// julianday() rounds to the nearest millisecond.
		return (w.at.UnixNano() + 500_000) / 1_000_000
	}
	sort.Slice(rows, func(a, b int) bool {
		x, y := rows[a], rows[b]
		if ms(x) != ms(y) {
			return ms(x) > ms(y)
		}
		if x.event != y.event {
			return x.event
		}
		return x.key > y.key
	})
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.name
	}
	return out
}

func (j *journal) read(q HistoryQuery) HistoryPage {
	j.t.Helper()
	page, err := j.db.History(q)
	if err != nil {
		j.t.Fatalf("History(%+v): %v", q, err)
	}
	return page
}

func names(rows []HistoryRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Step != nil {
			out = append(out, fmt.Sprintf("s%d", r.Step.Step))
		} else {
			out = append(out, fmt.Sprintf("e%d", r.Event.ID))
		}
	}
	return out
}

// walkDown reads the whole feed a page of n at a time, following Bottom.
func (j *journal) walkDown(n int) []string {
	j.t.Helper()
	page := j.read(HistoryQuery{Limit: n})
	got := names(page.Rows)
	for guard := 0; page.More; guard++ {
		if guard > 1000 {
			j.t.Fatalf("paging by %d never ended; read %v", n, got)
		}
		bottom := page.Bottom
		page = j.read(HistoryQuery{Before: bottom, Limit: n})
		if len(page.Rows) == 0 {
			j.t.Fatalf("a page below %+v said there was more and returned nothing", *bottom)
		}
		got = append(got, names(page.Rows)...)
	}
	return got
}

// walkOffsets reads the whole feed by position, n at a time.
func (j *journal) walkOffsets(n int) []string {
	j.t.Helper()
	var got []string
	for off := 0; ; off += n {
		page := j.read(HistoryQuery{Offset: off, Limit: n})
		got = append(got, names(page.Rows)...)
		if !page.More {
			return got
		}
	}
}

// TestHistory_ATieListsTheEventAboveTheStep pins the one ordering rule that is
// not a timestamp comparison: a step and an event recorded at the same instant
// list the event first, the order in which the orchestrator writes them, and
// a page boundary falling between the two neither drops nor repeats either.
func TestHistory_ATieListsTheEventAboveTheStep(t *testing.T) {
	j := newJournal(t)
	at := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	older := j.addStep(at.Add(-time.Minute), "older")
	step := j.addStep(at, "the step")
	event := j.addEvent(at, "")
	newer := j.addEvent(at.Add(time.Minute), "")

	want := []string{newer, event, step, older}
	if got := names(j.read(HistoryQuery{Limit: 10}).Rows); !equalNames(got, want) {
		t.Fatalf("newest page = %v, want %v", got, want)
	}
	// The event was written after the step here; written before it, the tie
	// still goes the same way, so the rule does not depend on write order.
	j2 := newJournal(t)
	event2 := j2.addEvent(at, "")
	step2 := j2.addStep(at, "the step")
	if got := names(j2.read(HistoryQuery{Limit: 10}).Rows); !equalNames(got, []string{event2, step2}) {
		t.Fatalf("event written first: newest page = %v, want %v", got, []string{event2, step2})
	}

	for n := 1; n <= len(want); n++ {
		if got := j.walkDown(n); !equalNames(got, want) {
			t.Errorf("paging down %d at a time read %v, want %v", n, got, want)
		}
		if got := j.walkOffsets(n); !equalNames(got, want) {
			t.Errorf("paging by offset %d at a time read %v, want %v", n, got, want)
		}
	}

	// The boundary exactly between the tied pair: one row above it, the
	// other below.
	first := j.read(HistoryQuery{Limit: 2})
	if got := names(first.Rows); !equalNames(got, []string{newer, event}) {
		t.Fatalf("first two = %v", got)
	}
	if got := names(j.read(HistoryQuery{Before: first.Bottom, Limit: 1}).Rows); !equalNames(got, []string{step}) {
		t.Fatalf("the row below the tied event = %v, want [%s]", got, step)
	}
	// And between two rows of one table at one instant.
	j3 := newJournal(t)
	a, b := j3.addEvent(at, ""), j3.addEvent(at, "")
	one := j3.read(HistoryQuery{Limit: 1})
	if got := names(one.Rows); !equalNames(got, []string{b}) {
		t.Fatalf("two events at one instant: first = %v, want the later-written %s", got, b)
	}
	if got := names(j3.read(HistoryQuery{Before: one.Bottom, Limit: 5}).Rows); !equalNames(got, []string{a}) {
		t.Fatalf("below the later-written event = %v, want [%s]", got, a)
	}
}

// TestHistory_EveryPagingReadsTheFeedOnce builds a journal that interleaves
// the tables irregularly — runs of one table, ties within and across tables,
// rows a millisecond apart, a step whose time was never recorded, events in
// another UTC offset, and rows written late with older timestamps the way a
// remote run's come back — and walks it at every page size, by place and by
// position. Each walk must read exactly the feed's order: nothing twice,
// nothing skipped.
func TestHistory_EveryPagingReadsTheFeedOnce(t *testing.T) {
	j := newJournal(t)
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	berlin := time.FixedZone("CEST", 2*60*60)
	j.addStep(time.Time{}, "a step from before times were recorded")
	for i := 0; i < 12; i++ {
		when := at.Add(time.Duration(i) * time.Minute)
		j.addEvent(when, "")
		if i%3 == 0 {
			j.addEvent(when, "") // two events at one instant
		}
		if i%2 == 0 {
			j.addStep(when, "") // a step at the event's instant
		}
		if i%4 == 1 {
			// Written by a process two hours east of UTC, as RecordEvent
			// stores it: in its own offset.
			j.addEvent(when.Add(15*time.Second).In(berlin), "")
		}
		if i%5 == 4 {
			j.addStep(when.Add(30*time.Second), "")
			j.addStep(when.Add(30*time.Second+300*time.Microsecond), "") // the same millisecond
		}
	}
	// Written last, timestamped earlier: a remote run's rows coming home.
	j.addEvent(at.Add(-time.Hour), "")
	j.addStep(at.Add(5*time.Minute+10*time.Second), "")
	j.addEvent(at.Add(5*time.Minute+10*time.Second), "")

	want := j.wantOrder()
	if got := names(j.read(HistoryQuery{Limit: 500}).Rows); !equalNames(got, want) {
		t.Fatalf("the newest page of everything is\n  %v\nwant\n  %v", got, want)
	}
	for n := 1; n <= len(want)+1; n++ {
		if got := j.walkDown(n); !equalNames(got, want) {
			t.Fatalf("paging down %d at a time read\n  %v\nwant\n  %v", n, got, want)
		}
		if got := j.walkOffsets(n); !equalNames(got, want) {
			t.Fatalf("paging by offset %d at a time read\n  %v\nwant\n  %v", n, got, want)
		}
	}
}

// TestHistory_AfterReturnsWhatWasWrittenSinceTheTop is the live half: what is
// written after a page was read is exactly what a read past its Top returns —
// including a row timestamped earlier than rows already shown, which a cursor
// made of timestamps would have left behind.
func TestHistory_AfterReturnsWhatWasWrittenSinceTheTop(t *testing.T) {
	j := newJournal(t)
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	j.addStep(at, "")
	j.addEvent(at.Add(time.Second), "")
	first := j.read(HistoryQuery{Limit: 50})
	if first.Top != (HistoryCursor{Step: 0, Event: 1}) {
		t.Fatalf("Top = %+v, want {0 1}", first.Top)
	}

	s1 := j.addStep(at.Add(time.Minute), "")
	e2 := j.addEvent(at.Add(2*time.Minute), "")
	lateEvent := j.addEvent(at.Add(-time.Hour), "")

	top := first.Top
	next := j.read(HistoryQuery{After: &top, Limit: 50})
	if next.Gap {
		t.Fatal("three new rows under a limit of 50 read as a gap")
	}
	// In feed order: the late event, timestamped an hour before the rows
	// already read, is new all the same — and lists last.
	if got := names(next.Rows); !equalNames(got, []string{e2, s1, lateEvent}) {
		t.Fatalf("after %+v = %v, want [%s %s %s]", top, got, e2, s1, lateEvent)
	}
	if next.Top != (HistoryCursor{Step: 1, Event: 3}) {
		t.Fatalf("Top after the read = %+v, want {1 3}", next.Top)
	}
	again := next.Top
	if rows := j.read(HistoryQuery{After: &again, Limit: 50}).Rows; len(rows) != 0 {
		t.Fatalf("nothing was written, yet a read past the new top returned %v", names(rows))
	}
}

// TestHistory_AfterMoreThanTheLimitIsAGap: past the limit the read cannot
// continue the caller's list, so it says so and hands back the newest page.
func TestHistory_AfterMoreThanTheLimitIsAGap(t *testing.T) {
	j := newJournal(t)
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	j.addStep(at, "")
	top := j.read(HistoryQuery{Limit: 50}).Top
	for i := 1; i <= 4; i++ {
		j.addEvent(at.Add(time.Duration(i)*time.Second), "")
	}
	page := j.read(HistoryQuery{After: &top, Limit: 3})
	if !page.Gap {
		t.Fatal("four new rows under a limit of 3 did not read as a gap")
	}
	if got, want := names(page.Rows), names(j.read(HistoryQuery{Limit: 3}).Rows); !equalNames(got, want) {
		t.Fatalf("a gap's rows = %v, want the newest page %v", got, want)
	}
	if !page.More || page.Top != (HistoryCursor{Step: 0, Event: 4}) {
		t.Fatalf("a gap's page: More=%v Top=%+v, want true {0 4}", page.More, page.Top)
	}
}

// TestHistory_ACursorAboveTheJournalStartsOver: the database was replaced and
// its numbering restarted, so the rows written since are numbered below the
// cursor a client holds. Reading past that cursor would never return them.
func TestHistory_ACursorAboveTheJournalStartsOver(t *testing.T) {
	j := newJournal(t)
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	s := j.addStep(at, "")
	stale := HistoryCursor{Step: 900, Event: 0}
	page := j.read(HistoryQuery{After: &stale, Limit: 50})
	if !page.Gap || !equalNames(names(page.Rows), []string{s}) {
		t.Fatalf("after a cursor above the journal: Gap=%v rows=%v, want a gap and [%s]", page.Gap, names(page.Rows), s)
	}
}

// TestHistory_EmptyJournal: a project that never ran has a top that the first
// rows it records are above.
func TestHistory_EmptyJournal(t *testing.T) {
	j := newJournal(t)
	page := j.read(HistoryQuery{Limit: 50})
	if len(page.Rows) != 0 || page.More || page.Bottom != nil || page.Top != (HistoryCursor{Step: -1, Event: 0}) {
		t.Fatalf("empty journal: rows=%v More=%v Bottom=%v Top=%+v", names(page.Rows), page.More, page.Bottom, page.Top)
	}
	s := j.addStep(time.Now(), "")
	e := j.addEvent(time.Now(), "")
	top := page.Top
	if got := names(j.read(HistoryQuery{After: &top, Limit: 50}).Rows); !containsAll(got, s, e) || len(got) != 2 {
		t.Fatalf("the first rows after an empty top = %v, want %s and %s", got, s, e)
	}
}

// TestHistory_LongValuesAreCutAndAvailableWhole bounds what a page carries: a
// long step output is cut on a character boundary and a long details blob is
// left out rather than cut mid-document, each with its full length; the
// single-row reads return them whole.
func TestHistory_LongValuesAreCutAndAvailableWhole(t *testing.T) {
	j := newJournal(t)
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	output := strings.Repeat("é", 100) // two bytes each
	j.addStep(at, output)
	details := `{"note":"` + strings.Repeat("x", 300) + `"}`
	j.addEvent(at.Add(time.Second), details)
	j.addEvent(at.Add(2*time.Second), `{"short":true}`)

	page := j.read(HistoryQuery{Limit: 50, MaxValue: 101})
	if len(page.Rows) != 3 {
		t.Fatalf("rows = %v", names(page.Rows))
	}
	short, long, step := page.Rows[0], page.Rows[1], page.Rows[2]
	if short.Cut != 0 || short.Event.Details != `{"short":true}` {
		t.Errorf("a short details blob was touched: cut=%d %q", short.Cut, short.Event.Details)
	}
	if long.Cut != len(details) || long.Event.Details != "" {
		t.Errorf("long details: cut=%d details=%q, want cut=%d and none", long.Cut, long.Event.Details, len(details))
	}
	if step.Cut != len(output) || len(step.Step.Output) != 100 || !utf8.ValidString(step.Step.Output) {
		t.Errorf("long output: cut=%d len=%d valid=%v, want cut=%d, 100 bytes, valid UTF-8",
			step.Cut, len(step.Step.Output), utf8.ValidString(step.Step.Output), len(output))
	}

	whole, err := j.db.HistoryStep(0)
	if err != nil || whole == nil || whole.Output != output {
		t.Fatalf("HistoryStep(0) = %v, %v; want the whole output", whole, err)
	}
	ev, err := j.db.HistoryEvent(long.Event.ID)
	if err != nil || ev == nil || ev.Details != details {
		t.Fatalf("HistoryEvent = %v, %v; want the whole details", ev, err)
	}
	if missing, err := j.db.HistoryStep(99); err != nil || missing != nil {
		t.Fatalf("HistoryStep(99) = %v, %v; want nothing", missing, err)
	}
}

// TestHistory_RejectsContradictoryQueries: a read is one direction.
func TestHistory_RejectsContradictoryQueries(t *testing.T) {
	j := newJournal(t)
	c, p := HistoryCursor{}, HistoryPlace{}
	for _, q := range []HistoryQuery{
		{Limit: 0},
		{Limit: 5, Before: &p, After: &c},
		{Limit: 5, Offset: 3, After: &c},
		{Limit: 5, Offset: 3, Before: &p},
		{Limit: 5, Offset: -1},
	} {
		if _, err := j.db.History(q); err == nil {
			t.Errorf("History(%+v) was accepted", q)
		}
	}
}

func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsAll(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// TestHistory_PagesSeekTheIndex holds a page to what makes its cost
// independent of the journal's length: SQLite seeks migration 0059's index and
// reads the order off it, with no scan from the top and no sort.
func TestHistory_PagesSeekTheIndex(t *testing.T) {
	db := openFresh(t)
	plan := func(query string, args ...any) string {
		t.Helper()
		rows, err := db.conn.Query(`EXPLAIN QUERY PLAN `+query, args...)
		if err != nil {
			t.Fatalf("explain %s: %v", query, err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatal(err)
			}
			out = append(out, detail)
		}
		return strings.Join(out, "; ")
	}
	for _, bounded := range []bool{false, true} {
		stepTail, eventTail := historyBelowTails(bounded)
		args := []any{}
		if bounded {
			args = []any{2461318.5, 7}
		}
		for table, q := range map[string]string{
			"steps":  stepColumns + stepTail + " LIMIT 51",
			"events": eventColumns + eventTail + " LIMIT 51",
		} {
			got := plan(q, args...)
			index := table + "_history_order"
			want := "SCAN " + table + " USING INDEX " + index
			if bounded {
				want = "SEARCH " + table + " USING INDEX " + index + " (<expr><?)"
			}
			if got != want {
				t.Errorf("%s page (bounded=%v) plan = %q, want %q", table, bounded, got, want)
			}
		}
	}
}
