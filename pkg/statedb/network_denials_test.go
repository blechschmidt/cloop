package statedb

import (
	"fmt"
	"testing"
	"time"
)

var d0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func denialEntry(dst string, port int, rule string, n int64, at time.Time) DenialRow {
	return DenialRow{Dst: dst, Port: port, Proto: "tcp", Rule: rule, Why: "not in the project's allow list",
		Count: n, FirstSeen: at, LastSeen: at}
}

// TestRecordDenialsAccumulates: a destination is one row per run and task,
// its counts summed and its interval widened, and only its first report is
// new.
func TestRecordDenialsAccumulates(t *testing.T) {
	db := openTestDB(t)
	w := DenialWrite{RunID: "run-1", TaskID: 7, ExecutorID: "sgx", Fingerprint: "0123456789ab",
		Entries: []DenialRow{denialEntry("203.0.113.7", 443, "default", 3, d0)}}
	res, err := db.RecordDenials(w)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.New) != 1 || res.New[0].TaskID != 7 || res.New[0].RunID != "run-1" {
		t.Fatalf("first report: %+v", res)
	}
	w.Entries = []DenialRow{denialEntry("203.0.113.7", 443, "default", 11, d0.Add(time.Minute))}
	w.Entries[0].FirstSeen = d0.Add(-time.Second)
	if res, err = db.RecordDenials(w); err != nil || len(res.New) != 0 {
		t.Fatalf("second report: %+v, %v", res, err)
	}
	rows, err := db.RunDenials("run-1")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v, %v", rows, err)
	}
	r := rows[0]
	if r.Count != 14 || !r.FirstSeen.Equal(d0.Add(-time.Second)) || !r.LastSeen.Equal(d0.Add(time.Minute)) {
		t.Errorf("row = %+v", r)
	}
	if got := DenialDestination(r.Dst, r.Port, r.Proto); got != "203.0.113.7:443/tcp" {
		t.Errorf("destination %q", got)
	}
	// Under another task, the same destination is a row of its own.
	w.TaskID = 8
	if res, _ := db.RecordDenials(w); len(res.New) != 1 {
		t.Errorf("another task's first refusal was not new: %+v", res)
	}
}

// TestRecordDenialsCapsARun: past MaxDenialRowsPerRun a run's new
// destinations become its unitemised count, and every refusal is counted.
func TestRecordDenialsCapsARun(t *testing.T) {
	db := openTestDB(t)
	var sent int64
	for i := 0; i < MaxDenialRowsPerRun+40; i++ {
		e := denialEntry(fmt.Sprintf("198.51.100.%d", i%250), 1000+i, "default", 2, d0)
		sent += 2
		res, err := db.RecordDenials(DenialWrite{RunID: "spray", Entries: []DenialRow{e}, At: d0})
		if err != nil {
			t.Fatal(err)
		}
		if i == MaxDenialRowsPerRun && !res.FirstUnitemised {
			t.Errorf("the first destination past the cap did not start the unitemised row: %+v", res)
		}
	}
	if _, err := db.RecordDenials(DenialWrite{RunID: "spray", Unitemised: 5, At: d0}); err != nil {
		t.Fatal(err)
	}
	sent += 5
	rows, err := db.RunDenials("spray")
	if err != nil {
		t.Fatal(err)
	}
	var itemised, total int64
	for _, r := range rows {
		total += r.Count
		if r.Rule != DenialUnitemised {
			itemised++
		}
	}
	if itemised != MaxDenialRowsPerRun {
		t.Errorf("%d itemised rows, cap %d", itemised, MaxDenialRowsPerRun)
	}
	if total != sent {
		t.Errorf("counted %d refusals of %d", total, sent)
	}
	totals, err := db.RunDenialTotals("spray")
	if err != nil || len(totals) != 2 {
		t.Fatalf("totals = %+v, %v", totals, err)
	}
	for _, tt := range totals {
		if tt.Rule == "default" && (tt.Destinations != MaxDenialRowsPerRun || len(tt.Top) != 8) {
			t.Errorf("default total = %+v", tt)
		}
	}
}

// TestTaskDenialsMatchesByTaskOrWindow: a row filed under a task is the
// task's; one no task was named for is the task's when its run is the task's
// and its refusals fall while the task ran.
func TestTaskDenialsMatchesByTaskOrWindow(t *testing.T) {
	db := openTestDB(t)
	mk := func(task int, dst string, at time.Time) {
		if _, err := db.RecordDenials(DenialWrite{RunID: "r", TaskID: task,
			Entries: []DenialRow{denialEntry(dst, 443, "default", 1, at)}}); err != nil {
			t.Fatal(err)
		}
	}
	mk(3, "192.0.2.1", d0)                     // filed under task 3
	mk(0, "192.0.2.2", d0.Add(5*time.Minute))  // during task 3's window
	mk(0, "192.0.2.3", d0.Add(30*time.Minute)) // after it
	mk(4, "192.0.2.4", d0)                     // another task's
	if _, err := db.RecordDenials(DenialWrite{RunID: "r", Unitemised: 9, At: d0}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.TaskDenials(3, []string{"r"}, d0.Add(-time.Minute), d0.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[r.Dst+"|"+r.Rule] = true
	}
	for _, want := range []string{"192.0.2.1|default", "192.0.2.2|default", "|" + DenialUnitemised} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	for _, not := range []string{"192.0.2.3|default", "192.0.2.4|default"} {
		if got[not] {
			t.Errorf("%s is not task 3's", not)
		}
	}
}

// TestRecentDenialsSummarisesAcrossRuns: the firewall card's list is one line
// per destination and rule, across runs, newest first, the unitemised rows
// left out.
func TestRecentDenialsSummarisesAcrossRuns(t *testing.T) {
	db := openTestDB(t)
	for i, run := range []string{"a", "b"} {
		e := denialEntry("203.0.113.7", 443, "default", 2, d0.Add(time.Duration(i)*time.Hour))
		e.Why = fmt.Sprintf("why %d", i)
		if _, err := db.RecordDenials(DenialWrite{RunID: run, ExecutorID: "ex-" + run, Entries: []DenialRow{e}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.RecordDenials(DenialWrite{RunID: "a", Entries: []DenialRow{denialEntry("10.0.0.5", 5432,
		"block:10.0.0.0/8", 1, d0.Add(-time.Hour))}, Unitemised: 3, At: d0}); err != nil {
		t.Fatal(err)
	}
	sums, err := db.RecentDenials(d0.Add(-2*time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 2 {
		t.Fatalf("summaries = %+v", sums)
	}
	s := sums[0]
	if s.Dst != "203.0.113.7" || s.Count != 4 || s.Runs != 2 || s.Why != "why 1" || s.LastRunID != "b" || s.ExecutorID != "ex-b" {
		t.Errorf("first summary = %+v", s)
	}
	if sums[1].Rule != "block:10.0.0.0/8" {
		t.Errorf("second summary = %+v", sums[1])
	}
}

// TestDenialsTableIsBoundedByItsWriter: rows past the age bound go when a
// row is added.
func TestDenialsTableIsBoundedByItsWriter(t *testing.T) {
	db := openTestDB(t)
	old := time.Now().Add(-denialMaxAge - time.Hour)
	if _, err := db.RecordDenials(DenialWrite{RunID: "old", Entries: []DenialRow{denialEntry("192.0.2.9", 1, "default", 1, old)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordDenials(DenialWrite{RunID: "new", Entries: []DenialRow{denialEntry("192.0.2.8", 1, "default", 1, time.Now())}}); err != nil {
		t.Fatal(err)
	}
	if rows, _ := db.RunDenials("old"); len(rows) != 0 {
		t.Errorf("a row past the age bound survived: %+v", rows)
	}
	if rows, _ := db.RunDenials("new"); len(rows) != 1 {
		t.Errorf("the new row went too: %+v", rows)
	}
	if _, err := db.RecordDenials(DenialWrite{}); err == nil {
		t.Error("a report without a run id was recorded")
	}
}

// TestEgressRefusalsReadsTheTrail: the proxy's denied requests of a run, from
// its audit rows.
func TestEgressRefusalsReadsTheTrail(t *testing.T) {
	db := openTestDB(t)
	for _, ev := range []*AuditEvent{
		{EventType: "egress.connect", EntityType: "secret", Payload: `{"decision":"deny","run_id":"r1","host":"evil.example","port":443,"reason":"host not allowed"}`},
		{EventType: "egress.connect", EntityType: "secret", Payload: `{"decision":"allow","run_id":"r1","host":"ok.example","port":443}`},
		{EventType: "egress.request", EntityType: "secret", Payload: `{"decision":"deny","run_id":"r2","host":"other.example","port":80}`},
	} {
		if err := db.AppendAuditEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.EgressRefusals([]string{"r1"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host != "evil.example" || got[0].Port != 443 || got[0].Reason != "host not allowed" {
		t.Errorf("refusals = %+v", got)
	}
}
