package statedb

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// One writer per checkpoint window (Task 20404): a window is written once,
// a leader change resumes from the marker rather than skipping or repeating a
// window, and a claim its holder never finished is taken over once stale.
func TestAuditCheckpointWindowClaims(t *testing.T) {
	d := openFresh(t)
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	const stale = time.Minute

	claim := func(w int64, member string, at time.Time) AuditCheckpointClaim {
		t.Helper()
		c, err := d.ClaimAuditCheckpointWindow(w, 5*time.Minute, member, at, stale)
		if err != nil {
			t.Fatalf("claim %d by %s: %v", w, member, err)
		}
		return c
	}
	complete := func(w int64, member string) bool {
		t.Helper()
		ok, err := d.CompleteAuditCheckpointWindow(w, member)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	if c := claim(100, "a", t0); !c.Claimed {
		t.Fatal("the first claim of a window was refused")
	}
	// Another member during a's fresh claim waits, and is told when to look.
	c := claim(100, "b", t0.Add(10*time.Second))
	if c.Claimed || c.HeldBy != "a" || !c.RetryAt.Equal(t0.Add(stale)) {
		t.Fatalf("b claimed a's fresh window, or was not told to retry at %s: %+v", t0.Add(stale), c)
	}
	// a retrying its own window gets it back.
	if c := claim(100, "a", t0.Add(20*time.Second)); !c.Claimed {
		t.Fatal("a could not resume its own claim")
	}
	if !complete(100, "a") {
		t.Fatal("a could not complete the window it holds")
	}
	// A new leader in the same window does not write it again.
	if c := claim(100, "b", t0.Add(2*time.Minute)); c.Claimed {
		t.Fatal("a completed window was claimed again: it would be written twice")
	}
	// It writes the next one.
	if c := claim(101, "b", t0.Add(5*time.Minute)); !c.Claimed {
		t.Fatal("the next window was refused")
	}
	// b dies before writing it; a, elected, waits out the claim and takes over.
	if c := claim(101, "a", t0.Add(5*time.Minute+30*time.Second)); c.Claimed {
		t.Fatal("a took over b's claim before it went stale")
	}
	if c := claim(101, "a", t0.Add(6*time.Minute+time.Second)); !c.Claimed || c.Window != 101 {
		t.Fatalf("a stale claim was not taken over: the window would be skipped (%+v)", c)
	}
	if complete(101, "b") {
		t.Error("b completed a window that was taken over from it")
	}
	if !complete(101, "a") {
		t.Fatal("a could not complete the window it took over")
	}

	// A member that dies in a window's last seconds: its claim goes stale
	// only in the next window. The next leader writes the abandoned window
	// late, then the current one — none is skipped.
	if c := claim(102, "b", t0.Add(14*time.Minute+50*time.Second)); !c.Claimed {
		t.Fatal("claim 102")
	}
	c = claim(103, "a", t0.Add(15*time.Minute+10*time.Second))
	if c.Claimed || c.HeldBy != "b" {
		t.Fatalf("a fresh claim on the previous window was ignored: %+v", c)
	}
	c = claim(103, "a", t0.Add(15*time.Minute+51*time.Second))
	if !c.Claimed || c.Window != 102 {
		t.Fatalf("the abandoned window was not taken over late: %+v", c)
	}
	if !complete(102, "a") {
		t.Fatal("complete 102")
	}
	if c := claim(103, "a", t0.Add(15*time.Minute+52*time.Second)); !c.Claimed || c.Window != 103 {
		t.Fatalf("after the late window, the current one: %+v", c)
	}
	if !complete(103, "a") {
		t.Fatal("complete 103")
	}
	if c, err := d.ClaimAuditCheckpointWindow(103*5/15, 15*time.Minute, "a", t0.Add(16*time.Minute), stale); err != nil ||
		!c.Claimed || c.FutureMarker {
		t.Errorf("an interval change read as a marker from the future, or was refused: %+v %v", c, err)
	}
	if c := claim(103, "a", t0.Add(16*time.Minute+30*time.Second)); !c.Claimed {
		t.Errorf("changing the interval back was refused: %+v", c)
	}
	if !complete(103, "a") {
		t.Fatal("complete 103 again")
	}

	// A member one window ahead has already written; a lagging clock defers.
	if c := claim(105, "c", t0.Add(25*time.Minute)); !c.Claimed {
		t.Fatal("claim 105")
	}
	if !complete(105, "c") {
		t.Fatal("complete 105")
	}
	if c := claim(104, "a", t0.Add(25*time.Minute)); c.Claimed {
		t.Error("a window behind the marker was claimed")
	}
	// A marker far in the future cannot be right, and is replaced rather
	// than obeyed — obeying it would stop checkpoints.
	if c := claim(1_000_000, "x", t0.Add(26*time.Minute)); !c.Claimed {
		t.Fatal("claim far ahead")
	}
	c = claim(106, "a", t0.Add(30*time.Minute))
	if !c.Claimed || !c.FutureMarker {
		t.Errorf("a marker from the future was obeyed: %+v", c)
	}
	m, ok, err := d.AuditCheckpointWindowMarker()
	if err != nil || !ok || m.Window != 106 || m.Member != "a" || m.Done || m.IntervalS != 300 {
		t.Errorf("marker = %+v (%v, %v)", m, ok, err)
	}
}

func TestAuditHeadAndRowAt(t *testing.T) {
	d := openFresh(t)
	h, err := d.AuditHead()
	if err != nil {
		t.Fatal(err)
	}
	if h.LastID != 0 || h.Rows != 0 || h.Anchor != nil {
		t.Fatalf("empty chain head = %+v", h)
	}
	for i := 0; i < 3; i++ {
		if err := d.AppendAuditEvent(testEvent(auditaction.ActionTaskUpsert)); err != nil {
			t.Fatal(err)
		}
	}
	h, err = d.AuditHead()
	if err != nil {
		t.Fatal(err)
	}
	row, found, err := d.AuditRowAt(3)
	if err != nil || !found {
		t.Fatalf("row 3: %v %v", found, err)
	}
	if h.LastID != 3 || h.FirstID != 1 || h.Rows != 3 || h.LastRowHash != row.RowHash || h.LastTimestamp.IsZero() {
		t.Errorf("head = %+v, want id 3 hashing %s", h, row.RowHash)
	}
	if _, found, _ := d.AuditRowAt(4); found {
		t.Error("row 4 exists")
	}
}
