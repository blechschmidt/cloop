package statedb

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

// The requirements gate's setting (Task 20461) is stored on its own, survives
// a load, and a save from a copy that predates it does not switch it off.
func TestRequirementsGateSettingIsStoredOnItsOwn(t *testing.T) {
	db := openFresh(t)
	if err := db.SaveState(&State{Goal: "g"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveRequirementsGate(&pm.RequirementsGate{Mode: pm.RequirementsGateLinkedMust, Assess: true}); err != nil {
		t.Fatal(err)
	}
	// A run's save, from a copy loaded before the gate was set.
	if err := db.SaveState(&State{Goal: "g"}); err != nil {
		t.Fatal(err)
	}
	s, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if g := s.RequirementsGate; g == nil || g.Mode != pm.RequirementsGateLinkedMust || !g.Assess {
		t.Fatalf("gate = %+v", s.RequirementsGate)
	}
	if err := db.SaveRequirementsGate(&pm.RequirementsGate{Mode: "sometimes"}); err == nil {
		t.Error("an unknown mode was stored")
	}
	if err := db.SaveRequirementsGate(&pm.RequirementsGate{Mode: pm.RequirementsGateOff, Assess: true}); err != nil {
		t.Fatal(err)
	}
	if s, err = db.LoadState(); err != nil || s.RequirementsGate.Active() || !s.RequirementsGate.Assess {
		t.Fatalf("switched off: %+v, %v", s.RequirementsGate, err)
	}
}

func result(r requirements.Requirement, verdict string, at time.Time) requirements.Result {
	return requirements.Result{RequirementID: r.ID, Fingerprint: r.Fingerprint(), Method: requirements.MethodTests,
		Verdict: verdict, StartedAt: at}
}

// A check is tied to the task it gated; a requirement fulfilled at its
// previous check of the same definition and unfulfilled now is a regression,
// and one whose definition changed in between is not.
func TestRequirementChecksRecordTheTaskAndRegressions(t *testing.T) {
	db := openFresh(t)
	a := addReq(t, db, "kept", "true")
	b := addReq(t, db, "redefined", "true")
	c := addReq(t, db, "failing all along", "false")
	at := time.Now().Add(-time.Hour).UTC()
	if _, err := db.RecordRequirementChecks(CheckRecord{RunID: "before", Commit: "aaaa"},
		[]requirements.Result{
			result(a, requirements.VerdictFulfilled, at),
			result(b, requirements.VerdictFulfilled, at),
			result(c, requirements.VerdictUnfulfilled, at),
		}); err != nil {
		t.Fatal(err)
	}
	b.Tests = []requirements.Test{{Command: "test -f b"}}
	b, err := db.UpdateRequirement(b, "x")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := db.RecordRequirementChecks(CheckRecord{RunID: "gate1", Commit: "bbbb", TaskID: 7},
		[]requirements.Result{
			result(a, requirements.VerdictUnfulfilled, at.Add(time.Minute)),
			result(b, requirements.VerdictUnfulfilled, at.Add(time.Minute)),
			result(c, requirements.VerdictUnfulfilled, at.Add(time.Minute)),
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 3 {
		t.Fatalf("stored = %+v", stored)
	}
	byID := map[int]RequirementCheck{}
	for _, s := range stored {
		byID[s.RequirementID] = s
		if s.TaskID != 7 {
			t.Errorf("R-%d's check is not tied to the task: %+v", s.RequirementID, s)
		}
	}
	if g := byID[a.ID]; !g.Regression || g.Was == nil || g.Was.Verdict != requirements.VerdictFulfilled || g.Was.Commit != "aaaa" {
		t.Errorf("R-%d = %+v, want a regression from aaaa", a.ID, g)
	}
	if byID[b.ID].Regression {
		t.Error("a requirement whose definition changed was called a regression")
	}
	if byID[c.ID].Regression {
		t.Error("a requirement that never passed was called a regression")
	}

	// What was stored reads back the same.
	latest, err := db.LatestRequirementChecks()
	if err != nil {
		t.Fatal(err)
	}
	if l := latest[a.ID]; !l.Regression || l.TaskID != 7 || l.Was != nil {
		t.Errorf("latest R-%d = %+v", a.ID, l)
	}
	regs, err := db.RequirementRegressionsSince(at, 10)
	if err != nil || len(regs) != 1 || regs[0].RequirementID != a.ID || regs[0].TaskID != 7 || regs[0].Commit != "bbbb" {
		t.Fatalf("regressions = %+v, %v", regs, err)
	}
	if regs, err := db.RequirementRegressionsSince(time.Now().Add(time.Hour), 10); err != nil || len(regs) != 0 {
		t.Errorf("regressions in the future = %+v, %v", regs, err)
	}

	// A fulfilled check after the regression is not one, and the next failure
	// is measured against it.
	if _, err := db.RecordRequirementChecks(CheckRecord{RunID: "gate2", TaskID: 7},
		[]requirements.Result{result(a, requirements.VerdictFulfilled, at.Add(2*time.Minute))}); err != nil {
		t.Fatal(err)
	}
	again, err := db.RecordRequirementChecks(CheckRecord{RunID: "gate3", Commit: "cccc", TaskID: 8},
		[]requirements.Result{result(a, requirements.VerdictError, at.Add(3*time.Minute))})
	if err != nil || len(again) != 1 || again[0].Regression {
		t.Errorf("a check that could not run is not a regression: %+v, %v", again, err)
	}
}

// A regression persists through the retries of the task that caused it: the
// task's own failing checks are not the baseline, and each later failure is
// still a regression — reported as persisting, so the notifier tells it once.
// Another task's failure after it is not a regression of that task's.
func TestRegressionPersistsThroughTheTasksRetries(t *testing.T) {
	db := openFresh(t)
	a := addReq(t, db, "kept", "true")
	at := time.Now().Add(-time.Hour).UTC()
	record := func(task int, verdict string, n int) RequirementCheck {
		t.Helper()
		got, err := db.RecordRequirementChecks(CheckRecord{RunID: "r", TaskID: task, Commit: "c"},
			[]requirements.Result{result(a, verdict, at.Add(time.Duration(n)*time.Minute))})
		if err != nil || len(got) != 1 {
			t.Fatalf("record: %+v, %v", got, err)
		}
		return got[0]
	}
	record(0, requirements.VerdictFulfilled, 0)
	first := record(5, requirements.VerdictUnfulfilled, 1)
	record(5, requirements.VerdictError, 2)
	second := record(5, requirements.VerdictUnfulfilled, 3)
	if !first.Regression || first.Persisting || !second.Regression || !second.Persisting || second.Was == nil || second.Was.TaskID != 0 {
		t.Fatalf("first %+v, second %+v", first, second)
	}
	if other := record(6, requirements.VerdictUnfulfilled, 4); other.Regression {
		t.Errorf("another task's failure after task 5 broke it was called its regression: %+v", other)
	}
	regs, err := db.RequirementRegressionsSince(at, 10)
	if err != nil || len(regs) != 1 || regs[0].ID != first.ID {
		t.Fatalf("the notifier would see %+v, %v — want the first only", regs, err)
	}
	checks, err := db.RequirementChecks(a.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	persisting := 0
	for _, c := range checks {
		if c.Persisting {
			persisting++
		}
	}
	if persisting != 1 {
		t.Errorf("persisting regressions read back = %d, want 1", persisting)
	}
}

// A gate's run is recorded with its task.
func TestRequirementRunRecordsTheTask(t *testing.T) {
	db := openFresh(t)
	run := RequirementRun{RunID: "gate-run", State: RequirementRunDone, Source: "gate", StartedBy: "requirements-gate",
		RequirementIDs: []int{1, 2}, TaskID: 42, Counts: requirements.Counts{Fulfilled: 1, Unfulfilled: 1}}
	if err := db.RecordFinishedRequirementRun(run); err != nil {
		t.Fatal(err)
	}
	got, err := db.RequirementRunByID("gate-run")
	if err != nil || got.TaskID != 42 || got.Source != "gate" || got.Counts.Unfulfilled != 1 {
		t.Fatalf("run = %+v, %v", got, err)
	}
}

// A task's gate record survives the database, and one too large to be a
// record is not read at all.
func TestTaskRequirementsCheckColumn(t *testing.T) {
	rc := &pm.TaskRequirementsCheck{Mode: "linked", Outcome: pm.RequirementsUnmet, RunID: "r1", Commit: "abcd",
		Decision: "requeued", Consecutive: 1,
		Requirements: []pm.RequirementVerdict{{Result: requirements.Result{RequirementID: 3, Verdict: requirements.VerdictUnfulfilled,
			Method: requirements.MethodTests}, Blocking: true, Regression: true, Was: "fulfilled"}}}
	raw := encodeRequirementsCheck(rc)
	back := decodeRequirementsCheck(raw)
	if back == nil || back.RunID != "r1" || !back.Requirements[0].Regression || back.Requirements[0].RequirementID != 3 {
		t.Fatalf("round trip = %+v", back)
	}
	for _, bad := range []string{"", "null", "{", `{"mode":"linked"}`, `{"outcome":"met","requirements":[` + string(make([]byte, maxRequirementsCheckBytes)) + `]}`} {
		if got := decodeRequirementsCheck(bad); got != nil {
			t.Errorf("decodeRequirementsCheck(%.40q) = %+v, want nil", bad, got)
		}
	}
	if encodeRequirementsCheck(nil) != "" {
		t.Error("an absent record is not the empty string")
	}
}
