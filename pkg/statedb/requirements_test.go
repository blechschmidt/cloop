package statedb

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

func addReq(t *testing.T, db *DB, title string, tests ...string) requirements.Requirement {
	t.Helper()
	r := requirements.Requirement{Title: title}
	for _, c := range tests {
		r.Tests = append(r.Tests, requirements.Test{Command: c})
	}
	got, err := db.AddRequirement(r, "alice")
	if err != nil {
		t.Fatalf("AddRequirement(%q): %v", title, err)
	}
	return got
}

func auditCount(t *testing.T, db *DB, action auditaction.Action) int {
	t.Helper()
	rows, _, err := db.ListAuditEvents(AuditFilter{EventType: string(action)})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func TestRequirementsRoundTripAndNeverReuseAnID(t *testing.T) {
	db := openFresh(t)
	a := addReq(t, db, "first", "go test ./a")
	b := addReq(t, db, "second")
	if a.ID != 1 || b.ID != 2 || a.CreatedBy != "alice" || a.CreatedAt.IsZero() {
		t.Fatalf("added %+v and %+v", a, b)
	}
	if _, err := db.DeleteRequirement(b.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	// R-2 named one requirement; a new one must not inherit its verdicts,
	// audit rows or the tasks that name it.
	if c := addReq(t, db, "third"); c.ID != 3 {
		t.Fatalf("the requirement added after R-2 was deleted got id %d", c.ID)
	}
	if _, err := db.Requirement(b.ID); !errors.Is(err, ErrRequirementNotFound) {
		t.Fatalf("a deleted requirement reads %v", err)
	}

	a.Description, a.Priority, a.Tags = "in detail", requirements.PriorityMust, []string{"Core"}
	up, err := db.UpdateRequirement(a, "carol")
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.Requirement(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Description != "in detail" || got.Priority != "must" || strings.Join(got.Tags, ",") != "core" ||
		got.CreatedBy != "alice" || got.UpdatedBy != "carol" || len(got.Tests) != 1 || up.UpdatedBy != "carol" {
		t.Fatalf("after the update: %+v", got)
	}
	if _, err := db.UpdateRequirement(requirements.Requirement{ID: 99, Title: "x"}, "c"); !errors.Is(err, ErrRequirementNotFound) {
		t.Errorf("updating a missing requirement: %v", err)
	}
	if _, err := db.AddRequirement(requirements.Requirement{Title: ""}, "c"); !errors.Is(err, requirements.ErrInvalid) {
		t.Errorf("adding an invalid requirement: %v", err)
	}
	all, err := db.Requirements()
	if err != nil || len(all) != 2 || all[0].ID != 1 || all[1].ID != 3 {
		t.Fatalf("Requirements = %+v, %v", all, err)
	}
	for action, want := range map[auditaction.Action]int{
		auditaction.ActionRequirementCreate: 3, auditaction.ActionRequirementUpdate: 1, auditaction.ActionRequirementDelete: 1,
	} {
		if n := auditCount(t, db, action); n != want {
			t.Errorf("%d %s rows, want %d", n, action, want)
		}
	}
	// A save that changes nothing records no update.
	if _, err := db.UpdateRequirement(got, "carol"); err != nil {
		t.Fatal(err)
	}
	if n := auditCount(t, db, auditaction.ActionRequirementUpdate); n != 1 {
		t.Errorf("an unchanged save was audited: %d update rows", n)
	}
}

func TestRequirementChecksRecordOnlyWhatStillApplies(t *testing.T) {
	db := openFresh(t)
	a := addReq(t, db, "tested", "true")
	b := addReq(t, db, "edited meanwhile", "true")
	c := addReq(t, db, "deleted meanwhile")
	fpB := b.Fingerprint()
	b.Tests = []requirements.Test{{Command: "false"}}
	if _, err := db.UpdateRequirement(b, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DeleteRequirement(c.ID, "x"); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Minute).UTC()
	stored, err := db.RecordRequirementChecks(CheckRecord{RunID: "run1", Commit: "abc123", Dirty: true, ExecutorID: "local", CheckedBy: "alice"},
		[]requirements.Result{
			{RequirementID: a.ID, Fingerprint: a.Fingerprint(), Method: requirements.MethodTests, Verdict: requirements.VerdictFulfilled,
				Summary: "1 test passed", StartedAt: at, Tests: []requirements.TestResult{{Command: "true", Outcome: requirements.OutcomePass, Output: "ok"}}},
			{RequirementID: b.ID, Fingerprint: fpB, Method: requirements.MethodTests, Verdict: requirements.VerdictFulfilled},
			{RequirementID: c.ID, Method: requirements.MethodNone, Verdict: requirements.VerdictUnverified},
			{RequirementID: a.ID, Method: requirements.MethodTests, Verdict: "great"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].RequirementID != a.ID {
		t.Fatalf("stored %+v: only R-1's result still applies", stored)
	}
	latest, err := db.LatestRequirementChecks()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := latest[a.ID]
	if !ok || len(latest) != 1 || got.Commit != "abc123" || !got.Dirty || got.ExecutorID != "local" || got.CheckedBy != "alice" ||
		!got.CheckedAt.Equal(at.Truncate(time.Microsecond)) || got.Tests[0].Output != "ok" || got.RunID != "run1" {
		t.Fatalf("latest = %+v", latest)
	}

	// A person's verdict is recorded against the requirement as it reads now.
	v, err := db.RecordRequirementVerdict(b.ID, requirements.VerdictUnfulfilled, "seen on staging", "bob")
	if err != nil || v.Method != requirements.MethodManual || v.Summary != "seen on staging" {
		t.Fatalf("RecordRequirementVerdict = %+v, %v", v, err)
	}
	if _, err := db.RecordRequirementVerdict(b.ID, "maybe", "", "bob"); !errors.Is(err, requirements.ErrInvalid) {
		t.Errorf("a verdict of maybe: %v", err)
	}
	if n := auditCount(t, db, auditaction.ActionRequirementVerdict); n != 1 {
		t.Errorf("%d verdict audit rows", n)
	}
	gone, err := db.DeleteRequirement(a.ID, "x")
	if err != nil || gone.ID != a.ID {
		t.Fatal(err)
	}
	if checks, _ := db.RequirementChecks(a.ID, 10); len(checks) != 0 {
		t.Errorf("a deleted requirement kept %d checks", len(checks))
	}
}

func TestRequirementChecksAreBounded(t *testing.T) {
	db := openFresh(t)
	a := addReq(t, db, "t", "true")
	for i := 0; i < requirementChecksKept+15; i++ {
		if _, err := db.RecordRequirementChecks(CheckRecord{RunID: fmt.Sprint("run", i)}, []requirements.Result{{
			RequirementID: a.ID, Fingerprint: a.Fingerprint(), Method: requirements.MethodTests, Verdict: requirements.VerdictFulfilled,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	checks, err := db.RequirementChecks(a.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM requirement_checks`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != requirementChecksKept || len(checks) != requirementChecksKept || checks[0].RunID != fmt.Sprint("run", requirementChecksKept+14) {
		t.Fatalf("%d rows kept, newest %q", n, checks[0].RunID)
	}

	// An output too large for a row is dropped, the verdict kept.
	huge := strings.Repeat("x", requirements.MaxOutputBytes)
	var tests []requirements.TestResult
	for i := 0; i < requirements.MaxTests; i++ {
		tests = append(tests, requirements.TestResult{Command: "c", Outcome: requirements.OutcomeFail, ExitCode: 1, Output: huge + strings.Repeat("é", 20000)})
	}
	res := []requirements.Result{{RequirementID: a.ID, Fingerprint: a.Fingerprint(), Method: requirements.MethodTests,
		Verdict: requirements.VerdictUnfulfilled, Tests: tests}}
	stored, err := db.RecordRequirementChecks(CheckRecord{RunID: "big"}, res)
	if err != nil || len(stored) != 1 || stored[0].Tests[0].Output != "" || !stored[0].Tests[0].Truncated {
		t.Fatalf("an oversized check stored as %v, %v", len(stored), err)
	}
	if res[0].Tests[0].Output == "" {
		t.Error("recording emptied the caller's own results")
	}
}

// TestOneRequirementsCheckAtATime: a run is the project's, whichever member
// asks — and a run whose member died stops blocking at its deadline.
func TestOneRequirementsCheckAtATime(t *testing.T) {
	db := openFresh(t)
	other, err := Open(db.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })

	first, err := db.StartRequirementRun(RequirementRun{RunID: "run-a", Source: "dashboard", StartedBy: "alice",
		Deadline: time.Now().Add(time.Hour), RequirementIDs: []int{1, 2}})
	if err != nil || first.State != RequirementRunRunning {
		t.Fatalf("first run: %+v, %v", first, err)
	}
	busy, err := other.StartRequirementRun(RequirementRun{RunID: "run-b", Deadline: time.Now().Add(time.Hour)})
	if !errors.Is(err, ErrRequirementCheckRunning) || busy.RunID != "run-a" || busy.StartedBy != "alice" {
		t.Fatalf("a second run through another handle: %+v, %v", busy, err)
	}
	if active, found, err := other.ActiveRequirementRun(); err != nil || !found || active.RunID != "run-a" {
		t.Fatalf("ActiveRequirementRun = %+v %v %v", active, found, err)
	}

	asked, err := other.RequestRequirementRunCancel("run-a")
	if err != nil || !asked {
		t.Fatalf("cancel: %v %v", asked, err)
	}
	if yes, err := db.TouchRequirementRun("run-a"); err != nil || !yes {
		t.Fatalf("the running member did not see the cancel: %v %v", yes, err)
	}
	ended, err := db.FinishRequirementRun("run-a", RequirementRunCancelled, requirements.Counts{Fulfilled: 1}, "local", "cancelled")
	if err != nil || !ended {
		t.Fatalf("finish: %v %v", ended, err)
	}
	if again, _ := db.FinishRequirementRun("run-a", RequirementRunDone, requirements.Counts{}, "", ""); again {
		t.Error("a run ended twice")
	}
	if asked, _ := other.RequestRequirementRunCancel("run-a"); asked {
		t.Error("an ended run took a cancel")
	}
	run, err := db.RequirementRunByID("run-a")
	if err != nil || run.State != RequirementRunCancelled || run.Counts.Fulfilled != 1 || run.FinishedAt.IsZero() ||
		len(run.RequirementIDs) != 2 || run.Error != "cancelled" {
		t.Fatalf("the ended run reads %+v, %v", run, err)
	}

	// A run whose member died: still "running" in its row, past its deadline.
	if _, err := db.StartRequirementRun(RequirementRun{RunID: "run-dead", Deadline: time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := db.ActiveRequirementRun(); found {
		t.Error("a lapsed run still reads as active")
	}
	if r, _ := db.RequirementRunByID("run-dead"); r.State != RequirementRunLapsed {
		t.Errorf("the dead member's run reads %q, want lapsed", r.State)
	}
	if _, err := other.StartRequirementRun(RequirementRun{RunID: "run-c", Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("a lapsed run blocked the next one: %v", err)
	}
	// A member killed mid-check: its deadline hours away, but its heartbeat
	// silent. It stops holding the project's check, and reads as lapsed.
	if _, err := db.conn.Exec(`UPDATE requirement_runs SET heartbeat = ? WHERE run_id = 'run-c'`,
		formatReqTime(time.Now().Add(-requirementRunSilence-time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := db.ActiveRequirementRun(); found {
		t.Error("a silent run still reads as active")
	}
	if r, _ := db.RequirementRunByID("run-c"); r.State != RequirementRunLapsed {
		t.Errorf("the silent run reads %q, want lapsed", r.State)
	}
	if _, err := db.StartRequirementRun(RequirementRun{RunID: "run-d", Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("a silent run blocked the next one: %v", err)
	}
	// And a beating one keeps holding it.
	if _, err := db.TouchRequirementRun("run-d"); err != nil {
		t.Fatal(err)
	}
	if _, err := other.StartRequirementRun(RequirementRun{RunID: "run-e", Deadline: time.Now().Add(time.Hour)}); !errors.Is(err, ErrRequirementCheckRunning) {
		t.Errorf("a beating run did not hold the check: %v", err)
	}
	if _, err := db.RequirementRunByID("nope"); !errors.Is(err, ErrRequirementNotFound) {
		t.Errorf("a missing run: %v", err)
	}
}

func TestRequirementRunsAreBounded(t *testing.T) {
	db := openFresh(t)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < requirementRunsKept+10; i++ {
		if err := db.RecordFinishedRequirementRun(RequirementRun{RunID: fmt.Sprint("cli-", i), State: RequirementRunDone,
			Source: "cli", StartedAt: base.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := db.RecentRequirementRuns(0)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM requirement_runs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n > requirementRunsKept+1 || runs[0].RunID != fmt.Sprint("cli-", requirementRunsKept+9) {
		t.Fatalf("%d runs kept, newest %q", n, runs[0].RunID)
	}
	if err := db.RecordFinishedRequirementRun(RequirementRun{RunID: "x", State: RequirementRunRunning}); err == nil {
		t.Error("a finished run was recorded as running")
	}
	AuditRequirementCheck(db, runs[0], "abc", false, "cli:root")
	if n := auditCount(t, db, auditaction.ActionRequirementCheck); n != 1 {
		t.Errorf("%d check audit rows", n)
	}
}

// TestRequirementRowsAreReadDefensively: on a shared-filesystem executor the
// workload can write this database, so what is read back is bounded however
// it was written.
func TestRequirementRowsAreReadDefensively(t *testing.T) {
	db := openFresh(t)
	if _, err := db.conn.Exec(`INSERT INTO requirements (title, tags, tests) VALUES (?, ?, ?)`,
		strings.Repeat("t", 10000), `not json`, `[`+strings.Repeat(`{"command":"x"},`, 40)+`{"command":"x"}]`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.Exec(`INSERT INTO requirement_checks (requirement_id, verdict, detail) VALUES (1, 'pwned', 'nope')`); err != nil {
		t.Fatal(err)
	}
	reqs, err := db.Requirements()
	if err != nil || len(reqs) != 1 {
		t.Fatal(err)
	}
	if r := reqs[0]; len(r.Title) > 4*requirements.MaxTitleRunes || len(r.Tests) != requirements.MaxTests || r.Tags != nil {
		t.Errorf("read back %d-byte title, %d tests, tags %v", len(r.Title), len(r.Tests), r.Tags)
	}
	latest, err := db.LatestRequirementChecks()
	if err != nil {
		t.Fatal(err)
	}
	if c := latest[1]; c.Verdict != requirements.VerdictError {
		t.Errorf("a forged verdict reads %q", c.Verdict)
	}
}
