package statedb

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

func proofFor(r requirements.Requirement, outcome string) requirements.Proof {
	pass := func() requirements.ProofSide {
		s := requirements.ProofSide{Commit: "1111111111111111111111111111111111111111"}
		for _, t := range r.Tests {
			s.Tests = append(s.Tests, requirements.TestResult{Command: t.Command, Outcome: requirements.OutcomePass})
		}
		return s
	}
	p := requirements.Proof{RequirementID: r.ID, Fingerprint: r.Fingerprint(), Outcome: outcome, Summary: outcome,
		BaseFrom: requirements.BaseFromTask, Before: pass(), After: pass(), Fallback: true, NewTests: true, CodeChanged: true,
		TestFiles: []requirements.ProofFile{{Path: "a_test.go", Status: requirements.FileAdded}},
		StartedAt: time.Now().UTC(), DurationMS: 42}
	p.After.Commit, p.After.Dirty = "2222222222222222222222222222222222222222", true
	p.Before.Tests[0].Outcome, p.Before.Tests[0].ExitCode, p.Before.Tests[0].Output = requirements.OutcomeFail, 1, "red at the base"
	return p
}

// TestRequirementProofsRoundTripBoundedLikeChecks: a proof reads back as it
// was recorded; a requirement keeps its newest proofs only; a proof of a
// definition that changed meanwhile, or of a requirement that is gone, is
// not kept; deleting the requirement takes its proofs.
func TestRequirementProofsRoundTripBoundedLikeChecks(t *testing.T) {
	db := openFresh(t)
	a := addReq(t, db, "proved", "go test ./a")
	b := addReq(t, db, "also proved", "go test ./b")

	stored, err := db.RecordRequirementProofs(ProofRecord{RunID: "run-1", ExecutorID: "local", ProvedBy: "alice", TaskID: 7},
		[]requirements.Proof{proofFor(a, requirements.ProofProven)})
	if err != nil || len(stored) != 1 {
		t.Fatalf("record = %v, %v", stored, err)
	}
	got, err := db.RequirementProofs(a.ID, 0)
	if err != nil || len(got) != 1 {
		t.Fatalf("read = %v, %v", got, err)
	}
	p := got[0]
	if p.Outcome != requirements.ProofProven || p.RunID != "run-1" || p.ProvedBy != "alice" || p.TaskID != 7 ||
		p.ExecutorID != "local" || !p.Fallback || !p.NewTests || !p.CodeChanged || !p.After.Dirty ||
		p.Before.Commit != strings.Repeat("1", 40) || p.After.Commit != strings.Repeat("2", 40) ||
		p.BaseFrom != requirements.BaseFromTask || len(p.TestFiles) != 1 || p.DurationMS != 42 {
		t.Fatalf("read back %+v", p)
	}
	if p.Before.Tests[0].Output != "red at the base" || p.After.Tests[0].Output != "" {
		t.Fatalf("outputs: before %q after %q", p.Before.Tests[0].Output, p.After.Tests[0].Output)
	}

	// Stale and orphaned proofs are not kept.
	stale := proofFor(b, requirements.ProofVacuous)
	stale.Fingerprint = "not-b's-definition"
	gone := proofFor(requirements.Requirement{ID: 99, Title: "x", Tests: []requirements.Test{{Command: "c"}}}, requirements.ProofProven)
	bogus := proofFor(b, "certainly")
	if stored, err := db.RecordRequirementProofs(ProofRecord{}, []requirements.Proof{stale, gone, bogus}); err != nil || len(stored) != 0 {
		t.Fatalf("kept %v, %v", stored, err)
	}

	for i := 0; i < requirementProofsKept+5; i++ {
		if _, err := db.RecordRequirementProofs(ProofRecord{RunID: "bulk"}, []requirements.Proof{proofFor(b, requirements.ProofVacuous)}); err != nil {
			t.Fatal(err)
		}
	}
	if all, _ := db.RequirementProofs(b.ID, 1000); len(all) != requirementProofsKept {
		t.Fatalf("R-%d keeps %d proofs, want %d", b.ID, len(all), requirementProofsKept)
	}
	latest, err := db.LatestRequirementProofs()
	if err != nil || latest[a.ID].Outcome != requirements.ProofProven || latest[b.ID].Outcome != requirements.ProofVacuous {
		t.Fatalf("latest = %+v, %v", latest, err)
	}

	if _, _, err := db.DeleteRequirement(b.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if left, _ := db.RequirementProofs(b.ID, 0); len(left) != 0 {
		t.Fatalf("a deleted requirement left %d proofs", len(left))
	}
}

// TestProofRunsTakeTheCheckSlot: a proof run is a requirement run of kind
// prove, and holds the project's one slot as a check does.
func TestProofRunsTakeTheCheckSlot(t *testing.T) {
	db := openFresh(t)
	r := addReq(t, db, "proved", "go test ./a")
	run, err := db.StartRequirementRun(RequirementRun{RunID: "prove-1", Kind: RequirementRunKindProve, Source: "dashboard",
		StartedBy: "alice", Deadline: time.Now().Add(time.Hour), RequirementIDs: []int{r.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartRequirementRun(RequirementRun{RunID: "check-1", Deadline: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("a check started while a proof held the slot")
	}
	got, err := db.RequirementRunByID(run.RunID)
	if err != nil || got.Kind != RequirementRunKindProve {
		t.Fatalf("run = %+v, %v", got, err)
	}
	if _, err := db.FinishRequirementRun(run.RunID, RequirementRunDone, requirements.Counts{}, "local", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordFinishedRequirementRun(RequirementRun{RunID: "cli-1", State: RequirementRunDone, Source: "cli"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.RequirementRunByID("cli-1"); got.Kind != RequirementRunKindCheck {
		t.Fatalf("a run of no kind reads as %q", got.Kind)
	}
	AuditRequirementProof(db, got, []requirements.Proof{proofFor(r, requirements.ProofProven)}, "alice")
	if n := auditCount(t, db, auditaction.ActionRequirementProve); n != 1 {
		t.Fatalf("%d requirement.prove rows", n)
	}
}
