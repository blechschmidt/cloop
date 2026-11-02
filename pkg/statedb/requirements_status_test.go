package statedb

// What the database knows of where each approved requirement stands (Task
// 20463): its latest verdict, when its current definition last held, and on a
// device the hub's facts its seed carried.

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

func TestRequirementStandingsKnowWhenEachLastHeld(t *testing.T) {
	db := openFresh(t)
	db.AsProject()
	r, err := db.AddRequirement(requirements.Requirement{Title: "Exit 2", Priority: requirements.PriorityMust,
		Tests: []requirements.Test{{Command: "true"}}}, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddRequirement(requirements.Requirement{Title: "A draft", Status: requirements.StatusDraft}, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	held, err := db.RecordRequirementVerdict(r.ID, requirements.VerdictFulfilled, "", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := db.RecordRequirementVerdict(r.ID, requirements.VerdictUnfulfilled, "broke", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	st, err := db.RequirementStandings()
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 1 || st[0].Verdict != requirements.VerdictUnfulfilled || !st[0].HeldAt.Equal(held.CheckedAt.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("standings %+v, want R-1 unfulfilled and held at %v — the draft has none", st, held.CheckedAt)
	}

	// Changed, it has not held as it reads now.
	r.Title = "Exit 3"
	if _, err := db.UpdateRequirement(r, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if st, err = db.RequirementStandings(); err != nil || !st[0].HeldAt.IsZero() || !st[0].Earlier {
		t.Fatalf("after a change: %+v, %v", st, err)
	}
}

// On a device the seed's facts stand in for the checks the database here
// does not hold, and the run's own newer checks are laid over them.
func TestRequirementFactsLayTheRunsChecksOverTheSeeds(t *testing.T) {
	db := openFresh(t)
	db.AsProject()
	r, err := db.AddRequirement(requirements.Requirement{Title: "Exit 2", Priority: requirements.PriorityMust,
		Tests: []requirements.Test{{Command: "true"}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	seed := requirements.StatusSummary{Requirements: []requirements.Standing{
		{ID: r.ID, Title: "Exit 2", Priority: requirements.PriorityMust, Tested: true, ChangedAt: old,
			Verdict: requirements.VerdictUnfulfilled, CheckedAt: old, Action: requirements.ActionFix, Gaps: []string{"unfulfilled"}},
		{ID: 7, Title: "Only the hub has it", Priority: requirements.PriorityShould, ChangedAt: old},
	}, Omitted: 3}
	if err := db.SeedRequirementStatus(seed); err != nil {
		t.Fatal(err)
	}
	facts, omitted, err := db.RequirementFacts()
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 || facts[0].Verdict != requirements.VerdictUnfulfilled || facts[0].Action != "" || omitted != 3 {
		t.Fatalf("facts %+v, omitted %d", facts, omitted)
	}
	// The run's gate checks it, and finds it holding.
	if _, err := db.RecordRequirementVerdict(r.ID, requirements.VerdictFulfilled, "", "gate"); err != nil {
		t.Fatal(err)
	}
	if facts, _, err = db.RequirementFacts(); err != nil || facts[0].Verdict != requirements.VerdictFulfilled || facts[0].HeldAt.IsZero() ||
		!facts[0].ChangedAt.Equal(old) {
		t.Fatalf("after the run's check: %+v, %v", facts, err)
	}
	if err := db.SeedRequirementStatus(requirements.StatusSummary{}); err != nil {
		t.Fatal(err)
	}
	if facts, _, err = db.RequirementFacts(); err != nil || len(facts) != 1 {
		t.Fatalf("with the seed's facts cleared: %+v, %v", facts, err)
	}
}
