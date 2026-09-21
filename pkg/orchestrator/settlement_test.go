package orchestrator

// Tests for the settled-plan banner (Task 20332).
//
// The case that matters is the first one: a plan whose only task failed used to
// print "🎉 All tasks complete! Goal achieved." directly beneath the provider
// error that killed it. Everything else here exists so that fixing that did not
// quietly change what a genuinely finished run says.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

func planWith(statuses ...pm.TaskStatus) *pm.Plan {
	p := &pm.Plan{}
	for i, st := range statuses {
		p.Tasks = append(p.Tasks, &pm.Task{ID: i + 1, Title: "t", Status: st})
	}
	return p
}

// TestFailedPlanDoesNotClaimSuccess is the reported bug.
func TestFailedPlanDoesNotClaimSuccess(t *testing.T) {
	line, achieved := settlementLine(planWith(pm.TaskFailed), false)
	if achieved {
		t.Fatalf("a plan whose only task failed is not an achieved goal; got %q", line)
	}
	for _, want := range []string{"1 failed", "not reached"} {
		if !strings.Contains(line, want) {
			t.Errorf("line should mention %q; got %q", want, line)
		}
	}
	if strings.Contains(line, "Goal achieved") {
		t.Errorf("line must not claim the goal was achieved; got %q", line)
	}
}

// TestAllDoneStillCelebrates: the success path is unchanged, including the
// wording, because it is what every passing run prints.
func TestAllDoneStillCelebrates(t *testing.T) {
	line, achieved := settlementLine(planWith(pm.TaskDone, pm.TaskDone), false)
	if !achieved || !strings.Contains(line, "Goal achieved") {
		t.Fatalf("all-done should report success; got %q (achieved=%v)", line, achieved)
	}
}

// TestSkippedCountsAsSettledSuccess follows CountByStatus, where a skipped task
// is a done one. A plan deliberately skipped through is not a failure, and
// telling an operator it was would train them to ignore the warning.
func TestSkippedCountsAsSettledSuccess(t *testing.T) {
	line, achieved := settlementLine(planWith(pm.TaskDone, pm.TaskSkipped), false)
	if !achieved {
		t.Fatalf("done+skipped should report success; got %q", line)
	}
}

// TestBlockedIsNamedSeparately: a task left pending when IsComplete says the
// plan is settled is permanently blocked, and its remedy — an unmet dependency —
// differs from a failure's, so the banner distinguishes them.
func TestBlockedIsNamedSeparately(t *testing.T) {
	line, achieved := settlementLine(planWith(pm.TaskDone, pm.TaskPending), false)
	if achieved {
		t.Fatalf("a blocked task is not success; got %q", line)
	}
	if !strings.Contains(line, "permanently blocked") {
		t.Errorf("line should name the blockage; got %q", line)
	}
}

// TestMixedFailureAndBlockageReportsBoth — an operator fixing one and rerunning
// should not discover the other only on the next pass.
func TestMixedFailureAndBlockageReportsBoth(t *testing.T) {
	line, _ := settlementLine(planWith(pm.TaskFailed, pm.TaskPending, pm.TaskDone), false)
	for _, want := range []string{"1 failed", "1 permanently blocked"} {
		if !strings.Contains(line, want) {
			t.Errorf("line should mention %q; got %q", want, line)
		}
	}
}

// TestTimedOutCountsAsFailure mirrors CountByStatus, which folds a timeout into
// the failed tally. A run killed by its own budget has not reached its goal.
func TestTimedOutCountsAsFailure(t *testing.T) {
	_, achieved := settlementLine(planWith(pm.TaskTimedOut), false)
	if achieved {
		t.Error("a timed-out task is not an achieved goal")
	}
}

// TestAutoEvolveKeepsItsNotice on both branches: the run continues either way,
// and an operator watching the loop needs to be told so — the change is only
// that the failing branch no longer congratulates them on the way past.
func TestAutoEvolveKeepsItsNotice(t *testing.T) {
	ok, achieved := settlementLine(planWith(pm.TaskDone), true)
	if !achieved || !strings.Contains(ok, "Auto-evolve") {
		t.Errorf("clean auto-evolve line = %q (achieved=%v)", ok, achieved)
	}
	bad, achieved := settlementLine(planWith(pm.TaskFailed), true)
	if achieved {
		t.Errorf("failed auto-evolve run should not report success; got %q", bad)
	}
	if !strings.Contains(bad, "auto-evolve") {
		t.Errorf("failed auto-evolve line should still say the run continues; got %q", bad)
	}
}

// TestNilPlanIsHarmless: the callers hold a live plan, but this renders output
// on a path that runs after a long session and must not be the thing that
// panics at the end of one.
func TestNilPlanIsHarmless(t *testing.T) {
	if _, achieved := settlementLine(nil, false); !achieved {
		t.Error("nil plan should fall back to the unchanged success line")
	}
}
