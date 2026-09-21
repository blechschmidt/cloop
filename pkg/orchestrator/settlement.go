// settlement.go renders the banner printed when a plan stops having runnable
// work.
//
// # The line this replaces
//
// Plan.IsComplete answers "is there anything left to run", and both PM loops
// printed the same thing whenever it said no:
//
//	🎉 All tasks complete! Goal achieved.
//	   0/1 tasks complete
//
// The two lines contradict each other, and the first one wins — it is bold,
// green, has an emoji, and says the thing an operator is hoping to read. It was
// printed verbatim underneath
//
//	✗ Provider error: claude CLI start error: exec: "claude":
//	  executable file not found in $PATH
//
// on a remote executor that could not run the harness at all, and underneath a
// 401 from an expired credential on the same project an hour later. In both
// cases nothing had run, nothing could have run, and the session signed off
// claiming the goal was reached.
//
// # Why IsComplete is nonetheless right
//
// It is not a bug in IsComplete: "settled" genuinely is what the loop needs to
// know, and a failed task settles a plan exactly as a finished one does — there
// is nothing more to dispatch either way. A permanently blocked task settles it
// too, without ever having run. The defect was reading a *scheduling* predicate
// as an *outcome* one, so the fix belongs at the print and not at the predicate:
// the loop keeps asking the question it needs, and the operator stops being told
// the answer to a different one.
package orchestrator

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// settlementLine returns the banner for a settled plan and whether the
// settlement is actually success.
//
// The bool is the whole interface: callers use it to pick the colour, so a
// run that ended badly cannot be rendered in the success style by a caller that
// forgot to look at the counts. Both PM loops declare their own successColor
// locally, which is why this returns a verdict rather than a colour.
func settlementLine(p *pm.Plan, autoEvolve bool) (line string, achieved bool) {
	if p == nil {
		return "🎉 All tasks complete! Goal achieved.", true
	}
	_, failed := p.CountByStatus()
	// Anything still pending at the moment a plan is judged complete is
	// permanently blocked — that is the only way IsComplete tolerates a pending
	// task — so it is counted separately from a failure. The distinction is
	// worth the line because the remedies differ: a failure is retried, a
	// blocked task has an unmet dependency that will never be met.
	blocked := 0
	for _, t := range p.Tasks {
		if t.Status == pm.TaskPending {
			blocked++
		}
	}

	if failed == 0 && blocked == 0 {
		if autoEvolve {
			return "🎉 All tasks complete! Auto-evolve enabled — discovering more work.", true
		}
		return "🎉 All tasks complete! Goal achieved.", true
	}

	var parts []string
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", failed))
	}
	if blocked > 0 {
		parts = append(parts, fmt.Sprintf("%d permanently blocked", blocked))
	}
	detail := strings.Join(parts, ", ")
	if autoEvolve {
		// Auto-evolve still runs, and saying so matters: the run is not over,
		// so an operator watching for a prompt should not stop watching. It
		// just no longer claims the goal was reached on the way there.
		return fmt.Sprintf("⚠ No runnable tasks left (%s) — auto-evolve will look for more work.", detail), false
	}
	return fmt.Sprintf("⚠ No runnable tasks left (%s). The goal was not reached.", detail), false
}
