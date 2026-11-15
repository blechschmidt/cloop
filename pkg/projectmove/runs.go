package projectmove

import (
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// RunFacts is what the hub knows about one project's runs: the project's own,
// or one of its features'.
type RunFacts struct {
	// Executing reports a run in progress: a cloop process on the hub, a
	// workload the hub dispatched that its executor still reports running,
	// or a run another member of the hub's cluster owns. ExecutingDetail
	// says which, for the message.
	Executing       bool
	ExecutingDetail string
	// Queued is a run waiting in an executor pool's queue, if there is one.
	Queued *QueuedRun
	// Status and Pause are the project's stored run status ("running",
	// "paused", ...) and, when paused, why.
	Status string
	Pause  *pausereason.Reason
	// Plan is the project's plan, read for its human review gates. Nil when
	// it could not be read.
	Plan *pm.Plan
	// Error is why these facts could not be read, when they could not; the
	// check then reports it rather than guessing.
	Error string
}

// QueuedRun is a run waiting in an executor pool's queue.
type QueuedRun struct {
	PoolID string
	// State is the queue entry's state: "waiting" for a runner, or
	// "assigned" one that is starting.
	State string
	Since time.Time
}

// checkRuns turns one project's run facts into findings. who names the project
// or feature they are about.
func checkRuns(who string, f RunFacts) []Finding {
	if f.Error != "" {
		return []Finding{{
			Kind: KindRun, Severity: SeverityBlocker, Side: SideSource,
			Title:   "Could not tell whether " + who + " has a run",
			Message: "Reading " + who + "'s run state failed: " + f.Error + ".",
			Remedy:  "A move must not start while a run might be executing. Fix what stops the hub reading the project's state, then run the preflight again.",
		}}
	}
	var out []Finding
	live := f.Executing || f.Pause.RunWaits()
	switch {
	case live:
		detail := f.ExecutingDetail
		if detail == "" && f.Pause.RunWaits() {
			detail = "the run is alive, waiting for disk space (" + f.Pause.Label() + ")"
		}
		msg := who + " has a run executing"
		if detail != "" {
			msg += ": " + detail
		}
		out = append(out, Finding{
			Kind: KindRun, Severity: SeverityBlocker, Side: SideSource,
			Title:   "A run is executing in " + who,
			Message: msg + ". A move never interrupts a running task: the run would go on writing to the source while it was being captured.",
			Remedy:  "Stop the run (Stop on the project's Overview, or `cloop remote stop <project>`) or let it finish, then run the preflight again.",
		})
	case f.Queued != nil:
		state := f.Queued.State
		if state == "" {
			state = "waiting"
		}
		msg := fmt.Sprintf("%s has a run in executor pool %s's queue (%s", who, f.Queued.PoolID, state)
		if !f.Queued.Since.IsZero() {
			msg += fmt.Sprintf(" since %s", f.Queued.Since.UTC().Format(time.RFC3339))
		}
		msg += "). A runner taking it during the move would start the run on the pool while the project was moving away."
		out = append(out, Finding{
			Kind: KindRun, Severity: SeverityBlocker, Side: SideSource,
			Title:   "A run is queued for an executor pool in " + who,
			Message: msg,
			Remedy:  "Stop the run, which takes it out of the pool's queue, then run the preflight again. A run a runner has just been assigned cannot be taken back for up to 20 minutes: wait for it to start, then stop it.",
		})
	case f.Status == "paused" && f.Pause != nil && f.Pause.Code == pausereason.CodeUsageCap && f.Pause.ResumesAt != nil:
		out = append(out, Finding{
			Kind: KindRun, Severity: SeverityBlocker, Side: SideSource,
			Title: "The hub will restart " + who + "'s paused run by itself",
			Message: fmt.Sprintf("%s's run is paused (%s) and the hub restarts it at %s without anyone asking. "+
				"A restart during the move would dispatch it to whichever executor the binding named at that moment.",
				who, f.Pause.Label(), f.Pause.ResumesAt.UTC().Format(time.RFC3339)),
			Remedy: "Stop the run, which cancels the scheduled restart, then move. Start it again on the target afterwards; it resumes from the task it paused on.",
		})
	case f.Status == "paused" && f.Pause != nil:
		out = append(out, pausedFinding(who, f.Pause))
	case f.Status == "paused":
		out = append(out, Finding{
			Kind: KindRun, Severity: SeverityWarning, Side: SideSource,
			Title:   who + "'s run is paused",
			Message: who + "'s run is paused and records no reason. The pause carries: the project stays paused on the target until someone starts it.",
			Remedy:  "Start the project on the target after the move.",
		})
	}
	if f.Plan != nil {
		if g := f.Plan.WaitingGate(); g != nil {
			out = append(out, Finding{
				Kind: KindRun, Severity: SeverityWarning, Side: SideSource,
				Title: fmt.Sprintf("%s is waiting at review gate #%d", who, g.ID),
				Message: fmt.Sprintf("Task #%d %q is a human review gate the run has reached; nothing after it runs until it is approved. "+
					"The gate is part of the plan, so it carries: it holds the queue on the target as it does here, and is approved there.",
					g.ID, oneLine(g.Title)),
				Remedy: "Review and approve (or reject) the gate before the move, while the work it reviews is still where the reviewer expects it, or after it on the target.",
				Items:  []Item{{Name: fmt.Sprintf("#%d", g.ID), Detail: oneLine(g.Title)}},
			})
		}
	}
	return out
}

// pausedFinding describes a pause no process is waiting out.
func pausedFinding(who string, r *pausereason.Reason) Finding {
	label := r.Label()
	f := Finding{Kind: KindRun, Side: SideSource, Title: who + "'s run is paused: " + label}
	switch r.Code {
	case pausereason.CodeIdle, pausereason.CodePlanOnly, pausereason.CodeOperator, pausereason.CodeCancelled, pausereason.CodeStale:
		// The run ended; "paused" is how the plan says it may grow again.
		f.Severity = SeverityWillCarry
		f.Message = fmt.Sprintf("%s's last run ended (%s) and nothing is waiting on it. The project's state carries as it is.", who, label)
	case pausereason.CodeExecutorLost, pausereason.CodeDiskLimit:
		f.Severity = SeverityWarning
		f.Message = fmt.Sprintf("%s's run stopped because of its executor (%s). The pause carries; moving to an executor that does not share the problem is one way to resolve it.", who, label)
		f.Remedy = "Start the project on the target after the move; its run resumes from the task it stopped on."
	case pausereason.CodePoolCapacity:
		f.Severity = SeverityWarning
		f.Message = fmt.Sprintf("%s is marked as waiting for an executor pool's capacity, but no run of it is in a pool's queue: the mark is stale.", who)
		f.Remedy = "Start the project on the target after the move."
	default:
		f.Severity = SeverityWarning
		f.Message = fmt.Sprintf("%s's run is paused waiting for a decision (%s). The pause carries: the project stays paused on the target, waiting for the same decision.", who, label)
		f.Remedy = "Resolve what the run is waiting for, then start it on the target after the move; it resumes from the task it paused on."
	}
	if r.TaskID > 0 {
		f.Items = []Item{{Name: fmt.Sprintf("task #%d", r.TaskID)}}
	}
	return f
}

// oneLine collapses s onto one line and bounds it, for a title quoted in a
// message.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 120 {
		s = string(r[:117]) + "..."
	}
	return s
}
