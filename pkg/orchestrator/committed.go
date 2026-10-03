package orchestrator

// committed.go holds tasks to a project's "done means committed" setting (Task
// 20370).
//
// unfinished.go hands a turn back when the agent's final message says it is
// waiting on its own work. That is phrase matching, and it keeps missing new
// wordings: Task 20368 ended "The only thing still running is the adversarial
// review agent. I'll address what it finds, re-run -race on the touched
// packages, then commit and push." — nothing matched, the task was recorded
// done, and 24 changed paths sat uncommitted: the twelfth "done" task this
// project had to rescue from a stranded tree. settleBackground cannot see that
// cause either, because Claude Code's background subagents run inside the CLI
// process rather than as processes of their own.
//
// So, where a project opts in, the symptom itself is the signal. When an
// attempt starts, the guard records what the repository looks like
// (pkg/donecheck). When the agent's turn ends — with TASK_DONE, or without a
// signal but otherwise acceptable as done — the guard asks which paths this
// attempt changed and left uncommitted and, with "pushed", which of its commits
// HEAD's upstream lacks. Anything outstanding hands the turn back through
// completeTask, in the same conversation, at most maxTurnContinuations times,
// naming exactly what to finish. A turn that still ends that way is an
// uncommitted_work abort: back to pending, the work left where the agent put
// it, the next attempt held to it, and the run's consecutive-abort ceiling —
// the bound unfinished_turn has — stopping a task that never finishes.
//
// Nothing here ever reverts, stashes or commits the agent's work. The check
// only reads.

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/donecheck"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
	"github.com/fatih/color"
)

// commitCheckTimeout bounds one check, which is a `git status` and, with
// "pushed", a few rev-lists.
const commitCheckTimeout = 3 * time.Minute

// commitGuard holds one attempt at a task to the project's commit policy. It
// is opened as the attempt starts, in the directory the agent works in, and
// read whenever one of the agent's turns ends.
//
// A parallel worker uses its task's guard from its own goroutine, so a guard
// reads nothing shared: what it needs of the task is copied in when it opens.
type commitGuard struct {
	o         *Orchestrator
	policy    pm.CommitPolicy
	base      *donecheck.Baseline
	gate      *gateRun
	taskID    int
	startedAt *time.Time
	// wroteVerdict reports that a hand-back recorded the attempt as not
	// done, which a turn that then finishes takes back.
	wroteVerdict bool
	// last is the most recent check's report.
	last *donecheck.Report
}

// openCommitGuard prepares the check for an attempt at task about to run in
// dir. It returns nil when the project's policy is off, and nil with a note to
// print when the policy is on but cannot apply: dir is not a git repository,
// or git could not read it.
func (o *Orchestrator) openCommitGuard(ctx context.Context, policy *pm.CommitPolicy, dir string, task *pm.Task, gate *gateRun) (*commitGuard, string) {
	if !policy.Active() || task == nil {
		return nil, ""
	}
	g := &commitGuard{o: o, policy: *policy, gate: gate, taskID: task.ID, startedAt: copyTime(task.StartedAt)}
	// What an earlier attempt at the task was blamed for stays the task's.
	carry, err := donecheck.ReadCarry(g.carryPath(), task.ID)
	if err != nil {
		color.New(color.Faint).Printf("  done means committed: ignoring task %d's record of its last attempt: %v\n", task.ID, err)
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commitCheckTimeout)
	defer cancel()
	base, err := donecheck.Take(cctx, dir, carry)
	if err != nil {
		return nil, fmt.Sprintf("done means committed: not checked for task %d — %v", task.ID, err)
	}
	g.base = base
	return g, ""
}

// carryPath is where the task's carry lives: beside its live artifact and its
// verdict, in the project's own .cloop/ — not the worktree's.
func (g *commitGuard) carryPath() string {
	return filepath.Join(artifact.LiveArtifactDir(g.o.config.WorkDir), fmt.Sprintf("%d_uncommitted.json", g.taskID))
}

// options is what the check requires of pushes right now. A push the review
// gate holds is pending, not missing; a gate that cannot hold pushes has told
// the agent not to push at all, so the push is not asked for.
func (g *commitGuard) options() donecheck.Options {
	opts := donecheck.Options{Pushed: g.policy.Pushed}
	if !opts.Pushed || g.gate == nil {
		return opts
	}
	if !g.gate.holding() {
		opts.NoPush = "the review gate cannot hold pushes here, so the agent was told not to push: the push was not checked"
		return opts
	}
	for _, h := range g.gate.hold.Pushes() {
		if h.SrcSHA != "" {
			opts.Held = append(opts.Held, h.SrcSHA)
		}
	}
	return opts
}

// check reads what the attempt has left outstanding, and keeps the task's
// carry in step with it. A check that cannot run is reported and counts as
// nothing outstanding: the agent's word then stands, as it would with the
// setting off. It runs to completion even while the run is stopping, so a
// stop never passes for a clean tree.
func (g *commitGuard) check(ctx context.Context) *donecheck.Report {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commitCheckTimeout)
	defer cancel()
	rep, err := donecheck.Check(cctx, g.base, g.options())
	if err != nil {
		color.New(color.Faint).Printf("  done means committed: task %d could not be checked: %v\n", g.taskID, err)
		return nil
	}
	g.last = rep
	path := g.carryPath()
	if rep.Outstanding() {
		err = donecheck.WriteCarry(path, g.base.Next(g.taskID, rep))
	} else {
		err = donecheck.ClearCarry(path)
	}
	if err != nil {
		color.New(color.Faint).Printf("  done means committed: task %d's record for its next attempt: %v\n", g.taskID, err)
	}
	return rep
}

// acceptableAsDone reports whether the orchestrator would accept a turn as done
// were nothing else in the way: TASK_DONE, or no signal and none of the things
// that keep an unsignalled turn from being done — a refusal, a question, an
// unfinished turn. Work still running in the background fails the task anyway.
func acceptableAsDone(output string, bg *provider.BackgroundActivity) bool {
	switch pm.CheckTaskSignal(output) {
	case pm.TaskDone:
	case pm.TaskInProgress:
		if strings.TrimSpace(output) == "" || looksLikeClarificationQuestion(output) || looksLikeUnfinishedTurn(output) {
			return false
		}
		if _, refused := ClassifyAbort(output); refused {
			return false
		}
	default:
		return false
	}
	return !bg.Incomplete()
}

// handBackFor decides, inside completeTask, whether a finished turn goes back
// to the agent for its outstanding work. It returns the instruction to send,
// or "" when the turn stands.
func (g *commitGuard) handBackFor(ctx context.Context, res *provider.Result) string {
	if g == nil || res == nil || !acceptableAsDone(res.Output, res.Background) {
		return ""
	}
	rep := g.check(ctx)
	if !rep.Outstanding() {
		g.settle()
		return ""
	}
	g.noteHandBack(rep)
	return uncommittedTurnInstruction(rep, g.policy.Pushed)
}

// noteHandBack records, before the turn goes back, that the attempt is not
// done: a run that dies during the hand-back must not have its agent's
// TASK_DONE adopted by stale-task recovery (Task 20365). With the review gate
// on, the gate's pending verdict already says so.
func (g *commitGuard) noteHandBack(rep *donecheck.Report) {
	if g.gate != nil {
		return
	}
	g.o.writeVerdict(taskrecover.Verdict{
		TaskID:    g.taskID,
		Status:    pm.TaskPending,
		Reason:    string(AbortUncommittedWork),
		Source:    taskrecover.SourceAbort,
		Detail:    "the agent's turn ended with " + sanitizeLine(rep.Summary()) + ", and it was handed the turn back to finish the work",
		StartedAt: copyTime(g.startedAt),
	})
	g.wroteVerdict = true
}

// settle takes back noteHandBack once a handed-back turn has finished its
// work, so the agent's own signal is what recovery reads again.
func (g *commitGuard) settle() {
	if g.wroteVerdict {
		g.wroteVerdict = false
		g.o.clearVerdict(g.taskID)
	}
}

// abortFor is the last word on a turn the orchestrator is about to accept: the
// uncommitted_work abort when the attempt left work outstanding, nil when it
// did not — or when the turn is not one the orchestrator would accept anyway.
// The abort is written down as the task's verdict before anything announces
// it (Task 20365).
func (g *commitGuard) abortFor(ctx context.Context, output string, bg *provider.BackgroundActivity) *Abort {
	if g == nil || !acceptableAsDone(output, bg) {
		return nil
	}
	rep := g.check(ctx)
	if !rep.Outstanding() {
		g.settle()
		return nil
	}
	ab := uncommittedAbort(rep, g.policy.Pushed)
	g.o.writeVerdict(taskrecover.Verdict{
		TaskID:    g.taskID,
		Status:    pm.TaskPending,
		Reason:    string(ab.Class),
		Source:    taskrecover.SourceAbort,
		Detail:    ab.Reason,
		Summary:   truncate(output, 500),
		StartedAt: copyTime(g.startedAt),
	})
	g.wroteVerdict = false
	return &ab
}

// passNote is the task annotation for a final check that found nothing
// outstanding but could not check everything — no upstream to push to, say —
// or "" when there is nothing to note.
func (g *commitGuard) passNote() string {
	if g == nil || g.last == nil || g.last.Outstanding() || len(g.last.Notes) == 0 {
		return ""
	}
	return fmt.Sprintf("Done means %s: %s.", g.policy.Describe(), sanitizeLine(strings.Join(g.last.Notes, "; ")))
}

// uncommittedAbort describes an attempt that ended with work outstanding.
func uncommittedAbort(rep *donecheck.Report, pushed bool) Abort {
	details := map[string]any{
		"requires_push":     pushed,
		"uncommitted_paths": rep.UncommittedCount,
	}
	var names []string
	for i, c := range rep.Uncommitted {
		if i == 10 {
			break
		}
		names = append(names, displayPath(c.Path))
	}
	if len(names) > 0 {
		details["paths"] = names
	}
	if pushed {
		details["unpushed_commits"] = rep.UnpushedCount
		if rep.Pending > 0 {
			details["pending_pushes"] = rep.Pending
		}
		if rep.Upstream != "" {
			details["upstream"] = rep.Upstream
		}
		var shas []string
		for i, c := range rep.Unpushed {
			if i == 10 {
				break
			}
			shas = append(shas, c.Short())
		}
		if len(shas) > 0 {
			details["commits"] = shas
		}
	}
	if len(rep.Notes) > 0 {
		details["notes"] = rep.Notes
	}
	return Abort{
		Class:    AbortUncommittedWork,
		Reason:   "the agent finished with " + sanitizeLine(rep.Summary()),
		Evidence: truncate(sanitizeLine(rep.Summary()), 200),
		Details:  details,
	}
}

// uncommittedTurnInstruction is the message that hands a turn back for its
// outstanding work. It names exactly what is outstanding, because "commit your
// work" alone invites committing everything in the tree — including an
// operator's edits that were there before the task started.
func uncommittedTurnInstruction(rep *donecheck.Report, pushed bool) string {
	var b strings.Builder
	want := "committed"
	if pushed {
		want = "committed and pushed to its branch's upstream"
	}
	fmt.Fprintf(&b, "Your turn ended, but this project counts a task as done only once its work is %s — and yours is not yet.\n\n", want)
	if rep.UncommittedCount > 0 {
		b.WriteString("These changes of this task are not committed (as `git status --short` shows them):\n")
		for _, c := range rep.Uncommitted {
			fmt.Fprintf(&b, "  %s %s\n", c.Code, displayPath(c.Path))
		}
		if more := rep.UncommittedCount - len(rep.Uncommitted); more > 0 {
			fmt.Fprintf(&b, "  … and %d more\n", more)
		}
		b.WriteString("\n")
	}
	if rep.UnpushedCount > 0 {
		on := "HEAD"
		if rep.Branch != "" {
			on = rep.Branch
		}
		fmt.Fprintf(&b, "These commits are on %s but not on its upstream %s:\n", on, rep.Upstream)
		for _, c := range rep.Unpushed {
			fmt.Fprintf(&b, "  %s %s\n", c.Short(), sanitizeLine(c.Subject))
		}
		if more := rep.UnpushedCount - len(rep.Unpushed); more > 0 {
			fmt.Fprintf(&b, "  … and %d more\n", more)
		}
		b.WriteString("\n")
	}
	b.WriteString("Continue the task now, in this turn:\n")
	if pushed {
		b.WriteString("- Finish the work these changes belong to, commit it, and push it. If the push is rejected, integrate the upstream's changes and push again.\n")
	} else {
		b.WriteString("- Finish the work these changes belong to and commit it.\n")
	}
	b.WriteString("- A change that should not be kept: revert it deliberately and say so, rather than leaving it in the tree.\n")
	b.WriteString("- Changes that were already in the working tree before this task started are not listed here: leave them alone, and do not commit them.\n")
	b.WriteString("- Do not end your turn while anything you depend on is still running; nothing will notify you.\n\n")
	b.WriteString("End with TASK_DONE, TASK_FAILED or TASK_SKIPPED on the last line.")
	return b.String()
}

// uncommittedTurnNote is the task annotation recording that its turn was
// handed back for outstanding work.
func uncommittedTurnNote(times int, pushed bool) string {
	n := "once"
	if times > 1 {
		n = fmt.Sprintf("%d times", times)
	}
	want := "committed"
	if pushed {
		want = "committed and pushed"
	}
	return fmt.Sprintf("Done means %s: the agent ended its turn with changes that were not, and its turn was handed back %s.", want, n)
}

// displayPath quotes a path that would not read as one on a line of its own.
func displayPath(p string) string {
	if p == "" || strings.IndexFunc(p, func(r rune) bool { return unicode.IsControl(r) }) >= 0 ||
		strings.TrimSpace(p) != p {
		return strconv.Quote(p)
	}
	return p
}

// sanitizeLine keeps text that came from the repository — a commit subject, a
// path — on one line.
func sanitizeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// keepsWorktree reports whether an attempt aborted for ab leaves work in its
// task worktree that the next attempt must start from. Removing the worktree
// would discard it: the branch holds only what was committed.
func keepsWorktree(ab *Abort) bool {
	return ab != nil && (ab.Class == AbortUncommittedWork || ab.Class == AbortUnfinishedTurn)
}

// pauseForUncommittedWork stops a run whose consecutive-abort ceiling was
// reached on an uncommitted_work abort. Where unfinished_turn and the other
// aborts end the run as failed, this one is a pause with its own reason: the
// work is in the tree, and someone has to decide what becomes of it before the
// run goes on. The pause is stored before it is announced. mu, when the
// parallel loop passes it, guards the state while it is written.
func (o *Orchestrator) pauseForUncommittedWork(s *state.ProjectState, task *pm.Task, ab Abort, attempts int, mu sync.Locker) error {
	detail := fmt.Sprintf("%d attempts in a row ended short; the last, task #%d, left its work uncommitted", attempts, task.ID)
	if err := o.pauseLocked(s, pausereason.New(pausereason.CodeUncommittedWork, detail), "the pause ("+detail+")", mu); err != nil {
		return err
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      state.EventSessionPaused,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      state.NoStep,
		Message:   "Run paused: " + detail,
	}, map[string]any{
		"pause_code": string(pausereason.CodeUncommittedWork),
		"attempts":   attempts,
		"reason":     ab.Reason,
	})
	color.New(color.FgYellow).Printf("⏸ Pausing run: %s (%s). Commit or revert that work, then run cloop again.\n", detail, ab.Reason)
	return nil
}

// pushed reports whether the guard requires pushes. A nil guard does not.
func (g *commitGuard) pushed() bool { return g != nil && g.policy.Pushed }
