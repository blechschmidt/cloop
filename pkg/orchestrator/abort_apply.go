package orchestrator

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
)

// maxAbortWait bounds how long a run will sit waiting for a usage window to
// reopen. Claude's five-hour window fits comfortably under it; its weekly one
// does not, and blocking a hub for six days is worse than exiting cleanly and
// letting the operator (or the UI's Run button) resume. Beyond this ceiling
// the session pauses instead of sleeping.
const maxAbortWait = 90 * time.Minute

// abortBackoff is the wait applied to a retryable abort whose message carried
// no parseable reset time. Long enough that a flapping provider is not
// hammered, short enough that a transient hiccup does not stall the plan.
const abortBackoff = 60 * time.Second

// repoFingerprint captures enough of the repository's state to tell whether a
// task changed anything: the committed tip plus the porcelain status of the
// working tree. Commits, staged changes and untracked files all move it.
//
// Returns "" when workDir is not a git repository, which makes the diff half
// of the evidence rule silently inapplicable rather than an error — plenty of
// cloop projects are not repositories, and for those the artifact is the only
// evidence available.
func repoFingerprint(workDir string) string {
	if workDir == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	head, err := gitOutput(ctx, workDir, "rev-parse", "HEAD")
	if err != nil {
		// A repository with no commits yet still has a working tree worth
		// fingerprinting, so only give up if status also fails.
		head = ""
	}
	status, err := gitOutput(ctx, workDir, "status", "--porcelain")
	if err != nil {
		if head == "" {
			return ""
		}
		return head
	}
	return head + "\n" + status
}

func gitOutput(ctx context.Context, workDir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = workDir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// repoChanged reports whether the repository moved between two fingerprints.
// An empty "before" means we could not fingerprint (not a repo, or git was
// unavailable), in which case we cannot claim a diff.
func repoChanged(before, after string) bool {
	if before == "" || after == "" {
		return false
	}
	return before != after
}

// abortTask records an aborted run and returns the task to pending.
//
// Pending rather than failed is the whole point: an aborted task never ran, so
// the plan's failure accounting must not count it, auto-evolve must not treat
// it as shipped, and the operator must see it queued rather than closed. The
// reason lands in its own event type so the journal can distinguish "the agent
// decided this was impossible" from "the agent was never allowed to try".
//
// The caller must hold whatever lock guards task mutation (the parallel loop
// holds mu).
func (o *Orchestrator) abortTask(s *state.ProjectState, task *pm.Task, ab Abort, step int) {
	task.Status = pm.TaskPending
	// A run that produced nothing has no completion instant and no elapsed
	// work; leaving these set would render the task as a finished one.
	task.CompletedAt = nil
	task.ActualMinutes = 0

	note := fmt.Sprintf("Task aborted before completion (%s): %s. Reset to pending — it never ran, so it is not done.",
		ab.Class, ab.Reason)
	if !ab.RetryAfter.IsZero() {
		note += fmt.Sprintf(" Retry scheduled after %s.", ab.RetryAfter.UTC().Format(time.RFC1123))
	}
	pm.AddAnnotation(task, "cloop", note)

	details := map[string]any{
		"abort_class": string(ab.Class),
		"reason":      ab.Reason,
		"retryable":   ab.Class.Retryable(),
	}
	if ab.Evidence != "" {
		details["evidence"] = ab.Evidence
	}
	if !ab.RetryAfter.IsZero() {
		details["retry_after"] = ab.RetryAfter.UTC().Format(time.RFC3339)
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      state.EventTaskAborted,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      step,
		Message: fmt.Sprintf("Task #%d aborted (%s): %s — reset to pending",
			task.ID, ab.Class, ab.Reason),
	}, details)

	if !o.log.IsJSON() {
		color.New(color.FgYellow).Printf("⚠ Task %d aborted (%s): %s — reset to pending, not done\n",
			task.ID, ab.Class, ab.Reason)
	}
	o.log.Warn(logger.EventTaskAborted, task.ID, task.Title, details)
}

// abortWait decides how long to hold off after an abort, and whether to give
// up on the run entirely. Split out from scheduleAbortRetry so the policy can
// be tested without sleeping through it.
//
//   - A non-retryable class (quota, credential, harness refusal) needs an
//     operator; retrying just burns the rest of the plan against the same wall.
//   - A usage window whose reset the message named is waited out, up to
//     ceiling. Beyond that — Claude's weekly limit is days away — pausing and
//     letting the operator or the UI resume beats blocking a hub for a week.
//   - A retryable abort with no parseable reset falls back to backoff.
func abortWait(ab Abort, now time.Time, ceiling, backoff time.Duration) (wait time.Duration, pause bool) {
	if !ab.Class.Retryable() {
		return 0, true
	}
	wait = backoff
	if !ab.RetryAfter.IsZero() {
		wait = ab.RetryAfter.Sub(now)
		if wait < 0 {
			wait = 0
		}
	}
	if wait > ceiling {
		return wait, true
	}
	return wait, false
}

// scheduleAbortRetry decides what the run does next after an abort. It returns
// stop=true when the run should end rather than immediately retry.
//
// Waiting matters because abortTask puts the task back to pending: the very
// next iteration picks that same task and hits the same wall. The old code did
// not spin — it marked the task done and moved on — which is how five
// consecutive tasks were closed against a single limit message.
func (o *Orchestrator) scheduleAbortRetry(ctx context.Context, s *state.ProjectState, ab Abort) (stop bool) {
	wait, pause := abortWait(ab, o.now(), o.abortWaitCeiling(), o.abortRetryBackoff())
	if pause {
		if ab.RetryAfter.IsZero() {
			color.New(color.FgYellow).Printf("⏸ Pausing run: %s. Resolve it and run cloop again.\n", ab.Reason)
		} else {
			color.New(color.FgYellow).Printf(
				"⏸ Pausing run: %s; it does not reset until %s (%s away). Run cloop again after that.\n",
				ab.Reason, ab.RetryAfter.UTC().Format(time.RFC1123), wait.Round(time.Minute))
		}
		s.SetPaused(abortPauseReason(ab))
		s.Save()
		return true
	}
	if wait <= 0 {
		return false
	}

	color.New(color.FgYellow).Printf("⏳ Waiting %s before retrying: %s\n", wait.Round(time.Second), ab.Reason)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}

// abortWaitCeiling is maxAbortWait unless a test has narrowed it.
func (o *Orchestrator) abortWaitCeiling() time.Duration {
	if o.testAbortWaitCeiling != 0 {
		return o.testAbortWaitCeiling
	}
	return maxAbortWait
}

// abortRetryBackoff is abortBackoff unless a test has shortened it.
func (o *Orchestrator) abortRetryBackoff() time.Duration {
	if o.testAbortBackoff != 0 {
		return o.testAbortBackoff
	}
	return abortBackoff
}

// abortPauseReason maps an abort onto the pause reason recorded against the
// run. A usage window reopens on its own and carries the instant it does; the
// classes that need an operator do not, and saying so is the difference
// between a project the hub may resume and one it must not touch.
func abortPauseReason(ab Abort) pausereason.Reason {
	if ab.Class == AbortUsageLimit {
		return pausereason.NewUntil(pausereason.CodeUsageCap, ab.Reason, ab.RetryAfter)
	}
	return pausereason.New(pausereason.CodeAbort, ab.Reason)
}

// abortSummaryForQueue renders the queue's terminal note for an aborted item.
func abortSummaryForQueue(ab Abort) string {
	return strings.TrimSpace(fmt.Sprintf("aborted (%s): %s", ab.Class, ab.Reason))
}
