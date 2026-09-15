package orchestrator

import (
	"context"
	"errors"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/ratelimit"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// This file routes the Claude Code subscription cap through the same abort
// machinery every other retryable wall goes through (Task 20285).
//
// It used to be the one path that did not. Both loops called
// enforceClaudeCodeLimits, printed the error, wrote a bare `Status = "paused"`
// and returned — so a project stopped indefinitely even though the exact
// instant it could continue was already in the snapshot that stopped it.
// pkg/ratelimit parses each window's reset from the OAuth usage API; nothing
// read it. A five-hour window that reopened at 14:50 left a fleet parked until
// somebody noticed and pressed Run.
//
// Routing it through scheduleAbortRetry gives a near reset the same treatment
// as any other usage limit — wait it out in-process and carry on — and, when
// the wait is too long to hold a worker for, records resumes_at so the hub can
// restart the run later without a human (see pkg/ui/autoresume.go).

// handleUsageCap decides what a run does about a tripped subscription cap.
//
// It returns stop=true when the run should end, in which case the state has
// already been paused with a reason and the audit row written. stop=false
// means the window reopened while we waited and the caller should carry on
// with its loop.
func (o *Orchestrator) handleUsageCap(ctx context.Context, s *state.ProjectState, capErr error) (stop bool) {
	color.New(color.FgRed, color.Bold).Printf("\n✗ %v\n", capErr)

	// The typed error is what carries the reset times. A plain error can still
	// arrive here if enforcement ever grows another failure mode, and that must
	// pause rather than be mistaken for a window that reopens on its own.
	var capped *ratelimit.CapExceededError
	if !errors.As(capErr, &capped) {
		s.SetPaused(pausereason.New(pausereason.CodeUsageCap, capErr.Error()))
		s.Save()
		return true
	}

	resumesAt := capped.ResumesAt()
	detail := capped.Label()

	// A cap that is tripped *and* whose reset has already passed is a stale
	// snapshot: the usage API lagging, or our own one-minute cache. Handing
	// that to abortWait would return a zero wait, the loop would `continue`,
	// re-read the same cached snapshot and arrive straight back here — a hot
	// loop for as long as the staleness lasts. A reset in the past says
	// nothing about when the cap clears, so drop it and let the backoff
	// decide, exactly as for a window that reported no reset at all.
	retryAfter := resumesAt
	if !retryAfter.IsZero() && !retryAfter.After(o.now()) {
		retryAfter = time.Time{}
	}

	// AbortUsageLimit is retryable, so abortWait waits out a reset inside the
	// ceiling and pauses beyond it — exactly the policy this path wanted and
	// had been hand-rolling as "always pause".
	ab := Abort{
		Class:      AbortUsageLimit,
		Reason:     detail,
		Evidence:   capErr.Error(),
		RetryAfter: retryAfter,
	}

	// scheduleAbortRetry makes and performs the decision: it either sleeps
	// until the window reopens and lets the run continue, or pauses — and on
	// the pause branch abortPauseReason(ab) yields precisely the usage_cap
	// reason this path wants, RetryAfter included, so there is nothing to set
	// up front.
	//
	// Deciding once matters. An earlier version called abortWait here too and
	// pre-set the reason, which read two different clocks: at the exact
	// ceiling boundary the first could say "pause" and the second "wait",
	// leaving a run marked paused that then carried on.
	stop = o.scheduleAbortRetry(ctx, s, ab)

	// Audit the pause from the state it actually produced, rather than from a
	// prediction. stop is true for a cancelled wait as well, so it is not the
	// thing to test — this is.
	if s.PausedFor(pausereason.CodeUsageCap) {
		o.auditCapPause(capped, detail, resumesAt)
		fields := map[string]interface{}{"detail": detail}
		if resumesAt.IsZero() {
			o.log.Warn(logger.EventTaskAborted, 0,
				"run paused: subscription cap reached, reset time unknown", fields)
		} else {
			fields["resumes_at"] = resumesAt.UTC().Format(time.RFC3339)
			o.log.Warn(logger.EventTaskAborted, 0,
				"run paused: subscription cap reached", fields)
		}
	}
	return stop
}

// auditCapPause writes the run.cap_paused row. Best-effort: a project whose DB
// handle was already closed still pauses correctly, it just does not leave a
// trail, and failing the pause over a missing audit row would be worse.
func (o *Orchestrator) auditCapPause(capped *ratelimit.CapExceededError, detail string, resumesAt time.Time) {
	if o.statedb == nil {
		return
	}
	in := statedb.CapPauseInput{
		ProjectPath: o.config.WorkDir,
		Detail:      detail,
		ResumesAt:   resumesAt,
	}
	for _, v := range capped.Violations {
		in.Windows = append(in.Windows, v.Window)
	}
	if len(capped.Violations) > 0 {
		in.Utilization = capped.Violations[0].Utilization
		in.Cap = capped.Violations[0].Cap
	}
	statedb.AuditCapPause(o.statedb, in)
}

// now is the orchestrator's clock, overridable so cap policy can be tested
// against a rolled-over window without sleeping through one.
func (o *Orchestrator) now() time.Time {
	if o.testNow != nil {
		return o.testNow()
	}
	return time.Now()
}
