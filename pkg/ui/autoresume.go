package ui

import (
	"context"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Auto-resume for runs that a Claude Code subscription cap stopped (Task 20285).
//
// The orchestrator waits out a window that reopens soon — abort_apply.go's
// ceiling is 90 minutes — and holding a worker longer than that to sleep off
// Claude's *weekly* window would block a hub for days. So a distant cap pauses
// the run instead, and records the reset instant as the pause reason's
// ResumesAt. That is the half this file completes: without it the recorded
// instant is a fact nobody acts on, and the project sits paused until a human
// notices and presses Run. For an unattended fleet that is the difference
// between a five-hour gap and a week-long one.
//
// The sweep only ever restarts a run paused *solely* for a usage cap. Every
// other reason either needs a decision (a declined approval, a spent budget)
// or describes a run that was not meant to continue (plan-only, an operator's
// Stop) — resuming those on a timer would override the intent that stopped
// them. AutoResumable enforces that; this file must not widen it.

// autoResumeCheckInterval is how often the sweep asks "has any window rolled
// over?". Five minutes bounds the lateness of a resume without making the
// wake-up itself notable: a cap pause lasts hours, so arriving up to five
// minutes late costs nothing an operator can perceive.
const autoResumeCheckInterval = 5 * time.Minute

// autoResumeStartupDelay defers the first sweep past the hub's own startup,
// matching the other watchers. A hub coming up has stale-run reconciliation to
// do first (stale_recovery.go), and resuming a project while that is still
// deciding what the last run left behind would race it.
const autoResumeStartupDelay = 45 * time.Second

// autoResumeEnabled reports whether the hub may restart cap-paused runs.
// Default on — see config.UIConfig.AutoResumeOnCapReset for why.
//
// An unreadable config leaves the default in force rather than disabling the
// sweep: the feature exists to stop a fleet stalling unattended, and a typo in
// an unrelated part of the file should not quietly reinstate that.
func (s *Server) autoResumeEnabled() bool {
	cfg, err := s.loadHubConfig()
	if err != nil || cfg == nil || cfg.UI.AutoResumeOnCapReset == nil {
		return true
	}
	return *cfg.UI.AutoResumeOnCapReset
}

// clock is the hub's time source, replaced in tests so a rolled-over usage
// window can be simulated instead of slept through.
func (s *Server) clock() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

// watchAutoResume restarts cap-paused runs whose window has reopened.
//
// Designed to be invoked as `go s.watchAutoResume(ctx)` from Run(). Returns
// when ctx is cancelled.
func (s *Server) watchAutoResume(ctx context.Context) {
	defer recoverGoroutine("watchAutoResume")

	startupDelay := time.NewTimer(autoResumeStartupDelay)
	defer startupDelay.Stop()
	select {
	case <-ctx.Done():
		return
	case <-startupDelay.C:
	}

	s.runAutoResumeSweep(ctx)

	ticker := time.NewTicker(autoResumeCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runAutoResumeSweep(ctx)
		}
	}
}

// runAutoResumeSweep visits every known project once. A failure in one is
// logged and skipped so it cannot stall the rest.
func (s *Server) runAutoResumeSweep(ctx context.Context) {
	defer recoverGoroutine("runAutoResumeSweep")

	if !s.autoResumeEnabled() {
		return
	}
	for _, e := range s.allProjectEntries() {
		if ctx.Err() != nil {
			return
		}
		s.maybeAutoResume(e.Path)
	}
}

// maybeAutoResume restarts one project if its cap window has rolled over.
// Returns true when a run was started, which is what the tests assert on.
func (s *Server) maybeAutoResume(workDir string) bool {
	st, err := state.LoadLite(workDir)
	if err != nil || st == nil {
		return false
	}

	// AutoResumable is the whole policy: paused, for a usage cap, with a
	// reset that is now in the past. Everything else stays paused.
	if !st.PauseReason.AutoResumable(s.clock()) {
		return false
	}

	// A project someone already restarted by hand needs no help, and starting
	// a second harness in one working directory is the race handleRun refuses
	// for the same reason: both schedule from the same plan and overwrite each
	// other's status writes.
	if s.projectExecuting(workDir) {
		return false
	}

	reason := st.PauseReason
	if err := s.startAutoResumeRun(workDir); err != nil {
		s.log().Warn(logger.EventSessionStart, 0, "auto-resume: could not restart cap-paused run",
			map[string]interface{}{"project": workDir, "error": err.Error()})
		return false
	}

	var resumesAt time.Time
	if reason.ResumesAt != nil {
		resumesAt = *reason.ResumesAt
	}
	s.log().Info(logger.EventSessionStart, 0, "auto-resume: subscription window reopened, run restarted",
		map[string]interface{}{
			"project":    workDir,
			"detail":     reason.Label(),
			"resumes_at": resumesAt.UTC().Format(time.RFC3339),
		})
	s.auditAutoResume(workDir, reason, resumesAt)
	return true
}

// auditAutoResume records that a machine, not a person, started this run.
// Best-effort: a project whose control-plane DB cannot be opened is still
// resumed, because refusing to work when the trail is unwritable would turn a
// logging fault into an availability one.
func (s *Server) auditAutoResume(workDir string, reason *pausereason.Reason, resumesAt time.Time) {
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return
	}
	defer db.Close() //nolint:errcheck
	statedb.AuditCapResume(db, statedb.CapResumeInput{
		ProjectPath:  workDir,
		PausedDetail: reason.Label(),
		ResumesAt:    resumesAt,
		ResumedAt:    s.clock(),
	})
}

// startAutoResumeRun dispatches the harness for a project with no HTTP request
// behind it.
//
// There is no authenticated caller to attribute this to — the trigger is a
// timer. runIdentity(nil, workDir) resolves the project's registered owner, so
// the run is still billed to whoever owns the project rather than vanishing
// into the local identity; and claudeEnvResolver is nil-tolerant, so a
// per-user Claude scope simply is not pinned, exactly as for any other
// non-interactive dispatch.
func (s *Server) startAutoResumeRun(workDir string) error {
	if s.autoResumeStart != nil {
		return s.autoResumeStart(workDir)
	}

	payer := s.runIdentity(nil, workDir)
	s.openSpendCursor(workDir, payer)

	exe := s.selfExe()
	ex, handle, err := startWorkloadAs(nil, payer, workDir,
		[]string{exe, "run"}, map[string]string{"handler": "auto_resume"})
	if err != nil {
		return err
	}

	s.liveLogStartRun(workDir)
	s.trackRun(workDir, ex, handle.ID)
	s.broadcastRunState(workDir, true, true)

	lines, streamErr := ex.Stream(context.Background(), handle.ID)
	if streamErr != nil {
		s.liveLogSetRunning(workDir, false)
		s.runEnded(workDir, ex, handle.ID)
		return streamErr
	}
	// No concurrency slot to return: auto-resume takes none, because the
	// admission gate exists to stop one tenant starving the fleet by opening
	// runs faster than they finish, and a timer that only ever restarts an
	// already-admitted run cannot do that.
	go s.consumeRunOutput(workDir, ex, handle.ID, lines, nil)
	return nil
}
