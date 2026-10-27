package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/ratelimit"
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
//
// The one exception is not a widening but a misfiling: before Task 20440 a run
// that budget.block_extra_usage held out of an exhausted subscription window
// was recorded as a budget pause. It is a usage cap in all but its code, and
// capPauseCleared recognises it by its wording and resumes it once the usage
// API shows the window open again. Any other budget pause stays put.

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

// errResumeDeclined is the answer of a cluster member that was handed a resume
// and, checking again, did not start it.
var errResumeDeclined = errors.New("auto-resume: the member holding the project's executor did not restart the run")

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

// SweepAutoResume runs one pass of the sweep now: what Run's watcher does every
// autoResumeCheckInterval, for a process that serves the hub's Handler without
// Run — an embedding program, or internal/ssohubtest's hub in a test's process,
// whose end-to-end tests drive an automatic resume through it (Task 20449).
func (s *Server) SweepAutoResume(ctx context.Context) { s.runAutoResumeSweep(ctx) }

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
	acct, ok := s.autoResumeReady(workDir, st)
	if !ok {
		return false
	}

	reason := st.PauseReason
	if err := s.startAutoResumeRun(workDir); err != nil {
		if errors.Is(err, errResumeDeclined) {
			return false
		}
		s.log().Warn(logger.EventSessionStart, 0, "auto-resume: could not restart cap-paused run",
			map[string]interface{}{"project": workDir, "error": err.Error()})
		s.holdRefusedResume(workDir, err)
		return false
	}

	var resumesAt time.Time
	fields := map[string]interface{}{"project": workDir, "detail": reason.Label()}
	if reason.ResumesAt != nil {
		resumesAt = *reason.ResumesAt
		fields["resumes_at"] = resumesAt.UTC().Format(time.RFC3339)
	}
	for k, v := range acct.auditFields() {
		fields[k] = v
	}
	s.log().Info(logger.EventSessionStart, 0, "auto-resume: subscription window reopened, run restarted", fields)
	s.auditAutoResume(workDir, reason, resumesAt, acct)
	return true
}

// autoResumeReady reports whether workDir's run, as st records it, is to be
// restarted now, and whom the restart acts for (resume_account.go). The sweep
// and the cluster member it hands a resume to both ask it, the member again
// because the state may have changed in the round trip.
//
// AutoResumable is the policy: paused, for a usage cap, with a reset that is
// now in the past. Everything else stays paused — bar the one pause an older
// build recorded as a budget pause for what was really an exhausted window
// (see capPauseCleared).
//
// A resume that could not act for the run's starter is settled here as the
// pause that actually holds it (holdRefusedResume), before the usage API is
// asked: for an older build's pause that read would be made under the very
// home that is missing, and could only ever answer "unknown".
func (s *Server) autoResumeReady(workDir string, st *state.ProjectState) (*resumeAccount, bool) {
	now := s.clock()
	if !resumablePause(st, now) {
		return nil, false
	}
	// A project someone already restarted by hand needs no help, and starting
	// a second harness in one working directory is the race handleRun refuses
	// for the same reason: both schedule from the same plan and overwrite each
	// other's status writes.
	if s.projectExecuting(workDir) {
		return nil, false
	}
	acct := s.resumeAccountFor(workDir)
	if err := s.resumeRefusalFor(workDir, acct); err != nil {
		s.holdRefusedResume(workDir, err)
		return nil, false
	}
	// An older build's pause clears by the starter's own usage windows. With
	// no account to read them under — nobody nameable, a home that is gone,
	// on an executor that would not have used it — nothing could ever show
	// the window reopened, and the pause is held as what it is rather than
	// left looking like a budget nobody can raise.
	if !st.PauseReason.AutoResumable(now) {
		if _, ok := acct.usageDir(); !ok {
			s.holdRefusedResume(workDir, acct.noUsage())
			return nil, false
		}
	}
	if !s.capPauseCleared(st, now, acct) {
		return nil, false
	}
	return acct, true
}

// resumablePause reports whether st is paused for a subscription window the
// hub restarts runs after: a usage cap whose reset has passed, or the
// extra-usage pause an older build recorded, whatever its window says now.
func resumablePause(st *state.ProjectState, now time.Time) bool {
	if st == nil {
		return false
	}
	if st.PauseReason.AutoResumable(now) {
		return true
	}
	return st.Status == "paused" && legacyExtraUsagePause(st.PauseReason)
}

// resumeRefusalFor is the refusal a dispatch of workDir acting for acct would
// meet on the executor the project resolves to now, or nil. The dispatch
// settles the same check against the executor it resolves itself, and that is
// the guarantee; this answers early, so the refusal becomes the pause that
// holds the run instead of a failure every sweep repeats. A project that
// resolves no executor is left to the dispatch, whose refusal names its own,
// more fundamental, reason.
func (s *Server) resumeRefusalFor(workDir string, acct *resumeAccount) error {
	if acct == nil || !acct.who.personal {
		return nil
	}
	if acct.unavailable != nil && acct.unavailable.AnyExecutor {
		return acct.unavailable
	}
	registerBuiltinExecutors()
	ex, err := executor.Resolve(workDir)
	if err != nil || ex == nil {
		return nil
	}
	if err := acct.check(ex); err != nil {
		return err
	}
	// A copilot run on the hub's own host needs a Copilot credential of the
	// starter's (Task 20449): settled as the dispatch will settle it, and only
	// that refusal answered here — every other one the dispatch names itself.
	if _, err := newResumeClearance(acct).settle(ex, workDir); err != nil {
		if su, ok := errStarterUnavailable(err); ok && su.Copilot {
			return su
		}
	}
	return nil
}

// capPauseCleared reports whether st is paused for a subscription window that
// has reopened by now, judged for the account the resume would act on.
//
// For a pause this build's orchestrator recorded, that is AutoResumable: the
// window's reset is in the reason. The other case is a pause recorded before
// Task 20440 by a run holding an exhausted window off to avoid extra usage —
// filed as a spent budget with no reset, so on its own terms nothing could
// ever resume it. Builds keep writing it after the hub that reads it moves on:
// a long-lived run keeps the binary it started with, and an edge device runs
// its own. For that pause the hub asks the usage API instead, and restarts the
// run once no window is exhausted any more. The run it starts is this build's,
// which records a proper usage-cap pause should the wall still be there.
//
// The windows asked about are the starter's own (Task 20443): read under the
// Claude home the resume acts on, or the hub's own login where that is the
// account the run used. Another account's windows say nothing about this
// run's — the hub's own login on a hub with single sign-on is nobody's.
func (s *Server) capPauseCleared(st *state.ProjectState, now time.Time, acct *resumeAccount) bool {
	if st == nil {
		return false
	}
	if st.PauseReason.AutoResumable(now) {
		return true
	}
	if st.Status != "paused" || !legacyExtraUsagePause(st.PauseReason) {
		return false
	}
	configDir, ok := acct.usageDir()
	if !ok {
		// No account to read: the pause stays for a person, as it always did.
		return false
	}
	usage, err := s.subscriptionUsage(configDir)
	if err != nil || usage == nil {
		// Unreadable is not reopened: the pause stays for the next sweep, or
		// for the person who presses Run, exactly as before.
		return false
	}
	return len(ratelimit.CheckExhaustedWindows(usage.At(now))) == 0
}

// legacyExtraUsagePause recognises the pause budget.Enforce recorded before
// Task 20440 moved the extra-usage check next to the subscription caps: code
// budget, no reset time, and a detail naming an exhausted window — "Claude
// Code 5-hour window exhausted (100%) — pausing to avoid extra usage (set
// budget.block_extra_usage: false to allow)". Every other budget pause is a
// spend limit somebody set, and stays a human's to clear.
func legacyExtraUsagePause(r *pausereason.Reason) bool {
	if r == nil || r.Code != pausereason.CodeBudget || r.ResumesAt != nil {
		return false
	}
	d := r.Detail
	return strings.HasPrefix(d, "Claude Code ") &&
		strings.Contains(d, " window exhausted (") &&
		strings.Contains(d, "pausing to avoid extra usage")
}

// subscriptionUsage is the Claude Code usage the sweep judges an older
// build's pause by: that of the login under configDir, the Claude home the
// resume acts on — "" for the hub's own (resumeAccount.usageDir).
func (s *Server) subscriptionUsage(configDir string) (*ratelimit.ClaudeUsage, error) {
	if s.autoResumeUsage != nil {
		return s.autoResumeUsage(configDir)
	}
	return resumeAccountUsage(configDir)
}

// holdRefusedResume gives a cap pause whose resume was refused the pause that
// actually holds it, when the refusal is one waiting will not change: a
// workspace over its disk limit (Task 20405), or a starter the resume cannot
// act for (Task 20443). Left as a cap pause, every sweep would try again — and
// be refused — while the badge kept saying the subscription was the reason.
// Neither is auto-resumable, so each waits for a person.
//
// A refusal the next sweep may not meet — the control plane could not be read
// just now — is logged and left: the pause stays the cap pause it was.
func (s *Server) holdRefusedResume(workDir string, err error) {
	if su, ok := errStarterUnavailable(err); ok {
		if su.Transient {
			s.log().Warn(logger.EventSessionStart, 0, "auto-resume: whom the run acts for could not be read; trying again next sweep",
				map[string]interface{}{"project": workDir, "reason": su.logDetail()})
			return
		}
		s.repauseForStarter(workDir, su)
		return
	}
	s.repauseIfOverDiskLimit(workDir, err)
}

// repauseForStarter records that a cap-paused run cannot be resumed for the
// person who started it: paused starter_unavailable, naming them and why, and
// journaled. Never resumed on the hub's shared login instead.
func (s *Server) repauseForStarter(workDir string, su *starterUnavailableError) {
	st, lerr := state.Load(workDir)
	if lerr != nil || st == nil || st.Status != "paused" || !resumablePause(st, s.clock()) {
		return
	}
	prior := st.PauseReason.Label()
	st.SetPaused(su.pause())
	if serr := st.SaveDirect(); serr != nil {
		s.log().Warn(logger.EventSessionStart, 0, "auto-resume: could not record why the run cannot be resumed",
			map[string]interface{}{"project": workDir, "error": serr.Error()})
		return
	}
	s.log().Warn(logger.EventSessionStart, 0, "auto-resume: held, the run's starter cannot be acted for",
		map[string]interface{}{"project": workDir, "starter": su.Identity, "reason": su.logDetail()})
	details := map[string]any{
		"pause_code": string(pausereason.CodeStarterUnavailable),
		"via":        "auto_resume",
		"was":        prior,
	}
	if su.Identity != "" {
		details["starter"] = su.Identity
		details["starter_basis"] = su.Basis
	}
	state.LogEventDetails(workDir, state.EventRow{
		Type: state.EventSessionPaused,
		Step: state.NoStep,
		Message: fmt.Sprintf("Auto-resume held: the run is paused for a subscription window the hub restarts "+
			"it after (%s), but %s. %s", prior, su.Error(), su.Remediation()),
	}, details)
	s.broadcastStateDiff(workDir, st)
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
}

// repauseIfOverDiskLimit gives a cap pause whose resume was refused because
// the workspace is over its disk limit (Task 20405) the pause that actually
// holds it. Left as a cap pause, every sweep would try again — and be refused,
// and journal the refusal — while the badge kept saying the subscription was
// the reason; a disk_limit pause is not auto-resumable, so it waits for the
// person who frees the space or raises the limit.
func (s *Server) repauseIfOverDiskLimit(workDir string, err error) {
	var overLimit *executor.DiskLimitError
	if !errors.As(err, &overLimit) {
		return
	}
	st, lerr := state.Load(workDir)
	if lerr != nil || st == nil || st.Status != "paused" || !resumablePause(st, s.clock()) {
		return
	}
	st.SetPaused(diskLimitPause(overLimit.Breach))
	if serr := st.SaveDirect(); serr != nil {
		s.log().Warn(logger.EventSessionStart, 0, "auto-resume: could not record the disk-limit pause",
			map[string]interface{}{"project": workDir, "error": serr.Error()})
		return
	}
	s.broadcastStateDiff(workDir, st)
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
}

// auditAutoResume records that a machine, not a person, started this run, and
// whom it acted for. Best-effort: a project whose control-plane DB cannot be
// opened is still resumed, because refusing to work when the trail is
// unwritable would turn a logging fault into an availability one.
func (s *Server) auditAutoResume(workDir string, reason *pausereason.Reason, resumesAt time.Time, acct *resumeAccount) {
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return
	}
	defer db.Close() //nolint:errcheck
	// A cap pause and its resume are two halves of one story about this plan,
	// so they have to land in the same chain the pause did — the project's.
	db.AsProject()
	in := statedb.CapResumeInput{
		ProjectPath:  workDir,
		PausedDetail: reason.Label(),
		ResumesAt:    resumesAt,
		ResumedAt:    s.clock(),
	}
	if acct != nil && acct.who.personal {
		in.ActedFor, in.ActedForBasis = acct.who.identity, acct.basis
	}
	statedb.AuditCapResume(db, in)
}

// handOffAutoResume asks member m, which holds the connection to workDir's
// executor, to restart its run. The member checks everything again and may
// decline — the state moved, or it holds the run because it cannot act for
// its starter (Task 20443) — and a resume it did not start is not one to
// record: errResumeDeclined.
func (s *Server) handOffAutoResume(m hubcluster.Member, workDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var reply struct {
		Started *bool `json:"started"`
	}
	if err := s.clusterNode().Call(ctx, m, http.MethodPost, clusterAPIAutoResume,
		map[string]string{"project": workDir}, &reply); err != nil {
		return err
	}
	if reply.Started != nil && !*reply.Started {
		return errResumeDeclined
	}
	return nil
}

// startAutoResumeRun dispatches the harness for a project with no HTTP request
// behind it.
//
// There is no authenticated caller to attribute this to — the trigger is a
// timer. runIdentity(nil, workDir) resolves the project's registered owner, so
// the run is still billed to whoever owns the project rather than vanishing
// into the local identity. Whom it acts for, and on which Claude account, is
// the person who started the run it resumes (resumeAccountFor, Task 20443):
// their home on an executor that shares this filesystem, as handleRun would
// have pinned it for them; a refusal when that cannot be — never the hub's
// own login in their place.
func (s *Server) startAutoResumeRun(workDir string) error {
	if s.autoResumeStart != nil {
		return s.autoResumeStart(workDir)
	}

	// The sweep runs on the leader, but a project on an edge agent can only be
	// dispatched by the hub member holding that agent's socket (Task 20354).
	// That member re-checks everything before starting anything.
	if m, ok := s.dispatchMember(workDir); ok {
		return s.handOffAutoResume(m, workDir)
	}

	if owner, err := s.claimRun(workDir, "auto_resume"); err != nil {
		return fmt.Errorf("%w (member %s)", err, owner.InstanceID)
	}

	payer := s.runIdentity(nil, workDir)
	s.openSpendCursor(workDir, payer)

	exe := s.selfExe()
	// The resume acts for whoever started the run it resumes, as recorded at
	// that run's dispatch: on their personal Claude credential where a sandbox
	// is granted one (Task 20379), and on their Claude home where the run
	// shares this host (Task 20443). A missing grant leaves the project
	// paused, and the sweep tries again on its next tick, by when someone may
	// have granted one; a starter it cannot act for is a pause of its own.
	acct := s.resumeAccountFor(workDir)
	ex, handle, err := startWorkloadAs(acct.envFor, newResumeClearance(acct), payer, workDir,
		[]string{exe, "run"}, map[string]string{"handler": "auto_resume"}, s.recordingRun(workDir, "auto_resume"))
	if err != nil {
		s.releaseRunClaim(workDir)
		return err
	}

	s.liveLogStartRun(workDir)
	streamCtx, cancelStream := context.WithCancel(context.Background())
	s.trackRunWithCancel(workDir, ex, handle.ID, cancelStream)
	s.broadcastRunState(workDir, true, true)
	s.publishRunState(workDir, true)

	lines, streamErr := ex.Stream(streamCtx, handle.ID)
	if streamErr != nil {
		cancelStream()
		s.liveLogSetRunning(workDir, false)
		s.publishRunState(workDir, false)
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
