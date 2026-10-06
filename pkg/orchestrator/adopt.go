package orchestrator

// adopt.go: a long-lived run moving to a newly deployed build at a task
// boundary (Task 20389).
//
// Nightly deploys replace the hub's binary, and a hub restart deliberately
// keeps runs alive, so a run in auto-evolve never ends and never upgrades. This
// project's own run was found 132 commits behind the deployed hub: "done means
// committed" switched on for it had never been enforced, the disk floor was
// inactive on a 98%-full disk, and it wrote a database six migrations ahead of
// what it knew. Only a manual restart fixed it.
//
// A host-process run can do better, because it can replace its own image and
// stay the same process. At a safe point it validates the binary at the path it
// was started from, writes a handoff, and calls execve with the same argv and
// environment. The pid survives, and with it the (starttime, boot_id) identity
// the local executor driver checks, the hub's claim on the run, and the stdout
// pipe the hub's live log reads — the hub never sees the run stop.
//
// The safe point is the top of either loop: after a task (or a parallel round)
// has settled and before the next one is picked, which is also before an
// evolve round. A parallel run only gets there once its round has drained:
// rounds launch together and wait for each other, so a pending adoption stops
// dispatch and lets the tasks in flight finish first. Before replacing itself
// the run also insists that no child process is alive (an exec does not take
// children with it, and the new image could never wait for them), stops its
// background pollers, and persists its state.
//
// What triggers it is either a one-shot request filed by the hub ("adopt the
// hub's build at the next task boundary"), addressed to this process, or the
// project's "follow new builds" option. Either way the candidate must answer
// `version --json` within ten seconds with a sequence strictly greater than
// this build's and a schema at least the database's (runbuild.Judge). Anything
// else — a refusal, a probe that fails, an exec that fails — is journalled with
// its reason, and the run carries on on the build it has. Device and container
// runs keep their own upgrade paths.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/runbuild"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskqueue"
	"github.com/fatih/color"
)

// adoptBuild is what a loop returns to hand the run to a newer build. Run,
// which owns the pollers and the stores, does the exec.
type adoptBuild struct {
	cand    *runbuild.Candidate
	handoff runbuild.Handoff
	request *runbuild.Request
}

func (a *adoptBuild) Error() string {
	return "orchestrator: handing the run to " + a.handoff.To.Short()
}

// adoptHooks are what adoption asks of the system; tests replace them.
type adoptHooks struct {
	self      func() (runbuild.Ident, error)
	startPath func() (string, error)
	open      func(path string) (*runbuild.Candidate, error)
	probe     func(ctx context.Context, c *runbuild.Candidate) (runbuild.Build, error)
	children  func() ([]runbuild.Child, error)
	// checkArgs asks the candidate whether it accepts this run's command line.
	checkArgs func(ctx context.Context, c *runbuild.Candidate, args []string) error
	exec      func(c *runbuild.Candidate, argv, env []string) error
	// beforeExec, when set, runs just before the exec (tests).
	beforeExec func()
	// childWait is how long a boundary waits for child processes to exit;
	// settle how long a deployed file must have been in place before a run
	// that follows new builds adopts it.
	childWait time.Duration
	settle    time.Duration
}

// followSettle is how long a newly deployed binary must have been in place
// before a run that follows new builds adopts it. The deploy at :8888 installs
// the binary, restarts the hub and health-checks it for half a minute, then
// puts the previous binary back if that failed; a run that adopted the new one
// inside that window would have migrated its database to a schema the
// rolled-back hub refuses, with no way back.
const followSettle = 3 * time.Minute

// maxAdoptAttempts is how often a file whose probe, argv check or exec failed
// is tried again before it is given up on: a timeout on a loaded host is not a
// broken build, but a broken build must not be retried at every boundary.
const maxAdoptAttempts = 3

func defaultAdoptHooks() adoptHooks {
	return adoptHooks{
		self:      runbuild.SelfIdent,
		startPath: runbuild.StartPath,
		open:      runbuild.Open,
		probe: func(ctx context.Context, c *runbuild.Candidate) (runbuild.Build, error) {
			return c.Probe(ctx, runbuild.ProbeTimeout)
		},
		children: runbuild.LiveChildren,
		checkArgs: func(ctx context.Context, c *runbuild.Candidate, args []string) error {
			return c.CheckArgs(ctx, runbuild.ProbeTimeout, args)
		},
		exec:      runbuild.Exec,
		childWait: 5 * time.Second,
		settle:    followSettle,
	}
}

// runCarry is the run's bookkeeping that outlives one entry into a loop. A
// mode switch leaves one loop for the other, and an adoption leaves a loop in
// one image for a loop in the next; neither starts a new run.
type runCarry struct {
	sessionStart     time.Time
	sessionStartStep int
	errors           int
	emptyEvolves     int
	// started is set by the first loop entry. Whatever a run does once per
	// start — re-plan on --replan, reset failed tasks, optimise, ask at a
	// terminal, run the pre_plan hook, announce itself — happens only then.
	started bool
}

// enterLoop is called by both loops as they start. fresh is true only for a
// run's first entry in its first image.
func (o *Orchestrator) enterLoop(s *state.ProjectState) (fresh bool, c *runCarry) {
	if o.carry == nil {
		o.carry = &runCarry{sessionStart: time.Now(), sessionStartStep: s.CurrentStep}
		if h := o.config.Handoff; h != nil {
			if !h.SessionStart.IsZero() {
				o.carry.sessionStart = h.SessionStart
				o.carry.sessionStartStep = h.SessionStartStep
			}
			o.carry.errors = h.ConsecutiveErrors
			o.carry.emptyEvolves = h.ConsecutiveEmptyEvolves
		}
		o.carry.started = o.config.Resumed
	}
	fresh = !o.carry.started
	o.carry.started = true
	return fresh, o.carry
}

// ── The run's own record ────────────────────────────────────────────────────

// recordRunOwner writes the run-owner record — this process, the path it was
// started from, the build it runs — and, for an image that took over from
// another, journals the adoption. Called once per image, before either loop.
func (o *Orchestrator) recordRunOwner() {
	id, idErr := o.adopt.self()
	path, _ := o.adopt.startPath()
	kind := o.executorKind()
	now := time.Now()
	rec := &runbuild.Owner{
		Ident: id, Host: runbuild.Hostname(), Exe: path, Executor: kind,
		Adoptable: runbuild.Supported && idErr == nil && kind == executor.KindLocalProcess,
		RunID:     resolveRunID(o.config.WorkDir), StartedAt: processStartTime(),
		Build: o.selfBuild, BuildSince: now,
	}
	h := o.config.Handoff
	if h != nil {
		rec.Reexecs = h.Reexecs + 1
		prev := h.From
		rec.Previous = &prev
		if h.Exe != "" {
			rec.Exe = h.Exe
		}
	} else if o.config.Resumed {
		// The handoff was announced and lost: take the count from the record
		// the previous image left, which names this very process (New took
		// its run id and start from it too).
		if prev := o.state.RunOwner; prev != nil && prev.Ident.Same(id) {
			rec.Reexecs = prev.Reexecs + 1
			b := prev.Build
			rec.Previous = &b
			rec.Exe = prev.Exe
			rec.StartedAt = prev.StartedAt
		}
		// A request this process was acting on is answered by this image.
		if r := o.state.AdoptRequest; r.For(id) && o.statedb != nil {
			_, _ = o.statedb.ClearAdoptRequest(r.ID)
		}
	}
	o.owner = rec
	if o.statedb != nil {
		if err := o.statedb.SaveRunOwner(rec); err != nil {
			o.log.Warn(logger.EventSessionStart, 0, "could not record this run's build", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}
	if !o.config.Resumed {
		return
	}

	details := map[string]any{
		"to":      rec.Build,
		"pid":     rec.PID,
		"reexecs": rec.Reexecs,
		"exe":     rec.Exe,
	}
	msg := "Run continued on " + rec.Build.Label()
	if h != nil {
		details["from"] = h.From
		details["reason"] = h.Reason
		details["run_id"] = h.RunID
		details["evolve_step"] = h.EvolveStep
		details["consecutive_errors"] = h.ConsecutiveErrors
		details["consecutive_empty_evolves"] = h.ConsecutiveEmptyEvolves
		details["status"] = h.Status
		if h.RequestedBy != "" {
			details["requested_by"] = h.RequestedBy
		}
		msg = fmt.Sprintf("Run re-executed: %s → %s (%s)", h.From.Short(), rec.Build.Short(), h.Reason)
		if h.To.Sequence != 0 && h.To.Sequence != rec.Build.Sequence {
			// The binary answered the probe as one build and started as
			// another: say so rather than let the row claim the plan.
			details["probed"] = h.To
		}
	} else {
		details["handoff_error"] = o.config.HandoffError
		msg = "Run re-executed on " + rec.Build.Short() + ", but its handoff was lost: " + o.config.HandoffError
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type: state.EventRunReexecuted, Step: state.NoStep, Message: msg,
	}, details)
	if o.statedb != nil {
		from := runbuild.Build{}
		reason := ""
		if h != nil {
			from, reason = h.From, h.Reason
		}
		statedb.AuditRunReexecuted(o.statedb, statedb.RunReexecInput{
			ProjectPath: o.config.WorkDir, RunID: rec.RunID, PID: rec.PID,
			From: from, To: rec.Build, Reason: reason, Reexecs: rec.Reexecs,
		})
		if h != nil && h.RequestID != "" {
			_, _ = o.statedb.ClearAdoptRequest(h.RequestID)
		}
	}
	color.New(color.FgCyan, color.Bold).Printf("\n↻ %s\n", msg)
}

// logRunStarted journals the start of a run, with the build it starts on:
// the row a reader of the history matches a later run_reexecuted row against.
func (o *Orchestrator) logRunStarted(s *state.ProjectState) {
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:    state.EventSessionStarted,
		Step:    state.NoStep,
		Message: "Run started on " + o.selfBuild.Short(),
	}, map[string]any{
		"goal":          s.Goal,
		"provider":      o.provider.Name(),
		"model":         s.Model,
		"auto_evolve":   s.AutoEvolve,
		"innovate":      s.InnovateMode,
		"parallel":      s.Parallel,
		"max_parallel":  s.MaxParallel,
		"follow_builds": s.FollowBuilds,
		"build":         o.selfBuild,
		"pid":           os.Getpid(),
	})
}

// executorKind is the kind of executor this run was placed on, by its
// placement record; a run nobody placed is on this host.
func (o *Orchestrator) executorKind() string {
	_, kind, _ := resolveTaskAttribution(o.config.WorkDir)
	if kind == "" {
		kind = executor.KindLocalProcess
	}
	return kind
}

// ── The safe point ──────────────────────────────────────────────────────────

// atTaskBoundary is where a loop offers the run to a newer build: the top of
// the loop, with nothing in flight. It returns an *adoptBuild for the loop to
// return when the run should move, nil when it should carry on, and any other
// error only when the state could not be persisted before moving.
func (o *Orchestrator) atTaskBoundary(ctx context.Context, s *state.ProjectState, c *runCarry, parallel bool) error {
	if o.statedb == nil || ctx.Err() != nil {
		return nil
	}
	self, err := o.adopt.self()
	if err != nil {
		return nil
	}
	req := s.AdoptRequest
	requested := req.For(self)
	if !requested && !s.FollowBuilds {
		return nil
	}
	if !requested {
		req = nil
	}
	// A verdict or outcome write that needed the disk reserve leaves a note
	// the next disk check acts on (diskfloor.go); a new image would not have
	// it. That check runs first, and the request keeps until the boundary
	// after it.
	if o.reserveNotePending() {
		return nil
	}
	refuse := func(cand *runbuild.Build, reason string) error {
		o.refuseAdoption(req, cand, reason)
		return nil
	}
	if !runbuild.Supported {
		if requested {
			return refuse(nil, "adopting a build needs Linux")
		}
		return nil
	}
	if kind := o.executorKind(); kind != executor.KindLocalProcess {
		if requested {
			return refuse(nil, fmt.Sprintf("this run is on a %s executor, which keeps its own upgrade path", kind))
		}
		return nil
	}
	path, err := o.adopt.startPath()
	if o.owner != nil && o.owner.Exe != "" {
		path, err = o.owner.Exe, nil
	}
	if err != nil || path == "" {
		if requested {
			return refuse(nil, fmt.Sprintf("the path this run was started from is not known (%v)", err))
		}
		return nil
	}
	cand, err := o.adopt.open(path)
	if err != nil {
		if errors.Is(err, runbuild.ErrSameBinary) {
			if requested {
				return refuse(nil, fmt.Sprintf("%s still holds the build this run is executing (%s)", path, o.selfBuild.Short()))
			}
			return nil
		}
		if requested {
			return refuse(nil, err.Error())
		}
		o.noteOnce("open:"+err.Error(), fmt.Sprintf("not adopting the binary at %s: %v", path, err))
		return nil
	}
	fileID := cand.ID()
	if !requested && o.refusedFiles[fileID] {
		_ = cand.Close()
		return nil
	}
	if !requested {
		if age := time.Since(cand.InstalledAt()); age < o.adopt.settle {
			_ = cand.Close()
			if !o.adoptNotes["settle:"+path+fmt.Sprint(fileID)] {
				o.adoptNotes["settle:"+path+fmt.Sprint(fileID)] = true
				color.New(color.Faint).Printf("  a new build is at %s; adopting it once it has been in place %s\n",
					path, o.adopt.settle)
			}
			return nil
		}
	}
	if kids := o.waitForChildren(); len(kids) > 0 {
		_ = cand.Close()
		names := make([]string, len(kids))
		for i, k := range kids {
			names[i] = k.String()
		}
		reason := "child processes are still running (" + strings.Join(names, ", ") + "), and a new image could not wait for them"
		if requested {
			return refuse(nil, reason)
		}
		o.noteOnce("children:"+strings.Join(names, ","), "not adopting a new build at this boundary: "+reason)
		return nil
	}

	build, err := o.adopt.probe(ctx, cand)
	if err != nil {
		_ = cand.Close()
		if ctx.Err() != nil {
			return nil // the run is stopping; the probe was cut short, not refused
		}
		return refuse(nil, o.failedAttempt(fileID, fmt.Sprintf("%s: %v", path, err)))
	}
	dbSchema, err := o.statedb.CurrentSchemaVersion()
	if err != nil {
		_ = cand.Close()
		reason := "the project database's schema could not be read: " + err.Error()
		if requested {
			return refuse(&build, reason)
		}
		o.noteOnce("schema:"+err.Error(), "not adopting a new build at this boundary: "+reason)
		return nil
	}
	if err := runbuild.Judge(o.selfBuild, build, dbSchema); err != nil {
		_ = cand.Close()
		o.refusedFiles[fileID] = true
		return refuse(&build, err.Error())
	}
	// "Adopt the hub's build": never one past the hub that asked. A binary
	// ahead of it is a deploy still being checked, which may yet be rolled
	// back — and a run cannot follow it back down.
	if req != nil && req.Hub.Sequence > 0 && build.Sequence > req.Hub.Sequence {
		_ = cand.Close()
		return refuse(&build, fmt.Sprintf("%s is newer than the hub that asked (sequence %d against %d): a deploy "+
			"that may still be rolled back; ask again once the hub runs it", build.Short(), build.Sequence, req.Hub.Sequence))
	}
	if err := o.adopt.checkArgs(ctx, cand, os.Args[1:]); err != nil {
		_ = cand.Close()
		if ctx.Err() != nil {
			return nil
		}
		return refuse(&build, o.failedAttempt(fileID, fmt.Sprintf("%s %v", build.Short(), err)))
	}

	reason := "this project follows new builds"
	h := runbuild.Handoff{
		Run: self, Reason: reason, From: o.selfBuild, To: build, Exe: path,
		RunID: resolveRunID(o.config.WorkDir), ProcessStart: processStartTime(),
		SessionStart: c.sessionStart, SessionStartStep: c.sessionStartStep,
		EvolveStep: s.EvolveStep, ConsecutiveErrors: c.errors, ConsecutiveEmptyEvolves: c.emptyEvolves,
		Status: s.Status, Parallel: parallel,
	}
	if o.owner != nil {
		h.Reexecs = o.owner.Reexecs
	}
	if req != nil {
		h.RequestID, h.RequestedBy = req.ID, req.RequestedBy
		h.Reason = "requested"
		if req.RequestedBy != "" {
			h.Reason += " by " + req.RequestedBy
		}
	}
	if pr := pausereason.Normalize(s.Status, s.PauseReason); pr != nil {
		h.PauseReason, _ = marshalJSON(pr)
	}
	if dl, ok := ctx.Deadline(); ok {
		h.Deadline = dl
	}
	// Stored before the exec. A failure here is reported, and the run stays
	// where it is rather than stopping: this write exists only for the
	// adoption, and if the database refuses writes the next task's start
	// stops the run where every failed write is handled.
	if err := saveState(s, mergeExternal); err != nil {
		_ = cand.Close()
		pf := &persistFailure{what: "the run's state, before it adopts " + build.Short(), err: err,
			why: "it was saved only for the adoption, which is abandoned; the run carries on on its own build"}
		o.reportPersistFailure(pf)
		return refuse(&build, "the run's state could not be saved first: "+err.Error())
	}
	o.handingOver = true
	return &adoptBuild{cand: cand, handoff: h, request: req}
}

// waitForChildren returns the children still alive after up to childWait.
func (o *Orchestrator) waitForChildren() []runbuild.Child {
	deadline := time.Now().Add(o.adopt.childWait)
	for {
		kids, err := o.adopt.children()
		if err != nil {
			// procfs that cannot be read cannot vouch for anything.
			return []runbuild.Child{{Comm: "unknown: " + err.Error()}}
		}
		if len(kids) == 0 || time.Now().After(deadline) {
			return kids
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// failedAttempt counts a failure that may not be the file's fault — a probe
// that timed out on a loaded host, an exec that hit EAGAIN — and gives the
// file up only after maxAdoptAttempts. It returns the reason to journal.
func (o *Orchestrator) failedAttempt(id runbuild.FileID, reason string) string {
	o.adoptFailures[id]++
	n := o.adoptFailures[id]
	if n >= maxAdoptAttempts {
		o.refusedFiles[id] = true
		return fmt.Sprintf("%s (attempt %d of %d; not trying this file again)", reason, n, maxAdoptAttempts)
	}
	return fmt.Sprintf("%s (attempt %d of %d)", reason, n, maxAdoptAttempts)
}

// reserveNotePending reports a disk-reserve note the next disk check has not
// consumed yet.
func (o *Orchestrator) reserveNotePending() bool {
	o.diskMu.Lock()
	defer o.diskMu.Unlock()
	return o.reserveSpent != ""
}

// refuseAdoption journals an adoption that will not happen, clears the
// request it answers, and says so on the run's output.
func (o *Orchestrator) refuseAdoption(req *runbuild.Request, cand *runbuild.Build, reason string) {
	details := map[string]any{"outcome": "refused", "reason": reason, "build": o.selfBuild}
	if cand != nil {
		details["candidate"] = *cand
	}
	trigger := "follow new builds"
	if req != nil {
		trigger = "a request"
		details["request_id"] = req.ID
		if req.RequestedBy != "" {
			details["requested_by"] = req.RequestedBy
			trigger += " by " + req.RequestedBy
		}
	}
	details["trigger"] = trigger
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type: state.EventRunAdoption, Step: state.NoStep,
		Message: "Not adopting a new build (" + trigger + "): " + reason,
	}, details)
	if req != nil && o.statedb != nil {
		_, _ = o.statedb.ClearAdoptRequest(req.ID)
	}
	color.New(color.FgYellow).Printf("⚠ Not adopting a new build: %s — staying on %s\n", reason, o.selfBuild.Short())
}

// noteOnce journals a follow-mode note the first time it is true, so a
// condition that holds at every boundary is said once, not at every task.
func (o *Orchestrator) noteOnce(key, msg string) {
	if o.adoptNotes[key] {
		return
	}
	o.adoptNotes[key] = true
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type: state.EventRunAdoption, Step: state.NoStep, Message: msg,
	}, map[string]any{"outcome": "deferred", "trigger": "follow new builds", "build": o.selfBuild})
	color.New(color.Faint).Printf("  %s\n", msg)
}

// ── The exec ────────────────────────────────────────────────────────────────

// handOver replaces this process's image with the adopted build. It returns
// only if that failed, having journalled why and reopened what it closed: the
// run then carries on on this build.
func (o *Orchestrator) handOver(ctx context.Context, ad *adoptBuild) {
	defer func() { _ = ad.cand.Close() }()
	o.handingOver = false
	if ctx.Err() != nil {
		// Stopped while handing over: the stop wins, and the loop pauses.
		return
	}
	h := ad.handoff
	path := runbuild.HandoffPath(filepath.Join(o.config.WorkDir, ".cloop"), os.Getpid())
	h.WrittenAt = time.Now()
	if err := runbuild.WriteHandoff(path, h); err != nil {
		o.adoptionFailed(ad, "its handoff could not be written: "+err.Error())
		return
	}
	color.New(color.FgCyan, color.Bold).Printf("\n↻ Adopting %s at a task boundary (%s); this run continues on it\n",
		h.To.Label(), h.Reason)
	// An exec ends every goroutine: let the last task's webhooks go out first.
	o.webhook.Wait(10 * time.Second)
	o.closeStoresForExec()
	if o.adopt.beforeExec != nil {
		o.adopt.beforeExec()
	}
	// A stop that arrived while the handoff was written must not be lost to
	// the exec: the new image would start with a fresh context.
	if ctx.Err() != nil {
		_ = os.Remove(path)
		o.reopenStores()
		return
	}
	env := append(withoutEnvKey(os.Environ(), runbuild.EnvHandoff), runbuild.EnvHandoff+"="+path)
	err := o.adopt.exec(ad.cand, os.Args, env)
	// Only reached when the exec did not happen.
	_ = os.Remove(path)
	o.reopenStores()
	if err == nil {
		err = errors.New("the exec returned without replacing the process")
	}
	o.adoptionFailed(ad, "exec failed: "+err.Error())
}

func (o *Orchestrator) adoptionFailed(ad *adoptBuild, reason string) {
	to := ad.handoff.To
	o.refuseAdoption(ad.request, &to, o.failedAttempt(ad.cand.ID(), reason))
}

// closeStoresForExec closes the database handles before the exec. Nothing is
// writing — the pollers have stopped and the loop is at a boundary — so this
// loses nothing; it leaves no handle for the new image to inherit by accident.
func (o *Orchestrator) closeStoresForExec() {
	if o.statedb != nil {
		_ = o.statedb.Close()
		o.statedb = nil
	}
	if o.queue != nil {
		_ = o.queue.Close()
		o.queue = nil
	}
}

// reopenStores undoes closeStoresForExec after an exec that did not happen,
// opening what New opened, where New opened it.
func (o *Orchestrator) reopenStores() {
	dir := o.state.WorkDir
	if q, err := taskqueue.Open(dir); err == nil {
		o.queue = q
	} else {
		o.log.Warn(logger.EventSessionStart, 0, "task queue unavailable after a failed adoption",
			map[string]interface{}{"error": err.Error()})
	}
	if db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db")); err == nil {
		db.AsProject()
		o.statedb = db
	} else {
		o.log.Warn(logger.EventSessionStart, 0, "statedb unavailable after a failed adoption: manual aborts "+
			"and journal rows are off for the rest of this run", map[string]interface{}{"error": err.Error()})
	}
}

func withoutEnvKey(env []string, key string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// marshalJSON encodes v for a handoff field.
func marshalJSON(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// ── What a new image inherits from the process ─────────────────────────────

// processStartOverride is the first image's start time, for an image that
// took over from it: placement records are judged stale against the process's
// start, and a new image is not a new process.
var processStartOverride atomic.Pointer[time.Time]

// processStartTime is when this process started, whatever image it runs now.
func processStartTime() time.Time {
	if t := processStartOverride.Load(); t != nil {
		return *t
	}
	return processStart
}

// pinnedRunID is the execution id an adopting image handed over: the new
// image keeps it, so its tasks join to the leases the hub issued the run.
var pinnedRunID atomic.Pointer[string]

// inheritFromHandoff applies what a handoff says about the process itself.
func inheritFromHandoff(h *runbuild.Handoff) {
	if h == nil {
		return
	}
	if !h.ProcessStart.IsZero() {
		t := h.ProcessStart
		processStartOverride.Store(&t)
	}
	if id := strings.TrimSpace(h.RunID); id != "" {
		pinnedRunID.Store(&id)
	}
}
