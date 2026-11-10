package agent

// ephemeral.go is `cloop executor agent --ephemeral` (Task 20483): the agent as
// an executor pool's runner, started by a controller for one run.
//
// Task 20482 taught the agent to *be* a runner when the hub said so — keep the
// credential in memory, end with success on a retiring bye. That is enough for
// a well-behaved hub and nothing more: an agent started as a runner that was
// handed a device's enrollment token would persist a long-lived credential in a
// Pod; one whose hub crashed between settling the run and retiring it would
// idle until the hub's janitor noticed, twenty minutes on; one stopped by its
// controller would leave the hub to guess, for a grace period, whether it was
// coming back; and nothing anywhere said why a runner's process ended.
//
// --ephemeral makes the runner's side of the contract the agent's own:
//
//   - It enrolls with a runner token (clrt1.) and nothing else, never reads or
//     writes a stored credential, and refuses a hub whose welcome does not say
//     it is a runner.
//   - It takes one run. A second start is refused on the device as well as by
//     the hub.
//   - When its run is over and reported — the final status, the write-back and
//     the project's state delivered — it waits RetireGrace for the hub's
//     retiring bye and then exits on its own.
//   - Leaving of its own accord (stopped, or done waiting), it says so to the
//     hub with a retiring bye, so the hub retires it at once rather than after
//     the grace a dropped link gets.
//   - On every exit it wipes what it held: the credential and the token in
//     memory, the token file where it can, every lease's files, and everything
//     it created under its work root.
//   - It reports its retirement: a one-line JSON report on its log and in the
//     termination log a Kubernetes container ends with, which its controller
//     reads to tell a runner that finished from one that was refused.
//
// The exit status follows the report: zero for a retirement — the hub's, or
// its own after its run, or a stop — and non-zero for a refusal, such as a
// token that expired before the runner reached the hub.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// DefaultRetireGrace is how long an ephemeral runner whose run is over and
// reported waits for the hub to retire it before it exits on its own. The
// hub retires a runner as it settles the run, which takes seconds; two minutes
// covers a hub member restarting in between and stays far below the twenty the
// hub's janitor would take to notice.
const DefaultRetireGrace = 2 * time.Minute

// DefaultTerminationLog is where Kubernetes reads a container's termination
// message from: a file the kubelet mounts into every container, and whose
// contents appear in the Pod's status when the container ends.
const DefaultTerminationLog = "/dev/termination-log"

// maxTerminationMessage is what Kubernetes keeps of a termination message.
const maxTerminationMessage = 4096

// errEphemeralNotRunner refuses a hub that did not enroll an --ephemeral agent
// as a runner.
var errEphemeralNotRunner = errors.New("agent: --ephemeral: the hub did not enroll this agent as an executor pool's runner")

// RetirementReport is what an ephemeral runner says about how it ended.
type RetirementReport struct {
	// Retired is true when the runner ended as a runner should: retired by
	// the hub, retired by itself after its run, or stopped. False is a
	// refusal or a failure, and the process exits non-zero.
	Retired bool `json:"retired"`
	// By says who ended it: "hub", "self" (its run was over and the hub did
	// not retire it in time), "stopped" (a signal), or "refused".
	By string `json:"by"`
	// Reason is why, in a sentence.
	Reason string `json:"reason"`
	// ExecutorID is the hub's name for the runner, once it enrolled.
	ExecutorID string `json:"executor_id,omitempty"`
	// Runs is how many runs it was handed: 0 or 1.
	Runs int `json:"runs"`
	// Interrupted is true when it was stopped while its run was going.
	Interrupted bool `json:"interrupted,omitempty"`
	// Wiped reports whether every piece of secret material it held was
	// destroyed; WipeErrors says what could not be.
	Wiped      bool     `json:"wiped"`
	WipeErrors []string `json:"wipe_errors,omitempty"`
	// At is when it ended.
	At time.Time `json:"at"`
}

// ephemeralState is what the agent tracks about its one run. Guarded by
// Agent.mu.
type ephemeralState struct {
	// runs counts the workloads this runner reserved: at most one.
	runs int
	// runOver is closed once the run's workload has been forgotten — its
	// outcome delivered — with nothing else running.
	runOver     chan struct{}
	runOverDone bool
	// retiredByHub is the reason of the hub's retiring bye, once one came.
	retiredByHub string
	// selfRetired is set when the runner gave up waiting for the hub.
	selfRetired string
}

// initEphemeral prepares an --ephemeral agent in New, after the root exists.
func (a *Agent) initEphemeral() error {
	if !remote.IsRunnerToken(a.token) {
		return fmt.Errorf("agent: --ephemeral needs an executor pool's runner token, which a controller " +
			"gets from the hub's pool-controller endpoint; this is not one. A permanent device enrolls " +
			"without --ephemeral")
	}
	if a.cfg.MaxConcurrent != 1 {
		// A runner takes one run; advertising more would have the hub's
		// placement believe in capacity the runner refuses.
		a.cfg.MaxConcurrent = 1
	}
	a.eph.runOver = make(chan struct{})
	entries, err := os.ReadDir(a.root)
	if err != nil {
		return fmt.Errorf("agent: --ephemeral: read the work root %s: %w", a.root, err)
	}
	if len(entries) > 0 {
		// The runner removes everything under its root when it exits, so the
		// root has to be its own: one that already holds something is
		// someone else's, or an earlier runner's that never got to wipe.
		return fmt.Errorf("agent: --ephemeral needs an empty --workdir-root of its own, which it empties again "+
			"on exit; %s holds %d entries", a.root, len(entries))
	}
	return nil
}

// reserveEphemeral is reserve's rule for a runner: one run, ever. Caller
// holds a.mu.
func (a *Agent) reserveEphemeralLocked() bool {
	if !a.cfg.Ephemeral {
		return true
	}
	if a.eph.runs >= 1 {
		return false
	}
	a.eph.runs++
	return true
}

// noteForgottenLocked marks the run over once its workload is gone and
// nothing else runs. Caller holds a.mu.
func (a *Agent) noteForgottenLocked() {
	if !a.cfg.Ephemeral || a.eph.runs == 0 || len(a.workloads) > 0 || a.eph.runOverDone {
		return
	}
	a.eph.runOverDone = true
	close(a.eph.runOver)
}

// noteRetiredByHub records the hub's retiring bye.
func (a *Agent) noteRetiredByHub(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.eph.retiredByHub == "" {
		a.eph.retiredByHub = strings.TrimSpace(reason)
		if a.eph.retiredByHub == "" {
			a.eph.retiredByHub = "retired"
		}
	}
}

// runEphemeral is Run for an --ephemeral agent.
//
// The serving context is not the caller's: cancelling a WebSocket read closes
// the link, and a runner leaving of its own accord — stopped, or done waiting
// for the hub — has one thing to say on it first. So the watcher says it, on
// the live session, and only then ends the serving context.
func (a *Agent) runEphemeral(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		a.watchEphemeral(ctx, runCtx, cancel)
	}()
	err := a.serve(runCtx)
	cancel()
	<-watched

	report := a.retirement(ctx.Err() != nil, err)
	report.WipeErrors = a.wipeEphemeral()
	report.Wiped = len(report.WipeErrors) == 0
	a.writeTerminationLog(report)
	line, _ := json.Marshal(report)
	a.cfg.logf("runner report: %s", line)
	if report.Retired {
		return nil
	}
	if err == nil {
		err = errors.New(report.Reason)
	}
	return err
}

// watchEphemeral ends the runner when it is stopped, or once its run is over
// and the hub has not retired it within the grace — saying goodbye to the hub
// first, either way.
func (a *Agent) watchEphemeral(parent, runCtx context.Context, cancel context.CancelFunc) {
	a.mu.Lock()
	over := a.eph.runOver
	a.mu.Unlock()
	grace := a.cfg.RetireGrace
	if grace <= 0 {
		grace = DefaultRetireGrace
	}
	var expired <-chan time.Time
	for {
		select {
		case <-runCtx.Done():
			// serve ended on its own: the hub retired it, or refused it.
			return
		case <-parent.Done():
			a.leave()
			cancel()
			return
		case <-over:
			over = nil
			t := time.NewTimer(grace)
			defer t.Stop()
			expired = t.C
		case <-expired:
			a.mu.Lock()
			a.eph.selfRetired = fmt.Sprintf("its run is over and reported, and the hub did not retire it within %s", grace)
			reason := a.eph.selfRetired
			a.mu.Unlock()
			a.cfg.logf("runner: %s; leaving", reason)
			a.leave()
			cancel()
			return
		}
	}
}

// leave tells the hub, on the live session if there is one, that this runner
// is going for good.
func (a *Agent) leave() {
	if sess := a.currentSession(); sess != nil {
		a.sayFarewell(sess)
	}
}

// retirement classifies how serve ended; stopped says the caller's context
// ended it.
func (a *Agent) retirement(stopped bool, err error) RetirementReport {
	a.mu.Lock()
	r := RetirementReport{ExecutorID: a.cred.AgentID, Runs: a.eph.runs, At: a.cfg.now().UTC()}
	byHub, self := a.eph.retiredByHub, a.eph.selfRetired
	running := len(a.workloads) > 0
	a.mu.Unlock()
	switch {
	case byHub != "":
		r.Retired, r.By, r.Reason = true, "hub", "the hub retired it: "+byHub
	case self != "":
		r.Retired, r.By, r.Reason = true, "self", self
	case err == nil && stopped:
		r.Retired, r.By = true, "stopped"
		switch {
		case running:
			r.Reason, r.Interrupted = "it was stopped while its run was going", true
		case r.Runs > 0:
			r.Reason = "it was stopped after its run"
		default:
			r.Reason = "it was stopped before it was handed a run"
		}
	case err != nil:
		r.By, r.Reason = "refused", strings.TrimSpace(err.Error())
	default:
		r.By, r.Reason = "refused", "the hub ended its session"
	}
	return r
}

// farewellReason is what a runner leaving of its own accord tells the hub.
func (a *Agent) farewellReason() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.eph.selfRetired != "":
		return "the runner retired itself: " + a.eph.selfRetired
	case len(a.workloads) > 0:
		return "the runner was stopped during its run"
	case a.eph.runs > 0:
		return "the runner was stopped after its run"
	}
	return "the runner was stopped before it was handed a run"
}

// sayFarewell tells the hub, on the session about to close, that this runner
// is going for good. Best effort and bounded: the process is exiting either
// way, and the hub's own grace covers a farewell that never arrives.
func (a *Agent) sayFarewell(sess *deviceSession) {
	frame, err := sess.frame(remote.TypeBye, "", "", remote.ByePayload{
		Reason: a.farewellReason(), Reconnect: false, Retired: true,
	})
	if err != nil {
		return
	}
	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sess.write(wctx, frame); err != nil {
		a.cfg.logf("runner: could not tell the hub it is leaving: %v", err)
	}
}

// wipeEphemeral destroys what an ephemeral runner held, and returns what it
// could not destroy.
func (a *Agent) wipeEphemeral() []string {
	var problems []string
	// The credential and the token, in memory. A Go string cannot be
	// overwritten in place; dropping the only references is what is possible,
	// and nothing below keeps another.
	a.mu.Lock()
	a.cred = Credential{}
	a.token = ""
	handles := make([]string, 0, len(a.workloads))
	for id := range a.workloads {
		handles = append(handles, id)
	}
	a.mu.Unlock()

	// Every workload still known is stopped first — a runner stopped during
	// its run must not leave the run going on its own, with its files about
	// to vanish under it — and then forgotten: forget is the one exit that
	// wipes a workload's credential files and releases its leases.
	for _, id := range handles {
		if a.terminateWorkload(context.Background(), id, "the runner is exiting") {
			a.awaitWorkloadEnd(id, killGrace+5*time.Second)
		}
		a.forget(id)
	}

	// The token file. In a Pod it is a read-only Secret volume, which the
	// controller deletes with the Pod; anywhere else it goes now.
	if tf := strings.TrimSpace(a.cfg.TokenFile); tf != "" {
		if err := os.Remove(tf); err != nil && !errors.Is(err, os.ErrNotExist) && !isReadOnlyFS(err) {
			problems = append(problems, fmt.Sprintf("remove the token file %s: %v", tf, err))
		}
	}

	// Everything under its work root, which was empty when it started: the
	// run's tree, its home, the lease directories, a shipped branch.
	// RemoveAll does not follow a symbolic link it meets, so a link the run
	// left there is removed, not what it points at.
	if entries, err := os.ReadDir(a.root); err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			if err := os.RemoveAll(filepath.Join(a.root, name)); err != nil {
				problems = append(problems, fmt.Sprintf("remove %s: %v", filepath.Join(a.root, name), err))
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		problems = append(problems, fmt.Sprintf("read the work root %s: %v", a.root, err))
	}
	return problems
}

// awaitWorkloadEnd waits, up to limit, for a stopped workload to finish.
func (a *Agent) awaitWorkloadEnd(handleID string, limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		wl, ok := a.workload(handleID)
		if !ok || wl.isFinished() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	a.cfg.logf("runner: workload %s did not end within %s of being stopped", handleID, limit)
}

// isReadOnlyFS reports whether err is the read-only filesystem a Secret
// volume is mounted on.
func isReadOnlyFS(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "read-only file system") ||
		errors.Is(err, os.ErrPermission))
}

// writeTerminationLog writes the report where the configured path says; a
// path that cannot be written is logged and skipped.
func (a *Agent) writeTerminationLog(r RetirementReport) {
	path := strings.TrimSpace(a.cfg.TerminationLog)
	if path == "" {
		return
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	if len(b) > maxTerminationMessage {
		// Shorten the free text rather than cut the JSON, which would leave a
		// controller with a message it cannot read.
		r.WipeErrors = r.WipeErrors[:min(len(r.WipeErrors), 3)]
		if len(r.Reason) > 1024 {
			r.Reason = r.Reason[:1024] + "…"
		}
		b, _ = json.Marshal(r)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		a.cfg.logf("runner: write the termination log %s: %v", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		a.cfg.logf("runner: write the termination log %s: %v", path, err)
	}
}
