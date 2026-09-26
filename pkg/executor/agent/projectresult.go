package agent

// projectresult.go sends a seeded run's changes back to the control plane
// (Task 20339) — the return half of the project seed.
//
// The hub sends the project with the start frame because this device cannot
// read the hub's database. For the same reason the hub cannot read this
// device's: once `cloop run` has recorded its outcomes in the workspace and
// exited, nothing but this frame carries them to the database the dashboard
// renders. Before it existed a remote run could finish its task and the
// dashboard would still show the task pending, and the next start ran it again.
//
// # Ordering
//
// The same slot as the write-back, for the same reasons: after the harness has
// exited, because the database is only final then, and before the terminal
// status, because that frame closes the hub's log stream and the hub settles
// the run — merges its result — the moment the stream closes.
//
// # Placement
//
// A seeded workload is also told where it is running. The orchestrator stamps
// every task it starts with the executor it finds in .cloop/sandbox-run.json —
// a record the hub writes into the project directory, which is a directory this
// device cannot see. Without a copy here the run concluded it was a bare local
// process and said so on every task ("executor local, isolation none"), which
// is precisely the claim the dashboard exists to flag as host execution. The
// hub does not believe the device's account either way — it stamps its own
// dispatch record when it merges — but the run's own journal and notes should
// not be wrong.

import (
	"context"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// maxProjectResultErrLen bounds the reason sent when there is no result. The
// hub refuses a longer one as a protocol error, which would lose the reason
// altogether.
const maxProjectResultErrLen = 2000

// recordSeed remembers the project this workload was started with.
func (w *workload) recordSeed(seed []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seed = seed
}

// projectReturn reports what returnProjectState needs, and whether there is
// anything left to do.
func (w *workload) projectReturn() (seed []byte, dir string, cached *remote.ProjectResultPayload, pending bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.seed) == 0 || w.projectReturned || !w.finished {
		return nil, "", nil, false
	}
	return w.seed, w.workDir, w.projectResult, true
}

func (w *workload) cacheProjectResult(p remote.ProjectResultPayload) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.projectResult = &p
}

func (w *workload) markProjectReturned() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.projectReturned = true
	// The seed and the reading are only needed until delivery; a finished
	// workload is retained until its status goes out, and these are the two
	// largest things it holds.
	w.seed = nil
	w.projectResult = nil
}

// recordPlacement writes the device's own placement record into a seeded
// workspace, so the run attributes its tasks to this executor. See the package
// comment above. Best-effort: a missing record costs the run's notes their
// accuracy, not the run.
func (a *Agent) recordPlacement(wl *workload, dir string, spec executor.Spec) {
	rec := artifact.SandboxRecord{
		ExecutorID:   a.AgentID(),
		ExecutorKind: executor.KindRemoteAgent,
		Isolation:    string(executor.IsolationRemote),
		RunID:        strings.TrimSpace(spec.Labels[executor.LabelRunID]),
		StartedAt:    a.cfg.now(),
	}
	if _, err := artifact.WriteSandboxRun(dir, rec); err != nil {
		a.cfg.logf("workload %s: could not record where it runs (%v); its tasks will be "+
			"attributed as local on this device's side", wl.handleID, err)
	}
}

// returnProjectState reads back what a finished, seeded run changed and sends it
// to the control plane. It never returns an error: a result that cannot be read
// is reported *as* the result, carrying the reason, because the hub's journal
// is where an operator will look for why the dashboard did not update.
func (a *Agent) returnProjectState(ctx context.Context, wl *workload, sess *deviceSession) {
	defer func() {
		if r := recover(); r != nil {
			a.cfg.logf("panic returning the project state of %s: %v", wl.handleID, r)
		}
	}()

	seed, dir, cached, pending := wl.projectReturn()
	if !pending || sess == nil {
		return
	}
	if !remote.SupportsProjectResult(sess.version) {
		// A hub below v13 has no handler for the frame and would answer it
		// with a protocol error — and, predating the merge, would have nothing
		// to do with a result anyway. Nothing is lost by not sending, and
		// marking it done keeps a reconnect from trying again.
		wl.markProjectReturned()
		return
	}

	payload := cached
	if payload == nil {
		started := a.cfg.now()
		redact := wl.redactor()
		p := remote.ProjectResultPayload{}
		data, err := projectseed.Harvest(dir, seed, redact.String)
		if err != nil {
			reason := redact.String(err.Error())
			if len(reason) > maxProjectResultErrLen {
				reason = reason[:maxProjectResultErrLen]
			}
			p.Err = reason
			a.cfg.logf("workload %s: could not read the run's changes back: %s", wl.handleID, reason)
		} else {
			p.Data = data
			a.cfg.logf("workload %s: read the run's changes back in %s (%d bytes)",
				wl.handleID, a.cfg.now().Sub(started).Round(time.Millisecond), len(data))
		}
		wl.cacheProjectResult(p)
		payload = &p
	}

	frame, err := sess.frame(remote.TypeProjectResult, "", wl.handleID, *payload)
	if err != nil {
		a.cfg.logf("workload %s: encode the project result: %v", wl.handleID, err)
		return
	}
	// Serialised with the output flusher, like every other frame for this
	// handle: the hub settles the run when its status arrives, and this frame
	// must not overtake the output that precedes it.
	wl.sendMu.Lock()
	err = sess.write(ctx, frame)
	wl.sendMu.Unlock()
	if err != nil {
		a.cfg.logf("workload %s: send the project result: %v; it will be re-sent after the next reconnect",
			wl.handleID, err)
		return
	}
	wl.markProjectReturned()
}
