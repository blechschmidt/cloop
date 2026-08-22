package agent

// writeback.go gets a finished task's work *off* the device — workspace.go's
// mirror image, and the other half of the same bug.
//
// Provisioning fixed a run that started against no code. Without this file the
// same run ends by throwing the code away: the harness edits the tree under the
// agent's root, exits, and the only copy of that work stays on a device the
// control plane cannot read. The transcript still describes the edits, so
// nothing in the hub's view says the work was lost.
//
// # Why this file is thin
//
// The commit-and-deliver itself lives in pkg/executor/gitwriteback, because
// this device is not the only thing that has to do it — the Kubernetes driver
// runs the same sequence via `cloop workspace writeback`. Two copies would be
// two chances to reintroduce the loss, and the drifted copy would be silent for
// the same reason a drifted provisioner is.
//
// What stays here is genuinely the device's: when the write-back runs relative
// to the harness, how the bundle is chunked onto a link that may drop, and what
// happens when it does.
//
// # Ordering
//
// The write-back runs after the harness has exited and before the terminal
// status frame is sent. Both halves matter. After, because a commit taken while
// the harness is still writing would capture a half-written file. Before,
// because the status frame is what closes the hub's log stream, and
// executor.Run reads the status the instant that stream closes — a result
// arriving afterwards would be attached to a handle whose consumer had already
// returned with nothing.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// writeBackTimeout bounds one write-back.
//
// Shorter than the provisioning timeout on purpose. A stalled clone costs a run
// that had not started; a stalled write-back holds a finished workload's slot
// while the work it is trying to deliver sits on disk, and the hub is waiting
// for a terminal status it will not get until this returns.
const writeBackTimeout = 10 * time.Minute

// performWriteBack recovers the workload's file changes and sends them to the
// control plane.
//
// It never returns an error. A write-back that fails is reported *as* the
// result — the harness ran, the task's outcome is whatever the harness decided,
// and turning a delivery failure into a workload failure would misattribute it.
// What the operator needs is for the reason to be visible, which is what the
// Err field and the emitted log line are for.
func (a *Agent) performWriteBack(ctx context.Context, wl *workload, sess *deviceSession) {
	defer func() {
		if r := recover(); r != nil {
			a.cfg.logf("panic writing back %s: %v", wl.handleID, r)
		}
	}()

	// Only a finished workload has a tree worth committing. The guard matters
	// because flushAll calls this for every workload it knows about after a
	// reconnect, including ones still running — and a commit taken while the
	// harness is mid-write would capture a half-written file and report it as
	// the task's output.
	if !wl.isFinished() {
		return
	}
	spec, ok := wl.writeBackSpec()
	if !ok || !spec.writeBack.Enabled() {
		return
	}

	emit := func(text string) {
		wl.buf.Append(text)
		if s := a.currentSession(); s != nil {
			a.flush(ctx, s, wl)
		}
	}

	wbCtx, cancel := context.WithTimeout(ctx, writeBackTimeout)
	defer cancel()

	started := a.cfg.now()
	res, err := gitwriteback.Produce(wbCtx, gitwriteback.Request{
		Dir:       spec.workDir,
		Workspace: spec.workspace,
		WriteBack: spec.writeBack,
		// The base was read before the harness ran. Re-deriving it now would
		// read whatever HEAD the harness left behind — a harness that committed
		// on its own would shrink the range to exclude its own earlier work.
		BaseSHA:    spec.baseSHA,
		Credential: spec.credential,
		ExitCode:   wl.exitCode(),
		// Every caller in the tree opts in: a harness that exited non-zero left
		// the tree mid-edit, and a half-applied refactor merged into main is
		// worse than one that was discarded, because the loss is visible and
		// the half-change is not.
		OnlyOnSuccess: true,
		Emit:          emit,
		Host:          deviceName(),
	})
	took := a.cfg.now().Sub(started).Round(time.Millisecond)
	if res.BundlePath != "" {
		defer os.Remove(res.BundlePath)
	}
	if err != nil {
		a.cfg.logf("write-back for %s failed after %s: %v", wl.handleID, took, err)
		if res.Err == "" {
			res.Err = err.Error()
		}
	} else {
		a.cfg.logf("write-back for %s in %s: %s", wl.handleID, took, res.WriteBackResult.Describe())
	}

	// The session is re-read rather than reused: producing the write-back took
	// real time, and the link the workload started on may be gone. A result
	// that cannot be sent is dropped here, and the next session's resume will
	// re-run this from the start — which is why the hub treats a chunk at
	// offset 0 as a restart rather than an overlap.
	if s := a.currentSession(); s != nil {
		sess = s
	}
	if sess == nil {
		a.cfg.logf("write-back for %s has no session to report on; it will be retried", wl.handleID)
		return
	}

	if res.Err == "" && res.Mode == executor.WriteBackBundle && res.BundlePath != "" {
		if sendErr := a.sendBundle(ctx, sess, wl, res.BundlePath, res.BundleBytes); sendErr != nil {
			a.cfg.logf("sending the bundle for %s: %v", wl.handleID, sendErr)
			// The metadata still goes out, carrying the reason. A silent drop
			// would leave the hub with a handle that reported success and
			// delivered nothing, which is the exact shape of the failure this
			// file exists to remove.
			res.Err = "the bundle could not be sent to the control plane: " + sendErr.Error()
			res.BundleBytes, res.BundleSHA256 = 0, ""
		}
	}

	a.reply(ctx, sess, remote.TypeResult, "", wl.handleID,
		remote.ResultPayload{Result: res.WriteBackResult})
	wl.markWrittenBack()
}

// sendBundle streams a bundle file to the control plane as result chunks.
//
// It reads in MaxResultChunkBytes slices rather than loading the file, because
// a bundle is bounded but not small and the device it is being read on may have
// less memory than the hub does.
func (a *Agent) sendBundle(ctx context.Context, sess *deviceSession, wl *workload,
	path string, expect int64) error {

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read the bundle back: %w", err)
	}
	defer f.Close()

	// Serialised against the output flusher for the same reason log chunks are:
	// two goroutines writing frames for one handle could interleave, and an
	// out-of-order result chunk is a refused write-back rather than a
	// re-ordered log line.
	wl.sendMu.Lock()
	defer wl.sendMu.Unlock()

	buf := make([]byte, remote.MaxResultChunkBytes)
	var offset int64
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			frame, err := sess.frame(remote.TypeResultChunk, "", wl.handleID,
				remote.ResultChunkPayload{Offset: offset, Data: buf[:n]})
			if err != nil {
				return fmt.Errorf("encoding the chunk at offset %d: %w", offset, err)
			}
			// Written directly rather than through Agent.reply, which logs a
			// send failure and swallows it. A dropped chunk is not a dropped
			// log line: the bundle would arrive with a hole and the hub would
			// refuse the whole write-back, so the error has to reach the caller
			// that can report it.
			if err := sess.write(ctx, frame); err != nil {
				return fmt.Errorf("chunk at offset %d: %w", offset, err)
			}
			offset += int64(n)
		}
		if readErr != nil {
			if readErr.Error() == "EOF" {
				break
			}
			return fmt.Errorf("reading the bundle at offset %d: %w", offset, readErr)
		}
	}
	if expect != 0 && offset != expect {
		// The file changed size between being measured and being read. Refusing
		// here means the hub is never handed a bundle whose digest was computed
		// over different bytes than the ones it received.
		return fmt.Errorf("the bundle is %d bytes but %d were measured", offset, expect)
	}
	return nil
}

// planWriteBack records what this workload will need to return its work, and
// refuses the start when the device cannot honour what the Spec asked for.
//
// Refusing at start rather than discovering it at the end is the whole point.
// A write-back that turns out to be impossible after the harness has run has
// already lost the work; one refused before it runs costs a scheduling
// decision, and the hub can place the task somewhere that can deliver.
func (a *Agent) planWriteBack(ctx context.Context, spec executor.Spec,
	cred executor.GitCredential) (*writeBackPlan, error) {

	wb := spec.WriteBack
	if !wb.Enabled() {
		return nil, nil
	}
	if err := wb.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", executor.ErrWriteBackUnavailable, err)
	}
	if !a.Capabilities().WriteBack {
		return nil, fmt.Errorf("%w: this workload asks for its changes to be written back, but "+
			"%s has no git and cannot commit them; place it on a device that does, or dispatch "+
			"it without a write-back and accept that its edits stay here",
			executor.ErrWriteBackUnavailable, deviceName())
	}
	if spec.Workspace.Kind != executor.WorkspaceGit {
		// Unreachable through Spec.Validate, which enforces the same rule. Kept
		// because this is the last place the assumption is still checkable, and
		// the failure it prevents — committing in a directory that is not the
		// project — is not one to discover from its symptoms.
		return nil, fmt.Errorf("%w: a write-back needs a git workspace to have a branch and an "+
			"origin, and this workload's workspace is %q",
			executor.ErrWriteBackUnavailable, spec.Workspace.Kind)
	}

	// The base is the tree as provisioned, read now, while it is still exactly
	// what the fetch produced.
	base, err := headSHA(ctx, spec.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read the provisioned tree's HEAD on %s, so there "+
			"would be nothing to compute the returned changes against: %v",
			executor.ErrWriteBackUnavailable, deviceName(), err)
	}
	return &writeBackPlan{
		writeBack:  wb,
		workspace:  spec.Workspace,
		workDir:    spec.WorkDir,
		baseSHA:    base,
		credential: cred,
	}, nil
}

// headSHA reads the commit a freshly provisioned tree is parked on.
func headSHA(ctx context.Context, dir string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "HEAD")
	cmd.Env = executor.GitBaseEnv()
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	sha := strings.TrimSpace(string(out))
	if err := executor.ValidateCommitSHA(sha); err != nil {
		return "", err
	}
	return sha, nil
}

// writeBackPlan is what a workload remembers about its write-back between the
// start frame and the moment the harness exits.
//
// It is held on the workload rather than re-read from the Spec because the Spec
// handed to the inner driver has been rewritten: provisionedWorkspace turns the
// git workspace into a bind one, which is the truth for running the harness and
// useless for pushing afterwards — a bind workspace has no Repo to push to.
type writeBackPlan struct {
	writeBack executor.WriteBack
	workspace executor.Workspace
	workDir   string
	// baseSHA is the commit the tree was provisioned at, read before the
	// harness was allowed to touch anything.
	baseSHA string
	// credential authenticates a push. It is held in memory for the length of
	// one workload and never written anywhere: the whole point of the broker
	// is that this material is short-lived, and a token persisted on an edge
	// device outlives every guarantee that makes it safe to lease.
	credential executor.GitCredential
}
