package ui

// shared_tree.go keeps the dashboard's helpers from preparing the directory a
// run is working in on a device (Task 20517).
//
// # The failure it removes
//
// A remote agent keeps one directory per project and starts every workload of
// the project in it. The helper subcommands the dashboard dispatches — the
// Requirements tab reading the spec file when it opens, a Split preview,
// Revise, a requirement check — went out with the project's workspace and its
// seed exactly like a run, and the device prepared the directory for each of
// them: fetched the tree into it, and placed the hub's copy of the project,
// which deletes the database it finds there.
//
// While a run worked in the directory, that database was the run's. On
// sgx-rust-attestation the run then found tasks the operator had added on the
// hub since it started, took them for tasks added on the device and worked
// through them, and came back with them as tasks it had created: the merge
// put them in beside the originals, which stayed pending and ran again. Its
// journal from before the read was gone. On a git project the read would also
// have reset the run's checkout under it.
//
// # The rule
//
// While this hub follows a run of the project in the directory the helper
// would use — same project, same device — the helper goes without a seed and
// without a tree to fetch or a branch to build: it runs on the directory as
// the run has it, which is what a helper on a host executor has always seen.
// A device whose agent knows executor.LabelWorkload holds every run it runs to
// the same rule itself; this is the hub's half, which a device on an older
// agent depends on.
//
// A reproduction checks the project out at the commit it reproduces, so it is
// refused while a run is in the directory rather than sent there.
//
// # What it costs
//
// A helper in a run's directory sees the run's copy of the project, not the
// hub's. A task added on the hub while the run works is not in it, and its ID
// may name a task the run made there. So the Split preview and the blocker
// analysis, which read the task they are about from that copy by ID, are
// refused for a task the run was not sent as it is now (runCopyDiffers). A
// model call that still fails for want of a task says why (readModelCall,
// sharedRunTreeReason) instead of "task not found".

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// keepsProjectDirectories reports whether ex starts every workload of a
// project in one directory it keeps between them: a remote agent does, and a
// virtual executor on one runs in its device's. A container on this host, a
// Pod, a pool runner's one run each get a tree of their own.
func keepsProjectDirectories(ex executor.Executor) bool {
	if ex == nil {
		return false
	}
	return deviceOfExecutor(ex).Kind() == executor.KindRemoteAgent
}

// liveRun is a run working in a project's directory on a device.
type liveRun struct {
	// handle and executor name its workload.
	handle   string
	executor string
	// tasks is what its seed held under each task ID; nil when this process
	// did not dispatch it and never saw the seed.
	tasks map[int]string
}

// runInTree returns the run carried out as a seed that works in workDir's
// directory on ex's device, when there is one this process follows: from its
// dispatch, or its adoption, until it is settled. Only on an executor that
// keeps project directories.
//
// A record whose workload its executor no longer knows, or knows to have
// ended, is no run in the directory: a dispatch that lost sight of its
// workload can leave one behind, and taking it for a run would keep every
// helper of the project on the device's old copy for good.
func runInTree(ex executor.Executor, workDir string) (liveRun, bool) {
	if !keepsProjectDirectories(ex) || strings.TrimSpace(workDir) == "" {
		return liveRun{}, false
	}
	dir, device := filepath.Clean(workDir), deviceOfExecutor(ex).ID()
	var found []liveRun
	seededMu.Lock()
	for key, d := range seeded {
		if d.workDir == "" || d.device != device || filepath.Clean(d.workDir) != dir {
			continue
		}
		exID, handle, _ := strings.Cut(key, "\x00")
		found = append(found, liveRun{handle: handle, executor: exID, tasks: d.tasks})
	}
	seededMu.Unlock()
	for _, r := range found {
		if runStillLive(r.executor, r.handle) {
			return r, true
		}
	}
	return liveRun{}, false
}

// runLivenessTimeout bounds the question runInTree puts to a run's executor.
// An executor that cannot answer in time is taken to be running it: wrongly,
// a helper sees the device's copy of the project for a while; the other way,
// it is prepared over a run.
const runLivenessTimeout = 5 * time.Second

// runStillLive reports whether handleID's workload on the executor registered
// as exID may still be running.
func runStillLive(exID, handleID string) bool {
	runEx, err := executor.Get(exID)
	if err != nil {
		// The executor is gone from this process: nothing can be sent to
		// its device through it either.
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), runLivenessTimeout)
	defer cancel()
	st, err := runEx.Status(ctx, handleID)
	switch {
	case errors.Is(err, executor.ErrHandleNotFound):
		return false
	case err != nil:
		return true
	}
	return !st.State.Terminal()
}

// shareRunTree is spec, a helper dispatched to ex for the project at workDir,
// as it must go while a run of that project works in its directory on the
// same device: in the device's directory for the project, without the seed,
// the tree to fetch or the branch to build that would prepare the directory
// over the run. Returned unchanged, with "", when no such run is followed
// here; otherwise with the run's handle. It takes a spec before or after
// applyWorkspace.
func shareRunTree(spec executor.Spec, ex executor.Executor, workDir string) (executor.Spec, string) {
	run, ok := runInTree(ex, workDir)
	if !ok {
		return spec, ""
	}
	// Already the device's name once applyWorkspace ran; DeviceWorkDir leaves
	// a relative path as it is.
	spec.WorkDir = executor.DeviceWorkDir(spec.WorkDir)
	spec.ProjectSeed, spec.HumanGates, spec.SeedStartable, spec.SeedTasks = nil, false, nil, nil
	// The device's own directory, which is what it is while the run is in
	// it: kept there, and fetched into by nobody. An agent older than the
	// rule prepares nothing for this kind but the seed, which is gone.
	spec.Workspace = executor.Workspace{Kind: executor.WorkspaceExecutor, SizeLimitMB: spec.Workspace.SizeLimitMB}
	// The caller removes the file, if there was one.
	spec.BranchBundleFile = ""
	fmt.Fprintf(os.Stderr, "[ui] %s: `cloop %s` runs on executor %s in the directory run %s works in, "+
		"on the run's copy of the project\n", workDir, subcommandName(spec.Argv), ex.ID(), run.handle)
	return spec, run.handle
}

// errRunInTree refuses a workload that must prepare a directory a run is
// working in.
var errRunInTree = errors.New("a run of this project is working in its directory")

// refuseBesideRun refuses to send a workload that prepares the project's
// directory — a reproduction, which checks out the commit it reproduces —
// while a run of the project works in that directory on ex's device. what
// says what is refused, for the message.
func refuseBesideRun(ex executor.Executor, workDir, what string) error {
	if _, ok := runInTree(ex, workDir); !ok {
		return nil
	}
	return fmt.Errorf("%w on executor %s, and %s would check the project out over the run's work there; "+
		"try again once the run ends", errRunInTree, ex.ID(), what)
}

// runCopyDiffers says why a model call about task t must not be made now, or
// "" when it may: while a run of the project works in its directory on a
// device, the call runs on the run's copy of the project and reads t from it
// by ID — and the copy has t as the hub has it only if t was in the run's seed
// with the same title and description. A task added since may have its ID
// taken there by one the run made, and the call would answer about that one.
// what names the call, for the message.
func runCopyDiffers(workDir string, t *pm.Task, what string) string {
	if t == nil {
		return ""
	}
	registerBuiltinExecutors()
	ex, err := executor.Resolve(workDir)
	if err != nil {
		// The dispatch says why, in its own words.
		return ""
	}
	run, ok := runInTree(ex, workDir)
	if !ok {
		return ""
	}
	switch digest, sent := run.tasks[t.ID]; {
	case run.tasks == nil:
		return fmt.Sprintf("a run of this project is working on executor %s, and %s would run there on the run's "+
			"own copy of the project, which this hub cannot check holds task #%d as you see it. Try again "+
			"once the run ends", ex.ID(), what, t.ID)
	case !sent || subtle.ConstantTimeCompare([]byte(digest), []byte(projectseed.TaskDigest(t))) != 1:
		return fmt.Sprintf("a run of this project is working on executor %s, and %s would run there on the run's "+
			"own copy of the project, which does not have task #%d as you see it: the task was added or "+
			"changed after the run started. Try again once the run ends", ex.ID(), what, t.ID)
	}
	return ""
}

// runTreeSharedError is a helper that ran in a run's directory (shareRunTree)
// and did not end well. It changes no message and hides nothing from
// errors.Is and errors.As: it only records where the helper ran.
type runTreeSharedError struct {
	err      error
	executor string
}

func (e *runTreeSharedError) Error() string { return e.err.Error() }
func (e *runTreeSharedError) Unwrap() error { return e.err }

// sharedRunTreeReason explains a model call that failed for want of a task,
// when it ran on a run's copy of the project: the task was added on the hub
// after the run started, so the copy the call read does not have it. ok is
// false for any other failure, which is shown as it came.
func sharedRunTreeReason(failure string, err error) (reason string, ok bool) {
	var shared *runTreeSharedError
	if !errors.As(err, &shared) || !strings.Contains(failure, statedb.ErrTaskNotFound.Error()) {
		return "", false
	}
	return fmt.Sprintf("a run of this project is working on executor %s, and this ran there on the run's "+
		"copy of the project, which does not have this task: it was added after the run started. "+
		"Try again once the run ends", shared.executor), true
}
