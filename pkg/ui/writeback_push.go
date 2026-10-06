package ui

// writeback_push.go: a run returns its work by push (executors.write_back:
// push, Task 20390).
//
// A run on an executor that does not share this hub's filesystem works in a
// clone of the project's repository on that executor. Without a write-back,
// what it changed stays there unless the run's own git pushes it. With
// executors.write_back: push, the hub asks the executor to commit what the
// run changed, once its workload has exited successfully, to a fresh branch
// cloop/run-<id> and push it to the project's origin with the workspace's own
// credential — through the git proxy's pinned session for the workspace when
// the proxy runs, so the proxy's ref policy decides the push and the device
// never holds the forge credential.
//
// That is the push the restored workspace session exists for: it happens when
// the workload ends, possibly long after a hub restart, presenting a session
// the stopped hub process minted (workspace_lease.go).
//
// The write-back is measured against an exact commit, never a branch name —
// the base has to be the commit the device started from (executor.Spec
// Validate) — so the workspace is pinned to the commit the hub's checkout
// records for origin/<branch>: the origin's tip as the hub last fetched it. A
// project whose checkout has no such ref, or none checked out, is dispatched
// as before, without a write-back, and its journal says why.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/featurehub"
	"github.com/blechschmidt/cloop/pkg/state"
)

// pushWriteBackGitTimeout bounds the hub's read of its own checkout.
const pushWriteBackGitTimeout = 15 * time.Second

// applyPushWriteBack asks ex to push the run's work back, when the hub is
// configured to and the workspace can carry it. It returns the spec and the
// workspace to dispatch, pinned when it asked; otherwise unchanged, with the
// reason on the project's journal.
func applyPushWriteBack(spec executor.Spec, ws executor.Workspace, ex executor.Executor, workDir string,
	origin gitOrigin) (executor.Spec, executor.Workspace) {
	cfg, err := controlPlaneConfig()
	if err != nil || cfg == nil || !cfg.Executors.RunWriteBackPush() {
		return spec, ws
	}
	skip := func(why string) (executor.Spec, executor.Workspace) {
		logWriteBack(workDir, "Write-back: this run's work will not be pushed back to "+ws.Repo+" — "+why+".")
		return spec, ws
	}
	switch {
	case !ex.Capabilities().SupportsWriteBack:
		return skip(fmt.Sprintf("executor %q cannot return a workload's work", ex.ID()))
	case strings.TrimSpace(ws.CredentialGrant) == "":
		return skip("no GitHub grant authorises a push to it")
	case spec.DisableNetwork:
		return skip("the sandbox has no network to push from")
	}
	sha, err := originTrackingCommit(workDir, origin.Ref)
	if err != nil {
		return skip(err.Error())
	}
	branch, err := runWriteBackBranch(time.Now())
	if err != nil {
		return skip(err.Error())
	}
	ws.Ref = sha
	spec.WriteBack = executor.WriteBack{
		Mode:    executor.WriteBackPush,
		Branch:  branch,
		Message: fmt.Sprintf("cloop: the work of a run on %s", ex.ID()),
	}
	return spec, ws
}

// originTrackingCommit returns the commit the checkout at workDir records for
// origin/<branch>: the origin's tip as this hub last fetched it, which the
// origin has, unlike a local commit that was never pushed.
func originTrackingCommit(workDir, branch string) (string, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return "", fmt.Errorf("the project's checkout has no branch checked out, so there is no origin " +
			"branch to measure the run's work against")
	}
	ctx, cancel := context.WithTimeout(context.Background(), pushWriteBackGitTimeout)
	defer cancel()
	sha, err := featurehub.TrackingCommit(ctx, workDir, branch)
	if err != nil {
		return "", fmt.Errorf("the project's checkout has no commit for origin/%s to start the run from — "+
			"fetch the origin on the hub first (%v)", branch, err)
	}
	return sha, nil
}

// runWriteBackBranch names the branch one run's work is pushed to:
// cloop/run-<UTC time>-<random>, under the cloop/ namespace every write-back
// branch must live in (executor.ValidateWriteBackBranch).
func runWriteBackBranch(now time.Time) (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("name the run's branch: %v", err)
	}
	branch := executor.WriteBackBranchPrefix + "run-" + now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
	if err := executor.ValidateWriteBackBranch(branch); err != nil {
		return "", err
	}
	return branch, nil
}

// journalPushWriteBack records on the project's journal what became of a
// run's push write-back, once the run has ended.
func journalPushWriteBack(workDir string, ex executor.Executor, st executor.Status) {
	if st.WriteBack == nil || st.WriteBack.Mode != executor.WriteBackPush || ex == nil {
		return
	}
	wb := *st.WriteBack
	details := map[string]any{"executor_id": ex.ID(), "branch": wb.Branch, "mode": string(wb.Mode)}
	var msg string
	switch {
	case wb.Err != "":
		details["error"] = wb.Err
		msg = fmt.Sprintf("Write-back: the run's work could not be pushed back from executor %q: %s", ex.ID(), wb.Err)
	case wb.CommitSHA == "":
		msg = fmt.Sprintf("Write-back: the run on executor %q changed nothing, so nothing was pushed back.", ex.ID())
	default:
		details["commit"] = wb.CommitSHA
		msg = fmt.Sprintf("Write-back: the run's work was pushed to %s at %s from executor %q.",
			wb.Branch, wb.CommitSHA, ex.ID())
	}
	state.LogEventDetails(workDir, state.EventRow{Type: state.EventWriteBack, Step: state.NoStep, Message: msg}, details)
}

// logWriteBack writes one write-back line on the project's journal.
func logWriteBack(workDir, msg string) {
	state.LogEvent(workDir, state.EventRow{Type: state.EventWriteBack, Step: state.NoStep, Message: msg})
}
