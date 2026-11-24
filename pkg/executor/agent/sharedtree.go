package agent

// sharedtree.go keeps a run's project directory from being prepared over while
// the run works in it (Task 20517).
//
// # The failure it removes
//
// This agent keeps one directory per project and starts every workload of the
// project in it: the hub's runs, and the short commands the dashboard runs
// against the project — reading its spec file when the Requirements tab
// opens, a Split preview, a requirement check. Each start prepared the
// directory: fetched the tree (a kept checkout reset to the fetched commit,
// its untracked files cleaned) and placed the hub's copy of the project,
// which deletes the database a previous workload left there.
//
// On sgx-rust-attestation a spec file read did that while a run was half way
// through its plan. The run's next look at its database found the hub's copy:
// tasks the operator had added on the hub since the run started, which the
// run took for tasks added on the device and worked through, and none of its
// own journal from before. The hub merged them back as tasks the run had
// created, beside the originals still pending there — a finished task shown
// twice, then run again. On a git project the same read would have reset the
// run's checkout, uncommitted work and all.
//
// # The rule
//
// A workload the hub labels a run (executor.LabelWorkload) holds its directory
// from its start until its outcome has been read back and its final status is
// on its way. While it does:
//
//   - a helper is started on the directory as the run has it: nothing is
//     fetched, no project state is placed, no placement record is written and
//     nothing is read back from it afterwards. It sees the project as the run
//     sees it, as a helper on a host executor always has;
//   - a second run is refused: two runs in one directory each undo the
//     other's work, whatever made the hub send it.
//
// And only one workload prepares a directory at a time. A labelled start for a
// directory another workload is still preparing waits for that to finish, then
// decides: a helper that waited for a run shares the directory the run made, a
// run that waited for a helper prepares it again. Without the wait, a run that
// started while a helper's fetch was still going would have the helper's reset
// and project state land on it a moment later — the same failure the other way
// round.
//
// A workload without the label — from a hub older than this rule — is started
// as before: the rule is the hub's statement of what a workload is, and this
// agent does not guess it from an argv.

import (
	"context"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// treeClaim is how a starting workload may use its project's directory.
type treeClaim struct {
	// share says a run works in the directory, and this helper is started on
	// it as the run has it. holder is that run's handle.
	share  bool
	holder string
	// refusal is why the start is refused; "" when it is not.
	refusal string
}

// workloadRole is what spec's labels say the workload is to its project, or
// "" when they say nothing this agent knows.
func workloadRole(labels map[string]string) string {
	switch role := strings.TrimSpace(labels[executor.LabelWorkload]); role {
	case executor.WorkloadRun, executor.WorkloadHelper:
		return role
	}
	return ""
}

// claimTree decides how wl, a workload of the given role, may work in dir,
// and records that it does — after waiting, if another workload is still
// preparing the directory. Decided and recorded under a.mu, so two starts for
// one directory see each other whichever frame arrives first. The wait ends
// early, refusing the start, when ctx ends or the workload is stopped.
func (a *Agent) claimTree(ctx context.Context, wl *workload, dir, role string) treeClaim {
	for {
		a.mu.Lock()
		claim, wait := a.treeClaimLocked(wl, dir, role)
		if wait == nil {
			if claim.refusal == "" {
				wl.tree, wl.role = dir, role
				if !claim.share {
					// Prepared by this workload, from now until markTreeReady.
					wl.preparing = make(chan struct{})
				}
			}
			a.mu.Unlock()
			return claim
		}
		a.mu.Unlock()
		if !a.awaitTree(ctx, wl, wait) {
			return treeClaim{refusal: fmt.Sprintf("this workload was stopped while it waited for another "+
				"workload of its project to finish preparing %s on %s", dir, deviceName())}
		}
	}
}

// awaitTree waits for wait to close, reporting false when ctx ends or wl is
// stopped first. A stop reaches it the way it reaches a fetch in progress:
// through the workload's provisioning cancel, which handleSignal and forget
// both call.
func (a *Agent) awaitTree(ctx context.Context, wl *workload, wait <-chan struct{}) bool {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wl.setProvisionCancel(cancel)
	defer wl.setProvisionCancel(nil)
	select {
	case <-wait:
		return true
	case <-wctx.Done():
		return false
	}
}

// treeClaimLocked is claimTree's decision: a claim, or a channel to wait on
// before deciding again. Caller holds a.mu.
func (a *Agent) treeClaimLocked(wl *workload, dir, role string) (treeClaim, <-chan struct{}) {
	if role == "" {
		return treeClaim{}, nil
	}
	var preparing <-chan struct{}
	for id, o := range a.workloads {
		if o == wl || o.tree != dir {
			continue
		}
		if o.role == executor.WorkloadRun {
			switch {
			case role == executor.WorkloadRun:
				return treeClaim{refusal: fmt.Sprintf("a run of this project is still working in %s on %s "+
					"(workload %s); two runs in one directory would each undo the other's work, so this one "+
					"was not started — wait for that run to end, or stop it", dir, deviceName(), id)}, nil
			case o.preparing != nil:
				// The run is still making the directory: shared once it has.
				return treeClaim{}, o.preparing
			default:
				return treeClaim{share: true, holder: id}, nil
			}
		}
		if o.preparing != nil && preparing == nil {
			preparing = o.preparing
		}
	}
	return treeClaim{}, preparing
}

// markTreeReady records that wl has its directory prepared: a start waiting
// for it goes on.
func (a *Agent) markTreeReady(wl *workload) {
	a.mu.Lock()
	defer a.mu.Unlock()
	endPreparingLocked(wl)
}

// releaseTree records that wl no longer holds its directory: a run whose
// outcome has been read back, its work given back, and whose final status is
// about to go out, after which the hub may start the project's next run at
// once. Caller does not hold a.mu.
func (a *Agent) releaseTree(wl *workload) {
	a.mu.Lock()
	defer a.mu.Unlock()
	endPreparingLocked(wl)
	wl.tree, wl.role = "", ""
}

// endPreparingLocked ends wl's preparing of its directory, if it was. Caller
// holds a.mu.
func endPreparingLocked(wl *workload) {
	if wl.preparing != nil {
		close(wl.preparing)
		wl.preparing = nil
	}
}
