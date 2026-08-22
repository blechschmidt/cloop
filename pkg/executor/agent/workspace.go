package agent

// workspace.go materialises a workload's source tree on the device, before the
// harness is allowed to start.
//
// Until this existed the agent created an empty directory beneath its root and
// launched the harness there. On a remote device that is not a small bug: the
// run starts cleanly, streams a plausible transcript back to the control plane,
// and operates on no code at all. Nothing in the control plane's view
// distinguishes it from a real run.
//
// # Why this file is thin
//
// The clone itself lives in pkg/executor/gitprovision, because this device is
// not the only thing that has to do it: the Kubernetes driver runs the same
// sequence in an init container via `cloop workspace provision`. Two copies of
// "how cloop clones a repo into a sandbox" would be two chances to reintroduce
// the empty-workspace bug, and the second copy would drift silently — the
// symptom of a drifted provisioner is a run that *looks* fine.
//
// What stays here is what is genuinely the device's: where the workload's
// directory is and whether it is confined (Agent.resolveWorkDir), how long a
// fetch may take on an edge uplink, how a stop cancels one mid-clone, and how
// the provisioning output reaches the hub's live log.

import (
	"context"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
)

// workspaceProvisionTimeout bounds one workspace provisioning.
//
// A first clone of a large repository over an edge device's uplink is
// legitimately minutes, so this is generous. It exists because the alternative
// is unbounded: a fetch stalled on a half-open TCP connection would hold a
// concurrency slot and a handle the control plane believes is starting, for as
// long as the agent runs. The other way to hang — a credential prompt on a
// terminal nobody will answer — is already ruled out by executor.GitBaseEnv.
const workspaceProvisionTimeout = 30 * time.Minute

// prepareWorkspace materialises spec.Workspace before the harness starts, and
// streams what it does into the workload's log.
//
// It returns the device's own reason on failure. The caller turns that into the
// start frame's Error field, so an operator watching the run panel reads "no
// git on edge-3" or "the tree is 4 GB, over this workload's 512 MB limit"
// rather than a generic refusal from the control plane.
func (a *Agent) prepareWorkspace(ctx context.Context, wl *workload, spec executor.Spec, cred executor.GitCredential) error {
	if spec.Workspace.Kind == executor.WorkspaceBind {
		// "bind" asserts that the executor shares the control plane's
		// filesystem and the tree is already at WorkDir. A remote agent shares
		// nothing with the hub: that path names a directory on another machine,
		// and the one this device would create is empty. Refusing names the
		// placement mistake; cloning instead would invent a repository nobody
		// asked for.
		return fmt.Errorf("%w: this workload was dispatched with a bind workspace, which means the "+
			"executor is expected to already hold the tree at %q — but %s is a remote agent and "+
			"shares no filesystem with the control plane. Give the project a git workspace, or run "+
			"it on an executor that does share the host filesystem",
			executor.ErrWorkspaceUnavailable, spec.WorkDir, deviceName())
	}
	if !spec.Workspace.NeedsProvisioning() {
		return nil
	}

	// Not the frame's context, and not a detached one.
	//
	// ctx here is the agent's process lifetime, which is the right outer bound:
	// a fetch whose agent is shutting down has nowhere to report its result.
	// What it lacks is a way to abort one clone, so the cancel is published on
	// the workload — handleSignal calls it, and so does forget when the control
	// plane stops tracking the handle. The timeout covers the third case, a
	// fetch that neither finishes nor fails.
	provCtx, cancel := context.WithTimeout(ctx, workspaceProvisionTimeout)
	defer cancel()
	wl.setProvisionCancel(cancel)
	defer wl.setProvisionCancel(nil)

	// Provisioning output goes into the workload's own retained buffer, so it
	// reaches the run's live log through the same offset-acknowledged path as
	// the harness's output — including across a reconnect, since the control
	// plane already knows this handle: it named it before sending the start.
	emit := func(text string) {
		wl.buf.Append(text)
		if sess := a.currentSession(); sess != nil {
			a.flush(ctx, sess, wl)
		}
	}

	started := a.cfg.now()
	err := provisionWorkspace(provCtx, spec.WorkDir, spec.Workspace, cred, emit)
	took := a.cfg.now().Sub(started).Round(time.Millisecond)
	if err != nil {
		// Already redacted by the provisioner; logging it here is what puts the
		// reason in the device's own journal as well as in the reply.
		a.cfg.logf("workspace for %s failed after %s: %v", wl.handleID, took, err)
		return err
	}
	a.cfg.logf("workspace for %s ready in %s (%s)", wl.handleID, took, spec.Workspace.Describe())
	return nil
}

// provisionWorkspace runs the shared engine with this device's identity.
//
// dir must already exist and already be confined to this agent's root — see
// Agent.resolveWorkDir, which is the security boundary; the provisioner is the
// filesystem work that happens inside it.
//
// The only thing the device contributes is how it names itself in a diagnostic:
// an operator reading "no git on this device (edge-3)" knows which machine to
// go and fix, which a message from a generic provisioner could not tell them.
func provisionWorkspace(ctx context.Context, dir string, w executor.Workspace,
	cred executor.GitCredential, emit func(string)) error {

	return gitprovision.Provision(ctx, gitprovision.Request{
		Dir:        dir,
		Workspace:  w,
		Credential: cred,
		Emit:       emit,
		Host:       deviceName(),
	})
}

// provisionedWorkspace is what a workspace becomes once this device has
// materialised it, for the benefit of the driver that runs the harness next.
//
// The agent does not execute the harness itself; it hands the Spec to an inner
// localprocess driver. A git workspace passed down unchanged would be asking
// that driver to fetch a tree this device has just finished fetching — and it
// refuses, correctly, because a driver that runs in the host's own filesystem
// would be cloning over a checkout it does not own.
//
// "bind" is not a fudge to get past that refusal: it is the literal truth after
// provisioning. The tree is at WorkDir on the machine that is about to run, and
// that is the whole content of the assertion. The size limit is carried across
// because it still describes the workload's budget.
//
// A workspace that needed no provisioning is returned untouched — "none" means
// an intentionally empty tree, and rewriting it to bind would claim a tree that
// was never meant to exist.
func provisionedWorkspace(w executor.Workspace) executor.Workspace {
	if !w.NeedsProvisioning() {
		return w
	}
	return executor.Workspace{Kind: executor.WorkspaceBind, SizeLimitMB: w.SizeLimitMB}
}

// deviceName is what this device calls itself in a diagnostic the control plane
// will display.
func deviceName() string { return gitprovision.HostLabel("device") }
