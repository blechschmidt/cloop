package remote

// workspace.go is the control plane's half of getting a source tree onto a
// device.
//
// The device does the work — only it knows its own filesystem, and only it can
// enforce confinement on the directory it clones into — so what is left here is
// everything that must *not* happen on the device: deciding whether this agent
// can be trusted with the job at all (see MinWorkspaceVersion), leasing the
// credential for exactly the length of one dispatch, and writing the audit rows
// that say which grant fetched which repository onto which machine.
//
// The credential's whole lifetime on this side is one function call. It is
// leased in Executor.Start, marshalled into one frame, and released the moment
// the agent answers — never stored on the Executor, never in a Spec, never in a
// log line.

import (
	"context"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// leaseWorkspace obtains the credential this spec's workspace fetch needs.
//
// The returned release function is always non-nil so a caller can defer it
// unconditionally, and it is a no-op on every path where nothing was leased —
// including the error paths, where the lease has already been given back before
// this returns. A lease held open for a workload that will not start is a
// credential the broker believes is out in the world.
func (e *Executor) leaseWorkspace(ctx context.Context, spec executor.Spec) (executor.GitCredential, func(), error) {
	noop := func() {}
	if !spec.Workspace.RequiresCredential() {
		// Either not a git workspace at all, or a public repository. Neither
		// needs a lease, and minting one anyway would put a token on the wire
		// for a fetch that will not present it.
		return executor.GitCredential{}, noop, nil
	}

	src := e.opts.Workspace
	if src == nil {
		// The spec names a grant and this control plane has no broker wired in.
		// Raising the same typed error the broker itself would raise keeps the
		// operator's next step identical whichever half is missing, instead of
		// making "no source configured" a distinct mystery.
		repoPath, _ := spec.Workspace.RepoPath()
		return executor.GitCredential{}, noop, &executor.WorkspaceGrantError{
			Repo:        spec.Workspace.Repo,
			RepoPath:    repoPath,
			Grant:       strings.TrimSpace(spec.Workspace.CredentialGrant),
			ExecutorID:  e.id,
			ProjectPath: projectOf(spec),
			Reason: "this control plane has no secret broker configured, so no grant can be " +
				"leased for the fetch",
		}
	}

	cred, release, err := src.ForWorkspace(ctx, projectOf(spec), spec.Workspace)
	if release == nil {
		// The interface promises non-nil, but a caller of Start must not
		// segfault because someone's source forgot.
		release = noop
	}
	if err != nil {
		release()
		// Returned unchanged. A *executor.WorkspaceGrantError names the
		// repository, the grant and the command that creates it, and callers
		// several layers up (the run panel, the placement error) match it with
		// errors.As — wrapping it here would keep errors.As working but bury
		// the remediation behind two prefixes nobody needs.
		return executor.GitCredential{}, noop, err
	}
	return cred, release, nil
}

// auditWorkspaceStart emits the provisioning start row and returns the function
// that emits its end row.
//
// Two rows rather than one because the interesting question after an incident
// is how long a credential was in use against an external service, and a single
// row written after the fact cannot answer it. The end function takes the
// dispatch's error so the row records the outcome rather than merely the
// attempt.
func (e *Executor) auditWorkspaceStart(handleID string, spec executor.Spec, cred executor.GitCredential) func(error) {
	ev := executor.WorkspaceEvent{
		Phase:        executor.WorkspaceProvisionStart,
		ExecutorID:   e.id,
		ExecutorKind: executor.KindRemoteAgent,
		HandleID:     handleID,
		ProjectPath:  projectOf(spec),
		Workspace:    spec.Workspace,
		GrantID:      cred.GrantID,
		LeaseID:      cred.LeaseID,
	}
	executor.AuditWorkspace(ev)

	started := e.opts.now()
	secrets := cred.Secrets()
	return func(err error) {
		ev.Phase = executor.WorkspaceProvisionEnd
		ev.DurationMS = e.opts.now().Sub(started).Milliseconds()
		if err != nil {
			// The device redacts its own output before it reaches the started
			// frame, but an error assembled on this side could still quote the
			// payload the credential travelled in. Audit rows are durable, so
			// this is the last place to catch that.
			ev.Err = executor.RedactSecrets(err.Error(), secrets)
		}
		executor.AuditWorkspace(ev)
	}
}

// projectOf names the project a spec belongs to, for the lease request and the
// audit row.
//
// It mirrors the Kubernetes driver's convention — the "project" label, falling
// back to the working directory — so one workload has one identity in the audit
// trail no matter which driver ran it.
func projectOf(spec executor.Spec) string {
	if p := strings.TrimSpace(spec.Labels["project"]); p != "" {
		return p
	}
	return strings.TrimSpace(spec.WorkDir)
}

// SupportsWorkspaceProvisioning reports whether the currently attached agent
// can materialise a git workspace: it must have advertised the capability *and*
// speak a protocol version that can carry the credential. False for a
// disconnected executor, since with no session there is nothing to ask.
func (e *Executor) SupportsWorkspaceProvisioning() bool {
	sess := e.currentSession()
	if sess == nil {
		return false
	}
	return SupportsWorkspaceProvisioning(sess.Version()) && e.AgentCapabilities().WorkspaceProvisioning
}

// describeWorkspace renders a spec's workspace for a log line. It can never
// contain a credential — executor.Workspace has no field that could hold one.
func describeWorkspace(spec executor.Spec) string {
	if spec.Workspace.IsZero() {
		return ""
	}
	return fmt.Sprintf(" (workspace: %s)", spec.Workspace.Describe())
}
