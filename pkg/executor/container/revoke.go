package container

// revoke.go implements executor.Revoker for the container driver: taking a
// secret lease's material back from a sandbox that is already running.
//
// # Why this needed writing at all
//
// The staging code in secrets.go has always ended with a comment explaining
// that two leases must not share a staging directory, "or a revocation of
// either would take both". The revocation it was guarding against did not
// exist. Nothing in this driver had ever consulted Spec.RevocableSecrets, this
// driver exposed no revocation entry point, and the Executors panel reported
// every non-remote driver as revocable on the theory that the hub owns their
// filesystem — true of the directory, and silent about whether any code wipes
// it. A GitHub PAT or a kubeconfig leased to a local container sandbox could
// not be withdrawn until the task ended on its own.
//
// # What a revocation can and cannot reach here
//
// The two delivery modes have genuinely different strengths, and the report
// says which one applied rather than averaging them into "revoked":
//
//   - Files are genuinely gone. The staging directory is bind-mounted into the
//     sandbox, so the container's view is the same inode as the host's:
//     unlinking on this side is what makes the next read inside the sandbox
//     fail. This is the strong case and it covers the credentials that matter
//     most — kubeconfigs and the git credential helper's token file.
//
//   - Environment variables cannot be scrubbed. The workload received its
//     environment from the kernel at exec time and no API reaches into another
//     process's memory; worse, the runtime keeps its own copy in the container
//     config on disk, which `podman inspect` will print for as long as the
//     container exists. So env-borne material is revoked the only way it can
//     be — `rm --force`, which kills the process and deletes the config with
//     it — and the report says Killed rather than EnvScrubbed. Claiming a
//     scrub here would be exactly the lie this file exists to remove.
//
// That escalation applies even to RevokeScrub. The operator asked for the
// gentler action; the gentler action is not available for this material; doing
// nothing and reporting success is the only worse answer than killing. The
// kill is reported, so the escalation is visible rather than surprising.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// This driver is a Revoker. The assertion is load-bearing: placement refuses
// any workload carrying revocable credentials on a driver that does not
// implement this interface, so a signature drift here would take the container
// backend out of service for leased work rather than fail a build.
var _ executor.Revoker = (*Executor)(nil)

// SupportsRevocation reports whether a revocation issued now would be honoured.
//
// Always true for this driver. Unlike a remote agent — which can be offline,
// or too old to understand the frame — the sandbox runs on this host, its
// credential files are in a directory this process created, and the runtime
// that would have to kill it is the one already being used to start it. There
// is no third party whose availability the guarantee depends on.
func (e *Executor) SupportsRevocation() bool { return true }

// HoldsLease reports whether any container this executor tracks was started
// with material from leaseID.
func (e *Executor) HoldsLease(leaseID string) bool { return e.leases.Holds(leaseID) }

// Leases lists the lease IDs this executor is holding material for.
func (e *Executor) Leases() []string { return e.leases.Leases() }

// Revocations reports this executor's revocation log for the Secrets panel.
func (e *Executor) Revocations() []executor.RevokeOutcome { return e.revocations.Snapshot() }

// RevokeLease takes one lease's material back from every container holding it.
//
// It returns an outcome rather than an error for the reason the remote driver
// documents: the caller's next move depends on which failure, and an error
// alone cannot say whether the material is gone, in doubt, or still out there.
// The log entry is written before any wiping starts, so a revocation is never
// lost to a crash between the two.
func (e *Executor) RevokeLease(ctx context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	if ctx == nil {
		ctx = context.Background()
	}
	now := e.now()
	out := executor.RevokeOutcome{
		LeaseID:    strings.TrimSpace(req.LeaseID),
		GrantID:    strings.TrimSpace(req.GrantID),
		ExecutorID: e.id,
		Action:     req.Effective(),
		Reason:     req.Reason,
		State:      executor.RevokeStatePending,
		SentAt:     now,
	}
	if out.LeaseID == "" {
		out.State = executor.RevokeStateFailed
		out.Error = "revoke requires a lease id"
		return out
	}
	e.revocations.Record(out)

	ack := executor.RevokeReport{
		LeaseID: out.LeaseID,
		GrantID: out.GrantID,
		Action:  out.Action,
	}

	// Handles this driver adopted from a persisted row that did not record its
	// lease bindings. They might be holding the lease being revoked and there
	// is no second authority to ask — unlike the remote driver, whose agent
	// answers for its own device, the index below is the *only* record
	// that a container was ever given a credential. So the doubt
	// travels onto the report, which turns the outcome failed: an operator
	// reading "revoked" here has to be able to act on it.
	unresolved := e.leases.UnresolvedError()

	held := e.leases.Handles(req)
	if len(held) == 0 {
		// Not holding it is a success, not a failure: "the material is not
		// here" is the end state the revocation asked for. Known says which
		// of the two happened, so an operator can tell "wiped it" from
		// "there was nothing to wipe" — the difference matters when the
		// question is where a leaked credential went.
		e.settle(&out, ack, unresolved)
		return out
	}
	ack.Known = true

	var errs []error
	for _, handleID := range executor.SortedHandles(held) {
		removed, killed, err := e.revokeHandle(ctx, handleID, held[handleID], req)
		ack.FilesRemoved += removed
		if killed {
			ack.Killed = append(ack.Killed, handleID)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	e.settle(&out, ack, errors.Join(append(errs, unresolved)...))
	return out
}

// settle finalises an outcome and its log entry from one report.
func (e *Executor) settle(out *executor.RevokeOutcome, ack executor.RevokeReport, err error) {
	if err != nil {
		ack.Error = err.Error()
	}
	at := e.now()
	e.revocations.Settle(out.LeaseID, out.GrantID, ack, at)
	out.AckedAt, out.Ack = at, &ack
	if ack.Error != "" {
		out.State, out.Error = executor.RevokeStateFailed, ack.Error
		return
	}
	out.State = executor.RevokeStateRevoked
}

// revokeHandle takes req's material back from one container.
//
// It reports files wiped and whether the container had to be terminated, so
// the caller can assemble one report across every handle the lease reached.
func (e *Executor) revokeHandle(ctx context.Context, handleID string,
	bindings []executor.SecretBinding, req executor.RevokeRequest) (removed int, killed bool, err error) {

	rec, lookupErr := e.lookup(handleID)
	if lookupErr != nil {
		// The handle went away between the index read and here — the workload
		// finished, and finish() wiped its stage. Nothing to do and nothing
		// wrong; drop the stale index entry so a second revocation does not
		// chase it again.
		e.leases.Release(handleID)
		return 0, false, nil
	}

	var errs []error
	if removed, err = rec.secretStage.revoke(req); err != nil {
		errs = append(errs, fmt.Errorf("handle %s: %w", handleID, err))
	}

	// Env-borne material forces termination: see the file header. An explicit
	// RevokeKill forces it regardless of how the material was delivered,
	// because that action exists for a credential that is compromised rather
	// than merely over-granted.
	envKeys := executor.EnvKeys(bindings)
	if len(envKeys) == 0 && req.Effective() != executor.RevokeKill {
		return removed, false, errors.Join(errs...)
	}

	reason := fmt.Sprintf("secret lease %s revoked", req.LeaseID)
	if len(envKeys) > 0 && req.Effective() != executor.RevokeKill {
		reason = fmt.Sprintf(
			"secret lease %s revoked; %s was delivered as an environment variable, which cannot be "+
				"scrubbed from a running process", req.LeaseID, strings.Join(envKeys, ", "))
	}

	// `rm --force` rather than a kill signal: a stopped container still holds
	// the environment in the runtime's own config on disk, so stopping the
	// process would leave the credential readable by `inspect`. Removing it is
	// the only form of this operation that actually takes the material back.
	//
	// The cause is recorded before the removal and the death is claimed only
	// after it, which is why these are two calls rather than markKilled.
	//
	// Recording the cause first is not optional: `rm --force` makes the
	// container vanish, the reaper's `wait` then fails with "no such
	// container", and it can reach finish before this goroutine resumes. A
	// cause written after the removal would lose that race and the run would
	// be filed as "failed: could not be waited on" — erasing the one fact the
	// transcript had to keep, that a withdrawn credential killed it.
	//
	// Claiming the death only after it is equally deliberate: a container whose
	// removal failed is still running and still holding the credential, and a
	// record marked killed would have the panel report the sandbox as gone
	// while it keeps using a revoked token.
	rec.requestKill(reason)
	if !e.removeContainer(ctx, rec.name) {
		rec.abandonKill()
		errs = append(errs, fmt.Errorf(
			"handle %s: could not remove container %s; the workload may still hold %s",
			handleID, rec.name, executor.DescribeBindings(bindings)))
		return removed, false, errors.Join(errs...)
	}
	// The pump notices the container is gone and runs finish(), which releases
	// the index entry and wipes whatever the stage still held. Released here
	// too so a second revocation arriving before the pump catches up does not
	// try to kill a container that is already gone.
	e.leases.Release(handleID)
	return removed, true, errors.Join(errs...)
}
