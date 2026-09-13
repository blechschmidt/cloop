package localprocess

// revoke.go implements executor.Revoker for the host-process driver.
//
// The machinery was already here — scrub.go has dropped a lease's environment
// variables out of this driver's retained copies since Task 20178 — but it was
// reachable only from pkg/executor/agent, which called it on behalf of a remote
// agent revoking its own local work. The hub's own host driver had no
// revocation entry point at all, so a lease placed on it could not be withdrawn
// even though every piece needed to withdraw it was in this package.
//
// # What a revocation reaches here, and what it does not
//
//   - Environment variables are dropped from this driver's retained copies —
//     the exec.Cmd's Env and the recorded Spec — so they are never re-read and
//     do not sit in the hub's heap for the life of the handle. The *running
//     child* kept its own copy from fork time and no API can take that back.
//     This is exactly the remote agent's situation, and it is reported the same
//     way: EnvScrubbed names what the control plane dropped, and RevokeKill is
//     what an operator uses when the credential itself is compromised.
//
//   - Credential files are wiped. Unlike the container driver, this one stages
//     nothing: the files were written by the hub's own broker, and the binding
//     names them. Wiping the paths the binding names is therefore the whole of
//     the file revocation on this backend.
//
// This driver deliberately does *not* escalate a scrub into a kill the way the
// container and Kubernetes drivers do. Those two escalate because they hold a
// durable second copy of the environment — a container config in the runtime's
// store, a Pod object in etcd — that only destroying the workload removes. A
// forked child has no such copy, so killing it would buy nothing that scrubbing
// has not already bought, at the cost of the run.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/securewipe"
)

// This driver is a Revoker. The assertion is load-bearing: placement refuses
// any workload carrying revocable credentials on a driver that does not
// implement this interface, so a signature drift here would take host execution
// out of service for leased work rather than fail a build.
var _ executor.Revoker = (*Executor)(nil)

// SupportsRevocation reports whether a revocation issued now would be honoured.
// Always true: the process, its environment and its credential files are all on
// this machine, owned by this process.
func (e *Executor) SupportsRevocation() bool { return true }

// HoldsLease reports whether any process this executor tracks was started with
// material from leaseID.
func (e *Executor) HoldsLease(leaseID string) bool { return e.leases.Holds(leaseID) }

// Leases lists the lease IDs this executor is holding material for.
func (e *Executor) Leases() []string { return e.leases.Leases() }

// Revocations reports this executor's revocation log for the Secrets panel.
func (e *Executor) Revocations() []executor.RevokeOutcome { return e.revocations.Snapshot() }

// RevokeLease takes one lease's material back from every process holding it.
func (e *Executor) RevokeLease(ctx context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
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

	ack := executor.RevokeReport{LeaseID: out.LeaseID, GrantID: out.GrantID, Action: out.Action}

	// Handles this driver adopted from a persisted row that did not record its
	// lease bindings. They might be holding the lease being revoked and there
	// is no second authority to ask — unlike the remote driver, whose agent
	// answers for its own device, the index below is the *only* record
	// that a host process was ever given a credential. So the doubt
	// travels onto the report, which turns the outcome failed: an operator
	// reading "revoked" here has to be able to act on it.
	unresolved := e.leases.UnresolvedError()

	held := e.leases.Handles(req)
	if len(held) == 0 {
		// Not holding it is a success: "the material is not here" is the end
		// state the revocation asked for, and Known says which of the two
		// happened.
		e.settle(&out, ack, unresolved)
		return out
	}
	ack.Known = true

	var errs []error
	for _, handleID := range executor.SortedHandles(held) {
		bindings := held[handleID]

		ack.EnvScrubbed = append(ack.EnvScrubbed, e.ScrubSpecSecrets(handleID, bindings)...)

		removed, err := wipeBindingFiles(bindings)
		ack.FilesRemoved += removed
		if err != nil {
			errs = append(errs, fmt.Errorf("handle %s: %w", handleID, err))
		}

		if req.Effective() != executor.RevokeKill {
			continue
		}
		if killErr := e.Signal(ctx, handleID, executor.SignalKill); killErr != nil {
			errs = append(errs, fmt.Errorf("handle %s: kill: %w", handleID, killErr))
			continue
		}
		ack.Killed = append(ack.Killed, handleID)
		e.leases.Release(handleID)
	}
	e.settle(&out, ack, errors.Join(append(errs, unresolved)...))
	return out
}

// settle finalises an outcome and its log entry from one report.
func (e *Executor) settle(out *executor.RevokeOutcome, ack executor.RevokeReport, err error) {
	if err != nil {
		ack.Error = err.Error()
	}
	at := time.Now()
	e.revocations.Settle(out.LeaseID, out.GrantID, ack, at)
	out.AckedAt, out.Ack = at, &ack
	if ack.Error != "" {
		out.State, out.Error = executor.RevokeStateFailed, ack.Error
		return
	}
	out.State = executor.RevokeStateRevoked
}

// wipeBindingFiles zeroes and unlinks the credential files a lease delivered.
//
// The paths come from the binding rather than from anything this driver wrote,
// because on this backend the broker writes them directly: the workload runs on
// the hub's own filesystem, so the lease directory it materialised is already
// the one the process reads.
//
// # Why the confinement check is here
//
// A list of paths plus an unlink is an arbitrary-file-deletion primitive, and a
// binding is a value that travels — it is built on the hub today, but the same
// struct crosses a process boundary on the remote path and this driver is what
// pkg/executor/agent runs on the far side of it. The agent's own vault refuses
// any path whose parent is not named `cloop-lease-*` and reports the refusal
// rather than skipping it silently; this does the same, because a second
// implementation of the same operation with the check left out is how the
// guarantee ends up depending on which code path reached the disk.
//
// securewipe.File does not apply this rule itself — it checks only that the
// target is a regular file and not a symlink — so the caller has to. Only
// securewipe.Dir enforces the prefix.
func wipeBindingFiles(bindings []executor.SecretBinding) (int, error) {
	var (
		errs    []error
		removed int
	)
	for _, b := range bindings {
		for _, path := range b.Files {
			if !securewipe.IsLeaseDir(filepath.Dir(path)) {
				// Reported, never skipped quietly: "I did not delete your
				// credential file" is something the operator has to be told,
				// and a path that reaches here from outside a lease directory
				// is evidence of a problem rather than a stray argument.
				errs = append(errs, fmt.Errorf(
					"refusing to unlink %s: it is not inside a %s* directory", path, securewipe.LeaseDirPrefix))
				continue
			}
			if err := securewipe.File(path); err != nil {
				errs = append(errs, fmt.Errorf("wipe %s: %w", path, err))
				continue
			}
			removed++
		}
		if dir := strings.TrimSpace(b.Dir); dir != "" && securewipe.IsLeaseDir(dir) {
			if err := securewipe.Dir(dir); err != nil {
				errs = append(errs, fmt.Errorf("remove lease dir %s: %w", dir, err))
			}
		}
	}
	return removed, errors.Join(errs...)
}
