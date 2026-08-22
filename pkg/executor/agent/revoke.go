package agent

// revoke.go is the device side of taking a credential back mid-run.
//
// The frame arrives on an established session, so it is already authenticated
// as coming from the control plane this device enrolled with. What it asks for
// is destructive but strictly narrowing: remove material, optionally stop a
// task. There is no revoke that grants anything, which is why the agent can
// honour it without a second authorisation step — the worst a hostile frame
// can achieve is denial of service against work the same control plane
// dispatched, and a control plane that wanted that could simply stop sending
// work.
//
// The one thing it must not become is a filesystem primitive. See vault.go for
// the confinement rules on the paths a revoke may name.

import (
	"context"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// killGrace is how long a revoked-and-killed workload gets to exit after
// SIGTERM before the agent escalates to SIGKILL.
//
// It is short. A revocation with action=kill means an operator has decided the
// credential is compromised and the task must stop using it; a task that
// ignores the polite signal must not be able to keep working with a revoked
// credential just by trapping SIGTERM. Five seconds is enough for a harness to
// flush its output — which the pump forwards regardless — and not enough to
// matter to an incident response.
const killGrace = 5 * time.Second

// handleRevoke honours a revoke frame and acks with what it achieved.
//
// The ack is sent on every path, including failure. Silence would be
// indistinguishable, from the control plane, from an unreachable agent — and
// the UI would then show "unreachable" for a device that is right here and
// told us exactly what went wrong.
func (a *Agent) handleRevoke(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	defer func() {
		if r := recover(); r != nil {
			a.cfg.logf("panic handling revoke: %v", r)
			a.reply(ctx, sess, remote.TypeRevoked, frame.ID, "", remote.RevokedPayload{
				Error: "the agent panicked while scrubbing this lease; treat the credential as still live",
			})
		}
	}()

	payload, err := remote.DecodeRevoke(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	action := payload.Effective()
	leaseID := strings.TrimSpace(payload.LeaseID)

	// The scrub itself. Env values are dropped from the driver's retained
	// environment, credential files are wiped and unlinked, and the egress
	// allowlist entry goes with them — all under the vault's lock, so a
	// concurrent start for the same lease serialises against it.
	report := a.vault.scrub(leaseID, payload.GrantID, a.scrubHandleEnv)

	ack := remote.RevokedPayload{
		LeaseID:       leaseID,
		GrantID:       payload.GrantID,
		Action:        action,
		Known:         report.Known,
		EnvScrubbed:   report.EnvKeys,
		FilesRemoved:  report.FilesRemoved,
		EgressDropped: report.EgressDropped,
	}
	if len(report.Errors) > 0 {
		ack.Error = strings.Join(report.Errors, "; ")
	}

	if action == remote.RevokeKill && report.Known {
		ack.Killed = a.killHolders(ctx, report.Handles, payload.Reason)
	}

	switch {
	case !report.Known:
		a.cfg.logf("revoke %s: not held by this agent (nothing to scrub)", leaseID)
	default:
		a.cfg.logf("revoke %s (%s): scrubbed %d env var(s), removed %d file(s)%s%s",
			leaseID, action, len(report.EnvKeys), report.FilesRemoved,
			killedSuffix(ack.Killed), reasonSuffix(payload.Reason))
	}

	a.reply(ctx, sess, remote.TypeRevoked, frame.ID, "", ack)
}

// scrubHandleEnv drops a workload's leased environment variables from the
// local driver's retained copies. It is the vault's envScrubber.
//
// What it can and cannot do is the sharpest limit in the whole feature: the
// child process was handed its environment by the kernel at exec time and
// keeps it. This removes the agent's references so the value is not re-read,
// re-injected on a restart, or captured in a core dump of the agent — and
// nothing more. RevokeKill exists because that is sometimes not enough.
func (a *Agent) scrubHandleEnv(handleID string, keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	wl, ok := a.workload(handleID)
	if !ok {
		return nil
	}
	localID, _ := wl.local()
	if localID == "" {
		// The workload is bound but not yet launched. Its material has not
		// reached the driver, and the bind/launch ordering in handleStart
		// means the start will observe the scrub rather than race it.
		return nil
	}
	return a.local.ScrubEnv(localID, keys)
}

// killHolders terminates every workload still holding a revoked lease.
//
// SIGTERM first so a harness can flush and exit cleanly, SIGKILL after
// killGrace so a process that traps the signal cannot outlive the revocation.
// The returned list is what was actually signalled, so the ack does not claim
// to have stopped a task that had already finished.
func (a *Agent) killHolders(ctx context.Context, handles []string, reason string) []string {
	var killed []string
	for _, handleID := range handles {
		wl, ok := a.workload(handleID)
		if !ok {
			continue
		}
		localID, _ := wl.local()
		if localID == "" {
			continue
		}
		if st := wl.snapshot(); st.State.Terminal() {
			continue
		}
		if err := a.local.Signal(ctx, localID, executor.SignalTerminate); err != nil {
			a.cfg.logf("revoke: terminate %s: %v", handleID, err)
			continue
		}
		killed = append(killed, handleID)
		a.cfg.logf("revoke: terminated %s because its credential was revoked%s",
			handleID, reasonSuffix(reason))
		go a.escalateKill(handleID, localID)
	}
	return killed
}

// escalateKill sends SIGKILL if the workload is still alive after killGrace.
//
// Detached from the revoke's context on purpose: the ack goes out immediately,
// and the escalation must not be cancelled by the request that triggered it
// returning. Bounded by killGrace either way, so it cannot leak.
func (a *Agent) escalateKill(handleID, localID string) {
	defer func() {
		if r := recover(); r != nil {
			a.cfg.logf("panic escalating kill for %s: %v", handleID, r)
		}
	}()
	timer := time.NewTimer(killGrace)
	defer timer.Stop()
	<-timer.C

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := a.local.Status(ctx, localID)
	if err != nil || st.State.Terminal() {
		return
	}
	if err := a.local.Signal(ctx, localID, executor.SignalKill); err != nil {
		a.cfg.logf("revoke: force-kill %s: %v", handleID, err)
		return
	}
	a.cfg.logf("revoke: force-killed %s after %s; it did not exit on SIGTERM", handleID, killGrace)
}

func killedSuffix(killed []string) string {
	if len(killed) == 0 {
		return ""
	}
	return ", killed " + strings.Join(killed, ", ")
}

func reasonSuffix(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return ""
	}
	return " (" + reason + ")"
}
