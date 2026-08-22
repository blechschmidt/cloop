package remote_test

// Control-plane-side revocation tests, driven with a scripted peer.
//
// These cover the parts of revocation that only the hub can get wrong: the
// version rule that keeps revocable material off an agent too old to give it
// back, the ack-state machine the Secrets panel renders, and the replay that
// stops an unplugged device from reconnecting with a credential the operator
// already withdrew. The end-to-end behaviour on the device — files actually
// unlinked, tasks actually killed — is in revoke_e2e_test.go, against a real
// agent.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// leasedSpec is a workload carrying revocable brokered material.
func leasedSpec(dir, leaseID string) executor.Spec {
	return executor.Spec{
		WorkDir: dir,
		Argv:    []string{"sleep", "60"},
		Env:     []string{"GITHUB_TOKEN=ghp_secret", "PATH=/usr/bin"},
		Secrets: []executor.SecretBinding{{
			LeaseID:    leaseID,
			GrantID:    "grant_1",
			SecretName: "github-ci",
			Kind:       "github_pat",
			EnvKeys:    []string{"GITHUB_TOKEN"},
		}},
	}
}

// helloAt builds an agent hello advertising a specific protocol version.
func helloAt(version int) remote.HelloPayload {
	return remote.HelloPayload{
		ProtocolVersion: version,
		AgentID:         "agent-1",
		Name:            "edge-1",
		Capabilities:    remote.AgentCapabilities{OS: "linux", Arch: "amd64"},
	}
}

// answerRevoke replies to the next revoke frame with the given ack, and
// reports what the hub actually sent.
func answerRevoke(t *testing.T, p *peer, ack remote.RevokedPayload) chan remote.RevokePayload {
	t.Helper()
	got := make(chan remote.RevokePayload, 1)
	go func() {
		f := p.readUntil(remote.TypeRevoke)
		payload, err := remote.DecodeRevoke(f)
		if err != nil {
			t.Errorf("decode revoke: %v", err)
			close(got)
			return
		}
		got <- payload
		ack.LeaseID = payload.LeaseID
		reply, err := remote.NewFrame(remote.TypeRevoked, f.ID, "", ack)
		if err != nil {
			t.Errorf("build revoked: %v", err)
			return
		}
		p.write(reply)
	}()
	return got
}

// TestOldAgentIsRefusedRevocableWorkload is the version-negotiation rule.
//
// A v1 agent must still connect and still run ordinary work — stranding a
// fleet mid-upgrade over a capability most workloads do not need would be a
// worse failure than the one being prevented. What it must not receive is a
// workload whose credentials the control plane has promised it can take back,
// because it has no frame with which to honour that promise.
func TestOldAgentIsRefusedRevocableWorkload(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(1), nil)
	defer sess.Close()

	if sess.Version() != 1 {
		t.Fatalf("negotiated version = %d, want 1 (the agent's maximum)", sess.Version())
	}
	if ex.SupportsRevocation() {
		t.Error("a v1 session must not claim to support revocation")
	}

	_, err := ex.Start(context.Background(), leasedSpec(t.TempDir(), "lease_abc"))
	if !errors.Is(err, remote.ErrRevocationUnsupported) {
		t.Fatalf("Start error = %v, want ErrRevocationUnsupported", err)
	}
	// The diagnostic is what an operator reads in the Executors panel, so it
	// has to name the device, the credential, and the fix rather than saying
	// "unsupported".
	for _, want := range []string{"edge-1", "github-ci", "v1", "install --upgrade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q; got %q", want, err)
		}
	}

	// And the refusal is specific to revocable material: the same device runs
	// ordinary work, which is the whole point of keeping MinProtocolVersion
	// at 1.
	plain := executor.Spec{WorkDir: t.TempDir(), Argv: []string{"sleep", "60"}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f := p.readUntil(remote.TypeStart)
		reply, _ := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle,
			remote.StartedPayload{HandleID: f.Handle, StartedAt: time.Now()})
		p.write(reply)
	}()
	if _, err := ex.Start(context.Background(), plain); err != nil {
		t.Fatalf("a v1 agent must still accept work with no revocable secrets: %v", err)
	}
	<-done
}

// TestRevokeSendsFrameAndRecordsAck walks the happy path and checks that the
// ack — not the send — is what flips the state to revoked.
func TestRevokeSendsFrameAndRecordsAck(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	startLeased(t, ex, p, "lease_abc")
	if !ex.HoldsLease("lease_abc") {
		t.Fatal("the executor should record the lease its workload was started with")
	}

	sent := answerRevoke(t, p, remote.RevokedPayload{
		Known:        true,
		EnvScrubbed:  []string{"GITHUB_TOKEN"},
		FilesRemoved: 1,
	})

	res := ex.RevokeLease(context.Background(), remote.RevokePayload{
		LeaseID: "lease_abc",
		Reason:  "operator revoked the grant",
		Action:  remote.RevokeScrub,
	})

	got := <-sent
	if got.LeaseID != "lease_abc" {
		t.Errorf("revoke carried lease %q, want lease_abc", got.LeaseID)
	}
	if got.Reason != "operator revoked the grant" {
		t.Errorf("reason not carried to the device; got %q", got.Reason)
	}
	if got.Effective() != remote.RevokeScrub {
		t.Errorf("action = %q, want scrub", got.Effective())
	}

	if res.State != remote.RevokeStateRevoked {
		t.Fatalf("state = %q, want revoked (error=%q)", res.State, res.Error)
	}
	if res.Ack == nil || res.Ack.FilesRemoved != 1 {
		t.Errorf("the agent's report should reach the caller verbatim; got %+v", res.Ack)
	}
	if res.AckedAt.IsZero() {
		t.Error("an acked revocation must be timestamped, so an incident can bound the exposure")
	}
	if len(ex.Revocations()) != 1 {
		t.Errorf("the revocation log should hold one entry, got %d", len(ex.Revocations()))
	}
}

// TestRevokeOnOfflineAgentIsUnreachableNotRevoked is the honesty test.
//
// When the device cannot be reached the credential is still on it. Reporting
// success would let an operator close an incident on a live token, so the
// result must say unreachable and the revocation must be retained for replay.
func TestRevokeOnOfflineAgentIsUnreachableNotRevoked(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	startLeased(t, ex, p, "lease_abc")

	// The device drops off. Its workload keeps running on the far side, and
	// so does the credential it holds.
	sess.Close()
	waitFor(t, 2*time.Second, func() bool { return !ex.Connected() }, "the session should detach")

	res := ex.RevokeLease(context.Background(), remote.RevokePayload{LeaseID: "lease_abc"})
	if res.State != remote.RevokeStateUnreachable {
		t.Fatalf("state = %q, want unreachable", res.State)
	}
	if res.State.Terminal() {
		t.Error("an unreachable revocation must not be treated as settled")
	}
	if !strings.Contains(res.Error, "queued") {
		t.Errorf("the error should tell the operator the revocation is queued; got %q", res.Error)
	}
}

// TestRevocationIsReplayedOnReconnect closes the window that makes the queue
// worth having: a device unplugged during a revocation must not come back
// holding a credential that was already withdrawn.
func TestRevocationIsReplayedOnReconnect(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	startLeased(t, ex, p, "lease_abc")

	sess.Close()
	waitFor(t, 2*time.Second, func() bool { return !ex.Connected() }, "the session should detach")

	if res := ex.RevokeLease(context.Background(), remote.RevokePayload{
		LeaseID: "lease_abc",
		Reason:  "revoked while the device was offline",
		Action:  remote.RevokeKill,
	}); res.State != remote.RevokeStateUnreachable {
		t.Fatalf("state = %q, want unreachable", res.State)
	}

	// The device returns. Nothing asks it for the credential again — the
	// hub's own lease record was wiped when the operator pressed the button —
	// so the replay is the only thing that can close this.
	p2, sess2 := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess2.Close()

	sent := answerRevoke(t, p2, remote.RevokedPayload{Known: true, EnvScrubbed: []string{"GITHUB_TOKEN"}})

	select {
	case got := <-sent:
		if got.LeaseID != "lease_abc" {
			t.Errorf("replayed revoke carried lease %q, want lease_abc", got.LeaseID)
		}
		// The action survives the queue. A revocation an operator escalated to
		// "kill" must not quietly demote itself to a scrub because the device
		// happened to be offline when they pressed it.
		if got.Effective() != remote.RevokeKill {
			t.Errorf("replayed action = %q, want kill", got.Effective())
		}
		if got.Reason != "revoked while the device was offline" {
			t.Errorf("replayed reason = %q", got.Reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the revocation owed to this agent was never replayed on reconnect")
	}

	waitFor(t, 3*time.Second, func() bool {
		for _, r := range ex.Revocations() {
			if r.LeaseID == "lease_abc" && r.State == remote.RevokeStateRevoked {
				return true
			}
		}
		return false
	}, "the replayed revocation should settle as revoked once acked")
}

// TestReplayRefusedOnDowngradedAgent covers the awkward case the version rule
// cannot prevent: a device that held revocable material and came back speaking
// an older protocol. The revocation cannot be honoured, and saying so is the
// only correct outcome.
func TestReplayRefusedOnDowngradedAgent(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	startLeased(t, ex, p, "lease_abc")
	sess.Close()
	waitFor(t, 2*time.Second, func() bool { return !ex.Connected() }, "the session should detach")

	ex.RevokeLease(context.Background(), remote.RevokePayload{LeaseID: "lease_abc"})

	_, sess2 := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(1), nil)
	defer sess2.Close()

	waitFor(t, 3*time.Second, func() bool {
		for _, r := range ex.Revocations() {
			if r.LeaseID == "lease_abc" && r.State == remote.RevokeStateFailed {
				return strings.Contains(r.Error, "v1")
			}
		}
		return false
	}, "a downgraded agent should fail the replay with a version diagnostic, not silently succeed")
}

// TestRevokeOnLeaseNobodyHoldsIsNotAnError checks the "material is not here"
// case. It is the end state the revocation wanted, so it acks rather than
// failing — and the agent's Known=false is what distinguishes it.
func TestRevokeOnLeaseNobodyHoldsIsNotAnError(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	sent := answerRevoke(t, p, remote.RevokedPayload{Known: false})
	res := ex.RevokeLease(context.Background(), remote.RevokePayload{LeaseID: "lease_unknown"})
	<-sent

	if res.State != remote.RevokeStateRevoked {
		t.Fatalf("state = %q, want revoked (nothing to take back is success)", res.State)
	}
	if res.Ack == nil || res.Ack.Known {
		t.Error("the ack must report that the agent was not holding the lease")
	}
}

// TestHubFansOutOnlyToHolders checks that a revocation is not broadcast to
// devices that were never given the credential.
func TestHubFansOutOnlyToHolders(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	startLeased(t, ex, p, "lease_abc")
	if got := ex.Leases(); len(got) != 1 || got[0] != "lease_abc" {
		t.Fatalf("Leases() = %v, want [lease_abc]", got)
	}
	if ex.HoldsLease("lease_other") {
		t.Error("HoldsLease must not match a lease this executor was never given")
	}
}

// TestFinishedWorkloadReleasesItsLease checks that a completed task stops
// being reported as a holder — otherwise a revocation would wait for an ack
// about a credential that went with the process.
func TestFinishedWorkloadReleasesItsLease(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	handle := startLeased(t, ex, p, "lease_abc")

	status, err := remote.NewFrame(remote.TypeStatus, "", handle.ID, remote.StatusPayload{
		Status: executor.Status{
			HandleID:   handle.ID,
			State:      executor.StateExited,
			FinishedAt: time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("build status: %v", err)
	}
	p.write(status)

	waitFor(t, 3*time.Second, func() bool { return !ex.HoldsLease("lease_abc") },
		"a terminal workload should release its lease binding")
}

// TestProtocolVersionNegotiationKeepsV1Agents guards the compatibility promise
// itself: bumping ProtocolVersion must not lock out the deployed fleet.
func TestProtocolVersionNegotiationKeepsV1Agents(t *testing.T) {
	if remote.MinProtocolVersion != 1 {
		t.Fatalf("MinProtocolVersion = %d; raising it strands every deployed v1 device",
			remote.MinProtocolVersion)
	}
	if remote.ProtocolVersion < remote.MinRevocationVersion {
		t.Fatalf("ProtocolVersion (%d) must be at least MinRevocationVersion (%d)",
			remote.ProtocolVersion, remote.MinRevocationVersion)
	}

	for _, tc := range []struct {
		peer int
		want int
	}{
		{peer: 1, want: 1},
		{peer: 2, want: 2},
		// A newer peer drops to our maximum rather than being refused.
		{peer: 99, want: remote.ProtocolVersion},
	} {
		got, err := remote.NegotiateVersion(tc.peer)
		if err != nil {
			t.Fatalf("NegotiateVersion(%d): %v", tc.peer, err)
		}
		if got != tc.want {
			t.Errorf("NegotiateVersion(%d) = %d, want %d", tc.peer, got, tc.want)
		}
		if remote.SupportsRevocation(got) != (got >= remote.MinRevocationVersion) {
			t.Errorf("SupportsRevocation(%d) disagrees with MinRevocationVersion", got)
		}
	}
}

// TestSessionStampsNegotiatedVersionOnOutboundFrames is the bug this whole
// version scheme would have if frames were stamped with the build's maximum:
// a v1 agent rejects a v2 envelope as out of range, so every frame the hub
// sent would be dropped and the negotiation would be decorative.
func TestSessionStampsNegotiatedVersionOnOutboundFrames(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(1), nil)
	defer sess.Close()

	done := make(chan remote.Frame, 1)
	go func() { done <- p.readUntil(remote.TypeStart) }()

	go func() {
		_, _ = ex.Start(context.Background(), executor.Spec{
			WorkDir: t.TempDir(), Argv: []string{"sleep", "60"},
		})
	}()

	select {
	case f := <-done:
		if f.V != 1 {
			t.Errorf("start frame stamped v%d on a v1 session; a v1 agent would reject it", f.V)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("frame should be valid at the negotiated version: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no start frame arrived")
	}
}

// startLeased drives a Start carrying revocable material through a scripted
// peer and returns the handle.
func startLeased(t *testing.T, ex *remote.Executor, p *peer, leaseID string) executor.Handle {
	t.Helper()
	type result struct {
		h   executor.Handle
		err error
	}
	resCh := make(chan result, 1)

	go func() {
		f := p.readUntil(remote.TypeStart)
		// Assert in passing that the binding actually crossed the wire: the
		// agent cannot scrub what it was never told about.
		payload, err := remote.DecodeStart(f)
		if err != nil {
			t.Errorf("decode start: %v", err)
		} else if len(payload.Spec.Secrets) != 1 || payload.Spec.Secrets[0].LeaseID != leaseID {
			t.Errorf("start frame should carry the lease binding; got %+v", payload.Spec.Secrets)
		}
		reply, _ := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID: f.Handle, PID: 111, StartedAt: time.Now(),
		})
		p.write(reply)
	}()

	go func() {
		h, err := ex.Start(context.Background(), leasedSpec(t.TempDir(), leaseID))
		resCh <- result{h, err}
	}()

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("Start: %v", res.err)
		}
		return res.h
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not complete")
		return executor.Handle{}
	}
}
