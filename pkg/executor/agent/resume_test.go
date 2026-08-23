package agent

// Resume-refusal tests: what the device does with a workload the control plane
// will not take back (Task 20191).
//
// reconnect_test.go covers the accepting half — the agent resends from the
// offset it is told. This file covers the refusing half, which had no test and
// no implementation worth the name: the agent called forget(), which dropped
// bookkeeping, cancelled provisioning and released the vault binding, and left
// the process running. Nothing would ever read its output, collect its result
// or signal it, and no reaper existed on either side of the link, so a
// control-plane restart quietly converted every run in flight into a harness
// burning a CPU until somebody logged into the device.
//
// Every test here therefore asserts on the *process*, not on bookkeeping. The
// workload traps SIGTERM and prints on its way out, so a chunk carrying
// DYINGWORDS is proof that a signal reached the child — which is the only
// evidence that distinguishes a real kill from a tidier forget().

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// dyingWorkload is a start frame for a harness that announces itself, traps
// SIGTERM, prints a distinctive tail and exits with a recognisable code.
func dyingWorkload(t *testing.T, handleID string) remote.Frame {
	t.Helper()
	f, err := remote.NewFrame(remote.TypeStart, "req-"+handleID, handleID, remote.StartPayload{
		HandleID: handleID,
		Spec: executor.Spec{
			WorkDir: "proj",
			Argv: []string{"/bin/sh", "-c",
				`trap 'printf DYINGWORDS; exit 3' TERM; printf READY; while :; do sleep 0.05; done`},
		},
	})
	if err != nil {
		t.Fatalf("build start: %v", err)
	}
	return f
}

// collectUntilTerminal accumulates log text until a terminal status arrives,
// returning both.
//
// It deliberately does not check offset contiguity the way readLogText does.
// A refused workload is killed without its send offset being rewound, so its
// dying output legitimately arrives labelled at the offset the previous session
// had already reached — asserting contiguity from zero here would fail on
// correct behaviour.
func collectUntilTerminal(t *testing.T, cp *controlPlane, timeout time.Duration) (string, remote.StatusPayload, bool) {
	t.Helper()
	var out strings.Builder
	var final remote.StatusPayload
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		frame, err := cp.read(time.Until(deadline))
		if err != nil {
			break
		}
		switch frame.Type {
		case remote.TypeLogChunk:
			chunk, err := remote.DecodeLogChunk(frame)
			if err != nil {
				t.Fatalf("DecodeLogChunk: %v", err)
			}
			out.WriteString(chunk.Text)
		case remote.TypeStatus:
			sp, err := remote.DecodeStatus(frame)
			if err != nil {
				t.Fatalf("DecodeStatus: %v", err)
			}
			if sp.Status.State.Terminal() {
				return out.String(), sp, true
			}
		}
	}
	return out.String(), final, false
}

// runRefusedResume drives an agent through start, disconnect and a reconnect
// whose welcome carries the given resume verdicts, and reports what the device
// did afterwards.
func runRefusedResume(t *testing.T, handleID string, verdicts []remote.ResumeAck) (*Agent, *controlPlane) {
	t.Helper()
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshake(t, "agent-1", nil, "clac1.a.b.c")
	cp.write(dyingWorkload(t, handleID))
	cp.readUntil(remote.TypeStarted, 10*time.Second)
	if got := readLogText(t, cp, 5, 10*time.Second); got != "READY" {
		t.Fatalf("startup output = %q, want READY", got)
	}

	// The link drops; the workload keeps running on the device. This is the
	// state a hub restart leaves behind.
	_ = cp.conn.Close("simulated control-plane restart")

	var cp2 *controlPlane
	select {
	case cp2 = <-conns:
	case <-time.After(20 * time.Second):
		t.Fatal("the agent should have reconnected after the link dropped")
	}
	cp2.handshake(t, "agent-1", verdicts, "")
	return a, cp2
}

// TestExplicitResumeTerminateKillsTheWorkload is the protocol-v5 path: the hub
// says in so many words that it has no record of this workload, and the device
// stops it.
func TestExplicitResumeTerminateKillsTheWorkload(t *testing.T) {
	const handleID = "h1"
	a, cp := runRefusedResume(t, handleID, []remote.ResumeAck{{
		HandleID: handleID,
		Action:   remote.ResumeTerminate,
		Reason:   "the control plane has no record of this workload",
	}})

	tail, final, sawTerminal := collectUntilTerminal(t, cp, 20*time.Second)
	if !strings.Contains(tail, "DYINGWORDS") {
		t.Fatalf("the workload was never signalled — forget() alone leaves it running forever; "+
			"collected %q", tail)
	}
	if !sawTerminal {
		t.Fatal("a terminated workload should still report its outcome on the live session")
	}
	if final.Status.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3 (the SIGTERM trap's)", final.Status.ExitCode)
	}
	if _, ok := a.workload(handleID); ok {
		t.Error("a terminated workload must also stop being tracked, or its slot leaks")
	}
}

// TestUnacknowledgedResumeOfferKillsTheWorkload is the case that matters for a
// deployed fleet. Agents are upgraded independently of hubs, so for most of a
// rollout an upgraded device is talking to a hub that can only refuse by
// omission — and omission has to kill, or the fix reaches nobody.
func TestUnacknowledgedResumeOfferKillsTheWorkload(t *testing.T) {
	const handleID = "h1"
	a, cp := runRefusedResume(t, handleID, nil)

	tail, final, sawTerminal := collectUntilTerminal(t, cp, 20*time.Second)
	if !strings.Contains(tail, "DYINGWORDS") {
		t.Fatalf("an offer the control plane did not acknowledge must be stopped, not merely "+
			"abandoned; collected %q", tail)
	}
	if !sawTerminal {
		t.Fatal("a terminated workload should still report its outcome on the live session")
	}
	if final.Status.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3 (the SIGTERM trap's)", final.Status.ExitCode)
	}
	if _, ok := a.workload(handleID); ok {
		t.Error("an abandoned workload must stop being tracked")
	}
}

// TestUnknownResumeActionKeepsTheWorkloadRunning is the compatibility floor in
// the other direction: a device meeting a control plane newer than itself.
// An action this build does not recognise must not be read as an instruction to
// destroy hours of compute.
func TestUnknownResumeActionKeepsTheWorkloadRunning(t *testing.T) {
	const handleID = "h1"
	a, cp := runRefusedResume(t, handleID, []remote.ResumeAck{{
		HandleID:   handleID,
		FromOffset: 0,
		Action:     "hand-off-to-another-hub",
	}})

	// Told to resume from 0, the agent resends the retained bytes — which is
	// what an unrecognised action must degrade to.
	if got := readLogText(t, cp, 5, 10*time.Second); got != "READY" {
		t.Fatalf("resent output = %q, want READY: an unknown action must resume, not kill", got)
	}
	if _, ok := a.workload(handleID); !ok {
		t.Fatal("an unrecognised resume action must leave the workload running")
	}
	if st := mustWorkload(t, a, handleID).snapshot(); st.State.Terminal() {
		t.Fatalf("the workload was terminated on an unrecognised action; state = %q", st.State)
	}
}

// TestAcceptedResumeIsUnaffected guards the common path against this change:
// an ordinary acceptance must still rewind and resend, and must never be
// mistaken for a refusal.
func TestAcceptedResumeIsUnaffected(t *testing.T) {
	const handleID = "h1"
	a, cp := runRefusedResume(t, handleID, []remote.ResumeAck{{
		HandleID:   handleID,
		FromOffset: 0,
		Action:     remote.ResumeContinue,
	}})

	if got := readLogText(t, cp, 5, 10*time.Second); got != "READY" {
		t.Fatalf("resent output = %q, want READY", got)
	}
	if _, ok := a.workload(handleID); !ok {
		t.Fatal("an accepted resume must leave the workload running")
	}
}

// mustWorkload fetches a workload the caller has already asserted exists.
func mustWorkload(t *testing.T, a *Agent, handleID string) *workload {
	t.Helper()
	wl, ok := a.workload(handleID)
	if !ok {
		t.Fatalf("workload %s is gone", handleID)
	}
	return wl
}
