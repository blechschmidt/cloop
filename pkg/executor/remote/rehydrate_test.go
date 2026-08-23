package remote_test

// Durable-handle tests for the remote driver (Task 20191).
//
// The property under test is what a control-plane restart does to work that is
// already running on a device. Before the handle store there was exactly one
// record that a remote workload existed — the in-memory handle map — so a
// restart erased it, the reconnecting agent's resume offer matched nothing, and
// the agent abandoned a process that then ran forever with nobody reading it.
//
// These tests simulate the restart the only way that is honest: build an
// executor, dispatch through it, throw the whole executor away, and build a new
// one from nothing but the store. Anything that survives that survived a
// restart; anything that did not, did not.

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// newStoredExecutor builds an executor backed by a durable handle store,
// rehydrating from it exactly as a restarting hub would.
func newStoredExecutor(t *testing.T, store executor.HandleStore) *remote.Executor {
	t.Helper()
	ex, err := remote.NewExecutor(remote.Options{
		ID:          "agent-1",
		Name:        "edge-1",
		HandleStore: store,
	})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	return ex
}

// helloOffering builds a reconnect hello that offers one surviving workload.
func helloOffering(version int, handleID string, logOffset int64) remote.HelloPayload {
	hello := helloAt(version)
	hello.Resume = []remote.ResumeHandle{{
		HandleID:  handleID,
		StartedAt: time.Now().Add(-time.Minute),
		LogOffset: logOffset,
	}}
	return hello
}

// TestStartPersistsHandleIdentity pins the row Start writes. Everything else in
// this file depends on its shape, and a row missing the external ID or the
// driver is one a cross-driver sweep cannot act on.
func TestStartPersistsHandleIdentity(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex := newStoredExecutor(t, store)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)

	dir := t.TempDir()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f := p.readUntil(remote.TypeStart)
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID: f.Handle, PID: 4242, StartedAt: time.Now(),
		})
		if err != nil {
			return
		}
		p.write(reply)
	}()
	handle, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: dir,
		Argv:    []string{"sleep", "60"},
		Labels:  map[string]string{"project": "/srv/projects/demo", "task_id": "20191"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-done

	rows, err := store.ListHandles("agent-1")
	if err != nil {
		t.Fatalf("ListHandles: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 persisted handle, got %d", len(rows))
	}
	rec := rows[0]
	if rec.HandleID != handle.ID {
		t.Errorf("HandleID = %q, want %q", rec.HandleID, handle.ID)
	}
	if rec.Driver != executor.KindRemoteAgent {
		t.Errorf("Driver = %q, want %q", rec.Driver, executor.KindRemoteAgent)
	}
	// The whole point of the column for this driver: the agent offers the
	// handle ID back, so that is the name the "runtime" knows the workload by.
	if rec.ExternalID != handle.ID {
		t.Errorf("ExternalID = %q, want the handle ID %q", rec.ExternalID, handle.ID)
	}
	if rec.ProjectPath != "/srv/projects/demo" {
		t.Errorf("ProjectPath = %q, want the project label", rec.ProjectPath)
	}
	if rec.TaskID != 20191 {
		t.Errorf("TaskID = %d, want 20191", rec.TaskID)
	}
	if rec.StartedAt.IsZero() {
		t.Error("StartedAt must be the dispatch time; the orphan sweep compares it against a grace period")
	}
}

// TestHandlesSurviveAControlPlaneRestart is the restart simulation. A hub that
// comes back must be able to stream, inspect and signal work it dispatched
// before it died — the three operations that used to answer ErrHandleNotFound
// for a workload that was alive the whole time.
func TestHandlesSurviveAControlPlaneRestart(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	first := newStoredExecutor(t, store)
	p, _ := connect(t, first, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, first, p)

	// The control plane dies. Everything it held in memory goes with it; only
	// the store is left.
	revived := newStoredExecutor(t, store)

	tracked := revived.Handles()
	if len(tracked) != 1 || tracked[0] != handle.ID {
		t.Fatalf("rehydrated handles = %v, want exactly [%s]", tracked, handle.ID)
	}

	if _, err := revived.Stream(context.Background(), handle.ID); err != nil {
		t.Errorf("Stream on a rehydrated handle: %v", err)
	}

	st, err := revived.Status(context.Background(), handle.ID)
	if errors.Is(err, executor.ErrHandleNotFound) {
		t.Fatal("Status must not report a rehydrated handle as unknown; that is the bug")
	}
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	// No session has attached to the revived executor, so the documented
	// answer is "unknown, last seen running" rather than an error.
	if st.State != executor.StateUnknown {
		t.Errorf("state = %q, want unknown for a rehydrated handle with no live session", st.State)
	}

	err = revived.Signal(context.Background(), handle.ID, executor.SignalTerminate)
	if errors.Is(err, executor.ErrHandleNotFound) {
		t.Fatal("Signal must not report a rehydrated handle as unknown; that is the bug")
	}
	if !errors.Is(err, remote.ErrAgentUnreachable) {
		t.Fatalf("Signal with no session should say the agent is unreachable, got %v", err)
	}

	// The reattached stream begins where the previous process stopped, and the
	// UI must not present it as the whole run.
	if !revived.LogGapped(handle.ID) {
		t.Error("a rehydrated handle's log starts mid-run and must be reported as gapped")
	}
}

// TestReconnectingAgentResumesAgainstARehydratedHub is the regression test for
// consequence (a). The agent offers the handle it is still running, the
// rehydrated hub recognises it, and output flows again.
func TestReconnectingAgentResumesAgainstARehydratedHub(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	first := newStoredExecutor(t, store)
	p, sess := connect(t, first, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, first, p)
	sess.Close()

	revived := newStoredExecutor(t, store)

	lines, err := revived.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	sink := newStreamSink(lines)

	// The device reconnects, still running the workload, and offers it back.
	p2, _ := connectWithWelcome(t, revived, remote.AgentRecord{AgentID: "agent-1"},
		helloOffering(remote.ProtocolVersion, handle.ID, 4096), func(w remote.WelcomePayload) {
			if len(w.ResumeAccepted) != 1 {
				t.Fatalf("expected 1 resume verdict, got %d", len(w.ResumeAccepted))
			}
			ack := w.ResumeAccepted[0]
			if ack.HandleID != handle.ID {
				t.Fatalf("verdict is for %q, want %q", ack.HandleID, handle.ID)
			}
			if ack.Effective() != remote.ResumeContinue {
				t.Fatalf("a handle the hub rehydrated must be resumed, not %q", ack.Effective())
			}
			// Zero, not the offered 4096: no offset was persisted, so the hub
			// asks for everything the device still holds rather than inventing
			// a number that would tell the agent to discard bytes.
			if ack.FromOffset != 0 {
				t.Fatalf("resume offset = %d, want 0 for a rehydrated handle", ack.FromOffset)
			}
		})

	const recovered = "still building\n"
	p2.sendLog(handle.ID, 0, recovered)

	statusFrame, err := remote.NewFrame(remote.TypeStatus, "", handle.ID, remote.StatusPayload{
		Status:      executor.Status{HandleID: handle.ID, State: executor.StateExited, ExitCode: 0},
		FinalOffset: int64(len(recovered)),
	})
	if err != nil {
		t.Fatalf("build status: %v", err)
	}
	p2.write(statusFrame)
	sink.waitClosed(t, 3*time.Second)

	got := sink.text()
	// The banner comes first — a transcript that begins abruptly mid-build is
	// otherwise indistinguishable from a harness producing nonsense — and the
	// device's output follows it.
	if !strings.Contains(got, "reattaching") {
		t.Errorf("a reattached stream should say so, got %q", got)
	}
	if !strings.HasSuffix(got, recovered) {
		t.Fatalf("resumed output = %q, want it to end with %q", got, recovered)
	}
	final, err := revived.Status(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if final.State != executor.StateExited {
		t.Errorf("final state = %q, want exited", final.State)
	}
	// A workload the device reported terminal has nothing left to reattach to.
	waitFor(t, 2*time.Second, func() bool { return store.Len() == 0 },
		"a terminal status must drop the durable row")
}

// TestUnmatchedResumeOfferIsToldToTerminate is the leak half of consequence
// (a). An offer the hub cannot match is work nobody can read, collect or stop,
// and answering it with silence is what left harnesses running forever.
func TestUnmatchedResumeOfferIsToldToTerminate(t *testing.T) {
	ex := newTestExecutor(t, nil)

	connectWithWelcome(t, ex, remote.AgentRecord{AgentID: "agent-1"},
		helloOffering(remote.ProtocolVersion, "ghost-handle", 8192), func(w remote.WelcomePayload) {
			if len(w.ResumeAccepted) != 1 {
				t.Fatalf("an unmatched offer must get an explicit verdict, got %d entries",
					len(w.ResumeAccepted))
			}
			ack := w.ResumeAccepted[0]
			if ack.HandleID != "ghost-handle" {
				t.Fatalf("verdict is for %q, want ghost-handle", ack.HandleID)
			}
			if ack.Effective() != remote.ResumeTerminate {
				t.Fatalf("an offer the control plane cannot match must be terminated, got %q",
					ack.Effective())
			}
			if ack.Reason == "" {
				t.Error("a refusal must carry a reason; it is the only explanation the device's " +
					"own log will ever have for the kill")
			}
		})
}

// TestUnmatchedResumeOfferIsOmittedForOlderAgents is the backward-compatibility
// floor. An agent built before ResumeAck.Action ignores the field, so an entry
// carrying a terminate would read to it as permission to keep streaming into a
// hub that answers every chunk with CodeUnknownHandle. It must instead see
// exactly the payload a pre-v5 hub sent: nothing.
func TestUnmatchedResumeOfferIsOmittedForOlderAgents(t *testing.T) {
	ex := newTestExecutor(t, nil)
	old := remote.MinResumeTerminateVersion - 1
	if old < remote.MinProtocolVersion {
		t.Skipf("no supported protocol version predates resume verdicts")
	}

	_, sess := connectWithWelcome(t, ex, remote.AgentRecord{AgentID: "agent-1"},
		helloOffering(old, "ghost-handle", 8192), func(w remote.WelcomePayload) {
			if len(w.ResumeAccepted) != 0 {
				t.Fatalf("a v%d agent must see the pre-v5 payload for an unmatched offer, got %+v",
					old, w.ResumeAccepted)
			}
		})
	if sess.Version() != old {
		t.Fatalf("negotiated version = %d, want %d", sess.Version(), old)
	}
}

// TestResumeAckEffectiveIsConservative pins the decode-side default. An agent
// meeting a control plane whose dialect it does not know must fail towards
// keeping hours of compute, not towards destroying it.
func TestResumeAckEffectiveIsConservative(t *testing.T) {
	for _, tc := range []struct {
		name string
		ack  remote.ResumeAck
		want remote.ResumeAction
	}{
		{"absent action", remote.ResumeAck{HandleID: "h"}, remote.ResumeContinue},
		{"unknown action", remote.ResumeAck{HandleID: "h", Action: "wormhole"}, remote.ResumeContinue},
		{"explicit continue", remote.ResumeAck{HandleID: "h", Action: remote.ResumeContinue}, remote.ResumeContinue},
		{"explicit terminate", remote.ResumeAck{HandleID: "h", Action: remote.ResumeTerminate}, remote.ResumeTerminate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ack.Effective(); got != tc.want {
				t.Fatalf("Effective() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUnmatchedResumeOffersAreBounded covers the one part of a welcome whose
// size the peer chooses. A device offering thousands of invented handle IDs
// must not make the hub assemble a frame larger than the peer's own read limit
// will accept — the excess falls through to omission, which is the pre-v5
// answer and which an upgraded agent still reads as "stop this".
func TestUnmatchedResumeOffersAreBounded(t *testing.T) {
	ex := newTestExecutor(t, nil)

	hello := helloAt(remote.ProtocolVersion)
	const offered = 4096
	hello.Resume = make([]remote.ResumeHandle, 0, offered)
	for i := 0; i < offered; i++ {
		hello.Resume = append(hello.Resume, remote.ResumeHandle{
			HandleID: "ghost-" + strconv.Itoa(i),
		})
	}

	connectWithWelcome(t, ex, remote.AgentRecord{AgentID: "agent-1"}, hello,
		func(w remote.WelcomePayload) {
			if len(w.ResumeAccepted) >= offered {
				t.Fatalf("the hub answered all %d invented offers; that is an amplification the "+
					"peer controls", len(w.ResumeAccepted))
			}
			if len(w.ResumeAccepted) == 0 {
				t.Fatal("the bound must still refuse as many as it can, or a real device with " +
					"work in flight learns nothing")
			}
			for _, ack := range w.ResumeAccepted {
				if ack.Effective() != remote.ResumeTerminate {
					t.Fatalf("verdict for %q = %q, want terminate", ack.HandleID, ack.Effective())
				}
			}
		})
}

// TestResumeTerminateVersionFloorStaysInRange is the fleet-compatibility guard
// for the new floor, matching the ones MinRevocationVersion and
// MinWorkspaceVersion already carry: a floor above the negotiable range would
// make the feature permanently unreachable, and one at or below the minimum
// would claim every deployed v1 device understands a frame field that did not
// exist when it was built.
func TestResumeTerminateVersionFloorStaysInRange(t *testing.T) {
	if remote.MinResumeTerminateVersion > remote.ProtocolVersion {
		t.Fatalf("MinResumeTerminateVersion (%d) is above ProtocolVersion (%d): no session could "+
			"ever negotiate it", remote.MinResumeTerminateVersion, remote.ProtocolVersion)
	}
	if remote.MinResumeTerminateVersion <= remote.MinProtocolVersion {
		t.Fatalf("MinResumeTerminateVersion (%d) must be newer than MinProtocolVersion (%d), or "+
			"agents predating ResumeAck.Action would be sent verdicts they silently ignore",
			remote.MinResumeTerminateVersion, remote.MinProtocolVersion)
	}
	for v := remote.MinProtocolVersion; v <= remote.ProtocolVersion; v++ {
		if remote.SupportsResumeTerminate(v) != (v >= remote.MinResumeTerminateVersion) {
			t.Errorf("SupportsResumeTerminate(%d) disagrees with MinResumeTerminateVersion", v)
		}
	}
}

// TestFailedStartLeavesNoDurableRow covers Start's early-drop path. The row is
// written before the start frame goes out, so a workload the agent refused must
// not leave identity behind — the next boot would adopt it, report it running,
// and then resolve it as a failed run that never ran.
func TestFailedStartLeavesNoDurableRow(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex := newStoredExecutor(t, store)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		f := p.readUntil(remote.TypeStart)
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID: f.Handle,
			Error:    "exec: \"sleep\": executable file not found",
		})
		if err != nil {
			return
		}
		p.write(reply)
	}()

	_, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"sleep", "60"},
	})
	<-done
	if err == nil {
		t.Fatal("Start must fail when the agent refuses the workload")
	}
	if store.Len() != 0 {
		t.Fatalf("a refused start left %d durable row(s) behind", store.Len())
	}
	if len(ex.Handles()) != 0 {
		t.Fatalf("a refused start left the handle tracked: %v", ex.Handles())
	}
}

// TestDeregisterKeepsRowsForWorkloadsStillOnTheDevice is the gate the
// Kubernetes driver got wrong first. Tearing an executor down marks its handles
// failed, but the processes are still on the device — so the rows are the only
// surviving record that a machine we have stopped talking to is running our
// work, and erasing them is exactly wrong at exactly the wrong moment.
func TestDeregisterKeepsRowsForWorkloadsStillOnTheDevice(t *testing.T) {
	handleStore := executor.NewMemoryHandleStore()
	enrollStore := newMemStore()
	if err := enrollStore.PutAgent(remote.AgentRecord{
		AgentID:   "agent-1",
		Name:      "edge-1",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("PutAgent: %v", err)
	}

	hub, err := remote.NewHub(remote.HubOptions{
		Store:       enrollStore,
		Registry:    executor.NewRegistry(),
		HandleStore: handleStore,
		Logf:        func(format string, args ...any) { t.Logf("hub: "+format, args...) },
	})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}
	if err := hub.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	ex, ok := hub.Executor("agent-1")
	if !ok {
		t.Fatal("Restore should have built an executor for the enrolled agent")
	}

	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, ex, p)
	if handleStore.Len() != 1 {
		t.Fatalf("expected the hub's store to be wired through to the executor, got %d rows",
			handleStore.Len())
	}

	hub.Deregister("agent-1")

	st, err := ex.Status(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.State.Terminal() {
		t.Fatalf("deregistering must resolve live handles, state = %q", st.State)
	}
	if handleStore.Len() != 1 {
		t.Fatal("deregistering an executor must not erase the identity of workloads still " +
			"running on the device; that row is all that is left of them")
	}
}

// TestAttachHandleStoreAdoptsEachHandleOnce covers the boot-order path: the hub
// builds executors before the state database is open, so the store arrives
// afterwards. Attaching twice — a caller that also passed Options.HandleStore,
// or a config reload — must not produce two handles, two buses, or a finished
// handle walked backwards into "running".
func TestAttachHandleStoreAdoptsEachHandleOnce(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	if err := store.PutHandle(executor.HandleRecord{
		HandleID:   "h-adopt",
		ExecutorID: "agent-1",
		Driver:     executor.KindRemoteAgent,
		ExternalID: "h-adopt",
		StartedAt:  time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := newTestExecutor(t, nil)
	if len(ex.Handles()) != 0 {
		t.Fatal("an executor built without a store must start empty")
	}

	ex.AttachHandleStore(store)
	if got := ex.Handles(); len(got) != 1 || got[0] != "h-adopt" {
		t.Fatalf("handles after attach = %v, want [h-adopt]", got)
	}
	first, err := ex.Status(context.Background(), "h-adopt")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	ex.AttachHandleStore(store)
	ex.AttachHandleStore(nil) // must not clear: see AttachHandleStore's doc
	if got := ex.Handles(); len(got) != 1 {
		t.Fatalf("re-attaching adopted the handle again: %v", got)
	}
	second, err := ex.Status(context.Background(), "h-adopt")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !second.StartedAt.Equal(first.StartedAt) {
		t.Errorf("re-adoption rewrote the handle's start time: %s then %s",
			first.StartedAt, second.StartedAt)
	}
}

// TestAdoptIgnoresAnotherDriversRow is the cross-driver guard. Executor IDs are
// unique within a registry so this should be unreachable, but the one way to
// reach it — enrolling an agent under an ID a container executor used to hold —
// would have this driver accept resume offers for a container name and answer
// status requests about it with fabricated confidence.
func TestAdoptIgnoresAnotherDriversRow(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	if err := store.PutHandle(executor.HandleRecord{
		HandleID:   "h-container",
		ExecutorID: "agent-1",
		Driver:     executor.KindContainer,
		ExternalID: "cloop-sandbox-abc",
		StartedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := newStoredExecutor(t, store)
	if got := ex.Handles(); len(got) != 0 {
		t.Fatalf("a container row must not be adopted by the remote driver, got %v", got)
	}
}

// connectWithWelcome performs the agent side of the handshake and hands the
// decoded welcome to inspect before returning.
//
// It exists because connect drains the welcome without showing it, and every
// resume verdict this file asserts on lives in exactly that frame.
func connectWithWelcome(
	t *testing.T,
	ex *remote.Executor,
	agent remote.AgentRecord,
	hello remote.HelloPayload,
	inspect func(remote.WelcomePayload),
) (*peer, *remote.Session) {
	t.Helper()
	cpConn, agentConn := remote.NewPipe(64)

	type result struct {
		sess *remote.Session
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		sess, err := remote.Accept(context.Background(), cpConn, remote.AcceptOptions{
			Agent:         agent,
			Executor:      ex,
			HeartbeatPoll: 5 * time.Millisecond,
		})
		resCh <- result{sess, err}
	}()

	p := &peer{t: t, conn: agentConn}
	frame, err := remote.NewFrame(remote.TypeHello, "hello", "", hello)
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	p.write(frame)

	welcomeFrame := p.readUntil(remote.TypeWelcome)
	welcome, err := remote.DecodeWelcome(welcomeFrame)
	if err != nil {
		t.Fatalf("DecodeWelcome: %v", err)
	}
	if inspect != nil {
		inspect(welcome)
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("Accept: %v", res.err)
		}
		return p, res.sess
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not complete")
		return nil, nil
	}
}
