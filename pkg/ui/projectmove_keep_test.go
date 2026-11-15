package ui

// A working copy a move placed on a device is the project's own, and a run
// there starts from it (Task 20497): the hub marks the run's workspace Keep
// from the move journal, and the device then fetches without checking the
// forge's tip out over the copy.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// journalMove records a move of the project at dir onto target in the
// control plane's journal, ended at phase with the given delivery.
func journalMove(t *testing.T, dir, target, delivery string, phase projectmove.Phase) {
	t.Helper()
	cp := controlPlaneDir()
	store := projectmove.DBStore{Open: func() (*statedb.DB, error) { return statedb.Open(state.DBPath(cp)) }}
	id, err := projectmove.NewMoveID()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	m, err := store.Create(context.Background(), projectmove.Move{
		ID: id, Project: projectmove.Project{Name: "moved", Path: dir}, Target: target,
		Phase: projectmove.PhasePreflight, CreatedAt: at, UpdatedAt: at,
	})
	if err != nil {
		t.Fatalf("record a move: %v", err)
	}
	m.Detail.Capture = &projectmove.CaptureRecord{Delivery: delivery}
	if _, err := store.Advance(context.Background(), m, phase); err != nil {
		t.Fatalf("end the move %s: %v", phase, err)
	}
}

func TestARunKeepsTheWorkingCopyAMovePlacedOnItsDevice(t *testing.T) {
	dir := seedFixture(t, "a moved project")
	device := seedCapableExecutor() // edge-01
	other := seedCapableExecutor()
	other.id = "edge-02"
	mintGitHubGrant(t, controlPlaneDir(), "ci-pat-edge-02", "executor:edge-02", []string{"acme/*"})

	keep := func(ex executor.Executor) bool {
		t.Helper()
		spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
		if err != nil {
			t.Fatalf("applyWorkspace on %s: %v", ex.ID(), err)
		}
		if spec.Workspace.Kind != executor.WorkspaceGit {
			t.Fatalf("workspace kind = %q, want git", spec.Workspace.Kind)
		}
		if err := spec.Validate(); err != nil {
			t.Fatalf("the dispatched spec does not validate: %v", err)
		}
		return spec.Workspace.Keep
	}

	if keep(device) {
		t.Error("a project no move ever placed on the device keeps its checkout: the device's checkout is a copy of the forge, refreshed per run")
	}
	journalMove(t, dir, "edge-01", projectmove.DeliverDevice, projectmove.PhaseDone)
	if !keep(device) {
		t.Error("after a verified move seeded the device, the next run would check the forge's tip out over the moved working copy")
	}
	if keep(other) {
		t.Error("a run on another device keeps a working copy the move put somewhere else")
	}
	// A later move that failed or was rolled back changed nothing there.
	journalMove(t, dir, "edge-02", projectmove.DeliverDevice, projectmove.PhaseFailed)
	journalMove(t, dir, "edge-02", projectmove.DeliverDevice, projectmove.PhaseRolledBack)
	if !keep(device) {
		t.Error("a move that failed after the verified one stopped the device keeping the moved working copy")
	}
	// Moved away, then bound back by hand: the copy left on the device is
	// no longer the project's.
	journalMove(t, dir, "local", projectmove.DeliverHubTree, projectmove.PhaseDone)
	if keep(device) {
		t.Error("the device keeps a working copy the project has since been moved off")
	}
	// A move that delivered nothing to a device's working copy does not make
	// the device's checkout the project's.
	journalMove(t, dir, "edge-01", projectmove.DeliverForge, projectmove.PhaseDone)
	if keep(device) {
		t.Error("a forge delivery made the device keep its checkout")
	}
	journalMove(t, dir, "edge-01", projectmove.DeliverDevice, projectmove.PhaseDone)
	if !keep(device) {
		t.Error("moved back onto the device, the next run does not keep the working copy")
	}
}

// flakyAgent is a device whose agent connects after a number of health
// checks: a hub that restarted mid-move resumes before its agents reconnect.
type flakyAgent struct {
	*harnessExec
	offline int
	checks  int
	other   error
}

func (f *flakyAgent) HealthCheck(context.Context) error {
	f.checks++
	if f.other != nil {
		return f.other
	}
	if f.checks <= f.offline {
		return fmt.Errorf("%w: agent %s has no live session", remote.ErrAgentUnreachable, f.id)
	}
	return nil
}

// TestAMoveStepWaitsForItsDevicesAgent (Task 20497): a step on a device
// waits a bounded time for the agent to connect instead of failing — and
// rolling the move back — the moment the hub resumed it.
func TestAMoveStepWaitsForItsDevicesAgent(t *testing.T) {
	oldWait, oldPoll := moveAgentWait, moveAgentPoll
	moveAgentWait, moveAgentPoll = time.Second, 10*time.Millisecond
	t.Cleanup(func() { moveAgentWait, moveAgentPoll = oldWait, oldPoll })

	late := &flakyAgent{harnessExec: newHarnessExec("late", executor.KindRemoteAgent, executor.IsolationRemote), offline: 5}
	if err := waitForAgent(context.Background(), late, nil); err != nil || late.checks != 6 {
		t.Errorf("an agent that connects late: %v after %d checks, want nil after 6", err, late.checks)
	}
	gone := &flakyAgent{harnessExec: newHarnessExec("gone", executor.KindRemoteAgent, executor.IsolationRemote), offline: 1 << 30}
	start := time.Now()
	if err := waitForAgent(context.Background(), gone, nil); !errors.Is(err, remote.ErrAgentUnreachable) || time.Since(start) < moveAgentWait {
		t.Errorf("an agent that never connects: %v after %s, want ErrAgentUnreachable after %s", err, time.Since(start), moveAgentWait)
	}
	// Anything else is the step's to report: no wait.
	odd := &flakyAgent{harnessExec: newHarnessExec("odd", executor.KindRemoteAgent, executor.IsolationRemote), other: errors.New("not this")}
	if err := waitForAgent(context.Background(), odd, nil); err != nil || odd.checks != 1 {
		t.Errorf("another health-check failure: %v after %d checks, want nil after 1", err, odd.checks)
	}
}

// TestASweepLeavesAMoveBeingStartedAlone (Task 20497): a move at its
// preflight is being started by the request that asked for it, and a sweep
// that drove it would fail it under that request; only one gone quiet for
// longer than any preflight takes is a start that died.
func TestASweepLeavesAMoveBeingStartedAlone(t *testing.T) {
	srv := New(t.TempDir(), 0, "")
	now := time.Now().UTC()
	fresh := projectmove.Move{ID: "0123456789abcdef", Phase: projectmove.PhasePreflight, CreatedAt: now, UpdatedAt: now}
	if srv.drivesHere(fresh) {
		t.Error("a sweep would drive — and fail — a move whose preflight is running")
	}
	stale := fresh
	stale.UpdatedAt = now.Add(-movePreflightStale - time.Minute)
	if !srv.drivesHere(stale) {
		t.Error("a sweep leaves a move whose start died at its preflight open, holding the project")
	}
}

// TestKeepingAMovedCopyFollowsTheProjectNotJustItsLastMove (Task 20497,
// review): a move between a device and its own virtual executor moves
// nothing and keeps the copy the project's runs use; a binding written by
// hand after the last move ended means the device's copy no longer has what
// the project did since; and a run whose work is pushed back starts from the
// commit the hub pins, never from a kept copy.
func TestKeepingAMovedCopyFollowsTheProjectNotJustItsLastMove(t *testing.T) {
	dir := seedFixture(t, "a moved project")
	device := seedCapableExecutor() // edge-01
	run := executor.Spec{}
	journalMove(t, dir, "edge-01", projectmove.DeliverDevice, projectmove.PhaseDone)
	journalMove(t, dir, "edge-01", projectmove.DeliverSameDevice, projectmove.PhaseDone)
	if !keepsMovedCopy(run, dir, device) {
		t.Error("a move onto the device's own virtual executor made the next run check the forge out over the moved copy")
	}
	push := executor.Spec{WriteBack: executor.WriteBack{Mode: executor.WriteBackPush}}
	if keepsMovedCopy(push, dir, device) {
		t.Error("a run whose work is pushed back kept the moved copy instead of starting from the pinned commit")
	}
	// Bound away and back by hand, after the move ended.
	time.Sleep(10 * time.Millisecond)
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recordExecutor(t, db, "edge-01", executor.KindRemoteAgent)
	if err := db.BindProjectExecutor(policyProjectPath(dir), "edge-01", "someone"); err != nil {
		t.Fatal(err)
	}
	if keepsMovedCopy(run, dir, device) {
		t.Error("a project bound to the device by hand after the move keeps the stale moved copy")
	}
}

// TestAMoveStepOnADeviceAnotherMemberHoldsIsHandedOff (Task 20497, review):
// while the agent is connected to another member of a hub cluster, the step
// is that member's to run, and the wait says so at once.
func TestAMoveStepOnADeviceAnotherMemberHoldsIsHandedOff(t *testing.T) {
	gone := &flakyAgent{harnessExec: newHarnessExec("held", executor.KindRemoteAgent, executor.IsolationRemote), offline: 1 << 30}
	start := time.Now()
	if err := waitForAgent(context.Background(), gone, func() bool { return true }); !errors.Is(err, errMoveElsewhere) || time.Since(start) > time.Second {
		t.Errorf("waitForAgent = %v after %s, want errMoveElsewhere at once", err, time.Since(start))
	}
}
