package pm

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// gate builds a pending, unapproved human review gate at a queue position.
func gate(id, priority int) *Task {
	g := NewHumanGate("", "")
	g.ID, g.Priority = id, priority
	return g
}

func TestGateHoldsEveryTaskAfterIt(t *testing.T) {
	t.Parallel()
	// 1 and 2 run, then the gate (priority 3), then 4 and 5.
	p := &Plan{Tasks: []*Task{mk(1, 1, false), mk(2, 2, false), gate(3, 3), mk(4, 4, false), mk(5, 4, false)}}

	if got := ids(p.ReadyTasks()); !sameIDs(got, []int{1, 2}) {
		t.Fatalf("ReadyTasks = %v, want [1 2]: tasks after a closed gate must wait for it", got)
	}
	if b := p.GateBarrier(); b == nil || b.ID != 3 {
		t.Fatalf("GateBarrier = %v, want task 3", b)
	}
	if g := p.WaitingGate(); g != nil {
		t.Fatalf("WaitingGate = %d with work still ahead of the gate", g.ID)
	}

	p.Tasks[0].Status, p.Tasks[1].Status = TaskDone, TaskDone
	if got := p.ReadyTasks(); len(got) != 0 {
		t.Fatalf("ReadyTasks = %v once the work ahead finished; the gate is not work and holds 4 and 5", ids(got))
	}
	if g := p.WaitingGate(); g == nil || g.ID != 3 {
		t.Fatalf("WaitingGate = %v, want the gate (3): the run has reached it", g)
	}
	if p.IsComplete() {
		t.Fatal("IsComplete with a closed gate in the plan")
	}

	ApproveGate(p.Tasks[2], "alice@example.com", time.Now())
	if got := ids(p.ReadyTasks()); !sameIDs(got, []int{4, 5}) {
		t.Fatalf("ReadyTasks after approval = %v, want [4 5]", got)
	}
	if g := p.WaitingGate(); g != nil {
		t.Fatalf("WaitingGate = %d after approval", g.ID)
	}
	if p.Tasks[2].Status != TaskDone || p.Tasks[2].CompletedAt == nil {
		t.Errorf("approved gate = %s, completed %v; want done, with a completion time", p.Tasks[2].Status, p.Tasks[2].CompletedAt)
	}
	if n := len(p.Tasks[2].Annotations); n != 1 || p.Tasks[2].Annotations[0].Author != "alice@example.com" {
		t.Errorf("approval annotations = %+v, want one by the approver", p.Tasks[2].Annotations)
	}
}

func TestOnlyTheFirstClosedGateHolds(t *testing.T) {
	t.Parallel()
	p := &Plan{Tasks: []*Task{gate(9, 5), mk(1, 1, false), gate(7, 2), mk(2, 3, false)}}
	if b := p.GateBarrier(); b == nil || b.ID != 7 {
		t.Fatalf("GateBarrier = %v, want 7, the first gate in execution order (not the first in the slice)", b)
	}
	if got := ids(p.ReadyTasks()); !sameIDs(got, []int{1}) {
		t.Fatalf("ReadyTasks = %v, want [1]", got)
	}
	p.Tasks[2].Approved = true // approved but not yet passed: no longer holds anything
	if b := p.GateBarrier(); b == nil || b.ID != 9 {
		t.Fatalf("GateBarrier after approving 7 = %v, want 9", b)
	}
	if got := ids(p.ReadyTasks()); !sameIDs(got, []int{1, 2}) {
		t.Fatalf("ReadyTasks = %v, want [1 2]", got)
	}
}

func TestGateStatesAndTheirMeaning(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		edit   func(*Task)
		closed bool
	}{
		{"pending", func(*Task) {}, true},
		{"approved, not yet passed", func(g *Task) { g.Approved = true }, false},
		{"passed", func(g *Task) { g.Status = TaskDone }, false},
		{"bypassed", func(g *Task) { g.Status = TaskSkipped }, false},
		{"failed by hand", func(g *Task) { g.Status = TaskFailed }, true},
		{"marked running by hand", func(g *Task) { g.Status = TaskInProgress }, true},
	} {
		g := gate(1, 1)
		tc.edit(g)
		if got := g.GateClosed(); got != tc.closed {
			t.Errorf("%s: GateClosed = %v, want %v", tc.name, got, tc.closed)
		}
	}
	if w := mk(1, 1, false); w.GateClosed() || !w.IsWork() || w.IsHumanGate() {
		t.Error("an ordinary task reads as a gate")
	}
	// A kind this build does not know is never handed to an agent, and holds
	// the queue like a closed gate rather than being skipped past.
	unknown := &Task{ID: 2, Priority: 1, Status: TaskPending, Kind: "milestone"}
	if unknown.IsWork() || !unknown.GateClosed() {
		t.Error("an unknown kind must hold the queue, not run")
	}
	p := &Plan{Tasks: []*Task{unknown, mk(3, 2, false)}}
	if got := p.ReadyTasks(); len(got) != 0 {
		t.Errorf("ReadyTasks = %v behind an entry of unknown kind", ids(got))
	}
}

func TestWaitingGateWaitsForWorkInProgress(t *testing.T) {
	t.Parallel()
	running := mk(1, 1, false)
	running.Status = TaskInProgress
	p := &Plan{Tasks: []*Task{running, gate(2, 2), mk(3, 3, false)}}
	if g := p.WaitingGate(); g != nil {
		t.Fatalf("WaitingGate = %d while task 1 is still running", g.ID)
	}
	running.Status = TaskDone
	if g := p.WaitingGate(); g == nil || g.ID != 2 {
		t.Fatalf("WaitingGate = %v once task 1 finished, want 2", g)
	}
}

// A task ahead of the gate that depends on one behind it can never start until
// the gate opens: the run has reached the gate, not stalled short of it.
func TestWaitingGateCountsTasksStuckBehindIt(t *testing.T) {
	t.Parallel()
	ahead := mk(1, 1, false)
	ahead.DependsOn = []int{3}
	p := &Plan{Tasks: []*Task{ahead, gate(2, 2), mk(3, 3, false)}}
	if g := p.WaitingGate(); g == nil || g.ID != 2 {
		t.Fatalf("WaitingGate = %v, want 2", g)
	}
}

func TestIsCompleteWaitsForAGateAtTheEnd(t *testing.T) {
	t.Parallel()
	done := mk(1, 1, false)
	done.Status = TaskDone
	p := &Plan{Tasks: []*Task{done, gate(2, 2)}}
	if p.IsComplete() {
		t.Fatal("a plan whose last entry is a closed gate is complete; auto-evolve would plan past the review")
	}
	p.Tasks[1].Approved = true
	if p.IsComplete() {
		t.Fatal("complete before the run recorded the approved gate as passed")
	}
	PassGate(p.Tasks[1], time.Now())
	if !p.IsComplete() {
		t.Fatal("not complete with every task done and the gate passed")
	}
}

func TestReopenGateClosesItAgain(t *testing.T) {
	t.Parallel()
	g := gate(1, 1)
	ApproveGate(g, "bob", time.Now())
	ReopenGate(g)
	if !g.GateClosed() || g.Approved || g.Status != TaskPending || g.CompletedAt != nil {
		t.Fatalf("reopened gate = %+v, want closed and pending again", g)
	}
}

func TestMoveInQueueTakesEffectBetweenEqualPriorities(t *testing.T) {
	t.Parallel()
	// Everything at priority 3: the old move swapped two equal priorities and
	// changed nothing at all.
	done := mk(9, 1, false)
	done.Status = TaskDone
	p := &Plan{Tasks: []*Task{mk(1, 3, false), mk(2, 3, false), gate(3, 3), mk(4, 3, false), done}}

	other, err := p.MoveInQueue(3, true)
	if err != nil {
		t.Fatalf("MoveInQueue(3, up): %v", err)
	}
	if other.ID != 2 {
		t.Errorf("moved past %d, want 2", other.ID)
	}
	if got := ids(p.Queue()); !sameIDs(got, []int{1, 3, 2, 4}) {
		t.Fatalf("queue after moving the gate up = %v, want [1 3 2 4]", got)
	}
	if got := ids(p.ReadyTasks()); !sameIDs(got, []int{1}) {
		t.Fatalf("ReadyTasks = %v, want [1]: the gate now holds 2 and 4", got)
	}
	if _, err := p.MoveInQueue(3, false); err != nil {
		t.Fatal(err)
	}
	if _, err := p.MoveInQueue(3, false); err != nil {
		t.Fatal(err)
	}
	if got := ids(p.Queue()); !sameIDs(got, []int{1, 2, 4, 3}) {
		t.Fatalf("queue after moving the gate down twice = %v, want [1 2 4 3]", got)
	}
	if _, err := p.MoveInQueue(3, false); !errors.Is(err, ErrQueueEdge) {
		t.Errorf("moving the last entry down: err = %v, want ErrQueueEdge", err)
	}
	if _, err := p.MoveInQueue(9, true); !errors.Is(err, ErrNotQueued) {
		t.Errorf("moving a done task: err = %v, want ErrNotQueued", err)
	}
	if done.Priority != 1 {
		t.Errorf("a move renumbered finished history: task 9 priority = %d", done.Priority)
	}
}

func TestMoveInQueueRefusesToCrossAPin(t *testing.T) {
	t.Parallel()
	p := &Plan{Tasks: []*Task{mk(1, 1, true), gate(2, 1)}}
	_, err := p.MoveInQueue(2, true)
	if err == nil || !strings.Contains(err.Error(), "unpin task 1") {
		t.Fatalf("err = %v, want a refusal naming the pin", err)
	}
}

func TestInsertInQueue(t *testing.T) {
	t.Parallel()
	build := func() *Plan {
		done := mk(1, 1, false)
		done.Status = TaskDone
		return &Plan{Tasks: []*Task{done, mk(2, 5, false), mk(3, 5, false), mk(4, 5, false)}}
	}
	for _, tc := range []struct {
		name          string
		after, before int
		want          []int
	}{
		{"end by default", 0, 0, []int{2, 3, 4, 10}},
		{"after a queued task, between equal priorities", 2, 0, []int{2, 10, 3, 4}},
		{"after a finished task goes to the head", 1, 0, []int{10, 2, 3, 4}},
		{"before a queued task", 0, 4, []int{2, 3, 10, 4}},
	} {
		p := build()
		g := NewHumanGate("Check the schema", "")
		g.ID = p.NextTaskID() + 5 // 10
		if err := p.InsertInQueue(g, tc.after, tc.before); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := ids(p.Queue()); !sameIDs(got, tc.want) {
			t.Errorf("%s: queue = %v, want %v", tc.name, got, tc.want)
		}
		if p.TaskByID(10) == nil {
			t.Errorf("%s: the gate was not added to the plan", tc.name)
		}
	}

	p := build()
	if err := p.InsertInQueue(NewHumanGate("", ""), 0, 1); !errors.Is(err, ErrNotQueued) {
		t.Errorf("before a finished task: err = %v, want ErrNotQueued", err)
	}
	if err := p.InsertInQueue(NewHumanGate("", ""), 42, 0); err == nil {
		t.Error("after a task that does not exist: no error")
	}
	if err := p.InsertInQueue(NewHumanGate("", ""), 2, 3); err == nil {
		t.Error("both after and before: no error")
	}
	if n := len(p.Tasks); n != 4 {
		t.Errorf("a refused insert added the gate anyway: %d tasks", n)
	}
}

func TestInsertInQueueKeepsAGateInsideARunOfPins(t *testing.T) {
	t.Parallel()
	p := &Plan{Tasks: []*Task{mk(1, 1, true), mk(2, 2, true), mk(3, 1, false)}}
	g := NewHumanGate("", "")
	g.ID = 4
	if err := p.InsertInQueue(g, 1, 0); err != nil {
		t.Fatal(err)
	}
	if got := ids(p.Queue()); !sameIDs(got, []int{1, 4, 2, 3}) {
		t.Fatalf("queue = %v, want [1 4 2 3]: the gate belongs between the two pinned tasks", got)
	}
	g2 := NewHumanGate("", "")
	g2.ID = 5
	if err := p.InsertInQueue(g2, 2, 0); err != nil {
		t.Fatal(err)
	}
	if g2.Pinned {
		t.Error("a gate after the last pinned task was pinned; it would jump ahead of nothing but itself")
	}
	if got := ids(p.Queue()); !sameIDs(got, []int{1, 4, 2, 5, 3}) {
		t.Fatalf("queue = %v, want [1 4 2 5 3]", got)
	}
}

func TestNewHumanGateDefaults(t *testing.T) {
	t.Parallel()
	g := NewHumanGate("  ", "  look at the migration  ")
	if g.Title != DefaultGateTitle || g.Description != "look at the migration" || !g.IsHumanGate() || g.Status != TaskPending {
		t.Fatalf("NewHumanGate = %+v", g)
	}
	for _, s := range []TaskStatus{TaskPending, TaskDone, TaskSkipped} {
		if !GateStatusAllowed(s) {
			t.Errorf("GateStatusAllowed(%s) = false", s)
		}
	}
	for _, s := range []TaskStatus{TaskInProgress, TaskFailed, TaskTimedOut} {
		if GateStatusAllowed(s) {
			t.Errorf("GateStatusAllowed(%s) = true", s)
		}
	}
}

// The agent never reads a gate as one of its tasks: not as upcoming work, and
// not as finished work it might build on.
func TestPromptsLeaveGatesOut(t *testing.T) {
	t.Parallel()
	passed := NewHumanGate("Review the API shape", "")
	passed.ID, passed.Status = 2, TaskDone
	closed := NewHumanGate("Review the migration", "")
	closed.ID, closed.Priority = 4, 9
	done := &Task{ID: 1, Title: "Design the API", Status: TaskDone}
	cur := &Task{ID: 3, Title: "Implement the API", Status: TaskInProgress}
	p := &Plan{Tasks: []*Task{done, passed, cur, closed}}

	for name, prompt := range map[string]string{
		"execute": ExecuteTaskPrompt("goal", "", "", p, cur, true),
		"replan":  AdaptiveReplanPrompt("goal", "", p, cur, "boom"),
	} {
		if strings.Contains(prompt, "Review the") {
			t.Errorf("%s prompt lists a review gate:\n%s", name, prompt)
		}
		if !strings.Contains(prompt, "Design the API") {
			t.Errorf("%s prompt lost the finished work", name)
		}
	}
}

func TestSetStatusByHand(t *testing.T) {
	t.Parallel()
	now := time.Now()
	work := mk(1, 1, false)
	if ok, err := SetStatusByHand(work, TaskFailed, "bob", now); ok || err != nil || work.Status != TaskFailed {
		t.Fatalf("work: approved=%v err=%v status=%s", ok, err, work.Status)
	}

	g := gate(2, 2)
	for _, s := range []TaskStatus{TaskFailed, TaskInProgress, TaskTimedOut} {
		if _, err := SetStatusByHand(g, s, "bob", now); err == nil {
			t.Errorf("a gate took %s", s)
		}
	}
	if g.Status != TaskPending || g.Approved {
		t.Fatalf("a refused status changed the gate: %+v", g)
	}
	if ok, err := SetStatusByHand(g, TaskDone, "bob", now); !ok || err != nil || !g.Approved || g.Status != TaskDone {
		t.Fatalf("done on a closed gate: approved=%v err=%v gate=%+v", ok, err, g)
	}
	if ok, _ := SetStatusByHand(g, TaskDone, "bob", now); ok {
		t.Error("done on an open gate counted as a second approval")
	}
	if _, err := SetStatusByHand(g, TaskPending, "bob", now); err != nil || g.Approved || !g.GateClosed() {
		t.Fatalf("pending did not close the gate: %v %+v", err, g)
	}
	if ok, err := SetStatusByHand(g, TaskSkipped, "bob", now); ok || err != nil || g.GateClosed() {
		t.Fatalf("skipped did not bypass the gate: %v %v %+v", ok, err, g)
	}
}

// A deadline never moves a gate: its place in the queue is where a person
// asked the run to stop.
func TestOverdueGateIsNotBoosted(t *testing.T) {
	t.Parallel()
	g := gate(1, 7)
	past := time.Now().Add(-time.Hour)
	g.Deadline = &past
	res := CheckAndBoostOverdue(&Plan{Tasks: []*Task{g}})
	if len(res) != 1 || res[0].Boosted || g.Priority != 7 {
		t.Fatalf("results %+v, gate priority %d: an overdue gate was moved", res, g.Priority)
	}
}

// A move changes no more priorities than it has to: two entries of different
// priority trade theirs, and every other entry keeps its own, so a P1 badge or
// a numbering someone chose survives a move elsewhere in the queue. An insert
// takes its neighbour's priority without renumbering anything.
func TestQueueEditsKeepOtherPriorities(t *testing.T) {
	t.Parallel()
	p := &Plan{Tasks: []*Task{mk(1, 10, false), mk(2, 20, false), mk(3, 30, false), mk(4, 40, false)}}
	if _, err := p.MoveInQueue(3, true); err != nil {
		t.Fatal(err)
	}
	want := map[int]int{1: 10, 2: 30, 3: 20, 4: 40}
	for id, pr := range want {
		if got := p.TaskByID(id).Priority; got != pr {
			t.Errorf("after moving 3 up, task %d has priority %d, want %d", id, got, pr)
		}
	}
	g := NewHumanGate("", "")
	g.ID = 5
	if err := p.InsertInQueue(g, 1, 0); err != nil {
		t.Fatal(err)
	}
	if got := ids(p.Queue()); !sameIDs(got, []int{1, 5, 3, 2, 4}) {
		t.Fatalf("queue = %v, want [1 5 3 2 4]", got)
	}
	for id, pr := range want {
		if got := p.TaskByID(id).Priority; got != pr {
			t.Errorf("inserting the gate renumbered task %d: %d, want %d", id, got, pr)
		}
	}
}
