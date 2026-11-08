package pm

// Human review gates (Task 20477).
//
// A human review gate is an entry in the task list that no agent ever runs. It
// keeps its place in the run queue like any task, by the same pinned, priority
// and id order, moved by the same drag in the dashboard and the same
// `cloop task move`, and a run stops when it reaches one: every task ahead of it
// has finished, so a person can look at what those tasks produced, edit the
// tasks still to come or put new ones ahead of the gate, and only then let the
// run carry on past it by approving the gate.
//
// A gate is a task rather than a list of its own because its position is the
// whole of its meaning, and the queue is where positions live. Being a task
// also means everything that lists, reorders, exports, merges or seeds tasks
// carries gates with it, rather than a second implementation of each that
// could disagree with the first about where a gate stands.
//
// The states, all of them ordinary task fields:
//
//   - closed: pending and not approved. The first closed gate in execution
//     order holds every task after it, however ready.
//   - approved: Approved is set and the status is still pending. Nothing waits
//     on it any more; the run records that it went past (done) at its next
//     look at the plan. Approved is a definition field, so an approval made
//     while a run holds the plan survives that run's saves.
//   - passed (done) or bypassed (skipped): history.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// TaskKind distinguishes work for an agent from the entries of a plan that
// are not work.
type TaskKind string

const (
	// KindWork is an ordinary task: work for an agent. It is the zero value,
	// so every task stored before kinds existed is work.
	KindWork TaskKind = ""
	// KindHumanGate is a human review gate.
	KindHumanGate TaskKind = "human_gate"
)

// DefaultGateTitle is the title of a gate created without one.
const DefaultGateTitle = "Human review"

// IsWork reports whether t is work for an agent. Only work is ever handed to
// one. A human review gate is not work, and neither is a kind added by a newer
// build that this one does not know: such an entry holds the queue as a closed
// gate would, rather than reach an agent as a task it was never meant to be.
func (t *Task) IsWork() bool { return t.Kind == KindWork }

// IsHumanGate reports whether t is a human review gate.
func (t *Task) IsHumanGate() bool { return t.Kind == KindHumanGate }

// GateClosed reports whether t holds the run queue: an entry that is not work,
// has not been approved, and has been neither passed nor bypassed.
func (t *Task) GateClosed() bool {
	if t.IsWork() || t.Approved {
		return false
	}
	return t.Status != TaskDone && t.Status != TaskSkipped
}

// GateBarrier returns the closed gate that holds the queue: the first one in
// execution order. Every task after it in that order waits until it is
// approved. Nil when the plan holds no closed gate.
func (p *Plan) GateBarrier() *Task {
	if p == nil {
		return nil
	}
	var barrier *Task
	for _, t := range p.Tasks {
		if t != nil && t.GateClosed() && (barrier == nil || LessByExecutionOrder(t, barrier)) {
			barrier = t
		}
	}
	return barrier
}

// HeldBy reports whether gate holds t: t comes after the gate in execution
// order. A nil gate holds nothing.
func HeldBy(gate, t *Task) bool {
	return gate != nil && t != gate && LessByExecutionOrder(gate, t)
}

// WaitingGate returns the closed gate a run has reached: the barrier, once no
// work ahead of it can run. Nothing is in progress and nothing is ready, so
// what remains needs a person. It is the moment a run stops for review, and
// nil while work ahead of the gate is still running or could start.
//
// "Nothing ready" counts pending tasks ahead of the gate that cannot start —
// waiting on a dependency held behind the gate, or blocked by a failed one —
// as reached too: no run could move them without a person either.
func (p *Plan) WaitingGate() *Task {
	barrier := p.GateBarrier()
	if barrier == nil {
		return nil
	}
	for _, t := range p.Tasks {
		if t != nil && t.Status == TaskInProgress {
			return nil
		}
	}
	if len(p.ReadyTasks()) > 0 {
		return nil
	}
	return barrier
}

// NewHumanGate returns a pending gate with the given title, or
// DefaultGateTitle, and note: what the reviewer should look at. It carries no
// ID or priority yet; InsertInQueue gives it both a place and the priority
// that holds it there.
func NewHumanGate(title, note string) *Task {
	title = strings.TrimSpace(title)
	if title == "" {
		title = DefaultGateTitle
	}
	return &Task{
		Kind:        KindHumanGate,
		Title:       title,
		Description: strings.TrimSpace(note),
		Status:      TaskPending,
	}
}

// ApproveGate opens gate t for whoever approved it: approved, and passed at
// now unless it already was. The approval is noted on the gate under by.
func ApproveGate(t *Task, by string, now time.Time) {
	t.Approved = true
	if t.Status != TaskDone && t.Status != TaskSkipped {
		t.Status = TaskDone
		at := now.UTC()
		t.CompletedAt = &at
	}
	if by = strings.TrimSpace(by); by == "" {
		by = "user"
	}
	AddAnnotation(t, by, "Approved: the run may continue past this review gate.")
}

// PassGate records that a run went past approved gate t at now.
func PassGate(t *Task, now time.Time) {
	t.Status = TaskDone
	if t.CompletedAt == nil {
		at := now.UTC()
		t.CompletedAt = &at
	}
	AddAnnotation(t, "cloop", "Passed: the gate was approved, so the run continued past it.")
}

// ReopenGate closes gate t again: pending and no longer approved, so a run
// stops at it once more.
func ReopenGate(t *Task) {
	t.Approved = false
	t.Status = TaskPending
	t.CompletedAt = nil
}

// SetStatusByHand applies a status a person chose for t. Work takes it as it
// is. A gate gives it its own meaning: done approves the gate (approved, and
// passed at now, noted under by), pending closes it again and skipped bypasses
// it; any other status is refused, and t is left alone. It reports whether the
// change approved a gate, which the caller records once it is saved.
//
// Every route by which a person sets a status uses it — the dashboard's two,
// `cloop task done|reset|skip|fail`, `cloop task bulk` and `cloop serve`'s
// API — so none of them can open a gate without it counting as an approval.
func SetStatusByHand(t *Task, to TaskStatus, by string, now time.Time) (approved bool, err error) {
	if t.IsWork() {
		t.Status = to
		return false, nil
	}
	if !GateStatusAllowed(to) {
		return false, fmt.Errorf("task %d is a human review gate: it is pending (waiting for review), "+
			"done (approved) or skipped, never %s", t.ID, to)
	}
	switch {
	case to == TaskDone && t.GateClosed():
		ApproveGate(t, by, now)
		return true, nil
	case to == TaskPending:
		ReopenGate(t)
	default:
		t.Status = to
	}
	return false, nil
}

// GateStatusAllowed reports whether a gate may be given status s by hand. A
// gate is closed (pending), passed (done) or bypassed (skipped). It never runs,
// so it is never in progress, and nothing it does can fail.
func GateStatusAllowed(s TaskStatus) bool {
	return s == TaskPending || s == TaskDone || s == TaskSkipped
}

// Queue returns the run queue: every pending entry of the plan, gates
// included, in execution order.
func (p *Plan) Queue() []*Task {
	if p == nil {
		return nil
	}
	var q []*Task
	for _, t := range p.Tasks {
		if t != nil && t.Status == TaskPending {
			q = append(q, t)
		}
	}
	return SortByExecutionOrder(q)
}

// Rerank gives the entries of q the priorities 1..len(q) in the order given,
// which is what dragging the dashboard's rows does (POST /api/tasks/reorder):
// the queue then runs in exactly q's order, whatever priorities its entries
// had, so a move between two tasks of equal priority is not lost on the ID
// tiebreak. Pinned entries keep their flag, and with it their place ahead of
// the unpinned ones.
func Rerank(q []*Task) {
	for i, t := range q {
		t.Priority = i + 1
	}
}

// ErrQueueEdge is returned by MoveInQueue for an entry already at the end of
// the queue it was asked to move towards.
var ErrQueueEdge = errors.New("already at the edge of the run queue")

// ErrNotQueued is returned for an entry that is not pending: a finished task's
// place is history, and a running one has left the queue.
var ErrNotQueued = errors.New("not in the run queue")

// MoveInQueue moves the pending entry id one place up (towards the head of the
// queue) or down. It returns the entry it moved past.
//
// The change is the smallest that makes the move take effect: the two entries
// trade priorities, as they always did, and every other entry keeps its own.
// Where that is not enough — two entries of equal priority trade nothing, and
// the id tiebreak can carry a third entry between them — the queue is
// re-ranked in the new order instead, as a drag in the dashboard does.
//
// Pinned entries run ahead of every unpinned one, so an entry cannot be moved
// past one that differs from it in that: the move is refused rather than
// silently undone by the pin.
func (p *Plan) MoveInQueue(id int, up bool) (*Task, error) {
	q := p.Queue()
	idx := -1
	for i, t := range q {
		if t.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		if t := p.TaskByID(id); t != nil {
			return nil, fmt.Errorf("task %d is %s: %w", id, t.Status, ErrNotQueued)
		}
		return nil, fmt.Errorf("task %d: %w", id, ErrNotQueued)
	}
	j, where := idx+1, "end"
	if up {
		j, where = idx-1, "head"
	}
	if j < 0 || j >= len(q) {
		return nil, fmt.Errorf("task %d is at the %s of the run queue: %w", id, where, ErrQueueEdge)
	}
	if q[idx].Pinned != q[j].Pinned {
		pinned, other := q[idx], q[j]
		if !pinned.Pinned {
			pinned, other = other, pinned
		}
		return nil, fmt.Errorf("task %d is pinned and task %d is not, and pinned tasks run first: "+
			"unpin task %d to move it past task %d", pinned.ID, other.ID, pinned.ID, other.ID)
	}
	want := append([]*Task(nil), q...)
	want[idx], want[j] = want[j], want[idx]
	q[idx].Priority, q[j].Priority = q[j].Priority, q[idx].Priority
	if !sameQueue(SortByExecutionOrder(want), want) {
		Rerank(want)
	}
	return want[idx], nil
}

// sameQueue reports whether a and b list the same entries in the same order.
func sameQueue(a, b []*Task) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// InsertInQueue adds t to the plan at a position in the run queue:
//
//   - after > 0: right after task after. A task that is running or finished
//     has left the queue, so everything still in it comes after that task: t
//     goes to the head of the queue.
//   - before > 0: right before task before, which must still be in the queue.
//   - neither: the end of the queue.
//
// t takes the priority of the entry it follows (or one less than the head's,
// at the head), so no other entry's priority changes; where the id tiebreak
// would then carry t past its neighbour, the queue is re-ranked instead. t
// also takes the pinned flag of the entry it goes before, so it is not carried
// past a run of pinned entries by the pin of its neighbour. The caller gives t
// its ID, higher than any other; t's status should be pending.
func (p *Plan) InsertInQueue(t *Task, after, before int) error {
	if after > 0 && before > 0 {
		return errors.New("give a position after a task or before one, not both")
	}
	q := p.Queue()
	at := len(q)
	switch {
	case after > 0:
		ref := p.TaskByID(after)
		if ref == nil {
			return fmt.Errorf("task %d: no such task in this plan", after)
		}
		at = 0
		for i, e := range q {
			if e.ID == after {
				at = i + 1
				break
			}
		}
	case before > 0:
		ref := p.TaskByID(before)
		if ref == nil {
			return fmt.Errorf("task %d: no such task in this plan", before)
		}
		at = -1
		for i, e := range q {
			if e.ID == before {
				at = i
				break
			}
		}
		if at < 0 {
			return fmt.Errorf("task %d is %s, so nothing can be placed before it: %w", before, ref.Status, ErrNotQueued)
		}
	}
	t.Pinned = at < len(q) && q[at].Pinned
	want := make([]*Task, 0, len(q)+1)
	want = append(append(append(want, q[:at]...), t), q[at:]...)
	switch {
	case at > 0:
		t.Priority = q[at-1].Priority
	case len(q) > 0:
		t.Priority = q[0].Priority - 1
	default:
		t.Priority = 1
	}
	if t.Priority < 1 || !sameQueue(SortByExecutionOrder(want), want) {
		Rerank(want)
	}
	p.Tasks = append(p.Tasks, t)
	return nil
}

// NextTaskID returns the ID a new task in p takes: one past the highest in use.
func (p *Plan) NextTaskID() int {
	max := 0
	if p != nil {
		for _, t := range p.Tasks {
			if t != nil && t.ID > max {
				max = t.ID
			}
		}
	}
	return max + 1
}

// HasPendingGates reports whether the plan holds a pending entry that is not
// work: one that a cloop predating human review gates would hand to an agent
// as a task. Approved gates count until a run records them as passed.
func (p *Plan) HasPendingGates() bool {
	if p == nil {
		return false
	}
	for _, t := range p.Tasks {
		if t != nil && !t.IsWork() && t.Status == TaskPending {
			return true
		}
	}
	return false
}

// WorkTasks returns the plan's work, leaving out the entries no agent runs.
// Prompts that show an agent the plan use it: a gate is a decision for a
// person, and listed among the tasks it would read as one more thing to do.
func WorkTasks(tasks []*Task) []*Task {
	out := make([]*Task, 0, len(tasks))
	for _, t := range tasks {
		if t != nil && t.IsWork() {
			out = append(out, t)
		}
	}
	return out
}
