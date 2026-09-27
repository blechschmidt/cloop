package suggest

import (
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Ledger turns reviewed suggestions into tasks and remembers which ones it
// has turned, so one generation's proposals can be accepted a few at a time.
//
// For brainstormed ideas that is bookkeeping: each becomes an independent
// task. For a plan it is what keeps the plan intact when its tasks are
// accepted one by one, out of order, or not all of them — each task still
// waits for the work the plan put before it:
//
//   - Tasks join the end of the run queue in plan order, so a plan accepted
//     in one go runs top to bottom.
//   - A task whose prerequisite was never added depends on that
//     prerequisite's own prerequisites instead, transitively, so skipping a
//     step does not cut the chain.
//   - A task added before one of its prerequisites gains the dependency when
//     the prerequisite arrives, provided it has not started yet.
//
// A Ledger is not safe for concurrent use.
type Ledger struct {
	plan  bool
	deps  map[int][]int   // plan task → the earlier plan tasks it depends on
	added map[int]taskRef // suggestion ID → the task it became
}

// taskRef identifies the task a suggestion became. A task ID is reused once
// the highest task is deleted, so the ID alone could name a stranger: the
// title or the description it was created with must still match — either, so
// editing one of them does not orphan the task.
type taskRef struct {
	id                 int
	title, description string
}

func (r taskRef) is(t *pm.Task) bool {
	return t.Title == r.title || (r.description != "" && t.Description == r.description)
}

// NewLedger returns an empty ledger for one generation's result.
func NewLedger(r *Result) *Ledger {
	l := &Ledger{added: map[int]taskRef{}}
	if r == nil || r.Request == "" {
		return l
	}
	l.plan = true
	l.deps = make(map[int][]int, len(r.Suggestions))
	for _, s := range r.Suggestions {
		if s != nil {
			l.deps[s.ID] = append([]int(nil), s.DependsOn...)
		}
	}
	return l
}

// Clone returns an independent copy. Apply a clone, and keep it only once
// the plan it changed has been saved.
func (l *Ledger) Clone() *Ledger {
	c := &Ledger{plan: l.plan, deps: l.deps, added: make(map[int]taskRef, len(l.added))}
	for k, v := range l.added {
		c.added[k] = v
	}
	return c
}

// Pending returns the suggestions in all that have not become tasks yet.
func (l *Ledger) Pending(all []*Suggestion) []*Suggestion {
	out := make([]*Suggestion, 0, len(all))
	for _, s := range all {
		if _, done := l.added[s.ID]; !done {
			out = append(out, s)
		}
	}
	return out
}

// Apply appends picked to plan as pending tasks and returns the tasks it
// added, in the order added. A suggestion that already became a task still in
// the plan is skipped, so repeating a request is harmless.
func (l *Ledger) Apply(plan *pm.Plan, picked []*Suggestion) []*pm.Task {
	byID := make(map[int]*pm.Task, len(plan.Tasks))
	maxID, maxPri := 0, 0
	for _, t := range plan.Tasks {
		byID[t.ID] = t
		maxID = max(maxID, t.ID)
		maxPri = max(maxPri, t.Priority)
	}
	// live resolves a suggestion to the task it became, if that task is still
	// in the plan. One the user has since removed counts as never added.
	live := func(sid int) (*pm.Task, bool) {
		ref, ok := l.added[sid]
		if !ok {
			return nil, false
		}
		t, ok := byID[ref.id]
		return t, ok && ref.is(t)
	}

	ordered := make([]*Suggestion, 0, len(picked))
	seen := map[int]bool{}
	for _, s := range picked {
		if s != nil && strings.TrimSpace(s.Title) != "" && !seen[s.ID] {
			seen[s.ID] = true
			ordered = append(ordered, s)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	var out []*pm.Task
	fresh := map[int]bool{}
	for _, s := range ordered {
		if _, ok := live(s.ID); ok {
			continue
		}
		maxID++
		t := &pm.Task{
			ID:          maxID,
			Title:       s.Title,
			Description: s.Description,
			Priority:    PriorityFor(s.Effort),
			Status:      pm.TaskPending,
			Role:        RoleFor(s.Category),
		}
		if l.plan {
			// The queue's tail, not an effort guess: sizing a plan's tasks
			// independently would let a small late step jump the large
			// early step it builds on.
			maxPri++
			t.Priority = maxPri
			t.DependsOn = l.prereqs(s.ID, live)
		}
		plan.Tasks = append(plan.Tasks, t)
		byID[t.ID] = t
		l.added[s.ID] = taskRef{t.ID, t.Title, t.Description}
		fresh[t.ID] = true
		out = append(out, t)
	}

	if l.plan && len(out) > 0 {
		steps := make([]int, 0, len(l.added))
		for sid := range l.added {
			steps = append(steps, sid)
		}
		sort.Ints(steps)
		for _, sid := range steps {
			t, ok := live(sid)
			if !ok || fresh[t.ID] || t.Status != pm.TaskPending {
				continue
			}
			for _, dep := range l.prereqs(sid, live) {
				// Only the tasks just added: an older dependency missing from
				// t was removed by someone on purpose.
				if fresh[dep] && !containsInt(t.DependsOn, dep) && !reaches(byID, dep, t.ID) {
					t.DependsOn = append(t.DependsOn, dep)
				}
			}
		}
	}
	return out
}

// prereqs returns the tasks plan step sid must wait for: the tasks its
// dependencies became, looking through any that never became one.
func (l *Ledger) prereqs(sid int, live func(int) (*pm.Task, bool)) []int {
	var out []int
	seen := map[int]bool{}
	var walk func(int)
	walk = func(s int) {
		for _, d := range l.deps[s] {
			if seen[d] {
				continue
			}
			seen[d] = true
			if t, ok := live(d); ok {
				out = append(out, t.ID)
			} else {
				walk(d)
			}
		}
	}
	walk(sid)
	sort.Ints(out)
	return out
}

// reaches reports whether task from depends, directly or transitively, on
// task target — in which case making target depend on from closes a cycle.
func reaches(byID map[int]*pm.Task, from, target int) bool {
	seen := map[int]bool{}
	stack := []int{from}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if id == target {
			return true
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if t := byID[id]; t != nil {
			stack = append(stack, t.DependsOn...)
		}
	}
	return false
}

// RoleFor maps a suggestion's category to the agent role best suited to it.
func RoleFor(c Category) pm.AgentRole {
	switch c {
	case CategoryFeature, CategoryPerformance, CategoryIntegration:
		return pm.RoleBackend
	case CategoryUX:
		return pm.RoleFrontend
	case CategorySecurity:
		return pm.RoleSecurity
	case CategoryDX:
		return pm.RoleDevOps
	case CategoryDocs:
		return pm.RoleDocs
	default:
		return ""
	}
}

// PriorityFor converts an idea's effort to a task priority (1 = highest).
// Smaller efforts get slightly higher priority to keep things moving.
func PriorityFor(e Effort) int {
	switch e {
	case EffortXS, EffortS:
		return 3
	case EffortM:
		return 4
	case EffortL, EffortXL:
		return 5
	default:
		return 4
	}
}
