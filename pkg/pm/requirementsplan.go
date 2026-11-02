package pm

// requirementsplan.go: tasks proposed with the requirements in view (Task
// 20463). An auto-evolve round is told where the project's requirements stand
// (requirements.StatusSummary) and asked to link what it closes; what it
// answers is then held to the summary here before it joins the plan — the
// rules of requirements/planning.go, applied to tasks.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// Tags a task made to close a requirement's gap carries.
const (
	// TagRequirement marks a task that closes an approved requirement's gap.
	TagRequirement = "requirement"
	// TagTestOnly marks one whose whole job is a test for a requirement that
	// is believed to hold: it changes nothing else.
	TagTestOnly = "test-only"
)

// TaskViews is plan's tasks as requirements.Assess reads them.
func TaskViews(plan *Plan) []requirements.TaskView {
	if plan == nil {
		return nil
	}
	out := make([]requirements.TaskView, 0, len(plan.Tasks))
	for _, t := range plan.Tasks {
		if t == nil {
			continue
		}
		v := requirements.TaskView{ID: t.ID, Status: string(t.Status), Requirements: t.Requirements}
		if t.CompletedAt != nil {
			v.CompletedAt = *t.CompletedAt
		}
		out = append(out, v)
	}
	return out
}

// LinkProposedTasks holds the requirement links of tasks a planner proposed
// to sum: each keeps only approved requirements sum names — never a draft, a
// deprecated requirement or an id the model made up — and one the model gave
// no links names the requirements its title does (R-<n>). A task that then
// closes a gap is tagged so. What it does is the model's to say: one that
// links only requirements lacking a test is not taken to write nothing but
// the test — only a task by template is (CloseMustGaps).
func LinkProposedTasks(tasks []*Task, sum requirements.StatusSummary) {
	for _, t := range tasks {
		if t == nil {
			continue
		}
		ids := t.Requirements
		if len(ids) == 0 {
			ids = requirements.MentionedRefs(t.Title)
		}
		t.Requirements = sum.KeepLinks(ids, false)
		if kind := sum.KindFor(t.Requirements); kind != "" {
			addTag(t, TagRequirement)
		}
	}
}

// markGapTask tags a task by template for the kind of gap it closes: one
// that only adds a test is a test task — tagged, given to the testing role,
// and told how its test is to be named.
func markGapTask(t *Task, kind string) {
	if kind == "" {
		return
	}
	addTag(t, TagRequirement)
	if kind != requirements.ActionTest {
		return
	}
	addTag(t, TagTestOnly)
	t.Role = RoleTesting
	if !strings.Contains(t.Description, "shell command") {
		t.Description = strings.TrimRight(t.Description, "\n") + requirements.TestKindNote
	}
}

func addTag(t *Task, tag string) {
	if !slices.Contains(t.Tags, tag) {
		t.Tags = append(t.Tags, tag)
	}
}

// RequirementDuplicate is a proposed task dropped for repeating open work:
// every requirement it links is implemented by an open task already.
type RequirementDuplicate struct {
	Task *Task
	// Open are the open tasks that implement what it links.
	Open []int
}

// Reason says why it was dropped.
func (d RequirementDuplicate) Reason() string {
	keys := make([]string, len(d.Task.Requirements))
	for i, id := range d.Task.Requirements {
		keys[i] = requirements.Key(id)
	}
	open := make([]string, len(d.Open))
	for i, id := range d.Open {
		open[i] = fmt.Sprintf("#%d", id)
	}
	return fmt.Sprintf("%q links %s, which open task %s already implements", d.Task.Title,
		strings.Join(keys, ", "), strings.Join(open, ", "))
}

// DedupByRequirements drops the candidates that link only requirements an
// open task already implements: the semantic dedup's question, answered from
// the links (Task 20463). A candidate that links nothing is left for the
// semantic dedup to judge.
func DedupByRequirements(candidates []*Task, sum requirements.StatusSummary) (kept []*Task, dropped []RequirementDuplicate) {
	for _, t := range candidates {
		if open := sum.CoveringTasks(t.Requirements); len(open) > 0 {
			dropped = append(dropped, RequirementDuplicate{Task: t, Open: open})
			continue
		}
		kept = append(kept, t)
	}
	return kept, dropped
}

// CloseMustGaps adds to tasks, for each must gap they leave uncovered — at
// most requirements.MaxGapFallback — the task by template that closes it
// (requirements.GapTask). Whatever the model proposed, a project with open
// must gaps gets the tasks that close them. The added tasks have no IDs yet:
// OrderByRequirements gives them.
func CloseMustGaps(tasks []*Task, sum requirements.StatusSummary) []*Task {
	links := make([][]int, 0, len(tasks))
	for _, t := range tasks {
		links = append(links, t.Requirements)
	}
	for i, st := range sum.UncoveredMusts(links...) {
		if i == requirements.MaxGapFallback {
			break
		}
		title, desc := requirements.GapTask(st)
		t := &Task{Title: title, Description: desc, Status: TaskPending, Requirements: []int{st.ID}}
		markGapTask(t, st.Action)
		tasks = append(tasks, t)
	}
	return tasks
}

// OrderByRequirements puts tasks in the order they should run and numbers
// them from firstID in that order: the tasks that close gaps first, by the
// priority of the requirements they close (requirements.PlanOrder), each
// still after the tasks of the batch it depends on. A task closing a gap
// takes the priority its requirement asks for (requirements.TaskPriority, or
// a more important one a later task of the batch waits on); when the batch
// closes a must gap, every task that closes none is put behind all of them —
// gap-closing work before any new feature. A dependency on a task the plan
// already has — one numbered below firstID — is kept as it is; one on a task
// of the batch that was dropped names nothing, and is dropped too, before its
// number can be handed to another task of the batch.
func OrderByRequirements(tasks []*Task, sum requirements.StatusSummary, firstID int) []*Task {
	n := len(tasks)
	if n == 0 {
		return tasks
	}
	index := make(map[int]int, n)
	for i, t := range tasks {
		if t.ID > 0 {
			index[t.ID] = i
		}
	}
	ranks := make([]int, n)
	deps := make([][]int, n)
	for i, t := range tasks {
		ranks[i] = sum.RankFor(t.Requirements)
		for _, d := range t.DependsOn {
			if j, ok := index[d]; ok && j != i {
				deps[i] = append(deps[i], j)
			}
		}
	}
	order, effective := requirements.PlanOrder(ranks, deps)

	newID := make(map[int]int, n) // a task's old ID → its new one
	out := make([]*Task, 0, n)
	mustGap, lastGapPriority := false, 0
	for k, i := range order {
		t := tasks[i]
		if t.ID > 0 {
			newID[t.ID] = firstID + k
		}
		if effective[i] < requirements.NoRank {
			t.Priority = requirements.TaskPriority(requirements.RankPriority(effective[i]))
			mustGap = mustGap || effective[i] == 0
			lastGapPriority = max(lastGapPriority, t.Priority)
		}
		out = append(out, t)
	}
	for k, i := range order {
		t := tasks[i]
		t.ID = firstID + k
		var kept []int
		for _, d := range t.DependsOn {
			if _, inBatch := index[d]; inBatch {
				if nd, ok := newID[d]; ok && nd != t.ID && !slices.Contains(kept, nd) {
					kept = append(kept, nd)
				}
				continue
			}
			if d > 0 && d < firstID && !slices.Contains(kept, d) {
				kept = append(kept, d)
			}
		}
		t.DependsOn = kept
		if mustGap && effective[i] == requirements.NoRank && t.Priority <= lastGapPriority {
			t.Priority = lastGapPriority + 1
		}
	}
	return out
}
