package suggest

// requirements.go: a generation held to the project's requirements (Task
// 20463). Whoever generated it — the model on an executor, a cloop the hub
// cannot vouch for — it is read again here against the requirement status
// summary, the same way by `cloop suggest`, `cloop requirements plan` and the
// hub, before anything of it reaches a person or the plan. See
// requirements/planning.go for the rules.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// Purpose says what a generation was for, which decides how much of it the
// requirements may change.
type Purpose int

const (
	// ForIdeas is a brainstorm: an idea that repeats open work is dropped,
	// each must gap the ideas leave uncovered gets an idea by template, and
	// the ideas that close gaps come first, before any new feature.
	ForIdeas Purpose = iota
	// ForRequest is a plan of something a person asked for: its tasks keep
	// their order and none is added or dropped — the person asked for that
	// work. Its links are held to the requirements all the same.
	ForRequest
	// ForGaps is a plan from the requirements (`cloop requirements plan`):
	// its tasks close open gaps and link nothing else, a task repeating open
	// work is dropped, every must gap gets a task, and the tasks run by the
	// priority of what they close, each after the tasks it depends on.
	ForGaps
)

// RequirementsRequest is the request a plan from the requirements answers:
// what marks it as a plan, whose tasks depend on each other, rather than
// loose ideas.
const RequirementsRequest = "Close the open gaps in the project's requirements"

// ApplyRequirements holds r's suggestions to sum, as purpose allows, and
// records in r.Notes what that changed. r must be normalized first
// (NormalizePlan, NormalizeIdeas); its suggestions are renumbered 1..N again
// when their order changes. limit, when above 0, bounds a plan from the
// requirements, tasks added for must gaps included. A project with no
// approved requirement keeps none of the links a model proposed, and nothing
// else changes.
func ApplyRequirements(r *Result, sum requirements.StatusSummary, purpose Purpose, limit int) {
	if r == nil {
		return
	}
	if sum.Empty() {
		for _, s := range r.Suggestions {
			s.Requirements, s.Kind, s.Priority = nil, "", 0
		}
		return
	}
	kept := make([]*Suggestion, 0, len(r.Suggestions))
	for _, s := range r.Suggestions {
		ids := []int(s.Requirements)
		if len(ids) == 0 {
			ids = requirements.MentionedRefs(s.Title)
		}
		links := sum.KeepLinks(ids, false)
		if purpose != ForRequest {
			if open := sum.CoveringTasks(links); len(open) > 0 {
				r.Notes = append(r.Notes, fmt.Sprintf("Left out %q: %s already implemented by open task %s.",
					s.Title, keyList(links), taskRefs(open)))
				continue
			}
		}
		if purpose == ForGaps {
			links = sum.KeepLinks(links, true)
		}
		setLinks(s, links, sum, purpose == ForGaps)
		kept = append(kept, s)
	}
	r.Suggestions = kept

	if purpose != ForRequest {
		room := requirements.MaxGapFallback
		if purpose == ForGaps {
			if limit <= 0 || limit > MaxCount {
				limit = MaxCount
			}
			room = limit - len(r.Suggestions)
		}
		var links [][]int
		nextID := 0
		for _, s := range r.Suggestions {
			links = append(links, s.Requirements)
			nextID = max(nextID, s.ID)
		}
		for _, st := range sum.UncoveredMusts(links...) {
			if room <= 0 {
				break
			}
			room--
			// Numbered past every suggestion kept: one dropped above left a
			// gap, and its number may still be what a kept one depends on.
			nextID++
			title, desc := requirements.GapTask(st)
			s := &Suggestion{ID: nextID, Title: title, Description: desc, Effort: EffortM,
				Rationale: st.Key() + " is a must requirement with an open gap, and nothing else proposed closes it."}
			setLinks(s, []int{st.ID}, sum, true)
			r.Suggestions = append(r.Suggestions, s)
			r.Notes = append(r.Notes, fmt.Sprintf("Added %q: the must requirement %s had no task.", title, st.Key()))
		}
		orderByRequirements(r, sum)
	}
}

// setLinks gives s the links it keeps and what follows from them: its kind,
// and for a test task a description that says how its test is named. Only a
// task closing gaps alone — of a plan from the requirements, or by template —
// is taken to be a test task for linking only requirements that lack a test:
// an idea or a person's request may do more than test what it links.
func setLinks(s *Suggestion, links []int, sum requirements.StatusSummary, gapsOnly bool) {
	s.Requirements = links
	s.Kind = sum.KindFor(links)
	s.Priority = 0
	if s.Kind != requirements.ActionTest {
		return
	}
	if !gapsOnly {
		s.Kind = ""
		return
	}
	if !strings.Contains(s.Description, "shell command") {
		s.Description = strings.TrimRight(s.Description, "\n") + requirements.TestKindNote
	}
}

// orderByRequirements orders r's suggestions by the requirements they close
// (requirements.PlanOrder) and renumbers them in that order. A suggestion
// that closes a gap takes the priority its requirement asks for; when one
// closes a must gap, every suggestion that closes none is put behind all of
// them.
func orderByRequirements(r *Result, sum requirements.StatusSummary) {
	n := len(r.Suggestions)
	index := make(map[int]int, n)
	for i, s := range r.Suggestions {
		index[s.ID] = i
	}
	ranks := make([]int, n)
	deps := make([][]int, n)
	for i, s := range r.Suggestions {
		ranks[i] = sum.RankFor(s.Requirements)
		for _, d := range s.DependsOn {
			if j, ok := index[d]; ok && j != i {
				deps[i] = append(deps[i], j)
			}
		}
	}
	order, effective := requirements.PlanOrder(ranks, deps)
	newID := make(map[int]int, n)
	out := make([]*Suggestion, 0, n)
	mustGap, lastGap := false, 0
	for k, i := range order {
		s := r.Suggestions[i]
		newID[s.ID] = k + 1
		if effective[i] < requirements.NoRank {
			s.Priority = requirements.TaskPriority(requirements.RankPriority(effective[i]))
			mustGap = mustGap || effective[i] == 0
			lastGap = max(lastGap, s.Priority)
		}
		out = append(out, s)
	}
	for k, i := range order {
		s := r.Suggestions[i]
		s.ID = k + 1
		var deps []int
		for _, d := range s.DependsOn {
			if nd, ok := newID[d]; ok && nd < s.ID {
				deps = append(deps, nd)
			}
		}
		slices.Sort(deps)
		s.DependsOn = deps
		if mustGap && effective[i] == requirements.NoRank {
			s.Priority = max(PriorityFor(s.Effort), lastGap+1)
		}
	}
	r.Suggestions = out
}

func keyList(ids []int) string {
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = requirements.Key(id)
	}
	if len(keys) == 1 {
		return keys[0] + " is"
	}
	return strings.Join(keys, ", ") + " are"
}

func taskRefs(ids []int) string {
	refs := make([]string, len(ids))
	for i, id := range ids {
		refs[i] = fmt.Sprintf("#%d", id)
	}
	return strings.Join(refs, ", ")
}

// Uncovered are the must gaps r's suggestions leave open: what a person
// reviewing them is warned of.
func Uncovered(r *Result, sum requirements.StatusSummary) []requirements.Standing {
	var links [][]int
	if r != nil {
		for _, s := range r.Suggestions {
			links = append(links, s.Requirements)
		}
	}
	return sum.UncoveredMusts(links...)
}
