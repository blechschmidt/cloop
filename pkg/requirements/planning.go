package requirements

// planning.go: the rules every planner holds its proposals to once it knows
// where the requirements stand (standing.go) — Task 20463.
//
// A planner — `cloop requirements plan`, the suggestions panel's brainstorm,
// an auto-evolve round — asks the model for tasks, and the model is told which
// requirements have open gaps. What it answers is then held to the summary
// here, the same way wherever it is read, so the hub can read again what an
// executor's cloop sent it:
//
//   - a task links only approved requirements the summary names: an id the
//     model made up, a draft's or a deprecated requirement's is dropped;
//   - a task's kind follows from what it links — a task that links only
//     requirements that lack nothing but a test is a test task;
//   - work is ordered by the requirements it closes, must first, each task
//     still after the tasks it depends on (PlanOrder);
//   - a must gap the model left uncovered gets a task by template (GapTask),
//     so "a project with open must gaps gets gap-closing tasks before any new
//     feature" holds whatever the model did;
//   - a proposal that links only requirements an open task already implements
//     repeats that task, and is dropped (CoveringTasks).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// MaxProposed bounds the tasks one plan proposes — the plan's tasks, or the
// tasks the plan assistant proposes in one answer.
const MaxProposed = 20

// MaxGapFallback bounds the tasks by template one brainstorm or evolve round
// adds for must gaps the model left uncovered; the rest wait for the next.
const MaxGapFallback = 5

// LooseRefs reads the requirements a model says a task links: numbers, or
// names such as "R-3", "#3" or "3". Unlike Refs, an entry that names no
// requirement is passed over rather than refused — the model's answer is read
// for what it can be trusted with, and each id is checked against the project
// afterwards. Anything but a list reads as none.
type LooseRefs []int

// UnmarshalJSON reads a JSON list of requirement ids or names.
func (r *LooseRefs) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		*r = nil
		return nil
	}
	out := make(LooseRefs, 0, min(len(raw), MaxTaskLinks))
	for _, e := range raw {
		if len(out) == MaxTaskLinks {
			break
		}
		e = bytes.TrimSpace(e)
		var id int
		if len(e) > 0 && e[0] == '"' {
			var s string
			if json.Unmarshal(e, &s) != nil {
				continue
			}
			n, err := ParseRef(s)
			if err != nil {
				continue
			}
			id = n
		} else if json.Unmarshal(e, &id) != nil || id <= 0 {
			continue
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		out = nil
	}
	*r = out
	return nil
}

var mentionRe = regexp.MustCompile(`\bR-([1-9][0-9]{0,5})\b`)

// MentionedRefs are the requirements text names as R-<n>, in the order it
// first names them, at most MaxTaskLinks.
func MentionedRefs(text string) []int {
	var out []int
	for _, m := range mentionRe.FindAllStringSubmatch(text, -1) {
		id, err := strconv.Atoi(m[1])
		if err != nil || slices.Contains(out, id) {
			continue
		}
		out = append(out, id)
		if len(out) == MaxTaskLinks {
			break
		}
	}
	return out
}

// KeepLinks is ids as the links a proposed task may carry: requirements the
// summary names — approved ones, so never a draft or a deprecated one — in
// id order, without repeats, at most MaxTaskLinks. With targetsOnly only the
// requirements with a gap a task closes are kept.
func (s StatusSummary) KeepLinks(ids []int, targetsOnly bool) []int {
	var out []int
	for _, id := range ids {
		st, ok := s.Lookup(id)
		if !ok || slices.Contains(out, id) || (targetsOnly && !st.Target()) {
			continue
		}
		out = append(out, id)
	}
	slices.Sort(out)
	if len(out) > MaxTaskLinks {
		out = out[:MaxTaskLinks]
	}
	return out
}

// KindFor is the kind of a task that links ids: test when every requirement
// it links that has a gap lacks only a test, else the strongest action among
// them; empty when it links none with a gap a task closes.
func (s StatusSummary) KindFor(ids []int) string {
	best := len(targetActions)
	for _, id := range ids {
		st, ok := s.Lookup(id)
		if !ok {
			continue
		}
		if i := slices.Index(targetActions, st.Action); i >= 0 && i < best {
			best = i
		}
	}
	if best == len(targetActions) {
		return ""
	}
	return targetActions[best]
}

// RankFor is the rank of the most important requirement with an open gap
// that ids links (PriorityRank), or NoRank when it links none.
func (s StatusSummary) RankFor(ids []int) int {
	rank := NoRank
	for _, id := range ids {
		if st, ok := s.Lookup(id); ok && st.Target() {
			rank = min(rank, st.Rank())
		}
	}
	return rank
}

// PriorityFor is the priority of the most important requirement with an open
// gap that ids links, or "" when it links none.
func (s StatusSummary) PriorityFor(ids []int) string { return RankPriority(s.RankFor(ids)) }

// CoveringTasks are the open tasks that implement the requirements ids names,
// when an open task implements every one of them: a proposal that links only
// those repeats work already planned. Nil when ids is empty, or names a
// requirement no open task implements.
func (s StatusSummary) CoveringTasks(ids []int) []int {
	if len(ids) == 0 {
		return nil
	}
	var tasks []int
	for _, id := range ids {
		st, ok := s.Lookup(id)
		if !ok || len(st.Open) == 0 {
			return nil
		}
		for _, t := range st.Open {
			if !slices.Contains(tasks, t) {
				tasks = append(tasks, t)
			}
		}
	}
	slices.Sort(tasks)
	return tasks
}

// UncoveredMusts are the must gaps that none of the link lists names: what a
// plan leaves open of what comes first.
func (s StatusSummary) UncoveredMusts(links ...[]int) []Standing {
	var out []Standing
	for _, st := range s.MustGaps() {
		covered := false
		for _, l := range links {
			if slices.Contains(l, st.ID) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, st)
		}
	}
	return out
}

// GapTask is the task that closes st's gap by template, for a must gap no
// planner proposed one for: its title and description. The task links st, so
// its agent is also given the requirement's details and tests as its contract.
func GapTask(st Standing) (title, description string) {
	key := st.Key()
	var b strings.Builder
	switch st.Action {
	case ActionFix:
		title = "Restore " + key + ": " + st.Title
		fmt.Fprintf(&b, "Requirement %s does not hold: %s\n", key, sentence(st.Title))
		if st.Summary != "" {
			fmt.Fprintf(&b, "\nIts last check (%s): %s\n", st.Verdict, st.Summary)
		}
		b.WriteString("\nChange the project so the requirement holds again")
		if st.Tested {
			b.WriteString(", and run its tests to show it.\n")
		} else {
			b.WriteString(". It has no automated test: write one that passes exactly when it holds, using the " +
				"project's own test framework, and end your summary with the single shell command, run from the " +
				"project's root, that runs only that test.\n")
		}
	case ActionVerify:
		title = "Verify " + key + ": " + st.Title
		fmt.Fprintf(&b, "Requirement %s changed since it was last found to hold: %s\n", key, sentence(st.Title))
		b.WriteString("\nRun its tests against the current code. If they fail, change the project so the " +
			"requirement holds as it reads now, and run them again to show it.\n")
	case ActionTest:
		title = "Add a test for " + key + ": " + st.Title
		fmt.Fprintf(&b, "Requirement %s has no automated test: %s\n", key, sentence(st.Title))
		b.WriteString("\nIt is believed to hold. Write an automated test that passes exactly when this requirement " +
			"holds, using the project's own test framework, and make it pass without changing what the project " +
			"does. End your summary with the single shell command, run from the project's root, that runs only " +
			"this test — it becomes the requirement's test once a person attaches it.\n")
	default:
		title = "Implement " + key + ": " + st.Title
		fmt.Fprintf(&b, "Nothing shows yet that requirement %s holds: %s\n", key, sentence(st.Title))
		b.WriteString("\nChange the project so it does")
		if st.Tested {
			b.WriteString(", and run its tests to show it.\n")
		} else {
			b.WriteString(", and write an automated test that passes exactly when it holds. End your summary with " +
				"the single shell command, run from the project's root, that runs only that test.\n")
		}
	}
	return truncateRunes(title, MaxTitleRunes), b.String()
}

// sentence is s ended as a sentence: a description read with its line breaks
// collapsed — as the suggestions panel shows one — runs on otherwise.
func sentence(s string) string {
	if strings.HasSuffix(s, ".") || strings.HasSuffix(s, "!") || strings.HasSuffix(s, "?") {
		return s
	}
	return s + "."
}

// TestKindNote is what a test task's description is given when it does not
// say how its test is to be named: the command is what a person attaches.
const TestKindNote = "\n\nWrite only the test: change nothing about what the project does. End your summary with " +
	"the single shell command, run from the project's root, that runs only this test — it becomes the " +
	"requirement's test once a person attaches it."

// PlanOrder orders proposals by the requirements they close, most important
// first, each after the proposals it depends on. ranks[i] is proposal i's
// rank (RankFor) and deps[i] the indexes of the proposals it depends on. It
// returns the order, as indexes, and each proposal's effective rank: a
// proposal that more important work waits for runs as early as that work.
// Proposals of equal rank keep the order they came in.
func PlanOrder(ranks []int, deps [][]int) (order []int, effective []int) {
	n := len(ranks)
	effective = slices.Clone(ranks)
	// Inherit: repeat until nothing changes. Each pass can only lower a
	// rank, and there are five ranks.
	for changed := true; changed; {
		changed = false
		for i := range n {
			for _, d := range deps[i] {
				if d >= 0 && d < n && effective[i] < effective[d] {
					effective[d] = effective[i]
					changed = true
				}
			}
		}
	}
	placed := make([]bool, n)
	for len(order) < n {
		best := -1
		for i := range n {
			if placed[i] || !depsPlaced(deps[i], placed, i) {
				continue
			}
			if best < 0 || effective[i] < effective[best] {
				best = i
			}
		}
		if best < 0 {
			// A cycle: nothing is ready. Take the first left, as it came.
			best = slices.Index(placed, false)
		}
		placed[best] = true
		order = append(order, best)
	}
	return order, effective
}

func depsPlaced(deps []int, placed []bool, self int) bool {
	for _, d := range deps {
		if d >= 0 && d < len(placed) && d != self && !placed[d] {
			return false
		}
	}
	return true
}

// PlanPrompt asks the model for the tasks that close the open gaps of sum.
// existing lists the plan's open tasks; count > 0 asks for at most that many
// tasks, 0 leaves it to the gaps, up to MaxProposed.
func PlanPrompt(goal, instructions, fileTree, existing string, sum StatusSummary, count int) string {
	var b strings.Builder
	b.WriteString("You are a senior software architect planning the work that closes the gaps in a project's\n" +
		"requirements — its spec. A gap is an approved requirement the project does not demonstrably meet yet.\n" +
		"AI coding agents will carry out the tasks you plan, one after another.\n\n")
	fmt.Fprintf(&b, "## PROJECT GOAL\n%s\n\n", goal)
	if instructions != "" {
		fmt.Fprintf(&b, "## CONSTRAINTS\n%s\n\n", instructions)
	}
	if existing != "" {
		fmt.Fprintf(&b, "## OPEN TASKS (do NOT plan work these already cover)\n%s\n\n", existing)
	}
	if fileTree != "" {
		fmt.Fprintf(&b, "## PROJECT STRUCTURE\n```\n%s\n```\n\n", fileTree)
	}
	b.WriteString(sum.Section())

	limit := MaxProposed
	if count > 0 && count < limit {
		limit = count
	}
	b.WriteString("## TASK\n")
	fmt.Fprintf(&b, "Plan the tasks that close the open gaps listed above, in at most %d tasks. ", limit)
	b.WriteString("Plan nothing for a requirement that is not listed as an open gap.\n\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Close the must gaps first, then should, then could: list the tasks in that order.\n")
	b.WriteString("- Every must gap must be closed by a task. One task may close several closely related gaps.\n")
	b.WriteString("- \"requirements\" lists the ids of the requirements a task closes, as numbers — only open gaps " +
		"from the list above, and only the ones the task makes hold.\n")
	b.WriteString("- \"kind\" says what the task does: fix (restore a requirement that fails), implement (make one " +
		"hold that nothing shows holds), verify (re-verify one that changed, restoring it if needed) or test.\n")
	b.WriteString("- A gap whose remedy is \"a task that only adds its test\" gets a task of kind test: it writes an " +
		"automated test that passes exactly when the requirement holds, changes nothing else, and ends its summary " +
		"with the single shell command, run from the project's root, that runs only that test.\n")
	b.WriteString("- Each description must stand on its own: the agent doing a task sees that task and the requirements " +
		"it links, not this plan.\n")
	b.WriteString("- depends_on lists the ids of EARLIER tasks in this plan that must be finished first; [] if none.\n\n")
	b.WriteString("For category, choose from: feature, ux, performance, security, dx, integration, docs\n")
	b.WriteString("For effort, choose from: xs (<1h), s (1-4h), m (4-16h), l (1-5d), xl (>1wk)\n\n")
	b.WriteString("Output ONLY valid JSON, no explanation, no markdown:\n")
	b.WriteString(`{"summary":"one sentence overview of the plan","suggestions":[`)
	b.WriteString(`{"id":1,"title":"short title","description":"what to do and how","rationale":"which gap it closes and why it comes here",` +
		`"category":"feature","effort":"m","depends_on":[],"requirements":[3],"kind":"fix"},`)
	b.WriteString(`{"id":2,"title":"...","description":"...","rationale":"...","category":"dx","effort":"s","depends_on":[1],"requirements":[5],"kind":"test"}`)
	b.WriteString(`]}`)
	return b.String()
}

// NothingToPlan says why a plan from the requirements has no task: the
// project has no approved requirement, or none with a gap a task closes — and
// what the others wait for instead.
func NothingToPlan(sum StatusSummary) string {
	if sum.Empty() {
		return "Nothing to plan: the project has no approved requirements."
	}
	waiting := map[string][]string{}
	for _, st := range sum.Requirements {
		waiting[st.Action] = append(waiting[st.Action], st.Key())
	}
	msg := "Nothing to plan: every approved requirement holds, is being worked on, or waits for something a task does not do."
	for _, w := range []struct{ action, says string }{
		{ActionCovered, "An open task implements"},
		{ActionCheck, "Waiting for a check (cloop requirements check, or Check all)"},
		{ActionAttachTest, "Waiting for a person to give them the test a finished task wrote"},
		{ActionStuck, "Waiting for a person — the task meant to close them failed"},
	} {
		if keys := waiting[w.action]; len(keys) > 0 {
			msg += fmt.Sprintf(" %s: %s.", w.says, strings.Join(keys, ", "))
		}
	}
	return msg
}

// GapRules is what a prompt that proposes new work — a brainstorm, an
// auto-evolve round — asks of it once it knows the requirements: link what it
// closes, and close the must gaps before proposing anything new.
func (s StatusSummary) GapRules() string {
	if s.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("## REQUIREMENTS RULES\n")
	b.WriteString("- Give every proposed task that closes a requirement's gap the ids of the requirements it " +
		"closes in \"requirements\", as numbers — only approved requirements from the list above. A task that " +
		"closes none gets [].\n")
	b.WriteString("- Propose nothing for a requirement an open task already implements, or one that waits for a " +
		"check or a person.\n")
	if must := s.MustGaps(); len(must) > 0 {
		keys := make([]string, len(must))
		for i, st := range must {
			keys[i] = st.Key()
		}
		fmt.Fprintf(&b, "- The project has open must gaps (%s). Your first tasks must close them, before any new "+
			"feature or improvement; a task that only adds a test for a requirement believed to hold writes that "+
			"test and nothing else.\n", strings.Join(keys, ", "))
	}
	b.WriteString("\n")
	return b.String()
}

// ProposedTask is one task the plan assistant proposed in an answer, with the
// requirements it says the task covers (ParseProposedTasks).
type ProposedTask struct {
	Title        string    `json:"title"`
	Requirements LooseRefs `json:"requirements,omitempty"`
}

// ChatRules is what the plan assistant is asked to do when it proposes tasks,
// for the dashboard to show which requirements each covers.
func (s StatusSummary) ChatRules() string {
	if s.Empty() {
		return ""
	}
	return "## WHEN YOU PROPOSE TASKS\n" +
		"When your answer proposes new tasks, end it with a fenced code block whose info string is `tasks`,\n" +
		"holding a JSON list with one object per proposed task: its title, and the ids of the approved\n" +
		"requirements above that it covers — only ones it makes hold. For example:\n" +
		"```tasks\n[{\"title\": \"Restore the config exit code\", \"requirements\": [3]}, {\"title\": \"Add dark mode\", \"requirements\": []}]\n```\n" +
		"Close open must gaps first, and say so plainly when your proposal leaves one uncovered.\n\n"
}

var tasksFenceRe = regexp.MustCompile("(?s)(?:^|\n)[ \t]*```tasks[ \t]*\n(.*?)\n[ \t]*```[ \t]*(?:\n|$)")

// ParseProposedTasks finds the last ```tasks block of answer and reads the
// tasks it proposes: at most MaxProposed, each with a title of one line.
// clean is answer without that block. A block that does not hold a list of
// tasks is left in the answer, and proposes nothing.
func ParseProposedTasks(answer string) (clean string, tasks []ProposedTask) {
	locs := tasksFenceRe.FindAllStringSubmatchIndex(answer, -1)
	if len(locs) == 0 {
		return answer, nil
	}
	loc := locs[len(locs)-1]
	body := answer[loc[2]:loc[3]]
	var raw []ProposedTask
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &raw) != nil {
		return answer, nil
	}
	for _, t := range raw {
		title, err := NormalizeTitle(oneLine(t.Title))
		if err != nil {
			continue
		}
		t.Title = title
		tasks = append(tasks, t)
		if len(tasks) == MaxProposed {
			break
		}
	}
	clean = strings.TrimSpace(answer[:loc[0]] + "\n" + answer[loc[1]:])
	return clean, tasks
}
