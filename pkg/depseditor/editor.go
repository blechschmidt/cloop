// Package depseditor provides an interactive TUI for viewing and editing task dependencies.
package depseditor

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/viz"
)

// HasCycle returns true if the dependency graph formed by the tasks contains a cycle.
// It uses DFS with a three-state color marking (unvisited / in-stack / done).
func HasCycle(tasks []*pm.Task) bool {
	adj := make(map[int][]int, len(tasks))
	ids := make([]int, 0, len(tasks))
	for _, t := range tasks {
		adj[t.ID] = t.DependsOn
		ids = append(ids, t.ID)
	}

	// 0 = unvisited, 1 = in-stack, 2 = done
	state := make(map[int]int, len(ids))

	var dfs func(id int) bool
	dfs = func(id int) bool {
		switch state[id] {
		case 1:
			return true // back-edge → cycle
		case 2:
			return false // already fully explored
		}
		state[id] = 1
		for _, dep := range adj[id] {
			if dfs(dep) {
				return true
			}
		}
		state[id] = 2
		return false
	}

	for _, id := range ids {
		if state[id] == 0 {
			if dfs(id) {
				return true
			}
		}
	}
	return false
}

// WouldCreateCycle reports whether adding newDepID to the DependsOn list of taskID
// would introduce a cycle in the plan's dependency graph.
func WouldCreateCycle(plan *pm.Plan, taskID, newDepID int) bool {
	modified := make([]*pm.Task, 0, len(plan.Tasks))
	for _, t := range plan.Tasks {
		tc := *t
		if tc.ID == taskID {
			deps := make([]int, len(tc.DependsOn)+1)
			copy(deps, tc.DependsOn)
			deps[len(tc.DependsOn)] = newDepID
			tc.DependsOn = deps
		}
		modified = append(modified, &tc)
	}
	return HasCycle(modified)
}

// PlanHasCycle reports whether the plan's current dependency graph has any cycle.
func PlanHasCycle(plan *pm.Plan) bool {
	return HasCycle(plan.Tasks)
}

// ────────────────────────────────────────────────────────────────────────────
// bubbletea model
// ────────────────────────────────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
)

// Model is the bubbletea model for the interactive dependency editor.
type Model struct {
	targetID  int
	target    *pm.Task
	others    []*pm.Task   // all tasks except target, sorted by ID
	selected  map[int]bool // IDs currently in DependsOn
	cursor    int
	hasCycle  bool
	confirmed bool
	cancelled bool
	plan      *pm.Plan // original plan (not mutated until confirmation)
	width     int
}

// New creates a Model for editing the dependencies of the task identified by targetID.
func New(plan *pm.Plan, targetID int) (*Model, error) {
	var target *pm.Task
	for _, t := range plan.Tasks {
		if t.ID == targetID {
			target = t
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("task %d not found", targetID)
	}

	others := make([]*pm.Task, 0, len(plan.Tasks)-1)
	for _, t := range plan.Tasks {
		if t.ID != targetID {
			others = append(others, t)
		}
	}
	sort.Slice(others, func(i, j int) bool { return others[i].ID < others[j].ID })

	selected := make(map[int]bool, len(target.DependsOn))
	for _, depID := range target.DependsOn {
		selected[depID] = true
	}

	return &Model{
		targetID: targetID,
		target:   target,
		others:   others,
		selected: selected,
		cursor:   0,
		plan:     plan,
		width:    80,
	}, nil
}

// Confirmed reports whether the user pressed Enter to save changes.
func (m Model) Confirmed() bool { return m.confirmed }

// Cancelled reports whether the user pressed Escape/q to abort.
func (m Model) Cancelled() bool { return m.cancelled }

// Result returns the updated dependency ID list to persist on confirmation.
func (m Model) Result() []int {
	deps := make([]int, 0, len(m.selected))
	for _, t := range m.others {
		if m.selected[t.ID] {
			deps = append(deps, t.ID)
		}
	}
	return deps
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.cancelled = true
			return m, tea.Quit

		case "enter":
			if !m.hasCycle {
				m.confirmed = true
				return m, tea.Quit
			}
			// stay and show the warning

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.others)-1 {
				m.cursor++
			}

		case " ":
			if len(m.others) == 0 {
				break
			}
			t := m.others[m.cursor]
			if m.selected[t.ID] {
				delete(m.selected, t.ID)
			} else {
				m.selected[t.ID] = true
			}
			m.hasCycle = m.computeHasCycle()
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
	}
	return m, nil
}

// computeHasCycle rebuilds a temporary plan from current selections and checks for cycles.
func (m Model) computeHasCycle() bool {
	tasks := make([]*pm.Task, 0, len(m.plan.Tasks))
	for _, t := range m.plan.Tasks {
		tc := *t
		if tc.ID == m.targetID {
			deps := make([]int, 0, len(m.selected))
			for id := range m.selected {
				deps = append(deps, id)
			}
			tc.DependsOn = deps
		}
		tasks = append(tasks, &tc)
	}
	return HasCycle(tasks)
}

// View implements tea.Model.
func (m Model) View() string {
	w := m.width
	if w < 40 {
		w = 80
	}
	ruler := strings.Repeat("─", min(w-4, 70))

	var sb strings.Builder

	// ── Header ──────────────────────────────────────────────────────────────
	sb.WriteString("\n")
	sb.WriteString(ansiBold + ansiCyan)
	sb.WriteString(fmt.Sprintf("  Dependency Editor  —  Task #%d: %s", m.targetID, truncate(m.target.Title, 52)))
	sb.WriteString(ansiReset + "\n")
	sb.WriteString("  " + ruler + "\n\n")

	// ── Key hint ────────────────────────────────────────────────────────────
	sb.WriteString(ansiDim + "  ↑/↓  navigate    SPACE  toggle    ENTER  confirm    q/ESC  cancel\n" + ansiReset)
	sb.WriteString("\n")

	// ── Checklist ───────────────────────────────────────────────────────────
	if len(m.others) == 0 {
		sb.WriteString("  " + ansiDim + "(no other tasks in plan)" + ansiReset + "\n")
	} else {
		for i, t := range m.others {
			isSelected := m.selected[t.ID]
			isCursor := i == m.cursor

			// cursor arrow
			arrow := "  "
			if isCursor {
				arrow = ansiBold + "> " + ansiReset
			}

			// checkbox
			var check string
			if isSelected {
				if m.hasCycle {
					check = ansiRed + "[✓]" + ansiReset
				} else {
					check = ansiGreen + "[✓]" + ansiReset
				}
			} else {
				check = ansiDim + "[ ]" + ansiReset
			}

			// title
			title := truncate(t.Title, 55)
			var titleStr string
			if isSelected && m.hasCycle {
				titleStr = ansiRed + title + ansiReset
			} else if isSelected {
				titleStr = ansiGreen + title + ansiReset
			} else if isCursor {
				titleStr = ansiBold + title + ansiReset
			} else {
				titleStr = title
			}

			sb.WriteString(fmt.Sprintf("%s%s  #%-3d  %s\n", arrow, check, t.ID, titleStr))
		}
	}

	sb.WriteString("\n  " + ruler + "\n")

	// ── Cycle warning / dep summary ─────────────────────────────────────────
	if m.hasCycle {
		sb.WriteString(ansiBold + ansiRed + "  ⚠  CYCLE DETECTED — resolve the cycle before confirming\n" + ansiReset)
	} else if len(m.selected) == 0 {
		sb.WriteString(ansiDim + "  No dependencies selected.\n" + ansiReset)
	} else {
		parts := make([]string, 0, len(m.selected))
		for _, t := range m.others {
			if m.selected[t.ID] {
				parts = append(parts, fmt.Sprintf("#%d", t.ID))
			}
		}
		sb.WriteString(fmt.Sprintf("  Task #%d depends on: %s%s%s\n",
			m.targetID, ansiGreen, strings.Join(parts, ", "), ansiReset))
	}

	// ── Dependency graph preview ─────────────────────────────────────────────
	sb.WriteString("\n  " + ruler + "\n")
	sb.WriteString(ansiBold + "  Dependency graph preview:\n" + ansiReset + "\n")

	// Build a temporary plan with the current selections applied.
	tmpPlan := m.buildTempPlan()
	graph := viz.RenderASCII(tmpPlan, true)
	// Indent each line of the graph by 2 spaces.
	for _, line := range strings.Split(strings.TrimRight(graph, "\n"), "\n") {
		sb.WriteString("  " + line + "\n")
	}
	sb.WriteString("\n")

	return sb.String()
}

// buildTempPlan creates a shallow copy of the plan with the editor's current
// selections applied to the target task's DependsOn field.
func (m Model) buildTempPlan() *pm.Plan {
	tasks := make([]*pm.Task, 0, len(m.plan.Tasks))
	for _, t := range m.plan.Tasks {
		tc := *t
		if tc.ID == m.targetID {
			deps := make([]int, 0, len(m.selected))
			for id := range m.selected {
				deps = append(deps, id)
			}
			sort.Ints(deps)
			tc.DependsOn = deps
		}
		tasks = append(tasks, &tc)
	}
	return &pm.Plan{
		Goal:    m.plan.Goal,
		Tasks:   tasks,
		Version: m.plan.Version,
	}
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
