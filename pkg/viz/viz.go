// Package viz renders task dependency graphs in multiple formats.
package viz

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Format is the output format for the dependency graph.
type Format string

const (
	FormatASCII   Format = "ascii"
	FormatMermaid Format = "mermaid"
	FormatDOT     Format = "dot"
)

// statusColor returns an ANSI color escape for a task status (for ASCII mode).
func statusColor(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return "\033[32m" // green
	case pm.TaskInProgress:
		return "\033[33m" // yellow
	case pm.TaskFailed:
		return "\033[31m" // red
	case pm.TaskSkipped:
		return "\033[90m" // dark gray
	default: // pending
		return "\033[37m" // white
	}
}

const colorReset = "\033[0m"

// statusSymbol returns a short symbol for the task status.
func statusSymbol(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return "✓"
	case pm.TaskInProgress:
		return "●"
	case pm.TaskFailed:
		return "✗"
	case pm.TaskSkipped:
		return "⊘"
	default:
		return "○"
	}
}

// mermaidStatus maps task status to a Mermaid CSS class name.
func mermaidClass(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return "done"
	case pm.TaskInProgress:
		return "inprogress"
	case pm.TaskFailed:
		return "failed"
	case pm.TaskSkipped:
		return "skipped"
	default:
		return "pending"
	}
}

// RenderASCII renders an ASCII dependency graph with box-drawing characters.
// Color is enabled when useColor is true.
func RenderASCII(plan *pm.Plan, useColor bool) string {
	if plan == nil || len(plan.Tasks) == 0 {
		return "(no tasks in plan)\n"
	}

	// Build adjacency: dependents[id] = list of task IDs that depend on id
	// We render the graph top-down: roots first, then dependents.
	taskByID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		taskByID[t.ID] = t
	}

	// Topological sort (Kahn's algorithm) for render order.
	inDeg := make(map[int]int, len(plan.Tasks))
	children := make(map[int][]int, len(plan.Tasks))
	for _, t := range plan.Tasks {
		if _, ok := inDeg[t.ID]; !ok {
			inDeg[t.ID] = 0
		}
		for _, dep := range t.DependsOn {
			inDeg[t.ID]++
			children[dep] = append(children[dep], t.ID)
		}
	}

	queue := []int{}
	for _, t := range plan.Tasks {
		if inDeg[t.ID] == 0 {
			queue = append(queue, t.ID)
		}
	}
	sort.Ints(queue)

	order := []int{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		order = append(order, cur)
		ch := children[cur]
		sort.Ints(ch)
		for _, c := range ch {
			inDeg[c]--
			if inDeg[c] == 0 {
				queue = append(queue, c)
			}
		}
	}
	// Append any remaining (cycle guard)
	seen := make(map[int]bool, len(order))
	for _, id := range order {
		seen[id] = true
	}
	for _, t := range plan.Tasks {
		if !seen[t.ID] {
			order = append(order, t.ID)
		}
	}

	var sb strings.Builder

	// Header
	sb.WriteString("Task Dependency Graph")
	if plan.Goal != "" {
		sb.WriteString(": ")
		goal := plan.Goal
		if len(goal) > 60 {
			goal = goal[:57] + "..."
		}
		sb.WriteString(goal)
	}
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 60))
	sb.WriteString("\n\n")

	// Legend
	if useColor {
		sb.WriteString(statusColor(pm.TaskPending) + "○ pending" + colorReset + "  ")
		sb.WriteString(statusColor(pm.TaskInProgress) + "● in_progress" + colorReset + "  ")
		sb.WriteString(statusColor(pm.TaskDone) + "✓ done" + colorReset + "  ")
		sb.WriteString(statusColor(pm.TaskFailed) + "✗ failed" + colorReset + "  ")
		sb.WriteString(statusColor(pm.TaskSkipped) + "⊘ skipped" + colorReset)
	} else {
		sb.WriteString("○ pending  ● in_progress  ✓ done  ✗ failed  ⊘ skipped")
	}
	sb.WriteString("\n\n")

	// Render each task as a box with dependency arrows.
	for _, id := range order {
		t, ok := taskByID[id]
		if !ok {
			continue
		}

		sym := statusSymbol(t.Status)
		title := t.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}

		label := fmt.Sprintf("[%d] %s %s", t.ID, sym, title)
		boxWidth := len(label) + 4
		if boxWidth < 30 {
			boxWidth = 30
		}
		innerWidth := boxWidth - 2

		top := "┌" + strings.Repeat("─", innerWidth) + "┐"
		mid := "│ " + padRight(fmt.Sprintf("%s %s %s", coloredSym(sym, t.Status, useColor), fmt.Sprintf("[%d]", t.ID), coloredTitle(title, t.Status, useColor)), innerWidth-2, useColor) + " │"
		bot := "└" + strings.Repeat("─", innerWidth) + "┘"

		// Show deps inside the box as a second line if any
		var depStr string
		if len(t.DependsOn) > 0 {
			depIDs := make([]string, len(t.DependsOn))
			for i, d := range t.DependsOn {
				depIDs[i] = fmt.Sprintf("#%d", d)
			}
			depStr = "  needs: " + strings.Join(depIDs, ", ")
			if len(depStr) > innerWidth-2 {
				depStr = depStr[:innerWidth-5] + "..."
			}
		}

		sb.WriteString(top + "\n")
		sb.WriteString(mid + "\n")
		if depStr != "" {
			depLine := "│ " + padRightPlain(depStr, innerWidth-2) + " │"
			sb.WriteString(depLine + "\n")
		}
		sb.WriteString(bot + "\n")

		// Draw arrows to dependents
		ch := children[id]
		sort.Ints(ch)
		for i, cid := range ch {
			child, ok2 := taskByID[cid]
			if !ok2 {
				continue
			}
			connector := "├──▶"
			if i == len(ch)-1 {
				connector = "└──▶"
			}
			childTitle := child.Title
			if len(childTitle) > 40 {
				childTitle = childTitle[:37] + "..."
			}
			sb.WriteString(fmt.Sprintf("  %s #%d %s\n", connector, child.ID, childTitle))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// coloredSym returns the symbol with ANSI color if enabled.
func coloredSym(sym string, status pm.TaskStatus, useColor bool) string {
	if !useColor {
		return sym
	}
	return statusColor(status) + sym + colorReset
}

// coloredTitle returns the title with ANSI color if enabled.
func coloredTitle(title string, status pm.TaskStatus, useColor bool) string {
	if !useColor {
		return title
	}
	return statusColor(status) + title + colorReset
}

// padRight pads s to width, accounting for ANSI escape sequences in the string.
func padRight(s string, width int, hasColor bool) string {
	if !hasColor {
		return padRightPlain(s, width)
	}
	// visible length: strip ANSI codes
	visible := stripANSI(s)
	pad := width - len(visible)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

func padRightPlain(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// stripANSI removes ANSI escape sequences to compute visible length.
func stripANSI(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			// skip until 'm'
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j + 1
		} else {
			out.WriteByte(s[i])
			i++
		}
	}
	return out.String()
}

// highlightColor is the ANSI escape for the highlighted task and its dep cone.
const highlightColor = "\033[95m" // bright magenta

// dependencyCone returns the set of task IDs reachable from highlightID by
// following DependsOn edges (the task itself plus all transitive deps).
func dependencyCone(plan *pm.Plan, highlightID int) map[int]bool {
	cone := map[int]bool{highlightID: true}
	taskByID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		taskByID[t.ID] = t
	}

	// BFS/DFS over DependsOn edges.
	queue := []int{highlightID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		t, ok := taskByID[cur]
		if !ok {
			continue
		}
		for _, dep := range t.DependsOn {
			if !cone[dep] {
				cone[dep] = true
				queue = append(queue, dep)
			}
		}
	}
	return cone
}

// RenderASCIIHighlighted renders the ASCII graph with the selected task and its
// full dependency cone (the task itself plus all transitive dependencies)
// rendered in a distinct bright-magenta colour.  Tasks outside the cone are
// dimmed.  Pass highlightID <= 0 to disable highlighting (identical to
// RenderASCII).
func RenderASCIIHighlighted(plan *pm.Plan, highlightID int, useColor bool) string {
	if highlightID <= 0 || !useColor {
		return RenderASCII(plan, useColor)
	}

	cone := dependencyCone(plan, highlightID)

	// We produce a modified render by overriding the color logic.
	// Rather than duplicating the full render logic, we render a copy of the
	// plan where highlighted tasks use a distinct prefix that we post-process.
	// Instead, we directly override the color used per task.

	if plan == nil || len(plan.Tasks) == 0 {
		return "(no tasks in plan)\n"
	}

	taskByID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		taskByID[t.ID] = t
	}

	inDeg := make(map[int]int, len(plan.Tasks))
	children := make(map[int][]int, len(plan.Tasks))
	for _, t := range plan.Tasks {
		if _, ok := inDeg[t.ID]; !ok {
			inDeg[t.ID] = 0
		}
		for _, dep := range t.DependsOn {
			inDeg[t.ID]++
			children[dep] = append(children[dep], t.ID)
		}
	}

	queue := []int{}
	for _, t := range plan.Tasks {
		if inDeg[t.ID] == 0 {
			queue = append(queue, t.ID)
		}
	}
	sort.Ints(queue)

	order := []int{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		order = append(order, cur)
		ch := children[cur]
		sort.Ints(ch)
		for _, c := range ch {
			inDeg[c]--
			if inDeg[c] == 0 {
				queue = append(queue, c)
			}
		}
	}
	seen := make(map[int]bool, len(order))
	for _, id := range order {
		seen[id] = true
	}
	for _, t := range plan.Tasks {
		if !seen[t.ID] {
			order = append(order, t.ID)
		}
	}

	var sb strings.Builder

	sb.WriteString("Task Dependency Graph")
	if plan.Goal != "" {
		sb.WriteString(": ")
		goal := plan.Goal
		if len(goal) > 60 {
			goal = goal[:57] + "..."
		}
		sb.WriteString(goal)
	}
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 60))
	sb.WriteString("\n\n")

	sb.WriteString(highlightColor + "★ highlighted task + dependency cone" + colorReset + "  ")
	sb.WriteString(statusColor(pm.TaskPending) + "○ pending" + colorReset + "  ")
	sb.WriteString(statusColor(pm.TaskDone) + "✓ done" + colorReset)
	sb.WriteString("\n\n")

	for _, id := range order {
		t, ok := taskByID[id]
		if !ok {
			continue
		}

		inCone := cone[id]

		sym := statusSymbol(t.Status)
		title := t.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}

		var nodeColor string
		if inCone {
			nodeColor = highlightColor
		} else {
			nodeColor = "\033[2m" // dim for tasks outside the cone
		}

		label := fmt.Sprintf("[%d] %s %s", t.ID, sym, title)
		boxWidth := len(label) + 4
		if boxWidth < 30 {
			boxWidth = 30
		}
		innerWidth := boxWidth - 2

		top := nodeColor + "┌" + strings.Repeat("─", innerWidth) + "┐" + colorReset
		symStr := sym
		if inCone {
			symStr = highlightColor + sym + colorReset
		}
		titleStr := nodeColor + title + colorReset
		idStr := fmt.Sprintf("[%d]", t.ID)
		mid := nodeColor + "│ " + colorReset + padRight(fmt.Sprintf("%s %s %s", symStr, idStr, titleStr), innerWidth-2, true) + nodeColor + " │" + colorReset
		bot := nodeColor + "└" + strings.Repeat("─", innerWidth) + "┘" + colorReset

		var depStr string
		if len(t.DependsOn) > 0 {
			depIDs := make([]string, len(t.DependsOn))
			for i, d := range t.DependsOn {
				depIDs[i] = fmt.Sprintf("#%d", d)
			}
			depStr = "  needs: " + strings.Join(depIDs, ", ")
			if len(depStr) > innerWidth-2 {
				depStr = depStr[:innerWidth-5] + "..."
			}
		}

		sb.WriteString(top + "\n")
		sb.WriteString(mid + "\n")
		if depStr != "" {
			depLine := nodeColor + "│ " + colorReset + padRightPlain(depStr, innerWidth-2) + nodeColor + " │" + colorReset
			sb.WriteString(depLine + "\n")
		}
		sb.WriteString(bot + "\n")

		ch := children[id]
		sort.Ints(ch)
		for i, cid := range ch {
			child, ok2 := taskByID[cid]
			if !ok2 {
				continue
			}
			connector := "├──▶"
			if i == len(ch)-1 {
				connector = "└──▶"
			}
			childTitle := child.Title
			if len(childTitle) > 40 {
				childTitle = childTitle[:37] + "..."
			}
			arrowColor := "\033[2m"
			if inCone {
				arrowColor = highlightColor
			}
			sb.WriteString(fmt.Sprintf("  %s%s #%d %s%s\n", arrowColor, connector, child.ID, childTitle, colorReset))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// RenderMermaid renders the dependency graph in Mermaid flowchart format.
func RenderMermaid(plan *pm.Plan) string {
	if plan == nil || len(plan.Tasks) == 0 {
		return "%% (no tasks in plan)\n"
	}

	var sb strings.Builder
	sb.WriteString("```mermaid\nflowchart TD\n")

	// Style classes
	sb.WriteString("    classDef pending fill:#555,stroke:#999,color:#fff\n")
	sb.WriteString("    classDef inprogress fill:#b8860b,stroke:#ffd700,color:#fff\n")
	sb.WriteString("    classDef done fill:#2d6a4f,stroke:#52b788,color:#fff\n")
	sb.WriteString("    classDef failed fill:#7f1d1d,stroke:#ef4444,color:#fff\n")
	sb.WriteString("    classDef skipped fill:#374151,stroke:#6b7280,color:#aaa\n\n")

	// Nodes
	for _, t := range plan.Tasks {
		sym := statusSymbol(t.Status)
		title := mermaidEscape(t.Title)
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		label := fmt.Sprintf("%s #%d: %s", sym, t.ID, title)
		sb.WriteString(fmt.Sprintf("    T%d[\"%s\"]\n", t.ID, label))
	}

	sb.WriteString("\n")

	// Edges
	for _, t := range plan.Tasks {
		for _, dep := range t.DependsOn {
			sb.WriteString(fmt.Sprintf("    T%d --> T%d\n", dep, t.ID))
		}
	}

	sb.WriteString("\n")

	// Class assignments
	for _, t := range plan.Tasks {
		sb.WriteString(fmt.Sprintf("    class T%d %s\n", t.ID, mermaidClass(t.Status)))
	}

	sb.WriteString("```\n")
	return sb.String()
}

func mermaidEscape(s string) string {
	s = strings.ReplaceAll(s, `"`, `'`)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return s
}

// RenderDOT renders the dependency graph in Graphviz DOT format.
func RenderDOT(plan *pm.Plan) string {
	if plan == nil || len(plan.Tasks) == 0 {
		return "digraph cloop {}\n"
	}

	var sb strings.Builder
	sb.WriteString("digraph cloop {\n")
	sb.WriteString("    rankdir=TD;\n")
	sb.WriteString("    node [shape=box, style=filled, fontname=\"Helvetica\"];\n\n")

	for _, t := range plan.Tasks {
		color, fontcolor := dotColors(t.Status)
		sym := statusSymbol(t.Status)
		title := dotEscape(t.Title)
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		label := fmt.Sprintf("%s #%d\\n%s", sym, t.ID, title)
		sb.WriteString(fmt.Sprintf("    T%d [label=\"%s\", fillcolor=\"%s\", fontcolor=\"%s\"];\n",
			t.ID, label, color, fontcolor))
	}

	sb.WriteString("\n")

	for _, t := range plan.Tasks {
		for _, dep := range t.DependsOn {
			sb.WriteString(fmt.Sprintf("    T%d -> T%d;\n", dep, t.ID))
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

func dotColors(s pm.TaskStatus) (fill, font string) {
	switch s {
	case pm.TaskDone:
		return "#2d6a4f", "#ffffff"
	case pm.TaskInProgress:
		return "#b8860b", "#ffffff"
	case pm.TaskFailed:
		return "#7f1d1d", "#ffffff"
	case pm.TaskSkipped:
		return "#374151", "#aaaaaa"
	default:
		return "#555555", "#ffffff"
	}
}

func dotEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
