// Package batchedit implements a full-screen bubbletea TUI for bulk-editing
// multiple tasks at once. Left panel shows a multi-select task list; right
// panel shows an edit form. Enter applies changes to all selected tasks.
package batchedit

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Result is returned after the TUI exits.
type Result struct {
	Saved   bool
	Changes []Change // one entry per modified task
}

// Change describes a field-level change applied to a single task.
type Change struct {
	TaskID    int
	TaskTitle string
	Field     string
	OldValue  string
	NewValue  string
}

// form field indices
const (
	fieldPriority = 0
	fieldTags     = 1
	fieldAssignee = 2
	fieldDeadline = 3
	fieldStatus   = 4
	numFields     = 5
)

var fieldNames = [numFields]string{"Priority", "Tags", "Assignee", "Deadline", "Status"}

// panel focus
const (
	panelList = 0
	panelForm = 1
)

// ---- styles -----------------------------------------------------------------

var (
	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

	styleHelp = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	stylePanelBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("240"))

	stylePanelFocus = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("33"))

	styleTaskNormal = lipgloss.NewStyle().
			Padding(0, 1)

	styleTaskCursor = lipgloss.NewStyle().
			Background(lipgloss.Color("237")).
			Foreground(lipgloss.Color("255")).
			Padding(0, 1)

	styleTaskChecked = lipgloss.NewStyle().
				Foreground(lipgloss.Color("40")).
				Padding(0, 1)

	styleTaskCheckedCursor = lipgloss.NewStyle().
				Background(lipgloss.Color("22")).
				Foreground(lipgloss.Color("40")).
				Padding(0, 1)

	styleFieldLabel = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("33")).
			Width(10)

	styleFieldActive = lipgloss.NewStyle().
				Foreground(lipgloss.Color("255")).
				Background(lipgloss.Color("237")).
				Padding(0, 1)

	styleFieldInactive = lipgloss.NewStyle().
				Foreground(lipgloss.Color("247")).
				Padding(0, 1)

	styleStatusBar = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	styleApply = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("40"))

	styleError = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			Bold(true)
)

// Model is the bubbletea model for the batch-edit TUI.
type Model struct {
	tasks    []*pm.Task // sorted display order (pinned first, then by priority)
	selected map[int]bool // task IDs that are checked
	cursor   int          // index into tasks slice (list panel)

	panel      int // panelList or panelForm
	activeField int // field index in form panel

	// form field values (strings, applied on Enter)
	fieldValues [numFields]string

	width  int
	height int

	result Result
	done   bool
}

// New creates a new batch-edit model for the given plan tasks.
func New(tasks []*pm.Task) Model {
	// Sort: pinned first, then by priority
	sorted := make([]*pm.Task, len(tasks))
	copy(sorted, tasks)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	sorted = pm.SortPinnedFirst(sorted)

	return Model{
		tasks:    sorted,
		selected: make(map[int]bool),
	}
}

// Run launches the bubbletea TUI and returns the result.
func Run(tasks []*pm.Task) (Result, error) {
	m := New(tasks)
	p := tea.NewProgram(m, tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		return Result{}, err
	}
	fm, ok := final.(Model)
	if !ok {
		return Result{}, nil
	}
	return fm.result, nil
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global: Esc / q always exit without saving
	if key == "esc" || key == "q" {
		m.result = Result{Saved: false}
		m.done = true
		return m, tea.Quit
	}

	// Tab / Shift-Tab switch panels (or cycle fields inside form panel)
	if key == "tab" {
		if m.panel == panelList {
			m.panel = panelForm
		} else {
			m.activeField = (m.activeField + 1) % numFields
		}
		return m, nil
	}
	if key == "shift+tab" {
		if m.panel == panelForm {
			m.activeField = (m.activeField - 1 + numFields) % numFields
			// If we wrapped around to the last field from field 0, go back to list panel
			if m.activeField == numFields-1 {
				m.panel = panelList
			}
		}
		return m, nil
	}

	switch m.panel {
	case panelList:
		return m.handleListKey(key)
	case panelForm:
		return m.handleFormKey(key)
	}
	return m, nil
}

func (m Model) handleListKey(key string) (Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.tasks)-1 {
			m.cursor++
		}
	case " ":
		// Toggle selection for current task
		if len(m.tasks) > 0 {
			id := m.tasks[m.cursor].ID
			m.selected[id] = !m.selected[id]
		}
	case "a":
		// Select / deselect all
		if len(m.selected) == len(m.tasks) {
			m.selected = make(map[int]bool)
		} else {
			for _, t := range m.tasks {
				m.selected[t.ID] = true
			}
		}
	case "enter":
		if m.panel == panelList && len(m.selected) > 0 {
			m.panel = panelForm
		}
	}
	return m, nil
}

func (m Model) handleFormKey(key string) (Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.activeField > 0 {
			m.activeField--
		}
	case "down", "j":
		if m.activeField < numFields-1 {
			m.activeField++
		}
	case "enter":
		// Apply changes to all selected tasks and exit
		changes, ok := m.applyChanges()
		if ok {
			m.result = Result{Saved: true, Changes: changes}
			m.done = true
			return m, tea.Quit
		}
	case "backspace":
		if len(m.fieldValues[m.activeField]) > 0 {
			m.fieldValues[m.activeField] = m.fieldValues[m.activeField][:len(m.fieldValues[m.activeField])-1]
		}
	default:
		// Printable characters: append to active field value
		if len(key) == 1 {
			m.fieldValues[m.activeField] += key
		}
	}
	return m, nil
}

// applyChanges mutates the selected tasks with the non-empty form values.
// Returns the list of changes and true on success.
func (m Model) applyChanges() ([]Change, bool) {
	var changes []Change

	priorityStr := strings.TrimSpace(m.fieldValues[fieldPriority])
	tagsStr := strings.TrimSpace(m.fieldValues[fieldTags])
	assigneeStr := strings.TrimSpace(m.fieldValues[fieldAssignee])
	deadlineStr := strings.TrimSpace(m.fieldValues[fieldDeadline])
	statusStr := strings.TrimSpace(m.fieldValues[fieldStatus])

	// Validate priority
	var newPriority int
	if priorityStr != "" {
		n, err := fmt.Sscanf(priorityStr, "%d", &newPriority)
		if n != 1 || err != nil || newPriority < 1 || newPriority > 100 {
			return nil, false
		}
	}

	// Validate status
	var newStatus pm.TaskStatus
	if statusStr != "" {
		switch strings.ToLower(statusStr) {
		case "pending":
			newStatus = pm.TaskPending
		case "in_progress", "inprogress", "in-progress":
			newStatus = pm.TaskInProgress
		case "done":
			newStatus = pm.TaskDone
		case "failed":
			newStatus = pm.TaskFailed
		case "skipped":
			newStatus = pm.TaskSkipped
		default:
			return nil, false
		}
	}

	// Validate deadline
	var deadlineTime *interface{} // just to check if it parses
	_ = deadlineTime
	if deadlineStr != "" && deadlineStr != "none" && deadlineStr != "clear" {
		_, err := pm.ParseDeadline(deadlineStr)
		if err != nil {
			return nil, false
		}
	}

	for _, t := range m.tasks {
		if !m.selected[t.ID] {
			continue
		}

		if priorityStr != "" {
			old := fmt.Sprintf("%d", t.Priority)
			t.Priority = newPriority
			changes = append(changes, Change{t.ID, t.Title, "priority", old, priorityStr})
		}

		if tagsStr != "" {
			oldTags := strings.Join(t.Tags, ",")
			// Merge new tags (deduplicated)
			newTags := parseTags(tagsStr)
			existing := make(map[string]bool, len(t.Tags))
			for _, tag := range t.Tags {
				existing[tag] = true
			}
			for _, tag := range newTags {
				if !existing[tag] {
					t.Tags = append(t.Tags, tag)
					existing[tag] = true
				}
			}
			changes = append(changes, Change{t.ID, t.Title, "tags", oldTags, strings.Join(t.Tags, ",")})
		}

		if assigneeStr != "" {
			old := t.Assignee
			t.Assignee = assigneeStr
			changes = append(changes, Change{t.ID, t.Title, "assignee", old, assigneeStr})
		}

		if deadlineStr != "" {
			var oldDeadline string
			if t.Deadline != nil {
				oldDeadline = t.Deadline.Format("2006-01-02")
			}
			if deadlineStr == "none" || deadlineStr == "clear" {
				t.Deadline = nil
				changes = append(changes, Change{t.ID, t.Title, "deadline", oldDeadline, "(cleared)"})
			} else {
				dl, _ := pm.ParseDeadline(deadlineStr)
				t.Deadline = &dl
				changes = append(changes, Change{t.ID, t.Title, "deadline", oldDeadline, dl.Format("2006-01-02")})
			}
		}

		if statusStr != "" {
			old := string(t.Status)
			t.Status = newStatus
			changes = append(changes, Change{t.ID, t.Title, "status", old, string(newStatus)})
		}
	}
	return changes, true
}

func parseTags(s string) []string {
	var tags []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			tags = append(tags, part)
		}
	}
	return tags
}

// View implements tea.Model.
func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	// Calculate panel widths. Leave 4 chars for borders.
	innerW := m.width - 4 // 2 panels × 2 border chars
	leftW := innerW * 2 / 5
	rightW := innerW - leftW
	panelH := m.height - 4 // header + status bar

	leftContent := m.renderList(leftW, panelH-2)
	rightContent := m.renderForm(rightW, panelH-2)

	// Apply panel border styles
	var leftPanel, rightPanel string
	if m.panel == panelList {
		leftPanel = stylePanelFocus.Width(leftW).Height(panelH).Render(leftContent)
		rightPanel = stylePanelBorder.Width(rightW).Height(panelH).Render(rightContent)
	} else {
		leftPanel = stylePanelBorder.Width(leftW).Height(panelH).Render(leftContent)
		rightPanel = stylePanelFocus.Width(rightW).Height(panelH).Render(rightContent)
	}

	body := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, rightPanel)

	header := styleTitle.Render("  cloop task batch-edit")
	statusBar := m.renderStatusBar()

	return lipgloss.JoinVertical(lipgloss.Left, header, body, statusBar)
}

func (m Model) renderList(w, h int) string {
	title := styleTitle.Render(fmt.Sprintf("Tasks (%d/%d selected)", len(m.selected), len(m.tasks)))
	lines := []string{title, ""}

	visibleStart := 0
	if m.cursor >= h-3 {
		visibleStart = m.cursor - (h - 3)
	}

	for i := visibleStart; i < len(m.tasks) && len(lines) < h; i++ {
		t := m.tasks[i]
		checked := m.selected[t.ID]
		isCursor := i == m.cursor

		checkbox := "[ ]"
		if checked {
			checkbox = "[x]"
		}

		tags := ""
		if len(t.Tags) > 0 {
			tags = " [" + strings.Join(t.Tags, ",") + "]"
		}

		title := truncate(t.Title, w-18)
		line := fmt.Sprintf("%s #%d P%d %s%s", checkbox, t.ID, t.Priority, title, tags)
		line = truncate(line, w-2)

		switch {
		case checked && isCursor:
			lines = append(lines, styleTaskCheckedCursor.Render(line))
		case checked:
			lines = append(lines, styleTaskChecked.Render(line))
		case isCursor:
			lines = append(lines, styleTaskCursor.Render(line))
		default:
			lines = append(lines, styleTaskNormal.Render(line))
		}
	}

	return strings.Join(lines, "\n")
}

func (m Model) renderForm(w, h int) string {
	selCount := len(m.selected)
	var headerText string
	if selCount == 0 {
		headerText = styleError.Render("  Select tasks first (Space)")
	} else {
		headerText = styleApply.Render(fmt.Sprintf("  Edit fields — applies to %d task(s)", selCount))
	}
	lines := []string{headerText, ""}

	helpLines := [numFields]string{
		"1-100",
		"comma-separated",
		"username",
		"2d / 2026-01-01 / none",
		"pending/in_progress/done/failed/skipped",
	}

	for i := 0; i < numFields; i++ {
		label := styleFieldLabel.Render(fieldNames[i] + ":")
		val := m.fieldValues[i]
		if val == "" {
			val = helpLines[i]
		}

		var valueRendered string
		if i == m.activeField && m.panel == panelForm {
			cursor := "_"
			if m.fieldValues[i] == "" {
				valueRendered = styleFieldActive.Render(cursor + " ")
			} else {
				valueRendered = styleFieldActive.Render(val + cursor)
			}
		} else {
			valueRendered = styleFieldInactive.Render(val)
		}

		line := lipgloss.JoinHorizontal(lipgloss.Center, label, valueRendered)
		lines = append(lines, line, "")
	}

	if m.panel == panelForm {
		lines = append(lines, "", styleApply.Render("  Enter = apply to all selected"))
	}

	return strings.Join(lines, "\n")
}

func (m Model) renderStatusBar() string {
	var hints []string
	if m.panel == panelList {
		hints = []string{
			"↑↓ navigate",
			"Space select/deselect",
			"a select all",
			"Tab → form",
			"Enter → form",
			"q/Esc quit",
		}
	} else {
		hints = []string{
			"↑↓/Tab cycle fields",
			"type to edit",
			"Enter apply",
			"Shift+Tab back",
			"q/Esc quit",
		}
	}
	return styleStatusBar.Render("  " + strings.Join(hints, "  ·  "))
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
