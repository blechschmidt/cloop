// Package tui implements a terminal UI dashboard for cloop using bubbletea and lipgloss.
package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// pollInterval is how often we re-read state.json.
const pollInterval = 500 * time.Millisecond

// view modes
type viewMode int

const (
	viewMain        viewMode = iota
	viewDetail               // task detail / artifact view
	viewAddTask
	viewAnnotations          // annotations modal for selected task
)

// ---- styles ----------------------------------------------------------------

var (
	styleBold      = lipgloss.NewStyle().Bold(true)
	styleHeader    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	stylePanelBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("240"))

	styleTaskSelected = lipgloss.NewStyle().
				Background(lipgloss.Color("237")).
				Foreground(lipgloss.Color("255"))

	styleStatusBar = lipgloss.NewStyle().
			Background(lipgloss.Color("235")).
			Foreground(lipgloss.Color("250")).
			Padding(0, 1)

	styleHelp = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	styleError = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			Bold(true)

	// task status colours
	statusColors = map[pm.TaskStatus]lipgloss.Color{
		pm.TaskPending:    "243",
		pm.TaskInProgress: "33",
		pm.TaskDone:       "82",
		pm.TaskFailed:     "196",
		pm.TaskSkipped:    "220",
	}

	statusSymbols = map[pm.TaskStatus]string{
		pm.TaskPending:    "○",
		pm.TaskInProgress: "●",
		pm.TaskDone:       "✓",
		pm.TaskFailed:     "✗",
		pm.TaskSkipped:    "⊘",
	}

	priorityBadgeColors = []lipgloss.Color{
		"196", // P1 - red
		"202", // P2 - orange
		"226", // P3 - yellow
		"34",  // P4 - green
		"27",  // P5+ - blue
	}
)

// ---- messages --------------------------------------------------------------

type tickMsg struct{}

type stateLoadedMsg struct {
	s   *state.ProjectState
	err error
}

type addTaskDoneMsg struct{ err error }

// ---- model -----------------------------------------------------------------

type Model struct {
	workdir string
	state   *state.ProjectState
	err     error

	// task list cursor
	cursor   int
	taskOffset int // scroll offset for task list

	// log panel scroll
	logOffset int

	// terminal dimensions
	width  int
	height int

	// detail view
	mode       viewMode
	detailText string

	// add task input
	addInput string

	startTime time.Time
}

// New creates a new TUI model for the given working directory.
func New(workdir string) Model {
	return Model{
		workdir:   workdir,
		startTime: time.Now(),
	}
}

// ---- init ------------------------------------------------------------------

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		loadState(m.workdir),
		tick(),
	)
}

// ---- update ----------------------------------------------------------------

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		return m, tea.Batch(loadState(m.workdir), tick())

	case stateLoadedMsg:
		if msg.err == nil {
			m.state = msg.s
			m.err = nil
			// clamp cursor
			if m.state.Plan != nil && m.cursor >= len(m.state.Plan.Tasks) {
				m.cursor = max(0, len(m.state.Plan.Tasks)-1)
			}
		} else {
			m.err = msg.err
		}
		return m, nil

	case addTaskDoneMsg:
		m.mode = viewMain
		m.addInput = ""
		if msg.err != nil {
			m.err = msg.err
		}
		return m, loadState(m.workdir)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.mode {
	case viewDetail:
		switch msg.String() {
		case "q", "esc", "enter":
			m.mode = viewMain
		case "up", "k":
			if m.logOffset > 0 {
				m.logOffset--
			}
		case "down", "j":
			m.logOffset++
		}
		return m, nil

	case viewAnnotations:
		switch msg.String() {
		case "q", "esc", "enter", "n":
			m.mode = viewMain
		case "up", "k":
			if m.logOffset > 0 {
				m.logOffset--
			}
		case "down", "j":
			m.logOffset++
		}
		return m, nil

	case viewAddTask:
		switch msg.String() {
		case "esc":
			m.mode = viewMain
			m.addInput = ""
		case "enter":
			if strings.TrimSpace(m.addInput) != "" {
				title := strings.TrimSpace(m.addInput)
				return m, addTask(m.workdir, title)
			}
			m.mode = viewMain
		case "backspace", "ctrl+h":
			if len(m.addInput) > 0 {
				m.addInput = m.addInput[:len(m.addInput)-1]
			}
		default:
			if len(msg.Runes) > 0 {
				m.addInput += string(msg.Runes)
			}
		}
		return m, nil

	default: // viewMain
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.state != nil && m.state.Plan != nil && m.cursor < len(m.state.Plan.Tasks)-1 {
				m.cursor++
			}
		case "r":
			return m, runCloop(m.workdir)
		case "s":
			return m, stopCloop(m.workdir)
		case "a":
			m.mode = viewAddTask
			m.addInput = ""
		case "enter":
			m.mode = viewDetail
			m.logOffset = 0
			m.detailText = m.buildDetailText()
		case "n":
			m.mode = viewAnnotations
			m.logOffset = 0
		}
	}
	return m, nil
}

// ---- view ------------------------------------------------------------------

func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	switch m.mode {
	case viewDetail:
		return m.viewDetail()
	case viewAddTask:
		return m.viewAddTask()
	case viewAnnotations:
		return m.viewAnnotations()
	default:
		return m.viewMain()
	}
}

func (m Model) viewMain() string {
	// Reserve rows: 3 header + 1 stats + 1 help = 5
	const reserved = 5
	contentHeight := m.height - reserved
	if contentHeight < 4 {
		contentHeight = 4
	}

	leftWidth := m.width/3 + 2
	rightWidth := m.width - leftWidth - 3
	if rightWidth < 10 {
		rightWidth = 10
	}

	taskPanel := m.renderTaskPanel(leftWidth, contentHeight)
	logPanel := m.renderLogPanel(rightWidth, contentHeight)

	body := lipgloss.JoinHorizontal(lipgloss.Top, taskPanel, " ", logPanel)

	header := m.renderHeader()
	stats := m.renderStats()
	help := styleHelp.Render("  r run  s stop  a add-task  ↑↓ navigate  enter detail  n notes  q quit")

	return lipgloss.JoinVertical(lipgloss.Left, header, body, stats, help)
}

func (m Model) renderHeader() string {
	goal := "(no project)"
	status := ""
	if m.state != nil {
		goal = truncate(m.state.Goal, m.width-30)
		status = m.state.Status
	}
	if m.err != nil {
		status = "error: " + m.err.Error()
	}

	left := styleHeader.Render(" cloop TUI") + "  " + styleBold.Render(goal)
	right := lipgloss.NewStyle().Foreground(stateColor(status)).Render(status)
	space := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if space < 0 {
		space = 0
	}
	return left + strings.Repeat(" ", space) + right
}

func (m Model) renderTaskPanel(w, h int) string {
	inner := w - 4 // border padding
	var rows []string

	title := styleHeader.Render("Tasks")
	rows = append(rows, title)

	if m.state == nil || m.state.Plan == nil || len(m.state.Plan.Tasks) == 0 {
		rows = append(rows, styleHelp.Render("no tasks — press 'a' to add"))
	} else {
		tasks := m.state.Plan.Tasks
		visibleLines := h - 3
		if visibleLines < 1 {
			visibleLines = 1
		}

		// scroll so cursor stays in view
		if m.cursor < m.taskOffset {
			m.taskOffset = m.cursor
		}
		if m.cursor >= m.taskOffset+visibleLines {
			m.taskOffset = m.cursor - visibleLines + 1
		}

		for i := m.taskOffset; i < len(tasks) && i < m.taskOffset+visibleLines; i++ {
			t := tasks[i]
			sym := statusSymbols[t.Status]
			col := statusColors[t.Status]
			if col == "" {
				col = "250"
			}
			badge := lipgloss.NewStyle().Foreground(col).Render(sym)
			pri := priorityBadge(t.Priority)
			title := truncate(t.Title, inner-8)
			tagStr := ""
			if len(t.Tags) > 0 {
				tagStr = " [" + strings.Join(t.Tags, ",") + "]"
			}
			notesStr := ""
			if len(t.Annotations) > 0 {
				notesStr = fmt.Sprintf(" ✎%d", len(t.Annotations))
			}
			line := fmt.Sprintf("%s %s %s%s%s", badge, pri, title, tagStr, notesStr)
			if i == m.cursor {
				line = styleTaskSelected.Width(inner).Render(line)
			}
			rows = append(rows, line)
		}
	}

	content := strings.Join(rows, "\n")
	return stylePanelBorder.Width(w).Height(h).Render(content)
}

func (m Model) renderLogPanel(w, h int) string {
	var rows []string
	rows = append(rows, styleHeader.Render("Live Log"))

	if m.state == nil {
		rows = append(rows, styleHelp.Render("waiting for state…"))
	} else {
		lines := m.buildLogLines()
		visibleLines := h - 3
		if visibleLines < 1 {
			visibleLines = 1
		}
		// scroll from bottom by default
		start := len(lines) - visibleLines - m.logOffset
		if start < 0 {
			start = 0
		}
		end := start + visibleLines
		if end > len(lines) {
			end = len(lines)
		}
		for _, l := range lines[start:end] {
			rows = append(rows, truncate(l, w-4))
		}
	}

	content := strings.Join(rows, "\n")
	return stylePanelBorder.Width(w).Height(h).Render(content)
}

func (m Model) buildLogLines() []string {
	var lines []string
	steps := m.state.Steps
	// show last 200 output lines across most recent steps
	for i := len(steps) - 1; i >= 0 && len(lines) < 200; i-- {
		step := steps[i]
		header := fmt.Sprintf("── Step %d ─────────────────────────────", step.Step)
		stepLines := strings.Split(strings.TrimRight(step.Output, "\n"), "\n")
		block := append([]string{header}, stepLines...)
		lines = append(block, lines...)
	}
	if m.state.PMMode && m.state.Plan != nil {
		// prepend current task info
		for _, t := range m.state.Plan.Tasks {
			if t.Status == pm.TaskInProgress {
				lines = append([]string{
					fmt.Sprintf("▶ Running task %d: %s", t.ID, t.Title),
					"",
				}, lines...)
				break
			}
		}
	}
	return lines
}

func (m Model) renderStats() string {
	if m.state == nil {
		return styleStatusBar.Width(m.width).Render("")
	}
	s := m.state

	tokens := fmt.Sprintf("in:%d  out:%d", s.TotalInputTokens, s.TotalOutputTokens)

	var costStr string
	if usd := cost.EstimateSessionCost(s.Provider, s.Model, s.TotalInputTokens, s.TotalOutputTokens); usd > 0 || s.Provider == "ollama" {
		costStr = cost.FormatCost(usd)
	} else if s.Model != "" {
		if usd, ok := cost.Estimate(s.Model, s.TotalInputTokens, s.TotalOutputTokens); ok {
			costStr = cost.FormatCost(usd)
		}
	}

	elapsed := time.Since(s.CreatedAt).Round(time.Second)
	step := fmt.Sprintf("step %d/%d", s.CurrentStep, s.MaxSteps)
	if s.MaxSteps == 0 {
		step = fmt.Sprintf("step %d", s.CurrentStep)
	}

	parts := []string{step, tokens}
	if costStr != "" {
		parts = append(parts, "cost "+costStr)
	}
	parts = append(parts, "elapsed "+elapsed.String())
	if s.Provider != "" {
		parts = append(parts, "provider: "+s.Provider)
	}

	return styleStatusBar.Width(m.width).Render(strings.Join(parts, "  │  "))
}

func (m Model) viewDetail() string {
	title := "Task Detail"
	if m.state != nil && m.state.Plan != nil && m.cursor < len(m.state.Plan.Tasks) {
		t := m.state.Plan.Tasks[m.cursor]
		title = fmt.Sprintf("Task %d: %s", t.ID, t.Title)
	}
	header := styleHeader.Render(title) + "\n"
	help := "\n" + styleHelp.Render("  ↑↓ scroll  q/esc/enter back")

	lines := strings.Split(m.detailText, "\n")
	visible := m.height - 4
	if visible < 1 {
		visible = 1
	}
	start := m.logOffset
	if start >= len(lines) {
		start = max(0, len(lines)-1)
	}
	end := start + visible
	if end > len(lines) {
		end = len(lines)
	}

	body := strings.Join(lines[start:end], "\n")
	return header + body + help
}

func (m Model) buildDetailText() string {
	if m.state == nil || m.state.Plan == nil || m.cursor >= len(m.state.Plan.Tasks) {
		return "(no task selected)"
	}
	t := m.state.Plan.Tasks[m.cursor]

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", t.Status))
	sb.WriteString(fmt.Sprintf("Priority:    %d\n", t.Priority))
	if t.Role != "" {
		sb.WriteString(fmt.Sprintf("Role:        %s\n", t.Role))
	}
	if len(t.DependsOn) > 0 {
		deps := make([]string, len(t.DependsOn))
		for i, d := range t.DependsOn {
			deps[i] = fmt.Sprintf("%d", d)
		}
		sb.WriteString(fmt.Sprintf("Depends on:  %s\n", strings.Join(deps, ", ")))
	}
	if len(t.Tags) > 0 {
		sb.WriteString(fmt.Sprintf("Tags:        %s\n", strings.Join(t.Tags, ", ")))
	}
	if t.EstimatedMinutes > 0 {
		sb.WriteString(fmt.Sprintf("Estimated:   %dm\n", t.EstimatedMinutes))
	}
	if t.ActualMinutes > 0 {
		sb.WriteString(fmt.Sprintf("Actual:      %dm\n", t.ActualMinutes))
	}
	if t.StartedAt != nil {
		sb.WriteString(fmt.Sprintf("Started:     %s\n", t.StartedAt.Format(time.RFC3339)))
	}
	if t.CompletedAt != nil {
		sb.WriteString(fmt.Sprintf("Completed:   %s\n", t.CompletedAt.Format(time.RFC3339)))
	}
	if t.Description != "" {
		sb.WriteString("\nDescription:\n")
		sb.WriteString(t.Description)
		sb.WriteString("\n")
	}
	if t.Result != "" {
		sb.WriteString("\nResult:\n")
		sb.WriteString(t.Result)
		sb.WriteString("\n")
	}
	// Try to read artifact
	if t.ArtifactPath != "" {
		artifactPath := filepath.Join(m.workdir, t.ArtifactPath)
		if data, err := os.ReadFile(artifactPath); err == nil {
			sb.WriteString("\n── Artifact ──────────────────────────────\n")
			// show up to first 100 lines of artifact
			artifactLines := strings.Split(string(data), "\n")
			limit := 100
			if len(artifactLines) < limit {
				limit = len(artifactLines)
			}
			sb.WriteString(strings.Join(artifactLines[:limit], "\n"))
			if len(artifactLines) > 100 {
				sb.WriteString(fmt.Sprintf("\n… (%d more lines)", len(artifactLines)-100))
			}
		}
	}
	return sb.String()
}

func (m Model) viewAnnotations() string {
	title := "Notes"
	var annotations []pm.Annotation
	if m.state != nil && m.state.Plan != nil && m.cursor < len(m.state.Plan.Tasks) {
		t := m.state.Plan.Tasks[m.cursor]
		title = fmt.Sprintf("Notes — Task %d: %s", t.ID, t.Title)
		annotations = t.Annotations
	}
	header := styleHeader.Render(title) + "\n"
	help := "\n" + styleHelp.Render("  ↑↓ scroll  n/q/esc close")

	var sb strings.Builder
	if len(annotations) == 0 {
		sb.WriteString(styleHelp.Render("  No notes yet. Use 'cloop task annotate <id> <text>' to add one."))
	} else {
		for i, a := range annotations {
			ts := a.Timestamp.Format("2006-01-02 15:04:05")
			authorLabel := "[user]"
			authorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
			if a.Author == "ai" {
				authorLabel = "[ai]  "
				authorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("33"))
			}
			sb.WriteString(fmt.Sprintf("  #%d  %s  %s\n", i+1, ts, authorStyle.Render(authorLabel)))
			sb.WriteString(fmt.Sprintf("       %s\n\n", strings.ReplaceAll(a.Text, "\n", "\n       ")))
		}
	}

	lines := strings.Split(sb.String(), "\n")
	visible := m.height - 4
	if visible < 1 {
		visible = 1
	}
	start := m.logOffset
	if start >= len(lines) {
		start = max(0, len(lines)-1)
	}
	end := start + visible
	if end > len(lines) {
		end = len(lines)
	}
	body := strings.Join(lines[start:end], "\n")
	return header + body + help
}

func (m Model) viewAddTask() string {
	header := styleHeader.Render("Add Task") + "\n\n"
	prompt := "Title: " + m.addInput + "█"
	help := "\n\n" + styleHelp.Render("  enter to confirm  esc to cancel")
	return header + prompt + help
}

// ---- helpers ---------------------------------------------------------------

func priorityBadge(p int) string {
	label := fmt.Sprintf("P%d", p)
	idx := p - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(priorityBadgeColors) {
		idx = len(priorityBadgeColors) - 1
	}
	return lipgloss.NewStyle().
		Foreground(priorityBadgeColors[idx]).
		Render(label)
}

func stateColor(status string) lipgloss.Color {
	switch status {
	case "running":
		return "33"
	case "complete":
		return "82"
	case "failed":
		return "196"
	case "paused", "evolving":
		return "220"
	default:
		return "250"
	}
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---- commands --------------------------------------------------------------

func tick() tea.Cmd {
	return tea.Tick(pollInterval, func(time.Time) tea.Msg {
		return tickMsg{}
	})
}

func loadState(workdir string) tea.Cmd {
	return func() tea.Msg {
		s, err := state.Load(workdir)
		return stateLoadedMsg{s: s, err: err}
	}
}

func runCloop(workdir string) tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("cloop", "run")
		cmd.Dir = workdir
		cmd.Start() //nolint:errcheck — fire and forget
		return nil
	}
}

func stopCloop(workdir string) tea.Cmd {
	return func() tea.Msg {
		// Write a stop signal file that the orchestrator polls for.
		stopFile := filepath.Join(workdir, ".cloop", "stop")
		os.WriteFile(stopFile, []byte("stop"), 0o644) //nolint:errcheck
		return nil
	}
}

func addTask(workdir, title string) tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("cloop", "task", "add", title)
		cmd.Dir = workdir
		err := cmd.Run()
		return addTaskDoneMsg{err: err}
	}
}

// Run starts the bubbletea program in fullscreen mode.
func Run(workdir string) error {
	p := tea.NewProgram(
		New(workdir),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	_, err := p.Run()
	return err
}
