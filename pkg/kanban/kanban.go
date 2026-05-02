// Package kanban implements a full-screen bubbletea kanban board for cloop.
package kanban

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

const pollInterval = 2 * time.Second

// column indices
const (
	colPending    = 0
	colInProgress = 1
	colDone       = 2
	colFailed     = 3
	numCols       = 4
)

var colTitles = [numCols]string{"Pending", "In Progress", "Done", "Failed/Skipped"}

var colStatuses = [numCols][]pm.TaskStatus{
	{pm.TaskPending},
	{pm.TaskInProgress},
	{pm.TaskDone},
	{pm.TaskFailed, pm.TaskSkipped, pm.TaskTimedOut},
}

// view modes
type viewMode int

const (
	modeKanban viewMode = iota
	modeDetail
	modeAdd
	modeMove // moving a task between columns
)

// ---- styles -----------------------------------------------------------------

var (
	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	styleHelp   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleError  = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)

	styleColumnBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("240"))

	styleColumnActive = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("33"))

	styleTaskNormal = lipgloss.NewStyle().
			Padding(0, 1)

	styleTaskSelected = lipgloss.NewStyle().
				Background(lipgloss.Color("237")).
				Foreground(lipgloss.Color("255")).
				Padding(0, 1)

	styleTaskMoving = lipgloss.NewStyle().
			Background(lipgloss.Color("52")).
			Foreground(lipgloss.Color("220")).
			Padding(0, 1)

	styleCountBadge = lipgloss.NewStyle().
			Foreground(lipgloss.Color("255")).
			Background(lipgloss.Color("238")).
			Padding(0, 1)

	styleStatusBar = lipgloss.NewStyle().
			Background(lipgloss.Color("235")).
			Foreground(lipgloss.Color("250")).
			Padding(0, 1)

	priorityColors = []lipgloss.Color{
		"196", // P1 red
		"202", // P2 orange
		"226", // P3 yellow
		"34",  // P4 green
		"27",  // P5+ blue
	}

	statusSymbols = map[pm.TaskStatus]string{
		pm.TaskPending:    "○",
		pm.TaskInProgress: "●",
		pm.TaskDone:       "✓",
		pm.TaskFailed:     "✗",
		pm.TaskSkipped:    "⊘",
		pm.TaskTimedOut:   "⏱",
	}
)

// ---- messages ---------------------------------------------------------------

type tickMsg struct{}
type stateLoadedMsg struct {
	s   *state.ProjectState
	err error
}
type opDoneMsg struct{ err error }

// ---- model ------------------------------------------------------------------

// Model is the bubbletea model for the kanban board.
type Model struct {
	workdir string
	st      *state.ProjectState
	err     error

	width  int
	height int

	// per-column columns (list of task IDs in display order)
	cols [numCols][]*pm.Task

	col    int // active column
	cursor int // cursor within active column

	mode       viewMode
	detailText string

	// add task
	addInput string

	// move mode: remembers source column + task
	moveFromCol    int
	moveFromCursor int
	moveTask       *pm.Task
}

// New returns an initialized kanban Model.
func New(workdir string) Model {
	return Model{workdir: workdir}
}

// Run launches the kanban board in alt-screen mode.
func Run(workdir string) error {
	p := tea.NewProgram(New(workdir), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ---- init -------------------------------------------------------------------

func (m Model) Init() tea.Cmd {
	return tea.Batch(loadState(m.workdir), tick())
}

// ---- update -----------------------------------------------------------------

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
			m.st = msg.s
			m.err = nil
			m.rebuildCols()
		} else {
			m.err = msg.err
		}
		return m, nil

	case opDoneMsg:
		if msg.err != nil {
			m.err = msg.err
		}
		m.mode = modeKanban
		m.addInput = ""
		m.moveTask = nil
		return m, loadState(m.workdir)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) rebuildCols() {
	if m.st == nil || m.st.Plan == nil {
		for i := range m.cols {
			m.cols[i] = nil
		}
		return
	}
	for i := range m.cols {
		m.cols[i] = nil
	}
	for _, t := range m.st.Plan.Tasks {
		placed := false
		for ci, statuses := range colStatuses {
			for _, s := range statuses {
				if t.Status == s {
					m.cols[ci] = append(m.cols[ci], t)
					placed = true
					break
				}
			}
			if placed {
				break
			}
		}
		if !placed {
			// treat unknown statuses as pending
			m.cols[colPending] = append(m.cols[colPending], t)
		}
	}
	// clamp cursor
	if col := m.col; col >= 0 && col < numCols {
		if n := len(m.cols[col]); n == 0 {
			m.cursor = 0
		} else if m.cursor >= n {
			m.cursor = n - 1
		}
	}
}

func (m Model) selectedTask() *pm.Task {
	col := m.cols[m.col]
	if len(col) == 0 || m.cursor >= len(col) {
		return nil
	}
	return col[m.cursor]
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.mode {
	case modeDetail:
		switch msg.String() {
		case "q", "esc", "enter":
			m.mode = modeKanban
		}
		return m, nil

	case modeAdd:
		switch msg.String() {
		case "esc":
			m.mode = modeKanban
			m.addInput = ""
		case "enter":
			title := strings.TrimSpace(m.addInput)
			if title != "" {
				return m, addTask(m.workdir, title)
			}
			m.mode = modeKanban
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

	case modeMove:
		switch msg.String() {
		case "esc":
			m.mode = modeKanban
			m.moveTask = nil
		case "left", "h":
			if m.col > 0 {
				m.col--
				m.cursor = 0
			}
		case "right", "l":
			if m.col < numCols-1 {
				m.col++
				m.cursor = 0
			}
		case "enter", " ":
			// Drop the task into this column
			if m.moveTask != nil {
				newStatus := colStatuses[m.col][0]
				taskID := m.moveTask.ID
				return m, setTaskStatus(m.workdir, taskID, newStatus)
			}
			m.mode = modeKanban
		}
		return m, nil

	default: // modeKanban
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "left", "h":
			if m.col > 0 {
				m.col--
				m.cursor = 0
			}
		case "right", "l":
			if m.col < numCols-1 {
				m.col++
				m.cursor = 0
			}
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			col := m.cols[m.col]
			if m.cursor < len(col)-1 {
				m.cursor++
			}
		case "enter":
			if t := m.selectedTask(); t != nil {
				m.detailText = buildDetailText(t)
				m.mode = modeDetail
			}
		case "d":
			if t := m.selectedTask(); t != nil {
				return m, setTaskStatus(m.workdir, t.ID, pm.TaskDone)
			}
		case "f":
			if t := m.selectedTask(); t != nil {
				return m, setTaskStatus(m.workdir, t.ID, pm.TaskFailed)
			}
		case "s":
			if t := m.selectedTask(); t != nil {
				return m, setTaskStatus(m.workdir, t.ID, pm.TaskSkipped)
			}
		case "a":
			m.mode = modeAdd
			m.addInput = ""
		case "r":
			if t := m.selectedTask(); t != nil {
				m.moveTask = t
				m.moveFromCol = m.col
				m.moveFromCursor = m.cursor
				m.mode = modeMove
			}
		}
		return m, nil
	}
}

// ---- view -------------------------------------------------------------------

func (m Model) View() string {
	if m.width == 0 {
		return "Loading…"
	}
	switch m.mode {
	case modeDetail:
		return m.viewDetail()
	case modeAdd:
		return m.viewAdd()
	case modeMove:
		return m.viewKanban(true)
	default:
		return m.viewKanban(false)
	}
}

func (m Model) viewKanban(moveMode bool) string {
	// Header
	goal := "(no project)"
	if m.st != nil && m.st.Goal != "" {
		goal = truncate(m.st.Goal, m.width-20)
	}
	headerLine := styleHeader.Render(" cloop kanban") + "  " + goal
	if m.err != nil {
		headerLine += "  " + styleError.Render("err: "+m.err.Error())
	}

	// Compute column widths: divide available width equally
	// Reserve 1 char between cols (numCols-1 separators)
	availW := m.width
	colW := (availW - (numCols - 1)) / numCols
	if colW < 12 {
		colW = 12
	}

	// Height: reserve 3 lines (header + help + blank)
	colH := m.height - 3
	if colH < 4 {
		colH = 4
	}

	cols := make([]string, numCols)
	for ci := 0; ci < numCols; ci++ {
		isActive := ci == m.col
		cols[ci] = m.renderColumn(ci, colW, colH, isActive, moveMode)
	}

	board := lipgloss.JoinHorizontal(lipgloss.Top, cols[0], " ", cols[1], " ", cols[2], " ", cols[3])

	helpText := "  ←→ col  ↑↓ task  enter detail  d done  f fail  s skip  r move  a add  q quit"
	if moveMode {
		helpText = "  MOVE MODE: ←→ choose column  enter/space drop here  esc cancel"
	}
	help := styleHelp.Render(helpText)

	return lipgloss.JoinVertical(lipgloss.Left, headerLine, board, help)
}

func (m Model) renderColumn(ci, w, h int, isActive, moveMode bool) string {
	tasks := m.cols[ci]
	count := len(tasks)

	// title row
	title := colTitles[ci]
	badge := styleCountBadge.Render(fmt.Sprintf(" %d ", count))
	titleRow := styleHeader.Render(title) + " " + badge

	// inner width (border takes 2 per side = 4 total from lipgloss border)
	inner := w - 4
	if inner < 4 {
		inner = 4
	}

	visibleRows := h - 4 // border + title + padding
	if visibleRows < 1 {
		visibleRows = 1
	}

	var rows []string
	rows = append(rows, titleRow)

	if count == 0 {
		rows = append(rows, styleHelp.Render("  (empty)"))
	} else {
		// scroll window
		offset := 0
		if isActive && m.cursor >= visibleRows {
			offset = m.cursor - visibleRows + 1
		}
		for i := offset; i < count && i < offset+visibleRows; i++ {
			t := tasks[i]
			line := renderTaskCard(t, inner)
			selected := isActive && i == m.cursor
			moving := moveMode && m.moveTask != nil && t.ID == m.moveTask.ID
			if moving {
				line = styleTaskMoving.Width(inner).Render(truncate(line, inner))
			} else if selected {
				line = styleTaskSelected.Width(inner).Render(truncate(line, inner))
			} else {
				line = styleTaskNormal.Width(inner).Render(truncate(line, inner))
			}
			rows = append(rows, line)
		}
		if count > visibleRows {
			remaining := count - visibleRows
			rows = append(rows, styleHelp.Render(fmt.Sprintf("  +%d more", remaining)))
		}
	}

	// highlight active column if move mode drop target
	isDropTarget := moveMode && ci == m.col
	content := strings.Join(rows, "\n")
	style := styleColumnBorder
	if isActive || isDropTarget {
		style = styleColumnActive
	}
	return style.Width(w).Height(h).Render(content)
}

func renderTaskCard(t *pm.Task, width int) string {
	sym := statusSymbols[t.Status]
	if sym == "" {
		sym = "?"
	}
	priColor := priorityColors[len(priorityColors)-1]
	idx := t.Priority - 1
	if idx >= 0 && idx < len(priorityColors) {
		priColor = priorityColors[idx]
	}
	priLabel := lipgloss.NewStyle().Foreground(priColor).Render(fmt.Sprintf("P%d", t.Priority))
	titleW := width - 7
	if titleW < 4 {
		titleW = 4
	}
	title := truncate(t.Title, titleW)
	line := fmt.Sprintf("%s %s %s", sym, priLabel, title)
	if len(t.Tags) > 0 {
		line += " [" + strings.Join(t.Tags, ",") + "]"
	}
	return line
}

func (m Model) viewDetail() string {
	help := styleHelp.Render("  enter/esc/q back")
	return styleHeader.Render("Task Detail") + "\n\n" + m.detailText + "\n\n" + help
}

func (m Model) viewAdd() string {
	header := styleHeader.Render("Add Task") + "\n\n"
	prompt := "Title: " + m.addInput + "█"
	help := "\n\n" + styleHelp.Render("  enter confirm  esc cancel")
	return header + prompt + help
}

func buildDetailText(t *pm.Task) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ID:          %d\n", t.ID))
	sb.WriteString(fmt.Sprintf("Title:       %s\n", t.Title))
	sb.WriteString(fmt.Sprintf("Status:      %s\n", t.Status))
	sb.WriteString(fmt.Sprintf("Priority:    P%d\n", t.Priority))
	if t.Role != "" {
		sb.WriteString(fmt.Sprintf("Role:        %s\n", t.Role))
	}
	if len(t.Tags) > 0 {
		sb.WriteString(fmt.Sprintf("Tags:        %s\n", strings.Join(t.Tags, ", ")))
	}
	if len(t.DependsOn) > 0 {
		deps := make([]string, len(t.DependsOn))
		for i, d := range t.DependsOn {
			deps[i] = fmt.Sprintf("%d", d)
		}
		sb.WriteString(fmt.Sprintf("Depends on:  %s\n", strings.Join(deps, ", ")))
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
		sb.WriteString(truncate(t.Result, 500))
		sb.WriteString("\n")
	}
	if t.FailureDiagnosis != "" {
		sb.WriteString("\nFailure Diagnosis:\n")
		sb.WriteString(truncate(t.FailureDiagnosis, 300))
		sb.WriteString("\n")
	}
	if len(t.Annotations) > 0 {
		sb.WriteString(fmt.Sprintf("\nAnnotations: %d\n", len(t.Annotations)))
		for _, a := range t.Annotations {
			sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", a.Timestamp.Format("2006-01-02 15:04"), a.Author, truncate(a.Text, 80)))
		}
	}
	return sb.String()
}

// ---- helpers ----------------------------------------------------------------

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ---- tea commands -----------------------------------------------------------

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

func addTask(workdir, title string) tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("cloop", "task", "add", title, "--no-refine")
		cmd.Dir = workdir
		err := cmd.Run()
		if err != nil {
			// fallback: add without --no-refine flag (older builds)
			cmd2 := exec.Command("cloop", "task", "add", title)
			cmd2.Dir = workdir
			err = cmd2.Run()
		}
		return opDoneMsg{err: err}
	}
}

// setTaskStatus calls `cloop task bulk <op> <id>` to update a task's status.
func setTaskStatus(workdir string, taskID int, newStatus pm.TaskStatus) tea.Cmd {
	return func() tea.Msg {
		op := statusToOp(newStatus)
		if op == "" {
			return opDoneMsg{err: fmt.Errorf("unsupported status %s", newStatus)}
		}
		cmd := exec.Command("cloop", "task", "bulk", op, fmt.Sprintf("%d", taskID))
		cmd.Dir = workdir
		err := cmd.Run()
		return opDoneMsg{err: err}
	}
}

// statusToOp maps a TaskStatus to the `cloop task bulk` operation name.
func statusToOp(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return "done"
	case pm.TaskFailed:
		return "fail"
	case pm.TaskSkipped:
		return "skip"
	case pm.TaskPending:
		return "reset"
	default:
		return ""
	}
}

