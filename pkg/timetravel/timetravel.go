// Package timetravel provides an interactive bubbletea TUI for replaying
// a task's checkpoint history step-by-step.
package timetravel

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/blechschmidt/cloop/pkg/checkpoint"
)

// ---- styles -----------------------------------------------------------------

var (
	styleTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	styleHelp  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleSep   = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))

	stylePane = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240"))

	stylePaneActive = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("33"))

	styleAdd    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))  // green
	styleRemove = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))   // red
	styleNeutral = lipgloss.NewStyle().Foreground(lipgloss.Color("11")) // yellow
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	styleCheckpointActive = lipgloss.NewStyle().
				Bold(true).
				Background(lipgloss.Color("237")).
				Foreground(lipgloss.Color("255")).
				Padding(0, 1)

	styleCheckpointInactive = lipgloss.NewStyle().
				Foreground(lipgloss.Color("244")).
				Padding(0, 1)

	styleEventStart    = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	styleEventComplete = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styleEventFail     = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleEventSkip     = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
)

// ---- model ------------------------------------------------------------------

// Model is the bubbletea model for the time-travel TUI.
type Model struct {
	entries  []*checkpoint.HistoryEntry
	taskID   int
	taskTitle string
	cursor   int // currently selected checkpoint index

	width  int
	height int
	ready  bool
}

// New creates a Model loaded with all checkpoints for the given task.
// Returns an error if no checkpoints are found.
func New(workDir string, taskID int, taskTitle string) (*Model, error) {
	entries, err := checkpoint.ListHistory(workDir, taskID)
	if err != nil {
		return nil, fmt.Errorf("loading checkpoints: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no checkpoint history found for task %d", taskID)
	}
	return &Model{
		entries:   entries,
		taskID:    taskID,
		taskTitle: taskTitle,
		cursor:    len(entries) - 1, // start at the latest checkpoint
	}, nil
}

// Run launches the bubbletea program in alt-screen mode.
func Run(m *Model) error {
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ---- bubbletea interface ----------------------------------------------------

func (m *Model) Init() tea.Cmd {
	return nil
}

type windowSizeMsg struct{ w, h int }

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "Q", "ctrl+c", "esc":
			return m, tea.Quit
		case "left", "h":
			if m.cursor > 0 {
				m.cursor--
			}
		case "right", "l":
			if m.cursor < len(m.entries)-1 {
				m.cursor++
			}
		case "0", "g":
			m.cursor = 0
		case "G", "$":
			m.cursor = len(m.entries) - 1
		}
	}
	return m, nil
}

func (m *Model) View() string {
	if !m.ready || m.width == 0 {
		return "Loading…"
	}

	// Reserve lines for header (2) + timeline bar (3) + help (1)
	const reservedLines = 7
	paneHeight := m.height - reservedLines
	if paneHeight < 4 {
		paneHeight = 4
	}

	// Split width: left (diff) 40%, right (output) 60%
	leftWidth := m.width * 40 / 100
	rightWidth := m.width - leftWidth - 2 // -2 for border gap
	if leftWidth < 20 {
		leftWidth = 20
	}
	if rightWidth < 20 {
		rightWidth = 20
	}

	// ---- header -------------------------------------------------------------
	header := styleTitle.Render(fmt.Sprintf(" Time Travel — %s", m.taskTitle))
	pos := styleDim.Render(fmt.Sprintf("  checkpoint %d/%d", m.cursor+1, len(m.entries)))

	// ---- timeline bar -------------------------------------------------------
	timeline := m.renderTimeline()

	// ---- left pane: diff ----------------------------------------------------
	diffContent := m.renderDiff(leftWidth - 4)
	leftPane := renderPane(diffContent, "State Diff", leftWidth, paneHeight, true)

	// ---- right pane: step log -----------------------------------------------
	logContent := m.renderLog(rightWidth - 4)
	rightPane := renderPane(logContent, "Step Log", rightWidth, paneHeight, false)

	// ---- join panes ---------------------------------------------------------
	panes := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, " ", rightPane)

	// ---- help ---------------------------------------------------------------
	help := styleHelp.Render("← → navigate   0/g first   G/$ last   q quit")

	return strings.Join([]string{header + pos, timeline, panes, help}, "\n")
}

// renderPane wraps content in a bordered panel with a title.
func renderPane(content, title string, width, height int, active bool) string {
	inner := wrapLines(content, width-4)
	lines := strings.Split(inner, "\n")
	// Pad/truncate to fill pane height (minus 2 for border)
	innerH := height - 2
	for len(lines) < innerH {
		lines = append(lines, "")
	}
	if len(lines) > innerH {
		lines = lines[:innerH]
	}
	body := strings.Join(lines, "\n")

	st := stylePane
	if active {
		st = stylePaneActive
	}
	return st.Width(width).Height(height).Render(
		styleDim.Render(title) + "\n" + body,
	)
}

// renderTimeline renders a compact horizontal timeline of all checkpoints.
func (m *Model) renderTimeline() string {
	var sb strings.Builder
	sb.WriteString(styleDim.Render(" "))
	for i, e := range m.entries {
		label := eventShort(e.Checkpoint.Event)
		if i == m.cursor {
			sb.WriteString(styleCheckpointActive.Render(fmt.Sprintf("[%d:%s]", i+1, label)))
		} else {
			sb.WriteString(styleCheckpointInactive.Render(fmt.Sprintf(" %d:%s ", i+1, label)))
		}
		if i < len(m.entries)-1 {
			sb.WriteString(styleDim.Render("─"))
		}
	}
	ts := ""
	if !m.entries[m.cursor].Checkpoint.Timestamp.IsZero() {
		ts = styleDim.Render("  " + m.entries[m.cursor].Checkpoint.Timestamp.Format("2006-01-02 15:04:05"))
	}
	return sb.String() + ts
}

// renderDiff produces a git-style diff between checkpoint[cursor-1] and checkpoint[cursor].
func (m *Model) renderDiff(maxWidth int) string {
	cur := m.entries[m.cursor].Checkpoint
	var sb strings.Builder

	sb.WriteString(styleDim.Render(fmt.Sprintf("checkpoint %d of %d\n", m.cursor+1, len(m.entries))))
	sb.WriteString(styleDim.Render(fmt.Sprintf("event: ")))
	sb.WriteString(eventStyled(cur.Event) + "\n\n")

	if m.cursor == 0 {
		// First checkpoint — just show state, no diff
		sb.WriteString(styleDim.Render("(initial checkpoint — no previous)\n\n"))
		writeField(&sb, "  status", "", cur.Status)
		if cur.OutputLength > 0 {
			writeField(&sb, "  output", "", fmt.Sprintf("%d chars", cur.OutputLength))
		}
		if cur.TokenCount > 0 {
			writeField(&sb, "  tokens", "", fmt.Sprintf("%d", cur.TokenCount))
		}
		if cur.StepNumber > 0 {
			writeField(&sb, "  step#", "", fmt.Sprintf("%d", cur.StepNumber))
		}
		return sb.String()
	}

	prev := m.entries[m.cursor-1].Checkpoint

	// Status
	diffField(&sb, "status", prev.Status, cur.Status)

	// Step number
	if prev.StepNumber != cur.StepNumber {
		diffFieldInt(&sb, "step#", prev.StepNumber, cur.StepNumber)
	} else {
		sb.WriteString(styleDim.Render(fmt.Sprintf("  step#:    %d\n", cur.StepNumber)))
	}

	// Output length
	diffFieldInt(&sb, "output", prev.OutputLength, cur.OutputLength)
	if cur.OutputLength != prev.OutputLength && cur.OutputLength > 0 {
		delta := cur.OutputLength - prev.OutputLength
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		sb.WriteString(styleDim.Render(fmt.Sprintf("            (%s%d chars delta)\n", sign, delta)))
	}

	// Token count
	diffFieldInt(&sb, "tokens", prev.TokenCount, cur.TokenCount)
	if cur.TokenCount != prev.TokenCount && cur.TokenCount > 0 {
		delta := cur.TokenCount - prev.TokenCount
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		sb.WriteString(styleDim.Render(fmt.Sprintf("            (%s%d delta)\n", sign, delta)))
	}

	// Output hash
	if prev.OutputHash != cur.OutputHash {
		if prev.OutputHash != "" {
			sb.WriteString(styleRemove.Render(fmt.Sprintf("- hash:     %s\n", prev.OutputHash)))
		}
		if cur.OutputHash != "" {
			sb.WriteString(styleAdd.Render(fmt.Sprintf("+ hash:     %s\n", cur.OutputHash)))
		}
	} else if cur.OutputHash != "" {
		sb.WriteString(styleDim.Render(fmt.Sprintf("  hash:     %s\n", cur.OutputHash)))
	}

	// Elapsed time
	if !prev.Timestamp.IsZero() && !cur.Timestamp.IsZero() {
		elapsed := cur.Timestamp.Sub(prev.Timestamp).Round(time.Millisecond)
		sb.WriteString(styleNeutral.Render(fmt.Sprintf("  Δ elapsed: %s\n", elapsed)))
	}

	return sb.String()
}

// renderLog renders the accumulated output at the current checkpoint,
// truncated to fit the pane.
func (m *Model) renderLog(maxWidth int) string {
	cur := m.entries[m.cursor].Checkpoint
	if cur.AccumulatedOutput == "" {
		return styleDim.Render("(no output recorded at this checkpoint)")
	}

	lines := strings.Split(cur.AccumulatedOutput, "\n")
	// Show the last N lines that fit the display
	const maxLines = 300
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}

	var sb strings.Builder
	sb.WriteString(styleDim.Render(fmt.Sprintf("output at checkpoint %d/%d (%d chars):\n",
		m.cursor+1, len(m.entries), cur.OutputLength)))
	sb.WriteString(styleSep.Render(strings.Repeat("─", min(maxWidth, 60))) + "\n")
	for _, l := range lines {
		if utf8.RuneCountInString(l) > maxWidth {
			runes := []rune(l)
			l = string(runes[:maxWidth-1]) + "…"
		}
		sb.WriteString(l + "\n")
	}
	return sb.String()
}

// ---- helpers ----------------------------------------------------------------

func diffField(sb *strings.Builder, field, from, to string) {
	if from != to {
		sb.WriteString(styleRemove.Render(fmt.Sprintf("- %-9s %s\n", field+":", from)))
		sb.WriteString(styleAdd.Render(fmt.Sprintf("+ %-9s %s\n", field+":", to)))
	} else {
		sb.WriteString(styleDim.Render(fmt.Sprintf("  %-9s %s\n", field+":", to)))
	}
}

func diffFieldInt(sb *strings.Builder, field string, from, to int) {
	if from != to {
		sb.WriteString(styleRemove.Render(fmt.Sprintf("- %-9s %d\n", field+":", from)))
		sb.WriteString(styleAdd.Render(fmt.Sprintf("+ %-9s %d\n", field+":", to)))
	} else {
		sb.WriteString(styleDim.Render(fmt.Sprintf("  %-9s %d\n", field+":", to)))
	}
}

func writeField(sb *strings.Builder, field, from, to string) {
	sb.WriteString(styleDim.Render(fmt.Sprintf("  %-9s %s\n", field+":", to)))
}

func eventShort(event string) string {
	switch event {
	case "start":
		return "start"
	case "complete":
		return "done"
	case "fail":
		return "FAIL"
	case "skip":
		return "skip"
	default:
		if event == "" {
			return "?"
		}
		if len(event) > 5 {
			return event[:5]
		}
		return event
	}
}

func eventStyled(event string) string {
	switch event {
	case "start":
		return styleEventStart.Render("start")
	case "complete":
		return styleEventComplete.Render("complete")
	case "fail":
		return styleEventFail.Render("FAILED")
	case "skip":
		return styleEventSkip.Render("skipped")
	default:
		if event == "" {
			return styleDim.Render("unknown")
		}
		return event
	}
}

// wrapLines wraps long lines to maxWidth.
func wrapLines(content string, maxWidth int) string {
	if maxWidth <= 0 {
		return content
	}
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		if utf8.RuneCountInString(line) <= maxWidth {
			result = append(result, line)
			continue
		}
		runes := []rune(line)
		for len(runes) > maxWidth {
			result = append(result, string(runes[:maxWidth]))
			runes = runes[maxWidth:]
		}
		if len(runes) > 0 {
			result = append(result, string(runes))
		}
	}
	return strings.Join(result, "\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
