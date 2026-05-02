package viz

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// spinnerFrames are the braille spinner animation frames for in_progress tasks.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ---- lipgloss styles -------------------------------------------------------

var (
	lgNodePending    = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	lgNodeInProgress = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	lgNodeDone       = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	lgNodeFailed     = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	lgNodeSkipped    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	lgArrow          = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	lgHeader         = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	lgSummaryBar     = lipgloss.NewStyle().
				Background(lipgloss.Color("235")).
				Foreground(lipgloss.Color("250")).
				Padding(0, 1)
	lgHelp = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	lgErr  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
)

// nodeStyle returns the lipgloss style for a given task status.
func nodeStyle(s pm.TaskStatus) lipgloss.Style {
	switch s {
	case pm.TaskInProgress:
		return lgNodeInProgress
	case pm.TaskDone:
		return lgNodeDone
	case pm.TaskFailed:
		return lgNodeFailed
	case pm.TaskSkipped:
		return lgNodeSkipped
	default:
		return lgNodePending
	}
}

// ---- tea messages ----------------------------------------------------------

type liveTickMsg time.Time
type liveStateMsg struct {
	plan *pm.Plan
	err  error
}

// ---- model -----------------------------------------------------------------

// liveModel is the bubbletea model for the live graph view.
type liveModel struct {
	workDir    string
	plan       *pm.Plan
	errMsg     string
	spinFrame  int
	startTimes map[int]time.Time // taskID -> when first observed as in_progress
	now        time.Time
	width      int
}

func newLiveModel(workDir string) liveModel {
	return liveModel{
		workDir:    workDir,
		startTimes: make(map[int]time.Time),
		now:        time.Now(),
	}
}

// loadStateCmd returns a tea.Cmd that reads the state from disk.
func loadStateCmd(workDir string) tea.Cmd {
	return func() tea.Msg {
		s, err := state.Load(workDir)
		if err != nil {
			return liveStateMsg{err: err}
		}
		if !s.PMMode || s.Plan == nil {
			return liveStateMsg{err: fmt.Errorf("no active plan — run 'cloop run --pm' first")}
		}
		return liveStateMsg{plan: s.Plan}
	}
}

// tickCmd schedules the next 500ms tick.
func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return liveTickMsg(t)
	})
}

func (m liveModel) Init() tea.Cmd {
	return tea.Batch(loadStateCmd(m.workDir), tickCmd())
}

func (m liveModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}

	case liveTickMsg:
		m.now = time.Time(msg)
		m.spinFrame = (m.spinFrame + 1) % len(spinnerFrames)
		return m, tea.Batch(loadStateCmd(m.workDir), tickCmd())

	case liveStateMsg:
		if msg.err != nil {
			m.errMsg = msg.err.Error()
		} else {
			m.errMsg = ""
			if msg.plan != nil {
				// Track start times: record first observation of in_progress status.
				for _, t := range msg.plan.Tasks {
					if t.Status == pm.TaskInProgress {
						if _, seen := m.startTimes[t.ID]; !seen {
							m.startTimes[t.ID] = m.now
						}
					}
				}
				m.plan = msg.plan
			}
		}
	}
	return m, nil
}

func (m liveModel) View() string {
	var sb strings.Builder

	// Header
	headerText := "  Live Task Graph"
	if m.plan != nil && m.plan.Goal != "" {
		g := m.plan.Goal
		if len(g) > 55 {
			g = g[:52] + "..."
		}
		headerText += ": " + g
	}
	sb.WriteString(lgHeader.Render(headerText))
	sb.WriteString("\n")

	divider := strings.Repeat("─", 62)
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(divider))
	sb.WriteString("\n\n")

	if m.errMsg != "" {
		sb.WriteString(lgErr.Render("  error: "+m.errMsg) + "\n")
		sb.WriteString(lgHelp.Render("  press q to quit") + "\n")
		return sb.String()
	}

	if m.plan == nil {
		sb.WriteString("  loading...\n")
		sb.WriteString(lgHelp.Render("  press q to quit") + "\n")
		return sb.String()
	}

	// Build adjacency data (same as RenderASCII)
	taskByID := make(map[int]*pm.Task, len(m.plan.Tasks))
	for _, t := range m.plan.Tasks {
		taskByID[t.ID] = t
	}
	inDeg := make(map[int]int, len(m.plan.Tasks))
	children := make(map[int][]int, len(m.plan.Tasks))
	for _, t := range m.plan.Tasks {
		if _, ok := inDeg[t.ID]; !ok {
			inDeg[t.ID] = 0
		}
		for _, dep := range t.DependsOn {
			inDeg[t.ID]++
			children[dep] = append(children[dep], t.ID)
		}
	}
	queue := []int{}
	for _, t := range m.plan.Tasks {
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
	for _, t := range m.plan.Tasks {
		if !seen[t.ID] {
			order = append(order, t.ID)
		}
	}

	// Render nodes
	for _, id := range order {
		t, ok := taskByID[id]
		if !ok {
			continue
		}

		style := nodeStyle(t.Status)

		// Build symbol (with spinner for in_progress)
		var sym string
		switch t.Status {
		case pm.TaskInProgress:
			sym = spinnerFrames[m.spinFrame]
		case pm.TaskDone:
			sym = "✓"
		case pm.TaskFailed:
			sym = "✗"
		case pm.TaskSkipped:
			sym = "⊘"
		default:
			sym = "○"
		}

		// Build title (truncated)
		title := t.Title
		if len(title) > 44 {
			title = title[:41] + "..."
		}

		// Build elapsed suffix for in_progress tasks
		var elapsed string
		if t.Status == pm.TaskInProgress {
			if start, ok := m.startTimes[t.ID]; ok && !start.IsZero() {
				d := m.now.Sub(start).Truncate(time.Second)
				elapsed = " " + lgNodeInProgress.Copy().Faint(true).Render(fmt.Sprintf("(%s)", d))
			}
		}

		// Format: "  SPIN [ID] TITLE  (elapsed)"
		nodeLabel := fmt.Sprintf("  %s [%d] %s", sym, t.ID, title)
		sb.WriteString(style.Render(nodeLabel) + elapsed + "\n")

		// Dependency line (if any)
		if len(t.DependsOn) > 0 {
			depIDs := make([]string, len(t.DependsOn))
			for i, d := range t.DependsOn {
				depIDs[i] = fmt.Sprintf("#%d", d)
			}
			depLine := "     needs: " + strings.Join(depIDs, ", ")
			sb.WriteString(style.Copy().Faint(true).Render(depLine) + "\n")
		}

		// Dependency arrows to children
		ch := children[id]
		sort.Ints(ch)
		for i, cid := range ch {
			child, ok2 := taskByID[cid]
			if !ok2 {
				continue
			}
			connector := "  ├──▶"
			if i == len(ch)-1 {
				connector = "  └──▶"
			}
			childTitle := child.Title
			if len(childTitle) > 38 {
				childTitle = childTitle[:35] + "..."
			}
			arrowLine := fmt.Sprintf("%s #%d %s", connector, child.ID, childTitle)
			sb.WriteString(lgArrow.Render(arrowLine) + "\n")
		}
		sb.WriteString("\n")
	}

	// Legend
	legend := fmt.Sprintf("  %s pending  %s in_progress  %s done  %s failed  %s skipped",
		lgNodePending.Render("○"),
		lgNodeInProgress.Render("⠋"),
		lgNodeDone.Render("✓"),
		lgNodeFailed.Render("✗"),
		lgNodeSkipped.Render("⊘"),
	)
	sb.WriteString(legend + "\n\n")

	// Summary bar
	var nPending, nInProgress, nDone, nFailed, nSkipped int
	for _, t := range m.plan.Tasks {
		switch t.Status {
		case pm.TaskPending:
			nPending++
		case pm.TaskInProgress:
			nInProgress++
		case pm.TaskDone:
			nDone++
		case pm.TaskFailed:
			nFailed++
		case pm.TaskSkipped:
			nSkipped++
		}
	}
	total := len(m.plan.Tasks)
	summaryText := fmt.Sprintf(
		"  total:%d  pending:%d  in_progress:%d  done:%d  failed:%d  skipped:%d",
		total, nPending, nInProgress, nDone, nFailed, nSkipped,
	)
	sb.WriteString(lgSummaryBar.Render(summaryText) + "\n")
	sb.WriteString(lgHelp.Render("  press q to quit • polls every 500ms") + "\n")

	return sb.String()
}

// RunLive starts the bubbletea live animated execution graph.
func RunLive(workDir string) error {
	m := newLiveModel(workDir)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
