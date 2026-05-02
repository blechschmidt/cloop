package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/forecast"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/sprint"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	sprintProvider string
	sprintModel    string
	sprintDays     int
)

var sprintCmd = &cobra.Command{
	Use:   "sprint",
	Short: "AI-powered sprint planning with velocity-based grouping",
	Long: `Sprint groups pending tasks into time-boxed sprints using AI.

Velocity data (actual vs estimated minutes from completed tasks) is used to
calibrate the time estimates. Deadlines, priorities, and dependencies are
respected when assigning tasks to sprints.

Sub-commands:
  plan        Call AI to generate a sprint plan from pending tasks
  list        Show all planned sprints with completion %
  show <n>    Show tasks in sprint N`,
}

var sprintPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Call AI to generate a sprint plan from pending tasks",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no plan found — run `cloop init` first")
		}

		f := forecast.Build(s)

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		provName := sprintProvider
		if provName == "" {
			provName = cfg.Provider
		}
		if provName == "" {
			provName = s.Provider
		}

		model := sprintModel
		if model == "" {
			switch provName {
			case "anthropic":
				model = cfg.Anthropic.Model
			case "openai":
				model = cfg.OpenAI.Model
			case "ollama":
				model = cfg.Ollama.Model
			case "claudecode":
				model = cfg.ClaudeCode.Model
			}
		}

		provCfg := provider.ProviderConfig{
			Name:             provName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		p, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("building provider: %w", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()

		bold := color.New(color.Bold)
		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)

		cyan.Printf("━━━ cloop sprint plan ━━━\n\n")

		bold.Printf("Goal:     ")
		fmt.Printf("%s\n", truncateSprint(s.Goal, 72))
		bold.Printf("Provider: ")
		fmt.Printf("%s", provName)
		if model != "" {
			fmt.Printf(" (%s)", model)
		}
		fmt.Printf("\n")
		bold.Printf("Sprint:   ")
		fmt.Printf("%d-day sprints\n", sprintDays)

		if f.MinuteDataPoints > 0 {
			bold.Printf("Velocity: ")
			fmt.Printf("ratio=%.2f (from %d tasks)  avg=%.0f min/task\n",
				f.VelocityRatio, f.MinuteDataPoints, f.AvgEstimatedMinutes)
		} else {
			dim.Printf("Velocity: no historical data — using 60 min/task default\n")
		}
		fmt.Println()

		dim.Printf("Calling AI to plan sprints...\n\n")

		var buf strings.Builder
		sprints, err := sprint.Plan(ctx, p, s, f, model, sprintDays, func(chunk string) {
			buf.WriteString(chunk)
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("sprint plan: %w", err)
		}

		sf := &sprint.SprintFile{Sprints: sprints}
		if err := sprint.Save(workdir, sf); err != nil {
			return fmt.Errorf("saving sprints: %w", err)
		}
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		printSprintTable(sprints, s.Plan)
		fmt.Printf("\n")
		dim.Printf("Saved to .cloop/sprints.json\n")
		return nil
	},
}

var sprintListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show all planned sprints with completion %",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		sf, err := sprint.Load(workdir)
		if err != nil {
			return err
		}

		cyan := color.New(color.FgCyan, color.Bold)
		cyan.Printf("━━━ cloop sprint list ━━━\n\n")

		if len(sf.Sprints) == 0 {
			fmt.Println("No sprints planned yet. Run `cloop sprint plan` to generate a sprint plan.")
			return nil
		}

		printSprintTable(sf.Sprints, s.Plan)
		return nil
	},
}

var sprintShowCmd = &cobra.Command{
	Use:   "show <n>",
	Short: "Show tasks in sprint N",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		n, err := strconv.Atoi(args[0])
		if err != nil || n < 1 {
			return fmt.Errorf("invalid sprint number: %s", args[0])
		}

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		sf, err := sprint.Load(workdir)
		if err != nil {
			return err
		}

		if len(sf.Sprints) == 0 {
			fmt.Println("No sprints planned yet. Run `cloop sprint plan` to generate a sprint plan.")
			return nil
		}

		var sp *sprint.Sprint
		for _, candidate := range sf.Sprints {
			if candidate.ID == n {
				sp = candidate
				break
			}
		}
		if sp == nil {
			return fmt.Errorf("sprint %d not found (have %d sprints)", n, len(sf.Sprints))
		}

		bold := color.New(color.Bold)
		cyan := color.New(color.FgCyan, color.Bold)
		green := color.New(color.FgGreen, color.Bold)
		yellow := color.New(color.FgYellow, color.Bold)
		red := color.New(color.FgRed, color.Bold)
		dim := color.New(color.Faint)

		pct := sp.CompletionPct(s.Plan)

		cyan.Printf("━━━ Sprint %d: %s ━━━\n\n", sp.ID, sp.Name)
		bold.Printf("Goal:       ")
		fmt.Printf("%s\n", sp.Goal)
		bold.Printf("Dates:      ")
		fmt.Printf("%s → %s\n", sp.StartDate.Format("2006-01-02"), sp.EndDate.Format("2006-01-02"))
		bold.Printf("Est. hours: ")
		fmt.Printf("%.1fh\n", sp.EstimatedHours)
		bold.Printf("Progress:   ")
		bar := progressBar(pct, 30)
		fmt.Printf("%s %d%%\n\n", bar, pct)

		bold.Printf("Tasks (%d)\n", len(sp.TaskIDs))
		fmt.Printf("%s\n", strings.Repeat("─", 72))

		for _, id := range sp.TaskIDs {
			if s.Plan == nil {
				fmt.Printf("  #%d\n", id)
				continue
			}
			task := s.Plan.TaskByID(id)
			if task == nil {
				dim.Printf("  #%d  (task not found)\n", id)
				continue
			}

			icon := sprintStatusIcon(task.Status)
			c := sprintStatusColor(task.Status, green, yellow, red, dim)

			estStr := ""
			if task.EstimatedMinutes > 0 {
				estStr = fmt.Sprintf(" [%dm]", task.EstimatedMinutes)
			}

			title := task.Title
			if len(title) > 55 {
				title = title[:54] + "…"
			}

			c.Printf("  %s  #%-4d  %-55s  P%d%s\n",
				icon, task.ID, title, task.Priority, estStr)
		}

		return nil
	},
}

// printSprintTable renders a summary table of sprints.
func printSprintTable(sprints []*sprint.Sprint, plan *pm.Plan) {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)

	fmt.Printf("%-4s  %-24s  %-10s  %-10s  %6s  %5s  %s\n",
		"#", "Name", "Start", "End", "Est h", "%", "Goal")
	fmt.Printf("%s\n", strings.Repeat("─", 85))

	for _, sp := range sprints {
		pct := sp.CompletionPct(plan)

		name := sp.Name
		if len(name) > 24 {
			name = name[:23] + "…"
		}
		goal := sp.Goal
		if len(goal) > 38 {
			goal = goal[:37] + "…"
		}

		pctStr := fmt.Sprintf("%d%%", pct)
		var pctColor *color.Color
		switch {
		case pct >= 100:
			pctColor = green
		case pct >= 50:
			pctColor = yellow
		default:
			pctColor = dim
		}

		bold.Printf("%-4d  ", sp.ID)
		fmt.Printf("%-24s  %-10s  %-10s  %5.1fh  ",
			name,
			sp.StartDate.Format("2006-01-02"),
			sp.EndDate.Format("2006-01-02"),
			sp.EstimatedHours,
		)
		pctColor.Printf("%5s  ", pctStr)
		fmt.Printf("%s\n", goal)
	}
}

func sprintStatusIcon(status pm.TaskStatus) string {
	switch status {
	case pm.TaskDone:
		return "✓"
	case pm.TaskInProgress:
		return "▶"
	case pm.TaskFailed:
		return "✗"
	case pm.TaskSkipped:
		return "⊘"
	case pm.TaskTimedOut:
		return "⏱"
	default:
		return "○"
	}
}

func sprintStatusColor(status pm.TaskStatus, green, yellow, red, dim *color.Color) *color.Color {
	switch status {
	case pm.TaskDone:
		return green
	case pm.TaskInProgress:
		return yellow
	case pm.TaskFailed, pm.TaskTimedOut:
		return red
	default:
		return dim
	}
}

func truncateSprint(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func init() {
	sprintPlanCmd.Flags().StringVar(&sprintProvider, "provider", "", "AI provider (claudecode, anthropic, openai, ollama)")
	sprintPlanCmd.Flags().StringVar(&sprintModel, "model", "", "Model override")
	sprintPlanCmd.Flags().IntVar(&sprintDays, "days", 7, "Sprint duration in days")

	sprintCmd.AddCommand(sprintPlanCmd)
	sprintCmd.AddCommand(sprintListCmd)
	sprintCmd.AddCommand(sprintShowCmd)
	rootCmd.AddCommand(sprintCmd)
}
