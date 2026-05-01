package cmd

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/milestone"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// ─── flags ────────────────────────────────────────────────────────────────────

var (
	msProvider    string
	msModel       string
	msDeadline    string
	msDesc        string
	msTasks       string // comma-separated task IDs
	msForce       bool   // allow overwriting existing milestones in plan
)

// ─── root milestone command ───────────────────────────────────────────────────

var milestoneCmd = &cobra.Command{
	Use:   "milestone",
	Short: "Sprint and release planning for PM mode",
	Long: `Organize PM tasks into milestones (sprints or releases).

Milestones group related tasks, track completion progress, and provide
AI-powered velocity forecasting toward deadlines.

Examples:
  cloop milestone create "v1.0 Launch" --deadline 2026-06-15 --tasks 1,2,3
  cloop milestone list
  cloop milestone show "v1.0 Launch"
  cloop milestone assign "v1.0 Launch" --tasks 4,5
  cloop milestone plan                  # AI generates milestone structure
  cloop milestone forecast              # velocity-based completion forecast
  cloop milestone delete "Foundation"`,
}

// ─── create ───────────────────────────────────────────────────────────────────

var milestoneCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new milestone",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found (run 'cloop init' first): %w", err)
		}

		name := args[0]
		// Check for duplicate name
		if existing := milestone.FindByName(s.Milestones, name); existing != nil {
			return fmt.Errorf("milestone %q already exists (id=%d). Use 'milestone assign' to add tasks.", name, existing.ID)
		}

		ms := &milestone.Milestone{
			ID:          milestone.NextID(s.Milestones),
			Name:        name,
			Description: msDesc,
			CreatedAt:   time.Now(),
		}

		if msDeadline != "" {
			t, err := time.Parse("2006-01-02", msDeadline)
			if err != nil {
				return fmt.Errorf("invalid --deadline %q: expected YYYY-MM-DD", msDeadline)
			}
			ms.Deadline = &t
		}

		if msTasks != "" {
			ids, err := parseDeps(msTasks)
			if err != nil {
				return fmt.Errorf("--tasks: %w", err)
			}
			ms.TaskIDs = ids
		}

		s.Milestones = append(s.Milestones, ms)
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		deadlineStr := "no deadline"
		if ms.Deadline != nil {
			deadlineStr = ms.Deadline.Format("2006-01-02")
		}
		color.Green("Milestone #%d created: %s (%s)", ms.ID, ms.Name, deadlineStr)
		if len(ms.TaskIDs) > 0 {
			fmt.Printf("  Tasks: %v\n", ms.TaskIDs)
		}
		return nil
	},
}

// ─── list ─────────────────────────────────────────────────────────────────────

var milestoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all milestones with progress",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found: %w", err)
		}
		if len(s.Milestones) == 0 {
			fmt.Println("No milestones defined yet.")
			fmt.Println("  cloop milestone create \"v1.0\" --deadline 2026-06-01")
			fmt.Println("  cloop milestone plan   # let AI organize tasks into milestones")
			return nil
		}

		milestone.SortByID(s.Milestones)
		bold := color.New(color.Bold)

		fmt.Println()
		bold.Printf("%-4s  %-24s  %-14s  %-10s  %s\n", "ID", "Name", "Status", "Progress", "Deadline")
		fmt.Println(strings.Repeat("─", 72))

		for _, ms := range s.Milestones {
			p := ms.Progress(s.Plan)
			status := ms.StatusLabel(s.Plan)

			deadlineStr := "—"
			if ms.Deadline != nil {
				deadlineStr = ms.Deadline.Format("Jan 02, 2006")
				if status == "overdue" {
					deadlineStr = color.RedString(deadlineStr + " (overdue)")
				} else if status == "at_risk" {
					deadlineStr = color.YellowString(deadlineStr)
				}
			}

			statusStr := formatMilestoneStatus(status)
			progressBar := renderMiniBar(p.PctDone, 12)
			pctStr := fmt.Sprintf("%s %.0f%%", progressBar, p.PctDone)

			fmt.Printf("%-4d  %-24s  %-14s  %-16s  %s\n",
				ms.ID,
				truncate(ms.Name, 24),
				statusStr,
				pctStr,
				deadlineStr,
			)
		}
		fmt.Println()
		return nil
	},
}

// ─── show ─────────────────────────────────────────────────────────────────────

var milestoneShowCmd = &cobra.Command{
	Use:   "show <name|id>",
	Short: "Show detailed milestone status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found: %w", err)
		}

		ms := resolveMilestone(s, args[0])
		if ms == nil {
			return fmt.Errorf("milestone %q not found", args[0])
		}

		p := ms.Progress(s.Plan)
		status := ms.StatusLabel(s.Plan)

		bold := color.New(color.Bold)
		fmt.Println()
		bold.Printf("Milestone #%d — %s\n", ms.ID, ms.Name)
		fmt.Println(strings.Repeat("─", 50))

		if ms.Description != "" {
			fmt.Printf("Description:  %s\n", ms.Description)
		}
		fmt.Printf("Status:       %s\n", formatMilestoneStatus(status))
		if ms.Deadline != nil {
			remaining := time.Until(*ms.Deadline)
			remStr := ""
			if remaining > 0 {
				remStr = fmt.Sprintf(" (%d days remaining)", int(math.Ceil(remaining.Hours()/24)))
			} else {
				remStr = fmt.Sprintf(" (%d days overdue)", int(math.Ceil(-remaining.Hours()/24)))
			}
			fmt.Printf("Deadline:     %s%s\n", ms.Deadline.Format("2006-01-02"), remStr)
		} else {
			fmt.Println("Deadline:     none")
		}
		fmt.Printf("Created:      %s\n", ms.CreatedAt.Format("2006-01-02"))
		fmt.Println()

		// Progress bar
		bar := renderBar(p.PctDone, 40)
		fmt.Printf("Progress:     %s %.0f%%\n", bar, p.PctDone)
		fmt.Printf("Tasks:        %d total — %d done, %d in-progress, %d pending, %d failed\n",
			p.Total, p.Done, p.InProgress, p.Pending, p.Failed)
		fmt.Println()

		// Task list
		if s.Plan != nil && len(ms.TaskIDs) > 0 {
			byID := make(map[int]*pm.Task)
			for i := range s.Plan.Tasks {
				byID[s.Plan.Tasks[i].ID] = s.Plan.Tasks[i]
			}
			bold.Println("Tasks:")
			for _, id := range ms.TaskIDs {
				t, ok := byID[id]
				if !ok {
					fmt.Printf("  #%d  [not found in plan]\n", id)
					continue
				}
				marker := taskStatusMarker(string(t.Status))
				roleStr := ""
				if t.Role != "" {
					roleStr = color.HiBlackString(" [%s]", t.Role)
				}
				fmt.Printf("  %s  #%d%s  %s\n", marker, t.ID, roleStr, t.Title)
			}
		}
		fmt.Println()
		return nil
	},
}

// ─── assign ───────────────────────────────────────────────────────────────────

var milestoneAssignCmd = &cobra.Command{
	Use:   "assign <name|id>",
	Short: "Assign tasks to a milestone",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found: %w", err)
		}

		ms := resolveMilestone(s, args[0])
		if ms == nil {
			return fmt.Errorf("milestone %q not found", args[0])
		}

		if msTasks == "" {
			return fmt.Errorf("--tasks is required (e.g. --tasks 1,2,3)")
		}
		ids, err := parseDeps(msTasks)
		if err != nil {
			return fmt.Errorf("--tasks: %w", err)
		}

		// Merge unique IDs
		existing := make(map[int]bool)
		for _, id := range ms.TaskIDs {
			existing[id] = true
		}
		added := 0
		for _, id := range ids {
			if !existing[id] {
				ms.TaskIDs = append(ms.TaskIDs, id)
				existing[id] = true
				added++
			}
		}

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
		color.Green("Assigned %d task(s) to milestone %q (total: %d tasks)", added, ms.Name, len(ms.TaskIDs))
		return nil
	},
}

// ─── plan ─────────────────────────────────────────────────────────────────────

var milestonePlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "AI-generated milestone plan from current task list",
	Long: `Let the AI organize your current PM task plan into logical milestones.

The AI groups tasks by dependency, priority, and theme into named sprints or
release milestones, with suggested deadlines and rationale.

Use --force to overwrite existing milestones.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found (run 'cloop init' first): %w", err)
		}
		if s.Goal == "" {
			return fmt.Errorf("no project goal — run 'cloop init' first")
		}
		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no tasks in plan — run 'cloop run --plan-only' first")
		}
		if len(s.Milestones) > 0 && !msForce {
			return fmt.Errorf("%d milestones already exist — use --force to replace them", len(s.Milestones))
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		providerName := msProvider
		if providerName == "" {
			providerName = cfg.Provider
		}
		if providerName == "" && s.Provider != "" {
			providerName = s.Provider
		}
		if providerName == "" {
			providerName = autoSelectProvider()
		}

		model := msModel
		if model == "" {
			switch providerName {
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
			Name:             providerName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		fmt.Printf("Generating milestone plan with %s...\n", prov.Name())

		existing := s.Milestones
		if msForce {
			existing = nil
		}

		milestones, err := milestone.Plan(
			context.Background(),
			prov,
			s.Goal,
			s.Plan,
			existing,
			provider.Options{Model: model},
		)
		if err != nil {
			return err
		}

		if msForce {
			s.Milestones = milestones
		} else {
			s.Milestones = append(s.Milestones, milestones...)
		}

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		color.Green("\nCreated %d milestones:\n", len(milestones))
		for _, ms := range milestones {
			deadlineStr := ""
			if ms.Deadline != nil {
				deadlineStr = fmt.Sprintf(" (deadline: %s)", ms.Deadline.Format("2006-01-02"))
			}
			fmt.Printf("  #%d  %s%s — %d tasks\n", ms.ID, ms.Name, deadlineStr, len(ms.TaskIDs))
			if ms.Description != "" {
				fmt.Printf("       %s\n", color.HiBlackString(ms.Description))
			}
		}
		fmt.Println()
		fmt.Println("Run 'cloop milestone list' to see progress.")
		return nil
	},
}

// ─── forecast ─────────────────────────────────────────────────────────────────

var milestoneForecastCmd = &cobra.Command{
	Use:   "forecast",
	Short: "Velocity-based completion forecast for all milestones",
	Long: `Calculate when each milestone will complete based on current task velocity.

Velocity is computed from the number of tasks completed since the project started.
This gives a data-driven estimate for each milestone's completion date.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found: %w", err)
		}
		if len(s.Milestones) == 0 {
			return fmt.Errorf("no milestones defined — run 'cloop milestone plan' first")
		}

		milestone.SortByID(s.Milestones)
		sessionStart := s.CreatedAt

		bold := color.New(color.Bold)
		fmt.Println()
		bold.Println("Milestone Velocity Forecast")
		fmt.Println(strings.Repeat("─", 60))
		fmt.Println()

		for _, ms := range s.Milestones {
			p := ms.Progress(s.Plan)
			forecast := ms.Forecast(s.Plan, sessionStart)

			status := ms.StatusLabel(s.Plan)
			statusStr := formatMilestoneStatus(status)

			fmt.Printf("%s  #%d — %s\n", statusStr, ms.ID, bold.Sprint(ms.Name))

			bar := renderBar(p.PctDone, 30)
			fmt.Printf("  Progress:   %s %.0f%% (%d/%d tasks done)\n",
				bar, p.PctDone, p.Done+p.Skipped, p.Total)

			if forecast.TasksPerDay > 0 {
				fmt.Printf("  Velocity:   %.2f tasks/day\n", forecast.TasksPerDay)
			}

			if forecast.EstimatedDate != nil {
				if forecast.DaysRemaining == 0 {
					fmt.Printf("  Estimate:   %s\n", color.GreenString("complete"))
				} else {
					fmt.Printf("  Estimate:   %s (~%d days)\n",
						forecast.EstimatedDate.Format("2006-01-02"),
						forecast.DaysRemaining)
				}
			}

			if ms.Deadline != nil {
				daysUntil := int(math.Ceil(time.Until(*ms.Deadline).Hours() / 24))
				if daysUntil < 0 {
					fmt.Printf("  Deadline:   %s (%d days overdue)\n",
						color.RedString(ms.Deadline.Format("2006-01-02")), -daysUntil)
				} else {
					fmt.Printf("  Deadline:   %s (%d days remaining)\n",
						ms.Deadline.Format("2006-01-02"), daysUntil)
				}
			}

			riskStr := forecast.RiskLevel
			switch forecast.RiskLevel {
			case "high":
				riskStr = color.RedString("high")
			case "medium":
				riskStr = color.YellowString("medium")
			case "low":
				riskStr = color.GreenString("low")
			}
			fmt.Printf("  Risk:       %s\n", riskStr)
			if forecast.Notes != "" {
				fmt.Printf("  Notes:      %s\n", color.HiBlackString(forecast.Notes))
			}
			fmt.Println()
		}
		return nil
	},
}

// ─── delete ───────────────────────────────────────────────────────────────────

var milestoneDeleteCmd = &cobra.Command{
	Use:   "delete <name|id>",
	Short: "Delete a milestone (tasks are not affected)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found: %w", err)
		}

		ms := resolveMilestone(s, args[0])
		if ms == nil {
			return fmt.Errorf("milestone %q not found", args[0])
		}

		// Remove
		filtered := s.Milestones[:0]
		for _, m := range s.Milestones {
			if m.ID != ms.ID {
				filtered = append(filtered, m)
			}
		}
		s.Milestones = filtered

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
		color.Yellow("Deleted milestone #%d: %s", ms.ID, ms.Name)
		return nil
	},
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// resolveMilestone finds a milestone by name or numeric ID string.
func resolveMilestone(s *state.ProjectState, nameOrID string) *milestone.Milestone {
	// Try numeric ID first
	if id, err := strconv.Atoi(nameOrID); err == nil {
		for _, ms := range s.Milestones {
			if ms.ID == id {
				return ms
			}
		}
	}
	return milestone.FindByName(s.Milestones, nameOrID)
}

func formatMilestoneStatus(status string) string {
	switch status {
	case "complete":
		return color.GreenString("complete")
	case "on_track":
		return color.CyanString("on_track")
	case "needs_attention":
		return color.YellowString("needs_attention")
	case "at_risk":
		return color.YellowString("at_risk")
	case "overdue":
		return color.RedString("overdue")
	case "in_progress":
		return color.CyanString("in_progress")
	case "empty":
		return color.HiBlackString("empty")
	default:
		return status
	}
}

func renderBar(pct float64, width int) string {
	filled := int(math.Round(pct / 100.0 * float64(width)))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	switch {
	case pct >= 80:
		return color.GreenString(bar)
	case pct >= 40:
		return color.YellowString(bar)
	default:
		return color.HiBlackString(bar)
	}
}

func renderMiniBar(pct float64, width int) string {
	filled := int(math.Round(pct / 100.0 * float64(width)))
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func taskStatusMarker(status string) string {
	switch status {
	case "done":
		return color.GreenString("✓")
	case "in_progress":
		return color.CyanString("▶")
	case "failed":
		return color.RedString("✗")
	case "skipped":
		return color.YellowString("⏭")
	default:
		return color.HiBlackString("○")
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

// ─── init ─────────────────────────────────────────────────────────────────────

func init() {
	// create flags
	milestoneCreateCmd.Flags().StringVar(&msDeadline, "deadline", "", "Target deadline (YYYY-MM-DD)")
	milestoneCreateCmd.Flags().StringVar(&msDesc, "description", "", "One-sentence milestone description")
	milestoneCreateCmd.Flags().StringVar(&msTasks, "tasks", "", "Comma-separated task IDs to assign (e.g. 1,2,3)")

	// assign flags
	milestoneAssignCmd.Flags().StringVar(&msTasks, "tasks", "", "Comma-separated task IDs to assign (required)")

	// plan flags
	milestonePlanCmd.Flags().StringVar(&msProvider, "provider", "", "AI provider to use")
	milestonePlanCmd.Flags().StringVar(&msModel, "model", "", "Override model")
	milestonePlanCmd.Flags().BoolVar(&msForce, "force", false, "Replace existing milestones with AI-generated plan")

	// Wire subcommands
	milestoneCmd.AddCommand(milestoneCreateCmd)
	milestoneCmd.AddCommand(milestoneListCmd)
	milestoneCmd.AddCommand(milestoneShowCmd)
	milestoneCmd.AddCommand(milestoneAssignCmd)
	milestoneCmd.AddCommand(milestonePlanCmd)
	milestoneCmd.AddCommand(milestoneForecastCmd)
	milestoneCmd.AddCommand(milestoneDeleteCmd)

	rootCmd.AddCommand(milestoneCmd)
}
