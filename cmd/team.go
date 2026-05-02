package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/team"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var teamCmd = &cobra.Command{
	Use:   "team",
	Short: "Multi-user task assignment and workload management",
	Long: `Manage team member task assignments and view per-user workload dashboards.

Examples:
  cloop team assign 3 alice       # assign task 3 to alice
  cloop team unassign 3           # remove assignment from task 3
  cloop team status               # show per-user workload table
  cloop team balance              # AI-suggested workload rebalancing`,
}

var teamAssignCmd = &cobra.Command{
	Use:   "assign <task-id> <user>",
	Short: "Assign a task to a team member",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task id %q: %w", args[0], err)
		}
		user := strings.TrimSpace(args[1])
		if user == "" {
			return fmt.Errorf("user name must not be empty; use 'cloop team unassign' to remove an assignment")
		}
		workdir, _ := os.Getwd()
		if err := team.Assign(workdir, taskID, user); err != nil {
			return err
		}
		color.New(color.FgGreen).Printf("Task %d assigned to %s\n", taskID, user)
		return nil
	},
}

var teamUnassignCmd = &cobra.Command{
	Use:   "unassign <task-id>",
	Short: "Remove the assignee from a task",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task id %q: %w", args[0], err)
		}
		workdir, _ := os.Getwd()
		if err := team.Assign(workdir, taskID, ""); err != nil {
			return err
		}
		color.New(color.FgYellow).Printf("Task %d unassigned\n", taskID)
		return nil
	},
}

var teamStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show per-user workload table",
	Long: `Display a table of team members and their assigned tasks, including
status, priority, and estimated hours.

Tasks with no assignee are shown in a separate "(unassigned)" section.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		members := team.Members(s.Plan)
		wl := team.Workload(s.Plan)

		headerColor := color.New(color.FgCyan, color.Bold)

		// Per-member section.
		for _, member := range members {
			tasks := wl[member]
			totalEst := 0
			pending, inProg, done := 0, 0, 0
			for _, t := range tasks {
				totalEst += t.EstimatedMinutes
				switch t.Status {
				case pm.TaskPending:
					pending++
				case pm.TaskInProgress:
					inProg++
				case pm.TaskDone, pm.TaskSkipped:
					done++
				}
			}

			estStr := ""
			if totalEst > 0 {
				h := totalEst / 60
				m := totalEst % 60
				if h > 0 {
					estStr = fmt.Sprintf(", ~%dh%dm est.", h, m)
				} else {
					estStr = fmt.Sprintf(", ~%dm est.", m)
				}
			}

			headerColor.Printf("\n%s", member)
			fmt.Printf("  (%d task(s): %d pending, %d in-progress, %d done%s)\n",
				len(tasks), pending, inProg, done, estStr)

			// Sort by priority then ID for deterministic output.
			sorted := make([]*pm.Task, len(tasks))
			copy(sorted, tasks)
			sort.SliceStable(sorted, func(i, j int) bool {
				if sorted[i].Priority != sorted[j].Priority {
					return sorted[i].Priority < sorted[j].Priority
				}
				return sorted[i].ID < sorted[j].ID
			})

			fmt.Printf("  %-5s  %-12s  %-4s  %-8s  %s\n", "ID", "STATUS", "PRIO", "EST", "TITLE")
			fmt.Printf("  %-5s  %-12s  %-4s  %-8s  %s\n", "-----", "------------", "----", "--------", "-----")
			for _, t := range sorted {
				estCell := "-"
				if t.EstimatedMinutes > 0 {
					h := t.EstimatedMinutes / 60
					m := t.EstimatedMinutes % 60
					if h > 0 {
						estCell = fmt.Sprintf("%dh%dm", h, m)
					} else {
						estCell = fmt.Sprintf("%dm", m)
					}
				}
				statusColor := statusRowColor(t.Status)
				line := fmt.Sprintf("  %-5d  %-12s  P%-3d  %-8s  %s",
					t.ID, string(t.Status), t.Priority, estCell, truncateStr(t.Title, 55))
				statusColor.Println(line)
			}
		}

		// Unassigned tasks.
		if unassigned := wl[""]; len(unassigned) > 0 {
			headerColor.Printf("\n(unassigned)")
			fmt.Printf("  (%d task(s))\n", len(unassigned))
			fmt.Printf("  %-5s  %-12s  %-4s  %-8s  %s\n", "ID", "STATUS", "PRIO", "EST", "TITLE")
			fmt.Printf("  %-5s  %-12s  %-4s  %-8s  %s\n", "-----", "------------", "----", "--------", "-----")
			for _, t := range unassigned {
				estCell := "-"
				if t.EstimatedMinutes > 0 {
					h := t.EstimatedMinutes / 60
					m := t.EstimatedMinutes % 60
					if h > 0 {
						estCell = fmt.Sprintf("%dh%dm", h, m)
					} else {
						estCell = fmt.Sprintf("%dm", m)
					}
				}
				line := fmt.Sprintf("  %-5d  %-12s  P%-3d  %-8s  %s",
					t.ID, string(t.Status), t.Priority, estCell, truncateStr(t.Title, 55))
				color.New(color.Faint).Println(line)
			}
		}

		if len(members) == 0 && len(wl[""]) == len(s.Plan.Tasks) {
			color.New(color.Faint).Println("No assignments yet. Use 'cloop team assign <task-id> <user>' to assign tasks.")
		}
		fmt.Println()
		return nil
	},
}

// Suggestion is a single AI-proposed reassignment.
type Suggestion struct {
	TaskID int    `json:"task_id"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

var (
	teamBalanceProvider string
	teamBalanceModel    string
	teamBalanceApply    bool
	teamBalanceTimeout  string
)

var teamBalanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "AI-suggested workload rebalancing",
	Long: `Ask the AI to analyse the current team workload and propose concrete task
reassignments to even out work across team members.

Use --apply to automatically accept all suggested reassignments.

Examples:
  cloop team balance
  cloop team balance --apply
  cloop team balance --provider anthropic --model claude-opus-4-6`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return err
		}

		provName := teamBalanceProvider
		if provName == "" {
			provName = cfg.Provider
		}
		model := teamBalanceModel
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

		timeout := 60 * time.Second
		if teamBalanceTimeout != "" {
			if d, parseErr := time.ParseDuration(teamBalanceTimeout); parseErr == nil {
				timeout = d
			}
		}

		prompt := team.BalancePrompt(s.Plan)

		fmt.Print("Analysing workload balance")
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var buf strings.Builder
		opts := provider.Options{
			Model: model,
			OnToken: func(tok string) {
				buf.WriteString(tok)
				fmt.Print(".")
			},
		}
		result, err := p.Complete(ctx, prompt, opts)
		fmt.Println()
		if err != nil {
			return fmt.Errorf("provider error: %w", err)
		}
		if result != nil && result.Output != "" {
			buf.Reset()
			buf.WriteString(result.Output)
		}

		raw := buf.String()

		// Extract JSON array from the response.
		start := strings.Index(raw, "[")
		end := strings.LastIndex(raw, "]")
		if start == -1 || end == -1 || end <= start {
			fmt.Println("No reassignment suggestions returned.")
			return nil
		}
		jsonPart := raw[start : end+1]

		var suggestions []Suggestion
		if jsonErr := json.Unmarshal([]byte(jsonPart), &suggestions); jsonErr != nil {
			return fmt.Errorf("parsing AI response: %w\nRaw response:\n%s", jsonErr, raw)
		}

		if len(suggestions) == 0 {
			color.New(color.FgGreen).Println("Workload is already balanced — no reassignments suggested.")
			return nil
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		headerColor.Printf("Suggested reassignments (%d):\n\n", len(suggestions))
		for i, sg := range suggestions {
			t := s.Plan.TaskByID(sg.TaskID)
			title := fmt.Sprintf("task #%d", sg.TaskID)
			if t != nil {
				title = fmt.Sprintf("task #%d (%s)", sg.TaskID, t.Title)
			}
			fromStr := sg.From
			if fromStr == "" {
				fromStr = "(unassigned)"
			}
			fmt.Printf("  %d. %s\n     %s → %s\n     Reason: %s\n\n",
				i+1, title, fromStr, sg.To, sg.Reason)
		}

		if teamBalanceApply {
			applied := 0
			for _, sg := range suggestions {
				if applyErr := team.Assign(workdir, sg.TaskID, sg.To); applyErr != nil {
					color.New(color.FgYellow).Printf("Warning: could not reassign task %d: %v\n", sg.TaskID, applyErr)
					continue
				}
				applied++
			}
			color.New(color.FgGreen).Printf("Applied %d/%d reassignments.\n", applied, len(suggestions))
		} else {
			color.New(color.Faint).Println("Run with --apply to accept all suggestions automatically.")
		}

		return nil
	},
}

// statusRowColor returns a color appropriate for a task row based on status.
func statusRowColor(status pm.TaskStatus) *color.Color {
	switch status {
	case pm.TaskDone:
		return color.New(color.FgGreen)
	case pm.TaskInProgress:
		return color.New(color.FgCyan)
	case pm.TaskFailed, pm.TaskTimedOut:
		return color.New(color.FgRed)
	case pm.TaskSkipped:
		return color.New(color.Faint)
	default:
		return color.New(color.Reset)
	}
}

func init() {
	teamBalanceCmd.Flags().StringVar(&teamBalanceProvider, "provider", "", "Provider to use for AI analysis")
	teamBalanceCmd.Flags().StringVar(&teamBalanceModel, "model", "", "Model override")
	teamBalanceCmd.Flags().BoolVar(&teamBalanceApply, "apply", false, "Automatically apply all suggested reassignments")
	teamBalanceCmd.Flags().StringVar(&teamBalanceTimeout, "timeout", "60s", "AI request timeout")

	teamCmd.AddCommand(teamAssignCmd)
	teamCmd.AddCommand(teamUnassignCmd)
	teamCmd.AddCommand(teamStatusCmd)
	teamCmd.AddCommand(teamBalanceCmd)
	rootCmd.AddCommand(teamCmd)
}
