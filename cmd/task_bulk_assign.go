package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/teamassign"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	bulkAssignDryRun   bool
	bulkAssignMember   string
	bulkAssignProvider string
	bulkAssignModel    string
	bulkAssignTimeout  string
)

var taskBulkAssignCmd = &cobra.Command{
	Use:   "bulk-assign",
	Short: "AI-powered automatic task assignment based on skill match",
	Long: `Automatically assign unassigned tasks to team members using AI skill matching.

The AI analyses each unassigned task's title, description, role, and tags against
each team member's inferred skills (derived from their completed task history) and
current workload, then produces a ranked assignment with reasoning.

Overdue tasks are always assigned to the least-loaded available member.

Team members are discovered from existing task assignments in the plan.
Use --member to restrict assignments to a single person (or to introduce a new
member who hasn't been assigned tasks yet).

Examples:
  cloop task bulk-assign
  cloop task bulk-assign --dry-run
  cloop task bulk-assign --member alice
  cloop task bulk-assign --provider anthropic --model claude-opus-4-6`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Collect unassigned pending/in-progress tasks.
		var targets []*pm.Task
		for _, t := range s.Plan.Tasks {
			if t.Assignee != "" {
				continue // already assigned
			}
			if t.Status != pm.TaskPending && t.Status != pm.TaskInProgress {
				continue // completed/failed — skip
			}
			targets = append(targets, t)
		}

		if len(targets) == 0 {
			color.New(color.FgGreen).Println("All tasks are already assigned.")
			return nil
		}

		// Build member list.
		members := teamassign.MembersWithSkills(s.Plan, bulkAssignMember)
		if len(members) == 0 {
			return fmt.Errorf("no team members found — assign at least one task manually with 'cloop team assign' or use --member <name>")
		}

		// Load provider.
		cfg, err := config.Load(workdir)
		if err != nil {
			return err
		}
		provName := bulkAssignProvider
		if provName == "" {
			provName = cfg.Provider
		}
		model := bulkAssignModel
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

		timeout := 90 * time.Second
		if bulkAssignTimeout != "" {
			if d, parseErr := time.ParseDuration(bulkAssignTimeout); parseErr == nil {
				timeout = d
			}
		}

		fmt.Printf("Analysing %d unassigned task(s) for %d member(s)", len(targets), len(members))
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Overdue tasks get special treatment — assign to least-loaded member
		// immediately, bypass AI for them.
		workloadCounts := teamassign.WorkloadCount(s.Plan)
		var overdueResults []teamassign.AssignmentResult
		var aiTargets []*pm.Task

		for _, t := range targets {
			if pm.IsOverdue(t) {
				assignee := teamassign.LeastLoadedMember(members, workloadCounts)
				workloadCounts[assignee]++ // update in-memory count
				overdueResults = append(overdueResults, teamassign.AssignmentResult{
					TaskID:    t.ID,
					Assignee:  assignee,
					Reasoning: fmt.Sprintf("Task is OVERDUE — assigned to least-loaded member (%s)", assignee),
				})
			} else {
				aiTargets = append(aiTargets, t)
			}
		}

		var aiResults []teamassign.AssignmentResult
		if len(aiTargets) > 0 {
			fmt.Print(".")
			var runErr error
			aiResults, runErr = teamassign.Run(ctx, p, model, aiTargets, members)
			if runErr != nil {
				fmt.Println()
				return fmt.Errorf("AI assignment failed: %w", runErr)
			}
		}
		fmt.Println()

		allResults := append(overdueResults, aiResults...)
		if len(allResults) == 0 {
			color.New(color.FgYellow).Println("AI returned no assignments.")
			return nil
		}

		// Print results table.
		headerColor := color.New(color.FgCyan, color.Bold)
		headerColor.Printf("\nBulk Assignment Results (%d task(s)):\n\n", len(allResults))

		// Column widths.
		const taskW, assigneeW = 50, 20
		fmt.Printf("  %-5s  %-*s  %-*s  %s\n",
			"ID", taskW, "TASK", assigneeW, "ASSIGNED TO", "REASONING")
		fmt.Printf("  %-5s  %-*s  %-*s  %s\n",
			"-----",
			taskW, strings.Repeat("-", taskW),
			assigneeW, strings.Repeat("-", assigneeW),
			strings.Repeat("-", 40))

		for _, r := range allResults {
			t := s.Plan.TaskByID(r.TaskID)
			title := fmt.Sprintf("#%d", r.TaskID)
			if t != nil {
				title = fmt.Sprintf("#%d %s", t.ID, truncateStr(t.Title, taskW-4))
			}
			reasoning := truncateStr(r.Reasoning, 60)
			assigneeStr := r.Assignee
			if pm.IsOverdue(t) {
				assigneeStr = color.New(color.FgYellow).Sprintf("%s [OVERDUE]", r.Assignee)
			}
			fmt.Printf("  %-5d  %-*s  %-*s  %s\n",
				r.TaskID, taskW, title, assigneeW, assigneeStr, reasoning)
		}
		fmt.Println()

		if bulkAssignDryRun {
			color.New(color.Faint).Println("Dry run — no changes saved. Remove --dry-run to apply.")
			return nil
		}

		applied := teamassign.ApplyAssignments(s.Plan, allResults)
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		color.New(color.FgGreen).Printf("Assigned %d task(s) successfully.\n", applied)
		return nil
	},
}

func init() {
	taskBulkAssignCmd.Flags().BoolVar(&bulkAssignDryRun, "dry-run", false, "Show assignments without saving them")
	taskBulkAssignCmd.Flags().StringVar(&bulkAssignMember, "member", "", "Only assign tasks to this specific team member")
	taskBulkAssignCmd.Flags().StringVar(&bulkAssignProvider, "provider", "", "Provider to use for AI analysis")
	taskBulkAssignCmd.Flags().StringVar(&bulkAssignModel, "model", "", "Model override")
	taskBulkAssignCmd.Flags().StringVar(&bulkAssignTimeout, "timeout", "90s", "AI request timeout")

	taskCmd.AddCommand(taskBulkAssignCmd)
}
