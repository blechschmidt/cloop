package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskadd"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	addDesc      string
	addPriority  int
	addDeps      string
	addRole      string
	addNoAI      bool
	addAuto      bool
	addProvider  string
	addModel     string
	addTimeout   string
)

var taskAddCmd = &cobra.Command{
	Use:   "add <description>",
	Short: "Add a new task using AI to structure the description",
	Long: `Add a new task to the plan. By default, the configured AI provider
structures the free-form description into a proper task with title,
description, priority, estimated duration, tags, and suggested dependencies.

The proposed task is previewed and you are prompted for confirmation before
it is appended to the plan. Use --auto to skip confirmation, or --no-ai to
bypass the AI step and add the description as the title directly.

Examples:
  cloop task add "we need to refactor the auth module to use JWT tokens"
  cloop task add "set up CI pipeline with GitHub Actions" --auto
  cloop task add "add unit tests for the payment service" --provider anthropic
  cloop task add "write release notes" --no-ai --priority 5`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		description := strings.Join(args, " ")

		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode {
			return fmt.Errorf("not in PM mode — run 'cloop init --pm' or 'cloop run --pm' first")
		}
		if s.Plan == nil {
			s.Plan = pm.NewPlan(s.Goal)
		}

		// --no-ai: simple add without AI structuring (legacy behavior)
		if addNoAI {
			return addTaskDirect(s, description)
		}

		// Build provider
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := addProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := addModel
		if model == "" {
			switch pName {
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
		if model == "" {
			model = s.Model
		}

		provCfg := provider.ProviderConfig{
			Name:             pName,
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

		timeout := 3 * time.Minute
		if addTimeout != "" {
			timeout, err = time.ParseDuration(addTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("Structuring task with AI...\n\n")

		spec, err := taskadd.Enrich(ctx, prov, opts, description, s.Plan)
		if err != nil {
			return fmt.Errorf("AI structuring failed: %w\n\nUse --no-ai to add without AI structuring.", err)
		}

		// Preview
		fmt.Printf("Proposed task:\n\n")
		warnColor.Printf("  Title:     %s\n", spec.Title)
		fmt.Printf("  Priority:  %d\n", spec.Priority)
		if spec.Role != "" {
			fmt.Printf("  Role:      %s\n", spec.Role)
		}
		if spec.EstimatedMinutes > 0 {
			fmt.Printf("  Estimate:  %d min\n", spec.EstimatedMinutes)
		}
		if len(spec.Tags) > 0 {
			fmt.Printf("  Tags:      %s\n", strings.Join(spec.Tags, ", "))
		}
		if len(spec.SuggestedDependsOn) > 0 {
			deps := make([]string, 0, len(spec.SuggestedDependsOn))
			for _, id := range spec.SuggestedDependsOn {
				deps = append(deps, fmt.Sprintf("#%d", id))
			}
			fmt.Printf("  Depends:   %s\n", strings.Join(deps, ", "))
		}
		if spec.Description != "" {
			fmt.Printf("  Desc:      ")
			dimColor.Printf("%s\n", spec.Description)
		}
		if spec.Rationale != "" {
			fmt.Printf("\n  Rationale: ")
			dimColor.Printf("%s\n", spec.Rationale)
		}
		fmt.Println()

		if !addAuto {
			fmt.Printf("Add this task? (y/N): ")
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return fmt.Errorf("no input received")
			}
			answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if answer != "y" && answer != "yes" {
				fmt.Println("Cancelled.")
				return nil
			}
		}

		// Determine ID
		maxID := 0
		for _, t := range s.Plan.Tasks {
			if t.ID > maxID {
				maxID = t.ID
			}
		}

		// Priority override from flag
		priority := spec.Priority
		if cmd.Flags().Changed("priority") {
			priority = addPriority
		}

		// Validate suggested dependencies exist in the plan
		deps := spec.SuggestedDependsOn
		if cmd.Flags().Changed("depends-on") {
			deps, err = parseDeps(addDeps)
			if err != nil {
				return err
			}
		} else {
			// Filter out any suggested dep IDs that don't exist in the plan
			planIDs := make(map[int]bool, len(s.Plan.Tasks))
			for _, t := range s.Plan.Tasks {
				planIDs[t.ID] = true
			}
			valid := deps[:0:0]
			for _, id := range deps {
				if planIDs[id] {
					valid = append(valid, id)
				}
			}
			deps = valid
		}

		role := pm.AgentRole(spec.Role)
		if cmd.Flags().Changed("role") {
			role = pm.AgentRole(addRole)
		}

		task := &pm.Task{
			ID:               maxID + 1,
			Title:            spec.Title,
			Description:      spec.Description,
			Priority:         priority,
			Role:             role,
			DependsOn:        deps,
			Tags:             spec.Tags,
			EstimatedMinutes: spec.EstimatedMinutes,
			Status:           pm.TaskPending,
		}
		s.Plan.Tasks = append(s.Plan.Tasks, task)

		if err := s.Save(); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("Added task %d: %s (priority %d)\n", task.ID, task.Title, task.Priority)
		return nil
	},
}

// addTaskDirect adds a task directly without AI, using the description as the title.
// This preserves backward-compatible behavior when --no-ai is specified.
func addTaskDirect(s *state.ProjectState, description string) error {
	maxID := 0
	for _, t := range s.Plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	priority := addPriority
	if priority == 0 {
		maxPriority := 0
		for _, t := range s.Plan.Tasks {
			if t.Priority > maxPriority {
				maxPriority = t.Priority
			}
		}
		priority = maxPriority + 1
	}

	deps, err := parseDeps(addDeps)
	if err != nil {
		return err
	}

	task := &pm.Task{
		ID:          maxID + 1,
		Title:       description,
		Description: addDesc,
		Priority:    priority,
		Role:        pm.AgentRole(addRole),
		DependsOn:   deps,
		Status:      pm.TaskPending,
	}
	s.Plan.Tasks = append(s.Plan.Tasks, task)

	if err := s.Save(); err != nil {
		return err
	}

	msg := fmt.Sprintf("Added task %d: %s (priority %d)", task.ID, task.Title, task.Priority)
	if task.Role != "" {
		msg += fmt.Sprintf(", role: %s", task.Role)
	}
	color.New(color.FgGreen).Println(msg)
	return nil
}

func init() {
	taskAddCmd.Flags().StringVar(&addDesc, "desc", "", "Task description (used with --no-ai)")
	taskAddCmd.Flags().IntVar(&addPriority, "priority", 0, "Override AI-suggested priority (1=highest)")
	taskAddCmd.Flags().StringVar(&addDeps, "depends-on", "", "Override dependency IDs (comma-separated, e.g. '1,2')")
	taskAddCmd.Flags().StringVar(&addRole, "role", "", "Override AI-suggested role (backend, frontend, testing, security, devops, data, docs, review)")
	taskAddCmd.Flags().BoolVar(&addNoAI, "no-ai", false, "Skip AI structuring; use description as task title directly")
	taskAddCmd.Flags().BoolVar(&addAuto, "auto", false, "Skip confirmation prompt and add immediately")
	taskAddCmd.Flags().StringVar(&addProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskAddCmd.Flags().StringVar(&addModel, "model", "", "Model override for the AI provider")
	taskAddCmd.Flags().StringVar(&addTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 2m, 300s)")

	taskCmd.AddCommand(taskAddCmd)
}
