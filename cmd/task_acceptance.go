package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/acceptance"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	acProvider string
	acModel    string
	acTimeout  string
	acFormat   string
	acApply    bool
)

var taskAICriteriaCmd = &cobra.Command{
	Use:   "ai-acceptance-criteria <task-id>",
	Short: "Generate formal acceptance criteria (Gherkin or checklist) for a task",
	Long: `Generate AI-powered formal acceptance criteria for a task.

Two output formats are supported:

  gherkin    BDD-style Feature/Scenario/Given/When/Then (default)
  checklist  Numbered pass/fail items

The command reads the task title, description, and any existing output artifact,
then prompts the AI to produce verifiable done criteria.

With --apply the criteria are:
  1. Persisted as an annotation on the task (visible in 'cloop task show <id>').
  2. Written to .cloop/acceptance/<task-id>.md for external review.

Examples:
  cloop task ai-acceptance-criteria 3
  cloop task ai-acceptance-criteria 3 --format checklist
  cloop task ai-acceptance-criteria 3 --apply
  cloop task ai-acceptance-criteria 3 --format gherkin --apply --provider anthropic`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Resolve task ID.
		var taskID int
		if _, scanErr := fmt.Sscanf(args[0], "%d", &taskID); scanErr != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}
		var task *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == taskID {
				task = t
				break
			}
		}
		if task == nil {
			return fmt.Errorf("task %d not found", taskID)
		}

		// Validate format.
		format := acceptance.Format(acFormat)
		if format != acceptance.FormatGherkin && format != acceptance.FormatChecklist {
			return fmt.Errorf("unknown format %q: must be 'gherkin' or 'checklist'", acFormat)
		}

		// Build provider.
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := acProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := acModel
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
		if acTimeout != "" {
			timeout, err = time.ParseDuration(acTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		// Read artifact output (may be empty).
		artifactOutput := acceptance.ReadArtifactOutput(workdir, task)

		dimColor := color.New(color.Faint)
		headerColor := color.New(color.FgCyan, color.Bold)
		successColor := color.New(color.FgGreen)
		labelColor := color.New(color.FgYellow)

		headerColor.Printf("Generating %s acceptance criteria for task #%d: %s\n\n", format, task.ID, task.Title)
		if artifactOutput != "" {
			dimColor.Printf("  Found existing task artifact (%d chars)\n", len(artifactOutput))
		}
		dimColor.Printf("  Calling AI (%s)...\n\n", pName)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		result, genErr := acceptance.Generate(ctx, prov, opts, task, format, artifactOutput)
		cancel()

		if genErr != nil {
			return fmt.Errorf("generating acceptance criteria: %w", genErr)
		}

		// Print criteria.
		labelColor.Printf("--- Acceptance Criteria (%s) ---\n\n", result.Format)
		fmt.Println(result.Criteria)
		fmt.Println()

		if acApply {
			dimColor.Printf("Applying criteria to task #%d...\n", task.ID)
			relPath, applyErr := acceptance.Apply(workdir, s, task, result)
			if applyErr != nil {
				return fmt.Errorf("applying acceptance criteria: %w", applyErr)
			}
			successColor.Printf("Saved annotation on task #%d\n", task.ID)
			successColor.Printf("Written to: %s\n", relPath)
		} else {
			dimColor.Printf("Tip: use --apply to persist criteria as a task annotation and save to .cloop/acceptance/\n")
		}

		return nil
	},
}

func init() {
	taskAICriteriaCmd.Flags().StringVar(&acProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	taskAICriteriaCmd.Flags().StringVar(&acModel, "model", "", "Model override for the AI provider")
	taskAICriteriaCmd.Flags().StringVar(&acTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 2m, 90s)")
	taskAICriteriaCmd.Flags().StringVar(&acFormat, "format", "gherkin", "Output format: gherkin or checklist")
	taskAICriteriaCmd.Flags().BoolVar(&acApply, "apply", false, "Persist criteria as task annotation and write .cloop/acceptance/<id>.md")
	taskCmd.AddCommand(taskAICriteriaCmd)
}
