package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/planedit"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	planEditYes      bool
	planEditProvider string
	planEditModel    string
	planEditTimeout  string
)

var planEditCmd = &cobra.Command{
	Use:   "edit <instruction>",
	Short: "AI-powered natural-language plan mutation",
	Long: `Apply a natural-language instruction to mutate the current task plan.

The AI reads the full plan, applies your instruction, and returns a modified
plan. A colored diff is shown before you are asked to confirm.

Examples:
  cloop plan edit "make task 3 depend on task 2"
  cloop plan edit "increase priority of all backend tasks to P1"
  cloop plan edit "add a code review task after each implementation task"
  cloop plan edit "remove all skipped tasks"
  cloop plan edit "assign all frontend tasks to alice"
  cloop plan edit "split the database migration task into separate up/down steps"
  cloop plan edit "rename task 5 to 'Integrate payment gateway'" --yes`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		instruction := strings.Join(args, " ")
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
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := planEditProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := planEditModel
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
		if planEditTimeout != "" {
			timeout, err = time.ParseDuration(planEditTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		dimColor := color.New(color.Faint)
		headerColor := color.New(color.FgCyan, color.Bold)

		headerColor.Printf("Plan Edit\n")
		fmt.Println(strings.Repeat("─", 72))
		dimColor.Printf("Instruction: %s\n\n", instruction)
		dimColor.Printf("Calling AI (provider: %s)...\n\n", prov.Name())

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		result, err := planedit.EditPlan(ctx, prov, opts, s.Plan, instruction)
		if err != nil {
			return fmt.Errorf("plan edit failed: %w", err)
		}

		// Compute and print diff.
		diff := pm.DiffPlans(s.Plan, result.ModifiedPlan)
		if diff.IsEmpty() && len(result.RemovedTasks) == 0 {
			dimColor.Println("No changes produced by the AI for that instruction.")
			return nil
		}

		printEditDiff(s.Plan, result)

		// Safety check: if the AI proposes removals and --yes was passed,
		// still require explicit confirmation for deletions.
		hasRemovals := len(result.RemovedTasks) > 0

		if !planEditYes || hasRemovals {
			prompt := "Apply these changes? (y/N): "
			if hasRemovals {
				warnColor := color.New(color.FgYellow, color.Bold)
				warnColor.Printf("\nWarning: %d task(s) will be removed. ", len(result.RemovedTasks))
			}
			fmt.Printf("\n%s", prompt)

			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return fmt.Errorf("no input received")
			}
			answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if answer != "y" && answer != "yes" {
				fmt.Println("Edit cancelled.")
				return nil
			}
		}

		s.Plan = result.ModifiedPlan
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		successColor := color.New(color.FgGreen, color.Bold)
		total := len(diff.Added) + len(diff.Removed) + len(diff.Changed) + len(result.RemovedTasks)
		successColor.Printf("\nPlan updated (%d change(s) applied).\n", total)
		return nil
	},
}

// printEditDiff displays a colored field-by-field diff between the original
// and modified plans.
func printEditDiff(original *pm.Plan, result *planedit.EditResult) {
	addColor := color.New(color.FgGreen)
	removeColor := color.New(color.FgRed)
	changeColor := color.New(color.FgYellow)
	dimColor := color.New(color.Faint)

	diff := pm.DiffPlans(original, result.ModifiedPlan)

	// Added tasks.
	if len(diff.Added) > 0 {
		addColor.Printf("+ Added (%d task(s)):\n", len(diff.Added))
		for _, t := range diff.Added {
			rolePart := ""
			if t.Role != "" {
				rolePart = fmt.Sprintf(" [%s]", t.Role)
			}
			addColor.Printf("  + #%d [P%d]%s %s\n", t.ID, t.Priority, rolePart, t.Title)
			if t.Description != "" {
				dimColor.Printf("       %s\n", truncateStr(t.Description, 100))
			}
		}
		fmt.Println()
	}

	// Removed tasks (AI-driven removal, tracked in RemovedTasks).
	if len(result.RemovedTasks) > 0 {
		removeColor.Printf("- Removed (%d task(s)):\n", len(result.RemovedTasks))
		for _, t := range result.RemovedTasks {
			removeColor.Printf("  - #%d %s\n", t.ID, t.Title)
		}
		fmt.Println()
	}

	// Changed tasks.
	if len(diff.Changed) > 0 {
		changeColor.Printf("~ Changed (%d task(s)):\n", len(diff.Changed))
		for _, td := range diff.Changed {
			changeColor.Printf("  ~ #%d %s\n", td.ID, td.Title)
			for _, fc := range td.Changes {
				dimColor.Printf("       %s: ", fc.Field)
				removeColor.Printf("%s", fc.OldValue)
				fmt.Printf(" → ")
				addColor.Printf("%s\n", fc.NewValue)
			}
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("─", 72))
	fmt.Printf("Summary: ")
	if len(diff.Added) > 0 {
		addColor.Printf("+%d added  ", len(diff.Added))
	}
	if len(result.RemovedTasks) > 0 {
		removeColor.Printf("-%d removed  ", len(result.RemovedTasks))
	}
	if len(diff.Changed) > 0 {
		changeColor.Printf("~%d changed  ", len(diff.Changed))
	}
	total := len(diff.Added) + len(result.RemovedTasks) + len(diff.Changed)
	dimColor.Printf("(%d total change(s))\n", total)
}

func init() {
	planEditCmd.Flags().BoolVar(&planEditYes, "yes", false, "Skip confirmation prompt (task removals still require confirmation)")
	planEditCmd.Flags().StringVar(&planEditProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	planEditCmd.Flags().StringVar(&planEditModel, "model", "", "Model override for the AI provider")
	planEditCmd.Flags().StringVar(&planEditTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 2m, 300s)")
}
