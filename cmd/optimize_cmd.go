package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/optimizer"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	optimizeCmdProvider    string
	optimizeCmdModel       string
	optimizeCmdApply       bool
	optimizeCmdDryRun      bool
	optimizeCmdTimeout     string
)

var optimizeCmd = &cobra.Command{
	Use:   "optimize",
	Short: "AI-review the plan and suggest structural improvements",
	Long: `Optimize analyzes the current task plan using AI and suggests:

  - Reordering tasks for better dependency flow and risk management
  - Splitting overly large tasks into focused sub-tasks
  - Merging trivially small or closely related tasks
  - Flagging contradictory, redundant, or risky tasks
  - Identifying missing or incorrect task dependencies

A pre-optimization snapshot is saved to plan history before any changes.

Examples:
  cloop optimize                    # review plan, prompt to apply reordering
  cloop optimize --apply            # review and auto-apply reordering
  cloop optimize --dry-run          # show suggestions without applying anything
  cloop optimize --provider anthropic --model claude-opus-4-5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found — run 'cloop init' first: %w", err)
		}
		if s.Goal == "" {
			return fmt.Errorf("no project goal — run 'cloop init' first")
		}
		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no tasks in plan — run 'cloop run --pm --plan-only' to decompose first")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		// Resolve provider
		pName := optimizeCmdProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := optimizeCmdModel
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

		timeout := 5 * time.Minute
		if optimizeCmdTimeout != "" {
			parsed, err := time.ParseDuration(optimizeCmdTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
			timeout = parsed
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

		headerColor := color.New(color.FgCyan, color.Bold)
		pmColor := color.New(color.FgMagenta, color.Bold)
		dimColor := color.New(color.Faint)
		goodColor := color.New(color.FgGreen, color.Bold)
		warnColor := color.New(color.FgYellow)
		errColor := color.New(color.FgRed)

		headerColor.Printf("\nAI Plan Optimizer\n")
		fmt.Printf("  Provider: %s\n", prov.Name())
		fmt.Printf("  Goal: %s\n", truncate(s.Goal, 80))
		fmt.Printf("  Tasks: %d\n\n", len(s.Plan.Tasks))

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		pmColor.Printf("Analyzing plan...\n\n")

		result, err := optimizer.Optimize(ctx, prov, model, timeout, s.Plan)
		if err != nil {
			return fmt.Errorf("optimizer failed: %w", err)
		}

		sep := strings.Repeat("─", 70)
		fmt.Println(sep)
		pmColor.Printf("Summary\n")
		fmt.Printf("  %s\n", result.Summary)
		fmt.Println(sep)
		fmt.Println()

		// Print suggestions grouped by severity.
		if len(result.Suggestions) == 0 {
			dimColor.Printf("  No suggestions — plan looks good!\n\n")
		} else {
			pmColor.Printf("Suggestions (%d):\n", len(result.Suggestions))
			for i, sg := range result.Suggestions {
				icon := "i"
				switch sg.Severity {
				case optimizer.SeverityError:
					icon = "x"
				case optimizer.SeverityWarning:
					icon = "!"
				}
				ids := ""
				if len(sg.TaskIDs) > 0 {
					parts := make([]string, len(sg.TaskIDs))
					for j, id := range sg.TaskIDs {
						parts[j] = fmt.Sprintf("#%d", id)
					}
					ids = " [" + strings.Join(parts, ", ") + "]"
				}
				label := fmt.Sprintf("[%s][%s]%s %s\n", sg.Type, icon, ids, sg.Description)
				fmt.Printf("  %d. ", i+1)
				switch sg.Severity {
				case optimizer.SeverityError:
					errColor.Printf("%s", label)
				case optimizer.SeverityWarning:
					warnColor.Printf("%s", label)
				default:
					dimColor.Printf("%s", label)
				}
			}
			fmt.Println()
		}

		// Print splits.
		if len(result.Splits) > 0 {
			pmColor.Printf("Suggested Splits:\n")
			for _, sp := range result.Splits {
				// Find original task title.
				origTitle := fmt.Sprintf("Task #%d", sp.OriginalID)
				for _, t := range s.Plan.Tasks {
					if t.ID == sp.OriginalID {
						origTitle = fmt.Sprintf("#%d %s", t.ID, t.Title)
						break
					}
				}
				fmt.Printf("  %s  →\n", origTitle)
				for j, nt := range sp.NewTasks {
					fmt.Printf("      %d. %s\n", j+1, nt)
				}
			}
			fmt.Println()
		}

		// Print merges.
		if len(result.Merges) > 0 {
			pmColor.Printf("Suggested Merges:\n")
			for _, mg := range result.Merges {
				parts := make([]string, len(mg.TaskIDs))
				for i, id := range mg.TaskIDs {
					title := fmt.Sprintf("#%d", id)
					for _, t := range s.Plan.Tasks {
						if t.ID == id {
							title = fmt.Sprintf("#%d %s", t.ID, t.Title)
							break
						}
					}
					parts[i] = title
				}
				fmt.Printf("  [%s]\n  → %q\n\n", strings.Join(parts, "\n   "), mg.MergedTitle)
			}
		}

		// Print reordering.
		if len(result.ReorderedIDs) > 0 {
			pmColor.Printf("Suggested Execution Order:\n")
			idToTitle := make(map[int]string, len(s.Plan.Tasks))
			for _, t := range s.Plan.Tasks {
				idToTitle[t.ID] = t.Title
			}
			for i, id := range result.ReorderedIDs {
				fmt.Printf("  %2d. #%d %s\n", i+1, id, idToTitle[id])
			}
			fmt.Println()
		} else {
			dimColor.Printf("  No reordering suggested.\n\n")
		}

		if optimizeCmdDryRun || len(result.ReorderedIDs) == 0 {
			if optimizeCmdDryRun {
				dimColor.Printf("(dry-run) No changes applied.\n\n")
			}
			return nil
		}

		// Determine whether to apply reordering.
		applyReorder := optimizeCmdApply
		if !applyReorder {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Apply suggested reordering to the plan? [y/N] ")
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(strings.ToLower(line))
			applyReorder = line == "y" || line == "yes"
		}

		if !applyReorder {
			dimColor.Printf("Reordering not applied.\n\n")
			return nil
		}

		// Save pre-optimization snapshot.
		if snapErr := pm.SaveSnapshot(workdir, s.Plan); snapErr != nil {
			warnColor.Printf("warning: could not save pre-optimization snapshot: %v\n", snapErr)
		}

		optimizer.ApplyReorder(s.Plan, result.ReorderedIDs)

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving plan: %w", err)
		}

		goodColor.Printf("Plan reordered successfully. Updated task list:\n\n")
		for _, t := range s.Plan.Tasks {
			fmt.Printf("  [P%d] #%d %s\n", t.Priority, t.ID, t.Title)
		}
		fmt.Println()
		dimColor.Printf("  Run 'cloop run --pm' to execute the optimized plan.\n\n")

		return nil
	},
}

func init() {
	optimizeCmd.Flags().StringVar(&optimizeCmdProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	optimizeCmd.Flags().StringVar(&optimizeCmdModel, "model", "", "Model to use")
	optimizeCmd.Flags().BoolVar(&optimizeCmdApply, "apply", false, "Automatically apply suggested reordering without prompting")
	optimizeCmd.Flags().BoolVar(&optimizeCmdDryRun, "dry-run", false, "Show suggestions without applying any changes")
	optimizeCmd.Flags().StringVar(&optimizeCmdTimeout, "timeout", "5m", "Timeout for the optimizer AI call")
	rootCmd.AddCommand(optimizeCmd)
}
