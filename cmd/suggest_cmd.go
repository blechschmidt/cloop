package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/suggest"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	suggestProvider string
	suggestModel    string
	suggestCount    int
	suggestYes      bool
	suggestDryRun   bool
)

var suggestCmd = &cobra.Command{
	Use:   "suggest",
	Short: "AI brainstorms feature ideas; accept/reject interactively to add as tasks",
	Long: `Suggest generates N AI-brainstormed feature ideas tailored to your project.
Each idea is presented interactively — accept it to add it as a PM task,
or reject it to skip.

The AI considers your project goal, codebase structure, recent activity,
and existing tasks to generate relevant, non-duplicate suggestions.

Examples:
  cloop suggest                          # brainstorm 5 ideas (default)
  cloop suggest --count 10               # brainstorm 10 ideas
  cloop suggest --yes                    # auto-accept all suggestions
  cloop suggest --dry-run                # show suggestions without prompting
  cloop suggest --provider anthropic     # use a specific provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found — run 'cloop init' first: %w", err)
		}
		if s.Goal == "" {
			return fmt.Errorf("no project goal — run 'cloop init' first")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		// Resolve provider
		pName := suggestProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := suggestModel
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

		// Build context
		projCtx := pm.BuildProjectContext(workdir)

		mem, _ := memory.Load(workdir)
		memStr := ""
		if mem != nil {
			memStr = mem.FormatForPrompt(10)
		}

		// Summarize existing tasks to avoid duplicates
		existingTasks := ""
		if s.Plan != nil && len(s.Plan.Tasks) > 0 {
			var tb strings.Builder
			for _, t := range s.Plan.Tasks {
				tb.WriteString(fmt.Sprintf("- [%s] Task %d: %s\n", t.Status, t.ID, t.Title))
			}
			existingTasks = tb.String()
		}

		prompt := suggest.BuildPrompt(
			s.Goal,
			s.Instructions,
			projCtx.FileTree,
			projCtx.RecentLog,
			memStr,
			existingTasks,
			suggestCount,
		)

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		boldColor := color.New(color.Bold)
		goodColor := color.New(color.FgGreen, color.Bold)
		warnColor := color.New(color.FgYellow)
		labelColor := color.New(color.FgMagenta)

		headerColor.Printf("\nBrainstorming %d feature ideas with %s...\n\n", suggestCount, prov.Name())
		dimColor.Printf("Goal: %s\n\n", truncate(s.Goal, 80))

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		result, err := suggest.Generate(ctx, prov, prompt, model, 3*time.Minute)
		if err != nil {
			return fmt.Errorf("suggestion generation failed: %w", err)
		}

		if len(result.Suggestions) == 0 {
			warnColor.Printf("  No suggestions returned. Try again or adjust your goal.\n\n")
			return nil
		}

		sep := strings.Repeat("─", 70)
		fmt.Println(sep)
		headerColor.Printf("  %d Feature Ideas\n", len(result.Suggestions))
		if result.Summary != "" {
			dimColor.Printf("  %s\n", result.Summary)
		}
		fmt.Println(sep)
		fmt.Println()

		if suggestDryRun {
			// Show all suggestions without prompting
			for i, sg := range result.Suggestions {
				printSuggestion(i+1, sg, boldColor, dimColor, labelColor)
			}
			dimColor.Printf("  (dry-run) Run without --dry-run to accept/reject interactively.\n\n")
			return nil
		}

		// Interactive accept/reject loop
		reader := bufio.NewReader(os.Stdin)
		accepted := []*suggest.Suggestion{}

		for i, sg := range result.Suggestions {
			printSuggestion(i+1, sg, boldColor, dimColor, labelColor)

			if suggestYes {
				goodColor.Printf("  → Accepted (--yes)\n\n")
				accepted = append(accepted, sg)
				continue
			}

			// Prompt user
			for {
				fmt.Printf("  Accept this idea? [y/n/q] ")
				line, err := reader.ReadString('\n')
				if err != nil {
					// stdin closed (non-interactive); skip remaining
					break
				}
				line = strings.TrimSpace(strings.ToLower(line))
				switch line {
				case "y", "yes":
					goodColor.Printf("  → Accepted\n\n")
					accepted = append(accepted, sg)
					goto next
				case "n", "no":
					dimColor.Printf("  → Skipped\n\n")
					goto next
				case "q", "quit":
					warnColor.Printf("  → Aborted. %d idea(s) accepted so far.\n\n", len(accepted))
					goto done
				default:
					fmt.Printf("  Please enter y (yes), n (no), or q (quit).\n")
				}
			}
		next:
		}

	done:
		if len(accepted) == 0 {
			dimColor.Printf("  No ideas accepted — nothing added to plan.\n\n")
			return nil
		}

		// Inject accepted suggestions as PM tasks
		if !s.PMMode {
			s.PMMode = true
		}
		if s.Plan == nil {
			s.Plan = pm.NewPlan(s.Goal)
		}

		maxID := 0
		for _, t := range s.Plan.Tasks {
			if t.ID > maxID {
				maxID = t.ID
			}
		}

		for _, sg := range accepted {
			maxID++
			role := suggestCategoryToRole(sg.Category)
			task := &pm.Task{
				ID:          maxID,
				Title:       sg.Title,
				Description: sg.Description,
				Priority:    suggestEffortToPriority(sg.Effort),
				Status:      pm.TaskPending,
				Role:        role,
			}
			s.Plan.Tasks = append(s.Plan.Tasks, task)
		}

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		fmt.Println(sep)
		goodColor.Printf("  Added %d idea(s) as PM tasks. Run 'cloop run --pm' to execute them.\n\n", len(accepted))

		// Show what was added
		for _, sg := range accepted {
			dimColor.Printf("  + [%s] %s\n", suggest.EffortLabel(sg.Effort), sg.Title)
		}
		fmt.Println()

		return nil
	},
}

// printSuggestion renders a single suggestion in terminal format.
func printSuggestion(n int, sg *suggest.Suggestion, boldColor, dimColor, labelColor *color.Color) {
	boldColor.Printf("  %d. %s", n, sg.Title)
	labelColor.Printf("  [%s | %s]\n", suggest.CategoryLabel(sg.Category), suggest.EffortLabel(sg.Effort))
	if sg.Description != "" {
		fmt.Printf("     What: %s\n", sg.Description)
	}
	if sg.Rationale != "" {
		dimColor.Printf("     Why:  %s\n", sg.Rationale)
	}
	fmt.Println()
}

// suggestCategoryToRole maps a suggestion category to the best PM agent role.
func suggestCategoryToRole(c suggest.Category) pm.AgentRole {
	switch c {
	case suggest.CategoryFeature:
		return pm.RoleBackend
	case suggest.CategoryUX:
		return pm.RoleFrontend
	case suggest.CategoryPerformance:
		return pm.RoleBackend
	case suggest.CategorySecurity:
		return pm.RoleSecurity
	case suggest.CategoryDX:
		return pm.RoleDevOps
	case suggest.CategoryIntegration:
		return pm.RoleBackend
	case suggest.CategoryDocs:
		return pm.RoleDocs
	default:
		return ""
	}
}

// suggestEffortToPriority converts effort to a PM task priority (1=highest).
// Smaller efforts get slightly higher priority to keep things moving.
func suggestEffortToPriority(e suggest.Effort) int {
	switch e {
	case suggest.EffortXS, suggest.EffortS:
		return 3
	case suggest.EffortM:
		return 4
	case suggest.EffortL, suggest.EffortXL:
		return 5
	default:
		return 4
	}
}

func init() {
	suggestCmd.Flags().StringVar(&suggestProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	suggestCmd.Flags().StringVar(&suggestModel, "model", "", "Model to use")
	suggestCmd.Flags().IntVar(&suggestCount, "count", 5, "Number of feature ideas to generate")
	suggestCmd.Flags().BoolVar(&suggestYes, "yes", false, "Auto-accept all suggestions")
	suggestCmd.Flags().BoolVar(&suggestDryRun, "dry-run", false, "Show suggestions without prompting or adding tasks")
	rootCmd.AddCommand(suggestCmd)
}
