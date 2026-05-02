package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/linter"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	lintFix      bool
	lintTaskID   int
	lintSkipAI   bool
	lintProvider string
	lintModel    string
	lintTimeout  string
)

var lintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Analyze task plan quality (static + AI checks)",
	Long: `Perform static and AI-based quality analysis on the current task plan.

Static checks (no AI required):
  • duplicate-title              Two tasks share the same title
  • missing-description          Description shorter than 20 characters
  • zero-priority                Task has priority 0 (unset)
  • circular-dependency          Dependency graph has a cycle
  • title-matches-done-task      Pending task title duplicates a completed task

AI checks (single batched provider call):
  • vague-verb                   Title uses vague verbs with no specifics
  • missing-acceptance-criteria  Description lacks measurable success conditions
  • unrealistic-scope            Task spans too many subsystems for a single unit

Exit code 1 when any ERROR-level issues are found (enables CI gating).

Examples:
  cloop lint                     # check all tasks
  cloop lint --task 5            # check only task #5
  cloop lint --skip-ai           # static checks only, no provider call
  cloop lint --fix               # auto-rewrite titles/descriptions via AI
  cloop lint --provider anthropic --model claude-opus-4-6`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm --plan-only' to create one")
		}

		// Build provider
		var prov provider.Provider
		if !lintSkipAI {
			cfg, err := config.Load(workdir)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			applyEnvOverrides(cfg)

			pName := lintProvider
			if pName == "" {
				pName = cfg.Provider
			}
			if pName == "" && s.Provider != "" {
				pName = s.Provider
			}
			if pName == "" {
				pName = autoSelectProvider()
			}

			if lintModel == "" {
				switch pName {
				case "anthropic":
					lintModel = cfg.Anthropic.Model
				case "openai":
					lintModel = cfg.OpenAI.Model
				case "ollama":
					lintModel = cfg.Ollama.Model
				case "claudecode":
					lintModel = cfg.ClaudeCode.Model
				}
			}
			if lintModel == "" {
				lintModel = s.Model
			}

			provCfg := provider.ProviderConfig{
				Name:             pName,
				AnthropicAPIKey:  cfg.Anthropic.APIKey,
				AnthropicBaseURL: cfg.Anthropic.BaseURL,
				OpenAIAPIKey:     cfg.OpenAI.APIKey,
				OpenAIBaseURL:    cfg.OpenAI.BaseURL,
				OllamaBaseURL:    cfg.Ollama.BaseURL,
			}
			prov, err = provider.Build(provCfg)
			if err != nil {
				return fmt.Errorf("provider: %w", err)
			}
		}

		timeout := 2 * time.Minute
		if lintTimeout != "" {
			timeout, err = time.ParseDuration(lintTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Print header
		headerColor := color.New(color.FgCyan, color.Bold)
		headerColor.Printf("\ncloop lint — task plan quality analyzer\n")
		if lintTaskID != 0 {
			fmt.Printf("  Scope: task #%d\n", lintTaskID)
		} else {
			fmt.Printf("  Scope: all %d tasks\n", len(s.Plan.Tasks))
		}
		if lintSkipAI || prov == nil {
			fmt.Printf("  AI checks: disabled\n")
		} else {
			fmt.Printf("  Provider: %s\n", prov.Name())
		}
		fmt.Println()

		opts := linter.Options{
			TaskID:   lintTaskID,
			SkipAI:   lintSkipAI || prov == nil,
			Provider: prov,
			Model:    lintModel,
		}

		issues, err := linter.Lint(ctx, s.Plan, opts)
		if err != nil {
			return err
		}

		if len(issues) == 0 {
			color.New(color.FgGreen).Printf("No issues found. Plan looks good!\n\n")
			return nil
		}

		printLintTable(issues)

		// Apply fixes if --fix requested
		if lintFix && prov != nil {
			fmt.Printf("\nGenerating AI fixes...\n")
			fixes, err := linter.GenerateFixes(ctx, prov, lintModel, s.Plan, issues)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not generate fixes: %v\n", err)
			} else if len(fixes) > 0 {
				changed := linter.ApplyFixes(s.Plan, fixes)
				if changed > 0 {
					if err := s.Save(); err != nil {
						return fmt.Errorf("saving state: %w", err)
					}
					color.New(color.FgGreen).Printf("\nApplied %d fix(es) to plan. Run 'cloop lint' again to verify.\n\n", changed)
				}
			} else {
				fmt.Printf("No fixable issues found.\n\n")
			}
		}

		// Exit 1 if any ERROR-level issues
		hasErrors := false
		for _, i := range issues {
			if i.Severity == linter.SeverityError {
				hasErrors = true
				break
			}
		}
		if hasErrors {
			os.Exit(1)
		}
		return nil
	},
}

// printLintTable renders issues grouped by severity with a summary footer.
func printLintTable(issues []linter.Issue) {
	sep := strings.Repeat("─", 72)

	errorColor := color.New(color.FgRed, color.Bold)
	warnColor := color.New(color.FgYellow, color.Bold)
	infoColor := color.New(color.FgCyan)
	dimColor := color.New(color.Faint)

	counts := map[linter.Severity]int{}
	for _, i := range issues {
		counts[i.Severity]++
	}

	for _, sev := range []linter.Severity{linter.SeverityError, linter.SeverityWarn, linter.SeverityInfo} {
		var group []linter.Issue
		for _, i := range issues {
			if i.Severity == sev {
				group = append(group, i)
			}
		}
		if len(group) == 0 {
			continue
		}

		fmt.Println(sep)
		switch sev {
		case linter.SeverityError:
			errorColor.Printf("  ERROR  (%d issue(s))\n", len(group))
		case linter.SeverityWarn:
			warnColor.Printf("  WARN   (%d issue(s))\n", len(group))
		case linter.SeverityInfo:
			infoColor.Printf("  INFO   (%d issue(s))\n", len(group))
		}
		fmt.Println(sep)

		for _, issue := range group {
			taskRef := ""
			if issue.TaskID != 0 {
				taskRef = fmt.Sprintf(" [task #%s]", strconv.Itoa(issue.TaskID))
			}
			fieldRef := ""
			if issue.Field != "" {
				fieldRef = fmt.Sprintf(" .%s", issue.Field)
			}
			badge := severityBadge(issue.Severity)
			fmt.Printf("  %s  %-30s%s%s\n", badge, issue.Code, taskRef, fieldRef)
			fmt.Printf("         %s\n", issue.Message)
			if issue.Suggestion != "" {
				dimColor.Printf("         Suggestion: %s\n", issue.Suggestion)
			}
			fmt.Println()
		}
	}

	fmt.Println(sep)
	// Summary line
	errCount := counts[linter.SeverityError]
	warnCount := counts[linter.SeverityWarn]
	infoCount := counts[linter.SeverityInfo]

	parts := []string{}
	if errCount > 0 {
		parts = append(parts, errorColor.Sprintf("%d error(s)", errCount))
	}
	if warnCount > 0 {
		parts = append(parts, warnColor.Sprintf("%d warning(s)", warnCount))
	}
	if infoCount > 0 {
		parts = append(parts, infoColor.Sprintf("%d info", infoCount))
	}
	fmt.Printf("\nSummary: %s\n", strings.Join(parts, ", "))
	if errCount > 0 {
		errorColor.Printf("Exit code 1 — fix ERROR-level issues to pass CI.\n\n")
	} else {
		fmt.Println()
	}
}

func severityBadge(s linter.Severity) string {
	switch s {
	case linter.SeverityError:
		return color.New(color.FgRed, color.Bold).Sprint("[ERROR]")
	case linter.SeverityWarn:
		return color.New(color.FgYellow).Sprint("[ WARN]")
	default:
		return color.New(color.FgCyan).Sprint("[ INFO]")
	}
}

func init() {
	lintCmd.Flags().BoolVar(&lintFix, "fix", false, "Apply AI-generated rewrites for title/description issues to the plan state")
	lintCmd.Flags().IntVar(&lintTaskID, "task", 0, "Lint only the specified task ID")
	lintCmd.Flags().BoolVar(&lintSkipAI, "skip-ai", false, "Run static checks only (no provider call)")
	lintCmd.Flags().StringVar(&lintProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	lintCmd.Flags().StringVar(&lintModel, "model", "", "Model override for the AI provider")
	lintCmd.Flags().StringVar(&lintTimeout, "timeout", "2m", "Timeout for the AI call (e.g. 90s, 3m)")
	rootCmd.AddCommand(lintCmd)
}
