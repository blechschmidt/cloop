package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/impact"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	impactProvider string
	impactModel    string
	impactTimeout  string
	impactApply    bool
)

var taskImpactCmd = &cobra.Command{
	Use:   "ai-impact",
	Short: "AI strategic impact scoring for pending tasks",
	Long: `Ask the AI to rate every pending/in-progress task by its strategic impact
toward the project goal on a 1-10 scale.

Unlike 'cloop task reorder' (which just reprioritizes), impact scoring provides
a quantitative breakdown with rationale per task and identifies which tasks are
'multipliers' (they unblock many others) vs 'leaf' tasks (independent, low leverage).

With --apply, an annotation containing the impact score and rationale is written
back to each scored task so it is visible in 'cloop task notes <id>'.

Examples:
  cloop task ai-impact
  cloop task ai-impact --apply
  cloop task ai-impact --provider anthropic --model claude-opus-4-6
  cloop task ai-impact --timeout 3m`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Count scoreable tasks
		activeCount := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
				activeCount++
			}
		}
		if activeCount == 0 {
			color.New(color.FgGreen).Println("No pending tasks to score — all tasks are complete.")
			return nil
		}

		// Build provider
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := impactProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := impactModel
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
		if impactTimeout != "" {
			timeout, err = time.ParseDuration(impactTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Printf("Scoring %d pending tasks by strategic impact...\n\n", activeCount)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		scores, err := impact.Score(ctx, prov, opts, s.Plan)
		if err != nil {
			return fmt.Errorf("impact scoring failed: %w", err)
		}
		if len(scores) == 0 {
			dimColor.Println("No scores returned.")
			return nil
		}

		// Render table
		renderImpactTable(scores)

		if impactApply {
			// Write impact score as annotation on each task
			for _, sc := range scores {
				var task *pm.Task
				for _, t := range s.Plan.Tasks {
					if t.ID == sc.TaskID {
						task = t
						break
					}
				}
				if task == nil {
					continue
				}
				annotation := fmt.Sprintf("AI Impact Score: %d/10 — %s", sc.ImpactScore, sc.Rationale)
				if sc.IsMultiplier {
					annotation += fmt.Sprintf(" [MULTIPLIER: unblocks %d task(s)]", sc.UnblocksCount)
				}
				pm.AddAnnotation(task, "ai-impact", annotation)
			}
			if err := s.Save(); err != nil {
				return fmt.Errorf("saving state: %w", err)
			}
			color.New(color.FgGreen).Printf("Impact scores written as annotations on %d tasks.\n", len(scores))
		}

		return nil
	},
}

// renderImpactTable prints a sorted table of impact scores with color coding.
func renderImpactTable(scores []impact.TaskImpact) {
	lowColor := color.New(color.FgRed)
	medColor := color.New(color.FgYellow)
	highColor := color.New(color.FgGreen)
	multiplierBadge := color.New(color.FgCyan, color.Bold)
	dimColor := color.New(color.Faint)
	headerColor := color.New(color.FgWhite, color.Bold)

	sep := "─────────────────────────────────────────────────────────────────────────"
	fmt.Println(sep)
	headerColor.Printf("  %-4s  %-5s  %-44s  %s\n", "ID", "SCORE", "TITLE", "TYPE")
	fmt.Println(sep)

	for _, sc := range scores {
		scoreStr := fmt.Sprintf("%2d/10", sc.ImpactScore)

		title := sc.TaskTitle
		if len([]rune(title)) > 44 {
			title = string([]rune(title)[:41]) + "..."
		}

		typePart := "leaf"
		if sc.IsMultiplier {
			typePart = fmt.Sprintf("MULTIPLIER (unblocks %d)", sc.UnblocksCount)
		}

		line := fmt.Sprintf("  #%-3d  %-5s  %-44s  %s\n", sc.TaskID, scoreStr, title, typePart)

		switch {
		case sc.IsMultiplier:
			multiplierBadge.Printf("  #%-3d  ", sc.TaskID)
			switch {
			case sc.ImpactScore >= 7:
				highColor.Printf("%-5s  ", scoreStr)
			case sc.ImpactScore >= 4:
				medColor.Printf("%-5s  ", scoreStr)
			default:
				lowColor.Printf("%-5s  ", scoreStr)
			}
			multiplierBadge.Printf("%-44s  %s\n", title, typePart)
		case sc.ImpactScore >= 7:
			highColor.Print(line)
		case sc.ImpactScore >= 4:
			medColor.Print(line)
		default:
			lowColor.Print(line)
		}

		if sc.Rationale != "" {
			dimColor.Printf("         %s\n", wrapImpactText(sc.Rationale, 65))
		}
		fmt.Println()
	}

	fmt.Println(sep)
	fmt.Println()

	// Legend
	dimColor.Println("  Score legend:")
	lowColor.Print("    1-3")
	dimColor.Println(" Low impact (nice-to-have, minor)")
	medColor.Print("    4-6")
	dimColor.Println(" Medium impact (useful, moderate value)")
	highColor.Print("    7-10")
	dimColor.Println(" High impact (core capability, critical)")
	multiplierBadge.Print("    MULTIPLIER")
	dimColor.Println(" Unblocks 2+ other pending tasks")
	fmt.Println()
}

// wrapImpactText wraps a string at the given column width for display.
func wrapImpactText(s string, width int) string {
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	// Find last space before width
	idx := width
	for idx > 0 && runes[idx] != ' ' {
		idx--
	}
	if idx == 0 {
		idx = width
	}
	return string(runes[:idx]) + "\n         " + wrapImpactText(string(runes[idx+1:]), width)
}

func init() {
	taskImpactCmd.Flags().StringVar(&impactProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskImpactCmd.Flags().StringVar(&impactModel, "model", "", "Model override for the AI provider")
	taskImpactCmd.Flags().StringVar(&impactTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 2m, 300s)")
	taskImpactCmd.Flags().BoolVar(&impactApply, "apply", false, "Write impact scores back as annotations on each task")

	taskCmd.AddCommand(taskImpactCmd)
}
