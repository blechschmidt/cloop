package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/critique"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	critiqueProvider string
	critiqueModel    string
	critiqueTimeout  string
	critiqueJSON     bool
)

var planCritiqueCmd = &cobra.Command{
	Use:   "critique",
	Short: "AI adversarial plan review — devil's advocate pressure-test",
	Long: `Adversarially pressure-test the current plan before execution.

Unlike 'cloop health' (which scores quality) or 'cloop risk' (which lists risks),
critique plays an opposing role: it actively argues against the plan, surfaces
overconfident assumptions, identifies missing tasks, flags logical gaps in task
ordering, and proposes alternative approaches.

Output sections:
  Assumptions  — stated/unstated assumptions the plan relies on (red)
  Gaps         — missing tasks or steps (red)
  Ordering     — sequencing and dependency issues (yellow)
  Alternatives — other approaches worth considering (cyan)
  Verdict      — overall adversarial verdict

Examples:
  cloop plan critique
  cloop plan critique --provider anthropic
  cloop plan critique --json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm --plan-only' to create one")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := critiqueProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := critiqueModel
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

		timeout := 3 * time.Minute
		if critiqueTimeout != "" {
			timeout, err = time.ParseDuration(critiqueTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
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

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		if !critiqueJSON {
			headerColor := color.New(color.FgRed, color.Bold)
			headerColor.Printf("\ncloop plan critique — adversarial plan review\n")
			fmt.Printf("  Provider: %s\n", prov.Name())
			fmt.Printf("  Goal: %s\n", truncateStr(s.Goal, 80))
			fmt.Printf("  Tasks: %d\n\n", len(s.Plan.Tasks))
			color.New(color.Faint).Printf("Generating adversarial critique...\n\n")
		}

		report, err := critique.Critique(ctx, prov, model, s.Plan, s.Goal)
		if err != nil {
			return fmt.Errorf("critique: %w", err)
		}

		if critiqueJSON {
			return printCritiqueJSON(report)
		}

		printCritiqueReport(report)
		return nil
	},
}

func printCritiqueReport(r *critique.CritiqueReport) {
	sep := strings.Repeat("─", 72)
	redBold := color.New(color.FgRed, color.Bold)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow, color.Bold)
	yellowPlain := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan, color.Bold)
	cyanPlain := color.New(color.FgCyan)
	dim := color.New(color.Faint)

	fmt.Println(sep)

	// Assumptions (red)
	redBold.Printf("ASSUMPTIONS  (%d)\n", len(r.Assumptions))
	dim.Println("Stated or unstated things this plan relies on being true:")
	if len(r.Assumptions) == 0 {
		dim.Println("  (none identified)")
	} else {
		for i, a := range r.Assumptions {
			red.Printf("  %d. %s\n", i+1, a)
		}
	}
	fmt.Println()

	// Gaps (red)
	redBold.Printf("GAPS  (%d)\n", len(r.Gaps))
	dim.Println("Missing tasks or steps the plan forgot:")
	if len(r.Gaps) == 0 {
		dim.Println("  (none identified)")
	} else {
		for i, g := range r.Gaps {
			red.Printf("  %d. %s\n", i+1, g)
		}
	}
	fmt.Println()

	// Ordering (yellow)
	yellow.Printf("ORDERING ISSUES  (%d)\n", len(r.Ordering))
	dim.Println("Sequencing problems and dependency conflicts:")
	if len(r.Ordering) == 0 {
		dim.Println("  (none identified)")
	} else {
		for i, o := range r.Ordering {
			yellowPlain.Printf("  %d. %s\n", i+1, o)
		}
	}
	fmt.Println()

	// Alternatives (cyan)
	cyan.Printf("ALTERNATIVES  (%d)\n", len(r.Alternatives))
	dim.Println("Other approaches worth considering:")
	if len(r.Alternatives) == 0 {
		dim.Println("  (none identified)")
	} else {
		for i, a := range r.Alternatives {
			cyanPlain.Printf("  %d. %s\n", i+1, a)
		}
	}
	fmt.Println()

	fmt.Println(sep)

	// Verdict
	color.New(color.FgRed, color.Bold).Printf("VERDICT\n")
	fmt.Printf("  %s\n", r.Verdict)
	fmt.Println(sep)
	fmt.Println()

	dim.Println("Use 'cloop plan edit <instruction>' to mutate the plan based on this critique.")
	dim.Println("Use 'cloop plan critique --json' for machine-readable output.")
	fmt.Println()
}

func printCritiqueJSON(r *critique.CritiqueReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func init() {
	planCritiqueCmd.Flags().StringVar(&critiqueProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	planCritiqueCmd.Flags().StringVar(&critiqueModel, "model", "", "Model override for the AI provider")
	planCritiqueCmd.Flags().StringVar(&critiqueTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 2m, 90s)")
	planCritiqueCmd.Flags().BoolVar(&critiqueJSON, "json", false, "Output critique as JSON")
	planCmd.AddCommand(planCritiqueCmd)
}
