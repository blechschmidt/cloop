package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/analyze"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	analyzeGoal     string
	analyzeDryRun   bool
	analyzeApply    bool
	analyzeProvider string
	analyzeModel    string
	analyzeTimeout  string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [dir]",
	Short: "AI-powered codebase bootstrapping: scan a project and propose a plan",
	Long: `Scan an existing project directory and auto-generate an initial cloop plan.

analyze examines the following signals:
  - git log --oneline -20 (recent commit history)
  - README.md / CHANGELOG.md
  - Directory tree (top 2 levels)
  - Open TODO/FIXME comments in source files
  - go.mod / package.json / Cargo.toml / pyproject.toml (first found)

It sends a structured context snapshot to the configured AI provider and asks
it to propose a 5-10 task plan grounded in the project's actual state.

Use --dry-run to preview the proposal without writing anything, or --apply to
write the plan directly to state without prompting.

Examples:
  cloop analyze                              # analyse current directory
  cloop analyze ~/projects/myapp             # analyse a specific directory
  cloop analyze --dry-run                    # preview proposal, do not write
  cloop analyze --apply                      # auto-accept and write plan
  cloop analyze --goal "improve test coverage and CI"
  cloop analyze --provider anthropic --model claude-opus-4-6`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Resolve target directory
		targetDir := "."
		if len(args) == 1 {
			targetDir = args[0]
		}
		absTarget, err := os.Getwd()
		if err != nil {
			return err
		}
		if targetDir != "." {
			absTarget = targetDir
		}

		// The cloop project lives in the current working directory
		workdir, _ := os.Getwd()

		// Load config (use workdir config even when analyzing a different dir)
		cfg, err := config.Load(workdir)
		if err != nil {
			// Non-fatal: use defaults
			cfg = &config.Config{}
		}
		applyEnvOverrides(cfg)

		// Resolve provider
		pName := analyzeProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		// Resolve model
		model := analyzeModel
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

		timeout := 5 * time.Minute
		if analyzeTimeout != "" {
			timeout, err = time.ParseDuration(analyzeTimeout)
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
		successColor := color.New(color.FgGreen, color.Bold)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("Analysing %s ...\n\n", absTarget)

		proposal, err := analyze.Analyze(ctx, prov, opts, absTarget, analyzeGoal)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		// Print proposal
		warnColor.Printf("Proposed goal: %s\n\n", proposal.Goal)
		fmt.Printf("Proposed tasks (%d):\n\n", len(proposal.Tasks))
		for _, t := range proposal.Tasks {
			roleStr := ""
			if t.Role != "" {
				roleStr = fmt.Sprintf(" [%s]", t.Role)
			}
			estStr := ""
			if t.EstimatedMinutes > 0 {
				estStr = fmt.Sprintf(" (~%d min)", t.EstimatedMinutes)
			}
			tagsStr := ""
			if len(t.Tags) > 0 {
				tagsStr = fmt.Sprintf(" #%s", strings.Join(t.Tags, " #"))
			}
			successColor.Printf("  P%d  %s%s%s%s\n", t.Priority, t.Title, roleStr, estStr, tagsStr)
			if t.Description != "" {
				dimColor.Printf("       %s\n", t.Description)
			}
			fmt.Println()
		}

		if analyzeDryRun {
			dimColor.Println("(dry-run: nothing written)")
			return nil
		}

		// Confirm unless --apply
		if !analyzeApply {
			fmt.Printf("Apply this plan? (y/N): ")
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

		// Convert proposal to pm.Plan and write to state
		plan := analyze.ProposalToPlan(proposal)

		// Load or create state
		s, loadErr := state.Load(workdir)
		if loadErr != nil {
			// No existing project: create a minimal state
			s = &state.ProjectState{
				Goal:    proposal.Goal,
				WorkDir: workdir,
				Status:  "pending",
				PMMode:  true,
			}
		}

		// Overwrite plan and enable PM mode
		s.Goal = proposal.Goal
		s.Plan = plan
		s.PMMode = true
		if pName != "" {
			s.Provider = pName
		}
		if model != "" {
			s.Model = model
		}

		// Ensure .cloop directory exists
		if err := os.MkdirAll(fmt.Sprintf("%s/.cloop", workdir), 0755); err != nil {
			return fmt.Errorf("creating .cloop dir: %w", err)
		}

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		successColor.Printf("Plan applied: %d tasks written to .cloop/state.json\n", len(plan.Tasks))
		dimColor.Println("Run 'cloop run --pm' to start executing.")
		return nil
	},
}

func init() {
	analyzeCmd.Flags().StringVar(&analyzeGoal, "goal", "", "Optional high-level goal hint to guide the AI analysis")
	analyzeCmd.Flags().BoolVar(&analyzeDryRun, "dry-run", false, "Print the proposed plan but do not write anything")
	analyzeCmd.Flags().BoolVar(&analyzeApply, "apply", false, "Auto-accept and write the plan without prompting")
	analyzeCmd.Flags().StringVar(&analyzeProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	analyzeCmd.Flags().StringVar(&analyzeModel, "model", "", "Model override for the AI provider")
	analyzeCmd.Flags().StringVar(&analyzeTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 3m, 300s)")

	rootCmd.AddCommand(analyzeCmd)
}
