package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	scopeGoal     string
	scopeProvider string
	scopeModel    string
)

// ScopeAnalysis holds the structured result of an AI scope analysis.
type ScopeAnalysis struct {
	TaskCount       int      `json:"task_count"`
	Complexity      string   `json:"complexity"`      // low, medium, high, very_high
	EstimatedSteps  int      `json:"estimated_steps"` // rough total AI calls
	Risks           []string `json:"risks"`
	Prerequisites   []string `json:"prerequisites"`
	Assumptions     []string `json:"assumptions"`
	RecommendedMode string   `json:"recommended_mode"` // loop, pm
	Summary         string   `json:"summary"`
}

var scopeCmd = &cobra.Command{
	Use:   "scope [goal]",
	Short: "AI-powered project scope analysis before you start",
	Long: `Analyze project scope using AI before committing to a full run.

Estimates task count, complexity, risks, prerequisites, and recommended
execution mode. Helps you plan resources and set expectations.

If no goal is provided, uses the current project goal from state.

Examples:
  cloop scope "Build a REST API with auth"
  cloop scope                           # analyze current project goal
  cloop scope --provider anthropic "Add OAuth support"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Resolve the goal: CLI arg > flag > current project state
		goal := scopeGoal
		if goal == "" && len(args) > 0 {
			goal = strings.Join(args, " ")
		}
		var instructions string
		if goal == "" {
			s, err := state.Load(workdir)
			if err != nil {
				return fmt.Errorf("no goal provided and no project found (run 'cloop init' first or pass a goal): %w", err)
			}
			goal = s.Goal
			instructions = s.Instructions
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		// Resolve provider
		pName := scopeProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := scopeModel
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

		// Build scope analysis prompt
		prompt := buildScopePrompt(goal, instructions)

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		headerColor.Printf("\nAnalyzing project scope...\n\n")
		dimColor.Printf("Goal: %s\n", goal)
		dimColor.Printf("Provider: %s\n\n", prov.Name())

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		result, err := prov.Complete(ctx, prompt, provider.Options{
			Model:   model,
			Timeout: 2 * time.Minute,
			WorkDir: workdir,
		})
		if err != nil {
			return fmt.Errorf("scope analysis failed: %w", err)
		}

		analysis, parseErr := parseScopeAnalysis(result.Output)
		if parseErr != nil {
			// Fallback: print raw output
			dimColor.Printf("(Could not parse structured analysis — showing raw output)\n\n")
			fmt.Println(result.Output)
			return nil
		}

		printScopeAnalysis(goal, analysis)
		return nil
	},
}

func buildScopePrompt(goal, instructions string) string {
	var b strings.Builder
	b.WriteString("You are an expert AI project manager performing a pre-flight scope analysis.\n")
	b.WriteString("Your job is to analyze a project goal and produce a realistic scope estimate.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}
	b.WriteString("## ANALYSIS INSTRUCTIONS\n")
	b.WriteString("Analyze the goal and estimate:\n")
	b.WriteString("- task_count: number of distinct implementation tasks (integer)\n")
	b.WriteString("- complexity: overall complexity (\"low\", \"medium\", \"high\", or \"very_high\")\n")
	b.WriteString("- estimated_steps: total AI invocations expected (integer, e.g. task_count * 1-3)\n")
	b.WriteString("- risks: list of 2-5 specific risks or blockers (strings)\n")
	b.WriteString("- prerequisites: list of things that must exist before starting (tools, access, files)\n")
	b.WriteString("- assumptions: key assumptions baked into this estimate\n")
	b.WriteString("- recommended_mode: \"loop\" for simple linear tasks, \"pm\" for multi-task projects\n")
	b.WriteString("- summary: 1-2 sentence plain-English scope summary\n\n")
	b.WriteString("Output ONLY valid JSON, no markdown, no explanation:\n")
	b.WriteString(`{"task_count":5,"complexity":"medium","estimated_steps":10,"risks":["risk1","risk2"],"prerequisites":["prereq1"],"assumptions":["assumption1"],"recommended_mode":"pm","summary":"Brief summary."}`)
	return b.String()
}

func parseScopeAnalysis(output string) (*ScopeAnalysis, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON in response")
	}
	var a ScopeAnalysis
	if err := json.Unmarshal([]byte(output[start:end+1]), &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func printScopeAnalysis(goal string, a *ScopeAnalysis) {
	headerColor := color.New(color.FgCyan, color.Bold)
	labelColor := color.New(color.FgYellow)
	successColor := color.New(color.FgGreen, color.Bold)
	warnColor := color.New(color.FgYellow, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)

	sep := strings.Repeat("─", 60)
	fmt.Println(sep)
	headerColor.Printf("  Scope Analysis\n")
	fmt.Println(sep)

	labelColor.Printf("Summary:    ")
	fmt.Printf("%s\n\n", a.Summary)

	labelColor.Printf("Tasks:      ")
	fmt.Printf("%d estimated\n", a.TaskCount)

	labelColor.Printf("Complexity: ")
	switch a.Complexity {
	case "low":
		successColor.Printf("%s\n", a.Complexity)
	case "medium":
		warnColor.Printf("%s\n", a.Complexity)
	case "high":
		failColor.Printf("%s\n", a.Complexity)
	case "very_high":
		failColor.Printf("%s\n", a.Complexity)
	default:
		fmt.Printf("%s\n", a.Complexity)
	}

	labelColor.Printf("AI Steps:   ")
	fmt.Printf("~%d estimated invocations\n", a.EstimatedSteps)

	labelColor.Printf("Mode:       ")
	if a.RecommendedMode == "pm" {
		fmt.Printf("--pm (product manager mode recommended)\n")
	} else {
		fmt.Printf("loop mode (standard feedback loop)\n")
	}

	if len(a.Prerequisites) > 0 {
		fmt.Println()
		labelColor.Printf("Prerequisites:\n")
		for _, p := range a.Prerequisites {
			fmt.Printf("  - %s\n", p)
		}
	}

	if len(a.Risks) > 0 {
		fmt.Println()
		labelColor.Printf("Risks:\n")
		for _, r := range a.Risks {
			warnColor.Printf("  ! ")
			fmt.Printf("%s\n", r)
		}
	}

	if len(a.Assumptions) > 0 {
		fmt.Println()
		labelColor.Printf("Assumptions:\n")
		for _, assumption := range a.Assumptions {
			dimColor.Printf("  ~ %s\n", assumption)
		}
	}

	fmt.Println()
	fmt.Println(sep)

	// Suggest next steps
	headerColor.Printf("  Suggested next steps:\n")
	if a.RecommendedMode == "pm" {
		fmt.Printf("  cloop init \"%s\"\n", truncateGoal(goal, 60))
		fmt.Printf("  cloop run --pm --verify --inject-context\n")
	} else {
		fmt.Printf("  cloop init \"%s\"\n", truncateGoal(goal, 60))
		fmt.Printf("  cloop run\n")
	}
	fmt.Println(sep)
	fmt.Println()
}

func truncateGoal(goal string, n int) string {
	if len(goal) <= n {
		return goal
	}
	return goal[:n] + "..."
}

func init() {
	scopeCmd.Flags().StringVarP(&scopeGoal, "goal", "g", "", "Goal to analyze (overrides positional argument)")
	scopeCmd.Flags().StringVar(&scopeProvider, "provider", "", "Provider to use for analysis")
	scopeCmd.Flags().StringVar(&scopeModel, "model", "", "Model to use for analysis")
	rootCmd.AddCommand(scopeCmd)
}
