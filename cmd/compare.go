package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/compare"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	cmpProviders string
	cmpModel     string
	cmpJudge     bool
	cmpJudgeProv string
	cmpTask      int
	cmpFormat    string
	cmpOutput    string
	cmpTimeout   int
	cmpFull      bool
)

var compareCmd = &cobra.Command{
	Use:   "compare [prompt]",
	Short: "Benchmark the same prompt across multiple AI providers",
	Long: `Run the same prompt against several AI providers simultaneously and compare
results side-by-side: response quality, latency, token counts, and cost.

Examples:
  cloop compare "What is the best way to structure a Go project?"
  cloop compare --providers anthropic,openai "Explain REST vs GraphQL"
  cloop compare --judge "Write a haiku about software"
  cloop compare --task 3           # use a PM task's prompt
  cloop compare --format md -o results.md "Design a caching strategy"
  cloop compare --full "Summarize microservices best practices"`,
	RunE: runCompare,
}

func init() {
	compareCmd.Flags().StringVar(&cmpProviders, "providers", "", "Comma-separated providers to compare (default: all configured)")
	compareCmd.Flags().StringVar(&cmpModel, "model", "", "Model override (applies to all providers)")
	compareCmd.Flags().BoolVar(&cmpJudge, "judge", false, "Use an AI judge to score each response (0–10)")
	compareCmd.Flags().StringVar(&cmpJudgeProv, "judge-provider", "", "Provider to use as judge (default: first successful provider)")
	compareCmd.Flags().IntVar(&cmpTask, "task", 0, "Use prompt from PM task #N instead of a literal prompt")
	compareCmd.Flags().StringVar(&cmpFormat, "format", "table", "Output format: table, md")
	compareCmd.Flags().StringVar(&cmpOutput, "output", "", "Save output to file (shorthand: -o)")
	compareCmd.Flags().StringVarP(&cmpOutput, "out", "o", "", "")
	compareCmd.Flags().IntVar(&cmpTimeout, "timeout", 120, "Per-provider timeout in seconds")
	compareCmd.Flags().BoolVar(&cmpFull, "full", false, "Show full responses (not truncated)")
	compareCmd.Flags().MarkHidden("out")
	rootCmd.AddCommand(compareCmd)
}

func runCompare(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()

	cfg, err := config.Load(workdir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	applyEnvOverrides(cfg)

	provCfg := provider.ProviderConfig{
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}

	// Determine which providers to use
	var provNames []string
	if cmpProviders != "" {
		for _, p := range strings.Split(cmpProviders, ",") {
			if p = strings.TrimSpace(p); p != "" {
				provNames = append(provNames, p)
			}
		}
	} else {
		provNames = configuredProviders(cfg)
	}
	if len(provNames) == 0 {
		return fmt.Errorf("no providers configured — use --providers or set up config")
	}
	if len(provNames) == 1 {
		return fmt.Errorf("compare requires at least 2 providers; got only %q", provNames[0])
	}

	// Build provider instances
	var provs []provider.Provider
	for _, name := range provNames {
		provCfg.Name = name
		p, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider %q: %w", name, err)
		}
		provs = append(provs, p)
	}

	// Determine prompt
	var prompt string
	if cmpTask > 0 {
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found — run 'cloop init' first: %w", err)
		}
		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no PM task plan found")
		}
		var found bool
		for _, t := range s.Plan.Tasks {
			if t.ID == cmpTask {
				prompt = fmt.Sprintf("Task: %s\n\nDescription: %s", t.Title, t.Description)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("task #%d not found", cmpTask)
		}
	} else {
		if len(args) == 0 {
			return fmt.Errorf("provide a prompt as argument or use --task N")
		}
		prompt = strings.Join(args, " ")
	}

	timeout := time.Duration(cmpTimeout) * time.Second

	headerColor := color.New(color.FgCyan, color.Bold)
	dimColor := color.New(color.Faint)
	boldColor := color.New(color.Bold)

	headerColor.Printf("\nComparing %d providers...\n", len(provs))
	dimColor.Printf("Prompt: %s\n\n", compare.Truncate(prompt, 120))

	// Show spinner-like status per provider
	provNameList := make([]string, len(provs))
	for i, p := range provs {
		provNameList[i] = p.Name()
	}
	dimColor.Printf("Running: %s\n\n", strings.Join(provNameList, ", "))

	ctx := context.Background()
	entries := compare.Run(ctx, prompt, provs, cmpModel, timeout)

	// Optionally run judge
	if cmpJudge {
		headerColor.Printf("Running AI judge...\n\n")
		judgeProv, judgeErr := resolveJudge(cfg, provCfg, entries)
		if judgeErr != nil {
			dimColor.Printf("Judge unavailable: %v\n\n", judgeErr)
		} else {
			judgePrompt := compare.JudgePrompt(prompt, entries)
			judgeOpts := provider.Options{
				Model:   cmpModel,
				Timeout: timeout,
			}
			if judgeOpts.Model == "" {
				judgeOpts.Model = judgeProv.DefaultModel()
			}
			judgeResult, judgeErr := judgeProv.Complete(ctx, judgePrompt, judgeOpts)
			if judgeErr != nil {
				dimColor.Printf("Judge error: %v\n\n", judgeErr)
			} else {
				compare.ParseJudgeOutput(judgeResult.Output, entries)
			}
		}
	}

	// Render output
	var out strings.Builder
	if cmpFormat == "md" {
		renderMarkdown(&out, prompt, entries, cmpFull)
	} else {
		renderTable(&out, entries, cmpFull, boldColor)
	}

	output := out.String()

	// Print to stdout (always)
	fmt.Print(output)

	// Save to file if requested
	if cmpOutput != "" {
		if err := os.WriteFile(cmpOutput, []byte(output), 0o644); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		dimColor.Printf("\nSaved to %s\n", cmpOutput)
	}

	return nil
}

// configuredProviders returns provider names that appear to be configured.
func configuredProviders(cfg *config.Config) []string {
	var names []string
	if cfg.Anthropic.APIKey != "" || os.Getenv("ANTHROPIC_API_KEY") != "" {
		names = append(names, "anthropic")
	}
	if cfg.OpenAI.APIKey != "" || os.Getenv("OPENAI_API_KEY") != "" {
		names = append(names, "openai")
	}
	// Always include ollama if base URL is set (local, no auth needed)
	if cfg.Ollama.BaseURL != "" {
		names = append(names, "ollama")
	}
	// claudecode last — only if we have at least one other provider
	if len(names) > 0 {
		names = append(names, "claudecode")
	}
	return names
}

// resolveJudge picks the judge provider from --judge-provider flag or first successful entry.
func resolveJudge(cfg *config.Config, baseCfg provider.ProviderConfig, entries []*compare.Entry) (provider.Provider, error) {
	name := cmpJudgeProv
	if name == "" {
		// Use first successful provider
		for _, e := range entries {
			if e != nil && e.Err == nil {
				name = e.ProviderName
				break
			}
		}
	}
	if name == "" {
		return nil, fmt.Errorf("no successful providers to use as judge")
	}
	baseCfg.Name = name
	return provider.Build(baseCfg)
}

// renderTable writes a terminal-friendly comparison table.
func renderTable(b *strings.Builder, entries []*compare.Entry, full bool, boldColor *color.Color) {
	okColor := color.New(color.FgGreen)
	errColor := color.New(color.FgRed)
	judgeColor := color.New(color.FgYellow, color.Bold)
	dimColor := color.New(color.Faint)
	headerColor := color.New(color.FgCyan, color.Bold)

	// Summary row
	headerColor.Fprintln(b, "=== COMPARISON RESULTS ===\n")

	for i, e := range entries {
		if e == nil {
			continue
		}

		boldColor.Fprintf(b, "── Provider %d: %s", i+1, strings.ToUpper(e.ProviderName))
		if e.Model != "" {
			dimColor.Fprintf(b, " (%s)", e.Model)
		}
		fmt.Fprintln(b)

		if e.Err != nil {
			errColor.Fprintf(b, "   ERROR: %v\n\n", e.Err)
			continue
		}

		// Metrics row
		okColor.Fprintf(b, "   Latency:  %s\n", e.Duration.Round(time.Millisecond))
		if e.InputTokens > 0 || e.OutputTokens > 0 {
			okColor.Fprintf(b, "   Tokens:   %d in / %d out\n", e.InputTokens, e.OutputTokens)
		}
		if e.CostKnown {
			okColor.Fprintf(b, "   Cost:     %s\n", cost.FormatCost(e.CostUSD))
		}
		if e.JudgeFeedback != "" {
			judgeColor.Fprintf(b, "   Score:    %d/10 — %s\n", e.JudgeScore, e.JudgeFeedback)
		}

		// Response preview
		resp := e.Output
		if !full {
			resp = compare.Truncate(resp, 400)
		}
		fmt.Fprintf(b, "\n   Response:\n")
		for _, line := range strings.Split(resp, "\n") {
			fmt.Fprintf(b, "   %s\n", line)
		}
		fmt.Fprintln(b)
	}

	// Speed and cost ranking
	writeRankings(b, entries)
}

func writeRankings(b *strings.Builder, entries []*compare.Entry) {
	rankColor := color.New(color.FgMagenta, color.Bold)
	dimColor := color.New(color.Faint)

	// Fastest
	var fastest *compare.Entry
	for _, e := range entries {
		if e != nil && e.Err == nil {
			if fastest == nil || e.Duration < fastest.Duration {
				fastest = e
			}
		}
	}
	// Cheapest (cost known)
	var cheapest *compare.Entry
	for _, e := range entries {
		if e != nil && e.Err == nil && e.CostKnown {
			if cheapest == nil || e.CostUSD < cheapest.CostUSD {
				cheapest = e
			}
		}
	}
	// Highest judge score
	var topJudge *compare.Entry
	for _, e := range entries {
		if e != nil && e.Err == nil && e.JudgeFeedback != "" {
			if topJudge == nil || e.JudgeScore > topJudge.JudgeScore {
				topJudge = e
			}
		}
	}

	rankColor.Fprintln(b, "=== RANKINGS ===\n")
	if fastest != nil {
		dimColor.Fprintf(b, "  Fastest:  %s (%s)\n", fastest.ProviderName, fastest.Duration.Round(time.Millisecond))
	}
	if cheapest != nil {
		dimColor.Fprintf(b, "  Cheapest: %s (%s)\n", cheapest.ProviderName, cost.FormatCost(cheapest.CostUSD))
	}
	if topJudge != nil {
		dimColor.Fprintf(b, "  Best (AI judge): %s (%d/10)\n", topJudge.ProviderName, topJudge.JudgeScore)
	}
	fmt.Fprintln(b)
}

// renderMarkdown writes a markdown comparison document.
func renderMarkdown(b *strings.Builder, prompt string, entries []*compare.Entry, full bool) {
	fmt.Fprintf(b, "# Provider Comparison\n\n")
	fmt.Fprintf(b, "**Prompt:** %s\n\n", prompt)
	fmt.Fprintf(b, "## Summary\n\n")
	fmt.Fprintf(b, "| Provider | Model | Latency | Tokens In | Tokens Out | Cost | Judge Score |\n")
	fmt.Fprintf(b, "|----------|-------|---------|-----------|------------|------|-------------|\n")
	for _, e := range entries {
		if e == nil {
			continue
		}
		if e.Err != nil {
			fmt.Fprintf(b, "| %s | — | ERROR | — | — | — | — |\n", e.ProviderName)
			continue
		}
		latency := e.Duration.Round(time.Millisecond).String()
		tokIn := strconv.Itoa(e.InputTokens)
		tokOut := strconv.Itoa(e.OutputTokens)
		costStr := "—"
		if e.CostKnown {
			costStr = cost.FormatCost(e.CostUSD)
		}
		judgeStr := "—"
		if e.JudgeFeedback != "" {
			judgeStr = fmt.Sprintf("%d/10", e.JudgeScore)
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			e.ProviderName, e.Model, latency, tokIn, tokOut, costStr, judgeStr)
	}
	fmt.Fprintln(b)

	for i, e := range entries {
		if e == nil {
			continue
		}
		fmt.Fprintf(b, "## Response %d — %s\n\n", i+1, e.ProviderName)
		if e.Err != nil {
			fmt.Fprintf(b, "**Error:** %v\n\n", e.Err)
			continue
		}
		if e.JudgeFeedback != "" {
			fmt.Fprintf(b, "> **AI Judge Score: %d/10** — %s\n\n", e.JudgeScore, e.JudgeFeedback)
		}
		resp := e.Output
		if !full {
			resp = compare.Truncate(resp, 800)
		}
		fmt.Fprintf(b, "%s\n\n", resp)
	}
}
