package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/clijson"
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
	suggestInput    string
	suggestYes      bool
	suggestDryRun   bool
	suggestJSON     bool
)

var suggestCmd = &cobra.Command{
	Use:   "suggest",
	Short: "AI brainstorms feature ideas, or plans a request; accept/reject interactively to add as tasks",
	Long: `Suggest generates N AI-brainstormed feature ideas tailored to your project.
Each idea is presented interactively — accept it to add it as a PM task,
or reject it to skip.

The AI considers your project goal, codebase structure, recent activity,
and existing tasks to generate relevant, non-duplicate suggestions.

With --input, it plans a request instead: the request is broken into the
ordered tasks of a plan, each naming the earlier tasks it depends on.
--count then sets how many tasks the plan has; leave it out and the plan is
as long as the request needs. Accepted tasks join the end of the run queue
in plan order, and keep their dependencies on each other — through any task
you reject.

Examples:
  cloop suggest                          # brainstorm 5 ideas (default)
  cloop suggest --count 10               # brainstorm 10 ideas
  cloop suggest --input "add OAuth login"             # plan it in as many tasks as it needs
  cloop suggest --input "add OAuth login" --count 4   # plan it in exactly 4 tasks
  cloop suggest --yes                    # auto-accept all suggestions
  cloop suggest --dry-run                # show suggestions without prompting
  cloop suggest --provider anthropic     # use a specific provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		request, err := suggest.CleanRequest(suggestInput)
		if err != nil {
			return fmt.Errorf("--input: %w", err)
		}
		planMode := request != ""
		count := suggestCount
		switch {
		case count < 0:
			return fmt.Errorf("--count must not be negative")
		case planMode && count > suggest.MaxCount:
			return fmt.Errorf("--count: a plan has at most %d tasks", suggest.MaxCount)
		case !planMode && count == 0:
			count = suggest.DefaultCount
		}

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
			// The mock provider scripts its answers per project; without
			// this, and without WorkDir below, it could find none.
			MockResponsesFile: cfg.Mock.ResponsesFile,
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

		// A plan writes a self-contained description for every task, up to
		// twenty of them, so it gets longer than a brainstorm does.
		timeout := 3 * time.Minute
		if planMode {
			timeout = 5 * time.Minute
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{Model: model, Timeout: timeout, WorkDir: workdir}
		generate := func() (*suggest.Result, error) {
			if planMode {
				prompt := suggest.BuildPlanPrompt(s.Goal, s.Instructions, projCtx.FileTree,
					projCtx.RecentLog, memStr, existingTasks, request, count)
				return suggest.GeneratePlan(ctx, prov, prompt, opts, request, count)
			}
			prompt := suggest.BuildPrompt(s.Goal, s.Instructions, projCtx.FileTree,
				projCtx.RecentLog, memStr, existingTasks, count)
			return suggest.Generate(ctx, prov, prompt, opts)
		}

		if suggestJSON {
			// Machine-readable mode for the Web UI: no decoration, no state
			// mutation. The payload is framed rather than written bare,
			// because the UI reads it back through an executor that merges
			// stdout and stderr into one stream — so a diagnostic from any
			// package that happens to run during startup would otherwise be
			// parsed as the result. See pkg/clijson (Task 20325).
			result, err := generate()
			if err != nil {
				return fmt.Errorf("suggestion generation failed: %w", err)
			}
			return clijson.Emit(os.Stdout, result)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		boldColor := color.New(color.Bold)
		goodColor := color.New(color.FgGreen, color.Bold)
		warnColor := color.New(color.FgYellow)
		labelColor := color.New(color.FgMagenta)

		noun := "idea"
		switch {
		case !planMode:
			headerColor.Printf("\nBrainstorming %d feature ideas with %s...\n\n", count, prov.Name())
			dimColor.Printf("Goal: %s\n\n", truncate(s.Goal, 80))
		case count > 0:
			noun = "task"
			headerColor.Printf("\nPlanning %d tasks with %s...\n\n", count, prov.Name())
			dimColor.Printf("Request: %s\n\n", truncate(request, 80))
		default:
			noun = "task"
			headerColor.Printf("\nPlanning tasks with %s...\n\n", prov.Name())
			dimColor.Printf("Request: %s\n\n", truncate(request, 80))
		}

		result, err := generate()
		if err != nil {
			return fmt.Errorf("suggestion generation failed: %w", err)
		}

		if len(result.Suggestions) == 0 {
			warnColor.Printf("  No suggestions returned. Try again or adjust your goal.\n\n")
			return nil
		}

		sep := strings.Repeat("─", 70)
		fmt.Println(sep)
		if planMode {
			headerColor.Printf("  A Plan of %d Tasks\n", len(result.Suggestions))
		} else {
			headerColor.Printf("  %d Feature Ideas\n", len(result.Suggestions))
		}
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
				fmt.Printf("  Accept this %s? [y/n/q] ", noun)
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

		// Inject accepted suggestions as PM tasks. For a plan the ledger also
		// wires each task to the accepted tasks it depends on, looking through
		// any that were rejected.
		if !s.PMMode {
			s.PMMode = true
		}
		if s.Plan == nil {
			s.Plan = pm.NewPlan(s.Goal)
		}
		added := suggest.NewLedger(result).Apply(s.Plan, accepted)

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		fmt.Println(sep)
		goodColor.Printf("  Added %d %s(s) as PM tasks. Run 'cloop run --pm' to execute them.\n\n", len(added), noun)

		// Show what was added
		for _, t := range added {
			after := ""
			if len(t.DependsOn) > 0 {
				after = fmt.Sprintf("  (after %s)", joinTaskIDs(t.DependsOn))
			}
			dimColor.Printf("  + #%d %s%s\n", t.ID, t.Title, after)
		}
		fmt.Println()

		return nil
	},
}

// joinTaskIDs renders task IDs as "#3, #4".
func joinTaskIDs(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("#%d", id)
	}
	return strings.Join(parts, ", ")
}

// printSuggestion renders a single suggestion in terminal format. A plan's
// tasks also say which earlier tasks they come after.
func printSuggestion(n int, sg *suggest.Suggestion, boldColor, dimColor, labelColor *color.Color) {
	boldColor.Printf("  %d. %s", n, sg.Title)
	labelColor.Printf("  [%s | %s]\n", suggest.CategoryLabel(sg.Category), suggest.EffortLabel(sg.Effort))
	if sg.Description != "" {
		fmt.Printf("     What: %s\n", sg.Description)
	}
	if sg.Rationale != "" {
		dimColor.Printf("     Why:  %s\n", sg.Rationale)
	}
	if len(sg.DependsOn) > 0 {
		steps := make([]string, len(sg.DependsOn))
		for i, d := range sg.DependsOn {
			steps[i] = strconv.Itoa(d)
		}
		dimColor.Printf("     After: %s\n", strings.Join(steps, ", "))
	}
	fmt.Println()
}

func init() {
	suggestCmd.Flags().StringVar(&suggestProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	suggestCmd.Flags().StringVar(&suggestModel, "model", "", "Model to use")
	suggestCmd.Flags().IntVar(&suggestCount, "count", 0, "Number of ideas to brainstorm (default 5); with --input, number of tasks in the plan (default: as many as the request needs)")
	suggestCmd.Flags().StringVar(&suggestInput, "input", "", "A request to break into a plan of tasks, instead of brainstorming ideas")
	suggestCmd.Flags().BoolVar(&suggestYes, "yes", false, "Auto-accept all suggestions")
	suggestCmd.Flags().BoolVar(&suggestDryRun, "dry-run", false, "Show suggestions without prompting or adding tasks")
	suggestCmd.Flags().BoolVar(&suggestJSON, "json", false, "Output suggestions as JSON to stdout (no interactive prompt, no state mutation)")
	rootCmd.AddCommand(suggestCmd)
}
