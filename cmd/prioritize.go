package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/prioritize"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	prioritizeProvider string
	prioritizeModel    string
	prioritizeApply    bool
	prioritizeDryRun   bool
)

var prioritizeCmd = &cobra.Command{
	Use:   "prioritize",
	Short: "AI-powered smart task reprioritization",
	Long: `Prioritize analyzes your current task plan and uses AI to suggest
the optimal execution order based on the critical path, dependencies,
risk factors, and value delivery.

By default it shows suggestions only. Use --apply to commit the changes.

Examples:
  cloop prioritize                         # show AI priority suggestions
  cloop prioritize --apply                 # apply suggestions immediately
  cloop prioritize --provider anthropic    # use specific provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}

		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm --plan-only' first")
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		boldColor := color.New(color.Bold)
		goodColor := color.New(color.FgGreen)
		warnColor := color.New(color.FgYellow)
		dimColor := color.New(color.Faint)

		// Print current ordering
		headerColor.Printf("\n  Task Reprioritization\n")
		fmt.Printf("  Goal: %s\n\n", truncate(s.Goal, 70))

		pending := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == "pending" && !s.Plan.PermanentlyBlocked(t) {
				pending++
			}
		}
		fmt.Printf("  Pending tasks eligible for reprioritization: %d\n\n", pending)

		// Sort current tasks by priority to show current order
		sorted := make([]*prioritize.Suggestion, 0)
		_ = sorted

		tasks := s.Plan.Tasks
		currentOrder := make([]*struct {
			ID    int
			Title string
			Prio  int
			Role  string
		}, 0)
		for _, t := range tasks {
			if t.Status == "pending" && !s.Plan.PermanentlyBlocked(t) {
				currentOrder = append(currentOrder, &struct {
					ID    int
					Title string
					Prio  int
					Role  string
				}{t.ID, t.Title, t.Priority, string(t.Role)})
			}
		}
		sort.Slice(currentOrder, func(i, j int) bool {
			return currentOrder[i].Prio < currentOrder[j].Prio
		})

		boldColor.Printf("  Current Priority Order:\n")
		for i, t := range currentOrder {
			dimColor.Printf("    %2d. [P%d, %s] Task %d: %s\n", i+1, t.Prio, t.Role, t.ID, truncate(t.Title, 55))
		}
		fmt.Println()

		// Determine provider
		provName := prioritizeProvider
		if provName == "" {
			provName = cfg.Provider
		}
		if provName == "" {
			provName = autoSelectProvider()
		}

		model := prioritizeModel
		if model == "" {
			switch provName {
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
			Name:             provName,
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

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()

		headerColor.Printf("  Analyzing with %s...\n\n", provName)

		result, err := prioritize.Generate(ctx, prov, s.Goal, s.Plan, model, 3*time.Minute)
		if err != nil {
			return fmt.Errorf("generating suggestions: %w", err)
		}

		if len(result.Suggestions) == 0 {
			goodColor.Printf("  Tasks are already optimally ordered — no changes suggested.\n\n")
			return nil
		}

		// Show summary
		if result.Summary != "" {
			boldColor.Printf("  Strategy: ")
			fmt.Printf("%s\n\n", result.Summary)
		}

		// Build lookup for display
		idToTitle := make(map[int]string)
		idToCurrentPrio := make(map[int]int)
		idToRole := make(map[int]string)
		for _, t := range s.Plan.Tasks {
			idToTitle[t.ID] = t.Title
			idToCurrentPrio[t.ID] = t.Priority
			idToRole[t.ID] = string(t.Role)
		}

		boldColor.Printf("  Suggested Changes:\n\n")
		changes := 0
		for _, sg := range result.Suggestions {
			currentPrio, ok := idToCurrentPrio[sg.TaskID]
			if !ok {
				continue
			}
			title := truncate(idToTitle[sg.TaskID], 50)
			role := idToRole[sg.TaskID]

			direction := "→"
			dirColor := warnColor
			if sg.NewPriority < currentPrio {
				direction = "↑"
				dirColor = goodColor // higher priority (lower number) = move up
			} else if sg.NewPriority > currentPrio {
				direction = "↓"
				dirColor = dimColor // lower priority = move down
			}

			fmt.Printf("  Task %d [%s]: ", sg.TaskID, role)
			dirColor.Printf("P%d %s P%d", currentPrio, direction, sg.NewPriority)
			fmt.Printf("  %s\n", title)
			if sg.Reason != "" {
				dimColor.Printf("    Reason: %s\n", sg.Reason)
			}
			changes++
		}
		fmt.Println()

		if changes == 0 {
			goodColor.Printf("  No priority changes needed.\n\n")
			return nil
		}

		// Show new order preview
		// Build a simulated new order for preview
		newPrios := make(map[int]int)
		for _, t := range s.Plan.Tasks {
			newPrios[t.ID] = t.Priority
		}
		for _, sg := range result.Suggestions {
			newPrios[sg.TaskID] = sg.NewPriority
		}

		type preview struct {
			ID   int
			Prio int
			Role string
			Title string
		}
		var previews []preview
		for _, t := range s.Plan.Tasks {
			if t.Status == "pending" && !s.Plan.PermanentlyBlocked(t) {
				previews = append(previews, preview{t.ID, newPrios[t.ID], string(t.Role), t.Title})
			}
		}
		sort.Slice(previews, func(i, j int) bool {
			return previews[i].Prio < previews[j].Prio
		})

		boldColor.Printf("  New Priority Order (preview):\n")
		for i, p := range previews {
			// Check if this task changed
			changed := newPrios[p.ID] != idToCurrentPrio[p.ID]
			line := fmt.Sprintf("    %2d. [P%d, %s] Task %d: %s\n", i+1, p.Prio, p.Role, p.ID, truncate(p.Title, 55))
			if changed {
				goodColor.Print(line)
			} else {
				dimColor.Print(line)
			}
		}
		fmt.Println()

		if prioritizeDryRun || !prioritizeApply {
			if !prioritizeApply {
				warnColor.Printf("  Run with --apply to commit these changes.\n\n")
			}
			return nil
		}

		// Apply
		n := prioritize.Apply(s.Plan, result)
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		goodColor.Printf("  Applied %d priority change(s). Run 'cloop status' to verify.\n\n", n)

		// Show hint about what cloop run will execute next
		next := s.Plan.NextTask()
		if next != nil {
			dimColor.Printf("  Next task to execute: Task %d — %s\n\n", next.ID, truncate(next.Title, 60))
		}

		// Add a note to memory if significant reordering
		if n >= 3 {
			memFile := workdir + "/.cloop/memory.md"
			timestamp := time.Now().Format("2006-01-02 15:04")
			note := fmt.Sprintf("\n## Reprioritization (%s)\n%s\nChanged %d task priorities via AI analysis.\n", timestamp, result.Summary, n)
			f, err := os.OpenFile(memFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err == nil {
				_, _ = f.WriteString(note)
				f.Close()
				dimColor.Printf("  Recorded in .cloop/memory.md\n\n")
			}
		}

		return nil
	},
}

func init() {
	prioritizeCmd.Flags().StringVar(&prioritizeProvider, "provider", "", "AI provider")
	prioritizeCmd.Flags().StringVar(&prioritizeModel, "model", "", "Model to use")
	prioritizeCmd.Flags().BoolVar(&prioritizeApply, "apply", false, "Apply suggested priority changes")
	prioritizeCmd.Flags().BoolVar(&prioritizeDryRun, "dry-run", false, "Show suggestions without applying (default)")
	rootCmd.AddCommand(prioritizeCmd)
}
