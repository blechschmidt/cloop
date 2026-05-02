package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/blocker"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	blockerProvider string
	blockerModel    string
	blockerTimeout  string
	blockerApply    bool
	blockerJSON     bool
	blockerAll      bool
)

var taskBlockerCmd = &cobra.Command{
	Use:   "ai-blocker [task-id]",
	Short: "Detect blocked tasks and get AI-powered resolution suggestions",
	Long: `Analyse a task (or all tasks) to detect whether it is blocked, then ask
the AI for a root-cause hypothesis and 3 concrete unblocking actions.

Detection heuristics (any one triggers a BLOCKED classification):
  - Task is in_progress with no artifact/checkpoint activity in >30 minutes
  - One or more dependency tasks have failed
  - Any annotation on the task contains the word "blocked"

The AI then produces:
  1. A root-cause hypothesis
  2. Three concrete, task-specific unblocking actions
  3. A recommendation: retry / skip / reassign

Use --apply to auto-annotate the task with the AI recommendation.
Use --all to scan every non-complete task and report blockers.

Examples:
  cloop task ai-blocker 5
  cloop task ai-blocker 5 --apply
  cloop task ai-blocker --all
  cloop task ai-blocker 5 --provider anthropic --model claude-opus-4-6
  cloop task ai-blocker 5 --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !blockerAll && len(args) != 1 {
			return fmt.Errorf("provide a task-id or use --all")
		}

		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := blockerProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := blockerModel
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
		if blockerTimeout != "" {
			timeout, err = time.ParseDuration(blockerTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// --all mode: scan every non-complete task
		if blockerAll {
			return runBlockerAll(ctx, prov, model, timeout, s, workdir)
		}

		// Single task mode
		taskID, err := strconv.Atoi(args[0])
		if err != nil || taskID < 1 {
			return fmt.Errorf("invalid task-id: %s", args[0])
		}

		task := s.Plan.TaskByID(taskID)
		if task == nil {
			return fmt.Errorf("task #%d not found", taskID)
		}

		cyan := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)

		if !blockerJSON {
			cyan.Printf("━━━ cloop task ai-blocker ━━━\n\n")
			dim.Printf("Task #%d: %s\n", task.ID, task.Title)
			dim.Printf("Provider: %s", pName)
			if model != "" {
				dim.Printf(" (%s)", model)
			}
			dim.Printf("\n\n")

			// Quick detection before calling AI
			info := blocker.Detect(workdir, task, s.Plan)
			if !info.Blocked {
				color.New(color.FgGreen).Printf("No blockers detected for task #%d (%s)\n\n", task.ID, task.Title)
				color.New(color.Faint).Printf("Heuristics checked: stalled, failed deps, blocked annotation\n")
				return nil
			}

			printDetectionBadges(info)
			dim.Printf("\nCalling AI for root-cause analysis...\n\n")
		}

		report, err := blocker.Analyze(ctx, prov, model, timeout, task, s.Plan, workdir)
		if err != nil {
			return fmt.Errorf("blocker analysis failed: %w", err)
		}

		if blockerJSON {
			data, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		printBlockerReport(report)

		// --apply: annotate the task with the AI recommendation
		if blockerApply {
			annotation := fmt.Sprintf("[ai-blocker] Recommendation: %s. Root cause: %s",
				strings.ToUpper(report.Recommendation), report.RootCause)
			pm.AddAnnotation(task, "ai-blocker", annotation)
			if err := s.Save(); err != nil {
				return fmt.Errorf("saving state: %w", err)
			}
			color.New(color.FgGreen).Printf("\nAnnotation applied to task #%d.\n", task.ID)
		}

		return nil
	},
}

// runBlockerAll scans all non-complete tasks, reports blockers, and optionally annotates them.
func runBlockerAll(ctx context.Context, prov provider.Provider, model string, timeout time.Duration, s *state.ProjectState, workdir string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen)

	cyan.Printf("━━━ cloop task ai-blocker --all ━━━\n\n")

	blocked := blocker.DetectAll(workdir, s.Plan)
	if len(blocked) == 0 {
		green.Printf("No blocked tasks detected across %d tasks.\n", len(s.Plan.Tasks))
		return nil
	}

	red.Printf("%d blocked task(s) detected:\n\n", len(blocked))
	for _, info := range blocked {
		printDetectionBadges(info)
		fmt.Println()
	}

	dim.Printf("Analysing each blocked task with AI...\n\n")

	stateChanged := false
	for _, info := range blocked {
		task := s.Plan.TaskByID(info.TaskID)
		if task == nil {
			continue
		}

		cyan.Printf("  Analysing #%d: %s\n", task.ID, task.Title)

		taskCtx, cancel := context.WithTimeout(ctx, timeout)
		report, err := blocker.Analyze(taskCtx, prov, model, timeout, task, s.Plan, workdir)
		cancel()
		if err != nil {
			color.New(color.FgRed).Printf("  Error: %v\n\n", err)
			continue
		}

		printBlockerReport(report)

		if blockerApply {
			annotation := fmt.Sprintf("[ai-blocker] Recommendation: %s. Root cause: %s",
				strings.ToUpper(report.Recommendation), report.RootCause)
			pm.AddAnnotation(task, "ai-blocker", annotation)
			stateChanged = true
			green.Printf("  Annotation applied to task #%d.\n\n", task.ID)
		}
	}

	if stateChanged {
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
	}

	return nil
}

// printDetectionBadges renders the detection summary for a BlockerInfo.
func printDetectionBadges(info *blocker.BlockerInfo) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)

	red.Printf("  [BLOCKED] ")
	fmt.Printf("Task #%d: %s\n", info.TaskID, info.TaskTitle)

	for _, r := range info.Reasons {
		switch r {
		case blocker.BlockReasonStalled:
			badge := "STALLED"
			if info.StalledSince != nil {
				idle := time.Since(*info.StalledSince).Round(time.Minute)
				badge = fmt.Sprintf("STALLED (%s idle)", idle)
			}
			yellow.Printf("          [%s]\n", badge)
		case blocker.BlockReasonFailedDep:
			depStrs := make([]string, len(info.FailedDeps))
			for i, d := range info.FailedDeps {
				depStrs[i] = fmt.Sprintf("#%d", d)
			}
			yellow.Printf("          [FAILED DEPS: %s]\n", strings.Join(depStrs, ", "))
		case blocker.BlockReasonAnnotation:
			yellow.Printf("          [ANNOTATED AS BLOCKED]\n")
		}
	}
}

// printBlockerReport renders the full AI analysis card to stdout.
func printBlockerReport(report *blocker.BlockerReport) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	sep := strings.Repeat("─", 72)
	fmt.Println(sep)
	bold.Printf("  BLOCKER ANALYSIS — Task #%d\n", report.TaskID)

	title := report.TaskTitle
	if len([]rune(title)) > 64 {
		title = string([]rune(title)[:61]) + "..."
	}
	dim.Printf("  %s\n", title)
	fmt.Println(sep)
	fmt.Println()

	// Root cause
	bold.Printf("  ROOT CAUSE HYPOTHESIS\n\n")
	red.Printf("  ⚠ ")
	for i, line := range wrapText(report.RootCause, 68) {
		if i == 0 {
			fmt.Printf("%s\n", line)
		} else {
			fmt.Printf("    %s\n", line)
		}
	}
	fmt.Println()

	// Unblocking actions
	fmt.Println(sep)
	bold.Printf("  UNBLOCKING ACTIONS\n\n")
	for i, action := range report.Actions {
		yellow.Printf("  %d. ", i+1)
		lines := wrapText(action, 66)
		for j, line := range lines {
			if j == 0 {
				fmt.Printf("%s\n", line)
			} else {
				fmt.Printf("     %s\n", line)
			}
		}
		fmt.Println()
	}

	// Recommendation
	fmt.Println(sep)
	bold.Printf("  RECOMMENDATION\n\n")
	rec := strings.ToUpper(report.Recommendation)
	switch report.Recommendation {
	case "retry":
		green.Printf("  ▶ %s", rec)
	case "skip":
		yellow.Printf("  ⏭ %s", rec)
	case "reassign":
		cyan.Printf("  ↗ %s", rec)
	default:
		fmt.Printf("  %s", rec)
	}
	fmt.Printf("\n\n")

	fmt.Println(sep)
	fmt.Println()
}

func init() {
	taskBlockerCmd.Flags().StringVar(&blockerProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	taskBlockerCmd.Flags().StringVar(&blockerModel, "model", "", "Model override for the AI provider")
	taskBlockerCmd.Flags().StringVar(&blockerTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 90s, 3m)")
	taskBlockerCmd.Flags().BoolVar(&blockerApply, "apply", false, "Auto-annotate the task with the AI recommendation")
	taskBlockerCmd.Flags().BoolVar(&blockerJSON, "json", false, "Output the blocker report as JSON")
	taskBlockerCmd.Flags().BoolVar(&blockerAll, "all", false, "Scan all non-complete tasks and report blockers")

	taskCmd.AddCommand(taskBlockerCmd)
}
