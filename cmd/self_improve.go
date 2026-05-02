package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/selfimprove"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	selfImproveProvider string
	selfImproveModel    string
	selfImproveInject   bool
	selfImproveDryRun   bool
	selfImproveSourceDir string
)

var selfImproveCmd = &cobra.Command{
	Use:   "self-improve",
	Short: "AI analysis of cloop's own performance bottlenecks and improvement opportunities",
	Long: `self-improve is a meta-command: cloop analyzes its own execution telemetry and
source code to propose concrete code improvements ranked by impact.

It collects:
  - Execution metrics from the last cloop run (.cloop/metrics.json)
  - Per-task analytics (failure rates, heal attempts, slow tasks)
  - Prompt statistics (high-failure prompt patterns)
  - Checkpoint state (interrupted runs indicate reliability issues)
  - The cloop source tree (when --source-dir is set or auto-detected)

The AI returns a ranked list of improvement suggestions with file:line citations.
Use --inject to automatically add the suggestions as PM tasks for execution.

Examples:
  cloop self-improve
  cloop self-improve --inject
  cloop self-improve --dry-run
  cloop self-improve --source-dir ~/src/cloop --provider anthropic`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Load state (optional — we can still analyse without a plan)
		s, _ := state.Load(workdir)

		cfg, err := config.Load(workdir)
		if err != nil {
			cfg = &config.Config{}
		}
		applyEnvOverrides(cfg)

		// Resolve provider
		pName := selfImproveProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s != nil && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		// Resolve model
		model := selfImproveModel
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
		if model == "" && s != nil {
			model = s.Model
		}

		// Resolve source directory (cloop's own source)
		sourceDir := selfImproveSourceDir
		if sourceDir == "" {
			// Try to auto-detect: walk up from binary or use executable path
			sourceDir = detectSourceDir()
		}

		// Build provider
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

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		boldColor := color.New(color.Bold)
		greenColor := color.New(color.FgGreen)
		yellowColor := color.New(color.FgYellow)
		redColor := color.New(color.FgRed)
		cyanColor := color.New(color.FgCyan)
		magentaColor := color.New(color.FgMagenta)
		sep := strings.Repeat("─", 72)

		headerColor.Printf("\ncloop self-improve — meta-feedback analysis\n")
		fmt.Println(sep)
		dimColor.Printf("Provider: %s", prov.Name())
		if model != "" {
			dimColor.Printf(" / Model: %s", model)
		}
		fmt.Println()
		if sourceDir != "" {
			dimColor.Printf("Source:   %s\n", sourceDir)
		}
		fmt.Println()

		// Collect telemetry
		dimColor.Printf("Collecting telemetry...")
		t := selfimprove.CollectTelemetry(s, workdir, sourceDir, model)
		fmt.Printf(" done.\n")

		// Print telemetry summary
		boldColor.Printf("Telemetry summary:\n")
		if t.MetricsSummary != nil {
			ms := t.MetricsSummary
			fmt.Printf("  Metrics:  tasks=%d  completed=%d  failed=%d  steps=%d\n",
				ms.TasksTotal, ms.TasksCompleted, ms.TasksFailed, ms.StepsTotal)
		} else {
			dimColor.Printf("  Metrics:  no .cloop/metrics.json found\n")
		}
		if t.AggStats != nil && t.AggStats.TotalTasks > 0 {
			agg := t.AggStats
			fmt.Printf("  Tasks:    total=%d  done=%d  failed=%d  heals=%d\n",
				agg.TotalTasks, agg.DoneTasks, agg.FailedTasks, agg.TotalHealAttempts)
		} else {
			dimColor.Printf("  Tasks:    no plan data\n")
		}
		if t.PromptStats.Total > 0 {
			ps := t.PromptStats
			failRate := float64(ps.Failed) / float64(ps.Total) * 100
			fmt.Printf("  Prompts:  total=%d  failure_rate=%.1f%%\n", ps.Total, failRate)
		} else {
			dimColor.Printf("  Prompts:  no prompt-stats.jsonl found\n")
		}
		if t.CheckpointExists {
			yellowColor.Printf("  Checkpoint: interrupted run found (task_id=%d)\n", t.CheckpointTaskID)
		}
		fmt.Println()

		// Build prompt
		prompt := selfimprove.BuildPrompt(t, sourceDir)

		if selfImproveDryRun {
			boldColor.Printf("Prompt preview (--dry-run):\n")
			lines := strings.Split(prompt, "\n")
			limit := 40
			if len(lines) < limit {
				limit = len(lines)
			}
			for _, l := range lines[:limit] {
				dimColor.Printf("  %s\n", l)
			}
			if len(lines) > 40 {
				dimColor.Printf("  ... (%d more lines)\n", len(lines)-40)
			}
			fmt.Println()
			dimColor.Printf("  Run without --dry-run to call the AI.\n\n")
			return nil
		}

		// Call AI
		dimColor.Printf("Calling %s for self-improvement analysis...\n\n", prov.Name())
		ctx := context.Background()
		suggestions, err := selfimprove.Analyze(ctx, prov, model, 3*time.Minute, prompt)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		// Display results
		fmt.Println(sep)
		headerColor.Printf("  Self-Improvement Suggestions (%d)\n", len(suggestions))
		fmt.Println(sep)
		fmt.Println()

		for _, sg := range suggestions {
			// Rank badge
			rankStr := fmt.Sprintf("[#%d]", sg.Rank)
			boldColor.Printf("  %s ", rankStr)

			// Category color
			catColor := cyanColor
			switch sg.Category {
			case "performance":
				catColor = yellowColor
			case "error_handling":
				catColor = redColor
			case "reliability":
				catColor = redColor
			case "ux":
				catColor = magentaColor
			case "testing":
				catColor = cyanColor
			}
			catColor.Printf("[%s]", sg.Category)

			// Impact/effort
			impactColor := greenColor
			if sg.Impact == "high" {
				impactColor = redColor
			} else if sg.Impact == "medium" {
				impactColor = yellowColor
			}
			impactColor.Printf(" impact:%s", sg.Impact)
			dimColor.Printf(" effort:%s\n", sg.Effort)

			// Title
			boldColor.Printf("  %s\n", sg.Title)

			// File citation
			if sg.FileCitation != "" {
				cyanColor.Printf("  → %s\n", sg.FileCitation)
			}

			// Description (word-wrapped at ~70 chars)
			if sg.Description != "" {
				for _, line := range selfImproveWrapText(sg.Description, 68) {
					fmt.Printf("  %s\n", line)
				}
			}
			fmt.Println()
		}

		fmt.Println(sep)

		if selfImproveInject {
			// Inject suggestions as PM tasks
			if s == nil {
				s = &state.ProjectState{WorkDir: workdir}
			}
			if !s.PMMode {
				s.PMMode = true
			}
			if s.Plan == nil {
				s.Plan = pm.NewPlan("cloop self-improvement")
			}

			maxID := 0
			for _, task := range s.Plan.Tasks {
				if task.ID > maxID {
					maxID = task.ID
				}
			}

			added := 0
			for _, sg := range suggestions {
				maxID++
				desc := sg.Description
				if sg.FileCitation != "" {
					desc = fmt.Sprintf("%s\n\nSee: %s", desc, sg.FileCitation)
				}
				task := &pm.Task{
					ID:          maxID,
					Title:       fmt.Sprintf("[self-improve] %s", sg.Title),
					Description: desc,
					Priority:    suggestionImpactToPriority(sg.Impact),
					Status:      pm.TaskPending,
					Tags:        []string{"self-improve", sg.Category},
				}
				s.Plan.Tasks = append(s.Plan.Tasks, task)
				added++
			}

			if err := s.Save(); err != nil {
				return fmt.Errorf("saving state: %w", err)
			}

			greenColor.Printf("  Injected %d suggestion(s) as PM tasks.\n", added)
			dimColor.Printf("  Run 'cloop run --pm' to execute them.\n\n")
		} else {
			dimColor.Printf("  Use --inject to add these as PM tasks.\n\n")
		}

		return nil
	},
}

// suggestionImpactToPriority maps AI suggestion impact to PM task priority (1=highest).
func suggestionImpactToPriority(impact string) int {
	switch impact {
	case "high":
		return 1
	case "medium":
		return 3
	default:
		return 5
	}
}

// detectSourceDir tries to find the cloop source directory.
// It checks common locations relative to the running binary and GOPATH.
func detectSourceDir() string {
	// 1. Try the GOPATH module cache path based on module name
	home, _ := os.UserHomeDir()
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = filepath.Join(home, "go")
	}

	// 2. Use runtime caller to find source location (works in development)
	_, file, _, ok := runtime.Caller(0)
	if ok {
		// file is like /root/Projects/cloop/cmd/self_improve.go
		// We want /root/Projects/cloop
		dir := filepath.Dir(filepath.Dir(file))
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}

	// 3. Check current working directory
	cwd, _ := os.Getwd()
	if _, err := os.Stat(filepath.Join(cwd, "go.mod")); err == nil {
		return cwd
	}

	// 4. Try executable directory
	exe, _ := os.Executable()
	if exe != "" {
		dir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		// One level up (e.g., binary in build/ subdirectory)
		parent := filepath.Dir(dir)
		if _, err := os.Stat(filepath.Join(parent, "go.mod")); err == nil {
			return parent
		}
	}

	_ = gopath // suppress unused warning
	return ""
}

// selfImproveWrapText wraps a string to the given width, returning lines.
func selfImproveWrapText(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	current := ""
	for _, w := range words {
		if current == "" {
			current = w
		} else if len(current)+1+len(w) <= width {
			current += " " + w
		} else {
			lines = append(lines, current)
			current = w
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func init() {
	selfImproveCmd.Flags().StringVar(&selfImproveProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	selfImproveCmd.Flags().StringVar(&selfImproveModel, "model", "", "Model to use")
	selfImproveCmd.Flags().BoolVar(&selfImproveInject, "inject", false, "Inject suggestions as PM tasks for execution")
	selfImproveCmd.Flags().BoolVar(&selfImproveDryRun, "dry-run", false, "Show prompt preview without calling AI")
	selfImproveCmd.Flags().StringVar(&selfImproveSourceDir, "source-dir", "", "Path to cloop source directory for deeper analysis")
	rootCmd.AddCommand(selfImproveCmd)
}
