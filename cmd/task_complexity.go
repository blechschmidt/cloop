package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/complexity"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	complexityProvider string
	complexityModel    string
	complexityApply    bool
	complexitySize     string // manual override: XS/S/M/L/XL
	complexityTimeout  string
)

var taskComplexityCmd = &cobra.Command{
	Use:   "ai-complexity [task-id]",
	Short: "AI T-shirt size complexity estimation for a task",
	Long: `Ask the AI to assign a T-shirt size (XS/S/M/L/XL) and Fibonacci story points
(1/2/3/5/8/13) to a task based on its description, dependencies, and up to 5
completed tasks from plan history used as calibration anchors.

With --apply, the complexity size and story points are written to the task and
stored in state (visible in 'cloop status' and used by 'cloop sprint plan').

With --size <XS|S|M|L|XL>, the AI is bypassed and the given size is applied
directly (useful for manual estimation or CI overrides).

Examples:
  cloop task ai-complexity 3
  cloop task ai-complexity 3 --apply
  cloop task ai-complexity 3 --size M --apply
  cloop task ai-complexity 3 --provider anthropic --model claude-opus-4-6`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		taskID, err := strconv.Atoi(args[0])
		if err != nil || taskID < 1 {
			return fmt.Errorf("invalid task-id: %s", args[0])
		}

		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		task := s.Plan.TaskByID(taskID)
		if task == nil {
			return fmt.Errorf("task #%d not found", taskID)
		}

		// Manual size override — no AI needed
		if complexitySize != "" {
			upper := strings.ToUpper(strings.TrimSpace(complexitySize))
			if !complexity.IsValidSize(upper) {
				return fmt.Errorf("invalid size %q — must be one of: XS, S, M, L, XL", complexitySize)
			}
			pts := complexity.PointsForSize(upper)
			est := &complexity.ComplexityEstimate{
				TaskID:      task.ID,
				TaskTitle:   task.Title,
				Size:        upper,
				StoryPoints: pts,
				Rationale:   "Manually assigned via --size flag.",
				Confidence:  "high",
			}
			printComplexityCard(est)
			if complexityApply {
				applyComplexity(task, est)
				if err := s.Save(); err != nil {
					return fmt.Errorf("saving state: %w", err)
				}
				color.New(color.FgGreen).Printf("Complexity %s (%d pts) applied to task #%d.\n", upper, pts, taskID)
			}
			return nil
		}

		// AI estimation path
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := complexityProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := complexityModel
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

		timeout := 2 * time.Minute
		if complexityTimeout != "" {
			timeout, err = time.ParseDuration(complexityTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)

		cyan.Printf("━━━ cloop task ai-complexity ━━━\n\n")
		dim.Printf("Task #%d: %s\n", task.ID, task.Title)
		dim.Printf("Provider: %s", pName)
		if model != "" {
			dim.Printf(" (%s)", model)
		}
		dim.Printf("\n\n")
		dim.Printf("Collecting calibration samples from completed tasks...\n")

		samples := complexity.SelectCalibrationSamples(s.Plan, 5)
		dim.Printf("Calibration samples: %d completed tasks\n\n", len(samples))
		dim.Printf("Calling AI for complexity estimate...\n\n")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		est, err := complexity.Estimate(ctx, prov, model, task, s.Plan, samples)
		if err != nil {
			return fmt.Errorf("complexity estimation failed: %w", err)
		}

		printComplexityCard(est)

		if complexityApply {
			applyComplexity(task, est)
			if err := s.Save(); err != nil {
				return fmt.Errorf("saving state: %w", err)
			}
			color.New(color.FgGreen).Printf("Complexity %s (%d pts) applied to task #%d and saved.\n",
				est.Size, est.StoryPoints, taskID)
		} else {
			dim.Printf("Use --apply to store this complexity on the task.\n")
		}

		return nil
	},
}

// applyComplexity writes the estimate into the task fields and adds an annotation.
func applyComplexity(task *pm.Task, est *complexity.ComplexityEstimate) {
	task.ComplexitySize = est.Size
	task.StoryPoints = est.StoryPoints
	annotation := fmt.Sprintf("AI Complexity: %s (%d pts, confidence=%s) — %s",
		est.Size, est.StoryPoints, est.Confidence, est.Rationale)
	if len(est.SimilarTasks) > 0 {
		annotation += fmt.Sprintf(" | Similar: %s", strings.Join(est.SimilarTasks, "; "))
	}
	pm.AddAnnotation(task, "ai-complexity", annotation)
}

// printComplexityCard renders a colorful single-task complexity card.
func printComplexityCard(est *complexity.ComplexityEstimate) {
	sizeColor := complexitySizeColor(est.Size)
	confColor := complexityConfidenceColor(est.Confidence)
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	sep := strings.Repeat("─", 72)
	fmt.Println(sep)

	// Header row
	bold.Printf("  Task #%-4d  ", est.TaskID)
	title := est.TaskTitle
	if len([]rune(title)) > 44 {
		title = string([]rune(title)[:41]) + "..."
	}
	fmt.Printf("%-46s\n", title)

	fmt.Println(sep)

	// Size + points
	bold.Printf("  Size:        ")
	sizeColor.Printf("%-4s", est.Size)
	dim.Printf("  (%s)\n", sizeDescription(est.Size))

	bold.Printf("  Story Points: ")
	sizeColor.Printf("%d\n", est.StoryPoints)

	bold.Printf("  Confidence:  ")
	confColor.Printf("%s\n", est.Confidence)

	if est.Rationale != "" {
		bold.Printf("  Rationale:\n")
		for _, line := range wrapLines(est.Rationale, 64) {
			fmt.Printf("    %s\n", line)
		}
	}

	if len(est.SimilarTasks) > 0 {
		bold.Printf("  Similar tasks used as reference:\n")
		for _, title := range est.SimilarTasks {
			dim.Printf("    • %s\n", title)
		}
	}

	fmt.Println(sep)
	fmt.Println()

	// Legend row
	dim.Printf("  Scale: ")
	for i, sz := range []string{"XS", "S", "M", "L", "XL"} {
		pts := complexity.PointsForSize(sz)
		if i > 0 {
			dim.Printf(" │ ")
		}
		c := complexitySizeColor(sz)
		c.Printf("%s(%dpt)", sz, pts)
	}
	fmt.Println()
	fmt.Println()
}

func sizeDescription(size string) string {
	switch size {
	case "XS":
		return "trivial, < 30 min"
	case "S":
		return "small, ~1 hour"
	case "M":
		return "medium, 2-4 hours"
	case "L":
		return "large, 4-8 hours"
	case "XL":
		return "extra-large, > 1 day"
	default:
		return ""
	}
}

func complexitySizeColor(size string) *color.Color {
	switch size {
	case "XS":
		return color.New(color.FgGreen, color.Bold)
	case "S":
		return color.New(color.FgGreen)
	case "M":
		return color.New(color.FgYellow)
	case "L":
		return color.New(color.FgRed)
	case "XL":
		return color.New(color.FgRed, color.Bold)
	default:
		return color.New(color.Reset)
	}
}

func complexityConfidenceColor(conf string) *color.Color {
	switch conf {
	case "high":
		return color.New(color.FgGreen)
	case "medium":
		return color.New(color.FgYellow)
	case "low":
		return color.New(color.FgRed)
	default:
		return color.New(color.Reset)
	}
}

// wrapLines splits text into lines of at most width runes.
func wrapLines(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len([]rune(line))+1+len([]rune(w)) <= width {
			line += " " + w
		} else {
			lines = append(lines, line)
			line = w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func init() {
	taskComplexityCmd.Flags().StringVar(&complexityProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	taskComplexityCmd.Flags().StringVar(&complexityModel, "model", "", "Model override for the AI provider")
	taskComplexityCmd.Flags().StringVar(&complexityTimeout, "timeout", "2m", "Timeout for the AI call (e.g. 90s, 3m)")
	taskComplexityCmd.Flags().BoolVar(&complexityApply, "apply", false, "Write complexity size and story points back to the task")
	taskComplexityCmd.Flags().StringVar(&complexitySize, "size", "", "Manual size override (XS/S/M/L/XL) — skips AI, implies --apply when combined")

	taskCmd.AddCommand(taskComplexityCmd)
}
