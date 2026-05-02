package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/coach"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	coachProvider string
	coachModel    string
	coachTimeout  string
)

var taskCoachCmd = &cobra.Command{
	Use:   "ai-coach <task-id>",
	Short: "AI expert coaching tips before executing a task",
	Long: `Before executing a task, the AI plays the role of a senior engineer who has
done hundreds of tasks like this. It gives 3-5 concrete, actionable coaching
tips specific to that task: how to approach it well, what to watch out for,
and common pitfalls. Also surfaces the key question to clarify before starting
and concrete success criteria.

This is distinct from 'cloop explain' (which narrates what will happen) —
coaching is prescriptive: here's HOW to do this well.

Examples:
  cloop task ai-coach 3
  cloop task ai-coach 5 --provider anthropic --model claude-opus-4-6
  cloop task ai-coach 7 --timeout 3m`,
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

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := coachProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := coachModel
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
		if coachTimeout != "" {
			timeout, err = time.ParseDuration(coachTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		cyan := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)

		cyan.Printf("━━━ cloop task ai-coach ━━━\n\n")
		dim.Printf("Task #%d: %s\n", task.ID, task.Title)
		dim.Printf("Provider: %s", pName)
		if model != "" {
			dim.Printf(" (%s)", model)
		}
		dim.Printf("\n\n")
		dim.Printf("Generating coaching session...\n\n")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		session, err := coach.Coach(ctx, prov, model, task, s.Plan, workdir)
		if err != nil {
			return fmt.Errorf("coaching failed: %w", err)
		}

		printCoachingCard(session)
		return nil
	},
}

// printCoachingCard renders a colorful coaching card to stdout.
func printCoachingCard(s *coach.CoachingSession) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	magenta := color.New(color.FgMagenta, color.Bold)

	sep := strings.Repeat("─", 72)
	fmt.Println(sep)
	bold.Printf("  COACHING CARD — Task #%d\n", s.TaskID)

	title := s.TaskTitle
	if len([]rune(title)) > 64 {
		title = string([]rune(title)[:61]) + "..."
	}
	dim.Printf("  %s\n", title)
	fmt.Println(sep)
	fmt.Println()

	// Tips
	bold.Printf("  COACHING TIPS\n\n")
	for i, tip := range s.Tips {
		cat := tip.Category
		catColor := categoryColor(cat, green, yellow, red, cyan, magenta)
		catColor.Printf("  [%s]", strings.ToUpper(cat))
		fmt.Printf("  Tip %d\n", i+1)
		for _, line := range wrapCoachText(tip.Advice, 66) {
			fmt.Printf("    %s\n", line)
		}
		fmt.Println()
	}

	// Key question
	if s.KeyQuestion != "" {
		fmt.Println(sep)
		bold.Printf("  KEY QUESTION TO CLARIFY FIRST\n\n")
		yellow.Printf("  ? ")
		for j, line := range wrapCoachText(s.KeyQuestion, 68) {
			if j == 0 {
				fmt.Printf("%s\n", line)
			} else {
				fmt.Printf("    %s\n", line)
			}
		}
		fmt.Println()
	}

	// Success criteria
	if len(s.SuccessCriteria) > 0 {
		fmt.Println(sep)
		bold.Printf("  DONE LOOKS LIKE\n\n")
		for _, criterion := range s.SuccessCriteria {
			green.Printf("  ✓ ")
			lines := wrapText(criterion, 68)
			for j, line := range lines {
				if j == 0 {
					fmt.Printf("%s\n", line)
				} else {
					fmt.Printf("    %s\n", line)
				}
			}
		}
		fmt.Println()
	}

	fmt.Println(sep)
	fmt.Println()
}

func categoryColor(cat string, green, yellow, red, cyan, magenta *color.Color) *color.Color {
	switch strings.ToLower(cat) {
	case "approach":
		return cyan
	case "pitfall":
		return red
	case "quality":
		return green
	case "speed":
		return yellow
	case "security":
		return magenta
	case "testing":
		return green
	default:
		return cyan
	}
}

// wrapCoachText wraps text to the given column width, returning lines.
func wrapCoachText(text string, width int) []string {
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
	taskCoachCmd.Flags().StringVar(&coachProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	taskCoachCmd.Flags().StringVar(&coachModel, "model", "", "Model override for the AI provider")
	taskCoachCmd.Flags().StringVar(&coachTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 90s, 3m)")

	taskCmd.AddCommand(taskCoachCmd)
}
