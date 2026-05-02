package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/microstandup"
	"github.com/blechschmidt/cloop/pkg/notify"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	standupTaskProvider string
	standupTaskModel    string
	standupTaskTimeout  string
	standupTaskSlack    bool
	standupTaskAll      bool
)

var taskStandupCmd = &cobra.Command{
	Use:   "ai-standup [task-id]",
	Short: "Generate a focused micro-standup card for an in-progress task",
	Long: `Generate a per-task micro-standup card with AI-powered blocker detection.

For a single task (supply task-id):
  Collects recent step log lines, checkpoint diff, elapsed vs estimated time,
  heal attempts, and linked PRs/issues. The AI produces:
    • Yesterday summary (what was accomplished)
    • Today plan (next 3 steps)
    • Blockers (specific things preventing progress)
    • Confidence score 1-5 with reasoning

Output is a compact ≤15 line card.

With --all:
  Runs for every in_progress task and aggregates the results.

With --slack:
  Posts the card(s) to the Slack webhook configured in .cloop/config.yaml
  (notify.slack_webhook).

Examples:
  cloop task ai-standup 3
  cloop task ai-standup 3 --slack
  cloop task ai-standup --all
  cloop task ai-standup --all --slack
  cloop task ai-standup 5 --provider anthropic --model claude-opus-4-5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Build provider.
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := standupTaskProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := standupTaskModel
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
		if standupTaskTimeout != "" {
			timeout, err = time.ParseDuration(standupTaskTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		// Resolve which tasks to process.
		var targets []*pm.Task

		if standupTaskAll {
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskInProgress {
					targets = append(targets, t)
				}
			}
			if len(targets) == 0 {
				color.New(color.Faint).Println("No in_progress tasks found.")
				return nil
			}
		} else {
			if len(args) == 0 {
				return fmt.Errorf("specify a task ID or use --all to run for all in_progress tasks")
			}
			var taskID int
			if _, scanErr := fmt.Sscanf(args[0], "%d", &taskID); scanErr != nil {
				return fmt.Errorf("invalid task ID %q: must be a number", args[0])
			}
			var task *pm.Task
			for _, t := range s.Plan.Tasks {
				if t.ID == taskID {
					task = t
					break
				}
			}
			if task == nil {
				return fmt.Errorf("task %d not found", taskID)
			}
			targets = []*pm.Task{task}
		}

		// Collect Slack webhook URL once.
		slackURL := ""
		if standupTaskSlack {
			slackURL = cfg.Notify.SlackWebhook
			if slackURL == "" {
				return fmt.Errorf("--slack requires notify.slack_webhook to be set in .cloop/config.yaml\n" +
					"Run: cloop config set notify.slack_webhook <url>")
			}
		}

		dimColor := color.New(color.Faint)
		headerColor := color.New(color.FgCyan, color.Bold)
		warnColor := color.New(color.FgYellow)
		successColor := color.New(color.FgGreen)
		failColor := color.New(color.FgRed)

		var allCards []*microstandup.Card
		var allSlackText []string

		for i, task := range targets {
			if i > 0 {
				fmt.Println()
			}

			headerColor.Printf("Generating micro-standup for task #%d: %s\n", task.ID, task.Title)

			// Warn if task is not in_progress (allow it anyway for flexibility).
			if task.Status != pm.TaskInProgress {
				warnColor.Printf("  Note: task status is %q (not in_progress)\n", task.Status)
			}

			dimColor.Printf("  Collecting context...\n")

			taskCtx, collectErr := microstandup.Collect(workdir, task, s.Plan.Goal)
			if collectErr != nil {
				failColor.Printf("  Failed to collect context: %v\n", collectErr)
				continue
			}

			dimColor.Printf("  Calling AI (%s)...\n", pName)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			card, genErr := microstandup.Generate(ctx, prov, opts, taskCtx)
			cancel()

			if genErr != nil {
				failColor.Printf("  AI generation failed: %v\n", genErr)
				continue
			}

			allCards = append(allCards, card)

			// Print the card.
			fmt.Println()
			fmt.Print(microstandup.FormatCard(card))

			slackText := microstandup.FormatSlack(card)
			allSlackText = append(allSlackText, slackText)
		}

		// Summary when --all.
		if standupTaskAll && len(allCards) > 1 {
			fmt.Println()
			headerColor.Printf("Aggregate summary: %d in_progress task(s)\n\n", len(allCards))
			blockedCount := 0
			for _, c := range allCards {
				if c.Blockers != "" && c.Blockers != "None" && c.Blockers != "none" {
					blockedCount++
				}
			}
			if blockedCount > 0 {
				warnColor.Printf("  %d task(s) have reported blockers — review above for details.\n", blockedCount)
			} else {
				successColor.Printf("  No blockers reported across %d tasks.\n", len(allCards))
			}
		}

		// Post to Slack.
		if standupTaskSlack && len(allSlackText) > 0 {
			title := "cloop micro-standup"
			if len(allCards) == 1 {
				title = fmt.Sprintf("cloop micro-standup: Task #%d", allCards[0].TaskID)
			} else {
				title = fmt.Sprintf("cloop micro-standup: %d tasks", len(allCards))
			}
			body := ""
			for j, text := range allSlackText {
				if j > 0 {
					body += "\n\n---\n\n"
				}
				body += text
			}
			dimColor.Printf("\nPosting to Slack...\n")
			if slackErr := notify.SendWebhook(slackURL, title, body); slackErr != nil {
				warnColor.Printf("Slack post failed: %v\n", slackErr)
			} else {
				successColor.Printf("Posted to Slack.\n")
			}
		}

		return nil
	},
}

func init() {
	taskStandupCmd.Flags().StringVar(&standupTaskProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	taskStandupCmd.Flags().StringVar(&standupTaskModel, "model", "", "Model override for the AI provider")
	taskStandupCmd.Flags().StringVar(&standupTaskTimeout, "timeout", "3m", "Timeout per AI call (e.g. 2m, 90s)")
	taskStandupCmd.Flags().BoolVar(&standupTaskSlack, "slack", false, "Post standup card(s) to configured Slack webhook")
	taskStandupCmd.Flags().BoolVar(&standupTaskAll, "all", false, "Generate standups for all in_progress tasks")
	taskCmd.AddCommand(taskStandupCmd)
}
