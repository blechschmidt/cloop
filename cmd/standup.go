package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/standup"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	standupProvider string
	standupModel    string
	standupHours    int
	standupFormat   string
	standupPost     bool
	standupSave     bool
	standupQuick    bool
)

var standupCmd = &cobra.Command{
	Use:   "standup",
	Short: "Generate an AI-powered daily standup report",
	Long: `Standup analyzes recent project activity and generates a structured
daily standup report: what was accomplished, what's planned next,
blockers, and a delivery forecast.

Reports can be posted to Slack via a configured webhook URL and/or
saved to .cloop/standup-YYYYMMDD.md.

Examples:
  cloop standup                           # AI standup (last 24h)
  cloop standup --hours 48                # look back 48 hours
  cloop standup --quick                   # metrics only, no AI
  cloop standup --post                    # post to Slack webhook
  cloop standup --save                    # save to .cloop/standup-DATE.md
  cloop standup --format slack            # Slack-formatted output
  cloop standup --provider anthropic      # use specific provider`,
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

		headerColor := color.New(color.FgCyan, color.Bold)
		boldColor := color.New(color.Bold)
		dimColor := color.New(color.Faint)
		goodColor := color.New(color.FgGreen)
		warnColor := color.New(color.FgYellow)
		badColor := color.New(color.FgRed)

		// Build the standup data (no AI needed for quick mode)
		r := standup.Build(s, standupHours)

		// Print header
		headerColor.Printf("\n  Daily Standup — %s\n", r.GeneratedAt.Format("Monday, January 2 2006"))
		fmt.Printf("  Project: %s\n", truncate(s.Goal, 70))
		fmt.Printf("  Window:  Last %dh | Provider: %s\n\n", standupHours, func() string {
			p := s.Provider
			if p == "" {
				p = "claudecode"
			}
			return p
		}())

		// Quick metrics summary
		m := r.Metrics
		fmt.Printf("  Progress: %d%% (%d/%d tasks)", m.CompletionPct(), m.DoneTasks, m.TotalTasks)
		if m.VelocityPerDay > 0 {
			fmt.Printf(" • Velocity: %.1f/day", m.VelocityPerDay)
		}
		if m.EstimatedDaysRemaining >= 0 {
			fmt.Printf(" • ETA: ~%.0fd", m.EstimatedDaysRemaining)
		}
		fmt.Println()

		riskLabel := m.RiskLabel()
		riskCol := goodColor
		if riskLabel == "HIGH" || riskLabel == "CRITICAL" {
			riskCol = badColor
		} else if riskLabel == "MEDIUM" {
			riskCol = warnColor
		}
		fmt.Printf("  Risk: ")
		riskCol.Printf("%s (%d/100)\n", riskLabel, m.RiskScore)
		fmt.Println()

		// Activity summary
		if len(r.CompletedTasks) > 0 {
			goodColor.Printf("  Completed in last %dh:\n", standupHours)
			for _, t := range r.CompletedTasks {
				dimColor.Printf("    ✓ [%s] %s\n", t.Role, t.Title)
			}
			fmt.Println()
		}
		if len(r.FailedTasks) > 0 {
			badColor.Printf("  Failed in last %dh:\n", standupHours)
			for _, t := range r.FailedTasks {
				dimColor.Printf("    ✗ %s\n", t.Title)
			}
			fmt.Println()
		}
		if len(r.InProgressTasks) > 0 {
			warnColor.Printf("  In Progress:\n")
			for _, t := range r.InProgressTasks {
				dimColor.Printf("    ● [%s] %s\n", t.Role, t.Title)
			}
			fmt.Println()
		}
		if len(r.BlockedTasks) > 0 {
			badColor.Printf("  Blocked:\n")
			for _, t := range r.BlockedTasks {
				dimColor.Printf("    ⊘ %s\n", t.Title)
			}
			fmt.Println()
		}
		if len(r.NextTasks) > 0 {
			boldColor.Printf("  Up Next:\n")
			for _, t := range r.NextTasks {
				dimColor.Printf("    → [P%d, %s] %s\n", t.Priority, t.Role, t.Title)
			}
			fmt.Println()
		}

		if standupQuick {
			return nil
		}

		// AI generation
		provName := standupProvider
		if provName == "" {
			provName = cfg.Provider
		}
		if provName == "" {
			provName = autoSelectProvider()
		}

		model := standupModel
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

		headerColor.Printf("  AI Standup Report  (provider: %s)\n", provName)
		fmt.Println(strings.Repeat("─", 60))
		fmt.Printf("ai> ")

		// Stream tokens to terminal
		var aiOutput strings.Builder
		onToken := func(tok string) {
			fmt.Print(tok)
			aiOutput.WriteString(tok)
		}

		report, err := standup.Generate(ctx, prov, s, model, standupHours, 5*time.Minute, onToken)
		if err != nil {
			return fmt.Errorf("generating standup: %w", err)
		}

		// If we streamed, aiOutput has the content; otherwise use report.AIText
		if aiOutput.Len() == 0 {
			fmt.Print(report.AIText)
		}
		fmt.Println("\n")

		dimColor.Printf("Generated at %s using %s\n\n", report.GeneratedAt.Format("2006-01-02 15:04:05"), provName)

		// Save to file if requested
		if standupSave {
			filename := fmt.Sprintf(".cloop/standup-%s.md", time.Now().Format("2006-01-02"))
			content := standup.FormatText(report, s.Goal, standupHours)
			if err := os.WriteFile(filepath.Join(workdir, filename), []byte(content), 0o644); err != nil {
				warnColor.Printf("Warning: could not save standup: %v\n", err)
			} else {
				goodColor.Printf("Saved to %s\n\n", filename)
			}
		}

		// Post to Slack/webhook if requested
		if standupPost {
			webhookURL := cfg.Webhook.URL
			if webhookURL == "" {
				return fmt.Errorf("--post requires webhook.url in .cloop/config.yaml\nSet it with: cloop config set webhook.url <url>")
			}

			var body string
			if strings.Contains(webhookURL, "hooks.slack.com") || standupFormat == "slack" {
				slackText := standup.FormatSlack(report, s.Goal, standupHours)
				b, _ := json.Marshal(map[string]string{"text": slackText})
				body = string(b)
			} else {
				b, _ := json.Marshal(map[string]interface{}{
					"event":     "standup",
					"goal":      s.Goal,
					"timestamp": report.GeneratedAt,
					"report":    report.AIText,
					"metrics": map[string]interface{}{
						"completion_pct": m.CompletionPct(),
						"velocity":       m.VelocityPerDay,
						"risk_label":     m.RiskLabel(),
						"risk_score":     m.RiskScore,
					},
				})
				body = string(b)
			}

			postCtx, postCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer postCancel()
			req, err := http.NewRequestWithContext(postCtx, "POST", webhookURL, bytes.NewBufferString(body))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("User-Agent", "cloop/1.0")
				for k, v := range cfg.Webhook.Headers {
					req.Header.Set(k, v)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					warnColor.Printf("Warning: webhook post failed: %v\n", err)
				} else {
					resp.Body.Close()
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						trunc := webhookURL
					if len(trunc) > 40 {
						trunc = trunc[:40]
					}
					goodColor.Printf("Posted to webhook (%s)\n\n", trunc)
					} else {
						warnColor.Printf("Warning: webhook returned %d\n", resp.StatusCode)
					}
				}
			}
		}

		return nil
	},
}

func init() {
	standupCmd.Flags().StringVar(&standupProvider, "provider", "", "AI provider")
	standupCmd.Flags().StringVar(&standupModel, "model", "", "Model to use")
	standupCmd.Flags().IntVar(&standupHours, "hours", 24, "Reporting window in hours")
	standupCmd.Flags().StringVar(&standupFormat, "format", "text", "Output format: text, slack")
	standupCmd.Flags().BoolVar(&standupPost, "post", false, "Post to configured webhook/Slack")
	standupCmd.Flags().BoolVar(&standupSave, "save", false, "Save to .cloop/standup-YYYYMMDD.md")
	standupCmd.Flags().BoolVar(&standupQuick, "quick", false, "Show activity summary only, skip AI")
	rootCmd.AddCommand(standupCmd)
}
