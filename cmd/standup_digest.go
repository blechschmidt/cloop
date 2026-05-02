package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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
	digestSince    string
	digestFormat   string
	digestPost     bool
	digestProvider string
	digestModel    string
	digestTimeout  string
	digestSave     bool
)

var standupDigestCmd = &cobra.Command{
	Use:   "digest",
	Short: "Generate a team-facing AI standup digest across all active tasks",
	Long: `Aggregate per-task micro-standup data for all tasks updated in the given
window, then ask the AI to write a concise team-facing digest covering:

  • What was done
  • What's in progress (with per-task confidence)
  • Blockers
  • Next priorities

Output formats:
  markdown   Plain Markdown suitable for Confluence, Notion, or GitHub (default)
  slack      Slack Block Kit JSON payload — ready to POST to an Incoming Webhook
  email      Self-contained HTML email body

The digest can be printed to stdout or POSTed to a configured Slack webhook.

Examples:
  cloop standup digest                          # last 24h, markdown
  cloop standup digest --since 48h              # look back 48 hours
  cloop standup digest --format slack           # Slack Block Kit JSON
  cloop standup digest --format email           # HTML email body
  cloop standup digest --format slack --post    # POST Block Kit to Slack webhook
  cloop standup digest --save                   # save to .cloop/digest-DATE.md`,
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

		// Parse --since into hours (overrides default 24h).
		windowHours := 24
		if digestSince != "" {
			d, parseErr := parseSinceDuration(digestSince)
			if parseErr != nil {
				return fmt.Errorf("--since: %w", parseErr)
			}
			windowHours = int(d.Hours())
			if windowHours < 1 {
				windowHours = 1
			}
		}

		// Normalise format.
		switch strings.ToLower(digestFormat) {
		case "slack", "email", "markdown", "":
			digestFormat = strings.ToLower(digestFormat)
		default:
			return fmt.Errorf("--format must be one of: markdown, slack, email")
		}

		// Build provider.
		pName := digestProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := digestModel
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

		timeout := 5 * time.Minute
		if digestTimeout != "" {
			timeout, err = time.ParseDuration(digestTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
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

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		goodColor := color.New(color.FgGreen)
		warnColor := color.New(color.FgYellow)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()

		headerColor.Printf("\n  Standup Digest — %s\n", time.Now().Format("Mon Jan 2, 2006"))
		fmt.Printf("  Project: %s\n", truncate(s.Goal, 70))
		fmt.Printf("  Window:  Last %dh | Provider: %s | Format: %s\n\n",
			windowHours, pName, digestFormat)

		dimColor.Println("  Collecting per-task context and generating micro-standups...")

		digest, err := standup.GenerateDigest(ctx, prov, opts, workdir, s, windowHours)
		if err != nil {
			return fmt.Errorf("generating digest: %w", err)
		}

		dimColor.Printf("  Tasks in window: %d completed, %d failed, %d in-progress\n\n",
			len(digest.CompletedTasks), len(digest.FailedTasks), len(digest.Cards))

		// Render output.
		var output string
		switch digestFormat {
		case "slack":
			output = standup.FormatDigestSlack(digest)
		case "email":
			output = standup.FormatDigestEmail(digest)
		default:
			output = standup.FormatDigestMarkdown(digest)
		}

		fmt.Println(output)

		// Save to file if requested.
		if digestSave {
			ext := "md"
			if digestFormat == "email" {
				ext = "html"
			} else if digestFormat == "slack" {
				ext = "json"
			}
			filename := fmt.Sprintf(".cloop/digest-%s.%s", time.Now().Format("2006-01-02"), ext)
			if writeErr := os.WriteFile(filename, []byte(output), 0o644); writeErr != nil {
				warnColor.Printf("Warning: could not save digest: %v\n", writeErr)
			} else {
				goodColor.Printf("Saved to %s\n", filename)
			}
		}

		// POST to Slack webhook if requested.
		if digestPost {
			slackURL := cfg.Notify.SlackWebhook
			if slackURL == "" {
				slackURL = cfg.Webhook.URL
			}
			if slackURL == "" {
				return fmt.Errorf("--post requires notify.slack_webhook (or webhook.url) in .cloop/config.yaml\n" +
					"Set it with: cloop config set notify.slack_webhook <url>")
			}

			dimColor.Printf("  Posting Block Kit payload to Slack...\n")
			postCtx, postCancel := context.WithTimeout(ctx, 15*time.Second)
			postErr := standup.PostDigestToSlack(postCtx, slackURL, digest)
			postCancel()
			if postErr != nil {
				warnColor.Printf("  Slack post failed: %v\n", postErr)
			} else {
				trunc := slackURL
				if len(trunc) > 50 {
					trunc = trunc[:50] + "..."
				}
				goodColor.Printf("  Posted to %s\n", trunc)
			}
		}

		return nil
	},
}

func init() {
	standupDigestCmd.Flags().StringVar(&digestSince, "since", "24h", "Lookback window as duration (e.g. 24h, 48h, 7d)")
	standupDigestCmd.Flags().StringVar(&digestFormat, "format", "markdown", "Output format: markdown, slack, email")
	standupDigestCmd.Flags().BoolVar(&digestPost, "post", false, "POST Block Kit payload to configured Slack webhook")
	standupDigestCmd.Flags().StringVar(&digestProvider, "provider", "", "AI provider override")
	standupDigestCmd.Flags().StringVar(&digestModel, "model", "", "Model override")
	standupDigestCmd.Flags().StringVar(&digestTimeout, "timeout", "5m", "Per-AI-call timeout (e.g. 3m, 90s)")
	standupDigestCmd.Flags().BoolVar(&digestSave, "save", false, "Save digest to .cloop/digest-DATE.<ext>")
	standupCmd.AddCommand(standupDigestCmd)
}
