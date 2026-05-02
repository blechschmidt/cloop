package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/changelog"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	changelogProvider string
	changelogModel    string
	changelogSince    string // step number or date
	changelogFormat   string // "markdown" or "json"
	changelogOutput   string // output file path
	changelogDryRun   bool
)

var changelogCmd = &cobra.Command{
	Use:   "changelog",
	Short: "AI-generated CHANGELOG from task and step history",
	Long: `Generate a human-readable CHANGELOG by asking the AI to synthesize
completed tasks and execution history from the current cloop session.

The AI groups entries by milestone (if milestones exist) and organizes them
into standard Keep-a-Changelog sections (Added, Changed, Fixed, etc.).

By default the output is appended to CHANGELOG.md in the working directory.
Use --dry-run to print to stdout instead.

Examples:
  cloop changelog                          # generate and append to CHANGELOG.md
  cloop changelog --dry-run                # print to stdout, no file written
  cloop changelog --since 5               # only include steps/tasks from step 5 onward
  cloop changelog --since 2024-01-01      # only include work after a date
  cloop changelog --format json           # emit JSON instead of markdown
  cloop changelog --output CHANGES.md     # write to a custom file
  cloop changelog --provider anthropic    # use a specific provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

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
		pName := changelogProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := changelogModel
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

		// Resolve --since to a step index
		sinceStep := parseSince(changelogSince, s.Steps)

		// Validate format
		format := strings.ToLower(changelogFormat)
		if format != "markdown" && format != "md" && format != "json" {
			return fmt.Errorf("unknown format %q: supported formats are markdown, json", changelogFormat)
		}
		if format == "md" {
			format = "markdown"
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Printf("\nGenerating CHANGELOG with %s...\n", prov.Name())
		dimColor.Printf("Goal: %s\n\n", truncate(s.Goal, 80))

		prompt := changelog.BuildPrompt(s, sinceStep, format)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		raw, err := changelog.Generate(ctx, prov, prompt, model, 3*time.Minute)
		if err != nil {
			return fmt.Errorf("changelog generation failed: %w", err)
		}

		var output string
		switch format {
		case "json":
			result, err := changelog.ParseJSON(raw)
			if err != nil {
				// Fall back to raw output with a warning
				color.New(color.FgYellow).Printf("Warning: could not parse JSON response (%v); printing raw output.\n\n", err)
				output = raw
			} else {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshalling changelog JSON: %w", err)
				}
				output = string(data) + "\n"
			}
		default: // markdown
			output = raw
			// Ensure the content ends with a newline
			if !strings.HasSuffix(output, "\n") {
				output += "\n"
			}
		}

		// Dry-run: print to stdout only
		if changelogDryRun {
			fmt.Print(output)
			return nil
		}

		// Determine output file
		outFile := changelogOutput
		if outFile == "" {
			outFile = "CHANGELOG.md"
		}

		// For markdown, append a header separator before appending
		if format == "markdown" {
			output = prependChangelogHeader(output)
		}

		// Append to file (create if missing)
		if err := appendToFile(outFile, output); err != nil {
			return fmt.Errorf("writing changelog: %w", err)
		}

		color.New(color.FgGreen, color.Bold).Printf("CHANGELOG appended to %s\n", outFile)
		return nil
	},
}

// parseSince converts the --since flag value to a step index.
// It accepts:
//   - a plain integer: treat as step number (0-based)
//   - a date string (YYYY-MM-DD): return the index of the first step on/after that date
//   - empty string: return 0 (all steps)
func parseSince(since string, steps []state.StepResult) int {
	if since == "" {
		return 0
	}

	// Try integer first
	if n, err := strconv.Atoi(since); err == nil {
		if n < 0 {
			return 0
		}
		return n
	}

	// Try date
	t, err := time.Parse("2006-01-02", since)
	if err != nil {
		// Unrecognised format — include everything
		return 0
	}

	for _, step := range steps {
		if !step.Time.Before(t) {
			return step.Step
		}
	}
	return len(steps) // nothing matches → empty range
}

// prependChangelogHeader adds a generation notice before the AI content.
func prependChangelogHeader(content string) string {
	notice := fmt.Sprintf("<!-- Generated by cloop changelog on %s -->\n\n",
		time.Now().Format("2006-01-02 15:04:05"))
	return notice + content
}

// appendToFile appends content to path, creating the file if it doesn't exist.
func appendToFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	// If the file already has content, add a separator
	info, err := f.Stat()
	if err == nil && info.Size() > 0 {
		_, _ = f.WriteString("\n---\n\n")
	}

	_, err = f.WriteString(content)
	return err
}

func init() {
	changelogCmd.Flags().StringVar(&changelogProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	changelogCmd.Flags().StringVar(&changelogModel, "model", "", "Model to use")
	changelogCmd.Flags().StringVar(&changelogSince, "since", "", "Include only steps/tasks from this step number or date (YYYY-MM-DD) onward")
	changelogCmd.Flags().StringVar(&changelogFormat, "format", "markdown", "Output format: markdown, json")
	changelogCmd.Flags().StringVarP(&changelogOutput, "output", "o", "", "Output file path (default: CHANGELOG.md)")
	changelogCmd.Flags().BoolVar(&changelogDryRun, "dry-run", false, "Print changelog to stdout instead of writing to file")
	rootCmd.AddCommand(changelogCmd)
}
