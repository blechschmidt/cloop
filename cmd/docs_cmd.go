package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/docs"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	docsFile     string
	docsProvider string
	docsModel    string
	docsTimeout  string
	docsYes      bool
)

// docsCmd is the parent command for all `cloop docs` subcommands.
var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "AI-powered documentation maintenance",
	Long: `AI-powered documentation maintenance for your cloop project.

Subcommands:
  check   Show documentation coverage score and list missing/stale docs
  update  AI-refresh one or all documentation files with diff preview
  watch   Re-run docs update after each completed task (polls state)

Examples:
  cloop docs check
  cloop docs update
  cloop docs update --file README.md
  cloop docs watch`,
}

// docsCheckCmd prints the coverage score and flags missing/stale docs.
var docsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Show documentation coverage score and list missing/stale docs",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		score, missing := docs.CoverageScore(workdir)

		boldColor := color.New(color.FgCyan, color.Bold)
		boldColor.Printf("Documentation coverage: %d/100\n\n", score)

		if score >= 80 {
			color.New(color.FgGreen).Printf("  Coverage is excellent.\n")
		} else if score >= 50 {
			color.New(color.FgYellow).Printf("  Coverage is partial — consider filling the gaps below.\n")
		} else {
			color.New(color.FgRed).Printf("  Coverage is low — several key docs are missing.\n")
		}

		if len(missing) > 0 {
			fmt.Println()
			color.New(color.FgRed).Printf("Missing docs:\n")
			for _, m := range missing {
				fmt.Printf("  - %s\n", m)
			}
		}

		// Show stale status for existing docs.
		pd, err := docs.Collect(workdir, workdir)
		if err == nil {
			var stale []string
			for _, f := range pd.Files {
				if f.Exists && f.IsStale {
					stale = append(stale, f.RelPath)
				}
			}
			if len(stale) > 0 {
				fmt.Println()
				color.New(color.FgYellow).Printf("Potentially stale docs (modified before last completed task):\n")
				for _, s := range stale {
					fmt.Printf("  - %s\n", s)
				}
			}
		}

		return nil
	},
}

// docsUpdateCmd refreshes one or all documentation files using the AI provider.
var docsUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "AI-refresh one or all documentation files with diff preview before writing",
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

		prov, model, err := buildDocsProvider(cfg, s)
		if err != nil {
			return err
		}

		timeout := 180 * time.Second
		if docsTimeout != "" {
			timeout, err = time.ParseDuration(docsTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		dimColor := color.New(color.Faint)
		dimColor.Printf("Collecting project context...\n")

		pd, err := docs.Collect(workdir, workdir)
		if err != nil {
			return fmt.Errorf("collecting docs context: %w", err)
		}

		// Determine which files to update.
		var targets []*docs.DocFile
		if docsFile != "" {
			// Single file mode: find matching file or create a stub.
			matched := false
			for _, f := range pd.Files {
				if f.RelPath == docsFile || filepath.Base(f.RelPath) == docsFile {
					targets = append(targets, f)
					matched = true
					break
				}
			}
			if !matched {
				// Create a stub for the requested file.
				absPath := filepath.Join(workdir, docsFile)
				stub := &docs.DocFile{
					RelPath: docsFile,
					AbsPath: absPath,
					Exists:  false,
				}
				targets = append(targets, stub)
			}
		} else {
			// All files: update existing docs plus stubs for missing coverage targets.
			for _, f := range pd.Files {
				targets = append(targets, f)
			}
		}

		if len(targets) == 0 {
			fmt.Println("No documentation files to update.")
			return nil
		}

		ctx := context.Background()
		scanner := bufio.NewScanner(os.Stdin)

		for _, df := range targets {
			fmt.Println()
			color.New(color.FgCyan, color.Bold).Printf("Updating %s ...\n", df.RelPath)

			updated, err := docs.Refresh(ctx, prov, model, timeout, df, pd)
			if err != nil {
				color.New(color.FgRed).Printf("  Error: %v\n", err)
				continue
			}

			// Show a simple diff: first/last lines of old vs new.
			if df.Exists && df.Content != "" {
				oldLines := strings.Split(strings.TrimSpace(df.Content), "\n")
				newLines := strings.Split(strings.TrimSpace(updated), "\n")
				fmt.Printf("\n  Old: %d lines → New: %d lines\n", len(oldLines), len(newLines))
				// Print first 5 lines of the new content as preview.
				fmt.Println("  Preview (first 5 lines):")
				for i, line := range newLines {
					if i >= 5 {
						break
					}
					fmt.Printf("    %s\n", line)
				}
			} else {
				newLines := strings.Split(strings.TrimSpace(updated), "\n")
				fmt.Printf("\n  New file: %d lines\n", len(newLines))
				fmt.Println("  Preview (first 5 lines):")
				for i, line := range newLines {
					if i >= 5 {
						break
					}
					fmt.Printf("    %s\n", line)
				}
			}

			// Confirm write unless --yes.
			write := docsYes
			if !write {
				fmt.Printf("\n  Write to %s? [y/N] ", df.RelPath)
				if scanner.Scan() {
					write = strings.ToLower(strings.TrimSpace(scanner.Text())) == "y"
				}
			}

			if write {
				// Ensure parent directory exists.
				if err := os.MkdirAll(filepath.Dir(df.AbsPath), 0o755); err != nil {
					color.New(color.FgRed).Printf("  mkdir error: %v\n", err)
					continue
				}
				if err := os.WriteFile(df.AbsPath, []byte(updated), 0o644); err != nil {
					color.New(color.FgRed).Printf("  write error: %v\n", err)
					continue
				}
				color.New(color.FgGreen).Printf("  Written: %s\n", df.RelPath)
			} else {
				dimColor.Printf("  Skipped.\n")
			}
		}

		return nil
	},
}

// docsWatchCmd polls for task completions and re-runs docs update after each one.
var docsWatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Re-run docs update after each completed task (polls PM state)",
	Long: `Watch PM mode state and automatically refresh documentation after each
task completes. Polls the cloop state every 10 seconds.

Press Ctrl+C to stop.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		timeout := 180 * time.Second
		if docsTimeout != "" {
			timeout, err = time.ParseDuration(docsTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		dimColor := color.New(color.Faint)
		boldColor := color.New(color.FgCyan, color.Bold)

		boldColor.Printf("cloop docs watch — polling for completed tasks...\n")
		dimColor.Printf("Press Ctrl+C to stop.\n\n")

		var lastDoneCount int
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		// Immediately capture current done count without running update.
		if s, err := state.Load(workdir); err == nil && s.Plan != nil {
			done, _ := s.Plan.CountByStatus()
			lastDoneCount = done
		}

		for range ticker.C {
			s, err := state.Load(workdir)
			if err != nil || s.Plan == nil {
				continue
			}
			done, _ := s.Plan.CountByStatus()
			if done <= lastDoneCount {
				continue
			}

			newlyDone := done - lastDoneCount
			lastDoneCount = done

			boldColor.Printf("[%s] %d new task(s) completed — refreshing docs...\n",
				time.Now().Format("15:04:05"), newlyDone)

			// Build provider (refresh each time in case config changed).
			prov, model, provErr := buildDocsProvider(cfg, s)
			if provErr != nil {
				color.New(color.FgRed).Printf("  Provider error: %v\n", provErr)
				continue
			}

			pd, collectErr := docs.Collect(workdir, workdir)
			if collectErr != nil {
				color.New(color.FgRed).Printf("  Context error: %v\n", collectErr)
				continue
			}

			ctx := context.Background()
			for _, df := range pd.Files {
				if !df.Exists {
					continue // skip missing files in watch mode
				}
				dimColor.Printf("  Refreshing %s ...\n", df.RelPath)
				updated, refreshErr := docs.Refresh(ctx, prov, model, timeout, df, pd)
				if refreshErr != nil {
					color.New(color.FgRed).Printf("  Error refreshing %s: %v\n", df.RelPath, refreshErr)
					continue
				}
				if err := os.WriteFile(df.AbsPath, []byte(updated), 0o644); err != nil {
					color.New(color.FgRed).Printf("  Write error for %s: %v\n", df.RelPath, err)
					continue
				}
				color.New(color.FgGreen).Printf("  Updated %s\n", df.RelPath)
			}
		}

		return nil
	},
}

// buildDocsProvider resolves and builds the AI provider for docs commands.
func buildDocsProvider(cfg *config.Config, s *state.ProjectState) (provider.Provider, string, error) {
	providerName := docsProvider
	if providerName == "" {
		providerName = cfg.Provider
	}
	if providerName == "" && s != nil {
		providerName = s.Provider
	}
	if providerName == "" {
		providerName = autoSelectProvider()
	}

	model := docsModel
	if model == "" && s != nil {
		model = s.Model
	}
	if model == "" {
		switch providerName {
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
		Name:             providerName,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}

	prov, err := provider.Build(provCfg)
	if err != nil {
		return nil, "", fmt.Errorf("provider: %w", err)
	}
	return prov, model, nil
}

func init() {
	// update flags
	docsUpdateCmd.Flags().StringVar(&docsFile, "file", "", "Only update this specific file (e.g. README.md)")
	docsUpdateCmd.Flags().StringVar(&docsProvider, "provider", "", "AI provider to use")
	docsUpdateCmd.Flags().StringVar(&docsModel, "model", "", "Model to use")
	docsUpdateCmd.Flags().StringVar(&docsTimeout, "timeout", "", "AI call timeout (e.g. 120s, 3m)")
	docsUpdateCmd.Flags().BoolVar(&docsYes, "yes", false, "Write files without confirmation prompt")

	// watch flags (share provider/model/timeout with update)
	docsWatchCmd.Flags().StringVar(&docsProvider, "provider", "", "AI provider to use")
	docsWatchCmd.Flags().StringVar(&docsModel, "model", "", "Model to use")
	docsWatchCmd.Flags().StringVar(&docsTimeout, "timeout", "", "AI call timeout (e.g. 120s, 3m)")

	docsCmd.AddCommand(docsCheckCmd)
	docsCmd.AddCommand(docsUpdateCmd)
	docsCmd.AddCommand(docsWatchCmd)
	rootCmd.AddCommand(docsCmd)
}
