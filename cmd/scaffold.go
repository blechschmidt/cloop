package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/scaffold"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	scaffoldDryRun    bool
	scaffoldOutputDir string
	scaffoldProvider  string
	scaffoldModel     string
	scaffoldTimeout   string
)

var scaffoldCmd = &cobra.Command{
	Use:   "scaffold",
	Short: "Generate a project skeleton from the active plan using AI",
	Long: `Read the active plan's goal and task list, then ask the AI to generate
a complete project skeleton: directory tree, stub files, config templates,
and a README.

The AI produces a JSON manifest describing which directories to create and
what content to write to each file. All paths are relative to --output-dir.

Use --dry-run to print the tree without writing anything to disk.

Examples:
  cloop scaffold                          # scaffold into current directory
  cloop scaffold --output-dir ./myapp     # scaffold into ./myapp
  cloop scaffold --dry-run                # preview tree, no writes
  cloop scaffold --provider anthropic
  cloop scaffold --provider anthropic --model claude-opus-4-6`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}
		if s.Goal == "" {
			return fmt.Errorf("no project initialized — run 'cloop init' first")
		}
		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no plan found — run 'cloop run --pm --plan-only' first to decompose your goal into tasks")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			cfg = &config.Config{}
		}
		applyEnvOverrides(cfg)

		// Resolve provider
		pName := scaffoldProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		// Resolve model
		model := scaffoldModel
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
		if scaffoldTimeout != "" {
			timeout, err = time.ParseDuration(scaffoldTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		outputDir := scaffoldOutputDir
		if outputDir == "" {
			outputDir = "."
		}
		// Make output dir absolute for display
		absOutput, err := filepath.Abs(outputDir)
		if err != nil {
			absOutput = outputDir
		}

		dimColor := color.New(color.Faint)
		headerColor := color.New(color.FgCyan, color.Bold)
		successColor := color.New(color.FgGreen, color.Bold)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("Generating project scaffold from plan (%d tasks)...\n", len(s.Plan.Tasks))
		dimColor.Printf("Provider: %s  Output: %s\n\n", pName, absOutput)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		sp, err := scaffold.Generate(ctx, prov, model, s.Plan, outputDir, scaffoldDryRun)
		if err != nil {
			return fmt.Errorf("scaffold: %w", err)
		}

		// Collect all paths for the summary table
		type entry struct {
			kind string // "dir" or "file"
			path string
		}
		var entries []entry
		for _, d := range sp.Dirs {
			entries = append(entries, entry{"dir", d})
		}
		for _, f := range sp.Files {
			entries = append(entries, entry{"file", f.Path})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

		if scaffoldDryRun {
			warnColor.Println("DRY-RUN — no files written\n")
		}

		fmt.Printf("%-6s  %s\n", "TYPE", "PATH")
		fmt.Printf("%-6s  %s\n", "----", "----")
		for _, e := range entries {
			kindStr := "file"
			if e.kind == "dir" {
				kindStr = color.New(color.FgBlue).Sprint("dir ")
			}
			fmt.Printf("%-6s  %s\n", kindStr, e.path)
		}
		fmt.Println()

		if scaffoldDryRun {
			dimColor.Printf("Total: %d dirs, %d files (dry-run)\n", len(sp.Dirs), len(sp.Files))
		} else {
			successColor.Printf("Scaffold complete: %d dirs, %d files written to %s\n", len(sp.Dirs), len(sp.Files), absOutput)
		}
		return nil
	},
}

func init() {
	scaffoldCmd.Flags().BoolVar(&scaffoldDryRun, "dry-run", false, "Print tree without writing any files")
	scaffoldCmd.Flags().StringVar(&scaffoldOutputDir, "output-dir", "", "Directory to write scaffold into (default: current directory)")
	scaffoldCmd.Flags().StringVar(&scaffoldProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	scaffoldCmd.Flags().StringVar(&scaffoldModel, "model", "", "Model override")
	scaffoldCmd.Flags().StringVar(&scaffoldTimeout, "timeout", "3m", "AI call timeout (e.g. 2m, 180s)")
	rootCmd.AddCommand(scaffoldCmd)
}
