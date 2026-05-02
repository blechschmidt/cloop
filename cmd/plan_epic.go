package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/epic"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	epicProvider string
	epicModel    string
	epicApply    bool
	epicTimeout  string
)

var planEpicCmd = &cobra.Command{
	Use:   "ai-epic",
	Short: "Cluster the task plan into named epics/themes using AI",
	Long: `Ask the AI to group your task plan into 3-7 named epics based on
semantic similarity and business value. Each epic gets a name, one-sentence
description, and the list of task IDs it covers.

With --apply, the epic name is written as an "epic:<name>" tag on each task
using the existing Tags field, so the grouping is persisted in state.

Examples:
  cloop plan ai-epic                       # show suggested epic groupings
  cloop plan ai-epic --apply               # apply epic tags to tasks
  cloop plan ai-epic --provider anthropic  # use a specific provider`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm --plan-only' to create one")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := epicProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := epicModel
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

		timeout := 3 * time.Minute
		if epicTimeout != "" {
			timeout, err = time.ParseDuration(epicTimeout)
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

		// ── Print header ──────────────────────────────────────────────────────
		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		boldColor := color.New(color.Bold)
		goodColor := color.New(color.FgGreen)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("\ncloop plan ai-epic — AI epic & theme clustering\n")
		dimColor.Printf("  Provider: %s | Tasks: %d\n\n",
			prov.Name(), len(s.Plan.Tasks))
		dimColor.Printf("Generating epic groupings...\n\n")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		epics, err := epic.Cluster(ctx, prov, model, s.Plan)
		if err != nil {
			return fmt.Errorf("clustering epics: %w", err)
		}

		// ── Build task-id → title lookup ──────────────────────────────────────
		idToTitle := make(map[int]string, len(s.Plan.Tasks))
		idToStatus := make(map[int]string, len(s.Plan.Tasks))
		for _, t := range s.Plan.Tasks {
			idToTitle[t.ID] = t.Title
			idToStatus[t.ID] = string(t.Status)
		}

		// ── Progress per epic ─────────────────────────────────────────────────
		progress := epic.Progress(s.Plan, epics)

		// ── Render table ──────────────────────────────────────────────────────
		epicColors := []*color.Color{
			color.New(color.FgCyan),
			color.New(color.FgGreen),
			color.New(color.FgYellow),
			color.New(color.FgMagenta),
			color.New(color.FgBlue),
			color.New(color.FgRed),
			color.New(color.FgHiCyan),
		}

		// Table header
		boldColor.Printf("  %-28s  %-6s  %-6s  %-6s  %s\n",
			"EPIC", "TOTAL", "DONE", "PEND", "DESCRIPTION")
		fmt.Printf("  %s\n", strings.Repeat("─", 90))

		for i, ep := range progress {
			ec := epicColors[i%len(epicColors)]

			pct := 0
			if ep.Total > 0 {
				pct = ep.Done * 100 / ep.Total
			}
			bar := renderProgressBar(pct, 12)

			ec.Printf("  %-28s", truncate(ep.Name, 28))
			fmt.Printf("  %-6d  ", ep.Total)
			goodColor.Printf("%-6d", ep.Done)
			fmt.Printf("  %-6d  ", ep.Pending)
			dimColor.Printf("%s %3d%%  ", bar, pct)
			fmt.Printf("%s\n", truncate(ep.Description, 48))

			// Show task IDs in a compact line.
			ids := make([]string, 0, len(ep.TaskIDs))
			for _, id := range ep.TaskIDs {
				ids = append(ids, fmt.Sprintf("#%d", id))
			}
			dimColor.Printf("    Tasks: %s\n", strings.Join(ids, " "))

			// Show a few task titles.
			shown := 0
			for _, id := range ep.TaskIDs {
				if shown >= 3 {
					remaining := len(ep.TaskIDs) - shown
					if remaining > 0 {
						dimColor.Printf("      ... and %d more\n", remaining)
					}
					break
				}
				title := idToTitle[id]
				status := idToStatus[id]
				marker := "○"
				if status == "done" {
					marker = "✓"
				} else if status == "in_progress" {
					marker = "●"
				} else if status == "failed" {
					marker = "✗"
				}
				dimColor.Printf("      %s #%d: %s\n", marker, id, truncate(title, 65))
				shown++
			}
			fmt.Println()
		}

		fmt.Printf("  %s\n", strings.Repeat("─", 90))
		boldColor.Printf("  %d epic(s) covering %d task(s)\n\n", len(epics), len(s.Plan.Tasks))

		// ── Apply tags ────────────────────────────────────────────────────────
		if !epicApply {
			warnColor.Printf("  Run with --apply to tag tasks with their epic names.\n\n")
			return nil
		}

		n := epic.ApplyTags(s.Plan, epics)
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
		goodColor.Printf("  Tagged %d task(s) with epic labels. Run 'cloop status' to verify.\n\n", n)
		return nil
	},
}

// renderProgressBar returns a fixed-width ASCII progress bar.
func renderProgressBar(pct, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := pct * width / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return "[" + bar + "]"
}

func init() {
	planEpicCmd.Flags().StringVar(&epicProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	planEpicCmd.Flags().StringVar(&epicModel, "model", "", "Model override")
	planEpicCmd.Flags().BoolVar(&epicApply, "apply", false, "Apply epic:name tags to tasks in state")
	planEpicCmd.Flags().StringVar(&epicTimeout, "timeout", "3m", "Timeout for AI call (e.g. 2m, 90s)")

	planCmd.AddCommand(planEpicCmd)
}
