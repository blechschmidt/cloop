package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/backlog"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	backlogProvider  string
	backlogModel     string
	backlogFormat    string
	backlogOutput    string
	backlogAsTasks   bool
	backlogMaxItems  int
)

var backlogCmd = &cobra.Command{
	Use:   "backlog",
	Short: "AI-generated prioritized product backlog from your codebase",
	Long: `Analyze your project and generate a prioritized product backlog.

The AI scans your codebase, git history, and existing task plan to surface
the highest-value improvements ranked by impact-to-effort ratio.

Each item includes:
  - Type: feature, bug, tech_debt, performance, security, docs
  - Impact: high / medium / low  (business/user value)
  - Effort: xs / s / m / l / xl  (implementation complexity)

Examples:
  cloop backlog                          # analyze current project
  cloop backlog --format md              # markdown output
  cloop backlog --format md -o backlog.md
  cloop backlog --as-tasks               # add top items to PM plan
  cloop backlog --provider anthropic`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Load project state (goal, plan, instructions)
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found (run 'cloop init' first): %w", err)
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
		pName := backlogProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := backlogModel
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

		// Build project context
		projCtx := pm.BuildProjectContext(workdir)

		// Load memory for context
		mem, _ := memory.Load(workdir)
		memStr := ""
		if mem != nil {
			memStr = mem.FormatForPrompt(10)
		}

		// Build existing plan summary for context
		existingPlan := ""
		if s.Plan != nil && len(s.Plan.Tasks) > 0 {
			var pb strings.Builder
			for _, t := range s.Plan.Tasks {
				pb.WriteString(fmt.Sprintf("- [%s] Task %d: %s\n", t.Status, t.ID, t.Title))
			}
			existingPlan = pb.String()
		}

		prompt := backlog.BuildPrompt(
			s.Goal,
			s.Instructions,
			projCtx.FileTree,
			projCtx.RecentLog,
			memStr,
			existingPlan,
		)

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Printf("\nGenerating product backlog...\n\n")
		dimColor.Printf("Goal:     %s\n", s.Goal)
		dimColor.Printf("Provider: %s\n\n", prov.Name())

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		analysis, err := backlog.Analyze(ctx, prov, model, 3*time.Minute, prompt)
		if err != nil {
			return fmt.Errorf("backlog analysis failed: %w", err)
		}

		// Sort by impact-to-effort score
		analysis.SortByScore()

		// Limit items if requested
		if backlogMaxItems > 0 && len(analysis.Items) > backlogMaxItems {
			analysis.Items = analysis.Items[:backlogMaxItems]
		}

		// Output
		switch backlogFormat {
		case "md", "markdown":
			md := analysis.FormatMarkdown()
			if backlogOutput != "" {
				if err := os.WriteFile(backlogOutput, []byte(md), 0644); err != nil {
					return fmt.Errorf("writing output file: %w", err)
				}
				dimColor.Printf("Backlog saved to %s\n", backlogOutput)
			} else {
				fmt.Print(md)
			}
		default:
			printBacklogTerminal(s.Goal, analysis)
		}

		// Optionally inject top items as PM tasks
		if backlogAsTasks {
			if err := injectBacklogAsTasks(workdir, s, analysis); err != nil {
				return fmt.Errorf("injecting tasks: %w", err)
			}
		}

		return nil
	},
}

// printBacklogTerminal renders the backlog as a rich terminal table.
func printBacklogTerminal(goal string, a *backlog.Analysis) {
	headerColor := color.New(color.FgCyan, color.Bold)
	labelColor := color.New(color.FgYellow)
	dimColor := color.New(color.Faint)

	sep := strings.Repeat("─", 72)
	fmt.Println(sep)
	headerColor.Printf("  Product Backlog — %d items\n", len(a.Items))
	fmt.Println(sep)

	if a.Summary != "" {
		labelColor.Printf("  Summary: ")
		fmt.Printf("%s\n", a.Summary)
		fmt.Println()
	}

	// Column widths
	fmt.Printf("  %-3s  %-12s  %-7s  %-10s  %s\n", "#", "Type", "Impact", "Effort", "Title")
	dimColor.Printf("  %s\n", strings.Repeat("─", 68))

	for i, item := range a.Items {
		typeStr := typeLabel(item.Type)
		impStr := impactLabel(item.Impact)
		effStr := effortShort(item.Effort)

		fmt.Printf("  %-3d  %-12s  %-7s  %-10s  %s\n",
			i+1,
			typeStr,
			impStr,
			effStr,
			item.Title,
		)
	}

	fmt.Println()
	fmt.Println(sep)

	// Show details for high-impact items
	highImpact := []*backlog.Item{}
	for _, item := range a.Items {
		if item.Impact == backlog.ImpactHigh {
			highImpact = append(highImpact, item)
		}
	}
	if len(highImpact) > 0 {
		headerColor.Printf("  High-Impact Items\n")
		fmt.Println(sep)
		for i, item := range highImpact {
			typeColor := typeColor(item.Type)
			typeColor.Printf("  %d. %s", i+1, item.Title)
			fmt.Printf(" [%s]\n", effortShort(item.Effort))
			if item.Description != "" {
				dimColor.Printf("     What: %s\n", item.Description)
			}
			if item.Rationale != "" {
				dimColor.Printf("     Why:  %s\n", item.Rationale)
			}
			fmt.Println()
		}
		fmt.Println(sep)
	}

	fmt.Println()
	dimColor.Printf("  Use --as-tasks to add these items to your PM plan.\n")
	dimColor.Printf("  Use --format md to export as markdown.\n\n")
}

// injectBacklogAsTasks converts backlog items into PM tasks and appends to the plan.
func injectBacklogAsTasks(workdir string, s *state.ProjectState, a *backlog.Analysis) error {
	if !s.PMMode {
		s.PMMode = true
	}
	if s.Plan == nil {
		s.Plan = pm.NewPlan(s.Goal)
	}

	// Find the highest existing task ID
	maxID := 0
	for _, t := range s.Plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	added := 0
	for _, item := range a.Items {
		maxID++
		role := backlogItemRole(item.Type)
		task := &pm.Task{
			ID:          maxID,
			Title:       item.Title,
			Description: item.Description,
			Priority:    impactToPriority(item.Impact, item.Effort),
			Status:      pm.TaskPending,
			Role:        role,
		}
		s.Plan.Tasks = append(s.Plan.Tasks, task)
		added++
	}

	if err := s.Save(); err != nil {
		return err
	}

	successColor := color.New(color.FgGreen, color.Bold)
	successColor.Printf("  Added %d backlog item(s) to PM plan. Run 'cloop run --pm' to execute.\n\n", added)
	return nil
}

// backlogItemRole maps item type to the best agent role.
func backlogItemRole(t backlog.ItemType) pm.AgentRole {
	switch t {
	case backlog.TypeFeature:
		return pm.RoleBackend
	case backlog.TypeBug:
		return pm.RoleReview
	case backlog.TypeTechDebt:
		return pm.RoleReview
	case backlog.TypePerformance:
		return pm.RoleBackend
	case backlog.TypeSecurity:
		return pm.RoleSecurity
	case backlog.TypeDocs:
		return pm.RoleDocs
	default:
		return ""
	}
}

// impactToPriority converts impact+effort into a PM task priority (1=highest).
func impactToPriority(impact backlog.Impact, effort backlog.Effort) int {
	i := map[backlog.Impact]int{backlog.ImpactHigh: 1, backlog.ImpactMedium: 2, backlog.ImpactLow: 3}[impact]
	if i == 0 {
		i = 2
	}
	return i
}

// --- display helpers ---

func typeLabel(t backlog.ItemType) string {
	switch t {
	case backlog.TypeFeature:
		return "feature"
	case backlog.TypeBug:
		return "bug"
	case backlog.TypeTechDebt:
		return "tech-debt"
	case backlog.TypePerformance:
		return "performance"
	case backlog.TypeSecurity:
		return "security"
	case backlog.TypeDocs:
		return "docs"
	default:
		return string(t)
	}
}

func impactLabel(i backlog.Impact) string {
	switch i {
	case backlog.ImpactHigh:
		return "HIGH"
	case backlog.ImpactMedium:
		return "medium"
	case backlog.ImpactLow:
		return "low"
	default:
		return string(i)
	}
}

func effortShort(e backlog.Effort) string {
	switch e {
	case backlog.EffortXS:
		return "XS  <1h"
	case backlog.EffortS:
		return "S   1-4h"
	case backlog.EffortM:
		return "M   4-16h"
	case backlog.EffortL:
		return "L   1-5d"
	case backlog.EffortXL:
		return "XL  >1wk"
	default:
		return string(e)
	}
}

func typeColor(t backlog.ItemType) *color.Color {
	switch t {
	case backlog.TypeBug:
		return color.New(color.FgRed)
	case backlog.TypeSecurity:
		return color.New(color.FgRed, color.Bold)
	case backlog.TypeFeature:
		return color.New(color.FgGreen)
	case backlog.TypeTechDebt:
		return color.New(color.FgYellow)
	case backlog.TypePerformance:
		return color.New(color.FgCyan)
	case backlog.TypeDocs:
		return color.New(color.Faint)
	default:
		return color.New(color.Reset)
	}
}

func init() {
	backlogCmd.Flags().StringVar(&backlogProvider, "provider", "", "Provider to use for analysis")
	backlogCmd.Flags().StringVar(&backlogModel, "model", "", "Model to use for analysis")
	backlogCmd.Flags().StringVar(&backlogFormat, "format", "terminal", "Output format: terminal | md")
	backlogCmd.Flags().StringVarP(&backlogOutput, "output", "o", "", "Write output to file (for --format md)")
	backlogCmd.Flags().BoolVar(&backlogAsTasks, "as-tasks", false, "Add backlog items to the PM task plan")
	backlogCmd.Flags().IntVar(&backlogMaxItems, "max-items", 0, "Maximum number of items to show/add (0 = all)")
	rootCmd.AddCommand(backlogCmd)
}
