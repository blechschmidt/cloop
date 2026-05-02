package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/journal"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	journalEntryType    string
	journalAuthor       string
	journalSummaryModel string
	journalSummaryProv  string
)

// taskJournalCmd is the parent "cloop task journal" command.
var taskJournalCmd = &cobra.Command{
	Use:   "journal",
	Short: "Per-task decision log with AI summarization",
	Long: `Maintain a structured decision journal for tasks.

Entry types: decision, observation, blocker, insight

Examples:
  cloop task journal add 3 "We chose PostgreSQL over SQLite for scalability"
  cloop task journal add 3 --type blocker "Waiting for API key from DevOps"
  cloop task journal list 3
  cloop task journal summary 3`,
}

// taskJournalAddCmd adds a new entry to a task's journal.
var taskJournalAddCmd = &cobra.Command{
	Use:   "add <task-id> <text>",
	Short: "Add a journal entry for a task",
	Long: `Append a structured entry to the task's decision journal.

The entry is stored in .cloop/journal/<task-id>.jsonl.

Examples:
  cloop task journal add 3 "We chose X over Y because of latency concerns"
  cloop task journal add 5 --type blocker "Blocked on database migration approval"
  cloop task journal add 2 --type insight "Caching reduced latency by 60%"`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		taskID := args[0]

		// Validate task exists in plan (if PM mode is active).
		s, stateErr := state.Load(workdir)
		if stateErr == nil && s.PMMode && s.Plan != nil {
			found := false
			for _, t := range s.Plan.Tasks {
				if fmt.Sprintf("%d", t.ID) == taskID {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("task %s not found in plan", taskID)
			}
		}

		entryType := journal.EntryType(journalEntryType)
		if !journal.IsValidType(entryType) {
			typeNames := make([]string, len(journal.ValidTypes))
			for i, v := range journal.ValidTypes {
				typeNames[i] = string(v)
			}
			return fmt.Errorf("invalid --type %q; must be one of: %s", journalEntryType, strings.Join(typeNames, ", "))
		}

		author := journalAuthor
		if author == "" {
			if u := os.Getenv("USER"); u != "" {
				author = u
			} else {
				author = "user"
			}
		}

		body := strings.Join(args[1:], " ")

		entry := journal.Entry{
			Timestamp: time.Now(),
			TaskID:    taskID,
			Author:    author,
			Type:      entryType,
			Body:      body,
		}

		if err := journal.Append(workdir, entry); err != nil {
			return err
		}

		typeColor := entryTypeColor(entryType)
		typeColor.Printf("[%s] ", string(entryType))
		fmt.Printf("Journal entry added for task %s\n", taskID)
		color.New(color.Faint).Printf("  %s\n", truncateStr(body, 100))
		return nil
	},
}

// taskJournalListCmd lists all journal entries for a task in a table view.
var taskJournalListCmd = &cobra.Command{
	Use:     "list <task-id>",
	Aliases: []string{"ls"},
	Short:   "List journal entries for a task",
	Long: `Show all journal entries for a task in chronological order.

Example:
  cloop task journal list 3`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		taskID := args[0]

		entries, err := journal.List(workdir, taskID)
		if err != nil {
			return err
		}

		titleColor := color.New(color.FgWhite, color.Bold)
		dimColor := color.New(color.Faint)

		titleColor.Printf("Journal: task %s — %d entries\n\n", taskID, len(entries))

		if len(entries) == 0 {
			dimColor.Printf("  No entries yet.\n")
			dimColor.Printf("  Add one: cloop task journal add %s --type decision \"We chose...\"\n", taskID)
			return nil
		}

		for i, e := range entries {
			ts := e.Timestamp.Format("2006-01-02 15:04:05")
			typeColor := entryTypeColor(e.Type)

			fmt.Printf("  %d.  %s  ", i+1, ts)
			typeColor.Printf("%-11s", "["+string(e.Type)+"]")
			dimColor.Printf("  by %s\n", e.Author)
			fmt.Printf("       %s\n\n", strings.ReplaceAll(e.Body, "\n", "\n       "))
		}
		return nil
	},
}

// taskJournalSummaryCmd requests an AI-generated summary of all journal entries for a task.
var taskJournalSummaryCmd = &cobra.Command{
	Use:   "summary <task-id>",
	Short: "AI-generated narrative summary of a task's journal",
	Long: `Use the configured AI provider to generate a concise narrative summary
of all journal entries for a task. Covers decisions, blockers, insights, and
the overall trajectory of the task.

Examples:
  cloop task journal summary 3
  cloop task journal summary 5 --provider anthropic`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		taskID := args[0]

		entries, err := journal.List(workdir, taskID)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			color.New(color.FgYellow).Printf("No journal entries for task %s.\n", taskID)
			return nil
		}

		// Load config + provider.
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		s, _ := state.Load(workdir)

		pName := journalSummaryProv
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s != nil && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := journalSummaryModel
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
		if model == "" && s != nil {
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

		color.New(color.Faint).Printf("Generating AI summary for task %s (%d entries)...\n\n", taskID, len(entries))

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		summary, err := journal.Summarize(ctx, prov, model, entries)
		if err != nil {
			return fmt.Errorf("summarize: %w", err)
		}

		titleColor := color.New(color.FgCyan, color.Bold)
		titleColor.Printf("Journal Summary: Task %s\n", taskID)
		color.New(color.Faint).Printf("────────────────────────\n\n")
		fmt.Println(summary)
		fmt.Println()
		return nil
	},
}

// entryTypeColor returns a color for the given entry type.
func entryTypeColor(t journal.EntryType) *color.Color {
	switch t {
	case journal.TypeDecision:
		return color.New(color.FgBlue, color.Bold)
	case journal.TypeBlocker:
		return color.New(color.FgRed, color.Bold)
	case journal.TypeInsight:
		return color.New(color.FgGreen, color.Bold)
	case journal.TypeObservation:
		return color.New(color.FgYellow)
	default:
		return color.New(color.Faint)
	}
}

func init() {
	taskJournalAddCmd.Flags().StringVar(&journalEntryType, "type", "decision",
		"Entry type: decision, observation, blocker, insight")
	taskJournalAddCmd.Flags().StringVar(&journalAuthor, "author", "",
		"Author name (defaults to $USER)")

	taskJournalSummaryCmd.Flags().StringVar(&journalSummaryProv, "provider", "",
		"AI provider to use (anthropic, openai, ollama, claudecode)")
	taskJournalSummaryCmd.Flags().StringVar(&journalSummaryModel, "model", "",
		"Model override for the AI provider")

	taskJournalCmd.AddCommand(taskJournalAddCmd)
	taskJournalCmd.AddCommand(taskJournalListCmd)
	taskJournalCmd.AddCommand(taskJournalSummaryCmd)

	taskCmd.AddCommand(taskJournalCmd)
}
