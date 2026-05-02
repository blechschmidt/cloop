package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kb"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var kbCmd = &cobra.Command{
	Use:   "kb",
	Short: "Manage the project knowledge base",
	Long: `Persistent project knowledge base stored in .cloop/kb.json.

KB entries are automatically injected into task execution prompts so the AI
always has relevant project context across sessions.

  cloop kb add "API conventions" --content "Always use snake_case for JSON fields"
  cloop kb add "Architecture overview" --file ./ARCHITECTURE.md --tags "arch,design"
  cloop kb list
  cloop kb get 1
  cloop kb rm 2
  cloop kb search "authentication"
  cloop kb search "database" --keyword`,
}

var kbAddCmd = &cobra.Command{
	Use:   "add <title>",
	Short: "Add a knowledge base entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		title := args[0]
		content, _ := cmd.Flags().GetString("content")
		filePath, _ := cmd.Flags().GetString("file")
		tagsStr, _ := cmd.Flags().GetString("tags")

		if filePath != "" {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}
			content = string(data)
		}
		if content == "" {
			return fmt.Errorf("provide --content or --file")
		}

		var tags []string
		if tagsStr != "" {
			for _, t := range strings.Split(tagsStr, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					tags = append(tags, t)
				}
			}
		}

		workDir, _ := os.Getwd()
		entry, err := kb.Add(workDir, title, content, tags)
		if err != nil {
			return err
		}
		color.New(color.FgGreen, color.Bold).Printf("Added KB entry #%d: %s\n", entry.ID, entry.Title)
		return nil
	},
}

var kbListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all knowledge base entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		base, err := kb.Load(workDir)
		if err != nil {
			return err
		}
		if len(base.Entries) == 0 {
			color.New(color.Faint).Println("No KB entries. Use 'cloop kb add' to create one.")
			return nil
		}
		bold := color.New(color.Bold)
		faint := color.New(color.Faint)
		for _, e := range base.Entries {
			tags := ""
			if len(e.Tags) > 0 {
				tags = fmt.Sprintf(" [%s]", strings.Join(e.Tags, ", "))
			}
			snippet := e.Content
			if len(snippet) > 80 {
				snippet = snippet[:80] + "..."
			}
			snippet = strings.ReplaceAll(snippet, "\n", " ")
			bold.Printf("#%d %s", e.ID, e.Title)
			fmt.Printf("%s\n", faint.Sprint(tags))
			faint.Printf("    %s\n", snippet)
		}
		return nil
	},
}

var kbGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Show a knowledge base entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid id: %s", args[0])
		}
		workDir, _ := os.Getwd()
		entry, err := kb.Get(workDir, id)
		if err != nil {
			return err
		}
		bold := color.New(color.Bold)
		faint := color.New(color.Faint)
		bold.Printf("#%d %s\n", entry.ID, entry.Title)
		if len(entry.Tags) > 0 {
			faint.Printf("Tags: %s\n", strings.Join(entry.Tags, ", "))
		}
		faint.Printf("Created: %s\n", entry.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Println()
		fmt.Println(entry.Content)
		return nil
	},
}

var kbRmCmd = &cobra.Command{
	Use:   "rm <id>",
	Short: "Remove a knowledge base entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid id: %s", args[0])
		}
		workDir, _ := os.Getwd()
		if err := kb.Remove(workDir, id); err != nil {
			return err
		}
		color.New(color.FgYellow).Printf("Removed KB entry #%d\n", id)
		return nil
	},
}

var kbSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search the knowledge base (AI-powered semantic search with keyword fallback)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		query := args[0]
		keyword, _ := cmd.Flags().GetBool("keyword")
		kbProvider, _ := cmd.Flags().GetString("provider")
		kbModel, _ := cmd.Flags().GetString("model")

		workDir, _ := os.Getwd()

		var entries []*kb.Entry
		if keyword {
			var err error
			entries, err = kb.TopRelevant(workDir, query, 10)
			if err != nil {
				return err
			}
		} else {
			cfg, err := config.Load(workDir)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			applyEnvOverrides(cfg)

			s, _ := state.Load(workDir)

			pName := kbProvider
			if pName == "" {
				pName = cfg.Provider
			}
			if pName == "" && s != nil && s.Provider != "" {
				pName = s.Provider
			}
			if pName == "" {
				pName = autoSelectProvider()
			}

			model := kbModel
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
				color.New(color.FgYellow).Fprintf(os.Stderr, "Provider unavailable (%v), falling back to keyword search\n", err)
				entries, err = kb.TopRelevant(workDir, query, 10)
				if err != nil {
					return err
				}
			} else {
				ctx := cmd.Context()
				entries, err = kb.AISearch(ctx, prov, model, workDir, query)
				if err != nil {
					color.New(color.FgYellow).Fprintf(os.Stderr, "AI search failed (%v), falling back to keyword search\n", err)
					entries, err = kb.TopRelevant(workDir, query, 10)
					if err != nil {
						return err
					}
				}
			}
		}

		if len(entries) == 0 {
			color.New(color.Faint).Println("No matching entries found.")
			return nil
		}
		bold := color.New(color.Bold)
		faint := color.New(color.Faint)
		for _, e := range entries {
			tags := ""
			if len(e.Tags) > 0 {
				tags = fmt.Sprintf(" [%s]", strings.Join(e.Tags, ", "))
			}
			snippet := e.Content
			if len(snippet) > 120 {
				snippet = snippet[:120] + "..."
			}
			snippet = strings.ReplaceAll(snippet, "\n", " ")
			bold.Printf("#%d %s", e.ID, e.Title)
			fmt.Printf("%s\n", faint.Sprint(tags))
			faint.Printf("    %s\n", snippet)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(kbCmd)

	// kb add flags
	kbAddCmd.Flags().StringP("content", "c", "", "Entry content text")
	kbAddCmd.Flags().StringP("file", "f", "", "Read content from file")
	kbAddCmd.Flags().String("tags", "", "Comma-separated tags")

	// kb search flags
	kbSearchCmd.Flags().Bool("keyword", false, "Use keyword overlap instead of AI semantic search")
	kbSearchCmd.Flags().String("provider", "", "Provider for AI search (default: from config)")
	kbSearchCmd.Flags().String("model", "", "Model for AI search (default: from config)")

	kbCmd.AddCommand(kbAddCmd, kbListCmd, kbGetCmd, kbRmCmd, kbSearchCmd)
}
