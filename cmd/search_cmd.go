package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/search"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	searchType     string
	searchSemantic bool
	searchJSON     bool
	searchProvider string
	searchModel    string
	searchTimeout  string
)

var searchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Full-text search across all cloop project artifacts",
	Long: `Search every cloop artifact in the project for a query string.

Sources searched:
  tasks      — task titles, descriptions, and annotations
  kb         — knowledge base entries
  journal    — per-task decision journal entries
  steplog    — step-by-step replay log (.cloop/replay.jsonl)
  artifact   — task output artifacts (.cloop/tasks/*.md)
  changelog  — AI-generated changelog (.cloop/CHANGELOG.md)
  retro      — retrospective reports (.cloop/retro-*.md)
  snapshot   — plan history snapshots (.cloop/plan-history/*.json)

Plain mode uses fast substring matching with highlighted excerpts.
Use --semantic to re-rank results by AI relevance.

Examples:
  cloop search "authentication"
  cloop search "database migration" --type tasks,kb
  cloop search "API" --semantic --provider anthropic
  cloop search "retry" --json`,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		query := strings.TrimSpace(args[0])
		if query == "" {
			return fmt.Errorf("query must not be empty")
		}

		workDir, _ := os.Getwd()

		types, err := search.ParseTypes(searchType)
		if err != nil {
			return err
		}

		opts := search.Options{
			Types:    types,
			Semantic: searchSemantic,
		}

		if searchSemantic {
			cfg, cerr := config.Load(workDir)
			if cerr != nil {
				return fmt.Errorf("loading config: %w", cerr)
			}
			s, _ := state.Load(workDir)
			provName := searchProvider
			if provName == "" && cfg != nil {
				provName = cfg.Provider
			}
			if provName == "" && s != nil {
				provName = s.Provider
			}
			if provName == "" {
				provName = autoSelectProvider()
			}
			model := searchModel
			if model == "" && cfg != nil {
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
			prov, perr := provider.Build(provCfg)
			if perr != nil {
				return fmt.Errorf("provider: %w", perr)
			}
			opts.Provider = prov
			opts.Model = model

			if searchTimeout != "" {
				d, derr := time.ParseDuration(searchTimeout)
				if derr != nil {
					return fmt.Errorf("invalid timeout: %w", derr)
				}
				opts.Timeout = d
			} else {
				opts.Timeout = 30 * time.Second
			}
		}

		ctx := context.Background()
		results, err := search.Run(ctx, workDir, query, opts)
		if err != nil {
			return fmt.Errorf("search: %w", err)
		}

		if searchJSON {
			return printSearchJSON(results)
		}
		printSearchResults(query, results)
		return nil
	},
}

func printSearchJSON(results []search.Result) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func printSearchResults(query string, results []search.Result) {
	bold := color.New(color.Bold)
	faint := color.New(color.Faint)
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	if len(results) == 0 {
		faint.Printf("No results found for %q\n", query)
		return
	}

	bold.Printf("Found %d result(s) for %q\n\n", len(results), query)

	sourceColor := map[search.SourceType]*color.Color{
		search.SourceTask:      color.New(color.FgGreen, color.Bold),
		search.SourceKB:        color.New(color.FgBlue, color.Bold),
		search.SourceJournal:   color.New(color.FgMagenta, color.Bold),
		search.SourceStepLog:   color.New(color.FgYellow, color.Bold),
		search.SourceArtifact:  color.New(color.FgCyan, color.Bold),
		search.SourceChangelog: color.New(color.FgWhite, color.Bold),
		search.SourceRetro:     color.New(color.FgRed, color.Bold),
		search.SourceSnapshot:  color.New(color.FgHiBlack, color.Bold),
	}

	for i, r := range results {
		// Source badge
		sc := sourceColor[r.Source]
		if sc == nil {
			sc = bold
		}
		sc.Printf("[%s]", strings.ToUpper(string(r.Source)))
		fmt.Print("  ")
		cyan.Print(r.Title)
		fmt.Println()

		// Highlighted excerpt
		highlighted := highlightQuery(r.Excerpt, query)
		fmt.Printf("    %s\n", highlighted)

		// Metadata line
		meta := []string{}
		if r.FilePath != "" {
			meta = append(meta, faint.Sprint(r.FilePath))
		}
		if !r.Timestamp.IsZero() {
			meta = append(meta, faint.Sprint(r.Timestamp.Format("2006-01-02")))
		}
		if r.Score > 0 {
			meta = append(meta, yellow.Sprintf("score:%d", r.Score))
		}
		if len(meta) > 0 {
			fmt.Printf("    %s\n", strings.Join(meta, "  "))
		}

		if i < len(results)-1 {
			green.Println()
		}
	}
}

// highlightQuery wraps all occurrences of query in the excerpt with bold+yellow styling.
func highlightQuery(excerpt, query string) string {
	if query == "" {
		return excerpt
	}
	hi := color.New(color.FgYellow, color.Bold)
	lower := strings.ToLower(excerpt)
	lq := strings.ToLower(query)
	var out strings.Builder
	pos := 0
	for {
		idx := strings.Index(lower[pos:], lq)
		if idx == -1 {
			out.WriteString(excerpt[pos:])
			break
		}
		abs := pos + idx
		out.WriteString(excerpt[pos:abs])
		out.WriteString(hi.Sprint(excerpt[abs : abs+len(query)]))
		pos = abs + len(query)
	}
	return out.String()
}

func init() {
	searchCmd.Flags().StringVar(&searchType, "type", "all", "Comma-separated source types to search: tasks,kb,journal,steplog,artifact,changelog,retro,snapshot,all")
	searchCmd.Flags().BoolVar(&searchSemantic, "semantic", false, "Use AI provider to re-rank results by semantic relevance")
	searchCmd.Flags().BoolVar(&searchJSON, "json", false, "Output results as JSON")
	searchCmd.Flags().StringVar(&searchProvider, "provider", "", "Provider for semantic re-ranking (default: from config)")
	searchCmd.Flags().StringVar(&searchModel, "model", "", "Model for semantic re-ranking")
	searchCmd.Flags().StringVar(&searchTimeout, "timeout", "30s", "Timeout for AI calls (e.g. 30s, 1m)")

	rootCmd.AddCommand(searchCmd)
}
