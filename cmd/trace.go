package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/trace"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	traceLimit    int
	traceSince    string
	traceFormat   string
	traceProvider string
	traceModel    string
	traceSave     bool
	traceNoModel  bool
)

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Map recent git commits to plan tasks",
	Long: `Walk recent git commits and correlate each commit with a task.

A commit whose subject names its task — "(Task 12)", "(Tasks 12, 13)" or
"cloop(task-12): …" — is linked to it with high confidence without asking a
model; the model is asked about the rest, unless --no-model says not to.

Displays a table showing: commit hash | message | matched task ID | task title | confidence.
Writes the mapping to .cloop/trace.json so 'cloop status' can show the last commit
linked to a task, and 'cloop requirements trace' and the dashboard's
Traceability view the commits each requirement's tasks produced.

Examples:
  cloop trace                              # trace last 50 commits
  cloop trace --limit 20                   # trace last 20 commits
  cloop trace --since 2024-01-01           # commits since a date
  cloop trace --since "2 weeks ago"        # commits since 2 weeks ago
  cloop trace --format json                # emit JSON instead of table
  cloop trace --provider anthropic         # use a specific provider
  cloop trace --no-model                   # link only commits that name their task
  cloop trace --save=false                 # don't write .cloop/trace.json`,
	RunE: runTrace,
}

func runTrace(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()

	s, _ := state.Load(workdir)

	cfg, err := config.Load(workdir)
	if err != nil {
		cfg = &config.Config{}
	}
	applyEnvOverrides(cfg)

	// Resolve provider
	pName := traceProvider
	if pName == "" {
		pName = cfg.Provider
	}
	if pName == "" && s != nil && s.Provider != "" {
		pName = s.Provider
	}
	if pName == "" {
		pName = autoSelectProvider()
	}

	model := traceModel
	if model == "" {
		model = cfg.ModelFor(pName)
	}

	provCfg := provider.ProviderConfig{
		Name:             pName,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}
	// No model asked, no provider built: the subjects that name their task
	// are all --no-model links.
	var prov provider.Provider
	with := "the commits' subjects only"
	if !traceNoModel {
		if prov, err = provider.Build(provCfg); err != nil {
			return fmt.Errorf("provider: %w", err)
		}
		with = prov.Name()
	}

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	// Show what we're about to do
	sinceMsg := ""
	if traceSince != "" {
		sinceMsg = fmt.Sprintf(" (since %s)", traceSince)
	}
	bold.Printf("\nTracing last %d commits%s with %s...\n\n", traceLimit, sinceMsg, with)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// The plan's tasks, read from the project's database: a project that has
	// moved off state.json still has them there.
	var tasks []*pm.Task
	if s != nil && s.Plan != nil {
		tasks = s.Plan.Tasks
	}
	tm, err := trace.Run(ctx, prov, model, workdir, tasks, traceLimit, traceSince)
	if err != nil {
		return fmt.Errorf("trace: %w", err)
	}

	if len(tm.Entries) == 0 {
		dim.Println("No commits found.")
		return nil
	}

	// Save to .cloop/trace.json unless --no-save was specified
	if traceSave {
		if err := trace.WriteTraceJSON(workdir, tm); err != nil {
			color.New(color.FgYellow).Printf("Warning: could not write trace.json: %v\n", err)
		} else {
			dim.Println("Saved to .cloop/trace.json")
		}
	}

	switch strings.ToLower(traceFormat) {
	case "json":
		data, err := json.MarshalIndent(tm, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))

	default: // table
		printTraceTable(tm)
	}

	return nil
}

func printTraceTable(tm *trace.TraceMap) {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	dim := color.New(color.Faint)
	bold := color.New(color.Bold)

	// Column widths
	const hashW = 9
	const msgW = 45
	const idW = 7
	const titleW = 35
	const confW = 8

	// Header
	sep := strings.Repeat("─", hashW+msgW+idW+titleW+confW+16)
	cyan.Println(sep)
	bold.Printf("  %-*s  %-*s  %-*s  %-*s  %-*s\n",
		hashW, "HASH",
		msgW, "COMMIT MESSAGE",
		idW, "TASK ID",
		titleW, "TASK TITLE",
		confW, "CONF",
	)
	cyan.Println(sep)

	for _, e := range tm.Entries {
		hash := e.Hash
		if len(hash) > hashW {
			hash = hash[:hashW]
		}

		msg := e.Subject
		if len(msg) > msgW {
			msg = msg[:msgW-1] + "…"
		}

		taskID := "-"
		if e.MatchedTaskID > 0 {
			taskID = fmt.Sprintf("#%d", e.MatchedTaskID)
		}

		title := e.MatchedTaskTitle
		if title == "" {
			title = "-"
		}
		if len(title) > titleW {
			title = title[:titleW-1] + "…"
		}

		conf := string(e.Confidence)

		var confColored string
		switch e.Confidence {
		case trace.ConfidenceHigh:
			confColored = green.Sprintf("%-*s", confW, conf)
		case trace.ConfidenceMedium:
			confColored = yellow.Sprintf("%-*s", confW, conf)
		case trace.ConfidenceLow:
			confColored = red.Sprintf("%-*s", confW, conf)
		default:
			confColored = dim.Sprintf("%-*s", confW, conf)
		}

		fmt.Printf("  %-*s  %-*s  %-*s  %-*s  %s\n",
			hashW, hash,
			msgW, msg,
			idW, taskID,
			titleW, title,
			confColored,
		)
	}
	cyan.Println(sep)

	// Summary
	var linked, high, med, low int
	for _, e := range tm.Entries {
		if e.MatchedTaskID > 0 {
			linked++
		}
		switch e.Confidence {
		case trace.ConfidenceHigh:
			high++
		case trace.ConfidenceMedium:
			med++
		case trace.ConfidenceLow:
			low++
		}
	}
	fmt.Printf("\n  %d commits  |  %d linked  |  ", len(tm.Entries), linked)
	green.Printf("%d high  ", high)
	yellow.Printf("%d medium  ", med)
	red.Printf("%d low\n\n", low)
}

func init() {
	traceCmd.Flags().IntVar(&traceLimit, "limit", 50, "Maximum number of commits to trace")
	traceCmd.Flags().StringVar(&traceSince, "since", "", "Only include commits since this date (e.g. 2024-01-01 or '2 weeks ago')")
	traceCmd.Flags().StringVar(&traceFormat, "format", "table", "Output format: table or json")
	traceCmd.Flags().StringVar(&traceProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	traceCmd.Flags().StringVar(&traceModel, "model", "", "Model to use")
	traceCmd.Flags().BoolVar(&traceSave, "save", true, "Write mapping to .cloop/trace.json")
	traceCmd.Flags().BoolVar(&traceNoModel, "no-model", false, "Link only commits whose subject names their task; ask no model")

	rootCmd.AddCommand(traceCmd)
}
