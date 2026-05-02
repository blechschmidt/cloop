package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/checkpoint"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	cpDiffAI       bool
	cpDiffProvider string
	cpDiffModel    string
	cpDiffTimeout  string
)

var taskCheckpointDiffCmd = &cobra.Command{
	Use:   "checkpoint-diff <task-id> [from-checkpoint-id [to-checkpoint-id]]",
	Short: "Show what changed between task checkpoints",
	Long: `Display a diff of task state between consecutive checkpoints saved during
PM execution. Each run saves a "start" and "complete/fail/skip" entry under
.cloop/task-checkpoints/task-<id>/.

With just a task-id, show diffs for all consecutive checkpoint pairs.
With from and to checkpoint IDs, compare those two specific entries.

Use --ai to get an AI-narrated plain-English summary of what happened.

Examples:
  cloop task checkpoint-diff 3
  cloop task checkpoint-diff 3 --ai
  cloop task checkpoint-diff 3 <from-id> <to-id>`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || len(args) > 3 {
			return fmt.Errorf("accepts 1 to 3 args (task-id [from-id [to-id]])")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Parse task ID
		var taskID int
		if _, err := fmt.Sscanf(args[0], "%d", &taskID); err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		// Load history
		entries, err := checkpoint.ListHistory(workdir, taskID)
		if err != nil {
			return fmt.Errorf("loading checkpoint history: %w", err)
		}
		if len(entries) == 0 {
			fmt.Printf("No checkpoint history found for task %d.\n", taskID)
			fmt.Printf("Checkpoints are saved automatically during 'cloop run --pm' execution.\n")
			return nil
		}

		// Determine which pairs to diff
		type diffPair struct {
			from *checkpoint.HistoryEntry
			to   *checkpoint.HistoryEntry
		}
		var pairs []diffPair

		if len(args) == 3 {
			// Specific from/to checkpoint IDs
			fromCP, err := checkpoint.LoadHistoryEntry(workdir, taskID, args[1])
			if err != nil {
				return fmt.Errorf("loading from-checkpoint %q: %w", args[1], err)
			}
			toCP, err := checkpoint.LoadHistoryEntry(workdir, taskID, args[2])
			if err != nil {
				return fmt.Errorf("loading to-checkpoint %q: %w", args[2], err)
			}
			pairs = []diffPair{{
				from: &checkpoint.HistoryEntry{ID: args[1], Checkpoint: fromCP},
				to:   &checkpoint.HistoryEntry{ID: args[2], Checkpoint: toCP},
			}}
		} else {
			// All consecutive pairs
			for i := 0; i+1 < len(entries); i++ {
				pairs = append(pairs, diffPair{from: entries[i], to: entries[i+1]})
			}
			if len(pairs) == 0 && len(entries) == 1 {
				// Only one entry — show it as-is
				printCheckpointEntry(entries[0])
				return nil
			}
		}

		// Get task title from state for header
		taskTitle := fmt.Sprintf("Task %d", taskID)
		if s, sErr := state.Load(workdir); sErr == nil && s.Plan != nil {
			for _, t := range s.Plan.Tasks {
				if t.ID == taskID {
					taskTitle = fmt.Sprintf("Task %d: %s", t.ID, t.Title)
					break
				}
			}
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		sep := strings.Repeat("─", 72)
		fmt.Println(sep)
		headerColor.Printf("  Checkpoint Diff — %s\n", taskTitle)
		headerColor.Printf("  %d checkpoint(s), %d pair(s)\n", len(entries), len(pairs))
		fmt.Println(sep)
		fmt.Println()

		// Print each diff pair
		var narrateInputs []string
		for i, p := range pairs {
			narrative := printCheckpointDiff(i+1, p.from, p.to)
			narrateInputs = append(narrateInputs, narrative)
		}

		// Also list all checkpoint IDs at the bottom for reference
		dimColor := color.New(color.Faint)
		dimColor.Printf("\nAll checkpoint IDs for task %d:\n", taskID)
		for _, e := range entries {
			ts := e.Checkpoint.Timestamp.Format("2006-01-02 15:04:05")
			if e.Checkpoint.Timestamp.IsZero() {
				ts = "unknown"
			}
			dimColor.Printf("  %-20s  event=%-8s  %s\n", e.ID, e.Checkpoint.Event, ts)
		}

		// AI narration mode
		if cpDiffAI {
			fmt.Println()
			if err := narrationMode(workdir, taskTitle, narrateInputs); err != nil {
				return fmt.Errorf("AI narration: %w", err)
			}
		}

		return nil
	},
}

// printCheckpointEntry shows a single checkpoint entry (when only one exists).
func printCheckpointEntry(e *checkpoint.HistoryEntry) {
	headerColor := color.New(color.FgCyan, color.Bold)
	dimColor := color.New(color.Faint)
	cp := e.Checkpoint

	sep := strings.Repeat("─", 72)
	fmt.Println(sep)
	headerColor.Printf("  Task %d: %s — 1 checkpoint (no diff available)\n", cp.TaskID, cp.TaskTitle)
	fmt.Println(sep)
	fmt.Printf("\n  ID:     %s\n", e.ID)
	fmt.Printf("  Event:  %s\n", cp.Event)
	fmt.Printf("  Status: %s\n", cp.Status)
	if !cp.Timestamp.IsZero() {
		fmt.Printf("  Time:   %s\n", cp.Timestamp.Format("2006-01-02 15:04:05"))
	}
	if cp.TokenCount > 0 {
		fmt.Printf("  Tokens: %d\n", cp.TokenCount)
	}
	if cp.OutputLength > 0 {
		dimColor.Printf("  Output: %d chars  hash=%s\n", cp.OutputLength, cp.OutputHash)
	}
	fmt.Println()
}

// printCheckpointDiff renders the diff between two checkpoint entries and returns
// a plain-text summary suitable for AI narration.
func printCheckpointDiff(pairIdx int, from, to *checkpoint.HistoryEntry) string {
	fromCP := from.Checkpoint
	toCP := to.Checkpoint

	addColor := color.New(color.FgGreen)
	removeColor := color.New(color.FgRed)
	neutralColor := color.New(color.FgYellow)
	dimColor := color.New(color.Faint)
	headerColor := color.New(color.FgWhite, color.Bold)

	sep := strings.Repeat("╌", 68)

	headerColor.Printf("  Pair %d:  [%s] → [%s]\n", pairIdx,
		labelEvent(fromCP.Event), labelEvent(toCP.Event))
	dimColor.Printf("  From: %s  (%s)\n", from.ID, fromCP.Timestamp.Format("15:04:05"))
	dimColor.Printf("  To:   %s  (%s)\n", to.ID, toCP.Timestamp.Format("15:04:05"))
	fmt.Println()

	var sb strings.Builder // for AI narration text

	// Status transition
	if fromCP.Status != toCP.Status {
		removeColor.Printf("  - status:  %s\n", fromCP.Status)
		addColor.Printf("  + status:  %s\n", toCP.Status)
		fmt.Fprintf(&sb, "Status changed from %q to %q. ", fromCP.Status, toCP.Status)
	} else {
		dimColor.Printf("    status:  %s (unchanged)\n", fromCP.Status)
		fmt.Fprintf(&sb, "Status remained %q. ", fromCP.Status)
	}

	// Elapsed time
	var elapsed time.Duration
	if !fromCP.Timestamp.IsZero() && !toCP.Timestamp.IsZero() {
		elapsed = toCP.Timestamp.Sub(fromCP.Timestamp)
	} else if toCP.ElapsedSec > 0 {
		elapsed = time.Duration(toCP.ElapsedSec * float64(time.Second))
	}
	if elapsed > 0 {
		neutralColor.Printf("  Δ elapsed: %s\n", elapsed.Round(time.Millisecond))
		fmt.Fprintf(&sb, "Elapsed time: %s. ", elapsed.Round(time.Second))
	}

	// Token usage delta
	tokenDelta := toCP.TokenCount - fromCP.TokenCount
	if tokenDelta != 0 {
		if tokenDelta > 0 {
			addColor.Printf("  Δ tokens:  +%d  (total: %d)\n", tokenDelta, toCP.TokenCount)
		} else {
			removeColor.Printf("  Δ tokens:  %d  (total: %d)\n", tokenDelta, toCP.TokenCount)
		}
		fmt.Fprintf(&sb, "Token usage delta: %+d (total %d). ", tokenDelta, toCP.TokenCount)
	} else if toCP.TokenCount > 0 {
		dimColor.Printf("    tokens:  %d (unchanged)\n", toCP.TokenCount)
	}

	// Output length delta
	lenDelta := toCP.OutputLength - fromCP.OutputLength
	if lenDelta != 0 {
		if lenDelta > 0 {
			addColor.Printf("  Δ output:  +%d chars  (from %d to %d)\n", lenDelta, fromCP.OutputLength, toCP.OutputLength)
		} else {
			removeColor.Printf("  Δ output:  %d chars  (from %d to %d)\n", lenDelta, fromCP.OutputLength, toCP.OutputLength)
		}
		fmt.Fprintf(&sb, "Output length changed by %+d chars. ", lenDelta)
	} else if toCP.OutputLength > 0 {
		dimColor.Printf("    output:  %d chars (unchanged)\n", toCP.OutputLength)
	}

	// Output hash change
	if fromCP.OutputHash != "" && toCP.OutputHash != "" {
		if fromCP.OutputHash != toCP.OutputHash {
			removeColor.Printf("  - hash:    %s\n", fromCP.OutputHash)
			addColor.Printf("  + hash:    %s\n", toCP.OutputHash)
			fmt.Fprintf(&sb, "Output content changed (hash %s → %s). ", fromCP.OutputHash, toCP.OutputHash)
		} else {
			dimColor.Printf("    hash:    %s (unchanged)\n", fromCP.OutputHash)
		}
	} else if toCP.OutputHash != "" {
		addColor.Printf("  + hash:    %s\n", toCP.OutputHash)
		fmt.Fprintf(&sb, "New output hash: %s. ", toCP.OutputHash)
	}

	// Step number delta
	if fromCP.StepNumber != toCP.StepNumber {
		neutralColor.Printf("  Δ steps:   %d → %d (+%d)\n",
			fromCP.StepNumber, toCP.StepNumber, toCP.StepNumber-fromCP.StepNumber)
		fmt.Fprintf(&sb, "Steps progressed from %d to %d. ", fromCP.StepNumber, toCP.StepNumber)
	}

	fmt.Println()
	dimColor.Printf("  %s\n\n", sep)

	return sb.String()
}

func labelEvent(event string) string {
	switch event {
	case "start":
		return "start"
	case "complete":
		return "complete"
	case "fail":
		return "FAILED"
	case "skip":
		return "skipped"
	default:
		if event == "" {
			return "unknown"
		}
		return event
	}
}

// narrationMode calls the AI to summarize the checkpoint diffs in plain English.
func narrationMode(workdir, taskTitle string, narrateInputs []string) error {
	cfg, err := config.Load(workdir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	applyEnvOverrides(cfg)

	s, _ := state.Load(workdir)

	pName := cpDiffProvider
	if pName == "" {
		pName = cfg.Provider
	}
	if pName == "" && s != nil && s.Provider != "" {
		pName = s.Provider
	}
	if pName == "" {
		pName = autoSelectProvider()
	}

	model := cpDiffModel
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

	timeout := 2 * time.Minute
	if cpDiffTimeout != "" {
		timeout, err = time.ParseDuration(cpDiffTimeout)
		if err != nil {
			return fmt.Errorf("invalid timeout: %w", err)
		}
	}

	prompt := buildNarrationPrompt(taskTitle, narrateInputs)

	headerColor := color.New(color.FgCyan, color.Bold)
	headerColor.Printf("AI Narration (%s)\n", pName)
	sep := strings.Repeat("─", 72)
	fmt.Println(sep)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	opts := provider.Options{
		Model:   model,
		Timeout: timeout,
		OnToken: func(tok string) { fmt.Print(tok) },
	}

	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return fmt.Errorf("provider call: %w", err)
	}
	// If streaming, tokens were printed in-flight via OnToken; otherwise print now.
	if opts.OnToken == nil && result != nil {
		fmt.Print(result.Output)
	}
	fmt.Printf("\n%s\n", sep)
	return nil
}

func buildNarrationPrompt(taskTitle string, diffs []string) string {
	var sb strings.Builder
	sb.WriteString("You are analyzing checkpoint data for a software task execution.\n\n")
	sb.WriteString("Task: ")
	sb.WriteString(taskTitle)
	sb.WriteString("\n\n")
	sb.WriteString("Here are the observed changes between checkpoint pairs:\n\n")
	for i, d := range diffs {
		fmt.Fprintf(&sb, "Pair %d: %s\n", i+1, d)
	}
	sb.WriteString("\nWrite a concise plain-English narrative (3-5 sentences) explaining:\n")
	sb.WriteString("1. What happened during this task execution\n")
	sb.WriteString("2. Whether it succeeded, failed, or was skipped\n")
	sb.WriteString("3. Any notable changes (tokens used, output produced, time taken)\n")
	sb.WriteString("4. What the overall progression looks like\n\n")
	sb.WriteString("Be factual and concise. Do not repeat raw numbers verbatim — summarize them.\n")
	return sb.String()
}

func init() {
	taskCheckpointDiffCmd.Flags().BoolVar(&cpDiffAI, "ai", false, "Use AI to narrate the checkpoint diff in plain English")
	taskCheckpointDiffCmd.Flags().StringVar(&cpDiffProvider, "provider", "", "AI provider for --ai narration (anthropic, openai, ollama, claudecode)")
	taskCheckpointDiffCmd.Flags().StringVar(&cpDiffModel, "model", "", "Model override for --ai narration")
	taskCheckpointDiffCmd.Flags().StringVar(&cpDiffTimeout, "timeout", "2m", "Timeout for the AI call (e.g. 2m, 300s)")
}
