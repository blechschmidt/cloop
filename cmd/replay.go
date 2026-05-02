package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/replay"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var replayCmd = &cobra.Command{
	Use:   "replay [task-id]",
	Short: "Stream stored PM step outputs from the replay log",
	Long: `Stream all recorded PM step outputs from .cloop/replay.jsonl.

Optionally filter by a specific task ID. By default output is displayed with
realistic timing based on the original timestamps (configurable via --speed).
Use --json for raw JSONL output suitable for scripting.

Examples:
  cloop replay                    # replay all steps in sequence
  cloop replay 3                  # replay steps for task 3 only
  cloop replay --speed 2.0        # replay at 2x speed
  cloop replay --speed 0          # replay instantly (no delay)
  cloop replay --json             # raw JSONL output`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()

		taskID := 0
		if len(args) > 0 {
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid task-id %q: must be an integer", args[0])
			}
			taskID = id
		}

		speed, _ := cmd.Flags().GetFloat64("speed")
		jsonOut, _ := cmd.Flags().GetBool("json")

		entries, err := replay.Load(workDir, taskID)
		if err != nil {
			return fmt.Errorf("loading replay log: %w", err)
		}
		if len(entries) == 0 {
			if taskID > 0 {
				fmt.Printf("No replay entries found for task %d.\n", taskID)
			} else {
				fmt.Println("No replay entries found. Run 'cloop run --pm' to generate a log.")
			}
			return nil
		}

		if jsonOut {
			return replayJSON(entries)
		}
		return replayHuman(entries, speed)
	},
}

// replayJSON writes entries as raw JSONL to stdout.
func replayJSON(entries []replay.Entry) error {
	w := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return w.Flush()
}

// replayHuman streams entries to stdout with timing delays.
func replayHuman(entries []replay.Entry, speed float64) error {
	headerColor := color.New(color.FgYellow, color.Bold)
	dimColor := color.New(color.Faint)
	taskColor := color.New(color.FgCyan, color.Bold)

	headerColor.Printf("▶ Replaying %d step(s)", len(entries))
	if speed > 0 {
		headerColor.Printf(" at %.1fx speed", speed)
	} else {
		headerColor.Printf(" instantly")
	}
	headerColor.Println()
	fmt.Println()

	lastTS := entries[0].Ts
	for i, e := range entries {
		// Compute delay from gap between consecutive entries.
		if i > 0 && speed > 0 {
			gap := e.Ts.Sub(lastTS)
			if gap > 0 {
				delay := time.Duration(float64(gap) / speed)
				// Cap at 5 seconds to avoid very long waits.
				if delay > 5*time.Second {
					delay = 5 * time.Second
				}
				time.Sleep(delay)
			}
		}
		lastTS = e.Ts

		taskColor.Printf("━━━ Task %d: %s (step %d) ━━━\n", e.TaskID, e.TaskTitle, e.Step)
		dimColor.Printf("    %s\n\n", e.Ts.Format("2006-01-02 15:04:05"))

		// Print content line by line so it streams visually.
		printReplayContent(e.Content, speed)
		fmt.Println()
	}

	dimColor.Printf("✓ Replay complete (%d steps).\n", len(entries))
	return nil
}

// printReplayContent prints the content with per-line delays when speed > 0.
func printReplayContent(content string, speed float64) {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	for _, line := range lines {
		fmt.Println(line)
		if speed > 0 && len(lines) > 1 {
			// Small per-line delay to simulate streaming output (max 50ms).
			lineDelay := time.Duration(float64(20*time.Millisecond) / speed)
			if lineDelay > 50*time.Millisecond {
				lineDelay = 50 * time.Millisecond
			}
			time.Sleep(lineDelay)
		}
	}
}

func init() {
	replayCmd.Flags().Float64("speed", 1.0, "Playback speed multiplier (0 = instant, 2.0 = 2x faster)")
	replayCmd.Flags().Bool("json", false, "Output raw JSONL instead of formatted replay")
	rootCmd.AddCommand(replayCmd)
}
