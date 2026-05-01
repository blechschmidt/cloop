package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var watchIntervalStr string

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Live-refresh the project status while cloop runs",
	Long: `Watch polls the project state and refreshes the display on a fixed interval.
Useful when cloop run is running in another terminal.

Press Ctrl+C to stop watching.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		interval := 2 * time.Second
		if watchIntervalStr != "" {
			d, err := time.ParseDuration(watchIntervalStr)
			if err != nil {
				return fmt.Errorf("invalid --interval: %w", err)
			}
			interval = d
		}

		workdir, _ := os.Getwd()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigCh)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Initial render before first tick
		clearScreen()
		if _, err := renderWatchView(workdir, interval); err != nil {
			return err
		}

		for {
			select {
			case <-sigCh:
				fmt.Println()
				return nil
			case <-ticker.C:
				clearScreen()
				s, err := renderWatchView(workdir, interval)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					continue
				}
				// Auto-stop when session ends
				if s != nil && (s.Status == "complete" || s.Status == "failed") {
					return nil
				}
			}
		}
	},
}

// clearScreen moves cursor to top-left and clears the terminal.
func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// renderWatchView prints the live status panel and returns the loaded state.
func renderWatchView(workdir string, interval time.Duration) (*state.ProjectState, error) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	magenta := color.New(color.FgMagenta)

	s, err := state.Load(workdir)
	if err != nil {
		return nil, err
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	cyan.Printf("━━━ cloop watch [%s] ━━━\n\n", now)

	// Goal (truncated to terminal width)
	bold.Printf("Goal:     ")
	fmt.Printf("%s\n", truncateWatch(s.Goal, 70))

	// Status with color
	bold.Printf("Status:   ")
	switch s.Status {
	case "complete":
		green.Printf("%s\n", s.Status)
	case "running", "evolving":
		cyan.Printf("%s\n", s.Status)
	case "failed":
		red.Printf("%s\n", s.Status)
	default:
		yellow.Printf("%s\n", s.Status)
	}

	// Provider
	prov := s.Provider
	if prov == "" {
		prov = "claudecode"
	}
	bold.Printf("Provider: ")
	fmt.Printf("%s\n", prov)
	if s.Model != "" {
		bold.Printf("Model:    ")
		fmt.Printf("%s\n", s.Model)
	}

	// Progress
	if s.PMMode && s.Plan != nil {
		bold.Printf("Tasks:    ")
		magenta.Printf("%s\n", s.Plan.Summary())

		sorted := make([]*pm.Task, len(s.Plan.Tasks))
		copy(sorted, s.Plan.Tasks)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].Priority < sorted[j].Priority
		})
		for _, t := range sorted {
			dim.Printf("          %s Task %d: %s\n", taskMarker(t.Status), t.ID, truncateWatch(t.Title, 60))
		}
	} else {
		bold.Printf("Steps:    ")
		if s.MaxSteps > 0 {
			fmt.Printf("%d / %d\n", s.CurrentStep, s.MaxSteps)
		} else {
			fmt.Printf("%d (unlimited)\n", s.CurrentStep)
		}
	}

	// Tokens
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		bold.Printf("Tokens:   ")
		fmt.Printf("%d in / %d out\n", s.TotalInputTokens, s.TotalOutputTokens)
	}

	// Timeline
	elapsed := time.Since(s.CreatedAt).Round(time.Second)
	bold.Printf("Elapsed:  ")
	fmt.Printf("%s\n", elapsed)

	fmt.Println()

	// Last step output
	if len(s.Steps) > 0 {
		last := s.Steps[len(s.Steps)-1]
		yellow.Printf("━━━ Last step (#%d): %s [%s] ━━━\n", last.Step+1, last.Task, last.Duration)
		lines := strings.Split(strings.TrimSpace(last.Output), "\n")
		// Show last 15 lines
		if len(lines) > 15 {
			dim.Printf("  ... (%d lines omitted) ...\n", len(lines)-15)
			lines = lines[len(lines)-15:]
		}
		for _, line := range lines {
			fmt.Printf("  %s\n", line)
		}
		fmt.Println()
	}

	dim.Printf("Refreshing every %s — press Ctrl+C to stop\n", interval)

	return s, nil
}

func truncateWatch(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func init() {
	watchCmd.Flags().StringVar(&watchIntervalStr, "interval", "2s", "Refresh interval (e.g. 1s, 5s, 10s)")
	rootCmd.AddCommand(watchCmd)
}
