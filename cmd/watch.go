package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/filewatch"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	watchIntervalStr string
	watchGlobs       []string
	watchDebounceStr string
	watchAutoRun     bool
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Live-refresh status or trigger plan re-evaluation on file changes",
	Long: `Watch has two modes:

  Default (no --glob): polls project state and refreshes the display on a
  fixed interval. Useful when cloop run is in another terminal.

  File-watch mode (--glob): monitors file patterns with fsnotify. When a
  watched file changes, cloop resets relevant tasks to pending and (with
  --auto-run) triggers re-execution. Ideal for TDD-style AI loops.

  Examples:
    cloop watch                          # live status dashboard
    cloop watch --glob "**/*.go"         # re-evaluate plan on Go file changes
    cloop watch --glob "**/*.go" --auto-run  # re-evaluate and re-run automatically
    cloop watch --glob "src/**" --glob "tests/**" --debounce 5s

Glob patterns support ** for recursive matching (e.g. "**/*.go", "src/**/*.ts").
Multiple --glob flags are OR-combined.

Press Ctrl+C to stop.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// File-watch mode when --glob is provided.
		if len(watchGlobs) > 0 {
			return runFileWatchMode(workdir)
		}

		// Default: status polling mode.
		return runStatusWatchMode(workdir)
	},
}

// runFileWatchMode uses fsnotify to monitor files and trigger plan re-evaluation.
func runFileWatchMode(workdir string) error {
	debounce := 2 * time.Second
	if watchDebounceStr != "" {
		d, err := time.ParseDuration(watchDebounceStr)
		if err != nil {
			return fmt.Errorf("invalid --debounce: %w", err)
		}
		debounce = d
	}

	// Load config for additional watch patterns.
	cfg, err := config.Load(workdir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	globs := watchGlobs
	if len(globs) == 0 && len(cfg.Watch.Globs) > 0 {
		globs = cfg.Watch.Globs
	}
	if debounce == 2*time.Second && cfg.Watch.Debounce != "" {
		if d, err := time.ParseDuration(cfg.Watch.Debounce); err == nil {
			debounce = d
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[watch] stopping...")
		cancel()
	}()
	defer signal.Stop(sigCh)

	fwCfg := filewatch.Config{
		WorkDir:  workdir,
		Globs:    globs,
		Debounce: debounce,
	}

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	onTrigger := func(evt filewatch.ChangeEvent) {
		filewatch.PrintEvent(evt)

		if len(evt.ResetTaskIDs) > 0 && watchAutoRun {
			bold.Printf("[watch] triggering cloop run --pm ...\n")
			runArgs := []string{"run", "--pm"}
			runCmd := exec.CommandContext(ctx, os.Args[0], runArgs...)
			runCmd.Stdout = os.Stdout
			runCmd.Stderr = os.Stderr
			runCmd.Dir = workdir
			if err := runCmd.Run(); err != nil {
				dim.Printf("[watch] cloop run exited: %v\n", err)
			}
		} else if len(evt.ResetTaskIDs) > 0 {
			dim.Printf("[watch] run 'cloop run --pm' to re-execute, or use --auto-run\n")
		}
	}

	return filewatch.Run(ctx, fwCfg, onTrigger)
}

// runStatusWatchMode polls state and refreshes the display on a fixed interval.
func runStatusWatchMode(workdir string) error {
	interval := 2 * time.Second
	if watchIntervalStr != "" {
		d, err := time.ParseDuration(watchIntervalStr)
		if err != nil {
			return fmt.Errorf("invalid --interval: %w", err)
		}
		interval = d
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

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
			if s != nil && (s.Status == "complete" || s.Status == "failed") {
				return nil
			}
		}
	}
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
	watchCmd.Flags().StringVar(&watchIntervalStr, "interval", "2s", "Status-poll refresh interval (e.g. 1s, 5s, 10s)")
	watchCmd.Flags().StringArrayVar(&watchGlobs, "glob", nil, "File glob pattern to watch (repeatable; enables file-watch mode)")
	watchCmd.Flags().StringVar(&watchDebounceStr, "debounce", "2s", "Debounce duration after last file change before triggering (e.g. 500ms, 5s)")
	watchCmd.Flags().BoolVar(&watchAutoRun, "auto-run", false, "Automatically run 'cloop run --pm' after each triggered re-evaluation")
	rootCmd.AddCommand(watchCmd)
}
