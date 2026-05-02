package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/daemon"
	"github.com/blechschmidt/cloop/pkg/filewatch"
	"github.com/blechschmidt/cloop/pkg/hooks"
	"github.com/blechschmidt/cloop/pkg/notify"
	"github.com/blechschmidt/cloop/pkg/orchestrator"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/webhook"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	daemonIntervalStr string
	daemonProvider    string
	daemonModel       string
	daemonTailN       int
	daemonLogLines    int
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Persistent background daemon: autonomous plan execution without a terminal",
	Long: `cloop daemon runs as a persistent background process that autonomously
executes PM tasks, watches file triggers, and fires scheduled plan
re-evaluations without requiring an active terminal session.

PID is stored in .cloop/daemon.pid; log output goes to .cloop/daemon.log.
All events integrate with configured hooks, notifications, and webhooks.

Start the daemon:
  cloop daemon start                         # check for work every 5 minutes
  cloop daemon start --interval 2m           # custom polling frequency
  cloop daemon start --provider anthropic    # specific AI provider

Monitor:
  cloop daemon status                        # running? last activity?
  cloop daemon logs                          # full log
  cloop daemon logs --tail 30               # last 30 lines

Stop / restart:
  cloop daemon stop
  cloop daemon restart`,
}

// daemonStartCmd spawns the daemon worker in the background.
var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the background daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Reject if already running.
		if running, pid := daemon.IsRunning(workdir); running {
			color.New(color.FgGreen, color.Bold).Printf("Daemon already running (pid %d)\n", pid)
			return nil
		}

		// Require an existing project.
		if _, err := state.Load(workdir); err != nil {
			return fmt.Errorf("no cloop project found — run 'cloop init' first")
		}

		// Validate interval.
		interval, err := time.ParseDuration(daemonIntervalStr)
		if err != nil || interval < 10*time.Second {
			return fmt.Errorf("--interval must be a valid duration >= 10s (e.g. 30s, 1m, 5m)")
		}

		// Open log file for the worker's stdout/stderr.
		logPath := daemon.LogPath(workdir)
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("opening log file: %w", err)
		}
		defer logFile.Close()

		// Resolve our own executable.
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolving executable: %w", err)
		}

		// Build worker args.
		workerArgs := []string{"daemon", "worker", "--interval", daemonIntervalStr}
		if daemonProvider != "" {
			workerArgs = append(workerArgs, "--provider", daemonProvider)
		}
		if daemonModel != "" {
			workerArgs = append(workerArgs, "--model", daemonModel)
		}

		// Spawn detached background process.
		workerCmd := exec.Command(exe, workerArgs...)
		workerCmd.Stdout = logFile
		workerCmd.Stderr = logFile
		workerCmd.Dir = workdir
		workerCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

		if err := workerCmd.Start(); err != nil {
			return fmt.Errorf("starting daemon worker: %w", err)
		}
		pid := workerCmd.Process.Pid
		// Detach so this process doesn't wait for the worker.
		if err := workerCmd.Process.Release(); err != nil {
			return fmt.Errorf("detaching worker: %w", err)
		}

		if err := daemon.WritePID(workdir, pid); err != nil {
			return fmt.Errorf("writing PID: %w", err)
		}

		bold := color.New(color.Bold)
		green := color.New(color.FgGreen, color.Bold)
		dim := color.New(color.Faint)

		green.Printf("Daemon started (pid %d)\n", pid)
		bold.Printf("Interval:  ")
		fmt.Printf("%s\n", daemonIntervalStr)
		bold.Printf("Provider:  ")
		prov := daemonProvider
		if prov == "" {
			prov = "(from config)"
		}
		fmt.Printf("%s\n", prov)
		bold.Printf("Log:       ")
		fmt.Printf("%s\n", logPath)
		fmt.Println()
		dim.Printf("Monitor: cloop daemon status\n")
		dim.Printf("Logs:    cloop daemon logs --tail 20\n")
		dim.Printf("Stop:    cloop daemon stop\n")

		return nil
	},
}

// daemonStopCmd terminates the running daemon.
var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the background daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		if err := daemon.Stop(workdir); err != nil {
			return err
		}
		color.New(color.FgGreen, color.Bold).Printf("Daemon stopped\n")
		return nil
	},
}

// daemonRestartCmd stops and restarts the daemon.
var daemonRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the background daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Stop if running (ignore "not running" errors).
		if running, _ := daemon.IsRunning(workdir); running {
			if err := daemon.Stop(workdir); err != nil {
				return fmt.Errorf("stopping daemon: %w", err)
			}
			// Give it a moment to terminate.
			time.Sleep(500 * time.Millisecond)
		}

		// Delegate to the start logic.
		return daemonStartCmd.RunE(cmd, args)
	},
}

// daemonStatusCmd shows the current daemon state.
var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status and recent activity",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		bold := color.New(color.Bold)
		green := color.New(color.FgGreen, color.Bold)
		red := color.New(color.FgRed, color.Bold)
		yellow := color.New(color.FgYellow, color.Bold)
		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)

		running, pid := daemon.IsRunning(workdir)

		cyan.Printf("━━━ cloop daemon status ━━━\n\n")

		bold.Printf("Running:   ")
		if running {
			green.Printf("yes (pid %d)\n", pid)
		} else {
			yellow.Printf("no\n")
		}

		s, err := daemon.Load(workdir)
		if err != nil {
			return err
		}
		if s == nil {
			if !running {
				dim.Printf("\nDaemon has never been started. Run: cloop daemon start\n")
			}
			return nil
		}

		bold.Printf("Status:    ")
		switch s.Status {
		case "running":
			green.Printf("%s\n", s.Status)
		case "idle":
			cyan.Printf("%s\n", s.Status)
		case "stopped":
			yellow.Printf("%s\n", s.Status)
		case "error":
			red.Printf("%s\n", s.Status)
		default:
			fmt.Printf("%s\n", s.Status)
		}

		bold.Printf("Interval:  ")
		fmt.Printf("%s\n", s.Interval)

		if s.Provider != "" {
			bold.Printf("Provider:  ")
			fmt.Printf("%s", s.Provider)
			if s.Model != "" {
				fmt.Printf(" (%s)", s.Model)
			}
			fmt.Println()
		}

		bold.Printf("Started:   ")
		fmt.Printf("%s\n", s.StartedAt.Format("2006-01-02 15:04:05"))

		if !s.LastRunAt.IsZero() {
			bold.Printf("Last run:  ")
			ago := time.Since(s.LastRunAt).Round(time.Second)
			fmt.Printf("%s (%s ago)\n", s.LastRunAt.Format("15:04:05"), ago)
		}

		if !s.NextRunAt.IsZero() && running {
			bold.Printf("Next run:  ")
			in := time.Until(s.NextRunAt).Round(time.Second)
			if in < 0 {
				in = 0
			}
			fmt.Printf("%s (in %s)\n", s.NextRunAt.Format("15:04:05"), in)
		}

		bold.Printf("Cycles:    ")
		fmt.Printf("%d\n", s.RunCount)

		bold.Printf("Completed: ")
		green.Printf("%d tasks\n", s.TotalTasksCompleted)

		if s.TotalTasksFailed > 0 {
			bold.Printf("Failed:    ")
			red.Printf("%d tasks\n", s.TotalTasksFailed)
		}

		if s.WatchEnabled {
			bold.Printf("File watch:")
			fmt.Printf(" enabled (%d triggers)\n", s.WatchTriggers)
		}

		if s.LastError != "" {
			bold.Printf("Last err:  ")
			red.Printf("%s\n", s.LastError)
		}

		// Show recent log lines.
		fmt.Println()
		logPath := daemon.LogPath(workdir)
		if data, err := os.ReadFile(logPath); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			tail := 8
			if len(lines) < tail {
				tail = len(lines)
			}
			if tail > 0 {
				cyan.Printf("━━━ Recent log ━━━\n")
				for _, line := range lines[len(lines)-tail:] {
					dim.Printf("  %s\n", line)
				}
			}
		}

		if !running {
			fmt.Println()
			dim.Printf("Start with: cloop daemon start\n")
		}

		return nil
	},
}

// daemonLogsCmd prints the daemon log file.
var daemonLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View daemon log output",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		logPath := daemon.LogPath(workdir)

		data, err := os.ReadFile(logPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No daemon log found. Start the daemon first: cloop daemon start")
				return nil
			}
			return err
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if daemonTailN > 0 && len(lines) > daemonTailN {
			lines = lines[len(lines)-daemonTailN:]
		}
		for _, line := range lines {
			fmt.Println(line)
		}
		return nil
	},
}

// daemonFollowCmd streams the daemon log in real time.
var daemonFollowCmd = &cobra.Command{
	Use:   "follow",
	Short: "Follow the daemon log in real time",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		logPath := daemon.LogPath(workdir)

		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)

		cyan.Printf("Following daemon log (Ctrl+C to stop)...\n\n")

		// Print existing tail first.
		if data, err := os.ReadFile(logPath); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			tail := daemonLogLines
			if tail <= 0 {
				tail = 20
			}
			if len(lines) > tail {
				lines = lines[len(lines)-tail:]
				dim.Printf("  ... (showing last %d lines) ...\n", tail)
			}
			for _, line := range lines {
				fmt.Println(line)
			}
		}

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigCh)

		f, err := os.Open(logPath)
		if err != nil {
			return fmt.Errorf("opening log: %w", err)
		}
		defer f.Close()

		f.Seek(0, 2) // seek to end
		reader := bufio.NewReader(f)

		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-sigCh:
				fmt.Println()
				return nil
			case <-ticker.C:
				for {
					line, err := reader.ReadString('\n')
					if len(line) > 0 {
						fmt.Print(line)
					}
					if err != nil {
						break
					}
				}
			}
		}
	},
}

// daemonWorkerCmd is the hidden internal loop that the detached process runs.
var daemonWorkerCmd = &cobra.Command{
	Use:    "worker",
	Short:  "Internal: run the daemon loop (do not call directly)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		interval, err := time.ParseDuration(daemonIntervalStr)
		if err != nil {
			interval = 5 * time.Minute
		}

		logf := func(format string, a ...interface{}) {
			ts := time.Now().Format("2006-01-02 15:04:05")
			msg := fmt.Sprintf("[%s] "+format, append([]interface{}{ts}, a...)...)
			fmt.Println(msg)
		}

		logf("Daemon worker started (pid %d), interval=%s", os.Getpid(), interval)

		// Load config once to check for file-watch globs.
		cfg, cfgErr := config.Load(workdir)

		// Write initial state.
		s := &daemon.State{
			PID:          os.Getpid(),
			StartedAt:    time.Now(),
			Status:       "idle",
			Interval:     daemonIntervalStr,
			Provider:     daemonProvider,
			Model:        daemonModel,
			WatchEnabled: cfgErr == nil && len(cfg.Watch.Globs) > 0,
		}
		_ = s.Save(workdir)

		// Handle shutdown signals.
		ctx, cancel := context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			sig := <-sigCh
			logf("Received %s, shutting down", sig)
			cancel()
		}()

		defer func() {
			s.Status = "stopped"
			_ = s.Save(workdir)
			daemon.RemovePID(workdir)
			logf("Daemon worker stopped")
		}()

		// Start file watcher goroutine if globs are configured.
		if cfgErr == nil && len(cfg.Watch.Globs) > 0 {
			debounce := 2 * time.Second
			if cfg.Watch.Debounce != "" {
				if d, err2 := time.ParseDuration(cfg.Watch.Debounce); err2 == nil {
					debounce = d
				}
			}
			fwCfg := filewatch.Config{
				WorkDir:  workdir,
				Globs:    cfg.Watch.Globs,
				Debounce: debounce,
			}
			go func() {
				logf("File watcher started: %v", cfg.Watch.Globs)
				watchErr := filewatch.Run(ctx, fwCfg, func(evt filewatch.ChangeEvent) {
					logf("File change detected: %s (%d tasks reset)", evt.Context, len(evt.ResetTaskIDs))
					s.WatchTriggers++
					_ = s.Save(workdir)
					// Trigger an immediate orchestrator cycle.
					runDaemonCycle(ctx, workdir, s, cfg, logf)
				})
				if watchErr != nil && ctx.Err() == nil {
					logf("File watcher error: %v", watchErr)
				}
			}()
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Run once immediately on start.
		runDaemonCycle(ctx, workdir, s, cfg, logf)

		for {
			s.NextRunAt = time.Now().Add(interval)
			_ = s.Save(workdir)

			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if ctx.Err() != nil {
					return nil
				}
				// Re-load config each cycle so hot config changes are picked up.
				if c, err2 := config.Load(workdir); err2 == nil {
					cfg = c
				}
				runDaemonCycle(ctx, workdir, s, cfg, logf)
			}
		}
	},
}

// runDaemonCycle executes one daemon iteration: check for pending tasks and run them.
// It integrates with hooks, notify, and webhook packages.
func runDaemonCycle(ctx context.Context, workdir string, s *daemon.State, cfg *config.Config, logf func(string, ...interface{})) {
	s.Status = "running"
	s.LastRunAt = time.Now()
	s.RunCount++
	s.LastError = ""
	_ = s.Save(workdir)

	logf("Cycle #%d: checking for work", s.RunCount)

	// Load project state.
	projectState, err := state.Load(workdir)
	if err != nil {
		s.Status = "error"
		s.LastError = err.Error()
		_ = s.Save(workdir)
		logf("ERROR loading state: %v", err)
		return
	}

	if !projectState.PMMode || projectState.Plan == nil {
		s.Status = "idle"
		s.LastError = "not in PM mode — run 'cloop run --pm' first to create a plan"
		_ = s.Save(workdir)
		logf("No PM plan found, idle")
		return
	}

	// Count pending / in-progress tasks.
	pending, inProgress := 0, 0
	for _, t := range projectState.Plan.Tasks {
		switch t.Status {
		case "pending":
			pending++
		case "in_progress":
			inProgress++
		}
	}

	logf("Tasks: %d pending, %d in_progress", pending, inProgress)

	if pending == 0 && inProgress == 0 {
		s.Status = "idle"
		_ = s.Save(workdir)
		logf("All tasks complete — daemon idle")
		return
	}

	// Build provider.
	providerName := daemonProvider
	if cfg != nil {
		if providerName == "" {
			providerName = cfg.Provider
		}
	}
	if providerName == "" {
		providerName = projectState.Provider
	}
	if providerName == "" {
		providerName = "claudecode"
	}

	model := daemonModel
	if model == "" && cfg != nil {
		switch providerName {
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

	var provCfg provider.ProviderConfig
	if cfg != nil {
		provCfg = provider.ProviderConfig{
			Name:             providerName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
	} else {
		provCfg = provider.ProviderConfig{Name: providerName}
	}

	prov, err := provider.Build(provCfg)
	if err != nil {
		s.Status = "error"
		s.LastError = fmt.Sprintf("building provider: %v", err)
		_ = s.Save(workdir)
		logf("ERROR building provider %q: %v", providerName, err)
		return
	}

	// Fire pre-plan hook if configured.
	if cfg != nil && cfg.Hooks.PrePlan != "" {
		plan := projectState.Plan
		hctx := hooks.PlanContext{
			Goal:  plan.Goal,
			Total: len(plan.Tasks),
		}
		if err := hooks.RunPrePlan(hooks.Config{PrePlan: cfg.Hooks.PrePlan}, hctx); err != nil {
			logf("pre_plan hook failed: %v", err)
		}
	}

	// Send webhook: session started.
	if cfg != nil && cfg.Webhook.URL != "" {
		wc := webhook.New(cfg.Webhook.URL, cfg.Webhook.Events, cfg.Webhook.Headers, cfg.Webhook.Secret)
		wc.Send(webhook.EventSessionStarted, webhook.Payload{
			Goal: projectState.Plan.Goal,
		})
	}

	logf("Running orchestrator (provider=%s, model=%s)", providerName, model)

	doneBefore := daemonCountTasks(projectState, "done")
	failedBefore := daemonCountTasks(projectState, "failed")

	orchCfg := orchestrator.Config{
		WorkDir:      workdir,
		Model:        model,
		StepTimeout:  5 * time.Minute,
		PMMode:       true,
		StepsLimit:   1, // one task per cycle
		ProviderName: providerName,
		ProviderCfg:  provCfg,
	}

	orch, err := orchestrator.New(orchCfg, prov)
	if err != nil {
		s.Status = "error"
		s.LastError = err.Error()
		_ = s.Save(workdir)
		logf("ERROR creating orchestrator: %v", err)
		return
	}

	if err := orch.Run(ctx); err != nil && ctx.Err() == nil {
		s.Status = "error"
		s.LastError = err.Error()
		logf("ERROR during orchestrator run: %v", err)
	}

	// Reload state to see changes.
	newState, _ := state.Load(workdir)
	if newState != nil && newState.Plan != nil {
		doneAfter := daemonCountTasks(newState, "done")
		failedAfter := daemonCountTasks(newState, "failed")
		newDone := doneAfter - doneBefore
		newFailed := failedAfter - failedBefore

		s.TotalTasksCompleted += newDone
		s.TotalTasksFailed += newFailed

		if newDone > 0 {
			logf("Completed %d task(s) this cycle", newDone)
			// Desktop notification.
			notify.Send("cloop daemon", fmt.Sprintf("Completed %d task(s)", newDone))
		}
		if newFailed > 0 {
			logf("Failed %d task(s) this cycle", newFailed)
			notify.Send("cloop daemon", fmt.Sprintf("Failed %d task(s)", newFailed))
		}

		// Fire post-plan hook when all tasks are complete.
		if cfg != nil && cfg.Hooks.PostPlan != "" {
			plan := newState.Plan
			done2 := daemonCountTasks(newState, "done")
			failed2 := daemonCountTasks(newState, "failed")
			skipped2 := daemonCountTasks(newState, "skipped")
			if done2+failed2+skipped2 == len(plan.Tasks) {
				hctx := hooks.PlanContext{
					Goal:    plan.Goal,
					Total:   len(plan.Tasks),
					Done:    done2,
					Failed:  failed2,
					Skipped: skipped2,
				}
				if err := hooks.RunPostPlan(hooks.Config{PostPlan: cfg.Hooks.PostPlan}, hctx); err != nil {
					logf("post_plan hook failed: %v", err)
				}
			}
		}

		// Send webhook: plan complete or session summary.
		if cfg != nil && cfg.Webhook.URL != "" {
			wc := webhook.New(cfg.Webhook.URL, cfg.Webhook.Events, cfg.Webhook.Headers, cfg.Webhook.Secret)
			plan := newState.Plan
			done2 := daemonCountTasks(newState, "done")
			total := len(plan.Tasks)
			if done2 == total {
				wc.Send(webhook.EventPlanComplete, webhook.Payload{
					Goal: plan.Goal,
					Session: &webhook.SessionInfo{
						TotalTasks: total,
						DoneTasks:  done2,
					},
				})
			} else {
				wc.Send(webhook.EventSessionComplete, webhook.Payload{
					Goal: plan.Goal,
					Progress: &webhook.Progress{
						Done:  done2,
						Total: total,
					},
				})
			}
		}
	}

	s.Status = "idle"
	_ = s.Save(workdir)
	logf("Cycle #%d complete", s.RunCount)
}

func daemonCountTasks(ps *state.ProjectState, status string) int {
	if ps.Plan == nil {
		return 0
	}
	n := 0
	for _, t := range ps.Plan.Tasks {
		if string(t.Status) == status {
			n++
		}
	}
	return n
}

func init() {
	// start / restart share the same flags.
	for _, c := range []*cobra.Command{daemonStartCmd, daemonRestartCmd} {
		c.Flags().StringVar(&daemonIntervalStr, "interval", "5m", "How often the daemon checks for work (e.g. 30s, 1m, 5m)")
		c.Flags().StringVar(&daemonProvider, "provider", "", "AI provider to use (default: from config)")
		c.Flags().StringVar(&daemonModel, "model", "", "Model to use for task execution")
	}

	daemonLogsCmd.Flags().IntVar(&daemonTailN, "tail", 0, "Show only last N lines (0 = all)")

	daemonFollowCmd.Flags().IntVar(&daemonLogLines, "lines", 20, "Number of existing lines to show before following")

	// Worker flags (internal).
	daemonWorkerCmd.Flags().StringVar(&daemonIntervalStr, "interval", "5m", "")
	daemonWorkerCmd.Flags().StringVar(&daemonProvider, "provider", "", "")
	daemonWorkerCmd.Flags().StringVar(&daemonModel, "model", "", "")

	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonRestartCmd)
	daemonCmd.AddCommand(daemonLogsCmd)
	daemonCmd.AddCommand(daemonFollowCmd)
	daemonCmd.AddCommand(daemonWorkerCmd)

	rootCmd.AddCommand(daemonCmd)
}
