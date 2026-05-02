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

	"github.com/blechschmidt/cloop/pkg/agent"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/orchestrator"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	agentIntervalStr string
	agentProvider    string
	agentModel       string
	agentTail        int
	agentLogLines    int

	// agentRun flags
	agentRunMaxSteps int
	agentRunTimeout  string
	agentRunDryRun   bool
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Autonomous background agent: execute PM tasks without supervision",
	Long: `cloop agent runs as a background daemon, autonomously executing pending
PM tasks at a regular interval. It picks up where you left off, works
through the task queue, and notifies you via webhook when done.

Start the agent:
  cloop agent start                         # every 5 minutes
  cloop agent start --interval 2m           # every 2 minutes
  cloop agent start --provider anthropic    # use Claude API

Monitor the agent:
  cloop agent status                        # is it running? what's it doing?
  cloop agent logs                          # full log stream
  cloop agent logs --tail 30               # last 30 lines

Stop the agent:
  cloop agent stop`,
}

// agentStartCmd spawns the worker daemon in the background.
var agentStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the autonomous background agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Check if already running
		if running, pid := agent.IsRunning(workdir); running {
			green := color.New(color.FgGreen, color.Bold)
			green.Printf("Agent already running (pid %d)\n", pid)
			return nil
		}

		// Validate project exists
		if _, err := state.Load(workdir); err != nil {
			return fmt.Errorf("no cloop project found — run 'cloop init' first")
		}

		// Parse interval
		interval, err := time.ParseDuration(agentIntervalStr)
		if err != nil || interval < 30*time.Second {
			return fmt.Errorf("--interval must be a valid duration >= 30s (e.g. 1m, 5m, 10m)")
		}

		// Open log file
		logPath := agent.LogPath(workdir)
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("opening log file: %w", err)
		}
		defer logFile.Close()

		// Get current executable path
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolving executable: %w", err)
		}

		// Build worker args
		workerArgs := []string{"agent", "worker",
			"--interval", agentIntervalStr,
		}
		if agentProvider != "" {
			workerArgs = append(workerArgs, "--provider", agentProvider)
		}
		if agentModel != "" {
			workerArgs = append(workerArgs, "--model", agentModel)
		}

		// Spawn detached background process
		workerCmd := exec.Command(exe, workerArgs...)
		workerCmd.Stdout = logFile
		workerCmd.Stderr = logFile
		workerCmd.Dir = workdir
		workerCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

		if err := workerCmd.Start(); err != nil {
			return fmt.Errorf("starting agent worker: %w", err)
		}

		pid := workerCmd.Process.Pid
		// Detach from parent
		if err := workerCmd.Process.Release(); err != nil {
			return fmt.Errorf("detaching worker: %w", err)
		}

		// Write PID file
		if err := agent.WritePID(workdir, pid); err != nil {
			return fmt.Errorf("writing PID: %w", err)
		}

		bold := color.New(color.Bold)
		green := color.New(color.FgGreen, color.Bold)
		dim := color.New(color.Faint)

		green.Printf("Agent started (pid %d)\n", pid)
		bold.Printf("Interval:  ")
		fmt.Printf("%s\n", agentIntervalStr)
		bold.Printf("Provider:  ")
		prov := agentProvider
		if prov == "" {
			prov = "(from config)"
		}
		fmt.Printf("%s\n", prov)
		bold.Printf("Log:       ")
		fmt.Printf("%s\n", logPath)
		fmt.Println()
		dim.Printf("Monitor: cloop agent status\n")
		dim.Printf("Logs:    cloop agent logs --tail 20\n")
		dim.Printf("Stop:    cloop agent stop\n")

		return nil
	},
}

// agentStopCmd stops the running daemon.
var agentStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the background agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		if err := agent.Stop(workdir); err != nil {
			return err
		}

		green := color.New(color.FgGreen, color.Bold)
		green.Printf("Agent stopped\n")
		return nil
	},
}

// agentStatusCmd shows current daemon status.
var agentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show agent status and recent activity",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		bold := color.New(color.Bold)
		green := color.New(color.FgGreen, color.Bold)
		red := color.New(color.FgRed, color.Bold)
		yellow := color.New(color.FgYellow, color.Bold)
		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)

		running, pid := agent.IsRunning(workdir)

		cyan.Printf("━━━ cloop agent status ━━━\n\n")

		bold.Printf("Running:   ")
		if running {
			green.Printf("yes (pid %d)\n", pid)
		} else {
			yellow.Printf("no\n")
		}

		// Load agent state
		s, err := agent.Load(workdir)
		if err != nil {
			return err
		}
		if s == nil {
			if !running {
				dim.Printf("\nAgent has never been started. Run: cloop agent start\n")
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

		bold.Printf("Runs:      ")
		fmt.Printf("%d\n", s.RunCount)

		bold.Printf("Completed: ")
		green.Printf("%d tasks\n", s.TotalTasksCompleted)

		if s.TotalTasksFailed > 0 {
			bold.Printf("Failed:    ")
			red.Printf("%d tasks\n", s.TotalTasksFailed)
		}

		if s.LastError != "" {
			bold.Printf("Last err:  ")
			red.Printf("%s\n", s.LastError)
		}

		// Show log tail
		fmt.Println()
		logPath := agent.LogPath(workdir)
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
			dim.Printf("Start with: cloop agent start\n")
		}

		return nil
	},
}

// agentLogsCmd tails the agent log file.
var agentLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show agent log output",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		logPath := agent.LogPath(workdir)

		data, err := os.ReadFile(logPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No agent log found. Start the agent first: cloop agent start")
				return nil
			}
			return err
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if agentTail > 0 && len(lines) > agentTail {
			lines = lines[len(lines)-agentTail:]
		}
		for _, line := range lines {
			fmt.Println(line)
		}
		return nil
	},
}

// agentWorkerCmd is the hidden internal command that runs the actual daemon loop.
var agentWorkerCmd = &cobra.Command{
	Use:    "worker",
	Short:  "Internal: run the agent daemon loop (do not call directly)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		interval, err := time.ParseDuration(agentIntervalStr)
		if err != nil {
			interval = 5 * time.Minute
		}

		logf := func(format string, a ...interface{}) {
			msg := fmt.Sprintf("[%s] "+format, append([]interface{}{time.Now().Format("2006-01-02 15:04:05")}, a...)...)
			fmt.Println(msg)
		}

		logf("Agent worker started (pid %d), interval=%s", os.Getpid(), interval)

		// Write initial state
		s := &agent.State{
			PID:       os.Getpid(),
			StartedAt: time.Now(),
			Status:    "idle",
			Interval:  agentIntervalStr,
			Provider:  agentProvider,
			Model:     agentModel,
		}
		if err := s.Save(workdir); err != nil {
			logf("ERROR saving agent state: %v", err)
		}

		// Handle shutdown signals
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
			s.Save(workdir)
			agent.RemovePID(workdir)
			logf("Agent worker stopped")
		}()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Run immediately on start, then on each tick
		runAgentCycle(ctx, workdir, s, logf)

		for {
			s.NextRunAt = time.Now().Add(interval)
			s.Save(workdir)

			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if ctx.Err() != nil {
					return nil
				}
				runAgentCycle(ctx, workdir, s, logf)
			}
		}
	},
}

// runAgentCycle executes one agent iteration: check for pending tasks and run them.
func runAgentCycle(ctx context.Context, workdir string, s *agent.State, logf func(string, ...interface{})) {
	s.Status = "running"
	s.LastRunAt = time.Now()
	s.RunCount++
	s.LastError = ""
	s.Save(workdir)

	logf("Cycle #%d: checking for work", s.RunCount)

	// Load project state
	projectState, err := state.Load(workdir)
	if err != nil {
		s.Status = "error"
		s.LastError = err.Error()
		s.Save(workdir)
		logf("ERROR loading state: %v", err)
		return
	}

	if !projectState.PMMode || projectState.Plan == nil {
		s.Status = "idle"
		s.LastError = "not in PM mode — run 'cloop run --pm' first to create a plan"
		s.Save(workdir)
		logf("No PM plan found, idle")
		return
	}

	// Count pending tasks
	pending := 0
	inProgress := 0
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
		s.Save(workdir)
		logf("All tasks complete — agent idle")
		return
	}

	// Load config and build provider
	cfg, err := config.Load(workdir)
	if err != nil {
		s.Status = "error"
		s.LastError = err.Error()
		s.Save(workdir)
		logf("ERROR loading config: %v", err)
		return
	}

	providerName := agentProvider
	if providerName == "" {
		providerName = cfg.Provider
	}
	if providerName == "" {
		providerName = projectState.Provider
	}
	if providerName == "" {
		providerName = "claudecode"
	}

	model := agentModel
	if model == "" {
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

	provCfg := provider.ProviderConfig{
		Name:             providerName,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}

	prov, err := provider.Build(provCfg)
	if err != nil {
		s.Status = "error"
		s.LastError = fmt.Sprintf("building provider: %v", err)
		s.Save(workdir)
		logf("ERROR building provider %q: %v", providerName, err)
		return
	}

	logf("Running orchestrator (provider=%s, model=%s)", providerName, model)

	// Track task counts before execution
	doneBefore := countTasks(projectState, "done")
	failedBefore := countTasks(projectState, "failed")

	orchCfg := orchestrator.Config{
		WorkDir:      workdir,
		Model:        model,
		StepTimeout:  5 * time.Minute,
		PMMode:       true,
		StepsLimit:   1, // execute one task per agent cycle
		ProviderName: providerName,
		ProviderCfg:  provCfg,
	}

	orch, err := orchestrator.New(orchCfg, prov)
	if err != nil {
		s.Status = "error"
		s.LastError = err.Error()
		s.Save(workdir)
		logf("ERROR creating orchestrator: %v", err)
		return
	}

	if err := orch.Run(ctx); err != nil && ctx.Err() == nil {
		s.Status = "error"
		s.LastError = err.Error()
		logf("ERROR during orchestrator run: %v", err)
	}

	// Reload state to see what changed
	newState, _ := state.Load(workdir)
	if newState != nil && newState.Plan != nil {
		doneAfter := countTasks(newState, "done")
		failedAfter := countTasks(newState, "failed")
		newDone := doneAfter - doneBefore
		newFailed := failedAfter - failedBefore

		s.TotalTasksCompleted += newDone
		s.TotalTasksFailed += newFailed

		if newDone > 0 {
			logf("Completed %d task(s) this cycle", newDone)
		}
		if newFailed > 0 {
			logf("Failed %d task(s) this cycle", newFailed)
		}
	}

	s.Status = "idle"
	s.Save(workdir)
	logf("Cycle #%d complete", s.RunCount)
}

func countTasks(ps *state.ProjectState, status string) int {
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

// agentRunCmd is the ReAct-style autonomous tool-using agent.
var agentRunCmd = &cobra.Command{
	Use:   "run <goal>",
	Short: "Run an autonomous tool-using ReAct agent to accomplish a goal",
	Long: `Run an autonomous ReAct (Reason + Act) agent that drives a think→act→observe
loop until the goal is achieved or the step limit is reached.

The agent has access to built-in tools:
  read_file     — read file contents
  write_file    — create or overwrite files
  run_shell     — execute shell commands
  search_files  — find files by glob pattern
  web_fetch     — fetch a URL's content

Examples:
  cloop agent run "List all Go source files and count lines of code"
  cloop agent run "Read README.md and summarise the key points"
  cloop agent run --dry-run "Create a hello.txt file with 'Hello World'"
  cloop agent run --max-steps 30 "Refactor the config package to add validation"`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		goal := strings.Join(args, " ")
		workDir, _ := os.Getwd()

		// Parse timeout
		timeout := 2 * time.Minute
		if agentRunTimeout != "" {
			d, err := time.ParseDuration(agentRunTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
			timeout = d
		}

		// Load config and build provider
		cfg, err := config.Load(workDir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		providerName := agentProvider
		if providerName == "" {
			providerName = cfg.Provider
		}
		if providerName == "" {
			providerName = "claudecode"
		}

		model := agentModel
		if model == "" {
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

		provCfg := provider.ProviderConfig{
			Name:             providerName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("building provider %q: %w", providerName, err)
		}

		a := agent.New(agent.AgentConfig{
			Provider: prov,
			Model:    model,
			Timeout:  timeout,
			DryRun:   agentRunDryRun,
			WorkDir:  workDir,
		})

		ctx, cancel := context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()
		defer signal.Stop(sigCh)

		if _, err := a.Run(ctx, goal, agentRunMaxSteps); err != nil {
			if ctx.Err() != nil {
				color.New(color.FgYellow, color.Bold).Printf("\nAgent interrupted.\n")
				return nil
			}
			return err
		}
		return nil
	},
}

// agentClearLogsCmd truncates the log file.
var agentClearLogsCmd = &cobra.Command{
	Use:   "clear-logs",
	Short: "Clear the agent log file",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		logPath := agent.LogPath(workdir)
		if err := os.WriteFile(logPath, []byte{}, 0o644); err != nil {
			return err
		}
		fmt.Println("Agent log cleared.")
		return nil
	},
}

// agentFollowCmd follows the agent log in real time (like tail -f).
var agentFollowCmd = &cobra.Command{
	Use:   "follow",
	Short: "Follow the agent log in real time",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		logPath := agent.LogPath(workdir)

		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)

		cyan.Printf("Following agent log (Ctrl+C to stop)...\n\n")

		// Print existing content first
		if data, err := os.ReadFile(logPath); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			tail := agentLogLines
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

		// Poll for new content
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigCh)

		f, err := os.Open(logPath)
		if err != nil {
			return fmt.Errorf("opening log: %w", err)
		}
		defer f.Close()

		// Seek to end
		f.Seek(0, 2)
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

func init() {
	// Shared flags
	agentStartCmd.Flags().StringVar(&agentIntervalStr, "interval", "5m", "How often the agent checks for work (e.g. 1m, 5m, 10m)")
	agentStartCmd.Flags().StringVar(&agentProvider, "provider", "", "AI provider to use (default: from config)")
	agentStartCmd.Flags().StringVar(&agentModel, "model", "", "Model to use for task execution")

	agentLogsCmd.Flags().IntVar(&agentTail, "tail", 0, "Show only last N lines (0 = all)")

	agentFollowCmd.Flags().IntVar(&agentLogLines, "lines", 20, "Number of existing lines to show before following")

	// Worker (internal, hidden) — shares agentIntervalStr/agentProvider/agentModel
	agentWorkerCmd.Flags().StringVar(&agentIntervalStr, "interval", "5m", "")
	agentWorkerCmd.Flags().StringVar(&agentProvider, "provider", "", "")
	agentWorkerCmd.Flags().StringVar(&agentModel, "model", "", "")

	// agentRunCmd flags
	agentRunCmd.Flags().IntVar(&agentRunMaxSteps, "max-steps", 20, "Maximum number of ReAct steps before stopping")
	agentRunCmd.Flags().StringVar(&agentRunTimeout, "timeout", "2m", "Per-step provider timeout (e.g. 30s, 2m, 5m)")
	agentRunCmd.Flags().BoolVar(&agentRunDryRun, "dry-run", false, "Print actions without executing shell/write tools")
	agentRunCmd.Flags().StringVar(&agentProvider, "provider", "", "AI provider (default: from config)")
	agentRunCmd.Flags().StringVar(&agentModel, "model", "", "Model to use")

	agentCmd.AddCommand(agentRunCmd)
	agentCmd.AddCommand(agentStartCmd)
	agentCmd.AddCommand(agentStopCmd)
	agentCmd.AddCommand(agentStatusCmd)
	agentCmd.AddCommand(agentLogsCmd)
	agentCmd.AddCommand(agentFollowCmd)
	agentCmd.AddCommand(agentClearLogsCmd)
	agentCmd.AddCommand(agentWorkerCmd)

	rootCmd.AddCommand(agentCmd)
}
