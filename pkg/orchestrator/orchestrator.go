package orchestrator

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/checkpoint"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/diagnosis"
	cloopgit "github.com/blechschmidt/cloop/pkg/git"
	"github.com/blechschmidt/cloop/pkg/hooks"
	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/blechschmidt/cloop/pkg/notify"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/router"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/webhook"
	"github.com/fatih/color"
)

type Config struct {
	WorkDir     string
	Model       string
	MaxTokens   int
	StepTimeout time.Duration
	Verbose     bool
	DryRun      bool
	PMMode      bool
	PlanOnly    bool // only decompose tasks, don't execute them
	RetryFailed bool // retry failed tasks in PM mode
	Replan      bool // force re-decompose goal (wipes existing plan, keeps history)

	// MaxFailures is the number of consecutive task failures before PM mode stops (0 = default 3).
	MaxFailures int

	// ContextSteps is the number of recent steps to include in prompts (0 = default 3).
	ContextSteps int

	// StepsLimit is the maximum number of steps to run in this session only (not persisted).
	// 0 means no session limit. Takes precedence over MaxSteps when both are set.
	StepsLimit int

	// StepDelay is the duration to wait between steps (0 = no delay).
	StepDelay time.Duration

	// TokenBudget is the maximum total tokens (input + output) for the session (0 = unlimited).
	// When the cumulative token count reaches or exceeds this value the session pauses.
	TokenBudget int

	// CostLimit is the maximum estimated cost in USD for the session (0 = unlimited).
	// The session warns at 80% of the limit and pauses when the limit is reached.
	CostLimit float64

	// Provider to use. If empty, falls back to state.Provider, then config.yaml, then claudecode.
	ProviderName string

	// Provider config for building providers
	ProviderCfg provider.ProviderConfig

	// InnovateMode enables creative/experimental feature exploration in evolve prompts.
	InnovateMode bool

	// Parallel enables concurrent task execution in PM mode.
	// Independent tasks (all deps satisfied) run simultaneously.
	Parallel bool

	// MaxParallel is the maximum number of tasks to execute concurrently in PM
	// parallel mode. 0 (or unset) means no limit — all ready tasks run at once.
	// Setting this to 1 is equivalent to sequential execution.
	MaxParallel int

	// InjectContext enables project context injection (git status, file tree) into task prompts.
	InjectContext bool

	// AdaptiveReplan enables AI-driven replanning after task failures.
	// When enabled and a task fails, the provider re-thinks the remaining work.
	AdaptiveReplan bool

	// ReviewMode pauses before each task and waits for human approval (y/n/skip/quit).
	ReviewMode bool

	// Verify enables post-task verification: after TASK_DONE, run a second AI pass to confirm
	// the task was genuinely completed. If verification fails, the task is re-queued (up to 2 retries).
	Verify bool

	// MaxVerifyRetries is the max number of times a task can be re-queued by the verifier (default 2).
	MaxVerifyRetries int

	// UseMemory injects past session learnings into prompts.
	UseMemory bool

	// Learn extracts key learnings at end of session and saves them to memory.
	Learn bool

	// MemoryLimit is the max number of memory entries to inject into prompts (0 = all).
	MemoryLimit int

	// WebhookURL overrides the config-file webhook URL for this run (optional).
	WebhookURL string

	// WebhookEvents is the list of event types to fire (empty = all).
	WebhookEvents []string

	// WebhookSecret is used to sign each webhook POST body with HMAC-SHA256
	// in the X-Hub-Signature-256 header (GitHub-style). Empty = no signing.
	WebhookSecret string

	// Streaming enables token-by-token output to the terminal for providers that
	// support SSE streaming (anthropic, openai, ollama). When true, the orchestrator
	// passes an OnToken callback to Complete(); providers that do not support
	// streaming (e.g. claudecode) simply ignore it and fall back to buffered output.
	Streaming bool

	// Notify enables OS desktop notifications for key events: task done, task failed,
	// and session complete. Uses notify-send on Linux and osascript on macOS.
	Notify bool

	// Hooks configures shell commands run at task and plan lifecycle events.
	Hooks hooks.Config

	// DiagnoseFailures enables AI-powered failure diagnosis in PM mode (sequential only).
	// When a task emits TASK_FAILED, a second AI call analyzes the failure output and
	// stores a diagnosis in task.FailureDiagnosis. On retry (--retry-failed), the
	// diagnosis is injected into the retry prompt so the AI can correct its approach.
	DiagnoseFailures bool

	// GitMode enables per-task git branch workflow in PM mode (sequential only).
	// Each task is executed on a dedicated branch cloop/task-<id>-<slug>.
	// On TASK_DONE the branch is committed and merged back to the original branch.
	// On TASK_FAILED the branch is left open for inspection.
	GitMode bool

	// ContextTokenLimit is the maximum estimated token count for step/task-result history
	// included in prompts. When the accumulated history exceeds this limit the orchestrator
	// prunes oldest intermediate entries (keeping the first and last two) before building
	// the prompt. 0 means no limit. Default when unset: 100000.
	ContextTokenLimit int
}

type Orchestrator struct {
	config   Config
	state    *state.ProjectState
	provider provider.Provider
	router   *router.Router // routes tasks to role-specific providers
	memory   *memory.Memory
	webhook  *webhook.Client
}

func New(cfg Config, prov provider.Provider) (*Orchestrator, error) {
	s, err := state.Load(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	if cfg.Model != "" {
		s.Model = cfg.Model
	}
	if cfg.PMMode {
		s.PMMode = true
	}
	mem, _ := memory.Load(cfg.WorkDir)
	if mem == nil {
		mem = &memory.Memory{}
	}

	// Build webhook client (flag URL overrides config URL).
	var wh *webhook.Client
	if cfg.WebhookURL != "" {
		wh = webhook.New(cfg.WebhookURL, cfg.WebhookEvents, nil, cfg.WebhookSecret)
	}

	r := router.New(prov)
	return &Orchestrator{config: cfg, state: s, provider: prov, router: r, memory: mem, webhook: wh}, nil
}

// RegisterRoute adds a role→provider binding to the orchestrator's router.
// Must be called before Run().
func (o *Orchestrator) RegisterRoute(role pm.AgentRole, prov provider.Provider) {
	o.router.Register(role, prov)
}

func (o *Orchestrator) AddSteps(n int) {
	o.state.MaxSteps += n
	o.state.Save()
}

func (o *Orchestrator) SetAutoEvolve(enabled bool) {
	o.state.AutoEvolve = enabled
	o.state.Save()
}

// SetProvider persists the provider name in state so subsequent runs default to the same provider.
func (o *Orchestrator) SetProvider(name string) {
	if name != "" {
		o.state.Provider = name
		o.state.Save()
	}
}

func (o *Orchestrator) Run(ctx context.Context) error {
	if o.state.PMMode {
		return o.runPM(ctx)
	}
	return o.runLoop(ctx)
}

// runLoop is the original autonomous feedback loop.
func (o *Orchestrator) runLoop(ctx context.Context) error {
	s := o.state
	s.Status = "running"
	if err := s.Save(); err != nil {
		return err
	}

	sessionStart := time.Now()
	startStep := s.CurrentStep
	defer func() {
		newSteps := s.Steps
		if startStep < len(newSteps) {
			newSteps = newSteps[startStep:]
		} else {
			newSteps = nil
		}
		o.learnFromSession(ctx, newSteps)
		printSessionSummary(sessionStart, startStep, s)
	}()

	header := color.New(color.FgCyan, color.Bold)
	stepColor := color.New(color.FgYellow, color.Bold)
	successColor := color.New(color.FgGreen, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)

	header.Printf("\n🔄 cloop — Autonomous AI Feedback Loop\n")
	fmt.Printf("   Provider: %s\n", o.provider.Name())
	fmt.Printf("   Goal: %s\n", s.Goal)
	if s.MaxSteps > 0 {
		fmt.Printf("   Steps: %d/%d (completed/max)\n", s.CurrentStep, s.MaxSteps)
	} else {
		fmt.Printf("   Steps: %d (unlimited)\n", s.CurrentStep)
	}
	if o.config.StepsLimit > 0 {
		fmt.Printf("   Session limit: %d step(s) this run\n", o.config.StepsLimit)
	}
	if s.Instructions != "" {
		fmt.Printf("   Instructions: %s\n", s.Instructions)
	}
	fmt.Println()

	o.webhook.Send(webhook.EventSessionStarted, webhook.Payload{Goal: s.Goal})

	for s.MaxSteps == 0 || s.CurrentStep < s.MaxSteps {
		if o.config.StepsLimit > 0 && s.CurrentStep >= startStep+o.config.StepsLimit {
			color.New(color.FgYellow).Printf("⏸ Reached --steps limit (%d). Run 'cloop run' to continue.\n", o.config.StepsLimit)
			s.Status = "paused"
			s.Save()
			return nil
		}
		select {
		case <-ctx.Done():
			s.Status = "paused"
			s.Save()
			return ctx.Err()
		default:
		}

		step := s.CurrentStep + 1
		if s.MaxSteps > 0 {
			stepColor.Printf("━━━ Step %d/%d ━━━\n", step, s.MaxSteps)
		} else {
			stepColor.Printf("━━━ Step %d ━━━\n", step)
		}

		prompt := o.buildPrompt()

		if o.config.DryRun {
			dimColor.Printf("[dry-run] Prompt:\n%s\n\n", prompt)
			s.CurrentStep++
			continue
		}

		dimColor.Printf("→ Running %s...\n", o.provider.Name())
		start := time.Now()

		opts, wasStreamed := o.makeOpts(s.Model, true)
		result, err := o.provider.Complete(ctx, prompt, opts)
		if err != nil {
			failColor.Printf("✗ Provider error: %v\n", err)
			s.Status = "failed"
			s.Save()
			o.webhook.Send(webhook.EventSessionFailed, webhook.Payload{Goal: s.Goal})
			return err
		}

		duration := time.Since(start)

		stepResult := state.StepResult{
			Task:         fmt.Sprintf("Step %d", step),
			Output:       result.Output,
			ExitCode:     0,
			Duration:     duration.Round(time.Second).String(),
			Time:         time.Now(),
			InputTokens:  result.InputTokens,
			OutputTokens: result.OutputTokens,
		}
		s.TotalInputTokens += result.InputTokens
		s.TotalOutputTokens += result.OutputTokens
		s.AddStep(stepResult)

		if wasStreamed() {
			fmt.Println()
		} else {
			printOutput(result.Output, dimColor, o.config.Verbose)
		}
		dimColor.Printf("  [%s, provider: %s]\n\n", duration.Round(time.Second), result.Provider)

		if o.config.TokenBudget > 0 && s.TotalInputTokens+s.TotalOutputTokens >= o.config.TokenBudget {
			color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
			s.Status = "paused"
			s.Save()
			return nil
		}
		if o.checkCostLimit(s) {
			s.Status = "paused"
			s.Save()
			return nil
		}

		if o.isGoalComplete(result.Output) {
			successColor.Printf("🎉 Goal complete after %d steps!\n\n", step)
			if o.config.Notify {
				notify.Send("cloop: Goal Complete", s.Goal)
			}
			o.webhook.Send(webhook.EventSessionComplete, webhook.Payload{
				Goal: s.Goal,
				Session: &webhook.SessionInfo{
					InputTokens:  s.TotalInputTokens,
					OutputTokens: s.TotalOutputTokens,
					Duration:     time.Since(sessionStart).Round(time.Second).String(),
				},
			})
			if s.AutoEvolve {
				s.Status = "evolving"
				s.Save()
				return o.evolve(ctx)
			}
			s.Status = "complete"
			s.Save()
			return nil
		}

		s.Save()

		if o.config.StepDelay > 0 {
			select {
			case <-ctx.Done():
				s.Status = "paused"
				s.Save()
				return ctx.Err()
			case <-time.After(o.config.StepDelay):
			}
		}
	}

	color.New(color.FgYellow).Printf("⏸ Reached max steps (%d). Run 'cloop run' to continue or 'cloop run --add-steps N' to extend.\n", s.MaxSteps)
	s.Status = "paused"
	s.Save()
	return nil
}

// runPM dispatches to sequential or parallel task execution based on config.
func (o *Orchestrator) runPM(ctx context.Context) error {
	if o.config.Parallel {
		return o.runPMParallel(ctx)
	}
	return o.runPMSequential(ctx)
}

// runPMSequential runs PM tasks one at a time (original behaviour).
func (o *Orchestrator) runPMSequential(ctx context.Context) error {
	s := o.state
	s.Status = "running"
	if err := s.Save(); err != nil {
		return err
	}

	sessionStart := time.Now()
	startStep := s.CurrentStep
	defer func() {
		newSteps := s.Steps
		if startStep < len(newSteps) {
			newSteps = newSteps[startStep:]
		} else {
			newSteps = nil
		}
		o.learnFromSession(ctx, newSteps)
		printSessionSummary(sessionStart, startStep, s)
	}()

	header := color.New(color.FgCyan, color.Bold)
	stepColor := color.New(color.FgYellow, color.Bold)
	successColor := color.New(color.FgGreen, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)
	pmColor := color.New(color.FgMagenta, color.Bold)

	header.Printf("\n🧠 cloop PM — AI Product Manager Mode\n")
	fmt.Printf("   Provider: %s\n", o.provider.Name())
	fmt.Printf("   Goal: %s\n", s.Goal)
	fmt.Println()

	o.webhook.Send(webhook.EventSessionStarted, webhook.Payload{Goal: s.Goal})

	// If --replan requested, clear existing plan and force re-decomposition.
	if o.config.Replan && s.Plan != nil {
		pmColor.Printf("Replanning: clearing existing plan (%d tasks) and re-decomposing.\n\n", len(s.Plan.Tasks))
		s.Plan = nil
		s.Save()
	}

	// Phase 1: Decompose goal into tasks (if not already done)
	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		pmColor.Printf("Decomposing goal into tasks...\n")
		plan, err := pm.Decompose(ctx, o.provider, s.Goal, s.Instructions, s.Model, o.config.StepTimeout)
		if err != nil {
			failColor.Printf("x Failed to decompose goal: %v\n", err)
			s.Status = "failed"
			s.Save()
			return err
		}
		s.Plan = plan
		s.Save()

		fmt.Printf("\n")
		pmColor.Printf("Task Plan (%d tasks):\n", len(plan.Tasks))
		for _, t := range plan.Tasks {
			fmt.Printf("  %d. [P%d] %s\n", t.ID, t.Priority, t.Title)
			dimColor.Printf("       %s\n", truncate(t.Description, 120))
		}
		fmt.Println()
	} else {
		// If retry-failed is set, reset failed tasks to pending
		if o.config.RetryFailed {
			retried := 0
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskFailed {
					t.Status = pm.TaskPending
					retried++
				}
			}
			if retried > 0 {
				pmColor.Printf("Retrying %d failed task(s).\n\n", retried)
				s.Save()
			}
		}
		pmColor.Printf("Resuming plan: %s\n\n", s.Plan.Summary())
	}

	// Plan-only mode: just show the plan, don't execute
	if o.config.PlanOnly {
		s.Status = "paused"
		s.Save()
		return nil
	}

	// Stale checkpoint detection: if a checkpoint.json exists for a task that is
	// still marked in_progress (e.g. the previous run was killed), ask the user
	// whether to resume or restart that task.
	// Note: NextTask() only returns pending tasks, so an in_progress task would be
	// permanently skipped without intervention. The checkpoint ensures we notice and
	// give the user control.
	if cp, cpErr := checkpoint.Load(o.config.WorkDir); cpErr == nil && cp != nil {
		// Find the matching task in the current plan.
		var staleTask *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == cp.TaskID && t.Status == pm.TaskInProgress {
				staleTask = t
				break
			}
		}
		if staleTask != nil {
			color.New(color.FgYellow, color.Bold).Printf("\n⚠ Stale checkpoint detected: Task %d — %s\n", cp.TaskID, cp.TaskTitle)
			dimColor.Printf("  The previous run was interrupted while executing this task.\n")
			dimColor.Printf("  Started: %s ago\n\n", time.Since(cp.StartTimestamp).Round(time.Second))
			fmt.Printf("Retry this task or skip it? [r]etry / [s]kip: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
				if answer == "s" || answer == "skip" {
					staleTask.Status = pm.TaskSkipped
					staleTask.StartedAt = nil
					s.Save()
					_ = checkpoint.Clear(o.config.WorkDir)
					dimColor.Printf("→ Task %d skipped.\n\n", staleTask.ID)
				} else {
					// Default: retry — reset to pending so NextTask() picks it up.
					staleTask.Status = pm.TaskPending
					staleTask.StartedAt = nil
					s.Save()
					_ = checkpoint.Clear(o.config.WorkDir)
					dimColor.Printf("→ Retrying task %d.\n\n", staleTask.ID)
				}
			} else {
				// EOF / non-interactive: default to retry.
				staleTask.Status = pm.TaskPending
				staleTask.StartedAt = nil
				s.Save()
				_ = checkpoint.Clear(o.config.WorkDir)
			}
		} else {
			// No matching in-progress task — checkpoint is fully stale; remove it.
			_ = checkpoint.Clear(o.config.WorkDir)
		}
	}

	// Pre-plan hook: run once before execution starts.
	if err := hooks.RunPrePlan(o.config.Hooks, hooks.PlanContext{
		Goal:  s.Goal,
		Total: len(s.Plan.Tasks),
	}); err != nil {
		failColor.Printf("✗ pre_plan hook failed: %v — aborting plan execution.\n", err)
		s.Status = "failed"
		s.Save()
		return err
	}

	// Post-plan hook: runs when plan finishes (done or paused).
	defer func() {
		done, failed := s.Plan.CountByStatus()
		skipped := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskSkipped {
				skipped++
			}
		}
		if hookErr := hooks.RunPostPlan(o.config.Hooks, hooks.PlanContext{
			Goal:    s.Goal,
			Total:   len(s.Plan.Tasks),
			Done:    done,
			Failed:  failed,
			Skipped: skipped,
		}); hookErr != nil {
			dimColor.Printf("  post_plan hook error (ignored): %v\n", hookErr)
		}
	}()

	// Phase 2: Execute tasks in priority order

	// Capture the original git branch once before execution so we can merge back.
	var gitOriginalBranch string
	if o.config.GitMode {
		var gitErr error
		gitOriginalBranch, gitErr = cloopgit.CurrentBranch(o.config.WorkDir)
		if gitErr != nil {
			failColor.Printf("✗ --git: could not determine current branch: %v — disabling git mode.\n", gitErr)
			o.config.GitMode = false
		}
	}

	consecutiveErrors := 0
	maxConsecutiveErrors := o.config.MaxFailures
	if maxConsecutiveErrors <= 0 {
		maxConsecutiveErrors = 3
	}

	for {
		select {
		case <-ctx.Done():
			s.Status = "paused"
			s.Save()
			return ctx.Err()
		default:
		}

		if o.config.StepsLimit > 0 && s.CurrentStep >= startStep+o.config.StepsLimit {
			color.New(color.FgYellow).Printf("⏸ Reached --steps limit (%d). Run 'cloop run' to continue.\n", o.config.StepsLimit)
			s.Status = "paused"
			s.Save()
			return nil
		}

		s.SyncFromDisk()
		if s.Plan.IsComplete() {
			successColor.Printf("🎉 All tasks complete! Goal achieved.\n")
			successColor.Printf("   %s\n\n", s.Plan.Summary())
			if o.config.Notify {
				notify.Send("cloop: All Tasks Complete", s.Goal)
			}
			done, failed := s.Plan.CountByStatus()
			o.webhook.Send(webhook.EventPlanComplete, webhook.Payload{
				Goal: s.Goal,
				Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
				Session: &webhook.SessionInfo{
					TotalTasks:   len(s.Plan.Tasks),
					DoneTasks:    done,
					FailedTasks:  failed,
					InputTokens:  s.TotalInputTokens,
					OutputTokens: s.TotalOutputTokens,
					Duration:     time.Since(sessionStart).Round(time.Second).String(),
				},
			})
			if s.AutoEvolve {
				s.Status = "evolving"
				s.Save()
				n, err := o.evolvePM(ctx)
				if err != nil {
					color.New(color.FgMagenta, color.Bold).Printf("\n⏹ Evolve stopped: %v\n", err)
					s.Status = "complete"
					s.Save()
					return nil
				}
				if n == 0 {
					s.Status = "complete"
					s.Save()
					return nil
				}
				s.Status = "running"
				continue
			}
			s.Status = "complete"
			s.Save()
			return nil
		}

		task := s.Plan.NextTask()
		if task == nil {
			// Auto-skip tasks that are permanently blocked by failed deps
			skipped := 0
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskPending && s.Plan.PermanentlyBlocked(t) {
					failColor.Printf("⊘ Task %d skipped (blocked by failed dependency): %s\n", t.ID, t.Title)
					t.Status = pm.TaskSkipped
					skipped++
				}
			}
			if skipped > 0 {
				s.Save()
				continue
			}
			break
		}

		// Check max steps limit
		if s.MaxSteps > 0 && s.CurrentStep >= s.MaxSteps {
			color.New(color.FgYellow).Printf("⏸ Reached max steps (%d). Run 'cloop run' to continue.\n", s.MaxSteps)
			s.Status = "paused"
			s.Save()
			return nil
		}

		stepColor.Printf("━━━ Task %d/%d: %s ━━━\n", task.ID, len(s.Plan.Tasks), task.Title)
		dimColor.Printf("       %s\n\n", truncate(task.Description, 150))

		// Human-in-the-loop review mode: ask before executing each task.
		if o.config.ReviewMode {
			action := reviewTask(task)
			switch action {
			case "skip":
				task.Status = pm.TaskSkipped
				dimColor.Printf("→ Task %d skipped by user.\n\n", task.ID)
				s.Save()
				continue
			case "quit":
				s.Status = "paused"
				s.Save()
				color.New(color.FgYellow).Printf("⏸ Review mode: user quit. Run 'cloop run' to resume.\n")
				return nil
			case "no":
				s.Status = "paused"
				s.Save()
				color.New(color.FgYellow).Printf("⏸ Task execution declined. Run 'cloop run' to resume.\n")
				return nil
			}
			// "yes" falls through
		}

		// Pre-task hook: skip the task if it exits non-zero.
		if hookErr := hooks.RunPreTask(o.config.Hooks, hooks.TaskContext{
			ID:     task.ID,
			Title:  task.Title,
			Status: "pending",
			Role:   string(task.Role),
		}); hookErr != nil {
			dimColor.Printf("⊘ pre_task hook failed for task %d (%s): %v — skipping task.\n", task.ID, task.Title, hookErr)
			task.Status = pm.TaskSkipped
			s.Save()
			continue
		}

		now := time.Now()
		task.Status = pm.TaskInProgress
		task.StartedAt = &now
		s.Save()

		// Write mid-execution checkpoint so an interrupted run can resume.
		cp := &checkpoint.Checkpoint{
			TaskID:         task.ID,
			TaskTitle:      task.Title,
			StepNumber:     s.CurrentStep,
			StartTimestamp: now,
			Provider:       o.provider.Name(),
		}
		if cpErr := checkpoint.Save(o.config.WorkDir, cp); cpErr != nil {
			dimColor.Printf("  checkpoint write error (ignored): %v\n", cpErr)
		}

		{
			done, failed := s.Plan.CountByStatus()
			o.webhook.Send(webhook.EventTaskStarted, webhook.Payload{
				Goal: s.Goal,
				Task: &webhook.TaskInfo{ID: task.ID, Title: task.Title, Description: task.Description, Status: "in_progress"},
				Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
				Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
			})
		}

		// Build prompt with optional project context injection.
		var projCtx *pm.ProjectContext
		if o.config.InjectContext {
			projCtx = pm.BuildProjectContext(o.config.WorkDir)
		}
		promptPlan, keptResults, totalResults := o.prunePlanForPrompt(s.Plan)
		if keptResults < totalResults {
			color.New(color.FgYellow).Printf("Context pruned: kept %d of %d steps to fit token budget\n", keptResults, totalResults)
		}
		prompt := pm.ExecuteTaskPrompt(s.Goal, s.Instructions, promptPlan, task, projCtx)
		// Prepend memory if enabled
		if o.config.UseMemory && o.memory != nil {
			limit := o.config.MemoryLimit
			if limit == 0 {
				limit = 20
			}
			if mem := o.memory.FormatForPrompt(limit); mem != "" {
				prompt = mem + prompt
			}
		}

		if o.config.DryRun {
			dimColor.Printf("[dry-run] Task prompt:\n%s\n\n", prompt)
			task.Status = pm.TaskDone
			s.Save()
			continue
		}

		// Git mode: create a dedicated branch for this task before execution.
		var gitTaskBranch string
		if o.config.GitMode {
			var gitErr error
			gitTaskBranch, gitErr = cloopgit.CreateTaskBranch(o.config.WorkDir, task)
			if gitErr != nil {
				dimColor.Printf("  git branch error (ignored): %v\n", gitErr)
				gitTaskBranch = ""
			} else {
				dimColor.Printf("  git: checked out branch %s\n", gitTaskBranch)
			}
		}

		// Select provider: role-specific route takes precedence over default.
		taskProvider := o.router.For(task.Role)
		dimColor.Printf("→ Running %s on task %d...\n", taskProvider.Name(), task.ID)
		start := time.Now()

		opts, wasStreamed := o.makeOpts(s.Model, true)
		result, err := taskProvider.Complete(ctx, prompt, opts)
		if err != nil {
			failColor.Printf("✗ Provider error: %v\n", err)
			task.Status = pm.TaskFailed
			consecutiveErrors++
			s.Save()
			if consecutiveErrors >= maxConsecutiveErrors {
				s.Status = "failed"
				s.Save()
				return fmt.Errorf("%d consecutive errors", consecutiveErrors)
			}
			continue
		}

		duration := time.Since(start)
		stepResult := state.StepResult{
			Task:         fmt.Sprintf("Task %d: %s", task.ID, task.Title),
			Output:       result.Output,
			Duration:     duration.Round(time.Second).String(),
			Time:         time.Now(),
			InputTokens:  result.InputTokens,
			OutputTokens: result.OutputTokens,
		}
		s.TotalInputTokens += result.InputTokens
		s.TotalOutputTokens += result.OutputTokens
		s.AddStep(stepResult)

		if wasStreamed() {
			fmt.Println()
		} else {
			printOutput(result.Output, dimColor, o.config.Verbose)
		}
		dimColor.Printf("  [%s, provider: %s]\n\n", duration.Round(time.Second), result.Provider)

		if o.config.TokenBudget > 0 && s.TotalInputTokens+s.TotalOutputTokens >= o.config.TokenBudget {
			color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
			// Mark the in-progress task as pending so it retries next time
			task.Status = pm.TaskPending
			s.Status = "paused"
			s.Save()
			return nil
		}
		if o.checkCostLimit(s) {
			task.Status = pm.TaskPending
			s.Status = "paused"
			s.Save()
			return nil
		}

		// Update task status based on signal in output
		signal := pm.CheckTaskSignal(result.Output)
		completedAt := time.Now()
		task.CompletedAt = &completedAt
		task.Result = truncate(result.Output, 500)
		if task.StartedAt != nil {
			task.ActualMinutes = int(completedAt.Sub(*task.StartedAt).Minutes())
		}

		taskDur := time.Since(*task.StartedAt).Round(time.Second).String()
		switch signal {
		case pm.TaskDone:
			// Optionally verify the task was genuinely completed before accepting it.
			if o.config.Verify {
				maxRetries := o.config.MaxVerifyRetries
				if maxRetries <= 0 {
					maxRetries = 2
				}
				dimColor.Printf("  Verifying task %d...\n", task.ID)
				pass, verifyErr := pm.VerifyTask(ctx, o.provider, s.Goal, s.Instructions, s.Model, o.config.StepTimeout, task, result.Output)
				if verifyErr != nil {
					dimColor.Printf("  Verification error (treating as pass): %v\n", verifyErr)
					pass = true
				}
				if !pass {
					task.VerifyRetries++
					if task.VerifyRetries <= maxRetries {
						failColor.Printf("✗ Verification FAILED for task %d (%s) — re-queuing (attempt %d/%d)\n\n", task.ID, task.Title, task.VerifyRetries, maxRetries)
						task.Status = pm.TaskPending
						s.Save()
						continue
					}
					failColor.Printf("✗ Verification failed %d time(s) for task %d — marking failed.\n\n", task.VerifyRetries, task.ID)
					task.Status = pm.TaskFailed
					{
						done, failed := s.Plan.CountByStatus()
						o.webhook.Send(webhook.EventTaskFailed, webhook.Payload{
							Goal:     s.Goal,
							Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "failed", Duration: taskDur},
							Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
							Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
						})
					}
					consecutiveErrors++
					s.Save()
					if consecutiveErrors >= maxConsecutiveErrors {
						s.Status = "failed"
						s.Save()
						o.webhook.Send(webhook.EventSessionFailed, webhook.Payload{
							Goal:    s.Goal,
							Session: &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
						})
						return fmt.Errorf("%d consecutive task failures", consecutiveErrors)
					}
					continue
				}
				pmColor.Printf("✓ Verification PASSED for task %d: %s\n\n", task.ID, task.Title)
			}
			task.Status = pm.TaskDone
			successColor.Printf("✓ Task %d complete: %s\n\n", task.ID, task.Title)
			if o.config.Notify {
				notify.Send("cloop: Task Done", task.Title)
			}
			{
				done, failed := s.Plan.CountByStatus()
				o.webhook.Send(webhook.EventTaskDone, webhook.Payload{
					Goal:     s.Goal,
					Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "done", Duration: taskDur},
					Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
					Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
				})
			}
			consecutiveErrors = 0
		case pm.TaskSkipped:
			task.Status = pm.TaskSkipped
			dimColor.Printf("→ Task %d skipped: %s\n\n", task.ID, task.Title)
			{
				done, failed := s.Plan.CountByStatus()
				o.webhook.Send(webhook.EventTaskSkipped, webhook.Payload{
					Goal:     s.Goal,
					Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "skipped"},
					Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
					Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
				})
			}
			consecutiveErrors = 0
		case pm.TaskFailed:
			task.Status = pm.TaskFailed
			failColor.Printf("✗ Task %d failed: %s\n\n", task.ID, task.Title)
			{
				done, failed := s.Plan.CountByStatus()
				o.webhook.Send(webhook.EventTaskFailed, webhook.Payload{
					Goal:     s.Goal,
					Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "failed", Duration: taskDur},
					Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
					Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
				})
			}
			if o.config.Notify {
				notify.Send("cloop: Task Failed", task.Title)
			}
			consecutiveErrors++

			// AI failure diagnosis: analyze what went wrong and store it on the task.
			// This runs before adaptive replan so the diagnosis can inform replanning too.
			if o.config.DiagnoseFailures {
				dimColor.Printf("  Diagnosing failure for task %d...\n", task.ID)
				diag, diagErr := diagnosis.AnalyzeFailure(ctx, o.provider, s.Model, o.config.StepTimeout, task, result.Output)
				if diagErr != nil {
					dimColor.Printf("  Diagnosis error (ignored): %v\n", diagErr)
				} else if diag != "" {
					task.FailureDiagnosis = diag
					dimColor.Printf("  Diagnosis: %s\n\n", truncate(diag, 200))
				}
				s.Save()
			}

			// Adaptive replanning: re-think remaining tasks on failure.
			if o.config.AdaptiveReplan {
				pmColor.Printf("Adaptive replan: re-thinking remaining tasks after failure...\n")
				failureReason := truncate(result.Output, 400)
				newTasks, replanErr := pm.AdaptiveReplan(ctx, o.provider, s.Goal, s.Instructions, s.Model, o.config.StepTimeout, s.Plan, task, failureReason)
				if replanErr != nil {
					failColor.Printf("  Replan failed: %v — continuing with existing plan.\n\n", replanErr)
				} else if len(newTasks) > 0 {
					// Replace remaining pending tasks with replanned tasks.
					kept := []*pm.Task{}
					for _, t := range s.Plan.Tasks {
						if t.Status != pm.TaskPending {
							kept = append(kept, t)
						}
					}
					s.Plan.Tasks = append(kept, newTasks...)
					pmColor.Printf("  Replanned: added %d revised task(s).\n\n", len(newTasks))
					consecutiveErrors = 0 // reset after successful replan
					s.Save()
					continue
				} else {
					pmColor.Printf("  Replan: no new tasks — plan is complete or blocked.\n\n")
				}
			}

			if consecutiveErrors >= maxConsecutiveErrors {
				s.Status = "failed"
				s.Save()
				o.webhook.Send(webhook.EventSessionFailed, webhook.Payload{
					Goal:    s.Goal,
					Session: &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
				})
				return fmt.Errorf("%d consecutive task failures", consecutiveErrors)
			}
		default:
			// No signal found — treat as done (AI finished without explicit signal)
			task.Status = pm.TaskDone
			successColor.Printf("✓ Task %d complete (no explicit signal): %s\n\n", task.ID, task.Title)
			if o.config.Notify {
				notify.Send("cloop: Task Done", task.Title)
			}
			{
				done, failed := s.Plan.CountByStatus()
				o.webhook.Send(webhook.EventTaskDone, webhook.Payload{
					Goal:     s.Goal,
					Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "done", Duration: taskDur},
					Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
					Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
				})
			}
			consecutiveErrors = 0
		}

		// Persist full AI response as a Markdown artifact file.
		o.writeTaskArtifact(task, result.Output)

		// Task completed (done/skipped/failed) — clear the mid-execution checkpoint.
		if cpClearErr := checkpoint.Clear(o.config.WorkDir); cpClearErr != nil {
			dimColor.Printf("  checkpoint clear error (ignored): %v\n", cpClearErr)
		}

		// Git mode: commit and merge on success; leave branch open on failure.
		if o.config.GitMode && gitTaskBranch != "" {
			switch task.Status {
			case pm.TaskDone, pm.TaskSkipped:
				if commitErr := cloopgit.CommitTaskArtifacts(o.config.WorkDir, task); commitErr != nil {
					dimColor.Printf("  git commit error (ignored): %v\n", commitErr)
				} else if mergeErr := cloopgit.MergeBranch(o.config.WorkDir, gitOriginalBranch, gitTaskBranch); mergeErr != nil {
					dimColor.Printf("  git merge error (ignored): %v\n", mergeErr)
				} else {
					dimColor.Printf("  git: merged %s → %s\n", gitTaskBranch, gitOriginalBranch)
				}
			case pm.TaskFailed:
				dimColor.Printf("  git: leaving branch %s open for inspection (task failed)\n", gitTaskBranch)
				// Return to original branch so the next task can start from it.
				if checkoutErr := cloopgit.CheckoutBranch(o.config.WorkDir, gitOriginalBranch); checkoutErr != nil {
					dimColor.Printf("  git checkout original branch error (ignored): %v\n", checkoutErr)
				}
			}
		}

		// Post-task hook: always run regardless of task outcome.
		if hookErr := hooks.RunPostTask(o.config.Hooks, hooks.TaskContext{
			ID:     task.ID,
			Title:  task.Title,
			Status: string(task.Status),
			Role:   string(task.Role),
		}); hookErr != nil {
			dimColor.Printf("  post_task hook error (ignored): %v\n", hookErr)
		}

		s.Save()

		if o.config.StepDelay > 0 {
			select {
			case <-ctx.Done():
				s.Status = "paused"
				s.Save()
				return ctx.Err()
			case <-time.After(o.config.StepDelay):
			}
		}
	}

	s.Status = "paused"
	s.Save()
	return nil
}

// reviewTask prompts the user to approve, skip, or quit before executing a task.
// Returns "yes", "no", "skip", or "quit".
func reviewTask(task *pm.Task) string {
	reviewColor := color.New(color.FgCyan)
	reviewColor.Printf("Review: Task %d [P%d] — %s\n", task.ID, task.Priority, task.Title)
	if task.Description != "" {
		color.New(color.Faint).Printf("  %s\n", truncate(task.Description, 200))
	}
	fmt.Printf("Execute this task? [y]es / [n]o (pause) / [s]kip / [q]uit: ")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
		switch answer {
		case "y", "yes", "":
			return "yes"
		case "n", "no":
			return "no"
		case "s", "skip":
			return "skip"
		case "q", "quit":
			return "quit"
		}
		fmt.Printf("Please enter y, n, s, or q: ")
	}
	return "quit" // EOF or error
}

// taskResult holds the output of a single parallel task execution.
type taskResult struct {
	task         *pm.Task
	result       *provider.Result
	err          error
	duration     time.Duration
	bufferedOut  string
}

// runPMParallel runs all dependency-ready tasks concurrently in each round,
// then waits for them to complete before starting the next round.
func (o *Orchestrator) runPMParallel(ctx context.Context) error {
	s := o.state
	s.Status = "running"
	if err := s.Save(); err != nil {
		return err
	}

	sessionStart := time.Now()
	startStep := s.CurrentStep
	defer func() { printSessionSummary(sessionStart, startStep, s) }()

	header := color.New(color.FgCyan, color.Bold)
	successColor := color.New(color.FgGreen, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)
	pmColor := color.New(color.FgMagenta, color.Bold)
	stepColor := color.New(color.FgYellow, color.Bold)

	header.Printf("\n🧠 cloop PM — AI Product Manager Mode (parallel)\n")
	fmt.Printf("   Provider: %s\n", o.provider.Name())
	fmt.Printf("   Goal: %s\n", s.Goal)
	fmt.Println()

	// Replan / decompose phase (same as sequential).
	if o.config.Replan && s.Plan != nil {
		pmColor.Printf("Replanning: clearing existing plan (%d tasks) and re-decomposing.\n\n", len(s.Plan.Tasks))
		s.Plan = nil
		s.Save()
	}

	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		pmColor.Printf("Decomposing goal into tasks...\n")
		plan, err := pm.Decompose(ctx, o.provider, s.Goal, s.Instructions, s.Model, o.config.StepTimeout)
		if err != nil {
			failColor.Printf("x Failed to decompose goal: %v\n", err)
			s.Status = "failed"
			s.Save()
			return err
		}
		s.Plan = plan
		s.Save()
		fmt.Printf("\n")
		pmColor.Printf("Task Plan (%d tasks):\n", len(plan.Tasks))
		for _, t := range plan.Tasks {
			fmt.Printf("  %d. [P%d] %s\n", t.ID, t.Priority, t.Title)
			dimColor.Printf("       %s\n", truncate(t.Description, 120))
		}
		fmt.Println()
	} else {
		if o.config.RetryFailed {
			retried := 0
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskFailed {
					t.Status = pm.TaskPending
					retried++
				}
			}
			if retried > 0 {
				pmColor.Printf("Retrying %d failed task(s).\n\n", retried)
				s.Save()
			}
		}
		pmColor.Printf("Resuming plan: %s\n\n", s.Plan.Summary())
	}

	if o.config.PlanOnly {
		s.Status = "paused"
		s.Save()
		return nil
	}

	consecutiveErrors := 0
	maxConsecutiveErrors := o.config.MaxFailures
	if maxConsecutiveErrors <= 0 {
		maxConsecutiveErrors = 3
	}

	var mu sync.Mutex

	for {
		select {
		case <-ctx.Done():
			s.Status = "paused"
			s.Save()
			return ctx.Err()
		default:
		}

		if o.config.StepsLimit > 0 && s.CurrentStep >= startStep+o.config.StepsLimit {
			color.New(color.FgYellow).Printf("⏸ Reached --steps limit (%d). Run 'cloop run' to continue.\n", o.config.StepsLimit)
			s.Status = "paused"
			s.Save()
			return nil
		}

		s.SyncFromDisk()
		if s.Plan.IsComplete() {
			successColor.Printf("🎉 All tasks complete! Goal achieved.\n")
			successColor.Printf("   %s\n\n", s.Plan.Summary())
			if o.config.Notify {
				notify.Send("cloop: All Tasks Complete", s.Goal)
			}
			{
				done, failed := s.Plan.CountByStatus()
				o.webhook.Send(webhook.EventPlanComplete, webhook.Payload{
					Goal:     s.Goal,
					Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
					Session:  &webhook.SessionInfo{
						TotalTasks:   len(s.Plan.Tasks),
						DoneTasks:    done,
						FailedTasks:  failed,
						InputTokens:  s.TotalInputTokens,
						OutputTokens: s.TotalOutputTokens,
					},
				})
			}
			if s.AutoEvolve {
				s.Status = "evolving"
				s.Save()
				n, err := o.evolvePM(ctx)
				if err != nil {
					color.New(color.FgMagenta, color.Bold).Printf("\n⏹ Evolve stopped: %v\n", err)
					s.Status = "complete"
					s.Save()
					return nil
				}
				if n == 0 {
					s.Status = "complete"
					s.Save()
					return nil
				}
				s.Status = "running"
				continue
			}
			s.Status = "complete"
			s.Save()
			return nil
		}

		// Auto-skip permanently blocked tasks.
		skipped := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskPending && s.Plan.PermanentlyBlocked(t) {
				failColor.Printf("⊘ Task %d skipped (blocked by failed dependency): %s\n", t.ID, t.Title)
				t.Status = pm.TaskSkipped
				skipped++
			}
		}
		if skipped > 0 {
			s.Save()
			continue
		}

		ready := s.Plan.ReadyTasks()
		if len(ready) == 0 {
			break
		}

		// Apply worker pool limit: cap the batch to MaxParallel if set.
		if o.config.MaxParallel > 0 && len(ready) > o.config.MaxParallel {
			ready = ready[:o.config.MaxParallel]
		}

		// Mark all ready tasks as in-progress before starting goroutines.
		now := time.Now()
		for _, t := range ready {
			t.Status = pm.TaskInProgress
			t.StartedAt = &now
		}
		s.Save()

		if len(ready) == 1 {
			stepColor.Printf("━━━ Task %d/%d: %s ━━━\n", ready[0].ID, len(s.Plan.Tasks), ready[0].Title)
		} else {
			stepColor.Printf("━━━ Running %d tasks in parallel ━━━\n", len(ready))
			for _, t := range ready {
				dimColor.Printf("   • Task %d: %s\n", t.ID, t.Title)
			}
		}

		// Apply token-budget pruning to the plan once before launching parallel tasks.
		parallelPromptPlan, keptPar, totalPar := o.prunePlanForPrompt(s.Plan)
		if keptPar < totalPar {
			color.New(color.FgYellow).Printf("Context pruned: kept %d of %d steps to fit token budget\n", keptPar, totalPar)
		}

		// Launch goroutines for each ready task.
		// Streaming is disabled in parallel mode to avoid interleaved token output.
		results := make([]taskResult, len(ready))
		var wg sync.WaitGroup
		for i, task := range ready {
			wg.Add(1)
			go func(idx int, t *pm.Task) {
				defer wg.Done()
				prompt := pm.ExecuteTaskPrompt(s.Goal, s.Instructions, parallelPromptPlan, t)
				start := time.Now()
				// Use role-specific provider if configured.
				taskProvider := o.router.For(t.Role)
				opts, _ := o.makeOpts(s.Model, false) // no streaming in parallel
				result, err := taskProvider.Complete(ctx, prompt, opts)
				dur := time.Since(start)
				results[idx] = taskResult{task: t, result: result, err: err, duration: dur}
			}(i, task)
		}
		wg.Wait()

		// Process results sequentially for clean output.
		for _, res := range results {
			task := res.task
			if res.err != nil {
				failColor.Printf("✗ Provider error on task %d: %v\n", task.ID, res.err)
				mu.Lock()
				task.Status = pm.TaskFailed
				consecutiveErrors++
				s.Save()
				tooManyErrors := consecutiveErrors >= maxConsecutiveErrors
				mu.Unlock()
				if tooManyErrors {
					s.Status = "failed"
					s.Save()
					return fmt.Errorf("%d consecutive errors", consecutiveErrors)
				}
				continue
			}

			result := res.result
			stepResult := state.StepResult{
				Task:         fmt.Sprintf("Task %d: %s", task.ID, task.Title),
				Output:       result.Output,
				Duration:     res.duration.Round(time.Second).String(),
				Time:         time.Now(),
				InputTokens:  result.InputTokens,
				OutputTokens: result.OutputTokens,
			}

			mu.Lock()
			s.TotalInputTokens += result.InputTokens
			s.TotalOutputTokens += result.OutputTokens
			s.AddStep(stepResult)
			mu.Unlock()

			printOutput(result.Output, dimColor, o.config.Verbose)
			dimColor.Printf("  [%s, provider: %s]\n\n", res.duration.Round(time.Second), result.Provider)

			if o.config.TokenBudget > 0 && s.TotalInputTokens+s.TotalOutputTokens >= o.config.TokenBudget {
				color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
				task.Status = pm.TaskPending
				s.Status = "paused"
				s.Save()
				return nil
			}
			if o.checkCostLimit(s) {
				task.Status = pm.TaskPending
				s.Status = "paused"
				s.Save()
				return nil
			}

			signal := pm.CheckTaskSignal(result.Output)
			completedAt := time.Now()
			task.CompletedAt = &completedAt
			task.Result = truncate(result.Output, 500)
			if task.StartedAt != nil {
				task.ActualMinutes = int(completedAt.Sub(*task.StartedAt).Minutes())
			}

			taskDur := res.duration.Round(time.Second).String()
			mu.Lock()
			switch signal {
			case pm.TaskDone:
				task.Status = pm.TaskDone
				successColor.Printf("✓ Task %d complete: %s\n\n", task.ID, task.Title)
				if o.config.Notify {
					notify.Send("cloop: Task Done", task.Title)
				}
				{
					done, failed := s.Plan.CountByStatus()
					o.webhook.Send(webhook.EventTaskDone, webhook.Payload{
						Goal:     s.Goal,
						Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "done", Duration: taskDur},
						Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
						Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					})
				}
				consecutiveErrors = 0
			case pm.TaskSkipped:
				task.Status = pm.TaskSkipped
				dimColor.Printf("→ Task %d skipped: %s\n\n", task.ID, task.Title)
				{
					done, failed := s.Plan.CountByStatus()
					o.webhook.Send(webhook.EventTaskSkipped, webhook.Payload{
						Goal:     s.Goal,
						Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "skipped"},
						Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
						Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					})
				}
				consecutiveErrors = 0
			case pm.TaskFailed:
				task.Status = pm.TaskFailed
				failColor.Printf("✗ Task %d failed: %s\n\n", task.ID, task.Title)
				if o.config.Notify {
					notify.Send("cloop: Task Failed", task.Title)
				}
				{
					done, failed := s.Plan.CountByStatus()
					o.webhook.Send(webhook.EventTaskFailed, webhook.Payload{
						Goal:     s.Goal,
						Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "failed", Duration: taskDur},
						Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
						Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					})
				}
				consecutiveErrors++
			default:
				task.Status = pm.TaskDone
				successColor.Printf("✓ Task %d complete (no explicit signal): %s\n\n", task.ID, task.Title)
				if o.config.Notify {
					notify.Send("cloop: Task Done", task.Title)
				}
				{
					done, failed := s.Plan.CountByStatus()
					o.webhook.Send(webhook.EventTaskDone, webhook.Payload{
						Goal:     s.Goal,
						Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "done", Duration: taskDur},
						Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
						Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					})
				}
				consecutiveErrors = 0
			}
			// Persist full AI response as a Markdown artifact file.
			o.writeTaskArtifact(task, result.Output)

			tooManyErrors := consecutiveErrors >= maxConsecutiveErrors
			s.Save()
			mu.Unlock()

			if tooManyErrors {
				s.Status = "failed"
				s.Save()
				return fmt.Errorf("%d consecutive task failures", consecutiveErrors)
			}
		}
	}

	s.Status = "paused"
	s.Save()
	return nil
}

// writeTaskArtifact persists the full AI response for a task to
// .cloop/tasks/<id>-<slug>.md and sets task.ArtifactPath. Errors are
// non-fatal — logged to stderr but do not abort the run.
func (o *Orchestrator) writeTaskArtifact(task *pm.Task, output string) {
	path, err := artifact.WriteTaskArtifact(o.config.WorkDir, task, output)
	if err != nil {
		color.New(color.Faint).Printf("  artifact write error (ignored): %v\n", err)
		return
	}
	task.ArtifactPath = path
}

// makeOpts builds provider.Options for a completion call.
// When o.config.Streaming is true it attaches an OnToken callback that prints
// each token immediately to stdout; wasStreamed() returns true if at least one
// token was received that way.  Callers should call printOutput() only when
// wasStreamed() is false to avoid double-printing.
// For parallel execution pass streaming=false to avoid interleaved output.
func (o *Orchestrator) makeOpts(model string, streaming bool) (provider.Options, func() bool) {
	var streamed bool
	opts := provider.Options{
		Model:     model,
		MaxTokens: o.config.MaxTokens,
		Timeout:   o.config.StepTimeout,
		WorkDir:   o.config.WorkDir,
	}
	if streaming && o.config.Streaming {
		opts.OnToken = func(token string) {
			fmt.Print(token)
			streamed = true
		}
	}
	return opts, func() bool { return streamed }
}

// tokenLimit returns the effective ContextTokenLimit: the configured value or the default
// of 100000 when the field is zero.
func (o *Orchestrator) tokenLimit() int {
	if o.config.ContextTokenLimit > 0 {
		return o.config.ContextTokenLimit
	}
	return 100000
}

// pruneStepHistory applies token-budget pruning to a step slice.
// It collects the step outputs as strings, calls pm.PruneToTokenBudget, then
// reconstructs the []state.StepResult slice for the entries that were retained.
// Returns (prunedSteps, originalCount, keptCount).
func pruneStepHistory(steps []state.StepResult, budgetTokens int) ([]state.StepResult, int, int) {
	n := len(steps)
	if n == 0 {
		return steps, 0, 0
	}
	texts := make([]string, n)
	for i, step := range steps {
		texts[i] = step.Output
	}
	pruned := pm.PruneToTokenBudget(texts, budgetTokens)
	if len(pruned) == n {
		return steps, n, n
	}
	// Reconstruct the StepResult slice that corresponds to the pruned text slice.
	// PruneToTokenBudget always keeps index 0 and the last two; it drops oldest
	// intermediates from index 1 forward. The drop count equals n - len(pruned).
	dropCount := n - len(pruned)
	result := make([]state.StepResult, 0, len(pruned))
	result = append(result, steps[0])
	if n >= 3 {
		// Middle: steps[1:n-2]; kept = steps[1+dropCount:n-2]
		middleStart := 1 + dropCount
		if middleStart < n-2 {
			result = append(result, steps[middleStart:n-2]...)
		}
		result = append(result, steps[n-2:]...)
	} else if n == 2 {
		result = append(result, steps[1])
	}
	return result, n, len(result)
}

// prunePlanForPrompt returns a shallow copy of plan with the Result field of older
// completed tasks cleared so that the prompt fits within the token budget.
// Returns the (possibly modified) plan and counts (kept, total) for warning output.
// Returns the original plan unchanged when no pruning is needed.
func (o *Orchestrator) prunePlanForPrompt(plan *pm.Plan) (*pm.Plan, int, int) {
	budget := o.tokenLimit()
	if plan == nil {
		return plan, 0, 0
	}
	// Collect completed-task result strings and their indices in plan.Tasks.
	var results []string
	var completedIdx []int
	for i, t := range plan.Tasks {
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
			results = append(results, t.Result)
			completedIdx = append(completedIdx, i)
		}
	}
	total := len(results)
	if total == 0 {
		return plan, 0, 0
	}
	pruned := pm.PruneToTokenBudget(results, budget)
	if len(pruned) == total {
		return plan, total, total
	}
	// PruneToTokenBudget drops oldest intermediates: completedIdx[1..dropCount].
	dropCount := total - len(pruned)
	droppedSet := make(map[int]bool, dropCount)
	for i := 1; i <= dropCount && i < total; i++ {
		droppedSet[completedIdx[i]] = true
	}
	// Build a shallow copy of the plan with Result cleared for dropped tasks.
	newPlan := *plan
	newTasks := make([]*pm.Task, len(plan.Tasks))
	for i, t := range plan.Tasks {
		if droppedSet[i] {
			tc := *t
			tc.Result = ""
			newTasks[i] = &tc
		} else {
			newTasks[i] = t
		}
	}
	newPlan.Tasks = newTasks
	return &newPlan, len(pruned), total
}

func (o *Orchestrator) buildPrompt() string {
	s := o.state
	var b strings.Builder

	b.WriteString("You are working towards a project goal in an autonomous feedback loop.\n")
	b.WriteString("Each step you take should make meaningful progress towards the goal.\n")
	b.WriteString("You have full file system access and can run commands.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", s.Goal))

	// Inject memory if enabled
	if o.config.UseMemory && o.memory != nil {
		limit := o.config.MemoryLimit
		if limit == 0 {
			limit = 20
		}
		if mem := o.memory.FormatForPrompt(limit); mem != "" {
			b.WriteString(mem)
		}
	}

	if s.Instructions != "" {
		b.WriteString(fmt.Sprintf("## ADDITIONAL INSTRUCTIONS\n%s\n\n", s.Instructions))
	}

	if s.MaxSteps > 0 {
		b.WriteString(fmt.Sprintf("## PROGRESS\nStep %d of %d max.\n\n", s.CurrentStep+1, s.MaxSteps))
	} else {
		b.WriteString(fmt.Sprintf("## PROGRESS\nStep %d (no step limit).\n\n", s.CurrentStep+1))
	}

	contextSteps := o.config.ContextSteps
	if contextSteps < 0 {
		contextSteps = 3
	}

	// Apply token-budget pruning to the full step list before count-based slicing.
	effectiveSteps := s.Steps
	if len(s.Steps) > 0 {
		pruned, origCount, keptCount := pruneStepHistory(s.Steps, o.tokenLimit())
		if keptCount < origCount {
			color.New(color.FgYellow).Printf("Context pruned: kept %d of %d steps to fit token budget\n", keptCount, origCount)
			effectiveSteps = pruned
		}
	}

	// Derive recent / older split from the (possibly pruned) step list.
	var recent []state.StepResult
	if contextSteps > 0 {
		n := contextSteps
		if n > len(effectiveSteps) {
			n = len(effectiveSteps)
		}
		if n > 0 {
			recent = effectiveSteps[len(effectiveSteps)-n:]
		}
	}

	// For older steps beyond the recent window, include a brief one-line summary
	// so the AI has a high-level view of overall session progress.
	// When contextSteps==0 (context disabled), skip history entirely.
	if contextSteps > 0 && len(effectiveSteps) > len(recent) {
		older := effectiveSteps[:len(effectiveSteps)-len(recent)]
		b.WriteString("## SESSION HISTORY (brief)\n")
		for _, step := range older {
			summary := stepSummaryLine(step.Output, 150)
			b.WriteString(fmt.Sprintf("- Step %d (%s): %s\n", step.Step+1, step.Duration, summary))
		}
		b.WriteString("\n")
	}

	if len(recent) > 0 {
		b.WriteString("## RECENT STEPS\n")
		for _, step := range recent {
			b.WriteString(fmt.Sprintf("### Step %d (%s)\n", step.Step+1, step.Duration))
			output := step.Output
			if len(output) > 2000 {
				output = output[:1000] + "\n...(truncated)...\n" + output[len(output)-1000:]
			}
			b.WriteString(output)
			b.WriteString("\n\n")
		}
	}

	b.WriteString("## INSTRUCTIONS FOR THIS STEP\n")
	b.WriteString("1. Assess current progress towards the goal\n")
	b.WriteString("2. Determine the most impactful next action\n")
	b.WriteString("3. Execute it (create/edit files, run commands, etc.)\n")
	b.WriteString("4. Verify your work compiles/runs if applicable\n")
	b.WriteString("5. Summarize what you did and what remains\n\n")
	b.WriteString("If the project goal is FULLY COMPLETE, end your response with exactly:\nGOAL_COMPLETE\n")

	return b.String()
}

// evolvePM discovers new tasks via AI and appends them to the plan.
// Returns the number of tasks added. Called when AutoEvolve is set and the PM plan is complete.
func (o *Orchestrator) evolvePM(ctx context.Context) (int, error) {
	s := o.state
	s.EvolveStep++

	evolveColor := color.New(color.FgMagenta, color.Bold)
	dimColor := color.New(color.Faint)

	evolveColor.Printf("━━━ Evolve #%d — Discovering new tasks ━━━\n", s.EvolveStep)
	dimColor.Printf("→ Asking AI for improvement ideas...\n")

	prompt := pm.EvolveDiscoverPrompt(s.Goal, s.Instructions, s.Plan, s.EvolveStep, o.config.InnovateMode)
	opts, _ := o.makeOpts(s.Model, true)
	result, err := o.provider.Complete(ctx, prompt, opts)
	if err != nil {
		return 0, err
	}

	stepResult := state.StepResult{
		Task:         fmt.Sprintf("Evolve #%d: discover tasks", s.EvolveStep),
		Output:       result.Output,
		Duration:     result.Duration.Round(time.Second).String(),
		Time:         time.Now(),
		InputTokens:  result.InputTokens,
		OutputTokens: result.OutputTokens,
	}
	s.TotalInputTokens += result.InputTokens
	s.TotalOutputTokens += result.OutputTokens
	s.AddStep(stepResult)

	newTasks, err := pm.ParseEvolveTasks(s.Goal, result.Output, s.Plan)
	if err != nil {
		dimColor.Printf("  Task discovery parse error: %v\n", err)
		s.Save()
		return 0, nil
	}
	if len(newTasks) == 0 {
		dimColor.Printf("  No new tasks discovered — project is fully evolved.\n")
		s.Save()
		return 0, nil
	}

	s.Plan.Tasks = append(s.Plan.Tasks, newTasks...)
	s.Save()

	o.webhook.Send(webhook.EventEvolveDiscovered, webhook.Payload{
		Goal: s.Goal,
		Session: &webhook.SessionInfo{
			NewTasksFound: len(newTasks),
			EvolveStep:    s.EvolveStep,
			InputTokens:   s.TotalInputTokens,
			OutputTokens:  s.TotalOutputTokens,
		},
	})

	evolveColor.Printf("  Discovered %d new task(s):\n", len(newTasks))
	for _, t := range newTasks {
		fmt.Printf("    + [P%d] %s\n", t.Priority, t.Title)
		dimColor.Printf("      %s\n", truncate(t.Description, 100))
	}
	fmt.Println()

	return len(newTasks), nil
}

func (o *Orchestrator) evolve(ctx context.Context) error {
	s := o.state

	evolveColor := color.New(color.FgMagenta, color.Bold)
	stepColor := color.New(color.FgYellow, color.Bold)
	successColor := color.New(color.FgGreen, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)

	evolveColor.Printf("\n🧠 Auto-Evolve — Continuously improving the project\n")
	fmt.Printf("   Press Ctrl+C to stop.\n\n")

	for {
		select {
		case <-ctx.Done():
			s.Status = "complete"
			s.Save()
			evolveColor.Printf("\n⏸ Auto-evolve stopped. Project is complete.\n")
			return nil
		default:
		}

		// Prefer pending tasks over random improvements.
		// If the plan has pending tasks, execute the next one before discovering new ones.
		if s.Plan != nil {
			nextTask := s.Plan.NextTask()
			if nextTask != nil {
				stepColor.Printf("━━━ Evolve Task %d: %s ━━━\n", nextTask.ID, nextTask.Title)
				dimColor.Printf("       %s\n\n", truncate(nextTask.Description, 150))

				now := time.Now()
				nextTask.Status = pm.TaskInProgress
				nextTask.StartedAt = &now
				s.Save()

				evolvePrunedPlan, keptEv, totalEv := o.prunePlanForPrompt(s.Plan)
				if keptEv < totalEv {
					color.New(color.FgYellow).Printf("Context pruned: kept %d of %d steps to fit token budget\n", keptEv, totalEv)
				}
				prompt := pm.ExecuteTaskPrompt(s.Goal, s.Instructions, evolvePrunedPlan, nextTask)
				dimColor.Printf("→ Executing task %d via %s...\n", nextTask.ID, o.provider.Name())
				start := time.Now()

				evoOpts, evoWasStreamed := o.makeOpts(s.Model, true)
				result, err := o.provider.Complete(ctx, prompt, evoOpts)
				if err != nil {
					failColor.Printf("✗ Provider error on task %d: %v\n", nextTask.ID, err)
					nextTask.Status = pm.TaskFailed
					s.Status = "complete"
					s.Save()
					return nil
				}

				duration := time.Since(start)
				stepResult := state.StepResult{
					Task:         fmt.Sprintf("Evolve Task %d: %s", nextTask.ID, nextTask.Title),
					Output:       result.Output,
					Duration:     duration.Round(time.Second).String(),
					Time:         time.Now(),
					InputTokens:  result.InputTokens,
					OutputTokens: result.OutputTokens,
				}
				s.TotalInputTokens += result.InputTokens
				s.TotalOutputTokens += result.OutputTokens
				s.AddStep(stepResult)

				if evoWasStreamed() {
					fmt.Println()
				} else {
					printOutput(result.Output, dimColor, o.config.Verbose)
				}
				dimColor.Printf("  [%s, provider: %s]\n\n", duration.Round(time.Second), result.Provider)

				completedAt := time.Now()
				nextTask.CompletedAt = &completedAt
				nextTask.Result = truncate(result.Output, 500)
				if nextTask.StartedAt != nil {
					nextTask.ActualMinutes = int(completedAt.Sub(*nextTask.StartedAt).Minutes())
				}

				signal := pm.CheckTaskSignal(result.Output)
				switch signal {
				case pm.TaskDone:
					nextTask.Status = pm.TaskDone
					successColor.Printf("✓ Evolve task %d complete: %s\n\n", nextTask.ID, nextTask.Title)
				case pm.TaskSkipped:
					nextTask.Status = pm.TaskSkipped
					dimColor.Printf("→ Evolve task %d skipped: %s\n\n", nextTask.ID, nextTask.Title)
				case pm.TaskFailed:
					nextTask.Status = pm.TaskFailed
					failColor.Printf("✗ Evolve task %d failed: %s\n\n", nextTask.ID, nextTask.Title)
				default:
					nextTask.Status = pm.TaskDone
					successColor.Printf("✓ Evolve task %d complete (no signal): %s\n\n", nextTask.ID, nextTask.Title)
				}
				s.Save()
				continue
			}

			// All tasks done — discover new ones via AI before falling back to free-form.
			s.SyncFromDisk()
			if s.Plan.IsComplete() {
				n, err := o.evolvePM(ctx)
				if err != nil {
					evolveColor.Printf("\n⏹ Evolve task discovery failed: %v\n", err)
					s.Status = "complete"
					s.Save()
					return nil
				}
				if n > 0 {
					continue // execute the newly discovered tasks
				}
				// No new tasks — fall through to free-form evolve below
			}
		}

		s.EvolveStep++
		stepColor.Printf("━━━ Evolve #%d ━━━\n", s.EvolveStep)

		prompt := o.buildEvolvePrompt()
		dimColor.Printf("→ Thinking of improvements...\n")

		freeOpts, freeWasStreamed := o.makeOpts(s.Model, true)
		result, err := o.provider.Complete(ctx, prompt, freeOpts)
		if err != nil {
			evolveColor.Printf("\n⏹ Auto-evolve ended: %v\n", err)
			s.Status = "complete"
			s.Save()
			return nil
		}

		stepResult := state.StepResult{
			Task:         fmt.Sprintf("Evolve #%d", s.EvolveStep),
			Output:       result.Output,
			Duration:     result.Duration.Round(time.Second).String(),
			Time:         time.Now(),
			InputTokens:  result.InputTokens,
			OutputTokens: result.OutputTokens,
		}
		s.TotalInputTokens += result.InputTokens
		s.TotalOutputTokens += result.OutputTokens
		s.AddStep(stepResult)

		if freeWasStreamed() {
			fmt.Println()
		} else {
			printOutput(result.Output, dimColor, o.config.Verbose)
		}
		dimColor.Printf("  [%s, provider: %s]\n\n", result.Duration.Round(time.Second), result.Provider)
		s.Save()
	}
}

func (o *Orchestrator) buildEvolvePrompt() string {
	s := o.state
	var b strings.Builder

	b.WriteString("You are in AUTO-EVOLVE mode. The original project goal has been completed.\n")
	b.WriteString("Now you should independently improve the project by adding useful features,\n")
	b.WriteString("improving code quality, adding tests, fixing edge cases, improving docs, etc.\n\n")

	b.WriteString(fmt.Sprintf("## ORIGINAL GOAL (completed)\n%s\n\n", s.Goal))

	if s.Instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", s.Instructions))
	}

	b.WriteString(fmt.Sprintf("## EVOLVE ITERATION\n#%d\n\n", s.EvolveStep))

	recent := s.LastNSteps(2)
	if len(recent) > 0 {
		b.WriteString("## RECENT WORK\n")
		for _, step := range recent {
			b.WriteString(fmt.Sprintf("### %s (%s)\n", step.Task, step.Duration))
			output := step.Output
			if len(output) > 2000 {
				output = output[:1000] + "\n...(truncated)...\n" + output[len(output)-1000:]
			}
			b.WriteString(output)
			b.WriteString("\n\n")
		}
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("1. Explore the current codebase\n")
	b.WriteString("2. Identify a meaningful improvement (feature, test, refactor, docs, perf)\n")
	b.WriteString("3. Implement it\n")
	b.WriteString("4. Verify it works\n")
	b.WriteString("5. Summarize what you added and why\n\n")
	b.WriteString("Pick ONE focused improvement per iteration. Make it count.\n")

	if o.config.InnovateMode {
		b.WriteString("\n## 🚀 INNOVATION MODE ACTIVE\n")
		b.WriteString("Go beyond obvious improvements. Think creatively and unconventionally.\n")
		b.WriteString("Explore ideas that could be genuinely novel or surprising:\n")
		b.WriteString("- Cross-provider intelligence (use multiple providers together, consensus, fallback chains)\n")
		b.WriteString("- Self-optimization (analyze own performance, tune prompts, learn from failures)\n")
		b.WriteString("- Predictive capabilities (anticipate what the user needs next)\n")
		b.WriteString("- Meta-learning (extract patterns from past iterations to improve future ones)\n")
		b.WriteString("- Novel interaction patterns (watch mode enhancements, collaborative modes, branching)\n")
		b.WriteString("- Emergent behaviors (let the system surprise you with useful capabilities)\n")
		b.WriteString("- Integration points (webhooks, APIs, CI/CD, external tools)\n")
		b.WriteString("\nDon't just add features — invent capabilities that don't exist in other tools.\n")
		b.WriteString("Be bold. If it might not work, try it anyway and document what you learned.\n")
	}

	return b.String()
}

func (o *Orchestrator) isGoalComplete(output string) bool {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		return false
	}
	check := lines
	if len(check) > 5 {
		check = check[len(check)-5:]
	}
	for _, line := range check {
		if strings.TrimSpace(line) == "GOAL_COMPLETE" {
			return true
		}
	}
	return false
}

func printOutput(output string, dimColor *color.Color, verbose bool) {
	printOutputTo(os.Stdout, output, dimColor, verbose)
}

func printOutputTo(w io.Writer, output string, dimColor *color.Color, verbose bool) {
	lines := strings.Split(output, "\n")
	if !verbose && len(lines) > 20 {
		for _, line := range lines[:10] {
			fmt.Fprintf(w, "  %s\n", line)
		}
		dimColor.Fprintf(w, "  ... (%d lines omitted, use --verbose to see all) ...\n", len(lines)-20)
		for _, line := range lines[len(lines)-10:] {
			fmt.Fprintf(w, "  %s\n", line)
		}
	} else {
		for _, line := range lines {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// stepSummaryLine returns a short one-line summary of a step's output.
// It picks the last non-empty, non-signal line (avoiding GOAL_COMPLETE /
// TASK_* markers) and truncates it to maxLen runes.
func stepSummaryLine(output string, maxLen int) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	signals := map[string]bool{
		"GOAL_COMPLETE": true,
		"TASK_DONE":     true,
		"TASK_SKIPPED":  true,
		"TASK_FAILED":   true,
	}
	// Walk backwards to find the last meaningful line.
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || signals[line] {
			continue
		}
		if len([]rune(line)) > maxLen {
			runes := []rune(line)
			return string(runes[:maxLen]) + "..."
		}
		return line
	}
	return "(no summary)"
}

// learnFromSession asks the AI to extract learnings from the session and saves them.
func (o *Orchestrator) learnFromSession(ctx context.Context, steps []state.StepResult) {
	if !o.config.Learn || o.memory == nil || len(steps) == 0 {
		return
	}
	// Build a compact session summary from step outputs.
	var sb strings.Builder
	for i, step := range steps {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... (%d more steps)\n", len(steps)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("Step %d (%s): %s\n", step.Step+1, step.Duration, truncate(step.Output, 300)))
	}
	summary := sb.String()

	dimColor := color.New(color.Faint)
	dimColor.Printf("  Extracting session learnings...\n")

	learnings, err := memory.ExtractLearnings(ctx, o.provider, o.state.Model, o.state.Goal, summary, o.memory)
	if err != nil {
		dimColor.Printf("  Memory extraction failed: %v\n", err)
		return
	}
	if len(learnings) == 0 {
		dimColor.Printf("  No new learnings extracted.\n")
		return
	}
	if err := o.memory.Save(o.config.WorkDir); err != nil {
		dimColor.Printf("  Failed to save memory: %v\n", err)
		return
	}
	dimColor.Printf("  Saved %d learning(s) to project memory.\n", len(learnings))
}

// checkCostLimit evaluates the current session cost against the configured
// CostLimit. It logs a warning at 80% and returns true (stop) when the limit
// is reached. model and provider come from state/config respectively.
func (o *Orchestrator) checkCostLimit(s *state.ProjectState) (stop bool) {
	if o.config.CostLimit <= 0 {
		return false
	}
	model := s.Model
	if model == "" {
		model = o.config.Model
	}
	usd := cost.EstimateSessionCost(o.config.ProviderName, model, s.TotalInputTokens, s.TotalOutputTokens)
	if usd >= o.config.CostLimit {
		color.New(color.FgRed).Printf(
			"⏸ Cost limit reached (%s). Run 'cloop run' to continue.\n",
			cost.FormatCostWithLimit(usd, o.config.CostLimit),
		)
		return true
	}
	if usd >= o.config.CostLimit*0.8 {
		color.New(color.FgYellow).Printf(
			"  Cost warning: %s (80%% of limit %s)\n",
			cost.FormatCost(usd), cost.FormatCost(o.config.CostLimit),
		)
	}
	return false
}

// printSessionSummary prints a one-line summary after a run session ends.
// It is called via defer so it always runs, even on error paths.
func printSessionSummary(start time.Time, startStep int, s *state.ProjectState) {
	steps := s.CurrentStep - startStep
	elapsed := time.Since(start).Round(time.Second)
	dimColor := color.New(color.Faint)
	dimColor.Printf("Session: %d step(s) in %s", steps, elapsed)
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		dimColor.Printf(", %d in / %d out tokens (cumulative)", s.TotalInputTokens, s.TotalOutputTokens)
		if s.Model != "" {
			if usd, ok := cost.Estimate(s.Model, s.TotalInputTokens, s.TotalOutputTokens); ok {
				dimColor.Printf(" ≈ %s", cost.FormatCost(usd))
			}
		}
	}
	dimColor.Printf("\n")
}
