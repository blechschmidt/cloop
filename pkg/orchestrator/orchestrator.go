package orchestrator

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
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

	// StepDelay is the duration to wait between steps (0 = no delay).
	StepDelay time.Duration

	// Provider to use. If empty, falls back to state.Provider, then config.yaml, then claudecode.
	ProviderName string

	// Provider config for building providers
	ProviderCfg provider.ProviderConfig
}

type Orchestrator struct {
	config   Config
	state    *state.ProjectState
	provider provider.Provider
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
	return &Orchestrator{config: cfg, state: s, provider: prov}, nil
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
	if s.Instructions != "" {
		fmt.Printf("   Instructions: %s\n", s.Instructions)
	}
	fmt.Println()

	for s.MaxSteps == 0 || s.CurrentStep < s.MaxSteps {
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

		result, err := o.provider.Complete(ctx, prompt, provider.Options{
			Model:     s.Model,
			MaxTokens: o.config.MaxTokens,
			Timeout:   o.config.StepTimeout,
			WorkDir:   o.config.WorkDir,
		})
		if err != nil {
			failColor.Printf("✗ Provider error: %v\n", err)
			s.Status = "failed"
			s.Save()
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

		printOutput(result.Output, dimColor, o.config.Verbose)
		dimColor.Printf("  [%s, provider: %s]\n\n", duration.Round(time.Second), result.Provider)

		if o.isGoalComplete(result.Output) {
			successColor.Printf("🎉 Goal complete after %d steps!\n\n", step)
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

// runPM runs the product manager mode: decompose goal → execute tasks → verify.
func (o *Orchestrator) runPM(ctx context.Context) error {
	s := o.state
	s.Status = "running"
	if err := s.Save(); err != nil {
		return err
	}

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

	// Phase 2: Execute tasks in priority order
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

		if s.Plan.IsComplete() {
			successColor.Printf("🎉 All tasks complete! Goal achieved.\n")
			successColor.Printf("   %s\n\n", s.Plan.Summary())
			s.Status = "complete"
			s.Save()
			return nil
		}

		task := s.Plan.NextTask()
		if task == nil {
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
		now := time.Now()
		task.Status = pm.TaskInProgress
		task.StartedAt = &now
		s.Save()

		prompt := pm.ExecuteTaskPrompt(s.Goal, s.Instructions, s.Plan, task)

		if o.config.DryRun {
			dimColor.Printf("[dry-run] Task prompt:\n%s\n\n", prompt)
			task.Status = pm.TaskDone
			s.Save()
			continue
		}

		dimColor.Printf("→ Running %s on task %d...\n", o.provider.Name(), task.ID)
		start := time.Now()

		result, err := o.provider.Complete(ctx, prompt, provider.Options{
			Model:     s.Model,
			MaxTokens: o.config.MaxTokens,
			Timeout:   o.config.StepTimeout,
			WorkDir:   o.config.WorkDir,
		})
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

		printOutput(result.Output, dimColor, o.config.Verbose)
		dimColor.Printf("  [%s, provider: %s]\n\n", duration.Round(time.Second), result.Provider)

		// Update task status based on signal in output
		signal := pm.CheckTaskSignal(result.Output)
		completedAt := time.Now()
		task.CompletedAt = &completedAt
		task.Result = truncate(result.Output, 500)

		switch signal {
		case pm.TaskDone:
			task.Status = pm.TaskDone
			successColor.Printf("✓ Task %d complete: %s\n\n", task.ID, task.Title)
			consecutiveErrors = 0
		case pm.TaskSkipped:
			task.Status = pm.TaskSkipped
			dimColor.Printf("→ Task %d skipped: %s\n\n", task.ID, task.Title)
			consecutiveErrors = 0
		case pm.TaskFailed:
			task.Status = pm.TaskFailed
			failColor.Printf("✗ Task %d failed: %s\n\n", task.ID, task.Title)
			consecutiveErrors++
			if consecutiveErrors >= maxConsecutiveErrors {
				s.Status = "failed"
				s.Save()
				return fmt.Errorf("%d consecutive task failures", consecutiveErrors)
			}
		default:
			// No signal found — treat as done (AI finished without explicit signal)
			task.Status = pm.TaskDone
			successColor.Printf("✓ Task %d complete (no explicit signal): %s\n\n", task.ID, task.Title)
			consecutiveErrors = 0
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

func (o *Orchestrator) buildPrompt() string {
	s := o.state
	var b strings.Builder

	b.WriteString("You are working towards a project goal in an autonomous feedback loop.\n")
	b.WriteString("Each step you take should make meaningful progress towards the goal.\n")
	b.WriteString("You have full file system access and can run commands.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", s.Goal))

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
	recent := s.LastNSteps(contextSteps)
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

func (o *Orchestrator) evolve(ctx context.Context) error {
	s := o.state

	evolveColor := color.New(color.FgMagenta, color.Bold)
	stepColor := color.New(color.FgYellow, color.Bold)
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

		s.EvolveStep++
		stepColor.Printf("━━━ Evolve #%d ━━━\n", s.EvolveStep)

		prompt := o.buildEvolvePrompt()
		dimColor.Printf("→ Thinking of improvements...\n")

		result, err := o.provider.Complete(ctx, prompt, provider.Options{
			Model:     s.Model,
			MaxTokens: o.config.MaxTokens,
			Timeout:   o.config.StepTimeout,
			WorkDir:   o.config.WorkDir,
		})
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

		printOutput(result.Output, dimColor, o.config.Verbose)
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
