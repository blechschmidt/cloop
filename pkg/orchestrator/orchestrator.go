package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/claude"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
)

type Config struct {
	WorkDir         string
	Model           string
	MaxTokens       int
	StepTimeout     time.Duration
	Verbose         bool
	DryRun          bool
	SkipPermissions bool
}

type Orchestrator struct {
	config Config
	state  *state.ProjectState
}

func New(cfg Config) (*Orchestrator, error) {
	s, err := state.Load(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	if cfg.Model != "" {
		s.Model = cfg.Model
	}
	return &Orchestrator{config: cfg, state: s}, nil
}

func (o *Orchestrator) AddSteps(n int) {
	o.state.MaxSteps += n
	o.state.Save()
}

func (o *Orchestrator) SetAutoEvolve(enabled bool) {
	o.state.AutoEvolve = enabled
	o.state.Save()
}

func (o *Orchestrator) Run(ctx context.Context) error {
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

	header.Printf("\n🔄 cloop — Feedback Loop for Claude Code\n")
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

	consecutiveErrors := 0
	const maxConsecutiveErrors = 3

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

		// Build the prompt with full context
		prompt := o.buildPrompt()

		if o.config.DryRun {
			dimColor.Printf("[dry-run] Prompt:\n%s\n\n", prompt)
			s.CurrentStep++
			continue
		}

		// Run Claude Code
		dimColor.Printf("→ Running Claude Code...\n")
		start := time.Now()

		result, err := claude.Run(ctx, prompt, claude.Options{
			Model:           s.Model,
			WorkDir:         o.config.WorkDir,
			MaxTokens:       o.config.MaxTokens,
			Timeout:         o.config.StepTimeout,
			SkipPermissions: o.config.SkipPermissions,
		})
		if err != nil {
			failColor.Printf("✗ Claude Code failed: %v\n", err)
			s.Status = "failed"
			s.Save()
			return err
		}

		duration := time.Since(start)

		// Store step result
		stepResult := state.StepResult{
			Task:     fmt.Sprintf("Step %d", step),
			Output:   result.Output,
			ExitCode: result.ExitCode,
			Duration: duration.Round(time.Second).String(),
			Time:     time.Now(),
		}
		s.AddStep(stepResult)

		// Print output summary
		outputLines := strings.Split(result.Output, "\n")
		if len(outputLines) > 20 {
			for _, line := range outputLines[:10] {
				fmt.Printf("  %s\n", line)
			}
			dimColor.Printf("  ... (%d lines omitted) ...\n", len(outputLines)-20)
			for _, line := range outputLines[len(outputLines)-10:] {
				fmt.Printf("  %s\n", line)
			}
		} else {
			for _, line := range outputLines {
				fmt.Printf("  %s\n", line)
			}
		}

		dimColor.Printf("  [%s, exit %d]\n\n", duration.Round(time.Second), result.ExitCode)

		// Check if goal is complete
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

		// Check for failure
		if result.ExitCode != 0 {
			consecutiveErrors++
			failColor.Printf("⚠ Step %d exited with code %d (%d/%d consecutive errors)\n\n",
				step, result.ExitCode, consecutiveErrors, maxConsecutiveErrors)
			if consecutiveErrors >= maxConsecutiveErrors {
				failColor.Printf("✗ Too many consecutive errors. Stopping.\n")
				s.Status = "failed"
				s.Save()
				return fmt.Errorf("%d consecutive errors", consecutiveErrors)
			}
		} else {
			consecutiveErrors = 0
		}

		s.Save()
	}

	color.New(color.FgYellow).Printf("⏸ Reached max steps (%d). Run 'cloop run' to continue or 'cloop run --add-steps N' to extend.\n", s.MaxSteps)
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

	// Include recent step history for context
	recent := s.LastNSteps(3)
	if len(recent) > 0 {
		b.WriteString("## RECENT STEPS\n")
		for _, step := range recent {
			b.WriteString(fmt.Sprintf("### Step %d (%s)\n", step.Step+1, step.Duration))
			// Truncate output to keep prompt manageable
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

	evolveColor.Printf("\n🧠 Auto-Evolve — Claude is now improving the project on its own\n")
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

		dimColor.Printf("→ Claude is thinking of improvements...\n")

		result, err := claude.Run(ctx, prompt, claude.Options{
			Model:           s.Model,
			WorkDir:         o.config.WorkDir,
			MaxTokens:       o.config.MaxTokens,
			Timeout:         o.config.StepTimeout,
			SkipPermissions: o.config.SkipPermissions,
		})
		if err != nil {
			// Token exhaustion or other error — stop gracefully
			evolveColor.Printf("\n⏹ Auto-evolve ended: %v\n", err)
			s.Status = "complete"
			s.Save()
			return nil
		}

		stepResult := state.StepResult{
			Task:     fmt.Sprintf("Evolve #%d", s.EvolveStep),
			Output:   result.Output,
			ExitCode: result.ExitCode,
			Duration: result.Duration.Round(time.Second).String(),
			Time:     time.Now(),
		}
		s.AddStep(stepResult)

		// Print summary
		outputLines := strings.Split(result.Output, "\n")
		if len(outputLines) > 20 {
			for _, line := range outputLines[:10] {
				fmt.Printf("  %s\n", line)
			}
			dimColor.Printf("  ... (%d lines omitted) ...\n", len(outputLines)-20)
			for _, line := range outputLines[len(outputLines)-10:] {
				fmt.Printf("  %s\n", line)
			}
		} else {
			for _, line := range outputLines {
				fmt.Printf("  %s\n", line)
			}
		}

		dimColor.Printf("  [%s, exit %d]\n\n", result.Duration.Round(time.Second), result.ExitCode)
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

	// Show the last 2 steps for context
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
	// Check last few lines for the signal
	checkLines := lines
	if len(checkLines) > 5 {
		checkLines = checkLines[len(checkLines)-5:]
	}
	for _, line := range checkLines {
		if strings.TrimSpace(line) == "GOAL_COMPLETE" {
			return true
		}
	}
	return false
}
