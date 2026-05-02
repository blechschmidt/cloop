// Package flow implements a declarative automation pipeline runner.
// Flows are defined in YAML files and consist of sequential steps that
// invoke cloop subcommands with optional conditions and failure policies.
package flow

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// OnFailurePolicy controls what happens when a step fails.
type OnFailurePolicy string

const (
	OnFailureContinue OnFailurePolicy = "continue"
	OnFailureAbort    OnFailurePolicy = "abort"
	OnFailureRetry    OnFailurePolicy = "retry"
)

// FlowStep represents a single step in an automation pipeline.
type FlowStep struct {
	// Name is a human-readable label for the step.
	Name string `yaml:"name"`

	// Command is the cloop subcommand to invoke (e.g., "lint", "run", "report").
	Command string `yaml:"command"`

	// Args are extra arguments passed to the cloop subcommand.
	Args []string `yaml:"args,omitempty"`

	// If is a shell condition evaluated before executing the step.
	// The step is skipped when the condition exits non-zero.
	// Example: "test -f go.mod"
	If string `yaml:"if,omitempty"`

	// OnFailure controls behaviour when the step's Command fails.
	// Valid values: "continue" (default), "abort", "retry".
	OnFailure OnFailurePolicy `yaml:"on_failure,omitempty"`

	// Env holds extra environment variables injected for this step only.
	Env map[string]string `yaml:"env,omitempty"`

	// MaxRetries is the number of additional attempts when OnFailure is "retry".
	// Defaults to 2.
	MaxRetries int `yaml:"max_retries,omitempty"`
}

// Flow is the top-level structure parsed from a flow YAML file.
type Flow struct {
	// Name is a human-readable title for the pipeline.
	Name string `yaml:"name"`

	// Description is an optional longer description of the pipeline's purpose.
	Description string `yaml:"description,omitempty"`

	// Steps is the ordered list of pipeline steps.
	Steps []FlowStep `yaml:"steps"`
}

// StepResult captures the outcome of a single step execution.
type StepResult struct {
	StepName string
	Skipped  bool
	Err      error
	Duration time.Duration
	Attempts int
}

// RunConfig controls the behaviour of Run.
type RunConfig struct {
	// WorkDir is the directory from which cloop commands are executed.
	WorkDir string

	// CloopBin is the path to the cloop binary. Defaults to the current executable.
	CloopBin string

	// DryRun prints commands without executing them.
	DryRun bool

	// Stdout and Stderr for step output. Defaults to os.Stdout/Stderr.
	Stdout *os.File
	Stderr *os.File
}

// Load reads and parses a Flow from the given YAML file path.
func Load(path string) (*Flow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading flow file: %w", err)
	}
	var f Flow
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing flow YAML: %w", err)
	}
	if f.Name == "" {
		f.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return &f, nil
}

// Run executes the flow sequentially, honouring step conditions and failure policies.
// It returns a slice of StepResults (one per step) and a combined error if any step
// caused the pipeline to abort.
func Run(ctx context.Context, flow *Flow, cfg RunConfig) ([]StepResult, error) {
	cloopBin := cfg.CloopBin
	if cloopBin == "" {
		self, err := os.Executable()
		if err != nil {
			cloopBin = "cloop"
		} else {
			cloopBin = self
		}
	}
	stdout := cfg.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	results := make([]StepResult, 0, len(flow.Steps))

	for i, step := range flow.Steps {
		result := StepResult{StepName: step.Name}
		if result.StepName == "" {
			result.StepName = fmt.Sprintf("step-%d", i+1)
		}

		// Evaluate condition.
		if step.If != "" {
			condOK, err := evalCondition(ctx, step.If, cfg.WorkDir, cfg.DryRun)
			if err != nil {
				result.Err = fmt.Errorf("condition eval: %w", err)
				results = append(results, result)
				fmt.Fprintf(stdout, "  [SKIP] %s — condition error: %v\n", result.StepName, err)
				continue
			}
			if !condOK {
				result.Skipped = true
				results = append(results, result)
				fmt.Fprintf(stdout, "  [SKIP] %s — condition false\n", result.StepName)
				continue
			}
		}

		policy := step.OnFailure
		if policy == "" {
			policy = OnFailureAbort
		}
		maxRetries := step.MaxRetries
		if policy == OnFailureRetry && maxRetries == 0 {
			maxRetries = 2
		}

		var lastErr error
		attempts := 0
		for {
			attempts++
			start := time.Now()
			lastErr = execStep(ctx, cloopBin, step, cfg, stdout, stderr)
			result.Duration += time.Since(start)
			if lastErr == nil {
				break
			}
			if policy == OnFailureRetry && attempts <= maxRetries {
				fmt.Fprintf(stdout, "  [RETRY] %s (attempt %d/%d)\n", result.StepName, attempts+1, maxRetries+1)
				continue
			}
			break
		}
		result.Attempts = attempts
		result.Err = lastErr
		results = append(results, result)

		if lastErr != nil {
			switch policy {
			case OnFailureContinue:
				fmt.Fprintf(stdout, "  [FAIL] %s — continuing (on_failure: continue)\n", result.StepName)
			default: // abort
				fmt.Fprintf(stdout, "  [FAIL] %s — aborting pipeline\n", result.StepName)
				return results, fmt.Errorf("step %q failed: %w", result.StepName, lastErr)
			}
		}
	}
	return results, nil
}

// execStep runs a single flow step's cloop command.
func execStep(ctx context.Context, cloopBin string, step FlowStep, cfg RunConfig, stdout, stderr *os.File) error {
	// Build command: cloop <command> [args...]
	args := append([]string{step.Command}, step.Args...)

	stepName := step.Name
	if stepName == "" {
		stepName = step.Command
	}
	fmt.Fprintf(stdout, "  [RUN]  %s: %s %s\n", stepName, filepath.Base(cloopBin), strings.Join(args, " "))

	if cfg.DryRun {
		return nil
	}

	cmd := exec.CommandContext(ctx, cloopBin, args...)
	cmd.Dir = cfg.WorkDir
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Merge environment: inherit current + step-specific overrides.
	env := os.Environ()
	for k, v := range step.Env {
		env = append(env, k+"="+v)
	}
	cmd.Env = env

	return cmd.Run()
}

// evalCondition evaluates a shell condition string using /bin/sh -c.
// Returns true if the command exits 0.
func evalCondition(ctx context.Context, cond, workDir string, dryRun bool) (bool, error) {
	if dryRun {
		return true, nil
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cond)
	cmd.Dir = workDir
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 0 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

// ListFlows returns all .yaml / .yml files found in the flows directory
// (.cloop/flows/ relative to workDir).
func ListFlows(workDir string) ([]string, error) {
	dir := filepath.Join(workDir, ".cloop", "flows")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading flows directory: %w", err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths, nil
}

// ExampleFlow returns a sample Flow struct that can be serialised to YAML.
func ExampleFlow() *Flow {
	return &Flow{
		Name:        "my-pipeline",
		Description: "Example cloop automation pipeline",
		Steps: []FlowStep{
			{
				Name:      "lint plan",
				Command:   "lint",
				OnFailure: OnFailureContinue,
			},
			{
				Name:    "health check",
				Command: "health",
				If:      "test -f .cloop/state.db",
			},
			{
				Name:      "run tasks",
				Command:   "run",
				Args:      []string{"--pm", "--dry-run"},
				OnFailure: OnFailureAbort,
				Env:       map[string]string{"CLOOP_TIMEOUT": "300"},
			},
			{
				Name:    "generate report",
				Command: "report",
			},
		},
	}
}

// ReleaseFlow returns the built-in release pipeline template.
func ReleaseFlow() *Flow {
	return &Flow{
		Name:        "release",
		Description: "Standard release pipeline: lint → test → changelog → pr",
		Steps: []FlowStep{
			{
				Name:      "lint",
				Command:   "lint",
				OnFailure: OnFailureAbort,
			},
			{
				Name:      "health",
				Command:   "health",
				OnFailure: OnFailureContinue,
			},
			{
				Name:      "changelog",
				Command:   "changelog",
				OnFailure: OnFailureContinue,
			},
			{
				Name:      "pr",
				Command:   "pr",
				OnFailure: OnFailureAbort,
			},
		},
	}
}

// ReviewFlow returns the built-in review pipeline template.
func ReviewFlow() *Flow {
	return &Flow{
		Name:        "review",
		Description: "Code review pipeline: analyze → health → risk → explain",
		Steps: []FlowStep{
			{
				Name:      "analyze",
				Command:   "analyze",
				OnFailure: OnFailureContinue,
			},
			{
				Name:      "health",
				Command:   "health",
				OnFailure: OnFailureContinue,
			},
			{
				Name:      "risk",
				Command:   "risk",
				OnFailure: OnFailureContinue,
			},
			{
				Name:      "explain",
				Command:   "explain",
				OnFailure: OnFailureContinue,
			},
		},
	}
}

// BuiltinTemplates returns all built-in flow templates keyed by name.
func BuiltinTemplates() map[string]*Flow {
	return map[string]*Flow{
		"release": ReleaseFlow(),
		"review":  ReviewFlow(),
	}
}

// MarshalYAML serialises a Flow to a YAML byte slice with a header comment.
func MarshalYAML(f *Flow) ([]byte, error) {
	return yaml.Marshal(f)
}
