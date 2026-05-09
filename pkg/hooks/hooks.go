// Package hooks executes user-defined shell commands before and after tasks and plans.
// Commands run via "sh -c" with task context passed as environment variables.
// Hook values prefixed with "plugin:<name>" invoke a discovered plugin instead of
// a raw shell command.
package hooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/plugin"
)

// DefaultTimeout is the maximum wall-clock duration any hook (or plugin invoked
// from a hook) may run before it is killed. A misbehaving hook (e.g. one that
// blocks on stdin or loops forever) would otherwise stall plan execution
// indefinitely. Callers may override per-config via Config.Timeout. Setting
// Config.Timeout to a negative duration disables the timeout entirely.
const DefaultTimeout = 10 * time.Minute

// Config holds the shell commands to run at lifecycle events.
// All fields are optional; an empty string disables the hook.
type Config struct {
	// PreTask runs before each task starts. Exit non-zero skips the task.
	PreTask string `yaml:"pre_task,omitempty"`
	// PostTask runs after each task completes (regardless of outcome).
	PostTask string `yaml:"post_task,omitempty"`
	// PrePlan runs once before plan execution begins.
	PrePlan string `yaml:"pre_plan,omitempty"`
	// PostPlan runs once after the plan finishes (all tasks done/failed/skipped).
	PostPlan string `yaml:"post_plan,omitempty"`
	// PostTaskReview enables AI code review annotations after each successful task.
	// When true, the orchestrator runs git diff HEAD~1 after TASK_DONE and calls
	// the provider for a correctness/security/style review stored as a task annotation.
	PostTaskReview bool `yaml:"post_task_review,omitempty"`
	// Timeout caps the wall-clock duration of each hook invocation. Zero falls
	// back to DefaultTimeout. A negative value disables the timeout (use only
	// for hooks that legitimately run longer than 10 minutes).
	Timeout time.Duration `yaml:"-"`
}

// TaskContext carries task metadata exposed to hook commands as env vars.
type TaskContext struct {
	ID     int
	Title  string
	Status string
	Role   string
}

// PlanContext carries plan metadata exposed to plan hook commands as env vars.
type PlanContext struct {
	Goal    string
	Total   int
	Done    int
	Failed  int
	Skipped int
}

// RunPreTask executes cfg.PreTask with the task's env vars set.
// Returns a non-nil error (with message) if the command exits non-zero;
// callers should skip the task when this happens.
// Returns nil immediately if cfg.PreTask is empty.
// extraEnv is an optional list of KEY=value strings (e.g. from cloop env vars)
// that are added to the subprocess environment alongside task context vars.
func RunPreTask(cfg Config, task TaskContext, extraEnv ...string) error {
	if cfg.PreTask == "" {
		return nil
	}
	return runHook(cfg.PreTask, append(taskEnv(task), extraEnv...), "pre_task", cfg.Timeout)
}

// RunPostTask executes cfg.PostTask. Errors are returned but callers
// typically only log them — post-task failures do not affect task status.
// Returns nil immediately if cfg.PostTask is empty.
// extraEnv is an optional list of KEY=value strings injected into the subprocess env.
func RunPostTask(cfg Config, task TaskContext, extraEnv ...string) error {
	if cfg.PostTask == "" {
		return nil
	}
	return runHook(cfg.PostTask, append(taskEnv(task), extraEnv...), "post_task", cfg.Timeout)
}

// RunPrePlan executes cfg.PrePlan. Returns a non-nil error if the command
// exits non-zero; callers should abort plan execution in that case.
// Returns nil immediately if cfg.PrePlan is empty.
// extraEnv is an optional list of KEY=value strings injected into the subprocess env.
func RunPrePlan(cfg Config, plan PlanContext, extraEnv ...string) error {
	if cfg.PrePlan == "" {
		return nil
	}
	return runHook(cfg.PrePlan, append(planEnv(plan), extraEnv...), "pre_plan", cfg.Timeout)
}

// RunPostPlan executes cfg.PostPlan. Errors are returned but do not abort anything.
// Returns nil immediately if cfg.PostPlan is empty.
// extraEnv is an optional list of KEY=value strings injected into the subprocess env.
func RunPostPlan(cfg Config, plan PlanContext, extraEnv ...string) error {
	if cfg.PostPlan == "" {
		return nil
	}
	return runHook(cfg.PostPlan, append(planEnv(plan), extraEnv...), "post_plan", cfg.Timeout)
}

// ParseTimeout converts a config-string timeout (e.g. "30s", "5m") into a
// time.Duration suitable for Config.Timeout. Empty input maps to 0, which the
// runner interprets as DefaultTimeout. A parse error is returned to the caller
// so misconfigured YAML is surfaced rather than silently swallowed.
func ParseTimeout(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid hook timeout %q: %w", s, err)
	}
	return d, nil
}

// effectiveTimeout resolves the timeout for a hook invocation.
//   - Negative cfg value: no timeout.
//   - Zero cfg value: DefaultTimeout (10 min).
//   - Positive cfg value: used as-is.
func effectiveTimeout(cfgTimeout time.Duration) time.Duration {
	if cfgTimeout < 0 {
		return 0
	}
	if cfgTimeout == 0 {
		return DefaultTimeout
	}
	return cfgTimeout
}

// runHook executes cmd via "sh -c" with extra env vars merged into the
// current process environment. Output (stdout+stderr) is forwarded to the
// caller's terminal so hook scripts can print messages. The hook is killed
// if it exceeds the timeout (default 10 minutes).
//
// If cmd is prefixed with "plugin:<name>", the named plugin is invoked via
// plugin.Run instead of a shell command. Optional arguments can follow the
// name separated by spaces: "plugin:lint --strict".
func runHook(cmd string, extra []string, hookName string, timeout time.Duration) error {
	timeout = effectiveTimeout(timeout)

	if strings.HasPrefix(cmd, "plugin:") {
		rest := strings.TrimPrefix(cmd, "plugin:")
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			return fmt.Errorf("hook %s: plugin: requires a plugin name", hookName)
		}
		name := parts[0]
		args := parts[1:]
		workDir, _ := os.Getwd()
		ctx, cancel := newRunCtx(timeout)
		defer cancel()
		if err := plugin.RunCtx(ctx, workDir, name, args, extra); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("hook %s timed out after %s (plugin %s): %w", hookName, timeout, name, err)
			}
			return fmt.Errorf("hook %s failed: %w", hookName, err)
		}
		return nil
	}

	ctx, cancel := newRunCtx(timeout)
	defer cancel()

	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	c.Env = append(os.Environ(), extra...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	err := c.Run()
	if err != nil {
		// Distinguish "killed by timeout" from "exited non-zero" so callers see
		// a meaningful message instead of a generic "signal: killed".
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("hook %s timed out after %s: %w", hookName, timeout, err)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("hook %s failed: %w", hookName, err)
		}
		return fmt.Errorf("hook %s failed: %w", hookName, err)
	}
	return nil
}

// newRunCtx returns a context with the given timeout, or a cancel-only context
// when timeout <= 0. The returned cancel must always be called to release
// resources.
func newRunCtx(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), timeout)
}

func taskEnv(t TaskContext) []string {
	return []string{
		"CLOOP_TASK_ID=" + strconv.Itoa(t.ID),
		"CLOOP_TASK_TITLE=" + t.Title,
		"CLOOP_TASK_STATUS=" + t.Status,
		"CLOOP_TASK_ROLE=" + t.Role,
	}
}

func planEnv(p PlanContext) []string {
	return []string{
		"CLOOP_PLAN_GOAL=" + p.Goal,
		"CLOOP_PLAN_TOTAL=" + strconv.Itoa(p.Total),
		"CLOOP_PLAN_DONE=" + strconv.Itoa(p.Done),
		"CLOOP_PLAN_FAILED=" + strconv.Itoa(p.Failed),
		"CLOOP_PLAN_SKIPPED=" + strconv.Itoa(p.Skipped),
	}
}
