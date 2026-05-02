// Package hooks executes user-defined shell commands before and after tasks and plans.
// Commands run via "sh -c" with task context passed as environment variables.
// Hook values prefixed with "plugin:<name>" invoke a discovered plugin instead of
// a raw shell command.
package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/plugin"
)

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
	return runHook(cfg.PreTask, append(taskEnv(task), extraEnv...), "pre_task")
}

// RunPostTask executes cfg.PostTask. Errors are returned but callers
// typically only log them — post-task failures do not affect task status.
// Returns nil immediately if cfg.PostTask is empty.
// extraEnv is an optional list of KEY=value strings injected into the subprocess env.
func RunPostTask(cfg Config, task TaskContext, extraEnv ...string) error {
	if cfg.PostTask == "" {
		return nil
	}
	return runHook(cfg.PostTask, append(taskEnv(task), extraEnv...), "post_task")
}

// RunPrePlan executes cfg.PrePlan. Returns a non-nil error if the command
// exits non-zero; callers should abort plan execution in that case.
// Returns nil immediately if cfg.PrePlan is empty.
// extraEnv is an optional list of KEY=value strings injected into the subprocess env.
func RunPrePlan(cfg Config, plan PlanContext, extraEnv ...string) error {
	if cfg.PrePlan == "" {
		return nil
	}
	return runHook(cfg.PrePlan, append(planEnv(plan), extraEnv...), "pre_plan")
}

// RunPostPlan executes cfg.PostPlan. Errors are returned but do not abort anything.
// Returns nil immediately if cfg.PostPlan is empty.
// extraEnv is an optional list of KEY=value strings injected into the subprocess env.
func RunPostPlan(cfg Config, plan PlanContext, extraEnv ...string) error {
	if cfg.PostPlan == "" {
		return nil
	}
	return runHook(cfg.PostPlan, append(planEnv(plan), extraEnv...), "post_plan")
}

// runHook executes cmd via "sh -c" with extra env vars merged into the
// current process environment. Output (stdout+stderr) is forwarded to the
// caller's terminal so hook scripts can print messages.
//
// If cmd is prefixed with "plugin:<name>", the named plugin is invoked via
// plugin.Run instead of a shell command. Optional arguments can follow the
// name separated by spaces: "plugin:lint --strict".
func runHook(cmd string, extra []string, hookName string) error {
	if strings.HasPrefix(cmd, "plugin:") {
		rest := strings.TrimPrefix(cmd, "plugin:")
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			return fmt.Errorf("hook %s: plugin: requires a plugin name", hookName)
		}
		name := parts[0]
		args := parts[1:]
		workDir, _ := os.Getwd()
		if err := plugin.Run(workDir, name, args, extra); err != nil {
			return fmt.Errorf("hook %s failed: %w", hookName, err)
		}
		return nil
	}

	c := exec.Command("sh", "-c", cmd)
	c.Env = append(os.Environ(), extra...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("hook %s failed: %w", hookName, err)
	}
	return nil
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
