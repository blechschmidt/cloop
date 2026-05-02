// Package hooks executes user-defined shell commands before and after tasks and plans.
// Commands run via "sh -c" with task context passed as environment variables.
package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
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
func RunPreTask(cfg Config, task TaskContext) error {
	if cfg.PreTask == "" {
		return nil
	}
	return runHook(cfg.PreTask, taskEnv(task), "pre_task")
}

// RunPostTask executes cfg.PostTask. Errors are returned but callers
// typically only log them — post-task failures do not affect task status.
// Returns nil immediately if cfg.PostTask is empty.
func RunPostTask(cfg Config, task TaskContext) error {
	if cfg.PostTask == "" {
		return nil
	}
	return runHook(cfg.PostTask, taskEnv(task), "post_task")
}

// RunPrePlan executes cfg.PrePlan. Returns a non-nil error if the command
// exits non-zero; callers should abort plan execution in that case.
// Returns nil immediately if cfg.PrePlan is empty.
func RunPrePlan(cfg Config, plan PlanContext) error {
	if cfg.PrePlan == "" {
		return nil
	}
	return runHook(cfg.PrePlan, planEnv(plan), "pre_plan")
}

// RunPostPlan executes cfg.PostPlan. Errors are returned but do not abort anything.
// Returns nil immediately if cfg.PostPlan is empty.
func RunPostPlan(cfg Config, plan PlanContext) error {
	if cfg.PostPlan == "" {
		return nil
	}
	return runHook(cfg.PostPlan, planEnv(plan), "post_plan")
}

// runHook executes cmd via "sh -c" with extra env vars merged into the
// current process environment. Output (stdout+stderr) is forwarded to the
// caller's terminal so hook scripts can print messages.
func runHook(cmd string, extra []string, hookName string) error {
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
