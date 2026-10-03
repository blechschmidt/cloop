package multiagent

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// passRecorder answers each pass and records what it was called with.
type passRecorder struct {
	mu      sync.Mutex
	prompts []string
	opts    []provider.Options
	// background is what the coder pass leaves behind.
	background *provider.BackgroundActivity
}

func (p *passRecorder) Complete(_ context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	p.mu.Lock()
	n := len(p.prompts)
	p.prompts = append(p.prompts, prompt)
	p.opts = append(p.opts, opts)
	p.mu.Unlock()
	res := &provider.Result{InputTokens: 10 * (n + 1), OutputTokens: n + 1, ThinkingTokens: 2,
		SessionID: []string{"arch-session", "coder-session", "review-session"}[n%3]}
	switch n {
	case 0:
		res.Output = "Design: one function."
	case 1:
		res.Output = "Implemented and pushed.\nTASK_DONE"
		res.Background = p.background
	default:
		res.Output = "Looks right.\nTASK_DONE"
	}
	return res, nil
}
func (p *passRecorder) Name() string         { return "recorder" }
func (p *passRecorder) DefaultModel() string { return "m" }

// Every pass runs with the options a single agent would get — the review
// gate's push hold above all — and is told about the gate (Task 20365).
func TestRunTask_EveryPassGetsTheCallersOptions(t *testing.T) {
	var waited int
	base := provider.Options{
		Model:            "opus",
		Effort:           "high",
		ExtendedThinking: true,
		ThinkingBudget:   4096,
		WorkDir:          "/srv/project",
		Env:              []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=url.cloopgate::.pushInsteadOf", "GIT_CONFIG_VALUE_0="},
		OnBackgroundWait: func(provider.BackgroundActivity) { waited++ },
	}
	rec := &passRecorder{}
	res, err := RunTask(context.Background(), rec, base, Brief{
		Task:   &pm.Task{ID: 7, Title: "Add division", Description: "guard the divisor"},
		Goal:   "calculator",
		Notice: "## REVIEW GATE\nYour pushes are held until the reviewer approves.\n",
	})
	if err != nil {
		t.Fatalf("RunTask: %v", err)
	}
	if len(rec.opts) != 3 {
		t.Fatalf("passes = %d, want 3", len(rec.opts))
	}
	wantSystem := []string{ArchitectSystemPrompt, CoderSystemPrompt, ReviewerSystemPrompt}
	for i, o := range rec.opts {
		if o.Model != "opus" || o.Effort != "high" || !o.ExtendedThinking || o.ThinkingBudget != 4096 ||
			o.WorkDir != "/srv/project" {
			t.Errorf("pass %d options = %+v, want the caller's", i, o)
		}
		if strings.Join(o.Env, " ") != strings.Join(base.Env, " ") {
			t.Errorf("pass %d environment = %v: the review gate's push hold did not reach it", i, o.Env)
		}
		if o.OnBackgroundWait == nil {
			t.Errorf("pass %d has no background-wait notice", i)
		}
		if o.SystemPrompt != wantSystem[i] {
			t.Errorf("pass %d system prompt is not its role's", i)
		}
		// Task 20148: no step timeout means none, not a hidden ten minutes.
		if o.Timeout != 0 {
			t.Errorf("pass %d timeout = %s, want none", i, o.Timeout)
		}
		if !strings.Contains(rec.prompts[i], "## REVIEW GATE") {
			t.Errorf("pass %d was not told about the review gate", i)
		}
	}

	if res.InputTokens != 60 || res.OutputTokens != 6 || res.ThinkingTokens != 6 {
		t.Errorf("tokens = %d/%d/%d, want every pass's summed", res.InputTokens, res.OutputTokens, res.ThinkingTokens)
	}
	if res.SessionID != "coder-session" {
		t.Errorf("session = %q, want the coder's: a review fix round resumes the agent that made the changes", res.SessionID)
	}
}

func TestRunTask_KeepsTheCallersTimeout(t *testing.T) {
	rec := &passRecorder{}
	if _, err := RunTask(context.Background(), rec, provider.Options{Timeout: 3 * time.Minute},
		Brief{Task: &pm.Task{ID: 1, Title: "t"}}); err != nil {
		t.Fatal(err)
	}
	for i, o := range rec.opts {
		if o.Timeout != 3*time.Minute {
			t.Errorf("pass %d timeout = %s, want the caller's 3m", i, o.Timeout)
		}
	}
}

// Work a pass left running is reported, so the orchestrator judges the task
// by it as it judges a single agent's.
func TestRunTask_ReportsBackgroundWork(t *testing.T) {
	rec := &passRecorder{background: &provider.BackgroundActivity{Detected: 2, Drained: false, Commands: []string{"make train"}}}
	res, err := RunTask(context.Background(), rec, provider.Options{}, Brief{Task: &pm.Task{ID: 1, Title: "train"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Background.Incomplete() || res.Background.Detected != 2 {
		t.Fatalf("background = %+v, want the coder's unfinished work", res.Background)
	}
}

func TestRunTask_RefusesNoTask(t *testing.T) {
	if _, err := RunTask(context.Background(), &passRecorder{}, provider.Options{}, Brief{}); err == nil {
		t.Fatal("RunTask without a task did not fail")
	}
}
