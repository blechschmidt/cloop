package orchestrator

// A chained task keeps its predecessor's output across a reload (Task 20361).
//
// ChainInput is not stored — it is a copy of up to 16 MiB of transcript — so
// before ensureChainInput a chain only worked when the predecessor finished in
// the same process that then ran the chained task. A stop and resume between
// the two, or a parallel run, dispatched the chained task without its input.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

const chainReloadTag = "chain:reload"

// chainedProject saves a plan whose task 1 is done, with an artifact, and whose
// task 2 is chained to it and pending — the state a run leaves behind when it
// stops between the two.
func chainedProject(t *testing.T, body string) string {
	t.Helper()
	dir := statedbtest.Dir(t)
	art := filepath.Join(".cloop", "tasks", "1-produce.md")
	if err := os.MkdirAll(filepath.Join(dir, ".cloop", "tasks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, art), []byte("---\nid: 1\n---\n\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := state.Init(dir, "goal", 0)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	done := time.Now().UTC()
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "produce", Status: pm.TaskDone, Tags: []string{chainReloadTag},
			ArtifactPath: art, Result: "short summary", CompletedAt: &done},
		{ID: 2, Title: "consume", Status: pm.TaskPending, Tags: []string{chainReloadTag}, DependsOn: []int{1}},
	}}
	// The process that finished task 1 handed its output over in memory...
	o := &Orchestrator{config: Config{WorkDir: dir}}
	o.injectChainOutput(s.Plan, s.Plan.TaskByID(1), "fallback")
	if s.Plan.TaskByID(2).ChainInput == "" {
		t.Fatal("precondition: the in-process hand-over did not happen")
	}
	// ...and then stopped.
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return dir
}

func TestChainInputSurvivesAReload(t *testing.T) {
	const body = "Built the index; it lives at build/index.json.\n"
	dir := chainedProject(t, body)

	resumed, err := state.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	task := resumed.Plan.TaskByID(2)
	if task.ChainInput != "" {
		t.Fatalf("precondition: ChainInput came back from the database (%q); it is meant to be derived", task.ChainInput)
	}

	o := &Orchestrator{config: Config{WorkDir: dir}}
	o.ensureChainInput(resumed.Plan, task)
	if task.ChainInput != body {
		t.Fatalf("ChainInput after a reload = %q, want the predecessor's output %q", task.ChainInput, body)
	}
	prompt := pm.ExecuteTaskPrompt(resumed.Goal, "", dir, resumed.Plan, task, true)
	if !strings.Contains(prompt, "PREVIOUS STEP OUTPUT") || !strings.Contains(prompt, "build/index.json") {
		t.Errorf("the chained task's prompt does not carry its predecessor's output:\n%s", prompt)
	}
}

func TestEnsureChainInputFollowsTheSameRuleAsTheHandOver(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	cases := []struct {
		name string
		deps []*pm.Task
		task *pm.Task
		want string
	}{{
		name: "a predecessor that is not done hands nothing over",
		deps: []*pm.Task{{ID: 1, Status: pm.TaskInProgress, Tags: []string{chainReloadTag}, Result: "partial"}},
		task: &pm.Task{ID: 9, Tags: []string{chainReloadTag}, DependsOn: []int{1}},
		want: "",
	}, {
		name: "a predecessor in another chain hands nothing over",
		deps: []*pm.Task{{ID: 1, Status: pm.TaskDone, Tags: []string{"chain:other"}, Result: "theirs"}},
		task: &pm.Task{ID: 9, Tags: []string{chainReloadTag}, DependsOn: []int{1}},
		want: "",
	}, {
		name: "a done task that is not a dependency hands nothing over",
		deps: []*pm.Task{{ID: 1, Status: pm.TaskDone, Tags: []string{chainReloadTag}, Result: "unrelated"}},
		task: &pm.Task{ID: 9, Tags: []string{chainReloadTag}},
		want: "",
	}, {
		name: "without an artifact the summary is handed over, as injectChainOutput would",
		deps: []*pm.Task{{ID: 1, Status: pm.TaskDone, Tags: []string{chainReloadTag}, Result: "summary only"}},
		task: &pm.Task{ID: 9, Tags: []string{chainReloadTag}, DependsOn: []int{1}},
		want: "summary only",
	}, {
		name: "of two predecessors the one that finished last wins",
		deps: []*pm.Task{
			{ID: 1, Status: pm.TaskDone, Tags: []string{chainReloadTag}, Result: "later", CompletedAt: &late},
			{ID: 2, Status: pm.TaskDone, Tags: []string{chainReloadTag}, Result: "earlier", CompletedAt: &early},
		},
		task: &pm.Task{ID: 9, Tags: []string{chainReloadTag}, DependsOn: []int{1, 2}},
		want: "later",
	}, {
		name: "an input already handed over in this process is kept",
		deps: []*pm.Task{{ID: 1, Status: pm.TaskDone, Tags: []string{chainReloadTag}, Result: "stored"}},
		task: &pm.Task{ID: 9, Tags: []string{chainReloadTag}, DependsOn: []int{1}, ChainInput: "live"},
		want: "live",
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := &pm.Plan{Tasks: append(append([]*pm.Task(nil), tc.deps...), tc.task)}
			o := &Orchestrator{config: Config{WorkDir: t.TempDir()}}
			o.ensureChainInput(plan, tc.task)
			if tc.task.ChainInput != tc.want {
				t.Errorf("ChainInput = %q, want %q", tc.task.ChainInput, tc.want)
			}
		})
	}
}
