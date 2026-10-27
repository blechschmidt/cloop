package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// toolAgent stands in for a harness that works in the project with tools of
// its own: it writes files into whatever outbox its environment names.
type toolAgent struct {
	mu      sync.Mutex
	prompts map[int]string // task id → the prompt it was given
	envs    map[int][]string
	files   map[string]string // name → content, written for every task
}

func (a *toolAgent) Name() string         { return claudecode.ProviderName }
func (a *toolAgent) DefaultModel() string { return "test-model" }

func (a *toolAgent) Complete(_ context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	var box, task string
	for _, kv := range opts.Env {
		if v, ok := strings.CutPrefix(kv, attachments.EnvOutbox+"="); ok {
			box = v
		}
		if v, ok := strings.CutPrefix(kv, attachments.EnvTaskID+"="); ok {
			task = v
		}
	}
	var id int
	fmt.Sscanf(task, "%d", &id)
	a.mu.Lock()
	a.prompts[id] = prompt
	a.envs[id] = opts.Env
	a.mu.Unlock()
	if box != "" {
		for name, content := range a.files {
			path := filepath.Join(box, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(path, []byte(fmt.Sprintf(content, id)), 0o644); err != nil {
				return nil, err
			}
		}
	}
	return &provider.Result{Output: "made the report\nTASK_DONE", Provider: claudecode.ProviderName}, nil
}

func newToolAgent(files map[string]string) *toolAgent {
	return &toolAgent{prompts: map[int]string{}, envs: map[int][]string{}, files: files}
}

func planOf(t *testing.T, dir string, parallel bool, ids ...int) {
	t.Helper()
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Parallel = parallel
	if parallel {
		s.MaxParallel = len(ids)
	}
	s.Plan = &pm.Plan{Goal: "goal"}
	for _, id := range ids {
		s.Plan.Tasks = append(s.Plan.Tasks, &pm.Task{ID: id, Title: fmt.Sprintf("task %d", id), Priority: id, Status: pm.TaskPending})
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
}

func storedAttachments(t *testing.T, dir string, taskID int) []statedb.AttachmentRow {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.TaskAttachments(taskID)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestARunAttachesWhatItsAgentLeavesInTheOutbox: the agent is told where its
// outbox is — in the prompt and in its environment — and what it copies there
// is attached to its task when the attempt ends, recorded in the journal, and
// counted on the task.
func TestARunAttachesWhatItsAgentLeavesInTheOutbox(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parallel=%v", parallel), func(t *testing.T) {
			dir := tempDir(t)
			planOf(t, dir, parallel, 1, 2)
			agent := newToolAgent(map[string]string{
				"report.md":     "# Report of task %d\n",
				"plots/out.csv": "task,%d\n",
			})
			o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, agent)
			if err := o.runPM(context.Background()); err != nil {
				t.Fatalf("runPM: %v", err)
			}

			dbPath := state.DBPath(dir)
			for _, id := range []int{1, 2} {
				box := attachments.OutboxDir(dbPath, id)
				abs, _ := filepath.Abs(box)
				if p := agent.prompts[id]; !strings.Contains(p, "## ATTACHMENTS\n") || !strings.Contains(p, abs) {
					t.Errorf("task %d's prompt does not name its outbox %s", id, abs)
				}
				if i, j := strings.Index(agent.prompts[id], "## ATTACHMENTS"), strings.LastIndex(agent.prompts[id], "## INSTRUCTIONS"); i < 0 || j < i {
					t.Errorf("task %d: the attachments section must come before the closing instructions", id)
				}
				rows := storedAttachments(t, dir, id)
				if len(rows) != 2 {
					t.Fatalf("task %d has %d attachments, want 2: %+v", id, len(rows), rows)
				}
				names := map[string]statedb.AttachmentRow{}
				for _, r := range rows {
					names[r.Name] = r
				}
				report, ok := names["report.md"]
				if !ok || names["plots/out.csv"].ID == "" {
					t.Fatalf("task %d's attachments = %+v", id, rows)
				}
				if report.RunID == "" || report.Source != statedb.AttachmentSourceRun {
					t.Errorf("task %d's report is not attributed to its run: %+v", id, report)
				}
				data, err := os.ReadFile(filepath.Join(attachments.StoreDir(dbPath), report.ID))
				if err != nil || string(data) != fmt.Sprintf("# Report of task %d\n", id) {
					t.Errorf("task %d's stored report = %q, %v — each task gets its own files", id, data, err)
				}
				if _, err := os.Lstat(box); !os.IsNotExist(err) {
					t.Errorf("task %d's outbox was not emptied: %v", id, err)
				}
			}

			st, err := state.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []int{1, 2} {
				if got := st.Plan.TaskByID(id); got.AttachmentCount != 2 || got.Status != pm.TaskDone {
					t.Errorf("task %d loads with %d attachments, status %s", id, got.AttachmentCount, got.Status)
				}
			}
			events, _, err := state.ListEvents(dir, 0, 200)
			if err != nil {
				t.Fatal(err)
			}
			journaled := map[int]bool{}
			for _, e := range events {
				if e.Type == state.EventTaskAttachments && strings.Contains(e.Message, "Attached 2 files") {
					journaled[e.TaskID] = true
				}
			}
			if !journaled[1] || !journaled[2] {
				t.Errorf("journal rows for the attachments: %v", journaled)
			}
		})
	}
}

// TestAnAgentWithoutToolsIsNotOfferedAnOutbox: an HTTP provider returns text;
// it gets no section and no environment, and no outbox is made for it.
func TestAnAgentWithoutToolsIsNotOfferedAnOutbox(t *testing.T) {
	dir := tempDir(t)
	planOf(t, dir, false, 1)
	var seen provider.Options
	var prompt string
	prov := &textOnlyProvider{name: "anthropic", output: "TASK_DONE", onCall: func(p string, o provider.Options) {
		prompt, seen = p, o
	}}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "## ATTACHMENTS") {
		t.Error("a provider with no tools was told about an outbox")
	}
	for _, kv := range seen.Env {
		if strings.HasPrefix(kv, attachments.EnvOutbox+"=") {
			t.Errorf("a provider with no tools was given %s", kv)
		}
	}
	if _, err := os.Lstat(attachments.OutboxDir(state.DBPath(dir), 1)); !os.IsNotExist(err) {
		t.Errorf("an outbox was made for an agent that cannot use it: %v", err)
	}
}

// textOnlyProvider returns one output and reports every call: an HTTP provider.
type textOnlyProvider struct {
	name   string
	output string
	onCall func(string, provider.Options)
}

func (p *textOnlyProvider) Name() string         { return p.name }
func (p *textOnlyProvider) DefaultModel() string { return "m" }
func (p *textOnlyProvider) Complete(_ context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	if p.onCall != nil {
		p.onCall(prompt, opts)
	}
	return &provider.Result{Output: p.output, Provider: p.name}, nil
}

// TestOutboxesLeftByAnEndedAttemptAreStillCollected: an attempt the run left
// early — stopped, paused, requeued — never reaches the collection at its
// end. What it left is attached when the task's next attempt starts, under the
// run that made it, or when the run loop exits; and the outbox of a task the
// plan no longer has is removed rather than inherited by the next task given
// its id.
func TestOutboxesLeftByAnEndedAttemptAreStillCollected(t *testing.T) {
	dir := tempDir(t)
	planOf(t, dir, false, 1, 2)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, &mockProvider{name: "mock"})
	dbPath := state.DBPath(dir)
	leave := func(taskID int, name string) {
		t.Helper()
		box, err := attachments.PrepareOutbox(dbPath, taskID)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(box, name), []byte("left by task "+fmt.Sprint(taskID)), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	task1 := o.state.Plan.TaskByID(1)
	task1.RunID = "run-that-was-stopped"
	leave(1, "partial.log")
	o.collectAttachments(task1, false)
	rows := storedAttachments(t, dir, 1)
	if len(rows) != 1 || rows[0].RunID != "run-that-was-stopped" {
		t.Fatalf("attempt-start collection: %+v", rows)
	}
	if _, err := os.Stat(attachments.OutboxDir(dbPath, 1)); err != nil {
		t.Fatalf("the outbox of an attempt about to start was removed: %v", err)
	}

	leave(2, "at-exit.txt")
	leave(9, "orphan.txt") // a task the plan does not have
	o.drainOutboxes()
	if rows := storedAttachments(t, dir, 2); len(rows) != 1 || rows[0].Name != "at-exit.txt" {
		t.Fatalf("the run-exit drain: %+v", rows)
	}
	if left := attachments.Outboxes(dbPath); len(left) != 0 {
		t.Fatalf("outboxes left after the drain: %v", left)
	}
}

func TestRunsToolsReadsAFallbackChain(t *testing.T) {
	for name, want := range map[string]bool{
		"claudecode":           true,
		"claudecode→anthropic": true,
		"copilot":              true,
		"copilot→claudecode":   true,
		"anthropic":            false,
		"anthropic→claudecode": false,
		"anthropic→copilot":    false,
		"openai":               false,
	} {
		if got := runsTools(&textOnlyProvider{name: name}); got != want {
			t.Errorf("runsTools(%q) = %v, want %v", name, got, want)
		}
	}
}
