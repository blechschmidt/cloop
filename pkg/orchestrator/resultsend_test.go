package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Task 20513: a run seeded into its sandbox sends the files its tasks attach
// to the hub as each attempt ends, and marks them sent.

// resultsHub stands in for the hub's results endpoint: it checks what arrives
// as the hub does, and answers as told for each file name.
type resultsHub struct {
	mu       sync.Mutex
	got      map[string][]byte // name → bytes
	uploads  []knowledgerun.ResultUpload
	failures map[string]int // name → how many sends to answer 503 before taking one
	refuse   map[string]bool
}

func newResultsHub() *resultsHub {
	return &resultsHub{got: map[string][]byte{}, failures: map[string]int{}, refuse: map[string]bool{}}
}

func (h *resultsHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != knowledgerun.MountPath+knowledgerun.PathResults || r.Header.Get("Authorization") != "Bearer "+testKnowledgeToken ||
		r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	u, err := knowledgerun.ParseResultUpload(r.URL.Query())
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	sum := sha256.Sum256(body)
	if int64(len(body)) != u.Size || hex.EncodeToString(sum[:]) != u.SHA256 {
		http.Error(w, `{"error":"the bytes do not match"}`, http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failures[u.Name] > 0 {
		h.failures[u.Name]--
		http.Error(w, `{"error":"restarting"}`, http.StatusServiceUnavailable)
		return
	}
	if h.refuse[u.Name] {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte(`{"error":{"code":"PAYLOAD_TOO_LARGE","message":"no room for it on the hub"}}`))
		return
	}
	h.got[u.Name] = body
	h.uploads = append(h.uploads, u)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(knowledgerun.ResultResponse{Outcome: knowledgerun.ResultAttached, ID: u.ID, Task: u.Task})
}

func fastResultRetries(t *testing.T) {
	t.Helper()
	waits, budget := resultRetryWaits, resultFlushBudget
	resultRetryWaits = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond}
	resultFlushBudget = 20 * time.Second
	t.Cleanup(func() { resultRetryWaits, resultFlushBudget = waits, budget })
}

func TestASeededRunSendsWhatItsTasksAttachToTheHub(t *testing.T) {
	fastResultRetries(t)
	hub := newResultsHub()
	hub.failures["report.md"] = 2 // the hub is restarting: tried again
	hub.refuse["huge.bin"] = true // refused for good: left for the result
	srv := httptest.NewServer(hub)
	defer srv.Close()
	t.Setenv(knowledgerun.EnvResultsURL, srv.URL+knowledgerun.MountPath)
	t.Setenv(knowledgerun.EnvResultsToken, testKnowledgeToken)
	// The same session's input-file variables, as a seeded run has them:
	// the orchestrator's too, and taken back from the agent like these.
	t.Setenv(knowledgerun.EnvInputsURL, srv.URL+knowledgerun.MountPath)
	t.Setenv(knowledgerun.EnvInputsToken, testKnowledgeToken)

	dir := tempDir(t)
	planOf(t, dir, false, 1)
	agent := newToolAgent(map[string]string{"report.md": "# report of task %d\n", "huge.bin": "pretend %d is big"})
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, agent)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatal(err)
	}

	hub.mu.Lock()
	report, uploads := hub.got["report.md"], append([]knowledgerun.ResultUpload(nil), hub.uploads...)
	_, hugeArrived := hub.got["huge.bin"]
	hub.mu.Unlock()
	if string(report) != "# report of task 1\n" || hugeArrived {
		t.Fatalf("the hub got report.md = %q, huge.bin %v", report, hugeArrived)
	}
	if len(uploads) != 1 || uploads[0].Task != 1 || uploads[0].TitleSHA256 != knowledgerun.TitleDigest("task 1") ||
		uploads[0].Created {
		t.Fatalf("uploads = %+v: task 1, by its title, as a task the run was sent", uploads)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.TaskAttachments(1)
	if err != nil || len(rows) != 2 {
		t.Fatalf("task 1's attachments in the run's own store = %+v, %v", rows, err)
	}
	for _, row := range rows {
		sent := attachments.WasSent(state.DBPath(dir), row.ID)
		if want := row.Name == "report.md"; sent != want || (want && row.ID != uploads[0].ID) {
			t.Errorf("%s: marked sent %v, want %v (sent as %s)", row.Name, sent, want, uploads[0].ID)
		}
	}
	// The variables the run sends with are the orchestrator's: the agent's
	// environment takes them back.
	for _, kv := range agent.envs[1] {
		if v, ok := strings.CutPrefix(kv, knowledgerun.EnvResultsToken+"="); ok && v != "" {
			t.Fatalf("the agent's environment carries the variable the run sends with: %s", kv)
		}
	}
	blanked := map[string]bool{}
	for _, kv := range agent.envs[1] {
		blanked[kv] = true
	}
	for _, name := range []string{knowledgerun.EnvResultsURL, knowledgerun.EnvResultsToken, knowledgerun.EnvInputsURL,
		knowledgerun.EnvInputsToken} {
		if !blanked[name+"="] {
			t.Errorf("the agent's environment does not take %s back: %v", name, agent.envs[1])
		}
	}
}

// A file of a task the run did not start with is sent as one only the run's
// result can place; so is one of a task it retitled.
func TestAFileOfATaskTheRunMadeIsSentAsSuch(t *testing.T) {
	fastResultRetries(t)
	hub := newResultsHub()
	srv := httptest.NewServer(hub)
	defer srv.Close()
	t.Setenv(knowledgerun.EnvResultsURL, srv.URL+knowledgerun.MountPath)
	t.Setenv(knowledgerun.EnvResultsToken, testKnowledgeToken)

	dir := tempDir(t)
	planOf(t, dir, false, 1, 2)
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := newResultSender(resultsEnv, state.DBPath(dir), st.Plan)
	if s == nil {
		t.Fatal("no sender for a run with a session")
	}
	s.logf = func(*color.Color, string, ...any) {}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	put := func(task int, name string) statedb.AttachmentRow {
		row, err := attachments.Put(db, state.DBPath(dir), task, attachments.Meta{Name: name, Source: statedb.AttachmentSourceRun},
			strings.NewReader(name), attachments.MaxFileBytes, nil)
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	s.send(context.Background(), resultItem{row: put(1, "kept.txt"), title: "task 1"})
	s.send(context.Background(), resultItem{row: put(2, "retitled.txt"), title: "task 2, as the agent renamed it"})
	// A task the run created: not in the plan it started with.
	st.Plan.Tasks = append(st.Plan.Tasks, &pm.Task{ID: 3, Title: "made by the run", Status: pm.TaskPending})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	s.send(context.Background(), resultItem{row: put(3, "made.txt"), title: "made by the run"})

	hub.mu.Lock()
	defer hub.mu.Unlock()
	created := map[string]bool{}
	for _, u := range hub.uploads {
		created[u.Name] = u.Created
	}
	if len(created) != 3 || created["kept.txt"] || !created["retitled.txt"] || !created["made.txt"] {
		t.Fatalf("created flags = %v", created)
	}
}

// The end of the run waits for what is still being sent, for a while, and no
// longer: a hub that cannot be reached does not hold the run up for good.
func TestTheEndOfARunWaitsForItsFilesOnlySoLong(t *testing.T) {
	waits, budget, stopped := resultRetryWaits, resultFlushBudget, resultFlushBudgetStopped
	resultRetryWaits = []time.Duration{time.Hour}
	resultFlushBudget, resultFlushBudgetStopped = 300*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { resultRetryWaits, resultFlushBudget, resultFlushBudgetStopped = waits, budget, stopped })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"restarting"}`, http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	t.Setenv(knowledgerun.EnvResultsURL, srv.URL+knowledgerun.MountPath)
	t.Setenv(knowledgerun.EnvResultsToken, testKnowledgeToken)

	dir := tempDir(t)
	planOf(t, dir, false, 1)
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := newResultSender(resultsEnv, state.DBPath(dir), st.Plan)
	var lines []string
	var mu sync.Mutex
	s.logf = func(_ *color.Color, format string, args ...any) {
		mu.Lock()
		lines = append(lines, format)
		mu.Unlock()
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	row, err := attachments.Put(db, state.DBPath(dir), 1, attachments.Meta{Name: "a.txt", Source: statedb.AttachmentSourceRun},
		strings.NewReader("a"), attachments.MaxFileBytes, nil)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	s.start()
	s.enqueue(st.Plan.Tasks[0], []statedb.AttachmentRow{row})
	start := time.Now()
	s.finish(false)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("finish took %s against an unreachable hub", took)
	}
	if attachments.WasSent(state.DBPath(dir), row.ID) {
		t.Fatal("a file the hub never took is marked sent")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(strings.Join(lines, "\n"), "could not be sent to the hub in time") {
		t.Fatalf("the run's output does not say what was not sent: %q", lines)
	}
	// A run with no session has no sender, and nothing to wait for.
	var none *resultSender
	none.start()
	none.enqueue(st.Plan.Tasks[0], []statedb.AttachmentRow{row})
	none.finish(true)
}
