package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Task 20511: the files a person attaches to a task for its agent reach the
// agent at the start of every attempt.

// inputReader stands in for a harness with tools: it reads whatever its
// environment says its task's input files are, as an agent would.
type inputReader struct {
	mu      sync.Mutex
	prompts map[int]string
	seen    map[int]map[string]string // task → file in the inbox → content
	dirs    map[int]string
}

func newInputReader() *inputReader {
	return &inputReader{prompts: map[int]string{}, seen: map[int]map[string]string{}, dirs: map[int]string{}}
}

func (a *inputReader) Name() string         { return claudecode.ProviderName }
func (a *inputReader) DefaultModel() string { return "test-model" }

func (a *inputReader) Complete(_ context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	var inbox string
	id := 0
	for _, kv := range opts.Env {
		if v, ok := strings.CutPrefix(kv, attachments.EnvInbox+"="); ok {
			inbox = v
		}
		if v, ok := strings.CutPrefix(kv, attachments.EnvTaskID+"="); ok {
			fmt.Sscanf(v, "%d", &id)
		}
	}
	files := map[string]string{}
	if inbox != "" {
		entries, err := os.ReadDir(inbox)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			data, err := os.ReadFile(filepath.Join(inbox, e.Name()))
			if err != nil {
				return nil, err
			}
			files[e.Name()] = string(data)
		}
	}
	a.mu.Lock()
	a.prompts[id], a.seen[id], a.dirs[id] = prompt, files, inbox
	a.mu.Unlock()
	return &provider.Result{Output: "read the inputs\nTASK_DONE", Provider: claudecode.ProviderName}, nil
}

// attachInputFile attaches content to a task of the project at dir as an
// input file, as an upload in the dashboard does.
func attachInputFile(t *testing.T, dir string, task int, name, content string) statedb.AttachmentRow {
	t.Helper()
	dbPath := state.DBPath(dir)
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	row, err := attachments.Put(db, dbPath, task, attachments.Meta{Name: name, Source: statedb.AttachmentSourceUpload,
		Role: statedb.AttachmentRoleInput, AddedBy: "ada", CreatedAt: time.Now()}, strings.NewReader(content),
		attachments.MaxFileBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestTheAgentIsGivenItsTasksInputFiles(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parallel=%v", parallel), func(t *testing.T) {
			dir := tempDir(t)
			planOf(t, dir, parallel, 1, 2, 3)
			attachInputFile(t, dir, 1, "spec.md", "# The spec of task 1\n")
			attachInputFile(t, dir, 2, "rows.csv", "a,b\n1,2\n")
			attachInputFile(t, dir, 2, "more/rows.csv", "c,d\n")
			agent := newInputReader()
			o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, agent)
			if err := o.runPM(context.Background()); err != nil {
				t.Fatalf("runPM: %v", err)
			}

			want := map[int]map[string]string{
				1: {"spec.md": "# The spec of task 1\n"},
				2: {"rows.csv": "a,b\n1,2\n", "rows (2).csv": "c,d\n"},
				3: {},
			}
			dbPath := state.DBPath(dir)
			for id, files := range want {
				got := agent.seen[id]
				if fmt.Sprint(got) != fmt.Sprint(files) {
					t.Errorf("task %d's agent read %v from its inbox, want %v", id, got, files)
				}
				p := agent.prompts[id]
				if len(files) == 0 {
					if strings.Contains(p, "## INPUT FILES") || agent.dirs[id] != "" {
						t.Errorf("task %d has no input files but its agent was told of some", id)
					}
					continue
				}
				abs, _ := filepath.Abs(attachments.InboxDir(dbPath, id))
				if agent.dirs[id] != abs || !strings.Contains(p, "## INPUT FILES\n") || !strings.Contains(p, abs) {
					t.Errorf("task %d's prompt and environment do not name its inbox %s (env %q)", id, abs, agent.dirs[id])
				}
				var names []string
				for n := range files {
					names = append(names, n)
				}
				sort.Strings(names)
				for _, n := range names {
					if !strings.Contains(p, "- "+n+" (") {
						t.Errorf("task %d's prompt does not list %s", id, n)
					}
				}
				if i, j := strings.Index(p, "## INPUT FILES"), strings.LastIndex(p, "## INSTRUCTIONS"); j < i {
					t.Errorf("task %d: the input files must be named before the closing instructions", id)
				}
				// The attempt is over: its copies are gone, the files are not.
				if _, err := os.Lstat(attachments.InboxDir(dbPath, id)); !os.IsNotExist(err) {
					t.Errorf("task %d's inbox outlived the run: %v", id, err)
				}
				inputs := 0
				for _, r := range storedAttachments(t, dir, id) {
					if r.Role == statedb.AttachmentRoleInput {
						inputs++
					}
				}
				if inputs != len(files) {
					t.Errorf("task %d keeps %d input files after the run, want %d", id, inputs, len(files))
				}
			}
		})
	}
}

func TestATextAgentIsGivenTheTextOfItsInputFiles(t *testing.T) {
	dir := tempDir(t)
	planOf(t, dir, false, 1)
	attachInputFile(t, dir, 1, "notes.txt", "Use port 8443, not 8080.\n")
	attachInputFile(t, dir, 1, "logo.png", "\x89PNG\r\n\x1a\n binary")
	var prompt string
	var seen provider.Options
	prov := &textOnlyProvider{name: "anthropic", output: "TASK_DONE", onCall: func(p string, o provider.Options) {
		prompt, seen = p, o
	}}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## INPUT FILES", "### notes.txt", "Use port 8443, not 8080.", "logo.png",
		"cannot open files"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("the prompt does not hold %q", want)
		}
	}
	if strings.Contains(prompt, "## ATTACHMENTS") {
		t.Error("a provider with no tools was told about an outbox")
	}
	for _, kv := range seen.Env {
		if strings.HasPrefix(kv, attachments.EnvInbox+"=") {
			t.Errorf("a provider with no tools was given %s", kv)
		}
	}
	if _, err := os.Lstat(attachments.InboxDir(state.DBPath(dir), 1)); !os.IsNotExist(err) {
		t.Errorf("an inbox was made for an agent that cannot open one: %v", err)
	}
}

// fakeHub serves the run-scoped input file endpoints for one task.
type fakeHub struct {
	title    string
	files    map[string]string // id → content
	names    map[string]string // id → name
	mismatch string            // answered for a task under another title
	mu       sync.Mutex
	asked    []string
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testKnowledgeToken {
		http.Error(w, `{"error":"no"}`, http.StatusUnauthorized)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.asked = append(h.asked, r.URL.Path+" "+string(raw))
	h.mu.Unlock()
	switch r.URL.Path {
	case knowledgerun.MountPath + knowledgerun.PathInputs:
		var req knowledgerun.InputsRequest
		_ = json.Unmarshal(raw, &req)
		out := knowledgerun.InputsResponse{Task: req.Task, Files: []knowledgerun.InputFile{}}
		if req.TitleSHA256 != knowledgerun.TitleDigest(h.title) {
			out.Mismatch = h.mismatch
		} else {
			ids := make([]string, 0, len(h.files))
			for id := range h.files {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				sum := sha256.Sum256([]byte(h.files[id]))
				out.Files = append(out.Files, knowledgerun.InputFile{ID: id, Name: h.names[id],
					Size: int64(len(h.files[id])), SHA256: hex.EncodeToString(sum[:]), MediaType: "text/plain"})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case knowledgerun.MountPath + knowledgerun.PathInputFile:
		var req knowledgerun.InputFileRequest
		_ = json.Unmarshal(raw, &req)
		content := h.files[req.ID]
		if strings.HasPrefix(h.names[req.ID], "corrupt") {
			content = strings.ToUpper(content) // what the listing's digest does not match
		}
		_, _ = w.Write([]byte(content))
	default:
		http.NotFound(w, r)
	}
}

// testKnowledgeToken has the shape of a run session's token.
const testKnowledgeToken = "cloop_know1_0123456789abcdef01234567.c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA"

func TestASeededRunFetchesItsInputFilesFromTheHub(t *testing.T) {
	hub := &fakeHub{
		title: "task 1",
		files: map[string]string{strings.Repeat("a", 32): "the spec, from the hub", strings.Repeat("b", 32): "bytes"},
		names: map[string]string{strings.Repeat("a", 32): "spec.md", strings.Repeat("b", 32): "corrupt.txt"},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()
	t.Setenv(knowledgerun.EnvInputsURL, srv.URL+knowledgerun.MountPath)
	t.Setenv(knowledgerun.EnvInputsToken, testKnowledgeToken)

	dir := tempDir(t)
	planOf(t, dir, false, 1, 2)
	// The sandbox's own database: an input file in it is not the hub's, and
	// a seeded run never reads it.
	attachInputFile(t, dir, 1, "local-only.md", "never given")
	agent := newInputReader()
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, agent)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(agent.seen[1]); got != fmt.Sprint(map[string]string{"spec.md": "the spec, from the hub"}) {
		t.Fatalf("task 1's agent read %s from its inbox", got)
	}
	if p := agent.prompts[1]; !strings.Contains(p, "corrupt.txt is not available to you") || !strings.Contains(p, "SHA-256") {
		t.Errorf("the file whose bytes did not match is not named as missing:\n%s", p)
	}
	// Task 2's title is not the hub's: the hub answers with nothing, and the
	// agent is told nothing.
	if len(agent.seen[2]) != 0 || strings.Contains(agent.prompts[2], "## INPUT FILES") {
		t.Errorf("task 2 was given input files: %v", agent.seen[2])
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.asked) == 0 || !strings.Contains(hub.asked[0], `"title_sha256":"`+knowledgerun.TitleDigest("task 1")+`"`) {
		t.Fatalf("the hub was asked %q; every request names its task's title", hub.asked)
	}
}

func TestARenamedTasksAgentIsToldItHasNoneOfItsInputFiles(t *testing.T) {
	hub := &fakeHub{title: "the hub's new title", mismatch: "the hub's task 1 is not this run's copy of it any more"}
	srv := httptest.NewServer(hub)
	defer srv.Close()
	t.Setenv(knowledgerun.EnvInputsURL, srv.URL+knowledgerun.MountPath)
	t.Setenv(knowledgerun.EnvInputsToken, testKnowledgeToken)
	dir := tempDir(t)
	planOf(t, dir, false, 1)
	agent := newInputReader()
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, agent)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p := agent.prompts[1]; !strings.Contains(p, "could not be fetched (the hub's task 1 is not this run's copy of it any more)") {
		t.Fatalf("the agent of a task renamed on the hub is not told it has none of its input files:\n%s", p)
	}
}

func TestAnAbortStopsTheInputFetch(t *testing.T) {
	// A hub that never finishes sending a file.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.HasSuffix(r.URL.Path, knowledgerun.PathInputs) {
			var req knowledgerun.InputsRequest
			_ = json.Unmarshal(raw, &req)
			_ = json.NewEncoder(w).Encode(knowledgerun.InputsResponse{Task: req.Task, Files: []knowledgerun.InputFile{
				{ID: strings.Repeat("c", 32), Name: "slow.bin", Size: 1 << 20}}})
			return
		}
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("a start"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	t.Setenv(knowledgerun.EnvInputsURL, srv.URL+knowledgerun.MountPath)
	t.Setenv(knowledgerun.EnvInputsToken, testKnowledgeToken)
	dir := tempDir(t)
	planOf(t, dir, false, 1)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, newInputReader())
	task := o.state.Plan.TaskByID(1)
	done := make(chan *taskOutbox, 1)
	go func() { done <- o.openOutbox(context.Background(), task, newInputReader()) }()
	// The fetch registers its cancel with the watchdog, which an abort from
	// the dashboard fires.
	deadline := time.Now().Add(10 * time.Second)
	for !o.watchdog.Cancel(1) {
		if time.Now().After(deadline) {
			t.Fatal("the input fetch never registered a cancel an abort could fire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case b := <-done:
		if b == nil || b.inbox == nil || b.inbox.Placed() != 0 || !strings.Contains(b.inbox.Files[0].Unavailable, "could not") {
			t.Fatalf("after the abort: %+v", b)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an abort did not stop the input fetch")
	}
}

func TestAnUnreachableHubIsNamedInThePrompt(t *testing.T) {
	saved := hubInputAttempts
	hubInputAttempts = []time.Duration{0, time.Millisecond}
	defer func() { hubInputAttempts = saved }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"restarting"}`, http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	t.Setenv(knowledgerun.EnvInputsURL, srv.URL+knowledgerun.MountPath)
	t.Setenv(knowledgerun.EnvInputsToken, testKnowledgeToken)

	dir := tempDir(t)
	planOf(t, dir, false, 1)
	agent := newInputReader()
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, agent)
	if err := o.runPM(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := agent.prompts[1]
	if !strings.Contains(p, "## INPUT FILES") || !strings.Contains(p, "could not be fetched") || !strings.Contains(p, "restarting") {
		t.Fatalf("the agent is not told its input files could not be fetched:\n%s", p)
	}
}
