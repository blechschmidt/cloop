package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// resultsHub plays the hub's endpoint for a run's attached files
// (POST /api/run/knowledge/results), taking each file sent with token.
type resultsHub struct {
	token string
	mu    sync.Mutex
	got   map[string][]byte
}

func (h *resultsHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != knowledgerun.MountPath+knowledgerun.PathResults ||
		r.Header.Get("Authorization") != "Bearer "+h.token {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	u, err := knowledgerun.ParseResultUpload(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil || int64(len(data)) != u.Size {
		http.Error(w, "short", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	h.got[u.Name] = data
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(knowledgerun.ResultResponse{Outcome: knowledgerun.ResultAttached, ID: u.ID, Task: u.Task})
}

func (h *resultsHub) files() map[string][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string][]byte, len(h.got))
	for k, v := range h.got {
		out[k] = v
	}
	return out
}

// TestAgentSendsTheFilesARunDidNotSend is the device half of Task 20515. A
// seeded run attached two files and sent one of them to the hub itself — the
// other it could not: its `cloop` predates the live send, or the hub was
// restarting. The agent, holding the run's session, sends the other once the
// workload has exited and before it reads the run back, so the result
// describes both as on the hub and carries neither, and the run's transcript
// says what was sent.
func TestAgentSendsTheFilesARunDidNotSend(t *testing.T) {
	token := knowledgerun.TokenPrefix + "0123456789abcdef01234567.secret"
	hub := &resultsHub{token: token, got: map[string][]byte{}}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	cp := <-conns
	cp.handshakeAt(t, "FL6HRGvUlqxf96aO", remote.ProtocolVersion)

	seed, finished := seededProject(t)
	dbPath := filepath.Join(finished, "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	report := []byte("# Threat model\n" + strings.Repeat("A trust boundary, and what crosses it.\n", 900))
	sent, err := attachments.Put(db, dbPath, 1, attachments.Meta{Name: "already-sent.log", Source: statedb.AttachmentSourceRun},
		bytes.NewReader([]byte("the run sent this one")), attachments.MaxFileBytes, nil)
	if err == nil {
		_, err = attachments.Put(db, dbPath, 1, attachments.Meta{Name: "THREAT_MODEL.md", Source: statedb.AttachmentSourceRun},
			bytes.NewReader(report), attachments.MaxFileBytes, nil)
	}
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := attachments.MarkSent(dbPath, sent.ID); err != nil {
		t.Fatal(err)
	}

	env := []string{
		knowledgerun.EnvResultsURL + "=" + srv.URL + knowledgerun.MountPath,
		knowledgerun.EnvResultsToken + "=" + token,
		redact.EnvKey + "=" + knowledgerun.EnvResultsToken,
	}
	// The workload leaves the database and the store the run would have.
	argv := []string{"/bin/sh", "-c", "cp '" + finished + "/state.db' .cloop/state.db && " +
		"cp -R '" + finished + "/attachments' .cloop/"}
	frames := startSeededWith(t, cp, remote.ProtocolVersion, seed, argv, env)

	got := hub.files()
	if len(got) != 1 || !bytes.Equal(got["THREAT_MODEL.md"], report) {
		t.Fatalf("the hub got %d files (%v); want THREAT_MODEL.md, whole, and nothing the run sent itself",
			len(got), keysOf(got))
	}
	var transcript strings.Builder
	var result *projectseed.Result
	for _, f := range frames {
		switch f.Type {
		case remote.TypeLogChunk:
			if c, err := remote.DecodeLogChunk(f); err == nil {
				transcript.WriteString(c.Text)
			}
		case remote.TypeProjectResult:
			p, err := remote.DecodeProjectResult(f)
			if err != nil || p.Err != "" {
				t.Fatalf("project result: %v %s", err, p.Err)
			}
			if result, err = projectseed.DecodeResult(p.Data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if result == nil || len(result.Attachments) != 2 {
		t.Fatalf("the result describes %v", result)
	}
	for _, at := range result.Attachments {
		if !at.Sent || len(at.Data) != 0 {
			t.Errorf("%s in the result: sent %v, carrying %d bytes; want it described as on the hub",
				at.Name, at.Sent, len(at.Data))
		}
	}
	if !strings.Contains(transcript.String(), "📤 THREAT_MODEL.md") || strings.Contains(transcript.String(), token) {
		t.Errorf("transcript = %q; want the sent file named, and no token", transcript.String())
	}
}

// TestAgentSendsNothingWithoutARunSession: a run the hub gave no session for
// its files — no network, or a hub with no public address — brings them back
// in its result, as before.
func TestAgentSendsNothingWithoutARunSession(t *testing.T) {
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	cp := <-conns
	cp.handshakeAt(t, "agent-1", remote.ProtocolVersion)

	seed, finished := seededProject(t)
	dbPath := filepath.Join(finished, "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = attachments.Put(db, dbPath, 1, attachments.Meta{Name: "notes.txt", Source: statedb.AttachmentSourceRun},
		bytes.NewReader([]byte("carried home")), attachments.MaxFileBytes, nil)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"/bin/sh", "-c", "cp '" + finished + "/state.db' .cloop/state.db && " +
		"cp -R '" + finished + "/attachments' .cloop/"}
	frames := startSeeded(t, cp, remote.ProtocolVersion, seed, argv)
	for _, f := range frames {
		if f.Type != remote.TypeProjectResult {
			continue
		}
		p, err := remote.DecodeProjectResult(f)
		if err != nil {
			t.Fatal(err)
		}
		r, err := projectseed.DecodeResult(p.Data)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Attachments) != 1 || string(r.Attachments[0].Data) != "carried home" || r.Attachments[0].Sent {
			t.Fatalf("attachments = %+v; want notes.txt carried in the result", r.Attachments)
		}
		return
	}
	t.Fatal("no project result")
}

// stalledHub is a results endpoint that takes a file and never answers,
// until the request is given up or the test ends; entered is told of each
// request.
func stalledHub(t *testing.T) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read whole, so the server watches the connection — and sees the
		// agent give up — while the handler waits.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	// Cleanups run last first: the handlers are let go before Close waits
	// for them.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv, entered
}

// seededWithAFile is seededProject whose run attached report.md, and the
// argv of a workload that leaves that run's database and store.
func seededWithAFile(t *testing.T) (seed []byte, argv []string) {
	t.Helper()
	seed, finished := seededProject(t)
	dbPath := filepath.Join(finished, "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = attachments.Put(db, dbPath, 1, attachments.Meta{Name: "report.md", Source: statedb.AttachmentSourceRun},
		bytes.NewReader([]byte("# Report\n")), attachments.MaxFileBytes, nil)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	return seed, []string{"/bin/sh", "-c", "cp '" + finished + "/state.db' .cloop/state.db && " +
		"cp -R '" + finished + "/attachments' .cloop/"}
}

// startWithSession sends cp a seeded start whose run has a results session at
// base, without waiting for anything.
func startWithSession(t *testing.T, cp *controlPlane, seed []byte, argv []string, base string) {
	t.Helper()
	token := knowledgerun.TokenPrefix + "0123456789abcdef01234567.secret"
	start, err := remote.NewFrameAt(remote.ProtocolVersion, remote.TypeStart, "start-1", "handle-seeded",
		remote.StartPayload{
			HandleID: "handle-seeded",
			Spec: executor.Spec{
				WorkDir: "test-remote-executor-4009d014",
				Argv:    argv,
				Env: []string{knowledgerun.EnvResultsURL + "=" + base + knowledgerun.MountPath,
					knowledgerun.EnvResultsToken + "=" + token, redact.EnvKey + "=" + knowledgerun.EnvResultsToken},
				Labels: map[string]string{executor.LabelRunID: "run_from_hub"},
			},
			ProjectSeed: seed,
		})
	if err != nil {
		t.Fatal(err)
	}
	cp.write(start)
}

// untilTerminal reads frames until the terminal status, and returns the
// project result that came before it.
func untilTerminal(t *testing.T, cp *controlPlane, within time.Duration) *projectseed.Result {
	t.Helper()
	var result *projectseed.Result
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		f, err := cp.read(time.Until(deadline))
		if err != nil {
			break
		}
		switch f.Type {
		case remote.TypeProjectResult:
			p, err := remote.DecodeProjectResult(f)
			if err != nil || p.Err != "" {
				t.Fatalf("project result: %v %s", err, p.Err)
			}
			if result, err = projectseed.DecodeResult(p.Data); err != nil {
				t.Fatal(err)
			}
		case remote.TypeStatus:
			if st, err := remote.DecodeStatus(f); err == nil && st.Status.State.Terminal() {
				if result == nil {
					t.Fatal("the terminal status came before the project result")
				}
				return result
			}
		}
	}
	t.Fatalf("no terminal status within %s", within)
	return nil
}

// TestWhileTheAgentSendsTheRunsFilesItIsOverButNotReported (Task 20515):
// while the agent sends what the run left, the workload's own record says it
// exited — a revoke does not claim to stop it, a terminal is not opened beside
// it — and the hub is still told it is running, because its outcome has not
// gone out. A stop then cuts the sending short: the outcome goes out at once,
// and the file comes back in the result instead.
func TestWhileTheAgentSendsTheRunsFilesItIsOverButNotReported(t *testing.T) {
	srv, entered := stalledHub(t)
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	cp := <-conns
	cp.handshakeAt(t, "agent-1", remote.ProtocolVersion)

	seed, argv := seededWithAFile(t)
	startWithSession(t, cp, seed, argv, srv.URL)
	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		t.Fatal("the agent never sent the run's file")
	}
	wl, ok := a.workload("handle-seeded")
	if !ok {
		t.Fatal("the workload is gone while its files are being sent")
	}
	if st := wl.snapshot(); !st.State.Terminal() {
		t.Errorf("the workload's record says %s while its files are sent; the process has exited", st.State)
	}
	if a.terminateWorkload(context.Background(), "handle-seeded", "a revoke") {
		t.Error("a revoke claimed to stop a workload that had already exited")
	}

	req, err := remote.NewFrameAt(remote.ProtocolVersion, remote.TypeStatusReq, "sr-1", "handle-seeded", remote.StatusReqPayload{})
	if err != nil {
		t.Fatal(err)
	}
	cp.write(req)
	reply := cp.readUntil(remote.TypeStatus, 10*time.Second)
	if st, err := remote.DecodeStatus(reply); err != nil || st.Status.State.Terminal() {
		t.Fatalf("a status request during the send was answered %+v (%v); the outcome has not gone out", st, err)
	}

	sig, err := remote.NewFrameAt(remote.ProtocolVersion, remote.TypeSignal, "sig-1", "handle-seeded",
		remote.SignalPayload{Signal: executor.SignalInterrupt})
	if err != nil {
		t.Fatal(err)
	}
	stopped := time.Now()
	cp.write(sig)
	result := untilTerminal(t, cp, 20*time.Second)
	if took := time.Since(stopped); took > 15*time.Second {
		t.Errorf("the outcome went out %s after the stop", took)
	}
	if len(result.Attachments) != 1 || string(result.Attachments[0].Data) != "# Report\n" || result.Attachments[0].Sent {
		t.Fatalf("attachments = %+v; want report.md carried in the result", result.Attachments)
	}
}

// TestTheRunsOutcomeDoesNotWaitLongerThanTheSendBudget: a hub that never
// answers holds the run's outcome back for runFilesBudget and no longer, and
// what was not sent comes back in the result.
func TestTheRunsOutcomeDoesNotWaitLongerThanTheSendBudget(t *testing.T) {
	defer func(old time.Duration) { runFilesBudget = old }(runFilesBudget)
	runFilesBudget = 500 * time.Millisecond
	srv, _ := stalledHub(t)
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	cp := <-conns
	cp.handshakeAt(t, "agent-1", remote.ProtocolVersion)

	seed, argv := seededWithAFile(t)
	startWithSession(t, cp, seed, argv, srv.URL)
	result := untilTerminal(t, cp, 20*time.Second)
	if len(result.Attachments) != 1 || string(result.Attachments[0].Data) != "# Report\n" || result.Attachments[0].Sent {
		t.Fatalf("attachments = %+v; want report.md carried in the result", result.Attachments)
	}
}

// TestAStopBeforeTheSendingStartsStillHolds: a stop that lands between the
// workload's exit and the start of the sending — when there is nothing yet to
// cancel — is not lost: the sending, when it starts, is called off at once.
func TestAStopBeforeTheSendingStartsStillHolds(t *testing.T) {
	wl := &workload{}
	wl.stopRunFiles()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !wl.setStopFiles(cancel) {
		t.Fatal("a stop before the sending started was forgotten")
	}
	wl.setStopFiles(nil)
	other := &workload{}
	if other.setStopFiles(cancel) {
		t.Fatal("a workload nobody stopped says it was")
	}
	other.stopRunFiles()
	if ctx.Err() == nil {
		t.Fatal("a stop during the sending did not cancel it")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
