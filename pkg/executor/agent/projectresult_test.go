package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// handshakeAt is handshake with the session version chosen by the test.
func (c *controlPlane) handshakeAt(t *testing.T, executorID string, version int) {
	t.Helper()
	f := c.readUntil(remote.TypeHello, 5*time.Second)
	welcome, err := remote.NewFrameAt(version, remote.TypeWelcome, f.ID, "", remote.WelcomePayload{
		ProtocolVersion:  version,
		ExecutorID:       executorID,
		Credential:       "clac1.issued.secret.mac",
		HeartbeatSeconds: int(remote.HeartbeatInterval / time.Second),
	})
	if err != nil {
		t.Fatalf("build welcome: %v", err)
	}
	c.write(welcome)
}

// seededProject returns a seed for a one-task project, and a directory holding
// the database a finished `cloop run` of it leaves behind: the task done.
func seededProject(t *testing.T) (seed []byte, finished string) {
	t.Helper()
	seed, err := projectseed.Build(&state.ProjectState{
		Goal: "Test the cloop remote executor",
		Plan: &pm.Plan{Goal: "Test the cloop remote executor", Tasks: []*pm.Task{
			{ID: 1, Title: "Create a file named hello which contains the string world", Status: pm.TaskPending},
		}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	dir := t.TempDir()
	if err := projectseed.Write(dir, seed); err != nil {
		t.Fatalf("Write: %v", err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	now := time.Now().UTC()
	st.Plan.Tasks[0].Status = pm.TaskDone
	st.Plan.Tasks[0].Result = "Created hello containing world"
	st.Plan.Tasks[0].CompletedAt = &now
	st.Status = "complete"
	if err := st.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return seed, filepath.Join(dir, ".cloop")
}

// finishRun is a workload that plays a finished `cloop run`: it installs the
// database the run would have left in the seeded workspace.
func finishRun(src string) []string {
	return []string{"/bin/sh", "-c",
		"cp '" + src + "/state.db' .cloop/state.db && " +
			"if [ -f '" + src + "/state.db-wal' ]; then cp '" + src + "/state.db-wal' .cloop/; fi"}
}

// startSeeded dispatches a seeded workload over cp and returns the frames the
// agent sent up to and including the terminal status.
func startSeeded(t *testing.T, cp *controlPlane, version int, seed []byte, argv []string) []remote.Frame {
	t.Helper()
	const handleID = "handle-seeded"
	start, err := remote.NewFrameAt(version, remote.TypeStart, "start-1", handleID, remote.StartPayload{
		HandleID: handleID,
		Spec: executor.Spec{
			WorkDir: "test-remote-executor-4009d014",
			Argv:    argv,
			Labels:  map[string]string{executor.LabelRunID: "run_from_hub"},
		},
		ProjectSeed: seed,
	})
	if err != nil {
		t.Fatalf("build start: %v", err)
	}
	cp.write(start)

	var frames []remote.Frame
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		f, err := cp.read(time.Until(deadline))
		if err != nil {
			t.Fatalf("reading agent frames: %v", err)
		}
		frames = append(frames, f)
		if f.Type == remote.TypeStarted {
			if sp, _ := remote.DecodeStarted(f); sp.Error != "" {
				t.Fatalf("agent refused the workload: %s", sp.Error)
			}
		}
		if f.Type == remote.TypeStatus {
			if st, err := remote.DecodeStatus(f); err == nil && st.Status.State.Terminal() {
				return frames
			}
		}
	}
	t.Fatal("the workload never reported a terminal status")
	return nil
}

// TestAgentReturnsTheRunsProjectBeforeItsFinalStatus is the device half of
// Task 20339. A seeded run finished its task in the workspace; the agent has to
// read that back and send it — and send it *before* the terminal status, which
// is what closes the hub's log stream and makes the hub settle the run.
func TestAgentReturnsTheRunsProjectBeforeItsFinalStatus(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "work")
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshakeAt(t, "FL6HRGvUlqxf96aO", remote.ProtocolVersion)

	seed, finished := seededProject(t)
	frames := startSeeded(t, cp, remote.ProtocolVersion, seed, finishRun(finished))

	var result *remote.ProjectResultPayload
	for i, f := range frames {
		if f.Type != remote.TypeProjectResult {
			continue
		}
		if i == len(frames)-1 {
			t.Fatal("the project result was the last frame; it must precede the terminal status")
		}
		p, err := remote.DecodeProjectResult(f)
		if err != nil {
			t.Fatalf("DecodeProjectResult: %v", err)
		}
		result = &p
	}
	if result == nil {
		t.Fatalf("the agent sent no project result; frames: %v", frames)
	}
	if result.Err != "" {
		t.Fatalf("the agent could not read the run back: %s", result.Err)
	}
	res, err := projectseed.DecodeResult(result.Data)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if len(res.Tasks) != 1 || res.Tasks[0].After.Status != pm.TaskDone || res.Tasks[0].Before.Status != pm.TaskPending {
		t.Fatalf("result tasks = %+v, want task 1 pending → done", res.Tasks)
	}
	if res.Status != "complete" {
		t.Errorf("result status = %q", res.Status)
	}

	// The run was told where it is. Without this record the orchestrator on
	// the device stamps every task "local, isolation none".
	rec, ok := artifact.LoadSandboxRun(filepath.Join(root, "test-remote-executor-4009d014"))
	if !ok {
		t.Fatal("no placement record beside the seed")
	}
	if rec.ExecutorID != "FL6HRGvUlqxf96aO" || rec.ExecutorKind != executor.KindRemoteAgent ||
		rec.Isolation != string(executor.IsolationRemote) || rec.RunID != "run_from_hub" {
		t.Errorf("placement record = %+v", rec)
	}
}

// TestAgentSendsNoProjectResultToAnOlderHub: a v12 hub has no case for the
// frame and answers it with a protocol error. The agent must stay silent on
// such a session — and the run must still end normally.
func TestAgentSendsNoProjectResultToAnOlderHub(t *testing.T) {
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	old := remote.MinProjectResultVersion - 1
	cp.handshakeAt(t, "agent-1", old)

	seed, finished := seededProject(t)
	frames := startSeeded(t, cp, old, seed, finishRun(finished))
	for _, f := range frames {
		if f.Type == remote.TypeProjectResult {
			t.Fatalf("sent a project_result frame to a v%d hub", old)
		}
		if f.V > old {
			t.Errorf("%s frame stamped v%d on a v%d session", f.Type, f.V, old)
		}
	}
}

// TestAgentReportsWhyItCouldNotReadTheRunBack: a workload that destroyed its
// project leaves nothing to read, and the hub's journal needs the reason rather
// than silence.
func TestAgentReportsWhyItCouldNotReadTheRunBack(t *testing.T) {
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshakeAt(t, "agent-1", remote.ProtocolVersion)

	seed, _ := seededProject(t)
	frames := startSeeded(t, cp, remote.ProtocolVersion, seed, []string{"/bin/sh", "-c", "rm -rf .cloop"})
	for _, f := range frames {
		if f.Type != remote.TypeProjectResult {
			continue
		}
		p, err := remote.DecodeProjectResult(f)
		if err != nil {
			t.Fatalf("DecodeProjectResult: %v", err)
		}
		if len(p.Data) != 0 || !strings.Contains(p.Err, "gone") {
			raw, _ := json.Marshal(p)
			t.Fatalf("payload = %s, want a reason naming the missing project", raw)
		}
		return
	}
	t.Fatal("no project result was sent for a run whose project vanished")
}

// TestUnseededWorkloadSendsNoProjectResult: only a dispatch that carried a
// project out has one to bring back.
func TestUnseededWorkloadSendsNoProjectResult(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "work")
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshakeAt(t, "agent-1", remote.ProtocolVersion)
	frames := startSeeded(t, cp, remote.ProtocolVersion, nil, []string{"/bin/sh", "-c", "true"})
	for _, f := range frames {
		if f.Type == remote.TypeProjectResult {
			t.Fatal("an unseeded workload sent a project result")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "test-remote-executor-4009d014", ".cloop")); !os.IsNotExist(err) {
		t.Errorf("an unseeded workload got a .cloop directory: %v", err)
	}
}
