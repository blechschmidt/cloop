package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// slotProbe is a session's connection that notes, as each capture frame is
// written, which capture holds the agent's slot and whether that frame's
// capture still has its scratch.
type slotProbe struct {
	a *Agent
	// cancelOnChunk delivers the hub's capture_cancel while each chunk is
	// being written, and endedMidWrite notes a chunk whose write context
	// ended before its write returned.
	cancelOnChunk bool
	mu            sync.Mutex
	frames        []probedFrame
	endedMidWrite bool
}

type probedFrame struct {
	typ     remote.FrameType
	handle  string
	heldBy  string
	scratch bool
	result  remote.CaptureResultPayload
}

func (p *slotProbe) WriteFrame(ctx context.Context, f remote.Frame) error {
	if p.cancelOnChunk && f.Type == remote.TypeCaptureChunk {
		p.a.handleCaptureCancel(remote.Frame{Type: remote.TypeCaptureCancel, Handle: f.Handle})
		if ctx.Err() != nil {
			p.mu.Lock()
			p.endedMidWrite = true
			p.mu.Unlock()
		}
	}
	pf := probedFrame{typ: f.Type, handle: f.Handle}
	p.a.capture.mu.Lock()
	pf.heldBy = p.a.capture.id
	p.a.capture.mu.Unlock()
	if _, err := os.Lstat(filepath.Join(p.a.root, ".cloop-capture-"+f.Handle)); err == nil {
		pf.scratch = true
	}
	if f.Type == remote.TypeCaptureResult {
		if err := json.Unmarshal(f.Payload, &pf.result); err != nil {
			return err
		}
	}
	p.mu.Lock()
	p.frames = append(p.frames, pf)
	p.mu.Unlock()
	return nil
}

func (p *slotProbe) ReadFrame(ctx context.Context) (remote.Frame, error) {
	<-ctx.Done()
	return remote.Frame{}, ctx.Err()
}

func (p *slotProbe) Close(string) error { return nil }

// results are the capture_result frames written, in order.
func (p *slotProbe) results() []probedFrame {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []probedFrame
	for _, f := range p.frames {
		if f.typ == remote.TypeCaptureResult {
			out = append(out, f)
		}
	}
	return out
}

func captureFrame(t *testing.T, id, tenant, workDir string) remote.Frame {
	t.Helper()
	f, err := remote.NewFrame(remote.TypeCaptureReq, "c-"+id, id, remote.CaptureRequestPayload{
		CaptureID: id, Mode: remote.CaptureInspect, WorkDir: workDir, Tenant: tenant,
		Limits: remote.CaptureLimits{Document: 1 << 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestACaptureFreesItsSlotBeforeItAnswers: the hub may ask a device for the
// next capture the moment it reads one's answer, so the agent gives back its
// capture slot, and the capture's scratch, before the answer goes out. Given
// back once the handler returned, a request arriving in between was told the
// device was "answering another capture" (TestLoopbackRunnerCapturesOnlyItsTenant
// failed so in CI, on fb8bd447). A busy answer leaves the slot to the capture
// that holds it.
func TestACaptureFreesItsSlotBeforeItAnswers(t *testing.T) {
	tenant := "prj-" + strings.Repeat("ab", 16)
	trees := t.TempDir()
	a := &Agent{cfg: Config{Logf: t.Logf, Holds: tenant, Ephemeral: true}, root: t.TempDir(), workspaceRoot: trees}
	probe := &slotProbe{a: a}
	sess := &deviceSession{conn: probe, closed: make(chan struct{})}
	ctx := context.Background()

	// Refusals: a capture naming no tenant, and one naming another.
	a.handleCaptureReq(ctx, sess, captureFrame(t, "cap-none", "", "demo-0a1b2c3d"))
	a.handleCaptureReq(ctx, sess, captureFrame(t, "cap-other", "prj-"+strings.Repeat("cd", 16), "demo-0a1b2c3d"))

	// A capture arriving while another holds the slot.
	if !a.capture.begin("cap-holder", func() {}) {
		t.Fatal("the slot was not free")
	}
	a.handleCaptureReq(ctx, sess, captureFrame(t, "cap-busy", tenant, "demo-0a1b2c3d"))
	a.capture.mu.Lock()
	holder := a.capture.id
	a.capture.mu.Unlock()
	if holder != "cap-holder" {
		t.Fatalf("after a busy answer the slot is held by %q, want the capture that held it", holder)
	}
	a.capture.end("cap-holder")

	// An answered capture: its document goes out while it holds the slot, its
	// result once it has given the slot and its scratch back.
	answered := false
	if _, err := exec.LookPath("git"); err == nil {
		seedCaptureRepo(t, filepath.Join(trees, "demo-0a1b2c3d"))
		a.handleCaptureReq(ctx, sess, captureFrame(t, "cap-ok", tenant, "demo-0a1b2c3d"))
		answered = true
	} else {
		t.Log("git not installed: the answered capture is not checked")
	}

	want := map[string]string{"cap-none": remote.CaptureCodeRefused, "cap-other": remote.CaptureCodeRefused, "cap-busy": remote.CaptureCodeBusy}
	if answered {
		want["cap-ok"] = ""
	}
	results := probe.results()
	if len(results) != len(want) {
		t.Fatalf("%d results written, want %d: %+v", len(results), len(want), results)
	}
	for _, r := range results {
		code, ok := want[r.handle]
		if !ok {
			t.Errorf("a result for %q", r.handle)
			continue
		}
		if r.result.Code != code {
			t.Errorf("capture %s answered %q (%s), want %q", r.handle, r.result.Code, r.result.Error, code)
		}
		switch {
		case r.handle == "cap-busy" && r.heldBy != "cap-holder":
			t.Errorf("the busy answer went out with the slot held by %q, want the capture that held it", r.heldBy)
		case r.handle != "cap-busy" && r.heldBy != "":
			t.Errorf("capture %s answered while the slot was still held by %q", r.handle, r.heldBy)
		}
		if r.scratch {
			t.Errorf("capture %s answered while its scratch was still there", r.handle)
		}
	}
	if answered {
		parts := 0
		probe.mu.Lock()
		for _, f := range probe.frames {
			if f.typ == remote.TypeCaptureChunk && f.handle == "cap-ok" {
				parts++
				if f.heldBy != "cap-ok" {
					t.Errorf("a chunk of cap-ok went out with the slot held by %q", f.heldBy)
				}
			}
		}
		probe.mu.Unlock()
		if parts == 0 {
			t.Error("the answered capture sent no chunk")
		}
	}
}

// TestAHubCancelNeverEndsAChunksWrite: the hub's capture_cancel stops the
// capture, at the next chunk, and never ends the context a chunk is being
// written under: coder/websocket closes the whole connection when a write's
// context ends before the write has returned, so a cancel arriving mid-chunk
// would have dropped the device's session along with the capture.
func TestAHubCancelNeverEndsAChunksWrite(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	tenant := "prj-" + strings.Repeat("ab", 16)
	trees := t.TempDir()
	seedCaptureRepo(t, filepath.Join(trees, "demo-0a1b2c3d"))
	a := &Agent{cfg: Config{Logf: t.Logf, Holds: tenant, Ephemeral: true}, root: t.TempDir(), workspaceRoot: trees}
	probe := &slotProbe{a: a, cancelOnChunk: true}
	sess := &deviceSession{conn: probe, closed: make(chan struct{})}
	a.handleCaptureReq(context.Background(), sess, captureFrame(t, "cap-cancelled", tenant, "demo-0a1b2c3d"))

	chunks := 0
	probe.mu.Lock()
	for _, f := range probe.frames {
		if f.typ == remote.TypeCaptureChunk {
			chunks++
		}
	}
	ended := probe.endedMidWrite
	probe.mu.Unlock()
	if chunks == 0 {
		t.Fatal("the capture wrote no chunk")
	}
	if ended {
		t.Error("the hub's cancel ended the context a chunk was being written under")
	}
	if got := len(probe.results()); got != 1 {
		t.Errorf("%d results written, want 1", got)
	}
}

// seedCaptureRepo makes dir a working copy with one commit.
func seedCaptureRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.go"), []byte("package app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "app.go"}, {"commit", "-qm", "a commit"}} {
		cmd := exec.Command("git", append([]string{"-c", "init.defaultBranch=main"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}
