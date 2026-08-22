package remote_test

// Write-back over the remote protocol, end to end: a real sandbox tree produces
// a real git bundle, a hand-written agent streams it back as result frames, the
// hub assembles and verifies it, and pkg/writeback lands it on a branch.
//
// The agent is hand-written rather than the loopback one on purpose. What is
// under test here is the *transport* — chunk ordering, the digest check, the
// ceiling, what the hub does when the stream is wrong — and a well-behaved
// agent cannot produce a bad stream. Most of the assertions below are about
// frames a real agent would never send, so the test has to be the one sending
// them.
//
// The bundle itself is genuine, made by the same gitwriteback.Produce a device
// runs. A synthesised byte slice would let the whole path pass without git ever
// having agreed that what arrived was a bundle.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/writeback"
)

const wbBranch = "cloop/task-7-remote-work"

// --- a real repository and a real bundle ------------------------------------

func wbGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// wbScene is the hub's copy of a project and a sandbox's copy of the same tree.
type wbScene struct {
	hub     string
	sandbox string
	base    string
}

func newWBScene(t *testing.T) *wbScene {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	hub := filepath.Join(root, "hub")
	if err := os.MkdirAll(hub, 0o755); err != nil {
		t.Fatal(err)
	}
	wbGit(t, hub, "init", "--quiet", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(hub, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wbGit(t, hub, "add", "-A")
	wbGit(t, hub, "commit", "--quiet", "-m", "seed")

	sandbox := filepath.Join(root, "sandbox")
	wbGit(t, root, "clone", "--quiet", hub, sandbox)
	return &wbScene{hub: hub, sandbox: sandbox, base: wbGit(t, hub, "rev-parse", "HEAD")}
}

// produce runs the real sandbox-side engine and returns what a device would
// have to send.
func (s *wbScene) produce(t *testing.T) (executor.WriteBackResult, []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.sandbox, "retry.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := gitwriteback.Produce(context.Background(), gitwriteback.Request{
		Dir: s.sandbox,
		Workspace: executor.Workspace{
			Kind: executor.WorkspaceGit,
			Repo: "https://example.invalid/acme/widgets.git",
			Ref:  s.base,
		},
		WriteBack: executor.WriteBack{
			Mode: executor.WriteBackBundle, Branch: wbBranch,
			Message: "cloop(task-7): work from an edge device",
		},
		BaseSHA: s.base,
	})
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(res.BundlePath) })
	raw, err := os.ReadFile(res.BundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	return res.WriteBackResult, raw
}

// --- driving the protocol ---------------------------------------------------

// startedHandle brings a handle into existence on the hub the way a start does,
// so result frames have somewhere to land.
//
// It goes through the executor's own Start rather than reaching into its state,
// because a handle the hub does not believe in is precisely the case
// TestWriteBackForAnUnknownHandleIsRefused covers, and a helper that fabricated
// one would make that test vacuous.
func startedHandle(t *testing.T, ex *remote.Executor, p *peer) string {
	t.Helper()
	type started struct {
		h   executor.Handle
		err error
	}
	ch := make(chan started, 1)
	go func() {
		h, err := ex.Start(context.Background(), executor.Spec{
			Argv:      []string{"true"},
			WorkDir:   "/tmp/project",
			Workspace: executor.Workspace{Kind: executor.WorkspaceNone},
		})
		ch <- started{h, err}
	}()

	req := p.readUntil(remote.TypeStart)
	payload, err := remote.DecodeStart(req)
	if err != nil {
		t.Fatalf("decode start: %v", err)
	}
	ack, err := remote.NewFrame(remote.TypeStarted, req.ID, payload.HandleID,
		remote.StartedPayload{HandleID: payload.HandleID, PID: 4242, StartedAt: time.Now()})
	if err != nil {
		t.Fatalf("build started: %v", err)
	}
	p.write(ack)

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("Start: %v", res.err)
		}
		return res.h.ID
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return")
		return ""
	}
}

// sendChunks streams data as the agent would, in slices of size n.
func sendChunks(t *testing.T, p *peer, handle string, data []byte, n int) {
	t.Helper()
	for off := 0; off < len(data); off += n {
		end := min(off+n, len(data))
		f, err := remote.NewFrame(remote.TypeResultChunk, "", handle,
			remote.ResultChunkPayload{Offset: int64(off), Data: data[off:end]})
		if err != nil {
			t.Fatalf("build chunk: %v", err)
		}
		p.write(f)
	}
}

func sendResult(t *testing.T, p *peer, handle string, res executor.WriteBackResult) {
	t.Helper()
	f, err := remote.NewFrame(remote.TypeResult, "", handle, remote.ResultPayload{Result: res})
	if err != nil {
		t.Fatalf("build result: %v", err)
	}
	p.write(f)
}

// finish sends the terminal status, which is what closes the hub's log stream.
func finish(t *testing.T, p *peer, handle string, exitCode int) {
	t.Helper()
	f, err := remote.NewFrame(remote.TypeStatus, "", handle, remote.StatusPayload{
		Status: executor.Status{
			HandleID: handle, State: executor.StateExited,
			ExitCode: exitCode, FinishedAt: time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("build status: %v", err)
	}
	p.write(f)
}

// awaitWriteBack waits for the workload to finish and returns what the hub
// recorded, the same way a real consumer does: subscribe, drain until the
// driver closes the channel, then read the status.
//
// Deliberately not a poll on Status. Status round-trips to the agent while a
// handle is not yet terminal, and this test's agent is hand-written and answers
// nothing it was not told to — so a poll that raced the status frame would
// block forever on a status_req. Waiting on the stream close is also the
// stronger assertion: it is exactly the moment executor.Run reads Status, so a
// result that only appeared *after* it would fail here rather than pass by a
// margin that does not exist in production.
func awaitWriteBack(t *testing.T, ex *remote.Executor, handle string) *executor.WriteBackResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lines, err := ex.Stream(ctx, handle)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	for range lines {
		// Drained, not inspected: the close is the signal.
	}
	st, err := ex.Status(ctx, handle)
	if err != nil {
		t.Fatalf("Status after the stream closed: %v", err)
	}
	if st.WriteBack == nil {
		t.Fatal("the workload finished with no write-back recorded on the handle")
	}
	return st.WriteBack
}

// --- the round trip ---------------------------------------------------------

// TestWriteBackRoundTripLandsRemoteWorkOnTheHub is the whole point of the
// feature in one test: a file written inside a sandbox ends up on a branch in
// the hub's repository, having travelled as protocol frames.
func TestWriteBackRoundTripLandsRemoteWorkOnTheHub(t *testing.T) {
	s := newWBScene(t)
	reported, bundle := s.produce(t)

	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p)

	// Deliberately smaller than the bundle so the reassembly path is exercised
	// rather than the single-chunk shortcut.
	sendChunks(t, p, handle, bundle, 64)
	sendResult(t, p, handle, reported)
	finish(t, p, handle, 0)

	got := awaitWriteBack(t, ex, handle)
	if got.Err != "" {
		t.Fatalf("the hub rejected a well-formed write-back: %s", got.Err)
	}
	if got.CommitSHA != reported.CommitSHA {
		t.Errorf("hub recorded commit %s, sandbox produced %s", got.CommitSHA, reported.CommitSHA)
	}

	assembled, err := ex.WriteBackBundle(handle)
	if err != nil {
		t.Fatalf("WriteBackBundle: %v", err)
	}
	if len(assembled) != len(bundle) {
		t.Fatalf("assembled %d bytes, sent %d", len(assembled), len(bundle))
	}

	// And now the part that makes it work rather than merely arrive.
	res, err := writeback.Apply(context.Background(), writeback.Request{
		RepoDir: s.hub, Reported: *got, Bundle: assembled, TaskID: 7,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.CommitSHA != reported.CommitSHA {
		t.Errorf("landed %s, sandbox produced %s", res.CommitSHA, reported.CommitSHA)
	}
	if body := wbGit(t, s.hub, "show", wbBranch+":retry.go"); !strings.Contains(body, "package main") {
		t.Errorf("the sandbox's file did not survive the trip: %q", body)
	}
}

// TestWriteBackBundleIsReleasedOnce pins that collecting the bundle frees it.
// A hub holding every finished task's work product in memory is a leak that
// only shows up under fleet load.
func TestWriteBackBundleIsReleasedOnce(t *testing.T) {
	s := newWBScene(t)
	reported, bundle := s.produce(t)

	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p)

	sendChunks(t, p, handle, bundle, 1024)
	sendResult(t, p, handle, reported)
	finish(t, p, handle, 0)
	awaitWriteBack(t, ex, handle)

	if _, err := ex.WriteBackBundle(handle); err != nil {
		t.Fatalf("first collection: %v", err)
	}
	if _, err := ex.WriteBackBundle(handle); !errors.Is(err, executor.ErrWriteBackUnavailable) {
		t.Errorf("second collection = %v, want ErrWriteBackUnavailable", err)
	}
}

// --- streams a well-behaved agent would never send --------------------------

// TestWriteBackRefusesAGapInTheStream is the difference between this and the
// log stream. Log output is deliberately lossy so a slow consumer never blocks
// a workload; a bundle with a hole is not a smaller bundle, it is one git will
// reject with a message about something else entirely.
func TestWriteBackRefusesAGapInTheStream(t *testing.T) {
	s := newWBScene(t)
	reported, bundle := s.produce(t)
	if len(bundle) < 200 {
		t.Fatalf("bundle is too small (%d bytes) to skip a slice", len(bundle))
	}

	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p)

	first, err := remote.NewFrame(remote.TypeResultChunk, "", handle,
		remote.ResultChunkPayload{Offset: 0, Data: bundle[:64]})
	if err != nil {
		t.Fatal(err)
	}
	p.write(first)
	// Skips bytes 64..128 entirely.
	gapped, err := remote.NewFrame(remote.TypeResultChunk, "", handle,
		remote.ResultChunkPayload{Offset: 128, Data: bundle[128:]})
	if err != nil {
		t.Fatal(err)
	}
	p.write(gapped)
	sendResult(t, p, handle, reported)
	finish(t, p, handle, 0)

	got := awaitWriteBack(t, ex, handle)
	if got.Err == "" {
		t.Fatal("a bundle with a 64-byte hole was accepted")
	}
	if !strings.Contains(got.Err, "hole") {
		t.Errorf("Err = %q, want it to name the gap", got.Err)
	}
	if _, err := ex.WriteBackBundle(handle); err == nil {
		t.Error("a gapped bundle was still collectable")
	}
}

// TestWriteBackRefusesATamperedBundle covers the digest, which is the only
// evidence that what arrived is what was measured.
func TestWriteBackRefusesATamperedBundle(t *testing.T) {
	s := newWBScene(t)
	reported, bundle := s.produce(t)

	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p)

	// Same length, different bytes: the length check alone would pass.
	altered := append([]byte(nil), bundle...)
	altered[len(altered)/2] ^= 0xff
	sendChunks(t, p, handle, altered, 256)
	sendResult(t, p, handle, reported)
	finish(t, p, handle, 0)

	got := awaitWriteBack(t, ex, handle)
	if got.Err == "" {
		t.Fatal("a bundle whose bytes did not match the reported digest was accepted")
	}
	if !strings.Contains(got.Err, "digest") {
		t.Errorf("Err = %q, want it to name the digest", got.Err)
	}
}

// TestWriteBackRefusesAMissingDigest pins that the digest is not optional. With
// only a length to check, a substitution of equal size would pass unnoticed.
func TestWriteBackRefusesAMissingDigest(t *testing.T) {
	s := newWBScene(t)
	reported, bundle := s.produce(t)
	reported.BundleSHA256 = ""

	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p)

	sendChunks(t, p, handle, bundle, 4096)
	sendResult(t, p, handle, reported)
	finish(t, p, handle, 0)

	got := awaitWriteBack(t, ex, handle)
	if got.Err == "" || !strings.Contains(got.Err, "digest") {
		t.Fatalf("Err = %q, want a refusal naming the missing digest", got.Err)
	}
}

// TestWriteBackRefusesBytesForAPushResult pins that the two modes are not
// interchangeable. A push leaves its objects at the origin, so bytes arriving
// alongside one mean the device is not describing what it did.
func TestWriteBackRefusesBytesForAPushResult(t *testing.T) {
	s := newWBScene(t)
	reported, bundle := s.produce(t)
	reported.Mode = executor.WriteBackPush
	reported.Pushed = true

	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p)

	sendChunks(t, p, handle, bundle, 4096)
	sendResult(t, p, handle, reported)
	finish(t, p, handle, 0)

	got := awaitWriteBack(t, ex, handle)
	if got.Err == "" {
		t.Fatal("bundle bytes accompanying a push result were accepted")
	}
}

// TestWriteBackRestartsCleanlyAtOffsetZero covers the reconnect case: a device
// whose link dropped mid-transfer starts again from the beginning, and the
// partial bytes from the dead session must not be spliced onto the new ones.
func TestWriteBackRestartsCleanlyAtOffsetZero(t *testing.T) {
	s := newWBScene(t)
	reported, bundle := s.produce(t)

	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p)

	// A truncated first attempt, then the whole thing again from zero.
	sendChunks(t, p, handle, bundle[:len(bundle)/2], 128)
	sendChunks(t, p, handle, bundle, 128)
	sendResult(t, p, handle, reported)
	finish(t, p, handle, 0)

	got := awaitWriteBack(t, ex, handle)
	if got.Err != "" {
		t.Fatalf("a restarted transfer was refused: %s", got.Err)
	}
	assembled, err := ex.WriteBackBundle(handle)
	if err != nil {
		t.Fatalf("WriteBackBundle: %v", err)
	}
	if len(assembled) != len(bundle) {
		t.Fatalf("assembled %d bytes, want %d — the two attempts were spliced",
			len(assembled), len(bundle))
	}
}

// TestWriteBackRefusesAnOverlappingChunk pins the decision not to trim
// overlaps the way the log path does. A re-sent slice that differs from the
// stored one would rewrite bytes already counted, and nothing can tell the
// benign case from the hostile one.
func TestWriteBackRefusesAnOverlappingChunk(t *testing.T) {
	s := newWBScene(t)
	reported, bundle := s.produce(t)

	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p)

	sendChunks(t, p, handle, bundle[:256], 256)
	overlap, err := remote.NewFrame(remote.TypeResultChunk, "", handle,
		remote.ResultChunkPayload{Offset: 128, Data: bundle[128:512]})
	if err != nil {
		t.Fatal(err)
	}
	p.write(overlap)
	sendResult(t, p, handle, reported)
	finish(t, p, handle, 0)

	got := awaitWriteBack(t, ex, handle)
	if got.Err == "" {
		t.Fatal("an overlapping chunk was accepted")
	}
}

// TestWriteBackChunkForAnUnknownHandleIsRefused covers a device streaming for a
// handle the hub has forgotten — the normal consequence of a control-plane
// restart. It must be told, not silently accumulated against nothing.
func TestWriteBackChunkForAnUnknownHandleIsRefused(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)

	f, err := remote.NewFrame(remote.TypeResultChunk, "", "handle-that-never-existed",
		remote.ResultChunkPayload{Offset: 0, Data: []byte("some bundle bytes")})
	if err != nil {
		t.Fatal(err)
	}
	p.write(f)

	reply := p.readUntil(remote.TypeError)
	payload, err := remote.DecodeError(reply)
	if err != nil {
		t.Fatalf("decode error frame: %v", err)
	}
	if payload.Code != remote.CodeUnknownHandle {
		t.Errorf("code = %q, want %q", payload.Code, remote.CodeUnknownHandle)
	}
}

// --- protocol-level bounds --------------------------------------------------

func TestDecodeResultChunkEnforcesItsBounds(t *testing.T) {
	handle := "h1"
	cases := []struct {
		name    string
		payload remote.ResultChunkPayload
	}{
		{"negative offset", remote.ResultChunkPayload{Offset: -1, Data: []byte("x")}},
		{"empty chunk", remote.ResultChunkPayload{Offset: 0}},
		{"over the per-chunk cap", remote.ResultChunkPayload{
			Offset: 0, Data: make([]byte, remote.MaxResultChunkBytes+1)}},
		{"ends past the write-back ceiling", remote.ResultChunkPayload{
			Offset: executor.MaxWriteBackBundleBytes, Data: []byte("x")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := remote.NewFrame(remote.TypeResultChunk, "", handle, tc.payload)
			if err != nil {
				t.Fatalf("build frame: %v", err)
			}
			if _, err := remote.DecodeResultChunk(f); err == nil {
				t.Fatal("decoded a chunk that should have been refused")
			}
		})
	}
}

func TestDecodeResultEnforcesTheReportedLength(t *testing.T) {
	for _, size := range []int64{-1, executor.MaxWriteBackBundleBytes + 1} {
		f, err := remote.NewFrame(remote.TypeResult, "", "h1", remote.ResultPayload{
			Result: executor.WriteBackResult{
				Mode: executor.WriteBackBundle, BundleBytes: size,
			},
		})
		if err != nil {
			t.Fatalf("build frame: %v", err)
		}
		if _, err := remote.DecodeResult(f); err == nil {
			t.Errorf("decoded a result reporting %d bytes", size)
		}
	}
}

// TestSupportsWriteBackTracksTheProtocolVersion pins the placement rule. An
// older agent does not reject Spec.WriteBack, it ignores it — runs the harness,
// reports success, and keeps the work. Refusing to place such a workload is the
// only thing standing between that and a silent loss.
func TestSupportsWriteBackTracksTheProtocolVersion(t *testing.T) {
	if remote.SupportsWriteBack(remote.MinWriteBackVersion - 1) {
		t.Errorf("v%d should not claim write-back support", remote.MinWriteBackVersion-1)
	}
	if !remote.SupportsWriteBack(remote.MinWriteBackVersion) {
		t.Errorf("v%d should claim write-back support", remote.MinWriteBackVersion)
	}

	// A current-version device that advertised the capability.
	ex := newTestExecutor(t, nil)
	hello := defaultHello()
	hello.Capabilities.WriteBack = true
	connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	if !ex.Capabilities().SupportsWriteBack {
		t.Error("a v4 device advertising write-back was reported as unable")
	}

	// A device on an older protocol: the capability must be narrowed away even
	// though the device claims it, because the session cannot carry the frames.
	old := newTestExecutor(t, nil)
	oldHello := defaultHello()
	oldHello.ProtocolVersion = remote.MinWriteBackVersion - 1
	oldHello.Capabilities.WriteBack = true
	connect(t, old, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, oldHello, nil)
	if old.Capabilities().SupportsWriteBack {
		t.Error("a pre-v4 session claimed write-back support; a workload placed there would " +
			"run, report success, and leave its work on the device")
	}
}
