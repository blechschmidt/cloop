package remote_test

// What a compromised agent can make the hub hold in memory through the frames
// that return a run's work (Task 20399).
//
// Before these rules a device could pin the hard 128 MiB bundle ceiling on
// every handle the hub tracked for it — running ones and up to 256 finished
// ones — because result chunks were accepted for a finished handle, a
// collected bundle was refilled from offset 0, a handle that asked for no
// write-back took the ceiling anyway, nothing counted the total, and revoking
// the device freed nothing. 32 GiB per device per hub process.
//
// Every test here is a frame sequence no honest agent sends, which is why the
// agent is hand-written: an honest one sends chunks, then the result, then the
// final status, and nothing after. Payloads are a few hundred bytes against an
// injected budget of a few kilobytes, because the test pipe round-trips JSON
// and the property is the arithmetic, not the scale.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// pinBase is the commit a pinning test's tree is notionally at. Only its form
// matters: nothing here runs git.
var pinBase = strings.Repeat("b", 40)

// fakeBundle returns n bytes and the result a device would report for them.
// The transport never opens a bundle, so these need only add up.
func fakeBundle(n int) ([]byte, executor.WriteBackResult) {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*7 + 3)
	}
	sum := sha256.Sum256(data)
	return data, executor.WriteBackResult{
		Mode:         executor.WriteBackBundle,
		Branch:       wbBranch,
		CommitSHA:    strings.Repeat("c", 40),
		BaseSHA:      pinBase,
		BundleBytes:  int64(n),
		BundleSHA256: hex.EncodeToString(sum[:]),
	}
}

// charged is what n bundle bytes arriving in chunks chunks count against a
// budget: the bytes, and ResultChunkOverhead for each chunk that holds them.
func charged(n, chunks int) int64 { return int64(n + chunks*remote.ResultChunkOverhead) }

// pinnedExecutor builds an executor for agentID drawing on budget.
func pinnedExecutor(t *testing.T, agentID string, budget *remote.ResultBudget, store executor.HandleStore,
	clock *fakeClock) *remote.Executor {
	t.Helper()
	opts := remote.Options{ID: agentID, Name: agentID, ResultBudget: budget, HandleStore: store}
	if clock != nil {
		opts.Now = clock.Now
	}
	ex, err := remote.NewExecutor(opts)
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	return ex
}

// helloFor is defaultHello for another agent ID.
func helloFor(agentID string) remote.HelloPayload {
	h := defaultHello()
	h.AgentID, h.Name = agentID, agentID
	return h
}

// noWriteBackSpec is a dispatch that asks for nothing back.
func noWriteBackSpec() executor.Spec {
	return executor.Spec{Argv: []string{"true"}, WorkDir: "/tmp/project"}
}

// barrier returns once the hub has handled every frame the peer sent before
// it, with the error frames it answered on the way. A heartbeat is the barrier
// because the session handles frames in order and acknowledges a beat; running
// names the handles the device is still running, so the beat's reconciliation
// leaves them alone.
func barrier(t *testing.T, p *peer, running ...string) []remote.ErrorPayload {
	t.Helper()
	f, err := remote.NewFrame(remote.TypeHeartbeat, "hb-barrier", "",
		remote.HeartbeatPayload{Seq: 1, ActiveHandles: running})
	if err != nil {
		t.Fatalf("build heartbeat: %v", err)
	}
	p.write(f)
	var refused []remote.ErrorPayload
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		fr, err := p.read()
		if err != nil {
			t.Fatalf("waiting for the heartbeat ack: %v", err)
		}
		switch fr.Type {
		case remote.TypeHeartbeatAck:
			return refused
		case remote.TypeError:
			e, err := remote.DecodeError(fr)
			if err != nil {
				t.Fatalf("decode error frame: %v", err)
			}
			refused = append(refused, e)
		}
	}
	t.Fatal("the hub never acknowledged the barrier heartbeat")
	return nil
}

// wantRefusals asserts n refusals came back, each naming want.
func wantRefusals(t *testing.T, got []remote.ErrorPayload, n int, want string) {
	t.Helper()
	if len(got) != n {
		t.Fatalf("the hub refused %d frames, want %d: %+v", len(got), n, got)
	}
	for _, e := range got {
		if !strings.Contains(e.Message, want) {
			t.Errorf("refusal %q does not say %q", e.Message, want)
		}
	}
}

// wantPinned asserts what ex, and the whole budget, hold.
func wantPinned(t *testing.T, ex *remote.Executor, budget *remote.ResultBudget, mine, total int64) {
	t.Helper()
	if got := ex.PinnedResultBytes(); got != mine {
		t.Errorf("executor %s holds %d bytes of returned work, want %d", ex.ID(), got, mine)
	}
	if got := budget.Usage().Pinned; got != total {
		t.Errorf("the budget counts %d bytes, want %d", got, total)
	}
}

// statusOf reads a finished handle's status the way a consumer does.
func statusOf(t *testing.T, ex *remote.Executor, handle string) executor.Status {
	t.Helper()
	st, err := ex.Status(context.Background(), handle)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return st
}

// TestWriteBackChunkAfterTheFinalStatusIsRefused: a device that has reported
// its final status sends a bundle anyway. Nothing of it is kept.
func TestWriteBackChunkAfterTheFinalStatusIsRefused(t *testing.T) {
	budget := remote.NewResultBudget(4<<10, 16<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, bundleSpec(pinBase, 0))

	data, res := fakeBundle(512)
	finish(t, p, handle, 0)
	sendChunks(t, p, handle, data, 256)
	sendResult(t, p, handle, res)

	wantRefusals(t, barrier(t, p), 3, "final status")
	wantPinned(t, ex, budget, 0, 0)
	if _, err := ex.WriteBackBundle(handle); !errors.Is(err, executor.ErrWriteBackUnavailable) {
		t.Errorf("a bundle sent after the final status was collectable: %v", err)
	}
	if wb := statusOf(t, ex, handle).WriteBack; wb != nil {
		t.Errorf("a result sent after the final status reached the run: %+v", wb)
	}
}

// TestWriteBackChunkAfterTheResultIsRefused covers both sides of the result
// frame. Before it, a restart from offset 0 is how a device recovers a
// transfer its link dropped; after it, the same frame is the old hole — a
// collected bundle refilled — and is refused, as is a second result.
func TestWriteBackChunkAfterTheResultIsRefused(t *testing.T) {
	budget := remote.NewResultBudget(4<<10, 16<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	data, res := fakeBundle(512)

	// A first attempt cut short, then the whole bundle again from zero: legal,
	// and the first attempt's bytes are given back before the second's count.
	sendChunks(t, p, handle, data[:256], 128)
	sendChunks(t, p, handle, data, 128)
	sendResult(t, p, handle, res)
	if refused := barrier(t, p, handle); len(refused) != 0 {
		t.Fatalf("an honest restart was refused: %+v", refused)
	}
	wantPinned(t, ex, budget, charged(512, 4), charged(512, 4))

	// After the result: the same restart, and a second result.
	sendChunks(t, p, handle, data, 256)
	sendResult(t, p, handle, res)
	wantRefusals(t, barrier(t, p, handle), 3, "already closed with its result frame")
	wantPinned(t, ex, budget, charged(512, 4), charged(512, 4))

	finish(t, p, handle, 0)
	if got := awaitWriteBack(t, ex, handle); got.Err != "" {
		t.Fatalf("the verified write-back was spoiled by the frames after it: %s", got.Err)
	}
	bundle, err := ex.WriteBackBundle(handle)
	if err != nil || len(bundle) != len(data) {
		t.Fatalf("collected %d bytes, %v; want the %d the result verified", len(bundle), err, len(data))
	}
	wantPinned(t, ex, budget, 0, 0)

	// And after collection, the frame that used to refill the buffer.
	sendChunks(t, p, handle, data, 512)
	wantRefusals(t, barrier(t, p), 1, "final status")
	wantPinned(t, ex, budget, 0, 0)
}

// TestWriteBackFramesForAHandleThatAskedForNoneAreRefused: a handle accepts
// only what its spec asked for. No write-back means no chunk and no result; a
// push means a result with no bytes; no project seed means no project state.
func TestWriteBackFramesForAHandleThatAskedForNoneAreRefused(t *testing.T) {
	budget := remote.NewResultBudget(4<<10, 16<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	data, res := fakeBundle(512)

	none := startedHandle(t, ex, p, noWriteBackSpec())
	sendChunks(t, p, none, data, 256)
	sendResult(t, p, none, res)
	pr, err := remote.NewFrame(remote.TypeProjectResult, "", none, remote.ProjectResultPayload{Data: data})
	if err != nil {
		t.Fatal(err)
	}
	p.write(pr)
	refused := barrier(t, p, none)
	if len(refused) != 4 {
		t.Fatalf("the hub refused %d of the four frames, want all four: %+v", len(refused), refused)
	}
	wantRefusals(t, refused[:2], 2, "no bundle write-back")
	wantRefusals(t, refused[2:3], 1, "no write-back")
	wantRefusals(t, refused[3:], 1, "no project seed")
	wantPinned(t, ex, budget, 0, 0)

	push := bundleSpec(pinBase, 0)
	push.WriteBack = executor.WriteBack{Mode: executor.WriteBackPush, Branch: wbBranch}
	pushed := startedHandle(t, ex, p, push)
	sendChunks(t, p, pushed, data, 512)
	pushRes := res
	pushRes.Mode, pushRes.Pushed, pushRes.BundleBytes, pushRes.BundleSHA256 = executor.WriteBackPush, true, 0, ""
	sendResult(t, p, pushed, pushRes)
	wantRefusals(t, barrier(t, p, none, pushed), 1, "no bundle write-back")
	wantPinned(t, ex, budget, 0, 0)
	finish(t, p, pushed, 0)
	if got := awaitWriteBack(t, ex, pushed); got.Err != "" || !got.Pushed {
		t.Errorf("a push's result, which carries no bytes, was not recorded: %+v", got)
	}
}

// TestWriteBackBundleCapIsTheSpecs: the most a handle may send is what its
// spec asked for — not the hard ceiling every handle used to get.
func TestWriteBackBundleCapIsTheSpecs(t *testing.T) {
	budget := remote.NewResultBudget(64<<10, 64<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)

	// The control: exactly the cap lands.
	exact, exactRes := fakeBundle(1024)
	fits := startedHandle(t, ex, p, bundleSpec(pinBase, 1024))
	sendChunks(t, p, fits, exact, 512)
	sendResult(t, p, fits, exactRes)
	finish(t, p, fits, 0)
	if got := awaitWriteBack(t, ex, fits); got.Err != "" {
		t.Fatalf("a bundle of exactly its cap was refused: %s", got.Err)
	}
	if _, err := ex.WriteBackBundle(fits); err != nil {
		t.Fatalf("collecting a bundle of exactly its cap: %v", err)
	}

	// One chunk more is refused, and what had arrived is let go of.
	over, overRes := fakeBundle(1536)
	handle := startedHandle(t, ex, p, bundleSpec(pinBase, 1024))
	sendChunks(t, p, handle, over, 512)
	wantRefusals(t, barrier(t, p, handle), 1, "1024-byte cap")
	wantPinned(t, ex, budget, 0, 0)
	sendResult(t, p, handle, overRes)
	finish(t, p, handle, 0)
	got := awaitWriteBack(t, ex, handle)
	if !strings.Contains(got.Err, "1024-byte cap") {
		t.Errorf("the run's write-back says %q; it should name the cap it crossed", got.Err)
	}
	if _, err := ex.WriteBackBundle(handle); err == nil {
		t.Error("a bundle over its cap was collectable")
	}
}

// TestWriteBackExecutorBudgetSpansItsHandles: the budget is the executor's,
// not each handle's, so a device cannot multiply it by running more work.
func TestWriteBackExecutorBudgetSpansItsHandles(t *testing.T) {
	// Room for exactly two 512-byte bundles sent in one chunk each.
	budget := remote.NewResultBudget(2*charged(512, 1), 64<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	data, res := fakeBundle(512)

	first := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	second := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	third := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	sendChunks(t, p, first, data, 512)
	sendChunks(t, p, second, data, 512)
	if refused := barrier(t, p, first, second, third); len(refused) != 0 {
		t.Fatalf("bundles inside the budget were refused: %+v", refused)
	}
	full := 2 * charged(512, 1)
	wantPinned(t, ex, budget, full, full)

	sendChunks(t, p, third, data[:256], 256)
	wantRefusals(t, barrier(t, p, first, second, third), 1, "max_pinned_writeback_bytes")
	wantPinned(t, ex, budget, full, full)

	// The refusal is the handle's write-back failing, with the reason the
	// run's journal will carry; the two that fit are untouched.
	sendResult(t, p, third, res)
	finish(t, p, third, 0)
	got := awaitWriteBack(t, ex, third)
	if !strings.Contains(got.Err, "budget of 1.1 KiB") || !strings.Contains(got.Err, "1.1 KiB is already held") {
		t.Errorf("the refused write-back says %q; it should name the budget and what was held", got.Err)
	}
	for _, h := range []string{first, second} {
		sendResult(t, p, h, res)
		finish(t, p, h, 0)
		if got := awaitWriteBack(t, ex, h); got.Err != "" {
			t.Errorf("a bundle inside the budget failed: %s", got.Err)
		}
	}

	// Collecting one makes room for the next.
	if _, err := ex.WriteBackBundle(first); err != nil {
		t.Fatalf("collect: %v", err)
	}
	wantPinned(t, ex, budget, charged(512, 1), charged(512, 1))
	fourth := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	sendChunks(t, p, fourth, data, 512)
	if refused := barrier(t, p, fourth); len(refused) != 0 {
		t.Fatalf("collecting a bundle did not give its bytes back: %+v", refused)
	}
	wantPinned(t, ex, budget, full, full)
}

// TestTinyChunksAreChargedForTheMemoryTheyHold: a device that splits its
// bundle into one-byte chunks makes the hub keep one slice per byte. Counted
// by their bytes alone they would hold some fifty times what the budget says;
// each chunk is charged its overhead too, so the same budget holds the same
// memory however the bundle is cut.
func TestTinyChunksAreChargedForTheMemoryTheyHold(t *testing.T) {
	budget := remote.NewResultBudget(charged(64, 64), 64<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	data, _ := fakeBundle(65)

	sendChunks(t, p, handle, data, 1)
	wantRefusals(t, barrier(t, p, handle), 1, "max_pinned_writeback_bytes")
	wantPinned(t, ex, budget, 0, 0)
}

// TestWriteBackProcessCeilingSpansExecutors: each device inside its own
// budget, the fleet together past the process's — the case a per-executor
// budget alone does not cover.
func TestWriteBackProcessCeilingSpansExecutors(t *testing.T) {
	// Each device may hold a 1 KiB bundle in two chunks; the process, one and a half.
	budget := remote.NewResultBudget(charged(1024, 2), charged(1024, 2)+charged(512, 1))
	a := pinnedExecutor(t, "agent-1", budget, nil, nil)
	b := pinnedExecutor(t, "agent-2", budget, nil, nil)
	pa, _ := connect(t, a, remote.AgentRecord{AgentID: "agent-1"}, helloFor("agent-1"), nil)
	pb, _ := connect(t, b, remote.AgentRecord{AgentID: "agent-2"}, helloFor("agent-2"), nil)
	data, _ := fakeBundle(1024)

	ha := startedHandle(t, a, pa, bundleSpec(pinBase, 0))
	hb := startedHandle(t, b, pb, bundleSpec(pinBase, 0))
	sendChunks(t, pa, ha, data, 512)
	if refused := barrier(t, pa, ha); len(refused) != 0 {
		t.Fatalf("agent-1 inside its budget was refused: %+v", refused)
	}
	sendChunks(t, pb, hb, data, 512)
	wantRefusals(t, barrier(t, pb, hb), 1, "max_pinned_writeback_total_bytes")
	wantPinned(t, a, budget, charged(1024, 2), charged(1024, 2))
	wantPinned(t, b, budget, 0, charged(1024, 2))
	if u := budget.Usage(); u.MaxPerExecutor != charged(1024, 2) || u.Executors != 1 {
		t.Errorf("usage = %+v, want one executor holding %d", u, charged(1024, 2))
	}
}

// TestRevokeAndDeregisterGiveTheBytesBack: revoking a device, or removing it
// from a hub member, lets go of everything its handles hold — a finished
// handle's uncollected bundle and a running one's partial alike — and frees
// the budget it was counted against.
func TestRevokeAndDeregisterGiveTheBytesBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove func(*remote.Hub) error
	}{
		{"revoke", func(h *remote.Hub) error { return h.Revoke("agent-1") }},
		{"deregister", func(h *remote.Hub) error { h.Deregister("agent-1"); return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := remote.NewResultBudget(4<<10, 16<<10)
			store := newMemStore()
			if err := store.PutAgent(remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}); err != nil {
				t.Fatal(err)
			}
			hub, err := remote.NewHub(remote.HubOptions{
				Store: store, Registry: executor.NewRegistry(), ResultBudget: budget,
			})
			if err != nil {
				t.Fatalf("NewHub: %v", err)
			}
			if err := hub.Restore(); err != nil {
				t.Fatalf("Restore: %v", err)
			}
			ex, ok := hub.Executor("agent-1")
			if !ok {
				t.Fatal("Restore did not build the enrolled agent's executor")
			}
			p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
			data, res := fakeBundle(512)

			done := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
			sendChunks(t, p, done, data, 256)
			sendResult(t, p, done, res)
			finish(t, p, done, 0)
			running := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
			sendChunks(t, p, running, data[:256], 256)
			barrier(t, p, running)
			wantPinned(t, ex, budget, charged(768, 3), charged(768, 3))

			if err := tc.remove(hub); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			wantPinned(t, ex, budget, 0, 0)
			if _, err := ex.WriteBackBundle(done); err == nil {
				t.Errorf("a %sd device's bundle was still collectable", tc.name)
			}
		})
	}
}

// TestEvictionGivesTheBytesBack: a finished handle evicted to make room for
// new work takes its uncollected bundle with it. An evicted handle is one no
// consumer can reach, so bytes kept for it are bytes nothing will collect.
func TestEvictionGivesTheBytesBack(t *testing.T) {
	budget := remote.NewResultBudget(4<<10, 16<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	data, res := fakeBundle(512)

	oldest := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	sendChunks(t, p, oldest, data, 512)
	sendResult(t, p, oldest, res)
	finish(t, p, oldest, 0)
	barrier(t, p)
	wantPinned(t, ex, budget, charged(512, 1), charged(512, 1))

	// Answer the starts that follow from here on, so the map can be filled.
	ctx, cancel := context.WithCancel(context.Background())
	acked := make(chan struct{})
	go func() {
		defer close(acked)
		for {
			f, err := p.conn.ReadFrame(ctx)
			if err != nil {
				return
			}
			if f.Type != remote.TypeStart {
				continue
			}
			reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle,
				remote.StartedPayload{HandleID: f.Handle, PID: 1, StartedAt: time.Now()})
			if err != nil {
				return
			}
			if err := p.conn.WriteFrame(ctx, reply); err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); <-acked }()

	// 256 running handles beside the finished one is one past the retention
	// ceiling, and the finished one is the only handle eviction may take.
	for i := 0; i < 256; i++ {
		if _, err := ex.Start(context.Background(), noWriteBackSpec()); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	wantPinned(t, ex, budget, 0, 0)
	if _, err := ex.WriteBackBundle(oldest); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Errorf("the evicted handle's bundle = %v, want ErrHandleNotFound", err)
	}
}

// TestRehydratedHandleKeepsItsCap: a hub that restarts mid-run — or another
// member adopting the run — holds the device to the cap the run's spec asked
// for. After a restart a device resends its whole bundle from offset 0, so this
// is exactly the moment the cap has to have survived. A row an older hub wrote
// recorded no cap, and its handle gets the hard ceiling rather than a refusal.
func TestRehydratedHandleKeepsItsCap(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	first := pinnedExecutor(t, "agent-1", remote.NewResultBudget(64<<10, 64<<10), store, nil)
	p, sess := connect(t, first, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	capped := startedHandle(t, first, p, bundleSpec(pinBase, 1024))
	none := startedHandle(t, first, p, noWriteBackSpec())
	sess.Close()

	rows, err := store.ListHandles("agent-1")
	if err != nil || len(rows) != 2 {
		t.Fatalf("persisted %d rows, %v; want 2", len(rows), err)
	}
	for _, r := range rows {
		want := map[string]string{"writeback_mode": "bundle", "writeback_cap": "1024", "project_seeded": "false"}
		if r.HandleID == none {
			want = map[string]string{"writeback_mode": "none", "writeback_cap": "0", "project_seeded": "false"}
		}
		for k, v := range want {
			if r.Meta[k] != v {
				t.Errorf("row %s Meta[%q] = %q, want %q", r.HandleID, k, r.Meta[k], v)
			}
		}
	}

	// An older hub's row for a third run: identity and no allowance.
	legacy := "legacy-handle-0001"
	if err := store.PutHandle(executor.HandleRecord{
		HandleID: legacy, ExecutorID: "agent-1", Driver: executor.KindRemoteAgent,
		ExternalID: legacy, StartedAt: time.Now(), SecretsRecorded: true,
	}); err != nil {
		t.Fatal(err)
	}

	// The restart: a new executor from nothing but the store.
	budget := remote.NewResultBudget(64<<10, 64<<10)
	second := pinnedExecutor(t, "agent-1", budget, store, nil)
	hello := defaultHello()
	for _, h := range []string{capped, none, legacy} {
		hello.Resume = append(hello.Resume, remote.ResumeHandle{HandleID: h, StartedAt: time.Now()})
	}
	p2, _ := connect(t, second, remote.AgentRecord{AgentID: "agent-1"}, hello, nil)

	over, _ := fakeBundle(1536)
	sendChunks(t, p2, capped, over, 512)
	sendChunks(t, p2, none, over[:512], 512)
	sendChunks(t, p2, legacy, over, 512)
	refused := barrier(t, p2, capped, none, legacy)
	if len(refused) != 2 {
		t.Fatalf("after the restart the hub refused %d frames, want 2: %+v", len(refused), refused)
	}
	if !strings.Contains(refused[0].Message, "1024-byte cap") {
		t.Errorf("the capped handle's refusal says %q; its cap did not survive the restart", refused[0].Message)
	}
	if !strings.Contains(refused[1].Message, "no bundle write-back") {
		t.Errorf("the no-write-back handle's refusal says %q", refused[1].Message)
	}
	// The legacy handle took the whole bundle, under the hard ceiling.
	wantPinned(t, second, budget, charged(1536, 3), charged(1536, 3))
}

// TestAHubMemberHopDoesNotRefillTheBudget: rehydration runs on every
// handshake, so a device that leaves a hub member and comes back — directly,
// or by way of another member — must find the bytes it left there still
// counted. Detaching frees nothing: the handle outlives the link. The bytes go
// when the handle ends, which here is the first heartbeat after the device
// finished the run somewhere else.
func TestAHubMemberHopDoesNotRefillTheBudget(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	budget := remote.NewResultBudget(1024, 64<<10)
	memberA := pinnedExecutor(t, "agent-1", budget, store, nil)
	memberB := pinnedExecutor(t, "agent-1", remote.NewResultBudget(1024, 64<<10), store, nil)
	data, _ := fakeBundle(768)

	pa, sessA := connect(t, memberA, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	run := startedHandle(t, memberA, pa, bundleSpec(pinBase, 0))
	sendChunks(t, pa, run, data, 256)
	barrier(t, pa, run)
	left := charged(768, 3)
	wantPinned(t, memberA, budget, left, left)

	// The link to A drops; the device goes to B, then comes back to A.
	sessA.Close()
	waitFor(t, 2*time.Second, func() bool { return !memberA.Connected() }, "A should see the device leave")
	wantPinned(t, memberA, budget, left, left)
	_, sessB := connect(t, memberB, remote.AgentRecord{AgentID: "agent-1"},
		helloOffering(remote.ProtocolVersion, run, 0), nil)
	sessB.Close()
	pa2, _ := connect(t, memberA, remote.AgentRecord{AgentID: "agent-1"},
		helloOffering(remote.ProtocolVersion, run, 0), nil)
	wantPinned(t, memberA, budget, left, left)

	// So a second run on A gets what is left of the budget, not a fresh one.
	next := startedHandle(t, memberA, pa2, bundleSpec(pinBase, 0))
	sendChunks(t, pa2, next, data[:512], 512)
	wantRefusals(t, barrier(t, pa2, run, next), 1, "max_pinned_writeback_bytes")
	wantPinned(t, memberA, budget, left, left)

	// The device finished the first run elsewhere; its next beat on A no
	// longer lists it, and the bundle that will never be completed goes.
	barrier(t, pa2, next)
	wantPinned(t, memberA, budget, 0, 0)
	if wb := statusOf(t, memberA, run).WriteBack; wb == nil || !strings.Contains(wb.Err, "no result frame") {
		t.Errorf("the abandoned transfer reports %+v; it should say why nothing came back", wb)
	}
}

// TestTerminalStatusWithoutAResultReleasesThePartialBundle: a transfer that
// ends without its result frame will never be completed, so its bytes go when
// the final status arrives, and the run says why rather than reading as one
// that returned nothing.
func TestTerminalStatusWithoutAResultReleasesThePartialBundle(t *testing.T) {
	budget := remote.NewResultBudget(4<<10, 16<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	data, _ := fakeBundle(512)

	sendChunks(t, p, handle, data, 256)
	barrier(t, p, handle)
	wantPinned(t, ex, budget, charged(512, 2), charged(512, 2))
	finish(t, p, handle, 0)
	got := awaitWriteBack(t, ex, handle)
	if !strings.Contains(got.Err, "512 bytes of its bundle received and no result frame") {
		t.Errorf("the run's write-back says %q", got.Err)
	}
	wantPinned(t, ex, budget, 0, 0)
}

// TestAbandonReleasesEvenAVerifiedBundle: a run the hub failed over to another
// executor is not its project's run any more, so nothing it sent back may be
// landed — and the bytes go now, not when the handle is evicted.
func TestAbandonReleasesEvenAVerifiedBundle(t *testing.T) {
	budget := remote.NewResultBudget(4<<10, 16<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	data, res := fakeBundle(512)

	sendChunks(t, p, handle, data, 256)
	sendResult(t, p, handle, res)
	barrier(t, p, handle)
	wantPinned(t, ex, budget, charged(512, 2), charged(512, 2))

	answerStatusWith(t, p, executor.StateRunning)
	if err := ex.Abandon(context.Background(), handle, "failed over to edge-2"); err != nil {
		t.Fatalf("Abandon: %v", err)
	}
	wantPinned(t, ex, budget, 0, 0)
	if _, err := ex.WriteBackBundle(handle); err == nil || !strings.Contains(err.Error(), "abandoned") {
		t.Errorf("the abandoned run's bundle = %v; it should be gone, saying why", err)
	}
}

// answerStatusWith replies to the next signal or status request with state.
func answerStatusWith(t *testing.T, p *peer, state executor.State) {
	t.Helper()
	go func() {
		f := p.readUntil(remote.TypeSignal)
		reply, err := remote.NewFrame(remote.TypeStatus, f.ID, f.Handle, remote.StatusPayload{
			Status: executor.Status{HandleID: f.Handle, State: state},
		})
		if err != nil {
			return
		}
		p.write(reply)
	}()
}

// TestUncollectedResultIsReleasedAfterRetention: a verified bundle nobody
// collects — its run's follower died with a hub process — is let go of
// resultRetention after the run ended, on the next heartbeat, not held until
// eviction against the device's budget.
func TestUncollectedResultIsReleasedAfterRetention(t *testing.T) {
	clock := newFakeClock()
	budget := remote.NewResultBudget(4<<10, 16<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, clock)
	// The session keeps real time, so advancing the executor's clock does not
	// trip the heartbeat watchdog.
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	data, res := fakeBundle(512)

	sendChunks(t, p, handle, data, 256)
	sendResult(t, p, handle, res)
	finish(t, p, handle, 0)
	barrier(t, p)
	wantPinned(t, ex, budget, charged(512, 2), charged(512, 2))

	clock.Advance(14 * time.Minute)
	barrier(t, p)
	wantPinned(t, ex, budget, charged(512, 2), charged(512, 2))

	clock.Advance(2 * time.Minute)
	barrier(t, p)
	wantPinned(t, ex, budget, 0, 0)
	if _, err := ex.WriteBackBundle(handle); err == nil || !strings.Contains(err.Error(), "nobody collecting") {
		t.Errorf("a late collector is told %v; it should hear why the bundle is gone", err)
	}
}

// TestProjectResultCountsAgainstTheBudget: a seeded run's project-state
// document is held until collected, like a bundle, so it is counted like one
// — and one the budget cannot hold is refused with the reason recorded.
func TestProjectResultCountsAgainstTheBudget(t *testing.T) {
	budget := remote.NewResultBudget(1024, 64<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	seeded := noWriteBackSpec()
	// A seed is only checked for being gzip on the way out; the device is
	// hand-written and never opens it.
	seeded.ProjectSeed = []byte{0x1f, 0x8b, 0x08, 0x00}
	data, _ := fakeBundle(600)

	sendProject := func(handle string, doc []byte) {
		f, err := remote.NewFrame(remote.TypeProjectResult, "", handle, remote.ProjectResultPayload{Data: doc})
		if err != nil {
			t.Fatal(err)
		}
		p.write(f)
	}
	one := startedHandle(t, ex, p, seeded)
	two := startedHandle(t, ex, p, seeded)
	sendProject(one, data)
	// A resend replaces the first reading; it is not counted twice.
	sendProject(one, data)
	if refused := barrier(t, p, one, two); len(refused) != 0 {
		t.Fatalf("a project result inside the budget was refused: %+v", refused)
	}
	wantPinned(t, ex, budget, 600, 600)

	// A resend too large for the budget is refused, and the reading already
	// held stays: it is as true as it was before the resend.
	bigger, _ := fakeBundle(1100)
	sendProject(one, bigger)
	wantRefusals(t, barrier(t, p, one, two), 1, "max_pinned_writeback_bytes")
	wantPinned(t, ex, budget, 600, 600)

	sendProject(two, data)
	wantRefusals(t, barrier(t, p, one, two), 1, "max_pinned_writeback_bytes")
	wantPinned(t, ex, budget, 600, 600)
	finish(t, p, two, 0)
	barrier(t, p, one)
	res, err := ex.ProjectResult(two)
	if err != nil || !strings.Contains(res.Err, "the hub refused to hold it") {
		t.Errorf("the refused run's result = %+v, %v; it should say the hub refused it", res, err)
	}

	finish(t, p, one, 0)
	barrier(t, p)
	got, err := ex.ProjectResult(one)
	if err != nil || len(got.Data) != len(data) {
		t.Fatalf("collected %d bytes, %v; want %d", len(got.Data), err, len(data))
	}
	wantPinned(t, ex, budget, 0, 0)
}

// TestStatusFrameCannotCarryAWriteBack: the hub reports only the write-back it
// received through result frames. A device that skips them and puts a
// delivered write-back in its status frame claims what nothing verified.
func TestStatusFrameCannotCarryAWriteBack(t *testing.T) {
	ex := pinnedExecutor(t, "agent-1", remote.NewResultBudget(4<<10, 16<<10), nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	push := bundleSpec(pinBase, 0)
	push.WriteBack = executor.WriteBack{Mode: executor.WriteBackPush, Branch: wbBranch}
	handle := startedHandle(t, ex, p, push)

	f, err := remote.NewFrame(remote.TypeStatus, "", handle, remote.StatusPayload{Status: executor.Status{
		HandleID: handle, State: executor.StateExited, FinishedAt: time.Now(),
		Error: strings.Repeat("x", 64<<10),
		WriteBack: &executor.WriteBackResult{
			Mode: executor.WriteBackPush, Branch: wbBranch, Pushed: true, CommitSHA: strings.Repeat("d", 40),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	p.write(f)
	barrier(t, p)
	st := statusOf(t, ex, handle)
	if st.WriteBack != nil {
		t.Errorf("a write-back carried in the status frame reached the run: %+v", st.WriteBack)
	}
	if len(st.Error) > 9<<10 {
		t.Errorf("the hub keeps a %d-byte status error for this handle; the device's prose is bounded", len(st.Error))
	}
}

// TestResultFrameNamesAndProseAreBounded: a result is kept with its handle, so
// what a device calls its branch is refused past what a branch may be, and its
// error text is shortened rather than kept at whatever length it chose.
func TestResultFrameNamesAndProseAreBounded(t *testing.T) {
	for name, res := range map[string]executor.WriteBackResult{
		"oversized branch":   {Mode: executor.WriteBackBundle, Branch: "cloop/" + strings.Repeat("b", 1<<12)},
		"oversized commit":   {Mode: executor.WriteBackBundle, CommitSHA: strings.Repeat("a", 65)},
		"oversized digest":   {Mode: executor.WriteBackBundle, BundleSHA256: strings.Repeat("a", 65)},
		"unknown mode":       {Mode: executor.WriteBackMode(strings.Repeat("m", 512))},
		"oversized base sha": {Mode: executor.WriteBackBundle, BaseSHA: strings.Repeat("a", 65)},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := remote.NewFrame(remote.TypeResult, "", "h1", remote.ResultPayload{Result: res})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := remote.DecodeResult(f); err == nil {
				t.Fatal("decoded a result no honest agent could have sent")
			}
		})
	}

	ex := pinnedExecutor(t, "agent-1", remote.NewResultBudget(4<<10, 16<<10), nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, bundleSpec(pinBase, 0))
	_, res := fakeBundle(1)
	// Three bytes a character, so the bound does not fall on a boundary.
	res.Err = strings.Repeat("€", 32<<10)
	res.BundleBytes, res.BundleSHA256 = 0, ""
	sendResult(t, p, handle, res)
	finish(t, p, handle, 0)
	got := awaitWriteBack(t, ex, handle)
	if len(got.Err) > 9<<10 || !strings.HasSuffix(got.Err, "[truncated by the hub]") {
		t.Errorf("the hub kept a %d-byte write-back error; want it bounded and marked", len(got.Err))
	}
	if !strings.HasPrefix(got.Err, "€") || !utf8.ValidString(got.Err) {
		t.Error("the shortened error was cut inside a character")
	}
}

// TestResultBudgetLimitsDefault: an unset limit is the documented default —
// never "unbounded" — and the limits a hub sets apply to new bytes only.
func TestResultBudgetLimitsDefault(t *testing.T) {
	b := remote.NewResultBudget(0, -1)
	if per, total := b.Limits(); per != executor.DefaultPinnedWriteBackBytes ||
		total != executor.DefaultPinnedWriteBackTotalBytes {
		t.Errorf("unset limits = %d/%d, want the defaults %d/%d", per, total,
			executor.DefaultPinnedWriteBackBytes, executor.DefaultPinnedWriteBackTotalBytes)
	}
	b.SetLimits(1<<20, 1<<30)
	if per, total := b.Limits(); per != 1<<20 || total != 1<<30 {
		t.Errorf("limits = %d/%d after SetLimits(1 MiB, 1 GiB)", per, total)
	}
	if u := b.Usage(); u.Pinned != 0 || u.Executors != 0 || u.PerExecutorLimit != 1<<20 {
		t.Errorf("an unused budget reports %+v", u)
	}
	if remote.DefaultResultBudget() != remote.DefaultResultBudget() {
		t.Error("the process-wide budget is not one budget")
	}
}
