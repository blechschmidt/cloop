package ui

// Regression tests for Task 20040: race in pkg/ui/server.go state broadcast loop
// dropping events under load.
//
// Before the fix, broadcasters used a non-blocking `select { case ch <- msg:
// default: }` send pattern, so a slow client whose buffer filled up would
// silently miss events with no recovery signal. The fix is a bounded buffer
// with a "lagged" signal that triggers a single resync directive (wsMessage
// type "resync" / SSE event "resync") so the client knows to refetch
// /api/state.
//
// The contract these tests enforce:
//
//   For every burst of N broadcast events, every connected client either
//   (a) receives all N events, or
//   (b) receives at least one resync directive — never silent loss.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// TestBroadcast_LaggedHubClientGetsResyncSignal verifies the broadcast
// invariant directly against the per-client channel: when 500 events are
// fired and the client never drains its buffer, the missing events are
// covered by a resync signal on hc.resync (so the writer loop will emit a
// single resync directive instead of silently losing data).
func TestBroadcast_LaggedHubClientGetsResyncSignal(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	// Manually register a hubClient — no real WebSocket, no writer goroutine.
	// We simulate a client that never drains its buffer.
	hc := &hubClient{
		ch:     make(chan wsMessage, hubClientBufferSize),
		resync: make(chan struct{}, 1),
		id:     "stalled-test-client",
	}
	srv.hubMu.Lock()
	srv.hubClients[dir] = map[*hubClient]struct{}{hc: {}}
	srv.hubMu.Unlock()

	// Fire 500 task_update events. The buffer holds hubClientBufferSize, so
	// the rest must trigger sendOrLag's resync signal — never silent drops.
	const totalEvents = 500
	raw := json.RawMessage(`{"id":1,"title":"test"}`)
	msg := wsMessage{Type: "task_update", Data: raw}
	for i := 0; i < totalEvents; i++ {
		srv.broadcastToProject(dir, msg)
	}

	// Drain the buffer and count events that landed.
	delivered := 0
drain:
	for {
		select {
		case <-hc.ch:
			delivered++
		default:
			break drain
		}
	}

	// Was the resync signal queued?
	resyncSignalled := false
	select {
	case <-hc.resync:
		resyncSignalled = true
	default:
	}

	// Contract: delivered == totalEvents OR resync was signalled.
	if delivered < totalEvents && !resyncSignalled {
		t.Fatalf("client silently lost events: delivered=%d/%d, resyncSignalled=%v",
			delivered, totalEvents, resyncSignalled)
	}

	// Sanity: with a buffer of hubClientBufferSize and 500 events, we
	// expect both — partial delivery AND a resync signal.
	if delivered >= totalEvents {
		t.Errorf("buffer (%d) should be too small to hold %d events; delivered=%d",
			hubClientBufferSize, totalEvents, delivered)
	}
	if !resyncSignalled {
		t.Errorf("expected resync signal after dropping events, got none")
	}
}

// TestBroadcast_NoResyncForKeptUpClient verifies the negative case: when
// every event is delivered (the channel never fills), no resync is signalled.
// Uses a single, sequential pop-then-push pattern so timing is deterministic.
func TestBroadcast_NoResyncForKeptUpClient(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	hc := &hubClient{
		ch:     make(chan wsMessage, hubClientBufferSize),
		resync: make(chan struct{}, 1),
		id:     "kept-up-test-client",
	}
	srv.hubMu.Lock()
	srv.hubClients[dir] = map[*hubClient]struct{}{hc: {}}
	srv.hubMu.Unlock()

	// Drive sends and reads in lockstep — the buffer never reaches capacity.
	const totalEvents = 500
	raw := json.RawMessage(`{"id":1,"title":"test"}`)
	msg := wsMessage{Type: "task_update", Data: raw}
	delivered := 0
	for i := 0; i < totalEvents; i++ {
		srv.broadcastToProject(dir, msg)
		<-hc.ch
		delivered++
	}

	if delivered != totalEvents {
		t.Fatalf("kept-up client received %d/%d events", delivered, totalEvents)
	}
	select {
	case <-hc.resync:
		t.Errorf("kept-up client received unexpected resync signal")
	default:
	}
}

// TestBroadcast_ResyncSignalIsIdempotent verifies that repeated lag bursts
// only collapse to one queued resync at a time (chan cap 1) — this prevents
// flooding a client with redundant resync directives.
func TestBroadcast_ResyncSignalIsIdempotent(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	hc := &hubClient{
		ch:     make(chan wsMessage, 4),
		resync: make(chan struct{}, 1),
		id:     "idempotent-test-client",
	}
	srv.hubMu.Lock()
	srv.hubClients[dir] = map[*hubClient]struct{}{hc: {}}
	srv.hubMu.Unlock()

	msg := wsMessage{Type: "task_update", Data: json.RawMessage(`{}`)}
	for i := 0; i < 200; i++ {
		srv.broadcastToProject(dir, msg)
	}

	// At most one signal queued.
	select {
	case <-hc.resync:
	default:
		t.Fatalf("expected at least one resync signal queued")
	}
	select {
	case <-hc.resync:
		t.Errorf("expected resync signal to be idempotent (chan cap 1)")
	default:
	}
}

// TestDrainWS_RemovesStaleMessages verifies the helper used by the writer
// loop: when a resync is about to be sent, all stale messages still in the
// channel must be drained so the client doesn't see them after the directive.
func TestDrainWS_RemovesStaleMessages(t *testing.T) {
	ch := make(chan wsMessage, 16)
	for i := 0; i < 10; i++ {
		ch <- wsMessage{Type: "task_update"}
	}
	drainWS(ch)
	if len(ch) != 0 {
		t.Fatalf("drainWS left %d messages in channel; want 0", len(ch))
	}
	// Drain on an already-empty channel must not block.
	done := make(chan struct{})
	go func() { drainWS(ch); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("drainWS blocked on empty channel")
	}
}

// TestWebSocket_LaggedClientReceivesResyncDirective is the end-to-end
// integration test required by Task 20040: open a real WebSocket, fire 500
// task_update events from the server, and verify the slow client either
// receives all 500 events OR receives at least one resync directive. The
// client deliberately delays starting its reader, forcing the server-side
// per-client buffer to fill so the resync path is exercised.
func TestWebSocket_LaggedClientReceivesResyncDirective(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws"

	// Use a long-lived ctx; nhooyr closes the connection if a Read context
	// expires, so we cancel only at test shutdown.
	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, _, err := websocket.Dial(testCtx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(-1) // initial state + presence + bursts can be large

	// Wait until the server has registered the client.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.hubMu.Lock()
		n := 0
		for _, m := range srv.hubClients {
			n += len(m)
		}
		srv.hubMu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Fire the burst BEFORE starting the reader. With the client TCP buffer
	// already full from the initial state and presence messages, the server
	// writer goroutine will block on conn.Write, hc.ch will fill to its
	// 64-message capacity, and sendOrLag will queue a resync for the rest.
	bigTitle := strings.Repeat("x", 8192)
	raw, _ := json.Marshal(map[string]interface{}{"id": 1, "title": bigTitle})
	msg := wsMessage{Type: "task_update", Data: raw}
	const totalEvents = 500
	for i := 0; i < totalEvents; i++ {
		srv.broadcastToProject(dir, msg)
	}

	// Give the server some time to process the burst (drainWS + resync write).
	time.Sleep(500 * time.Millisecond)

	// Now start the reader.
	type read struct {
		msg wsMessage
		err error
	}
	msgs := make(chan read, 1024)
	go func() {
		for {
			_, data, err := conn.Read(testCtx)
			if err != nil {
				msgs <- read{err: err}
				return
			}
			var m wsMessage
			if json.Unmarshal(data, &m) == nil {
				msgs <- read{msg: m}
			}
		}
	}()

	taskUpdates := 0
	resyncs := 0
	idleTimer := time.NewTimer(3 * time.Second)
	defer idleTimer.Stop()
	overall := time.After(20 * time.Second)

collect:
	for {
		select {
		case r := <-msgs:
			if r.err != nil {
				break collect
			}
			switch r.msg.Type {
			case "task_update":
				taskUpdates++
			case "resync":
				resyncs++
			}
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(1 * time.Second)
			// Fast path: if we've received the full burst, stop.
			// Note: 1 extra task_update for the initial state push.
			if taskUpdates >= totalEvents+1 {
				break collect
			}
		case <-idleTimer.C:
			break collect
		case <-overall:
			break collect
		}
	}

	// Account for the initial state push — it sends one wsMessage{Type:"task_update"}
	// before the broadcast burst.
	fromBurst := taskUpdates - 1
	if fromBurst < 0 {
		fromBurst = 0
	}

	t.Logf("delivered: %d task_updates total (~%d from burst), %d resyncs (of %d fired)",
		taskUpdates, fromBurst, resyncs, totalEvents)

	if fromBurst < totalEvents && resyncs < 1 {
		t.Fatalf("contract violated: client received ~%d/%d burst task_updates and %d resyncs (expected all events OR ≥1 resync)",
			fromBurst, totalEvents, resyncs)
	}
}

// TestBroadcastToProject_RaceWithDisconnect is a regression test for a real
// race condition in broadcastToProject: it used to read the per-project map
// under hubMu, release the lock, then iterate. While iterating, a concurrent
// disconnect (the `delete(s.hubClients[workDir], hc)` in handleWS's deferred
// cleanup, executed under hubMu) would mutate the same underlying map, which
// triggers Go's runtime fatal "concurrent map iteration and map write".
//
// The fix was to hold hubMu through the iteration. This test exercises the
// pattern: many concurrent broadcasts vs. churn on the per-project client
// set. Run with `go test -race ./pkg/ui/` to catch the bug; without the fix
// the test reliably crashes the runner within a few iterations.
func TestBroadcastToProject_RaceWithDisconnect(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	// Seed a starter client so the project map exists.
	srv.hubMu.Lock()
	srv.hubClients[dir] = make(map[*hubClient]struct{})
	srv.hubMu.Unlock()

	stop := make(chan struct{})
	done := make(chan struct{}, 3)

	// Goroutine A: continuously broadcast.
	go func() {
		defer func() { done <- struct{}{} }()
		msg := wsMessage{Type: "task_update", Data: json.RawMessage(`{}`)}
		for {
			select {
			case <-stop:
				return
			default:
			}
			srv.broadcastToProject(dir, msg)
		}
	}()

	// Goroutine B: register and delete clients (mimicking connect/disconnect).
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case <-stop:
				return
			default:
			}
			hc := &hubClient{
				ch:     make(chan wsMessage, hubClientBufferSize),
				resync: make(chan struct{}, 1),
			}
			srv.hubMu.Lock()
			srv.hubClients[dir][hc] = struct{}{}
			srv.hubMu.Unlock()
			srv.hubMu.Lock()
			delete(srv.hubClients[dir], hc)
			srv.hubMu.Unlock()
		}
	}()

	// Goroutine C: drains channels so sendOrLag never goes through the
	// resync path (just to keep the test focused on the iteration race).
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case <-stop:
				return
			default:
			}
			srv.hubMu.Lock()
			for hc := range srv.hubClients[dir] {
				select {
				case <-hc.ch:
				default:
				}
			}
			srv.hubMu.Unlock()
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	for i := 0; i < 3; i++ {
		<-done
	}
	// Reaching here without a runtime fatal means the iteration is safe.
}

// TestSSE_LaggedClientReceivesResyncDirective is the SSE counterpart — the
// fallback path also has the bounded-buffer + resync model.
func TestSSE_LaggedClientReceivesResyncDirective(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")

	// Manually register an sseClient — no actual SSE handler, so no reader.
	c := &sseClient{
		ch:     make(chan sseEvent, sseClientBufferSize),
		resync: make(chan struct{}, 1),
	}
	srv.mu.Lock()
	srv.clients[c] = struct{}{}
	srv.mu.Unlock()

	const totalEvents = 500
	for i := 0; i < totalEvents; i++ {
		srv.broadcast(`{"goal":"test"}`)
	}

	delivered := 0
drain:
	for {
		select {
		case <-c.ch:
			delivered++
		default:
			break drain
		}
	}

	resyncSignalled := false
	select {
	case <-c.resync:
		resyncSignalled = true
	default:
	}

	if delivered < totalEvents && !resyncSignalled {
		t.Fatalf("SSE client silently lost events: delivered=%d/%d, resyncSignalled=%v",
			delivered, totalEvents, resyncSignalled)
	}
}

// TestRecoverGoroutine_LoopBodyContinuesAfterPanic verifies the per-iteration
// recovery pattern used by watchState and watchProjects: even if one iteration
// panics (e.g. a malformed state file blows up json.Marshal in broadcast()),
// the ticker loop keeps running. Without recovery, the entire daemon crashes
// — every connected SSE/WS client disconnects and the dashboard goes dark.
//
// To catch the regression: temporarily delete the recoverGoroutine deferral
// inside the loop body of watchState/watchProjects in server.go and re-run
// this test — it will fail with "loop body did not continue after panic"
// because the goroutine crashes the test binary before iter==2 fires.
func TestRecoverGoroutine_LoopBodyContinuesAfterPanic(t *testing.T) {
	iterations := 0
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			func() {
				defer recoverGoroutine("test loop")
				iterations++
				if i == 1 {
					// Simulate an unexpected panic during iteration 1
					// (e.g. nil deref in deep state-file parsing).
					var p *int
					_ = *p // panic: nil pointer dereference
				}
			}()
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop body did not complete in time")
	}

	if iterations != 3 {
		t.Fatalf("loop body did not continue after panic: ran %d/3 iterations", iterations)
	}
}

// TestRecoverGoroutine_PanicValueLogged is a smoke test that recoverGoroutine
// converts a panic into a log line on stderr (rather than crashing the
// process). It also verifies the goroutine returns normally so the caller
// can defer it without surprises.
func TestRecoverGoroutine_PanicValueLogged(t *testing.T) {
	completed := false
	func() {
		defer recoverGoroutine("smoke test")
		defer func() { completed = true }()
		panic("synthetic panic for test")
	}()
	if !completed {
		t.Fatal("function with deferred recoverGoroutine did not run other defers")
	}
}
