package logbus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// collect drains ch until it closes or the deadline expires, returning the
// concatenated text and whether the channel closed.
func collect(t *testing.T, ch <-chan executor.LogLine, d time.Duration) (string, bool) {
	t.Helper()
	var sb strings.Builder
	deadline := time.After(d)
	for {
		select {
		case line, ok := <-ch:
			if !ok {
				return sb.String(), true
			}
			sb.WriteString(line.Text)
		case <-deadline:
			return sb.String(), false
		}
	}
}

func TestSubscribeReceivesLiveChunks(t *testing.T) {
	b := New("h1", executor.StreamCombined, Options{})
	ch := b.Subscribe(context.Background())

	b.Emit("hello ")
	b.Emit("world")
	b.Close()

	got, closed := collect(t, ch, 2*time.Second)
	if !closed {
		t.Fatal("channel did not close after Close()")
	}
	if got != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}
}

func TestSubscribeReplaysBacklog(t *testing.T) {
	b := New("h1", executor.StreamCombined, Options{})
	b.Emit("before-subscribe ")

	ch := b.Subscribe(context.Background())
	b.Emit("after-subscribe")
	b.Close()

	got, closed := collect(t, ch, 2*time.Second)
	if !closed {
		t.Fatal("channel did not close")
	}
	if got != "before-subscribe after-subscribe" {
		t.Fatalf("late subscriber missed the backlog: got %q", got)
	}
}

func TestSubscribeAfterCloseStillReplays(t *testing.T) {
	// A short-lived workload can finish before the UI subscribes; the
	// subscriber must still see its output rather than an empty stream.
	b := New("h1", executor.StreamCombined, Options{})
	b.Emit("all the output")
	b.Close()

	ch := b.Subscribe(context.Background())
	got, closed := collect(t, ch, 2*time.Second)
	if !closed {
		t.Fatal("subscribing to a closed bus must yield a closed channel")
	}
	if got != "all the output" {
		t.Fatalf("got %q, want the replayed backlog", got)
	}
}

func TestSeqNumbersAreMonotonic(t *testing.T) {
	b := New("h1", executor.StreamCombined, Options{})
	ch := b.Subscribe(context.Background())
	for i := 0; i < 10; i++ {
		b.Emit(fmt.Sprintf("chunk-%d\n", i))
	}
	b.Close()

	var seqs []uint64
	for line := range ch {
		seqs = append(seqs, line.Seq)
	}
	if len(seqs) != 10 {
		t.Fatalf("got %d chunks, want 10", len(seqs))
	}
	for i, seq := range seqs {
		if seq != uint64(i+1) {
			t.Fatalf("Seq[%d] = %d, want %d — consumers detect drops via Seq gaps", i, seq, i+1)
		}
	}
}

func TestEmitDoesNotBlockOnASlowConsumer(t *testing.T) {
	// The core invariant: a stalled log viewer must never back-pressure into
	// the workload's writes. Emit more than the buffer and require Emit to
	// keep returning promptly.
	b := New("h1", executor.StreamCombined, Options{SubscriberBuffer: 4})
	_ = b.Subscribe(context.Background()) // never drained

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			b.Emit("x")
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked on a subscriber that never drains — this would stall the workload")
	}
	b.Close()
}

// TestDroppedChunksAreDetectableViaSeqGap is the contract executor.Run relies
// on to set RunResult.Dropped: chunks lost to a full buffer must leave a hole
// in the sequence, never be silently renumbered into a contiguous run.
//
// The scenario is a consumer that falls behind and then catches up, because
// that is the only way a *gap* can form. A consumer that never drains at all
// simply stops receiving, and its truncated prefix carries no gap to detect —
// a real limitation of the design, and the reason drops are also surfaced by
// the driver rather than only by Seq.
func TestDroppedChunksAreDetectableViaSeqGap(t *testing.T) {
	const buffer = 4
	b := New("h1", executor.StreamCombined, Options{SubscriberBuffer: buffer})
	ch := b.Subscribe(context.Background())

	// 1..4 fill the buffer; sends are non-blocking, so this is deterministic.
	for i := 1; i <= buffer; i++ {
		b.Emit(fmt.Sprintf("%d;", i))
	}
	// 5..14 arrive with the buffer full and are dropped.
	for i := buffer + 1; i <= 14; i++ {
		b.Emit(fmt.Sprintf("%d;", i))
	}
	// The consumer catches up, freeing the buffer.
	var seqs []uint64
	for i := 0; i < buffer; i++ {
		seqs = append(seqs, (<-ch).Seq)
	}
	// 15..16 now fit again.
	b.Emit("15;")
	b.Emit("16;")
	b.Close()
	for line := range ch {
		seqs = append(seqs, line.Seq)
	}

	want := []uint64{1, 2, 3, 4, 15, 16}
	if len(seqs) != len(want) {
		t.Fatalf("got %d chunks (%v), want %d (%v)", len(seqs), seqs, len(want), want)
	}
	for i := range want {
		if seqs[i] != want[i] {
			t.Fatalf("Seq[%d] = %d, want %d (full sequence %v) — renumbering would hide the loss",
				i, seqs[i], want[i], seqs)
		}
	}

	// Confirm the gap is discoverable the same way executor.Run finds it.
	var sawGap bool
	next := uint64(1)
	for _, s := range seqs {
		if s != next {
			sawGap = true
		}
		next = s + 1
	}
	if !sawGap {
		t.Fatal("no Seq gap observed; executor.Run could not set RunResult.Dropped")
	}
}

func TestReplayIsBounded(t *testing.T) {
	b := New("h1", executor.StreamCombined, Options{ReplayBytes: 64})
	for i := 0; i < 100; i++ {
		b.Emit(strings.Repeat("a", 32))
	}

	b.mu.Lock()
	bytes := b.replayBytes
	b.mu.Unlock()
	// The backlog keeps at most one chunk beyond the cap (it never empties
	// entirely), so allow one chunk of slack.
	if bytes > 64+32 {
		t.Fatalf("replay backlog grew to %d bytes with a 64-byte cap", bytes)
	}
}

func TestCancellingASubscriberDoesNotAffectOthers(t *testing.T) {
	b := New("h1", executor.StreamCombined, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	doomed := b.Subscribe(ctx)
	survivor := b.Subscribe(context.Background())

	b.Emit("first ")
	cancel()

	// The cancelled subscriber's channel must close on its own.
	if _, closed := collect(t, doomed, 2*time.Second); !closed {
		t.Fatal("a cancelled subscriber's channel did not close")
	}

	b.Emit("second")
	b.Close()

	got, closed := collect(t, survivor, 2*time.Second)
	if !closed {
		t.Fatal("the surviving subscriber's channel did not close")
	}
	if got != "first second" {
		t.Fatalf("the surviving subscriber lost data: got %q", got)
	}
}

// TestNoSendOnClosedChannelPanic reproduces the crash that motivated this
// package: a subscriber whose context is cancelled while the pump is mid-send
// on the very same channel. Without the per-subscriber send/close mutex this
// panics and takes the whole server down.
func TestNoSendOnClosedChannelPanic(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		b := New("h1", executor.StreamCombined, Options{SubscriberBuffer: 1})
		ctx, cancel := context.WithCancel(context.Background())
		_ = b.Subscribe(ctx)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				b.Emit("x")
			}
		}()
		go func() {
			defer wg.Done()
			cancel()
		}()
		wg.Wait()
		b.Close()
	}
}

// TestConcurrentSubscribeEmitClose is a race-detector target covering the
// full matrix of concurrent operations.
func TestConcurrentSubscribeEmitClose(t *testing.T) {
	b := New("h1", executor.StreamCombined, Options{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch := b.Subscribe(ctx)
			for range ch {
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.Emit("chunk")
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		b.Close()
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent operations deadlocked")
	}
}

func TestEmitAfterCloseIsANoOp(t *testing.T) {
	// The output pump and the process reaper race by nature; the pump losing
	// that race must not panic.
	b := New("h1", executor.StreamCombined, Options{})
	b.Close()
	b.Emit("late") // must not panic

	if !b.Closed() {
		t.Fatal("Closed() should report true after Close()")
	}
	ch := b.Subscribe(context.Background())
	got, _ := collect(t, ch, time.Second)
	if got != "" {
		t.Fatalf("a post-close Emit leaked into the backlog: %q", got)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	b := New("h1", executor.StreamCombined, Options{})
	ch := b.Subscribe(context.Background())
	b.Close()
	b.Close() // must not panic on a double close of the subscriber channels
	if _, closed := collect(t, ch, time.Second); !closed {
		t.Fatal("channel not closed")
	}
}

func TestEmptyChunksAreIgnored(t *testing.T) {
	b := New("h1", executor.StreamCombined, Options{})
	ch := b.Subscribe(context.Background())
	b.Emit("")
	b.Emit("real")
	b.Close()

	var n int
	for range ch {
		n++
	}
	if n != 1 {
		t.Fatalf("got %d chunks, want 1 — empty chunks should not be published", n)
	}
}

func TestLineMetadata(t *testing.T) {
	fixed := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	b := New("handle-42", executor.StreamStdout, Options{Now: func() time.Time { return fixed }})
	ch := b.Subscribe(context.Background())
	b.Emit("x")
	b.Close()

	line := <-ch
	if line.HandleID != "handle-42" {
		t.Errorf("HandleID = %q", line.HandleID)
	}
	if line.Stream != executor.StreamStdout {
		t.Errorf("Stream = %q", line.Stream)
	}
	if !line.Time.Equal(fixed) {
		t.Errorf("Time = %v, want %v", line.Time, fixed)
	}
}

func TestDefaultStreamIsCombined(t *testing.T) {
	b := New("h", "", Options{})
	ch := b.Subscribe(context.Background())
	b.Emit("x")
	b.Close()
	if line := <-ch; line.Stream != executor.StreamCombined {
		t.Fatalf("Stream = %q, want %q", line.Stream, executor.StreamCombined)
	}
}
