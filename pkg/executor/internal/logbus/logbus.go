// Package logbus fans one workload's output out to any number of live
// subscribers, with a bounded replay backlog for late joiners.
//
// Every executor driver needs the same thing: a workload writes to a pipe,
// zero or more Stream consumers want the bytes, consumers come and go at
// arbitrary times, and none of them may ever back-pressure the workload. The
// logic is small but the concurrency is subtle enough that it was worth
// getting wrong only once — pkg/executor/localprocess shipped a "send on
// closed channel" panic that took down the whole UI server when a viewer
// closed a browser tab mid-run. This package is that logic, extracted so
// drivers added later (containers, remote agents) inherit the fix instead of
// re-deriving it.
//
// Three invariants define the contract:
//
//  1. Emit never blocks. A subscriber whose buffer is full has chunks
//     dropped, because blocking here would propagate back into the
//     workload's own writes once its pipe filled — one stalled log viewer
//     would stall the agent. Consumers detect loss via gaps in LogLine.Seq.
//
//  2. Send and close are serialised per subscriber. A plain non-blocking
//     select cannot express this: when both a send and a close are ready Go
//     picks at random, so the send can land on an already-closed channel.
//
//  3. Replay is captured under the same lock that registers the subscriber,
//     so a chunk emitted concurrently with Subscribe is either in the
//     backlog or delivered live — never both, never neither.
package logbus

import (
	"context"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const (
	// DefaultSubscriberBuffer is how many chunks a single consumer may fall
	// behind before its chunks start being dropped.
	DefaultSubscriberBuffer = 512

	// DefaultReplayBytes bounds the output retained for consumers that
	// subscribe after the workload started. It only has to cover the gap
	// between Start returning and Stream being called, so it is small.
	DefaultReplayBytes = 64 << 10
)

// Bus is the fan-out point for one workload's output. The zero value is not
// usable; call New.
type Bus struct {
	handleID  string
	stream    executor.StreamName
	bufSize   int
	replayCap int
	nowFn     func() time.Time

	mu          sync.Mutex
	seq         uint64
	replay      []executor.LogLine
	replayBytes int
	subscribers map[*subscriber]struct{}
	closed      bool
}

// Options tunes a Bus. Zero fields take the package defaults.
type Options struct {
	// SubscriberBuffer overrides DefaultSubscriberBuffer.
	SubscriberBuffer int
	// ReplayBytes overrides DefaultReplayBytes.
	ReplayBytes int
	// Now overrides the clock, for deterministic tests.
	Now func() time.Time
}

// New returns a Bus that stamps chunks with handleID and stream.
func New(handleID string, stream executor.StreamName, opts Options) *Bus {
	if opts.SubscriberBuffer <= 0 {
		opts.SubscriberBuffer = DefaultSubscriberBuffer
	}
	if opts.ReplayBytes <= 0 {
		opts.ReplayBytes = DefaultReplayBytes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if stream == "" {
		stream = executor.StreamCombined
	}
	return &Bus{
		handleID:    handleID,
		stream:      stream,
		bufSize:     opts.SubscriberBuffer,
		replayCap:   opts.ReplayBytes,
		nowFn:       opts.Now,
		subscribers: make(map[*subscriber]struct{}),
	}
}

// subscriber is one live consumer. The mutex guards the send/close pair; see
// invariant 2 in the package doc.
type subscriber struct {
	mu     sync.Mutex
	ch     chan executor.LogLine
	done   chan struct{}
	closed bool
}

func (s *subscriber) send(line executor.LogLine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- line:
	default:
		// Dropped on purpose; see invariant 1.
	}
}

func (s *subscriber) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.done)
	close(s.ch)
}

// Emit publishes one output chunk. Empty chunks are ignored. Emitting after
// Close is a no-op rather than a panic: a driver's output pump and its
// process reaper race by nature, and the pump losing that race must not take
// the process down.
func (b *Bus) Emit(text string) {
	if text == "" {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.seq++
	line := executor.LogLine{
		HandleID: b.handleID,
		Stream:   b.stream,
		Text:     text,
		Time:     b.nowFn(),
		Seq:      b.seq,
	}
	b.replay = append(b.replay, line)
	b.replayBytes += len(text)
	for b.replayBytes > b.replayCap && len(b.replay) > 1 {
		b.replayBytes -= len(b.replay[0].Text)
		b.replay = b.replay[1:]
	}
	subs := make([]*subscriber, 0, len(b.subscribers))
	for sub := range b.subscribers {
		subs = append(subs, sub)
	}
	b.mu.Unlock()

	// Sent outside b.mu so a slow consumer cannot serialise the pump against
	// Subscribe; sub.send does its own locking against a concurrent close.
	for _, sub := range subs {
		sub.send(line)
	}
}

// Subscribe returns a channel that first replays the bounded backlog, then
// delivers live chunks, then closes when the bus is closed.
//
// Cancelling ctx unsubscribes this consumer only — the workload and every
// other consumer are unaffected. Subscribing to an already-closed bus is
// valid and yields the backlog followed by a close, so a caller that arrives
// after a short-lived workload finished still sees its output.
func (b *Bus) Subscribe(ctx context.Context) <-chan executor.LogLine {
	if ctx == nil {
		ctx = context.Background()
	}
	sub := &subscriber{
		ch:   make(chan executor.LogLine, b.bufSize),
		done: make(chan struct{}),
	}

	b.mu.Lock()
	// Replay under the lock so a chunk emitted concurrently cannot slip
	// between the backlog copy and the subscription; see invariant 3. The
	// backlog can exceed the subscriber buffer, in which case the oldest
	// replayed chunks are dropped — the same loss signal (a Seq gap) a slow
	// live consumer produces.
	for _, line := range b.replay {
		sub.send(line)
	}
	alreadyClosed := b.closed
	if !alreadyClosed {
		b.subscribers[sub] = struct{}{}
	}
	b.mu.Unlock()

	if alreadyClosed {
		sub.close()
		return sub.ch
	}

	// Bounded by whichever comes first: ctx cancellation or Close.
	go func() {
		select {
		case <-ctx.Done():
			b.unsubscribe(sub)
		case <-sub.done:
		}
	}()

	return sub.ch
}

// unsubscribe detaches and closes sub. Idempotent.
func (b *Bus) unsubscribe(sub *subscriber) {
	b.mu.Lock()
	delete(b.subscribers, sub)
	b.mu.Unlock()
	sub.close()
}

// Close releases every subscriber. Idempotent.
//
// Drivers must call it only after the workload's terminal status has been
// recorded: a consumer that sees its channel close is entitled to read a
// terminal Status immediately, and executor.Run depends on that ordering.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	subs := make([]*subscriber, 0, len(b.subscribers))
	for sub := range b.subscribers {
		subs = append(subs, sub)
	}
	b.subscribers = make(map[*subscriber]struct{})
	b.mu.Unlock()

	for _, sub := range subs {
		sub.close()
	}
}

// Closed reports whether Close has been called.
func (b *Bus) Closed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}
