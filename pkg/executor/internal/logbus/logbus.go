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
	"github.com/blechschmidt/cloop/pkg/redact"
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

	redact *redact.Set

	mu          sync.Mutex
	seq         uint64
	replay      []executor.LogLine
	replayBytes int
	subscribers map[*subscriber]struct{}
	closed      bool
	// pending holds the trailing bytes of the last Emit that could still
	// turn out to be the first bytes of a credential. Non-empty only while
	// a redaction set is installed and the workload happens to have stopped
	// mid-secret; Close releases whatever is left.
	pending string
}

// Options tunes a Bus. Zero fields take the package defaults.
type Options struct {
	// SubscriberBuffer overrides DefaultSubscriberBuffer.
	SubscriberBuffer int
	// ReplayBytes overrides DefaultReplayBytes.
	ReplayBytes int
	// Now overrides the clock, for deterministic tests.
	Now func() time.Time
	// Redact removes the workload's own leased credentials from its output.
	// Nil means the workload holds none, which is the common case and costs
	// nothing.
	//
	// It belongs here, on the bus, rather than on each consumer: every path
	// that output takes out of a driver — the live-log room, the replay
	// backlog a late subscriber reads, the buffer executor.Run persists —
	// starts at Emit. Filtering at any one consumer would leave the others.
	Redact *redact.Set
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
		redact:      opts.Redact,
		subscribers: make(map[*subscriber]struct{}),
	}
}

// Redactor returns the set installed at construction, or nil when the workload
// carries no credential.
//
// It exists so a second consumer of the same workload's output — an interactive
// attach session (Task 20265) — can scrub with the identical set rather than
// rebuild one from a Spec it does not have. The bus is where the driver already
// recorded "these bytes must never appear in this handle's output", so it is the
// honest place to ask, and asking keeps the two paths from drifting: a credential
// added to the log filter is filtered in the terminal by construction.
//
// The set is immutable after New, so handing it out shares no mutable state.
func (b *Bus) Redactor() *redact.Set {
	if b == nil {
		return nil
	}
	return b.redact
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
	if b.redact != nil {
		// Scrubbed here, before the chunk is numbered, so the replay backlog
		// and every live subscriber see the same redacted bytes and nothing
		// downstream has to remember to filter.
		//
		// The holdback is what makes a credential split across two reads of
		// the workload's pipe still match. It withholds bytes only when the
		// tail could actually begin a known secret, so ordinary output —
		// including a prompt with no trailing newline — is published with no
		// added latency.
		text = b.redact.String(b.pending + text)
		if hold := b.redact.Holdback(text); hold > 0 {
			b.pending = text[len(text)-hold:]
			text = text[:len(text)-hold]
		} else {
			b.pending = ""
		}
		if text == "" {
			b.mu.Unlock()
			return
		}
	}
	b.publishLocked(text)
}

// emitRaw publishes text without passing it through the redactor, for the one
// caller that has already scrubbed it: Close, flushing the held-back tail.
func (b *Bus) emitRaw(text string) {
	if text == "" {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.publishLocked(text)
}

// publishLocked numbers text, appends it to the bounded replay backlog and
// hands it to every live subscriber. Called with b.mu held; returns with it
// released, because the sends must not happen under the bus lock.
func (b *Bus) publishLocked(text string) {
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
	// Release whatever the redactor was still holding back. A workload whose
	// last bytes happened to look like the start of a credential must not
	// lose them: the tail of the output is where the error message is, which
	// is the same reason executor.Run truncates from the front.
	if b.redact != nil {
		b.mu.Lock()
		tail := b.pending
		b.pending = ""
		b.mu.Unlock()
		if tail != "" {
			b.emitRaw(b.redact.String(tail))
		}
	}

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
