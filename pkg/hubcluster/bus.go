package hubcluster

// bus.go: what one member produces that every member's clients must see.
//
// A dashboard socket is attached to one member, and the event it is waiting
// for is produced by whichever member owns the thing it describes. The bus is
// how the second reaches the first: publishers append to hub_bus, every member
// polls it by sequence number and hands what it finds to its subscribers.
//
// Two properties shape it.
//
// Publishing never blocks the caller. Events are queued and written in batches
// by a flusher, because the callers are broadcast paths running inside request
// handlers and output pumps, and a database write per line of harness output
// would put fsync latency into the one loop that must keep up with a chatty
// run. A full queue drops the newest event and counts it: an event that would
// have to wait for a stalled database is already late, and blocking would
// spread the stall to every request.
//
// A reader that falls behind finds out. Events are pruned after a retention
// window, and seq is AUTOINCREMENT with SQLite serialising writers, so the
// sequence numbers a reader sees are consecutive unless pruning took some it
// had not read. A jump is therefore proof of loss, and subscribers are told
// (OnGap) so they can resynchronise their clients rather than show a view
// that silently stopped matching.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// busQueueMax bounds the events waiting to be written.
	busQueueMax = 8192
	// busReadBatch is how many events one read returns.
	busReadBatch = 512
)

// Event is one message delivered from the bus.
type Event struct {
	Seq     int64
	Origin  string
	Target  string
	Topic   string
	Key     string
	Payload json.RawMessage
	At      time.Time
}

// Decode unmarshals the payload into v.
func (e Event) Decode(v any) error { return json.Unmarshal(e.Payload, v) }

type bus struct {
	n *Node

	mu     sync.Mutex
	subs   map[string][]func(Event)
	gaps   []func()
	queue  []statedb.HubEventRow
	cursor int64

	kick   chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// flushMu serialises writers so events leave in the order they were
	// queued; pollMu serialises readers so the cursor only moves forward.
	// Both are per bus: two nodes in one process (tests) are independent.
	flushMu sync.Mutex
	pollMu  sync.Mutex

	published atomic.Uint64
	delivered atomic.Uint64
	dropped   atomic.Uint64
	gapCount  atomic.Uint64
}

func newBus(n *Node) *bus {
	return &bus{
		n:    n,
		subs: map[string][]func(Event){},
		kick: make(chan struct{}, 1),
	}
}

// init positions the cursor past everything already published: a member that
// joins is interested in what happens from now on, not in replaying the last
// two minutes of other members' output into its clients.
func (b *bus) init() error {
	_, _, issued, err := b.n.store.HubEventBounds()
	if err != nil {
		return fmt.Errorf("hubcluster: read bus position: %w", err)
	}
	b.mu.Lock()
	b.cursor = issued
	b.mu.Unlock()
	return nil
}

func (b *bus) start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	b.mu.Lock()
	b.cancel = cancel
	b.mu.Unlock()
	b.wg.Add(2)
	go b.flushLoop(ctx)
	go b.pollLoop(ctx)
}

// close stops the loops and writes whatever is still queued.
func (b *bus) close() {
	b.mu.Lock()
	cancel := b.cancel
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	b.wg.Wait()
	b.flush()
}

// Publish sends an event to every other member. It is dropped without a
// write when no other member is alive, because nobody would read it.
func (n *Node) Publish(topic, key string, payload any) {
	n.publish("", topic, key, payload)
}

// PublishTo sends an event to one member. Unlike Publish it is written even
// when that member is not currently judged alive: a member that joined since
// the last refresh is alive whether or not this node has noticed.
func (n *Node) PublishTo(target, topic, key string, payload any) {
	if target == "" || target == n.ID() {
		return
	}
	n.publish(target, topic, key, payload)
}

func (n *Node) publish(target, topic, key string, payload any) {
	if n == nil || n.bus == nil {
		return
	}
	if target == "" && !n.HasPeers() {
		return
	}
	var raw []byte
	switch p := payload.(type) {
	case nil:
		raw = []byte("null")
	case json.RawMessage:
		raw = p
	case []byte:
		raw = p
	default:
		var err error
		if raw, err = json.Marshal(payload); err != nil {
			n.logf("hubcluster: publish %s: %v", topic, err)
			return
		}
	}
	b := n.bus
	b.mu.Lock()
	if len(b.queue) >= busQueueMax {
		b.mu.Unlock()
		b.dropped.Add(1)
		return
	}
	b.queue = append(b.queue, statedb.HubEventRow{
		Origin:    n.self.ID,
		Target:    target,
		Topic:     topic,
		Key:       key,
		Payload:   string(raw),
		CreatedAt: n.now(),
	})
	b.mu.Unlock()
	b.published.Add(1)
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

// Subscribe registers fn for topic; "*" receives every topic. fn runs on the
// bus goroutine, in sequence order, and must not block: a slow subscriber
// delays every event behind it.
func (n *Node) Subscribe(topic string, fn func(Event)) {
	if n == nil || n.bus == nil || fn == nil {
		return
	}
	n.bus.mu.Lock()
	n.bus.subs[topic] = append(n.bus.subs[topic], fn)
	n.bus.mu.Unlock()
}

// OnBusGap registers fn to run when this member discovers it missed events.
func (n *Node) OnBusGap(fn func()) {
	if n == nil || n.bus == nil || fn == nil {
		return
	}
	n.bus.mu.Lock()
	n.bus.gaps = append(n.bus.gaps, fn)
	n.bus.mu.Unlock()
}

// BusStats reports counters for status output and tests.
type BusStats struct {
	Published uint64 `json:"published"`
	Delivered uint64 `json:"delivered"`
	Dropped   uint64 `json:"dropped"`
	Gaps      uint64 `json:"gaps"`
	Cursor    int64  `json:"cursor"`
}

// BusStats returns this member's bus counters.
func (n *Node) BusStats() BusStats {
	if n == nil || n.bus == nil {
		return BusStats{}
	}
	b := n.bus
	b.mu.Lock()
	cursor := b.cursor
	b.mu.Unlock()
	return BusStats{
		Published: b.published.Load(),
		Delivered: b.delivered.Load(),
		Dropped:   b.dropped.Load(),
		Gaps:      b.gapCount.Load(),
		Cursor:    cursor,
	}
}

// FlushBus writes queued events now. Tests use it to make publication
// deterministic; production relies on the flusher.
func (n *Node) FlushBus() {
	if n != nil && n.bus != nil {
		n.bus.flush()
	}
}

// PollBus reads and delivers pending events now, for the same reason.
func (n *Node) PollBus() {
	if n != nil && n.bus != nil {
		n.bus.poll()
	}
}

func (b *bus) flushLoop(ctx context.Context) {
	defer b.wg.Done()
	ticker := time.NewTicker(b.n.opts.BusFlush)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.kick:
			// Give a burst a moment to accumulate so it goes out as one
			// transaction rather than one per event.
			select {
			case <-ctx.Done():
				return
			case <-time.After(b.n.opts.BusFlush):
			}
		case <-ticker.C:
		}
		b.flush()
	}
}

func (b *bus) flush() {
	b.flushMu.Lock()
	defer b.flushMu.Unlock()
	b.mu.Lock()
	batch := b.queue
	b.queue = nil
	b.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	if _, err := b.n.store.AppendHubEvents(batch); err != nil {
		// One retry covers a momentary lock; beyond that the events are
		// stale and blocking to keep them would stall the publishers.
		if _, err2 := b.n.store.AppendHubEvents(batch); err2 != nil {
			b.dropped.Add(uint64(len(batch)))
			b.n.logf("hubcluster: publish %d event(s): %v", len(batch), err2)
		}
	}
}

func (b *bus) pollLoop(ctx context.Context) {
	defer b.wg.Done()
	ticker := time.NewTicker(b.n.opts.BusPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		b.poll()
	}
}

func (b *bus) poll() {
	b.pollMu.Lock()
	defer b.pollMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			b.n.logf("hubcluster: bus poll panicked: %v", r)
		}
	}()
	for {
		b.mu.Lock()
		cursor := b.cursor
		b.mu.Unlock()
		events, err := b.n.store.HubEventsAfter(cursor, busReadBatch)
		if err != nil {
			b.n.logf("hubcluster: read bus: %v", err)
			return
		}
		if len(events) == 0 {
			return
		}
		if events[0].Seq > cursor+1 && cursor > 0 {
			b.gapCount.Add(1)
			b.n.logf("hubcluster: missed %d bus event(s) (cursor %d, next %d); resynchronising",
				events[0].Seq-cursor-1, cursor, events[0].Seq)
			b.notifyGap()
		}
		for _, row := range events {
			b.deliver(row)
		}
		b.mu.Lock()
		b.cursor = events[len(events)-1].Seq
		b.mu.Unlock()
		if len(events) < busReadBatch {
			return
		}
	}
}

func (b *bus) deliver(row statedb.HubEventRow) {
	self := b.n.self.ID
	if row.Origin == self {
		return
	}
	// A member arrived or went: learn it now rather than at the next beat.
	// So does an event from a member this one has not read yet.
	if row.Topic == memberTopic {
		b.n.kickRefresh()
		return
	}
	if _, known := b.n.Member(row.Origin); !known {
		b.n.kickRefresh()
	}
	if row.Target != "" && row.Target != self {
		return
	}
	ev := Event{
		Seq:     row.Seq,
		Origin:  row.Origin,
		Target:  row.Target,
		Topic:   row.Topic,
		Key:     row.Key,
		Payload: json.RawMessage(row.Payload),
		At:      row.CreatedAt,
	}
	b.mu.Lock()
	fns := append(append([]func(Event){}, b.subs[row.Topic]...), b.subs["*"]...)
	b.mu.Unlock()
	for _, fn := range fns {
		func() {
			defer func() {
				if r := recover(); r != nil {
					b.n.logf("hubcluster: subscriber for %s panicked: %v", row.Topic, r)
				}
			}()
			fn(ev)
		}()
	}
	b.delivered.Add(1)
}

func (b *bus) notifyGap() {
	b.mu.Lock()
	fns := append([]func(){}, b.gaps...)
	b.mu.Unlock()
	for _, fn := range fns {
		func() {
			defer func() {
				if r := recover(); r != nil {
					b.n.logf("hubcluster: gap hook panicked: %v", r)
				}
			}()
			fn()
		}()
	}
}
