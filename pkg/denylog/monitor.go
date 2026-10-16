package denylog

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// monitor.go turns the kernel's packet log into per-run batches.
//
// A logged packet names a bridge (its input interface) and a source address;
// neither names a run. The container driver supplies the mapping when it
// starts a sandbox — the bridge its network uses and the address the engine
// gave the container — and takes it back when the sandbox ends. Two windows
// need care:
//
//   - A container can send before the driver has read its address back from
//     the engine, so a packet nobody has claimed yet is held briefly
//     (maxPending of them, pendingTTL each) and counted for the run that
//     claims its address.
//   - The kernel batches its log for up to the group's flush timeout, so a
//     sandbox's last refusals can arrive after it has exited. A released run
//     keeps its addresses for linger, and FlushFinal waits out the timeout
//     before the final report.

// Timing. Variables so tests can shorten them.
var (
	// FlushInterval is how often batches are reported while a run lives:
	// soon enough that a developer watching the run's history sees a refusal
	// while it still explains what the harness is doing.
	FlushInterval = 2 * time.Second
	// settle is how long after a run ends its last log lines may still be in
	// the kernel's queue: the group's flush timeout (nflog_linux.go) plus the
	// reader's turn.
	settle = 450 * time.Millisecond
	// linger keeps a released run's addresses attributed.
	linger = 5 * time.Second
	// pendingTTL bounds how long an unclaimed packet waits for its run.
	pendingTTL = 10 * time.Second
	// forgetAfter drops a released run nobody collected the final report of.
	forgetAfter = 10 * time.Minute
)

// Run identifies one sandbox's refusals to a Sink.
type Run struct {
	// ID is the handle of the workload, in the executor that started it.
	ID string
	// Executor is that executor's ID.
	Executor string
}

// Sink receives a run's batch. An error means it was not delivered; the batch
// is kept and reported again.
type Sink func(r Run, b Batch) error

// ErrNoSink reports that this process has nowhere to send refusals, so there
// is nothing to read the group for.
var ErrNoSink = errors.New("denylog: no sink is installed in this process")

// Stats are a monitor's counters, for diagnostics.
type Stats struct {
	// Packets is every logged packet read from the group.
	Packets uint64
	// Foreign is packets under a prefix this package did not write.
	Foreign uint64
	// Unattributed is packets no run claimed within pendingTTL.
	Unattributed uint64
	// Malformed is packets whose header could not be read.
	Malformed uint64
	// Overruns is how often the socket's buffer overflowed and the kernel
	// discarded log lines.
	Overruns uint64
}

// attrKey is what attributes a packet: the interface it arrived on and its
// source address.
type attrKey struct {
	ifindex uint32
	addr    netip.Addr
}

type runState struct {
	run         Run
	fingerprint string
	keys        []attrKey
	agg         *aggregate
	released    time.Time
	// bridge is the interface the run's sandbox is attached to, and wide
	// says its address is not known — the engine had already released it
	// when the driver asked, because the sandbox exited first — so it claims
	// the bridge's unattributed packets for as long as nothing else is on it.
	bridge uint32
	wide   bool
}

type pendingObs struct {
	key  attrKey
	agg  aggKey
	at   time.Time
	seen time.Time
}

// source is the kernel's end: an NFLOG group bound in this process.
type source interface {
	read(buf []byte) (int, error)
	group() uint16
	close() error
}

// errRetry is a read that returned nothing and should simply be retried — the
// socket's receive timeout, which is how a blocked read notices Close.
var errRetry = errors.New("denylog: retry")

// errOverrun is a read the kernel answered with ENOBUFS: its queue overflowed
// and log lines were discarded. Counted; the next read goes on.
var errOverrun = errors.New("denylog: receive buffer overrun")

// Monitor reads one NFLOG group and reports refusals per run.
type Monitor struct {
	src  source
	sink Sink
	now  func() time.Time

	mu      sync.Mutex
	runs    map[string]*runState
	byAddr  map[attrKey]*runState
	pending []pendingObs
	stats   Stats
	closed  bool

	done chan struct{}
	wg   sync.WaitGroup
}

// newMonitor starts the read and flush loops over src.
func newMonitor(src source, sink Sink, now func() time.Time) *Monitor {
	if now == nil {
		now = time.Now
	}
	m := &Monitor{
		src: src, sink: sink, now: now,
		runs:   make(map[string]*runState),
		byAddr: make(map[attrKey]*runState),
		done:   make(chan struct{}),
	}
	m.wg.Add(2)
	go m.readLoop()
	go m.flushLoop()
	return m
}

// Group is the NFLOG group this monitor reads; rulesets log to it.
func (m *Monitor) Group() uint16 { return m.src.group() }

// Stats returns a snapshot of the counters.
func (m *Monitor) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

// Close stops both loops and releases the group.
func (m *Monitor) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()
	close(m.done)
	// The read loop notices within the socket's receive timeout; the socket
	// is closed only once nothing can be reading it, so its descriptor is
	// never reused under a read in flight.
	m.wg.Wait()
	return m.src.close()
}

// Track attributes packets from addrs on the interface ifindex to run, whose
// sandbox is filtered by the rule set fingerprint. A later Track of the same
// address takes it over: an engine reuses a departed container's address, and
// the newest claim is the live one.
//
// With no addresses the run claims the bridge instead: a sandbox that exited
// before the driver could read its address back has none any more, and its
// refusals — already in the kernel's queue, or held as unclaimed — are its
// own as long as it is the only run on that bridge. With another run there
// they are nobody's provably, and stay unattributed.
func (m *Monitor) Track(run Run, fingerprint string, ifindex uint32, addrs []netip.Addr) error {
	if run.ID == "" {
		return errors.New("denylog: a tracked run needs an id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("denylog: monitor is closed")
	}
	rs := m.runs[run.ID]
	if rs == nil {
		if len(m.runs) >= MaxRuns {
			m.gcLocked(m.now(), true)
			if len(m.runs) >= MaxRuns {
				return fmt.Errorf("denylog: already tracking %d runs", MaxRuns)
			}
		}
		rs = &runState{run: run, agg: newAggregate(MaxEntriesPerRun)}
		m.runs[run.ID] = rs
	}
	rs.fingerprint = fingerprint
	rs.released = time.Time{}
	rs.bridge, rs.wide = ifindex, len(addrs) == 0 && len(rs.keys) == 0
	for _, a := range addrs {
		k := attrKey{ifindex: ifindex, addr: a.Unmap()}
		if prev := m.byAddr[k]; prev != nil && prev != rs {
			prev.keys = removeKey(prev.keys, k)
		}
		m.byAddr[k] = rs
		if !containsKey(rs.keys, k) {
			rs.keys = append(rs.keys, k)
		}
	}
	// Packets that arrived before the address was known.
	claim := rs.wide && m.bridgeClaimLocked(ifindex) == rs
	kept := m.pending[:0]
	for _, p := range m.pending {
		if containsKey(rs.keys, p.key) || claim && p.key.ifindex == ifindex {
			rs.agg.add(p.agg, p.at)
			continue
		}
		kept = append(kept, p)
	}
	m.pending = kept
	return nil
}

// bridgeClaimLocked is the run an unattributed packet on ifindex belongs to:
// the one run attached to that bridge, when it is known only by the bridge.
func (m *Monitor) bridgeClaimLocked(ifindex uint32) *runState {
	var only *runState
	for _, rs := range m.runs {
		if rs.bridge != ifindex {
			continue
		}
		if !rs.released.IsZero() && m.now().Sub(rs.released) > linger {
			continue
		}
		if only != nil || !rs.wide {
			return nil
		}
		only = rs
	}
	return only
}

// Release marks run's sandbox gone. Its addresses stay attributed for linger,
// for the log lines still queued in the kernel; its refusals are reported by
// FlushFinal, or by the monitor itself once forgetAfter has passed.
func (m *Monitor) Release(runID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rs := m.runs[runID]; rs != nil && rs.released.IsZero() {
		rs.released = m.now()
	}
}

// Tracked reports whether run is known to the monitor.
func (m *Monitor) Tracked(runID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs[runID] != nil
}

// FlushFinal reports what is left of run with Final set and forgets it. It
// waits — at most settle — for log lines the kernel may still hold, so it is
// called once the sandbox has exited and before the run's end is reported. A
// run the monitor does not know is nothing to report. An error means the
// report did not arrive: the run is kept, and a later FlushFinal tries again.
func (m *Monitor) FlushFinal(ctx context.Context, runID string) error {
	m.mu.Lock()
	rs := m.runs[runID]
	var wait time.Duration
	if rs != nil {
		since := time.Duration(0)
		if !rs.released.IsZero() {
			since = m.now().Sub(rs.released)
		}
		wait = settle - since
	}
	m.mu.Unlock()
	if rs == nil {
		return nil
	}
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}

	m.mu.Lock()
	rs = m.runs[runID]
	if rs == nil {
		m.mu.Unlock()
		return nil
	}
	b := rs.agg.take()
	b.Fingerprint, b.Final = rs.fingerprint, true
	run := rs.run
	m.mu.Unlock()

	if err := m.deliver(run, b); err != nil {
		m.mu.Lock()
		if cur := m.runs[runID]; cur != nil {
			cur.agg.putBack(b)
		}
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	if cur := m.runs[runID]; cur == rs {
		m.forgetLocked(rs)
	}
	m.mu.Unlock()
	return nil
}

func (m *Monitor) deliver(r Run, b Batch) (err error) {
	if m.sink == nil {
		return ErrNoSink
	}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("denylog: sink panicked: %v", p)
		}
	}()
	return m.sink(r, b)
}

func (m *Monitor) forgetLocked(rs *runState) {
	for _, k := range rs.keys {
		if m.byAddr[k] == rs {
			delete(m.byAddr, k)
		}
	}
	delete(m.runs, rs.run.ID)
}

// observe records one logged packet.
func (m *Monitor) observe(p Packet) {
	// The fingerprint in the prefix is the table's; the run's is the one its
	// Track named, which is what its report carries.
	_, rule, ok := ParsePrefix(p.Prefix)
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.Packets++
	if !ok {
		m.stats.Foreign++
		return
	}
	h, ok := ParseHeader(p.Payload)
	if !ok {
		m.stats.Malformed++
		return
	}
	at := now
	// The kernel's own timestamp when it sent one that is plausible: it is
	// when the packet was refused rather than when the batch reached us.
	if !p.Time.IsZero() && p.Time.Before(now.Add(time.Minute)) && p.Time.After(now.Add(-time.Minute)) {
		at = p.Time
	}
	k := aggKey{dst: h.Dst.Unmap(), port: h.DstPort, proto: normalizeProto(h.Proto), rule: rule}
	src := attrKey{ifindex: p.InDev, addr: h.Src.Unmap()}
	if rs := m.byAddr[src]; rs != nil {
		rs.agg.add(k, at)
		return
	}
	if rs := m.bridgeClaimLocked(p.InDev); rs != nil {
		rs.agg.add(k, at)
		return
	}
	if len(m.pending) >= maxPending {
		m.pending = m.pending[1:]
		m.stats.Unattributed++
	}
	m.pending = append(m.pending, pendingObs{key: src, agg: k, at: at, seen: now})
}

func (m *Monitor) readLoop() {
	defer m.wg.Done()
	buf := make([]byte, 64<<10)
	backoff := 10 * time.Millisecond
	for {
		select {
		case <-m.done:
			return
		default:
		}
		n, err := m.src.read(buf)
		switch {
		case err == nil:
			backoff = 10 * time.Millisecond
			_ = ParseMessages(buf[:n], m.observe)
		case errors.Is(err, errRetry):
		case errors.Is(err, errOverrun):
			m.mu.Lock()
			m.stats.Overruns++
			m.mu.Unlock()
		default:
			// A socket error with no recovery but to wait: never a busy loop
			// in a process that holds CAP_NET_ADMIN.
			select {
			case <-m.done:
				return
			case <-time.After(backoff):
			}
			if backoff < time.Second {
				backoff *= 2
			}
		}
	}
}

func (m *Monitor) flushLoop() {
	defer m.wg.Done()
	t := time.NewTicker(FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.flushOnce()
		}
	}
}

// flushOnce reports every run with something new, and does the bookkeeping:
// unclaimed packets expire, released runs stop being attributed after linger
// and are forgotten after forgetAfter.
func (m *Monitor) flushOnce() {
	type out struct {
		rs *runState
		b  Batch
	}
	m.mu.Lock()
	now := m.now()
	m.gcLocked(now, false)
	var due []out
	for _, rs := range m.runs {
		if !rs.agg.pending() {
			continue
		}
		b := rs.agg.take()
		b.Fingerprint = rs.fingerprint
		due = append(due, out{rs, b})
	}
	m.mu.Unlock()

	for _, o := range due {
		if err := m.deliver(o.rs.run, o.b); err != nil {
			m.mu.Lock()
			if m.runs[o.rs.run.ID] == o.rs {
				o.rs.agg.putBack(o.b)
			}
			m.mu.Unlock()
		}
	}
}

// gcLocked expires what has outlived its window. force also forgets released
// runs whose final report is overdue — the way Track makes room at MaxRuns.
func (m *Monitor) gcLocked(now time.Time, force bool) {
	kept := m.pending[:0]
	for _, p := range m.pending {
		if now.Sub(p.seen) > pendingTTL {
			m.stats.Unattributed++
			continue
		}
		kept = append(kept, p)
	}
	m.pending = kept
	for _, rs := range m.runs {
		if rs.released.IsZero() {
			continue
		}
		age := now.Sub(rs.released)
		if age > linger {
			for _, k := range rs.keys {
				if m.byAddr[k] == rs {
					delete(m.byAddr, k)
				}
			}
			rs.keys = nil
		}
		if age > forgetAfter || force && age > linger && !rs.agg.pending() {
			m.forgetLocked(rs)
		}
	}
}

func containsKey(ks []attrKey, k attrKey) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

func removeKey(ks []attrKey, k attrKey) []attrKey {
	out := ks[:0]
	for _, x := range ks {
		if x != k {
			out = append(out, x)
		}
	}
	return out
}

// ─── the process's monitor ──────────────────────────────────────────────────

var proc struct {
	sync.Mutex
	sink  Sink
	mon   *Monitor
	err   error
	errAt time.Time
}

// startRetry is how long a failed start is remembered before the next caller
// tries again: a group another process held may be free by then, and a
// capability missing now will be missing then too, cheaply.
const startRetry = time.Minute

// SetSink installs where this process's refusals go — an agent's session, or
// the hub itself — and returns the function that restores the previous one.
// With no sink installed Shared refuses, and drivers render no log statements.
func SetSink(s Sink) (restore func()) {
	proc.Lock()
	prev := proc.sink
	proc.sink = s
	proc.err, proc.errAt = nil, time.Time{}
	proc.Unlock()
	return func() {
		proc.Lock()
		proc.sink = prev
		proc.Unlock()
	}
}

// deliverProc calls whatever sink is installed now, so a monitor outlives a
// SetSink that replaces its sink (tests do; processes set theirs once).
func deliverProc(r Run, b Batch) error {
	proc.Lock()
	s := proc.sink
	proc.Unlock()
	if s == nil {
		return ErrNoSink
	}
	return s(r, b)
}

// Shared returns this process's monitor, binding the NFLOG group on first use.
// It fails with ErrNoSink in a process that installed no sink, and with the
// reason the group could not be bound — no CAP_NET_ADMIN, no AF_NETLINK, no
// free group — otherwise; a failure is remembered for a minute.
func Shared() (*Monitor, error) {
	proc.Lock()
	defer proc.Unlock()
	if proc.mon != nil {
		return proc.mon, nil
	}
	if proc.sink == nil {
		return nil, ErrNoSink
	}
	if proc.err != nil && time.Since(proc.errAt) < startRetry {
		return nil, proc.err
	}
	src, err := openSource(baseGroup(), groupTries)
	if err != nil {
		proc.err, proc.errAt = err, time.Now()
		return nil, err
	}
	proc.mon = newMonitor(src, deliverProc, nil)
	return proc.mon, nil
}

// Running reports whether this process reads a group, and if not, why — the
// sentence an operator is shown in place of a list of refusals.
func Running() (bool, string) {
	proc.Lock()
	defer proc.Unlock()
	switch {
	case proc.mon != nil:
		return true, ""
	case proc.err != nil:
		return false, proc.err.Error()
	case proc.sink == nil:
		return false, "this process records no refusals"
	default:
		return false, "no filtered sandbox has started in this process yet"
	}
}
