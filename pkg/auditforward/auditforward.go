// Package auditforward ships the audit trail off the hub as it is written
// (Task 20426).
//
// # The gap it closes
//
// The trail is hash-chained, so a row edited in place breaks the chain, and
// checkpoints (pkg/auditcheckpoint) pin each chain's length off the database,
// so a deleted tail is caught. Neither keeps the content: whoever can write
// state.db can delete rows nobody exported, and the verifier can then say only
// that something is missing. Until this package the content left the hub when
// an operator remembered to cron `cloop audit-log export | logger`.
//
// A forwarder is the cluster leader's duty (pkg/ui runs it through
// runLeaderDuty): it tails every chain — the control plane's and each
// registered project's, the trail pkg/auditmerge reads as one — and sends each
// row to every sink in audit.forward: syslog over TLS (RFC 5424 messages,
// RFC 5425 octet-counted framing), HTTPS (an NDJSON POST, or Splunk HEC
// events), or a file outside every .cloop/ directory.
//
// # Delivery
//
// Each sink has a durable cursor per chain in the control plane's database
// (statedb.AuditForwardCursor): the newest row the sink acknowledged, by id
// and row_hash. A batch is read from the database after the cursor, sent, and
// the cursor advanced only once the sink has acknowledged it — by
// compare-and-swap against the position the batch was read from, so a leader
// that lost its lease mid-send cannot move a cursor its successor already
// moved. A leader killed after the sink acknowledged and before the cursor
// moved leaves the batch to be sent again: delivery is at-least-once, every
// record carries its row_hash as the idempotency key, and its prev_hash so a
// receiver can verify the chain it has received.
//
// What counts as acknowledged depends on the sink: an https sink's 2xx (and a
// HEC body whose code is 0); a file sink's fsync; a syslog sink's receiver
// having acknowledged every byte at the TCP level (RFC 5425 has no
// application-level acknowledgement, so a receiver that crashes holding
// acknowledged bytes loses them — use https where that matters).
//
// # What a sink that is down costs
//
// Nothing an audit append waits on. Each sink has its own goroutine, reads the
// chains through its own handles, and backs off exponentially while it fails.
// The backlog stays in the database; the forwarder holds at most one batch per
// sink in memory however far behind a sink falls, and catches up batch by
// batch. Retention (pkg/auditretention) will not prune a row a live cursor has
// not passed unless forced, and the forwarder records it if one is forced.
package auditforward

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Chain roles, as records name them: the same words auditmerge and the
// checkpoints use.
const (
	SourceControlPlane = "control-plane"
	SourceProject      = "project"
)

// Chain is one audit chain the forwarder tails.
type Chain struct {
	// Source is SourceControlPlane or SourceProject.
	Source string
	// Dir is the directory holding .cloop/state.db.
	Dir string
	// Path is the database's absolute path: what a cursor is keyed on.
	Path string
}

// Credentials opens a secret-store reference ("name" or "name#KEY") for a sink
// to present. The caller zeroes what it returns once it is in use.
type Credentials func(ref string) ([]byte, error)

// Options configures a Forwarder.
type Options struct {
	// ControlPlane is the control plane's database path: where the cursors
	// live and where the forwarder's own audit rows go.
	ControlPlane string

	// Config returns the audit.forward section in force. Re-read every
	// ConfigPoll, so an edit takes effect without a restart.
	Config func() (config.AuditForwardConfig, error)

	// ConfigSource names where Config read from, for the audit row recording
	// a change ("config.yaml", or the overlay merged over it).
	ConfigSource string

	// Refused lists the sinks the loader switched off, by repair key, for the
	// same audit row. May be nil.
	Refused func() []string

	// Chains returns the chains to forward, each database once, the control
	// plane first. Re-read every ConfigPoll.
	Chains func() []Chain

	// Credentials opens the secrets sinks name. Nil makes every sink that
	// names one fail to start, with that said.
	Credentials Credentials

	// Version is stamped into CEF records and the HTTP User-Agent.
	Version string

	// Poll is how often a caught-up sink looks for new rows. Zero means two
	// seconds.
	Poll time.Duration

	// ConfigPoll is how often the configuration and the chain list are
	// re-read. Zero means ten seconds.
	ConfigPoll time.Duration

	// Logf receives one line per noteworthy event: a sink failing, a
	// discontinuity. Nil writes to stderr.
	Logf func(format string, args ...any)

	// Now overrides the clock. Nil means time.Now.
	Now func() time.Time

	// Hooks are for tests.
	Hooks Hooks
}

// Hooks let a test stand where a process would die.
type Hooks struct {
	// AfterAck runs after a sink acknowledged a batch and before its cursor
	// moves. A test that never returns from it, or calls runtime.Goexit, is a
	// leader killed between the two.
	AfterAck func(sink string, chain Chain, firstID, lastID int64)
}

// Forwarder ships every chain to every configured sink while Run runs.
type Forwarder struct {
	opts Options

	mu      sync.Mutex
	workers map[string]*worker
	status  map[string]*sinkState
	chains  []Chain

	handles *handleCache
	cp      *statedb.DB

	// configured remembers the last fingerprint recorded, so a change is
	// recorded once per process, not once per poll.
	configured string
	// marked is the project chains this process has recorded the control
	// plane in (hold.go).
	marked sync.Map
}

// New builds a Forwarder. It opens nothing until Run.
func New(opts Options) (*Forwarder, error) {
	if opts.ControlPlane == "" {
		return nil, fmt.Errorf("auditforward: no control-plane database")
	}
	if opts.Config == nil || opts.Chains == nil {
		return nil, fmt.Errorf("auditforward: Config and Chains are required")
	}
	if opts.Poll <= 0 {
		opts.Poll = 2 * time.Second
	}
	if opts.ConfigPoll <= 0 {
		opts.ConfigPoll = 10 * time.Second
	}
	return &Forwarder{
		opts:    opts,
		workers: map[string]*worker{},
		status:  map[string]*sinkState{},
		handles: newHandleCache(),
	}, nil
}

func (f *Forwarder) now() time.Time {
	if f.opts.Now != nil {
		return f.opts.Now()
	}
	return time.Now()
}

func (f *Forwarder) logf(format string, args ...any) {
	if f.opts.Logf != nil {
		f.opts.Logf(format, args...)
		return
	}
	fmt.Fprintf(os.Stderr, "[audit-forward] "+format+"\n", args...)
}

// Run forwards until ctx ends: it starts a worker per configured sink, keeps
// the set in step with the configuration, and stops every worker before it
// returns. Safe to call again after it returns.
func (f *Forwarder) Run(ctx context.Context) {
	defer f.shutdown()
	for {
		f.safeReconcile(ctx)
		t := time.NewTimer(f.opts.ConfigPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// safeReconcile is reconcile with a panic reported rather than ending Run:
// the workers already running keep forwarding.
func (f *Forwarder) safeReconcile(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			f.logf("reconciling the sinks panicked: %v", r)
		}
	}()
	f.reconcile(ctx)
}

// reconcile re-reads the configuration and the chains, records a changed
// configuration, retires cursors nothing forwards any more, and starts, stops
// or restarts workers to match.
func (f *Forwarder) reconcile(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	// A hub with no database has nothing to forward and nowhere to keep a
	// cursor; opening one here would create it.
	if _, err := os.Stat(f.opts.ControlPlane); err != nil {
		return
	}
	cfg, err := f.opts.Config()
	if err != nil {
		f.logf("could not read audit.forward; keeping the sinks running as they are: %v", err)
		return
	}
	chains := dedupChains(f.opts.Chains())
	f.mu.Lock()
	f.chains = chains
	f.mu.Unlock()

	cp, err := f.controlPlane()
	if err != nil {
		f.logf("could not open the control plane at %s: %v", f.opts.ControlPlane, err)
		return
	}
	f.recordConfiguration(cp, cfg)

	hub := hubName(cfg)
	want := map[string]config.AuditForwardSink{}
	for _, s := range cfg.Sinks {
		want[s.Name] = s
	}

	// Workers are stopped outside the lock: a worker reads the chain list
	// under it, and stop waits for the worker to return. They are stopped
	// before the cursors are synced, so a removed sink's worker cannot touch
	// its cursor after it is retired.
	f.mu.Lock()
	var stopping []*worker
	for name, w := range f.workers {
		s, ok := want[name]
		if ok && s == w.cfg && hub == w.hub {
			continue
		}
		stopping = append(stopping, w)
		delete(f.workers, name)
		delete(f.status, name)
	}
	f.mu.Unlock()
	for _, w := range stopping {
		w.stop()
	}
	f.syncCursors(cp, cfg.Sinks, chains)
	f.handles.sweep(f.now())

	f.mu.Lock()
	defer f.mu.Unlock()
	for name, s := range want {
		if _, running := f.workers[name]; running {
			continue
		}
		st := &sinkState{s: SinkStatus{Name: name, Type: s.Type, Endpoint: s.Endpoint()}}
		f.status[name] = st
		w := newWorker(f, s, hub, st)
		f.workers[name] = w
		w.start(ctx)
	}
}

// shutdown stops every worker and closes every handle — the workers first, so
// none can reopen the control plane after it is closed.
func (f *Forwarder) shutdown() {
	f.mu.Lock()
	workers := f.workers
	f.workers = map[string]*worker{}
	f.status = map[string]*sinkState{}
	f.mu.Unlock()
	for _, w := range workers {
		w.stop()
	}
	f.handles.closeAll()
	f.mu.Lock()
	cp := f.cp
	f.cp = nil
	f.mu.Unlock()
	if cp != nil {
		_ = cp.Close()
	}
}

// controlPlane returns the forwarder's control-plane handle, opening it once.
func (f *Forwarder) controlPlane() (*statedb.DB, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cp != nil {
		return f.cp, nil
	}
	db, err := statedb.Open(f.opts.ControlPlane)
	if err != nil {
		return nil, err
	}
	f.cp = db.AsControlPlane()
	return f.cp, nil
}

// currentChains is the chain list the last reconcile read.
func (f *Forwarder) currentChains() []Chain {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Chain(nil), f.chains...)
}

// Snapshot reports every running sink as its worker last saw it, sorted by
// name. It is what the leader's metrics are read from.
func (f *Forwarder) Snapshot() []SinkStatus {
	f.mu.Lock()
	sts := make([]*sinkState, 0, len(f.status))
	for _, st := range f.status {
		sts = append(sts, st)
	}
	f.mu.Unlock()
	out := make([]SinkStatus, 0, len(sts))
	for _, st := range sts {
		out = append(out, st.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SinkStatus is one sink as its worker last saw it.
type SinkStatus struct {
	Name     string
	Type     string
	Endpoint string

	// Chains is per chain, keyed by database path.
	Chains map[string]ChainStatus

	// LastError is the newest send failure, cleared by a delivery.
	LastError   string
	LastErrorAt time.Time
	// LastDeliveredAt is when the sink last acknowledged a batch.
	LastDeliveredAt time.Time
}

// ChainStatus is one sink's position in one chain.
type ChainStatus struct {
	Chain Chain
	// AckedID is the newest row the sink acknowledged; HeadID the newest
	// row the chain held when last read.
	AckedID int64
	HeadID  int64
	// PendingSince is the timestamp of the oldest row the sink has not
	// acknowledged; zero when it is caught up.
	PendingSince time.Time
}

// sinkState is a SinkStatus its worker updates while Snapshot reads it.
type sinkState struct {
	mu sync.Mutex
	s  SinkStatus
}

func (st *sinkState) snapshot() SinkStatus {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := st.s
	out.Chains = make(map[string]ChainStatus, len(st.s.Chains))
	for k, v := range st.s.Chains {
		out.Chains[k] = v
	}
	return out
}

func (st *sinkState) setChain(cs ChainStatus) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.s.Chains == nil {
		st.s.Chains = map[string]ChainStatus{}
	}
	st.s.Chains[cs.Chain.Path] = cs
}

func (st *sinkState) failed(msg string, at time.Time) {
	st.mu.Lock()
	st.s.LastError, st.s.LastErrorAt = msg, at
	st.mu.Unlock()
}

func (st *sinkState) delivered(at time.Time) {
	st.mu.Lock()
	st.s.LastError, st.s.LastErrorAt, st.s.LastDeliveredAt = "", time.Time{}, at
	st.mu.Unlock()
}

// Backlog is how many rows the sink has not acknowledged, across chains.
func (s SinkStatus) Backlog() int64 {
	var n int64
	for _, c := range s.Chains {
		if c.HeadID > c.AckedID {
			n += c.HeadID - c.AckedID
		}
	}
	return n
}

// Lag is the age of the oldest row the sink has not acknowledged; zero when it
// is caught up.
func (s SinkStatus) Lag(now time.Time) time.Duration {
	var oldest time.Time
	for _, c := range s.Chains {
		if c.PendingSince.IsZero() {
			continue
		}
		if oldest.IsZero() || c.PendingSince.Before(oldest) {
			oldest = c.PendingSince
		}
	}
	if oldest.IsZero() || now.Before(oldest) {
		return 0
	}
	return now.Sub(oldest)
}

// dedupChains drops a chain whose database another already names, keeping the
// first: on the hub's own project the control plane and the project are one
// file, listed control plane first.
func dedupChains(in []Chain) []Chain {
	seen := map[string]bool{}
	out := make([]Chain, 0, len(in))
	for _, c := range in {
		if c.Path == "" || seen[c.Path] {
			continue
		}
		seen[c.Path] = true
		out = append(out, c)
	}
	return out
}

// hubName is how this hub names itself in what it sends.
func hubName(cfg config.AuditForwardConfig) string {
	if cfg.Hostname != "" {
		return cfg.Hostname
	}
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "cloop-hub"
	}
	return sanitizeToken(h, 255)
}
