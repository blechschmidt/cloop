// Package hublease fences a cloop control plane to one process (Task 20214).
//
// The problem it solves is a silent one. Two `cloop ui` processes can open the
// same .cloop/state.db and neither will ever see an error: SQLite's WAL keeps
// the file consistent under concurrent writers, which is exactly why the bug
// hides. What diverges is everything the hub keeps *beside* the database —
// pkg/ui holds its project-status cache, run registry, chat histories, live-log
// rooms and WebSocket client set in process memory, and broadcasts reach only
// the clients of the process that produced the event. A browser attached to the
// second hub therefore reads a snapshot that quietly stopped advancing, while
// both processes run the same background sweeps against shared rows and can
// issue two stop signals for one run.
//
// deploy/helm/cloop-hub pins replicaCount to 1 for this reason, but a values
// comment cannot enforce anything. This package makes the constraint the
// code's: a hub takes a lease before it touches the control plane, renews it on
// a ticker, and gives it up on a clean shutdown.
//
// The design rests on three decisions worth stating, because each one is the
// answer to a way leases usually fail:
//
//	A lease is liveness, not ownership. It is held for a TTL and renewed, so
//	the holder crashing costs a bounded wait rather than a permanent wedge.
//	"Treat a stale lease as free" is what stops a SIGKILLed hub from locking
//	its own successor out forever.
//
//	Renewal is fenced. Every write is conditioned on our instance id, so a hub
//	that was paused past the TTL — swapped out, stopped, or stuck in a long GC
//	— discovers at its next beat that the row is no longer its own, and stands
//	down. Without this, "stale means free" would be a licence for two live
//	hubs, which is worse than the bug being fixed.
//
//	A crash on the same host does not cost the TTL. A holder that recorded its
//	pid under this machine's boot id can be probed directly; if the process is
//	gone, the lease is dead now rather than in a minute. That matters because
//	the common case is systemd restarting a killed hub within seconds, and a
//	restart that refuses for a minute reads as an outage.
//
// Policy lives here; the SQL is pkg/statedb's (migrations/0026_hub_instances.sql).
package hublease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// DefaultTTL is how long a lease survives without a renewal. Past it the
	// lease is free and another hub may take it.
	//
	// Sixty seconds is a compromise between two costs that pull opposite ways.
	// Too short and an ordinary stall — a slow fsync, a paused container, a
	// host under load — hands the control plane to a second process while the
	// first is still alive and about to notice. Too long and a hub killed
	// without a chance to release locks its own restart out for that long,
	// which on a supervised deployment means a visible outage. Three missed
	// beats is the usual ratio; the same-host liveness probe below is what
	// keeps the common crash from paying this cost at all.
	DefaultTTL = 60 * time.Second

	// DefaultInterval is how often the holder renews. TTL/3, so two beats can
	// be lost to transient database contention without the lease lapsing.
	DefaultInterval = 20 * time.Second
)

// Store is the persistence hublease needs. *statedb.DB satisfies it; tests
// substitute their own to drive races that are not reproducible against a real
// database (a holder that renews between another hub's read and its write).
type Store interface {
	GetHubLease(scope string) (statedb.HubLeaseRow, error)
	AcquireHubLease(row, expect statedb.HubLeaseRow) (bool, error)
	RenewHubLease(scope, instanceID string, at time.Time) (bool, error)
	ReleaseHubLease(scope, instanceID string, at time.Time) (bool, error)
	ClearHubLease(scope string, expect statedb.HubLeaseRow, at time.Time) (bool, error)
}

// Options configures Acquire. Only DBPath (or Store) is required.
type Options struct {
	// DBPath is the control-plane database to fence. Ignored when Store is set.
	DBPath string
	// Store overrides DBPath. When supplied the caller owns its lifetime;
	// Release will not close it.
	Store Store

	// Scope names the fence. Empty means statedb.HubScope.
	Scope string
	// Address is the listen address this hub will serve, recorded so a refusal
	// can name the port the holder is on rather than only its pid.
	Address string
	// Version is this build's identifier, recorded for forensics.
	Version string

	// TTL and Interval default to DefaultTTL and DefaultInterval.
	TTL      time.Duration
	Interval time.Duration

	// Now and ProcessAlive are injection points for tests. Production leaves
	// them nil.
	Now          func() time.Time
	ProcessAlive func(pid int) bool
	// Identity overrides the recorded hostname/pid/boot id. Tests use it to
	// impersonate another host; production leaves it zero.
	Identity Identity
}

// Identity is who the holder claims to be.
type Identity struct {
	Hostname string
	PID      int
	// BootID identifies this boot of this kernel. A pid recorded before a
	// reboot names an unrelated process after one, so the liveness probe
	// refuses to trust a pid unless the boot ids match and are non-empty.
	BootID string
}

// Lease is a held fence. It is safe to use from multiple goroutines.
type Lease struct {
	store      Store
	ownsStore  bool
	scope      string
	instanceID string
	row        statedb.HubLeaseRow

	ttl      time.Duration
	interval time.Duration
	now      func() time.Time

	lost     chan struct{}
	lostOnce sync.Once
	mu       sync.Mutex
	lostErr  error

	stop     context.CancelFunc
	stopped  chan struct{}
	relOnce  sync.Once
	released bool
}

// Acquire takes the lease, or explains who has it.
//
// A refusal is a *ConflictError carrying the holder, so callers that want to
// react to the distinction (rather than print it) can use errors.As. Anything
// else is an ordinary failure to reach the database.
//
// The returned Lease is not yet renewing; call Start to begin heartbeats. The
// split exists so a caller can acquire early — before anything else touches the
// control plane — and only start the ticker once it has a context to tie it to.
func Acquire(opts Options) (*Lease, error) {
	scope := strings.TrimSpace(opts.Scope)
	if scope == "" {
		scope = statedb.HubScope
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	alive := opts.ProcessAlive
	if alive == nil {
		alive = processAlive
	}
	self := opts.Identity
	if self.Hostname == "" && self.PID == 0 && self.BootID == "" {
		self = LocalIdentity()
	}

	store, ownsStore, err := resolveStore(opts)
	if err != nil {
		return nil, err
	}

	instanceID, err := newInstanceID()
	if err != nil {
		closeIfOwned(store, ownsStore)
		return nil, err
	}

	observed, err := readLease(store, scope)
	if err != nil {
		closeIfOwned(store, ownsStore)
		return nil, err
	}

	if verdict := evaluate(observed, self, now(), ttl, alive); !verdict.takeable {
		closeIfOwned(store, ownsStore)
		return nil, &ConflictError{
			DBPath: opts.DBPath,
			Holder: observed,
			TTL:    ttl,
			Age:    now().Sub(observed.HeartbeatAt),
		}
	}

	at := now()
	row := statedb.HubLeaseRow{
		Scope:       scope,
		InstanceID:  instanceID,
		Hostname:    self.Hostname,
		PID:         self.PID,
		BootID:      self.BootID,
		Address:     opts.Address,
		Version:     opts.Version,
		AcquiredAt:  at,
		HeartbeatAt: at,
	}
	ok, err := store.AcquireHubLease(row, observed)
	if err != nil {
		closeIfOwned(store, ownsStore)
		return nil, err
	}
	if !ok {
		// The row changed between our read and our write, which means somebody
		// else won. Re-read so the refusal names the actual winner rather than
		// the row we judged; a stale name here would send an operator to stop
		// a process that is not the problem.
		winner, rerr := readLease(store, scope)
		closeIfOwned(store, ownsStore)
		if rerr != nil {
			return nil, rerr
		}
		return nil, &ConflictError{
			DBPath: opts.DBPath,
			Holder: winner,
			TTL:    ttl,
			Age:    now().Sub(winner.HeartbeatAt),
			Raced:  true,
		}
	}

	return &Lease{
		store:      store,
		ownsStore:  ownsStore,
		scope:      scope,
		instanceID: instanceID,
		row:        row,
		ttl:        ttl,
		interval:   interval,
		now:        now,
		lost:       make(chan struct{}),
	}, nil
}

// Start begins renewing in the background until ctx is cancelled, the lease is
// released, or it is lost. Calling it more than once is a no-op after the first.
func (l *Lease) Start(ctx context.Context) {
	if l == nil {
		return
	}
	// Guarded because Release is documented as callable from any goroutine and
	// reads these two fields. In practice Run calls Start once, but "in
	// practice" is not what the race detector checks and not what a future
	// caller will read.
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stop != nil || l.released {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	l.stop = cancel
	l.stopped = make(chan struct{})
	go l.heartbeat(runCtx)
}

// Lost is closed when this instance no longer holds the lease and did not
// release it: another hub took over, or renewals failed for longer than the TTL
// so another hub is now entitled to. A hub must stop serving when it fires —
// past that point it has no claim to the control plane and would be the second
// writer this package exists to prevent.
//
// A nil Lease returns nil, which blocks forever in a select. That is deliberate:
// it lets callers that did not take a lease use the same select as callers that
// did.
func (l *Lease) Lost() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.lost
}

// LostErr explains why Lost fired, or nil if it has not.
func (l *Lease) LostErr() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lostErr
}

// InstanceID is this holder's identity, recorded in every row it writes.
func (l *Lease) InstanceID() string {
	if l == nil {
		return ""
	}
	return l.instanceID
}

// Release gives up the lease and stops renewing. It is idempotent and safe to
// call on a lease that was already lost — the release is fenced on our instance
// id, so it cannot free a lease a successor has since taken.
func (l *Lease) Release() error {
	if l == nil {
		return nil
	}
	var err error
	l.relOnce.Do(func() {
		l.mu.Lock()
		l.released = true
		stop, stopped := l.stop, l.stopped
		l.mu.Unlock()

		// Wait for the heartbeat goroutine to be gone before writing the
		// release, so a beat in flight cannot land after it and revive a lease
		// this process has given up.
		if stop != nil {
			stop()
			<-stopped
		}
		if _, rerr := l.store.ReleaseHubLease(l.scope, l.instanceID, l.now()); rerr != nil {
			err = rerr
		}
		closeIfOwned(l.store, l.ownsStore)
	})
	return err
}

// heartbeat renews on a ticker until the context ends or the lease is gone.
func (l *Lease) heartbeat(ctx context.Context) {
	defer close(l.stopped)

	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()

	lastOK := l.now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		ok, err := l.store.RenewHubLease(l.scope, l.instanceID, l.now())
		switch {
		case err != nil:
			// A database error is not proof we lost the lease, so it does not
			// end the hub on its own — a single busy timeout under load would
			// otherwise take the control plane down. But it cannot be ignored
			// either: once we have been unable to renew for a full TTL another
			// hub is entitled to take over, and continuing to serve past that
			// point is precisely the split-brain this package prevents. So we
			// retry inside the TTL and stand down at it.
			if l.now().Sub(lastOK) >= l.ttl {
				l.lose(fmt.Errorf("hublease: could not renew for %s, assuming the lease lapsed: %w",
					l.ttl, err))
				return
			}
		case !ok:
			l.lose(errors.New("hublease: the lease is no longer held by this instance — " +
				"another hub took it over, or an operator cleared it"))
			return
		default:
			lastOK = l.now()
		}
	}
}

func (l *Lease) lose(err error) {
	l.mu.Lock()
	released := l.released
	if !released {
		l.lostErr = err
	}
	l.mu.Unlock()
	if released {
		return
	}
	l.lostOnce.Do(func() { close(l.lost) })
}

// verdict is the outcome of judging an observed row.
type verdict struct {
	takeable bool
	reason   string
}

// evaluate decides whether an observed lease row may be taken.
//
// Ordered from cheapest and most certain to least: no row at all, a graceful
// release, a lapsed heartbeat, and finally the same-host probe — which is the
// only branch that can contradict a *fresh* heartbeat, and so is the only one
// that has to be conservative about what it does not know.
func evaluate(row statedb.HubLeaseRow, self Identity, now time.Time, ttl time.Duration, alive func(int) bool) verdict {
	if row.InstanceID == "" {
		return verdict{takeable: true, reason: "no lease has ever been taken"}
	}
	if !row.ReleasedAt.IsZero() {
		return verdict{takeable: true, reason: "the previous holder released it"}
	}
	if row.HeartbeatAt.IsZero() || now.Sub(row.HeartbeatAt) >= ttl {
		return verdict{takeable: true, reason: "the previous holder stopped heartbeating"}
	}
	// The heartbeat is fresh, so the holder was alive a moment ago. Only a
	// direct observation may override that, and only when the pid is
	// unambiguous: the same machine, and the same boot of it. A pid from
	// another host says nothing here, and a pid from a previous boot names
	// whatever process inherited the number. Both fall through to the TTL.
	if row.Hostname != "" && row.Hostname == self.Hostname &&
		row.BootID != "" && row.BootID == self.BootID &&
		row.PID > 0 && !alive(row.PID) {
		return verdict{takeable: true, reason: "the holder's process is gone"}
	}
	return verdict{}
}

// ConflictError reports that another instance holds the lease.
type ConflictError struct {
	DBPath string
	Holder statedb.HubLeaseRow
	TTL    time.Duration
	Age    time.Duration
	// Raced is true when the holder won a simultaneous start rather than
	// already holding the lease when we looked.
	Raced bool
}

func (e *ConflictError) Error() string {
	var b strings.Builder
	b.WriteString("another cloop hub already controls this state")
	if e.DBPath != "" {
		fmt.Fprintf(&b, " (%s)", e.DBPath)
	}
	b.WriteString("\n\n")

	where := e.Holder.Hostname
	if where == "" {
		where = "an unrecorded host"
	}
	fmt.Fprintf(&b, "  holder     %s on %s", shortID(e.Holder.InstanceID), where)
	if e.Holder.PID > 0 {
		fmt.Fprintf(&b, " (pid %d)", e.Holder.PID)
	}
	if e.Holder.Address != "" {
		fmt.Fprintf(&b, ", serving %s", e.Holder.Address)
	}
	b.WriteString("\n")
	if !e.Holder.AcquiredAt.IsZero() {
		fmt.Fprintf(&b, "  since      %s\n", e.Holder.AcquiredAt.Format(time.RFC3339))
	}
	if e.Age >= 0 {
		fmt.Fprintf(&b, "  last beat  %s ago (the lease lapses after %s of silence)\n",
			roundDur(e.Age), e.TTL)
	}
	if e.Raced {
		b.WriteString("  note       it won a simultaneous start with this process\n")
	}

	b.WriteString(`
Two hubs sharing one control plane do not share the state they keep in memory:
each has its own project-status cache, run registry and WebSocket clients, so a
browser attached to one never sees the other's events, and both run the same
background sweeps over the same rows. cloop refuses to start rather than diverge
quietly.

To resolve:
  * stop the other hub — it is the one named above; or
  * start this one from a different directory. A hub roots its control plane at
    its working directory, so a second dashboard needs a second one; or
  * if that hub is already gone, its lease lapses on its own and the next start
    succeeds. `)
	fmt.Fprintf(&b, "`cloop hub lease status` shows the countdown, and\n    `cloop hub lease clear` releases a lapsed lease immediately.")
	return b.String()
}

// Status is a read-only view of the fence, for `cloop hub lease status`.
type Status struct {
	Present bool
	Row     statedb.HubLeaseRow
	// Live is true when the lease is held and may not be taken.
	Live bool
	// Age is how long since the last heartbeat.
	Age time.Duration
	// Expires is how long until a live lease lapses; zero when it is not live.
	Expires time.Duration
	// Reason explains a non-live lease.
	Reason string
	TTL    time.Duration
}

// Inspect reports the current state of the fence without touching it.
func Inspect(opts Options) (Status, error) {
	scope := strings.TrimSpace(opts.Scope)
	if scope == "" {
		scope = statedb.HubScope
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	alive := opts.ProcessAlive
	if alive == nil {
		alive = processAlive
	}
	self := opts.Identity
	if self.Hostname == "" && self.PID == 0 && self.BootID == "" {
		self = LocalIdentity()
	}

	store, ownsStore, err := resolveStore(opts)
	if err != nil {
		return Status{}, err
	}
	defer closeIfOwned(store, ownsStore)

	row, err := readLease(store, scope)
	if err != nil {
		return Status{}, err
	}
	if row.InstanceID == "" {
		return Status{TTL: ttl, Reason: "no lease has ever been taken"}, nil
	}

	v := evaluate(row, self, now(), ttl, alive)
	st := Status{Present: true, Row: row, Live: !v.takeable, Reason: v.reason, TTL: ttl}
	if !row.HeartbeatAt.IsZero() {
		st.Age = now().Sub(row.HeartbeatAt)
		if st.Live {
			st.Expires = ttl - st.Age
		}
	}
	return st, nil
}

// ErrLeaseLive is returned by Clear when the lease is still held.
var ErrLeaseLive = errors.New("hublease: the lease is live")

// Clear releases a lapsed lease on an operator's behalf.
//
// It refuses while the lease is live, and that gate is the reason the command
// is safe to document: the failure mode of a "force" escape hatch is an
// operator evicting a hub that was working, which produces exactly the two-hub
// state the fence exists to prevent — except now with the second hub believing
// it is sole owner. A lease that really is abandoned lapses on its own, so
// there is nothing a force flag would unblock that waiting does not.
//
// The release is conditioned on the row still carrying the heartbeat Clear
// judged, so a holder that comes back between the check and the write keeps its
// lease rather than being evicted by a decision that is no longer true.
func Clear(opts Options) (statedb.HubLeaseRow, error) {
	scope := strings.TrimSpace(opts.Scope)
	if scope == "" {
		scope = statedb.HubScope
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	alive := opts.ProcessAlive
	if alive == nil {
		alive = processAlive
	}
	self := opts.Identity
	if self.Hostname == "" && self.PID == 0 && self.BootID == "" {
		self = LocalIdentity()
	}

	store, ownsStore, err := resolveStore(opts)
	if err != nil {
		return statedb.HubLeaseRow{}, err
	}
	defer closeIfOwned(store, ownsStore)

	row, err := readLease(store, scope)
	if err != nil {
		return statedb.HubLeaseRow{}, err
	}
	if row.InstanceID == "" || !row.ReleasedAt.IsZero() {
		return row, nil // already free; clearing is a no-op, not an error
	}
	if v := evaluate(row, self, now(), ttl, alive); !v.takeable {
		return row, fmt.Errorf("%w: %s", ErrLeaseLive, (&ConflictError{
			Holder: row,
			TTL:    ttl,
			Age:    now().Sub(row.HeartbeatAt),
		}).Error())
	}
	ok, err := store.ClearHubLease(scope, row, now())
	if err != nil {
		return row, err
	}
	if !ok {
		return row, fmt.Errorf("%w: it was renewed while being cleared", ErrLeaseLive)
	}
	return row, nil
}

// LocalIdentity describes this process.
func LocalIdentity() Identity {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return Identity{Hostname: host, PID: os.Getpid(), BootID: bootID()}
}

// bootID returns this boot's kernel identifier, or "" where there is none.
//
// Linux-only by construction, and that is the intended scope: it exists to make
// a recorded pid safe to probe, and every other branch of the fence works
// without it. On a platform with no boot id the same-host fast path simply
// never engages and a crashed holder costs the TTL instead of nothing.
func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// processAlive reports whether pid names a live process on this host.
//
// Signal 0 performs the permission and existence checks without delivering
// anything. EPERM means the process exists but belongs to another user, which
// counts as alive: guessing "dead" there would let a hub evict a healthy one
// running as a different account.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	return errors.Is(err, os.ErrPermission)
}

func resolveStore(opts Options) (Store, bool, error) {
	if opts.Store != nil {
		return opts.Store, false, nil
	}
	if strings.TrimSpace(opts.DBPath) == "" {
		return nil, false, errors.New("hublease: DBPath or Store is required")
	}
	// The lease is the first thing to open this database, which makes it the
	// first thing that can find .cloop/ missing. A hub started in a directory
	// that has never held a project is an ordinary case — the dashboard comes
	// up empty and the operator registers projects from it — so create the
	// directory rather than refusing. 0755 matches pkg/state.Save, the other
	// creator of this path; anything under it that needs to be private sets its
	// own mode.
	if err := os.MkdirAll(filepath.Dir(opts.DBPath), 0o755); err != nil {
		return nil, false, fmt.Errorf("hublease: create %s: %w", filepath.Dir(opts.DBPath), err)
	}
	db, err := statedb.Open(opts.DBPath)
	if err != nil {
		return nil, false, fmt.Errorf("hublease: open %s: %w", opts.DBPath, err)
	}
	return db, true, nil
}

func closeIfOwned(store Store, owns bool) {
	if !owns {
		return
	}
	if c, ok := store.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// readLease returns the row, normalising "no row" to a zero value. Absence is
// the ordinary first-start case and callers all treat it as "free", so making
// them each unwrap the sentinel would only invite one of them to forget.
func readLease(store Store, scope string) (statedb.HubLeaseRow, error) {
	row, err := store.GetHubLease(scope)
	if errors.Is(err, statedb.ErrHubLeaseNotFound) {
		return statedb.HubLeaseRow{}, nil
	}
	if err != nil {
		return statedb.HubLeaseRow{}, err
	}
	return row, nil
}

func newInstanceID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("hublease: generate instance id: %w", err)
	}
	return "hub_" + hex.EncodeToString(buf), nil
}

// shortID abbreviates an instance id for human-facing output. The full value is
// in the row for anyone who needs to match it exactly.
func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12] + "…"
}

// roundDur trims sub-second noise from an age so a refusal reads as a sentence.
func roundDur(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d.Round(time.Second)
}
