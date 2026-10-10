// Package hubcluster lets several `cloop ui` processes serve one control plane
// (Task 20354).
//
// A hub used to be a singleton, and pkg/hublease made it one on purpose: the
// database was shared, but everything a hub keeps beside it lived in one
// process — the agent WebSocket it holds, the run whose output it streams, the
// dashboard sockets it pushes to, the sweeps it runs over shared rows. A second
// process would diverge quietly, so it was refused.
//
// This package replaces the refusal with membership. Every hub process joins
// the control plane as a member and heartbeats; the members share four things
// through the database they already share:
//
//	membership   who is serving, how to reach them, and whether they are alive
//	             (hub_members). Liveness is a heartbeat TTL, plus a pid probe
//	             that answers at once for a member on the same machine and pid
//	             namespace — the common crash is a supervisor restarting a
//	             killed process within seconds, and that should not cost a TTL.
//
//	leadership   the pre-existing hub lease (hub_instances), now held by one
//	             member at a time for the work that must happen exactly once:
//	             retention, backups, auto-resume, the session janitor. Losing
//	             it demotes the member; it no longer shuts the process down.
//
//	events       a bus (hub_bus) for what one member produces and every
//	             member's clients must see — a line of harness output, a run
//	             starting, an executor going offline. Batched on write, polled
//	             by sequence number on read.
//
//	ownership    which member holds a thing that cannot be shared (hub_owners):
//	             an agent's socket, a dispatched run, an in-flight login. A
//	             request about it that reaches another member is forwarded to
//	             the owner over an authenticated peer channel, and a thing whose
//	             owner died is adopted by a member able to reach it.
//
// The SQL is pkg/statedb's (migrations/0052_hub_cluster.sql); policy — who is
// alive, who may adopt, how a peer proves it is one — is here.
//
// # What a cluster requires
//
// One database file that every member opens through the same kernel: members
// on one machine, or containers on one node sharing a volume. SQLite's WAL
// needs shared memory between its connections, so it does not work over a
// network filesystem, and the bus's sequence-number cursor relies on SQLite
// having exactly one writer at a time. A control plane spread over several
// machines needs a network database, which is not this package's concern —
// but nothing here assumes the members share a pid namespace, a process table
// or a loopback interface: every cross-member question is answered from the
// database or over the peer channel.
package hubcluster

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Defaults. Chosen so a crashed member on another machine is noticed within
// half a minute, and one on this machine within a heartbeat.
const (
	// DefaultHeartbeat is how often a member renews its row and re-reads the
	// member list.
	DefaultHeartbeat = 5 * time.Second
	// DefaultMemberTTL is how long a member survives without renewing. Four
	// missed beats: a slow fsync or a GC pause must not hand a live member's
	// runs to someone else.
	DefaultMemberTTL = 20 * time.Second
	// DefaultBusPoll is how often a member reads the bus. It is the latency a
	// dashboard attached to one member sees for an event another produced.
	DefaultBusPoll = 250 * time.Millisecond
	// DefaultBusFlush bounds how long a published event waits to be batched.
	DefaultBusFlush = 50 * time.Millisecond
	// DefaultBusRetention is how long an event stays on the bus. Members read
	// it within a poll interval; the rest of the window is for a member that
	// stalled — past it, the member learns it missed events and resyncs.
	DefaultBusRetention = 2 * time.Minute
	// DefaultCampaign is how often a follower checks whether leadership is
	// free.
	DefaultCampaign = 5 * time.Second
	// memberRowRetention is how long a dead member's row is kept for
	// `cloop hub cluster status` before the leader deletes it.
	memberRowRetention = 24 * time.Hour
)

// Store is the persistence a Node needs. *statedb.DB satisfies it.
type Store interface {
	hublease.Store

	JoinHubMember(row statedb.HubMemberRow) error
	HeartbeatHubMember(instanceID string, at time.Time) (bool, error)
	LeaveHubMember(instanceID string, at time.Time) error
	ListHubMembers() ([]statedb.HubMemberRow, error)
	PruneHubMembers(cutoff time.Time) (int64, error)

	AppendHubEvents(events []statedb.HubEventRow) (int64, error)
	HubEventsAfter(after int64, limit int) ([]statedb.HubEventRow, error)
	HubEventBounds() (lowest, highest, issued int64, err error)
	PruneHubEvents(cutoff time.Time) (int64, error)

	GetHubOwner(kind, key string) (statedb.HubOwnerRow, error)
	ListHubOwners(kind string) ([]statedb.HubOwnerRow, error)
	ClaimHubOwner(row, expect statedb.HubOwnerRow) (bool, error)
	PutHubOwner(row statedb.HubOwnerRow) error
	UpdateHubOwnerMeta(kind, key, instanceID, meta string, at time.Time) (bool, error)
	ReleaseHubOwner(kind, key, instanceID string) (bool, error)
	ReleaseHubOwnerIfClaim(expect statedb.HubOwnerRow) (bool, error)

	HubMeta(key string) (string, bool, error)
	SetHubMeta(key, value string) error
	SetHubMetaIfAbsent(key, value string) (string, error)

	MarkHubSeen(kind, key string, expires, now time.Time) (bool, error)
	PruneHubSeen(now time.Time) (int64, error)
}

// Options configures Join. DBPath (or Store) is required.
type Options struct {
	// DBPath is the control-plane database. Ignored when Store is set.
	DBPath string
	// Store overrides DBPath; the caller then owns its lifetime.
	Store Store

	// Address is the listen address, for display (":8080").
	Address string
	// AdvertiseURL is how peers reach this member's HTTP listener. Required
	// for forwarding: a member with none can serve, but a request another
	// member owns cannot be forwarded to it.
	AdvertiseURL string
	// Version is this build's identifier.
	Version string
	// Endpoints are further named endpoints recorded in the member row's
	// meta: URLs a peer dials, or — for a reader on the same machine, like
	// the Claude home root an offboarding compares (Task 20400) — a path.
	Endpoints map[string]string

	Heartbeat    time.Duration
	MemberTTL    time.Duration
	BusPoll      time.Duration
	BusFlush     time.Duration
	BusRetention time.Duration
	Campaign     time.Duration
	// LeaderTTL and LeaderInterval configure the leader lease. Zero uses the
	// hublease defaults.
	LeaderTTL      time.Duration
	LeaderInterval time.Duration

	// Peer configures the channel members forward requests over.
	Peer PeerOptions

	// Logf receives operational messages. Nil discards them.
	Logf func(format string, args ...any)

	// Test hooks. Production leaves them zero.
	Now          func() time.Time
	ProcessAlive func(pid int) bool
	Identity     hublease.Identity
	InstanceID   string
}

// Member is one hub process in the cluster.
type Member struct {
	ID           string            `json:"id"`
	Hostname     string            `json:"hostname"`
	PID          int               `json:"pid"`
	BootID       string            `json:"-"`
	Address      string            `json:"address"`
	AdvertiseURL string            `json:"advertise_url"`
	Version      string            `json:"version"`
	Endpoints    map[string]string `json:"endpoints,omitempty"`
	StartedAt    time.Time         `json:"started_at"`
	HeartbeatAt  time.Time         `json:"heartbeat_at"`
	LeftAt       time.Time         `json:"left_at,omitzero"`
	// Alive is the verdict at the time the member list was read.
	Alive bool `json:"alive"`
	// Leader reports whether this member held the leader lease then.
	Leader bool `json:"leader"`
	// Self marks the member reading the list.
	Self bool `json:"self"`
}

// Endpoint returns a named endpoint, or "".
func (m Member) Endpoint(name string) string {
	if m.Endpoints == nil {
		return ""
	}
	return m.Endpoints[name]
}

// ErrLegacyHub is returned by Join when the control plane is held by a hub
// that predates clustering: it holds the lease but is not a member, so it
// neither forwards nor reads the bus, and serving beside it would be exactly
// the divergence the lease used to prevent.
var ErrLegacyHub = errors.New("hubcluster: a hub that cannot join a cluster controls this state")

// Node is this process's membership in the cluster.
type Node struct {
	opts  Options
	store Store
	owns  bool
	self  Member
	now   func() time.Time
	alive func(int) bool
	logf  func(string, ...any)
	peer  *peerChannel

	mu      sync.RWMutex
	members map[string]Member // every row read at the last refresh, verdicts applied
	started bool
	closed  bool
	fenced  int // times our own row vanished and we re-joined

	onMembers []func(live []Member)

	lead leadership
	bus  *bus

	// refreshKick asks the heartbeat loop to re-read the member table now,
	// rather than at the next beat: a member joined or left.
	refreshKick chan struct{}

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Join registers this process as a member of the control plane at opts.DBPath.
// The returned Node is not yet heartbeating; call Start.
func Join(opts Options) (*Node, error) {
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = DefaultHeartbeat
	}
	if opts.MemberTTL <= 0 {
		opts.MemberTTL = DefaultMemberTTL
	}
	if opts.MemberTTL <= opts.Heartbeat {
		opts.MemberTTL = 4 * opts.Heartbeat
	}
	if opts.BusPoll <= 0 {
		opts.BusPoll = DefaultBusPoll
	}
	if opts.BusFlush <= 0 {
		opts.BusFlush = DefaultBusFlush
	}
	if opts.BusRetention <= 0 {
		opts.BusRetention = DefaultBusRetention
	}
	if opts.Campaign <= 0 {
		opts.Campaign = DefaultCampaign
	}

	store, owns, err := resolveStore(opts)
	if err != nil {
		return nil, err
	}
	n := &Node{
		opts:    opts,
		store:   store,
		owns:    owns,
		now:     opts.Now,
		alive:   opts.ProcessAlive,
		logf:    opts.Logf,
		members: map[string]Member{},

		refreshKick: make(chan struct{}, 1),
	}
	if n.now == nil {
		n.now = func() time.Time { return time.Now().UTC() }
	}
	if n.alive == nil {
		n.alive = processAlive
	}
	if n.logf == nil {
		n.logf = func(string, ...any) {}
	}

	id := strings.TrimSpace(opts.InstanceID)
	if id == "" {
		if id, err = newInstanceID(); err != nil {
			n.closeStore()
			return nil, err
		}
	}
	ident := opts.Identity
	if ident.Hostname == "" && ident.PID == 0 && ident.BootID == "" {
		ident = hublease.LocalIdentity()
	}
	n.self = Member{
		ID:           id,
		Hostname:     ident.Hostname,
		PID:          ident.PID,
		BootID:       ident.BootID,
		Address:      opts.Address,
		AdvertiseURL: strings.TrimRight(strings.TrimSpace(opts.AdvertiseURL), "/"),
		Version:      opts.Version,
		Endpoints:    copyMap(opts.Endpoints),
		Self:         true,
		Alive:        true,
	}

	// A hub from before clustering holds the lease without being a member. It
	// would neither forward to us nor read what we publish, so joining it
	// would be the silent divergence the lease was built to stop.
	if err := n.awaitLegacyHolder(); err != nil {
		n.closeStore()
		return nil, err
	}

	key, err := loadPeerKey(store)
	if err != nil {
		n.closeStore()
		return nil, err
	}
	n.peer, err = newPeerChannel(n, key, opts.Peer)
	if err != nil {
		n.closeStore()
		return nil, err
	}

	at := n.now()
	n.self.StartedAt, n.self.HeartbeatAt = at, at
	if err := store.JoinHubMember(n.memberRow()); err != nil {
		n.closeStore()
		return nil, fmt.Errorf("hubcluster: join: %w", err)
	}
	n.bus = newBus(n)
	if err := n.bus.init(); err != nil {
		_ = store.LeaveHubMember(id, n.now())
		n.closeStore()
		return nil, err
	}
	if err := n.refresh(); err != nil {
		n.logf("hubcluster: initial member refresh: %v", err)
	}
	return n, nil
}

// awaitLegacyHolder is refuseLegacyHolder with one allowance. A pre-cluster
// holder that has missed a renewal almost certainly died without releasing —
// the upgrade from such a build, when its last process was killed rather than
// stopped — and its lease lapses by itself within the TTL. Its row cannot be
// probed: it carries no pid namespace, so nothing here can tell its pid from
// one in another container. Refusing would only have a supervisor restart this
// process until the lapse (and a deploy script with a shorter health window
// roll the upgrade back), so Join waits for it instead. It never takes the
// lease early: a holder that renews while this waits is serving after all,
// and the refusal stands.
func (n *Node) awaitLegacyHolder() error {
	interval := n.opts.LeaderInterval
	if interval <= 0 {
		interval = hublease.DefaultInterval
	}
	missed := interval + interval/4
	logged := false
	for {
		err := n.refuseLegacyHolder()
		var legacy *LegacyHubError
		if !errors.As(err, &legacy) || legacy.Age <= missed {
			return err
		}
		if !logged {
			n.logf("hubcluster: the pre-cluster hub %s (pid %d on %s) holding this control plane has not "+
				"renewed for %s; waiting for its lease to lapse", legacy.Holder.InstanceID, legacy.Holder.PID,
				legacy.Holder.Hostname, legacy.Age.Round(time.Millisecond))
			logged = true
		}
		time.Sleep(min(interval/4, time.Second))
	}
}

// refuseLegacyHolder returns ErrLegacyHub when a live hub holds the lease
// without being a member.
func (n *Node) refuseLegacyHolder() error {
	row, err := n.store.GetHubLease(statedb.HubScope)
	if errors.Is(err, statedb.ErrHubLeaseNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("hubcluster: read leader lease: %w", err)
	}
	if !row.Held() {
		return nil
	}
	st, err := hublease.Inspect(hublease.Options{
		Store:        n.store,
		TTL:          n.opts.LeaderTTL,
		Now:          n.now,
		ProcessAlive: n.alive,
		Identity:     n.identity(),
	})
	if err != nil {
		return fmt.Errorf("hubcluster: inspect leader lease: %w", err)
	}
	if !st.Live {
		return nil
	}
	rows, err := n.store.ListHubMembers()
	if err != nil {
		return fmt.Errorf("hubcluster: list members: %w", err)
	}
	for _, m := range rows {
		if m.InstanceID == row.InstanceID && m.LeftAt.IsZero() {
			return nil
		}
	}
	return &LegacyHubError{Holder: row, Age: n.now().Sub(row.HeartbeatAt), TTL: st.TTL}
}

// LegacyHubError names the pre-cluster hub that holds the control plane.
type LegacyHubError struct {
	Holder statedb.HubLeaseRow
	Age    time.Duration
	TTL    time.Duration
}

func (e *LegacyHubError) Error() string {
	where := e.Holder.Hostname
	if where == "" {
		where = "an unrecorded host"
	}
	var b strings.Builder
	b.WriteString("another cloop hub controls this state and cannot share it\n\n")
	fmt.Fprintf(&b, "  holder     %s on %s", e.Holder.InstanceID, where)
	if e.Holder.PID > 0 {
		fmt.Fprintf(&b, " (pid %d)", e.Holder.PID)
	}
	if e.Holder.Address != "" {
		fmt.Fprintf(&b, ", serving %s", e.Holder.Address)
	}
	b.WriteString("\n")
	if e.Holder.Version != "" {
		fmt.Fprintf(&b, "  version    %s\n", e.Holder.Version)
	}
	fmt.Fprintf(&b, "  last beat  %s ago\n", e.Age.Round(time.Second))
	b.WriteString(`
That hub holds the control-plane lease without being a cluster member — it
predates clustering, or it runs with ui.cluster.exclusive — so it would neither
forward requests to this process nor see the events it publishes. Upgrade it (a
current build joins the cluster instead of holding the control plane alone),
remove ui.cluster.exclusive, or stop it. ` + "`cloop hub lease status`" + ` shows it; the
lease lapses on its own once it stops.`)
	return b.String()
}

// Unwrap lets errors.Is(err, ErrLegacyHub) match.
func (e *LegacyHubError) Unwrap() error { return ErrLegacyHub }

// Start begins heartbeating, campaigning for leadership and reading the bus.
// It returns immediately; Close stops everything.
func (n *Node) Start(ctx context.Context) {
	n.mu.Lock()
	if n.started || n.closed {
		n.mu.Unlock()
		return
	}
	n.started = true
	runCtx, cancel := context.WithCancel(ctx)
	n.cancel = cancel
	n.mu.Unlock()

	n.bus.start(runCtx)
	n.wg.Add(2)
	go n.heartbeatLoop(runCtx)
	go n.campaignLoop(runCtx)
	n.announce(memberJoined)
}

// Close leaves the cluster: leadership is released, the member row is marked
// left so peers adopt what this member owned at once rather than after the TTL,
// and pending events are flushed. Idempotent.
func (n *Node) Close() error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	cancel := n.cancel
	n.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	n.wg.Wait()
	n.lead.stepDown(n, "the member is leaving")
	n.bus.close()

	err := n.store.LeaveHubMember(n.self.ID, n.now())
	if err == nil {
		n.announce(memberLeft)
	}
	n.closeStore()
	return err
}

// Membership announcements, on memberTopic. A member reads the member table
// on every heartbeat, so without them a join or a leave reaches the others up
// to a heartbeat late — and a member that believed it was alone publishes
// nothing, which for the newcomer means the first seconds of every run's
// output. Every member polls the bus even alone, so an announcement is seen
// within a poll.
const (
	memberTopic  = "hubcluster.member"
	memberJoined = "joined"
	memberLeft   = "left"
)

// announce writes a membership event straight to the bus, past the queue and
// past the no-peers shortcut: it is written after the member row it announces,
// and a member that thinks it is alone may be the one that is wrong.
func (n *Node) announce(what string) {
	row := statedb.HubEventRow{Origin: n.self.ID, Topic: memberTopic, Key: what, Payload: "null", CreatedAt: n.now()}
	if _, err := n.store.AppendHubEvents([]statedb.HubEventRow{row}); err != nil {
		n.logf("hubcluster: announce %s: %v", what, err)
	}
}

// kickRefresh asks for a membership refresh without waiting for it.
func (n *Node) kickRefresh() {
	select {
	case n.refreshKick <- struct{}{}:
	default:
	}
}

// ID is this member's instance id.
func (n *Node) ID() string {
	if n == nil {
		return ""
	}
	return n.self.ID
}

// Self returns this member's own record.
func (n *Node) Self() Member {
	if n == nil {
		return Member{}
	}
	m := n.self
	m.Leader = n.IsLeader()
	return m
}

// Members returns every member row read at the last refresh, live or not,
// ordered by start time.
func (n *Node) Members() []Member {
	if n == nil {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]Member, 0, len(n.members))
	for _, m := range n.members {
		out = append(out, m)
	}
	sortMembers(out)
	return out
}

// LiveMembers returns the members judged alive at the last refresh, this one
// included.
func (n *Node) LiveMembers() []Member {
	var out []Member
	for _, m := range n.Members() {
		if m.Alive {
			out = append(out, m)
		}
	}
	return out
}

// Peers returns the live members other than this one.
func (n *Node) Peers() []Member {
	var out []Member
	for _, m := range n.LiveMembers() {
		if !m.Self {
			out = append(out, m)
		}
	}
	return out
}

// HasPeers reports whether any other member is alive. A node without peers
// skips publishing: nobody would read it.
func (n *Node) HasPeers() bool {
	if n == nil {
		return false
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, m := range n.members {
		if m.Alive && !m.Self {
			return true
		}
	}
	return false
}

// Member returns a member by id, alive or not.
func (n *Node) Member(id string) (Member, bool) {
	if n == nil {
		return Member{}, false
	}
	n.mu.RLock()
	m, ok := n.members[id]
	n.mu.RUnlock()
	return m, ok
}

// IsAlive reports whether id names a live member. This member is always alive
// to itself. An id not seen at the last refresh is re-checked against the
// database, because a member that joined a moment ago is alive whether or not
// this node has refreshed since.
func (n *Node) IsAlive(id string) bool {
	if n == nil || id == "" {
		return false
	}
	if id == n.self.ID {
		return true
	}
	if m, ok := n.Member(id); ok {
		return m.Alive
	}
	if err := n.refresh(); err != nil {
		return false
	}
	m, ok := n.Member(id)
	return ok && m.Alive
}

// OnMembership registers fn to run after every refresh that changed which
// members are alive. fn receives the live members, this one included. It runs
// on the heartbeat goroutine and must not block.
func (n *Node) OnMembership(fn func(live []Member)) {
	if n == nil || fn == nil {
		return
	}
	n.mu.Lock()
	n.onMembers = append(n.onMembers, fn)
	n.mu.Unlock()
}

func (n *Node) identity() hublease.Identity {
	return hublease.Identity{Hostname: n.self.Hostname, PID: n.self.PID, BootID: n.self.BootID}
}

func (n *Node) memberRow() statedb.HubMemberRow {
	meta := "{}"
	if len(n.self.Endpoints) > 0 {
		if b, err := json.Marshal(n.self.Endpoints); err == nil {
			meta = string(b)
		}
	}
	return statedb.HubMemberRow{
		InstanceID:   n.self.ID,
		Hostname:     n.self.Hostname,
		PID:          n.self.PID,
		BootID:       n.self.BootID,
		Address:      n.self.Address,
		AdvertiseURL: n.self.AdvertiseURL,
		Version:      n.self.Version,
		Meta:         meta,
		StartedAt:    n.self.StartedAt,
		HeartbeatAt:  n.self.HeartbeatAt,
	}
}

// heartbeatLoop renews this member's row and refreshes the member list.
func (n *Node) heartbeatLoop(ctx context.Context) {
	defer n.wg.Done()
	ticker := time.NewTicker(n.opts.Heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.refreshKick:
			if err := n.refresh(); err != nil {
				n.logf("hubcluster: refresh members: %v", err)
			}
			continue
		case <-ticker.C:
		}
		n.beat()
	}
}

// beat is one heartbeat: renew, re-join if fenced out, refresh.
func (n *Node) beat() {
	defer func() {
		if r := recover(); r != nil {
			n.logf("hubcluster: heartbeat panicked: %v", r)
		}
	}()
	ok, err := n.store.HeartbeatHubMember(n.self.ID, n.now())
	switch {
	case err != nil:
		n.logf("hubcluster: heartbeat: %v", err)
	case !ok:
		// Our row is gone or marked left while we are still serving: a peer
		// pruned us as dead (we were paused past the TTL) or an operator
		// removed us. Anything we owned may have been adopted meanwhile, and
		// every owner check re-reads the row, so re-joining is safe — the
		// alternative is serving as a member nobody else can see, which is
		// the one state that must not exist.
		n.mu.Lock()
		n.fenced++
		n.mu.Unlock()
		n.logf("hubcluster: this member's row was removed while it was serving; re-joining")
		n.self.HeartbeatAt = n.now()
		if err := n.store.JoinHubMember(n.memberRow()); err != nil {
			n.logf("hubcluster: re-join: %v", err)
		}
	}
	if err := n.refresh(); err != nil {
		n.logf("hubcluster: refresh members: %v", err)
	}
	if n.IsLeader() {
		n.leaderHousekeeping()
	}
}

// refresh re-reads the member list and applies liveness verdicts.
func (n *Node) refresh() error {
	rows, err := n.store.ListHubMembers()
	if err != nil {
		return err
	}
	now := n.now()
	leaderID := n.lead.holderID(n)
	next := make(map[string]Member, len(rows))
	for _, r := range rows {
		m := memberFromRow(r)
		m.Self = m.ID == n.self.ID
		m.Alive = m.Self || n.judgeAlive(r, now)
		m.Leader = m.ID != "" && m.ID == leaderID
		next[m.ID] = m
	}
	if _, ok := next[n.self.ID]; !ok {
		self := n.self
		self.Leader = n.IsLeader()
		next[self.ID] = self
	}

	n.mu.Lock()
	changed := liveSetChanged(n.members, next)
	n.members = next
	hooks := append([]func([]Member){}, n.onMembers...)
	n.mu.Unlock()

	if changed {
		live := n.LiveMembers()
		for _, fn := range hooks {
			func() {
				defer func() {
					if r := recover(); r != nil {
						n.logf("hubcluster: membership hook panicked: %v", r)
					}
				}()
				fn(live)
			}()
		}
	}
	return nil
}

// judgeAlive decides whether a member row describes a live process.
//
// A graceful leave is final. A heartbeat older than the TTL is dead. A fresh
// heartbeat is alive unless the member is on this machine, in this pid
// namespace, and its pid is gone — the one observation that may overrule a
// fresh heartbeat, for the reason hublease gives.
func (n *Node) judgeAlive(r statedb.HubMemberRow, now time.Time) bool {
	self := hublease.Identity{Hostname: n.self.Hostname, PID: n.self.PID, BootID: n.self.BootID}
	return judgeRow(r, now, n.opts.MemberTTL, self, n.alive)
}

// judgeRow is judgeAlive for an observer that may not be a member — a CLI
// deciding whether hub processes are serving — seeing the rows from self.
func judgeRow(r statedb.HubMemberRow, now time.Time, ttl time.Duration, self hublease.Identity, alive func(int) bool) bool {
	if !r.LeftAt.IsZero() {
		return false
	}
	if r.HeartbeatAt.IsZero() || now.Sub(r.HeartbeatAt) >= ttl {
		return false
	}
	if r.Hostname != "" && r.Hostname == self.Hostname &&
		r.BootID != "" && r.BootID == self.BootID &&
		r.PID > 0 && !alive(r.PID) {
		return false
	}
	return true
}

// leaderHousekeeping trims what nobody reads any more: bus events past their
// retention and the rows of members long gone.
func (n *Node) leaderHousekeeping() {
	now := n.now()
	if _, err := n.store.PruneHubEvents(now.Add(-n.opts.BusRetention)); err != nil {
		n.logf("hubcluster: prune bus: %v", err)
	}
	if _, err := n.store.PruneHubMembers(now.Add(-memberRowRetention)); err != nil {
		n.logf("hubcluster: prune members: %v", err)
	}
	if _, err := n.store.PruneHubSeen(now); err != nil {
		n.logf("hubcluster: prune seen values: %v", err)
	}
}

// MarkSeen records a single-use value as seen until expires, cluster-wide, and
// reports whether it was fresh. See statedb.MarkHubSeen.
func (n *Node) MarkSeen(kind, key string, expires time.Time) (bool, error) {
	if n == nil {
		return true, nil
	}
	return n.store.MarkHubSeen(kind, key, expires, n.now())
}

func memberFromRow(r statedb.HubMemberRow) Member {
	m := Member{
		ID:           r.InstanceID,
		Hostname:     r.Hostname,
		PID:          r.PID,
		BootID:       r.BootID,
		Address:      r.Address,
		AdvertiseURL: r.AdvertiseURL,
		Version:      r.Version,
		StartedAt:    r.StartedAt,
		HeartbeatAt:  r.HeartbeatAt,
		LeftAt:       r.LeftAt,
	}
	if s := strings.TrimSpace(r.Meta); s != "" && s != "{}" {
		var eps map[string]string
		if json.Unmarshal([]byte(s), &eps) == nil && len(eps) > 0 {
			m.Endpoints = eps
		}
	}
	return m
}

func liveSetChanged(prev, next map[string]Member) bool {
	count := func(m map[string]Member) int {
		c := 0
		for _, v := range m {
			if v.Alive {
				c++
			}
		}
		return c
	}
	if count(prev) != count(next) {
		return true
	}
	for id, m := range next {
		if m.Alive != prev[id].Alive {
			return true
		}
	}
	return false
}

func sortMembers(ms []Member) {
	// Insertion sort: member lists are a handful long.
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && memberLess(ms[j], ms[j-1]); j-- {
			ms[j], ms[j-1] = ms[j-1], ms[j]
		}
	}
}

func memberLess(a, b Member) bool {
	if !a.StartedAt.Equal(b.StartedAt) {
		return a.StartedAt.Before(b.StartedAt)
	}
	return a.ID < b.ID
}

func copyMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func resolveStore(opts Options) (Store, bool, error) {
	if opts.Store != nil {
		return opts.Store, false, nil
	}
	if strings.TrimSpace(opts.DBPath) == "" {
		return nil, false, errors.New("hubcluster: DBPath or Store is required")
	}
	if err := os.MkdirAll(filepath.Dir(opts.DBPath), 0o755); err != nil {
		return nil, false, fmt.Errorf("hubcluster: create %s: %w", filepath.Dir(opts.DBPath), err)
	}
	db, err := statedb.Open(opts.DBPath)
	if err != nil {
		return nil, false, fmt.Errorf("hubcluster: open %s: %w", opts.DBPath, err)
	}
	// The membership rows live in the control plane's own chain; see
	// statedb's audit_home.go for why a handle declares which one it is.
	db.AsControlPlane()
	return db, true, nil
}

func (n *Node) closeStore() {
	if !n.owns {
		return
	}
	if c, ok := n.store.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

func newInstanceID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("hubcluster: generate instance id: %w", err)
	}
	return "hub_" + hex.EncodeToString(buf), nil
}

// LiveMemberRows reads the member table at dbPath and returns the rows of
// members that are serving now, judged the way members judge each other. For
// callers outside a cluster — the CLI, an exclusive hub deciding whether it
// may start — that have no Node of their own.
func LiveMemberRows(dbPath string, now time.Time) ([]statedb.HubMemberRow, error) {
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("hubcluster: open %s: %w", dbPath, err)
	}
	defer db.Close()
	rows, err := db.ListHubMembers()
	if err != nil {
		return nil, err
	}
	var out []statedb.HubMemberRow
	for _, r := range rows {
		if RowAlive(r, now) {
			out = append(out, r)
		}
	}
	return out, nil
}

// RowAlive judges one member row from this process, the way members judge
// each other: a leave is final, a heartbeat older than DefaultMemberTTL is
// dead, and a fresh one is alive unless it names a process on this machine, in
// this pid namespace, that is gone.
func RowAlive(r statedb.HubMemberRow, now time.Time) bool {
	return judgeRow(r, now, DefaultMemberTTL, hublease.LocalIdentity(), processAlive)
}
