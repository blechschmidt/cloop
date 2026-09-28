package hubcluster

// leader.go: one member at a time runs the work that must happen once.
//
// Leadership is the hub lease that used to make the whole hub a singleton
// (pkg/hublease, Task 20214), held under the member's own instance id so that
// "who leads" and "which member is that" are one question. Everything that
// made the lease trustworthy carries over — fenced renewal, a TTL instead of
// ownership, the same-host crash probe — and one thing changes: losing it
// demotes the member instead of ending the process. A follower is a full hub;
// it just does not run the sweeps.

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// leaderStepDownWait bounds how long a demoted leader waits for its duties to
// notice their context ended before releasing the lease anyway.
const leaderStepDownWait = 10 * time.Second

type leaderDuty struct {
	name string
	fn   func(ctx context.Context)
}

type leadership struct {
	mu     sync.Mutex
	lease  *hublease.Lease
	ctx    context.Context
	cancel context.CancelFunc
	// running counts this term's duties. A fresh WaitGroup per term: a duty
	// that outlives its step-down wait must not share a counter with the
	// next term's, or that term's Add would race the previous term's Wait.
	running *sync.WaitGroup
	duties  []leaderDuty
	onElect []func(bool)
	// holder is the instance id last seen holding the lease, this member's
	// own when it leads.
	holder string
	// legacyWarned latches the warning about a lease holder that is not a
	// member, so a follower beside one says so once rather than every tick.
	legacyWarned bool
	// terms counts elections won, for tests and status output.
	terms int
}

// IsLeader reports whether this member currently holds leadership.
func (n *Node) IsLeader() bool {
	if n == nil {
		return false
	}
	n.lead.mu.Lock()
	defer n.lead.mu.Unlock()
	return n.lead.lease != nil
}

// LeaderID returns the instance id last observed holding leadership, or "".
func (n *Node) LeaderID() string {
	if n == nil {
		return ""
	}
	return n.lead.holderID(n)
}

// Terms reports how many times this member has been elected.
func (n *Node) Terms() int {
	if n == nil {
		return 0
	}
	n.lead.mu.Lock()
	defer n.lead.mu.Unlock()
	return n.lead.terms
}

// WhileLeader runs fn, in its own goroutine, for as long as this member leads:
// started at each election and cancelled at each demotion. Duties registered
// while the member already leads start at once.
//
// fn must return when its context ends. A duty that ignores cancellation holds
// up the hand-over for leaderStepDownWait and is then abandoned — with the
// lease released, so the next leader may start the same duty while this one is
// still running it. Every duty is written to be safe against that overlap
// anyway; the wait only makes it rare.
func (n *Node) WhileLeader(name string, fn func(ctx context.Context)) {
	if n == nil || fn == nil {
		return
	}
	d := leaderDuty{name: name, fn: fn}
	n.lead.mu.Lock()
	n.lead.duties = append(n.lead.duties, d)
	ctx := n.lead.ctx
	wg := n.lead.running
	leading := n.lead.lease != nil
	if leading {
		wg.Add(1)
	}
	n.lead.mu.Unlock()
	if leading {
		go n.runDuty(ctx, wg, d)
	}
}

// OnLeadership registers fn to run on every election (true) and demotion
// (false). It runs on the campaign goroutine and must not block.
func (n *Node) OnLeadership(fn func(leader bool)) {
	if n == nil || fn == nil {
		return
	}
	n.lead.mu.Lock()
	n.lead.onElect = append(n.lead.onElect, fn)
	n.lead.mu.Unlock()
}

func (l *leadership) holderID(n *Node) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lease != nil {
		return n.self.ID
	}
	return l.holder
}

// campaignLoop tries for leadership immediately and then on every tick, and
// watches a held lease for loss.
func (n *Node) campaignLoop(ctx context.Context) {
	defer n.wg.Done()
	n.campaign(ctx)
	ticker := time.NewTicker(n.opts.Campaign)
	defer ticker.Stop()
	for {
		n.lead.mu.Lock()
		lease := n.lead.lease
		n.lead.mu.Unlock()
		var lost <-chan struct{}
		if lease != nil {
			lost = lease.Lost()
		}
		select {
		case <-ctx.Done():
			return
		case <-lost:
			err := lease.LostErr()
			n.logf("hubcluster: leadership lost: %v", err)
			n.lead.stepDown(n, "leadership was lost")
		case <-ticker.C:
			n.campaign(ctx)
		}
	}
}

// campaign makes one attempt at leadership when this member does not hold it.
func (n *Node) campaign(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			n.logf("hubcluster: campaign panicked: %v", r)
		}
	}()
	if n.IsLeader() || ctx.Err() != nil {
		return
	}
	lease, err := hublease.Acquire(hublease.Options{
		Store:        n.store,
		Address:      n.self.Address,
		Version:      n.self.Version,
		TTL:          n.opts.LeaderTTL,
		Interval:     n.opts.LeaderInterval,
		Now:          n.now,
		ProcessAlive: n.alive,
		Identity:     n.identity(),
		InstanceID:   n.self.ID,
	})
	if err != nil {
		var conflict *hublease.ConflictError
		if errors.As(err, &conflict) {
			n.observeHolder(conflict.Holder)
			return
		}
		n.logf("hubcluster: campaign: %v", err)
		return
	}
	n.becomeLeader(ctx, lease)
}

// observeHolder records who leads, and warns once if it is not a member.
func (n *Node) observeHolder(row statedb.HubLeaseRow) {
	n.lead.mu.Lock()
	n.lead.holder = row.InstanceID
	warned := n.lead.legacyWarned
	n.lead.mu.Unlock()
	if warned || row.InstanceID == "" {
		return
	}
	if _, isMember := n.Member(row.InstanceID); isMember {
		return
	}
	// Refresh once before concluding: a leader that joined a moment ago is a
	// member this node has not read yet.
	_ = n.refresh()
	if _, isMember := n.Member(row.InstanceID); isMember {
		return
	}
	n.lead.mu.Lock()
	n.lead.legacyWarned = true
	n.lead.mu.Unlock()
	n.logf("hubcluster: WARNING: the control-plane lease is held by %s on %s (pid %d), "+
		"which is not a cluster member — a hub from before clustering started while no "+
		"member led. It does not forward or read the event bus; stop or upgrade it.",
		row.InstanceID, row.Hostname, row.PID)
}

func (n *Node) becomeLeader(parent context.Context, lease *hublease.Lease) {
	ctx, cancel := context.WithCancel(parent)
	lease.Start(ctx)

	n.lead.mu.Lock()
	n.lead.lease = lease
	n.lead.ctx = ctx
	n.lead.cancel = cancel
	n.lead.holder = n.self.ID
	n.lead.legacyWarned = false
	n.lead.terms++
	duties := append([]leaderDuty(nil), n.lead.duties...)
	hooks := append([]func(bool){}, n.lead.onElect...)
	wg := &sync.WaitGroup{}
	wg.Add(len(duties))
	n.lead.running = wg
	n.lead.mu.Unlock()

	n.logf("hubcluster: %s elected leader", n.self.ID)
	for _, d := range duties {
		go n.runDuty(ctx, wg, d)
	}
	for _, fn := range hooks {
		n.safeHook(func() { fn(true) })
	}
	// The member list carries a leader flag; refresh so it is right now
	// rather than at the next heartbeat.
	_ = n.refresh()
}

func (n *Node) runDuty(ctx context.Context, wg *sync.WaitGroup, d leaderDuty) {
	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			n.logf("hubcluster: leader duty %s panicked: %v", d.name, r)
		}
	}()
	d.fn(ctx)
}

// stepDown ends this member's term: duties are cancelled and awaited, then the
// lease is released. Safe to call when not leading.
func (l *leadership) stepDown(n *Node, why string) {
	l.mu.Lock()
	lease, cancel, wg := l.lease, l.cancel, l.running
	l.lease, l.cancel, l.ctx, l.running = nil, nil, nil, nil
	if lease != nil {
		l.holder = ""
	}
	hooks := append([]func(bool){}, l.onElect...)
	l.mu.Unlock()
	if lease == nil {
		return
	}
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(leaderStepDownWait):
		n.logf("hubcluster: leader duties still running %s after stepping down (%s)",
			leaderStepDownWait, why)
	}
	if err := lease.Release(); err != nil {
		n.logf("hubcluster: release leadership: %v", err)
	}
	n.logf("hubcluster: %s stepped down: %s", n.self.ID, why)
	for _, fn := range hooks {
		n.safeHook(func() { fn(false) })
	}
}

func (n *Node) safeHook(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			n.logf("hubcluster: leadership hook panicked: %v", r)
		}
	}()
	fn()
}
