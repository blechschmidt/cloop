package hubcluster

// probe.go: a member that heartbeats but no longer answers (Task 20419).
//
// Liveness is a heartbeat, and a heartbeat proves one goroutine and one
// database write. A member can keep both going while everything that serves
// requests is stuck — a deadlock in a handler, a listener that stopped
// accepting, a peer address that leads nowhere — and before this file such a
// member was as alive as any other: requests forwarded to it waited on it
// without bound, and the runs it owned were never adopted, because adoption is
// for members that are gone.
//
// So each member that enables probing asks every live peer, over the peer
// channel, whether it is answering: a signed GET of PingPath, bounded by
// ProbeTimeout. A peer that has failed every probe for UnresponsiveAfter — and
// at least twice, so one slow answer is never a verdict — is judged
// unresponsive, and from then on this member treats it as down for everything
// that hands work over: what it owns is adopted (Owner.Alive is false), no
// request is forwarded to it, and the requests already waiting on it are
// failed at once instead of at their timeouts. Its first answer clears the
// verdict.
//
// The verdict is this member's own. Every member forms one, and each acts on
// it only where it already acts: the leader adopts a container run, the member
// holding an agent's socket adopts the agent's. Adoption is a compare-and-swap
// on the owner row, so two members judging differently still produce one
// adopter, and a member that was judged wrongly — slow rather than stuck —
// finds its run adopted at its next ownership check and lets it go, exactly as
// a member paused past its heartbeat TTL does.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PingPath is the internal endpoint a member answers probes on. pkg/ui serves
// it behind the peer signature, like every endpoint under the internal prefix.
const PingPath = "/api/internal/cluster/ping"

// Probe defaults. A stuck member is judged within UnresponsiveAfter — the
// member TTL — plus one probe, which is the window in which a crashed member
// on another machine is noticed too.
const (
	DefaultProbeInterval = 5 * time.Second
	DefaultProbeTimeout  = 5 * time.Second
)

// ErrMemberUnresponsive is the cause of a request failed because the member it
// waited on was judged unresponsive, and the error a request to such a member
// fails with without being sent.
var ErrMemberUnresponsive = errors.New("hubcluster: the member is not answering")

// probeState is what this member has learned from probing one peer.
type probeState struct {
	// failingSince is when the current run of failed probes began, zero while
	// the peer answers.
	failingSince time.Time
	failures     int
	// unresponsive is the verdict, and since when it stands.
	unresponsive bool
	since        time.Time
	lastErr      string
}

// probes is a Node's probe bookkeeping.
type probes struct {
	mu    sync.Mutex
	state map[string]*probeState
}

// Responsive reports whether this member considers id answering: true for
// itself, for a member it has not probed, and for one it has heard from since
// its last failure; false only for a member judged unresponsive.
func (n *Node) Responsive(id string) bool {
	return n.unresponsiveErr(id) == nil
}

// Serving reports whether id is a member that serves this control plane now:
// heartbeating (IsAlive) and answering (Responsive). It is the test everything
// that hands work to another member, or takes work over from one, applies.
func (n *Node) Serving(id string) bool {
	return n.IsAlive(id) && n.Responsive(id)
}

// unresponsiveErr returns an error wrapping ErrMemberUnresponsive, naming how
// long the member has failed to answer, or nil.
func (n *Node) unresponsiveErr(id string) error {
	if n == nil || id == "" || id == n.self.ID {
		return nil
	}
	n.probes.mu.Lock()
	defer n.probes.mu.Unlock()
	st := n.probes.state[id]
	if st == nil || !st.unresponsive {
		return nil
	}
	detail := "it has failed every probe since " + st.failingSince.UTC().Format(time.RFC3339)
	if st.lastErr != "" {
		detail += " (last: " + st.lastErr + ")"
	}
	return fmt.Errorf("%w: %s", ErrMemberUnresponsive, detail)
}

// unresponsiveSince returns when id was judged unresponsive, or zero.
func (n *Node) unresponsiveSince(id string) time.Time {
	if n == nil {
		return time.Time{}
	}
	n.probes.mu.Lock()
	defer n.probes.mu.Unlock()
	if st := n.probes.state[id]; st != nil && st.unresponsive {
		return st.since
	}
	return time.Time{}
}

// probeLoop probes every live peer each ProbeInterval until ctx ends.
func (n *Node) probeLoop(ctx context.Context) {
	defer n.wg.Done()
	ticker := time.NewTicker(n.opts.ProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		n.ProbePeers(ctx)
	}
}

// ProbePeers probes every live peer once, concurrently, and applies the
// results. The probe loop calls it each interval; a test may call it to move
// the verdict along without waiting for one.
func (n *Node) ProbePeers(ctx context.Context) {
	if n == nil || n.peer == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			n.logf("hubcluster: probe panicked: %v", r)
		}
	}()
	peers := n.Peers()
	n.forgetProbes(peers)
	type result struct {
		id  string
		err error
	}
	results := make(chan result, len(peers))
	var asked int
	for _, m := range peers {
		if strings.TrimSpace(m.AdvertiseURL) == "" {
			// Nothing can be forwarded to a member with no address, so there
			// is nothing to learn about whether it would answer.
			continue
		}
		asked++
		go func(m Member) {
			pctx, cancel := context.WithTimeout(ctx, n.opts.ProbeTimeout)
			defer cancel()
			err := n.call(pctx, m, http.MethodGet, PingPath, nil, nil, true)
			var ce *CallError
			if errors.As(err, &ce) {
				// It answered. Whatever it said — a refused signature from a
				// member that has not seen this one yet, say — it is serving.
				err = nil
			}
			results <- result{id: m.ID, err: err}
		}(m)
	}
	changed := false
	for i := 0; i < asked; i++ {
		r := <-results
		if n.recordProbe(r.id, r.err, n.now()) {
			changed = true
		}
	}
	if changed {
		n.runMembershipHooks()
	}
}

// recordProbe applies one probe's outcome to id, and reports whether the
// verdict changed.
func (n *Node) recordProbe(id string, err error, at time.Time) bool {
	n.probes.mu.Lock()
	if n.probes.state == nil {
		n.probes.state = map[string]*probeState{}
	}
	st := n.probes.state[id]
	if st == nil {
		st = &probeState{}
		n.probes.state[id] = st
	}
	if err == nil {
		was := st.unresponsive
		*st = probeState{}
		n.probes.mu.Unlock()
		if was {
			n.logf("hubcluster: member %s answers again; it is no longer treated as down", id)
		}
		return was
	}
	if st.failures == 0 {
		st.failingSince = at
	}
	st.failures++
	st.lastErr = err.Error()
	flipped := false
	if !st.unresponsive && st.failures >= 2 && at.Sub(st.failingSince) >= n.opts.UnresponsiveAfter {
		st.unresponsive, st.since, flipped = true, at, true
	}
	since, lastErr := st.failingSince, st.lastErr
	n.probes.mu.Unlock()
	if flipped {
		cause := fmt.Errorf("%w: it has failed every probe since %s (last: %s)", ErrMemberUnresponsive,
			since.UTC().Format(time.RFC3339), lastErr)
		failed := n.peer.failInflight(id, cause)
		n.logf("hubcluster: member %s still heartbeats but has not answered since %s (%s); treating it as down "+
			"for adoption and forwarding, and failing the %d request(s) waiting on it",
			id, since.UTC().Format(time.RFC3339), lastErr, failed)
	}
	return flipped
}

// forgetProbes drops what was learned about members no longer live: a member
// that left or died is judged by its heartbeat now, and one that comes back
// under the same id starts with a clean record.
func (n *Node) forgetProbes(live []Member) {
	keep := make(map[string]bool, len(live))
	for _, m := range live {
		keep[m.ID] = true
	}
	n.probes.mu.Lock()
	defer n.probes.mu.Unlock()
	for id := range n.probes.state {
		if !keep[id] {
			delete(n.probes.state, id)
		}
	}
}

// servingMembers returns the live members this one considers answering, this
// one included: what the membership hooks are handed.
func (n *Node) servingMembers() []Member {
	var out []Member
	for _, m := range n.LiveMembers() {
		if m.Self || n.Responsive(m.ID) {
			out = append(out, m)
		}
	}
	return out
}

// runMembershipHooks hands the serving members to every OnMembership hook.
func (n *Node) runMembershipHooks() {
	n.mu.RLock()
	hooks := append([]func([]Member){}, n.onMembers...)
	n.mu.RUnlock()
	if len(hooks) == 0 {
		return
	}
	live := n.servingMembers()
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

// LeadsAdoption reports whether this member adopts what members that stopped
// serving left behind — their container, Pod and host-process runs, the
// workloads their dispatches started: the leader, which already does the work
// that must happen once — or, while the leader itself heartbeats without
// answering, the member serving longest in its stead (Task 20419). An
// unresponsive leader keeps its lease, which is renewed in the database, so
// leadership alone would leave its own runs adopted by nobody.
func (n *Node) LeadsAdoption() bool {
	if n == nil {
		return false
	}
	if n.IsLeader() {
		return true
	}
	leader := n.LeaderID()
	if leader == "" || leader == n.self.ID || !n.IsAlive(leader) || n.Responsive(leader) {
		// No leader just now (one is being elected), this member, or a
		// leader that is gone — a new one is elected — or answering.
		return false
	}
	for _, m := range n.Members() {
		if m.ID == leader || !m.Alive {
			continue
		}
		if m.Self {
			return true
		}
		if n.Responsive(m.ID) {
			return false
		}
	}
	return false
}
