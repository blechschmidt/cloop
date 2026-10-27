package ui

// takeover_retry.go: a takeover that decided nothing is tried again (Task
// 20451).
//
// The hub process adopting a run takes over what the run's owner row names:
// its secret leases (run_takeover.go), its workspace lease (workspace_lease.go)
// and its egress sessions (session_restore.go). An attempt is decided when it
// ends one way or the other for good — the credential taken over; held by the
// process that adopted the run first; released, or never recorded; revoked,
// and taken back; refused because it lapsed or its grants no longer authorise
// it. It is undecided when nothing could be learned: the secret store could not
// be read for a moment, the database was locked, the disk was at its floor, a
// KMS was down for a member that had not opened the store yet.
//
// An undecided attempt used to print a line on stderr and move on, which was
// worse than a refusal. resumeRun rewrote the owner row from what this process
// held, so the id was gone from it and nothing tried again; nobody extended the
// lease, which lapsed at its TTL for the janitor to retire; the run's git proxy
// and Kubernetes monitor sessions and its App-token refresh went with it, never
// restored; and the run carried on until its next push or kubectl call failed,
// with nothing on the run saying why.
//
// Now an undecided takeover is kept here and tried again from this process —
// two seconds after the first attempt, the wait doubling to a minute — until an
// attempt decides it or the credential's recorded expiry passes:
//
//   - its id stays in the run's owner row beside what this process holds, and
//     the row names it among the takeovers still undecided, so a process that
//     adopts the run after this one tries it too, and `cloop hub doctor` and
//     Settings → Hub health report it (runs.lease_takeovers);
//   - the run's event history says so when it is first undecided, and again
//     when it is taken over or fails, with the reason (EventLeaseTakeover);
//   - every attempt is counted in cloop_lease_takeovers_total{kind,outcome};
//   - a request presenting a session it feeds brings the next attempt forward;
//   - one still undecided when it lapses, or when its run ends, is recorded on
//     the run as failed, and the run carries on without it.
//
// An egress session a live member still serves is kept here too, for another
// reason. Nothing forwards egress between members, and the workload's proxy
// address may well be that member's own listener, so the session is left with
// it (session_restore.go). It stays named in the run's owner row all the same,
// and is taken over here once that member stops; the member serving it ends it
// when the run ends, which it learns from the run's owner row
// (followMovedRunEgress). Before, the row forgot it — a member that then died
// took the session with it — and the member serving it renewed it for as long
// as it could not ask the device about a run it no longer followed: a day.

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// What a takeover is of: the cloop_lease_takeovers_total kinds.
const (
	takeoverRun       = hubmetrics.TakeoverKindRun
	takeoverWorkspace = hubmetrics.TakeoverKindWorkspace
	takeoverEgress    = hubmetrics.TakeoverKindEgress
)

// The retry's pacing. Variables so tests can shorten them.
var (
	// takeoverRetryFirst is the wait before the second attempt; each wait
	// after it doubles, up to takeoverRetryMax.
	takeoverRetryFirst = 2 * time.Second
	takeoverRetryMax   = time.Minute
	// takeoverNudgeSpacing is the least time between the last attempt and
	// one a request presenting a session brings forward.
	takeoverNudgeSpacing = 2 * time.Second
	// egressElsewhereCheck is how often an egress session a live member
	// serves is looked at again, on top of the membership changes that wake
	// it.
	egressElsewhereCheck = 30 * time.Second
	// movedEgressCheck is how often the member serving a moved run's egress
	// session reads the run's owner row to learn whether the run is over.
	movedEgressCheck = 10 * time.Second
)

// takeoverNow is the clock a takeover's deadline is judged by: the one leases
// and sessions record their expiries on. A variable so a test can drive it with
// its broker's.
var takeoverNow = time.Now

// takeoverReasonMax bounds the reason a takeover carries into the run's owner
// row and its journal: an error from a store can quote a great deal.
const takeoverReasonMax = 600

// takeoverResult is what one attempt at a credential decided.
type takeoverResult struct {
	// outcome is a hubmetrics.Takeover* value: TakeoverRetrying when nothing
	// was decided, and "" when there was nothing for this process to take
	// over — held here already, or not taken over by design.
	outcome string
	// err says why, for anything but taken over.
	err error
	// holder is the live hub process that still serves an egress session
	// left with it.
	holder string
}

func (r takeoverResult) undecided() bool { return r.outcome == hubmetrics.TakeoverRetrying }

// pendingTakeover is one credential of a run this process adopted that an
// attempt could not decide or — an egress session — that a live member still
// serves.
type pendingTakeover struct {
	srv      *Server
	kind, id string
	workDir  string
	ex       executor.Executor
	handleID string
	// session names a workspace lease's pinned git session.
	session string

	// attemptMu serialises attempts: the retry's own, and one a request
	// makes at once (retryPendingEgressNow).
	attemptMu sync.Mutex

	mu sync.Mutex
	// holder is the live hub process serving an egress session left with
	// it; "" while the takeover is undecided.
	holder string
	// undecidedSince is when an attempt first decided nothing; zero for a
	// session that has only ever been left with its holder.
	undecidedSince time.Time
	attempts       int
	reason         string
	// until is the recorded expiry an undecided takeover is tried until.
	until time.Time
	// last is when the last attempt was made, by the wall clock.
	last  time.Time
	ended bool
	// endedAs is the outcome p was ended with, for an attempt that was
	// still running then to undo what it took (attemptPending).
	endedAs string

	wake     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
}

func takeoverKey(kind, id string) string { return kind + "/" + id }

// elsewhere reports whether p is an egress session a live member serves.
func (p *pendingTakeover) elsewhere() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.holder != ""
}

// wasUndecided reports whether an attempt at p ever decided nothing.
func (p *pendingTakeover) wasUndecided() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.undecidedSince.IsZero()
}

func (p *pendingTakeover) isEnded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ended
}

// end marks p over with outcome, and reports whether this call did.
func (p *pendingTakeover) end(outcome string) bool {
	p.mu.Lock()
	first := !p.ended
	if first {
		p.ended, p.endedAs = true, outcome
	}
	p.mu.Unlock()
	p.stopOnce.Do(func() { close(p.stop) })
	return first
}

// endedWith reports the outcome p was ended with.
func (p *pendingTakeover) endedWith() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.endedAs
}

// nudge brings p's next attempt forward. It never blocks.
func (p *pendingTakeover) nudge() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// noteUndecided records an attempt that decided nothing.
func (p *pendingTakeover) noteUndecided(cause error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.undecidedSince.IsZero() {
		p.undecidedSince = takeoverNow()
	}
	p.holder = ""
	p.attempts++
	p.reason = takeoverReason(cause)
}

func (p *pendingTakeover) deadline() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.until
}

func (p *pendingTakeover) lastAttempt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// snapshot copies what p's journal rows and the run's owner row say of it.
func (p *pendingTakeover) snapshot() (holder string, since time.Time, attempts int, reason string, until time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.holder, p.undecidedSince, p.attempts, p.reason, p.until
}

// record is p as the run's owner row names an undecided takeover.
func (p *pendingTakeover) record() hubcluster.RunTakeover {
	_, since, attempts, reason, until := p.snapshot()
	return hubcluster.RunTakeover{Kind: p.kind, ID: p.id, Since: since.UTC(), Attempts: attempts,
		Reason: reason, Until: until.UTC()}
}

// takeoverReason renders an attempt's error for the owner row and the journal:
// with credentials redacted, and bounded.
func takeoverReason(err error) string {
	if err == nil {
		return ""
	}
	msg := secretbroker.RedactString(err.Error())
	if len(msg) > takeoverReasonMax {
		msg = msg[:takeoverReasonMax] + "…"
	}
	return msg
}

// ── the registry ─────────────────────────────────────────────────────────────

// pendingTakeovers holds the takeovers this process keeps trying, by kind and
// id. Per process, like the leases themselves.
var pendingTakeovers = &takeoverRegistry{m: map[string]*pendingTakeover{}}

// takeoverRetries counts the retries running, so a test can wait for them to
// stop before it puts back what they read.
var takeoverRetries sync.WaitGroup

type takeoverRegistry struct {
	mu sync.Mutex
	m  map[string]*pendingTakeover
}

// add keeps p, and reports false when its credential is kept already.
func (r *takeoverRegistry) add(p *pendingTakeover) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := takeoverKey(p.kind, p.id)
	if _, ok := r.m[key]; ok {
		return false
	}
	r.m[key] = p
	return true
}

func (r *takeoverRegistry) get(kind, id string) *pendingTakeover {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[takeoverKey(kind, id)]
}

// removeIf forgets p if it is the takeover kept under its key.
func (r *takeoverRegistry) removeIf(p *pendingTakeover) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if key := takeoverKey(p.kind, p.id); r.m[key] == p {
		delete(r.m, key)
	}
}

// all returns every takeover kept, in key order.
func (r *takeoverRegistry) all() []*pendingTakeover {
	r.mu.Lock()
	out := make([]*pendingTakeover, 0, len(r.m))
	for _, p := range r.m {
		out = append(out, p)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return takeoverKey(out[i].kind, out[i].id) < takeoverKey(out[j].kind, out[j].id)
	})
	return out
}

// forHandle returns the takeovers kept for the workload handleID on
// executorID, in key order.
func (r *takeoverRegistry) forHandle(executorID, handleID string) []*pendingTakeover {
	if executorID == "" || handleID == "" {
		return nil
	}
	var out []*pendingTakeover
	for _, p := range r.all() {
		if p.ex != nil && p.ex.ID() == executorID && p.handleID == handleID {
			out = append(out, p)
		}
	}
	return out
}

// ── deciding ─────────────────────────────────────────────────────────────────

// settleFirstTakeover counts the first attempt at one credential of a run this
// process is adopting, and keeps one that decided nothing — or an egress
// session a live member still serves — to try again.
func (s *Server) settleFirstTakeover(kind, workDir string, ex executor.Executor, handleID, id, session string,
	res takeoverResult) {
	if res.outcome == "" || ex == nil {
		return
	}
	hubmetrics.LeaseTakeovers.Inc(kind, res.outcome)
	switch {
	case res.undecided():
		s.keepTakeover(kind, workDir, ex, handleID, id, session, "", res.err)
	case kind == takeoverEgress && res.holder != "":
		s.keepTakeover(kind, workDir, ex, handleID, id, "", res.holder, res.err)
	}
}

// keepTakeover keeps a credential to try again — undecided, or with holder an
// egress session that live process serves — journals it once, and starts its
// retry.
func (s *Server) keepTakeover(kind, workDir string, ex executor.Executor, handleID, id, session, holder string,
	cause error) {
	p := &pendingTakeover{
		srv: s, kind: kind, id: id, workDir: workDir, ex: ex, handleID: handleID, session: session,
		holder: holder, last: time.Now(), wake: make(chan struct{}, 1), stop: make(chan struct{}),
	}
	if holder == "" {
		now := takeoverNow()
		p.undecidedSince, p.attempts, p.reason = now, 1, takeoverReason(cause)
		p.until = takeoverDeadline(kind, id, now)
	}
	if !pendingTakeovers.add(p) {
		return // kept already: its own retry goes on
	}
	journalTakeover(p, "", nil)
	fields := map[string]interface{}{"project": workDir, "kind": kind, "id": id, "executor": ex.ID(), "handle": handleID}
	if holder != "" {
		fields["holder"] = holder
		s.log().Info("cluster", 0, "left an adopted run's egress session with the live hub process serving it", fields)
	} else {
		fields["reason"], fields["until"] = p.reason, p.until.UTC().Format(time.RFC3339)
		s.log().Warn("cluster", 0, "could not take over a credential of an adopted run; trying again", fields)
	}
	takeoverRetries.Add(1)
	go s.retryTakeover(p)
}

// retryTakeover is p's retry: until an attempt decides it, its deadline
// passes, or its run is no longer this process's.
func (s *Server) retryTakeover(p *pendingTakeover) {
	defer takeoverRetries.Done()
	defer recoverGoroutine("retry the takeover of " + takeoverKey(p.kind, p.id))
	delay := takeoverRetryFirst
	for {
		wait := delay
		if p.elsewhere() {
			wait = egressElsewhereCheck
		} else if left := p.deadline().Sub(takeoverNow()); left < wait {
			// Never past the deadline: one last attempt at it.
			wait = max(left, 0)
		}
		if !p.sleep(wait) {
			return
		}
		if s.attemptPending(p) {
			return
		}
		if !p.elsewhere() {
			if delay *= 2; delay > takeoverRetryMax {
				delay = takeoverRetryMax
			}
		}
	}
}

// sleep waits d, or less when an attempt is brought forward — though never to
// less than takeoverNudgeSpacing after the last one — and reports false once p
// is over.
func (p *pendingTakeover) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-p.stop:
		return false
	case <-t.C:
		return true
	case <-p.wake:
	}
	if gap := takeoverNudgeSpacing - time.Since(p.lastAttempt()); gap > 0 {
		g := time.NewTimer(gap)
		defer g.Stop()
		select {
		case <-p.stop:
			return false
		case <-g.C:
		case <-t.C:
		}
	}
	return true
}

// attemptPending makes one more attempt at p, and reports whether p is over.
func (s *Server) attemptPending(p *pendingTakeover) bool {
	p.attemptMu.Lock()
	defer p.attemptMu.Unlock()
	if p.isEnded() {
		return true
	}
	p.mu.Lock()
	p.last = time.Now()
	p.mu.Unlock()
	var res takeoverResult
	switch outcome, why := s.takeoverRunState(p); {
	case outcome != "" && p.elsewhere():
		// A session a live member serves: nothing to take over on a guess,
		// and nothing to count or say when the run moved or ended — it was
		// counted when it was left with that member, which ends it with
		// the run.
		if outcome == hubmetrics.TakeoverRetrying {
			return false
		}
		if p.end("") {
			pendingTakeovers.removeIf(p)
			s.refreshRunCredentials(p.workDir, p.ex, p.handleID)
		}
		return true
	case outcome == hubmetrics.TakeoverRetrying:
		// Whether the run is still this process's cannot be read: nothing
		// is taken over on a guess, and the attempt counts as undecided.
		res = takeoverResult{outcome: outcome, err: why}
	case outcome != "":
		s.endTakeover(p, outcome, why)
		return true
	default:
		res = s.attemptTakeover(p)
	}
	took := res
	if p.isEnded() {
		// Ended while the attempt ran — the run ended, or moved to another
		// member — by whoever ended it, which counted and journaled it. What
		// the attempt took over meanwhile is let go of here.
		s.undoEndedAttempt(p, res)
		return true
	}
	switch {
	case res.outcome == "":
		// Taken over meanwhile by another path in this process.
		res.outcome = hubmetrics.TakeoverTakenOver
	case p.kind == takeoverEgress && res.holder != "":
		// Still served by a live member: nothing new to count or say.
		p.mu.Lock()
		p.holder = res.holder
		p.mu.Unlock()
		return false
	case res.undecided():
		hubmetrics.LeaseTakeovers.Inc(p.kind, hubmetrics.TakeoverRetrying)
		first := !p.wasUndecided()
		p.noteUndecided(res.err)
		if first {
			// A session left with its holder, whose holder stopped, and
			// whose takeover now decides nothing: tried until it lapses.
			now := takeoverNow()
			p.mu.Lock()
			p.until = takeoverDeadline(p.kind, p.id, now)
			p.mu.Unlock()
			journalTakeover(p, "", nil)
		} else if until, ok := recordedExpiry(p.kind, p.id); ok {
			p.mu.Lock()
			p.until = until
			p.mu.Unlock()
		}
		if !takeoverNow().Before(p.deadline()) {
			_, _, _, reason, until := p.snapshot()
			s.endTakeover(p, hubmetrics.TakeoverFailed, fmt.Errorf("it was still undecided when it lapsed at %s: %s",
				until.UTC().Format(time.RFC3339), reason))
			return true
		}
		s.refreshRunCredentials(p.workDir, p.ex, p.handleID)
		return false
	}
	if !s.endTakeover(p, res.outcome, res.err) {
		// Ended by someone else between the check above and here, who
		// left what the attempt took to it.
		s.undoEndedAttempt(p, took)
	}
	return true
}

// undoEndedAttempt lets go of what an attempt took over after p was ended
// underneath it. A run that moved to another member gets its lease the way a
// handed-over run's lease goes — kept until the adopter takes it — and its
// egress session served from here until the run ends; a run that is over has
// both closed.
func (s *Server) undoEndedAttempt(p *pendingTakeover, res takeoverResult) {
	if res.outcome != hubmetrics.TakeoverTakenOver {
		return
	}
	moved := p.endedWith() == hubmetrics.TakeoverMoved
	switch p.kind {
	case takeoverEgress:
		egr := liveEgress.byHandle(p.handleID)
		if egr == nil || egr.sess == nil || egr.sess.ID != p.id {
			return
		}
		if moved {
			go s.followMovedRunEgress(p.workDir, egr, p.ex.ID(), p.handleID)
			return
		}
		egr.close("its run ended before its takeover was decided")
	default:
		sl := liveLeases.get(p.id)
		if sl == nil {
			return
		}
		if moved {
			handOverWhenTaken(sl)
			return
		}
		sl.Close()
	}
}

// handOverWhenTaken lets go of a lease whose run another member took over,
// once that member holds it (awaitLeaseTakeover), or at once when it does
// already.
func handOverWhenTaken(sl *secretLease) {
	if sl == nil || sl.broker == nil || sl.lease == nil {
		return
	}
	if sl.broker.HeldElsewhere(sl.lease.ID) {
		sl.handOver()
		return
	}
	go awaitLeaseTakeover(sl)
}

// lostWhileOwned turns a takeover that lost the lease's conditional write into
// one tried again when this process still owns the run (Task 20451): the
// process that won it took the lease without owning the run — a retry it made
// as the run moved here — and the next attempt takes it from that process.
// Refused by takeoverGuard, the run is another member's, and moved stands.
func (s *Server) lostWhileOwned(workDir string, ex executor.Executor, handleID string, res takeoverResult) takeoverResult {
	if res.outcome != hubmetrics.TakeoverMoved || res.holder != "" {
		return res
	}
	if s.clusterNode() == nil {
		return res
	}
	p := &pendingTakeover{workDir: workDir, ex: ex, handleID: handleID}
	switch state, why := s.takeoverRunState(p); state {
	case "":
		return takeoverResult{outcome: hubmetrics.TakeoverRetrying,
			err: fmt.Errorf("another hub process took it over while this one owns the run: %v", res.err)}
	case hubmetrics.TakeoverRetrying:
		// Not knowing whether the run is this process's decides nothing:
		// the next attempt asks again, and the guard before its write too.
		return takeoverResult{outcome: hubmetrics.TakeoverRetrying,
			err: fmt.Errorf("%v, and %v", res.err, why)}
	}
	return res
}

// takeoverGuard is the condition a takeover of a credential of workDir's run
// takes it over on (Task 20451): this process owns the run, and so may take
// the credential from whoever holds it. Asked by the broker just before the
// conditional write that takes the lease, so a retry made after the run moved
// to another member — which holds the lease for it — refuses as moved rather
// than taking it back; an owner row that cannot be read decides nothing.
func (s *Server) takeoverGuard(workDir string) secretbroker.RestoreOption {
	return secretbroker.TakingFrom(func(holder string) error {
		n := s.clusterNode()
		if n == nil {
			return nil
		}
		o, found, err := n.Lookup(ownerRun, workDir)
		if err != nil {
			return fmt.Errorf("the run's owner row could not be read: %w", err)
		}
		if !found {
			return fmt.Errorf("%w: the run is no longer on record", secretbroker.ErrLeaseMoved)
		}
		if !o.Self {
			return fmt.Errorf("%w: hub process %s owns the run now", secretbroker.ErrLeaseMoved, o.InstanceID)
		}
		return nil
	})
}

// attemptTakeover makes one attempt at p's credential.
func (s *Server) attemptTakeover(p *pendingTakeover) takeoverResult {
	switch p.kind {
	case takeoverWorkspace:
		return s.takeOverWorkspace(p.workDir, p.ex, p.handleID, &runWorkspaceMeta{Lease: p.id, Session: p.session})
	case takeoverEgress:
		return s.takeOverEgress(p.workDir, p.ex, p.handleID, p.id)
	default:
		return s.takeOverRunLease(p.workDir, p.ex, p.handleID, p.id)
	}
}

// takeoverRunState reports, as an outcome and why, whether p's run is still
// this process's to take credentials over for: "" while it is; moved when
// another member adopted it — and reads p off the run's owner row — and failed
// when the run is over; retrying when its owner row cannot be read, which
// decides nothing.
func (s *Server) takeoverRunState(p *pendingTakeover) (string, error) {
	n := s.clusterNode()
	if n == nil {
		return "", nil
	}
	o, found, err := n.Lookup(ownerRun, p.workDir)
	if err != nil {
		return hubmetrics.TakeoverRetrying, fmt.Errorf("the run's owner row could not be read: %w", err)
	}
	if !found {
		return hubmetrics.TakeoverFailed, errors.New("its run is no longer on record: it ended before the credential could be taken over")
	}
	var meta runOwnerMeta
	if err := o.Meta(&meta); err == nil && (meta.Handle == "" || meta.Executor != p.ex.ID() || meta.Handle != p.handleID) {
		return hubmetrics.TakeoverFailed, errors.New("its run is over: the project's run on record is another")
	}
	if !o.Self {
		return hubmetrics.TakeoverMoved, fmt.Errorf("hub process %s adopted the run, and takes it over from the run's "+
			"owner row", o.InstanceID)
	}
	return "", nil
}

// endTakeover ends p with outcome — counted, journaled when it ever went
// undecided or was taken over in the end — brings the run's owner row up to
// date, and reports whether this call ended p.
func (s *Server) endTakeover(p *pendingTakeover, outcome string, cause error) bool {
	if !p.end(outcome) {
		return false
	}
	if outcome != "" {
		hubmetrics.LeaseTakeovers.Inc(p.kind, outcome)
	}
	if p.wasUndecided() || outcome == hubmetrics.TakeoverTakenOver {
		journalTakeover(p, outcome, cause)
	}
	// Forgotten once counted and journaled, so whoever finds it gone finds
	// both; and before the owner row is rewritten, which names it no more.
	pendingTakeovers.removeIf(p)
	fields := map[string]interface{}{"project": p.workDir, "kind": p.kind, "id": p.id, "outcome": outcome}
	if cause != nil {
		fields["reason"] = takeoverReason(cause)
	}
	if outcome == hubmetrics.TakeoverFailed {
		s.log().Warn("cluster", 0, "gave up taking over a credential of an adopted run", fields)
	} else {
		s.log().Info("cluster", 0, "decided the takeover of a credential of an adopted run", fields)
	}
	s.refreshRunCredentials(p.workDir, p.ex, p.handleID)
	return true
}

// endRunTakeovers ends what is still kept for a run that is over, for why. A
// takeover still undecided is recorded as failed — the run never had the
// credential back — and, with retire, its record retired if the store will
// have that now and no attempt is running: one that is lets go of what it
// takes itself (undoEndedAttempt), and a record left behind is the janitor's
// once it lapses. An egress session a live member serves is that member's to
// end, which it does once the run's owner row no longer names the run.
func (s *Server) endRunTakeovers(ex executor.Executor, handleID, why string, retire bool) {
	if ex == nil || handleID == "" {
		return
	}
	for _, p := range pendingTakeovers.forHandle(ex.ID(), handleID) {
		state, _ := s.takeoverRunState(p)
		if p.elsewhere() {
			// Uncounted: counted as moved when it was left with its holder.
			// For a run that moved on, an attempt running now follows the
			// session it took rather than closing it (undoEndedAttempt).
			how := ""
			if state == hubmetrics.TakeoverMoved {
				how = hubmetrics.TakeoverMoved
			}
			if p.end(how) {
				pendingTakeovers.removeIf(p)
			}
			continue
		}
		if state == hubmetrics.TakeoverMoved {
			// Another member owns the run: it is not over, and what this
			// member kept is that member's to take over, not to retire.
			s.endTakeover(p, hubmetrics.TakeoverMoved,
				errors.New("another hub process adopted the run, and takes it over from the run's owner row"))
			continue
		} else if state == hubmetrics.TakeoverRetrying {
			retire = false // nothing is retired on a guess: the janitor's, once it lapses
		}
		_, _, _, reason, _ := p.snapshot()
		if !s.endTakeover(p, hubmetrics.TakeoverFailed, fmt.Errorf("%s before it could be taken over "+
			"(the last attempt: %s)", why, reason)) || !retire {
			continue
		}
		if !p.attemptMu.TryLock() {
			continue // an attempt is running: it lets go of what it takes
		}
		switch p.kind {
		case takeoverEgress:
			retireRunEgressRecords([]string{p.id}, "its run ended while no hub process held the session")
		default:
			if !liveLeases.held(p.id) {
				retireLeaseRecord(p.id, "its run ended while no hub process held the lease")
			}
		}
		p.attemptMu.Unlock()
	}
}

// handOverRunTakeovers lets go of what is kept for a run another member took
// over: that member reads it off the run's owner row, which still names it,
// and tries it itself. An attempt still running lets go of what it takes.
func (s *Server) handOverRunTakeovers(ex executor.Executor, handleID string) {
	if ex == nil {
		return
	}
	for _, p := range pendingTakeovers.forHandle(ex.ID(), handleID) {
		if p.elsewhere() {
			// Counted as moved when it was left with its holder.
			if p.end(hubmetrics.TakeoverMoved) {
				pendingTakeovers.removeIf(p)
			}
			continue
		}
		s.endTakeover(p, hubmetrics.TakeoverMoved,
			errors.New("another hub process adopted the run, and takes it over from the run's owner row"))
	}
}

// wakeTakeoversHeldElsewhere brings forward the next look at every egress
// session a live member was serving for a run this process adopted: one of
// those members may just have stopped.
func wakeTakeoversHeldElsewhere() {
	for _, p := range pendingTakeovers.all() {
		if p.elsewhere() {
			p.nudge()
		}
	}
}

// nudgeTakeoverOf brings forward the next attempt at the takeover a request
// presenting row's session waits on: the lease the session stands on, or — an
// egress session — the session itself.
func nudgeTakeoverOf(row statedb.ProxySessionRow) {
	if row.Kind == statedb.ProxySessionEgress {
		if p := pendingTakeovers.get(takeoverEgress, row.SessionID); p != nil {
			p.nudge()
		}
		return
	}
	if row.LeaseID == "" {
		return
	}
	for _, kind := range []string{takeoverRun, takeoverWorkspace} {
		if p := pendingTakeovers.get(kind, row.LeaseID); p != nil {
			p.nudge()
		}
	}
}

// ── deadlines ────────────────────────────────────────────────────────────────

// takeoverDeadline is the expiry a takeover is tried until: the lease's or the
// session's, as its record says now. While the record cannot be read at all it
// is the longest either is issued for, counted from since: nothing lives longer
// unextended, and the process that extended it is the one that stopped.
func takeoverDeadline(kind, id string, since time.Time) time.Time {
	if t, ok := recordedExpiry(kind, id); ok {
		return t
	}
	if kind == takeoverEgress {
		return since.Add(egressbroker.DefaultSessionTTL)
	}
	return since.Add(secretbroker.DefaultMaxLeaseTTL)
}

// recordedExpiry reads the expiry the record of a lease or an egress session
// carries.
func recordedExpiry(kind, id string) (time.Time, bool) {
	if kind == takeoverEgress {
		db, closeDB := egressRecordDB()
		if db == nil {
			return time.Time{}, false
		}
		defer closeDB()
		row, err := db.GetProxySession(statedb.ProxySessionEgress, id)
		if err != nil {
			return time.Time{}, false
		}
		return row.ExpiresAt, true
	}
	dir := controlPlaneDir()
	if dir == "" {
		return time.Time{}, false
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return time.Time{}, false
	}
	defer db.Close()
	row, err := db.GetSecretLease(id)
	if err != nil {
		return time.Time{}, false
	}
	return row.ExpiresAt, true
}

// ── the run's owner row ──────────────────────────────────────────────────────

// runMetaLocks serialise the writes of a run's credentials into its owner
// row, so the last one written is the one that read the latest state. Sharded
// by project, so a retry waiting on a busy database holds up only its own
// run's writes, not another project's start.
var runMetaLocks [64]sync.Mutex

// lockRunMeta locks workDir's owner-row writes and returns the unlock.
func lockRunMeta(workDir string) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(workDir))
	mu := &runMetaLocks[h.Sum32()%uint32(len(runMetaLocks))]
	mu.Lock()
	return mu.Unlock
}

// fillRunCredentials sets the credentials meta names: what this process holds
// for the workload, and what it keeps trying (Task 20451) — so a process
// adopting the run after this one tries those too — with the undecided ones
// named apart, for `cloop hub doctor` and Settings → Hub health.
func fillRunCredentials(meta *runOwnerMeta, executorID, handleID string) {
	meta.Leases = liveLeases.forHandle(executorID, handleID)
	meta.Egress = liveEgress.idsForHandle(handleID)
	meta.Workspace = liveLeases.workspaceForHandle(executorID, handleID)
	meta.Takeovers = nil
	for _, p := range pendingTakeovers.forHandle(executorID, handleID) {
		switch p.kind {
		case takeoverRun:
			meta.Leases = appendMissing(meta.Leases, p.id)
		case takeoverWorkspace:
			if meta.Workspace == nil {
				meta.Workspace = &runWorkspaceMeta{Lease: p.id, Session: p.session}
			}
		case takeoverEgress:
			meta.Egress = appendMissing(meta.Egress, p.id)
		}
		if !p.elsewhere() {
			meta.Takeovers = append(meta.Takeovers, p.record())
		}
	}
	sort.Strings(meta.Leases)
	sort.Strings(meta.Egress)
}

func appendMissing(list []string, v string) []string {
	for _, have := range list {
		if have == v {
			return list
		}
	}
	return append(list, v)
}

// refreshRunCredentials rewrites the credentials workDir's owner row names, if
// this member owns the run and the row is the workload's. The rest of the row
// is left as it is.
func (s *Server) refreshRunCredentials(workDir string, ex executor.Executor, handleID string) {
	n := s.clusterNode()
	if n == nil || workDir == "" || ex == nil {
		return
	}
	defer lockRunMeta(workDir)()
	o, found, err := n.Lookup(ownerRun, workDir)
	if err != nil || !found || !o.Self {
		return
	}
	var meta runOwnerMeta
	if err := o.Meta(&meta); err != nil || meta.Executor != ex.ID() || meta.Handle != handleID {
		return
	}
	fillRunCredentials(&meta, ex.ID(), handleID)
	if _, err := n.UpdateMeta(ownerRun, workDir, meta); err != nil {
		s.log().Warn("cluster", 0, "could not record the credentials of an adopted run",
			map[string]interface{}{"project": workDir, "error": err.Error()})
	}
}

// ── the journal ──────────────────────────────────────────────────────────────

// journalTakeover writes one row on the run's journal: for outcome "", that p
// is kept — undecided, or left with the live process serving it — and for any
// other, what it came to.
func journalTakeover(p *pendingTakeover, outcome string, cause error) {
	holder, since, attempts, reason, until := p.snapshot()
	self := leaseHolderID()
	subject := takeoverSubject(p)
	var msg string
	switch {
	case outcome == "" && holder != "":
		msg = fmt.Sprintf("%s stays with hub process %s, which still serves it: nothing forwards egress between hub "+
			"processes. This process (%s) takes it over if that one stops, and that one ends it when the run ends.",
			subject, holder, self)
	case outcome == "":
		msg = fmt.Sprintf("%s could not be taken over by the hub process that adopted this run (%s): %s. It is tried "+
			"again until it lapses at %s; until then %s.", subject, self, reason, until.UTC().Format(time.RFC3339),
			takeoverStake(p.kind))
	case outcome == hubmetrics.TakeoverTakenOver && since.IsZero():
		msg = fmt.Sprintf("%s was taken over by the hub process that adopted this run (%s): the one that served it "+
			"stopped.", subject, self)
	case outcome == hubmetrics.TakeoverTakenOver:
		msg = fmt.Sprintf("%s was taken over by the hub process that adopted this run (%s) after %d attempts over %s; "+
			"what it feeds is served again.", subject, self, attempts+1, takeoverNow().Sub(since).Round(time.Second))
	case outcome == hubmetrics.TakeoverFailed:
		msg = fmt.Sprintf("%s was never taken over: %s. The run carries on without it: %s.", subject,
			takeoverReason(cause), takeoverStake(p.kind))
	default:
		msg = fmt.Sprintf("%s was not taken over: %s.", subject, takeoverReason(cause))
	}
	details := map[string]any{
		"kind": p.kind, "id": p.id, "member": self, "executor": p.ex.ID(), "handle": p.handleID,
		"attempts": attempts,
	}
	if outcome == "" {
		details["outcome"] = hubmetrics.TakeoverRetrying
		if holder != "" {
			details["outcome"], details["holder"] = hubmetrics.TakeoverMoved, holder
		}
	} else {
		details["outcome"] = outcome
	}
	if p.session != "" {
		details["session"] = p.session
	}
	if !since.IsZero() {
		details["since"] = since.UTC().Format(time.RFC3339)
		details["until"] = until.UTC().Format(time.RFC3339)
	}
	if r := takeoverReason(cause); r != "" {
		details["reason"] = r
	} else if reason != "" {
		details["reason"] = reason
	}
	raw, _ := json.Marshal(details)
	state.LogEvent(p.workDir, state.EventRow{
		Type: state.EventLeaseTakeover, Step: state.NoStep, Message: msg, Details: string(raw),
	})
}

// takeoverSubject names p's credential in its journal rows.
func takeoverSubject(p *pendingTakeover) string {
	switch p.kind {
	case takeoverWorkspace:
		if p.session != "" {
			return fmt.Sprintf("The run's workspace lease %s (pinned git proxy session %s)", p.id, p.session)
		}
		return "The run's workspace lease " + p.id
	case takeoverEgress:
		return "The run's egress proxy session " + p.id
	default:
		return "The run's secret lease " + p.id
	}
}

// takeoverStake says what a run goes without while kind is not taken over.
func takeoverStake(kind string) string {
	switch kind {
	case takeoverWorkspace:
		return "the pinned git session it stands on is not served, so the run's push write-back through it is refused"
	case takeoverEgress:
		return "the run's requests through the hub's egress proxy are refused"
	default:
		return "what it feeds — the run's git proxy and Kubernetes monitor sessions, its GitHub App tokens, its " +
			"model relay session — is not served, so the run's git pushes and kubectl calls through the hub are refused"
	}
}

// ── a moved run's egress session ─────────────────────────────────────────────

// followMovedRunEgress keeps serving, from this process, the egress session of
// a run another member adopted while this one lives, and ends it when the run
// ends. The session is not handed over — nothing forwards egress between
// members, and the workload's proxy address may be this process's own listener
// — but the run is settled by its adopter now, so this process learns of its
// end only from the run's owner row: gone, or naming another workload.
func (s *Server) followMovedRunEgress(workDir string, egr *runEgress, executorID, handleID string) {
	if egr == nil || egr.sess == nil {
		return
	}
	defer recoverGoroutine("follow the egress session of a moved run: " + handleID)
	t := time.NewTicker(movedEgressCheck)
	defer t.Stop()
	for {
		select {
		case <-egr.sess.Done():
			return
		case <-t.C:
		}
		switch verdict, why := s.movedRunEgressVerdict(workDir, egr, executorID, handleID); verdict {
		case movedEgressOver:
			egr.close(why)
			return
		case movedEgressTaken:
			egr.suspend(why)
			return
		case movedEgressBack:
			return
		}
	}
}

// What the member serving a moved run's egress session does with it next.
const (
	movedEgressServe = iota
	// movedEgressOver: the run ended; the session ends with it.
	movedEgressOver
	// movedEgressTaken: another process took its record over, and serves it.
	movedEgressTaken
	// movedEgressBack: the run is this member's again, and so is the session.
	movedEgressBack
)

func (s *Server) movedRunEgressVerdict(workDir string, egr *runEgress, executorID, handleID string) (int, string) {
	n := s.clusterNode()
	if n == nil {
		return movedEgressServe, ""
	}
	o, found, err := n.Lookup(ownerRun, workDir)
	if err != nil {
		return movedEgressServe, ""
	}
	if !found {
		return movedEgressOver, "its run ended on the hub process that adopted it"
	}
	var meta runOwnerMeta
	if err := o.Meta(&meta); err == nil && (meta.Handle == "" || meta.Executor != executorID || meta.Handle != handleID) {
		// A claim for another run — the project's next, started here or
		// anywhere — or one not dispatched yet: this run is over.
		return movedEgressOver, "its run ended on the hub process that adopted it"
	}
	if o.Self {
		return movedEgressBack, ""
	}
	db, closeDB := egressRecordDB()
	if db == nil {
		return movedEgressServe, ""
	}
	defer closeDB()
	row, err := db.GetProxySession(statedb.ProxySessionEgress, egr.sess.ID)
	switch {
	case errors.Is(err, statedb.ErrProxySessionNotFound):
		return movedEgressOver, "its record is gone"
	case err != nil:
		return movedEgressServe, ""
	case row.Holder != "" && row.Holder != leaseHolderID():
		return movedEgressTaken, "hub process " + row.Holder + " took its record over and serves it"
	}
	return movedEgressServe, ""
}
