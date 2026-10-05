package egressbroker

// durable.go lets a proxy session outlive the hub process that redeemed it
// (Task 20383).
//
// A session lived only in the memory of the process whose proxy served it, and
// for a reason the Session comment used to give: its quota could not be
// enforced by anything else, so a session that survived its process would be a
// credential with no meter on it. That reason holds only while the counters die
// with the process. A broker with a SessionStore records every Durable session
// when it is redeemed and checkpoints its counters as it goes; the hub process
// that adopts the session's run restores it with those counters, and every byte
// the restored session moves is counted on top of them, against the same quota.
// What a SIGKILL can lose is the traffic since the last checkpoint — the
// keepalive's tick, a minute at most — never the quota itself.
//
// Restore re-reads the grant, as a renewal does: a session whose grant was
// revoked or expired while no process held it is refused, with a denied row,
// and never comes back.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

var (
	// ErrSessionExists: the broker already holds a session with that id.
	ErrSessionExists = errors.New("egressbroker: a session with that id is already live")
	// ErrStoreUnavailable: RestoreSession could not read the session's grant.
	// That says nothing about the grant, so the session is neither restored
	// nor ended, and the caller tries again.
	ErrStoreUnavailable = errors.New("egressbroker: the grant store could not be read")
)

// SessionRecord is what a SessionStore keeps of a session: its identity, the
// SHA-256 of its token, the grant snapshot it enforces and the requester it was
// issued to — never the token.
type SessionRecord struct {
	ID string
	// TokenSHA256 is the hex SHA-256 of the proxy token.
	TokenSHA256 string
	GrantID     string
	// Grant is the policy snapshot the session enforces, quotas included.
	Grant      Grant
	ExecutorID string
	ProjectID  string
	TaskID     string
	RunID      string
	Actor      string
	// Labels are the requester's, so a restore asks whether the grant is still
	// issued to the same party.
	Labels    map[string]string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Counters  SessionCounters
}

// SessionCounters is what a session has moved.
type SessionCounters struct {
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
	Requests  int64 `json:"requests"`
}

// SessionStore persists the record of every Durable session: its redemption,
// its renewals, its counters and its end. Errors are the implementation's to
// report — a session whose record could not be written still serves, and is
// noted on its redemption row.
type SessionStore interface {
	SaveSession(rec SessionRecord) error
	ExtendSession(id string, expiresAt time.Time) error
	CheckpointSession(id string, c SessionCounters) error
	CloseSession(id, reason string, at time.Time, c SessionCounters) error
}

// WithSessionStore records every Durable session in store (Task 20383).
func WithSessionStore(store SessionStore) Option {
	return func(b *Broker) {
		if store != nil {
			b.sessionStore = store
		}
	}
}

// durability is a session's link to its record. The zero value is a session
// with none.
type durability struct {
	mu      sync.Mutex
	durable bool
	// last is the counters the record holds, so a checkpoint that would
	// write the same numbers again writes nothing.
	last SessionCounters
}

// Durable reports whether a SessionStore holds a record of the session.
func (s *Session) Durable() bool {
	if s == nil {
		return false
	}
	s.rec.mu.Lock()
	defer s.rec.mu.Unlock()
	return s.rec.durable
}

// Counters snapshots what the session has moved.
func (s *Session) Counters() SessionCounters {
	if s == nil {
		return SessionCounters{}
	}
	return SessionCounters{BytesUp: s.BytesUp(), BytesDown: s.BytesDown(), Requests: s.Requests()}
}

// record renders the session for its store.
func (s *Session) record(hash [sha256.Size]byte) SessionRecord {
	return SessionRecord{
		ID:          s.ID,
		TokenSHA256: hex.EncodeToString(hash[:]),
		GrantID:     s.GrantID,
		Grant:       s.Grant,
		ExecutorID:  s.ExecutorID,
		ProjectID:   s.ProjectID,
		TaskID:      s.TaskID,
		RunID:       s.RunID,
		Actor:       s.Actor,
		Labels:      copyLabels(s.requester.Labels),
		IssuedAt:    s.IssuedAt,
		ExpiresAt:   s.ExpiresAt(),
		Counters:    s.Counters(),
	}
}

// saveRecord writes a new session's record, before the session is visible.
func (b *Broker) saveRecord(sess *Session) error {
	if b.sessionStore == nil {
		return nil
	}
	if err := b.sessionStore.SaveSession(sess.record(sess.tokenHash)); err != nil {
		return err
	}
	sess.rec.mu.Lock()
	sess.rec.durable = true
	sess.rec.last = sess.Counters()
	sess.rec.mu.Unlock()
	return nil
}

// CheckpointSession writes a live durable session's counters to its record
// when they moved since the last checkpoint. A hub calls it on its keepalive's
// tick, which bounds what a SIGKILL can lose to one tick of traffic.
func (b *Broker) CheckpointSession(id string) {
	sess := b.Session(id)
	if sess == nil || sess.Closed() || b.sessionStore == nil {
		return
	}
	now := sess.Counters()
	sess.rec.mu.Lock()
	if !sess.rec.durable || sess.rec.last == now {
		sess.rec.mu.Unlock()
		return
	}
	sess.rec.mu.Unlock()
	if err := b.sessionStore.CheckpointSession(id, now); err != nil {
		return
	}
	sess.rec.mu.Lock()
	sess.rec.last = now
	sess.rec.mu.Unlock()
}

// recordExtension moves a durable session's recorded deadline, and checkpoints
// its counters with it.
func (b *Broker) recordExtension(sess *Session) {
	if b.sessionStore == nil || !sess.Durable() {
		return
	}
	_ = b.sessionStore.ExtendSession(sess.ID, sess.ExpiresAt())
	b.CheckpointSession(sess.ID)
}

// recordClose records a durable session's end with its final counters.
func (b *Broker) recordClose(sess *Session, reason string) {
	if b.sessionStore == nil || !sess.Durable() {
		return
	}
	_ = b.sessionStore.CloseSession(sess.ID, reason, b.now(), sess.Counters())
}

// RestoreRequest is a session to bring back.
type RestoreRequest struct {
	// Record is the session as its store recorded it.
	Record SessionRecord
	// From names the hub process the session was taken over from.
	From string
}

// RestoreSession brings back a session another hub process redeemed, under the
// same id, token hash and deadline, enforcing the grant snapshot it was issued
// with and counting on from the counters its record holds.
//
// The grant is re-read first, exactly as a renewal re-reads it: one revoked or
// expired while no process held the session, or no longer issued to its
// requester, refuses the restore with a denied egress.restore row, and the
// session is never served again. A grant that could not be read refuses
// nothing: ErrStoreUnavailable, and the caller tries again. The deadline is
// clamped to what a renewal would set now — the grant's expiry, the session
// ceiling from now — never moved later; a session already past it is refused
// as expired.
func (b *Broker) RestoreSession(ctx context.Context, req RestoreRequest) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec := req.Record
	ev := secretbroker.Event{
		Action:     secretbroker.ActionEgressRestore,
		Actor:      rec.Actor,
		LeaseID:    rec.ID,
		GrantID:    rec.GrantID,
		ExecutorID: rec.ExecutorID,
		ProjectID:  rec.ProjectID,
		TaskID:     rec.TaskID,
		RunID:      rec.RunID,
	}
	id := strings.TrimSpace(rec.ID)
	hash, err := hex.DecodeString(strings.TrimSpace(rec.TokenSHA256))
	if id == "" || err != nil || len(hash) != sha256.Size {
		return nil, b.deny(ev, fmt.Errorf("%w: session %q has an unusable record", ErrInvalidGrant, rec.ID))
	}
	if rec.Grant.ID != rec.GrantID {
		return nil, b.deny(ev, fmt.Errorf("%w: session %s recorded a snapshot of grant %s under grant %s",
			ErrInvalidGrant, id, rec.Grant.ID, rec.GrantID))
	}

	requester := secretbroker.Requester{
		ExecutorID: rec.ExecutorID,
		ProjectID:  rec.ProjectID,
		Labels:     copyLabels(rec.Labels),
	}
	now := b.now()
	// recheckGrant reports a grant it could not read as missing, which would
	// end the session for good on a read error.
	if _, err := b.store.GetGrant(rec.GrantID); err != nil && !errors.Is(err, ErrGrantNotFound) {
		return nil, fmt.Errorf("%w: grant %s: %v", ErrStoreUnavailable, rec.GrantID, err)
	}
	probe := &Session{GrantID: rec.GrantID, requester: requester}
	current, err := b.recheckGrant(probe, now)
	if err != nil {
		return nil, b.deny(ev, err)
	}
	ev.Subject = current.Subject.String()

	// The policy is the stored grant's, not the record's snapshot: a grant is
	// immutable but for its revocation, so the stored grant is the authority
	// and a snapshot that disagrees with it was not written by Redeem. A
	// quota the grant leaves to the hub is the tighter of the one the session
	// was redeemed under and this broker's default now: a default lowered
	// while no process served the session applies to it, a raised one does
	// not widen it.
	snapshot := current
	if snapshot.MaxBytesUp == 0 {
		snapshot.MaxBytesUp = tighterQuota(rec.Grant.MaxBytesUp, b.defaultUp)
	}
	if snapshot.MaxBytesDown == 0 {
		snapshot.MaxBytesDown = tighterQuota(rec.Grant.MaxBytesDown, b.defaultDown)
	}
	ev.Constraints = snapshot.Summary()

	// The deadline is the recorded one, never later than a renewal would set
	// it now: the grant's own expiry, and this broker's session ceiling from
	// now.
	deadline := rec.ExpiresAt
	if limit := current.SessionDeadline(now, b.maxSessionTTL); limit.Before(deadline) {
		deadline = limit
	}
	if !now.Before(deadline) {
		return nil, b.deny(ev, fmt.Errorf("%w: session %s lapsed at %s while no hub process held it",
			ErrSessionExpired, id, deadline.UTC().Format(time.RFC3339)))
	}

	sess := &Session{
		ID:         id,
		GrantID:    rec.GrantID,
		Grant:      snapshot,
		ExecutorID: rec.ExecutorID,
		ProjectID:  rec.ProjectID,
		TaskID:     rec.TaskID,
		RunID:      rec.RunID,
		Actor:      rec.Actor,
		IssuedAt:   rec.IssuedAt,
		doneCh:     make(chan struct{}),
		requester:  requester,
	}
	copy(sess.tokenHash[:], hash)
	sess.setExpiry(deadline)
	sess.bytesUp.Store(max(rec.Counters.BytesUp, 0))
	sess.bytesDown.Store(max(rec.Counters.BytesDown, 0))
	sess.requests.Store(max(rec.Counters.Requests, 0))
	sess.rec.durable = b.sessionStore != nil
	sess.rec.last = sess.Counters()

	b.mu.Lock()
	if _, live := b.sessions[id]; live {
		b.mu.Unlock()
		return nil, b.deny(ev, fmt.Errorf("%w: %s", ErrSessionExists, id))
	}
	b.sessions[id] = sess
	b.mu.Unlock()
	hubmetrics.EgressSessionsLive.Inc()

	// The same race Redeem closes: a revocation that landed between the
	// re-read above and the insert is caught here, or by Revoke's snapshot of
	// the map, which now holds the session.
	fresh, ferr := b.store.GetGrant(rec.GrantID)
	if ferr != nil && !errors.Is(ferr, ErrGrantNotFound) {
		// Unknown either way: not served, not ended, tried again.
		b.SuspendSession(id, "its grant could not be re-read")
		return nil, fmt.Errorf("%w: grant %s: %v", ErrStoreUnavailable, rec.GrantID, ferr)
	}
	if ferr != nil || !fresh.Active(b.now()) {
		b.CloseSession(id, "grant became inactive during restore")
		return nil, b.deny(ev, fmt.Errorf("%w: grant was revoked or expired during the restore", ErrNoGrant))
	}

	ev.ExpiresAt = deadline
	ev.BytesUp, ev.BytesDown = sess.BytesUp(), sess.BytesDown()
	ev.Decision = secretbroker.DecisionAllow
	ev.Reason = fmt.Sprintf("proxy session restored by the hub process that adopted its run, counting on from "+
		"%s up and %s down", FormatBytes(sess.BytesUp()), FormatBytes(sess.BytesDown()))
	if from := strings.TrimSpace(req.From); from != "" {
		ev.Reason += " (held until then by " + from + ")"
	}
	b.emit(ev)
	return sess, nil
}

// SuspendSession stops serving a session without ending it: it leaves the
// broker and its sockets close — the process is going away, or another one
// serves the session now — but no close row is written and its record stays
// open, with its counters checkpointed, for the hub process that adopts its run
// to restore. It reports whether the session was here.
func (b *Broker) SuspendSession(id, reason string) bool {
	b.CheckpointSession(id)
	b.mu.Lock()
	sess := b.sessions[id]
	delete(b.sessions, id)
	b.mu.Unlock()
	if sess == nil {
		return false
	}
	if reason == "" {
		reason = "suspended"
	}
	if sess.end("suspended: " + reason) {
		hubmetrics.EgressSessionsLive.Add(-1)
	}
	return true
}

// tighterQuota is the smaller of two byte quotas, where zero is unlimited.
func tighterQuota(a, b int64) int64 {
	switch {
	case a <= 0:
		return max(b, 0)
	case b <= 0:
		return a
	}
	return min(a, b)
}
