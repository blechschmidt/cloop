package claudeproxy

// durable.go lets a CI session outlive the hub process that minted it (Task
// 20390).
//
// A session lived only in the registry of the process that minted it, for up
// to MaxTTL. When that process stopped — the nightly deploy of a hub, a
// rolling update of a cluster — every GitHub Actions job relaying through it
// went on presenting its token and got a 401: Claude Code retries one for
// about three minutes and then fails the job with "Not logged in", and the job
// cannot federate again, because the OIDC token it exchanged has been spent.
//
// A registry with a Store records every session when it is minted — its id,
// the SHA-256 of its token, the rule and pipeline it was minted for, its
// policy, never the token — keeps its counters in step (Checkpoint) and
// records its end. A process that stops gracefully suspends its sessions
// instead of closing them. When a request presents the token of a session no
// live process serves, the hub process receiving it may take the record over
// and Restore the session: under the same id and token hash, with the
// counters it had reached, held to its rule as the rule stands then. Unlike
// the git proxy's sessions no lease stands behind one, so restoring it where
// the request arrives separates it from nothing.
//
// What a record is worth to someone who reads it: nothing that authenticates.
// The token hash is what the registry keeps in memory instead of the token,
// and the upstream credential is the hub's configuration, not the session's.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Errors Restore distinguishes.
var (
	// ErrSessionExists: the registry already holds a session with that id.
	ErrSessionExists = errors.New("claudeproxy: a session with that id is already live")
	// ErrSessionLapsed: the session's TTL ran out before it could be restored.
	ErrSessionLapsed = errors.New("claudeproxy: session lapsed before it could be restored")
	// ErrRecordGone is what a Store answers a checkpoint whose record is no
	// longer this process's to write: closed by another hub process — its
	// rule was withdrawn, it was revoked — or taken over by one. The
	// registry stops serving the session: the record, not this process's
	// memory, says whether a session stands.
	ErrRecordGone = errors.New("claudeproxy: the session's record is closed or held by another hub process")
	// ErrClosedHere: this registry closed the session — revoked, expired,
	// its rule withdrawn — and does not bring back a session it ended, even
	// when the write of that end to the record failed.
	ErrClosedHere = errors.New("claudeproxy: this hub process closed the session")
	// ErrTooManySessions: MaxSessions are live. It says nothing about the
	// session asked for, which may be minted or restored once one ends.
	ErrTooManySessions = errors.New("claudeproxy: the session limit is reached")
)

// SessionRecord is what a Store keeps of a session: everything Restore needs.
// It has no field a token or an upstream credential could travel in.
type SessionRecord struct {
	ID string
	// TokenSHA256 is the hex SHA-256 of the session token.
	TokenSHA256 string
	Policy      Policy

	RuleID     string
	RuleName   string
	Project    string
	Subject    string
	Repository string
	Ref        string
	Workflow   string
	Actor      string
	RunID      string
	RunURL     string
	// Claims is the verified assertion the session was minted for, as the
	// hub chose to record it: opaque to this package, which never reads it.
	// The hub holds a restored session to its rule against it.
	Claims json.RawMessage

	IssuedAt  time.Time
	ExpiresAt time.Time

	// Usage and LastUsed are what the session had spent when it was last
	// checkpointed.
	Usage    Usage
	LastUsed time.Time
}

// SessionStore persists the record of every session and keeps it in step.
//
// Errors are the implementation's to report: the registry cannot do anything
// useful with one beyond what it does — a session whose record could not be
// written is served all the same, and its minted row says what was lost.
type SessionStore interface {
	// SaveSession records a session this process now serves.
	SaveSession(rec SessionRecord) error
	// CheckpointSession records what a session this process serves has
	// spent so far.
	CheckpointSession(id string, u Usage, lastUsed time.Time) error
	// CloseSession records that a session this process served has ended,
	// and why, with what it spent.
	CloseSession(id, reason string, at time.Time, u Usage) error
}

// checkpoint is the account of a session last written to its Store.
type checkpoint struct {
	usage    Usage
	lastUsed int64
}

// record renders the session for its Store.
func (s *Session) record(claims json.RawMessage) SessionRecord {
	return SessionRecord{
		ID:          s.ID,
		TokenSHA256: hex.EncodeToString(s.tokenHash[:]),
		Policy:      s.Policy.clone(),
		RuleID:      s.RuleID,
		RuleName:    s.RuleName,
		Project:     s.Project,
		Subject:     s.Subject,
		Repository:  s.Repository,
		Ref:         s.Ref,
		Workflow:    s.Workflow,
		Actor:       s.Actor,
		RunID:       s.RunID,
		RunURL:      s.RunURL,
		Claims:      append(json.RawMessage(nil), claims...),
		IssuedAt:    s.IssuedAt,
		ExpiresAt:   s.ExpiresAt,
		Usage:       s.Usage(),
		LastUsed:    s.LastUsed(),
	}
}

// Durable reports whether a Store holds a record of the session.
func (s *Session) Durable() bool { return s != nil && s.durable }

// clone copies a policy, so a record never shares its allowlist with the
// session it describes.
func (p Policy) clone() Policy {
	p.Models = append([]string(nil), p.Models...)
	return p
}

// closeRecord records a durable session's end. Called once, by whichever path
// ended it.
func (r *Registry) closeRecord(s *Session, reason string) {
	if s == nil || !s.durable || r.Store == nil {
		return
	}
	_ = r.Store.CloseSession(s.ID, reason, r.now(), s.Usage())
}

// Checkpoint writes to the Store what every durable session has spent since
// its last checkpoint, and returns how many it wrote. The hub calls it on a
// timer — so a process that dies loses at most one interval's counts — and
// when it stops. A session whose counters have not moved is skipped, and one
// whose write fails is tried again next time.
func (r *Registry) Checkpoint() int {
	if r.Store == nil {
		return 0
	}
	r.mu.Lock()
	live := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		if s.durable {
			live = append(live, s)
		}
	}
	r.mu.Unlock()
	n := 0
	for _, s := range live {
		if r.checkpoint(s) {
			n++
		}
	}
	return n
}

// checkpoint writes one session's counters if they moved, and reports whether
// it wrote them. A record that is not this process's any more ends the
// session here (ErrRecordGone).
func (r *Registry) checkpoint(s *Session) bool {
	cur := checkpoint{usage: s.Usage(), lastUsed: s.lastUsed.Load()}
	if last := s.flushed.Load(); last != nil && *last == cur {
		return false
	}
	if err := r.Store.CheckpointSession(s.ID, cur.usage, s.LastUsed()); err != nil {
		if errors.Is(err, ErrRecordGone) {
			r.dropGone(s)
		}
		return false
	}
	s.flushed.Store(&cur)
	return true
}

// dropGone stops serving a session whose record another hub process closed or
// took over. Its record is not written: it is not this process's. Recorded
// as a suspension — this process stopped serving it — since whoever closed
// the record wrote the close, and whoever took it over serves it on.
func (r *Registry) dropGone(s *Session) {
	r.mu.Lock()
	if r.sessions[s.ID] == s {
		delete(r.sessions, s.ID)
	}
	r.mu.Unlock()
	if s.closed.Swap(true) {
		return
	}
	reason := "stopped serving here: its record was closed or taken over by another hub process"
	s.closedReason.Store(&reason)
	u := s.Usage()
	r.emit(Event{
		Kind: EventSessionSuspended, SessionID: s.ID, RuleID: s.RuleID, RuleName: s.RuleName,
		Project: s.Project, Repository: s.Repository, Ref: s.Ref, Workflow: s.Workflow,
		Actor: s.Actor, RunID: s.RunID, Subject: s.Subject,
		Detail: fmt.Sprintf("%s: %d requests, %d denied, %d tokens", reason, u.Requests, u.Denied, u.TotalTokens()),
		At:     r.now(),
	})
}

// DurableIDs returns the ids of the recorded sessions this registry serves.
// With DropUnheld it is how the hub reconciles the registry with the records
// it holds: read the ids first, then the records, so a session minted between
// the two is not mistaken for one whose record went elsewhere.
func (r *Registry) DurableIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.sessions))
	for id, s := range r.sessions {
		if s.durable {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// DropUnheld stops serving each session in ids whose record is not among held
// — the open records this process holds, read after ids were — and returns how
// many it dropped. A session whose record was closed elsewhere stops at once,
// whether or not its counters moved since the last checkpoint.
func (r *Registry) DropUnheld(ids []string, held map[string]bool) int {
	n := 0
	for _, id := range ids {
		if held[id] {
			continue
		}
		r.mu.Lock()
		s := r.sessions[id]
		r.mu.Unlock()
		if s == nil || !s.durable {
			continue
		}
		r.dropGone(s)
		n++
	}
	return n
}

// tombstone remembers a session this registry closed, until it would have
// lapsed, so it is never restored here. Callers hold no lock.
func (r *Registry) tombstone(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closedHere == nil {
		r.closedHere = map[string]time.Time{}
	}
	r.closedHere[s.ID] = s.ExpiresAt
}

// pruneTombstonesLocked forgets the closed sessions that would have lapsed.
func (r *Registry) pruneTombstonesLocked(now time.Time) {
	for id, until := range r.closedHere {
		if !now.Before(until) {
			delete(r.closedHere, id)
		}
	}
}

// Suspend stops serving a session without ending it: what it spent is written
// to its Store, it leaves the registry, and a request already authenticated
// against it finishes while any later one is refused here — but its record
// stays open, so the hub process that receives its next request can restore
// it. A session the Store holds no record of is closed instead, with reason:
// nothing could restore it. It reports whether the session was suspended.
func (r *Registry) Suspend(id, reason string) bool {
	r.mu.Lock()
	s := r.sessions[id]
	if s != nil {
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	if s == nil {
		return false
	}
	return r.suspend(s, reason)
}

// SuspendAll suspends every session, as a hub stopping gracefully does, and
// returns the ids of the durable ones it suspended, sorted. Sessions with no
// record are closed with reason.
func (r *Registry) SuspendAll(reason string) []string {
	r.mu.Lock()
	live := make([]*Session, 0, len(r.sessions))
	for id, s := range r.sessions {
		live = append(live, s)
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	var out []string
	for _, s := range live {
		if r.suspend(s, reason) {
			out = append(out, s.ID)
		}
	}
	sort.Strings(out)
	return out
}

// suspend ends serving s, which has already left the registry.
func (r *Registry) suspend(s *Session, reason string) bool {
	if strings.TrimSpace(reason) == "" {
		reason = "suspended"
	}
	if !s.durable || r.Store == nil {
		r.closeSession(s, reason)
		return false
	}
	if s.closed.Swap(true) {
		return false
	}
	why := "suspended: " + reason
	s.closedReason.Store(&why)
	// Its spend, as of now: the process restoring it counts on from here.
	r.checkpoint(s)
	u := s.Usage()
	r.emit(Event{
		Kind: EventSessionSuspended, SessionID: s.ID, RuleID: s.RuleID, RuleName: s.RuleName,
		Project: s.Project, Repository: s.Repository, Ref: s.Ref, Workflow: s.Workflow,
		Actor: s.Actor, RunID: s.RunID, Subject: s.Subject,
		Detail: fmt.Sprintf("%s: %d requests, %d denied, %d tokens; its record is left for the hub "+
			"process that receives its next request", reason, u.Requests, u.Denied, u.TotalTokens()),
		At: r.now(),
	})
	return true
}

// RestoreRequest is a session to bring back.
type RestoreRequest struct {
	// Record is the session as its Store recorded it, with the policy and
	// deadline the caller holds it to now — never wider than recorded.
	Record SessionRecord
	// From names the hub process the session was taken over from, for the
	// restored row.
	From string
	// Detail, when set, is added to the restored row: what the caller
	// narrowed.
	Detail string
}

// Restore brings back a session another hub process minted, under the same id
// and token hash, with the counters it had reached. Its end is recorded in the
// Store like a minted session's.
//
// It refuses a record it could not have minted — an id or a token hash of the
// wrong shape, a policy permitting no model, a deadline beyond MaxTTL from its
// issue — and a session already past its deadline or already live here: a
// restored session is checked as strictly as a new one, because the record it
// comes from was read back from a database rather than produced here.
func (r *Registry) Restore(req RestoreRequest) (*Session, error) {
	v, err := r.checkRestore(req.Record)
	if err != nil {
		return nil, err
	}
	rec := req.Record
	s := &Session{
		ID:         v.id,
		Policy:     rec.Policy.clone(),
		RuleID:     rec.RuleID,
		RuleName:   rec.RuleName,
		Project:    rec.Project,
		Subject:    rec.Subject,
		Repository: rec.Repository,
		Ref:        rec.Ref,
		Workflow:   rec.Workflow,
		Actor:      rec.Actor,
		RunID:      rec.RunID,
		RunURL:     rec.RunURL,
		IssuedAt:   rec.IssuedAt,
		ExpiresAt:  rec.ExpiresAt,
		durable:    r.Store != nil,
	}
	copy(s.tokenHash[:], v.hash)
	u := rec.Usage
	s.requests.Store(nonNegative(u.Requests))
	s.denied.Store(nonNegative(u.Denied))
	s.inTok.Store(nonNegative(u.InputTokens))
	s.outTok.Store(nonNegative(u.OutputTokens))
	s.cacheRead.Store(nonNegative(u.CacheRead))
	s.cacheWrite.Store(nonNegative(u.CacheWrite))
	s.bytesUp.Store(nonNegative(u.BytesUp))
	s.bytesDown.Store(nonNegative(u.BytesDown))
	if !rec.LastUsed.IsZero() {
		s.lastUsed.Store(rec.LastUsed.UnixNano())
	}
	// What the record holds is what the store already has.
	s.flushed.Store(&checkpoint{usage: s.Usage(), lastUsed: s.lastUsed.Load()})

	now := r.now()
	r.mu.Lock()
	if _, live := r.sessions[v.id]; live {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrSessionExists, v.id)
	}
	if until, ok := r.closedHere[v.id]; ok && now.Before(until) {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrClosedHere, v.id)
	}
	if len(r.sessions) >= MaxSessions {
		r.reapLocked(now)
	}
	if len(r.sessions) >= MaxSessions {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: %d sessions are live", ErrTooManySessions, MaxSessions)
	}
	r.sessions[v.id] = s
	r.mu.Unlock()

	detail := fmt.Sprintf("restored under rule %s; models=%s max_requests=%d (%d spent) until %s",
		s.RuleName, strings.Join(s.Policy.Models, ","), s.Policy.MaxRequests, u.Requests,
		s.ExpiresAt.UTC().Format(time.RFC3339))
	if d := strings.TrimSpace(req.Detail); d != "" {
		detail += "; " + d
	}
	if from := strings.TrimSpace(req.From); from != "" {
		detail += " (held until then by " + from + ")"
	}
	r.emit(Event{
		Kind: EventSessionRestored, SessionID: s.ID, RuleID: s.RuleID, RuleName: s.RuleName,
		Project: s.Project, Repository: s.Repository, Ref: s.Ref, Workflow: s.Workflow,
		Actor: s.Actor, RunID: s.RunID, Subject: s.Subject, Detail: detail, At: now,
	})
	return s, nil
}

// CheckRestore reports why Restore would refuse rec, or nil.
func (r *Registry) CheckRestore(rec SessionRecord) error {
	_, err := r.checkRestore(rec)
	return err
}

// restoreCheck is what checkRestore derived from a record.
type restoreCheck struct {
	id   string
	hash []byte
}

func (r *Registry) checkRestore(rec SessionRecord) (restoreCheck, error) {
	id := strings.TrimSpace(rec.ID)
	if !validSessionID(id) {
		return restoreCheck{}, fmt.Errorf("claudeproxy: restore: session id %q is not one this hub mints", rec.ID)
	}
	hash, err := hex.DecodeString(strings.TrimSpace(rec.TokenSHA256))
	if err != nil || len(hash) != sha256.Size {
		return restoreCheck{}, fmt.Errorf("claudeproxy: restore %s: the recorded token hash is not a SHA-256", id)
	}
	if len(rec.Policy.Models) == 0 {
		return restoreCheck{}, fmt.Errorf("claudeproxy: restore %s: the session permits no model", id)
	}
	for _, m := range rec.Policy.Models {
		// Exactly as a rule may state one: a pattern with surrounding space
		// matched nothing at mint, and must not start matching now.
		if _, err := path.Match(m, "probe"); err != nil || m == "" || strings.TrimSpace(m) != m {
			return restoreCheck{}, fmt.Errorf("claudeproxy: restore %s: model pattern %q is not valid", id, m)
		}
	}
	if rec.Policy.MaxRequests < 0 || rec.Policy.MaxOutputTokens < 0 || rec.Policy.MaxBodyBytes < 0 {
		return restoreCheck{}, fmt.Errorf("claudeproxy: restore %s: the recorded policy has a negative bound", id)
	}
	now := r.now()
	if !now.Before(rec.ExpiresAt) {
		return restoreCheck{}, fmt.Errorf("%w: %s expired at %s", ErrSessionLapsed, id,
			rec.ExpiresAt.UTC().Format(time.RFC3339))
	}
	// No session Mint issues outlives MaxTTL from its issue — nor from now,
	// for an issue time in the future. A deadline beyond that was not
	// written by Mint.
	issued := rec.IssuedAt
	if issued.IsZero() || issued.After(now) {
		issued = now
	}
	if rec.IssuedAt.IsZero() || rec.ExpiresAt.After(issued.Add(MaxTTL)) {
		return restoreCheck{}, fmt.Errorf("claudeproxy: restore %s: a session issued %s cannot run until %s, "+
			"beyond the %s any session is minted for", id, rec.IssuedAt.UTC().Format(time.RFC3339),
			rec.ExpiresAt.UTC().Format(time.RFC3339), MaxTTL)
	}
	if r.Known(id) {
		return restoreCheck{}, fmt.Errorf("%w: %s", ErrSessionExists, id)
	}
	r.mu.Lock()
	until, closed := r.closedHere[id]
	r.mu.Unlock()
	if closed && now.Before(until) {
		return restoreCheck{}, fmt.Errorf("%w: %s", ErrClosedHere, id)
	}
	return restoreCheck{id: id, hash: hash}, nil
}

// validSessionID reports whether id has the shape Mint gives an id: 24
// lowercase hex characters.
func validSessionID(id string) bool {
	if len(id) != 24 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// SessionIDOf returns the id half of a session token without checking the
// secret half, and whether the token has the shape of one.
func SessionIDOf(token string) (string, bool) {
	id, ok := sessionIDOf(token)
	if !ok || !validSessionID(id) {
		return "", false
	}
	return id, true
}

func nonNegative(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

// ── narrowing ────────────────────────────────────────────────────────────────

// Narrow holds a recorded policy to the one its rule grants now: it returns a
// policy no wider than either. A model is permitted only when both allowlists
// permit it, and every cap is the lower of the two. It refuses when no model
// the session was minted for is permitted any more — a session that could
// authenticate and do nothing.
//
// The model intersection is computed on the patterns, conservatively: a pair
// of patterns whose common models cannot be proved to be one of them
// contributes nothing, so the result can be narrower than the exact
// intersection but never wider.
func Narrow(recorded, now Policy) (Policy, error) {
	models := IntersectModels(recorded.Models, now.Models)
	if len(models) == 0 {
		return Policy{}, fmt.Errorf("no model the session was minted for (%s) is permitted by its rule now (%s)",
			strings.Join(recorded.Models, ","), strings.Join(now.Models, ","))
	}
	out := Policy{
		Models:          models,
		MaxOutputTokens: minInt(recorded.OutputCap(), now.OutputCap()),
		MaxBodyBytes:    minInt64(recorded.BodyCap(), now.BodyCap()),
	}
	switch {
	case recorded.MaxRequests <= 0:
		out.MaxRequests = now.MaxRequests
	case now.MaxRequests <= 0:
		out.MaxRequests = recorded.MaxRequests
	default:
		out.MaxRequests = minInt(recorded.MaxRequests, now.MaxRequests)
	}
	return out, nil
}

// IntersectModels returns model patterns admitting only models both a and b
// admit, sorted. See Narrow for why it may drop a model both admit.
func IntersectModels(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range a {
		for _, q := range b {
			switch {
			case p == "" || q == "" || strings.TrimSpace(p) != p || strings.TrimSpace(q) != q:
			case p == q:
				add(p)
			case modelPatternWithin(p, q):
				add(p)
			case modelPatternWithin(q, p):
				add(q)
			}
		}
	}
	sort.Strings(out)
	return out
}

// modelPatternWithin reports whether every model p admits is provably admitted
// by q. It can prove two shapes: p a literal model id q matches; and p and q
// built from literal characters and '*' alone, with q matching p's text — each
// '*' of p then falls inside a span one of q's '*' covers, and a model id has
// no '/' for either '*' to stop at. Anything else is not proved.
func modelPatternWithin(p, q string) bool {
	if _, err := path.Match(q, ""); err != nil {
		return false
	}
	if _, err := path.Match(p, ""); err != nil {
		return false
	}
	literal := !strings.ContainsAny(p, `*?[\`)
	starsOnly := !strings.ContainsAny(p, `?[\`) && !strings.ContainsAny(q, `?[\`)
	if !literal && !starsOnly {
		return false
	}
	ok, err := path.Match(q, p)
	return err == nil && ok
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
