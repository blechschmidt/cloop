package gitproxy

// durable.go lets a session outlive the hub process that minted it (Task
// 20383).
//
// A session lived only in the registry of the process that minted it. When
// that process stopped — a deploy, a crash, the nightly restart of a hub while
// a device was running a task — the workload carried on presenting the
// session's token, and nothing could authenticate it: its next fetch or push
// got a 401. Since Task 20382 the process that adopts the run takes over its
// secret lease; this is the part of the lease's reach that came along with it.
//
// A registry with a Store records every Durable session when it is minted —
// its id, the SHA-256 of its token, its scope and expiry, never the token or
// the upstream credential — and records its end. The process that adopts the
// run reads the record, takes it over (a conditional write on the holder, so
// two processes cannot both restore one session), re-derives the upstream
// credential from the lease's grants, and calls Restore: the session is back,
// under the same id and token hash, enforcing the same scope until the same
// deadline. The workload notices nothing.
//
// What a record is worth to someone who reads it: nothing that authenticates.
// The token hash is the same thing the registry keeps in memory instead of the
// token, and SHA-256 of 256 bits of entropy is not something to reverse.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// EventSessionRestored records a session taken over from another hub process
// and restored into this registry.
const EventSessionRestored EventKind = "session_restored"

// Errors Restore distinguishes.
var (
	// ErrSessionExists: the registry already holds a session with that id.
	ErrSessionExists = errors.New("gitproxy: a session with that id is already live")
	// ErrSessionLapsed: the session's TTL ran out before it could be restored.
	ErrSessionLapsed = errors.New("gitproxy: session lapsed before it could be restored")
)

// SessionRecord is what a Store keeps of a session: everything Restore needs
// except the upstream credential, which whoever restores re-derives from the
// grant the session stands on.
type SessionRecord struct {
	ID string
	// TokenSHA256 is the hex SHA-256 of the session token.
	TokenSHA256  string
	RepoPath     string
	RepoPatterns []string
	// Upstream is the forge URL or host base; it carries no credential (Mint
	// refuses one with userinfo).
	Upstream   string
	Policy     Policy
	ProjectID  string
	TaskID     string
	ExecutorID string
	Actor      string
	RunID      string
	GrantID    string
	LeaseID    string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// SessionStore persists the record of every Durable session and its end.
//
// Errors are the implementation's to report: the registry cannot do anything
// useful with one beyond what it does — a session whose record could not be
// written is served all the same, and noted on its minted row.
type SessionStore interface {
	// SaveSession records a session this process now serves.
	SaveSession(rec SessionRecord) error
	// CloseSession records that a session this process served has ended,
	// and why. A session another process took over is not this process's to
	// close; an implementation fences the write on its own holder.
	CloseSession(id, reason string, at time.Time) error
}

// record renders the session for its Store.
func (s *Session) record() SessionRecord {
	return SessionRecord{
		ID:           s.ID,
		TokenSHA256:  hex.EncodeToString(s.tokenHash[:]),
		RepoPath:     s.RepoPath,
		RepoPatterns: append([]string(nil), s.RepoPatterns...),
		Upstream:     s.Upstream,
		Policy:       s.Policy,
		ProjectID:    s.ProjectID,
		TaskID:       s.TaskID,
		ExecutorID:   s.ExecutorID,
		Actor:        s.Actor,
		RunID:        s.RunID,
		GrantID:      s.GrantID,
		LeaseID:      s.LeaseID,
		IssuedAt:     s.IssuedAt,
		ExpiresAt:    s.ExpiresAt,
	}
}

// Durable reports whether a Store holds a record of the session.
func (s *Session) Durable() bool { return s != nil && s.durable }

// mintDetail is the minted row's detail: the policy and deadline, and what was
// lost when the record could not be written.
func mintDetail(pol Policy, expires time.Time, recordErr error) string {
	d := fmt.Sprintf("allow %s until %s", pol.RefSummary(), expires.UTC().Format(time.RFC3339))
	if recordErr != nil {
		d += "; not recorded durably, so it will not be restored if this hub process stops: " + recordErr.Error()
	}
	return d
}

// closeRecord records a durable session's end. Called once, by whichever path
// ended it.
func (r *Registry) closeRecord(s *Session, reason string) {
	if s == nil || !s.durable || r.Store == nil {
		return
	}
	_ = r.Store.CloseSession(s.ID, reason, r.now())
}

// RestoreRequest is a session to bring back.
type RestoreRequest struct {
	// Record is the session as its Store recorded it.
	Record SessionRecord
	// Credential is presented upstream on the session's behalf: re-derived by
	// the caller from the grant the session stands on, never read from the
	// record, which has none. CredentialExpiresAt and Refresh are as on
	// MintRequest.
	Credential          Credential
	CredentialExpiresAt time.Time
	Refresh             RefreshFunc
	// OnEnd is as on MintRequest.
	OnEnd func()
	// From names the hub process the session was taken over from, for the
	// restored row.
	From string
}

// Restore brings back a session another hub process minted, under the same id,
// token hash, scope and expiry, presenting the credential the caller
// re-derived. Its end is recorded in the Store like a minted durable
// session's.
//
// It refuses a record it could not have minted — an unusable upstream, an
// allowlist or policy Mint would refuse — and a session already past its TTL,
// already live here, or whose token hash is not a SHA-256: a restored session
// is checked as strictly as a new one, because the record it comes from was
// read back from a database rather than produced by this process.
func (r *Registry) Restore(req RestoreRequest) (*Session, error) {
	rec := req.Record
	v, err := r.checkRestore(rec)
	if err != nil {
		return nil, err
	}
	id, repoPath, patterns, upstream, pol, hash := v.id, v.repoPath, v.patterns, v.upstream, v.policy, v.hash
	if req.Refresh != nil && req.CredentialExpiresAt.IsZero() {
		return nil, fmt.Errorf("gitproxy: restore %s: a refreshable upstream credential needs its expiry", id)
	}
	now := r.now()

	cred := req.Credential
	if cred.GrantID == "" {
		cred.GrantID = rec.GrantID
	}
	if cred.LeaseID == "" {
		cred.LeaseID = rec.LeaseID
	}
	s := &Session{
		ID:           id,
		RepoPath:     repoPath,
		RepoPatterns: patterns,
		Upstream:     upstream,
		Policy:       pol,
		ProjectID:    rec.ProjectID,
		TaskID:       rec.TaskID,
		ExecutorID:   rec.ExecutorID,
		Actor:        rec.Actor,
		RunID:        rec.RunID,
		GrantID:      rec.GrantID,
		LeaseID:      rec.LeaseID,
		IssuedAt:     rec.IssuedAt,
		ExpiresAt:    rec.ExpiresAt,
		cred:         &credentialGen{cred: cred, expiresAt: req.CredentialExpiresAt},
		refresh:      req.Refresh,
		onEnd:        req.OnEnd,
		durable:      r.Store != nil,
	}
	copy(s.tokenHash[:], hash)

	r.mu.Lock()
	if r.sessions == nil {
		r.sessions = make(map[string]*Session)
	}
	if _, live := r.sessions[id]; live {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrSessionExists, id)
	}
	r.sessions[id] = s
	r.mu.Unlock()

	detail := fmt.Sprintf("restored with its run; allow %s until %s", pol.RefSummary(),
		s.ExpiresAt.UTC().Format(time.RFC3339))
	if from := strings.TrimSpace(req.From); from != "" {
		detail += " (held until then by " + from + ")"
	}
	r.emit(Event{
		Kind:      EventSessionRestored,
		SessionID: id,
		RepoPath:  s.scopeDescription(),
		ProjectID: s.ProjectID,
		TaskID:    s.TaskID,
		Actor:     s.Actor,
		At:        now,
		Detail:    detail,
	})
	return s, nil
}

// CheckRestore reports why Restore would refuse rec, or nil: everything it
// checks except the credential. A caller that must spend something to obtain
// the credential — mint a GitHub App token — asks first.
func (r *Registry) CheckRestore(rec SessionRecord) error {
	_, err := r.checkRestore(rec)
	return err
}

// restoreCheck is what checkRestore derived from a record.
type restoreCheck struct {
	id, repoPath, upstream string
	patterns               []string
	policy                 Policy
	hash                   []byte
}

func (r *Registry) checkRestore(rec SessionRecord) (restoreCheck, error) {
	id := strings.TrimSpace(rec.ID)
	if id == "" || strings.ContainsAny(id, ":/ \t\r\n") {
		return restoreCheck{}, fmt.Errorf("gitproxy: restore: session id %q is unusable", rec.ID)
	}
	hash, err := hex.DecodeString(strings.TrimSpace(rec.TokenSHA256))
	if err != nil || len(hash) != sha256.Size {
		return restoreCheck{}, fmt.Errorf("gitproxy: restore %s: the recorded token hash is not a SHA-256", id)
	}

	var (
		repoPath string
		patterns []string
		upstream string
	)
	if len(rec.RepoPatterns) > 0 {
		if patterns, err = normalizeRepoPatterns(rec.RepoPatterns); err != nil {
			return restoreCheck{}, fmt.Errorf("gitproxy: restore %s: %w", id, err)
		}
		if upstream, err = UpstreamHostBase(rec.Upstream); err != nil {
			return restoreCheck{}, fmt.Errorf("gitproxy: restore %s: %w", id, err)
		}
	} else {
		if repoPath, err = UpstreamRepoPath(rec.Upstream); err != nil {
			return restoreCheck{}, fmt.Errorf("gitproxy: restore %s: %w", id, err)
		}
		if p := NormalizeRepoPath(rec.RepoPath); p != "" && !strings.EqualFold(p, repoPath) {
			return restoreCheck{}, fmt.Errorf("gitproxy: restore %s: recorded repository %q does not match its upstream %q",
				id, rec.RepoPath, repoPath)
		}
		upstream = strings.TrimSuffix(strings.TrimSpace(rec.Upstream), "/")
	}

	pol := rec.Policy
	if pol.IsZero() {
		// Every minted session has a policy; a record without one was not
		// written by Mint, and a default here would grant what nobody chose.
		return restoreCheck{}, fmt.Errorf("gitproxy: restore %s: the record carries no policy", id)
	}
	pol.AllowedRefs = append([]string(nil), pol.AllowedRefs...)
	pol.RestrictRefs = append([]string(nil), pol.RestrictRefs...)
	pol.Normalize()
	if err := pol.Validate(); err != nil {
		return restoreCheck{}, fmt.Errorf("gitproxy: restore %s: %w", id, err)
	}

	now := r.now()
	if !now.Before(rec.ExpiresAt) {
		return restoreCheck{}, fmt.Errorf("%w: %s expired at %s", ErrSessionLapsed, id, rec.ExpiresAt.UTC().Format(time.RFC3339))
	}
	// No session Mint issues outlives MaxSessionTTL from its issue — nor from
	// now, for an issue time in the future. A deadline beyond that was not
	// written by Mint.
	issued := rec.IssuedAt
	if issued.IsZero() || issued.After(now) {
		issued = now
	}
	if rec.IssuedAt.IsZero() || rec.ExpiresAt.After(issued.Add(MaxSessionTTL)) {
		return restoreCheck{}, fmt.Errorf("gitproxy: restore %s: a session issued %s cannot run until %s, beyond "+
			"the %s any session is minted for", id, rec.IssuedAt.UTC().Format(time.RFC3339),
			rec.ExpiresAt.UTC().Format(time.RFC3339), MaxSessionTTL)
	}
	if r.Known(id) {
		return restoreCheck{}, fmt.Errorf("%w: %s", ErrSessionExists, id)
	}
	return restoreCheck{id: id, repoPath: repoPath, upstream: upstream, patterns: patterns, policy: pol, hash: hash}, nil
}

// Suspend stops serving a session without ending it: it leaves the registry,
// but its record stays open and its OnEnd does not run, so the hub process
// that adopts its run can restore it. A hub stopping gracefully suspends its
// durable sessions rather than closing them, and a process whose lease another
// one took over suspends the sessions that lease feeds — the new holder serves
// them now. It reports whether the session was here.
func (r *Registry) Suspend(id, reason string) bool {
	r.mu.Lock()
	s := r.sessions[id]
	delete(r.sessions, id)
	r.mu.Unlock()
	if s == nil {
		return false
	}
	if s.closed.CompareAndSwap(false, true) {
		if reason == "" {
			reason = "suspended"
		}
		s.reason.Store("suspended: " + reason)
	}
	return true
}

// CloseForLease closes every session whose upstream credential stands on
// leaseID, and reports how many it closed. It is how releasing a lease ends
// the sessions it fed when the lease no longer names them in its materials —
// one taken over from another process carries only grant ids.
func (r *Registry) CloseForLease(leaseID, reason string) int {
	n := 0
	for _, id := range r.sessionsForLease(leaseID) {
		r.Close(id, reason)
		n++
	}
	return n
}

// SuspendForLease suspends every durable session leaseID feeds and returns
// their ids, sorted. A session its Store holds no record of is closed instead,
// with reason: nothing could restore it, and a session that simply stopped
// being served would leave its audit trail without an end.
func (r *Registry) SuspendForLease(leaseID, reason string) []string {
	var out []string
	for _, id := range r.sessionsForLease(leaseID) {
		r.mu.RLock()
		s := r.sessions[id]
		r.mu.RUnlock()
		switch {
		case s == nil:
		case !s.Durable():
			r.Close(id, reason)
		case r.Suspend(id, reason):
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// sessionsForLease returns the ids of the live sessions leaseID feeds.
func (r *Registry) sessionsForLease(leaseID string) []string {
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for id, s := range r.sessions {
		if s.LeaseID == leaseID {
			out = append(out, id)
		}
	}
	return out
}
