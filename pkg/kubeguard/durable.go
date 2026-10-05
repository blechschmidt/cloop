package kubeguard

// durable.go lets a session outlive the hub process that minted it (Task
// 20383). It is pkg/gitproxy's durable.go for the Kubernetes monitor, and the
// reasoning is the same.
//
// A session lived only in the registry of the process that minted it, holding
// the cluster credential it spends. When that process stopped while a device
// still ran a task, the workload's kubeconfig named a session nothing could
// authenticate: its next kubectl call got a 401. A registry with a Store now
// records every Durable session — its id, the SHA-256 of its bearer token, the
// cluster it is pinned to, its context and policy, never the token or the
// cluster credential — and the process that adopts the run restores it under
// the same id and token hash, with a cluster credential it re-derives from the
// lease's grant.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// EventSessionRestored records a session taken over from another hub process
// and restored into this registry.
const EventSessionRestored EventKind = "session_restored"

// Errors Restore distinguishes.
var (
	// ErrSessionExists: the registry already holds a session with that id.
	ErrSessionExists = errors.New("kubeguard: a session with that id is already live")
	// ErrSessionLapsed: the session's TTL ran out before it could be restored.
	ErrSessionLapsed = errors.New("kubeguard: session lapsed before it could be restored")
)

// SessionRecord is what a Store keeps of a session: everything Restore needs
// except the cluster credential, which whoever restores re-derives from the
// grant the session stands on.
type SessionRecord struct {
	ID string
	// TokenSHA256 is the hex SHA-256 of the whole bearer token, "<id>.<secret>".
	TokenSHA256 string
	// ClusterURL is the API server the session is pinned to.
	ClusterURL  string
	ContextName string
	Policy      Policy
	ProjectID   string
	TaskID      string
	ExecutorID  string
	Actor       string
	GrantID     string
	LeaseID     string
	RunID       string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// SessionStore persists the record of every Durable session and its end.
// Errors are the implementation's to report; see pkg/gitproxy's SessionStore.
type SessionStore interface {
	SaveSession(rec SessionRecord) error
	CloseSession(id, reason string, at time.Time) error
}

// record renders the session for its Store.
func (s *Session) record() SessionRecord {
	pol := s.Policy
	pol.Verbs = append([]string(nil), pol.Verbs...)
	pol.Namespaces = append([]string(nil), pol.Namespaces...)
	pol.Resources = append([]string(nil), pol.Resources...)
	pol.NonResourcePaths = append([]string(nil), pol.NonResourcePaths...)
	return SessionRecord{
		ID:          s.ID,
		TokenSHA256: hex.EncodeToString(s.tokenHash[:]),
		ClusterURL:  s.ClusterURL,
		ContextName: s.ContextName,
		Policy:      pol,
		ProjectID:   s.ProjectID,
		TaskID:      s.TaskID,
		ExecutorID:  s.ExecutorID,
		Actor:       s.Actor,
		GrantID:     s.GrantID,
		LeaseID:     s.LeaseID,
		RunID:       s.RunID,
		IssuedAt:    s.IssuedAt,
		ExpiresAt:   s.ExpiresAt,
	}
}

// Durable reports whether a Store holds a record of the session.
func (s *Session) Durable() bool { return s != nil && s.durable }

// mintDetail is the minted row's detail.
func mintDetail(policy Policy, expires time.Time, recordErr error) string {
	d := fmt.Sprintf("%s until %s", policy.Summary(), expires.UTC().Format(time.RFC3339))
	if recordErr != nil {
		d += "; not recorded durably, so it will not be restored if this hub process stops: " + recordErr.Error()
	}
	return d
}

// closeRecord records a durable session's end, once, from whichever path ended
// it.
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
	// Kubeconfig is the cluster credential the session spends, re-derived by
	// the caller from the grant — the minimised document the guard was given
	// at mint. Parsed here into the same form Mint keeps, with the recorded
	// context, and refused if it no longer names the recorded cluster.
	Kubeconfig []byte
	// From names the hub process the session was taken over from.
	From string
}

// Restore brings back a session another hub process minted, under the same id,
// token hash, policy and expiry, spending the credential the caller re-derived.
//
// It refuses what Mint would refuse — a kubeconfig the shared parser rejects
// (exec plugins, auth providers, credential files), a policy that does not
// validate — and a session already past its TTL, already live here, whose
// token hash is not a SHA-256, or whose re-derived credential points at
// another cluster than the one the session was pinned to.
func (r *Registry) Restore(req RestoreRequest) (*Session, error) {
	rec := req.Record
	id := strings.TrimSpace(rec.ID)
	if id == "" || strings.ContainsAny(id, ". \t\r\n") {
		return nil, fmt.Errorf("kubeguard: restore: session id %q is unusable", rec.ID)
	}
	hash, err := hex.DecodeString(strings.TrimSpace(rec.TokenSHA256))
	if err != nil || len(hash) != sha256.Size {
		return nil, fmt.Errorf("kubeguard: restore %s: the recorded token hash is not a SHA-256", id)
	}
	if len(req.Kubeconfig) == 0 {
		return nil, fmt.Errorf("kubeguard: restore %s: no kubeconfig to spend", id)
	}
	rc, err := kubernetes.ParseKubeconfig(req.Kubeconfig, strings.TrimSpace(rec.ContextName))
	if err != nil {
		return nil, fmt.Errorf("kubeguard: restore %s: %w", id, err)
	}
	if !strings.EqualFold(strings.TrimSuffix(rc.Server, "/"), strings.TrimSuffix(rec.ClusterURL, "/")) {
		// The grant's kubeconfig now points elsewhere. The session was pinned to
		// one API server, and following an edit to another would spend the
		// re-derived credential somewhere the sandbox was never granted.
		return nil, fmt.Errorf("kubeguard: restore %s: the grant's kubeconfig now names %s, not %s the session was "+
			"pinned to", id, rc.Server, rec.ClusterURL)
	}

	policy := rec.Policy
	if policy.IsZero() {
		return nil, fmt.Errorf("kubeguard: restore %s: the record carries no policy", id)
	}
	policy.Normalize()
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("kubeguard: restore %s: session policy: %w", id, err)
	}

	now := r.now()
	if !now.Before(rec.ExpiresAt) {
		return nil, fmt.Errorf("%w: %s expired at %s", ErrSessionLapsed, id, rec.ExpiresAt.UTC().Format(time.RFC3339))
	}
	// No session Mint issues outlives MaxSessionTTL from its issue — nor from
	// now, for an issue time in the future. A deadline beyond that was not
	// written by Mint.
	issued := rec.IssuedAt
	if issued.IsZero() || issued.After(now) {
		issued = now
	}
	if rec.IssuedAt.IsZero() || rec.ExpiresAt.After(issued.Add(MaxSessionTTL)) {
		return nil, fmt.Errorf("kubeguard: restore %s: a session issued %s cannot run until %s, beyond the %s "+
			"any session is minted for", id, rec.IssuedAt.UTC().Format(time.RFC3339),
			rec.ExpiresAt.UTC().Format(time.RFC3339), MaxSessionTTL)
	}

	s := &Session{
		ID:          id,
		ClusterURL:  rc.Server,
		ContextName: rc.Context,
		Policy:      policy,
		ProjectID:   strings.TrimSpace(rec.ProjectID),
		TaskID:      strings.TrimSpace(rec.TaskID),
		ExecutorID:  strings.TrimSpace(rec.ExecutorID),
		Actor:       strings.TrimSpace(rec.Actor),
		GrantID:     strings.TrimSpace(rec.GrantID),
		LeaseID:     strings.TrimSpace(rec.LeaseID),
		RunID:       strings.TrimSpace(rec.RunID),
		IssuedAt:    rec.IssuedAt,
		ExpiresAt:   rec.ExpiresAt,
		upstream:    rc,
		durable:     r.Store != nil,
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

	detail := fmt.Sprintf("restored with its run; %s until %s", policy.Summary(),
		s.ExpiresAt.UTC().Format(time.RFC3339))
	if from := strings.TrimSpace(req.From); from != "" {
		detail += " (held until then by " + from + ")"
	}
	r.emit(Event{
		Kind: EventSessionRestored, SessionID: id, Cluster: s.ClusterURL, Context: s.ContextName,
		ProjectID: s.ProjectID, TaskID: s.TaskID, ExecutorID: s.ExecutorID,
		Actor: s.Actor, GrantID: s.GrantID, LeaseID: s.LeaseID,
		Detail: detail, At: now,
	})
	return s, nil
}

// Suspend stops serving a session without ending it: it leaves the registry,
// but its record stays open, so the hub process that adopts its run can restore
// it. See pkg/gitproxy's Registry.Suspend. It reports whether the session was
// here.
func (r *Registry) Suspend(id, reason string) bool {
	r.mu.Lock()
	s := r.sessions[id]
	delete(r.sessions, id)
	r.mu.Unlock()
	if s == nil {
		return false
	}
	s.mu.Lock()
	if !s.closed {
		if reason == "" {
			reason = "suspended"
		}
		s.closed, s.reason = true, "suspended: "+reason
	}
	s.mu.Unlock()
	return true
}

// SuspendForLease suspends every live durable session leaseID feeds and
// returns their ids, sorted. A session its Store holds no record of is closed
// instead, with reason: nothing could restore it. See pkg/gitproxy's
// Registry.SuspendForLease.
func (r *Registry) SuspendForLease(leaseID, reason string) []string {
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" {
		return nil
	}
	var out []string
	for _, s := range r.Sessions() {
		switch {
		case s.LeaseID != leaseID || s.Closed():
		case !s.Durable():
			r.Close(s.ID, reason)
		case r.Suspend(s.ID, reason):
			out = append(out, s.ID)
		}
	}
	sort.Strings(out)
	return out
}
