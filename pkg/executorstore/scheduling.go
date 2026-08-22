// scheduling.go adapts the executor scheduling layer (Task 20162) onto
// statedb, the same way store.go adapts the enrollment flow.
//
// The separation is the one this package already exists to maintain:
// pkg/executor defines HealthStore, SessionStore, and EventSink as interfaces
// because it is linked into the agent binary that runs on edge devices, and an
// executor driver has no business carrying a SQLite engine. Everything that
// knows about rows and SQL lives here.
//
// Two things in this file are load-bearing beyond plumbing:
//
//   - ClaimRequeue mints the *new* claim token. Token generation is
//     crypto/rand, and putting it here rather than in statedb keeps the storage
//     layer honestly dumb — it performs a conditional UPDATE with a token it
//     was handed and has no opinion about where tokens come from.
//   - The event sink writes to the audit log rather than the task event
//     journal. Fleet transitions are "what happened to this control plane's
//     infrastructure", not "what happened to this project's plan", and the
//     audit log's free-form entity/event types fit that without extending the
//     journal's closed enum of task lifecycle events.

package executorstore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Audit constants for fleet events. EntityType is "executor" so an operator can
// filter the audit log down to infrastructure changes with one predicate.
const (
	AuditEntityExecutor    = "executor"
	AuditEventStateChange  = "executor.state_change"
	AuditEventFailover     = "executor.failover"
	AuditActorSupervisor   = "supervisor"
	auditSessionEntityType = "executor_session"
)

// Scheduler implements executor.HealthStore, executor.SessionStore, and
// executor.EventSink over a *statedb.DB.
type Scheduler struct {
	db *statedb.DB
	// actor labels audit entries. Defaults to AuditActorSupervisor; the CLI
	// and UI override it so a cordon shows who ordered it.
	actor string
}

// Compile-time proof that the adapter satisfies every interface the supervisor
// is written against. Without these, a signature drift in pkg/executor would
// surface as a confusing nil-interface panic at wiring time instead of as a
// build error here.
var (
	_ executor.HealthStore  = (*Scheduler)(nil)
	_ executor.SessionStore = (*Scheduler)(nil)
	_ executor.EventSink    = (*Scheduler)(nil)
)

// NewScheduler wraps a database handle.
func NewScheduler(db *statedb.DB) (*Scheduler, error) {
	if db == nil {
		return nil, fmt.Errorf("executorstore: nil database")
	}
	return &Scheduler{db: db, actor: AuditActorSupervisor}, nil
}

// WithActor returns a copy that attributes audit entries to actor. Used by the
// CLI ("cli") and the Web UI (the authenticated subject) so a cordon is
// traceable to a person rather than to the supervisor that persisted it.
func (s *Scheduler) WithActor(actor string) *Scheduler {
	if s == nil {
		return nil
	}
	if actor == "" {
		return s
	}
	clone := *s
	clone.actor = actor
	return &clone
}

// ---------------------------------------------------------------- HealthStore

// LoadHealth returns the persisted health for an executor. An executor that has
// never been probed yields the zero Health and a nil error: "not yet observed"
// is a normal state for a backend registered from config a millisecond ago, not
// a lookup failure the supervisor should log.
func (s *Scheduler) LoadHealth(executorID string) (executor.Health, error) {
	row, err := s.db.GetExecutorHealth(executorID)
	if errors.Is(err, statedb.ErrExecutorHealthNotFound) {
		return executor.Health{ExecutorID: executorID}, nil
	}
	if err != nil {
		return executor.Health{}, fmt.Errorf("executorstore: load health for %s: %w", executorID, err)
	}
	return healthFromRow(row), nil
}

// SaveHealth persists a health record.
func (s *Scheduler) SaveHealth(h executor.Health) error {
	if h.ExecutorID == "" {
		return fmt.Errorf("executorstore: save health: executor ID is blank")
	}
	if err := s.db.PutExecutorHealth(rowFromHealth(h)); err != nil {
		return fmt.Errorf("executorstore: save health for %s: %w", h.ExecutorID, err)
	}
	return nil
}

// ListHealth returns every persisted health record, ordered by executor ID.
func (s *Scheduler) ListHealth() ([]executor.Health, error) {
	rows, err := s.db.ListExecutorHealth()
	if err != nil {
		return nil, fmt.Errorf("executorstore: list health: %w", err)
	}
	out := make([]executor.Health, 0, len(rows))
	for _, row := range rows {
		out = append(out, healthFromRow(row))
	}
	return out, nil
}

// ForgetHealth drops an executor's health record, for use when an executor is
// deleted. A stale record would otherwise resurrect as a phantom row in
// `cloop executor ls` naming a backend that no longer exists.
func (s *Scheduler) ForgetHealth(executorID string) error {
	if err := s.db.DeleteExecutorHealth(executorID); err != nil {
		return fmt.Errorf("executorstore: forget health for %s: %w", executorID, err)
	}
	return nil
}

func healthFromRow(row statedb.ExecutorHealthRow) executor.Health {
	return executor.Health{
		ExecutorID:          row.ExecutorID,
		State:               executor.NodeState(row.State),
		Reason:              row.Reason,
		ConsecutiveFailures: row.ConsecutiveFailures,
		LastSeen:            row.LastSeen,
		LastProbe:           row.LastProbe,
		StateChangedAt:      row.StateChangedAt,
	}.Normalize()
}

func rowFromHealth(h executor.Health) statedb.ExecutorHealthRow {
	h = h.Normalize()
	return statedb.ExecutorHealthRow{
		ExecutorID:          h.ExecutorID,
		State:               string(h.State),
		Reason:              h.Reason,
		ConsecutiveFailures: h.ConsecutiveFailures,
		LastSeen:            h.LastSeen,
		LastProbe:           h.LastProbe,
		StateChangedAt:      h.StateChangedAt,
	}
}

// --------------------------------------------------------------- SessionStore

// OpenSession records a dispatched workload as in flight.
//
// The caller supplies the session ID and claim token (see NewSessionID and
// NewClaimToken) because it needs the token in hand before the workload starts:
// a session that becomes visible to a supervisor before its owner knows the
// token is a session the owner can no longer defend against requeue.
func (s *Scheduler) OpenSession(sess executor.Session) error {
	if sess.Attempt <= 0 {
		sess.Attempt = 1
	}
	if sess.StartedAt.IsZero() {
		sess.StartedAt = time.Now().UTC()
	}
	row := statedb.ExecutorSessionRow{
		ID:          sess.ID,
		ExecutorID:  sess.ExecutorID,
		HandleID:    sess.HandleID,
		ProjectPath: sess.ProjectPath,
		TaskID:      sess.TaskID,
		ClaimToken:  sess.ClaimToken,
		State:       statedb.ExecutorSessionRunning,
		Attempt:     sess.Attempt,
		StartedAt:   sess.StartedAt,
		UpdatedAt:   sess.StartedAt,
		SpecJSON:    marshalSpec(sess.Spec),
	}
	if err := s.db.OpenExecutorSession(row); err != nil {
		return fmt.Errorf("executorstore: open session %s: %w", sess.ID, err)
	}
	return nil
}

// OpenRequeuedSession records the replacement session created by a failover,
// linking it back to the session it replaces.
func (s *Scheduler) OpenRequeuedSession(sess executor.Session, requeuedFrom string) error {
	if sess.Attempt <= 0 {
		sess.Attempt = 1
	}
	if sess.StartedAt.IsZero() {
		sess.StartedAt = time.Now().UTC()
	}
	row := statedb.ExecutorSessionRow{
		ID:           sess.ID,
		ExecutorID:   sess.ExecutorID,
		HandleID:     sess.HandleID,
		ProjectPath:  sess.ProjectPath,
		TaskID:       sess.TaskID,
		ClaimToken:   sess.ClaimToken,
		State:        statedb.ExecutorSessionRunning,
		Attempt:      sess.Attempt,
		StartedAt:    sess.StartedAt,
		UpdatedAt:    sess.StartedAt,
		RequeuedFrom: requeuedFrom,
		SpecJSON:     marshalSpec(sess.Spec),
	}
	if err := s.db.OpenExecutorSession(row); err != nil {
		return fmt.Errorf("executorstore: open requeued session %s: %w", sess.ID, err)
	}
	return nil
}

// RunningSessions returns the in-flight sessions on an executor. Passing ""
// returns every running session.
func (s *Scheduler) RunningSessions(executorID string) ([]executor.Session, error) {
	rows, err := s.db.ListExecutorSessions(executorID, true)
	if err != nil {
		return nil, fmt.Errorf("executorstore: list running sessions for %q: %w", executorID, err)
	}
	out := make([]executor.Session, 0, len(rows))
	for _, row := range rows {
		out = append(out, sessionFromRow(row))
	}
	return out, nil
}

// CountRunning returns the number of in-flight sessions on an executor.
func (s *Scheduler) CountRunning(executorID string) (int, error) {
	n, err := s.db.CountRunningExecutorSessions(executorID)
	if err != nil {
		return 0, fmt.Errorf("executorstore: count running sessions for %q: %w", executorID, err)
	}
	return n, nil
}

// ClaimRequeue is the exactly-once failover latch.
//
// It mints a fresh claim token and hands it to a single conditional UPDATE. The
// supervisor that wins gets the session back carrying the new token; every
// other caller — a concurrent supervisor, or this one after a restart replaying
// the same unreachable transition — presents a token that no longer matches and
// receives executor.ErrSessionClaimLost.
//
// The sentinel is translated at this boundary for the same reason store.go
// translates the enrollment sentinels: the supervisor distinguishes "I lost the
// race, do nothing" from "the database is broken, complain", and collapsing
// both into an opaque storage error would turn a benign race into log noise
// that hides a real outage.
func (s *Scheduler) ClaimRequeue(sessionID, claimToken string, at time.Time) (executor.Session, error) {
	next, err := NewClaimToken()
	if err != nil {
		return executor.Session{}, fmt.Errorf("executorstore: mint claim token: %w", err)
	}
	row, err := s.db.ClaimExecutorSessionRequeue(sessionID, claimToken, next, at)
	switch {
	case errors.Is(err, statedb.ErrExecutorSessionClaimLost):
		return executor.Session{}, fmt.Errorf("%w: session %s", executor.ErrSessionClaimLost, sessionID)
	case errors.Is(err, statedb.ErrExecutorSessionNotFound):
		return executor.Session{}, fmt.Errorf("%w: session %s", executor.ErrSessionClaimLost, sessionID)
	case err != nil:
		return executor.Session{}, fmt.Errorf("executorstore: claim session %s: %w", sessionID, err)
	}
	return sessionFromRow(row), nil
}

// CloseSession marks a session finished or failed.
func (s *Scheduler) CloseSession(sessionID, state string, at time.Time) error {
	switch state {
	case statedb.ExecutorSessionFinished, statedb.ExecutorSessionFailed, statedb.ExecutorSessionRequeued:
	default:
		return fmt.Errorf("executorstore: close session %s: invalid terminal state %q", sessionID, state)
	}
	if err := s.db.CloseExecutorSession(sessionID, state, at); err != nil {
		return fmt.Errorf("executorstore: close session %s: %w", sessionID, err)
	}
	return nil
}

func sessionFromRow(row statedb.ExecutorSessionRow) executor.Session {
	return executor.Session{
		ID:          row.ID,
		ExecutorID:  row.ExecutorID,
		HandleID:    row.HandleID,
		ProjectPath: row.ProjectPath,
		TaskID:      row.TaskID,
		ClaimToken:  row.ClaimToken,
		Attempt:     row.Attempt,
		StartedAt:   row.StartedAt,
		Spec:        unmarshalSpec(row.SpecJSON),
	}
}

// marshalSpec renders a dispatched workload for storage.
//
// A spec that will not marshal yields "" rather than an error: the session
// itself is still worth recording, because an unrequeueable session that the
// operator can *see* beats an invisible one. Failover then reports "no spec
// recorded" instead of silently starting an empty workload — see unmarshalSpec.
func marshalSpec(spec executor.Spec) string {
	if len(spec.Argv) == 0 {
		return ""
	}
	encoded, err := json.Marshal(redactLeasedEnv(spec))
	if err != nil {
		return ""
	}
	return string(encoded)
}

// redactedEnvValue replaces a brokered credential in the stored spec.
const redactedEnvValue = "<redacted:leased>"

// redactLeasedEnv removes brokered credential values before a spec is written
// to the database.
//
// A dispatched spec carries the secrets the broker leased to that workload, in
// plaintext, in Env. Persisting them verbatim undoes the point of TTL-leasing:
// a fifteen-minute credential written into executor_sessions outlives its
// lease, survives the revocation that was supposed to take it away, and is
// copied into every backup of the control-plane database. There is no revoke
// frame that can reach a row in SQLite.
//
// Only the variables the lease itself contributed are touched — Spec.Secrets
// names them — so the operator's own environment, which is not the broker's to
// redact, is stored unchanged and failover still reproduces it.
//
// A failover re-dispatch therefore starts without the leased credentials. That
// is the correct outcome rather than a regression: by the time a session is
// failed over its lease has almost certainly lapsed, so re-injecting the stored
// copy would hand the replacement executor a credential the broker already
// considers dead. A run that needs it fails loudly and is re-leased on the next
// start.
func redactLeasedEnv(spec executor.Spec) executor.Spec {
	if len(spec.Env) == 0 || len(spec.Secrets) == 0 {
		return spec
	}
	leased := make(map[string]struct{})
	for _, b := range spec.Secrets {
		for _, k := range b.EnvKeys {
			if k = strings.TrimSpace(k); k != "" {
				leased[k] = struct{}{}
			}
		}
	}
	if len(leased) == 0 {
		return spec
	}
	// Copy rather than rewrite in place: the caller's spec is the live one the
	// workload was started with, and mutating it here would scrub a running
	// task's environment as a side effect of recording it.
	env := make([]string, len(spec.Env))
	copy(env, spec.Env)
	for i, kv := range env {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, hit := leased[key]; hit {
			env[i] = key + "=" + redactedEnvValue
		}
	}
	spec.Env = env
	return spec
}

// unmarshalSpec restores a dispatched workload, yielding the zero Spec when the
// column is empty or corrupt. Callers must check Argv before re-dispatching;
// executor.Spec.Validate rejects an empty Argv, so the failure is loud.
func unmarshalSpec(s string) executor.Spec {
	if s == "" {
		return executor.Spec{}
	}
	var spec executor.Spec
	if err := json.Unmarshal([]byte(s), &spec); err != nil {
		return executor.Spec{}
	}
	return spec
}

// ------------------------------------------------------------------ EventSink

// ExecutorTransition records a state change in the audit log.
//
// Failures are swallowed deliberately. The sink is called from probe
// goroutines, and an audit write that fails must not be able to stop the
// supervisor from *acting* on a node going unreachable — losing the log line is
// bad, losing the failover is worse.
func (s *Scheduler) ExecutorTransition(t executor.Transition) {
	_ = s.db.AppendAuditEvent(&statedb.AuditEvent{
		Timestamp:  t.At,
		Actor:      s.actor,
		EventType:  AuditEventStateChange,
		EntityType: AuditEntityExecutor,
		EntityID:   t.ExecutorID,
		Payload: statedb.MarshalAuditPayload(map[string]any{
			"from":   string(t.From),
			"to":     string(t.To),
			"reason": t.Reason,
		}),
	})
}

// ExecutorFailover records one session moved off a dead node, including the
// case where no replacement was found.
func (s *Scheduler) ExecutorFailover(ev executor.FailoverEvent) {
	payload := map[string]any{
		"session_id":   ev.Session.ID,
		"from":         ev.From,
		"attempt":      ev.Session.Attempt,
		"project_path": ev.Session.ProjectPath,
		"task_id":      ev.Session.TaskID,
	}
	if ev.To != "" {
		payload["to"] = ev.To
	}
	if ev.Reason != "" {
		payload["error"] = ev.Reason
	}
	payload["placed"] = ev.To != "" && ev.Err == nil

	_ = s.db.AppendAuditEvent(&statedb.AuditEvent{
		Timestamp:  ev.At,
		Actor:      s.actor,
		EventType:  AuditEventFailover,
		EntityType: auditSessionEntityType,
		EntityID:   ev.Session.ID,
		Payload:    statedb.MarshalAuditPayload(payload),
	})
}

// ------------------------------------------------------------------- identity

// NewClaimToken mints a session claim token.
//
// The token arbitrates a race; it is not a secret, and anything that can write
// to the database can rewrite the row directly. crypto/rand is used anyway
// because it costs nothing here and removes the need to reason about whether a
// predictable token could ever let a stale supervisor guess its way back into
// ownership of a session it no longer holds.
func NewClaimToken() (string, error) {
	return randomHex(16)
}

// NewSessionID mints a session identifier. It is random rather than sequential
// so session IDs carry no information about fleet size or dispatch rate.
func NewSessionID() (string, error) {
	id, err := randomHex(12)
	if err != nil {
		return "", err
	}
	return "sess_" + id, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("executorstore: read random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
