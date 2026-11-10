package executorpool

// store.go: pools over the control plane's database, with their audit rows
// (Task 20482). Every mutation here records itself on the control plane's
// chain, so the API and any later CLI leave the same trail.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Store is the pools of one control plane.
type Store struct {
	db  *statedb.DB
	now func() time.Time
}

// NewStore returns the pools stored in db, which must be the control plane's
// database (statedb.DB.AsControlPlane): pool events belong on its chain.
func NewStore(db *statedb.DB) *Store {
	return &Store{db: db, now: time.Now}
}

// WithClock replaces the store's clock, for tests.
func (s *Store) WithClock(now func() time.Time) *Store {
	if now != nil {
		s.now = now
	}
	return s
}

// DB is the database the store reads and writes.
func (s *Store) DB() *statedb.DB { return s.db }

func (s *Store) audit(action auditaction.Action, poolID, actor string, payload map[string]any) {
	statedb.AuditExecutorPool(s.db, action, poolID, actor, payload)
}

// Create stores a new pool.
func (s *Store) Create(spec Spec, actor string) (Pool, error) {
	spec = spec.Normalize()
	if err := spec.Validate(); err != nil {
		return Pool{}, err
	}
	id, err := newPoolID()
	if err != nil {
		return Pool{}, err
	}
	now := s.now().UTC()
	p := Pool{ID: id, Name: spec.Name, Labels: spec.Labels, Capabilities: spec.Capabilities,
		MaxRunners: spec.MaxRunners, Owner: spec.Owner, WorkDirRoot: spec.WorkDirRoot,
		CreatedAt: now, CreatedBy: actor, UpdatedAt: now, UpdatedBy: actor}
	row, err := toRow(p)
	if err != nil {
		return Pool{}, err
	}
	if err := s.db.CreateExecutorPool(row); err != nil {
		return Pool{}, err
	}
	s.audit(auditaction.ActionExecutorPoolCreate, p.ID, actor, specPayload(p.Spec()))
	return p, nil
}

func specPayload(sp Spec) map[string]any {
	return map[string]any{"name": sp.Name, "labels": sp.Labels, "capabilities": sp.Capabilities,
		"max_runners": sp.MaxRunners, "owner": sp.Owner, "workdir_root": sp.WorkDirRoot}
}

// Get returns one pool.
func (s *Store) Get(id string) (Pool, error) {
	row, err := s.db.GetExecutorPool(id)
	if err != nil {
		return Pool{}, err
	}
	return fromRow(row), nil
}

// List returns every pool, by name.
func (s *Store) List() ([]Pool, error) {
	rows, err := s.db.ListExecutorPools()
	if err != nil {
		return nil, err
	}
	out := make([]Pool, 0, len(rows))
	for _, r := range rows {
		out = append(out, fromRow(r))
	}
	return out, nil
}

// Update replaces a live pool's definition. Lowering max_runners below the
// runners the pool already has retires none of them: it stops new ones being
// minted until enough have gone.
func (s *Store) Update(id string, spec Spec, actor string) (Pool, error) {
	spec = spec.Normalize()
	if err := spec.Validate(); err != nil {
		return Pool{}, err
	}
	prev, err := s.Get(id)
	if err != nil {
		return Pool{}, err
	}
	if prev.Revoked() {
		return Pool{}, fmt.Errorf("%w: %q", ErrRevoked, id)
	}
	next := prev
	next.Name, next.Labels, next.Capabilities = spec.Name, spec.Labels, spec.Capabilities
	next.MaxRunners, next.Owner, next.WorkDirRoot = spec.MaxRunners, spec.Owner, spec.WorkDirRoot
	next.UpdatedAt, next.UpdatedBy = s.now().UTC(), actor
	row, err := toRow(next)
	if err != nil {
		return Pool{}, err
	}
	if err := s.db.UpdateExecutorPool(row); err != nil {
		return Pool{}, err
	}
	payload := specPayload(next.Spec())
	payload["changed"] = changedFields(prev.Spec(), next.Spec())
	s.audit(auditaction.ActionExecutorPoolUpdate, id, actor, payload)
	return next, nil
}

// changedFields names what an update changed, for its audit row.
func changedFields(a, b Spec) []string {
	var out []string
	if a.Name != b.Name {
		out = append(out, "name")
	}
	if fmt.Sprint(a.Labels) != fmt.Sprint(b.Labels) {
		out = append(out, "labels")
	}
	if fmt.Sprintf("%+v", a.Capabilities) != fmt.Sprintf("%+v", b.Capabilities) {
		out = append(out, "capabilities")
	}
	if a.MaxRunners != b.MaxRunners {
		out = append(out, "max_runners")
	}
	if a.Owner != b.Owner {
		out = append(out, "owner")
	}
	if a.WorkDirRoot != b.WorkDirRoot {
		out = append(out, "workdir_root")
	}
	return out
}

// Revoke revokes a pool and everything it holds; see
// statedb.DB.RevokeExecutorPool. The caller ends the live runners' connections
// and gives back the cancelled runs' concurrency slots.
func (s *Store) Revoke(id, actor string) (statedb.ExecutorPoolRevocation, error) {
	rev, err := s.db.RevokeExecutorPool(id, actor, s.now().UTC())
	if err != nil {
		return rev, err
	}
	runners := make([]string, 0, len(rev.Runners))
	for _, r := range rev.Runners {
		runners = append(runners, r.ExecutorID)
	}
	cancelled := make([]string, 0, len(rev.Cancelled))
	for _, q := range rev.Cancelled {
		cancelled = append(cancelled, q.ID)
	}
	s.audit(auditaction.ActionExecutorPoolRevoke, id, actor, map[string]any{
		"name": rev.Pool.Name, "credentials": rev.Credentials, "tokens": rev.Tokens,
		"runners": runners, "cancelled_runs": cancelled,
	})
	return rev, nil
}

// ── audience ───────────────────────────────────────────────────────────────

// Audience returns who may run work on the pool's runners; empty is anyone.
func (s *Store) Audience(poolID string) ([]statedb.ExecutorAudienceEntry, error) {
	return s.db.ExecutorPoolAudience(poolID)
}

// Admit adds a principal to the pool's access list.
func (s *Store) Admit(poolID, kind, value, actor string) error {
	p, err := s.Get(poolID)
	if err != nil {
		return err
	}
	if p.Revoked() {
		return fmt.Errorf("%w: %q", ErrRevoked, poolID)
	}
	if err := s.db.AddExecutorPoolAudience(poolID, kind, value, actor); err != nil {
		return err
	}
	s.audit(auditaction.ActionExecutorPoolAudience, poolID, actor, map[string]any{
		"action": "add", "kind": strings.ToLower(strings.TrimSpace(kind)), "value": strings.TrimSpace(value), "restricted": true,
	})
	return nil
}

// Withdraw removes a principal from the pool's access list. Removing the
// last one makes the pool unrestricted again, which the audit row says.
func (s *Store) Withdraw(poolID, kind, value, actor string) error {
	if err := s.db.RemoveExecutorPoolAudience(poolID, kind, value); err != nil {
		return err
	}
	left, err := s.db.ExecutorPoolAudience(poolID)
	restricted := err != nil || len(left) > 0
	s.audit(auditaction.ActionExecutorPoolAudience, poolID, actor, map[string]any{
		"action": "remove", "kind": strings.ToLower(strings.TrimSpace(kind)), "value": strings.TrimSpace(value),
		"restricted": restricted,
	})
	return nil
}

// AudienceFingerprint is the fingerprint of the pool's access list now.
func (s *Store) AudienceFingerprint(poolID string) (string, error) {
	entries, err := s.db.ExecutorPoolAudience(poolID)
	if err != nil {
		return "", err
	}
	return AudienceFingerprint(entries), nil
}

// ── credentials ────────────────────────────────────────────────────────────

// Credential is a controller credential as the hub shows it: never the
// secret, which exists only in what MintCredential returns.
type Credential struct {
	ID         string    `json:"id"`
	PoolID     string    `json:"pool_id"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by,omitempty"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string    `json:"revoked_by,omitempty"`
}

func credentialFrom(r statedb.ExecutorPoolCredentialRow) Credential {
	return Credential{ID: r.ID, PoolID: r.PoolID, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
		LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt, RevokedBy: r.RevokedBy}
}

// MintCredential issues a controller credential for a live pool and returns
// it: the only time the secret exists outside the controller.
func (s *Store) MintCredential(poolID, actor string) (token string, cred Credential, err error) {
	token, id, hash, err := newCredential()
	if err != nil {
		return "", Credential{}, err
	}
	row := statedb.ExecutorPoolCredentialRow{ID: id, PoolID: poolID, SecretHash: hash, CreatedAt: s.now().UTC(), CreatedBy: actor}
	if err := s.db.PutExecutorPoolCredential(row); err != nil {
		return "", Credential{}, err
	}
	s.audit(auditaction.ActionExecutorPoolCredentialMint, poolID, actor, map[string]any{"credential_id": id})
	return token, credentialFrom(row), nil
}

// Credentials lists a pool's controller credentials, newest first.
func (s *Store) Credentials(poolID string) ([]Credential, error) {
	rows, err := s.db.ListExecutorPoolCredentials(poolID)
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(rows))
	for _, r := range rows {
		out = append(out, credentialFrom(r))
	}
	return out, nil
}

// RevokeCredential revokes one controller credential of poolID, and what it
// minted: its unredeemed runner tokens and its enrolled runners (see
// statedb.DB.RevokeExecutorPoolCredential). The caller ends those runners'
// connections. A credential of another pool is not found: the route names the
// pool it acts on.
func (s *Store) RevokeCredential(poolID, credentialID, actor string) (statedb.PoolCredentialRevocation, error) {
	row, err := s.db.GetExecutorPoolCredential(credentialID)
	if err != nil {
		return statedb.PoolCredentialRevocation{}, err
	}
	if row.PoolID != poolID {
		return statedb.PoolCredentialRevocation{}, fmt.Errorf("%w: %q", statedb.ErrPoolCredentialNotFound, credentialID)
	}
	rev, err := s.db.RevokeExecutorPoolCredential(credentialID, actor, s.now().UTC())
	if err != nil {
		return rev, err
	}
	if rev.Revoked || len(rev.Tokens) > 0 || len(rev.Runners) > 0 {
		runners := make([]string, 0, len(rev.Runners))
		for _, r := range rev.Runners {
			runners = append(runners, r.ExecutorID)
		}
		s.audit(auditaction.ActionExecutorPoolCredentialRevoke, poolID, actor, map[string]any{
			"credential_id": credentialID, "tokens": rev.Tokens, "runners": runners})
	}
	return rev, nil
}

// Authenticate verifies a controller credential and returns its live pool.
// Every failure is ErrCredentialInvalid, ErrCredentialRevoked or ErrRevoked;
// the route answers each with the same 401, and the error is for the log and
// the refusal metric.
func (s *Store) Authenticate(token string) (Pool, Credential, error) {
	id, secret, err := ParseCredential(token)
	if err != nil {
		return Pool{}, Credential{}, err
	}
	row, err := s.db.GetExecutorPoolCredential(id)
	if errors.Is(err, statedb.ErrPoolCredentialNotFound) {
		// Hash anyway, so an unknown ID costs what a known one does.
		_ = secretMatches(secret, strings.Repeat("0", 64))
		return Pool{}, Credential{}, fmt.Errorf("%w: unknown credential %s", ErrCredentialInvalid, id)
	}
	if err != nil {
		return Pool{}, Credential{}, err
	}
	if !secretMatches(secret, row.SecretHash) {
		return Pool{}, Credential{}, fmt.Errorf("%w: secret does not match credential %s", ErrCredentialInvalid, id)
	}
	if row.Revoked() {
		return Pool{}, Credential{}, fmt.Errorf("%w: credential %s was revoked at %s", ErrCredentialRevoked, id,
			row.RevokedAt.UTC().Format(time.RFC3339))
	}
	pool, err := s.Get(row.PoolID)
	if err != nil {
		return Pool{}, Credential{}, err
	}
	if pool.Revoked() {
		return Pool{}, Credential{}, fmt.Errorf("%w: pool %s was revoked at %s", ErrRevoked, pool.ID,
			pool.RevokedAt.UTC().Format(time.RFC3339))
	}
	now := s.now().UTC()
	if now.Sub(row.LastUsedAt) >= touchInterval {
		_ = s.db.TouchExecutorPoolCredential(id, now)
	}
	return pool, credentialFrom(row), nil
}

// ── runners ────────────────────────────────────────────────────────────────

// RunnerOptions are what a runner configuration carries besides its token.
type RunnerOptions struct {
	// Server is the agent endpoint URL the runner dials, and Pin the hub's
	// SPKI fingerprint: the same pinned transport every agent uses.
	Server string
	Pin    string
	// TTL bounds the tokens; zero is remote.MaxRunnerTTL, the most allowed.
	TTL time.Duration
	// Actor is the audit actor: CredentialActor for a controller.
	Actor string
	// CredentialID names the controller credential behind the request.
	CredentialID string
}

// RunnerConfig is one runner a controller may start.
type RunnerConfig struct {
	// EnrollmentID is the token's public ID: what the runner is known by
	// until it enrolls.
	EnrollmentID string `json:"enrollment_id"`
	// Name is the runner's name, the pool's name and a suffix.
	Name string `json:"name"`
	// Token is the single-use runner token; Bundle is it with the server and
	// the pin, as `cloop executor agent --token-file` reads it.
	Token  string `json:"token"`
	Bundle string `json:"bundle"`
	Server string `json:"server"`
	Pin    string `json:"pin,omitempty"`
	// Labels are the pool's, which the runner enrolls with.
	Labels      map[string]string `json:"labels,omitempty"`
	WorkDirRoot string            `json:"workdir_root,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at"`
	// Ephemeral is always true: the runner takes one run and is retired.
	Ephemeral bool `json:"ephemeral"`
}

// MintRunners issues n runner tokens for pool, or refuses: a revoked pool, an
// n outside 1..MaxRunnersPerRequest, or one that would take the pool past
// max_runners (a *statedb.PoolAtCapacityError). Atomic: all n or none.
func (s *Store) MintRunners(pool Pool, n int, opts RunnerOptions) ([]RunnerConfig, error) {
	if n < 1 || n > MaxRunnersPerRequest {
		return nil, fmt.Errorf("%w: ask for between 1 and %d runners, not %d", ErrInvalidSpec, MaxRunnersPerRequest, n)
	}
	if pool.Revoked() {
		return nil, fmt.Errorf("%w: %q", ErrRevoked, pool.ID)
	}
	if strings.TrimSpace(opts.Server) == "" {
		return nil, fmt.Errorf("executorpool: mint runners: no agent endpoint to put in the configuration")
	}
	now := s.now().UTC()
	tokens := make([]statedb.EnrollmentTokenRow, 0, n)
	runners := make([]statedb.ExecutorPoolRunnerRow, 0, n)
	configs := make([]RunnerConfig, 0, n)
	for i := 0; i < n; i++ {
		suffix, err := randomString(4)
		if err != nil {
			return nil, fmt.Errorf("executorpool: mint runners: %w", err)
		}
		name := pool.Name + "-" + strings.ToLower(strings.NewReplacer("-", "x", "_", "y").Replace(suffix))
		token, rec, err := remote.PrepareRunnerToken(remote.MintOptions{
			Name: name, TTL: opts.TTL, WorkDirRoot: pool.WorkDirRoot, Labels: pool.Labels,
			CreatedBy: opts.Actor, Now: func() time.Time { return now },
		})
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, statedb.EnrollmentTokenRow{ID: rec.ID, Name: rec.Name, SecretHash: rec.SecretHash,
			WorkDirRoot: rec.WorkDirRoot, Labels: rec.Labels, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt,
			CreatedBy: rec.CreatedBy})
		runners = append(runners, statedb.ExecutorPoolRunnerRow{EnrollmentID: rec.ID, PoolID: pool.ID, Name: name,
			CredentialID: opts.CredentialID})
		bundle, err := remote.Bundle{Server: opts.Server, Token: token, Pin: opts.Pin, EnrollmentID: rec.ID,
			Name: name, WorkDirRoot: rec.WorkDirRoot, ExpiresAt: rec.ExpiresAt}.Encode()
		if err != nil {
			return nil, err
		}
		configs = append(configs, RunnerConfig{EnrollmentID: rec.ID, Name: name, Token: token, Bundle: bundle,
			Server: opts.Server, Pin: opts.Pin, Labels: rec.Labels, WorkDirRoot: rec.WorkDirRoot,
			ExpiresAt: rec.ExpiresAt, Ephemeral: true})
	}
	if err := s.db.MintExecutorPoolRunners(pool.ID, tokens, runners, now); err != nil {
		return nil, err
	}
	ids := make([]string, 0, n)
	for _, c := range configs {
		ids = append(ids, c.EnrollmentID)
	}
	snapRunners, _ := s.db.ListExecutorPoolRunners(pool.ID, statedb.PoolRunnerPending, statedb.PoolRunnerIdle, statedb.PoolRunnerBusy)
	live := 0
	for _, r := range snapRunners {
		if r.Live(now) {
			live++
		}
	}
	s.audit(auditaction.ActionExecutorPoolTokenMint, pool.ID, opts.Actor, map[string]any{
		"credential_id": opts.CredentialID, "count": n, "enrollment_ids": ids,
		"expires_at": configs[0].ExpiresAt.UTC().Format(time.RFC3339), "runners": live, "max_runners": pool.MaxRunners,
	})
	return configs, nil
}

// RunnerOf returns the pool runner minted as enrollmentID.
func (s *Store) RunnerOf(enrollmentID string) (statedb.ExecutorPoolRunnerRow, error) {
	return s.db.GetExecutorPoolRunner(enrollmentID)
}

// RunnerByExecutor returns the pool runner whose agent is executorID.
func (s *Store) RunnerByExecutor(executorID string) (statedb.ExecutorPoolRunnerRow, error) {
	return s.db.ExecutorPoolRunnerByExecutor(executorID)
}

// AdmitRunner decides whether the runner token recorded as enrollmentID may be
// redeemed now: it must be a runner token of a live pool, still pending.
func (s *Store) AdmitRunner(enrollmentID string) error {
	r, err := s.db.GetExecutorPoolRunner(enrollmentID)
	if err != nil {
		return fmt.Errorf("%w: %s is not a runner token of any pool", remote.ErrTokenInvalid, enrollmentID)
	}
	pool, err := s.Get(r.PoolID)
	if err != nil {
		return err
	}
	if pool.Revoked() {
		return fmt.Errorf("%w: runner token %s's pool %s was revoked", remote.ErrRevoked, enrollmentID, pool.ID)
	}
	if r.State != statedb.PoolRunnerPending {
		return fmt.Errorf("%w: runner token %s is %s", remote.ErrTokenAlreadyUsed, enrollmentID, r.State)
	}
	// The controller credential that minted it must still be live: a
	// credential that leaked and was revoked takes its tokens with it.
	if r.CredentialID != "" {
		cred, err := s.db.GetExecutorPoolCredential(r.CredentialID)
		if err != nil {
			return fmt.Errorf("%w: runner token %s's controller credential: %v", remote.ErrRevoked, enrollmentID, err)
		}
		if cred.Revoked() {
			return fmt.Errorf("%w: runner token %s was minted with a revoked controller credential", remote.ErrRevoked, enrollmentID)
		}
	}
	return nil
}

// RunnerEnrolled records that the runner token enrollmentID became agent
// executorID on hub member member.
func (s *Store) RunnerEnrolled(enrollmentID, executorID, name, member string) (statedb.ExecutorPoolRunnerRow, error) {
	r, err := s.db.MarkExecutorPoolRunnerEnrolled(enrollmentID, executorID, member, s.now().UTC())
	if err != nil {
		return r, err
	}
	s.audit(auditaction.ActionExecutorPoolRunnerEnroll, r.PoolID, "system", map[string]any{
		"enrollment_id": enrollmentID, "executor_id": executorID, "name": name, "member": member,
	})
	return r, nil
}

// RetireRunner records a runner's retirement and reports whether this call
// retired it; only that call's caller writes its audit row. With states given,
// only a runner still in one of them is retired.
func (s *Store) RetireRunner(executorID, reason string, states ...string) (bool, error) {
	r, err := s.db.ExecutorPoolRunnerByExecutor(executorID)
	if err != nil {
		return false, err
	}
	retired, err := s.db.RetireExecutorPoolRunner(executorID, reason, s.now().UTC(), states...)
	if err != nil || !retired {
		return retired, err
	}
	payload := map[string]any{"executor_id": executorID, "reason": reason}
	if r.QueueID != "" {
		payload["queue_id"] = r.QueueID
		if q, err := s.db.GetPoolQueueEntry(r.QueueID); err == nil {
			payload["project_path"] = q.ProjectPath
		}
	}
	s.audit(auditaction.ActionExecutorPoolRunnerRetire, r.PoolID, "system", payload)
	return true, nil
}

// AuditRunnerRetired records a runner retired by its pool's revocation, which
// statedb retired in the revoking transaction.
func (s *Store) AuditRunnerRetired(poolID, executorID, reason string) {
	s.audit(auditaction.ActionExecutorPoolRunnerRetire, poolID, "system", map[string]any{
		"executor_id": executorID, "reason": reason,
	})
}

// AuditQueue records a queued run's movement.
func (s *Store) AuditQueue(q statedb.PoolQueueRow, action, actor, reason string) {
	payload := map[string]any{"queue_id": q.ID, "action": action, "project_path": q.ProjectPath}
	if q.Starter != "" {
		payload["starter"] = q.Starter
	}
	if q.ExecutorID != "" {
		payload["executor_id"] = q.ExecutorID
	}
	if reason != "" {
		payload["reason"] = reason
	}
	s.audit(auditaction.ActionExecutorPoolRunQueue, q.PoolID, actor, payload)
}

// Snapshot computes a pool's demand and runners from the shared database.
func (s *Store) Snapshot(pool Pool, access Access) (Snapshot, map[string]Verdict, error) {
	runners, err := s.db.ListExecutorPoolRunners(pool.ID, statedb.PoolRunnerPending, statedb.PoolRunnerIdle, statedb.PoolRunnerBusy)
	if err != nil {
		return Snapshot{}, nil, err
	}
	queue, err := s.db.ListPoolQueue(pool.ID, statedb.PoolQueueWaiting)
	if err != nil {
		return Snapshot{}, nil, err
	}
	fp, err := s.AudienceFingerprint(pool.ID)
	if err != nil {
		return Snapshot{}, nil, err
	}
	snap, verdicts := ComputeSnapshot(pool, runners, queue, fp, access, s.now())
	return snap, verdicts, nil
}

// SortedIDs returns the keys of verdicts in a stable order, for callers that
// act on them.
func SortedIDs(verdicts map[string]Verdict) []string {
	ids := make([]string, 0, len(verdicts))
	for id := range verdicts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
