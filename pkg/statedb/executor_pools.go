// Executor pool persistence (Task 20482).
//
// Rows for migrations/0099_executor_pools.sql; see that file for what each
// table and column means. This file owns the SQL and the atomicity: which
// counts happen inside which transaction is what makes max_runners a limit
// and the queue's hand-offs exactly-once, across every hub member sharing the
// database. What a pool decides — who may see a queued run, whether a runner
// may be minted — is pkg/executorpool's.
//
// Secrets are never stored: a controller credential and a runner token are
// held as hex SHA-256 of their secret part, hashed by their minters.

package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Runner states.
const (
	// PoolRunnerPending: a runner token was minted and not yet redeemed.
	PoolRunnerPending = "pending"
	// PoolRunnerIdle: the token was redeemed; the runner waits for a run.
	PoolRunnerIdle = "idle"
	// PoolRunnerBusy: the runner was handed a run (queue_id).
	PoolRunnerBusy = "busy"
	// PoolRunnerRetired: the runner took its run, its token expired, its
	// pool was revoked, or it left before it was given anything.
	PoolRunnerRetired = "retired"
)

// Queue states.
const (
	// PoolQueueWaiting: the run waits for a runner.
	PoolQueueWaiting = "waiting"
	// PoolQueueAssigned: a runner claimed the run and its member is starting
	// it.
	PoolQueueAssigned = "assigned"
	// PoolQueueDispatched: the run was started on its runner; from here it is
	// the project's run like any other.
	PoolQueueDispatched = "dispatched"
	// PoolQueueCancelled: the run was stopped, or its pool revoked, before it
	// started.
	PoolQueueCancelled = "cancelled"
	// PoolQueueFailed: the run could not be started on the runner it was
	// assigned, for a reason waiting will not change.
	PoolQueueFailed = "failed"
)

// Sentinel errors for executor pool persistence. Callers use errors.Is.
var (
	ErrExecutorPoolNotFound    = errors.New("statedb: executor pool not found")
	ErrExecutorPoolNameTaken   = errors.New("statedb: an executor pool with that name already exists")
	ErrExecutorPoolRevoked     = errors.New("statedb: executor pool was revoked")
	ErrPoolCredentialNotFound  = errors.New("statedb: executor pool credential not found")
	ErrPoolRunnerNotFound      = errors.New("statedb: executor pool runner not found")
	ErrPoolRunAlreadyQueued    = errors.New("statedb: a run of this project is already queued for a pool")
	ErrPoolQueueEntryNotFound  = errors.New("statedb: queued pool run not found")
	ErrExecutorPoolAtCapacity  = errors.New("statedb: executor pool is at max_runners")
	ErrPoolRunnerStateConflict = errors.New("statedb: executor pool runner is not in the state the change needs")
	// ErrExecutorPoolCordoned refuses a runner mint for a pool an
	// administrator holds (Task 20486).
	ErrExecutorPoolCordoned = errors.New("statedb: executor pool is cordoned")
)

// PoolAtCapacityError refuses a runner mint that would take a pool past its
// max_runners. It unwraps to ErrExecutorPoolAtCapacity.
type PoolAtCapacityError struct {
	PoolID    string
	Live      int
	Requested int
	Max       int
}

func (e *PoolAtCapacityError) Error() string {
	return fmt.Sprintf("statedb: executor pool %s has %d of %d runners; %d more would exceed max_runners",
		e.PoolID, e.Live, e.Max, e.Requested)
}

// Unwrap lets callers match with errors.Is(err, ErrExecutorPoolAtCapacity).
func (e *PoolAtCapacityError) Unwrap() error { return ErrExecutorPoolAtCapacity }

// ExecutorPoolRow is one executor pool.
type ExecutorPoolRow struct {
	ID     string
	Name   string
	Labels map[string]string
	// Capabilities is the JSON object pkg/executorpool decodes; storage keeps
	// it opaque.
	Capabilities string
	MaxRunners   int
	Owner        string
	WorkDirRoot  string
	CreatedAt    time.Time
	CreatedBy    string
	UpdatedAt    time.Time
	UpdatedBy    string
	RevokedAt    time.Time
	RevokedBy    string
	// CordonedAt, CordonedBy and CordonReason are set while an administrator
	// holds the pool (Task 20486): its runners are handed no queued run and
	// its controller is minted no runner, while busy runners finish.
	CordonedAt   time.Time
	CordonedBy   string
	CordonReason string
}

// Revoked reports whether the pool was revoked.
func (r ExecutorPoolRow) Revoked() bool { return !r.RevokedAt.IsZero() }

// Cordoned reports whether an administrator holds the pool.
func (r ExecutorPoolRow) Cordoned() bool { return !r.CordonedAt.IsZero() }

// ExecutorPoolCredentialRow is one controller credential.
type ExecutorPoolCredentialRow struct {
	ID         string
	PoolID     string
	SecretHash string
	CreatedAt  time.Time
	CreatedBy  string
	LastUsedAt time.Time
	RevokedAt  time.Time
	RevokedBy  string
	// ControllerVersion is the build its controller last named, and
	// ControllerProtocol the pool-controller protocol it last said it speaks,
	// 0 for none said (Task 20486).
	ControllerVersion  string
	ControllerProtocol int
}

// Revoked reports whether the credential was revoked.
func (r ExecutorPoolCredentialRow) Revoked() bool { return !r.RevokedAt.IsZero() }

// ExecutorPoolRunnerRow is one runner token and the runner it became.
type ExecutorPoolRunnerRow struct {
	EnrollmentID string
	PoolID       string
	Name         string
	ExecutorID   string
	State        string
	Member       string
	QueueID      string
	MintedAt     time.Time
	ExpiresAt    time.Time
	EnrolledAt   time.Time
	BusyAt       time.Time
	RetiredAt    time.Time
	RetireReason string
	// CredentialID is the controller credential that minted the runner.
	CredentialID string
	// Holds is the tenant whose data the runner's storage holds, as its
	// controller declared when minting it (Task 20484); "" for storage that
	// is empty, or none. Such a runner is handed only that tenant's runs.
	Holds string
	// Project, ProjectName and ProjectOwner are the run it was handed — its
	// tenant, its name and its owner key — set as it is handed it.
	Project      string
	ProjectName  string
	ProjectOwner string
}

// PoolRunnerProject is the project of a run as a runner is handed it (Task
// 20484): the tenant (executorpool.ProjectTenant) that decides which runners
// may take it, and the name and owner its controller records on the runner's
// storage.
type PoolRunnerProject struct {
	Tenant string
	Name   string
	Owner  string
}

// Live reports whether the runner counts against its pool's max_runners at
// now: a token not yet expired, or a runner not yet retired.
func (r ExecutorPoolRunnerRow) Live(now time.Time) bool {
	switch r.State {
	case PoolRunnerIdle, PoolRunnerBusy:
		return true
	case PoolRunnerPending:
		return r.ExpiresAt.IsZero() || now.Before(r.ExpiresAt)
	}
	return false
}

// PoolQueueRow is one run waiting for, or handed to, a pool's runner.
type PoolQueueRow struct {
	ID          string
	PoolID      string
	ProjectPath string
	Handler     string
	Starter     string
	Payer       string
	AudienceFP  string
	// Requirements and Slot are JSON documents their writers own.
	Requirements string
	Slot         string
	State        string
	Reason       string
	ExecutorID   string
	Member       string
	// Attempts counts the runners the run was handed.
	Attempts  int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Open reports whether the entry still waits or is being started.
func (r PoolQueueRow) Open() bool {
	return r.State == PoolQueueWaiting || r.State == PoolQueueAssigned
}

const executorPoolColumns = `id, name, labels_json, capabilities_json, max_runners, owner, workdir_root,
	created_at, created_by, updated_at, updated_by, revoked_at, revoked_by, cordoned_at, cordoned_by, cordon_reason`

const poolCredentialColumns = `id, pool_id, secret_hash, created_at, created_by, last_used_at, revoked_at, revoked_by,
	controller_version, controller_protocol`

const poolRunnerColumns = `enrollment_id, pool_id, name, executor_id, state, member, queue_id,
	minted_at, expires_at, enrolled_at, busy_at, retired_at, retire_reason, credential_id,
	holds, project, project_name, project_owner`

const poolQueueColumns = `id, pool_id, project_path, handler, starter, payer, audience_fp,
	requirements_json, slot_json, state, reason, executor_id, member, attempts, created_at, updated_at`

// ── pools ──────────────────────────────────────────────────────────────────

// CreateExecutorPool inserts a new pool.
func (d *DB) CreateExecutorPool(row ExecutorPoolRow) error {
	if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.Name) == "" {
		return errors.New("statedb: an executor pool needs an id and a name")
	}
	labels, err := marshalLabelMap(row.Labels)
	if err != nil {
		return fmt.Errorf("statedb: marshal executor pool labels: %w", err)
	}
	caps := strings.TrimSpace(row.Capabilities)
	if caps == "" {
		caps = "{}"
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = row.CreatedAt
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err = d.conn.Exec(`INSERT INTO executor_pools(`+executorPoolColumns+`)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.Name, labels, caps, row.MaxRunners, row.Owner, row.WorkDirRoot,
		formatOptionalTime(row.CreatedAt), row.CreatedBy, formatOptionalTime(row.UpdatedAt), row.UpdatedBy,
		formatOptionalTime(row.RevokedAt), row.RevokedBy,
		formatOptionalTime(row.CordonedAt), row.CordonedBy, row.CordonReason)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: %q", ErrExecutorPoolNameTaken, row.Name)
		}
		return fmt.Errorf("statedb: create executor pool %q: %w", row.Name, classifyDriverErr(err))
	}
	return nil
}

// CreateExecutorPoolWith inserts a new pool together with its access list
// and, when cred is not nil, its first controller credential, in one
// transaction (Task 20486): a create that fails part way leaves nothing — no
// pool open to everyone because its access list was not written, and no name
// taken by a pool nobody can use.
func (d *DB) CreateExecutorPoolWith(row ExecutorPoolRow, audience []ExecutorAudienceEntry, cred *ExecutorPoolCredentialRow) error {
	if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.Name) == "" {
		return errors.New("statedb: an executor pool needs an id and a name")
	}
	labels, err := marshalLabelMap(row.Labels)
	if err != nil {
		return fmt.Errorf("statedb: marshal executor pool labels: %w", err)
	}
	caps := strings.TrimSpace(row.Capabilities)
	if caps == "" {
		caps = "{}"
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = row.CreatedAt
	}
	for _, e := range audience {
		kind := strings.ToLower(strings.TrimSpace(e.Kind))
		if !validAudienceKinds[kind] || strings.TrimSpace(e.Value) == "" {
			return fmt.Errorf("statedb: audience principal %q:%q is not one of user, group, role", e.Kind, e.Value)
		}
	}
	if cred != nil && (strings.TrimSpace(cred.ID) == "" || strings.TrimSpace(cred.SecretHash) == "") {
		return errors.New("statedb: an executor pool credential needs an id and a secret hash")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: create executor pool %q: %w", row.Name, classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO executor_pools(`+executorPoolColumns+`)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.Name, labels, caps, row.MaxRunners, row.Owner, row.WorkDirRoot,
		formatOptionalTime(row.CreatedAt), row.CreatedBy, formatOptionalTime(row.UpdatedAt), row.UpdatedBy,
		formatOptionalTime(row.RevokedAt), row.RevokedBy,
		formatOptionalTime(row.CordonedAt), row.CordonedBy, row.CordonReason); err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: %q", ErrExecutorPoolNameTaken, row.Name)
		}
		return fmt.Errorf("statedb: create executor pool %q: %w", row.Name, classifyDriverErr(err))
	}
	for _, e := range audience {
		if _, err := tx.Exec(`INSERT INTO executor_pool_audience(pool_id, principal_kind, principal_value, added_at, added_by)
			VALUES(?,?,?,?,?)
			ON CONFLICT(pool_id, principal_kind, principal_value) DO NOTHING`,
			row.ID, strings.ToLower(strings.TrimSpace(e.Kind)), strings.TrimSpace(e.Value),
			formatOptionalTime(row.CreatedAt), e.AddedBy); err != nil {
			return fmt.Errorf("statedb: admit %s %q to executor pool %q: %w", e.Kind, e.Value, row.Name, classifyDriverErr(err))
		}
	}
	if cred != nil {
		if _, err := tx.Exec(`INSERT INTO executor_pool_credentials(`+poolCredentialColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			cred.ID, row.ID, cred.SecretHash, formatOptionalTime(row.CreatedAt), cred.CreatedBy, "", "", "", "", 0); err != nil {
			return fmt.Errorf("statedb: put executor pool credential %q: %w", cred.ID, classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: create executor pool %q: commit: %w", row.Name, classifyDriverErr(err))
	}
	return nil
}

// GetExecutorPool returns one pool, or ErrExecutorPoolNotFound.
func (d *DB) GetExecutorPool(id string) (ExecutorPoolRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return getExecutorPool(d.conn, id)
}

func getExecutorPool(q poolQuerier, id string) (ExecutorPoolRow, error) {
	row, err := scanExecutorPool(q.QueryRow(`SELECT `+executorPoolColumns+` FROM executor_pools WHERE id = ?`,
		strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutorPoolRow{}, fmt.Errorf("%w: %q", ErrExecutorPoolNotFound, id)
	}
	if err != nil {
		return ExecutorPoolRow{}, fmt.Errorf("statedb: read executor pool %q: %w", id, classifyDriverErr(err))
	}
	return row, nil
}

// ListExecutorPools returns every pool, by name.
func (d *DB) ListExecutorPools() ([]ExecutorPoolRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + executorPoolColumns + ` FROM executor_pools ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list executor pools: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ExecutorPoolRow
	for rows.Next() {
		row, err := scanExecutorPool(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan executor pool: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executor pools: %w", classifyDriverErr(err))
	}
	return out, nil
}

// UpdateExecutorPool rewrites a live pool's definition — name, labels,
// capabilities, max_runners, owner and workdir root — from row. A revoked pool
// is never changed again.
func (d *DB) UpdateExecutorPool(row ExecutorPoolRow) error {
	labels, err := marshalLabelMap(row.Labels)
	if err != nil {
		return fmt.Errorf("statedb: marshal executor pool labels: %w", err)
	}
	caps := strings.TrimSpace(row.Capabilities)
	if caps == "" {
		caps = "{}"
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`UPDATE executor_pools SET name = ?, labels_json = ?, capabilities_json = ?,
		max_runners = ?, owner = ?, workdir_root = ?, updated_at = ?, updated_by = ?
		WHERE id = ? AND revoked_at = ''`,
		row.Name, labels, caps, row.MaxRunners, row.Owner, row.WorkDirRoot,
		formatOptionalTime(row.UpdatedAt), row.UpdatedBy, row.ID)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: %q", ErrExecutorPoolNameTaken, row.Name)
		}
		return fmt.Errorf("statedb: update executor pool %q: %w", row.ID, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := getExecutorPool(d.conn, row.ID); err != nil {
			return err
		}
		return fmt.Errorf("%w: %q", ErrExecutorPoolRevoked, row.ID)
	}
	return nil
}

// ExecutorPoolRevocation is what revoking a pool took back, for the caller to
// finish: the live runners' connections close on the hub member holding them,
// and each cancelled run's concurrency slot is given back once, by the caller
// that received it here.
type ExecutorPoolRevocation struct {
	Pool        ExecutorPoolRow
	Credentials int
	// Tokens are the unredeemed runner tokens revoked.
	Tokens []string
	// Runners were idle or busy; their agent credentials are revoked and
	// their rows retired.
	Runners []ExecutorPoolRunnerRow
	// Cancelled are the runs that were waiting for the pool.
	Cancelled []PoolQueueRow
}

// RevokeExecutorPool revokes a pool and, in the same transaction, every
// credential of its controllers, every runner token not yet redeemed, every
// live runner's agent credential, and every run queued for it. Revoking a
// revoked pool returns ErrExecutorPoolRevoked and changes nothing.
func (d *DB) RevokeExecutorPool(id, by string, at time.Time) (ExecutorPoolRevocation, error) {
	if at.IsZero() {
		at = time.Now()
	}
	stamp := formatOptionalTime(at)
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return ExecutorPoolRevocation{}, fmt.Errorf("statedb: revoke executor pool %q: %w", id, classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()

	pool, err := getExecutorPool(tx, id)
	if err != nil {
		return ExecutorPoolRevocation{}, err
	}
	if pool.Revoked() {
		return ExecutorPoolRevocation{}, fmt.Errorf("%w: %q", ErrExecutorPoolRevoked, id)
	}
	out := ExecutorPoolRevocation{}
	if _, err := tx.Exec(`UPDATE executor_pools SET revoked_at = ?, revoked_by = ?, updated_at = ?, updated_by = ?
		WHERE id = ?`, stamp, by, stamp, by, id); err != nil {
		return out, fmt.Errorf("statedb: revoke executor pool %q: %w", id, classifyDriverErr(err))
	}
	res, err := tx.Exec(`UPDATE executor_pool_credentials SET revoked_at = ?, revoked_by = ?
		WHERE pool_id = ? AND revoked_at = ''`, stamp, by, id)
	if err != nil {
		return out, fmt.Errorf("statedb: revoke executor pool %q credentials: %w", id, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err == nil {
		out.Credentials = int(n)
	}

	runners, err := queryPoolRunners(tx, `WHERE pool_id = ? AND state IN (?, ?, ?)`, id,
		PoolRunnerPending, PoolRunnerIdle, PoolRunnerBusy)
	if err != nil {
		return out, err
	}
	for _, r := range runners {
		switch r.State {
		case PoolRunnerPending:
			if _, err := tx.Exec(`UPDATE executor_enrollment_tokens SET revoked_at = ?
				WHERE id = ? AND revoked_at = ''`, stamp, r.EnrollmentID); err != nil {
				return out, fmt.Errorf("statedb: revoke runner token %q: %w", r.EnrollmentID, classifyDriverErr(err))
			}
			out.Tokens = append(out.Tokens, r.EnrollmentID)
		default:
			if r.ExecutorID != "" {
				if _, err := tx.Exec(`UPDATE executor_agent_credentials SET revoked_at = ?
					WHERE agent_id = ? AND revoked_at = ''`, stamp, r.ExecutorID); err != nil {
					return out, fmt.Errorf("statedb: revoke runner %q: %w", r.ExecutorID, classifyDriverErr(err))
				}
			}
			out.Runners = append(out.Runners, r)
		}
		if _, err := tx.Exec(`UPDATE executor_pool_runners SET state = ?, retired_at = ?, retire_reason = ?
			WHERE enrollment_id = ?`, PoolRunnerRetired, stamp, "the pool was revoked", r.EnrollmentID); err != nil {
			return out, fmt.Errorf("statedb: retire runner %q: %w", r.EnrollmentID, classifyDriverErr(err))
		}
	}

	open, err := queryPoolQueue(tx, `WHERE pool_id = ? AND state IN (?, ?)`, id, PoolQueueWaiting, PoolQueueAssigned)
	if err != nil {
		return out, err
	}
	for _, q := range open {
		res, err := tx.Exec(`UPDATE executor_pool_queue SET state = ?, reason = ?, updated_at = ?
			WHERE id = ? AND state IN (?, ?)`, PoolQueueCancelled, "its executor pool was revoked", stamp,
			q.ID, PoolQueueWaiting, PoolQueueAssigned)
		if err != nil {
			return out, fmt.Errorf("statedb: cancel queued run %q: %w", q.ID, classifyDriverErr(err))
		}
		if n, _ := res.RowsAffected(); n == 1 {
			out.Cancelled = append(out.Cancelled, q)
		}
	}
	if err := tx.Commit(); err != nil {
		return out, fmt.Errorf("statedb: revoke executor pool %q: commit: %w", id, classifyDriverErr(err))
	}
	pool.RevokedAt, pool.RevokedBy = at, by
	out.Pool = pool
	return out, nil
}

// ── audience ───────────────────────────────────────────────────────────────

// AddExecutorPoolAudience admits a principal to a pool. Idempotent, like
// AddExecutorAudience, whose kinds it shares.
func (d *DB) AddExecutorPoolAudience(poolID, kind, value, addedBy string) error {
	poolID = strings.TrimSpace(poolID)
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	if poolID == "" || value == "" {
		return errors.New("statedb: an executor pool audience entry needs a pool and a principal")
	}
	if !validAudienceKinds[kind] {
		return fmt.Errorf("statedb: audience principal kind %q is not one of user, group, role", kind)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`INSERT INTO executor_pool_audience(pool_id, principal_kind, principal_value, added_at, added_by)
		VALUES(?,?,?,?,?)
		ON CONFLICT(pool_id, principal_kind, principal_value) DO UPDATE SET
		  added_at = excluded.added_at, added_by = excluded.added_by`,
		poolID, kind, value, formatOptionalTime(time.Now()), addedBy); err != nil {
		return fmt.Errorf("statedb: admit %s %q to executor pool %q: %w", kind, value, poolID, classifyDriverErr(err))
	}
	return nil
}

// RemoveExecutorPoolAudience withdraws a principal; one never admitted is not
// an error.
func (d *DB) RemoveExecutorPoolAudience(poolID, kind, value string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`DELETE FROM executor_pool_audience
		WHERE pool_id = ? AND principal_kind = ? AND principal_value = ?`,
		strings.TrimSpace(poolID), strings.ToLower(strings.TrimSpace(kind)), strings.TrimSpace(value)); err != nil {
		return fmt.Errorf("statedb: withdraw %s %q from executor pool %q: %w", kind, value, poolID, classifyDriverErr(err))
	}
	return nil
}

// ExecutorPoolAudience returns the principals admitted to a pool, oldest
// first. Empty means unrestricted; an error must be read as "unknown", never
// as unrestricted.
func (d *DB) ExecutorPoolAudience(poolID string) ([]ExecutorAudienceEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT pool_id, principal_kind, principal_value, added_at, added_by
		FROM executor_pool_audience WHERE pool_id = ?
		ORDER BY added_at ASC, principal_kind ASC, principal_value ASC`, strings.TrimSpace(poolID))
	if err != nil {
		return nil, fmt.Errorf("statedb: audience for executor pool %q: %w", poolID, classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ExecutorAudienceEntry
	for rows.Next() {
		var (
			e       ExecutorAudienceEntry
			addedAt string
		)
		if err := rows.Scan(&e.ExecutorID, &e.Kind, &e.Value, &addedAt, &e.AddedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan executor pool audience: %w", classifyDriverErr(err))
		}
		e.AddedAt = parseOptionalTime(addedAt)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: audience for executor pool %q: %w", poolID, classifyDriverErr(err))
	}
	return out, nil
}

// ── credentials ────────────────────────────────────────────────────────────

// PutExecutorPoolCredential stores a newly minted controller credential, for
// a live pool only.
func (d *DB) PutExecutorPoolCredential(row ExecutorPoolCredentialRow) error {
	if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.PoolID) == "" {
		return errors.New("statedb: an executor pool credential needs an id and a pool")
	}
	if strings.TrimSpace(row.SecretHash) == "" {
		return fmt.Errorf("statedb: executor pool credential %q has an empty secret hash", row.ID)
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: put executor pool credential: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	pool, err := getExecutorPool(tx, row.PoolID)
	if err != nil {
		return err
	}
	if pool.Revoked() {
		return fmt.Errorf("%w: %q", ErrExecutorPoolRevoked, row.PoolID)
	}
	if _, err := tx.Exec(`INSERT INTO executor_pool_credentials(`+poolCredentialColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.PoolID, row.SecretHash, formatOptionalTime(row.CreatedAt), row.CreatedBy,
		formatOptionalTime(row.LastUsedAt), formatOptionalTime(row.RevokedAt), row.RevokedBy,
		row.ControllerVersion, row.ControllerProtocol); err != nil {
		return fmt.Errorf("statedb: put executor pool credential %q: %w", row.ID, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: put executor pool credential %q: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetExecutorPoolCredential returns one credential, or
// ErrPoolCredentialNotFound.
func (d *DB) GetExecutorPoolCredential(id string) (ExecutorPoolCredentialRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row, err := scanPoolCredential(d.conn.QueryRow(`SELECT `+poolCredentialColumns+`
		FROM executor_pool_credentials WHERE id = ?`, strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutorPoolCredentialRow{}, fmt.Errorf("%w: %q", ErrPoolCredentialNotFound, id)
	}
	if err != nil {
		return ExecutorPoolCredentialRow{}, fmt.Errorf("statedb: read executor pool credential %q: %w", id, classifyDriverErr(err))
	}
	return row, nil
}

// ListExecutorPoolCredentials returns a pool's credentials, newest first.
func (d *DB) ListExecutorPoolCredentials(poolID string) ([]ExecutorPoolCredentialRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+poolCredentialColumns+` FROM executor_pool_credentials
		WHERE pool_id = ? ORDER BY created_at DESC, id`, strings.TrimSpace(poolID))
	if err != nil {
		return nil, fmt.Errorf("statedb: list executor pool credentials: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ExecutorPoolCredentialRow
	for rows.Next() {
		row, err := scanPoolCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan executor pool credential: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executor pool credentials: %w", classifyDriverErr(err))
	}
	return out, nil
}

// PoolCredentialRevocation is what revoking one controller credential took
// back: the runner tokens it minted that were not yet redeemed, and the
// runners it minted that had enrolled — their agent credentials are revoked
// and their rows retired, and the caller ends their connections.
type PoolCredentialRevocation struct {
	// Revoked is false when the credential was already revoked.
	Revoked bool
	Tokens  []string
	Runners []ExecutorPoolRunnerRow
}

// RevokeExecutorPoolCredential revokes one controller credential and, in the
// same transaction, everything it minted: a credential that leaked must not
// leave behind the runners it was used to start, nor tokens that still redeem.
func (d *DB) RevokeExecutorPoolCredential(id, by string, at time.Time) (PoolCredentialRevocation, error) {
	if at.IsZero() {
		at = time.Now()
	}
	id = strings.TrimSpace(id)
	stamp := formatOptionalTime(at)
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return PoolCredentialRevocation{}, fmt.Errorf("statedb: revoke executor pool credential %q: %w", id, classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM executor_pool_credentials WHERE id = ?`, id).Scan(&exists); err != nil {
		return PoolCredentialRevocation{}, fmt.Errorf("statedb: revoke executor pool credential %q: %w", id, classifyDriverErr(err))
	}
	if exists == 0 {
		return PoolCredentialRevocation{}, fmt.Errorf("%w: %q", ErrPoolCredentialNotFound, id)
	}
	res, err := tx.Exec(`UPDATE executor_pool_credentials SET revoked_at = ?, revoked_by = ?
		WHERE id = ? AND revoked_at = ''`, stamp, by, id)
	if err != nil {
		return PoolCredentialRevocation{}, fmt.Errorf("statedb: revoke executor pool credential %q: %w", id, classifyDriverErr(err))
	}
	out := PoolCredentialRevocation{}
	if n, _ := res.RowsAffected(); n == 1 {
		out.Revoked = true
	}
	minted, err := queryPoolRunners(tx, `WHERE credential_id = ? AND credential_id != '' AND state IN (?, ?, ?)`, id,
		PoolRunnerPending, PoolRunnerIdle, PoolRunnerBusy)
	if err != nil {
		return out, err
	}
	reason := "the controller credential that minted it was revoked"
	for _, r := range minted {
		if r.State == PoolRunnerPending {
			if _, err := tx.Exec(`UPDATE executor_enrollment_tokens SET revoked_at = ?
				WHERE id = ? AND revoked_at = ''`, stamp, r.EnrollmentID); err != nil {
				return out, fmt.Errorf("statedb: revoke runner token %q: %w", r.EnrollmentID, classifyDriverErr(err))
			}
			out.Tokens = append(out.Tokens, r.EnrollmentID)
		} else {
			if r.ExecutorID != "" {
				if _, err := tx.Exec(`UPDATE executor_agent_credentials SET revoked_at = ?
					WHERE agent_id = ? AND revoked_at = ''`, stamp, r.ExecutorID); err != nil {
					return out, fmt.Errorf("statedb: revoke runner %q: %w", r.ExecutorID, classifyDriverErr(err))
				}
			}
			out.Runners = append(out.Runners, r)
		}
		if _, err := tx.Exec(`UPDATE executor_pool_runners SET state = ?, retired_at = ?, retire_reason = ?
			WHERE enrollment_id = ?`, PoolRunnerRetired, stamp, reason, r.EnrollmentID); err != nil {
			return out, fmt.Errorf("statedb: retire runner %q: %w", r.EnrollmentID, classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return out, fmt.Errorf("statedb: revoke executor pool credential %q: commit: %w", id, classifyDriverErr(err))
	}
	return out, nil
}

// TouchExecutorPoolCredential records a credential's use. Bookkeeping: a
// failure is the caller's to ignore.
func (d *DB) TouchExecutorPoolCredential(id string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`UPDATE executor_pool_credentials SET last_used_at = ? WHERE id = ?`,
		formatOptionalTime(at), id); err != nil {
		return fmt.Errorf("statedb: touch executor pool credential %q: %w", id, classifyDriverErr(err))
	}
	return nil
}

// NoteExecutorPoolController records the build and the pool-controller
// protocol the controller using credential id says it is (Task 20486), and
// reports whether either changed. It writes only a change: the controller
// names itself on every request.
func (d *DB) NoteExecutorPoolController(id, version string, protocol int) (bool, error) {
	if protocol < 0 {
		protocol = 0
	}
	return d.execOne(`UPDATE executor_pool_credentials SET controller_version = ?, controller_protocol = ?
		WHERE id = ? AND (controller_version != ? OR controller_protocol != ?)`,
		fmt.Sprintf("note the controller of pool credential %s", id),
		version, protocol, strings.TrimSpace(id), version, protocol)
}

// SetExecutorPoolCordon holds a live pool (cordon true) or releases it, and
// reports whether that changed anything (Task 20486). Cordoning a cordoned
// pool keeps its first stamp; a revoked pool is never changed
// (ErrExecutorPoolRevoked).
func (d *DB) SetExecutorPoolCordon(id string, cordon bool, by, reason string, at time.Time) (bool, error) {
	if at.IsZero() {
		at = time.Now()
	}
	stamp := formatOptionalTime(at)
	d.mu.Lock()
	defer d.mu.Unlock()
	pool, err := getExecutorPool(d.conn, id)
	if err != nil {
		return false, err
	}
	if pool.Revoked() {
		return false, fmt.Errorf("%w: %q", ErrExecutorPoolRevoked, id)
	}
	var res sql.Result
	if cordon {
		res, err = d.conn.Exec(`UPDATE executor_pools SET cordoned_at = ?, cordoned_by = ?, cordon_reason = ?,
			updated_at = ?, updated_by = ? WHERE id = ? AND revoked_at = '' AND cordoned_at = ''`,
			stamp, by, reason, stamp, by, pool.ID)
	} else {
		res, err = d.conn.Exec(`UPDATE executor_pools SET cordoned_at = '', cordoned_by = '', cordon_reason = '',
			updated_at = ?, updated_by = ? WHERE id = ? AND revoked_at = '' AND cordoned_at != ''`,
			stamp, by, pool.ID)
	}
	if err != nil {
		return false, fmt.Errorf("statedb: cordon executor pool %q: %w", id, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ── runners ────────────────────────────────────────────────────────────────

// MintExecutorPoolRunners records runner tokens for a live pool, refusing —
// with a *PoolAtCapacityError — when they would take it past maxRunners.
//
// One transaction for the count and the inserts, opened with SQLite's write
// lock (the connection's _txlock=immediate): two controllers, or two hub
// members, minting at once are serialised, so the second counts the first's
// tokens and max_runners holds. tokens and runners pair up by index; each
// token row is the runner's executor_enrollment_tokens row.
func (d *DB) MintExecutorPoolRunners(poolID string, tokens []EnrollmentTokenRow, runners []ExecutorPoolRunnerRow, now time.Time) error {
	if len(tokens) == 0 || len(tokens) != len(runners) {
		return errors.New("statedb: mint executor pool runners: tokens and runners must pair up")
	}
	if now.IsZero() {
		now = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: mint executor pool runners: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	pool, err := getExecutorPool(tx, poolID)
	if err != nil {
		return err
	}
	if pool.Revoked() {
		return fmt.Errorf("%w: %q", ErrExecutorPoolRevoked, poolID)
	}
	if pool.Cordoned() {
		return fmt.Errorf("%w: %q", ErrExecutorPoolCordoned, poolID)
	}
	live, err := countLivePoolRunners(tx, poolID, now)
	if err != nil {
		return err
	}
	if live+len(runners) > pool.MaxRunners {
		return &PoolAtCapacityError{PoolID: poolID, Live: live, Requested: len(runners), Max: pool.MaxRunners}
	}
	for i, tok := range tokens {
		labels, err := marshalLabelMap(tok.Labels)
		if err != nil {
			return fmt.Errorf("statedb: marshal runner token labels: %w", err)
		}
		if strings.TrimSpace(tok.ID) == "" || strings.TrimSpace(tok.SecretHash) == "" {
			return errors.New("statedb: a runner token needs an id and a secret hash")
		}
		if _, err := tx.Exec(`INSERT INTO executor_enrollment_tokens(id, name, secret_hash, workdir_root, labels_json,
			created_at, expires_at, created_by, redeemed_at, redeemed_agent_id, revoked_at)
			VALUES(?,?,?,?,?,?,?,?,'','','')`,
			tok.ID, tok.Name, tok.SecretHash, tok.WorkDirRoot, labels,
			formatOptionalTime(tok.CreatedAt), formatOptionalTime(tok.ExpiresAt), tok.CreatedBy); err != nil {
			return fmt.Errorf("statedb: insert runner token %q: %w", tok.ID, classifyDriverErr(err))
		}
		r := runners[i]
		if r.EnrollmentID != tok.ID {
			return fmt.Errorf("statedb: runner %d names token %q, not %q", i, r.EnrollmentID, tok.ID)
		}
		if _, err := tx.Exec(`INSERT INTO executor_pool_runners(`+poolRunnerColumns+`)
			VALUES(?,?,?,'',?,'','',?,?,'','','','',?,?,'','','')`,
			r.EnrollmentID, poolID, r.Name, PoolRunnerPending,
			formatOptionalTime(tok.CreatedAt), formatOptionalTime(tok.ExpiresAt), r.CredentialID,
			strings.TrimSpace(r.Holds)); err != nil {
			return fmt.Errorf("statedb: insert runner %q: %w", r.EnrollmentID, classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: mint executor pool runners: commit: %w", classifyDriverErr(err))
	}
	return nil
}

// countLivePoolRunners counts what holds a place under max_runners at now.
func countLivePoolRunners(q poolQuerier, poolID string, now time.Time) (int, error) {
	var n int
	err := q.QueryRow(`SELECT COUNT(1) FROM executor_pool_runners
		WHERE pool_id = ? AND (state IN (?, ?) OR (state = ? AND (expires_at = '' OR expires_at > ?)))`,
		poolID, PoolRunnerIdle, PoolRunnerBusy, PoolRunnerPending, formatOptionalTime(now)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("statedb: count executor pool runners: %w", classifyDriverErr(err))
	}
	return n, nil
}

// GetExecutorPoolRunner returns the runner minted as enrollmentID.
func (d *DB) GetExecutorPoolRunner(enrollmentID string) (ExecutorPoolRunnerRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return getPoolRunner(d.conn, `WHERE enrollment_id = ?`, strings.TrimSpace(enrollmentID))
}

// ExecutorPoolRunnerByExecutor returns the runner whose agent is executorID.
func (d *DB) ExecutorPoolRunnerByExecutor(executorID string) (ExecutorPoolRunnerRow, error) {
	if strings.TrimSpace(executorID) == "" {
		return ExecutorPoolRunnerRow{}, fmt.Errorf("%w: no executor id", ErrPoolRunnerNotFound)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return getPoolRunner(d.conn, `WHERE executor_id = ?`, strings.TrimSpace(executorID))
}

func getPoolRunner(q poolQuerier, where string, args ...any) (ExecutorPoolRunnerRow, error) {
	row, err := scanPoolRunner(q.QueryRow(`SELECT `+poolRunnerColumns+` FROM executor_pool_runners `+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutorPoolRunnerRow{}, fmt.Errorf("%w: %v", ErrPoolRunnerNotFound, args)
	}
	if err != nil {
		return ExecutorPoolRunnerRow{}, fmt.Errorf("statedb: read executor pool runner: %w", classifyDriverErr(err))
	}
	return row, nil
}

// ListExecutorPoolRunners returns a pool's runners in the given states (all
// when none are given), oldest first. An empty poolID lists every pool's.
func (d *DB) ListExecutorPoolRunners(poolID string, states ...string) ([]ExecutorPoolRunnerRow, error) {
	where, args := "WHERE 1 = 1", []any{}
	if strings.TrimSpace(poolID) != "" {
		where += " AND pool_id = ?"
		args = append(args, strings.TrimSpace(poolID))
	}
	if len(states) > 0 {
		where += " AND state IN (" + placeholders(len(states)) + ")"
		for _, s := range states {
			args = append(args, s)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryPoolRunners(d.conn, where, args...)
}

func queryPoolRunners(q poolQuerier, where string, args ...any) ([]ExecutorPoolRunnerRow, error) {
	rows, err := q.Query(`SELECT `+poolRunnerColumns+` FROM executor_pool_runners `+where+
		` ORDER BY minted_at, enrollment_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list executor pool runners: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ExecutorPoolRunnerRow
	for rows.Next() {
		r, err := scanPoolRunner(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan executor pool runner: %w", classifyDriverErr(err))
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executor pool runners: %w", classifyDriverErr(err))
	}
	return out, nil
}

// MarkExecutorPoolRunnerEnrolled records that the runner token enrollmentID
// became agent executorID, held by member. Only a pending runner of a live
// pool enrolls; anything else is ErrPoolRunnerStateConflict or
// ErrExecutorPoolRevoked, and the caller retires the agent.
func (d *DB) MarkExecutorPoolRunnerEnrolled(enrollmentID, executorID, member string, at time.Time) (ExecutorPoolRunnerRow, error) {
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return ExecutorPoolRunnerRow{}, fmt.Errorf("statedb: enroll executor pool runner: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	r, err := getPoolRunner(tx, `WHERE enrollment_id = ?`, enrollmentID)
	if err != nil {
		return ExecutorPoolRunnerRow{}, err
	}
	pool, err := getExecutorPool(tx, r.PoolID)
	if err != nil {
		return ExecutorPoolRunnerRow{}, err
	}
	if pool.Revoked() {
		return ExecutorPoolRunnerRow{}, fmt.Errorf("%w: %q", ErrExecutorPoolRevoked, r.PoolID)
	}
	res, err := tx.Exec(`UPDATE executor_pool_runners SET state = ?, executor_id = ?, member = ?, enrolled_at = ?
		WHERE enrollment_id = ? AND state = ?`,
		PoolRunnerIdle, executorID, member, formatOptionalTime(at), enrollmentID, PoolRunnerPending)
	if err != nil {
		return ExecutorPoolRunnerRow{}, fmt.Errorf("statedb: enroll executor pool runner %q: %w", enrollmentID, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ExecutorPoolRunnerRow{}, fmt.Errorf("%w: runner %q is %s, not pending", ErrPoolRunnerStateConflict, enrollmentID, r.State)
	}
	if err := tx.Commit(); err != nil {
		return ExecutorPoolRunnerRow{}, fmt.Errorf("statedb: enroll executor pool runner %q: %w", enrollmentID, classifyDriverErr(err))
	}
	r.State, r.ExecutorID, r.Member, r.EnrolledAt = PoolRunnerIdle, executorID, member, at
	return r, nil
}

// MovePoolRunnerIdle returns a busy runner that was never started on to
// idle, for the next queued run, and reports whether it moved.
//
// A runner handed a run keeps that run's tenant as what it holds (Task
// 20484), unless it already held one: whatever the hand-over got as far as —
// a workspace fetched onto its storage, say — is that project's, and the next
// run it may be handed is that project's too. Never another's on the strength
// of "it did not start".
func (d *DB) MovePoolRunnerIdle(executorID string) (bool, error) {
	return d.execOne(`UPDATE executor_pool_runners SET state = ?, queue_id = '', busy_at = '',
		holds = CASE WHEN holds = '' THEN project ELSE holds END, project = '', project_name = '', project_owner = ''
		WHERE executor_id = ? AND executor_id != '' AND state = ?`,
		fmt.Sprintf("return runner %s to idle", executorID), PoolRunnerIdle, executorID, PoolRunnerBusy)
}

// SetExecutorPoolRunnerMember records which hub member holds an idle or busy
// runner's connection, after it reconnects to another.
func (d *DB) SetExecutorPoolRunnerMember(executorID, member string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`UPDATE executor_pool_runners SET member = ?
		WHERE executor_id = ? AND state IN (?, ?)`, member, executorID, PoolRunnerIdle, PoolRunnerBusy); err != nil {
		return fmt.Errorf("statedb: record runner %q's member: %w", executorID, classifyDriverErr(err))
	}
	return nil
}

// RetireExecutorPoolRunner retires the runner whose agent is executorID and
// reports whether this call was the one that retired it. With states given,
// only a runner in one of them is retired: a caller that decided a runner was
// idle from an earlier read must not retire it after another member handed it
// a run.
func (d *DB) RetireExecutorPoolRunner(executorID, reason string, at time.Time, states ...string) (bool, error) {
	if at.IsZero() {
		at = time.Now()
	}
	q := `UPDATE executor_pool_runners SET state = ?, retired_at = ?, retire_reason = ?
		WHERE executor_id = ? AND executor_id != '' AND state != ?`
	args := []any{PoolRunnerRetired, formatOptionalTime(at), reason, executorID, PoolRunnerRetired}
	if len(states) > 0 {
		q += ` AND state IN (` + placeholders(len(states)) + `)`
		for _, st := range states {
			args = append(args, st)
		}
	}
	return d.execOne(q, fmt.Sprintf("retire executor pool runner %s", executorID), args...)
}

// RetirePendingExecutorPoolRunner retires the runner minted as enrollmentID
// while it is still pending — minted and not enrolled — and revokes its token
// in the same transaction, so the token cannot be redeemed afterwards (Task
// 20483: a controller that minted a runner it then did not start gives its
// place under max_runners back at once rather than when the token lapses). It
// reports whether this call retired it; a runner that already enrolled, or was
// retired, is left alone.
func (d *DB) RetirePendingExecutorPoolRunner(enrollmentID, reason string, at time.Time) (bool, error) {
	enrollmentID = strings.TrimSpace(enrollmentID)
	if enrollmentID == "" {
		return false, fmt.Errorf("%w: no enrollment id", ErrPoolRunnerNotFound)
	}
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: retire pending runner: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE executor_pool_runners SET state = ?, retired_at = ?, retire_reason = ?
		WHERE enrollment_id = ? AND state = ?`, PoolRunnerRetired, formatOptionalTime(at), reason,
		enrollmentID, PoolRunnerPending)
	if err != nil {
		return false, fmt.Errorf("statedb: retire pending runner %q: %w", enrollmentID, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	if _, err := tx.Exec(`UPDATE executor_enrollment_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = ''`,
		formatOptionalTime(at), enrollmentID); err != nil {
		return false, fmt.Errorf("statedb: revoke runner token %q: %w", enrollmentID, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: retire pending runner %q: commit: %w", enrollmentID, classifyDriverErr(err))
	}
	return true, nil
}

// ExpireExecutorPoolRunners retires every runner token that lapsed unredeemed
// before now, and returns them.
func (d *DB) ExpireExecutorPoolRunners(now time.Time) ([]ExecutorPoolRunnerRow, error) {
	if now.IsZero() {
		now = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("statedb: expire runner tokens: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	lapsed, err := queryPoolRunners(tx, `WHERE state = ? AND expires_at != '' AND expires_at <= ?`,
		PoolRunnerPending, formatOptionalTime(now))
	if err != nil {
		return nil, err
	}
	var out []ExecutorPoolRunnerRow
	for _, r := range lapsed {
		res, err := tx.Exec(`UPDATE executor_pool_runners SET state = ?, retired_at = ?, retire_reason = ?
			WHERE enrollment_id = ? AND state = ?`, PoolRunnerRetired, formatOptionalTime(now),
			"its token expired unredeemed", r.EnrollmentID, PoolRunnerPending)
		if err != nil {
			return nil, fmt.Errorf("statedb: expire runner token %q: %w", r.EnrollmentID, classifyDriverErr(err))
		}
		if n, _ := res.RowsAffected(); n == 1 {
			out = append(out, r)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("statedb: expire runner tokens: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ── queue ──────────────────────────────────────────────────────────────────

// EnqueuePoolRun records a run waiting for a runner of its pool. A project
// with a run already open in a pool's queue gets ErrPoolRunAlreadyQueued; a
// revoked pool, ErrExecutorPoolRevoked.
func (d *DB) EnqueuePoolRun(row PoolQueueRow) error {
	if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.PoolID) == "" || strings.TrimSpace(row.ProjectPath) == "" {
		return errors.New("statedb: a queued pool run needs an id, a pool and a project")
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	row.UpdatedAt = row.CreatedAt
	row.State = PoolQueueWaiting
	if strings.TrimSpace(row.Requirements) == "" {
		row.Requirements = "{}"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: queue pool run: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	pool, err := getExecutorPool(tx, row.PoolID)
	if err != nil {
		return err
	}
	if pool.Revoked() {
		return fmt.Errorf("%w: %q", ErrExecutorPoolRevoked, row.PoolID)
	}
	if _, err := tx.Exec(`INSERT INTO executor_pool_queue(`+poolQueueColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.PoolID, row.ProjectPath, row.Handler, row.Starter, row.Payer, row.AudienceFP,
		row.Requirements, row.Slot, row.State, row.Reason, row.ExecutorID, row.Member, row.Attempts,
		formatOptionalTime(row.CreatedAt), formatOptionalTime(row.UpdatedAt)); err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: %q", ErrPoolRunAlreadyQueued, row.ProjectPath)
		}
		return fmt.Errorf("statedb: queue pool run for %q: %w", row.ProjectPath, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: queue pool run for %q: %w", row.ProjectPath, classifyDriverErr(err))
	}
	return nil
}

// GetPoolQueueEntry returns one queued run.
func (d *DB) GetPoolQueueEntry(id string) (PoolQueueRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := queryPoolQueue(d.conn, `WHERE id = ?`, strings.TrimSpace(id))
	if err != nil {
		return PoolQueueRow{}, err
	}
	if len(rows) == 0 {
		return PoolQueueRow{}, fmt.Errorf("%w: %q", ErrPoolQueueEntryNotFound, id)
	}
	return rows[0], nil
}

// OpenPoolQueueEntry returns the project's run waiting in, or being started
// from, a pool's queue; ok is false when it has none.
func (d *DB) OpenPoolQueueEntry(projectPath string) (row PoolQueueRow, ok bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := queryPoolQueue(d.conn, `WHERE project_path = ? AND state IN (?, ?)`,
		projectPath, PoolQueueWaiting, PoolQueueAssigned)
	if err != nil || len(rows) == 0 {
		return PoolQueueRow{}, false, err
	}
	return rows[0], true, nil
}

// ListPoolQueue returns a pool's queued runs in the given states (all when
// none are given), oldest first. An empty poolID lists every pool's.
func (d *DB) ListPoolQueue(poolID string, states ...string) ([]PoolQueueRow, error) {
	where, args := "WHERE 1 = 1", []any{}
	if strings.TrimSpace(poolID) != "" {
		where += " AND pool_id = ?"
		args = append(args, strings.TrimSpace(poolID))
	}
	if len(states) > 0 {
		where += " AND state IN (" + placeholders(len(states)) + ")"
		for _, s := range states {
			args = append(args, s)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryPoolQueue(d.conn, where, args...)
}

func queryPoolQueue(q poolQuerier, where string, args ...any) ([]PoolQueueRow, error) {
	rows, err := q.Query(`SELECT `+poolQueueColumns+` FROM executor_pool_queue `+where+` ORDER BY created_at, id`, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list queued pool runs: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []PoolQueueRow
	for rows.Next() {
		var (
			row              PoolQueueRow
			created, updated string
		)
		if err := rows.Scan(&row.ID, &row.PoolID, &row.ProjectPath, &row.Handler, &row.Starter, &row.Payer,
			&row.AudienceFP, &row.Requirements, &row.Slot, &row.State, &row.Reason, &row.ExecutorID, &row.Member,
			&row.Attempts, &created, &updated); err != nil {
			return nil, fmt.Errorf("statedb: scan queued pool run: %w", classifyDriverErr(err))
		}
		row.CreatedAt, row.UpdatedAt = parseOptionalTime(created), parseOptionalTime(updated)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list queued pool runs: %w", classifyDriverErr(err))
	}
	return out, nil
}

// AssignPoolQueueEntry hands the waiting run id to the idle runner
// executorID, held by member: in one transaction the run goes waiting →
// assigned and the runner idle → busy, or neither does. ok is false when
// either had moved on — another runner took the run, or this one was taken
// or retired — and the caller tries the next.
func (d *DB) AssignPoolQueueEntry(id, executorID, member string, at time.Time) (ok bool, err error) {
	return d.AssignPoolQueueEntryTo(id, executorID, member, at, PoolRunnerProject{})
}

// AssignPoolQueueEntryTo is AssignPoolQueueEntry for a run of project p
// (Task 20484): the runner is handed it only if its storage holds nothing or
// holds p's tenant — checked by the same UPDATE that claims the runner, so no
// reading of the runner beforehand can race it — and the runner records p, so
// the pool's controller learns each runner's project as it is handed one. A
// run whose tenant is unknown (p's zero value) goes to a runner holding
// nothing, never to one holding anybody's data.
func (d *DB) AssignPoolQueueEntryTo(id, executorID, member string, at time.Time, p PoolRunnerProject) (ok bool, err error) {
	if at.IsZero() {
		at = time.Now()
	}
	stamp := formatOptionalTime(at)
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: assign queued pool run: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	// A cordoned pool's runners are handed nothing (Task 20486): checked by
	// the UPDATE that claims the run, so a cordon cannot race the hand-off.
	res, err := tx.Exec(`UPDATE executor_pool_queue SET state = ?, executor_id = ?, member = ?, updated_at = ?, reason = '',
		attempts = attempts + 1
		WHERE id = ? AND state = ? AND NOT EXISTS (SELECT 1 FROM executor_pools p
		  WHERE p.id = executor_pool_queue.pool_id AND p.cordoned_at != '')`,
		PoolQueueAssigned, executorID, member, stamp, id, PoolQueueWaiting)
	if err != nil {
		return false, fmt.Errorf("statedb: assign queued pool run %q: %w", id, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	tenant := strings.TrimSpace(p.Tenant)
	res, err = tx.Exec(`UPDATE executor_pool_runners SET state = ?, queue_id = ?, busy_at = ?, member = ?,
		project = ?, project_name = ?, project_owner = ?
		WHERE executor_id = ? AND executor_id != '' AND state = ? AND (holds = '' OR holds = ?)`,
		PoolRunnerBusy, id, stamp, member, tenant, strings.TrimSpace(p.Name), strings.TrimSpace(p.Owner),
		executorID, PoolRunnerIdle, tenant)
	if err != nil {
		return false, fmt.Errorf("statedb: claim runner %q: %w", executorID, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: assign queued pool run %q: %w", id, classifyDriverErr(err))
	}
	return true, nil
}

// MovePoolQueueEntry moves a queued run from one of the states in from to
// to, recording reason, and reports whether it moved. The conditional move is
// what makes each hand-off happen once: of two members cancelling, or one
// cancelling while another dispatches, exactly one wins — and only the
// winner gives the run's concurrency slot back or hands it on.
func (d *DB) MovePoolQueueEntry(id string, from []string, to, reason string, at time.Time) (bool, error) {
	if len(from) == 0 {
		return false, errors.New("statedb: move queued pool run: no source state")
	}
	if at.IsZero() {
		at = time.Now()
	}
	args := []any{to, reason, formatOptionalTime(at), id}
	for _, s := range from {
		args = append(args, s)
	}
	return d.execOne(`UPDATE executor_pool_queue SET state = ?, reason = ?, updated_at = ?
		WHERE id = ? AND state IN (`+placeholders(len(from))+`)`,
		fmt.Sprintf("move queued pool run %s to %s", id, to), args...)
}

// NotePoolQueueReason updates a waiting run's reason, the sentence its
// project's readers see, without moving it.
func (d *DB) NotePoolQueueReason(id, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`UPDATE executor_pool_queue SET reason = ? WHERE id = ? AND state = ?`,
		reason, id, PoolQueueWaiting); err != nil {
		return fmt.Errorf("statedb: note queued pool run %q: %w", id, classifyDriverErr(err))
	}
	return nil
}

// PrunePoolQueue deletes closed queue rows and retired runner rows last
// changed before cutoff, and returns how many went.
func (d *DB) PrunePoolQueue(cutoff time.Time) (int, error) {
	stamp := formatOptionalTime(cutoff)
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM executor_pool_queue WHERE state NOT IN (?, ?) AND updated_at != '' AND updated_at < ?`,
		PoolQueueWaiting, PoolQueueAssigned, stamp)
	if err != nil {
		return 0, fmt.Errorf("statedb: prune queued pool runs: %w", classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	res, err = d.conn.Exec(`DELETE FROM executor_pool_runners WHERE state = ? AND retired_at != '' AND retired_at < ?`,
		PoolRunnerRetired, stamp)
	if err != nil {
		return int(n), fmt.Errorf("statedb: prune retired runners: %w", classifyDriverErr(err))
	}
	m, _ := res.RowsAffected()
	return int(n + m), nil
}

// BindProjectPool binds projectPath to a live executor pool.
func (d *DB) BindProjectPool(projectPath, poolID, boundBy string) error {
	if strings.TrimSpace(projectPath) == "" {
		return errors.New("statedb: project path is required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	pool, err := getExecutorPool(d.conn, poolID)
	if err != nil {
		return err
	}
	if pool.Revoked() {
		return fmt.Errorf("%w: %q", ErrExecutorPoolRevoked, poolID)
	}
	if _, err := d.conn.Exec(`INSERT INTO project_executors(project_path, executor_id, bound_at, bound_by)
		VALUES(?,?,?,?)
		ON CONFLICT(project_path) DO UPDATE SET
		  executor_id = excluded.executor_id, bound_at = excluded.bound_at, bound_by = excluded.bound_by`,
		projectPath, poolBindingValue(poolID), formatOptionalTime(time.Now()), boundBy); err != nil {
		return fmt.Errorf("statedb: bind project %q to executor pool %q: %w", projectPath, poolID, classifyDriverErr(err))
	}
	return nil
}

// poolBindingValue is executor.PoolBinding, spelled here so storage does not
// import the executor package.
func poolBindingValue(poolID string) string { return "pool:" + strings.TrimSpace(poolID) }

// ── controller status ──────────────────────────────────────────────────────

// PoolControllerStatusRow is the last health report one controller of a pool
// made (Task 20484): healthy, or the reason it cannot start runners — a
// volume stuck Pending, a full one — in a sentence for the people whose runs
// wait in the pool's queue.
type PoolControllerStatusRow struct {
	PoolID       string
	CredentialID string
	Healthy      bool
	Reason       string
	Message      string
	ReportedAt   time.Time
	// Storage is the controller's last count of its runners' volumes, a JSON
	// object its writer owns; "" for none (Task 20486).
	Storage string
}

// PutPoolControllerStatus records a controller's health report in place of
// its previous one.
func (d *DB) PutPoolControllerStatus(row PoolControllerStatusRow) error {
	if strings.TrimSpace(row.PoolID) == "" || strings.TrimSpace(row.CredentialID) == "" {
		return errors.New("statedb: a pool controller's report needs its pool and its credential")
	}
	if row.ReportedAt.IsZero() {
		row.ReportedAt = time.Now()
	}
	healthy := 0
	if row.Healthy {
		healthy = 1
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`INSERT INTO executor_pool_controller_status(pool_id, credential_id, healthy, reason,
		message, reported_at, storage_json) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(pool_id, credential_id) DO UPDATE SET
		  healthy = excluded.healthy, reason = excluded.reason, message = excluded.message,
		  reported_at = excluded.reported_at, storage_json = excluded.storage_json`,
		row.PoolID, row.CredentialID, healthy, row.Reason, row.Message, formatOptionalTime(row.ReportedAt),
		row.Storage); err != nil {
		return fmt.Errorf("statedb: record pool %q's controller report: %w", row.PoolID, classifyDriverErr(err))
	}
	return nil
}

// PoolControllerStatuses returns the last report of each of a pool's
// controllers, the newest first.
func (d *DB) PoolControllerStatuses(poolID string) ([]PoolControllerStatusRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT pool_id, credential_id, healthy, reason, message, reported_at, storage_json
		FROM executor_pool_controller_status WHERE pool_id = ? ORDER BY reported_at DESC, credential_id`,
		strings.TrimSpace(poolID))
	if err != nil {
		return nil, fmt.Errorf("statedb: read pool %q's controller reports: %w", poolID, classifyDriverErr(err))
	}
	defer rows.Close()
	var out []PoolControllerStatusRow
	for rows.Next() {
		var (
			r       PoolControllerStatusRow
			healthy int
			at      string
		)
		if err := rows.Scan(&r.PoolID, &r.CredentialID, &healthy, &r.Reason, &r.Message, &at, &r.Storage); err != nil {
			return nil, fmt.Errorf("statedb: scan a pool controller's report: %w", classifyDriverErr(err))
		}
		r.Healthy, r.ReportedAt = healthy != 0, parseOptionalTime(at)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read pool %q's controller reports: %w", poolID, classifyDriverErr(err))
	}
	return out, nil
}

// ── scanning ───────────────────────────────────────────────────────────────

// poolQuerier is what both the connection and a transaction offer: the reads
// above run inside the transactions that act on what they read.
type poolQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

// placeholders renders n comma-separated SQL placeholders.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

func scanExecutorPool(sc rowScanner) (ExecutorPoolRow, error) {
	var (
		row                                   ExecutorPoolRow
		labels                                string
		created, updated, revokedAt, cordoned string
	)
	if err := sc.Scan(&row.ID, &row.Name, &labels, &row.Capabilities, &row.MaxRunners, &row.Owner, &row.WorkDirRoot,
		&created, &row.CreatedBy, &updated, &row.UpdatedBy, &revokedAt, &row.RevokedBy,
		&cordoned, &row.CordonedBy, &row.CordonReason); err != nil {
		return ExecutorPoolRow{}, err
	}
	row.Labels = unmarshalLabelMap(labels)
	row.CreatedAt, row.UpdatedAt, row.RevokedAt = parseOptionalTime(created), parseOptionalTime(updated), parseOptionalTime(revokedAt)
	row.CordonedAt = parseOptionalTime(cordoned)
	return row, nil
}

func scanPoolCredential(sc rowScanner) (ExecutorPoolCredentialRow, error) {
	var (
		row                    ExecutorPoolCredentialRow
		created, used, revoked string
	)
	if err := sc.Scan(&row.ID, &row.PoolID, &row.SecretHash, &created, &row.CreatedBy, &used, &revoked, &row.RevokedBy,
		&row.ControllerVersion, &row.ControllerProtocol); err != nil {
		return ExecutorPoolCredentialRow{}, err
	}
	row.CreatedAt, row.LastUsedAt, row.RevokedAt = parseOptionalTime(created), parseOptionalTime(used), parseOptionalTime(revoked)
	return row, nil
}

func scanPoolRunner(sc rowScanner) (ExecutorPoolRunnerRow, error) {
	var (
		r                                    ExecutorPoolRunnerRow
		minted, expires, enrolled, busy, ret string
	)
	if err := sc.Scan(&r.EnrollmentID, &r.PoolID, &r.Name, &r.ExecutorID, &r.State, &r.Member, &r.QueueID,
		&minted, &expires, &enrolled, &busy, &ret, &r.RetireReason, &r.CredentialID,
		&r.Holds, &r.Project, &r.ProjectName, &r.ProjectOwner); err != nil {
		return ExecutorPoolRunnerRow{}, err
	}
	r.MintedAt, r.ExpiresAt, r.EnrolledAt = parseOptionalTime(minted), parseOptionalTime(expires), parseOptionalTime(enrolled)
	r.BusyAt, r.RetiredAt = parseOptionalTime(busy), parseOptionalTime(ret)
	return r, nil
}
