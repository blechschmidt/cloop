// Self-service secret grant requests (Task 20271).
//
// Rows for migrations/0037_secret_grant_requests.sql. The split is the same one
// broker.go describes: this file owns the SQL, pkg/secretstore converts between
// these rows and pkg/secretbroker's domain types, and pkg/secretbroker owns the
// lifecycle. A request names a secret; it never carries one, so — unlike
// broker_secrets — there is nothing sealed passing through here.

package statedb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// GrantRequestRow is one row of secret_grant_requests. Times are RFC3339
// strings and durations are whole seconds, matching the rest of the schema.
type GrantRequestRow struct {
	ID              string
	RequestedBy     string
	SecretID        string
	SecretName      string
	Kind            string
	SubjectType     string
	SubjectValue    string
	Scope           string
	ConstraintsJSON string
	TTLSeconds      int64
	Justification   string
	State           string
	CreatedAt       string
	ExpiresAt       string
	DecidedBy       string
	DecidedAt       string
	DecisionNote    string
	GrantID         string
	GrantExpiresAt  string
}

// GrantRequestUseRow is one row of secret_grant_request_uses: one lease that
// redeemed the grant an approval produced.
type GrantRequestUseRow struct {
	RequestID   string
	LeaseID     string
	GrantID     string
	ExecutorID  string
	ProjectPath string
	// TaskID is the unit of work that held the lease, or 0 when the dispatch
	// was run-scoped rather than task-scoped. See the migration's note: 0 means
	// "not attributed", never "no task ran".
	TaskID    int
	FirstSeen string
	LastSeen  string
}

// PutGrantRequest inserts or replaces a request by ID.
func (d *DB) PutGrantRequest(row GrantRequestRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return fmt.Errorf("statedb: grant request id is empty")
	}
	if strings.TrimSpace(row.SecretID) == "" {
		return fmt.Errorf("statedb: grant request %s has no secret id", row.ID)
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO secret_grant_requests(
		     id, requested_by, secret_id, secret_name, kind, subject_type, subject_value,
		     scope, constraints_json, ttl_seconds, justification, state, created_at,
		     expires_at, decided_by, decided_at, decision_note, grant_id, grant_expires_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   requested_by=excluded.requested_by, secret_id=excluded.secret_id,
		   secret_name=excluded.secret_name, kind=excluded.kind,
		   subject_type=excluded.subject_type, subject_value=excluded.subject_value,
		   scope=excluded.scope, constraints_json=excluded.constraints_json,
		   ttl_seconds=excluded.ttl_seconds, justification=excluded.justification,
		   state=excluded.state, created_at=excluded.created_at,
		   expires_at=excluded.expires_at, decided_by=excluded.decided_by,
		   decided_at=excluded.decided_at, decision_note=excluded.decision_note,
		   grant_id=excluded.grant_id, grant_expires_at=excluded.grant_expires_at`,
		row.ID, row.RequestedBy, row.SecretID, row.SecretName, row.Kind,
		row.SubjectType, row.SubjectValue, row.Scope, defaultJSON(row.ConstraintsJSON),
		row.TTLSeconds, row.Justification, defaultString(row.State, "pending"),
		row.CreatedAt, row.ExpiresAt, row.DecidedBy, row.DecidedAt,
		row.DecisionNote, row.GrantID, row.GrantExpiresAt,
	); err != nil {
		return fmt.Errorf("statedb: put grant request %s: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

const grantRequestColumns = `id, requested_by, secret_id, secret_name, kind,
	subject_type, subject_value, scope, constraints_json, ttl_seconds,
	justification, state, created_at, expires_at, decided_by, decided_at,
	decision_note, grant_id, grant_expires_at`

func scanGrantRequest(sc interface{ Scan(...any) error }) (GrantRequestRow, error) {
	var row GrantRequestRow
	err := sc.Scan(&row.ID, &row.RequestedBy, &row.SecretID, &row.SecretName, &row.Kind,
		&row.SubjectType, &row.SubjectValue, &row.Scope, &row.ConstraintsJSON,
		&row.TTLSeconds, &row.Justification, &row.State, &row.CreatedAt, &row.ExpiresAt,
		&row.DecidedBy, &row.DecidedAt, &row.DecisionNote, &row.GrantID, &row.GrantExpiresAt)
	return row, err
}

// GetGrantRequest returns one request by ID.
func (d *DB) GetGrantRequest(id string) (GrantRequestRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	row, err := scanGrantRequest(d.conn.QueryRow(
		`SELECT `+grantRequestColumns+` FROM secret_grant_requests WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return GrantRequestRow{}, fmt.Errorf("%w: grant request %q", ErrGrantRequestNotFound, id)
	}
	if err != nil {
		return GrantRequestRow{}, fmt.Errorf("statedb: get grant request %s: %w", id, classifyDriverErr(err))
	}
	return row, nil
}

// ListGrantRequests returns every request, newest first.
//
// Unfiltered, for the same reason ListBrokerGrants is: deciding which requests
// a caller may see is an authorisation question, and a store that pre-filtered
// would make "show me everything that was ever asked for" — the review
// question — unanswerable.
func (d *DB) ListGrantRequests() ([]GrantRequestRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT ` + grantRequestColumns + ` FROM secret_grant_requests
		 ORDER BY created_at DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list grant requests: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []GrantRequestRow
	for rows.Next() {
		row, serr := scanGrantRequest(rows)
		if serr != nil {
			return nil, fmt.Errorf("statedb: scan grant request: %w", classifyDriverErr(serr))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list grant requests: %w", classifyDriverErr(err))
	}
	return out, nil
}

// PutGrantRequestUse records that a lease redeemed an approved request's grant.
//
// Upsert on (request_id, lease_id): a lease is leased once and then renewed
// every few minutes, and each renewal should move last_seen rather than add a
// row. first_seen is preserved by the conflict clause for the same reason
// RevokeBrokerGrant refuses to move a revocation timestamp — when a credential
// first came into use is a fact, and a renewal must not rewrite it.
func (d *DB) PutGrantRequestUse(row GrantRequestUseRow) error {
	if strings.TrimSpace(row.RequestID) == "" || strings.TrimSpace(row.LeaseID) == "" {
		return fmt.Errorf("statedb: grant request use needs a request id and a lease id")
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO secret_grant_request_uses(
		     request_id, lease_id, grant_id, executor_id, project_path, task_id,
		     first_seen, last_seen)
		 VALUES (?,?,?,?,?,?,?,?)
		 ON CONFLICT(request_id, lease_id) DO UPDATE SET
		   grant_id=excluded.grant_id,
		   executor_id=excluded.executor_id,
		   project_path=excluded.project_path,
		   -- A later observation must not blank an attribution already made:
		   -- the lease path writes 0 because it runs before dispatch, and the
		   -- task is stamped in afterwards by AttributeRequestUseTasks.
		   task_id=CASE WHEN excluded.task_id != 0 THEN excluded.task_id ELSE task_id END,
		   last_seen=excluded.last_seen`,
		row.RequestID, row.LeaseID, row.GrantID, row.ExecutorID, row.ProjectPath,
		row.TaskID, row.FirstSeen, defaultString(row.LastSeen, row.FirstSeen),
	); err != nil {
		return fmt.Errorf("statedb: put grant request use %s/%s: %w",
			row.RequestID, row.LeaseID, classifyDriverErr(err))
	}
	return nil
}

// ListGrantRequestUses returns the leases recorded against one request, or —
// when requestID is empty — every recorded use.
func (d *DB) ListGrantRequestUses(requestID string) ([]GrantRequestUseRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `SELECT request_id, lease_id, grant_id, executor_id, project_path,
	                 task_id, first_seen, last_seen
	          FROM secret_grant_request_uses`
	args := []any{}
	if strings.TrimSpace(requestID) != "" {
		query += ` WHERE request_id = ?`
		args = append(args, requestID)
	}
	query += ` ORDER BY first_seen ASC, lease_id ASC`

	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list grant request uses: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []GrantRequestUseRow
	for rows.Next() {
		var row GrantRequestUseRow
		if err := rows.Scan(&row.RequestID, &row.LeaseID, &row.GrantID, &row.ExecutorID,
			&row.ProjectPath, &row.TaskID, &row.FirstSeen, &row.LastSeen); err != nil {
			return nil, fmt.Errorf("statedb: scan grant request use: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list grant request uses: %w", classifyDriverErr(err))
	}
	return out, nil
}

// AttributeRequestUseTasks stamps the task a recorded lease was dispatched for
// onto the use rows that do not have one yet, and reports how many it filled in.
//
// It exists because a lease is issued *before* the workload that will hold it is
// dispatched. At lease time the broker knows the executor and the project and
// genuinely does not know the task — there is no task yet — so the use row
// starts with task_id 0 and the answer arrives a moment later, when the driver
// writes an executor_handles row carrying both the task and the lease bindings
// that workload was started with.
//
// Reconciling the two afterwards is therefore the only way to get the
// attribution at all, and it has to happen while the handle is still live:
// handle rows are deleted when the workload reaches a terminal state, so a
// reconciliation that only ran on demand would report nothing for exactly the
// runs that have finished — which are the ones an approver reviews. Callers run
// it on the same schedule they sweep expired requests, and again when listing.
//
// Idempotent and monotonic: it only fills in zeros (the UPDATE's guard, and
// PutGrantRequestUse's) so a handle that has since been reused for other work
// cannot rewrite an attribution already made.
func (d *DB) AttributeRequestUseTasks() (int, error) {
	uses, err := d.ListGrantRequestUses("")
	if err != nil {
		return 0, err
	}
	pending := make(map[string]bool) // lease IDs still lacking a task
	for _, u := range uses {
		if u.TaskID == 0 {
			pending[u.LeaseID] = true
		}
	}
	if len(pending) == 0 {
		return 0, nil
	}

	handles, err := d.ListExecutorHandles("")
	if err != nil {
		return 0, err
	}

	// lease ID -> task ID, from the bindings each dispatched workload recorded.
	found := make(map[string]int)
	for _, h := range handles {
		if h.TaskID == 0 || strings.TrimSpace(h.SecretsJSON) == "" {
			continue
		}
		var bindings []struct {
			LeaseID string `json:"lease_id"`
		}
		if jerr := json.Unmarshal([]byte(h.SecretsJSON), &bindings); jerr != nil {
			// A handle whose bindings do not decode is a handle this build
			// cannot attribute. Skipping it leaves the use row unattributed,
			// which reads as "not known" — the honest answer — rather than
			// failing the whole sweep for one malformed row.
			continue
		}
		for _, b := range bindings {
			if pending[b.LeaseID] {
				found[b.LeaseID] = h.TaskID
			}
		}
	}
	if len(found) == 0 {
		return 0, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	filled := 0
	for leaseID, taskID := range found {
		res, uerr := d.conn.Exec(
			`UPDATE secret_grant_request_uses SET task_id = ?
			 WHERE lease_id = ? AND task_id = 0`, taskID, leaseID)
		if uerr != nil {
			return filled, fmt.Errorf("statedb: attribute lease %s: %w", leaseID, classifyDriverErr(uerr))
		}
		if n, aerr := res.RowsAffected(); aerr == nil {
			filled += int(n)
		}
	}
	return filled, nil
}

// ExpireGrantRequests moves every pending request whose deadline has passed to
// the expired state, and returns the rows it changed.
//
// Returning the rows rather than a count is what lets the caller emit one audit
// event per expiry. A request that lapses is a decision — nobody made one, and
// access was refused as a result — and the trail should say so with the same
// weight as a deny, so the requester can see why nothing happened.
//
// Requests with no deadline (expires_at = ”) are left alone: the broker always
// sets one, and a row from some future path that deliberately has none should
// not be swept by a rule it never opted into.
func (d *DB) ExpireGrantRequests(now time.Time) ([]GrantRequestRow, error) {
	stamp := now.UTC().Format(time.RFC3339Nano)

	d.mu.Lock()
	rows, err := d.conn.Query(
		`SELECT `+grantRequestColumns+` FROM secret_grant_requests
		 WHERE state = 'pending' AND expires_at != '' AND expires_at <= ?
		 ORDER BY created_at ASC`, stamp)
	if err != nil {
		d.mu.Unlock()
		return nil, fmt.Errorf("statedb: find expired grant requests: %w", classifyDriverErr(err))
	}
	var lapsed []GrantRequestRow
	for rows.Next() {
		row, serr := scanGrantRequest(rows)
		if serr != nil {
			rows.Close()
			d.mu.Unlock()
			return nil, fmt.Errorf("statedb: scan expired grant request: %w", classifyDriverErr(serr))
		}
		lapsed = append(lapsed, row)
	}
	rerr := rows.Err()
	rows.Close()
	if rerr != nil {
		d.mu.Unlock()
		return nil, fmt.Errorf("statedb: find expired grant requests: %w", classifyDriverErr(rerr))
	}
	if len(lapsed) == 0 {
		d.mu.Unlock()
		return nil, nil
	}

	// The UPDATE re-states the pending predicate so a decision that landed
	// between the SELECT and here wins. An approval racing an expiry sweep must
	// not be silently undone — the credential it minted would already exist.
	for i := range lapsed {
		res, uerr := d.conn.Exec(
			`UPDATE secret_grant_requests SET state = 'expired', decided_at = ?
			 WHERE id = ? AND state = 'pending'`, stamp, lapsed[i].ID)
		if uerr != nil {
			d.mu.Unlock()
			return nil, fmt.Errorf("statedb: expire grant request %s: %w",
				lapsed[i].ID, classifyDriverErr(uerr))
		}
		if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
			lapsed[i].ID = "" // decided underneath us; drop from the report
			continue
		}
		lapsed[i].State = "expired"
		lapsed[i].DecidedAt = stamp
	}
	d.mu.Unlock()

	out := lapsed[:0]
	for _, row := range lapsed {
		if row.ID != "" {
			out = append(out, row)
		}
	}
	return out, nil
}
