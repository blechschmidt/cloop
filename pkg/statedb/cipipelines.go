// CI/CD pipeline federation persistence (Task 20278).
//
// The rows behind the Settings page's CI/CD panel and the /api/ci/token
// exchange. This file owns the SQL and the wire-shaped row types; pkg/ciauth
// owns token verification, rule validation and matching. The split is the same
// one this package draws over api tokens and broker secrets, and for the same
// reason: the package holding the security decision should not also hold a
// driver.
//
// Nothing here validates a rule. A row read back is handed to pkg/ciauth to
// prepare, and a row that no longer prepares becomes inert and is reported —
// see ciauth.NewRuleSet. A second opinion about what a valid rule looks like is
// how the two drift apart, and the direction they would drift is "this layer
// admits something the validator would have refused".

package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CIPipelineRuleRow is one persisted allowlist entry.
type CIPipelineRuleRow struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	Repository  string `json:"repository,omitempty"`
	Ref         string `json:"ref,omitempty"`
	Workflow    string `json:"workflow,omitempty"`
	Environment string `json:"environment,omitempty"`
	Actor       string `json:"actor,omitempty"`
	EventName   string `json:"event_name,omitempty"`
	Condition   string `json:"condition,omitempty"`

	Models          []string `json:"models,omitempty"`
	MaxRequests     int      `json:"max_requests,omitempty"`
	MaxOutputTokens int      `json:"max_output_tokens,omitempty"`
	TTLSeconds      int      `json:"ttl_seconds,omitempty"`

	Project       string    `json:"project,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
	LastMatchedAt time.Time `json:"last_matched_at,omitempty"`
}

const ciPipelineRuleColumns = `id, name, enabled, repository, ref, workflow,
	environment, actor, event_name, condition, models_json, max_requests,
	max_output_tokens, ttl_seconds, project, created_by, created_at,
	updated_at, last_matched_at`

// PutCIPipelineRule inserts or replaces a rule.
//
// Unlike PutAPIToken this is an upsert, because a rule is a policy an operator
// edits rather than a credential in circulation: rewriting one is the intended
// operation, and the row carries no secret whose replacement could go
// unnoticed. What editing a rule must *also* do — revoke the sessions already
// minted under it — is the caller's job, because this layer does not know the
// live registry exists.
func (d *DB) PutCIPipelineRule(row CIPipelineRuleRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: ci pipeline rule id is required")
	}
	models, err := marshalStringSlice(row.Models)
	if err != nil {
		return fmt.Errorf("statedb: encode ci rule models: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err = d.conn.Exec(`INSERT INTO ci_pipeline_rules (`+ciPipelineRuleColumns+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name,
			enabled=excluded.enabled,
			repository=excluded.repository,
			ref=excluded.ref,
			workflow=excluded.workflow,
			environment=excluded.environment,
			actor=excluded.actor,
			event_name=excluded.event_name,
			condition=excluded.condition,
			models_json=excluded.models_json,
			max_requests=excluded.max_requests,
			max_output_tokens=excluded.max_output_tokens,
			ttl_seconds=excluded.ttl_seconds,
			project=excluded.project,
			updated_at=excluded.updated_at`,
		row.ID, row.Name, boolToInt(row.Enabled), row.Repository, row.Ref, row.Workflow,
		row.Environment, row.Actor, row.EventName, row.Condition, models,
		row.MaxRequests, row.MaxOutputTokens, row.TTLSeconds, row.Project,
		row.CreatedBy, formatTimeRFC(row.CreatedAt), formatTimeRFC(row.UpdatedAt),
		formatTimeRFC(row.LastMatchedAt))
	if err != nil {
		return wrap(classifyDriverErr(err), fmt.Errorf("put ci pipeline rule %s: %w", row.ID, err))
	}
	return nil
}

// GetCIPipelineRule returns one rule by ID.
func (d *DB) GetCIPipelineRule(id string) (CIPipelineRuleRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	row := d.conn.QueryRow(`SELECT `+ciPipelineRuleColumns+
		` FROM ci_pipeline_rules WHERE id = ?`, id)
	out, err := scanCIPipelineRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CIPipelineRuleRow{}, wrap(ErrCIPipelineRuleNotFound,
			fmt.Errorf("ci pipeline rule %s", id))
	}
	if err != nil {
		return CIPipelineRuleRow{}, wrap(classifyDriverErr(err),
			fmt.Errorf("get ci pipeline rule %s: %w", id, err))
	}
	return out, nil
}

// ListCIPipelineRules returns every rule in evaluation order: oldest first,
// then by ID.
//
// The order is the matching order, and it is stable across restarts on
// purpose. "First match wins" is only a meaningful rule if two hubs reading
// the same table agree about which rule is first.
func (d *DB) ListCIPipelineRules() ([]CIPipelineRuleRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`SELECT ` + ciPipelineRuleColumns +
		` FROM ci_pipeline_rules ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, wrap(classifyDriverErr(err), fmt.Errorf("list ci pipeline rules: %w", err))
	}
	defer rows.Close() //nolint:errcheck // read-only

	var out []CIPipelineRuleRow
	for rows.Next() {
		r, err := scanCIPipelineRule(rows)
		if err != nil {
			return nil, wrap(classifyDriverErr(err), fmt.Errorf("scan ci pipeline rule: %w", err))
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, wrap(classifyDriverErr(err), fmt.Errorf("list ci pipeline rules: %w", err))
	}
	return out, nil
}

// DeleteCIPipelineRule removes a rule. It reports whether a row was removed,
// so the caller can tell "deleted" from "already gone" without a prior read.
func (d *DB) DeleteCIPipelineRule(id string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.conn.Exec(`DELETE FROM ci_pipeline_rules WHERE id = ?`, id)
	if err != nil {
		return false, wrap(classifyDriverErr(err), fmt.Errorf("delete ci pipeline rule %s: %w", id, err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, wrap(classifyDriverErr(err), fmt.Errorf("delete ci pipeline rule %s: %w", id, err))
	}
	return n > 0, nil
}

// TouchCIPipelineRule stamps a rule as having admitted a pipeline.
//
// Failures are the caller's to ignore: last_matched_at is advisory, and a
// federation that succeeded must not be reported as failed because a
// bookkeeping write lost a race with a delete.
func (d *DB) TouchCIPipelineRule(id string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`UPDATE ci_pipeline_rules SET last_matched_at = ? WHERE id = ?`,
		formatTimeRFC(at), id)
	if err != nil {
		return wrap(classifyDriverErr(err), fmt.Errorf("touch ci pipeline rule %s: %w", id, err))
	}
	return nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type ciRowScanner interface {
	Scan(dest ...any) error
}

func scanCIPipelineRule(s ciRowScanner) (CIPipelineRuleRow, error) {
	var (
		r          CIPipelineRuleRow
		enabled    int
		modelsJSON string
		created    string
		updated    string
		matched    string
	)
	if err := s.Scan(&r.ID, &r.Name, &enabled, &r.Repository, &r.Ref, &r.Workflow,
		&r.Environment, &r.Actor, &r.EventName, &r.Condition, &modelsJSON,
		&r.MaxRequests, &r.MaxOutputTokens, &r.TTLSeconds, &r.Project,
		&r.CreatedBy, &created, &updated, &matched); err != nil {
		return r, err
	}
	r.Enabled = enabled != 0
	// A models column that will not decode does not fail the read: the rule
	// is still shown, with no model allowlist, which pkg/ciauth then refuses
	// to mint from. Failing the whole list instead would take every rule
	// offline because one row was hand-edited.
	r.Models = unmarshalStringSlice(modelsJSON)
	r.CreatedAt = parseOptionalTime(created)
	r.UpdatedAt = parseOptionalTime(updated)
	r.LastMatchedAt = parseOptionalTime(matched)
	return r, nil
}

// CIExchangeRow is one recorded federation attempt.
type CIExchangeRow struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Accepted   bool      `json:"accepted"`
	Issuer     string    `json:"issuer,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Repository string    `json:"repository,omitempty"`
	Ref        string    `json:"ref,omitempty"`
	Workflow   string    `json:"workflow,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	EventName  string    `json:"event_name,omitempty"`
	RunID      string    `json:"run_id,omitempty"`
	RuleID     string    `json:"rule_id,omitempty"`
	RuleName   string    `json:"rule_name,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`

	// Reason is a stable code; Detail is the human-readable explanation. The
	// pair exists so a dashboard can group by cause while still showing the
	// sentence that names the actual problem.
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`

	RemoteAddr string `json:"remote_addr,omitempty"`

	// Claims is the verified payload, or nil on a token that never verified.
	Claims map[string]any `json:"claims,omitempty"`
}

const ciExchangeColumns = `id, at, accepted, issuer, subject, repository, ref,
	workflow, actor, event_name, run_id, rule_id, rule_name, session_id,
	reason, detail, remote_addr, claims_json`

// PutCIExchange records a federation attempt.
func (d *DB) PutCIExchange(row CIExchangeRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: ci exchange id is required")
	}
	claims := ""
	if len(row.Claims) > 0 {
		b, err := json.Marshal(row.Claims)
		if err != nil {
			// An unencodable claim set must not lose the whole row: the
			// refusal reason is the part an operator needs.
			claims = ""
		} else {
			claims = string(b)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`INSERT OR REPLACE INTO ci_exchanges (`+ciExchangeColumns+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, formatTimeRFC(row.At), boolToInt(row.Accepted), row.Issuer, row.Subject,
		row.Repository, row.Ref, row.Workflow, row.Actor, row.EventName, row.RunID,
		row.RuleID, row.RuleName, row.SessionID, row.Reason, row.Detail,
		row.RemoteAddr, claims)
	if err != nil {
		return wrap(classifyDriverErr(err), fmt.Errorf("put ci exchange %s: %w", row.ID, err))
	}
	return nil
}

// ListCIExchanges returns the most recent exchanges, newest first.
func (d *DB) ListCIExchanges(limit int) ([]CIExchangeRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`SELECT `+ciExchangeColumns+
		` FROM ci_exchanges ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, wrap(classifyDriverErr(err), fmt.Errorf("list ci exchanges: %w", err))
	}
	defer rows.Close() //nolint:errcheck // read-only

	var out []CIExchangeRow
	for rows.Next() {
		var (
			r          CIExchangeRow
			at         string
			accepted   int
			claimsJSON string
		)
		if err := rows.Scan(&r.ID, &at, &accepted, &r.Issuer, &r.Subject, &r.Repository,
			&r.Ref, &r.Workflow, &r.Actor, &r.EventName, &r.RunID, &r.RuleID,
			&r.RuleName, &r.SessionID, &r.Reason, &r.Detail, &r.RemoteAddr,
			&claimsJSON); err != nil {
			return nil, wrap(classifyDriverErr(err), fmt.Errorf("scan ci exchange: %w", err))
		}
		r.At = parseOptionalTime(at)
		r.Accepted = accepted != 0
		if claimsJSON != "" {
			if err := json.Unmarshal([]byte(claimsJSON), &r.Claims); err != nil {
				r.Claims = nil
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, wrap(classifyDriverErr(err), fmt.Errorf("list ci exchanges: %w", err))
	}
	return out, nil
}

// PruneCIExchanges keeps the newest keep rows and deletes the rest.
//
// The exchange log is a debugging surface, not the audit trail, so it is
// bounded by count rather than by age: an operator debugging a pipeline wants
// the last N attempts, and a hub nobody has federated against in a month
// should still be able to show the exchange that failed.
func (d *DB) PruneCIExchanges(keep int) (int, error) {
	if keep < 0 {
		keep = 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.conn.Exec(`DELETE FROM ci_exchanges WHERE id NOT IN (
		SELECT id FROM ci_exchanges ORDER BY at DESC LIMIT ?)`, keep)
	if err != nil {
		return 0, wrap(classifyDriverErr(err), fmt.Errorf("prune ci exchanges: %w", err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrap(classifyDriverErr(err), fmt.Errorf("prune ci exchanges: %w", err))
	}
	return int(n), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
