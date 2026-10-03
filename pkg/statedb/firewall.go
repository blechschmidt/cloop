// firewall.go stores the two dashboard-set levels of the IP-layer egress
// firewall: one rule set per device, and one per project (Task 20363).
//
// See migrations/0055_egress_firewall_rules.sql for the tables and
// pkg/fwpolicy for the rule that the project's set, and every virtual
// executor's firewall, fit inside the device's. This file only stores; the
// containment decision is made by the caller, inside UpdateFirewalls when the
// write depends on what it read.
package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
)

// FirewallRecord is one stored rule set plus its provenance.
type FirewallRecord struct {
	// Subject is the executor ID or the project path the rules are keyed by.
	Subject     string                 `json:"subject"`
	Rules       executor.FirewallRules `json:"rules"`
	Fingerprint string                 `json:"fingerprint"`
	SetAt       time.Time              `json:"set_at,omitempty"`
	SetBy       string                 `json:"set_by,omitempty"`
}

// firewallTable names one of the two tables and its key column.
type firewallTable struct{ table, key string }

var (
	executorFirewalls = firewallTable{"executor_firewall_rules", "executor_id"}
	projectFirewalls  = firewallTable{"project_firewall_rules", "project_path"}
)

// sqlQueryer is what both *sql.DB and *sql.Tx offer, so the reads below serve
// the plain accessors and the serialized transaction alike.
type sqlQueryer interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

// encodeFirewall normalizes and validates rules before they become durable.
//
// Validated here as well as at the HTTP boundary because this is the last point
// before the value is stored: a rule set that will not parse back is one the
// dispatch path must refuse every run over, which is safe but is an outage an
// admin caused by typing.
func encodeFirewall(subject string, r executor.FirewallRules) (string, string, error) {
	if strings.TrimSpace(subject) == "" {
		return "", "", errors.New("statedb: a firewall rule set needs a subject")
	}
	n, err := r.Normalize()
	if err != nil {
		return "", "", fmt.Errorf("statedb: firewall rules for %q: %w", subject, err)
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return "", "", fmt.Errorf("statedb: encode firewall rules for %q: %w", subject, err)
	}
	return string(raw), fwpolicy.Fingerprint(n), nil
}

func (t firewallTable) set(q sqlQueryer, subject string, r executor.FirewallRules, setBy string) error {
	raw, fp, err := encodeFirewall(subject, r)
	if err != nil {
		return err
	}
	_, err = q.Exec(`INSERT INTO `+t.table+`(`+t.key+`, rules, fingerprint, set_at, set_by)
		VALUES(?,?,?,?,?)
		ON CONFLICT(`+t.key+`) DO UPDATE SET
		  rules       = excluded.rules,
		  fingerprint = excluded.fingerprint,
		  set_at      = excluded.set_at,
		  set_by      = excluded.set_by`,
		strings.TrimSpace(subject), raw, fp, time.Now().UTC().Format(time.RFC3339Nano), setBy)
	if err != nil {
		return fmt.Errorf("statedb: set firewall rules for %q: %w", subject, classifyDriverErr(err))
	}
	return nil
}

func (t firewallTable) clear(q sqlQueryer, subject string) error {
	if _, err := q.Exec(`DELETE FROM `+t.table+` WHERE `+t.key+` = ?`, strings.TrimSpace(subject)); err != nil {
		return fmt.Errorf("statedb: clear firewall rules for %q: %w", subject, classifyDriverErr(err))
	}
	return nil
}

// get reads one rule set. The boolean is false when the subject has none.
//
// A row that does not decode is an error, never "absent". The callers read
// "absent" as "this level adds no narrowing", so a decode fault that became
// absence would widen a firewall exactly when the database is least healthy.
func (t firewallTable) get(q sqlQueryer, subject string) (FirewallRecord, bool, error) {
	rec := FirewallRecord{Subject: strings.TrimSpace(subject)}
	var raw, setAt string
	err := q.QueryRow(`SELECT rules, fingerprint, set_at, set_by FROM `+t.table+` WHERE `+t.key+` = ?`,
		rec.Subject).Scan(&raw, &rec.Fingerprint, &setAt, &rec.SetBy)
	if errors.Is(err, sql.ErrNoRows) {
		return FirewallRecord{}, false, nil
	}
	if err != nil {
		return FirewallRecord{}, false, fmt.Errorf("statedb: read firewall rules for %q: %w",
			subject, classifyDriverErr(err))
	}
	if rec.Rules, err = decodeFirewall(raw); err != nil {
		return FirewallRecord{}, false, fmt.Errorf("statedb: the firewall rules stored for %q are "+
			"unreadable: %w", subject, err)
	}
	rec.SetAt = parseOptionalTime(setAt)
	return rec, true, nil
}

func decodeFirewall(raw string) (executor.FirewallRules, error) {
	var r executor.FirewallRules
	dec := json.NewDecoder(strings.NewReader(raw))
	// Strict, because an unknown key is a rule this binary would silently
	// ignore — a newer build's field that narrows, read back as absent.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return executor.FirewallRules{}, err
	}
	return r.Normalize()
}

// list reads every rule set, newest first. A row that does not decode is an
// error for the whole list, for the reason get gives.
func (t firewallTable) list(q sqlQueryer) ([]FirewallRecord, error) {
	rows, err := q.Query(`SELECT ` + t.key + `, rules, fingerprint, set_at, set_by FROM ` + t.table +
		` ORDER BY set_at DESC, ` + t.key + ` ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list %s: %w", t.table, classifyDriverErr(err))
	}
	defer rows.Close()
	var out []FirewallRecord
	for rows.Next() {
		var rec FirewallRecord
		var raw, setAt string
		if err := rows.Scan(&rec.Subject, &raw, &rec.Fingerprint, &setAt, &rec.SetBy); err != nil {
			return nil, fmt.Errorf("statedb: scan %s: %w", t.table, classifyDriverErr(err))
		}
		if rec.Rules, err = decodeFirewall(raw); err != nil {
			return nil, fmt.Errorf("statedb: the firewall rules stored for %q are unreadable: %w", rec.Subject, err)
		}
		rec.SetAt = parseOptionalTime(setAt)
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list %s: %w", t.table, classifyDriverErr(err))
	}
	return out, nil
}

// ExecutorFirewall returns the device-level rule set stored for executorID.
func (d *DB) ExecutorFirewall(executorID string) (FirewallRecord, bool, error) {
	return executorFirewalls.get(d.conn, executorID)
}

// ProjectFirewall returns the rule set stored for the project at projectPath.
func (d *DB) ProjectFirewall(projectPath string) (FirewallRecord, bool, error) {
	return projectFirewalls.get(d.conn, projectPath)
}

// ListExecutorFirewalls returns every device-level rule set, newest first.
func (d *DB) ListExecutorFirewalls() ([]FirewallRecord, error) { return executorFirewalls.list(d.conn) }

// ListProjectFirewalls returns every project rule set, newest first.
func (d *DB) ListProjectFirewalls() ([]FirewallRecord, error) { return projectFirewalls.list(d.conn) }

// SetExecutorFirewall stores executorID's rule set, replacing any previous one.
// An empty rule set is stored, not refused: it means "reach nothing", the
// strongest thing a firewall can say. ClearExecutorFirewall removes the level.
//
// It does not check containment or constrain anything underneath; callers whose
// write depends on what they read use UpdateFirewalls.
func (d *DB) SetExecutorFirewall(executorID string, r executor.FirewallRules, setBy string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return executorFirewalls.set(d.conn, executorID, r, setBy)
}

// ClearExecutorFirewall removes executorID's rule set. Clearing an absent one is
// not an error.
func (d *DB) ClearExecutorFirewall(executorID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return executorFirewalls.clear(d.conn, executorID)
}

// SetProjectFirewall stores the project's rule set, replacing any previous one.
func (d *DB) SetProjectFirewall(projectPath string, r executor.FirewallRules, setBy string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return projectFirewalls.set(d.conn, projectPath, r, setBy)
}

// ClearProjectFirewall removes the project's rule set.
func (d *DB) ClearProjectFirewall(projectPath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return projectFirewalls.clear(d.conn, projectPath)
}

// FirewallTx is one serialized read-modify-write over everything the firewall's
// levels are stored in: the two rule tables, virtual executor definitions and
// project bindings.
//
// It exists for the saves whose correctness depends on what they read. A
// project's rule set is checked against its device's, and a device tightening
// rewrites the rule sets saved underneath it; done as separate statements, an
// admin narrowing a device and a maintainer saving a project at the same moment
// could each check against the other's old value and both commit, leaving a
// project outside its device until the next dispatch refused it. Inside one
// IMMEDIATE transaction the two serialize — across hub processes too, since the
// write lock is the database's.
type FirewallTx struct {
	tx *sql.Tx
}

// UpdateFirewalls runs fn inside one write transaction, committing when it
// returns nil and rolling back otherwise.
func (d *DB) UpdateFirewalls(fn func(*FirewallTx) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: firewall update: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck — no-op once Commit succeeds
	if err := fn(&FirewallTx{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: firewall update: commit: %w", classifyDriverErr(err))
	}
	return nil
}

// ExecutorFirewall reads a device's rule set inside the transaction.
func (t *FirewallTx) ExecutorFirewall(executorID string) (FirewallRecord, bool, error) {
	return executorFirewalls.get(t.tx, executorID)
}

// SetExecutorFirewall writes a device's rule set inside the transaction.
func (t *FirewallTx) SetExecutorFirewall(executorID string, r executor.FirewallRules, setBy string) error {
	return executorFirewalls.set(t.tx, executorID, r, setBy)
}

// ClearExecutorFirewall removes a device's rule set inside the transaction.
func (t *FirewallTx) ClearExecutorFirewall(executorID string) error {
	return executorFirewalls.clear(t.tx, executorID)
}

// ProjectFirewall reads a project's rule set inside the transaction.
func (t *FirewallTx) ProjectFirewall(projectPath string) (FirewallRecord, bool, error) {
	return projectFirewalls.get(t.tx, projectPath)
}

// SetProjectFirewall writes a project's rule set inside the transaction.
func (t *FirewallTx) SetProjectFirewall(projectPath string, r executor.FirewallRules, setBy string) error {
	return projectFirewalls.set(t.tx, projectPath, r, setBy)
}

// ClearProjectFirewall removes a project's rule set inside the transaction.
func (t *FirewallTx) ClearProjectFirewall(projectPath string) error {
	return projectFirewalls.clear(t.tx, projectPath)
}

// ListProjectFirewalls reads every project rule set inside the transaction.
func (t *FirewallTx) ListProjectFirewalls() ([]FirewallRecord, error) {
	return projectFirewalls.list(t.tx)
}

// VirtualExecutor reads one virtual executor inside the transaction.
func (t *FirewallTx) VirtualExecutor(id string) (VirtualExecutor, bool, error) {
	rows, err := queryVirtualExecutorsOn(t.tx, `WHERE id = ?`, strings.TrimSpace(id))
	if err != nil || len(rows) == 0 {
		return VirtualExecutor{}, false, err
	}
	return rows[0], true, nil
}

// VirtualExecutorsOf reads every virtual executor of one device inside the
// transaction.
func (t *FirewallTx) VirtualExecutorsOf(parentID string) ([]VirtualExecutor, error) {
	return queryVirtualExecutorsOn(t.tx, `WHERE parent_id = ? ORDER BY name, id`, strings.TrimSpace(parentID))
}

// SetVirtualExecutorSpec replaces one virtual executor's configuration inside
// the transaction, keeping its name.
func (t *FirewallTx) SetVirtualExecutorSpec(id string, spec executor.VirtualSpec, by string) error {
	cur, ok, err := t.VirtualExecutor(id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %q", ErrVirtualExecutorNotFound, id)
	}
	cur.Spec = spec
	return updateVirtualExecutorOn(t.tx, cur, by)
}

// CreateVirtualExecutor records a new virtual executor inside the transaction,
// so a save checked against its device's rule set commits only if that rule set
// is still the one it was checked against.
func (t *FirewallTx) CreateVirtualExecutor(v VirtualExecutor) error {
	return createVirtualExecutorOn(t.tx, v)
}

// UpdateVirtualExecutor replaces a virtual executor's name and configuration
// inside the transaction.
func (t *FirewallTx) UpdateVirtualExecutor(id, name string, spec executor.VirtualSpec, by string) error {
	cur, ok, err := t.VirtualExecutor(id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %q", ErrVirtualExecutorNotFound, id)
	}
	cur.Name, cur.Spec = name, spec
	return updateVirtualExecutorOn(t.tx, cur, by)
}

// ProjectExecutor reads a project's executor binding inside the transaction.
func (t *FirewallTx) ProjectExecutor(projectPath string) (string, bool, error) {
	var id string
	err := t.tx.QueryRow(`SELECT executor_id FROM project_executors WHERE project_path = ?`,
		projectPath).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("statedb: project executor for %q: %w", projectPath, classifyDriverErr(err))
	}
	return id, true, nil
}

// ProjectsBoundTo returns the paths of the projects pinned to any of ids, in
// path order.
func (t *FirewallTx) ProjectsBoundTo(ids ...string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := t.tx.Query(`SELECT project_path FROM project_executors WHERE executor_id IN (`+marks+
		`) ORDER BY project_path`, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: read project bindings: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("statedb: read project bindings: %w", classifyDriverErr(err))
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
