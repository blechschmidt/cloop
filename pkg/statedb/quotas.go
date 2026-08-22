package statedb

// Per-identity quota storage (Task 20182). See migrations/0020_quotas.sql for
// why there are two tables and why only one of them is ever rebuilt from live
// state. This file is the mechanical accessor layer and holds no policy:
// resolution, precedence and admission all live in pkg/quota, and the
// conversion between these rows and that model lives in pkg/quotastore.

import (
	"fmt"
	"strings"
	"time"
)

// QuotaOverrideRow is one row of quota_overrides. LimitsJSON is stored
// opaquely: the set of resources is pkg/quota's business, and a storage layer
// that validated it would be a second place to update when one is added.
type QuotaOverrideRow struct {
	Identity   string
	LimitsJSON string
	UpdatedAt  time.Time
	UpdatedBy  string
}

// QuotaCounterRow is one row of quota_counters.
type QuotaCounterRow struct {
	Identity  string
	Resource  string
	Bucket    string
	Value     float64
	UpdatedAt time.Time
}

// PutQuotaOverride inserts or replaces one identity's override.
func (d *DB) PutQuotaOverride(row QuotaOverrideRow) error {
	if strings.TrimSpace(row.Identity) == "" {
		return fmt.Errorf("statedb: quota override identity is required")
	}
	if row.LimitsJSON == "" {
		row.LimitsJSON = "{}"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO quota_overrides (identity, limits_json, updated_at, updated_by)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(identity) DO UPDATE SET
		     limits_json = excluded.limits_json,
		     updated_at  = excluded.updated_at,
		     updated_by  = excluded.updated_by`,
		row.Identity, row.LimitsJSON, formatOptionalTime(row.UpdatedAt), row.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("statedb: put quota override %q: %w", row.Identity, classifyDriverErr(err))
	}
	return nil
}

// ListQuotaOverrides returns every override, ordered by identity so the admin
// panel renders the same way on every load.
func (d *DB) ListQuotaOverrides() ([]QuotaOverrideRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT identity, limits_json, updated_at, updated_by
		   FROM quota_overrides ORDER BY identity`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list quota overrides: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []QuotaOverrideRow
	for rows.Next() {
		var r QuotaOverrideRow
		var updated string
		if err := rows.Scan(&r.Identity, &r.LimitsJSON, &updated, &r.UpdatedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan quota override: %w", classifyDriverErr(err))
		}
		r.UpdatedAt = parseOptionalTime(updated)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list quota overrides: %w", classifyDriverErr(err))
	}
	return out, nil
}

// DeleteQuotaOverride removes one identity's override, reporting whether a
// row existed.
func (d *DB) DeleteQuotaOverride(identity string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM quota_overrides WHERE identity = ?`, identity)
	if err != nil {
		return false, fmt.Errorf("statedb: delete quota override %q: %w", identity, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, nil
	}
	return n > 0, nil
}

// PutQuotaCounter writes one counter's current value. A value at or below
// zero deletes the row instead of storing a zero: an identity holding nothing
// should not keep a row per resource forever, and a row that says 0 and a
// missing row must not be two different things the reader has to reconcile.
func (d *DB) PutQuotaCounter(row QuotaCounterRow) error {
	if strings.TrimSpace(row.Identity) == "" || strings.TrimSpace(row.Resource) == "" {
		return fmt.Errorf("statedb: quota counter identity and resource are required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if row.Value <= 0 {
		_, err := d.conn.Exec(
			`DELETE FROM quota_counters WHERE identity = ? AND resource = ? AND bucket = ?`,
			row.Identity, row.Resource, row.Bucket)
		if err != nil {
			return fmt.Errorf("statedb: clear quota counter: %w", classifyDriverErr(err))
		}
		return nil
	}

	_, err := d.conn.Exec(
		`INSERT INTO quota_counters (identity, resource, bucket, value, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(identity, resource, bucket) DO UPDATE SET
		     value      = excluded.value,
		     updated_at = excluded.updated_at`,
		row.Identity, row.Resource, row.Bucket, row.Value, formatOptionalTime(row.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: put quota counter: %w", classifyDriverErr(err))
	}
	return nil
}

// ListQuotaCounters returns every counter row.
func (d *DB) ListQuotaCounters() ([]QuotaCounterRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT identity, resource, bucket, value, updated_at FROM quota_counters`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list quota counters: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []QuotaCounterRow
	for rows.Next() {
		var r QuotaCounterRow
		var updated string
		if err := rows.Scan(&r.Identity, &r.Resource, &r.Bucket, &r.Value, &updated); err != nil {
			return nil, fmt.Errorf("statedb: scan quota counter: %w", classifyDriverErr(err))
		}
		r.UpdatedAt = parseOptionalTime(updated)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list quota counters: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ReplaceQuotaGauges swaps every gauge row (bucket = '') for rows in one
// transaction.
//
// A transaction rather than delete-then-insert because the intermediate state
// — no gauge counters at all — is a state in which every tenant has unlimited
// headroom. On a hub reconciling at startup that window is short, but it is
// exactly the window an attacker watching for a restart would aim at, and
// making it atomic costs nothing.
func (d *DB) ReplaceQuotaGauges(rows []QuotaCounterRow) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: replace quota gauges: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM quota_counters WHERE bucket = ''`); err != nil {
		return fmt.Errorf("statedb: clear quota gauges: %w", classifyDriverErr(err))
	}
	for _, r := range rows {
		if strings.TrimSpace(r.Identity) == "" || strings.TrimSpace(r.Resource) == "" || r.Value <= 0 {
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO quota_counters (identity, resource, bucket, value, updated_at)
			 VALUES (?, ?, '', ?, ?)`,
			r.Identity, r.Resource, r.Value, formatOptionalTime(r.UpdatedAt),
		); err != nil {
			return fmt.Errorf("statedb: insert quota gauge: %w", classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: commit quota gauges: %w", classifyDriverErr(err))
	}
	return nil
}

// PruneQuotaCounters deletes daily counters older than bucket. Gauge rows
// (bucket = '') are never pruned: they are live state, not history, and ''
// sorts before every date so an unguarded comparison would delete all of them.
func (d *DB) PruneQuotaCounters(bucket string) error {
	if strings.TrimSpace(bucket) == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`DELETE FROM quota_counters WHERE bucket != '' AND bucket < ?`, bucket)
	if err != nil {
		return fmt.Errorf("statedb: prune quota counters: %w", classifyDriverErr(err))
	}
	return nil
}
