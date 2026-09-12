// Hub instance lease (Task 20214).
//
// Rows for migrations/0026_hub_instances.sql. See that file for why the table
// is keyed by scope rather than by instance, and why the row survives release.
//
// This file owns the SQL only. What counts as stale, whether a recorded pid is
// still alive, and what an operator is told when acquisition fails are policy
// and live in pkg/hublease.
//
// Every mutation here is a compare-and-swap against the row the caller read.
// That is the whole point of the table: two hubs racing to start must not both
// conclude the lease was free, and a hub whose lease was taken while it was
// paused must discover that at its next renewal rather than carry on writing.

package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// HubScope is the fence name this binary writes. See the migration for why the
// column exists at all when there is only ever one value.
const HubScope = "hub"

// ErrHubLeaseNotFound is returned when no row exists for a scope.
var ErrHubLeaseNotFound = errors.New("statedb: hub lease not found")

// HubLeaseRow is one fence row: who holds the control plane, and since when.
type HubLeaseRow struct {
	Scope      string
	InstanceID string
	Hostname   string
	PID        int
	// BootID disambiguates a pid across reboots; '' when the platform does
	// not expose one. A liveness probe must not trust PID unless this matches
	// the probing host's current boot id.
	BootID  string
	Address string
	Version string

	AcquiredAt  time.Time
	HeartbeatAt time.Time
	// ReleasedAt is the instant of a graceful release; the zero time means the
	// lease is still held (or was abandoned without one).
	ReleasedAt time.Time
}

// Held reports whether the row represents a lease nobody has given up. It says
// nothing about whether the holder is alive — that is HeartbeatAt's job, and
// deciding it is pkg/hublease's.
func (r HubLeaseRow) Held() bool { return r.InstanceID != "" && r.ReleasedAt.IsZero() }

// AcquireHubLease takes the lease for row.Scope, conditioned on the current row
// still matching expect.
//
// It returns true when the lease was taken and false when it was not, without
// an error in either case: losing a race is an ordinary outcome here, not a
// failure, and the caller needs to re-read the row to describe the winner
// anyway.
//
// expect is the row the caller previously read, and is the entire concurrency
// story. A zero-valued expect means "I saw no row": the INSERT then succeeds
// only if none appeared in the meantime, because a conflict falls through to a
// DO UPDATE whose WHERE cannot match. A populated expect means "I saw this row
// and judged it takeable": the update applies only if it is still byte-for-byte
// that row, so a holder that renewed in the intervening microseconds keeps its
// lease and this caller is told it lost.
//
// This is one statement on purpose. SQLite applies it atomically without an
// explicit transaction, which avoids the read-then-upgrade pattern that
// deadlocks two processes against each other under WAL — the exact failure the
// busy_timeout cannot absorb.
func (d *DB) AcquireHubLease(row HubLeaseRow, expect HubLeaseRow) (bool, error) {
	if strings.TrimSpace(row.Scope) == "" {
		row.Scope = HubScope
	}
	if strings.TrimSpace(row.InstanceID) == "" {
		return false, errors.New("statedb: hub lease instance id is required")
	}
	now := time.Now().UTC()
	if row.AcquiredAt.IsZero() {
		row.AcquiredAt = now
	}
	// A lease with no heartbeat would read as infinitely stale the moment it
	// is written, so the acquiring write is also the first beat.
	if row.HeartbeatAt.IsZero() {
		row.HeartbeatAt = now
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`INSERT INTO hub_instances(scope, instance_id, hostname, pid, boot_id,
		                           address, version, acquired_at, heartbeat_at,
		                           released_at)
		 VALUES(?,?,?,?,?,?,?,?,?,'')
		 ON CONFLICT(scope) DO UPDATE SET
		   instance_id  = excluded.instance_id,
		   hostname     = excluded.hostname,
		   pid          = excluded.pid,
		   boot_id      = excluded.boot_id,
		   address      = excluded.address,
		   version      = excluded.version,
		   acquired_at  = excluded.acquired_at,
		   heartbeat_at = excluded.heartbeat_at,
		   released_at  = ''
		 WHERE hub_instances.instance_id  = ?
		   AND hub_instances.heartbeat_at = ?
		   AND hub_instances.released_at  = ?`,
		row.Scope, row.InstanceID, row.Hostname, row.PID, row.BootID,
		row.Address, row.Version,
		formatOptionalTime(row.AcquiredAt), formatOptionalTime(row.HeartbeatAt),
		expect.InstanceID,
		formatOptionalTime(expect.HeartbeatAt),
		formatOptionalTime(expect.ReleasedAt),
	)
	if err != nil {
		return false, fmt.Errorf("statedb: acquire hub lease %q: %w", row.Scope, classifyDriverErr(err))
	}
	return rowsChanged(res)
}

// RenewHubLease advances the heartbeat for a lease this instance holds.
//
// Returning false is the fencing signal, and callers must treat it as such: it
// means the row is no longer ours — taken over while we were paused, cleared by
// an operator, or released by us already — and the process must stop acting as
// the control plane rather than retry. It is deliberately not an error, because
// it is not one: it is an answer.
func (d *DB) RenewHubLease(scope, instanceID string, at time.Time) (bool, error) {
	if strings.TrimSpace(scope) == "" {
		scope = HubScope
	}
	if strings.TrimSpace(instanceID) == "" {
		return false, errors.New("statedb: hub lease instance id is required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE hub_instances SET heartbeat_at = ?
		 WHERE scope = ? AND instance_id = ? AND released_at = ''`,
		formatOptionalTime(at), scope, instanceID)
	if err != nil {
		return false, fmt.Errorf("statedb: renew hub lease %q: %w", scope, classifyDriverErr(err))
	}
	return rowsChanged(res)
}

// ReleaseHubLease gives up a lease held by instanceID, leaving the row in place
// with released_at set.
//
// Scoped to instanceID so a late release from a hub that already lost the lease
// cannot free the lease its successor now holds — the same fencing discipline
// as RenewHubLease, applied to the path most likely to run last.
func (d *DB) ReleaseHubLease(scope, instanceID string, at time.Time) (bool, error) {
	if strings.TrimSpace(scope) == "" {
		scope = HubScope
	}
	if strings.TrimSpace(instanceID) == "" {
		return false, errors.New("statedb: hub lease instance id is required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE hub_instances SET released_at = ?
		 WHERE scope = ? AND instance_id = ? AND released_at = ''`,
		formatOptionalTime(at), scope, instanceID)
	if err != nil {
		return false, fmt.Errorf("statedb: release hub lease %q: %w", scope, classifyDriverErr(err))
	}
	return rowsChanged(res)
}

// ClearHubLease marks a lease released on behalf of an operator, conditioned on
// the row still matching expect.
//
// This backs the `cloop hub lease clear` escape hatch. The compare-and-swap is
// what makes the command's staleness gate meaningful: the caller checks that
// the lease is stale and then clears it, and if the holder heartbeats in
// between, the observed heartbeat no longer matches and the clear is refused.
// Without it the gate would be advisory and the command could evict a hub that
// had just come back.
func (d *DB) ClearHubLease(scope string, expect HubLeaseRow, at time.Time) (bool, error) {
	if strings.TrimSpace(scope) == "" {
		scope = HubScope
	}
	if strings.TrimSpace(expect.InstanceID) == "" {
		return false, errors.New("statedb: hub lease clear needs the observed instance id")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE hub_instances SET released_at = ?
		 WHERE scope = ? AND instance_id = ? AND heartbeat_at = ? AND released_at = ''`,
		formatOptionalTime(at), scope, expect.InstanceID,
		formatOptionalTime(expect.HeartbeatAt))
	if err != nil {
		return false, fmt.Errorf("statedb: clear hub lease %q: %w", scope, classifyDriverErr(err))
	}
	return rowsChanged(res)
}

// GetHubLease returns the row for scope, or ErrHubLeaseNotFound.
func (d *DB) GetHubLease(scope string) (HubLeaseRow, error) {
	if strings.TrimSpace(scope) == "" {
		scope = HubScope
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT scope, instance_id, hostname, pid, boot_id, address, version,
		        acquired_at, heartbeat_at, released_at
		 FROM hub_instances WHERE scope = ?`, scope)
	out, err := scanHubLeaseRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return HubLeaseRow{}, fmt.Errorf("%w: %q", ErrHubLeaseNotFound, scope)
	}
	if err != nil {
		return HubLeaseRow{}, fmt.Errorf("statedb: get hub lease %q: %w", scope, classifyDriverErr(err))
	}
	return out, nil
}

func scanHubLeaseRow(sc rowScanner) (HubLeaseRow, error) {
	var (
		rec                                 HubLeaseRow
		acquiredAt, heartbeatAt, releasedAt string
	)
	if err := sc.Scan(&rec.Scope, &rec.InstanceID, &rec.Hostname, &rec.PID,
		&rec.BootID, &rec.Address, &rec.Version,
		&acquiredAt, &heartbeatAt, &releasedAt); err != nil {
		return HubLeaseRow{}, err
	}
	rec.AcquiredAt = parseOptionalTime(acquiredAt)
	rec.HeartbeatAt = parseOptionalTime(heartbeatAt)
	rec.ReleasedAt = parseOptionalTime(releasedAt)
	return rec, nil
}

// rowsChanged reports whether a statement modified anything.
//
// Split out because every mutation in this file reads its result the same way,
// and because a driver that cannot report RowsAffected must not be allowed to
// look like a lost race: that would turn "the lease is not yours" into a
// silently wrong answer in the one place the whole fence depends on it.
func rowsChanged(res sql.Result) (bool, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: hub lease rows affected: %w", err)
	}
	return n > 0, nil
}
