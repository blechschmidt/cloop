// autoupdate.go stores the fleet's auto-update policy: whether the control
// plane rolls its executors forward on its own, which release they converge on,
// and how many move at once (Task 20331).
//
// A sibling of executorsandbox.go and projectlimits.go — an operator's standing
// policy about a set of devices, held in the control plane, never readable by
// the devices it governs. The difference is that this one is fleet-wide rather
// than per-executor; see the migration for why.
package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/autoupdate"
)

// AutoUpdatePolicy is the stored policy plus its provenance.
type AutoUpdatePolicy struct {
	Policy autoupdate.Policy `json:"policy"`
	SetAt  time.Time         `json:"set_at,omitempty"`
	SetBy  string            `json:"set_by,omitempty"`
}

// AutoUpdatePolicyFor returns the fleet's policy.
//
// A fleet that has never been configured yields a disabled zero policy and no
// error. "Nobody has set this" and "automatic upgrades are off" are the same
// operational state, and making the caller distinguish them would put an
// error path in front of the overwhelmingly common case.
func AutoUpdatePolicyFor(d *DB) (AutoUpdatePolicy, error) {
	var (
		out     AutoUpdatePolicy
		enabled int
		setAt   string
	)
	d.mu.Lock()
	defer d.mu.Unlock()

	err := d.conn.QueryRow(`
		SELECT enabled, target_version, max_in_flight, set_at, set_by
		  FROM autoupdate_policy WHERE id = 1`,
	).Scan(&enabled, &out.Policy.TargetVersion, &out.Policy.MaxInFlight, &setAt, &out.SetBy)
	if errors.Is(err, sql.ErrNoRows) {
		return AutoUpdatePolicy{}, nil
	}
	if err != nil {
		return AutoUpdatePolicy{}, fmt.Errorf("statedb: read auto-update policy: %w", err)
	}
	out.Policy.Enabled = enabled != 0
	if setAt != "" {
		if t, perr := time.Parse(time.RFC3339, setAt); perr == nil {
			out.SetAt = t
		}
	}
	return out, nil
}

// SetAutoUpdatePolicy replaces the fleet's policy. setBy is the identity that
// set it, for the audit trail.
func SetAutoUpdatePolicy(d *DB, p autoupdate.Policy, setBy string) error {
	if p.MaxInFlight < 0 {
		return fmt.Errorf("statedb: auto-update max_in_flight cannot be negative (%d)",
			p.MaxInFlight)
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`
		INSERT INTO autoupdate_policy (id, enabled, target_version, max_in_flight, set_at, set_by)
		VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			enabled        = excluded.enabled,
			target_version = excluded.target_version,
			max_in_flight  = excluded.max_in_flight,
			set_at         = excluded.set_at,
			set_by         = excluded.set_by`,
		enabled, strings.TrimSpace(p.TargetVersion), p.MaxInFlight,
		time.Now().UTC().Format(time.RFC3339), strings.TrimSpace(setBy))
	if err != nil {
		return fmt.Errorf("statedb: write auto-update policy: %w", err)
	}
	return nil
}
