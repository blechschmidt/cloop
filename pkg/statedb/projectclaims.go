package statedb

// Project claims (Task 20418). See migrations/0068_project_claims.sql for the
// table and why it exists.
//
// Mechanical accessors only: which directories a project may be created in is
// pkg/projectconfine's question and pkg/ui's to ask. What this layer
// guarantees is that two creations whose paths are the same, or one inside
// the other, cannot both hold a claim: the overlap is checked and the claim
// inserted in one transaction, and every read-write handle takes the write
// lock at BEGIN (connpolicy.go), so the check cannot go stale between the
// two — not across goroutines, and not across the members of a hub cluster
// sharing this database.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/projectconfine"
)

// Project claim states.
const (
	// ProjectClaimCreating: a creation holds the path while it makes the
	// directory and initialises it.
	ProjectClaimCreating = "creating"
	// ProjectClaimCreated: the project exists and is registered.
	ProjectClaimCreated = "created"
)

// ProjectClaim is one row of project_claims.
type ProjectClaim struct {
	Path      string
	State     string
	Owner     string
	HubMade   bool
	Root      string
	ClaimedBy string
	ClaimedAt time.Time
	UpdatedAt time.Time
}

const projectClaimColumns = `path, state, owner, hub_made, root, claimed_by, claimed_at, updated_at`

// ClaimProjectPath records that claim.Path is being created.
//
// It refuses when a live claim is the same path, inside it, or above it, and
// returns that claim; held is nil when the path was claimed. stale decides
// which existing claims no longer hold their path — a creation that died with
// its hub, a project removed from the registry by hand — and those are
// deleted in the same transaction. A nil stale treats every claim as live.
//
// claim.Path must be canonical (projectconfine.Canonical).
func (d *DB) ClaimProjectPath(claim ProjectClaim, stale func(ProjectClaim) bool) (held *ProjectClaim, err error) {
	claim.Path = strings.TrimSpace(claim.Path)
	if claim.Path == "" {
		return nil, errors.New("statedb: a project claim needs a path")
	}
	now := time.Now().UTC()
	if claim.ClaimedAt.IsZero() {
		claim.ClaimedAt = now
	}
	err = d.claimTx(func(tx *sql.Tx) error {
		existing, err := queryProjectClaims(tx, ``)
		if err != nil {
			return err
		}
		var dead []string
		for i := range existing {
			c := existing[i]
			if projectconfine.Relate(claim.Path, c.Path) == "" {
				continue
			}
			if stale != nil && stale(c) {
				if c.Path != claim.Path {
					dead = append(dead, c.Path)
				}
				continue
			}
			held = &c
			return nil
		}
		// An upsert, because a stale claim on this very path is taken over in
		// place: every column is this creation's, and a column a newer binary
		// added keeps its value (tests/arch/rowreplace_test.go).
		_, err = tx.Exec(`INSERT INTO project_claims (`+projectClaimColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(path) DO UPDATE SET state = excluded.state, owner = excluded.owner,
				hub_made = excluded.hub_made, root = excluded.root, claimed_by = excluded.claimed_by,
				claimed_at = excluded.claimed_at, updated_at = excluded.updated_at`,
			claim.Path, ProjectClaimCreating, claim.Owner, boolInt(claim.HubMade), claim.Root, claim.ClaimedBy,
			formatOptionalTime(claim.ClaimedAt), formatOptionalTime(now))
		if err != nil {
			return fmt.Errorf("statedb: claim %s: %w", claim.Path, classifyDriverErr(err))
		}
		// Stale claims above or below this one are gone, not replaced.
		for _, path := range dead {
			if _, err := tx.Exec(`DELETE FROM project_claims WHERE path = ?`, path); err != nil {
				return fmt.Errorf("statedb: drop the stale claim on %s: %w", path, classifyDriverErr(err))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return held, nil
}

// CompleteProjectClaim marks a claim created, and records whether this hub
// made the directory and under which projects root. It fails when there is no
// claim on path to complete.
func (d *DB) CompleteProjectClaim(path string, hubMade bool, root string) error {
	return d.claimTx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE project_claims SET state = ?, hub_made = ?, root = ?, updated_at = ? WHERE path = ?`,
			ProjectClaimCreated, boolInt(hubMade), root, formatOptionalTime(time.Now().UTC()), strings.TrimSpace(path))
		if err != nil {
			return fmt.Errorf("statedb: complete the claim on %s: %w", path, classifyDriverErr(err))
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("statedb: no claim on %s to complete", path)
		}
		return nil
	})
}

// ReleaseProjectClaim drops the claim on path, if there is one: a creation that
// failed, or a project removed from the hub.
func (d *DB) ReleaseProjectClaim(path string) error {
	return d.claimTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM project_claims WHERE path = ?`, strings.TrimSpace(path)); err != nil {
			return fmt.Errorf("statedb: release the claim on %s: %w", path, classifyDriverErr(err))
		}
		return nil
	})
}

// ProjectClaimAt returns the claim on exactly path.
func (d *DB) ProjectClaimAt(path string) (ProjectClaim, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := queryProjectClaims(d.conn, `WHERE path = ?`, strings.TrimSpace(path))
	if err != nil || len(rows) == 0 {
		return ProjectClaim{}, false, err
	}
	return rows[0], true, nil
}

// ListProjectClaims returns every claim, ordered by path.
func (d *DB) ListProjectClaims() ([]ProjectClaim, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryProjectClaims(d.conn, `ORDER BY path`)
}

// claimTx runs fn in one write transaction.
func (d *DB) claimTx(fn func(tx *sql.Tx) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: project claims: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: project claims: commit: %w", classifyDriverErr(err))
	}
	return nil
}

// claimQuerier is the connection or a transaction holding the write lock.
type claimQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func queryProjectClaims(q claimQuerier, where string, args ...any) ([]ProjectClaim, error) {
	rows, err := q.Query(`SELECT `+projectClaimColumns+` FROM project_claims `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list project claims: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []ProjectClaim
	for rows.Next() {
		var c ProjectClaim
		var hubMade int
		var claimed, updated string
		if err := rows.Scan(&c.Path, &c.State, &c.Owner, &hubMade, &c.Root, &c.ClaimedBy, &claimed, &updated); err != nil {
			return nil, fmt.Errorf("statedb: scan project claim: %w", classifyDriverErr(err))
		}
		c.HubMade = hubMade != 0
		c.ClaimedAt = parseOptionalTime(claimed)
		c.UpdatedAt = parseOptionalTime(updated)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list project claims: %w", classifyDriverErr(err))
	}
	return out, nil
}
