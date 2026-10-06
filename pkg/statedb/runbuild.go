package statedb

// runbuild.go: the project's records of a run adopting newer builds (Task
// 20389) — the "follow new builds" option, the run-owner record and the
// one-shot adoption request.
//
// All three live in the metadata table, each under its own key and written by
// its own setter, for the reason review_gate and commit_policy are: the writer
// that changes one is never the process saving the plan. The dashboard flips
// the option and files requests while a run saves its tasks every few
// seconds; the run rewrites its own record while the dashboard saves edits.
// SaveState writes none of the three, so neither side can put back a copy it
// read before the other's change — and an older binary, which knows none of
// these keys, leaves them alone too (it upserts only the keys it knows).

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/runbuild"
)

const (
	metaFollowBuilds = "follow_builds"
	metaRunOwner     = "run_owner"
	metaAdoptRequest = "run_adopt_request"
)

// SaveFollowBuilds stores the project's "follow new builds" option.
func (d *DB) SaveFollowBuilds(on bool) error {
	value := ""
	if on {
		value = "1"
	}
	return d.saveMetaValue(metaFollowBuilds, value, "follow-builds option")
}

// SaveRunOwner stores the run-owner record. Nil clears it.
func (d *DB) SaveRunOwner(o *runbuild.Owner) error {
	value := ""
	if o != nil {
		b, err := json.Marshal(o)
		if err != nil {
			return fmt.Errorf("statedb: encode run owner: %w", err)
		}
		value = string(b)
	}
	return d.saveMetaValue(metaRunOwner, value, "run owner")
}

// SaveAdoptRequest files a request to adopt a newer build, replacing any
// earlier one.
func (d *DB) SaveAdoptRequest(r *runbuild.Request) error {
	if r == nil || r.ID == "" {
		return errors.New("statedb: an adoption request needs an id")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("statedb: encode adoption request: %w", err)
	}
	return d.saveMetaValue(metaAdoptRequest, string(b), "adoption request")
}

// ClearAdoptRequest removes the stored request if it is still the one with
// id, and reports whether it did. Compare-and-clear, inside one write
// transaction: the run clears the request it acted on, and must not clear a
// second one filed meanwhile.
func (d *DB) ClearAdoptRequest(id string) (bool, error) {
	if id == "" {
		return false, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: clear adoption request: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	raw, err := getMeta(tx, metaAdoptRequest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("statedb: read adoption request: %w", classifyDriverErr(err))
	}
	if raw == "" {
		return false, nil
	}
	var cur runbuild.Request
	if err := json.Unmarshal([]byte(raw), &cur); err == nil && cur.ID != id {
		return false, nil
	}
	if err := d.setMeta(tx, metaAdoptRequest, ""); err != nil {
		return false, fmt.Errorf("statedb: clear adoption request: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: clear adoption request: %w", classifyDriverErr(err))
	}
	return true, nil
}

func (d *DB) saveMetaValue(key, value, what string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(
		`INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value,
	); err != nil {
		return fmt.Errorf("statedb: save %s: %w", what, classifyDriverErr(err))
	}
	return nil
}

// PeekRunOwner reads the run-owner record of the project database at dbPath
// through a read-only handle: it never migrates or creates the database, so a
// diagnostic may read any project's record, whatever build wrote it. Nil when
// no run has recorded one.
func PeekRunOwner(dbPath string) (*runbuild.Owner, error) {
	conn, err := OpenConn(dbPath, ReadOnly)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var raw string
	err = conn.QueryRow(`SELECT value FROM metadata WHERE key=?`, metaRunOwner).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && raw == "") {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("statedb: read run owner: %w", classifyDriverErr(err))
	}
	var o runbuild.Owner
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		return nil, fmt.Errorf("statedb: decode run owner: %w", err)
	}
	return &o, nil
}
