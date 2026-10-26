package statedb

// hubmeta.go is a typed door onto the metadata table for facts the hub records
// about its own *infrastructure*, as opposed to facts about the project whose
// plan the rest of this database holds.
//
// # Why not a table of its own
//
// Because the shape does not earn one. The first tenant is a single record per
// Kubernetes executor — "a probe observed on this date that the cluster does,
// or does not, enforce NetworkPolicy" — which is a string keyed by a string
// and queried one key at a time. A migration adding a table for that would buy
// no index anyone uses, and would spend the one thing schema changes cost that
// nothing else here does: every migration is classified additive or breaking
// and a breaking one stops an older binary reading these databases at all (see
// schema_compat.go). The metadata table already exists in 0001_init, in every
// database this package has ever opened.
//
// # Why a prefix
//
// metadata is shared with the state serialiser, which stores the plan blob, the
// config blob and the schema bookkeeping there under unprefixed names. Namespacing
// hub facts under "hub." means a future key called "version" or "goal" cannot
// collide with one of those and silently overwrite a project's state.

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// hubMetaPrefix namespaces hub-scoped keys inside the shared metadata table.
const hubMetaPrefix = "hub."

// HubMeta reads a hub-scoped metadata value, reporting whether it was present.
//
// The bool matters and callers must read it: an absent record and a record
// holding the empty string mean different things to every caller this has, and
// the one that exists today reads "no probe has run" versus "a probe wrote
// something unparsable" — which get different messages and different remedies.
func (d *DB) HubMeta(key string) (string, bool, error) {
	full, err := hubMetaKey(key)
	if err != nil {
		return "", false, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	var value string
	err = d.conn.QueryRow(`SELECT value FROM metadata WHERE key = ?`, full).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("statedb: hub meta %s: %w", key, classifyDriverErr(err))
	}
	return value, true, nil
}

// ReadHubMeta is HubMeta through a bare connection: one OpenConn opened,
// typically ReadOnly, so that reading a hub's record neither migrates its
// database nor, when the file is missing, creates one (Task 20410). A database
// without the metadata table holds no value.
func ReadHubMeta(conn *sql.DB, key string) (string, bool, error) {
	full, err := hubMetaKey(key)
	if err != nil {
		return "", false, err
	}
	if ok, err := tableExists(conn, "metadata"); err != nil || !ok {
		return "", false, err
	}
	var value string
	err = conn.QueryRow(`SELECT value FROM metadata WHERE key = ?`, full).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("statedb: hub meta %s: %w", key, classifyDriverErr(err))
	}
	return value, true, nil
}

// SetHubMeta writes a hub-scoped metadata value, replacing any previous one.
func (d *DB) SetHubMeta(key, value string) error {
	full, err := hubMetaKey(key)
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO metadata(key, value) VALUES (?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, full, value,
	); err != nil {
		return fmt.Errorf("statedb: set hub meta %s: %w", key, classifyDriverErr(err))
	}
	return nil
}

// SetHubMetas writes several hub-scoped metadata values in one transaction,
// so a reader sees all of them or none: a record kept across two keys — one a
// newer build reads, one an older build still does — is never read half
// rewritten (Task 20443).
func (d *DB) SetHubMetas(values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	full := make([]string, len(keys))
	for i, k := range keys {
		f, err := hubMetaKey(k)
		if err != nil {
			return err
		}
		full[i] = f
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: set hub meta: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	for i, k := range keys {
		if _, err := tx.Exec(
			`INSERT INTO metadata(key, value) VALUES (?,?)
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, full[i], values[k],
		); err != nil {
			return fmt.Errorf("statedb: set hub meta %s: %w", k, classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: set hub meta: %w", classifyDriverErr(err))
	}
	return nil
}

// HubMetas reads several hub-scoped metadata values in one statement — one
// snapshot of the database, so values SetHubMetas wrote together are read
// together. A key with no value is absent from the map.
func (d *DB) HubMetas(keys ...string) (map[string]string, error) {
	out := map[string]string{}
	if len(keys) == 0 {
		return out, nil
	}
	short := make(map[string]string, len(keys))
	args := make([]any, len(keys))
	marks := make([]string, len(keys))
	for i, k := range keys {
		f, err := hubMetaKey(k)
		if err != nil {
			return nil, err
		}
		short[f] = k
		args[i] = f
		marks[i] = "?"
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`SELECT key, value FROM metadata WHERE key IN (`+strings.Join(marks, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: hub meta: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("statedb: hub meta: %w", classifyDriverErr(err))
		}
		out[short[key]] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: hub meta: %w", classifyDriverErr(err))
	}
	return out, nil
}

// SetHubMetaIfAbsent writes value only when key has no value yet, and returns
// whichever value the key holds afterwards. Two processes minting the same
// secret at once both call it and both come away with the first one written —
// which a read-then-SetHubMeta cannot promise, since the second write would
// silently replace a value the first process is already using.
func (d *DB) SetHubMetaIfAbsent(key, value string) (string, error) {
	full, err := hubMetaKey(key)
	if err != nil {
		return "", err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO metadata(key, value) VALUES (?,?) ON CONFLICT(key) DO NOTHING`, full, value,
	); err != nil {
		return "", fmt.Errorf("statedb: set hub meta %s: %w", key, classifyDriverErr(err))
	}
	var stored string
	if err := d.conn.QueryRow(`SELECT value FROM metadata WHERE key = ?`, full).Scan(&stored); err != nil {
		return "", fmt.Errorf("statedb: hub meta %s: %w", key, classifyDriverErr(err))
	}
	return stored, nil
}

// DeleteHubMeta removes a hub-scoped metadata value. Deleting one that is not
// there succeeds: the caller asked for it to be gone, and it is.
func (d *DB) DeleteHubMeta(key string) error {
	full, err := hubMetaKey(key)
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(`DELETE FROM metadata WHERE key = ?`, full); err != nil {
		return fmt.Errorf("statedb: delete hub meta %s: %w", key, classifyDriverErr(err))
	}
	return nil
}

// hubMetaKey validates and namespaces a caller's key.
//
// An empty key is refused rather than stored as the bare prefix: it would be a
// single shared slot that every caller who forgot to build their key would
// write to and read from, which is worse than an error because it works.
func hubMetaKey(key string) (string, error) {
	k := strings.TrimSpace(key)
	if k == "" {
		return "", fmt.Errorf("statedb: hub meta key is empty")
	}
	return hubMetaPrefix + k, nil
}
