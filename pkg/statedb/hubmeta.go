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
