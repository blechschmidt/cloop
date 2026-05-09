// Package globalbudget — SQLite mirror for the YAML global budget store
// (Task 20075).
//
// The canonical store remains ~/.config/cloop/budget.yaml (already atomic-
// write hardened). This file adds a parallel SQLite mirror at
// ~/.config/cloop/global.db so the global budget config is queryable
// alongside the per-project state.db, and recoverable from YAML loss.
//
// Failure mode: every SQLite mirror operation here is best-effort. If the
// SQLite write or read fails, callers fall back to YAML. The user-visible
// behaviour without SQLite is identical to the pre-Task-20075 behaviour;
// SQLite is purely additive.
package globalbudget

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	_ "modernc.org/sqlite"
)

const (
	globalDBFile        = "global.db"
	globalDBMetaKey     = "budget_yaml"
	globalDBSchema      = `
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
`
)

// dbMu guards the per-process open/close cycle so concurrent Save calls don't
// race on the same SQLite file. modernc/sqlite is goroutine-safe but the
// open-write-close pattern still benefits from in-process serialisation given
// we don't keep a long-lived handle.
var dbMu sync.Mutex

// globalDBPath returns ~/.config/cloop/global.db.
func globalDBPath() (string, error) {
	d, err := globalConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, globalDBFile), nil
}

// openGlobalDB opens (or creates) the global SQLite store and applies the
// schema. The caller must Close() the returned handle.
func openGlobalDB() (*sql.DB, string, error) {
	path, err := globalDBPath()
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", fmt.Errorf("globalbudget: creating db dir: %w", err)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, "", fmt.Errorf("globalbudget: open %s: %w", path, err)
	}
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(globalDBSchema); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("globalbudget: schema: %w", err)
	}
	return conn, path, nil
}

// mirrorToSQLite stores the YAML-serialised global budget config in
// ~/.config/cloop/global.db. Best-effort: errors are swallowed because YAML
// remains the authoritative store.
func mirrorToSQLite(yamlBlob []byte) {
	dbMu.Lock()
	defer dbMu.Unlock()

	conn, path, err := openGlobalDB()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Exec(
		`INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		globalDBMetaKey, string(yamlBlob),
	)
	// Tighten perms — global budget config is non-secret, but the SQLite
	// file lives in ~/.config/cloop/ alongside files that may carry tokens
	// in the future. 0o600 matches the YAML twin's perms.
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o600)
	}
}

// loadFromSQLite returns the YAML blob previously mirrored, or "" if no
// mirror exists. Used by Load() to recover when budget.yaml is missing.
func loadFromSQLite() string {
	dbMu.Lock()
	defer dbMu.Unlock()

	path, err := globalDBPath()
	if err != nil {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return ""
	}
	defer conn.Close()
	var v string
	row := conn.QueryRow(`SELECT value FROM metadata WHERE key=?`, globalDBMetaKey)
	if err := row.Scan(&v); err != nil {
		return ""
	}
	return v
}
