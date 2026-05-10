// Provider call audit-log helpers (Task 20105 / Task 20123).
//
// Thin facade over statedb.AppendProviderCall / ListProviderCalls /
// LoadProviderCall that resolves a workDir → state.db path with the same
// session-aware logic the rest of the package uses, opens the DB on demand,
// and closes it on return. These helpers are best-effort: persistence
// failures are reported as errors but the caller (pkg/provideraudit) is
// expected to log-and-discard so that observability never blocks user work.

package state

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ProviderCallRow is re-exported so callers don't have to import statedb
// directly.
type ProviderCallRow = statedb.ProviderCallRow

// AppendProviderCall persists one provider-call audit row to the project's
// state.db. Returns the assigned id on success. Returns (0, nil) when no
// project exists at workDir (so observability code can fan out to every
// project without bothering to check first).
func AppendProviderCall(workDir string, row ProviderCallRow) (int64, error) {
	if workDir == "" {
		return 0, nil
	}
	dir := ActiveDir(workDir)
	dbPath := effectiveDBPath(dir)
	if _, err := os.Stat(filepath.Dir(dbPath)); err != nil {
		// No .cloop/ directory yet — nothing to attach to.
		return 0, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return 0, fmt.Errorf("provider_call open %s: %w", dbPath, err)
	}
	defer db.Close()
	return db.AppendProviderCall(row)
}

// ListProviderCalls returns up to limit rows from the audit log starting
// at offset, latest-first. Returns (nil, 0, nil) for projects that have
// no state.db yet.
func ListProviderCalls(workDir string, offset, limit, taskID int, providerFilter string) ([]ProviderCallRow, int, error) {
	if workDir == "" {
		return nil, 0, nil
	}
	dir := ActiveDir(workDir)
	dbPath := effectiveDBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, 0, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	return db.ListProviderCalls(offset, limit, taskID, providerFilter)
}

// LoadProviderCall returns the full row for a single audit-log id.
func LoadProviderCall(workDir string, id int64) (*ProviderCallRow, error) {
	if workDir == "" {
		return nil, fmt.Errorf("workDir is empty")
	}
	dir := ActiveDir(workDir)
	dbPath := effectiveDBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("no state.db at %s", dbPath)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return db.LoadProviderCall(id)
}
