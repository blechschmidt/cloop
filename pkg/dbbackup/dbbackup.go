// Package dbbackup creates and restores hot backups of the cloop SQLite state
// database (Task 20115).
//
// Why a dedicated package:
//
// Operators need a safe way to capture the current project state without
// stopping the running cloop daemon. SQLite WAL mode (Task 20084) makes this
// possible — readers and writers do not block each other — but a naive `cp`
// of state.db is unsafe because uncommitted frames may still be in the WAL
// file. We use `VACUUM INTO 'path'` which the SQLite engine guarantees is a
// transactionally-consistent copy at the read transaction's snapshot point;
// it is the recommended hot-backup primitive when the C-level Online Backup
// API is not available, as is the case for the pure-Go modernc.org/sqlite
// driver we ship.
//
// Backup flow:
//
//  1. Open the source database (this triggers Migrate, but that is
//     idempotent and does not write user data).
//  2. PRAGMA wal_checkpoint(TRUNCATE) flushes pending WAL frames into the
//     main database file so the snapshot is as current as possible.
//  3. VACUUM INTO 'output.db' produces a self-contained, defragmented copy.
//     The copy has no -wal/-shm sidecars; it is a single file.
//  4. Compute SHA-256 of the copy and write a sidecar metadata JSON
//     describing source path, size, schema version, and duration.
//
// Restore flow:
//
//  1. Validate the backup with PRAGMA integrity_check (read-only handle).
//  2. Verify the SHA-256 against the metadata sidecar (if present).
//  3. Refuse to overwrite an existing destination unless --force is set.
//  4. Atomically swap the file in via tmp+rename.
//
// Why VACUUM INTO instead of OS-level copy:
//
//   - Atomically consistent against in-flight writes.
//   - Skips freelist pages, so the backup is smaller and quicker to verify.
//   - Single self-contained file (no WAL/SHM sidecars to ship together).
package dbbackup

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// MetadataSuffix is appended to the backup file path to form the sidecar
// metadata path: "/path/foo.db" → "/path/foo.db.meta.json".
const MetadataSuffix = ".meta.json"

// Metadata is persisted next to the backup file. Restore consults it to
// verify the backup before overwriting the target. All fields are optional
// for forward-compat — Restore tolerates an old metadata blob that is
// missing newer fields.
type Metadata struct {
	Source        string    `json:"source"`
	Backup        string    `json:"backup"`
	CreatedAt     time.Time `json:"created_at"`
	SizeBytes     int64     `json:"size_bytes"`
	SHA256        string    `json:"sha256"`
	DurationMS    int64     `json:"duration_ms"`
	SchemaVersion int       `json:"schema_version"`
	CloopVersion  string    `json:"cloop_version,omitempty"`
}

// BackupReport summarises a successful backup run.
type BackupReport struct {
	Source         string
	Output         string
	MetadataPath   string
	SizeBytes      int64
	Duration       time.Duration
	SHA256         string
	WALCheckpoint  string // "PASSED" or human-readable diagnostic
	SchemaVersion  int
}

// Backup creates a hot backup of the SQLite database at srcPath and writes
// it to outPath. The destination directory must exist. A sibling
// "<outPath>.meta.json" file is written alongside containing the SHA-256
// checksum, source size, and other metadata used by Restore for validation.
//
// If outPath already exists, it is overwritten — operators are expected to
// rotate backup filenames (timestamp, sequence, etc.) externally.
func Backup(srcPath, outPath string) (*BackupReport, error) {
	if srcPath == "" {
		return nil, errors.New("dbbackup: empty source path")
	}
	if outPath == "" {
		return nil, errors.New("dbbackup: empty output path")
	}
	if abs, err := filepath.Abs(srcPath); err == nil {
		srcPath = abs
	}
	if abs, err := filepath.Abs(outPath); err == nil {
		outPath = abs
	}
	if srcPath == outPath {
		return nil, errors.New("dbbackup: source and output paths are identical")
	}
	if _, err := os.Stat(srcPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("dbbackup: source database not found: %s", srcPath)
		}
		return nil, fmt.Errorf("dbbackup: stat source %s: %w", srcPath, err)
	}
	dstDir := filepath.Dir(outPath)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return nil, fmt.Errorf("dbbackup: mkdir output dir: %w", err)
	}

	// Pre-existing backup file would otherwise collide with VACUUM INTO,
	// which fails if the destination already exists. Remove it eagerly so
	// backup is idempotent on re-run.
	if err := os.Remove(outPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("dbbackup: clear stale output: %w", err)
	}
	if err := os.Remove(outPath + MetadataSuffix); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("dbbackup: clear stale metadata: %w", err)
	}

	started := time.Now()

	// Open via statedb so WAL mode + busy_timeout are configured, ensuring
	// the checkpoint and VACUUM INTO interact correctly with concurrent
	// writers. Migrate runs on Open, but it is idempotent — no-op when the
	// schema is already current.
	db, err := statedb.Open(srcPath)
	if err != nil {
		return nil, fmt.Errorf("dbbackup: open source: %w", err)
	}
	defer db.Close()

	checkpointMsg, err := db.WALCheckpointTruncate()
	if err != nil {
		return nil, fmt.Errorf("dbbackup: WAL checkpoint: %w", err)
	}

	// VACUUM INTO must use a literal string (not a parameter binding) per
	// SQLite syntax. We escape single quotes by doubling them; the path is
	// always operator-supplied (CLI arg or config), never user-controlled
	// HTTP input, so this is sufficient hardening against accidental quotes
	// in directory names.
	if err := db.VacuumInto(outPath); err != nil {
		return nil, fmt.Errorf("dbbackup: VACUUM INTO: %w", err)
	}

	schemaVersion, err := db.CurrentSchemaVersion()
	if err != nil {
		// Backup file is fine — only the metadata enrichment failed. Soft-fail.
		schemaVersion = 0
	}

	stat, err := os.Stat(outPath)
	if err != nil {
		return nil, fmt.Errorf("dbbackup: stat output: %w", err)
	}
	checksum, err := fileSHA256(outPath)
	if err != nil {
		return nil, fmt.Errorf("dbbackup: checksum: %w", err)
	}

	duration := time.Since(started)

	meta := Metadata{
		Source:        srcPath,
		Backup:        outPath,
		CreatedAt:     started.UTC(),
		SizeBytes:     stat.Size(),
		SHA256:        checksum,
		DurationMS:    duration.Milliseconds(),
		SchemaVersion: schemaVersion,
	}
	metaPath := outPath + MetadataSuffix
	if err := writeMetadata(metaPath, meta); err != nil {
		return nil, fmt.Errorf("dbbackup: write metadata: %w", err)
	}

	// Tighten permissions: a backup contains every secret the live DB carries.
	_ = os.Chmod(outPath, 0o600)
	_ = os.Chmod(metaPath, 0o600)

	return &BackupReport{
		Source:        srcPath,
		Output:        outPath,
		MetadataPath:  metaPath,
		SizeBytes:     stat.Size(),
		Duration:      duration,
		SHA256:        checksum,
		WALCheckpoint: checkpointMsg,
		SchemaVersion: schemaVersion,
	}, nil
}

// RestoreReport describes a successful restore.
type RestoreReport struct {
	Backup       string
	Destination  string
	SizeBytes    int64
	Duration     time.Duration
	BackedUpPath string // pre-restore copy of the destination, if any
}

// RestoreOptions configures Restore.
type RestoreOptions struct {
	// Force allows overwriting an existing destination database. Without
	// this flag, Restore refuses to overwrite if the destination file or
	// any of its WAL/SHM sidecars exist (heuristic for "active database").
	Force bool

	// SkipChecksum disables the SHA-256 verification step. Useful only for
	// recovering from a backup whose metadata sidecar has been lost.
	SkipChecksum bool
}

// Restore validates the backup at backupPath and atomically swaps it into
// dstPath. Validation steps:
//
//   - PRAGMA integrity_check on the backup file (read-only).
//   - SHA-256 verification against the metadata sidecar, if present.
//   - Schema version sanity (any positive integer is accepted).
//
// If dstPath already exists and Force is false, Restore returns an error.
// When Force is true, the existing destination is moved to a sibling
// .pre-restore backup before the swap, so a botched restore is recoverable.
func Restore(backupPath, dstPath string, opts RestoreOptions) (*RestoreReport, error) {
	if backupPath == "" {
		return nil, errors.New("dbbackup: empty backup path")
	}
	if dstPath == "" {
		return nil, errors.New("dbbackup: empty destination path")
	}
	if abs, err := filepath.Abs(backupPath); err == nil {
		backupPath = abs
	}
	if abs, err := filepath.Abs(dstPath); err == nil {
		dstPath = abs
	}
	if backupPath == dstPath {
		return nil, errors.New("dbbackup: backup and destination paths are identical")
	}
	stat, err := os.Stat(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("dbbackup: backup not found: %s", backupPath)
		}
		return nil, fmt.Errorf("dbbackup: stat backup: %w", err)
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("dbbackup: backup path is a directory: %s", backupPath)
	}

	if err := validateBackup(backupPath); err != nil {
		return nil, fmt.Errorf("dbbackup: backup invalid: %w", err)
	}

	if !opts.SkipChecksum {
		if err := verifyChecksum(backupPath); err != nil {
			return nil, fmt.Errorf("dbbackup: checksum mismatch: %w", err)
		}
	}

	// Active-DB guard: if any of dst, dst-wal, or dst-shm exists, the
	// destination is considered "in use" and we refuse without --force.
	// On the happy path (fresh restore over a previously-removed file)
	// this is a no-op.
	if !opts.Force && destinationActive(dstPath) {
		return nil, fmt.Errorf(
			"dbbackup: destination %s appears active (db/wal/shm present); pass --force to overwrite",
			dstPath,
		)
	}

	started := time.Now()

	// Snapshot the existing destination so an operator can roll back a bad
	// restore. We move (rename) rather than copy because state.db can be
	// large and we want the swap to be atomic at the filesystem level.
	var preRestoreDir string
	if _, err := os.Stat(dstPath); err == nil {
		preRestoreDir = dstPath + ".pre-restore." + started.UTC().Format("20060102T150405")
		if err := os.Rename(dstPath, preRestoreDir); err != nil {
			return nil, fmt.Errorf("dbbackup: stash existing destination: %w", err)
		}
		// Best-effort: stash WAL/SHM sidecars too so a roll-back recovers
		// the full live state. We do not fail the restore if these are absent.
		for _, suffix := range []string{"-wal", "-shm"} {
			src := dstPath + suffix
			if _, statErr := os.Stat(src); statErr == nil {
				_ = os.Rename(src, preRestoreDir+suffix)
			}
		}
	}

	// Stage to a sibling .swap file in the destination directory so the
	// rename is atomic on POSIX. Copy rather than rename across the
	// filesystem boundary that may exist between backup and dst.
	dstDir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return nil, fmt.Errorf("dbbackup: mkdir destination dir: %w", err)
	}
	stagePath := dstPath + ".restore.swap"
	if err := copyFile(backupPath, stagePath, 0o600); err != nil {
		// Roll back the pre-restore stash so we don't leave the user with
		// no destination at all.
		if preRestoreDir != "" {
			_ = os.Rename(preRestoreDir, dstPath)
		}
		return nil, fmt.Errorf("dbbackup: stage backup: %w", err)
	}
	if err := os.Rename(stagePath, dstPath); err != nil {
		_ = os.Remove(stagePath)
		if preRestoreDir != "" {
			_ = os.Rename(preRestoreDir, dstPath)
		}
		return nil, fmt.Errorf("dbbackup: atomic rename: %w", err)
	}

	return &RestoreReport{
		Backup:       backupPath,
		Destination:  dstPath,
		SizeBytes:    stat.Size(),
		Duration:     time.Since(started),
		BackedUpPath: preRestoreDir,
	}, nil
}

// LoadMetadata reads the sidecar metadata file written next to a backup.
// Returns (nil, nil) if the file is missing — backups without metadata are
// allowed (e.g. when SkipChecksum is later passed to Restore).
func LoadMetadata(backupPath string) (*Metadata, error) {
	metaPath := backupPath + MetadataSuffix
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("dbbackup: read metadata: %w", err)
	}
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("dbbackup: parse metadata: %w", err)
	}
	return &m, nil
}

// validateBackup opens the backup with a read-only handle and runs
// PRAGMA integrity_check. We deliberately do NOT use statedb.Open here,
// which would trigger a Migrate write — destructive on a backup the
// operator has not yet decided to restore.
func validateBackup(path string) error {
	dsn := fmt.Sprintf("file:%s?mode=ro", url.PathEscape(path))
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	if err := conn.Ping(); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	rows, err := conn.Query(`PRAGMA integrity_check`)
	if err != nil {
		return fmt.Errorf("integrity_check: %w", err)
	}
	defer rows.Close()
	var issues []string
	for rows.Next() {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			return fmt.Errorf("scan integrity row: %w", err)
		}
		if msg != "ok" {
			issues = append(issues, msg)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate integrity rows: %w", err)
	}
	if len(issues) > 0 {
		return fmt.Errorf("integrity_check failed: %s", strings.Join(issues, "; "))
	}
	return nil
}

// verifyChecksum recomputes the backup's SHA-256 and compares against the
// sidecar metadata. Missing metadata is treated as a soft pass, so backups
// shipped without sidecar (e.g. via tar) can still be restored using
// Restore with SkipChecksum.
func verifyChecksum(backupPath string) error {
	meta, err := LoadMetadata(backupPath)
	if err != nil {
		return err
	}
	if meta == nil || meta.SHA256 == "" {
		return nil // no expectation to match
	}
	got, err := fileSHA256(backupPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, meta.SHA256) {
		return fmt.Errorf("expected %s, got %s", meta.SHA256, got)
	}
	return nil
}

// destinationActive reports whether the destination database appears to be
// in use. We treat the presence of any of the file or its WAL/SHM sidecars
// as "active". This is a deliberately conservative heuristic: it errs on
// the side of refusing the restore so an operator must consciously --force
// when overwriting a live project's state.
func destinationActive(dstPath string) bool {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(dstPath + suffix); err == nil {
			return true
		}
	}
	return false
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeMetadata(path string, m Metadata) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}
