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
//     describing source path, size, schema version, and duration — and, read
//     back from the copy, the sealing keys its sealed rows depend on and
//     where its audit chain ends, the whole sealed under a key derived from
//     CLOOP_SECRET_KEY (manifest.go).
//
// Restore flow (Task 20410 put everything before the swap into Inspect):
//
//  1. Preflight, read-only, before anything is touched: PRAGMA
//     integrity_check, the schema this binary can open, the SHA-256 and the
//     seal over the sidecar, and whether the CLOOP_SECRET_KEY the restored
//     hub will run with derives every sealing key the backup's secrets are
//     sealed under. Each refusal names the flag that overrides it, if any.
//  2. Refuse to overwrite an existing destination unless --force is set.
//  3. Atomically swap the file in via tmp+rename.
//  4. Record the restore: an audit.restored row in the restored chain, and a
//     restore record sealed to the audit checkpoint sinks, so `cloop hub
//     audit verify --checkpoints` can tell this restore from a truncation.
//
// Why VACUUM INTO instead of OS-level copy:
//
//   - Atomically consistent against in-flight writes.
//   - Skips freelist pages, so the backup is smaller and quicker to verify.
//   - Single self-contained file (no WAL/SHM sidecars to ship together).
package dbbackup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// MetadataSuffix is appended to the backup file path to form the sidecar
// metadata path: "/path/foo.db" → "/path/foo.db.meta.json".
const MetadataSuffix = ".meta.json"

// maxMetadataSize bounds a sidecar.
const maxMetadataSize = 4 << 20

// Metadata is persisted next to the backup file. Restore consults it to
// verify the backup before overwriting the target. Every field after
// CloopVersion is the manifest (manifest.go), absent from sidecars written
// before Task 20410; such a sidecar is unsealed, and a restore says so.
type Metadata struct {
	Source        string    `json:"source"`
	Backup        string    `json:"backup"`
	CreatedAt     time.Time `json:"created_at"`
	SizeBytes     int64     `json:"size_bytes"`
	SHA256        string    `json:"sha256"`
	DurationMS    int64     `json:"duration_ms"`
	SchemaVersion int       `json:"schema_version"`
	CloopVersion  string    `json:"cloop_version,omitempty"`

	// Manifest is the manifest format, ManifestVersion.
	Manifest int `json:"manifest,omitempty"`
	// Keys are the sealing keys the backup's sealed rows depend on.
	Keys []ManifestKey `json:"keys,omitempty"`
	// Chain is where the backup's audit chain ends.
	Chain *ManifestChain `json:"chain,omitempty"`
	// KeyFingerprint names the CLOOP_SECRET_KEY the sidecar is sealed under,
	// and Seal is the seal; both empty on an unsealed sidecar.
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	Seal           string `json:"seal,omitempty"`
}

// BackupReport summarises a successful backup run.
type BackupReport struct {
	Source        string
	Output        string
	MetadataPath  string
	SizeBytes     int64
	Duration      time.Duration
	SHA256        string
	WALCheckpoint string // "PASSED" or human-readable diagnostic
	SchemaVersion int

	// Keys and Chain are what the manifest records.
	Keys  []ManifestKey
	Chain *ManifestChain
	// KeyFingerprint names the key the sidecar is sealed under; "" when it
	// is unsealed, because there was no CLOOP_SECRET_KEY.
	KeyFingerprint string
}

// Sealed reports whether the sidecar was sealed.
func (r *BackupReport) Sealed() bool { return r.KeyFingerprint != "" }

// BackupOptions configures BackupWithOptions.
type BackupOptions struct {
	// Key is the CLOOP_SECRET_KEY the sidecar is sealed under; "" writes an
	// unsealed sidecar, which a restore then refuses without --allow-unsealed.
	Key string
}

// Backup creates a hot backup of the SQLite database at srcPath and writes
// it to outPath, sealing its sidecar under the process's CLOOP_SECRET_KEY.
// See BackupWithOptions.
func Backup(srcPath, outPath string) (*BackupReport, error) {
	return BackupWithOptions(srcPath, outPath, BackupOptions{Key: os.Getenv(EnvKey)})
}

// BackupWithOptions creates a hot backup of the SQLite database at srcPath
// and writes it to outPath. The destination directory must exist. A sibling
// "<outPath>.meta.json" file is written alongside containing the SHA-256
// checksum, source size, and other metadata used by Restore for validation,
// and the manifest: the copy's sealing keys and audit head, sealed under
// opts.Key.
//
// If outPath already exists, it is overwritten — operators are expected to
// rotate backup filenames (timestamp, sequence, etc.) externally.
func BackupWithOptions(srcPath, outPath string, opts BackupOptions) (*BackupReport, error) {
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
	//
	// The version-skew guard is explicitly off here (Task 20226). It stops an
	// older binary *interpreting* a newer schema, and this path does not
	// interpret anything: WAL checkpoint and VACUUM INTO copy pages, and the
	// copy of a v30 database is a valid v30 database whichever binary made it.
	// Refusing would take backups away at the one moment an operator most
	// needs one — a rolled-back hub that will not start — and the documented
	// way out of that state (runbook: Rollback) begins with having a backup.
	db, err := statedb.OpenWithOptions(srcPath, statedb.OpenOptions{AllowSchemaDowngrade: true})
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

	// What the manifest records is read back from the copy, not from the
	// source: the source keeps taking writes, and a manifest that described
	// a moment the backup does not hold would be wrong in exactly the
	// details a restore relies on.
	facts, head, err := readBackupFacts(outPath)
	if err != nil {
		return nil, fmt.Errorf("dbbackup: read the backup's keys and audit head: %w", err)
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
		Manifest:      ManifestVersion,
		Keys:          manifestKeys(facts),
		Chain:         manifestChain(head),
	}
	if err := meta.seal(opts.Key); err != nil {
		return nil, fmt.Errorf("dbbackup: seal the sidecar: %w", err)
	}
	metaPath := outPath + MetadataSuffix
	if err := writeMetadata(metaPath, meta); err != nil {
		return nil, fmt.Errorf("dbbackup: write metadata: %w", err)
	}

	// Tighten permissions: a backup contains every secret the live DB carries.
	_ = os.Chmod(outPath, 0o600)
	_ = os.Chmod(metaPath, 0o600)

	return &BackupReport{
		Source:         srcPath,
		Output:         outPath,
		MetadataPath:   metaPath,
		SizeBytes:      stat.Size(),
		Duration:       duration,
		SHA256:         checksum,
		WALCheckpoint:  checkpointMsg,
		SchemaVersion:  schemaVersion,
		Keys:           meta.Keys,
		Chain:          meta.Chain,
		KeyFingerprint: meta.KeyFingerprint,
	}, nil
}

// readBackupFacts reads a backup's sealing keys and audit head through a
// read-only connection: the file is a backup, and statedb.Open would migrate
// it.
func readBackupFacts(path string) (statedb.SealedFacts, statedb.AuditHead, error) {
	conn, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		return statedb.SealedFacts{}, statedb.AuditHead{}, err
	}
	defer conn.Close()
	facts, err := statedb.ReadSealedFacts(conn, secretbroker.LegacySaltMetaKey)
	if err != nil {
		return facts, statedb.AuditHead{}, err
	}
	head, err := statedb.ReadAuditHead(conn)
	return facts, head, err
}

// RestoreReport describes a successful restore.
type RestoreReport struct {
	Backup       string
	Destination  string
	SizeBytes    int64
	Duration     time.Duration
	BackedUpPath string // pre-restore copy of the destination, if any

	// Preflight is what the backup was found to be before the swap.
	Preflight *Preflight
	// Recorded says how the restore was recorded; see Recording.
	Recorded Recording
}

// RestoreOptions configures Restore.
type RestoreOptions struct {
	// Force allows overwriting an existing destination database. Without
	// this flag, Restore refuses to overwrite if the destination file or
	// any of its WAL/SHM sidecars exist (heuristic for "active database").
	Force bool

	// Key is the CLOOP_SECRET_KEY the restored hub will run with. The
	// backup's sealing keys must derive from it, and its sidecar must carry
	// its seal; the restore record is sealed under it. Restore never reads
	// the environment itself: the caller says which key it means.
	Key string

	// SkipChecksum restores without checking the sidecar at all — no digest,
	// no seal. For a backup whose sidecar was lost; nothing then vouches that
	// the backup was not edited, and the restore records that it was skipped.
	SkipChecksum bool

	// AllowUnsealed accepts a sidecar whose seal cannot be checked here:
	// written unsealed (before Task 20410, or by a hub with no
	// CLOOP_SECRET_KEY), sealed under another key, or with no Key to check
	// it. The digest is still checked.
	AllowUnsealed bool

	// AcceptSecretLoss restores a backup whose sealing keys Key cannot
	// derive, and retires those keys in the restored database so the hub can
	// start and mint a fresh one; what they sealed is reported lost. The
	// backup file keeps them. Recorded on the audit.restored row and the
	// restore record.
	AcceptSecretLoss bool

	// Reason says why; it is recorded and required. Actor is who.
	Reason string
	Actor  string

	// CheckpointFile is the audit checkpoint file (audit.checkpoints.file):
	// where the restore looks for the newest checkpoint it supersedes, and
	// where it appends its restore record. "" reads and writes no file.
	// CheckpointStderr receives the record's stderr copy; nil writes none.
	CheckpointFile   string
	CheckpointStderr io.Writer
	// Chain is the role the restore record names, auditcheckpoint.Chain*;
	// "" takes the role the newest checkpoint for this database names, or
	// project when there is none.
	Chain string

	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// afterPreflight runs between a restore's preflight and its copy of the
// backup. Nil outside tests, which use it to change the file in that window.
var afterPreflight func(backupPath string)

// ErrNoReason is returned when a restore is asked for without a reason.
var ErrNoReason = errors.New("dbbackup: a restore needs a reason; it is recorded with the restore")

func (o RestoreOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Restore checks the backup at backupPath (Inspect), atomically swaps it into
// dstPath, and records the restore.
//
// Nothing is touched until every check has passed: a refusal returns a
// *RefusedError naming each reason and the flag, if any, that overrides it.
// If dstPath already exists and Force is false, Restore returns an error.
// When Force is true, the existing destination is moved to a sibling
// .pre-restore backup before the swap, so a botched restore is recoverable.
//
// Once the backup is in place the restore is recorded (record.go). A failure
// there returns the report with an *UnrecordedError: the database is
// restored, and the error says what is missing from the record of it.
func Restore(backupPath, dstPath string, opts RestoreOptions) (*RestoreReport, error) {
	if backupPath == "" {
		return nil, errors.New("dbbackup: empty backup path")
	}
	if dstPath == "" {
		return nil, errors.New("dbbackup: empty destination path")
	}
	if strings.TrimSpace(opts.Reason) == "" {
		return nil, ErrNoReason
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

	pre, err := Inspect(backupPath, PreflightOptions{
		Key:              opts.Key,
		SkipChecksum:     opts.SkipChecksum,
		AllowUnsealed:    opts.AllowUnsealed,
		AcceptSecretLoss: opts.AcceptSecretLoss,
	})
	if err != nil {
		return nil, err
	}
	if err := pre.Err(); err != nil {
		return nil, err
	}
	if afterPreflight != nil {
		afterPreflight(backupPath)
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
	// --force overwrites a database; it does not take one from under a hub
	// still serving it, which would keep writing to the file moved aside and
	// lose every write after the swap.
	if err := refuseServingHub(dstPath, opts.now()); err != nil {
		return nil, err
	}

	started := opts.now()

	// Stage to a sibling .swap file in the destination directory so the
	// rename is atomic on POSIX. Copy rather than rename across the
	// filesystem boundary that may exist between backup and dst. The copy is
	// hashed as it is made and must be the file the preflight checked:
	// whoever can write the backup could otherwise replace it between the
	// check and the copy, and restore something nothing vouched for.
	dstDir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return nil, fmt.Errorf("dbbackup: mkdir destination dir: %w", err)
	}
	stagePath := dstPath + ".restore.swap"
	staged, err := copyFileSHA256(backupPath, stagePath, 0o600)
	if err != nil {
		return nil, fmt.Errorf("dbbackup: stage backup: %w", err)
	}
	if !strings.EqualFold(staged, pre.SHA256) {
		_ = os.Remove(stagePath)
		return nil, fmt.Errorf("dbbackup: %s changed between its check and its copy (sha256 %s, then %s); "+
			"nothing was restored", backupPath, pre.SHA256, staged)
	}

	// Snapshot the existing destination so an operator can roll back a bad
	// restore. We move (rename) rather than copy because state.db can be
	// large and we want the swap to be atomic at the filesystem level.
	//
	// The database is three files, and they move together: a -wal left
	// beside the restored file is replayed into it the first time anything
	// opens it — SQLite does not ask whose log it is — which turns a restore
	// into the database the log came from. So every one that exists moves,
	// whether or not the main file does, a move that fails stops the restore,
	// and a failure after them puts all of them back.
	stash := dstPath + ".pre-restore." + started.UTC().Format("20060102T150405")
	var moved []string // suffixes moved aside, in order
	putBack := func() error {
		var errs []error
		for i := len(moved) - 1; i >= 0; i-- {
			if err := os.Rename(stash+moved[i], dstPath+moved[i]); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Lstat(dstPath + suffix); err != nil {
			continue
		}
		if err := os.Rename(dstPath+suffix, stash+suffix); err != nil {
			_ = os.Remove(stagePath)
			return nil, errors.Join(fmt.Errorf("dbbackup: move %s aside: %w", dstPath+suffix, err), putBack())
		}
		moved = append(moved, suffix)
	}
	var preRestoreDir string
	if len(moved) > 0 {
		preRestoreDir = stash + moved[0] // the main file's, unless only a sidecar was there
	}
	if err := os.Rename(stagePath, dstPath); err != nil {
		_ = os.Remove(stagePath)
		return nil, errors.Join(fmt.Errorf("dbbackup: atomic rename: %w", err), putBack())
	}

	report := &RestoreReport{
		Backup:       backupPath,
		Destination:  dstPath,
		SizeBytes:    pre.SizeBytes,
		BackedUpPath: preRestoreDir,
		Preflight:    pre,
	}
	report.Recorded, err = record(dstPath, pre, opts)
	report.Duration = opts.now().Sub(started)
	return report, err
}

// LoadMetadata reads the sidecar metadata file written next to a backup.
// Returns (nil, nil) if the file is missing; a restore then refuses unless
// SkipChecksum says the sidecar is not to be checked.
func LoadMetadata(backupPath string) (*Metadata, error) {
	metaPath := backupPath + MetadataSuffix
	f, err := os.Open(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("dbbackup: read metadata: %w", err)
	}
	defer f.Close()
	// A sidecar is a few kilobytes; one that is not is not a sidecar, and is
	// not read whole into memory to find that out.
	data, err := io.ReadAll(io.LimitReader(f, maxMetadataSize+1))
	if err != nil {
		return nil, fmt.Errorf("dbbackup: read metadata: %w", err)
	}
	if len(data) > maxMetadataSize {
		return nil, fmt.Errorf("dbbackup: metadata %s is over %d bytes", metaPath, maxMetadataSize)
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
// operator has not yet decided to restore. The read-only handle is the
// connection policy's (statedb.OpenConn), which also waits out a lock
// instead of failing on it.
func validateBackup(path string) error {
	conn, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer conn.Close()
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

// ErrHubServing is returned when a restore is refused because a hub process
// still serves the destination database.
var ErrHubServing = errors.New("dbbackup: a hub is serving the destination database")

// refuseServingHub fails when a hub process serves the database at dbPath —
// it holds the control-plane lease, or is a live member of a cluster whose
// leader is between leases — the check `cloop db maintain` makes before a
// VACUUM. A probe that fails is not evidence of a hub; a lapsed lease is none.
func refuseServingHub(dbPath string, now time.Time) error {
	if _, err := os.Stat(dbPath); err != nil {
		return nil // nothing there to serve
	}
	if st, err := hublease.Inspect(hublease.Options{DBPath: dbPath}); err == nil && st.Live {
		return fmt.Errorf("%w: %s (pid %d) has held the lease since %s — stop it first; a hub writing to a "+
			"database swapped from under it loses everything it writes after the swap",
			ErrHubServing, st.Row.Hostname, st.Row.PID, st.Row.AcquiredAt.Format(time.RFC3339))
	}
	if live, err := hubcluster.LiveMemberRows(dbPath, now); err == nil && len(live) > 0 {
		return fmt.Errorf("%w: %d hub process(es) serve it, %s (pid %d) among them — stop them first",
			ErrHubServing, len(live), live[0].Hostname, live[0].PID)
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

func writeMetadata(path string, m Metadata) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// copyFileSHA256 copies src to dst and returns the SHA-256 of what it copied.
func copyFileSHA256(src, dst string, mode os.FileMode) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return "", err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return "", err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
