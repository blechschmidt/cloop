// Sealing-key registry and rotation storage (Task 20181).
//
// The SQL half of envelope encryption: KEK records, rotation history, and the
// two queries a rotator needs over each population of sealed rows — "which
// rows are not yet under the target key" and "swap this row's envelope if it
// still looks exactly like what I read".
//
// As everywhere else in this package, nothing here decrypts. A KEK row holds
// a salt, which without CLOOP_SECRET_KEY is not key material; a sealed row
// holds a wrapped DEK, which without the KEK is not key material either. A
// storage layer that cannot see plaintext cannot leak it, however
// enthusiastically someone later instruments these functions — and rotation
// is exactly the kind of long-running job that grows debug logging.

package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Sentinels for the key registry.
var (
	// ErrKEKNotFound: no KEK row with that ID.
	ErrKEKNotFound = errors.New("statedb: sealing key not found")
	// ErrKEKInUse: retirement was refused because sealed rows still
	// reference the key. The refusal is computed inside the same
	// transaction as the retirement, so a row written concurrently either
	// blocks the retirement or arrives after it — never in between.
	ErrKEKInUse = errors.New("statedb: sealing key still referenced by sealed rows")
)

// KEKRow is one row of broker_keks.
type KEKRow struct {
	ID         string
	Salt       string
	State      string
	CheckValue []byte
	CreatedAt  string
	CreatedBy  string
	RetiredAt  string
}

// RotationRow is one row of key_rotations.
type RotationRow struct {
	ID         string
	ToKeyID    string
	State      string
	StartedAt  string
	UpdatedAt  string
	FinishedAt string
	StartedBy  string
	Total      int
	Rewrapped  int
	Skipped    int
	Failed     int
	LastError  string
}

// SealedRow is a row of sealed material as the rotator sees it: an ID, the
// associated data it is bound to, and the three envelope parts.
type SealedRow struct {
	ID         string
	KeyID      string
	WrappedDEK []byte
	Ciphertext []byte
}

// sealedPopulation is one table holding envelope-sealed material.
//
// Retirement's reference check is authoritative — it runs inside the retiring
// transaction — so this list is what actually decides whether a KEK may be
// shredded. A new sealed population added to the schema but not to this list
// would rotate correctly (rotation is driven by the SealedSet interface) and
// then be crypto-shredded out from under, which is precisely the failure
// retirement exists to prevent. SealedSetNames plus the drift gate in
// tests/security keep the two enumerations from separating.
type sealedPopulation struct {
	set        string
	countQuery string
}

var sealedPopulations = []sealedPopulation{
	{
		set:        "secrets",
		countQuery: `SELECT COUNT(*) FROM broker_secrets WHERE key_id = ?`,
	},
	{
		set: "sessions",
		countQuery: `SELECT COUNT(*) FROM sessions
		             WHERE refresh_key_id = ? AND refresh_sealed IS NOT NULL
		               AND length(refresh_sealed) > 0`,
	},
}

// SealedSetNames returns the populations retirement checks, so a test can
// assert they match the sets registered for rotation.
func SealedSetNames() []string {
	out := make([]string, 0, len(sealedPopulations))
	for _, p := range sealedPopulations {
		out = append(out, p.set)
	}
	return out
}

// takeWriteLock upgrades a deferred transaction to a write transaction before
// it reads anything.
//
// SQLite's Begin is BEGIN DEFERRED, which takes a read lock first and upgrades
// on the first write. For a check-then-act like retirement that is the wrong
// order: two connections can both read "nothing references this key" and only
// the second discover, at write time, that it is now wrong — and it discovers
// it as SQLITE_BUSY rather than as a refusal. Writing first makes the read
// happen under the write lock, so the check and the act cannot be separated by
// another connection's commit.
//
// The no-op self-update is the cheapest statement that takes the lock without
// changing anything: if the row does not exist the caller's own lookup reports
// that, with a better message than a lock error would.
func takeWriteLock(tx *sql.Tx, id string) error {
	if _, err := tx.Exec(`UPDATE broker_keks SET id = id WHERE id = ?`, id); err != nil {
		return fmt.Errorf("acquire write lock: %w", classifyDriverErr(err))
	}
	return nil
}

// ---------------------------------------------------------------------------
// KEK registry
// ---------------------------------------------------------------------------

// PutKEK inserts or replaces a KEK record.
//
// The WHERE clause on the upsert makes retirement terminal. Without it a
// PutKEK against a retired id would restore its salt and state, un-doing a
// crypto-shred with an ordinary write — the one operation in this file that is
// supposed to be irreversible.
func (d *DB) PutKEK(row KEKRow) error {
	if row.ID == "" {
		return fmt.Errorf("statedb: sealing key id is empty")
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO broker_keks(id, salt, state, check_value, created_at, created_by, retired_at)
		 VALUES (?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   salt=excluded.salt, state=excluded.state, check_value=excluded.check_value,
		   created_at=excluded.created_at, created_by=excluded.created_by,
		   retired_at=excluded.retired_at
		 WHERE broker_keks.state <> 'retired'`,
		row.ID, row.Salt, defaultString(row.State, "active"), row.CheckValue,
		row.CreatedAt, row.CreatedBy, row.RetiredAt,
	); err != nil {
		return fmt.Errorf("statedb: put sealing key %s: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// ListKEKs returns every KEK, newest first.
func (d *DB) ListKEKs() ([]KEKRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT id, salt, state, check_value, created_at, created_by, retired_at
		 FROM broker_keks ORDER BY created_at DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list sealing keys: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []KEKRow
	for rows.Next() {
		var row KEKRow
		if err := rows.Scan(&row.ID, &row.Salt, &row.State, &row.CheckValue,
			&row.CreatedAt, &row.CreatedBy, &row.RetiredAt); err != nil {
			return nil, fmt.Errorf("statedb: scan sealing key: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list sealing keys: %w", classifyDriverErr(err))
	}
	return out, nil
}

// PrimaryKEK returns the current primary, if any.
//
// Separate from ListKEKs because it sits on the seal path: every seal re-reads
// it to confirm this process has not fallen behind a rotation run elsewhere, so
// it has to be one indexed lookup and not a scan.
func (d *DB) PrimaryKEK() (KEKRow, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var row KEKRow
	err := d.conn.QueryRow(
		`SELECT id, salt, state, check_value, created_at, created_by, retired_at
		 FROM broker_keks WHERE state = 'primary'`,
	).Scan(&row.ID, &row.Salt, &row.State, &row.CheckValue,
		&row.CreatedAt, &row.CreatedBy, &row.RetiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return KEKRow{}, false, nil
	}
	if err != nil {
		return KEKRow{}, false, fmt.Errorf("statedb: read primary sealing key: %w", classifyDriverErr(err))
	}
	return row, true, nil
}

// PromoteKEK makes id the sole primary.
//
// Demotion and promotion happen in one transaction because the partial unique
// index permits only one primary: doing them in two statements outside a
// transaction would leave a window with none (a hub starting in that window
// mints a third key) or, if ordered the other way, fail on the index. The
// index is what makes this correct under concurrency rather than merely
// usually correct.
func (d *DB) PromoteKEK(id string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: promote sealing key: %w", classifyDriverErr(err))
	}
	defer tx.Rollback()

	if err := takeWriteLock(tx, id); err != nil {
		return fmt.Errorf("statedb: promote sealing key %s: %w", id, err)
	}

	var state string
	if err := tx.QueryRow(`SELECT state FROM broker_keks WHERE id = ?`, id).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrKEKNotFound, id)
		}
		return fmt.Errorf("statedb: promote sealing key %s: %w", id, classifyDriverErr(err))
	}
	if state == "retired" {
		return fmt.Errorf("%w: %s is retired and cannot be promoted", ErrKEKNotFound, id)
	}
	if _, err := tx.Exec(`UPDATE broker_keks SET state='active' WHERE state='primary' AND id <> ?`, id); err != nil {
		return fmt.Errorf("statedb: demote previous primary: %w", classifyDriverErr(err))
	}
	if _, err := tx.Exec(`UPDATE broker_keks SET state='primary' WHERE id = ?`, id); err != nil {
		return fmt.Errorf("statedb: promote sealing key %s: %w", id, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: promote sealing key %s: %w", id, classifyDriverErr(err))
	}
	_ = at
	return nil
}

// RetireKEK marks a KEK retired and destroys its salt.
//
// The reference check runs inside the retiring transaction, which is the
// difference between a guarantee and a race: checking first and retiring
// after would let a lease minted in between end up sealed under a key whose
// salt is already gone, and that material would be unrecoverable with no
// error anywhere to explain it.
//
// Blanking the salt is the point of retirement. A state flag alone could be
// ignored by a future code path or flipped back by a hand-edited database;
// without the salt the key cannot be derived from the passphrase at all, so
// retirement is a property of the cryptography rather than of the control
// flow.
func (d *DB) RetireKEK(id string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: retire sealing key: %w", classifyDriverErr(err))
	}
	defer tx.Rollback()

	if err := takeWriteLock(tx, id); err != nil {
		return fmt.Errorf("statedb: retire sealing key %s: %w", id, err)
	}

	var state string
	if err := tx.QueryRow(`SELECT state FROM broker_keks WHERE id = ?`, id).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrKEKNotFound, id)
		}
		return fmt.Errorf("statedb: retire sealing key %s: %w", id, classifyDriverErr(err))
	}
	if state == "primary" {
		return fmt.Errorf("%w: %s is the primary key", ErrKEKInUse, id)
	}

	for _, ref := range sealedPopulations {
		var n int
		if err := tx.QueryRow(ref.countQuery, id).Scan(&n); err != nil {
			return fmt.Errorf("statedb: count %s under %s: %w", ref.set, id, classifyDriverErr(err))
		}
		if n > 0 {
			return fmt.Errorf("%w: %d %s row(s) reference %s", ErrKEKInUse, n, ref.set, id)
		}
	}

	if _, err := tx.Exec(
		`UPDATE broker_keks SET state='retired', salt='', check_value=NULL, retired_at=? WHERE id = ?`,
		formatTimeRFC(at), id,
	); err != nil {
		return fmt.Errorf("statedb: retire sealing key %s: %w", id, classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: retire sealing key %s: %w", id, classifyDriverErr(err))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Rotation history
// ---------------------------------------------------------------------------

// PutRotation inserts or updates a rotation record.
func (d *DB) PutRotation(row RotationRow) error {
	if row.ID == "" {
		return fmt.Errorf("statedb: rotation id is empty")
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.conn.Exec(
		`INSERT INTO key_rotations(id, to_key_id, state, started_at, updated_at, finished_at,
		                           started_by, total, rewrapped, skipped, failed, last_error)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   to_key_id=excluded.to_key_id, state=excluded.state, updated_at=excluded.updated_at,
		   finished_at=excluded.finished_at, total=excluded.total, rewrapped=excluded.rewrapped,
		   skipped=excluded.skipped, failed=excluded.failed, last_error=excluded.last_error`,
		row.ID, row.ToKeyID, defaultString(row.State, "running"), row.StartedAt, row.UpdatedAt,
		row.FinishedAt, row.StartedBy, row.Total, row.Rewrapped, row.Skipped, row.Failed, row.LastError,
	); err != nil {
		return fmt.Errorf("statedb: put rotation %s: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// ListRotations returns rotation records, newest first.
func (d *DB) ListRotations(limit int) ([]RotationRow, error) {
	if limit <= 0 {
		limit = 20
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT id, to_key_id, state, started_at, updated_at, finished_at, started_by,
		        total, rewrapped, skipped, failed, last_error
		 FROM key_rotations ORDER BY started_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb: list rotations: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []RotationRow
	for rows.Next() {
		var row RotationRow
		if err := rows.Scan(&row.ID, &row.ToKeyID, &row.State, &row.StartedAt, &row.UpdatedAt,
			&row.FinishedAt, &row.StartedBy, &row.Total, &row.Rewrapped, &row.Skipped,
			&row.Failed, &row.LastError); err != nil {
			return nil, fmt.Errorf("statedb: scan rotation: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list rotations: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Sealed-row access for the rotator
// ---------------------------------------------------------------------------

// CountBrokerSecretsByKey groups secrets by the key they are sealed under.
func (d *DB) CountBrokerSecretsByKey() (map[string]int, error) {
	return d.countByKey(`SELECT key_id, COUNT(*) FROM broker_secrets GROUP BY key_id`, "secrets")
}

// CountSessionsByKey groups sessions holding a refresh token by sealing key.
//
// Sessions with no refresh token are excluded: they hold nothing sealed, so
// counting them would make a rotation look permanently incomplete on a hub
// whose IdP issues no refresh tokens.
func (d *DB) CountSessionsByKey() (map[string]int, error) {
	return d.countByKey(
		`SELECT refresh_key_id, COUNT(*) FROM sessions
		 WHERE refresh_sealed IS NOT NULL AND length(refresh_sealed) > 0
		 GROUP BY refresh_key_id`, "sessions")
}

func (d *DB) countByKey(query, what string) (map[string]int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("statedb: count %s by key: %w", what, classifyDriverErr(err))
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var keyID string
		var n int
		if err := rows.Scan(&keyID, &n); err != nil {
			return nil, fmt.Errorf("statedb: scan %s key count: %w", what, classifyDriverErr(err))
		}
		if keyID == "" {
			keyID = "legacy"
		}
		out[keyID] += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: count %s by key: %w", what, classifyDriverErr(err))
	}
	return out, nil
}

// ListBrokerSecretsNotUnderKey returns secrets still sealed under some other
// key. Ordered by ID so a stuck row appears in the same position each round,
// which makes an operator's "it keeps failing on the same one" observation
// true rather than coincidental.
func (d *DB) ListBrokerSecretsNotUnderKey(keyID string, limit int) ([]SealedRow, error) {
	return d.listSealed(
		`SELECT id, key_id, wrapped_dek, payload FROM broker_secrets
		 WHERE key_id <> ? ORDER BY id ASC LIMIT ?`, keyID, limit, "secrets")
}

// ListSessionsNotUnderKey returns sessions whose sealed refresh token is under
// some other key.
func (d *DB) ListSessionsNotUnderKey(keyID string, limit int) ([]SealedRow, error) {
	return d.listSealed(
		`SELECT id, refresh_key_id, refresh_wrapped_dek, refresh_sealed FROM sessions
		 WHERE refresh_key_id <> ? AND refresh_sealed IS NOT NULL AND length(refresh_sealed) > 0
		 ORDER BY id ASC LIMIT ?`, keyID, limit, "sessions")
}

func (d *DB) listSealed(query, keyID string, limit int, what string) ([]SealedRow, error) {
	if limit <= 0 {
		limit = 128
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(query, keyID, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb: list %s not under %s: %w", what, keyID, classifyDriverErr(err))
	}
	defer rows.Close()

	var out []SealedRow
	for rows.Next() {
		var row SealedRow
		if err := rows.Scan(&row.ID, &row.KeyID, &row.WrappedDEK, &row.Ciphertext); err != nil {
			return nil, fmt.Errorf("statedb: scan sealed %s row: %w", what, classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list %s not under %s: %w", what, keyID, classifyDriverErr(err))
	}
	return out, nil
}

// ReplaceBrokerSecretSealed swaps a secret's envelope under compare-and-swap.
//
// The WHERE clause matches the old key ID *and the exact ciphertext*, not just
// the ID. Matching the key alone would be a lost-update bug with teeth: a
// rotation that read a row, and an operator who re-minted that credential
// while the rotation was mid-flight, would race — and the rotation would win,
// silently restoring the superseded credential under a fresh wrap, with every
// column looking correct afterwards. Comparing the bytes turns that race into
// a no-op the rotator counts as skipped.
func (d *DB) ReplaceBrokerSecretSealed(id string, expect, next SealedRow) (bool, error) {
	return d.replaceSealed(
		`UPDATE broker_secrets SET key_id = ?, wrapped_dek = ?, payload = ?
		 WHERE id = ? AND key_id = ? AND payload = ?`, id, expect, next, "secret")
}

// ReplaceSessionSealed swaps a session's sealed refresh token under
// compare-and-swap, with the same reasoning as above: a session that refreshed
// its token mid-rotation must not have the previous token restored.
func (d *DB) ReplaceSessionSealed(id string, expect, next SealedRow) (bool, error) {
	return d.replaceSealed(
		`UPDATE sessions SET refresh_key_id = ?, refresh_wrapped_dek = ?, refresh_sealed = ?
		 WHERE id = ? AND refresh_key_id = ? AND refresh_sealed = ?`, id, expect, next, "session")
}

func (d *DB) replaceSealed(query, id string, expect, next SealedRow, what string) (bool, error) {
	if id == "" {
		return false, fmt.Errorf("statedb: %s id is empty", what)
	}
	if len(next.Ciphertext) == 0 {
		return false, fmt.Errorf("statedb: refusing to write an empty %s ciphertext", what)
	}
	// An empty expectation binds as SQL NULL, and `payload = NULL` is never
	// true — so the swap would match nothing and be reported as an ordinary
	// concurrent-write skip. A compare-and-swap that silently cannot match is
	// worse than an error, because the rotation looks like it converged.
	if len(expect.Ciphertext) == 0 {
		return false, fmt.Errorf("statedb: refusing to compare-and-swap %s %s against an empty ciphertext", what, id)
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.conn.Exec(query,
		next.KeyID, next.WrappedDEK, next.Ciphertext,
		id, expect.KeyID, expect.Ciphertext)
	if err != nil {
		return false, fmt.Errorf("statedb: rewrap %s %s: %w", what, id, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: rewrap %s %s: %w", what, id, classifyDriverErr(err))
	}
	return n > 0, nil
}

// defaultString returns fallback when s is empty.
func defaultString(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// formatTimeRFC renders a time for the schema's textual columns.
func formatTimeRFC(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
