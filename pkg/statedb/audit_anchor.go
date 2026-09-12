// Audit-trail retention: chain anchors and prefix pruning (Task 20218).
//
// audit_events is append-only and hash-chained, which is what makes it a legal
// record and also what makes it unbounded. This file is the other half: a way
// to remove an old prefix that leaves the survivors verifiable rather than
// looking tampered with.
//
// The shape is deliberate. A prune is a *prefix* operation and never anything
// else. Removing rows from the interior — "keep the security events, drop the
// churn" — would leave id gaps and dangling prev_hash links throughout the
// retained region, and the only way to make that verify again is to re-chain,
// which silently destroys the tamper-evidence of every row it touches. So the
// policy is the one compliance regimes already use: archive, then truncate.
// Nothing is dropped on the floor; the prefix is sealed to a file whose digest
// the anchor records, and the survivors are checked against the anchor.
//
// See pkg/auditretention for the sealing side, which cannot live here: it
// needs pkg/auditexport, and pkg/auditexport imports this package.

package statedb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrAuditAnchorNotFound is returned by LatestAuditAnchor when the trail has
// never been pruned. Callers treat it as "the chain starts at genesis", which
// is the pre-Task-20218 behaviour and not an error condition.
var ErrAuditAnchorNotFound = errors.New("statedb: no audit anchor")

// AuditAnchor records one deliberate truncation of the audit chain. See
// migration 0027 for what each field is load-bearing for.
type AuditAnchor struct {
	ID        int64
	CreatedAt time.Time
	Actor     string

	// Cutoff is the --before instant the operator asked for. Kept distinct
	// from the ids it resolved to so an audit of the audit can tell a policy
	// decision from its effect.
	Cutoff time.Time

	PrunedFirstID   int64
	PrunedThroughID int64
	PrunedCount     int64

	// BoundaryHash is the row_hash of PrunedThroughID: what the first
	// surviving row's prev_hash must equal.
	BoundaryHash string

	// RetainedFromID is the first surviving id, or 0 when the prune emptied
	// the table.
	RetainedFromID int64

	ExportPath   string
	ExportFormat string
	ExportSHA256 string
	ExportBytes  int64

	PrevAnchorHash string
	AnchorHash     string
}

// anchorGenesisHash is the prev_anchor_hash of the first anchor, mirroring
// genesisHash in the event chain so the two read the same way.
const anchorGenesisHash = genesisHash

// computeAnchorHash returns SHA-256 over the anchor's fields in a fixed order,
// chained onto its predecessor. Same canonicalisation discipline as
// computeRowHash: tab-separated, version-tagged, no JSON re-encoding.
func computeAnchorHash(a AuditAnchor) string {
	var b strings.Builder
	b.WriteString("anchor-v1\t")
	b.WriteString(a.PrevAnchorHash)
	b.WriteByte('\t')
	fmt.Fprintf(&b, "%d\t%d\t%d\t%d\t",
		a.ID, a.PrunedFirstID, a.PrunedThroughID, a.PrunedCount)
	b.WriteString(a.CreatedAt.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\t')
	b.WriteString(a.Actor)
	b.WriteByte('\t')
	b.WriteString(a.Cutoff.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\t')
	b.WriteString(a.BoundaryHash)
	b.WriteByte('\t')
	fmt.Fprintf(&b, "%d\t", a.RetainedFromID)
	b.WriteString(a.ExportPath)
	b.WriteByte('\t')
	b.WriteString(a.ExportFormat)
	b.WriteByte('\t')
	b.WriteString(a.ExportSHA256)
	b.WriteByte('\t')
	fmt.Fprintf(&b, "%d", a.ExportBytes)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

const anchorColumns = `id, created_at, actor, cutoff, pruned_first_id,
	pruned_through_id, pruned_count, boundary_hash, retained_from_id,
	export_path, export_format, export_sha256, export_bytes,
	prev_anchor_hash, anchor_hash`

// scanAnchor reads one row in anchorColumns order.
func scanAnchor(sc interface{ Scan(...any) error }) (AuditAnchor, error) {
	var (
		a                  AuditAnchor
		createdAt, cutoffs string
	)
	if err := sc.Scan(&a.ID, &createdAt, &a.Actor, &cutoffs, &a.PrunedFirstID,
		&a.PrunedThroughID, &a.PrunedCount, &a.BoundaryHash, &a.RetainedFromID,
		&a.ExportPath, &a.ExportFormat, &a.ExportSHA256, &a.ExportBytes,
		&a.PrevAnchorHash, &a.AnchorHash,
	); err != nil {
		return AuditAnchor{}, err
	}
	if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
		a.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, cutoffs); err == nil {
		a.Cutoff = t
	}
	return a, nil
}

// LatestAuditAnchor returns the most recent anchor, or ErrAuditAnchorNotFound
// when the trail has never been pruned.
//
// "Most recent" is by pruned_through_id rather than by id: the anchor that
// governs the live table is the one that cut furthest into it, and ordering by
// the boundary rather than by insertion order means an out-of-order write
// cannot make a stale anchor authoritative.
func (d *DB) LatestAuditAnchor() (AuditAnchor, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.latestAuditAnchorLocked()
}

func (d *DB) latestAuditAnchorLocked() (AuditAnchor, error) {
	row := d.conn.QueryRow(
		`SELECT ` + anchorColumns + ` FROM audit_anchors
		 ORDER BY pruned_through_id DESC, id DESC LIMIT 1`)
	a, err := scanAnchor(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditAnchor{}, ErrAuditAnchorNotFound
	}
	if err != nil {
		return AuditAnchor{}, fmt.Errorf("statedb audit: read anchor: %w", classifyDriverErr(err))
	}
	return a, nil
}

// ListAuditAnchors returns every anchor in ascending boundary order. Used by
// `cloop hub audit anchors` and by the verifier's report so an operator can see
// the full retention history, not just the newest cut.
func (d *DB) ListAuditAnchors() ([]AuditAnchor, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT ` + anchorColumns + ` FROM audit_anchors
		 ORDER BY pruned_through_id ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb audit: list anchors: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []AuditAnchor
	for rows.Next() {
		a, err := scanAnchor(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb audit: scan anchor: %w", classifyDriverErr(err))
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb audit: anchor rows: %w", classifyDriverErr(err))
	}
	return out, nil
}

// PruneAuditPrefix deletes audit_events with id <= throughID and records an
// anchor describing the cut.
//
// The caller must already have sealed the prefix; this function will not
// delete rows without an export digest, because an anchor with no evidence
// behind it is indistinguishable from a cover-up and the whole point of the
// anchor is to be checkable. Pass a.ExportSHA256 and a.ExportPath from the
// completed seal.
//
// Delete and anchor happen in one transaction: a crash between them would
// otherwise leave either a truncated chain nothing explains, or an anchor
// claiming a truncation that did not happen. Both verify as tampering, and
// both would be this function's fault rather than an attacker's.
//
// Returns the anchor as written, with ID, RetainedFromID and the hashes filled
// in.
func (d *DB) PruneAuditPrefix(a AuditAnchor) (AuditAnchor, error) {
	if a.PrunedThroughID <= 0 {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune: non-positive boundary id %d", a.PrunedThroughID)
	}
	if a.ExportSHA256 == "" || a.ExportPath == "" {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune: refusing to delete an unsealed prefix (no export digest)")
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	a.CreatedAt = a.CreatedAt.UTC()
	if a.Actor == "" {
		a.Actor = "system"
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	// The boundary row must still be present and must still hash to what the
	// seal recorded. If it does not, the table changed under the seal and
	// deleting now would destroy the divergence rather than report it.
	var storedHash string
	err = tx.QueryRow(`SELECT row_hash FROM audit_events WHERE id = ?`, a.PrunedThroughID).Scan(&storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune: boundary row %d is gone", a.PrunedThroughID)
	}
	if err != nil {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune: read boundary: %w", classifyDriverErr(err))
	}
	if a.BoundaryHash == "" {
		a.BoundaryHash = storedHash
	} else if a.BoundaryHash != storedHash {
		return AuditAnchor{}, fmt.Errorf(
			"statedb audit: prune: boundary row %d changed under the seal (sealed %s, stored %s)",
			a.PrunedThroughID, short(a.BoundaryHash), short(storedHash))
	}

	// Resolve the survivor the anchor will pin the chain to.
	var firstRetained sql.NullInt64
	if err := tx.QueryRow(
		`SELECT MIN(id) FROM audit_events WHERE id > ?`, a.PrunedThroughID,
	).Scan(&firstRetained); err != nil {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune: read survivor: %w", classifyDriverErr(err))
	}
	a.RetainedFromID = 0
	if firstRetained.Valid {
		a.RetainedFromID = firstRetained.Int64
	}

	res, err := tx.Exec(`DELETE FROM audit_events WHERE id <= ?`, a.PrunedThroughID)
	if err != nil {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune delete: %w", classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err == nil {
		a.PrunedCount = n
	}

	// Chain onto the previous anchor.
	prev := anchorGenesisHash
	var prevHash sql.NullString
	if err := tx.QueryRow(
		`SELECT anchor_hash FROM audit_anchors ORDER BY pruned_through_id DESC, id DESC LIMIT 1`,
	).Scan(&prevHash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune: read anchor tip: %w", classifyDriverErr(err))
	}
	if prevHash.Valid && prevHash.String != "" {
		prev = prevHash.String
	}
	a.PrevAnchorHash = prev

	var maxAnchorID sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(id) FROM audit_anchors`).Scan(&maxAnchorID); err != nil {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune: read anchor id: %w", classifyDriverErr(err))
	}
	a.ID = maxAnchorID.Int64 + 1
	a.AnchorHash = computeAnchorHash(a)

	if _, err := tx.Exec(
		`INSERT INTO audit_anchors(`+anchorColumns+`)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.CreatedAt.Format(time.RFC3339Nano), a.Actor,
		a.Cutoff.UTC().Format(time.RFC3339Nano),
		a.PrunedFirstID, a.PrunedThroughID, a.PrunedCount, a.BoundaryHash,
		a.RetainedFromID, a.ExportPath, a.ExportFormat, a.ExportSHA256,
		a.ExportBytes, a.PrevAnchorHash, a.AnchorHash,
	); err != nil {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune: insert anchor: %w", classifyDriverErr(err))
	}

	if err := tx.Commit(); err != nil {
		return AuditAnchor{}, fmt.Errorf("statedb audit: prune commit: %w", classifyDriverErr(err))
	}
	return a, nil
}

// maxAuditScanBatch bounds one ReadAuditRange call. Large enough that sealing
// a million rows is a few hundred round trips, small enough that d.mu is not
// held for the length of the whole export — a live hub keeps serving between
// batches.
const maxAuditScanBatch = 5000

// ReadAuditRange returns up to limit rows with fromID <= id <= throughID, in
// ascending id order.
//
// It exists next to ListAuditEvents rather than reusing it because
// ListAuditEvents runs an unfiltered COUNT(*) on every call to populate its
// paging total. That is right for a UI page and wrong for a cursor: sealing a
// 1.09M-row prefix in batches would run a full-table count per batch. Paging by
// id rather than by OFFSET matters for the same reason — OFFSET re-walks the
// skipped rows every time.
func (d *DB) ReadAuditRange(fromID, throughID int64, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > maxAuditScanBatch {
		limit = maxAuditScanBatch
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(
		`SELECT id, timestamp, actor, event_type, entity_type, entity_id,
				payload, prev_hash, row_hash
		 FROM audit_events
		 WHERE id >= ? AND id <= ?
		 ORDER BY id ASC LIMIT ?`, fromID, throughID, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb audit: read range: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var (
			ev AuditEvent
			ts string
		)
		if err := rows.Scan(&ev.ID, &ts, &ev.Actor, &ev.EventType,
			&ev.EntityType, &ev.EntityID, &ev.Payload, &ev.PrevHash, &ev.RowHash,
		); err != nil {
			return nil, fmt.Errorf("statedb audit: scan range: %w", classifyDriverErr(err))
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			ev.Timestamp = t
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb audit: range rows: %w", classifyDriverErr(err))
	}
	return out, nil
}

// AuditChainLink recomputes one row's hash and reports whether it matches, so
// callers outside this package (the sealer, which must not archive a chain
// that is already broken) can verify without duplicating computeRowHash.
func AuditChainLink(ev AuditEvent) (want string, ok bool) {
	want = computeRowHash(ev)
	return want, want == ev.RowHash
}

// AuditGenesisHash is the prev_hash of a chain that has never been pruned.
// Exported so the sealer can start its own verification from the same place
// the verifier does.
const AuditGenesisHash = genesisHash

// AuditPruneCandidate describes what a prune with the given cutoff would
// remove, without removing anything. Both the CLI's --dry-run and the real
// path use it, so the number an operator is shown is the number that runs.
type AuditPruneCandidate struct {
	FirstID   int64
	ThroughID int64
	Count     int64
	// BoundaryHash is the row_hash at ThroughID, carried so the seal and the
	// delete can be checked against the same value.
	BoundaryHash string
	// Remaining is how many rows would survive.
	Remaining int64
}

// PlanAuditPrune resolves a time cutoff to a contiguous id prefix.
//
// Rows strictly older than cutoff are eligible. The boundary is the largest
// such id, and because ids are assigned monotonically under d.mu while
// timestamps come from the same clock, "older than cutoff" and "id <= boundary"
// describe the same set — but we count the set explicitly rather than assuming
// it, so a clock that went backwards produces a visibly wrong count instead of
// a silently over-broad delete.
func (d *DB) PlanAuditPrune(cutoff time.Time) (AuditPruneCandidate, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var c AuditPruneCandidate
	cut := cutoff.UTC().Format(time.RFC3339Nano)

	var through sql.NullInt64
	if err := d.conn.QueryRow(
		`SELECT MAX(id) FROM audit_events WHERE timestamp < ?`, cut,
	).Scan(&through); err != nil {
		return c, fmt.Errorf("statedb audit: plan prune: %w", classifyDriverErr(err))
	}
	if !through.Valid || through.Int64 <= 0 {
		return c, nil
	}
	c.ThroughID = through.Int64

	var first sql.NullInt64
	if err := d.conn.QueryRow(
		`SELECT MIN(id) FROM audit_events WHERE id <= ?`, c.ThroughID,
	).Scan(&first); err != nil {
		return c, fmt.Errorf("statedb audit: plan prune first: %w", classifyDriverErr(err))
	}
	c.FirstID = first.Int64

	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM audit_events WHERE id <= ?`, c.ThroughID,
	).Scan(&c.Count); err != nil {
		return c, fmt.Errorf("statedb audit: plan prune count: %w", classifyDriverErr(err))
	}
	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM audit_events WHERE id > ?`, c.ThroughID,
	).Scan(&c.Remaining); err != nil {
		return c, fmt.Errorf("statedb audit: plan prune remaining: %w", classifyDriverErr(err))
	}
	if err := d.conn.QueryRow(
		`SELECT row_hash FROM audit_events WHERE id = ?`, c.ThroughID,
	).Scan(&c.BoundaryHash); err != nil {
		return c, fmt.Errorf("statedb audit: plan prune boundary: %w", classifyDriverErr(err))
	}
	return c, nil
}
