package statedb

// knowledge_sync.go is the storage half of the hub's knowledge sync scheduler
// (Task 20470; migration 0094): the lease that lets one hub process at a time
// sync a source, the batches a sync writes a page of documents in, the record
// of how each sync went, and the purge retention runs.
//
// What it guarantees on its own:
//
//   - A batch is one transaction. Each document in it is written whole — its
//     row, its chunks and their full-text entries — or not at all, and the
//     cursor a batch carries commits with the documents it moves past: a sync
//     that dies between two batches resumes from the last cursor that
//     committed, before the documents that did not.
//   - Every write a sync makes checks, in its own transaction, that the
//     source is the one the sync read and that the sync still holds the
//     source's lease. A process that stalled past its lease — and whose place
//     another took — writes nothing more.
//   - A purge works in bounded transactions, each a few milliseconds of write
//     lock, so a source of a million chunks is removed without stalling every
//     other writer of the control plane for as long as that takes.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

var (
	// ErrKnowledgeSyncLeaseHeld reports a source another sync is running:
	// AcquireKnowledgeSyncLease returns the holder's lease with it.
	ErrKnowledgeSyncLeaseHeld = errors.New("statedb: another sync of the knowledge source is running")
	// ErrKnowledgeSyncLeaseLost reports a write by a sync that no longer
	// holds its source's lease: it lapsed, and another sync may have taken
	// it. Nothing is written.
	ErrKnowledgeSyncLeaseLost = errors.New("statedb: the sync no longer holds the knowledge source's lease")
)

// Purge bounds.
var (
	// knowledgePurgeBatch is how many chunks, or documents, one purge
	// transaction removes. Removing a chunk removes its full-text entry, which
	// FTS5 does token by token, so a thousand is tens of milliseconds of write
	// lock. A variable so a test can watch a purge take several.
	knowledgePurgeBatch = 1000
)

// knowledgeTombstoneBatch is how many documents one transaction of a full
// listing's sweep, or of a reconciliation, takes out of the index. Taking one
// out drops its chunks' full-text entries, a few dozen each, so this is the
// sweep's counterpart of knowledgePurgeBatch: a sweep that removes most of a
// large source must not hold the write lock — and every other member's
// heartbeat behind it — until the last document is gone. A variable so a test
// can watch a sweep take several.
var knowledgeTombstoneBatch = 200

// inlineKnowledgePurgeBudget bounds the purge DeleteKnowledgeSource runs
// itself; what it leaves, the next PurgeKnowledge removes.
const inlineKnowledgePurgeBudget = 10 * time.Second

// ── The sync lease ──────────────────────────────────────────────────────────

// KnowledgeSyncLease is a source's sync lease: which sync holds it, in which
// hub process, why, and until when.
type KnowledgeSyncLease struct {
	SourceID int64
	// Holder is the sync's own id, unique to one sync.
	Holder string
	// Member is the hub process's instance id.
	Member string
	// Origin is what started the sync: "schedule" or "manual".
	Origin string
	// Actor names who asked for a manual sync.
	Actor      string
	AcquiredAt time.Time
	// ExpiresAt is when the lease lapses unless renewed; zero once released.
	ExpiresAt time.Time
}

// Live reports whether the lease is held at now.
func (l KnowledgeSyncLease) Live(now time.Time) bool {
	return l.Holder != "" && !l.ExpiresAt.IsZero() && l.ExpiresAt.After(now)
}

const knowledgeSyncLeaseCols = `source_id, holder, member, origin, actor, acquired_ns, expires_ns`

func scanKnowledgeSyncLease(s rowScanner) (KnowledgeSyncLease, error) {
	var (
		l                 KnowledgeSyncLease
		acquired, expires int64
	)
	if err := s.Scan(&l.SourceID, &l.Holder, &l.Member, &l.Origin, &l.Actor, &acquired, &expires); err != nil {
		return l, err
	}
	l.AcquiredAt, l.ExpiresAt = fromNanos(acquired), fromNanos(expires)
	return l, nil
}

// AcquireKnowledgeSyncLease takes source l.SourceID's sync lease for
// l.Holder, until l.ExpiresAt, unless another sync holds it at now: then it
// returns that sync's lease and ErrKnowledgeSyncLeaseHeld. A source that does
// not exist is ErrKnowledgeSourceNotFound.
//
// The read of the lease and the write of the new one are one transaction, and
// every statedb transaction takes the write lock at BEGIN, so two hub
// processes asking at once cannot both be told yes. A manual sync's lease is
// recorded on the audit trail as knowledge.source.sync, by l.Actor; a
// scheduled one is the hub's own routine work, and the source's sync status
// is its record.
func (d *DB) AcquireKnowledgeSyncLease(l KnowledgeSyncLease, now time.Time) (KnowledgeSyncLease, error) {
	if strings.TrimSpace(l.Holder) == "" || l.ExpiresAt.IsZero() || !l.ExpiresAt.After(now) {
		return KnowledgeSyncLease{}, errors.New("statedb: a knowledge sync lease needs a holder and an expiry after now")
	}
	l.AcquiredAt = now
	d.mu.Lock()
	src, held, err := d.acquireKnowledgeSyncLeaseLocked(l, now)
	d.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrKnowledgeSyncLeaseHeld) {
			return held, err
		}
		return KnowledgeSyncLease{}, err
	}
	if l.Origin == "manual" {
		payload := knowledgeAuditSource(src)
		payload["id"] = src.ID
		payload["origin"] = l.Origin
		payload["member"] = l.Member
		emit(d, &AuditEvent{
			Actor: actorOrSystem(l.Actor), EventType: string(auditaction.ActionKnowledgeSourceSync),
			EntityType: "knowledge_source", EntityID: fmt.Sprint(src.ID), Payload: MarshalAuditPayload(payload),
		})
	}
	return l, nil
}

func (d *DB) acquireKnowledgeSyncLeaseLocked(l KnowledgeSyncLease, now time.Time) (KnowledgeSourceRow, KnowledgeSyncLease, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: take the sync lease of knowledge source %d: %w", l.SourceID, classifyDriverErr(err))
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return KnowledgeSourceRow{}, KnowledgeSyncLease{}, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	src, err := scanKnowledgeSource(tx.QueryRow(`SELECT `+knowledgeSourceCols+` FROM knowledge_sources WHERE id = ?`, l.SourceID))
	if errors.Is(err, sql.ErrNoRows) {
		return src, KnowledgeSyncLease{}, fmt.Errorf("%w: %d", ErrKnowledgeSourceNotFound, l.SourceID)
	}
	if err != nil {
		return src, KnowledgeSyncLease{}, wrapErr(err)
	}
	cur, err := scanKnowledgeSyncLease(tx.QueryRow(`SELECT `+knowledgeSyncLeaseCols+` FROM knowledge_sync_leases
		WHERE source_id = ?`, l.SourceID))
	switch {
	case err == nil && cur.Live(now) && cur.Holder != l.Holder:
		return src, cur, fmt.Errorf("%w: source %d, on %s since %s", ErrKnowledgeSyncLeaseHeld, l.SourceID,
			cur.Member, cur.AcquiredAt.Format(time.RFC3339))
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return src, KnowledgeSyncLease{}, wrapErr(err)
	}
	if _, err := tx.Exec(`INSERT INTO knowledge_sync_leases (`+knowledgeSyncLeaseCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source_id) DO UPDATE SET
		  holder      = excluded.holder,
		  member      = excluded.member,
		  origin      = excluded.origin,
		  actor       = excluded.actor,
		  acquired_ns = excluded.acquired_ns,
		  expires_ns  = excluded.expires_ns`,
		l.SourceID, l.Holder, l.Member, l.Origin, l.Actor, nanos(l.AcquiredAt), nanos(l.ExpiresAt)); err != nil {
		return src, KnowledgeSyncLease{}, wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return src, KnowledgeSyncLease{}, wrapErr(err)
	}
	return src, KnowledgeSyncLease{}, nil
}

// RenewKnowledgeSyncLease extends holder's lease of source id to until. A
// lease that lapsed at now, or that another sync holds, is not renewed:
// ErrKnowledgeSyncLeaseLost, and the sync it belonged to must stop.
func (d *DB) RenewKnowledgeSyncLease(id int64, holder string, until, now time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`UPDATE knowledge_sync_leases SET expires_ns = ?
		WHERE source_id = ? AND holder = ? AND expires_ns > ?`, nanos(until), id, holder, nanos(now))
	if err != nil {
		return fmt.Errorf("statedb: renew the sync lease of knowledge source %d: %w", id, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("statedb: renew the sync lease of knowledge source %d: %w", id, classifyDriverErr(err))
	} else if n == 0 {
		return fmt.Errorf("%w: source %d", ErrKnowledgeSyncLeaseLost, id)
	}
	return nil
}

// ReleaseKnowledgeSyncLease gives up holder's lease of source id, so the next
// sync need not wait out its expiry. The row stays, saying who synced last. A
// lease holder no longer holds is left alone.
func (d *DB) ReleaseKnowledgeSyncLease(id int64, holder string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`UPDATE knowledge_sync_leases SET expires_ns = 0 WHERE source_id = ? AND holder = ?`,
		id, holder); err != nil {
		return fmt.Errorf("statedb: release the sync lease of knowledge source %d: %w", id, classifyDriverErr(err))
	}
	return nil
}

// LiveKnowledgeSyncLeases returns the sync leases held at now, by source id.
func (d *DB) LiveKnowledgeSyncLeases(now time.Time) (map[int64]KnowledgeSyncLease, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+knowledgeSyncLeaseCols+` FROM knowledge_sync_leases
		WHERE holder != '' AND expires_ns > ?`, nanos(now))
	if err != nil {
		return nil, fmt.Errorf("statedb: list knowledge sync leases: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	out := map[int64]KnowledgeSyncLease{}
	for rows.Next() {
		l, err := scanKnowledgeSyncLease(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: list knowledge sync leases: %w", classifyDriverErr(err))
		}
		out[l.SourceID] = l
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list knowledge sync leases: %w", classifyDriverErr(err))
	}
	return out, nil
}

// KnowledgeSyncFence names the sync lease a write is made under: the write
// is refused with ErrKnowledgeSyncLeaseLost unless Holder holds the source's
// lease at Now, and — when Version is set — with ErrKnowledgeSourceChanged
// unless the source is still the one the sync read. The zero fence checks
// nothing — for a sync nothing else can overlap, such as a test's.
type KnowledgeSyncFence struct {
	Holder string
	// Now is the writer's clock; zero means time.Now.
	Now time.Time
	// Version is the source's UpdatedAt as the sync read it, for the writes
	// that do not already compare it.
	Version time.Time
}

// checkTx refuses, inside tx, a write the fence no longer covers.
func (f KnowledgeSyncFence) checkTx(tx *sql.Tx, id int64) error {
	if !f.Version.IsZero() {
		var one int
		err := tx.QueryRow(`SELECT 1 FROM knowledge_sources WHERE id = ? AND updated_at = ?`, id,
			formatOptionalTime(f.Version)).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: source %d", ErrKnowledgeSourceChanged, id)
		}
		if err != nil {
			return fmt.Errorf("statedb: check knowledge source %d: %w", id, classifyDriverErr(err))
		}
	}
	if f.Holder == "" {
		return nil
	}
	now := f.Now
	if now.IsZero() {
		now = time.Now()
	}
	held, err := leaseHeldTx(tx, id, f.Holder, now)
	if err != nil {
		return fmt.Errorf("statedb: check the sync lease of knowledge source %d: %w", id, classifyDriverErr(err))
	}
	if !held {
		return fmt.Errorf("%w: source %d", ErrKnowledgeSyncLeaseLost, id)
	}
	return nil
}

// leaseHeldTx reports whether holder holds source id's lease at now.
func leaseHeldTx(tx *sql.Tx, id int64, holder string, now time.Time) (bool, error) {
	var one int
	err := tx.QueryRow(`SELECT 1 FROM knowledge_sync_leases WHERE source_id = ? AND holder = ? AND expires_ns > ?`,
		id, holder, nanos(now)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ── Batches ─────────────────────────────────────────────────────────────────

// KnowledgeBatchOp is one document of a batch: indexed, or taken out.
type KnowledgeBatchOp struct {
	// Doc is the document to index, and Chunk what makes its chunks — called
	// only when its content hash differs from the one stored, inside the
	// transaction (see IndexKnowledgeDocument).
	Doc   KnowledgeDocumentRow
	Chunk func() ([]KnowledgeChunk, bool)
	// Delete takes the document Doc.ExternalID names out of the index
	// instead, keeping its tombstone.
	Delete bool
}

// KnowledgeBatch is one transaction of a sync's writes to a source.
type KnowledgeBatch struct {
	SourceID int64
	// UpdatedAt is the source's UpdatedAt as the sync read it. A source
	// changed or deleted since is refused with ErrKnowledgeSourceChanged,
	// and nothing is written: a sync must not index what a configuration it
	// no longer has would list, nor record a cursor the new one cleared.
	UpdatedAt time.Time
	// Holder, when set, is the sync lease the writer holds; a writer that no
	// longer holds it at Now is refused with ErrKnowledgeSyncLeaseLost.
	Holder string
	// Now is the writer's clock, for the lease and for tombstones.
	Now time.Time
	Ops []KnowledgeBatchOp
	// Cursor, when set, is where the next sync resumes, written by the same
	// transaction as Ops: a cursor never commits ahead of the documents it
	// moves past.
	Cursor *string
}

// KnowledgeBatchResult says what each op of a batch did, in order: the
// outcome of an index, and for a deletion whether the source held the
// document.
type KnowledgeBatchResult struct {
	Outcomes []KnowledgeIndexOutcome
	Found    []bool
}

// ApplyKnowledgeBatch writes b in one transaction: the documents it indexes,
// then the ones it takes out, then the cursor.
//
// The ops must name distinct documents — a batch naming one twice is refused
// — which is what makes their order immaterial and lets every deletion come
// after every upsert: a deletion never precedes a write of the same rows
// (tests/arch/rowreplace_test.go). A sync that lists one document twice in a
// page keeps the last listing, as applying them in order would have.
func (d *DB) ApplyKnowledgeBatch(b KnowledgeBatch) (KnowledgeBatchResult, error) {
	res := KnowledgeBatchResult{Outcomes: make([]KnowledgeIndexOutcome, len(b.Ops)), Found: make([]bool, len(b.Ops))}
	now := b.Now
	if now.IsZero() {
		now = time.Now()
	}
	named := make(map[string]bool, len(b.Ops))
	for _, op := range b.Ops {
		id := strings.TrimSpace(op.Doc.ExternalID)
		if id == "" {
			return res, errors.New("statedb: a knowledge batch names a document without an external id")
		}
		if named[id] {
			return res, fmt.Errorf("statedb: a knowledge batch names document %q twice", id)
		}
		named[id] = true
	}
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: write a batch to knowledge source %d: %w", b.SourceID, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return res, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	var one int
	err = tx.QueryRow(`SELECT 1 FROM knowledge_sources WHERE id = ? AND updated_at = ?`,
		b.SourceID, formatOptionalTime(b.UpdatedAt)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return res, fmt.Errorf("%w: source %d", ErrKnowledgeSourceChanged, b.SourceID)
	}
	if err != nil {
		return res, wrapErr(err)
	}
	if err := (KnowledgeSyncFence{Holder: b.Holder, Now: now}).checkTx(tx, b.SourceID); err != nil {
		return res, err
	}
	for i, op := range b.Ops {
		if op.Delete {
			continue
		}
		op.Doc.SourceID = b.SourceID
		out, err := indexKnowledgeDocumentTx(tx, op.Doc, op.Chunk)
		if err != nil {
			return res, err
		}
		res.Outcomes[i] = out
	}
	for i, op := range b.Ops {
		if !op.Delete {
			continue
		}
		n, err := tombstoneKnowledgeDocumentsTx(tx, b.SourceID, now, `external_id = ?`, strings.TrimSpace(op.Doc.ExternalID))
		if err != nil {
			return res, wrapErr(err)
		}
		res.Found[i] = n > 0
	}
	if b.Cursor != nil {
		if _, err := tx.Exec(`UPDATE knowledge_sources SET sync_cursor = ? WHERE id = ?`, *b.Cursor, b.SourceID); err != nil {
			return res, wrapErr(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return res, wrapErr(err)
	}
	return res, nil
}

// ── Outcomes ────────────────────────────────────────────────────────────────

// KnowledgeSyncOutcome is how one sync of a source ended.
type KnowledgeSyncOutcome struct {
	// Status is "ok", "error", or "interrupted": stopped by its hub process
	// stopping or no longer leading, to resume from its cursor.
	Status string
	// Error is the failure's text, or what interrupted the sync, already
	// scrubbed of credentials; empty for ok.
	Error  string
	Origin string
	// StartedAt and FinishedAt bound the sync.
	StartedAt  time.Time
	FinishedAt time.Time
	// Report is what the sync did, a JSON object of counts.
	Report string
	// More reports a sync that stopped before its listing's end.
	More bool
	// Holder, when set, is the lease the sync held: the outcome is recorded
	// only while it still holds it, since a sync that lost its lease is no
	// longer the one whose outcome the source shows.
	Holder string
}

// RecordKnowledgeSyncOutcome records how a sync of source id ended. A sync
// that no longer holds its lease is refused with ErrKnowledgeSyncLeaseLost; a
// deleted source with ErrKnowledgeSourceNotFound.
func (d *DB) RecordKnowledgeSyncOutcome(id int64, o KnowledgeSyncOutcome) error {
	report := strings.TrimSpace(o.Report)
	if report == "" || !json.Valid([]byte(report)) {
		report = "{}"
	}
	duration := o.FinishedAt.Sub(o.StartedAt).Milliseconds()
	if duration < 0 || o.StartedAt.IsZero() {
		duration = 0
	}
	ok := int64(0)
	if o.Status == "ok" {
		ok = nanos(o.FinishedAt)
	}
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: record the sync of knowledge source %d: %w", id, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	if err := (KnowledgeSyncFence{Holder: o.Holder, Now: o.FinishedAt}).checkTx(tx, id); err != nil {
		return err
	}
	r, err := tx.Exec(`UPDATE knowledge_sources SET
		sync_status = ?, sync_error = ?, synced_at = ?, sync_started_ns = ?, sync_duration_ms = ?, sync_origin = ?,
		sync_report = ?, sync_more = ?, synced_ok_ns = CASE WHEN ? > 0 THEN ? ELSE synced_ok_ns END
		WHERE id = ?`,
		o.Status, o.Error, formatOptionalTime(o.FinishedAt), nanos(o.StartedAt), duration, o.Origin,
		report, boolInt(o.More), ok, ok, id)
	if err != nil {
		return wrapErr(err)
	}
	if n, err := r.RowsAffected(); err != nil {
		return wrapErr(err)
	} else if n == 0 {
		return fmt.Errorf("%w: %d", ErrKnowledgeSourceNotFound, id)
	}
	if err := tx.Commit(); err != nil {
		return wrapErr(err)
	}
	return nil
}

// ── Retention ───────────────────────────────────────────────────────────────

// KnowledgePurgeResult says what a purge removed, or in a dry run would have.
type KnowledgePurgeResult struct {
	// Tombstones counts the tombstones purged for being older than the cut.
	Tombstones int64 `json:"tombstones"`
	// Documents and Chunks count what deleted sources had left: their
	// documents, tombstones among them, and their chunks with their
	// full-text entries.
	Documents int64 `json:"documents"`
	Chunks    int64 `json:"chunks"`
	// Sources counts the deleted sources whose rows were found.
	Sources int `json:"sources"`
	// BodyBytes is the text the purged documents held.
	BodyBytes int64 `json:"body_bytes"`
}

// Rows is how many rows the purge removed.
func (r KnowledgePurgeResult) Rows() int64 { return r.Tombstones + r.Documents + r.Chunks }

func (r *KnowledgePurgeResult) add(o KnowledgePurgeResult) {
	r.Tombstones += o.Tombstones
	r.Documents += o.Documents
	r.Chunks += o.Chunks
	r.Sources += o.Sources
	r.BodyBytes += o.BodyBytes
}

// PurgeKnowledge removes the knowledge rows retention allows: every chunk and
// document of a source that no longer exists — what a source's deletion left
// when its own purge was cut short — and the tombstones of documents deleted
// before deletedBefore (zero purges none). In bounded transactions; ctx stops
// it between two. A dry run counts what it would remove and removes nothing.
func (d *DB) PurgeKnowledge(ctx context.Context, deletedBefore time.Time, dryRun bool) (KnowledgePurgeResult, error) {
	var out KnowledgePurgeResult
	gone, err := d.deletedKnowledgeSources()
	if err != nil {
		return out, err
	}
	for _, id := range gone {
		r, err := d.purgeKnowledgeOfSource(ctx, id, dryRun)
		out.add(r)
		if err != nil {
			return out, err
		}
	}
	out.Sources = len(gone)
	if deletedBefore.IsZero() {
		return out, nil
	}
	r, err := d.purgeKnowledgeTombstones(ctx, deletedBefore, dryRun)
	out.add(r)
	return out, err
}

// deletedKnowledgeSources lists the sources whose documents or chunks remain
// although the source does not. Each distinct source id is found by an index
// seek past the last, so this reads one entry per source, not per chunk.
func (d *DB) deletedKnowledgeSources() ([]int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	seen := map[int64]bool{}
	var gone []int64
	for _, table := range []string{"knowledge_chunks", "knowledge_documents"} {
		last := int64(-1 << 62)
		for {
			var next sql.NullInt64
			if err := d.conn.QueryRow(`SELECT MIN(source_id) FROM `+table+` WHERE source_id > ?`, last).
				Scan(&next); err != nil {
				return nil, fmt.Errorf("statedb: find deleted knowledge sources: %w", classifyDriverErr(err))
			}
			if !next.Valid {
				break
			}
			last = next.Int64
			if seen[last] {
				continue
			}
			seen[last] = true
			var n int
			if err := d.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_sources WHERE id = ?`, last).Scan(&n); err != nil {
				return nil, fmt.Errorf("statedb: find deleted knowledge sources: %w", classifyDriverErr(err))
			}
			if n == 0 {
				gone = append(gone, last)
			}
		}
	}
	return gone, nil
}

// purgeKnowledgeOfSource removes the chunks, then the documents, of source id
// — which must no longer exist: every transaction checks, so a purge can never
// reach a live source's rows — knowledgePurgeBatch at a time.
func (d *DB) purgeKnowledgeOfSource(ctx context.Context, id int64, dryRun bool) (KnowledgePurgeResult, error) {
	var out KnowledgePurgeResult
	if dryRun {
		wrapErr := func(err error) error {
			return fmt.Errorf("statedb: count what knowledge source %d left: %w", id, classifyDriverErr(err))
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		var exists int
		if err := d.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_sources WHERE id = ?`, id).Scan(&exists); err != nil {
			return out, wrapErr(err)
		}
		if exists > 0 {
			return out, nil
		}
		if err := d.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_chunks WHERE source_id = ?`, id).Scan(&out.Chunks); err != nil {
			return out, wrapErr(err)
		}
		if err := d.conn.QueryRow(`SELECT COUNT(*), COALESCE(SUM(body_bytes), 0) FROM knowledge_documents WHERE source_id = ?`, id).
			Scan(&out.Documents, &out.BodyBytes); err != nil {
			return out, wrapErr(err)
		}
		return out, nil
	}
	for _, table := range []string{"knowledge_chunks", "knowledge_documents"} {
		for {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			n, bytes, done, err := d.purgeKnowledgeBatch(id, table)
			if table == "knowledge_chunks" {
				out.Chunks += n
			} else {
				out.Documents += n
				out.BodyBytes += bytes
			}
			if err != nil {
				return out, err
			}
			if done {
				break
			}
		}
	}
	return out, nil
}

// purgeKnowledgeBatch removes up to knowledgePurgeBatch rows of table that
// belong to deleted source id, in one transaction; done reports nothing left.
func (d *DB) purgeKnowledgeBatch(id int64, table string) (n, bodyBytes int64, done bool, err error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: purge what knowledge source %d left: %w", id, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, 0, false, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM knowledge_sources WHERE id = ?`, id).Scan(&exists); err != nil {
		return 0, 0, false, wrapErr(err)
	}
	if exists > 0 {
		// Not deleted: nothing of a live source is ever purged.
		return 0, 0, true, nil
	}
	ids, err := idsTx(tx, `SELECT id FROM `+table+` WHERE source_id = ? LIMIT ?`, id, knowledgePurgeBatch)
	if err != nil {
		return 0, 0, false, wrapErr(err)
	}
	if len(ids) == 0 {
		return 0, 0, true, nil
	}
	list := jsonIDs(ids)
	switch table {
	case "knowledge_chunks":
		if _, err := tx.Exec(`DELETE FROM knowledge_chunks_fts WHERE rowid IN (SELECT value FROM json_each(?))`, list); err != nil {
			return 0, 0, false, wrapErr(err)
		}
	case "knowledge_documents":
		if err := tx.QueryRow(`SELECT COALESCE(SUM(body_bytes), 0) FROM knowledge_documents
			WHERE id IN (SELECT value FROM json_each(?))`, list).Scan(&bodyBytes); err != nil {
			return 0, 0, false, wrapErr(err)
		}
		if _, err := tx.Exec(`DELETE FROM knowledge_binding_documents WHERE document_id IN (SELECT value FROM json_each(?))`,
			list); err != nil {
			return 0, 0, false, wrapErr(err)
		}
	}
	res, err := tx.Exec(`DELETE FROM `+table+` WHERE id IN (SELECT value FROM json_each(?))`, list)
	if err != nil {
		return 0, 0, false, wrapErr(err)
	}
	if n, err = res.RowsAffected(); err != nil {
		return 0, 0, false, wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, false, wrapErr(err)
	}
	return n, bodyBytes, len(ids) < knowledgePurgeBatch, nil
}

// purgeKnowledgeTombstones removes the tombstones of documents deleted
// before before, knowledgePurgeBatch at a time — those of live sources: a
// deleted source's go with the rest of its rows. A tombstone has no chunks or
// matches — they went when it was made — but any found are removed with it.
func (d *DB) purgeKnowledgeTombstones(ctx context.Context, before time.Time, dryRun bool) (KnowledgePurgeResult, error) {
	var out KnowledgePurgeResult
	cut := nanos(before)
	if dryRun {
		d.mu.Lock()
		defer d.mu.Unlock()
		if err := d.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_documents WHERE deleted_ns > 0 AND deleted_ns < ?
			AND source_id IN (SELECT id FROM knowledge_sources)`, cut).Scan(&out.Tombstones); err != nil {
			return out, fmt.Errorf("statedb: count knowledge tombstones: %w", classifyDriverErr(err))
		}
		return out, nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		n, done, err := d.purgeKnowledgeTombstoneBatch(cut)
		out.Tombstones += n
		if err != nil || done {
			return out, err
		}
	}
}

func (d *DB) purgeKnowledgeTombstoneBatch(cut int64) (int64, bool, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: purge knowledge tombstones: %w", classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, false, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	ids, err := idsTx(tx, `SELECT id FROM knowledge_documents WHERE deleted_ns > 0 AND deleted_ns < ?
		AND source_id IN (SELECT id FROM knowledge_sources) LIMIT ?`, cut, knowledgePurgeBatch)
	if err != nil {
		return 0, false, wrapErr(err)
	}
	if len(ids) == 0 {
		return 0, true, nil
	}
	list := jsonIDs(ids)
	if err := dropKnowledgeChunksTx(tx, `document_id IN (SELECT value FROM json_each(?))`, list); err != nil {
		return 0, false, wrapErr(err)
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_binding_documents WHERE document_id IN (SELECT value FROM json_each(?))`,
		list); err != nil {
		return 0, false, wrapErr(err)
	}
	res, err := tx.Exec(`DELETE FROM knowledge_documents WHERE deleted_ns > 0 AND id IN (SELECT value FROM json_each(?))`, list)
	if err != nil {
		return 0, false, wrapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, false, wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return 0, false, wrapErr(err)
	}
	return n, len(ids) < knowledgePurgeBatch, nil
}

// idsTx runs a query of one integer column in tx.
func idsTx(tx *sql.Tx, query string, args ...any) ([]int64, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// jsonIDs renders ids as the JSON array json_each reads.
func jsonIDs(ids []int64) string {
	b, err := json.Marshal(ids)
	if err != nil {
		return "[]"
	}
	return string(b)
}
