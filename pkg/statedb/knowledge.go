package statedb

// knowledge.go stores enterprise knowledge sources, the projects they serve,
// the documents they hold and the full-text index over those documents (Task
// 20467; migration 0092).
//
// pkg/knowledge owns the rules — who may do what, what a valid source or
// binding is, how a document becomes chunks — and calls these with values it
// has already checked. What this file guarantees on its own is the shape of
// every write:
//
//   - Nothing replaces a row (tests/arch/rowreplace_test.go). A document and
//     its chunks are upserted in place, and only the chunks it no longer has
//     are deleted, after the upsert. A binding's narrowing is updated in place.
//     A document the source no longer holds keeps its row as a tombstone,
//     without its chunks or what it said, until retention purges it
//     (knowledge_sync.go).
//   - A chunk's text lives in knowledge_chunks_fts under the chunk's id, and
//     every write that touches one touches both, in one transaction. FTS5 owns
//     its copy of the text, so SQLite keeps the index consistent with it — an
//     external-content table would hand that job to this file, and a mistake
//     in it would be an index `PRAGMA integrity_check` reports as corrupt.
//   - A search reads only through knowledge_bindings for the project it is
//     asked about. There is no other path from a project to a chunk.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

var (
	// ErrKnowledgeSourceNotFound reports no knowledge source with an id.
	ErrKnowledgeSourceNotFound = errors.New("statedb: knowledge source not found")
	// ErrKnowledgeSourceNameTaken reports a second source of one owner under a
	// name the first already has.
	ErrKnowledgeSourceNameTaken = errors.New("statedb: a knowledge source with that name already exists")
	// ErrKnowledgeSourceChanged reports a write refused because the source
	// changed, or was deleted, after the writer read it: a sync's cursor after
	// a reconfiguration, or an edit made from a stale copy.
	ErrKnowledgeSourceChanged = errors.New("statedb: the knowledge source changed since it was read")
	// ErrKnowledgeBindingNotFound reports no binding with an id.
	ErrKnowledgeBindingNotFound = errors.New("statedb: knowledge binding not found")
	// ErrKnowledgeBindingChanged reports a binding whose query changed after a
	// sync computed which documents match it.
	ErrKnowledgeBindingChanged = errors.New("statedb: the knowledge binding's query changed")
	// ErrKnowledgeQuery reports a full-text query SQLite could not parse.
	ErrKnowledgeQuery = errors.New("statedb: invalid knowledge search query")
)

// maxKnowledgeChunks bounds one document's chunks at the storage layer, below
// any caller's own bound: a document past it is refused, not truncated, since
// a caller that passed this many has a bug the index should not absorb.
const maxKnowledgeChunks = 8192

// KnowledgeSourceRow is one row of knowledge_sources.
type KnowledgeSourceRow struct {
	ID         int64
	Kind       string
	Name       string
	Scope      string
	Owner      string
	Config     string
	SecretRef  string
	Enabled    bool
	SyncCursor string
	SyncStatus string
	SyncError  string
	SyncedAt   time.Time
	// ListingStartedAt is when the full listing in progress began; zero when
	// none is. FullListingAt is when one last reached its end.
	ListingStartedAt time.Time
	FullListingAt    time.Time
	// ReconciledAt is when the source's documents were last reconciled
	// against what its remote holds (ReconcileKnowledgeDocuments), or a full
	// listing last reached its end; zero for never.
	ReconciledAt time.Time
	// SyncIntervalMin is how often the hub syncs the source, in minutes; 0
	// means pkg/knowledge's default.
	SyncIntervalMin int
	// SyncStartedAt, SyncDuration and SyncOrigin describe the last sync:
	// when it began, how long it ran, and what started it (schedule or
	// manual). SyncReport is what it did, a JSON object of counts, and
	// SyncMore whether it stopped before its listing's end. SyncedOKAt is
	// when a sync last ended ok.
	SyncStartedAt time.Time
	SyncDuration  time.Duration
	SyncOrigin    string
	SyncReport    string
	SyncMore      bool
	SyncedOKAt    time.Time
	CreatedAt     time.Time
	CreatedBy     string
	UpdatedAt     time.Time
	UpdatedBy     string
}

const knowledgeSourceCols = `id, kind, name, scope, owner, config, secret_ref, enabled,
	sync_cursor, sync_status, sync_error, synced_at, listing_started_ns, full_listing_ns, reconciled_ns,
	sync_interval_min, sync_started_ns, sync_duration_ms, sync_origin, sync_report, sync_more, synced_ok_ns,
	created_at, created_by, updated_at, updated_by`

// nanos is t as the knowledge tables' *_ns columns hold it: Unix nanoseconds,
// 0 for the zero time. A number, so that "listed before the listing began" is
// an integer comparison rather than one of text whose width varies.
func nanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// fromNanos is nanos reversed.
func fromNanos(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// knowledgeAuditSource is the part of a source every knowledge.source row
// names.
//
// Its credential reference goes in as signs_in_with: the audit redactor blanks
// the value of every key containing "secret" or "credential", and a reference
// is a name — which secret the hub signs in with — not credential material.
func knowledgeAuditSource(row KnowledgeSourceRow) map[string]any {
	return map[string]any{
		"kind": row.Kind, "name": row.Name, "scope": row.Scope, "owner": row.Owner,
	}
}

// configForAudit returns a source's configuration as a JSON value for an audit
// payload, or its text when it does not decode.
func configForAudit(config string) any {
	var v any
	if err := json.Unmarshal([]byte(config), &v); err != nil {
		return config
	}
	return v
}

// CreateKnowledgeSource stores a new source and records it as actor. The id,
// timestamps and the sync columns are the store's; every other field is
// stored as given.
func (d *DB) CreateKnowledgeSource(row KnowledgeSourceRow, actor string) (KnowledgeSourceRow, error) {
	if strings.TrimSpace(row.Kind) == "" || strings.TrimSpace(row.Name) == "" {
		return row, errors.New("statedb: a knowledge source needs a kind and a name")
	}
	if row.Config == "" {
		row.Config = "{}"
	}
	now := time.Now().UTC()
	row.CreatedAt, row.UpdatedAt = now, now
	row.CreatedBy, row.UpdatedBy = actor, actor
	row.SyncCursor, row.SyncStatus, row.SyncError, row.SyncedAt = "", "", "", time.Time{}
	row.SyncReport = "{}"

	d.mu.Lock()
	res, err := d.conn.Exec(`INSERT INTO knowledge_sources
		(kind, name, scope, owner, config, secret_ref, enabled, sync_interval_min,
		 created_at, created_by, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.Kind, row.Name, row.Scope, row.Owner, row.Config, row.SecretRef, boolInt(row.Enabled), row.SyncIntervalMin,
		formatOptionalTime(row.CreatedAt), row.CreatedBy, formatOptionalTime(row.UpdatedAt), row.UpdatedBy)
	var id int64
	if err == nil {
		id, err = res.LastInsertId()
	}
	d.mu.Unlock()
	if err != nil {
		if isUniqueConstraintErr(err) {
			return row, fmt.Errorf("%w: %q", ErrKnowledgeSourceNameTaken, row.Name)
		}
		return row, fmt.Errorf("statedb: create knowledge source: %w", classifyDriverErr(err))
	}
	row.ID = id

	payload := knowledgeAuditSource(row)
	payload["id"] = row.ID
	payload["config"] = configForAudit(row.Config)
	payload["signs_in_with"] = row.SecretRef
	payload["enabled"] = row.Enabled
	payload["sync_interval_minutes"] = row.SyncIntervalMin
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionKnowledgeSourceCreate),
		EntityType: "knowledge_source", EntityID: fmt.Sprint(row.ID), Payload: MarshalAuditPayload(payload),
	})
	return row, nil
}

// KnowledgeSourceUpdate is a change to a source: the fields it may change, the
// names of the ones the request changed (for the audit row), and whether the
// next sync must start over.
type KnowledgeSourceUpdate struct {
	Name      string
	Config    string
	SecretRef string
	Enabled   bool
	// SyncIntervalMin is how often the hub syncs the source, in minutes; 0
	// for the default.
	SyncIntervalMin int
	Changed         []string
	// Resync clears the sync cursor and any full listing in progress, so the
	// next sync lists the source from the beginning — and, reaching the end,
	// removes what the old configuration brought and the new one does not.
	Resync bool
	// ExpectUpdatedAt is the source's UpdatedAt as the change was made from:
	// a source changed since then is refused with ErrKnowledgeSourceChanged,
	// rather than overwritten with the stale copy's other fields.
	ExpectUpdatedAt time.Time
}

// UpdateKnowledgeSource applies u to source id and records it as actor,
// returning the source as stored.
func (d *DB) UpdateKnowledgeSource(id int64, u KnowledgeSourceUpdate, actor string) (KnowledgeSourceRow, error) {
	if strings.TrimSpace(u.Name) == "" {
		return KnowledgeSourceRow{}, errors.New("statedb: a knowledge source needs a name")
	}
	if u.Config == "" {
		u.Config = "{}"
	}
	now := time.Now().UTC()
	d.mu.Lock()
	res, err := d.conn.Exec(`UPDATE knowledge_sources SET
		name = ?, config = ?, secret_ref = ?, enabled = ?, sync_interval_min = ?, updated_at = ?, updated_by = ?,
		sync_cursor = CASE WHEN ? THEN '' ELSE sync_cursor END,
		listing_started_ns = CASE WHEN ? THEN 0 ELSE listing_started_ns END
		WHERE id = ? AND updated_at = ?`,
		u.Name, u.Config, u.SecretRef, boolInt(u.Enabled), u.SyncIntervalMin, formatOptionalTime(now), actor,
		boolInt(u.Resync), boolInt(u.Resync), id, formatOptionalTime(u.ExpectUpdatedAt))
	var n int64
	if err == nil {
		n, err = res.RowsAffected()
	}
	exists := 0
	if err == nil && n == 0 {
		err = d.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_sources WHERE id = ?`, id).Scan(&exists)
	}
	d.mu.Unlock()
	if err != nil {
		if isUniqueConstraintErr(err) {
			return KnowledgeSourceRow{}, fmt.Errorf("%w: %q", ErrKnowledgeSourceNameTaken, u.Name)
		}
		return KnowledgeSourceRow{}, fmt.Errorf("statedb: update knowledge source %d: %w", id, classifyDriverErr(err))
	}
	if n == 0 && exists == 0 {
		return KnowledgeSourceRow{}, fmt.Errorf("%w: %d", ErrKnowledgeSourceNotFound, id)
	}
	if n == 0 {
		return KnowledgeSourceRow{}, fmt.Errorf("%w: source %d", ErrKnowledgeSourceChanged, id)
	}
	row, err := d.GetKnowledgeSource(id)
	if err != nil {
		return row, err
	}
	payload := knowledgeAuditSource(row)
	payload["id"] = row.ID
	payload["changed"] = u.Changed
	payload["config"] = configForAudit(row.Config)
	payload["signs_in_with"] = row.SecretRef
	payload["enabled"] = row.Enabled
	payload["sync_interval_minutes"] = row.SyncIntervalMin
	payload["resync"] = u.Resync
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionKnowledgeSourceUpdate),
		EntityType: "knowledge_source", EntityID: fmt.Sprint(row.ID), Payload: MarshalAuditPayload(payload),
	})
	return row, nil
}

// GetKnowledgeSource returns one source.
func (d *DB) GetKnowledgeSource(id int64) (KnowledgeSourceRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row, err := scanKnowledgeSource(d.conn.QueryRow(`SELECT `+knowledgeSourceCols+` FROM knowledge_sources WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return KnowledgeSourceRow{}, fmt.Errorf("%w: %d", ErrKnowledgeSourceNotFound, id)
	}
	if err != nil {
		return KnowledgeSourceRow{}, fmt.Errorf("statedb: get knowledge source %d: %w", id, classifyDriverErr(err))
	}
	return row, nil
}

// ListKnowledgeSources returns every source, oldest first.
func (d *DB) ListKnowledgeSources() ([]KnowledgeSourceRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + knowledgeSourceCols + ` FROM knowledge_sources ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list knowledge sources: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []KnowledgeSourceRow
	for rows.Next() {
		row, err := scanKnowledgeSource(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: list knowledge sources: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list knowledge sources: %w", classifyDriverErr(err))
	}
	return out, nil
}

func scanKnowledgeSource(s rowScanner) (KnowledgeSourceRow, error) {
	var (
		row                                     KnowledgeSourceRow
		enabled, more                           int
		listingStarted, fullListing, reconciled int64
		started, durationMS, okAt               int64
		syncedAt, createdAt, updated            string
	)
	if err := s.Scan(&row.ID, &row.Kind, &row.Name, &row.Scope, &row.Owner, &row.Config, &row.SecretRef, &enabled,
		&row.SyncCursor, &row.SyncStatus, &row.SyncError, &syncedAt, &listingStarted, &fullListing, &reconciled,
		&row.SyncIntervalMin, &started, &durationMS, &row.SyncOrigin, &row.SyncReport, &more, &okAt,
		&createdAt, &row.CreatedBy, &updated, &row.UpdatedBy); err != nil {
		return row, err
	}
	row.Enabled = enabled != 0
	row.ListingStartedAt = fromNanos(listingStarted)
	row.FullListingAt = fromNanos(fullListing)
	row.ReconciledAt = fromNanos(reconciled)
	row.SyncStartedAt = fromNanos(started)
	row.SyncDuration = time.Duration(durationMS) * time.Millisecond
	row.SyncMore = more != 0
	row.SyncedOKAt = fromNanos(okAt)
	row.SyncedAt = parseOptionalTime(syncedAt)
	row.CreatedAt = parseOptionalTime(createdAt)
	row.UpdatedAt = parseOptionalTime(updated)
	return row, nil
}

// KnowledgeSourceCounts is how much one source holds.
type KnowledgeSourceCounts struct {
	// Documents counts the live documents, tombstones not among them.
	Documents int
	Chunks    int
	Bindings  int
	// Tombstones counts the documents the source no longer holds whose rows
	// are kept until retention purges them (see 0094_knowledge_sync.sql).
	Tombstones int
	// BodyBytes is the text of the live documents, in bytes: what their
	// chunks were made from.
	BodyBytes int64
}

// CountKnowledge returns, per source id, its documents, chunks and bindings —
// of the sources ids names, or of every source when it names none. A source
// with none is absent from the map; rows of a source that no longer exists,
// which a deletion leaves for its purge to finish, are not counted.
func (d *DB) CountKnowledge(ids ...int64) (map[int64]KnowledgeSourceCounts, error) {
	where, arg := "", "[]"
	if len(ids) > 0 {
		b, err := json.Marshal(ids)
		if err != nil {
			return nil, fmt.Errorf("statedb: count knowledge: %w", err)
		}
		where, arg = ` WHERE source_id IN (SELECT value FROM json_each(?))`, string(b)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[int64]KnowledgeSourceCounts{}
	for _, q := range []struct {
		sql string
		set func(c *KnowledgeSourceCounts, n, m, b int64)
	}{
		{`SELECT source_id, COALESCE(SUM(deleted_ns = 0), 0), COALESCE(SUM(deleted_ns > 0), 0),
			COALESCE(SUM(CASE WHEN deleted_ns = 0 THEN body_bytes ELSE 0 END), 0)
			FROM knowledge_documents` + where + ` GROUP BY source_id`,
			func(c *KnowledgeSourceCounts, n, m, b int64) {
				c.Documents, c.Tombstones, c.BodyBytes = int(n), int(m), b
			}},
		{`SELECT source_id, COUNT(*), 0, 0 FROM knowledge_chunks` + where + ` GROUP BY source_id`,
			func(c *KnowledgeSourceCounts, n, _, _ int64) { c.Chunks = int(n) }},
		{`SELECT source_id, COUNT(*), 0, 0 FROM knowledge_bindings` + where + ` GROUP BY source_id`,
			func(c *KnowledgeSourceCounts, n, _, _ int64) { c.Bindings = int(n) }},
	} {
		var args []any
		if where != "" {
			args = append(args, arg)
		}
		rows, err := d.conn.Query(q.sql, args...)
		if err != nil {
			return nil, fmt.Errorf("statedb: count knowledge: %w", classifyDriverErr(err))
		}
		for rows.Next() {
			var id, n, m, b int64
			if err := rows.Scan(&id, &n, &m, &b); err != nil {
				rows.Close()
				return nil, fmt.Errorf("statedb: count knowledge: %w", classifyDriverErr(err))
			}
			c := out[id]
			q.set(&c, n, m, b)
			out[id] = c
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("statedb: count knowledge: %w", classifyDriverErr(err))
		}
	}
	// Rows a deleted source left behind: its purge removes them, and until
	// it has they are nobody's.
	var live map[int64]bool
	if len(out) > 0 {
		live = map[int64]bool{}
		rows, err := d.conn.Query(`SELECT id FROM knowledge_sources`)
		if err != nil {
			return nil, fmt.Errorf("statedb: count knowledge: %w", classifyDriverErr(err))
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, fmt.Errorf("statedb: count knowledge: %w", classifyDriverErr(err))
			}
			live[id] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("statedb: count knowledge: %w", classifyDriverErr(err))
		}
	}
	for id := range out {
		if !live[id] {
			delete(out, id)
		}
	}
	return out, nil
}

// DeleteKnowledgeSource removes a source and everything it brought — its
// documents, their chunks and index entries, its bindings and their matches —
// records it as actor, and returns the source and what went with it.
//
// In two steps. One transaction removes the source, its bindings, their
// matches and its sync lease: from its commit nothing of the source is
// searchable — every search joins through the source and its bindings — and
// no sync can write to it, since every write checks the source is there. Then
// its documents and chunks are purged in bounded transactions
// (purgeKnowledgeOfSource), so a source of a million chunks does not hold the
// database's write lock — and every other hub member's heartbeat behind it —
// for as long as deleting them all takes. A purge cut short, by
// inlineKnowledgePurgeBudget or by the process stopping, leaves the rest to
// the next one: the knowledge sync loop's, or the janitor's (PurgeKnowledge).
// Ids are never reused, so what is left can only ever be the deleted
// source's.
func (d *DB) DeleteKnowledgeSource(id int64, actor string) (KnowledgeSourceRow, KnowledgeSourceCounts, error) {
	d.mu.Lock()
	row, counts, err := d.deleteKnowledgeSourceLocked(id)
	d.mu.Unlock()
	if err != nil {
		return row, counts, err
	}
	payload := knowledgeAuditSource(row)
	payload["id"] = row.ID
	payload["documents"] = counts.Documents
	payload["chunks"] = counts.Chunks
	payload["bindings"] = counts.Bindings
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionKnowledgeSourceDelete),
		EntityType: "knowledge_source", EntityID: fmt.Sprint(row.ID), Payload: MarshalAuditPayload(payload),
	})
	// The source is gone whatever happens here: a purge that fails leaves
	// rows nothing can reach for the next purge, and is no reason to report
	// the deletion failed.
	ctx, cancel := context.WithTimeout(context.Background(), inlineKnowledgePurgeBudget)
	defer cancel()
	_, _ = d.purgeKnowledgeOfSource(ctx, id, false)
	return row, counts, nil
}

func (d *DB) deleteKnowledgeSourceLocked(id int64) (KnowledgeSourceRow, KnowledgeSourceCounts, error) {
	var counts KnowledgeSourceCounts
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: delete knowledge source %d: %w", id, classifyDriverErr(err))
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return KnowledgeSourceRow{}, counts, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	row, err := scanKnowledgeSource(tx.QueryRow(`SELECT `+knowledgeSourceCols+` FROM knowledge_sources WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return KnowledgeSourceRow{}, counts, fmt.Errorf("%w: %d", ErrKnowledgeSourceNotFound, id)
	}
	if err != nil {
		return KnowledgeSourceRow{}, counts, wrapErr(err)
	}
	// What goes with it, counted before anything goes: the documents and
	// chunks are purged after this transaction.
	if err := tx.QueryRow(`SELECT COUNT(*) FROM knowledge_documents WHERE source_id = ? AND deleted_ns = 0`, id).
		Scan(&counts.Documents); err != nil {
		return row, counts, wrapErr(err)
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM knowledge_chunks WHERE source_id = ?`, id).Scan(&counts.Chunks); err != nil {
		return row, counts, wrapErr(err)
	}
	steps := []struct {
		sql string
		n   *int
	}{
		{`DELETE FROM knowledge_binding_documents WHERE binding_id IN (SELECT id FROM knowledge_bindings WHERE source_id = ?)`, nil},
		{`DELETE FROM knowledge_bindings WHERE source_id = ?`, &counts.Bindings},
		{`DELETE FROM knowledge_sync_leases WHERE source_id = ?`, nil},
		{`DELETE FROM knowledge_sources WHERE id = ?`, nil},
	}
	for _, st := range steps {
		res, err := tx.Exec(st.sql, id)
		if err != nil {
			return row, counts, wrapErr(err)
		}
		if st.n != nil {
			n, err := res.RowsAffected()
			if err != nil {
				return row, counts, wrapErr(err)
			}
			*st.n = int(n)
		}
	}
	if err := tx.Commit(); err != nil {
		return row, counts, wrapErr(err)
	}
	return row, counts, nil
}

// SetKnowledgeSyncCursor records where the next sync of source id resumes. It
// is written only while the source is still the one the sync started from —
// updatedAt is the source's UpdatedAt as the sync read it — so a sync that
// outlives a reconfiguration cannot put back the cursor the new configuration
// cleared. ErrKnowledgeSourceChanged reports that case, and a deleted source.
func (d *DB) SetKnowledgeSyncCursor(id int64, updatedAt time.Time, cursor string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`UPDATE knowledge_sources SET sync_cursor = ? WHERE id = ? AND updated_at = ?`,
		cursor, id, formatOptionalTime(updatedAt))
	if err != nil {
		return fmt.Errorf("statedb: record knowledge sync cursor: %w", classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("statedb: record knowledge sync cursor: %w", classifyDriverErr(err))
	} else if n == 0 {
		return fmt.Errorf("%w: source %d", ErrKnowledgeSourceChanged, id)
	}
	return nil
}

// StartKnowledgeListing marks a full listing of source id begun at at: its
// cursor cleared, so the listing starts from the beginning, and at recorded,
// so the documents the listing does not reach can be told apart when it ends —
// in this sync or a later one that resumes it. Written only while the source
// is the one the sync read (updatedAt), like SetKnowledgeSyncCursor.
func (d *DB) StartKnowledgeListing(id int64, updatedAt, at time.Time) error {
	return d.StartKnowledgeListingFenced(KnowledgeSyncFence{}, id, updatedAt, at)
}

// StartKnowledgeListingFenced is StartKnowledgeListing for a sync holding
// f's lease: refused with ErrKnowledgeSyncLeaseLost once it does not.
func (d *DB) StartKnowledgeListingFenced(f KnowledgeSyncFence, id int64, updatedAt, at time.Time) error {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: start knowledge listing: %w", classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	if err := f.checkTx(tx, id); err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE knowledge_sources SET listing_started_ns = ?, sync_cursor = ''
		WHERE id = ? AND updated_at = ?`, nanos(at), id, formatOptionalTime(updatedAt))
	if err != nil {
		return wrapErr(err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return wrapErr(err)
	} else if n == 0 {
		return fmt.Errorf("%w: source %d", ErrKnowledgeSourceChanged, id)
	}
	if err := tx.Commit(); err != nil {
		return wrapErr(err)
	}
	return nil
}

// FinishKnowledgeListing ends the full listing of source id that began at
// started, at at: every document of the source no sync has listed since
// started — what the source no longer holds, or no longer shows — leaves the
// index, its chunks and matches with it and its row kept as a tombstone, and
// the listing is recorded complete, and as a reconciliation, since its sweep
// is one. Written only while the source is the one the sync read; it returns
// how many documents went.
//
// The sweep takes knowledgeTombstoneBatch documents out per transaction, the
// last of them recording the listing complete, so a sweep that removes most of
// a large source does not hold the write lock until it is done. One cut short
// — the process stopped, the source changed — has removed some of what it
// would have and left the listing in progress, and the next sync, resuming it
// at its end, sweeps the rest.
func (d *DB) FinishKnowledgeListing(id int64, updatedAt, started, at time.Time) (int, error) {
	return d.FinishKnowledgeListingFenced(KnowledgeSyncFence{}, id, updatedAt, started, at)
}

// FinishKnowledgeListingFenced is FinishKnowledgeListing for a sync holding
// f's lease: refused with ErrKnowledgeSyncLeaseLost once it does not.
func (d *DB) FinishKnowledgeListingFenced(f KnowledgeSyncFence, id int64, updatedAt, started, at time.Time) (int, error) {
	total := 0
	for {
		n, done, err := d.finishKnowledgeListingBatch(f, id, updatedAt, started, at)
		total += n
		if err != nil || done {
			return total, err
		}
	}
}

// finishKnowledgeListingBatch is one transaction of FinishKnowledgeListing:
// up to knowledgeTombstoneBatch documents out, and — when they were the last
// — the listing recorded complete.
func (d *DB) finishKnowledgeListingBatch(f KnowledgeSyncFence, id int64, updatedAt, started, at time.Time) (int, bool, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: finish knowledge listing of source %d: %w", id, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, false, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	if err := f.checkTx(tx, id); err != nil {
		return 0, false, err
	}
	var one int
	err = tx.QueryRow(`SELECT 1 FROM knowledge_sources WHERE id = ? AND updated_at = ? AND listing_started_ns = ?`,
		id, formatOptionalTime(updatedAt), nanos(started)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, fmt.Errorf("%w: source %d", ErrKnowledgeSourceChanged, id)
	}
	if err != nil {
		return 0, false, wrapErr(err)
	}
	ids, err := idsTx(tx, `SELECT id FROM knowledge_documents WHERE source_id = ? AND deleted_ns = 0 AND listed_ns < ?
		LIMIT ?`, id, nanos(started), knowledgeTombstoneBatch)
	if err != nil {
		return 0, false, wrapErr(err)
	}
	n := 0
	if len(ids) > 0 {
		if n, err = tombstoneKnowledgeDocumentsTx(tx, id, at, `id IN (SELECT value FROM json_each(?))`, jsonIDs(ids)); err != nil {
			return 0, false, wrapErr(err)
		}
	}
	done := len(ids) < knowledgeTombstoneBatch
	if done {
		if _, err := tx.Exec(`UPDATE knowledge_sources SET listing_started_ns = 0, full_listing_ns = ?, reconciled_ns = ?
			WHERE id = ?`, nanos(at), nanos(at), id); err != nil {
			return 0, false, wrapErr(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, false, wrapErr(err)
	}
	return n, done, nil
}

// ReconcileKnowledgeDocuments reconciles source id's documents with present,
// the external ids of every document its remote holds in scope now, as its
// connector reported them at at: each document of the source that present
// does not name leaves the index, its chunks and matches with it and its row
// kept as a tombstone — unless a sync listed it at or after listedBefore,
// which keeps a document a listing just indexed from being removed by an
// answer older than it (a search index that has not caught up yet). The
// reconciliation is recorded at at. Written only while the source is the one
// the sync read and no full listing of it is in progress, whose own sweep is
// the one to remove what it did not reach; ErrKnowledgeSourceChanged reports
// either. It returns how many documents went.
//
// Which documents go is read once; they are then taken out
// knowledgeTombstoneBatch per transaction, each checking again that the
// source has not changed and that the document still qualifies, and the last
// recording the reconciliation. One cut short records nothing, so the next
// sync reconciles again.
func (d *DB) ReconcileKnowledgeDocuments(id int64, updatedAt time.Time, present []string, listedBefore, at time.Time) (int, error) {
	return d.ReconcileKnowledgeDocumentsFenced(KnowledgeSyncFence{}, id, updatedAt, present, listedBefore, at)
}

// ReconcileKnowledgeDocumentsFenced is ReconcileKnowledgeDocuments for a sync
// holding f's lease: refused with ErrKnowledgeSyncLeaseLost once it does not.
func (d *DB) ReconcileKnowledgeDocumentsFenced(f KnowledgeSyncFence, id int64, updatedAt time.Time, present []string,
	listedBefore, at time.Time) (int, error) {
	ids, err := json.Marshal(present)
	if err != nil {
		return 0, fmt.Errorf("statedb: reconcile knowledge documents of source %d: %w", id, err)
	}
	if present == nil {
		ids = []byte("[]")
	}
	d.mu.Lock()
	doomed, err := func() ([]int64, error) {
		rows, err := d.conn.Query(`SELECT id FROM knowledge_documents
			WHERE source_id = ? AND deleted_ns = 0 AND listed_ns < ?
			  AND external_id NOT IN (SELECT value FROM json_each(?))`, id, nanos(listedBefore), string(ids))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []int64
		for rows.Next() {
			var doc int64
			if err := rows.Scan(&doc); err != nil {
				return nil, err
			}
			out = append(out, doc)
		}
		return out, rows.Err()
	}()
	d.mu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("statedb: reconcile knowledge documents of source %d: %w", id, classifyDriverErr(err))
	}
	total := 0
	for start := 0; ; start += knowledgeTombstoneBatch {
		end := min(start+knowledgeTombstoneBatch, len(doomed))
		last := end == len(doomed)
		n, err := d.reconcileKnowledgeBatch(f, id, updatedAt, doomed[start:end], listedBefore, at, last)
		total += n
		if err != nil || last {
			return total, err
		}
	}
}

// reconcileKnowledgeBatch is one transaction of a reconciliation: docs out —
// those still live and listed before listedBefore — and, when last, the
// reconciliation recorded.
func (d *DB) reconcileKnowledgeBatch(f KnowledgeSyncFence, id int64, updatedAt time.Time, docs []int64,
	listedBefore, at time.Time, last bool) (int, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: reconcile knowledge documents of source %d: %w", id, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	if err := f.checkTx(tx, id); err != nil {
		return 0, err
	}
	var one int
	err = tx.QueryRow(`SELECT 1 FROM knowledge_sources WHERE id = ? AND updated_at = ? AND listing_started_ns = 0`,
		id, formatOptionalTime(updatedAt)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: source %d", ErrKnowledgeSourceChanged, id)
	}
	if err != nil {
		return 0, wrapErr(err)
	}
	n := 0
	if len(docs) > 0 {
		if n, err = tombstoneKnowledgeDocumentsTx(tx, id, at, `listed_ns < ? AND id IN (SELECT value FROM json_each(?))`,
			nanos(listedBefore), jsonIDs(docs)); err != nil {
			return 0, wrapErr(err)
		}
	}
	if last {
		if _, err := tx.Exec(`UPDATE knowledge_sources SET reconciled_ns = ? WHERE id = ?`, nanos(at), id); err != nil {
			return 0, wrapErr(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, wrapErr(err)
	}
	return n, nil
}

// RecordKnowledgeSync records how a sync of source id ended: status ok or
// error, the error's text (empty on success), and when.
func (d *DB) RecordKnowledgeSync(id int64, status, errText string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`UPDATE knowledge_sources SET sync_status = ?, sync_error = ?, synced_at = ? WHERE id = ?`,
		status, errText, formatOptionalTime(at), id)
	if err != nil {
		return fmt.Errorf("statedb: record knowledge sync: %w", classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("statedb: record knowledge sync: %w", classifyDriverErr(err))
	} else if n == 0 {
		return fmt.Errorf("%w: %d", ErrKnowledgeSourceNotFound, id)
	}
	return nil
}

// ── Bindings ────────────────────────────────────────────────────────────────

// KnowledgeBindingRow is one row of knowledge_bindings.
type KnowledgeBindingRow struct {
	ID          int64
	SourceID    int64
	ProjectPath string
	// Spaces narrows the binding to documents in these space keys; empty
	// admits every space.
	Spaces []string
	// Query narrows it to the documents its source's connector reported as
	// matching this connector-native query at the last sync; empty admits
	// every document.
	Query string
	// NarrowedAt is when a sync last recorded which documents match Query;
	// zero when none has since it was set.
	NarrowedAt time.Time
	CreatedAt  time.Time
	CreatedBy  string
	UpdatedAt  time.Time
	UpdatedBy  string
}

const knowledgeBindingCols = `id, source_id, project_path, spaces, query, narrowed_at,
	created_at, created_by, updated_at, updated_by`

func scanKnowledgeBinding(s rowScanner) (KnowledgeBindingRow, error) {
	var (
		row                          KnowledgeBindingRow
		spaces, narrowed, created, u string
	)
	if err := s.Scan(&row.ID, &row.SourceID, &row.ProjectPath, &spaces, &row.Query, &narrowed,
		&created, &row.CreatedBy, &u, &row.UpdatedBy); err != nil {
		return row, err
	}
	if err := json.Unmarshal([]byte(spaces), &row.Spaces); err != nil {
		// A narrowing this build cannot read must not read as "no narrowing":
		// a binding nobody can interpret serves nothing.
		return row, fmt.Errorf("%w: binding %d has unreadable spaces %q", ErrSchemaMismatch, row.ID, spaces)
	}
	row.NarrowedAt = parseOptionalTime(narrowed)
	row.CreatedAt = parseOptionalTime(created)
	row.UpdatedAt = parseOptionalTime(u)
	return row, nil
}

// spacesColumn renders a binding's spaces as the column stores them: a JSON
// array, sorted and without duplicates, "[]" for none.
func spacesColumn(spaces []string) string {
	set := map[string]bool{}
	var out []string
	for _, s := range spaces {
		if s != "" && !set[s] {
			set[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "[]"
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// PutKnowledgeBinding binds source row.SourceID to project row.ProjectPath, or
// changes the narrowing of the binding the pair already has, and records it as
// actor. created reports which. A changed query forgets which documents
// matched the old one: the binding serves nothing it narrows until the next
// sync has asked the connector about the new one.
func (d *DB) PutKnowledgeBinding(row KnowledgeBindingRow, actor string) (KnowledgeBindingRow, bool, error) {
	if strings.TrimSpace(row.ProjectPath) == "" {
		return row, false, errors.New("statedb: a knowledge binding needs a project")
	}
	d.mu.Lock()
	out, created, src, err := d.putKnowledgeBindingLocked(row, actor)
	d.mu.Unlock()
	if err != nil {
		return out, false, err
	}
	payload := knowledgeAuditSource(src)
	payload["source_id"] = out.SourceID
	payload["binding_id"] = out.ID
	payload["project"] = out.ProjectPath
	payload["spaces"] = out.Spaces
	payload["query"] = out.Query
	payload["created"] = created
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionKnowledgeSourceBind),
		EntityType: "knowledge_source", EntityID: fmt.Sprint(out.SourceID), Payload: MarshalAuditPayload(payload),
	})
	return out, created, nil
}

func (d *DB) putKnowledgeBindingLocked(row KnowledgeBindingRow, actor string) (KnowledgeBindingRow, bool, KnowledgeSourceRow, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: bind knowledge source %d: %w", row.SourceID, classifyDriverErr(err))
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return row, false, KnowledgeSourceRow{}, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	src, err := scanKnowledgeSource(tx.QueryRow(`SELECT `+knowledgeSourceCols+` FROM knowledge_sources WHERE id = ?`, row.SourceID))
	if errors.Is(err, sql.ErrNoRows) {
		return row, false, src, fmt.Errorf("%w: %d", ErrKnowledgeSourceNotFound, row.SourceID)
	}
	if err != nil {
		return row, false, src, wrapErr(err)
	}
	var (
		prevID    int64
		prevQuery string
	)
	err = tx.QueryRow(`SELECT id, query FROM knowledge_bindings WHERE source_id = ? AND project_path = ?`,
		row.SourceID, row.ProjectPath).Scan(&prevID, &prevQuery)
	existed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return row, false, src, wrapErr(err)
	}
	now := formatOptionalTime(time.Now().UTC())
	var id int64
	err = tx.QueryRow(`INSERT INTO knowledge_bindings
		(source_id, project_path, spaces, query, narrowed_at, created_at, created_by, updated_at, updated_by)
		VALUES (?, ?, ?, ?, '', ?, ?, ?, ?)
		ON CONFLICT(source_id, project_path) DO UPDATE SET
		  spaces      = excluded.spaces,
		  query       = excluded.query,
		  narrowed_at = CASE WHEN knowledge_bindings.query = excluded.query
		                     THEN knowledge_bindings.narrowed_at ELSE '' END,
		  updated_at  = excluded.updated_at,
		  updated_by  = excluded.updated_by
		RETURNING id`,
		row.SourceID, row.ProjectPath, spacesColumn(row.Spaces), row.Query, now, actor, now, actor).Scan(&id)
	if err != nil {
		return row, false, src, wrapErr(err)
	}
	if existed && prevQuery != row.Query {
		if _, err := tx.Exec(`DELETE FROM knowledge_binding_documents WHERE binding_id = ?`, prevID); err != nil {
			return row, false, src, wrapErr(err)
		}
	}
	out, err := scanKnowledgeBinding(tx.QueryRow(`SELECT `+knowledgeBindingCols+` FROM knowledge_bindings WHERE id = ?`, id))
	if err != nil {
		return row, false, src, wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return row, false, src, wrapErr(err)
	}
	return out, !existed, src, nil
}

// GetKnowledgeBinding returns one binding.
func (d *DB) GetKnowledgeBinding(id int64) (KnowledgeBindingRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row, err := scanKnowledgeBinding(d.conn.QueryRow(`SELECT `+knowledgeBindingCols+` FROM knowledge_bindings WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return KnowledgeBindingRow{}, fmt.Errorf("%w: %d", ErrKnowledgeBindingNotFound, id)
	}
	if err != nil {
		return KnowledgeBindingRow{}, fmt.Errorf("statedb: get knowledge binding %d: %w", id, classifyDriverErr(err))
	}
	return row, nil
}

// KnowledgeBindingFilter narrows ListKnowledgeBindings. Zero fields match
// everything.
type KnowledgeBindingFilter struct {
	SourceID    int64
	ProjectPath string
}

// ListKnowledgeBindings returns the bindings f matches, oldest first.
func (d *DB) ListKnowledgeBindings(f KnowledgeBindingFilter) ([]KnowledgeBindingRow, error) {
	q := `SELECT ` + knowledgeBindingCols + ` FROM knowledge_bindings`
	var (
		where []string
		args  []any
	)
	if f.SourceID != 0 {
		where = append(where, "source_id = ?")
		args = append(args, f.SourceID)
	}
	if f.ProjectPath != "" {
		where = append(where, "project_path = ?")
		args = append(args, f.ProjectPath)
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id"
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list knowledge bindings: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []KnowledgeBindingRow
	for rows.Next() {
		row, err := scanKnowledgeBinding(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: list knowledge bindings: %w", classifyDriverErr(err))
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list knowledge bindings: %w", classifyDriverErr(err))
	}
	return out, nil
}

// DeleteKnowledgeBinding removes binding id, with the matches a sync recorded
// for it, records it as actor, and returns the binding as it was.
func (d *DB) DeleteKnowledgeBinding(id int64, actor string) (KnowledgeBindingRow, error) {
	d.mu.Lock()
	row, src, err := d.deleteKnowledgeBindingLocked(id)
	d.mu.Unlock()
	if err != nil {
		return row, err
	}
	payload := knowledgeAuditSource(src)
	payload["source_id"] = row.SourceID
	payload["binding_id"] = row.ID
	payload["project"] = row.ProjectPath
	emit(d, &AuditEvent{
		Actor: actorOrSystem(actor), EventType: string(auditaction.ActionKnowledgeSourceUnbind),
		EntityType: "knowledge_source", EntityID: fmt.Sprint(row.SourceID), Payload: MarshalAuditPayload(payload),
	})
	return row, nil
}

func (d *DB) deleteKnowledgeBindingLocked(id int64) (KnowledgeBindingRow, KnowledgeSourceRow, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: delete knowledge binding %d: %w", id, classifyDriverErr(err))
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return KnowledgeBindingRow{}, KnowledgeSourceRow{}, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	row, err := scanKnowledgeBinding(tx.QueryRow(`SELECT `+knowledgeBindingCols+` FROM knowledge_bindings WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return row, KnowledgeSourceRow{}, fmt.Errorf("%w: %d", ErrKnowledgeBindingNotFound, id)
	}
	if err != nil {
		return row, KnowledgeSourceRow{}, wrapErr(err)
	}
	// The source is read for the audit row; a binding outliving its source
	// cannot happen through this file, and is no reason to keep the binding.
	src, err := scanKnowledgeSource(tx.QueryRow(`SELECT `+knowledgeSourceCols+` FROM knowledge_sources WHERE id = ?`, row.SourceID))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return row, src, wrapErr(err)
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_binding_documents WHERE binding_id = ?`, id); err != nil {
		return row, src, wrapErr(err)
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_bindings WHERE id = ?`, id); err != nil {
		return row, src, wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return row, src, wrapErr(err)
	}
	return row, src, nil
}

// DeleteKnowledgeBindingsOfProject removes every binding of the project at
// projectPath, with the matches recorded for them, and records each as actor,
// reason saying why. It returns how many went.
//
// A project removed from the hub must take its bindings with it: they are
// keyed by path, and a binding that outlived its project would give whatever
// is registered at that path next the knowledge bound to the old one.
func (d *DB) DeleteKnowledgeBindingsOfProject(projectPath, actor, reason string) (int, error) {
	if strings.TrimSpace(projectPath) == "" {
		return 0, errors.New("statedb: dropping knowledge bindings needs a project")
	}
	d.mu.Lock()
	gone, sources, err := d.deleteKnowledgeBindingsOfProjectLocked(projectPath)
	d.mu.Unlock()
	if err != nil {
		return 0, err
	}
	for _, b := range gone {
		payload := knowledgeAuditSource(sources[b.SourceID])
		payload["source_id"] = b.SourceID
		payload["binding_id"] = b.ID
		payload["project"] = b.ProjectPath
		payload["reason"] = reason
		emit(d, &AuditEvent{
			Actor: actorOrSystem(actor), EventType: string(auditaction.ActionKnowledgeSourceUnbind),
			EntityType: "knowledge_source", EntityID: fmt.Sprint(b.SourceID), Payload: MarshalAuditPayload(payload),
		})
	}
	return len(gone), nil
}

func (d *DB) deleteKnowledgeBindingsOfProjectLocked(projectPath string) ([]KnowledgeBindingRow, map[int64]KnowledgeSourceRow, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: drop the knowledge bindings of %s: %w", projectPath, classifyDriverErr(err))
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return nil, nil, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	rows, err := tx.Query(`SELECT `+knowledgeBindingCols+` FROM knowledge_bindings WHERE project_path = ? ORDER BY id`, projectPath)
	if err != nil {
		return nil, nil, wrapErr(err)
	}
	var gone []KnowledgeBindingRow
	for rows.Next() {
		b, err := scanKnowledgeBinding(rows)
		if err != nil {
			rows.Close()
			return nil, nil, wrapErr(err)
		}
		gone = append(gone, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, wrapErr(err)
	}
	sources := map[int64]KnowledgeSourceRow{}
	for _, b := range gone {
		if _, ok := sources[b.SourceID]; ok {
			continue
		}
		src, err := scanKnowledgeSource(tx.QueryRow(`SELECT `+knowledgeSourceCols+` FROM knowledge_sources WHERE id = ?`, b.SourceID))
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, wrapErr(err)
		}
		sources[b.SourceID] = src
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_binding_documents WHERE binding_id IN
		(SELECT id FROM knowledge_bindings WHERE project_path = ?)`, projectPath); err != nil {
		return nil, nil, wrapErr(err)
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_bindings WHERE project_path = ?`, projectPath); err != nil {
		return nil, nil, wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, wrapErr(err)
	}
	return gone, sources, nil
}

// SetKnowledgeBindingDocuments records which documents of the binding's source
// match the binding's query, by their external ids — the connector's answer at
// a sync — replacing the previous answer. query is the query that answer is
// for: if the binding's query has changed since, ErrKnowledgeBindingChanged is
// returned and nothing is written, so a sync never attaches an old query's
// matches to a new one.
func (d *DB) SetKnowledgeBindingDocuments(bindingID int64, query string, externalIDs []string, at time.Time) error {
	return d.SetKnowledgeBindingDocumentsFenced(KnowledgeSyncFence{}, bindingID, query, externalIDs, at)
}

// SetKnowledgeBindingDocumentsFenced is SetKnowledgeBindingDocuments for a
// sync holding f's lease of the binding's source: refused once it does not,
// so a sync that stalled past its lease cannot put back the matches the one
// that took over cleared.
func (d *DB) SetKnowledgeBindingDocumentsFenced(f KnowledgeSyncFence, bindingID int64, query string, externalIDs []string,
	at time.Time) error {
	ids, err := json.Marshal(externalIDs)
	if err != nil {
		return fmt.Errorf("statedb: record knowledge binding matches: %w", err)
	}
	if externalIDs == nil {
		ids = []byte("[]")
	}
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: record knowledge binding %d matches: %w", bindingID, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	var (
		sourceID int64
		current  string
	)
	err = tx.QueryRow(`SELECT source_id, query FROM knowledge_bindings WHERE id = ?`, bindingID).Scan(&sourceID, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %d", ErrKnowledgeBindingNotFound, bindingID)
	}
	if err != nil {
		return wrapErr(err)
	}
	if err := f.checkTx(tx, sourceID); err != nil {
		return err
	}
	if current != query {
		return fmt.Errorf("%w: binding %d", ErrKnowledgeBindingChanged, bindingID)
	}
	// The new answer first, then whatever the old one had that it does not.
	if _, err := tx.Exec(`INSERT INTO knowledge_binding_documents (binding_id, document_id)
		SELECT ?, id FROM knowledge_documents
		WHERE source_id = ? AND deleted_ns = 0 AND external_id IN (SELECT value FROM json_each(?))
		ON CONFLICT(binding_id, document_id) DO NOTHING`, bindingID, sourceID, string(ids)); err != nil {
		return wrapErr(err)
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_binding_documents
		WHERE binding_id = ? AND document_id NOT IN (
		  SELECT id FROM knowledge_documents
		  WHERE source_id = ? AND deleted_ns = 0 AND external_id IN (SELECT value FROM json_each(?)))`,
		bindingID, sourceID, string(ids)); err != nil {
		return wrapErr(err)
	}
	if _, err := tx.Exec(`UPDATE knowledge_bindings SET narrowed_at = ? WHERE id = ?`,
		formatOptionalTime(at), bindingID); err != nil {
		return wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return wrapErr(err)
	}
	return nil
}

// ClearKnowledgeBindingDocuments forgets which documents match binding id's
// query, so the binding serves nothing it narrows until a sync answers again:
// what a sync does when it could not ask the connector, rather than keep an
// answer it can no longer vouch for.
func (d *DB) ClearKnowledgeBindingDocuments(id int64) error {
	return d.ClearKnowledgeBindingDocumentsFenced(KnowledgeSyncFence{}, id)
}

// ClearKnowledgeBindingDocumentsFenced is ClearKnowledgeBindingDocuments for
// a sync holding f's lease of the binding's source: refused once it does not,
// so a sync that stalled past its lease cannot clear the answer the one that
// took over recorded.
func (d *DB) ClearKnowledgeBindingDocumentsFenced(f KnowledgeSyncFence, id int64) error {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: clear knowledge binding %d matches: %w", id, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	if f.Holder != "" || !f.Version.IsZero() {
		var sourceID int64
		err := tx.QueryRow(`SELECT source_id FROM knowledge_bindings WHERE id = ?`, id).Scan(&sourceID)
		if errors.Is(err, sql.ErrNoRows) {
			// Gone since it was read: nothing of it to clear.
			return nil
		}
		if err != nil {
			return wrapErr(err)
		}
		if err := f.checkTx(tx, sourceID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_binding_documents WHERE binding_id = ?`, id); err != nil {
		return wrapErr(err)
	}
	if _, err := tx.Exec(`UPDATE knowledge_bindings SET narrowed_at = '' WHERE id = ?`, id); err != nil {
		return wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return wrapErr(err)
	}
	return nil
}

// ── Documents and chunks ────────────────────────────────────────────────────

// KnowledgeDocumentRow is one row of knowledge_documents.
type KnowledgeDocumentRow struct {
	ID              int64
	SourceID        int64
	ExternalID      string
	Title           string
	URL             string
	SpaceKey        string
	RemoteUpdatedAt time.Time
	// ACL is the source's access hints for the document, as the connector
	// reported them.
	ACL []string
	// Ancestors are the titles of what holds the document at its source,
	// outermost first, for a citation to place it by.
	Ancestors []string
	// ContentHash identifies what the chunks were made from; a document
	// indexed again with the same hash keeps its chunks.
	ContentHash string
	BodyBytes   int
	Truncated   bool
	ChunkCount  int
	IndexedAt   time.Time
	// ListedAt is when a sync last listed the document; a full listing that
	// ends removes the documents it did not list.
	ListedAt time.Time
}

// KnowledgeChunk is one chunk of a document, in order.
type KnowledgeChunk struct {
	Heading string
	Text    string
	Tokens  int
}

// KnowledgeIndexOutcome says what IndexKnowledgeDocument did.
type KnowledgeIndexOutcome string

const (
	// KnowledgeIndexCreated: the document was new.
	KnowledgeIndexCreated KnowledgeIndexOutcome = "created"
	// KnowledgeIndexUpdated: its content changed and its chunks were
	// rewritten.
	KnowledgeIndexUpdated KnowledgeIndexOutcome = "updated"
	// KnowledgeIndexUnchanged: its content hash matched; only its metadata
	// (URL, space, ACL hints, ancestors, the remote's timestamp) was written.
	KnowledgeIndexUnchanged KnowledgeIndexOutcome = "unchanged"
)

// IndexKnowledgeDocument stores doc and, unless its content hash is the one
// already stored, makes chunk's result its chunks: the chunks it had at the
// same positions are rewritten in place, new ones added, and the ones past the
// end removed, all in one transaction with their full-text entries.
//
// chunk is called only when the hash differs, inside the transaction, so a
// document whose content is unchanged is never chunked again — not even when
// two writers index it at once. It returns the chunks and whether they stop
// short of the document, which marks it truncated. It must not use this DB:
// the handle's lock is held while it runs.
//
// A document that comes back after it was deleted — its tombstone still kept
// — is indexed in its tombstone's row, keeping its id, and counts as created.
func (d *DB) IndexKnowledgeDocument(doc KnowledgeDocumentRow, chunk func() ([]KnowledgeChunk, bool)) (KnowledgeIndexOutcome, error) {
	if strings.TrimSpace(doc.ExternalID) == "" {
		return "", errors.New("statedb: a knowledge document needs an external id")
	}
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: index knowledge document %q: %w", doc.ExternalID, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return "", wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed

	var one int
	if err := tx.QueryRow(`SELECT 1 FROM knowledge_sources WHERE id = ?`, doc.SourceID).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%w: %d", ErrKnowledgeSourceNotFound, doc.SourceID)
		}
		return "", wrapErr(err)
	}
	outcome, err := indexKnowledgeDocumentTx(tx, doc, chunk)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", wrapErr(err)
	}
	return outcome, nil
}

// indexKnowledgeDocumentTx is IndexKnowledgeDocument's work inside tx, for a
// source the caller has checked exists.
func indexKnowledgeDocumentTx(tx *sql.Tx, doc KnowledgeDocumentRow, chunk func() ([]KnowledgeChunk, bool)) (KnowledgeIndexOutcome, error) {
	if strings.TrimSpace(doc.ExternalID) == "" {
		return "", errors.New("statedb: a knowledge document needs an external id")
	}
	acl := jsonStrings(doc.ACL)
	ancestors := jsonStrings(doc.Ancestors)
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: index knowledge document %q: %w", doc.ExternalID, classifyDriverErr(err))
	}
	var (
		docID    int64
		prevHash string
		prevGone int64
	)
	err := tx.QueryRow(`SELECT id, content_hash, deleted_ns FROM knowledge_documents WHERE source_id = ? AND external_id = ?`,
		doc.SourceID, doc.ExternalID).Scan(&docID, &prevHash, &prevGone)
	existed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", wrapErr(err)
	}
	// A tombstone has no content hash, so it never matches one; compared all
	// the same, since an empty hash is a caller's to pass.
	if existed && prevGone == 0 && prevHash == doc.ContentHash {
		if _, err := tx.Exec(`UPDATE knowledge_documents SET
			url = ?, space_key = ?, remote_updated_at = ?, acl = ?, ancestors = ?, listed_ns = ?
			WHERE id = ?`,
			doc.URL, doc.SpaceKey, formatOptionalTime(doc.RemoteUpdatedAt), acl, ancestors, nanos(doc.ListedAt),
			docID); err != nil {
			return "", wrapErr(err)
		}
		return KnowledgeIndexUnchanged, nil
	}

	var chunks []KnowledgeChunk
	if chunk != nil {
		var short bool
		chunks, short = chunk()
		doc.Truncated = doc.Truncated || short
	}
	if len(chunks) > maxKnowledgeChunks {
		return "", fmt.Errorf("statedb: knowledge document %q has %d chunks, more than %d",
			doc.ExternalID, len(chunks), maxKnowledgeChunks)
	}
	now := formatOptionalTime(time.Now().UTC())
	err = tx.QueryRow(`INSERT INTO knowledge_documents
		(source_id, external_id, title, url, space_key, remote_updated_at, acl, ancestors, content_hash,
		 body_bytes, truncated, chunk_count, indexed_at, listed_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source_id, external_id) DO UPDATE SET
		  title             = excluded.title,
		  url               = excluded.url,
		  space_key         = excluded.space_key,
		  remote_updated_at = excluded.remote_updated_at,
		  acl               = excluded.acl,
		  ancestors         = excluded.ancestors,
		  content_hash      = excluded.content_hash,
		  body_bytes        = excluded.body_bytes,
		  truncated         = excluded.truncated,
		  chunk_count       = excluded.chunk_count,
		  indexed_at        = excluded.indexed_at,
		  listed_ns         = excluded.listed_ns,
		  deleted_ns        = 0
		RETURNING id`,
		doc.SourceID, doc.ExternalID, doc.Title, doc.URL, doc.SpaceKey, formatOptionalTime(doc.RemoteUpdatedAt),
		acl, ancestors, doc.ContentHash, doc.BodyBytes, boolInt(doc.Truncated), len(chunks), now,
		nanos(doc.ListedAt)).Scan(&docID)
	if err != nil {
		return "", wrapErr(err)
	}
	if err := writeKnowledgeChunksTx(tx, doc, docID, chunks); err != nil {
		return "", wrapErr(err)
	}
	// What the document no longer has: chunks past its new end.
	if err := dropKnowledgeChunksTx(tx, `document_id = ? AND ordinal >= ?`, docID, len(chunks)); err != nil {
		return "", wrapErr(err)
	}
	// New content has not been matched against any binding's query: a match
	// made for the old content must not admit the new to a project, so the
	// document leaves every query binding until a sync asks the connector
	// about it again.
	if existed {
		if _, err := tx.Exec(`DELETE FROM knowledge_binding_documents WHERE document_id = ?`, docID); err != nil {
			return "", wrapErr(err)
		}
	}
	if existed && prevGone == 0 {
		return KnowledgeIndexUpdated, nil
	}
	return KnowledgeIndexCreated, nil
}

// writeKnowledgeChunksTx upserts chunks at their positions in document docID
// and writes each one's text to the full-text index under the chunk's id.
func writeKnowledgeChunksTx(tx *sql.Tx, doc KnowledgeDocumentRow, docID int64, chunks []KnowledgeChunk) error {
	for i, c := range chunks {
		var chunkID int64
		if err := tx.QueryRow(`INSERT INTO knowledge_chunks (document_id, source_id, ordinal, heading, tokens)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(document_id, ordinal) DO UPDATE SET
			  heading = excluded.heading,
			  tokens  = excluded.tokens
			RETURNING id`, docID, doc.SourceID, i, c.Heading, c.Tokens).Scan(&chunkID); err != nil {
			return err
		}
		// FTS5 has no upsert: rewrite the entry the chunk has, else add one.
		res, err := tx.Exec(`UPDATE knowledge_chunks_fts SET title = ?, heading = ?, body = ? WHERE rowid = ?`,
			doc.Title, c.Heading, c.Text, chunkID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			if _, err := tx.Exec(`INSERT INTO knowledge_chunks_fts (rowid, title, heading, body) VALUES (?, ?, ?, ?)`,
				chunkID, doc.Title, c.Heading, c.Text); err != nil {
				return err
			}
		}
	}
	return nil
}

// dropKnowledgeChunksTx deletes the chunks where matches, with their full-text
// entries and their vectors (knowledge_embeddings.go). where is one of this
// file's own predicates over knowledge_chunks.
func dropKnowledgeChunksTx(tx *sql.Tx, where string, args ...any) error {
	if _, err := tx.Exec(`DELETE FROM knowledge_chunk_embeddings WHERE chunk_id IN (SELECT id FROM knowledge_chunks WHERE `+where+`)`, args...); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_chunks_fts WHERE rowid IN (SELECT id FROM knowledge_chunks WHERE `+where+`)`, args...); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM knowledge_chunks WHERE `+where, args...)
	return err
}

// jsonStrings is a list of strings as the knowledge tables' JSON array
// columns hold it: "[]" for none.
func jsonStrings(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// stringsFromJSON is jsonStrings reversed: nil for a column that is empty or
// does not decode.
func stringsFromJSON(s string) []string {
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil || len(out) == 0 {
		return nil
	}
	return out
}

// GetKnowledgeDocument returns one document of a source; found is false when
// the source does not hold it — a tombstone included.
func (d *DB) GetKnowledgeDocument(sourceID int64, externalID string) (row KnowledgeDocumentRow, found bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var (
		remote, acl, ancestors, indexed string
		truncated                       int
	)
	var listed int64
	err = d.conn.QueryRow(`SELECT id, source_id, external_id, title, url, space_key, remote_updated_at, acl,
		ancestors, content_hash, body_bytes, truncated, chunk_count, indexed_at, listed_ns
		FROM knowledge_documents WHERE source_id = ? AND external_id = ? AND deleted_ns = 0`, sourceID, externalID).Scan(
		&row.ID, &row.SourceID, &row.ExternalID, &row.Title, &row.URL, &row.SpaceKey, &remote, &acl,
		&ancestors, &row.ContentHash, &row.BodyBytes, &truncated, &row.ChunkCount, &indexed, &listed)
	if errors.Is(err, sql.ErrNoRows) {
		return KnowledgeDocumentRow{}, false, nil
	}
	if err != nil {
		return KnowledgeDocumentRow{}, false, fmt.Errorf("statedb: get knowledge document %q: %w", externalID, classifyDriverErr(err))
	}
	row.ACL = stringsFromJSON(acl)
	row.Ancestors = stringsFromJSON(ancestors)
	row.RemoteUpdatedAt = parseOptionalTime(remote)
	row.IndexedAt = parseOptionalTime(indexed)
	row.ListedAt = fromNanos(listed)
	row.Truncated = truncated != 0
	return row, true, nil
}

// DeleteKnowledgeDocument takes one document out of a source's index: its
// chunks, their full-text entries and the bindings' matches of it go, and its
// row is kept as a tombstone (see tombstoneKnowledgeDocumentsTx). found is
// false when the source did not hold it, or held only its tombstone.
func (d *DB) DeleteKnowledgeDocument(sourceID int64, externalID string) (bool, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: delete knowledge document %q of source %d: %w", externalID, sourceID, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	n, err := tombstoneKnowledgeDocumentsTx(tx, sourceID, time.Now(), `external_id = ?`, externalID)
	if err != nil {
		return false, wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return false, wrapErr(err)
	}
	return n > 0, nil
}

// tombstoneKnowledgeDocumentsTx takes, in tx, the live documents of sourceID
// that match out of the index at at: their chunks, full-text entries and
// bindings' matches go, and each row is blanked to a tombstone — deleted_ns
// set, its title, URL, space, access hints, ancestors and content hash
// cleared — keeping only its id and external id until retention purges it.
// What a document said is gone at once; that it was here is kept a while, so
// a citation made before it went still resolves, and a document that comes
// back keeps its id. match is one of this file's own predicates over
// knowledge_documents, taking args; it returns how many documents went.
func tombstoneKnowledgeDocumentsTx(tx *sql.Tx, sourceID int64, at time.Time, match string, args ...any) (int, error) {
	docs := `SELECT id FROM knowledge_documents WHERE source_id = ? AND deleted_ns = 0 AND ` + match
	all := append([]any{sourceID}, args...)
	if err := dropKnowledgeChunksTx(tx, `document_id IN (`+docs+`)`, all...); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_binding_documents WHERE document_id IN (`+docs+`)`, all...); err != nil {
		return 0, err
	}
	res, err := tx.Exec(`UPDATE knowledge_documents SET
		deleted_ns = ?, title = '', url = '', space_key = '', remote_updated_at = '', acl = '[]', ancestors = '[]',
		content_hash = '', body_bytes = 0, truncated = 0, chunk_count = 0
		WHERE source_id = ? AND deleted_ns = 0 AND `+match, append([]any{tombstoneNanos(at)}, all...)...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// tombstoneNanos is at as a tombstone's deleted_ns: never 0, which would
// read as a live document.
func tombstoneNanos(at time.Time) int64 {
	if n := nanos(at); n > 0 {
		return n
	}
	return time.Now().UnixNano()
}

// ── Search ──────────────────────────────────────────────────────────────────

// KnowledgeSearchQuery is one full-text search, as pkg/knowledge built it.
type KnowledgeSearchQuery struct {
	// ProjectPath is the project searching: only sources bound to it are
	// read, through each binding's narrowing.
	ProjectPath string
	// Match is an FTS5 query expression.
	Match string
	// Limit is how many chunks to return, best first.
	Limit int
	// SnippetOpen and SnippetClose surround each matched term in the
	// snippet; SnippetEllipsis marks text left out; SnippetTokens is the
	// snippet's length in tokens (at most 64, as FTS5 allows).
	SnippetOpen, SnippetClose, SnippetEllipsis string
	SnippetTokens                              int
}

// KnowledgeHit is one chunk a search found.
type KnowledgeHit struct {
	ChunkID    int64
	DocumentID int64
	SourceID   int64
	Ordinal    int
	Heading    string
	Title      string
	URL        string
	SpaceKey   string
	ExternalID string
	SourceName string
	SourceKind string
	// Ancestors are the titles of what holds the document at its source,
	// outermost first.
	Ancestors []string
	Snippet   string
	// Rank is FTS5's BM25 score: lower is a better match (it is negative).
	Rank float64
}

// knowledgeSearchSQL ranks the chunks of the sources bound to one project by
// BM25 — a match in the title counts four times one in the body, in a heading
// twice. Each join is what keeps a project inside its own knowledge:
//
//	knowledge_bindings  only sources bound to this project path,
//	deleted_ns          never a tombstone, which has no chunks anyway,
//	spaces              only documents in the binding's space keys, if any,
//	query               only documents a sync recorded as matching the
//	                    binding's query, if it has one,
//	enabled             never a source an administrator switched off.
//
// json_each on a malformed spaces column fails the query rather than reading
// it as "no narrowing".
//
// Two phases. The best LIMIT chunks are ranked first, by id and score alone;
// only then are their snippets made, which FTS5 can do only inside a MATCH, so
// the outer query matches again — one lookup per ranked id: CROSS JOIN keeps
// the planner from putting the full-text scan outside, which would match the
// whole index a second time. Making a snippet is the expensive part, and in
// one phase SQLite makes one for every row that enters the running top LIMIT,
// which for a common word is most of the index.
const knowledgeSearchSQL = `WITH top AS (
  SELECT f.rowid AS id, bm25(knowledge_chunks_fts, 4.0, 2.0, 1.0) AS score
    FROM knowledge_chunks_fts AS f
    JOIN knowledge_chunks AS c ON c.id = f.rowid
    JOIN knowledge_documents AS d ON d.id = c.document_id
    JOIN knowledge_sources AS s ON s.id = c.source_id AND s.enabled = 1
    JOIN knowledge_bindings AS b ON b.source_id = c.source_id AND b.project_path = ?
   WHERE knowledge_chunks_fts MATCH ?
     AND d.deleted_ns = 0
     AND (b.spaces = '[]' OR d.space_key IN (SELECT value FROM json_each(b.spaces)))
     AND (b.query = '' OR EXISTS (SELECT 1 FROM knowledge_binding_documents AS m
                                   WHERE m.binding_id = b.id AND m.document_id = d.id))
   ORDER BY score, f.rowid
   LIMIT ?
)
SELECT c.id, c.document_id, c.source_id, c.ordinal, c.heading,
       d.title, d.url, d.space_key, d.external_id, s.name, s.kind, d.ancestors,
       snippet(knowledge_chunks_fts, 2, ?, ?, ?, ?), top.score
  FROM top
 CROSS JOIN knowledge_chunks_fts ON knowledge_chunks_fts.rowid = top.id
  JOIN knowledge_chunks AS c ON c.id = top.id
  JOIN knowledge_documents AS d ON d.id = c.document_id
  JOIN knowledge_sources AS s ON s.id = c.source_id
 WHERE knowledge_chunks_fts MATCH ?
 ORDER BY top.score, top.id`

// SearchKnowledge runs q and returns the best chunks first. ctx bounds it: a
// cancelled or expired context interrupts SQLite mid-query.
func (d *DB) SearchKnowledge(ctx context.Context, q KnowledgeSearchQuery) ([]KnowledgeHit, error) {
	if strings.TrimSpace(q.ProjectPath) == "" {
		return nil, errors.New("statedb: a knowledge search needs a project")
	}
	if strings.TrimSpace(q.Match) == "" || q.Limit <= 0 {
		return nil, nil
	}
	tokens := q.SnippetTokens
	if tokens <= 0 || tokens > 64 {
		tokens = 24
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.QueryContext(ctx, knowledgeSearchSQL, q.ProjectPath, q.Match, q.Limit,
		q.SnippetOpen, q.SnippetClose, q.SnippetEllipsis, tokens, q.Match)
	if err != nil {
		return nil, knowledgeQueryErr(err)
	}
	defer rows.Close()
	var out []KnowledgeHit
	for rows.Next() {
		var (
			h         KnowledgeHit
			ancestors string
		)
		if err := rows.Scan(&h.ChunkID, &h.DocumentID, &h.SourceID, &h.Ordinal, &h.Heading,
			&h.Title, &h.URL, &h.SpaceKey, &h.ExternalID, &h.SourceName, &h.SourceKind, &ancestors,
			&h.Snippet, &h.Rank); err != nil {
			return nil, knowledgeQueryErr(err)
		}
		h.Ancestors = stringsFromJSON(ancestors)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, knowledgeQueryErr(err)
	}
	return out, nil
}

// knowledgeQueryErr tells a query SQLite could not parse — the caller's
// mistake — from a database that could not answer. The statement itself is
// fixed text, so a parse error can only be the MATCH expression's; FTS5 words
// those as below, not all of them naming FTS5.
func knowledgeQueryErr(err error) error {
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{"fts5", "unterminated string", "syntax error", "unknown special query"} {
		if strings.Contains(msg, marker) {
			return fmt.Errorf("%w: %v", ErrKnowledgeQuery, err)
		}
	}
	return fmt.Errorf("statedb: search knowledge: %w", classifyDriverErr(err))
}

// KnowledgeChunkText returns the stored text of one chunk.
func (d *DB) KnowledgeChunkText(chunkID int64) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var body string
	err := d.conn.QueryRow(`SELECT body FROM knowledge_chunks_fts WHERE rowid = ?`, chunkID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("statedb: knowledge chunk %d not found", chunkID)
	}
	if err != nil {
		return "", fmt.Errorf("statedb: read knowledge chunk %d: %w", chunkID, classifyDriverErr(err))
	}
	return body, nil
}
