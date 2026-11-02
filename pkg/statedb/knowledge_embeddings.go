package statedb

// knowledge_embeddings.go stores the vectors semantic retrieval ranks
// knowledge chunks by (Task 20471; migration 0095).
//
// pkg/knowledge decides what a vector is — which model, made from which text,
// scaled how — and calls these with vectors it has checked. What this file
// guarantees on its own:
//
//   - A vector is current only while its document's content hash is the one
//     it was made under (doc_hash). Nothing has to clear a vector when its
//     document changes, so no writer — this build's or an older one's — can
//     leave a stale one looking current; a search and the embedding pass both
//     compare the hashes.
//   - A chunk's vectors go in the transaction its chunk goes in
//     (dropKnowledgeChunksTx), and a deleted source's are purged with the
//     rest of its rows. Vectors of a chunk an older build dropped, and of a
//     model the hub no longer uses, are purged by PurgeKnowledgeEmbeddings.
//   - A vector is written only for a chunk of the source named, while the
//     writer holds the source's sync lease; nothing replaces a row
//     (tests/arch/rowreplace_test.go): a vector is upserted in place.
//   - A scan of a project's vectors reads only through knowledge_bindings for
//     the project's path, with the same narrowing the full-text search applies.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// maxKnowledgeEmbeddingBatch bounds the chunks one PendingKnowledgeEmbeddings
// or PutKnowledgeEmbeddings call handles.
const maxKnowledgeEmbeddingBatch = 1024

// KnowledgeEmbeddingTodo is one chunk without a current vector of a model.
type KnowledgeEmbeddingTodo struct {
	ChunkID int64
	// DocHash is the chunk's document's content hash, read before its text:
	// a vector made from the text is current while the document keeps it.
	DocHash string
	// Title, Heading and Body are what the chunk says: its document's title,
	// its heading path, its text.
	Title, Heading, Body string
	// TextHash is the text hash of the vector the chunk has of the model —
	// one made before its document last changed — or "" for none. When it
	// matches what the chunk says now, that vector is still the chunk's.
	TextHash string
}

// PendingKnowledgeEmbeddings returns up to limit chunks of source sourceID with
// ids above after, in id order, that have no current vector of model: none at
// all, or one made under another content hash of their document. A pass over
// a source calls it again with the last id it was given, so each call reads on
// from there rather than past every chunk already done.
func (d *DB) PendingKnowledgeEmbeddings(ctx context.Context, sourceID int64, model string, after int64, limit int) ([]KnowledgeEmbeddingTodo, error) {
	if strings.TrimSpace(model) == "" {
		return nil, errors.New("statedb: pending knowledge embeddings need a model")
	}
	if limit <= 0 {
		return nil, nil
	}
	limit = min(limit, maxKnowledgeEmbeddingBatch)
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: find knowledge chunks to embed for source %d: %w", sourceID, classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// Which chunks first, without their text: reading the full-text table's
	// copy of a chunk is the expensive part, and most chunks a pass reads
	// past already have a vector.
	rows, err := d.conn.QueryContext(ctx, `SELECT c.id, d.content_hash, COALESCE(e.text_hash, '')
		  FROM knowledge_chunks AS c
		  JOIN knowledge_documents AS d ON d.id = c.document_id
		  LEFT JOIN knowledge_chunk_embeddings AS e ON e.chunk_id = c.id AND e.model = ?
		 WHERE c.source_id = ? AND c.id > ? AND d.deleted_ns = 0
		   AND (e.chunk_id IS NULL OR e.doc_hash <> d.content_hash)
		 ORDER BY c.id
		 LIMIT ?`, model, sourceID, after, limit)
	if err != nil {
		return nil, wrapErr(err)
	}
	var (
		out []KnowledgeEmbeddingTodo
		ids []int64
	)
	for rows.Next() {
		var t KnowledgeEmbeddingTodo
		if err := rows.Scan(&t.ChunkID, &t.DocHash, &t.TextHash); err != nil {
			rows.Close()
			return nil, wrapErr(err)
		}
		out = append(out, t)
		ids = append(ids, t.ChunkID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, wrapErr(err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	// The text second. A document rewritten in between gives text newer than
	// the hash read above: its vector is then filed under the older hash,
	// which is not current, and the next pass finds the text unchanged and
	// files it under the newer one without asking for it again. Never the
	// other way round, which is why the hash is read first.
	texts, err := d.conn.QueryContext(ctx, `SELECT f.rowid, f.title, f.heading, f.body
		  FROM json_each(?) AS j
		  JOIN knowledge_chunks_fts AS f ON f.rowid = j.value`, jsonIDs(ids))
	if err != nil {
		return nil, wrapErr(err)
	}
	defer texts.Close()
	at := make(map[int64]int, len(out))
	for i, t := range out {
		at[t.ChunkID] = i
	}
	found := make([]bool, len(out))
	for texts.Next() {
		var (
			id                   int64
			title, heading, body string
		)
		if err := texts.Scan(&id, &title, &heading, &body); err != nil {
			return nil, wrapErr(err)
		}
		if i, ok := at[id]; ok {
			out[i].Title, out[i].Heading, out[i].Body = title, heading, body
			found[i] = true
		}
	}
	if err := texts.Err(); err != nil {
		return nil, wrapErr(err)
	}
	// A chunk dropped between the two reads has no text to embed.
	kept := out[:0]
	for i, t := range out {
		if found[i] {
			kept = append(kept, t)
		}
	}
	return kept, nil
}

// KnowledgeEmbedding is one vector to store.
type KnowledgeEmbedding struct {
	ChunkID int64
	// DocHash is the document content hash the chunk's text was read under
	// (KnowledgeEmbeddingTodo.DocHash), TextHash the hash of that text.
	DocHash  string
	TextHash string
	// Vector is the encoded vector, Dims values long. Nil files the vector
	// the chunk already has of the model under DocHash instead — when that
	// vector was made from text with this TextHash, and so still is the
	// chunk's.
	Vector []byte
	Dims   int
}

// KnowledgeEmbeddingWrite says what PutKnowledgeEmbeddings wrote.
type KnowledgeEmbeddingWrite struct {
	// Stored counts the vectors written, Refreshed the vectors filed under
	// their document's new content hash.
	Stored    int
	Refreshed int
}

// PutKnowledgeEmbeddings stores vectors of model for chunks of source
// sourceID in one transaction, while the fence holds, and says what it wrote.
// A vector of a chunk that is no longer the source's is not written, nor a
// refresh of one whose stored vector was made from other text.
func (d *DB) PutKnowledgeEmbeddings(f KnowledgeSyncFence, sourceID int64, model string, rows []KnowledgeEmbedding) (KnowledgeEmbeddingWrite, error) {
	var out KnowledgeEmbeddingWrite
	if strings.TrimSpace(model) == "" {
		return out, errors.New("statedb: knowledge embeddings need a model")
	}
	if len(rows) == 0 {
		return out, nil
	}
	if len(rows) > maxKnowledgeEmbeddingBatch {
		return out, fmt.Errorf("statedb: %d knowledge embeddings in one write, more than %d", len(rows), maxKnowledgeEmbeddingBatch)
	}
	for _, r := range rows {
		if r.Vector != nil && (r.Dims <= 0 || len(r.Vector) != 4*r.Dims) {
			return out, fmt.Errorf("statedb: the vector of knowledge chunk %d is %d bytes, not %d float32 values",
				r.ChunkID, len(r.Vector), r.Dims)
		}
	}
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: store knowledge embeddings of source %d: %w", sourceID, classifyDriverErr(err))
	}
	now := f.Now
	if now.IsZero() {
		now = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return out, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	var one int
	if err := tx.QueryRow(`SELECT 1 FROM knowledge_sources WHERE id = ?`, sourceID).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return out, fmt.Errorf("%w: %d", ErrKnowledgeSourceNotFound, sourceID)
		}
		return out, wrapErr(err)
	}
	if err := f.checkTx(tx, sourceID); err != nil {
		return out, err
	}
	var stored, refreshed int
	for _, r := range rows {
		var res sql.Result
		if r.Vector == nil {
			res, err = tx.Exec(`UPDATE knowledge_chunk_embeddings SET doc_hash = ?
				WHERE chunk_id = ? AND model = ? AND source_id = ? AND text_hash = ?`,
				r.DocHash, r.ChunkID, model, sourceID, r.TextHash)
		} else {
			// The WHERE is what keeps a vector off a chunk that is gone, or
			// another source's; SQLite also needs one there to read the
			// ON CONFLICT that follows as the upsert's.
			res, err = tx.Exec(`INSERT INTO knowledge_chunk_embeddings
				(chunk_id, model, source_id, document_id, dims, vector, text_hash, doc_hash, embedded_ns)
				SELECT c.id, ?, c.source_id, c.document_id, ?, ?, ?, ?, ? FROM knowledge_chunks AS c
				 WHERE c.id = ? AND c.source_id = ?
				ON CONFLICT(chunk_id, model) DO UPDATE SET
				  document_id = excluded.document_id,
				  dims        = excluded.dims,
				  vector      = excluded.vector,
				  text_hash   = excluded.text_hash,
				  doc_hash    = excluded.doc_hash,
				  embedded_ns = excluded.embedded_ns`,
				model, r.Dims, r.Vector, r.TextHash, r.DocHash, nanos(now), r.ChunkID, sourceID)
		}
		if err != nil {
			return out, wrapErr(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return out, wrapErr(err)
		}
		if r.Vector == nil {
			refreshed += int(n)
		} else {
			stored += int(n)
		}
	}
	if err := tx.Commit(); err != nil {
		return out, wrapErr(err)
	}
	out.Stored, out.Refreshed = stored, refreshed
	return out, nil
}

// CountPendingKnowledgeEmbeddings counts the chunks of source sourceID with no
// current vector of model.
func (d *DB) CountPendingKnowledgeEmbeddings(ctx context.Context, sourceID int64, model string) (int, error) {
	if strings.TrimSpace(model) == "" {
		return 0, errors.New("statedb: pending knowledge embeddings need a model")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var n int
	err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*)
		  FROM knowledge_chunks AS c
		  JOIN knowledge_documents AS d ON d.id = c.document_id
		  LEFT JOIN knowledge_chunk_embeddings AS e ON e.chunk_id = c.id AND e.model = ?
		 WHERE c.source_id = ? AND d.deleted_ns = 0
		   AND (e.chunk_id IS NULL OR e.doc_hash <> d.content_hash)`, model, sourceID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("statedb: count knowledge chunks to embed for source %d: %w", sourceID, classifyDriverErr(err))
	}
	return n, nil
}

// KnowledgeVectorQuery is one scan of a project's vectors.
type KnowledgeVectorQuery struct {
	// ProjectPath is the project searching: only sources bound to it are
	// read, through each binding's narrowing.
	ProjectPath string
	// Model and Dims are the query vector's: only vectors of that model and
	// length are read.
	Model string
	Dims  int
	// Limit bounds how many vectors are read.
	Limit int
}

// KnowledgeVectorScan says what a scan read.
type KnowledgeVectorScan struct {
	// Candidates counts the vectors visited.
	Candidates int
	// Capped reports a project whose sources hold more current vectors than
	// Limit: the rest were not read.
	Capped bool
}

// knowledgeVectorSQL reads the current vectors of one model of the sources
// bound to one project, through the joins knowledgeSearchSQL makes — the
// project's own bindings, never a tombstone, the binding's space keys and
// query matches, never a disabled source — and only those made under their
// document's present content hash.
//
// It reaches the document through the vector's own document_id rather than
// through the chunk: one B-tree lookup fewer per vector, on a scan that makes
// one per vector of the project. A chunk is never dropped from a live
// document whose content hash stays the same, so a current vector is always
// a live chunk's; KnowledgeChunkHits, which reads the hits, joins the chunk
// all the same.
const knowledgeVectorSQL = `SELECT e.chunk_id, e.vector
  FROM knowledge_bindings AS b
  JOIN knowledge_sources AS s ON s.id = b.source_id AND s.enabled = 1
  JOIN knowledge_chunk_embeddings AS e ON e.source_id = b.source_id AND e.model = ?
  JOIN knowledge_documents AS d ON d.id = e.document_id AND d.source_id = e.source_id
 WHERE b.project_path = ?
   AND e.dims = ?
   AND d.deleted_ns = 0
   AND e.doc_hash = d.content_hash
   AND (b.spaces = '[]' OR d.space_key IN (SELECT value FROM json_each(b.spaces)))
   AND (b.query = '' OR EXISTS (SELECT 1 FROM knowledge_binding_documents AS m
                                 WHERE m.binding_id = b.id AND m.document_id = d.id))
 LIMIT ?`

// ScanKnowledgeVectors calls visit with each current vector of q.Model the
// sources bound to q.ProjectPath hold, at most q.Limit of them. The vector
// slice is valid only during the call. ctx bounds the scan: a cancelled or
// expired context interrupts SQLite mid-query. An error visit returns stops
// the scan and is returned.
func (d *DB) ScanKnowledgeVectors(ctx context.Context, q KnowledgeVectorQuery, visit func(chunkID int64, vector []byte) error) (KnowledgeVectorScan, error) {
	var out KnowledgeVectorScan
	if strings.TrimSpace(q.ProjectPath) == "" {
		return out, errors.New("statedb: a knowledge vector scan needs a project")
	}
	if strings.TrimSpace(q.Model) == "" || q.Dims <= 0 || q.Limit <= 0 {
		return out, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.QueryContext(ctx, knowledgeVectorSQL, q.Model, q.ProjectPath, q.Dims, q.Limit+1)
	if err != nil {
		return out, fmt.Errorf("statedb: scan knowledge vectors: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	for rows.Next() {
		if out.Candidates == q.Limit {
			out.Capped = true
			break
		}
		var (
			id  int64
			vec sql.RawBytes
		)
		if err := rows.Scan(&id, &vec); err != nil {
			return out, fmt.Errorf("statedb: scan knowledge vectors: %w", classifyDriverErr(err))
		}
		out.Candidates++
		if err := visit(id, vec); err != nil {
			return out, err
		}
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("statedb: scan knowledge vectors: %w", classifyDriverErr(err))
	}
	return out, nil
}

// KnowledgeChunkHit is a chunk a scan found, with what a search result shows
// of it.
type KnowledgeChunkHit struct {
	KnowledgeHit
	// Body is the chunk's text, for a snippet of a chunk found by meaning
	// rather than by its words.
	Body string
}

// KnowledgeChunkHits returns the chunks of ids the sources bound to
// projectPath hold — through each binding's narrowing, as a search reads them
// — with their documents and sources. An id the project cannot read, or that
// is gone, is left out: a binding removed since the scan that found it takes
// the chunk out of the project's results. Order is not ids'.
func (d *DB) KnowledgeChunkHits(ctx context.Context, projectPath string, ids []int64) ([]KnowledgeChunkHit, error) {
	if strings.TrimSpace(projectPath) == "" {
		return nil, errors.New("statedb: knowledge chunk hits need a project")
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > maxKnowledgeEmbeddingBatch {
		return nil, fmt.Errorf("statedb: %d knowledge chunks asked for at once, more than %d", len(ids), maxKnowledgeEmbeddingBatch)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.QueryContext(ctx, `SELECT c.id, c.document_id, c.source_id, c.ordinal, c.heading,
		       d.title, d.url, d.space_key, d.external_id, s.name, s.kind, d.ancestors, f.body
		  FROM json_each(?) AS j
		  JOIN knowledge_chunks AS c ON c.id = j.value
		  JOIN knowledge_documents AS d ON d.id = c.document_id
		  JOIN knowledge_sources AS s ON s.id = c.source_id AND s.enabled = 1
		  JOIN knowledge_bindings AS b ON b.source_id = c.source_id AND b.project_path = ?
		  JOIN knowledge_chunks_fts AS f ON f.rowid = c.id
		 WHERE d.deleted_ns = 0
		   AND (b.spaces = '[]' OR d.space_key IN (SELECT value FROM json_each(b.spaces)))
		   AND (b.query = '' OR EXISTS (SELECT 1 FROM knowledge_binding_documents AS m
		                                 WHERE m.binding_id = b.id AND m.document_id = d.id))`,
		jsonIDs(ids), projectPath)
	if err != nil {
		return nil, fmt.Errorf("statedb: read knowledge chunks: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []KnowledgeChunkHit
	for rows.Next() {
		var (
			h         KnowledgeChunkHit
			ancestors string
		)
		if err := rows.Scan(&h.ChunkID, &h.DocumentID, &h.SourceID, &h.Ordinal, &h.Heading, &h.Title, &h.URL,
			&h.SpaceKey, &h.ExternalID, &h.SourceName, &h.SourceKind, &ancestors, &h.Body); err != nil {
			return nil, fmt.Errorf("statedb: read knowledge chunks: %w", classifyDriverErr(err))
		}
		h.Ancestors = stringsFromJSON(ancestors)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read knowledge chunks: %w", classifyDriverErr(err))
	}
	return out, nil
}

// CountKnowledgeVectors returns, per source id, how many vectors of model the
// source's chunks have — current ones and ones whose document has changed
// since, which the next sync embeds again. A source with none is absent.
func (d *DB) CountKnowledgeVectors(model string) (map[int64]int, error) {
	out := map[int64]int{}
	if strings.TrimSpace(model) == "" {
		return out, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT source_id, COUNT(*) FROM knowledge_chunk_embeddings
		WHERE model = ? AND source_id IN (SELECT id FROM knowledge_sources) GROUP BY source_id`, model)
	if err != nil {
		return nil, fmt.Errorf("statedb: count knowledge vectors: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("statedb: count knowledge vectors: %w", classifyDriverErr(err))
		}
		out[id] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: count knowledge vectors: %w", classifyDriverErr(err))
	}
	return out, nil
}

// KnowledgeEmbeddingPurge says what PurgeKnowledgeEmbeddings removed, or in a
// dry run would have.
type KnowledgeEmbeddingPurge struct {
	// Orphans counts vectors whose chunk is gone: dropped by a build that
	// predates the vectors, which did not know to take them with it.
	Orphans int64 `json:"orphans"`
	// OtherModels counts vectors of a model other than the one kept.
	OtherModels int64 `json:"other_models"`
}

// Rows is how many rows the purge removed.
func (r KnowledgeEmbeddingPurge) Rows() int64 { return r.Orphans + r.OtherModels }

// PurgeKnowledgeEmbeddings removes the vectors no search can use: those whose
// chunk is gone, and — when keepModel is set — those of every other model, in
// transactions of knowledgePurgeBatch rows; ctx stops it between two. A dry
// run counts what it would remove and removes nothing.
func (d *DB) PurgeKnowledgeEmbeddings(ctx context.Context, keepModel string, dryRun bool) (KnowledgeEmbeddingPurge, error) {
	var out KnowledgeEmbeddingPurge
	keepModel = strings.TrimSpace(keepModel)
	type step struct {
		where string
		args  []any
		n     *int64
	}
	steps := []step{{where: `NOT EXISTS (SELECT 1 FROM knowledge_chunks AS c WHERE c.id = e.chunk_id)`, n: &out.Orphans}}
	if keepModel != "" {
		steps = append(steps, step{where: `e.model <> ?`, args: []any{keepModel}, n: &out.OtherModels})
	}
	for _, st := range steps {
		if dryRun {
			d.mu.Lock()
			err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM knowledge_chunk_embeddings AS e WHERE `+st.where,
				st.args...).Scan(st.n)
			d.mu.Unlock()
			if err != nil {
				return out, fmt.Errorf("statedb: count knowledge vectors to purge: %w", classifyDriverErr(err))
			}
			continue
		}
		for {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			n, err := d.purgeKnowledgeEmbeddingBatch(st.where, st.args...)
			*st.n += n
			if err != nil {
				return out, err
			}
			if n < int64(knowledgePurgeBatch) {
				break
			}
		}
	}
	return out, nil
}

// purgeKnowledgeEmbeddingBatch deletes up to knowledgePurgeBatch vectors where
// matches, in one transaction. where is one of PurgeKnowledgeEmbeddings' own
// predicates over knowledge_chunk_embeddings AS e.
func (d *DB) purgeKnowledgeEmbeddingBatch(where string, args ...any) (int64, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("statedb: purge knowledge vectors: %w", classifyDriverErr(err))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, wrapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	ids, err := idsTx(tx, `SELECT e.rowid FROM knowledge_chunk_embeddings AS e WHERE `+where+` LIMIT ?`,
		append(append([]any{}, args...), knowledgePurgeBatch)...)
	if err != nil {
		return 0, wrapErr(err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	res, err := tx.Exec(`DELETE FROM knowledge_chunk_embeddings WHERE rowid IN (SELECT value FROM json_each(?))`, jsonIDs(ids))
	if err != nil {
		return 0, wrapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return 0, wrapErr(err)
	}
	return n, nil
}
