// What a project's runs read of its knowledge (Task 20472): documents looked
// up through the project's bindings, and the hub's record of what each run's
// agent was served.
//
// Every read here joins through knowledge_bindings for one project path, with
// each binding's narrowing, exactly as knowledgeSearchSQL does: a run's
// knowledge session names its project, and nothing it asks for leaves it.

package statedb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProxySessionKnowledge is a run's knowledge session (Task 20472): the bearer
// token a run presents to the hub's run-scoped knowledge search, good for its
// own project's knowledge for as long as the run lives. scope_json is empty;
// project_id names the project, run_id the run.
const ProxySessionKnowledge = "knowledge"

// knowledgeProjectVisible is the predicate that keeps a document read for a
// project inside the project's bindings: an enabled source bound to it,
// never a tombstone, and through the binding's space keys and query
// matches. It expects the aliases d (knowledge_documents), s
// (knowledge_sources) and b (knowledge_bindings, joined on the source and the
// project path).
const knowledgeProjectVisible = `d.deleted_ns = 0
   AND s.enabled = 1
   AND (b.spaces = '[]' OR d.space_key IN (SELECT value FROM json_each(b.spaces)))
   AND (b.query = '' OR EXISTS (SELECT 1 FROM knowledge_binding_documents AS m
                                 WHERE m.binding_id = b.id AND m.document_id = d.id))`

// KnowledgeDocumentLookup names the document a run asks for: by the hub's
// id, by the URL a person reads it at, or by its key at the source — a Jira
// issue key such as ENG-42. Exactly one is set.
type KnowledgeDocumentLookup struct {
	ID  int64
	URL string
	Key string
}

// KnowledgeProjectDocument is one document as a project reads it, with its
// source.
type KnowledgeProjectDocument struct {
	ID         int64
	SourceID   int64
	SourceName string
	SourceKind string
	ExternalID string
	Title      string
	URL        string
	SpaceKey   string
	Ancestors  []string
	// RemoteUpdatedAt is when the source last changed it.
	RemoteUpdatedAt time.Time
	// Truncated reports a body the index cut at its bound.
	Truncated  bool
	ChunkCount int
}

// KnowledgeDocumentChunk is one chunk of a document, in the document's order.
type KnowledgeDocumentChunk struct {
	ID      int64
	Ordinal int
	Heading string
	Text    string
}

// maxKnowledgeLookupDocuments bounds what one lookup returns: a key or a URL
// names one document at most sources, and a few when the same page is
// connected twice.
const maxKnowledgeLookupDocuments = 8

// KnowledgeProjectDocuments returns the documents lookup names that the
// sources bound to projectPath hold, through each binding's narrowing: none
// when the project cannot read it, which is also the answer for a document of
// another project's source. A key matches a document whose title begins with
// it, as a Jira issue's does ("ENG-42 Fix the deploy"), or whose URL ends in
// /browse/<key>.
func (d *DB) KnowledgeProjectDocuments(ctx context.Context, projectPath string, lookup KnowledgeDocumentLookup) ([]KnowledgeProjectDocument, error) {
	if strings.TrimSpace(projectPath) == "" {
		return nil, errors.New("statedb: a knowledge document lookup needs a project")
	}
	var (
		match string
		args  []any
	)
	switch {
	case lookup.ID > 0:
		match, args = "d.id = ?", []any{lookup.ID}
	case strings.TrimSpace(lookup.URL) != "":
		match, args = "d.url = ?", []any{strings.TrimSpace(lookup.URL)}
	case strings.TrimSpace(lookup.Key) != "":
		key := strings.TrimSpace(lookup.Key)
		// substr comparisons rather than LIKE: a key's underscore is a LIKE
		// wildcard, and "ENG-4" must not find "ENG-42".
		match = `(d.title = ? OR substr(d.title, 1, ?) = ? OR substr(d.url, -?) = ?)`
		args = []any{key, len(key) + 1, key + " ", len(key) + len("/browse/"), "/browse/" + key}
	default:
		return nil, errors.New("statedb: a knowledge document lookup names an id, a URL or a key")
	}
	q := `SELECT DISTINCT d.id, d.source_id, s.name, s.kind, d.external_id, d.title, d.url, d.space_key,
	             d.ancestors, d.remote_updated_at, d.truncated, d.chunk_count
	        FROM knowledge_documents AS d
	        JOIN knowledge_sources AS s ON s.id = d.source_id
	        JOIN knowledge_bindings AS b ON b.source_id = d.source_id AND b.project_path = ?
	       WHERE ` + match + `
	         AND ` + knowledgeProjectVisible + `
	       ORDER BY d.id
	       LIMIT ?`
	all := append([]any{projectPath}, args...)
	all = append(all, maxKnowledgeLookupDocuments)
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.QueryContext(ctx, q, all...)
	if err != nil {
		return nil, fmt.Errorf("statedb: look up knowledge documents: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []KnowledgeProjectDocument
	for rows.Next() {
		var (
			doc                KnowledgeProjectDocument
			ancestors, updated string
			truncated          int
		)
		if err := rows.Scan(&doc.ID, &doc.SourceID, &doc.SourceName, &doc.SourceKind, &doc.ExternalID, &doc.Title,
			&doc.URL, &doc.SpaceKey, &ancestors, &updated, &truncated, &doc.ChunkCount); err != nil {
			return nil, fmt.Errorf("statedb: look up knowledge documents: %w", classifyDriverErr(err))
		}
		doc.Ancestors = stringsFromJSON(ancestors)
		doc.Truncated = truncated != 0
		doc.RemoteUpdatedAt = parseOptionalTime(updated)
		out = append(out, doc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: look up knowledge documents: %w", classifyDriverErr(err))
	}
	return out, nil
}

// KnowledgeProjectDocumentChunks returns the chunks of document docID, in
// order, provided the sources bound to projectPath may read it — none
// otherwise. It stops once the texts it read reach maxBytes, and reports
// whether chunks were left out.
func (d *DB) KnowledgeProjectDocumentChunks(ctx context.Context, projectPath string, docID int64, maxBytes int) ([]KnowledgeDocumentChunk, bool, error) {
	if strings.TrimSpace(projectPath) == "" {
		return nil, false, errors.New("statedb: knowledge document chunks need a project")
	}
	if docID <= 0 || maxBytes <= 0 {
		return nil, false, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.QueryContext(ctx, `SELECT c.id, c.ordinal, c.heading, f.body
		  FROM knowledge_chunks AS c
		  JOIN knowledge_documents AS d ON d.id = c.document_id
		  JOIN knowledge_sources AS s ON s.id = c.source_id
		  JOIN knowledge_chunks_fts AS f ON f.rowid = c.id
		 WHERE c.document_id = ?
		   AND EXISTS (SELECT 1 FROM knowledge_bindings AS b
		                WHERE b.source_id = c.source_id AND b.project_path = ?
		                  AND `+knowledgeProjectVisible+`)
		 ORDER BY c.ordinal, c.id`, docID, projectPath)
	if err != nil {
		return nil, false, fmt.Errorf("statedb: read knowledge document %d: %w", docID, classifyDriverErr(err))
	}
	defer rows.Close()
	var (
		out   []KnowledgeDocumentChunk
		total int
		cut   bool
	)
	for rows.Next() {
		if total >= maxBytes {
			cut = true
			break
		}
		var c KnowledgeDocumentChunk
		if err := rows.Scan(&c.ID, &c.Ordinal, &c.Heading, &c.Text); err != nil {
			return nil, false, fmt.Errorf("statedb: read knowledge document %d: %w", docID, classifyDriverErr(err))
		}
		total += len(c.Text)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("statedb: read knowledge document %d: %w", docID, classifyDriverErr(err))
	}
	return out, cut, nil
}

// maxKnowledgeRunReadsPerSession bounds what the hub records of one run's
// reads: past it, a run's agent reads on, and what it read is no longer kept
// for its tasks' citations.
const maxKnowledgeRunReadsPerSession = 2000

// RecordKnowledgeRunReads records that the run whose knowledge session is
// sessionID was served docIDs for task taskID. A document recorded for the
// task already is recorded once.
func (d *DB) RecordKnowledgeRunReads(sessionID string, taskID int, docIDs []int64, at time.Time) error {
	if strings.TrimSpace(sessionID) == "" || len(docIDs) == 0 {
		return nil
	}
	if taskID < 0 {
		taskID = 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: record knowledge reads: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	var have int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM knowledge_run_reads WHERE session_id = ?`, sessionID).Scan(&have); err != nil {
		return fmt.Errorf("statedb: record knowledge reads: %w", classifyDriverErr(err))
	}
	for _, id := range docIDs {
		if have >= maxKnowledgeRunReadsPerSession {
			break
		}
		if id <= 0 {
			continue
		}
		res, err := tx.Exec(`INSERT INTO knowledge_run_reads(session_id, task_id, document_id, read_ns)
			VALUES(?,?,?,?) ON CONFLICT(session_id, task_id, document_id) DO NOTHING`,
			sessionID, taskID, id, at.UnixNano())
		if err != nil {
			return fmt.Errorf("statedb: record knowledge reads: %w", classifyDriverErr(err))
		}
		if n, _ := res.RowsAffected(); n > 0 {
			have++
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: record knowledge reads: %w", classifyDriverErr(err))
	}
	return nil
}

// TakeKnowledgeRunReads returns the documents recorded as read for task
// taskID under knowledge session sessionID, in the order they were first
// read, and forgets them: the run keeps them on the task from here.
func (d *DB) TakeKnowledgeRunReads(sessionID string, taskID int) ([]int64, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("statedb: take knowledge reads: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(`SELECT document_id FROM knowledge_run_reads
		WHERE session_id = ? AND task_id = ? ORDER BY read_ns, document_id`, sessionID, taskID)
	if err != nil {
		return nil, fmt.Errorf("statedb: take knowledge reads: %w", classifyDriverErr(err))
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("statedb: take knowledge reads: %w", classifyDriverErr(err))
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, fmt.Errorf("statedb: take knowledge reads: %w", classifyDriverErr(err))
	}
	if _, err := tx.Exec(`DELETE FROM knowledge_run_reads WHERE session_id = ? AND task_id = ?`, sessionID, taskID); err != nil {
		return nil, fmt.Errorf("statedb: take knowledge reads: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("statedb: take knowledge reads: %w", classifyDriverErr(err))
	}
	return ids, nil
}

// PurgeKnowledgeRunReads forgets the reads of knowledge sessions that are no
// longer open — closed, or retired by the janitor — and any read before
// olderThan, and returns how many rows went. A run collects its tasks' reads
// as each attempt ends; what is left belongs to runs that ended without
// collecting them.
func (d *DB) PurgeKnowledgeRunReads(olderThan time.Time) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM knowledge_run_reads
		WHERE read_ns < ?
		   OR session_id NOT IN (SELECT session_id FROM proxy_sessions WHERE kind = ? AND closed_at = '')`,
		olderThan.UnixNano(), ProxySessionKnowledge)
	if err != nil {
		return 0, fmt.Errorf("statedb: purge knowledge reads: %w", classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
