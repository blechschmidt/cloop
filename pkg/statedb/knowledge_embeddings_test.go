package statedb

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const testModel = "openai/test-embed/4"

// vec encodes values as a stored vector.
func vec(values ...float32) []byte {
	b := make([]byte, 4*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return b
}

// embedAll gives every pending chunk of source id a vector of model, as the
// embedding pass would, and returns how many it wrote.
func embedAll(t *testing.T, db *DB, sourceID int64, model string) int {
	t.Helper()
	todo, err := db.PendingKnowledgeEmbeddings(context.Background(), sourceID, model, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]KnowledgeEmbedding, 0, len(todo))
	for _, td := range todo {
		rows = append(rows, KnowledgeEmbedding{ChunkID: td.ChunkID, DocHash: td.DocHash, TextHash: "t:" + td.Body,
			Vector: vec(1, 0, 0, 0), Dims: 4})
	}
	w, err := db.PutKnowledgeEmbeddings(KnowledgeSyncFence{}, sourceID, model, rows)
	if err != nil {
		t.Fatal(err)
	}
	return w.Stored
}

func scanIDs(t *testing.T, db *DB, project, model string, limit int) ([]int64, KnowledgeVectorScan) {
	t.Helper()
	var ids []int64
	scan, err := db.ScanKnowledgeVectors(context.Background(), KnowledgeVectorQuery{ProjectPath: project, Model: model,
		Dims: 4, Limit: limit}, func(id int64, v []byte) error {
		if len(v) != 16 {
			t.Fatalf("chunk %d's vector is %d bytes", id, len(v))
		}
		ids = append(ids, id)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, scan
}

func chunkIDsOf(t *testing.T, db *DB, sourceID int64, externalID string) []int64 {
	t.Helper()
	ids, err := queryIDs(db, `SELECT c.id FROM knowledge_chunks c JOIN knowledge_documents d ON d.id = c.document_id
		WHERE d.source_id = ? AND d.external_id = ? ORDER BY c.id`, sourceID, externalID)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func queryIDs(db *DB, query string, args ...any) ([]int64, error) {
	rows, err := db.conn.Query(query, args...)
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

func vectorRows(t *testing.T, db *DB) int {
	t.Helper()
	var n int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_chunk_embeddings`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestKnowledgeEmbeddingsMigrationIsAdditive: 0095 adds a table and a plain
// index — nothing a build that knows 0094 reads or trips over — and re-running
// it changes nothing.
func TestKnowledgeEmbeddingsMigrationIsAdditive(t *testing.T) {
	all, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var m migration
	for _, x := range all {
		if x.Version == 95 {
			m = x
		}
	}
	if !strings.Contains(m.Name, "knowledge_embeddings") {
		t.Fatalf("migration 0095 is %q, not the knowledge embeddings migration", m.Name)
	}
	if got := classifyMigration(m.SQL); got != CompatAdditive {
		t.Fatalf("0095 classifies %q; an older hub sharing this control plane would refuse the database", got)
	}
	db := openFresh(t)
	before := knowledgeSchema(t, db)
	for _, want := range []string{"table knowledge_chunk_embeddings", "index idx_knowledge_chunk_embeddings_source",
		"vector      BLOB    NOT NULL", "PRIMARY KEY (chunk_id, model)"} {
		if !strings.Contains(before, want) {
			t.Fatalf("the migrated schema has no %q:\n%s", want, before)
		}
	}
	for _, stmt := range splitStatements(m.SQL) {
		if _, err := db.conn.Exec(stmt); err != nil {
			t.Fatalf("re-running %s: %v", stmt, err)
		}
	}
	if after := knowledgeSchema(t, db); after != before {
		t.Fatalf("re-running 0095 changed the schema:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestKnowledgeEmbeddingsAreCurrentOnlyForTheirContent: a chunk is pending
// until it has a vector of the model; a vector stays current while its
// document keeps the content hash it was made under; a document that changes
// makes its chunks pending again — a refresh files a vector whose text did not
// change under the new hash without a new vector; another model's vectors are
// another model's.
func TestKnowledgeEmbeddingsAreCurrentOnlyForTheirContent(t *testing.T) {
	db := openFresh(t)
	ctx := context.Background()
	src := mustCreateSource(t, db, "wiki", "")
	mustIndex(t, db, src.ID, "p1", "Runbook", "", "h1", "first chunk", "second chunk")
	mustIndex(t, db, src.ID, "p2", "Other", "", "h2", "third chunk")

	todo, err := db.PendingKnowledgeEmbeddings(ctx, src.ID, testModel, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(todo) != 3 || todo[0].Title != "Runbook" || todo[0].Body != "first chunk" || todo[0].DocHash != "h1" ||
		todo[2].Body != "third chunk" || todo[0].TextHash != "" {
		t.Fatalf("pending = %+v", todo)
	}
	// Paged by id: after the first, the rest.
	rest, err := db.PendingKnowledgeEmbeddings(ctx, src.ID, testModel, todo[0].ChunkID, 10)
	if err != nil || len(rest) != 2 || rest[0].ChunkID != todo[1].ChunkID {
		t.Fatalf("pending after %d = %+v, %v", todo[0].ChunkID, rest, err)
	}
	if n := embedAll(t, db, src.ID, testModel); n != 3 {
		t.Fatalf("embedded %d, want 3", n)
	}
	if todo, _ := db.PendingKnowledgeEmbeddings(ctx, src.ID, testModel, 0, 10); len(todo) != 0 {
		t.Fatalf("still pending after embedding: %+v", todo)
	}
	if n, _ := db.CountPendingKnowledgeEmbeddings(ctx, src.ID, testModel); n != 0 {
		t.Fatalf("CountPending = %d", n)
	}
	// Another model has none of them.
	if n, _ := db.CountPendingKnowledgeEmbeddings(ctx, src.ID, "openai/other/4"); n != 3 {
		t.Fatalf("another model's pending = %d, want 3", n)
	}

	// p1 changes: its chunks are rewritten in place, and pending again.
	mustIndex(t, db, src.ID, "p1", "Runbook", "", "h1b", "first chunk", "second chunk, edited")
	todo, err = db.PendingKnowledgeEmbeddings(ctx, src.ID, testModel, 0, 10)
	if err != nil || len(todo) != 2 {
		t.Fatalf("pending after an edit = %+v, %v", todo, err)
	}
	if todo[0].DocHash != "h1b" || todo[0].TextHash != "t:first chunk" {
		t.Fatalf("the edited document's first chunk = %+v; it should carry the new hash and the old vector's text hash", todo[0])
	}
	// The scan no longer offers the stale vectors.
	mustBind(t, db, src.ID, "/srv/a", nil, "")
	if ids, _ := scanIDs(t, db, "/srv/a", testModel, 100); len(ids) != 1 {
		t.Fatalf("the scan offered %v; only p2's vector is current", ids)
	}
	// A refresh with the matching text hash files the first under the new
	// hash; one with another text hash files nothing.
	w, err := db.PutKnowledgeEmbeddings(KnowledgeSyncFence{}, src.ID, testModel, []KnowledgeEmbedding{
		{ChunkID: todo[0].ChunkID, DocHash: "h1b", TextHash: "t:first chunk"},
		{ChunkID: todo[1].ChunkID, DocHash: "h1b", TextHash: "t:second chunk, edited"},
	})
	if err != nil || w.Refreshed != 1 || w.Stored != 0 {
		t.Fatalf("refresh = %+v, %v; want one refreshed", w, err)
	}
	todo, _ = db.PendingKnowledgeEmbeddings(ctx, src.ID, testModel, 0, 10)
	if len(todo) != 1 || todo[0].Body != "second chunk, edited" {
		t.Fatalf("pending after the refresh = %+v", todo)
	}
	// A vector of the wrong size is refused before anything is written.
	if _, err := db.PutKnowledgeEmbeddings(KnowledgeSyncFence{}, src.ID, testModel, []KnowledgeEmbedding{
		{ChunkID: todo[0].ChunkID, DocHash: "h1b", TextHash: "x", Vector: vec(1, 2, 3), Dims: 4},
	}); err == nil {
		t.Fatal("a 3-value vector filed as 4 dimensions was stored")
	}
	// A vector for another source's chunk, or a chunk that is gone, is not.
	other := mustCreateSource(t, db, "other", "")
	w, err = db.PutKnowledgeEmbeddings(KnowledgeSyncFence{}, other.ID, testModel, []KnowledgeEmbedding{
		{ChunkID: todo[0].ChunkID, DocHash: "h1b", TextHash: "x", Vector: vec(1, 0, 0, 0), Dims: 4},
		{ChunkID: 99999, DocHash: "h1b", TextHash: "x", Vector: vec(1, 0, 0, 0), Dims: 4},
	})
	if err != nil || w.Stored != 0 {
		t.Fatalf("vectors for chunks not the source's = %+v, %v", w, err)
	}
}

// TestKnowledgeEmbeddingsFollowTheirChunks: a chunk's vectors go with it — a
// document rewritten shorter, deleted, purged, or its source deleted — and
// PurgeKnowledgeEmbeddings removes what an older build left and other models'.
func TestKnowledgeEmbeddingsFollowTheirChunks(t *testing.T) {
	db := openFresh(t)
	ctx := context.Background()
	src := mustCreateSource(t, db, "wiki", "")
	mustIndex(t, db, src.ID, "p1", "Runbook", "", "h1", "one", "two", "three")
	mustIndex(t, db, src.ID, "p2", "Other", "", "h2", "four")
	embedAll(t, db, src.ID, testModel)
	embedAll(t, db, src.ID, "openai/old-model/4")
	if n := vectorRows(t, db); n != 8 {
		t.Fatalf("%d vectors, want 8", n)
	}
	// Rewritten shorter: the dropped chunks' vectors go with them.
	mustIndex(t, db, src.ID, "p1", "Runbook", "", "h1b", "one")
	if n := vectorRows(t, db); n != 4 {
		t.Fatalf("%d vectors after p1 lost two chunks, want 4", n)
	}
	// Deleted: its tombstone keeps none.
	if found, err := db.DeleteKnowledgeDocument(src.ID, "p2"); err != nil || !found {
		t.Fatal(err)
	}
	if n := vectorRows(t, db); n != 2 {
		t.Fatalf("%d vectors after p2 was deleted, want 2", n)
	}
	counts, err := db.CountKnowledgeVectors(testModel)
	if err != nil || counts[src.ID] != 1 {
		t.Fatalf("CountKnowledgeVectors = %v, %v", counts, err)
	}

	// What an older build leaves: a chunk dropped without its vectors.
	if _, err := db.conn.Exec(`INSERT INTO knowledge_chunk_embeddings (chunk_id, model, source_id, document_id, dims, vector)
		VALUES (424242, ?, ?, 1, 4, ?)`, testModel, src.ID, vec(0, 1, 0, 0)); err != nil {
		t.Fatal(err)
	}
	dry, err := db.PurgeKnowledgeEmbeddings(ctx, testModel, true)
	if err != nil || dry.Orphans != 1 || dry.OtherModels != 1 {
		t.Fatalf("dry run = %+v, %v; want one orphan and one of the old model", dry, err)
	}
	if n := vectorRows(t, db); n != 3 {
		t.Fatalf("a dry run removed vectors: %d left", n)
	}
	// Without a model to keep, other models' are left alone.
	if res, err := db.PurgeKnowledgeEmbeddings(ctx, "", false); err != nil || res.Orphans != 1 || res.OtherModels != 0 {
		t.Fatalf("purge keeping every model = %+v, %v", res, err)
	}
	if res, err := db.PurgeKnowledgeEmbeddings(ctx, testModel, false); err != nil || res.OtherModels != 1 {
		t.Fatalf("purge keeping %s = %+v, %v", testModel, res, err)
	}
	if n := vectorRows(t, db); n != 1 {
		t.Fatalf("%d vectors after the purges, want 1", n)
	}

	// A deleted source's vectors go with the rest of its rows.
	if _, _, err := db.DeleteKnowledgeSource(src.ID, "admin@corp.example"); err != nil {
		t.Fatal(err)
	}
	if n := vectorRows(t, db); n != 0 {
		t.Fatalf("%d vectors outlived their source", n)
	}
}

// TestPurgeKnowledgeTakesADeletedSourcesVectors: what a deletion's own purge
// left of a source's vectors is found and removed by PurgeKnowledge.
func TestPurgeKnowledgeTakesADeletedSourcesVectors(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	mustIndex(t, db, src.ID, "p1", "Runbook", "", "h1", "one", "two")
	embedAll(t, db, src.ID, testModel)
	// The source goes, and only the source: as if its purge was cut short
	// before its first batch.
	if _, err := db.conn.Exec(`DELETE FROM knowledge_sources WHERE id = ?`, src.ID); err != nil {
		t.Fatal(err)
	}
	dry, err := db.PurgeKnowledge(context.Background(), time.Time{}, true)
	if err != nil || dry.Vectors != 2 || dry.Chunks != 2 {
		t.Fatalf("dry run = %+v, %v", dry, err)
	}
	res, err := db.PurgeKnowledge(context.Background(), time.Time{}, false)
	if err != nil || res.Vectors != 2 || res.Chunks != 2 || res.Documents != 1 {
		t.Fatalf("purge = %+v, %v", res, err)
	}
	if n := vectorRows(t, db); n != 0 {
		t.Fatalf("%d vectors left", n)
	}
}

// TestKnowledgeVectorScanIsolatesProjects: a project's scan reads only the
// vectors of the sources bound to it, through each binding's narrowing —
// spaces, query matches — never a disabled source's, a tombstone's or a stale
// one, only the query's model and length; and it stops at its limit, saying
// so.
func TestKnowledgeVectorScanIsolatesProjects(t *testing.T) {
	db := openFresh(t)
	ctx := context.Background()
	a := mustCreateSource(t, db, "a-wiki", "")
	b := mustCreateSource(t, db, "b-jira", "")
	mustBind(t, db, a.ID, "/srv/a", nil, "")
	mustIndex(t, db, a.ID, "a1", "Acquisition", "", "h1", "the target is Initech")
	mustIndex(t, db, b.ID, "ENG-1", "Login", "ENG", "h2", "cannot log in")
	mustIndex(t, db, b.ID, "HR-1", "Payroll", "HR", "h3", "salaries")
	embedAll(t, db, a.ID, testModel)
	embedAll(t, db, b.ID, testModel)
	aChunk, eng, hr := chunkIDsOf(t, db, a.ID, "a1"), chunkIDsOf(t, db, b.ID, "ENG-1"), chunkIDsOf(t, db, b.ID, "HR-1")

	if ids, _ := scanIDs(t, db, "/srv/a", testModel, 100); !reflect.DeepEqual(ids, aChunk) {
		t.Fatalf("project A scanned %v, want only its own %v", ids, aChunk)
	}
	for _, p := range []string{"/srv/b", "/srv", "/srv/a/", "/SRV/A", "/srv/a-other"} {
		if ids, _ := scanIDs(t, db, p, testModel, 100); len(ids) != 0 {
			t.Fatalf("project %q, bound to nothing, scanned %v", p, ids)
		}
	}
	if _, err := db.ScanKnowledgeVectors(ctx, KnowledgeVectorQuery{Model: testModel, Dims: 4, Limit: 5},
		func(int64, []byte) error { return nil }); err == nil {
		t.Fatal("a scan with no project was answered")
	}
	// Another model, or another length, reads nothing.
	if ids, _ := scanIDs(t, db, "/srv/a", "openai/other/4", 100); len(ids) != 0 {
		t.Fatalf("another model's scan read %v", ids)
	}
	var n int
	if _, err := db.ScanKnowledgeVectors(ctx, KnowledgeVectorQuery{ProjectPath: "/srv/a", Model: testModel, Dims: 3,
		Limit: 100}, func(int64, []byte) error { n++; return nil }); err != nil || n != 0 {
		t.Fatalf("a 3-dimensional scan read %d, %v", n, err)
	}

	// Spaces narrow it, and a query binding reads only what a sync matched.
	mustBind(t, db, b.ID, "/srv/eng", []string{"ENG"}, "")
	if ids, _ := scanIDs(t, db, "/srv/eng", testModel, 100); !reflect.DeepEqual(ids, eng) {
		t.Fatalf("ENG binding scanned %v, want %v", ids, eng)
	}
	q := mustBind(t, db, b.ID, "/srv/hr", nil, "project = HR")
	if ids, _ := scanIDs(t, db, "/srv/hr", testModel, 100); len(ids) != 0 {
		t.Fatalf("a query binding no sync answered scanned %v", ids)
	}
	if err := db.SetKnowledgeBindingDocuments(q.ID, "project = HR", []string{"HR-1"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ids, _ := scanIDs(t, db, "/srv/hr", testModel, 100); !reflect.DeepEqual(ids, hr) {
		t.Fatalf("the HR binding scanned %v, want %v", ids, hr)
	}
	// The hydration reads through the bindings too.
	hits, err := db.KnowledgeChunkHits(ctx, "/srv/hr", append(append([]int64{}, eng...), hr...))
	if err != nil || len(hits) != 1 || hits[0].ExternalID != "HR-1" || hits[0].Body != "salaries" {
		t.Fatalf("hits for the HR project = %+v, %v", hits, err)
	}

	// Limit, and a disabled source.
	mustIndex(t, db, a.ID, "a2", "More", "", "h4", "x", "y", "z")
	embedAll(t, db, a.ID, testModel)
	ids, scan := scanIDs(t, db, "/srv/a", testModel, 2)
	if len(ids) != 2 || !scan.Capped || scan.Candidates != 2 {
		t.Fatalf("a scan limited to 2 read %v (%+v)", ids, scan)
	}
	if _, scan := scanIDs(t, db, "/srv/a", testModel, 4); scan.Capped || scan.Candidates != 4 {
		t.Fatalf("a scan of exactly its limit = %+v, want uncapped", scan)
	}
	cur, err := db.GetKnowledgeSource(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateKnowledgeSource(a.ID, KnowledgeSourceUpdate{Name: cur.Name, Config: cur.Config,
		SecretRef: cur.SecretRef, Enabled: false, Changed: []string{"enabled"}, ExpectUpdatedAt: cur.UpdatedAt},
		"admin@corp.example"); err != nil {
		t.Fatal(err)
	}
	if ids, _ := scanIDs(t, db, "/srv/a", testModel, 100); len(ids) != 0 {
		t.Fatalf("a disabled source's vectors were scanned: %v", ids)
	}
	if hits, err := db.KnowledgeChunkHits(ctx, "/srv/a", aChunk); err != nil || len(hits) != 0 {
		t.Fatalf("a disabled source's chunk was read: %+v, %v", hits, err)
	}
	// A visit's error stops the scan.
	stop := errors.New("stop")
	if _, err := db.ScanKnowledgeVectors(ctx, KnowledgeVectorQuery{ProjectPath: "/srv/eng", Model: testModel, Dims: 4,
		Limit: 10}, func(int64, []byte) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("a visit's error = %v", err)
	}
}

// TestKnowledgeEmbeddingWritesHoldTheLease: a sync that no longer holds its
// source's lease writes no vector.
func TestKnowledgeEmbeddingWritesHoldTheLease(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	mustIndex(t, db, src.ID, "p1", "Runbook", "", "h1", "one")
	todo, err := db.PendingKnowledgeEmbeddings(context.Background(), src.ID, testModel, 0, 10)
	if err != nil || len(todo) != 1 {
		t.Fatal(todo, err)
	}
	now := time.Now()
	if _, err := db.AcquireKnowledgeSyncLease(KnowledgeSyncLease{SourceID: src.ID, Holder: "other", Member: "m",
		Origin: "schedule", ExpiresAt: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	_, err = db.PutKnowledgeEmbeddings(KnowledgeSyncFence{Holder: "lapsed", Now: now}, src.ID, testModel,
		[]KnowledgeEmbedding{{ChunkID: todo[0].ChunkID, DocHash: "h1", TextHash: "x", Vector: vec(1, 0, 0, 0), Dims: 4}})
	if !errors.Is(err, ErrKnowledgeSyncLeaseLost) {
		t.Fatalf("a write without the lease = %v", err)
	}
	if n := vectorRows(t, db); n != 0 {
		t.Fatalf("%d vectors written without the lease", n)
	}
}
