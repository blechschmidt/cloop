package statedb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// TestKnowledgeSyncMigrationIsAdditive: 0094 appends defaulted columns to the
// knowledge tables, adds a plain index and a new table — all of which a binary
// that knows 0093 but not 0094 neither reads nor trips over — and re-running
// it changes nothing.
func TestKnowledgeSyncMigrationIsAdditive(t *testing.T) {
	all, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var m migration
	for _, x := range all {
		if x.Version == 94 {
			m = x
		}
	}
	if !strings.Contains(m.Name, "knowledge_sync") {
		t.Fatalf("migration 0094 is %q, not the knowledge sync migration", m.Name)
	}
	if got := classifyMigration(m.SQL); got != CompatAdditive {
		t.Fatalf("0094 classifies %q; an older hub sharing this control plane would refuse the database", got)
	}
	db := openFresh(t)
	before := knowledgeSchema(t, db)
	for _, want := range []string{
		"sync_interval_min INTEGER NOT NULL DEFAULT 0", "sync_report TEXT NOT NULL DEFAULT '{}'",
		"deleted_ns INTEGER NOT NULL DEFAULT 0", "index idx_knowledge_documents_deleted", "table knowledge_sync_leases",
	} {
		if !strings.Contains(before, want) {
			t.Fatalf("the migrated schema has no %q:\n%s", want, before)
		}
	}
	tx, err := db.conn.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range splitStatements(m.SQL) {
		if ac, ok := parseAddColumnIfNotExists(stmt); ok {
			if err := ac.apply(tx); err != nil {
				t.Fatalf("re-applying %s: %v", stmt, err)
			}
			continue
		}
		if _, err := tx.Exec(stmt); err != nil {
			t.Fatalf("re-running %s: %v", stmt, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if after := knowledgeSchema(t, db); after != before {
		t.Fatalf("re-running 0094 changed the schema:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestKnowledgeSyncLease: one sync at a time holds a source's lease — a second
// is told who has it — until it is released or lapses; a lapsed holder can
// neither renew it nor write through it; a manual sync's lease is audited and
// a scheduled one's is not; and deleting the source takes the lease with it.
func TestKnowledgeSyncLease(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	lease := func(holder, origin string) KnowledgeSyncLease {
		return KnowledgeSyncLease{SourceID: src.ID, Holder: holder, Member: "member-" + holder, Origin: origin,
			Actor: "ada@corp.example", ExpiresAt: now.Add(2 * time.Minute)}
	}

	got, err := db.AcquireKnowledgeSyncLease(lease("a", "schedule"), now)
	if err != nil || got.Holder != "a" || !got.AcquiredAt.Equal(now) {
		t.Fatalf("acquire = %+v, %v", got, err)
	}
	held, err := db.AcquireKnowledgeSyncLease(lease("b", "manual"), now.Add(time.Second))
	if !errors.Is(err, ErrKnowledgeSyncLeaseHeld) || held.Holder != "a" || held.Member != "member-a" {
		t.Fatalf("a second sync = %+v, %v; want refused, naming a", held, err)
	}
	if !strings.Contains(err.Error(), "member-a") {
		t.Fatalf("the refusal does not say where the sync runs: %v", err)
	}
	live, err := db.LiveKnowledgeSyncLeases(now.Add(time.Second))
	if err != nil || live[src.ID].Holder != "a" {
		t.Fatalf("live leases = %+v, %v", live, err)
	}

	// Renewed, it outlives its first expiry; lapsed, it is anyone's.
	if err := db.RenewKnowledgeSyncLease(src.ID, "a", now.Add(4*time.Minute), now.Add(time.Minute)); err != nil {
		t.Fatalf("renew: %v", err)
	}
	early := lease("b", "manual")
	early.ExpiresAt = now.Add(5 * time.Minute)
	if _, err := db.AcquireKnowledgeSyncLease(early, now.Add(3*time.Minute)); !errors.Is(err, ErrKnowledgeSyncLeaseHeld) {
		t.Fatalf("a renewed lease was taken: %v", err)
	}
	later := now.Add(5 * time.Minute)
	b := lease("b", "manual")
	b.ExpiresAt = later.Add(2 * time.Minute)
	if _, err := db.AcquireKnowledgeSyncLease(b, later); err != nil {
		t.Fatalf("a lapsed lease was not taken over: %v", err)
	}
	if err := db.RenewKnowledgeSyncLease(src.ID, "a", later.Add(time.Hour), later); !errors.Is(err, ErrKnowledgeSyncLeaseLost) {
		t.Fatalf("the lapsed holder renewed: %v", err)
	}
	// Its writes are refused, the new holder's are not.
	row, _ := db.GetKnowledgeSource(src.ID)
	cursor := "page-2"
	if _, err := db.ApplyKnowledgeBatch(KnowledgeBatch{SourceID: src.ID, UpdatedAt: row.UpdatedAt, Holder: "a", Now: later,
		Cursor: &cursor}); !errors.Is(err, ErrKnowledgeSyncLeaseLost) {
		t.Fatalf("a batch by the lapsed holder = %v", err)
	}
	if err := db.RecordKnowledgeSyncOutcome(src.ID, KnowledgeSyncOutcome{Status: "ok", Holder: "a", StartedAt: now,
		FinishedAt: later}); !errors.Is(err, ErrKnowledgeSyncLeaseLost) {
		t.Fatalf("the lapsed holder recorded an outcome: %v", err)
	}
	if _, err := db.ApplyKnowledgeBatch(KnowledgeBatch{SourceID: src.ID, UpdatedAt: row.UpdatedAt, Holder: "b", Now: later,
		Cursor: &cursor}); err != nil {
		t.Fatalf("a batch by the holder: %v", err)
	}
	if row, _ = db.GetKnowledgeSource(src.ID); row.SyncCursor != "page-2" {
		t.Fatalf("the holder's cursor = %q", row.SyncCursor)
	}

	// The lapsed holder cannot record a binding's answer, nor clear one; the
	// holder can — as the source it read, not after the source changed.
	bound := mustBind(t, db, src.ID, "/p", nil, "label = x")
	mustIndex(t, db, src.ID, "doc", "Doc", "", "h", "words")
	lapsed := KnowledgeSyncFence{Holder: "a", Now: later, Version: row.UpdatedAt}
	if err := db.SetKnowledgeBindingDocumentsFenced(lapsed, bound.ID, "label = x", []string{"doc"}, later); !errors.Is(err, ErrKnowledgeSyncLeaseLost) {
		t.Fatalf("the lapsed holder recorded a binding's answer: %v", err)
	}
	if err := db.ClearKnowledgeBindingDocumentsFenced(lapsed, bound.ID); !errors.Is(err, ErrKnowledgeSyncLeaseLost) {
		t.Fatalf("the lapsed holder cleared a binding's answer: %v", err)
	}
	holder := KnowledgeSyncFence{Holder: "b", Now: later, Version: row.UpdatedAt}
	if err := db.SetKnowledgeBindingDocumentsFenced(holder, bound.ID, "label = x", []string{"doc"}, later); err != nil {
		t.Fatalf("the holder's answer: %v", err)
	}
	stale := KnowledgeSyncFence{Holder: "b", Now: later, Version: row.UpdatedAt.Add(-time.Second)}
	if err := db.ClearKnowledgeBindingDocumentsFenced(stale, bound.ID); !errors.Is(err, ErrKnowledgeSourceChanged) {
		t.Fatalf("clearing an answer for a source that changed since = %v", err)
	}
	if got, _ := db.GetKnowledgeBinding(bound.ID); got.NarrowedAt.IsZero() {
		t.Fatal("a refused clear cleared the binding")
	}

	// Released, the next sync need not wait for the expiry.
	if err := db.ReleaseKnowledgeSyncLease(src.ID, "a"); err != nil {
		t.Fatal(err)
	}
	if live, _ := db.LiveKnowledgeSyncLeases(later); live[src.ID].Holder != "b" {
		t.Fatal("a release by a sync that no longer held the lease freed the holder's")
	}
	if err := db.ReleaseKnowledgeSyncLease(src.ID, "b"); err != nil {
		t.Fatal(err)
	}
	if live, _ := db.LiveKnowledgeSyncLeases(later); len(live) != 0 {
		t.Fatalf("a released lease is live: %+v", live)
	}
	c := lease("c", "schedule")
	c.ExpiresAt = later.Add(time.Hour)
	if _, err := db.AcquireKnowledgeSyncLease(c, later.Add(time.Second)); err != nil {
		t.Fatalf("after the release: %v", err)
	}

	// Only the manual sync is on the audit trail.
	all, _, err := db.ListAuditEvents(AuditFilter{EntityType: "knowledge_source", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var events []AuditEvent
	for _, e := range all {
		if e.EventType == string(auditaction.ActionKnowledgeSourceSync) {
			events = append(events, e)
		}
	}
	if len(events) != 1 || events[0].Actor != "ada@corp.example" || !strings.Contains(events[0].Payload, `"origin":"manual"`) ||
		!strings.Contains(events[0].Payload, `"member":"member-b"`) {
		t.Fatalf("the audited syncs = %+v", events)
	}

	if _, _, err := db.DeleteKnowledgeSource(src.ID, "ada@corp.example"); err != nil {
		t.Fatal(err)
	}
	var leases int
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_sync_leases WHERE source_id = ?`, src.ID).Scan(&leases)
	if leases != 0 {
		t.Fatal("the deleted source's lease outlived it")
	}
	d := lease("d", "schedule")
	d.ExpiresAt = later.Add(2 * time.Hour)
	if _, err := db.AcquireKnowledgeSyncLease(d, later.Add(time.Hour)); !errors.Is(err, ErrKnowledgeSourceNotFound) {
		t.Fatalf("a lease of a deleted source = %v", err)
	}
}

// TestKnowledgeBatchCommitsWithItsCursor: a batch's documents and its cursor
// commit together or not at all — a batch that fails part-way leaves neither
// the documents it had written nor its cursor, and one refused for a changed
// source writes nothing.
func TestKnowledgeBatchCommitsWithItsCursor(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	row, _ := db.GetKnowledgeSource(src.ID)
	doc := func(id string) KnowledgeBatchOp {
		return KnowledgeBatchOp{Doc: KnowledgeDocumentRow{ExternalID: id, Title: id, ContentHash: "h-" + id},
			Chunk: chunksOf("text of " + id)}
	}
	cursor := "after-page-1"
	res, err := db.ApplyKnowledgeBatch(KnowledgeBatch{SourceID: src.ID, UpdatedAt: row.UpdatedAt,
		Ops: []KnowledgeBatchOp{doc("a"), doc("b")}, Cursor: &cursor})
	if err != nil || res.Outcomes[0] != KnowledgeIndexCreated || res.Outcomes[1] != KnowledgeIndexCreated {
		t.Fatalf("first batch = %+v, %v", res, err)
	}

	// The second document of the next batch cannot be written: the first is
	// rolled back with it, and the cursor stays where page 1 left it.
	tooMany := func() ([]KnowledgeChunk, bool) { return make([]KnowledgeChunk, maxKnowledgeChunks+1), false }
	cursor2 := "after-page-2"
	_, err = db.ApplyKnowledgeBatch(KnowledgeBatch{SourceID: src.ID, UpdatedAt: row.UpdatedAt,
		Ops:    []KnowledgeBatchOp{doc("c"), {Doc: KnowledgeDocumentRow{ExternalID: "d", ContentHash: "h-d"}, Chunk: tooMany}},
		Cursor: &cursor2})
	if err == nil {
		t.Fatal("a batch with an unwritable document was written")
	}
	if _, found, _ := db.GetKnowledgeDocument(src.ID, "c"); found {
		t.Fatal("a document of the failed batch was kept")
	}
	if row, _ := db.GetKnowledgeSource(src.ID); row.SyncCursor != "after-page-1" {
		t.Fatalf("the failed batch moved the cursor to %q", row.SyncCursor)
	}

	// A deletion and an unchanged document in one batch.
	res, err = db.ApplyKnowledgeBatch(KnowledgeBatch{SourceID: src.ID, UpdatedAt: row.UpdatedAt,
		Ops: []KnowledgeBatchOp{{Doc: KnowledgeDocumentRow{ExternalID: "a"}, Delete: true}, doc("b"),
			{Doc: KnowledgeDocumentRow{ExternalID: "never-held"}, Delete: true}}, Cursor: &cursor2})
	if err != nil || !res.Found[0] || res.Outcomes[1] != KnowledgeIndexUnchanged || res.Found[2] {
		t.Fatalf("a batch deleting a = %+v, %v", res, err)
	}

	// A batch naming one document twice is refused, before it writes.
	if _, err := db.ApplyKnowledgeBatch(KnowledgeBatch{SourceID: src.ID, UpdatedAt: row.UpdatedAt,
		Ops: []KnowledgeBatchOp{doc("f"), {Doc: KnowledgeDocumentRow{ExternalID: "f"}, Delete: true}}}); err == nil {
		t.Fatal("a batch naming a document twice was written")
	}
	if _, found, _ := db.GetKnowledgeDocument(src.ID, "f"); found {
		t.Fatal("a refused batch wrote a document")
	}

	// The source changed: the batch is refused whole.
	if _, err := db.UpdateKnowledgeSource(src.ID, KnowledgeSourceUpdate{Name: "renamed", Config: row.Config,
		SecretRef: row.SecretRef, Enabled: true, ExpectUpdatedAt: row.UpdatedAt}, "ada@corp.example"); err != nil {
		t.Fatal(err)
	}
	cursor3 := "after-page-3"
	if _, err := db.ApplyKnowledgeBatch(KnowledgeBatch{SourceID: src.ID, UpdatedAt: row.UpdatedAt,
		Ops: []KnowledgeBatchOp{doc("e")}, Cursor: &cursor3}); !errors.Is(err, ErrKnowledgeSourceChanged) {
		t.Fatalf("a batch for a changed source = %v", err)
	}
	if _, found, _ := db.GetKnowledgeDocument(src.ID, "e"); found {
		t.Fatal("a refused batch wrote a document")
	}
	if row, _ := db.GetKnowledgeSource(src.ID); row.SyncCursor != "after-page-2" {
		t.Fatalf("a refused batch moved the cursor to %q", row.SyncCursor)
	}
}

// TestKnowledgeTombstones: a deleted document leaves the index at once — its
// chunks, full-text entries, matches and what it said — but keeps its row and
// id; a document that comes back takes its tombstone's row and counts as new.
func TestKnowledgeTombstones(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	b := mustBind(t, db, src.ID, "/p", nil, "q")
	mustIndex(t, db, src.ID, "gone", "Layoffs plan", "HR", "h1", "secret reorganisation words", "more words")
	mustIndex(t, db, src.ID, "kept", "Kept", "", "h2", "other words")
	if err := db.SetKnowledgeBindingDocuments(b.ID, "q", []string{"gone", "kept"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var docID int64
	_ = db.conn.QueryRow(`SELECT id FROM knowledge_documents WHERE external_id = 'gone'`).Scan(&docID)

	if found, err := db.DeleteKnowledgeDocument(src.ID, "gone"); err != nil || !found {
		t.Fatalf("delete = %v, %v", found, err)
	}
	var (
		title, url, hash, acl string
		deleted               int64
		chunks, ftsRows       int
		matches               int
	)
	if err := db.conn.QueryRow(`SELECT title, url, content_hash, acl, deleted_ns FROM knowledge_documents WHERE id = ?`, docID).
		Scan(&title, &url, &hash, &acl, &deleted); err != nil {
		t.Fatalf("the tombstone: %v", err)
	}
	if title != "" || url != "" || hash != "" || acl != "[]" || deleted == 0 {
		t.Fatalf("the tombstone still says %q %q %q %q (deleted %d)", title, url, hash, acl, deleted)
	}
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_chunks WHERE document_id = ?`, docID).Scan(&chunks)
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_chunks_fts WHERE knowledge_chunks_fts MATCH '"reorganisation"'`).Scan(&ftsRows)
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_binding_documents WHERE document_id = ?`, docID).Scan(&matches)
	if chunks != 0 || ftsRows != 0 || matches != 0 {
		t.Fatalf("the deleted document kept %d chunks, %d full-text entries, %d matches", chunks, ftsRows, matches)
	}
	if _, found, _ := db.GetKnowledgeDocument(src.ID, "gone"); found {
		t.Fatal("a tombstone reads as a document")
	}
	counts, _ := db.CountKnowledge(src.ID)
	if c := counts[src.ID]; c.Documents != 1 || c.Tombstones != 1 || c.Chunks != 1 {
		t.Fatalf("counts with a tombstone = %+v", c)
	}
	if found, err := db.DeleteKnowledgeDocument(src.ID, "gone"); err != nil || found {
		t.Fatalf("deleting a tombstone = %v, %v", found, err)
	}
	// A matching answer does not admit a tombstone.
	if err := db.SetKnowledgeBindingDocuments(b.ID, "q", []string{"gone", "kept"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_binding_documents WHERE document_id = ?`, docID).Scan(&matches)
	if matches != 0 {
		t.Fatal("a tombstone was matched to a binding")
	}

	// It comes back, in the same row.
	if out := mustIndex(t, db, src.ID, "gone", "Plan", "HR", "h1", "back again"); out != KnowledgeIndexCreated {
		t.Fatalf("a document that came back = %s, want created", out)
	}
	var again int64
	_ = db.conn.QueryRow(`SELECT id FROM knowledge_documents WHERE external_id = 'gone' AND deleted_ns = 0`).Scan(&again)
	if again != docID {
		t.Fatalf("the document came back as %d, not in its tombstone's row %d", again, docID)
	}
	if hits := search(t, db, "/p", `"back"`); len(hits) != 0 {
		t.Fatal("a returning document was admitted to a query binding before a sync matched it")
	}
}

// TestRecordKnowledgeSyncOutcome: what a sync did is recorded on its source,
// and a success moves the last-ok time while a failure keeps it.
func TestRecordKnowledgeSyncOutcome(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	t0 := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	if err := db.RecordKnowledgeSyncOutcome(src.ID, KnowledgeSyncOutcome{Status: "ok", Origin: "schedule",
		StartedAt: t0, FinishedAt: t0.Add(1500 * time.Millisecond), Report: `{"created":3}`, More: true}); err != nil {
		t.Fatal(err)
	}
	row, _ := db.GetKnowledgeSource(src.ID)
	if row.SyncStatus != "ok" || !row.SyncStartedAt.Equal(t0) || row.SyncDuration != 1500*time.Millisecond ||
		row.SyncOrigin != "schedule" || row.SyncReport != `{"created":3}` || !row.SyncMore ||
		!row.SyncedOKAt.Equal(t0.Add(1500*time.Millisecond)) || row.SyncedAt.IsZero() {
		t.Fatalf("after an ok sync: %+v", row)
	}
	t1 := t0.Add(time.Hour)
	if err := db.RecordKnowledgeSyncOutcome(src.ID, KnowledgeSyncOutcome{Status: "error", Error: "503", Origin: "manual",
		StartedAt: t1, FinishedAt: t1.Add(time.Second), Report: "not json"}); err != nil {
		t.Fatal(err)
	}
	row, _ = db.GetKnowledgeSource(src.ID)
	if row.SyncStatus != "error" || row.SyncError != "503" || row.SyncReport != "{}" || row.SyncMore ||
		!row.SyncedOKAt.Equal(t0.Add(1500*time.Millisecond)) {
		t.Fatalf("after a failed sync: %+v", row)
	}
	if err := db.RecordKnowledgeSyncOutcome(src.ID+100, KnowledgeSyncOutcome{Status: "ok"}); !errors.Is(err, ErrKnowledgeSourceNotFound) {
		t.Fatalf("the outcome of a sync of no source = %v", err)
	}
}

// TestPurgeKnowledge: retention removes the tombstones older than its cut and
// everything a deleted source left, in transactions of a bounded size, and
// nothing of a live source; a dry run counts the same and removes nothing.
func TestPurgeKnowledge(t *testing.T) {
	defer func(n int) { knowledgePurgeBatch = n }(knowledgePurgeBatch)
	knowledgePurgeBatch = 3

	db := openFresh(t)
	live := mustCreateSource(t, db, "live", "")
	doomed := mustCreateSource(t, db, "doomed", "")
	for i := 0; i < 4; i++ {
		mustIndex(t, db, live.ID, fmt.Sprintf("l%d", i), "Live", "", fmt.Sprintf("lh%d", i), "live words", "more live words")
		mustIndex(t, db, doomed.ID, fmt.Sprintf("d%d", i), "Doomed", "", fmt.Sprintf("dh%d", i), "doomed words", "more", "and more")
	}
	// Two tombstones: one a month and a day old, one a day old.
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	for id, age := range map[string]time.Duration{"l0": 31 * 24 * time.Hour, "l1": 24 * time.Hour} {
		tx, err := db.conn.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tombstoneKnowledgeDocumentsTx(tx, live.ID, now.Add(-age), `external_id = ?`, id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	// A deletion whose own purge never ran: what a crash right after its
	// first transaction leaves.
	db.mu.Lock()
	_, _, err := db.deleteKnowledgeSourceLocked(doomed.ID)
	db.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	cut := now.Add(-30 * 24 * time.Hour)
	dry, err := db.PurgeKnowledge(context.Background(), cut, true)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Tombstones != 1 || dry.Documents != 4 || dry.Chunks != 12 || dry.Sources != 1 {
		t.Fatalf("dry run = %+v; want 1 tombstone and the doomed source's 4 documents and 12 chunks", dry)
	}
	var docs int
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_documents`).Scan(&docs)
	if docs != 8 {
		t.Fatalf("a dry run removed documents: %d left", docs)
	}

	got, err := db.PurgeKnowledge(context.Background(), cut, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tombstones != dry.Tombstones || got.Documents != dry.Documents || got.Chunks != dry.Chunks {
		t.Fatalf("purge = %+v, the dry run said %+v", got, dry)
	}
	for _, q := range []struct {
		sql  string
		want int
	}{
		{`SELECT COUNT(*) FROM knowledge_documents WHERE source_id = ` + fmt.Sprint(doomed.ID), 0},
		{`SELECT COUNT(*) FROM knowledge_chunks WHERE source_id = ` + fmt.Sprint(doomed.ID), 0},
		{`SELECT COUNT(*) FROM knowledge_documents WHERE source_id = ` + fmt.Sprint(live.ID), 3},
		{`SELECT COUNT(*) FROM knowledge_documents WHERE source_id = ` + fmt.Sprint(live.ID) + ` AND deleted_ns > 0`, 1},
		{`SELECT COUNT(*) FROM knowledge_chunks WHERE source_id = ` + fmt.Sprint(live.ID), 4},
		{`SELECT COUNT(*) FROM knowledge_chunks_fts WHERE rowid NOT IN (SELECT id FROM knowledge_chunks)`, 0},
	} {
		var n int
		if err := db.conn.QueryRow(q.sql).Scan(&n); err != nil || n != q.want {
			t.Errorf("%s = %d (%v), want %d", q.sql, n, err, q.want)
		}
	}
	if hits := search(t, db, "/p", `"live"`); len(hits) != 0 {
		t.Fatal("an unbound source was searchable")
	}
	mustBind(t, db, live.ID, "/p", nil, "")
	if hits := search(t, db, "/p", `"live"`); len(hits) != 4 {
		t.Fatalf("the live source's chunks after the purge: %d hits, want 4", len(hits))
	}
	again, err := db.PurgeKnowledge(context.Background(), cut, false)
	if err != nil || again.Rows() != 0 {
		t.Fatalf("a second purge = %+v, %v", again, err)
	}
	var ic string
	if err := db.conn.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity_check = %q, %v", ic, err)
	}
}

// TestDeletingASourceStopsItsSearchAtOnce: a source's deletion removes it from
// search in its first transaction, before its documents are purged, and the
// purge that follows leaves nothing behind.
func TestDeletingASourceStopsItsSearchAtOnce(t *testing.T) {
	defer func(n int) { knowledgePurgeBatch = n }(knowledgePurgeBatch)
	knowledgePurgeBatch = 2
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	mustBind(t, db, src.ID, "/p", nil, "")
	for i := 0; i < 5; i++ {
		mustIndex(t, db, src.ID, fmt.Sprintf("d%d", i), "Doc", "", fmt.Sprintf("h%d", i), "findable words")
	}
	db.mu.Lock()
	_, counts, err := db.deleteKnowledgeSourceLocked(src.ID)
	db.mu.Unlock()
	if err != nil || counts.Documents != 5 || counts.Chunks != 5 || counts.Bindings != 1 {
		t.Fatalf("delete = %+v, %v", counts, err)
	}
	mustBind(t, db, mustCreateSource(t, db, "other", "").ID, "/p", nil, "")
	if hits := search(t, db, "/p", `"findable"`); len(hits) != 0 {
		t.Fatalf("a deleted source's chunks are searchable before its purge: %+v", hits)
	}
	if c, _ := db.CountKnowledge(); c[src.ID] != (KnowledgeSourceCounts{}) {
		t.Fatalf("a deleted source's leftovers are counted: %+v", c)
	}
	r, err := db.purgeKnowledgeOfSource(context.Background(), src.ID, false)
	if err != nil || r.Documents != 5 || r.Chunks != 5 {
		t.Fatalf("purge = %+v, %v", r, err)
	}
}

// TestASweepTakesSeveralTransactions: a full listing's sweep and a
// reconciliation take documents out a bounded number per transaction; one cut
// short leaves the listing in progress and what it had removed removed, and
// the next finishes it.
func TestASweepTakesSeveralTransactions(t *testing.T) {
	defer func(n int) { knowledgeTombstoneBatch = n }(knowledgeTombstoneBatch)
	knowledgeTombstoneBatch = 2
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	for i := 0; i < 7; i++ {
		mustIndex(t, db, src.ID, fmt.Sprintf("d%d", i), "Doc", "", fmt.Sprintf("h%d", i), "words")
	}
	row, _ := db.GetKnowledgeSource(src.ID)
	started := time.Now()
	if err := db.StartKnowledgeListing(src.ID, row.UpdatedAt, started); err != nil {
		t.Fatal(err)
	}
	// The listing reaches d0 alone.
	if _, err := db.IndexKnowledgeDocument(KnowledgeDocumentRow{SourceID: src.ID, ExternalID: "d0", Title: "Doc",
		ContentHash: "h0", ListedAt: started.Add(time.Millisecond)}, chunksOf("words")); err != nil {
		t.Fatal(err)
	}
	// One transaction of the sweep, and then the process stops.
	n, done, err := db.finishKnowledgeListingBatch(KnowledgeSyncFence{}, src.ID, row.UpdatedAt, started, time.Now())
	if err != nil || n != 2 || done {
		t.Fatalf("one batch of the sweep = %d %v %v", n, done, err)
	}
	if row, _ = db.GetKnowledgeSource(src.ID); row.ListingStartedAt.IsZero() || !row.FullListingAt.IsZero() {
		t.Fatalf("a sweep cut short recorded the listing complete: %+v", row)
	}
	// The next sync, resuming the listing at its end, sweeps the rest.
	n, err = db.FinishKnowledgeListing(src.ID, row.UpdatedAt, started, time.Now())
	if err != nil || n != 4 {
		t.Fatalf("the rest of the sweep = %d, %v; want d1..d6 less the 2 already gone", n, err)
	}
	if row, _ = db.GetKnowledgeSource(src.ID); !row.ListingStartedAt.IsZero() || row.FullListingAt.IsZero() {
		t.Fatalf("the finished sweep did not record the listing complete: %+v", row)
	}
	if c, _ := db.CountKnowledge(src.ID); c[src.ID].Documents != 1 || c[src.ID].Tombstones != 6 {
		t.Fatalf("after the sweep: %+v", c[src.ID])
	}

	// A reconciliation the same way: five go, two at a time.
	for i := 0; i < 5; i++ {
		mustIndex(t, db, src.ID, fmt.Sprintf("r%d", i), "Doc", "", fmt.Sprintf("hr%d", i), "words")
	}
	at := time.Now().Add(2 * time.Hour)
	n, err = db.ReconcileKnowledgeDocuments(src.ID, row.UpdatedAt, []string{"d0"}, at.Add(-time.Hour), at)
	if err != nil || n != 5 {
		t.Fatalf("reconcile = %d, %v; want r0..r4", n, err)
	}
	if row, _ = db.GetKnowledgeSource(src.ID); !row.ReconciledAt.Equal(at.UTC()) && !row.ReconciledAt.Equal(at) {
		t.Fatalf("the reconciliation was not recorded: %v", row.ReconciledAt)
	}
	var ic string
	if err := db.conn.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity_check = %q, %v", ic, err)
	}
}
