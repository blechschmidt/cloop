package statedb

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestKnowledgeReconcileMigrationIsAdditive: 0093 appends two columns to the
// knowledge tables with defaults and no constraint, which a binary that knows
// 0092 but not 0093 neither reads nor trips over, and re-running it is a
// no-op.
func TestKnowledgeReconcileMigrationIsAdditive(t *testing.T) {
	all, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var m migration
	for _, x := range all {
		if x.Version == 93 {
			m = x
		}
	}
	if !strings.Contains(m.Name, "knowledge_reconcile") {
		t.Fatalf("migration 0093 is %q, not the knowledge reconciliation migration", m.Name)
	}
	if got := classifyMigration(m.SQL); got != CompatAdditive {
		t.Fatalf("0093 classifies %q; an older hub sharing this control plane would refuse the database", got)
	}
	db := openFresh(t)
	before := knowledgeSchema(t, db)
	for _, want := range []string{"ancestors TEXT NOT NULL DEFAULT '[]'", "reconciled_ns INTEGER NOT NULL DEFAULT 0"} {
		if !strings.Contains(before, want) {
			t.Fatalf("the migrated schema has no %q:\n%s", want, before)
		}
	}
	tx, err := db.conn.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range splitStatements(m.SQL) {
		ac, ok := parseAddColumnIfNotExists(stmt)
		if !ok {
			t.Fatalf("0093 holds a statement that is not an idempotent ADD COLUMN: %s", stmt)
		}
		if err := ac.apply(tx); err != nil {
			t.Fatalf("re-applying %s: %v", stmt, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if after := knowledgeSchema(t, db); after != before {
		t.Fatalf("re-running 0093 changed the schema:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestKnowledgeDocumentAncestors: a document's ancestors are written with it,
// rewritten when only its metadata changed, read back, and carried by every
// search hit on it.
func TestKnowledgeDocumentAncestors(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	mustBind(t, db, src.ID, "/p", nil, "")
	doc := KnowledgeDocumentRow{SourceID: src.ID, ExternalID: "p1", Title: "Deploys", ContentHash: "h1",
		Ancestors: []string{"Engineering", "Runbooks"}}
	if _, err := db.IndexKnowledgeDocument(doc, chunksOf("ship the hub")); err != nil {
		t.Fatal(err)
	}
	got, found, err := db.GetKnowledgeDocument(src.ID, "p1")
	if err != nil || !found || strings.Join(got.Ancestors, "/") != "Engineering/Runbooks" {
		t.Fatalf("read back = %+v, %v, %v", got.Ancestors, found, err)
	}
	// The parent was renamed: the same content, new metadata.
	doc.Ancestors = []string{"Engineering", "Operations"}
	if out, err := db.IndexKnowledgeDocument(doc, chunksOf("ship the hub")); err != nil || out != KnowledgeIndexUnchanged {
		t.Fatalf("re-index = %q, %v", out, err)
	}
	hits := search(t, db, "/p", `"ship"`)
	if len(hits) != 1 || strings.Join(hits[0].Ancestors, "/") != "Engineering/Operations" {
		t.Fatalf("the hit's ancestors = %+v", hits)
	}
	// None.
	doc.Ancestors = nil
	if _, err := db.IndexKnowledgeDocument(doc, nil); err != nil {
		t.Fatal(err)
	}
	if hits := search(t, db, "/p", `"ship"`); len(hits) != 1 || hits[0].Ancestors != nil {
		t.Fatalf("a document with no ancestors = %+v", hits)
	}
}

// TestReconcileKnowledgeDocuments: a reconciliation removes the documents its
// answer leaves out — with their chunks and matches — but not one listed since
// listedBefore; it records itself; and it refuses to run against a source that
// changed, or one in the middle of a full listing, whose sweep is the one to
// remove what it did not reach.
func TestReconcileKnowledgeDocuments(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	b := mustBind(t, db, src.ID, "/p", nil, "label = x")
	t0 := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	for i, id := range []string{"keep", "gone", "moved", "recent"} {
		listed := t0
		if id == "recent" {
			listed = t0.Add(50 * time.Minute)
		}
		if _, err := db.IndexKnowledgeDocument(KnowledgeDocumentRow{SourceID: src.ID, ExternalID: id, Title: id,
			ContentHash: id, ListedAt: listed}, chunksOf("text of "+id, "more "+string(rune('a'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SetKnowledgeBindingDocuments(b.ID, "label = x", []string{"keep", "gone"}, t0); err != nil {
		t.Fatal(err)
	}
	row, err := db.GetKnowledgeSource(src.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Mid full listing: refused.
	if err := db.StartKnowledgeListing(src.ID, row.UpdatedAt, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReconcileKnowledgeDocuments(src.ID, row.UpdatedAt, []string{"keep"}, t0, t0); !errors.Is(err, ErrKnowledgeSourceChanged) {
		t.Fatalf("a reconciliation during a full listing = %v", err)
	}
	if n, err := db.FinishKnowledgeListing(src.ID, row.UpdatedAt, t0, t0.Add(time.Minute)); err != nil || n != 0 {
		t.Fatalf("finish the listing = %d, %v", n, err)
	}
	if row, _ = db.GetKnowledgeSource(src.ID); !row.ReconciledAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("a full listing that ended did not count as a reconciliation: %v", row.ReconciledAt)
	}

	// A stale copy of the source: refused.
	if _, err := db.ReconcileKnowledgeDocuments(src.ID, row.UpdatedAt.Add(-time.Second), nil, t0, t0); !errors.Is(err, ErrKnowledgeSourceChanged) {
		t.Fatalf("a reconciliation of a changed source = %v", err)
	}

	at := t0.Add(time.Hour)
	n, err := db.ReconcileKnowledgeDocuments(src.ID, row.UpdatedAt, []string{"keep"}, at.Add(-30*time.Minute), at)
	if err != nil || n != 2 {
		t.Fatalf("reconcile = %d, %v; want gone and moved removed", n, err)
	}
	for id, want := range map[string]bool{"keep": true, "gone": false, "moved": false, "recent": true} {
		if _, found, _ := db.GetKnowledgeDocument(src.ID, id); found != want {
			t.Errorf("%s: present %v, want %v", id, found, want)
		}
	}
	counts, err := db.CountKnowledge(src.ID)
	if err != nil || counts[src.ID].Documents != 2 || counts[src.ID].Chunks != 4 {
		t.Fatalf("counts after the reconciliation = %+v, %v", counts[src.ID], err)
	}
	var orphans int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_chunks_fts WHERE rowid NOT IN (SELECT id FROM knowledge_chunks)`).
		Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("%d full-text entries outlived their chunks (%v)", orphans, err)
	}
	var matches int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_binding_documents WHERE binding_id = ?`, b.ID).
		Scan(&matches); err != nil || matches != 1 {
		t.Fatalf("%d binding matches left, want keep's alone (%v)", matches, err)
	}
	if row, _ = db.GetKnowledgeSource(src.ID); !row.ReconciledAt.Equal(at) {
		t.Fatalf("the reconciliation was not recorded: %v", row.ReconciledAt)
	}

	// An empty answer removes everything listed before the cut.
	if n, err := db.ReconcileKnowledgeDocuments(src.ID, row.UpdatedAt, nil, at.Add(time.Hour), at.Add(time.Hour)); err != nil || n != 2 {
		t.Fatalf("an empty answer = %d, %v", n, err)
	}
}
