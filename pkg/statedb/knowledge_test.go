package statedb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// knowledgeMigration returns migration 0092 as embedded.
func knowledgeMigration(t *testing.T) migration {
	t.Helper()
	all, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		if m.Version == 92 {
			if !strings.Contains(m.Name, "knowledge") {
				t.Fatalf("migration 0092 is %s, not the knowledge migration", m.Name)
			}
			return m
		}
	}
	t.Fatal("migration 0092 is not embedded")
	return migration{}
}

// knowledgeSchema renders every knowledge object in sqlite_master, FTS5's
// shadow tables included.
func knowledgeSchema(t *testing.T, db *DB) string {
	t.Helper()
	rows, err := db.conn.Query(`SELECT type || ' ' || name || ' ' || COALESCE(sql, '') FROM sqlite_master
		WHERE name LIKE '%knowledge%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return strings.Join(out, "\n")
}

// TestKnowledgeMigrationIsIdempotentAndAdditive: 0092 applies once, records
// the additive verdict an older binary sharing the control plane needs to keep
// opening the database, and re-running every statement of it — a stranded
// build that created the tables first, or an operator re-applying it — changes
// nothing, the FTS5 table included.
func TestKnowledgeMigrationIsIdempotentAndAdditive(t *testing.T) {
	m := knowledgeMigration(t)
	if got := classifyMigration(m.SQL); got != CompatAdditive {
		t.Fatalf("0092 classifies %q; the older hub sharing this control plane would refuse the database", got)
	}

	db := openFresh(t)
	var compat string
	if err := db.conn.QueryRow(`SELECT compat FROM schema_migrations WHERE version = 92`).Scan(&compat); err != nil {
		t.Fatalf("0092 is not recorded: %v", err)
	}
	if compat != string(CompatAdditive) {
		t.Fatalf("0092 recorded %q, want additive", compat)
	}
	before := knowledgeSchema(t, db)
	for _, want := range []string{
		"table knowledge_sources", "table knowledge_bindings", "table knowledge_documents",
		"table knowledge_chunks ", "table knowledge_chunks_fts CREATE VIRTUAL TABLE", "table knowledge_binding_documents",
		"table knowledge_chunks_fts_data", "index ux_knowledge_documents_external",
	} {
		if !strings.Contains(before, want) {
			t.Errorf("the migrated schema has no %q:\n%s", want, before)
		}
	}

	src := mustCreateSource(t, db, "wiki", "")
	if _, err := db.IndexKnowledgeDocument(KnowledgeDocumentRow{SourceID: src.ID, ExternalID: "p1", Title: "Page", ContentHash: "h1"},
		chunksOf("kept across a re-run")); err != nil {
		t.Fatal(err)
	}
	for i, stmt := range splitStatements(m.SQL) {
		if _, err := db.conn.Exec(stmt); err != nil {
			t.Fatalf("re-running statement %d of 0092: %v\n%s", i+1, err, stmt)
		}
	}
	if after := knowledgeSchema(t, db); after != before {
		t.Fatalf("re-running 0092 changed the schema:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	hits, err := db.SearchKnowledge(context.Background(), KnowledgeSearchQuery{ProjectPath: "/p", Match: `"kept"`, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatal("an unbound source was searchable")
	}
	if text, err := db.KnowledgeChunkText(1); err != nil || text != "kept across a re-run" {
		t.Fatalf("the indexed chunk did not survive a re-run: %q, %v", text, err)
	}

	// And it still opens: Migrate over the migrated file is a no-op.
	path := db.Path()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatalf("reopening after the re-run: %v", err)
	}
	defer again.Close()
	var ic string
	if err := again.conn.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity_check after the re-run = %q, %v", ic, err)
	}
}

// TestKnowledgeMigrationAdoptsTablesAStrandedBuildCreated: a database that
// already holds the knowledge tables but never recorded version 92 migrates
// over them rather than failing on them.
func TestKnowledgeMigrationAdoptsTablesAStrandedBuildCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	conn := openRaw(t, path)
	if _, err := MigrateTo(conn, 91); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range splitStatements(knowledgeMigration(t).SQL) {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	report, err := Migrate(conn)
	if err != nil {
		t.Fatalf("Migrate over pre-existing knowledge tables: %v", err)
	}
	found := false
	for _, v := range report.Applied {
		found = found || v == 92
	}
	if !found {
		t.Fatalf("0092 was not applied: %+v", report)
	}
}

func mustCreateSource(t *testing.T, db *DB, name, owner string) KnowledgeSourceRow {
	t.Helper()
	scope := "org"
	if owner != "" {
		scope = "personal"
	}
	row, err := db.CreateKnowledgeSource(KnowledgeSourceRow{
		Kind: "fake", Name: name, Scope: scope, Owner: owner, Config: `{"base_url":"https://wiki.example"}`,
		SecretRef: "wiki-token", Enabled: true,
	}, "admin@corp.example")
	if err != nil {
		t.Fatalf("create source %q: %v", name, err)
	}
	return row
}

func mustBind(t *testing.T, db *DB, sourceID int64, project string, spaces []string, query string) KnowledgeBindingRow {
	t.Helper()
	b, _, err := db.PutKnowledgeBinding(KnowledgeBindingRow{SourceID: sourceID, ProjectPath: project, Spaces: spaces, Query: query},
		"admin@corp.example")
	if err != nil {
		t.Fatalf("bind %d to %s: %v", sourceID, project, err)
	}
	return b
}

// chunksOf returns a chunking callback yielding texts as chunks.
func chunksOf(texts ...string) func() ([]KnowledgeChunk, bool) {
	return func() ([]KnowledgeChunk, bool) {
		var cs []KnowledgeChunk
		for _, c := range texts {
			cs = append(cs, KnowledgeChunk{Text: c, Tokens: len(c) / 4})
		}
		return cs, false
	}
}

func mustIndex(t *testing.T, db *DB, sourceID int64, id, title, space, hash string, chunks ...string) KnowledgeIndexOutcome {
	t.Helper()
	out, err := db.IndexKnowledgeDocument(KnowledgeDocumentRow{
		SourceID: sourceID, ExternalID: id, Title: title, SpaceKey: space, URL: "https://wiki.example/" + id,
		ContentHash: hash,
	}, chunksOf(chunks...))
	if err != nil {
		t.Fatalf("index %s: %v", id, err)
	}
	return out
}

func search(t *testing.T, db *DB, project, match string) []KnowledgeHit {
	t.Helper()
	hits, err := db.SearchKnowledge(context.Background(), KnowledgeSearchQuery{ProjectPath: project, Match: match, Limit: 20,
		SnippetOpen: "[", SnippetClose: "]", SnippetEllipsis: "…"})
	if err != nil {
		t.Fatalf("search %s for %s: %v", project, match, err)
	}
	return hits
}

func hitDocs(hits []KnowledgeHit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.ExternalID)
	}
	return out
}

// TestKnowledgeSearchRanksByBM25: a title match outranks a body match, more
// matching terms outrank fewer, the snippet marks the term, and every hit
// names its source, title and URL.
func TestKnowledgeSearchRanksByBM25(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	mustBind(t, db, src.ID, "/srv/a", nil, "")
	mustIndex(t, db, src.ID, "body-only", "Release notes", "ENG", "h1",
		"This quarter we changed how a rollback is performed during a deploy.")
	mustIndex(t, db, src.ID, "title", "Rollback runbook", "ENG", "h2",
		"Steps to follow when the service misbehaves after a release.")
	mustIndex(t, db, src.ID, "both-terms", "Operations", "ENG", "h3",
		"A rollback of the database migration needs the rollback script and the database backup.")
	mustIndex(t, db, src.ID, "unrelated", "Lunch menu", "ENG", "h4", "Soup and bread on Fridays.")

	hits := search(t, db, "/srv/a", `"rollback" OR "database"`)
	got := hitDocs(hits)
	if len(got) != 3 || got[0] != "both-terms" {
		t.Fatalf("ranking = %v; want the document matching both terms twice first, the unrelated one absent", got)
	}
	title := search(t, db, "/srv/a", `"rollback"`)
	if hitDocs(title)[0] != "title" {
		t.Fatalf("for one term, ranking = %v; a match in the title (weighted 4x) should lead", hitDocs(title))
	}
	for _, h := range hits {
		if h.SourceName != "wiki" || h.SourceKind != "fake" || h.Title == "" || !strings.HasPrefix(h.URL, "https://wiki.example/") {
			t.Errorf("hit %+v does not name its source, title and URL", h)
		}
		if h.Rank >= 0 {
			t.Errorf("hit %s rank %v; FTS5's bm25 is negative for a match", h.ExternalID, h.Rank)
		}
	}
	if !strings.Contains(hits[0].Snippet, "[rollback]") {
		t.Errorf("snippet %q does not mark the matched term", hits[0].Snippet)
	}
	// Ranked best first, and the order is total.
	for i := 1; i < len(hits); i++ {
		if hits[i].Rank < hits[i-1].Rank {
			t.Fatalf("hits are not ordered by rank: %v", hits)
		}
	}
}

// TestKnowledgeSearchIsolatesProjects is the property the binding table exists
// for: project B never reads a chunk from a source bound only to project A,
// however the query is spelled, and a project with no bindings reads nothing.
func TestKnowledgeSearchIsolatesProjects(t *testing.T) {
	db := openFresh(t)
	a := mustCreateSource(t, db, "a-wiki", "")
	b := mustCreateSource(t, db, "b-wiki", "")
	mustBind(t, db, a.ID, "/srv/a", nil, "")
	mustBind(t, db, b.ID, "/srv/b", nil, "")
	mustIndex(t, db, a.ID, "a-secret", "Acquisition plan", "", "h1", "The confidential acquisition target is Initech.")
	mustIndex(t, db, b.ID, "b-doc", "Team handbook", "", "h2", "The acquisition of new laptops goes through IT.")

	for _, match := range []string{`"acquisition"`, `"initech"`, `"confidential" OR "acquisition"`, `initech*`} {
		for _, h := range search(t, db, "/srv/b", match) {
			if h.SourceID != b.ID {
				t.Fatalf("project B searching %s got a chunk of source %d, bound only to A: %+v", match, h.SourceID, h)
			}
		}
		for _, project := range []string{"/srv/c", "/srv", "/srv/a/", "/srv/a-other", "/SRV/A", ""} {
			if project == "" {
				if _, err := db.SearchKnowledge(context.Background(), KnowledgeSearchQuery{Match: match, Limit: 5}); err == nil {
					t.Fatal("a search with no project was answered")
				}
				continue
			}
			if hits := search(t, db, project, match); len(hits) != 0 {
				t.Fatalf("project %q, bound to nothing, found %v", project, hitDocs(hits))
			}
		}
	}
	if got := hitDocs(search(t, db, "/srv/a", `"initech"`)); !reflect.DeepEqual(got, []string{"a-secret"}) {
		t.Fatalf("project A's own search = %v", got)
	}

	// Unbinding takes it away at once; binding B to A's source gives B exactly
	// that source.
	bindings, err := db.ListKnowledgeBindings(KnowledgeBindingFilter{SourceID: a.ID})
	if err != nil || len(bindings) != 1 {
		t.Fatalf("bindings of A: %v, %v", bindings, err)
	}
	if _, err := db.DeleteKnowledgeBinding(bindings[0].ID, "admin@corp.example"); err != nil {
		t.Fatal(err)
	}
	if hits := search(t, db, "/srv/a", `"initech"`); len(hits) != 0 {
		t.Fatalf("an unbound project still found %v", hitDocs(hits))
	}
}

// TestKnowledgeBindingNarrowing: a binding's spaces admit only documents in
// those spaces, and a binding's query admits only the documents a sync
// recorded for it — nothing before the first sync, and nothing it recorded for
// a query the binding no longer has.
func TestKnowledgeBindingNarrowing(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "jira", "")
	mustIndex(t, db, src.ID, "ENG-1", "Login fails", "ENG", "h1", "Users cannot log in after the upgrade.")
	mustIndex(t, db, src.ID, "OPS-1", "Login alerts", "OPS", "h2", "Alerting on login failures.")
	mustIndex(t, db, src.ID, "HR-1", "Login to payroll", "HR", "h3", "Payroll login for staff.")

	spaced := mustBind(t, db, src.ID, "/srv/eng", []string{"OPS", "ENG", "ENG"}, "")
	if !reflect.DeepEqual(spaced.Spaces, []string{"ENG", "OPS"}) {
		t.Fatalf("spaces stored as %v, want sorted and unique", spaced.Spaces)
	}
	if got := hitDocs(search(t, db, "/srv/eng", `"login"`)); len(got) != 2 || strings.Contains(strings.Join(got, ","), "HR-1") {
		t.Fatalf("a binding narrowed to ENG and OPS found %v", got)
	}

	queried := mustBind(t, db, src.ID, "/srv/q", nil, "labels = public")
	if hits := search(t, db, "/srv/q", `"login"`); len(hits) != 0 {
		t.Fatalf("a query binding served %v before any sync recorded what matches it", hitDocs(hits))
	}
	if err := db.SetKnowledgeBindingDocuments(queried.ID, "labels = public", []string{"OPS-1", "NOT-INDEXED"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := hitDocs(search(t, db, "/srv/q", `"login"`)); !reflect.DeepEqual(got, []string{"OPS-1"}) {
		t.Fatalf("after the sync, the query binding found %v, want only OPS-1", got)
	}
	// A second answer replaces the first.
	if err := db.SetKnowledgeBindingDocuments(queried.ID, "labels = public", []string{"HR-1"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := hitDocs(search(t, db, "/srv/q", `"login"`)); !reflect.DeepEqual(got, []string{"HR-1"}) {
		t.Fatalf("after the second answer, the query binding found %v, want only HR-1", got)
	}
	// New content was matched against nothing: the document leaves the query
	// binding until a sync asks again. Unchanged content keeps its match.
	mustIndex(t, db, src.ID, "HR-1", "Login to payroll", "HR", "h3", "Payroll login for staff.")
	if got := hitDocs(search(t, db, "/srv/q", `"login"`)); !reflect.DeepEqual(got, []string{"HR-1"}) {
		t.Fatalf("an unchanged document lost its match: %v", got)
	}
	mustIndex(t, db, src.ID, "HR-1", "Login to payroll", "HR", "h3-moved", "Payroll login, and the salary bands.")
	if hits := search(t, db, "/srv/q", `"login"`); len(hits) != 0 {
		t.Fatalf("a document re-indexed with new content kept the old content's match: %v", hitDocs(hits))
	}
	if err := db.SetKnowledgeBindingDocuments(queried.ID, "labels = public", []string{"HR-1"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.ClearKnowledgeBindingDocuments(queried.ID); err != nil {
		t.Fatal(err)
	}
	if hits := search(t, db, "/srv/q", `"login"`); len(hits) != 0 {
		t.Fatalf("a cleared binding still serves %v", hitDocs(hits))
	}
	// Changing the query forgets the old matches, and an answer computed for
	// the old query is refused.
	changed, created, err := db.PutKnowledgeBinding(KnowledgeBindingRow{SourceID: src.ID, ProjectPath: "/srv/q", Query: "labels = internal"}, "x")
	if err != nil || created || changed.ID != queried.ID || !changed.NarrowedAt.IsZero() {
		t.Fatalf("changing the query: %+v created=%v err=%v", changed, created, err)
	}
	if hits := search(t, db, "/srv/q", `"login"`); len(hits) != 0 {
		t.Fatalf("a changed query still served the old query's matches: %v", hitDocs(hits))
	}
	if err := db.SetKnowledgeBindingDocuments(queried.ID, "labels = public", []string{"HR-1"}, time.Now()); !errors.Is(err, ErrKnowledgeBindingChanged) {
		t.Fatalf("an answer for the old query = %v, want ErrKnowledgeBindingChanged", err)
	}
}

// TestKnowledgeIndexKeepsUnchangedDocuments: indexing a document with the hash
// it already has rewrites only its metadata; a changed hash rewrites chunks in
// place, and a shorter document loses the chunks past its end, from the
// full-text index too.
func TestKnowledgeIndexKeepsUnchangedDocuments(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	mustBind(t, db, src.ID, "/p", nil, "")
	if out := mustIndex(t, db, src.ID, "doc", "Guide", "ENG", "h1", "alpha one", "beta two", "gamma three"); out != KnowledgeIndexCreated {
		t.Fatalf("first index = %s", out)
	}
	ids := chunkIDs(t, db)

	chunked := 0
	out, err := db.IndexKnowledgeDocument(KnowledgeDocumentRow{SourceID: src.ID, ExternalID: "doc", Title: "Guide",
		SpaceKey: "OPS", ContentHash: "h1"}, func() ([]KnowledgeChunk, bool) {
		chunked++
		return chunksOf("never", "written")()
	})
	if err != nil || out != KnowledgeIndexUnchanged {
		t.Fatalf("same hash = %s, %v; want unchanged", out, err)
	}
	if chunked != 0 {
		t.Fatalf("an unchanged document was chunked %d times", chunked)
	}
	if got := chunkIDs(t, db); !reflect.DeepEqual(got, ids) {
		t.Fatalf("an unchanged document's chunks were rewritten: %v -> %v", ids, got)
	}
	if hits := search(t, db, "/p", `"never"`); len(hits) != 0 {
		t.Fatal("the chunks passed with an unchanged hash were indexed")
	}
	if hits := search(t, db, "/p", `"gamma"`); len(hits) != 1 || hits[0].SpaceKey != "OPS" {
		t.Fatalf("the metadata of an unchanged document was not updated: %+v", hits)
	}

	if out := mustIndex(t, db, src.ID, "doc", "Guide v2", "OPS", "h2", "delta four"); out != KnowledgeIndexUpdated {
		t.Fatalf("changed hash = %s, want updated", out)
	}
	got := chunkIDs(t, db)
	if len(got) != 1 || got[0] != ids[0] {
		t.Fatalf("after shrinking to one chunk the ids are %v, want [%d] — the first position rewritten in place", got, ids[0])
	}
	for _, gone := range []string{`"alpha"`, `"beta"`, `"gamma"`} {
		if hits := search(t, db, "/p", gone); len(hits) != 0 {
			t.Fatalf("%s still matches after the document lost it", gone)
		}
	}
	if hits := search(t, db, "/p", `"delta"`); len(hits) != 1 || hits[0].Title != "Guide v2" {
		t.Fatalf("the new content is not searchable under its new title: %+v", hits)
	}
	var orphans int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_chunks_fts WHERE rowid NOT IN (SELECT id FROM knowledge_chunks)`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("%d full-text entries outlived their chunks (%v)", orphans, err)
	}
	var ic string
	if err := db.conn.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity_check = %q, %v", ic, err)
	}
}

func chunkIDs(t *testing.T, db *DB) []int64 {
	t.Helper()
	rows, err := db.conn.Query(`SELECT id FROM knowledge_chunks ORDER BY document_id, ordinal`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

// TestKnowledgeDeletesLeaveNothingBehind: deleting a document, sweeping a
// source to a listing, and deleting a source remove chunks, full-text entries,
// matches and bindings with them.
func TestKnowledgeDeletesLeaveNothingBehind(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	other := mustCreateSource(t, db, "other", "")
	b := mustBind(t, db, src.ID, "/p", nil, "q")
	mustBind(t, db, other.ID, "/p", nil, "")
	for i := 0; i < 4; i++ {
		mustIndex(t, db, src.ID, fmt.Sprintf("d%d", i), "Doc", "", fmt.Sprintf("h%d", i), "shared words here", "more shared words")
	}
	mustIndex(t, db, other.ID, "keep", "Kept", "", "k", "shared words in another source")
	if err := db.SetKnowledgeBindingDocuments(b.ID, "q", []string{"d0", "d1", "d2", "d3"}, time.Now()); err != nil {
		t.Fatal(err)
	}

	if found, err := db.DeleteKnowledgeDocument(src.ID, "d0"); err != nil || !found {
		t.Fatalf("delete d0: %v %v", found, err)
	}
	if found, err := db.DeleteKnowledgeDocument(src.ID, "d0"); err != nil || found {
		t.Fatalf("deleting d0 again: found=%v err=%v", found, err)
	}
	// A full listing that reaches only d1 removes d2 and d3 at its end.
	srcRow, _ := db.GetKnowledgeSource(src.ID)
	started := time.Now()
	if err := db.StartKnowledgeListing(src.ID, srcRow.UpdatedAt, started); err != nil {
		t.Fatal(err)
	}
	if _, err := db.IndexKnowledgeDocument(KnowledgeDocumentRow{SourceID: src.ID, ExternalID: "d1", Title: "Doc",
		ContentHash: "h1", ListedAt: started.Add(time.Millisecond)}, chunksOf("never chunked")); err != nil {
		t.Fatal(err)
	}
	if n, err := db.FinishKnowledgeListing(src.ID, srcRow.UpdatedAt, started, time.Now()); err != nil || n != 2 {
		t.Fatalf("finishing a listing that reached only d1 removed %d, %v; want 2", n, err)
	}
	counts, err := db.CountKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	if c := counts[src.ID]; c.Documents != 1 || c.Chunks != 2 || c.Bindings != 1 {
		t.Fatalf("after the deletes the source holds %+v", c)
	}
	var matches int
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_binding_documents`).Scan(&matches)
	if matches != 1 {
		t.Fatalf("%d binding matches survive, want 1 (d1)", matches)
	}

	row, gone, err := db.DeleteKnowledgeSource(src.ID, "admin@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if row.Name != "wiki" || gone.Documents != 1 || gone.Chunks != 2 || gone.Bindings != 1 {
		t.Fatalf("delete reported %+v %+v", row, gone)
	}
	if _, err := db.GetKnowledgeSource(src.ID); !errors.Is(err, ErrKnowledgeSourceNotFound) {
		t.Fatalf("the deleted source still reads: %v", err)
	}
	for _, table := range []string{"knowledge_documents", "knowledge_chunks", "knowledge_bindings"} {
		var n int
		if err := db.conn.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE source_id = ?`, src.ID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%d rows of %s outlived their source (%v)", n, table, err)
		}
	}
	var fts, member int
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_chunks_fts`).Scan(&fts)
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM knowledge_binding_documents`).Scan(&member)
	if fts != 1 || member != 0 {
		t.Fatalf("after deleting the source: %d full-text entries (want the other source's 1), %d matches", fts, member)
	}
	if hits := search(t, db, "/p", `"shared"`); len(hits) != 1 || hits[0].SourceID != other.ID {
		t.Fatalf("the other source's search after the delete: %+v", hits)
	}
	// Writes to a deleted source are refused rather than recreating it.
	if _, err := db.IndexKnowledgeDocument(KnowledgeDocumentRow{SourceID: src.ID, ExternalID: "late"}, nil); !errors.Is(err, ErrKnowledgeSourceNotFound) {
		t.Fatalf("indexing into a deleted source = %v", err)
	}
	if _, _, err := db.PutKnowledgeBinding(KnowledgeBindingRow{SourceID: src.ID, ProjectPath: "/p"}, "x"); !errors.Is(err, ErrKnowledgeSourceNotFound) {
		t.Fatalf("binding a deleted source = %v", err)
	}
}

// TestKnowledgeSourceLifecycle: names are unique per owner, an update can
// clear the sync cursor, a sync's cursor write is refused once the source was
// reconfigured, and every mutation lands on the control plane's audit chain
// under its registered action.
func TestKnowledgeSourceLifecycle(t *testing.T) {
	db := openFresh(t).AsControlPlane()
	org := mustCreateSource(t, db, "wiki", "")
	mustCreateSource(t, db, "wiki", "alice@corp.example") // a personal source may share an org name
	if _, err := db.CreateKnowledgeSource(KnowledgeSourceRow{Kind: "fake", Name: "wiki", Scope: "org", Enabled: true}, "x"); !errors.Is(err, ErrKnowledgeSourceNameTaken) {
		t.Fatalf("a second org source named wiki = %v", err)
	}

	if err := db.SetKnowledgeSyncCursor(org.ID, org.UpdatedAt, "page-2"); err != nil {
		t.Fatal(err)
	}
	if err := db.StartKnowledgeListing(org.ID, org.UpdatedAt, time.Now()); err != nil {
		t.Fatal(err)
	}
	updated, err := db.UpdateKnowledgeSource(org.ID, KnowledgeSourceUpdate{
		Name: "wiki", Config: `{"base_url":"https://other.example"}`, SecretRef: "wiki-token", Enabled: true,
		Changed: []string{"config"}, Resync: true, ExpectUpdatedAt: org.UpdatedAt,
	}, "admin@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if updated.SyncCursor != "" || !updated.ListingStartedAt.IsZero() {
		t.Fatalf("a resync update left the cursor %q and the listing begun at %v", updated.SyncCursor, updated.ListingStartedAt)
	}
	// An edit made from the copy read before that one is refused, not applied
	// over it.
	if _, err := db.UpdateKnowledgeSource(org.ID, KnowledgeSourceUpdate{Name: "renamed", Enabled: false,
		ExpectUpdatedAt: org.UpdatedAt}, "other@corp.example"); !errors.Is(err, ErrKnowledgeSourceChanged) {
		t.Fatalf("a stale edit = %v, want ErrKnowledgeSourceChanged", err)
	}
	if _, err := db.UpdateKnowledgeSource(999, KnowledgeSourceUpdate{Name: "x", ExpectUpdatedAt: org.UpdatedAt}, "x"); !errors.Is(err, ErrKnowledgeSourceNotFound) {
		t.Fatalf("editing a missing source = %v", err)
	}
	if err := db.SetKnowledgeSyncCursor(org.ID, org.UpdatedAt, "page-3"); !errors.Is(err, ErrKnowledgeSourceChanged) {
		t.Fatalf("a cursor from before the reconfiguration = %v, want ErrKnowledgeSourceChanged", err)
	}
	if err := db.RecordKnowledgeSync(org.ID, "error", "boom", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetKnowledgeSource(org.ID)
	if err != nil || got.SyncStatus != "error" || got.SyncError != "boom" || got.SyncedAt.IsZero() {
		t.Fatalf("sync outcome not recorded: %+v %v", got, err)
	}
	b := mustBind(t, db, org.ID, "/p", []string{"ENG"}, "")
	if _, err := db.DeleteKnowledgeBinding(b.ID, "admin@corp.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DeleteKnowledgeBinding(b.ID, "admin@corp.example"); !errors.Is(err, ErrKnowledgeBindingNotFound) {
		t.Fatalf("deleting a deleted binding = %v", err)
	}
	if _, _, err := db.DeleteKnowledgeSource(org.ID, "admin@corp.example"); err != nil {
		t.Fatal(err)
	}

	want := []auditaction.Action{
		auditaction.ActionKnowledgeSourceCreate, auditaction.ActionKnowledgeSourceCreate,
		auditaction.ActionKnowledgeSourceUpdate, auditaction.ActionKnowledgeSourceBind,
		auditaction.ActionKnowledgeSourceUnbind, auditaction.ActionKnowledgeSourceDelete,
	}
	rows, _, err := db.ListAuditEvents(AuditFilter{EntityType: "knowledge_source", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var got2 []auditaction.Action
	for _, r := range rows {
		got2 = append(got2, auditaction.Action(r.EventType))
	}
	if !reflect.DeepEqual(got2, want) {
		t.Fatalf("audit rows = %v\nwant       %v", got2, want)
	}
	for _, r := range rows {
		if r.Actor != "admin@corp.example" {
			t.Errorf("%s row's actor = %q", r.EventType, r.Actor)
		}
		// The reference is a name, and it survives the audit redactor.
		if r.EventType == string(auditaction.ActionKnowledgeSourceCreate) && !strings.Contains(r.Payload, `"signs_in_with":"wiki-token"`) {
			t.Errorf("the create row does not say which secret the source signs in with: %s", r.Payload)
		}
	}
}

// TestKnowledgeSearchRefusesAMalformedQuery reports a query FTS5 cannot parse
// as the caller's mistake.
func TestKnowledgeSearchRefusesAMalformedQuery(t *testing.T) {
	db := openFresh(t)
	src := mustCreateSource(t, db, "wiki", "")
	mustBind(t, db, src.ID, "/p", nil, "")
	mustIndex(t, db, src.ID, "d", "Doc", "", "h", "words")
	if _, err := db.SearchKnowledge(context.Background(), KnowledgeSearchQuery{ProjectPath: "/p", Match: `"unbalanced`, Limit: 5}); !errors.Is(err, ErrKnowledgeQuery) {
		t.Fatalf("a malformed query = %v, want ErrKnowledgeQuery", err)
	}
}

// TestKnowledgeSearchMakesSnippetsOnlyForTheRankedChunks holds the search to
// its two phases: the outer query walks the ranked ids and looks each up in
// the full-text index (rowid and MATCH together), rather than matching the
// whole index a second time — and so makes a snippet only for the chunks it
// returns.
func TestKnowledgeSearchMakesSnippetsOnlyForTheRankedChunks(t *testing.T) {
	db := openFresh(t)
	rows, err := db.conn.Query(`EXPLAIN QUERY PLAN `+knowledgeSearchSQL,
		"/p", `"x"`, 10, "[", "]", "…", 16, `"x"`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, "SCAN top") {
		t.Fatalf("the outer query does not walk the ranked ids:\n%s", joined)
	}
	fullScans := 0
	for _, step := range plan {
		if strings.Contains(step, "VIRTUAL TABLE INDEX") && !strings.Contains(step, "json_each") &&
			!strings.Contains(step, ":=M") {
			fullScans++
		}
	}
	if fullScans != 1 {
		t.Fatalf("the full-text index is scanned in full %d times, want once (the ranking):\n%s", fullScans, joined)
	}
}
