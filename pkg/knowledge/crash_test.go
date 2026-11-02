package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The environment the child half of the crash test reads; set only for it.
const (
	crashEnvDB     = "CLOOP_KNOWLEDGE_CRASH_DB"
	crashEnvSource = "CLOOP_KNOWLEDGE_CRASH_SOURCE"
	crashEnvReady  = "CLOOP_KNOWLEDGE_CRASH_READY"
)

// crashDocs is what the crash test's source holds: six documents of several
// chunks each, listed two to a page.
func crashDocs() []Document {
	var out []Document
	for i := 0; i < 6; i++ {
		var body strings.Builder
		for _, part := range []string{"Overview", "Procedure", "Rollback"} {
			fmt.Fprintf(&body, "# %s\n\n", part)
			for w := 0; w < 70; w++ {
				fmt.Fprintf(&body, "word%d-%s-%d ", i, strings.ToLower(part), w)
			}
			body.WriteString("\n\n")
		}
		out = append(out, Document{ExternalID: fmt.Sprintf("d-%d", i), Title: fmt.Sprintf("Runbook %d", i),
			Body: body.String()})
	}
	return out
}

// TestCrashMidSyncChild is the child half of
// TestACrashMidSyncLeavesNoHalfIndexedDocument: a hub process syncing the
// source, which its parent kills with SIGKILL while it is inside the
// transaction writing the sync's second page — one document of that page
// already written in it, the next being chunked. It runs only as that test's
// child and is skipped otherwise.
func TestCrashMidSyncChild(t *testing.T) {
	path := os.Getenv(crashEnvDB)
	if path == "" {
		t.Skip("the child half of TestACrashMidSyncLeavesNoHalfIndexedDocument")
	}
	id, err := strconv.ParseInt(os.Getenv(crashEnvSource), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	ready := os.Getenv(crashEnvReady)
	reg := NewRegistry()
	if err := reg.Register(&fakeConnector{kind: "fake", docs: crashDocs(), pageSize: 2}); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(db.AsControlPlane(), WithRegistry(reg), WithCredentials(fakeSecrets{"wiki-bot": {"", "org-token-value-123"}}),
		WithChunking(ChunkOptions{MaxTokens: 64, OverlapTokens: 8}))
	documents := 0
	svc.onChunk = func() {
		documents++
		if documents == 4 {
			// d-3, the second document of the second page: d-2 is written in
			// this same transaction, which has not committed.
			if err := os.WriteFile(ready, []byte("inside page 2's transaction"), 0o600); err != nil {
				t.Error(err)
			}
			time.Sleep(time.Hour)
		}
	}
	r := NewRunner(RunnerOptions{Member: "doomed-member", StartDelay: -1, LeaseTTL: 2 * time.Second,
		Open: func() (*Service, func(), error) { return svc, func() {}, nil }})
	_, err = r.SyncNow(context.Background(), id, OriginSchedule, "")
	t.Fatalf("the sync ended (%v); it should have been killed inside its second page's transaction", err)
}

// TestACrashMidSyncLeavesNoHalfIndexedDocument: a hub process killed in the
// middle of a sync — SIGKILL, inside the transaction writing a page — leaves
// every document either whole, its chunks and full-text entries all there, or
// absent; the source's cursor where the last page that committed left it,
// never ahead of the documents it moves past; and a database that passes
// SQLite's integrity check. Once the dead process's lease lapses, the next
// sync resumes from that cursor and ends with exactly what a sync never
// interrupted indexes.
func TestACrashMidSyncLeavesNoHalfIndexedDocument(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a child process")
	}
	f := newFixture(t)
	f.conn.docs, f.conn.pageSize = crashDocs(), 2
	src := orgSource(t, f, "Runbooks")
	path := f.db.Path()
	ready := filepath.Join(t.TempDir(), "ready")

	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashMidSyncChild$", "-test.v")
	cmd.Env = append(os.Environ(), crashEnvDB+"="+path, crashEnvSource+"="+strconv.FormatInt(src.ID, 10),
		crashEnvReady+"="+ready)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("the child never reached its second page's transaction:\n%s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil { // SIGKILL: no deferred cleanup runs
		t.Fatal(err)
	}
	_ = cmd.Wait()

	// What the crash left.
	row, err := f.db.GetKnowledgeSource(src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.SyncCursor != "2" {
		t.Fatalf("after the crash the cursor is %q, want %q: where page 1 left it", row.SyncCursor, "2")
	}
	if got := indexedDocuments(t, path); strings.Join(got, ",") != "d-0,d-1" {
		t.Fatalf("after the crash the index holds %v, want page 1's d-0 and d-1 alone", got)
	}
	checkWholeDocuments(t, path)

	// The dead process's lease lapses; the next sync resumes from page 2.
	r := NewRunner(RunnerOptions{Member: "next-member", StartDelay: -1, Open: func() (*Service, func(), error) {
		return f.svc, func() {}, nil
	}})
	t.Cleanup(func() { r.Stop(10 * time.Second) })
	var res SyncResult
	for {
		res, err = r.SyncNow(context.Background(), src.ID, OriginSchedule, "")
		if !errors.Is(err, statedb.ErrKnowledgeSyncLeaseHeld) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the dead process's lease never lapsed")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || !res.Report.Complete || res.Report.Created != 4 || res.Report.Pages != 2 {
		t.Fatalf("the resumed sync = %+v, %v; want pages 2 and 3, d-2 to d-5 created", res.Report, err)
	}
	checkWholeDocuments(t, path)

	// Exactly what a sync never interrupted makes.
	clean := newFixture(t)
	clean.conn.docs, clean.conn.pageSize = crashDocs(), 2
	cleanSrc := orgSource(t, clean, "Runbooks")
	if _, err := clean.svc.Sync(context.Background(), cleanSrc.ID); err != nil {
		t.Fatal(err)
	}
	if got, want := chunkTexts(t, path), chunkTexts(t, clean.db.Path()); got != want {
		t.Fatalf("the resumed index differs from an uninterrupted one:\n got: %.300s\nwant: %.300s", got, want)
	}
}

func readOnly(t *testing.T, path string) *sql.DB {
	t.Helper()
	conn, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// indexedDocuments lists the live documents' external ids.
func indexedDocuments(t *testing.T, path string) []string {
	t.Helper()
	rows, err := readOnly(t, path).Query(`SELECT external_id FROM knowledge_documents WHERE deleted_ns = 0 ORDER BY external_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

// checkWholeDocuments fails unless every document has the chunks its row
// counts, every chunk its full-text entry and no entry outlives its chunk, and
// the database passes SQLite's integrity check.
func checkWholeDocuments(t *testing.T, path string) {
	t.Helper()
	conn := readOnly(t, path)
	for _, q := range []struct{ what, sql string }{
		{"documents whose chunks do not number their chunk_count",
			`SELECT COUNT(*) FROM knowledge_documents d WHERE d.chunk_count !=
			 (SELECT COUNT(*) FROM knowledge_chunks c WHERE c.document_id = d.id)`},
		{"live documents with no chunks", `SELECT COUNT(*) FROM knowledge_documents d WHERE d.deleted_ns = 0 AND
			 NOT EXISTS (SELECT 1 FROM knowledge_chunks c WHERE c.document_id = d.id)`},
		{"chunks without a full-text entry", `SELECT COUNT(*) FROM knowledge_chunks c WHERE NOT EXISTS
			 (SELECT 1 FROM knowledge_chunks_fts f WHERE f.rowid = c.id)`},
		{"full-text entries without a chunk", `SELECT COUNT(*) FROM knowledge_chunks_fts
			 WHERE rowid NOT IN (SELECT id FROM knowledge_chunks)`},
		{"chunks without a document", `SELECT COUNT(*) FROM knowledge_chunks
			 WHERE document_id NOT IN (SELECT id FROM knowledge_documents)`},
	} {
		var n int
		if err := conn.QueryRow(q.sql).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%d %s (%v)", n, q.what, err)
		}
	}
	var ic string
	if err := conn.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity_check = %q, %v", ic, err)
	}
}

// chunkTexts renders every live document's chunks, in order.
func chunkTexts(t *testing.T, path string) string {
	t.Helper()
	rows, err := readOnly(t, path).Query(`SELECT d.external_id, d.content_hash, c.ordinal, c.heading, f.body
		FROM knowledge_documents d JOIN knowledge_chunks c ON c.document_id = d.id
		JOIN knowledge_chunks_fts f ON f.rowid = c.id
		WHERE d.deleted_ns = 0 ORDER BY d.external_id, c.ordinal`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var (
			id, hash, heading, body string
			ordinal                 int
		)
		if err := rows.Scan(&id, &hash, &ordinal, &heading, &body); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %s %d %s %s\n", id, hash, ordinal, heading, body)
	}
	return b.String()
}
