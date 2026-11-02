package janitor

// The knowledge step (Task 20470): a pass purges the tombstones of knowledge
// documents deleted longer ago than retention.knowledge_deleted_days, and
// everything a deleted knowledge source left.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedKnowledge gives a project's state.db a live source of four documents —
// one deleted 40 days ago, one 2 days ago — and the rows of a deleted source
// whose own purge never ran. It returns the live and the deleted source's ids.
func seedKnowledge(t *testing.T, workDir string) (live, gone int64) {
	t.Helper()
	dbPath := filepath.Join(workDir, ".cloop", "state.db")
	statedbtest.Seed(t, dbPath)
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	create := func(name string) int64 {
		row, err := db.CreateKnowledgeSource(statedb.KnowledgeSourceRow{Kind: "fake", Name: name, Scope: "org",
			Config: `{}`, Enabled: true}, "admin@corp.example")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 4; i++ {
			if _, err := db.IndexKnowledgeDocument(statedb.KnowledgeDocumentRow{SourceID: row.ID,
				ExternalID: fmt.Sprintf("%s-%d", name, i), Title: name, ContentHash: fmt.Sprintf("%s-%d", name, i),
				BodyBytes: 100}, func() ([]statedb.KnowledgeChunk, bool) {
				return []statedb.KnowledgeChunk{{Text: "one " + name}, {Text: "two " + name}}, false
			}); err != nil {
				t.Fatal(err)
			}
		}
		return row.ID
	}
	live, gone = create("live"), create("gone")
	for _, id := range []string{"live-0", "live-1"} {
		if found, err := db.DeleteKnowledgeDocument(live, id); err != nil || !found {
			t.Fatalf("delete %s: %v %v", id, found, err)
		}
	}
	conn, err := statedb.OpenConn(dbPath, statedb.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for id, age := range map[string]time.Duration{"live-0": 40 * 24 * time.Hour, "live-1": 2 * 24 * time.Hour} {
		if _, err := conn.Exec(`UPDATE knowledge_documents SET deleted_ns = ? WHERE external_id = ?`,
			time.Now().Add(-age).UnixNano(), id); err != nil {
			t.Fatal(err)
		}
	}
	// What a source deletion cut short leaves: the source row gone, its
	// documents and chunks still there.
	if _, err := conn.Exec(`DELETE FROM knowledge_sources WHERE id = ?`, gone); err != nil {
		t.Fatal(err)
	}
	return live, gone
}

// seedKnowledgeSource adds a source of two documents to a seeded project's
// state.db and deletes its row alone, as a cut-short deletion leaves it.
func seedKnowledgeSource(t *testing.T, workDir, name string) (string, int64) {
	t.Helper()
	dbPath := filepath.Join(workDir, ".cloop", "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	row, err := db.CreateKnowledgeSource(statedb.KnowledgeSourceRow{Kind: "fake", Name: name, Scope: "org",
		Config: `{}`, Enabled: true}, "admin@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.IndexKnowledgeDocument(statedb.KnowledgeDocumentRow{SourceID: row.ID,
			ExternalID: fmt.Sprintf("%s-%d", name, i), Title: name, ContentHash: fmt.Sprintf("%s-%d", name, i)},
			func() ([]statedb.KnowledgeChunk, bool) {
				return []statedb.KnowledgeChunk{{Text: "text " + name}}, false
			}); err != nil {
			t.Fatal(err)
		}
	}
	conn, err := statedb.OpenConn(dbPath, statedb.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`DELETE FROM knowledge_sources WHERE id = ?`, row.ID); err != nil {
		t.Fatal(err)
	}
	return dbPath, row.ID
}

func knowledgeRows(t *testing.T, workDir, query string) int {
	t.Helper()
	conn, err := statedb.OpenConn(filepath.Join(workDir, ".cloop", "state.db"), statedb.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var n int
	if err := conn.QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRunOnce_PurgesKnowledgeTombstonesAndDeletedSources(t *testing.T) {
	dir := newProject(t)
	live, gone := seedKnowledge(t, dir)
	pol := rowPolicy(0, 0)

	dry, err := RunOnce(Options{WorkDir: dir, Policy: pol, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !dry.Knowledge.Ran || dry.Knowledge.Deleted != 1+4+8 || !strings.Contains(dry.Knowledge.Reason, "would purge 1 tombstone") {
		t.Fatalf("dry run = %+v; want 1 tombstone, and the deleted source's 4 documents and 8 chunks", dry.Knowledge)
	}
	if n := knowledgeRows(t, dir, `SELECT COUNT(*) FROM knowledge_documents`); n != 8 {
		t.Fatalf("a dry run removed documents: %d left of 8", n)
	}

	rep, err := RunOnce(Options{WorkDir: dir, Policy: pol})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rep.Errs() {
		t.Fatalf("step error: %v", e)
	}
	if rep.Knowledge.Deleted != dry.Knowledge.Deleted || rep.RowsDeleted() < rep.Knowledge.Deleted {
		t.Fatalf("the pass = %+v (rows deleted %d); the dry run said %d", rep.Knowledge, rep.RowsDeleted(),
			dry.Knowledge.Deleted)
	}
	for _, q := range []struct {
		what string
		sql  string
		want int
	}{
		{"the deleted source's documents", fmt.Sprintf(`SELECT COUNT(*) FROM knowledge_documents WHERE source_id = %d`, gone), 0},
		{"the deleted source's chunks", fmt.Sprintf(`SELECT COUNT(*) FROM knowledge_chunks WHERE source_id = %d`, gone), 0},
		{"the 40-day tombstone", `SELECT COUNT(*) FROM knowledge_documents WHERE external_id = 'live-0'`, 0},
		{"the 2-day tombstone", `SELECT COUNT(*) FROM knowledge_documents WHERE external_id = 'live-1' AND deleted_ns > 0`, 1},
		{"the live documents", fmt.Sprintf(`SELECT COUNT(*) FROM knowledge_documents WHERE source_id = %d AND deleted_ns = 0`, live), 2},
		{"the live documents' chunks", fmt.Sprintf(`SELECT COUNT(*) FROM knowledge_chunks WHERE source_id = %d`, live), 4},
		{"full-text entries without a chunk", `SELECT COUNT(*) FROM knowledge_chunks_fts WHERE rowid NOT IN (SELECT id FROM knowledge_chunks)`, 0},
	} {
		if got := knowledgeRows(t, dir, q.sql); got != q.want {
			t.Errorf("%s: %d rows, want %d", q.what, got, q.want)
		}
	}

	// With every row limit off, what a deleted source left still goes.
	_, gone2 := seedKnowledgeSource(t, dir, "gone-too")
	off := DefaultPolicy()
	off.KeepSnapshots, off.VacuumFreeRatio = 0, 1
	off.ProviderCallBodyMaxAge, off.ProviderCallMaxRows, off.StepMaxRows = -1, -1, -1
	off.EventMaxRows, off.CostMaxRows, off.TelemetryMaxAge, off.KnowledgeDeletedMaxAge = -1, -1, -1, -1
	rep, err = RunOnce(Options{WorkDir: dir, Policy: off})
	if err != nil {
		t.Fatal(err)
	}
	if n := knowledgeRows(t, dir, fmt.Sprintf(`SELECT COUNT(*) FROM knowledge_chunks WHERE source_id = %d`, gone2)); n != 0 ||
		!strings.Contains(rep.Steps.Reason, "disabled") {
		t.Fatalf("with every limit off: %d chunks of a deleted source left, steps %q", n, rep.Steps.Reason)
	}
	if n := knowledgeRows(t, dir, `SELECT COUNT(*) FROM knowledge_documents WHERE external_id = 'live-1' AND deleted_ns > 0`); n != 1 {
		t.Fatal("knowledge_deleted_days -1 purged a tombstone")
	}

	// retention.knowledge_deleted_days: -1 keeps every tombstone, and what a
	// deleted source left goes regardless.
	cfg := &config.Config{}
	cfg.Retention.KnowledgeDeletedDays = -1
	if got := PolicyFromConfig(cfg).normalise().KnowledgeDeletedMaxAge; got != 0 {
		t.Fatalf("knowledge_deleted_days -1 = %s, want tombstones kept", got)
	}
	cfg.Retention.KnowledgeDeletedDays = 1
	if got := PolicyFromConfig(cfg).normalise().KnowledgeDeletedMaxAge; got != 24*time.Hour {
		t.Fatalf("knowledge_deleted_days 1 = %s", got)
	}
	if got := DefaultPolicy().KnowledgeDeletedMaxAge; got != 30*24*time.Hour {
		t.Fatalf("the default keeps tombstones %s, want 30 days", got)
	}
}
