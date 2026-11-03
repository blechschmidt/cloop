package statedb

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// knowledgeRunReadsOf returns every recorded read of sessionID.
func (d *DB) knowledgeRunReadsOf(sessionID string) (map[int][]int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT task_id, document_id FROM knowledge_run_reads WHERE session_id = ?
		ORDER BY task_id, read_ns, document_id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int][]int64{}
	for rows.Next() {
		var (
			task int
			id   int64
		)
		if err := rows.Scan(&task, &id); err != nil {
			return nil, err
		}
		out[task] = append(out[task], id)
	}
	return out, rows.Err()
}

// TestKnowledgeProjectDocumentsByKey: a key finds the document whose title it
// begins — ENG-4 never ENG-42 — or whose URL ends in /browse/<key>, and only
// through the project's bindings; an underscore in a key is not a wildcard.
func TestKnowledgeProjectDocumentsByKey(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	src, err := db.CreateKnowledgeSource(KnowledgeSourceRow{Kind: "jira", Name: "Jira", Scope: "org", Config: "{}", Enabled: true}, "t")
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range []KnowledgeDocumentRow{
		{ExternalID: "1", Title: "ENG-42 Fix the deploy", URL: "https://j/browse/ENG-42"},
		{ExternalID: "2", Title: "ENG-4 Old bug", URL: "https://j/browse/ENG-4"},
		{ExternalID: "3", Title: "OPSX2-1 thing", URL: "https://j/browse/OPSX2-1"},
		{ExternalID: "4", Title: "Untitled", URL: "https://j/browse/OPS_2-1"},
	} {
		d.SourceID = src.ID
		d.ContentHash = string(rune('a' + i))
		if _, err := db.IndexKnowledgeDocument(d, func() ([]KnowledgeChunk, bool) {
			return []KnowledgeChunk{{Heading: "h", Text: "body of " + d.Title, Tokens: 3}}, false
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := db.PutKnowledgeBinding(KnowledgeBindingRow{SourceID: src.ID, ProjectPath: "/p"}, "t"); err != nil {
		t.Fatal(err)
	}
	find := func(project, key string) []string {
		docs, err := db.KnowledgeProjectDocuments(ctx, project, KnowledgeDocumentLookup{Key: key})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range docs {
			out = append(out, d.ExternalID)
		}
		return out
	}
	for key, want := range map[string]string{"ENG-42": "[1]", "ENG-4": "[2]", "OPS_2-1": "[4]", "ENG-9": "[]"} {
		if got := find("/p", key); fmt.Sprint(got) != want {
			t.Errorf("key %s found %v, want %s", key, got, want)
		}
	}
	if got := find("/other", "ENG-42"); len(got) != 0 {
		t.Errorf("a project the source is not bound to found %v", got)
	}
	docs, _ := db.KnowledgeProjectDocuments(ctx, "/p", KnowledgeDocumentLookup{Key: "ENG-42"})
	chunks, cut, err := db.KnowledgeProjectDocumentChunks(ctx, "/p", docs[0].ID, 1<<20)
	if err != nil || cut || len(chunks) != 1 || chunks[0].Text != "body of ENG-42 Fix the deploy" {
		t.Fatalf("chunks = %+v %v %v", chunks, cut, err)
	}
	if chunks, _, _ := db.KnowledgeProjectDocumentChunks(ctx, "/other", docs[0].ID, 1<<20); len(chunks) != 0 {
		t.Fatalf("another project read the chunks: %+v", chunks)
	}
}

// TestKnowledgeRunReads: a read is recorded once per task and document, taken
// back exactly once, bounded per session, and purged with its session.
func TestKnowledgeRunReads(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	if err := db.PutProxySession(ProxySessionRow{Kind: ProxySessionKnowledge, SessionID: "s1", TokenSHA256: "x",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordKnowledgeRunReads("s1", 3, []int64{7, 9, 7}, now); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordKnowledgeRunReads("s1", 4, []int64{7}, now); err != nil {
		t.Fatal(err)
	}
	ids, err := db.TakeKnowledgeRunReads("s1", 3)
	if err != nil || fmt.Sprint(ids) != "[7 9]" {
		t.Fatalf("take = %v %v", ids, err)
	}
	if again, _ := db.TakeKnowledgeRunReads("s1", 3); len(again) != 0 {
		t.Fatalf("taken twice: %v", again)
	}
	if n, err := db.PurgeKnowledgeRunReads(now.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("purged %d of an open session's reads: %v", n, err)
	}
	if _, err := db.CloseProxySession(ProxySessionKnowledge, "s1", "", now, "ended", ""); err != nil {
		t.Fatal(err)
	}
	if n, err := db.PurgeKnowledgeRunReads(now.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("purged %d of a closed session's reads: %v", n, err)
	}
	many := make([]int64, maxKnowledgeRunReadsPerSession+50)
	for i := range many {
		many[i] = int64(i + 1)
	}
	if err := db.RecordKnowledgeRunReads("s2", 1, many, now); err != nil {
		t.Fatal(err)
	}
	reads, _ := db.knowledgeRunReadsOf("s2")
	if len(reads[1]) != maxKnowledgeRunReadsPerSession {
		t.Fatalf("recorded %d reads for one session", len(reads[1]))
	}
}
