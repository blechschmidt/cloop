package auditretention

// End-to-end tests for the seal → truncate → anchor sequence (Task 20218).
//
// The invariant every test here is really checking is the same one: after a
// prune, every row that ever existed is either still in the table or inside
// exactly one archive, and both halves are verifiable.

import (
	"bufio"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite" // second connection for the tamper tests

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// dbPaths remembers each test database's file so the tamper helpers can reach
// it through their own connection rather than through cloop's write path.
var dbPaths = map[*statedb.DB]string{}

func newDB(t *testing.T) *statedb.DB {
	t.Helper()
	statedb.SetAuditEnabled(true)
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	dbPaths[db] = path
	t.Cleanup(func() {
		delete(dbPaths, db)
		_ = db.Close()
	})
	return db
}

// seed appends n rows one hour apart starting at base, and returns them.
func seed(t *testing.T, db *statedb.DB, base time.Time, n int) []statedb.AuditEvent {
	t.Helper()
	out := make([]statedb.AuditEvent, 0, n)
	for i := 0; i < n; i++ {
		ev := statedb.AuditEvent{
			Timestamp:  base.Add(time.Duration(i) * time.Hour),
			Actor:      fmt.Sprintf("actor-%d", i%3),
			EventType:  "task.upsert",
			EntityType: "task",
			EntityID:   fmt.Sprintf("%d", i),
			Payload:    fmt.Sprintf(`{"i":%d,"note":"row %d"}`, i, i),
		}
		if err := db.AppendAuditEvent(&ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		out = append(out, ev)
	}
	return out
}

func TestPruneSealsThenTruncatesAndStillVerifies(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 30)
	dir := t.TempDir()

	// Cut after row index 11 (id 12).
	cutoff := rows[12].Timestamp
	rep, err := Prune(db, Options{Before: cutoff, ExportDir: dir, Actor: "alice"})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if !rep.Pruned {
		t.Fatal("prune reported nothing done")
	}
	if rep.Anchor.PrunedCount != 12 {
		t.Errorf("pruned %d rows, want 12", rep.Anchor.PrunedCount)
	}
	if rep.Anchor.RetainedFromID != 13 {
		t.Errorf("retained_from_id = %d, want 13", rep.Anchor.RetainedFromID)
	}

	// The chain verifies across the gap, and says so.
	vr, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !vr.OK {
		t.Fatalf("chain broken after prune at id %d: %s", vr.BreakAtID, vr.Reason)
	}
	if !vr.Anchored || vr.ExportSHA256 != rep.ExportSHA256 {
		t.Errorf("verify report did not carry the anchor's digest")
	}
	if vr.Total != 18 {
		t.Errorf("verified %d surviving rows, want 18", vr.Total)
	}

	// Nothing was lost: the archive holds exactly the removed ids, in order,
	// with their hashes intact.
	got := readSealIDs(t, rep.ExportPath)
	if len(got) != 12 {
		t.Fatalf("archive holds %d rows, want 12", len(got))
	}
	for i, id := range got {
		if id != int64(i+1) {
			t.Fatalf("archive row %d has id %d, want %d", i, id, i+1)
		}
	}

	// And the seal matches its recorded digest.
	statuses, err := VerifySeals(db)
	if err != nil {
		t.Fatalf("verify seals: %v", err)
	}
	if len(statuses) != 1 || !statuses[0].OK {
		t.Fatalf("seal verification failed: %+v", statuses)
	}
}

// readSealIDs parses the JSONL archive and returns the ids in file order.
func readSealIDs(t *testing.T, path string) []int64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open seal: %v", err)
	}
	defer f.Close()
	var src io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, zerr := gzip.NewReader(f)
		if zerr != nil {
			t.Fatalf("open seal as gzip: %v", zerr)
		}
		defer zr.Close()
		src = zr
	}
	var ids []int64
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec struct {
			ID      int64  `json:"id"`
			RowHash string `json:"row_hash"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("archive line is not JSON: %v", err)
		}
		if rec.RowHash == "" {
			t.Fatalf("archive row %d carries no row_hash — the seal is not re-verifiable", rec.ID)
		}
		ids = append(ids, rec.ID)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan seal: %v", err)
	}
	return ids
}

func TestDryRunTouchesNothing(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 10)
	dir := t.TempDir()

	rep, err := Prune(db, Options{Before: rows[5].Timestamp, ExportDir: dir, DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if rep.Pruned {
		t.Fatal("dry run reported a prune")
	}
	if rep.Candidate.Count != 5 {
		t.Errorf("dry run planned %d rows, want 5", rep.Candidate.Count)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("dry run wrote %d files into the export dir", len(entries))
	}
	if vr, err := db.VerifyAuditChain(); err != nil || !vr.OK || vr.Total != 10 {
		t.Errorf("dry run altered the trail: %+v %v", vr, err)
	}
}

func TestPruneRefusesAZeroCutoff(t *testing.T) {
	db := newDB(t)
	if _, err := Prune(db, Options{ExportDir: t.TempDir()}); err == nil {
		t.Fatal("a zero cutoff was accepted; it would prune the whole trail")
	}
}

func TestPruneRefusesWithoutAnExportDir(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 5)
	if _, err := Prune(db, Options{Before: rows[3].Timestamp}); err == nil {
		t.Fatal("prune deleted rows with nowhere to seal them")
	}
	if vr, _ := db.VerifyAuditChain(); vr.Total != 5 {
		t.Errorf("rows were removed despite the refusal: %d remain", vr.Total)
	}
}

// TestSealRefusesABrokenChain is the ordering guarantee that matters most: a
// trail that is already tampered must be reported, not archived and then
// deleted — which would turn a detectable break into a permanent one.
func TestSealRefusesABrokenChain(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 10)

	// Tamper the way a real tamper would: raw SQL behind cloop's back.
	if err := rawExec(db, `UPDATE audit_events SET payload = '{"i":"forged"}' WHERE id = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	dir := t.TempDir()
	_, err := Prune(db, Options{Before: rows[7].Timestamp, ExportDir: dir})
	if err == nil {
		t.Fatal("a tampered prefix was sealed and pruned")
	}
	if !strings.Contains(err.Error(), "broken chain") {
		t.Errorf("error did not name the cause: %v", err)
	}
	// Nothing removed, and no half-written archive left behind.
	var n int
	if err := rawQueryInt(db, `SELECT COUNT(*) FROM audit_events`, &n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 10 {
		t.Errorf("rows removed despite the refusal: %d remain of 10", n)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			t.Errorf("a published archive was left behind after the refusal: %s", e.Name())
		}
	}
}

// TestSuccessivePrunesChainTheirAnchors covers retention applied repeatedly,
// which is what a scheduled `cloop db maintain` does.
func TestSuccessivePrunesChainTheirAnchors(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 30)
	dir := t.TempDir()

	first, err := Prune(db, Options{Before: rows[10].Timestamp, ExportDir: dir})
	if err != nil {
		t.Fatalf("first prune: %v", err)
	}
	second, err := Prune(db, Options{Before: rows[20].Timestamp, ExportDir: dir})
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}

	if second.Anchor.PrevAnchorHash != first.Anchor.AnchorHash {
		t.Errorf("second anchor does not chain onto the first")
	}
	if second.Anchor.PrunedFirstID != first.Anchor.PrunedThroughID+1 {
		t.Errorf("second prune started at id %d, want %d (a gap means rows escaped both archives)",
			second.Anchor.PrunedFirstID, first.Anchor.PrunedThroughID+1)
	}
	vr, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !vr.OK {
		t.Fatalf("chain broken after two prunes at id %d: %s", vr.BreakAtID, vr.Reason)
	}
	if vr.Total != 10 {
		t.Errorf("%d rows survived two prunes of 10 and 10 from 30, want 10", vr.Total)
	}

	// Union of both archives plus the survivors must be the original 30, with
	// no id counted twice.
	seen := map[int64]bool{}
	for _, r := range []*Report{first, second} {
		for _, id := range readSealIDs(t, r.ExportPath) {
			if seen[id] {
				t.Errorf("id %d appears in two archives", id)
			}
			seen[id] = true
		}
	}
	if len(seen) != 20 {
		t.Errorf("archives hold %d rows in total, want 20", len(seen))
	}

	statuses, err := VerifySeals(db)
	if err != nil {
		t.Fatalf("verify seals: %v", err)
	}
	if len(statuses) != 2 {
		t.Fatalf("expected 2 seal statuses, got %d", len(statuses))
	}
	for _, st := range statuses {
		if !st.OK {
			t.Errorf("anchor #%d seal failed: %v", st.Anchor.ID, st.Err)
		}
	}
}

// TestVerifySealsDetectsAnEditedArchive is the check that reaches outside the
// database — the only one an attacker who owns state.db cannot satisfy by
// rewriting a table.
func TestVerifySealsDetectsAnEditedArchive(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 12)
	dir := t.TempDir()

	rep, err := Prune(db, Options{Before: rows[6].Timestamp, ExportDir: dir})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if err := os.WriteFile(rep.ExportPath, []byte(`{"id":1,"actor":"forged"}`+"\n"), 0o600); err != nil {
		t.Fatalf("edit archive: %v", err)
	}
	statuses, err := VerifySeals(db)
	if err != nil {
		t.Fatalf("verify seals: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].OK {
		t.Fatal("an edited archive passed digest verification")
	}
	if !statuses[0].Present {
		t.Error("status should report the file as present but wrong, not missing")
	}

	// The in-database chain is untouched by the archive edit and must still
	// verify — the two checks are independent on purpose.
	if vr, err := db.VerifyAuditChain(); err != nil || !vr.OK {
		t.Errorf("editing an archive should not affect the live chain: %+v %v", vr, err)
	}
}

func TestVerifySealsReportsAMissingArchiveDistinctly(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 8)
	dir := t.TempDir()
	rep, err := Prune(db, Options{Before: rows[4].Timestamp, ExportDir: dir})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if err := os.Remove(rep.ExportPath); err != nil {
		t.Fatalf("remove archive: %v", err)
	}
	statuses, err := VerifySeals(db)
	if err != nil {
		t.Fatalf("verify seals: %v", err)
	}
	if statuses[0].Present {
		t.Error("a removed archive was reported as present")
	}
	if statuses[0].OK {
		t.Error("a removed archive was reported as verified")
	}
}

func TestResolveCutoff(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	got := ResolveCutoff(90, now)
	want := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ResolveCutoff(90) = %s, want %s", got, want)
	}
}

// TestPruneBatchesAcrossTheDefaultBatchSize exercises the multi-batch path,
// where an off-by-one in the cursor would drop or duplicate rows.
func TestPruneBatchesAcrossTheDefaultBatchSize(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 25)
	dir := t.TempDir()

	rep, err := Prune(db, Options{
		Before:    rows[20].Timestamp,
		ExportDir: dir,
		BatchSize: 4, // forces six batches for twenty rows
	})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	ids := readSealIDs(t, rep.ExportPath)
	if len(ids) != 20 {
		t.Fatalf("archive holds %d rows across batches, want 20", len(ids))
	}
	for i, id := range ids {
		if id != int64(i+1) {
			t.Fatalf("batched archive row %d has id %d, want %d", i, id, i+1)
		}
	}
	if vr, err := db.VerifyAuditChain(); err != nil || !vr.OK {
		t.Fatalf("chain broken after a batched prune: %+v %v", vr, err)
	}
}

// rawConn opens a second connection to the same file. Tamper tests use it so
// the mutation goes in behind cloop's back, which is the only way to produce
// the state the chain is supposed to detect — AppendAuditEvent would re-chain
// and hide it.
func rawConn(db *statedb.DB) (*sql.DB, error) {
	path, ok := dbPaths[db]
	if !ok {
		return nil, fmt.Errorf("no recorded path for this database")
	}
	return sql.Open("sqlite", path)
}

func rawExec(db *statedb.DB, stmt string) error {
	conn, err := rawConn(db)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Exec(stmt)
	return err
}

func rawQueryInt(db *statedb.DB, q string, out *int) error {
	conn, err := rawConn(db)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.QueryRow(q).Scan(out)
}

// TestSealIsCompressedByDefaultAndStillVerifiable pins the default and the
// property that makes it safe: the digest covers the file as written, so a
// compressed archive verifies through exactly the same path.
func TestSealIsCompressedByDefaultAndStillVerifiable(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 40)
	dir := t.TempDir()

	rep, err := Prune(db, Options{Before: rows[30].Timestamp, ExportDir: dir})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if !strings.HasSuffix(rep.ExportPath, ".jsonl.gz") {
		t.Errorf("seal is not compressed by default: %s", rep.ExportPath)
	}
	if rep.Anchor.ExportFormat != "jsonl.gz" {
		t.Errorf("anchor records format %q, want jsonl.gz", rep.Anchor.ExportFormat)
	}
	// Readable back, in full, in order.
	ids := readSealIDs(t, rep.ExportPath)
	if len(ids) != 30 {
		t.Fatalf("compressed archive holds %d rows, want 30", len(ids))
	}
	statuses, err := VerifySeals(db)
	if err != nil {
		t.Fatalf("verify seals: %v", err)
	}
	if len(statuses) != 1 || !statuses[0].OK {
		t.Fatalf("compressed seal failed digest verification: %+v", statuses)
	}
	if rep.ExportBytes <= 0 {
		t.Error("anchor recorded no archive size")
	}
}

func TestUncompressedSealOptOut(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := seed(t, db, base, 12)
	dir := t.TempDir()

	rep, err := Prune(db, Options{Before: rows[6].Timestamp, ExportDir: dir, Uncompressed: true})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if !strings.HasSuffix(rep.ExportPath, ".jsonl") || strings.HasSuffix(rep.ExportPath, ".gz") {
		t.Errorf("--no-compress produced %s", rep.ExportPath)
	}
	if got := readSealIDs(t, rep.ExportPath); len(got) != 6 {
		t.Errorf("plain archive holds %d rows, want 6", len(got))
	}
	statuses, _ := VerifySeals(db)
	if len(statuses) != 1 || !statuses[0].OK {
		t.Errorf("plain seal failed digest verification: %+v", statuses)
	}
}
