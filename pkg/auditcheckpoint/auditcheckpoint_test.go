package auditcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditretention"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestMain(m *testing.M) {
	// The production work factor is for passphrases travelling through log
	// pipelines; a test derives dozens of keys.
	kdfIterations = 1000
	os.Exit(m.Run())
}

// The checkpoint key comes from the same variable the secret broker seals
// under, so a hub has one root secret.
func TestEnvKeyIsTheSecretBrokers(t *testing.T) {
	if EnvKey != secretbroker.EnvPassphraseKey {
		t.Fatalf("EnvKey = %q, secret broker reads %q", EnvKey, secretbroker.EnvPassphraseKey)
	}
}

// chainDB is a migrated, empty database at a fresh path.
func chainDB(t *testing.T) (string, *statedb.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	statedbtest.Template().Seed(t, path)
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return path, db
}

// appendRows appends n rows timestamped one millisecond apart from start.
func appendRows(t *testing.T, db *statedb.DB, n int, start time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := db.AppendAuditEvent(&statedb.AuditEvent{
			Timestamp: start.Add(time.Duration(i) * time.Millisecond),
			Actor:     "test", EventType: "task.upsert", EntityType: "task",
			EntityID: fmt.Sprint(i), Payload: fmt.Sprintf(`{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// checkpoint is a sealed record of db's head at at, as the hub writes one:
// the newest anchor's archive verified before the record says so.
func checkpoint(t *testing.T, db *statedb.DB, path string, at time.Time, key *Key) Record {
	t.Helper()
	head, err := db.AuditHead()
	if err != nil {
		t.Fatal(err)
	}
	r := HeadRecord(head, ChainProject, path, ReasonInterval, at.Unix()/300, "member-a", at)
	if head.Anchor != nil {
		anchors, err := db.ListAuditAnchors()
		if err != nil {
			t.Fatal(err)
		}
		r.AnchorVerified = VerifyAnchor(anchors, *head.Anchor) == nil
	}
	key.Seal(&r)
	return r
}

// located numbers records the way Parse would.
func located(recs ...Record) []Located {
	out := make([]Located, len(recs))
	for i, r := range recs {
		out[i] = Located{Record: r, Line: i + 1}
	}
	return out
}

// rawSQL opens path behind statedb's back, as an attacker with the file would.
func rawSQL(t *testing.T, path string) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func testKey(t *testing.T, pass string) *Key {
	t.Helper()
	k, err := DeriveKey(pass)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealRoundTrip(t *testing.T) {
	key := testKey(t, "key-one-0123456789abcdef0123456789")
	other := testKey(t, "key-two-0123456789abcdef0123456789")
	if key.Fingerprint() == other.Fingerprint() || len(key.Fingerprint()) != 16 {
		t.Fatalf("fingerprints %q and %q", key.Fingerprint(), other.Fingerprint())
	}
	if again := testKey(t, "key-one-0123456789abcdef0123456789"); again.Fingerprint() != key.Fingerprint() {
		t.Fatal("the same passphrase derived a different key")
	}

	r := Record{Kind: Kind, Version: Version, Chain: ChainControlPlane, Path: "/srv/hub/.cloop/state.db",
		Reason: ReasonInterval, Window: 7, LastID: 41, LastRowHash: strings.Repeat("a", 64), Rows: 41,
		Time: FormatTime(time.Unix(1_800_000_000, 5)), Member: "m1"}
	if got := Check(r, key); got != SealUnsigned {
		t.Errorf("unsigned record checks as %s", got)
	}
	key.Seal(&r)
	if got := Check(r, key); got != SealValid {
		t.Fatalf("a freshly sealed record checks as %s", got)
	}
	if got := Check(r, nil); got != SealUnchecked {
		t.Errorf("without a key: %s", got)
	}
	if got := Check(r, other); got != SealForeignKey {
		t.Errorf("under another key: %s", got)
	}

	// Round trip through the file format keeps the seal valid.
	line, _ := json.Marshal(r)
	parsed, err := Parse(bytes.NewReader(append(line, '\n')))
	if err != nil || len(parsed.Records) != 1 || Check(parsed.Records[0].Record, key) != SealValid {
		t.Fatalf("after a JSON round trip: %+v, %v", parsed, err)
	}

	// Every field is covered.
	for name, edit := range map[string]func(*Record){
		"last_id":   func(r *Record) { r.LastID-- },
		"row hash":  func(r *Record) { r.LastRowHash = strings.Repeat("b", 64) },
		"path":      func(r *Record) { r.Path += "x" },
		"time":      func(r *Record) { r.Time = FormatTime(time.Unix(1_800_000_001, 0)) },
		"chain":     func(r *Record) { r.Chain = ChainProject },
		"anchor":    func(r *Record) { r.AnchorID = 3 },
		"window":    func(r *Record) { r.Window++ },
		"member":    func(r *Record) { r.Member = "m2" },
		"seal only": func(r *Record) { r.KeyFingerprint = "" },
	} {
		edited := r
		edit(&edited)
		if got := Check(edited, key); got != SealBad {
			t.Errorf("editing %s leaves the seal %s", name, got)
		}
	}
}

// The case the task is about: deleting the newest rows leaves a chain that
// verifies, and the checkpoint is what catches it.
func TestDeletingTheNewestRowsIsCaught(t *testing.T) {
	key := testKey(t, "truncation-key-0123456789abcdef")
	path, db := chainDB(t)
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

	appendRows(t, db, 10, t0)
	a := checkpoint(t, db, path, t0.Add(time.Minute), key)
	appendRows(t, db, 5, t0.Add(2*time.Minute))
	b := checkpoint(t, db, path, t0.Add(5*time.Minute), key)

	if rep, err := VerifyChain(db, path, ChainProject, located(a, b), key); err != nil || !rep.OK() {
		t.Fatalf("an untouched chain fails its checkpoints: %+v %v", rep, err)
	}

	if _, err := rawSQL(t, path).Exec(`DELETE FROM audit_events WHERE id > 12`); err != nil {
		t.Fatal(err)
	}
	if v, err := db.VerifyAuditChain(); err != nil || !v.OK {
		t.Fatalf("the shortened chain should still verify on its own (that is the gap): %+v %v", v, err)
	}

	rep, err := VerifyChain(db, path, ChainProject, located(a, b), key)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || len(rep.Failures) != 1 || rep.Failures[0].Result != ResultTruncated {
		t.Fatalf("truncation not caught: %+v", rep)
	}
	want := "tail truncated after id 12 although a checkpoint at " + b.Time + " saw id 15"
	if rep.Finding != want {
		t.Errorf("finding = %q\nwant      %q", rep.Finding, want)
	}
	if rep.Consistent != 1 {
		t.Errorf("the earlier checkpoint (id 10) should still agree: %+v", rep)
	}
}

// A prune removes a prefix on purpose and seals it; a checkpoint below its
// anchor is not truncation, so long as the sealed archive holds the row.
func TestAPruneBelowACheckpointIsNotTruncation(t *testing.T) {
	key := testKey(t, "prune-key-0123456789abcdef012345")
	path, db := chainDB(t)
	old := time.Now().Add(-72 * time.Hour).UTC()
	recent := time.Now().Add(-time.Hour).UTC()

	appendRows(t, db, 10, old)
	below := checkpoint(t, db, path, old.Add(time.Minute), key)
	appendRows(t, db, 5, recent)
	above := checkpoint(t, db, path, recent.Add(time.Minute), key)

	exportDir := t.TempDir()
	rep, err := auditretention.Prune(db, auditretention.Options{
		Before: time.Now().Add(-24 * time.Hour), ExportDir: exportDir, Actor: "test",
	})
	if err != nil || rep.Anchor.PrunedThroughID != 10 {
		t.Fatalf("prune: %+v %v", rep, err)
	}
	afterPrune := checkpoint(t, db, path, time.Now().UTC(), key)

	res, err := VerifyChain(db, path, ChainProject, located(below, above, afterPrune), key)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a prune below a checkpoint was reported: %s (%+v)", res.Finding, res.Failures)
	}
	if res.Pruned != 1 || res.Consistent != 2 {
		t.Errorf("pruned %d, consistent %d; want 1 and 2", res.Pruned, res.Consistent)
	}

	// The archive is what vouches for the pruned row: one that no longer
	// matches its anchor is a finding.
	if err := os.WriteFile(rep.ExportPath, []byte("not the archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _ = VerifyChain(db, path, ChainProject, located(below), key)
	if res.OK() || res.Failures[0].Result != ResultArchiveMismatch {
		t.Errorf("an altered archive passed: %+v", res)
	}

	// One that is simply not here (cold storage) is not — when a sealed
	// checkpoint saw the anchor, which pins its digest and its range.
	if err := os.Remove(rep.ExportPath); err != nil {
		t.Fatal(err)
	}
	res, _ = VerifyChain(db, path, ChainProject, located(below, afterPrune), key)
	if !res.OK() || res.PrunedUnverified != 1 {
		t.Errorf("a moved archive of a vouched-for prune failed the chain: %+v", res)
	}
	// Without a checkpoint that saw the anchor, nothing outside the database
	// says the prune happened, and an unreadable archive fails.
	res, _ = VerifyChain(db, path, ChainProject, located(below), key)
	if res.OK() || res.Failures[0].Result != ResultPruneUnproven {
		t.Errorf("an unvouched prune with no archive passed: %+v", res)
	}
}

// The attack a prune anchor invites: delete the rows a checkpoint saw, write an
// anchor over the hole that claims a prune, and point it at an archive that is
// not there — or at one that merely carries the right hash on the right id.
func TestAForgedPruneIsNotAccepted(t *testing.T) {
	key := testKey(t, "forged-prune-key-0123456789abcdef")
	path, db := chainDB(t)
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	appendRows(t, db, 9, t0)
	cp := checkpoint(t, db, path, t0.Add(time.Minute), key)
	appendRows(t, db, 3, t0.Add(2*time.Minute))

	conn := rawSQL(t, path)
	if _, err := conn.Exec(`DELETE FROM audit_events WHERE id <= 9`); err != nil {
		t.Fatal(err)
	}
	insertAnchor := func(exportPath, exportSHA string) {
		t.Helper()
		if _, err := conn.Exec(`DELETE FROM audit_anchors`); err != nil {
			t.Fatal(err)
		}
		a := statedb.AuditAnchor{ID: 1, CreatedAt: t0.Add(3 * time.Minute), Actor: "cli", Cutoff: t0,
			PrunedFirstID: 1, PrunedThroughID: 9, PrunedCount: 9, BoundaryHash: cp.LastRowHash,
			RetainedFromID: 10, ExportPath: exportPath, ExportFormat: "jsonl", ExportSHA256: exportSHA,
			PrevAnchorHash: statedb.AuditGenesisHash}
		a.AnchorHash, _ = statedb.AuditAnchorLink(a)
		if _, err := conn.Exec(`INSERT INTO audit_anchors(id, created_at, actor, cutoff, pruned_first_id,
			pruned_through_id, pruned_count, boundary_hash, retained_from_id, export_path, export_format,
			export_sha256, export_bytes, prev_anchor_hash, anchor_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			a.ID, FormatTime(a.CreatedAt), a.Actor, FormatTime(a.Cutoff), a.PrunedFirstID, a.PrunedThroughID,
			a.PrunedCount, a.BoundaryHash, a.RetainedFromID, a.ExportPath, a.ExportFormat, a.ExportSHA256, 0,
			a.PrevAnchorHash, a.AnchorHash); err != nil {
			t.Fatal(err)
		}
	}

	// An anchor over the hole: the chain itself now verifies.
	insertAnchor("/nonexistent/archive.jsonl.gz", strings.Repeat("0", 64))
	if v, err := db.VerifyAuditChain(); err != nil || !v.OK {
		t.Fatalf("the forged anchor should satisfy the chain on its own (that is the attack): %+v %v", v, err)
	}
	rep, _ := VerifyChain(db, path, ChainProject, located(cp), key)
	if rep.OK() || rep.Failures[0].Result != ResultPruneUnproven {
		t.Fatalf("a forged prune with no archive passed: %+v", rep)
	}

	// An "archive" holding just the row the checkpoint saw, with its digest
	// written into the anchor, is not the chain the anchor ends in.
	fake := filepath.Join(t.TempDir(), "fake.jsonl")
	body := fmt.Sprintf(`{"id":9,"timestamp":%q,"actor":"x","event_type":"task.upsert","entity_type":"task","entity_id":"8","payload":{},"prev_hash":%q,"row_hash":%q}`+"\n",
		FormatTime(t0), strings.Repeat("a", 64), cp.LastRowHash)
	if err := os.WriteFile(fake, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	insertAnchor(fake, hex.EncodeToString(sum[:]))
	rep, _ = VerifyChain(db, path, ChainProject, located(cp), key)
	if rep.OK() || rep.Failures[0].Result != ResultArchiveMismatch {
		t.Fatalf("a one-row fake archive passed: %+v", rep)
	}

	// And a path that is not a file at all neither hangs nor fills memory.
	insertAnchor("/dev/zero", strings.Repeat("0", 64))
	rep, _ = VerifyChain(db, path, ChainProject, located(cp), key)
	if rep.OK() || !strings.Contains(rep.Failures[0].Detail, "not a regular file") {
		t.Fatalf("/dev/zero as an archive: %+v", rep)
	}

	// The hub's next checkpoint sees the forged anchor. It reads the archive
	// before it says anything about it, finds nothing, and records the anchor
	// unverified — so its seal vouches for nothing, and the prune still fails.
	insertAnchor("/nonexistent/archive.jsonl.gz", strings.Repeat("0", 64))
	next := checkpoint(t, db, path, t0.Add(10*time.Minute), key)
	if next.AnchorID == 0 || next.AnchorVerified {
		t.Fatalf("the hub's checkpoint vouched for a forged anchor: %+v", next)
	}
	rep, _ = VerifyChain(db, path, ChainProject, located(cp, next), key)
	if rep.OK() || rep.Failures[0].Result != ResultPruneUnproven {
		t.Fatalf("a forged prune passed once a checkpoint had seen its anchor: %+v", rep)
	}
}

// A prune that commits while the records are being judged removes rows the
// verifier's first read did not know were going. They are re-read before a
// row is called deleted.
func TestAPruneDuringVerificationIsNotDeletion(t *testing.T) {
	key := testKey(t, "prune-race-key-0123456789abcdef0")
	path, db := chainDB(t)
	old := time.Now().Add(-72 * time.Hour).UTC()
	appendRows(t, db, 6, old)
	below := checkpoint(t, db, path, old.Add(time.Minute), key)
	appendRows(t, db, 2, time.Now().Add(-time.Hour).UTC())

	v := &verifier{db: db, key: key}
	if err := v.load(); err != nil {
		t.Fatal(err)
	}
	// The prune lands after the verifier read the anchors.
	if _, err := auditretention.Prune(db, auditretention.Options{
		Before: time.Now().Add(-24 * time.Hour), ExportDir: t.TempDir(), Actor: "test",
	}); err != nil {
		t.Fatal(err)
	}
	c := Checked{Located: located(below)[0], Seal: Check(below, key)}
	if _, err := v.judge(&c); err != nil {
		t.Fatal(err)
	}
	if c.Result != ResultPruned {
		t.Errorf("a row pruned mid-verification was judged %s: %s", c.Result, c.Detail)
	}
}

func TestParseSkipsOversizedLines(t *testing.T) {
	r := Record{Kind: Kind, Version: Version, Chain: ChainProject, Path: "/p/.cloop/state.db",
		LastID: 4, Time: FormatTime(time.Unix(1_800_000_000, 0))}
	line, _ := json.Marshal(r)
	input := string(line) + "\n" + strings.Repeat("x", maxLine+10) + "\n" + string(line) + "\n"
	res, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || res.Records[1].Line != 3 || len(res.Oversized) != 1 || res.Oversized[0] != 2 {
		t.Fatalf("records %d (lines %v), oversized %v", len(res.Records), res.Records, res.Oversized)
	}
}

// A record whose seal does not verify is refused: an attacker who truncated
// the chain must not be able to write a checkpoint that agrees with it.
func TestACheckpointWithABadSealIsRefused(t *testing.T) {
	key := testKey(t, "seal-key-0123456789abcdef01234567")
	path, db := chainDB(t)
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	appendRows(t, db, 8, t0)

	if _, err := rawSQL(t, path).Exec(`DELETE FROM audit_events WHERE id > 5`); err != nil {
		t.Fatal(err)
	}
	forged := checkpoint(t, db, path, t0.Add(time.Hour), key)
	// Forged by someone without the key: the record says the truncated head
	// is the real one, under a seal that is not this key's.
	forged.Seal = strings.Repeat("0", 64)

	rep, err := VerifyChain(db, path, ChainProject, located(forged), key)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || rep.Refused != 1 || rep.Failures[0].Result != ResultRefused {
		t.Fatalf("a forged checkpoint was not refused: %+v", rep)
	}
	if !strings.HasPrefix(rep.Finding, "checkpoint refused") {
		t.Errorf("finding = %q", rep.Finding)
	}
	if rep.Consistent != 0 || rep.Newest != nil {
		t.Errorf("the refused record was used: %+v", rep)
	}
}

// A database restored from an older backup and written to since diverges from
// the checkpoints after the backup, and is named as restored.
func TestAnOlderRestoredBackupIsNamed(t *testing.T) {
	key := testKey(t, "restore-key-0123456789abcdef0123")
	path, db := chainDB(t)
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

	appendRows(t, db, 10, t0)
	a := checkpoint(t, db, path, t0.Add(time.Minute), key)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	copyFile(t, path, backup)

	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	appendRows(t, db, 10, t0.Add(2*time.Minute))
	b := checkpoint(t, db, path, t0.Add(5*time.Minute), key)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Restore the backup, and let the hub carry on writing.
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
	copyFile(t, backup, path)
	db, err = statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	appendRows(t, db, 3, t0.Add(10*time.Minute))

	rep, err := VerifyChain(db, path, ChainProject, located(a, b), key)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || rep.Failures[0].Result != ResultRestored {
		t.Fatalf("restore not named: %+v", rep)
	}
	want := "the database was restored from a backup older than " + b.Time +
		": it still agrees with the checkpoint at " + a.Time + " (id 10), and has been written to since"
	if rep.Finding != want {
		t.Errorf("finding = %q\nwant      %q", rep.Finding, want)
	}

	// Write past the id the second checkpoint saw: the id is reused by a
	// different, later row — still a restore, not a rewrite.
	appendRows(t, db, 10, t0.Add(20*time.Minute))
	rep, _ = VerifyChain(db, path, ChainProject, located(a, b), key)
	if rep.OK() || rep.Failures[0].Result != ResultRestored {
		t.Errorf("with the id reused: %+v", rep)
	}
}

// Rewriting a row and recomputing every hash after it gives a chain that
// verifies; the checkpoint still knows the hash it saw.
func TestRewrittenHistoryIsCaught(t *testing.T) {
	key := testKey(t, "rewrite-key-0123456789abcdef0123")
	path, db := chainDB(t)
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	appendRows(t, db, 10, t0)
	cp := checkpoint(t, db, path, t0.Add(time.Minute), key)

	conn := rawSQL(t, path)
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	prev := rows[3].RowHash
	for _, ev := range rows[4:] {
		if ev.ID == 5 {
			ev.Payload = `{"i":"rewritten"}`
		}
		ev.PrevHash = prev
		ev.RowHash, _ = statedb.AuditChainLink(ev)
		if _, err := conn.Exec(`UPDATE audit_events SET payload=?, prev_hash=?, row_hash=? WHERE id=?`,
			ev.Payload, ev.PrevHash, ev.RowHash, ev.ID); err != nil {
			t.Fatal(err)
		}
		prev = ev.RowHash
	}
	if v, err := db.VerifyAuditChain(); err != nil || !v.OK {
		t.Fatalf("the re-hashed chain should verify on its own: %+v %v", v, err)
	}
	rep, err := VerifyChain(db, path, ChainProject, located(cp), key)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || rep.Failures[0].Result != ResultRewritten {
		t.Fatalf("rewrite not caught: %+v", rep)
	}
}

// A checkpoint that saw a prune anchor the database no longer has means the
// database is older than the checkpoint.
func TestAMissingAnchorIsNamed(t *testing.T) {
	key := testKey(t, "anchor-key-0123456789abcdef01234")
	path, db := chainDB(t)
	appendRows(t, db, 6, time.Now().Add(-72*time.Hour).UTC())
	appendRows(t, db, 2, time.Now().Add(-time.Hour).UTC())
	if _, err := auditretention.Prune(db, auditretention.Options{
		Before: time.Now().Add(-24 * time.Hour), ExportDir: t.TempDir(), Actor: "test",
	}); err != nil {
		t.Fatal(err)
	}
	cp := checkpoint(t, db, path, time.Now().UTC(), key)
	if cp.AnchorID == 0 {
		t.Fatal("the checkpoint did not record the anchor")
	}
	if _, err := rawSQL(t, path).Exec(`DELETE FROM audit_anchors`); err != nil {
		t.Fatal(err)
	}
	rep, _ := VerifyChain(db, path, ChainProject, located(cp), key)
	if rep.OK() || rep.Failures[0].Result != ResultAnchorMissing {
		t.Fatalf("a missing anchor was not named: %+v", rep)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// Records reach an operator through log pipelines as often as through the
// file; Parse reads them out of whatever wraps them.
func TestParseFindsRecordsInLogExports(t *testing.T) {
	r := Record{Kind: Kind, Version: Version, Chain: ChainProject, Path: "/p/.cloop/state.db",
		Reason: ReasonInterval, LastID: 3, Time: FormatTime(time.Unix(1_800_000_000, 0))}
	line, _ := json.Marshal(r)
	quoted, _ := json.Marshal(string(line))

	input := strings.Join([]string{
		string(line), // the file
		"Oct 10 12:00:00 hub cloop[42]: " + string(line),                                 // journald short
		`{"log":` + string(quoted) + `,"stream":"stderr","time":"2026-10-10T12:00:00Z"}`, // docker json-file
		`{"MESSAGE":` + string(quoted) + `,"_PID":"42"}`,                                 // journalctl -o json
		"cloop dashboard running at http://127.0.0.1:8080",                               // unrelated
		`{"kind":"` + Kind + `","last_id":`,                                              // torn write
	}, "\n")
	res, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 4 {
		t.Fatalf("found %d records, want 4: %+v", len(res.Records), res.Records)
	}
	for _, got := range res.Records {
		if got.LastID != 3 || got.Path != r.Path {
			t.Errorf("record on line %d = %+v", got.Line, got.Record)
		}
	}
	if len(res.Malformed) != 1 || res.Malformed[0] != 6 {
		t.Errorf("malformed = %v, want [6]", res.Malformed)
	}
}

func TestCheckFileKeepsCheckpointsOutOfCloopDirs(t *testing.T) {
	root := t.TempDir()
	cloopDir := filepath.Join(root, "proj", ".cloop")
	if err := os.MkdirAll(cloopDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "audit")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "sneaky")
	if err := os.Symlink(cloopDir, link); err != nil {
		t.Fatal(err)
	}
	// The file itself a link into .cloop, from a directory outside it.
	fileLink := filepath.Join(outside, "linked.jsonl")
	if err := os.Symlink(filepath.Join(cloopDir, "cps.jsonl"), fileLink); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cloopDir, "cps.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	danglingLink := filepath.Join(outside, "dangling.jsonl")
	if err := os.Symlink(filepath.Join(cloopDir, "not-yet.jsonl"), danglingLink); err != nil {
		t.Fatal(err)
	}

	for path, wantErr := range map[string]bool{
		filepath.Join(outside, "cps.jsonl"):  false,
		filepath.Join(cloopDir, "cps.jsonl"): true,
		filepath.Join(link, "cps.jsonl"):     true, // resolves into .cloop
		fileLink:                             true, // the file resolves into .cloop
		danglingLink:                         true, // a link to nothing yet, inside .cloop
		"/dev/null":                          true, // not a regular file
		"relative/cps.jsonl":                 true,
		filepath.Join(root, "nope", "x.log"): true, // directory missing
		outside:                              true, // a directory
	} {
		err := CheckFile(path)
		if (err != nil) != wantErr {
			t.Errorf("CheckFile(%s) = %v, want error %v", path, err, wantErr)
		}
	}
}

func TestSinkAppendsToTheFileAndStderr(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cps.jsonl")
	var stderr bytes.Buffer
	sink := Sink{File: file, Stderr: &stderr}
	r := Record{Kind: Kind, Version: Version, Chain: ChainProject, Path: "/p", LastID: 1,
		Time: FormatTime(time.Now())}
	if err := sink.Write([]Record{r, r}); err != nil {
		t.Fatal(err)
	}
	r.LastID = 2
	if err := sink.Write([]Record{r}); err != nil {
		t.Fatal(err)
	}
	parsed, err := ReadFile(file)
	if err != nil || len(parsed.Records) != 3 || parsed.Records[2].LastID != 2 {
		t.Fatalf("file holds %+v (%v), want three records appended", parsed.Records, err)
	}
	if n := strings.Count(stderr.String(), "\n"); n != 3 {
		t.Errorf("stderr got %d lines, want 3", n)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}

	if err := (Sink{File: filepath.Join(t.TempDir(), ".cloop", "x")}).Write([]Record{r}); err == nil {
		t.Error("a sink wrote inside .cloop")
	}
}
