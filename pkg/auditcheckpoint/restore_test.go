package auditcheckpoint

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// restoreScenario is a chain that was backed up at id 10, went on to id 15
// (which a checkpoint saw), and was then restored: the rows after 10 are
// gone, the restore appended its own row as id 11, and the hub carried on.
type restoreScenario struct {
	path    string
	db      *statedb.DB
	key     *Key
	t0      time.Time
	before  Record // the checkpoint at id 10, before the backup was taken
	lost    Record // the checkpoint at id 15, which the restore supersedes
	backup  statedb.AuditHead
	restore Record // sealed restore record
	after   Record // a checkpoint of the restored chain
}

func newRestoreScenario(t *testing.T) *restoreScenario {
	t.Helper()
	s := &restoreScenario{key: testKey(t, "restore-record-key-0123456789abcdef")}
	s.path, s.db = chainDB(t)
	// Hours ago, not a fixed date: a restore record dated ahead of the
	// verifier's clock is refused, and the scenario must not depend on when
	// the suite runs.
	s.t0 = time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)

	appendRows(t, s.db, 10, s.t0)
	s.before = checkpoint(t, s.db, s.path, s.t0.Add(time.Minute), s.key)
	var err error
	if s.backup, err = s.db.AuditHead(); err != nil {
		t.Fatal(err)
	}
	appendRows(t, s.db, 5, s.t0.Add(2*time.Minute))
	s.lost = checkpoint(t, s.db, s.path, s.t0.Add(5*time.Minute), s.key)

	// The restore: back to the backup's head, then its own row.
	if _, err := rawSQL(t, s.path).Exec(`DELETE FROM audit_events WHERE id > 10`); err != nil {
		t.Fatal(err)
	}
	at := s.t0.Add(30 * time.Minute)
	ev := &statedb.AuditEvent{Timestamp: at, Actor: "cli:alice", EventType: "audit.restored",
		EntityType: "audit", Payload: `{"reason":"disk failure"}`}
	if err := s.db.AppendAuditEvent(ev); err != nil {
		t.Fatal(err)
	}
	head, err := s.db.AuditHead()
	if err != nil {
		t.Fatal(err)
	}
	x := RestoreFrom(s.backup)
	x.BackupSHA256, x.BackupTime, x.Sidecar = strings.Repeat("ab", 32), FormatTime(s.t0.Add(90*time.Second)), "sealed"
	x.SupersededID, x.SupersededRowHash, x.SupersededTime = s.lost.LastID, s.lost.LastRowHash, s.lost.Time
	x.Actor, x.Reason = "cli:alice", "disk failure on hub-1"
	s.restore = RestoreRecord(head, ChainControlPlane, s.path, "hub-1-4242", at, x)
	s.key.Seal(&s.restore)

	appendRows(t, s.db, 3, s.t0.Add(40*time.Minute))
	s.after = checkpoint(t, s.db, s.path, s.t0.Add(45*time.Minute), s.key)
	return s
}

func (s *restoreScenario) verify(t *testing.T, key *Key, recs ...Record) ChainReport {
	t.Helper()
	rep, err := VerifyChain(s.db, s.path, ChainControlPlane, located(recs...), key)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// Without a restore record, a restore and a tail deleted while the hub kept
// writing are the same finding — which is right: nothing outside the
// database says otherwise.
func TestARestoreWithoutARecordStillFails(t *testing.T) {
	s := newRestoreScenario(t)
	rep := s.verify(t, s.key, s.before, s.lost, s.after)
	if rep.OK() || rep.Failures[0].Result != ResultRestored {
		t.Fatalf("an unrecorded restore passed: %+v", rep)
	}
	if !strings.Contains(rep.Hint, "no restore record accounts for it") {
		t.Errorf("hint %q", rep.Hint)
	}
}

// A sealed restore record accounts for the checkpoints sealed before it that
// saw past the head it restored to, and the verdict names what was lost.
func TestASealedRestoreRecordIsAcknowledged(t *testing.T) {
	s := newRestoreScenario(t)
	rep := s.verify(t, s.key, s.before, s.lost, s.restore, s.after)
	if !rep.OK() {
		t.Fatalf("an acknowledged restore failed: %s — %+v", rep.Finding, rep.Failures)
	}
	if rep.Acknowledged != 1 || rep.Consistent != 3 || rep.RestoreRecords != 1 || len(rep.Restores) != 1 {
		t.Fatalf("report %+v", rep)
	}
	f := rep.Restores[0]
	if f.Superseded != 1 || f.LostEvents != 5 || f.LostFromID != 11 || f.LostThroughID != 15 {
		t.Errorf("finding %+v", f)
	}
	want := fmt.Sprintf("restored (acknowledged): 5 events lost between %s and %s, by cli:alice, reason %q",
		FormatTime(s.backup.LastTimestamp), s.lost.Time, "disk failure on hub-1")
	if got := f.Summary(); got != want {
		t.Errorf("summary\n got %q\nwant %q", got, want)
	}
	for _, c := range []Checked{f.Record} {
		if c.Line != 3 {
			t.Errorf("the restore record is on line %d", c.Line)
		}
	}
}

// The superseded checkpoint is accounted for by the restore record however
// the verifier meets them — the restore record is the explanation, wherever it
// was read from.
func TestARestoreRecordSurvivesTheFileRoundTrip(t *testing.T) {
	s := newRestoreScenario(t)
	var lines []string
	for _, r := range []Record{s.before, s.lost, s.restore, s.after} {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	parsed, err := Parse(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil || len(parsed.Records) != 4 {
		t.Fatalf("%+v %v", parsed, err)
	}
	rep, err := VerifyChain(s.db, s.path, ChainControlPlane, parsed.Records, s.key)
	if err != nil || !rep.OK() || len(rep.Restores) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := Check(parsed.Records[2].Record, s.key); got != SealValid {
		t.Fatalf("the restore record read back checks as %s", got)
	}
}

// Deleting the tail while the hub keeps writing after a restore is still a
// finding: the record accounts only for checkpoints sealed before it.
func TestATruncationAfterTheRestoreIsNotAcknowledged(t *testing.T) {
	s := newRestoreScenario(t)
	if _, err := rawSQL(t, s.path).Exec(`DELETE FROM audit_events WHERE id > 12`); err != nil {
		t.Fatal(err)
	}
	appendRows(t, s.db, 4, s.t0.Add(50*time.Minute))
	rep := s.verify(t, s.key, s.before, s.lost, s.restore, s.after)
	if rep.OK() {
		t.Fatalf("a truncation after the restore passed: %+v", rep)
	}
	if first := rep.Failures[0]; first.Line != 4 || first.Result != ResultRestored {
		t.Fatalf("first failure %+v; want the post-restore checkpoint", first)
	}
	if rep.Acknowledged != 1 {
		t.Errorf("the pre-restore checkpoint is still acknowledged: %+v", rep)
	}
}

// A restore record nobody sealed is refused — written by hand, it would be a
// way to explain any truncation away — and so is one whose seal was forged.
func TestAHandWrittenRestoreRecordIsRefused(t *testing.T) {
	s := newRestoreScenario(t)

	unsigned := s.restore
	unsigned.Seal, unsigned.KeyFingerprint = "", ""
	rep := s.verify(t, s.key, s.before, s.lost, unsigned, s.after)
	if rep.OK() || rep.Refused != 1 || rep.Acknowledged != 0 {
		t.Fatalf("an unsigned restore record was accepted: %+v", rep)
	}
	if rep.Failures[0].Result != ResultRestored {
		t.Errorf("the superseded checkpoint is the first finding: %+v", rep.Failures)
	}
	if !strings.Contains(rep.Hint, "restore record on line 3") || !strings.Contains(rep.Hint, "carries no seal") {
		t.Errorf("hint %q", rep.Hint)
	}

	forged := s.restore
	forged.Restore = &Restore{}
	*forged.Restore = *s.restore.Restore
	forged.Restore.SupersededID = 99 // claims to account for more
	rep = s.verify(t, s.key, s.before, s.lost, forged, s.after)
	if rep.OK() || rep.Refused != 1 {
		t.Fatalf("an edited restore record was accepted: %+v", rep)
	}

	// Half a restore record — the reason without the section, or the
	// section under another reason — was never written by `cloop db restore`.
	half := s.restore
	half.Restore = nil
	s.key.Seal(&half)
	if rep = s.verify(t, s.key, s.before, s.lost, half, s.after); rep.OK() || rep.Refused != 1 {
		t.Fatalf("half a restore record was accepted: %+v", rep)
	}

	// Adding a restore section to a sealed checkpoint breaks its seal.
	dressed := s.after
	dressed.Restore = s.restore.Restore
	if got := Check(dressed, s.key); got != SealBad {
		t.Fatalf("a checkpoint dressed as a restore checks as %s", got)
	}
}

// A restore record pins the head the chain was restored to and the restore's
// own row. A chain that no longer holds them was cut back or rewritten after
// the restore, and the record accounts for nothing.
func TestARestoreRecordTheChainNoLongerHoldsFails(t *testing.T) {
	s := newRestoreScenario(t)
	if _, err := rawSQL(t, s.path).Exec(`DELETE FROM audit_events WHERE id > 10`); err != nil {
		t.Fatal(err)
	}
	appendRows(t, s.db, 6, s.t0.Add(time.Hour))
	rep := s.verify(t, s.key, s.before, s.lost, s.restore)
	if rep.OK() || rep.Acknowledged != 0 {
		t.Fatalf("a restore record the chain lost still accounted for something: %+v", rep)
	}
	var mismatch bool
	for _, f := range rep.Failures {
		if f.Result == ResultRestoreMismatch && f.Line == 3 {
			mismatch = true
		}
	}
	if !mismatch {
		t.Fatalf("the restore record is not named: %+v", rep.Failures)
	}

	// A record sealed under the key, claiming a restored head the chain never
	// had, fails as well.
	s = newRestoreScenario(t)
	wrong := s.restore
	x := *wrong.Restore
	x.RestoredRowHash = strings.Repeat("0", 64)
	wrong.Restore = &x
	s.key.Seal(&wrong)
	rep = s.verify(t, s.key, s.before, s.lost, wrong, s.after)
	if rep.OK() {
		t.Fatalf("a restore record whose restored head does not match passed: %+v", rep)
	}
	if rep.Failures[len(rep.Failures)-1].Result != ResultRestoreMismatch {
		t.Errorf("failures %+v", rep.Failures)
	}
}

// Only a record sealed under the key the verifier holds accounts for
// anything. Without a key nothing does, and the finding says what is missing.
func TestARestoreRecordCountsOnlyUnderTheVerifiersKey(t *testing.T) {
	s := newRestoreScenario(t)

	rep := s.verify(t, nil, s.before, s.lost, s.restore, s.after)
	if rep.OK() || rep.UntrustedRestores != 1 {
		t.Fatalf("without a key: %+v", rep)
	}
	if !strings.Contains(rep.Hint, "no "+EnvKey+" here to check its seal") {
		t.Errorf("hint %q", rep.Hint)
	}

	other := testKey(t, "some-other-hubs-key-0123456789abcdef")
	rep = s.verify(t, other, s.before, s.lost, s.restore, s.after)
	if rep.OK() || rep.UntrustedRestores != 1 {
		t.Fatalf("under another key: %+v", rep)
	}
	if !strings.Contains(rep.Hint, "sealed under another key") {
		t.Errorf("hint %q", rep.Hint)
	}
}

// A second restore, to an older backup, supersedes the first one's record
// along with everything else sealed before it.
func TestASecondRestoreSupersedesTheFirst(t *testing.T) {
	s := newRestoreScenario(t)

	// Restore again, to a backup at id 5.
	if _, err := rawSQL(t, s.path).Exec(`DELETE FROM audit_events WHERE id > 5`); err != nil {
		t.Fatal(err)
	}
	at := s.t0.Add(2 * time.Hour)
	if err := s.db.AppendAuditEvent(&statedb.AuditEvent{Timestamp: at, Actor: "cli:bob",
		EventType: "audit.restored", EntityType: "audit", Payload: "{}"}); err != nil {
		t.Fatal(err)
	}
	head, _ := s.db.AuditHead()
	five, ok, err := s.db.AuditRowAt(5)
	if err != nil || !ok {
		t.Fatal(err)
	}
	x := Restore{RestoredID: 5, RestoredRowHash: five.RowHash, RestoredTime: FormatTime(five.Timestamp),
		BackupSHA256: strings.Repeat("cd", 32), Sidecar: "sealed", Actor: "cli:bob",
		Reason: "the first restore used the wrong backup"}
	second := RestoreRecord(head, ChainControlPlane, s.path, "hub-1-5151", at, x)
	s.key.Seal(&second)

	rep := s.verify(t, s.key, s.before, s.lost, s.restore, s.after, second)
	if !rep.OK() {
		t.Fatalf("%s — %+v", rep.Finding, rep.Failures)
	}
	if len(rep.Restores) != 1 || rep.Restores[0].Record.Line != 5 {
		t.Fatalf("restores %+v", rep.Restores)
	}
	if rep.Acknowledged != 4 {
		t.Errorf("acknowledged %d; want the four records sealed before the second restore", rep.Acknowledged)
	}
}

// Superseded is what the restore command records: the newest trusted record,
// when it saw past the restored head.
func TestSupersededIsTheNewestTrustedRecordPastTheHead(t *testing.T) {
	s := newRestoreScenario(t)
	recs := located(s.before, s.lost)
	now := s.t0.Add(time.Hour)
	if got, ok := Superseded(recs, s.key, 10, now); !ok || got.LastID != 15 {
		t.Fatalf("got %+v %v", got, ok)
	}
	if _, ok := Superseded(recs, s.key, 15, now); ok {
		t.Error("a record within the restored head was superseded")
	}
	unsigned := s.lost
	unsigned.Seal, unsigned.KeyFingerprint = "", ""
	if got, ok := Superseded(located(s.before, unsigned), s.key, 10, now); ok {
		t.Errorf("an unsigned record was taken as superseded under a key: %+v", got)
	}
}

// A restore record's time decides which records it accounts for, so one dated
// ahead of the verifier's clock is refused rather than allowed to account for
// records not yet written.
func TestAFutureDatedRestoreRecordIsRefused(t *testing.T) {
	s := newRestoreScenario(t)
	future := s.restore
	future.Time = FormatTime(time.Now().Add(time.Hour))
	s.key.Seal(&future)
	rep := s.verify(t, s.key, s.before, s.lost, future, s.after)
	if rep.OK() || rep.Refused != 1 || rep.Acknowledged != 0 {
		t.Fatalf("a future-dated restore record was used: %+v", rep)
	}
	var refused Checked
	for _, f := range rep.Failures {
		if f.Result == ResultRefused {
			refused = f
		}
	}
	if !strings.Contains(refused.Detail, "ahead of this verifier's clock") {
		t.Errorf("detail %q", refused.Detail)
	}
}

// A restore of a backup nothing vouched for — restored with --skip-checksum
// or --allow-unsealed — is acknowledged for what it lost, and says what it
// put back was unchecked.
func TestAnUnvouchedRestoreSaysSo(t *testing.T) {
	s := newRestoreScenario(t)
	unchecked := s.restore
	x := *unchecked.Restore
	x.Sidecar = "skipped"
	unchecked.Restore = &x
	s.key.Seal(&unchecked)
	rep := s.verify(t, s.key, s.before, s.lost, unchecked, s.after)
	if !rep.OK() || len(rep.Restores) != 1 || rep.Restores[0].Vouched() {
		t.Fatalf("%+v", rep)
	}
	if got := rep.Restores[0].Summary(); !strings.Contains(got, "from a backup nothing vouched for (its sidecar skipped)") {
		t.Errorf("summary %q", got)
	}
	// The sidecar state is under the seal.
	edited := s.restore
	ex := *edited.Restore
	ex.Sidecar = "skipped"
	edited.Restore = &ex
	if got := Check(edited, s.key); got != SealBad {
		t.Errorf("a restore record whose sidecar state was edited checks as %s", got)
	}
}
