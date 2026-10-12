package auditcheckpoint

import (
	"testing"
	"time"
)

// Checkpoints written across a change of CLOOP_SECRET_KEY (Task 20425): the
// ones sealed before it carry the old root's fingerprint, the ones after the
// new one's. While the old root is configured as the previous one, both vouch
// for the chain; without it the old ones read as sealed under another key —
// never as forged — and a forged record claiming the old root is refused.
func TestCheckpointsAcrossAChangeOfRootVerify(t *testing.T) {
	const oldRoot, newRoot = "checkpoint-root-old-0123456789", "checkpoint-root-new-abcdefghij"
	path, db := chainDB(t)
	start := time.Now().Add(-time.Hour)
	oldKey, err := DeriveKey(oldRoot)
	if err != nil {
		t.Fatal(err)
	}
	both, err := KeyForRoots(newRoot, oldRoot)
	if err != nil {
		t.Fatal(err)
	}
	if both.PreviousFingerprint() != oldKey.Fingerprint() {
		t.Fatalf("PreviousFingerprint %q, want %q", both.PreviousFingerprint(), oldKey.Fingerprint())
	}

	var recs []Located
	record := func(k *Key, at time.Time) Record {
		head, err := db.AuditHead()
		if err != nil {
			t.Fatal(err)
		}
		r := HeadRecord(head, ChainControlPlane, path, ReasonInterval, 1, "m", at)
		k.Seal(&r)
		recs = append(recs, Located{Record: r, Line: len(recs) + 1})
		return r
	}
	appendRows(t, db, 3, start)
	before := record(oldKey, start.Add(time.Minute))
	appendRows(t, db, 2, start.Add(2*time.Minute))
	after := record(both, start.Add(3*time.Minute))
	if before.KeyFingerprint == after.KeyFingerprint || after.KeyFingerprint != both.Fingerprint() {
		t.Fatalf("seals: before %s, after %s", before.KeyFingerprint, after.KeyFingerprint)
	}

	rep, err := VerifyChain(db, path, ChainControlPlane, recs, both)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Valid != 2 || rep.ForeignKey != 0 {
		t.Fatalf("with the previous root configured: %s — %+v", rep.Finding, rep)
	}
	if got := Usable(recs, both, time.Now()); len(got) != 2 {
		t.Errorf("%d usable records, want both", len(got))
	}

	newOnly, err := DeriveKey(newRoot)
	if err != nil {
		t.Fatal(err)
	}
	rep, err = VerifyChain(db, path, ChainControlPlane, recs, newOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Valid != 1 || rep.ForeignKey != 1 || rep.Refused != 0 {
		t.Fatalf("with the new root alone: %s — %+v", rep.Finding, rep)
	}

	// Claiming the previous root does not get a forgery past the seal.
	forged := before
	forged.LastID++
	if got := Check(forged, both); got != SealBad {
		t.Errorf("a record edited under the previous root's fingerprint checks as %s", got)
	}
	// And the previous root never seals: what a hub mid-change writes is
	// sealed under the current root.
	var fresh Record
	both.Seal(&fresh)
	if fresh.KeyFingerprint != both.Fingerprint() {
		t.Errorf("sealed under %s, want the current root", fresh.KeyFingerprint)
	}
}
