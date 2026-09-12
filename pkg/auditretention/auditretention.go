// Package auditretention seals and prunes the audit trail (Task 20218).
//
// The audit_events table had no retention path: nothing pruned it, pkg/compact
// did not touch it, and on this project's own hub it reached 1,096,198 rows and
// 2.44 GB. Giving it a DELETE was not enough, because the table is hash-chained
// and Task 20167 ships a verifier — an unexplained truncation is indistinguish-
// able from tampering, and correctly reported as such.
//
// So a prune here is three things that must all happen or none of them:
//
//  1. SEAL. The prefix is streamed to a JSONL file, chain-verified row by row
//     on the way out, and digested. Nothing is deleted before that file is on
//     disk and fsynced.
//  2. TRUNCATE. The rows are deleted.
//  3. ANCHOR. A row records the boundary hash, the surviving id, and the
//     export's digest and location, so the verifier can walk across the gap.
//
// Steps 2 and 3 are one transaction inside statedb; step 1 completes before
// either. A crash anywhere leaves a state that is either "not pruned" or
// "pruned and explained", never "pruned and unexplained".
//
// Why the seal is always JSONL, whatever the operator's SIEM prefers: it is
// the only lossless format pkg/auditexport offers — CEF truncates payloads and
// CSV cannot be appended in batches without a second header — and an archive
// that has lost bytes cannot answer the question it was kept for. Converting a
// seal into CEF or CSV afterwards is `cloop audit-log export`; converting the
// other way is impossible.
package auditretention

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditexport"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// DefaultExportDirName is where seals land under a project's .cloop directory
// when the operator has not chosen somewhere else.
const DefaultExportDirName = "audit-archive"

// Options configures a prune.
type Options struct {
	// Before is the cutoff: rows with a timestamp strictly older are eligible.
	// Required — a zero value is rejected rather than silently interpreted as
	// "now", which would prune the entire trail.
	Before time.Time

	// ExportDir is the directory the seal is written to. Created if missing.
	ExportDir string

	// Actor is recorded on the anchor. Defaults to "system".
	Actor string

	// DryRun resolves and reports the candidate without writing or deleting
	// anything — not even the export.
	DryRun bool

	// BatchSize is how many rows are read and written per round trip. Zero
	// selects a sane default. Bounded internally.
	BatchSize int

	// Now is injected by tests. Production leaves it nil.
	Now func() time.Time
}

// Report describes what a prune did, or would have done.
type Report struct {
	DryRun bool
	Cutoff time.Time

	// Candidate is the resolved prefix. Count == 0 means there was nothing
	// older than the cutoff and no other field is meaningful.
	Candidate statedb.AuditPruneCandidate

	ExportPath   string
	ExportSHA256 string
	ExportBytes  int64

	// Anchor is the row written. Zero when DryRun or when nothing was pruned.
	Anchor statedb.AuditAnchor

	// Pruned reports that rows were actually deleted.
	Pruned bool
}

// ResolveCutoff turns a retention window in days into an instant.
func ResolveCutoff(retentionDays int, now time.Time) time.Time {
	return now.UTC().AddDate(0, 0, -retentionDays)
}

// Prune seals and removes the audit prefix older than opts.Before.
//
// It is safe to run against a live hub: the seal reads in bounded batches that
// release the database mutex between them, and the truncation is a single
// transaction. It does not VACUUM — reclaiming the freed pages is
// `cloop db maintain`, which has to care about peer hubs in a way this does
// not. See cmd/hub_audit_cmd.go.
func Prune(db *statedb.DB, opts Options) (*Report, error) {
	if db == nil {
		return nil, errors.New("auditretention: nil database")
	}
	if opts.Before.IsZero() {
		return nil, errors.New("auditretention: a cutoff is required (refusing to default to now, which would prune the whole trail)")
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	actor := strings.TrimSpace(opts.Actor)
	if actor == "" {
		actor = "system"
	}

	cand, err := db.PlanAuditPrune(opts.Before)
	if err != nil {
		return nil, err
	}
	rep := &Report{DryRun: opts.DryRun, Cutoff: opts.Before.UTC(), Candidate: cand}
	if cand.Count == 0 {
		return rep, nil
	}
	if opts.DryRun {
		return rep, nil
	}

	dir := strings.TrimSpace(opts.ExportDir)
	if dir == "" {
		return nil, errors.New("auditretention: no export directory (refusing to delete an unsealed prefix)")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("auditretention: create export dir: %w", err)
	}

	// The seal is named for the range it holds and the moment it was taken, so
	// successive prunes never collide and a directory listing reads as a
	// timeline without opening anything.
	name := fmt.Sprintf("audit-%d-%d-%s.jsonl",
		cand.FirstID, cand.ThroughID, now().UTC().Format("20060102T150405Z"))
	finalPath := filepath.Join(dir, name)

	digest, written, err := sealPrefix(db, cand, finalPath, opts.BatchSize)
	if err != nil {
		return nil, err
	}
	rep.ExportPath = finalPath
	rep.ExportSHA256 = digest
	rep.ExportBytes = written

	anchor, err := db.PruneAuditPrefix(statedb.AuditAnchor{
		CreatedAt:       now().UTC(),
		Actor:           actor,
		Cutoff:          opts.Before.UTC(),
		PrunedFirstID:   cand.FirstID,
		PrunedThroughID: cand.ThroughID,
		BoundaryHash:    cand.BoundaryHash,
		ExportPath:      finalPath,
		ExportFormat:    string(auditexport.FormatJSONL),
		ExportSHA256:    digest,
		ExportBytes:     written,
	})
	if err != nil {
		// The seal is already on disk and the rows are still in the database.
		// Leaving the file is deliberate: it is a valid archive of rows that
		// still exist, which is harmless, whereas deleting it here would
		// discard the only artifact an operator could use to work out how far
		// the interrupted prune got.
		return nil, fmt.Errorf("auditretention: prune after sealing to %s: %w", finalPath, err)
	}
	rep.Anchor = anchor
	rep.Pruned = true
	return rep, nil
}

// sealPrefix streams rows [cand.FirstID, cand.ThroughID] to path as JSONL,
// verifying the chain as it goes, and returns the file's SHA-256 and size.
//
// Verification during the seal is the point at which a pre-existing break has
// to be caught. Afterwards the rows are gone from the database and the only
// copy is this file; sealing a broken chain and then deleting the original
// would convert a detectable tamper into an archived one.
func sealPrefix(db *statedb.DB, cand statedb.AuditPruneCandidate, path string, batch int) (digest string, written int64, err error) {
	// Establish what the first row's prev_hash must be: the boundary of an
	// earlier prune if there was one, genesis otherwise.
	expectedPrev := statedb.AuditGenesisHash
	prior, aerr := db.LatestAuditAnchor()
	switch {
	case aerr == nil:
		expectedPrev = prior.BoundaryHash
	case errors.Is(aerr, statedb.ErrAuditAnchorNotFound):
	default:
		return "", 0, aerr
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".audit-seal-*.jsonl.tmp")
	if err != nil {
		return "", 0, fmt.Errorf("auditretention: create seal: %w", err)
	}
	tmpName := tmp.Name()
	// Remove the temp file on every failure path. On success the rename has
	// already consumed it and this is a no-op.
	defer func() {
		tmp.Close() //nolint:errcheck
		os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return "", 0, fmt.Errorf("auditretention: chmod seal: %w", err)
	}

	hasher := sha256.New()
	counter := &countingWriter{}
	sink := io.MultiWriter(tmp, hasher, counter)

	var (
		seen    int64
		nextID  = cand.FirstID
		lastID  int64
		lastRow string
	)
	for nextID <= cand.ThroughID {
		rows, err := db.ReadAuditRange(nextID, cand.ThroughID, batch)
		if err != nil {
			return "", 0, err
		}
		if len(rows) == 0 {
			break
		}
		for _, ev := range rows {
			if lastID > 0 && ev.ID != lastID+1 {
				return "", 0, fmt.Errorf(
					"auditretention: refusing to seal a broken chain: id gap, expected %d got %d",
					lastID+1, ev.ID)
			}
			if ev.PrevHash != expectedPrev {
				return "", 0, fmt.Errorf(
					"auditretention: refusing to seal a broken chain: prev_hash mismatch at id %d", ev.ID)
			}
			if want, ok := statedb.AuditChainLink(ev); !ok {
				return "", 0, fmt.Errorf(
					"auditretention: refusing to seal a broken chain: row_hash mismatch at id %d (recomputed %s)",
					ev.ID, want[:12])
			}
			expectedPrev = ev.RowHash
			lastID = ev.ID
			lastRow = ev.RowHash
			seen++
		}
		if err := auditexport.Write(sink, rows, auditexport.Options{Format: auditexport.FormatJSONL}); err != nil {
			return "", 0, fmt.Errorf("auditretention: write seal: %w", err)
		}
		nextID = rows[len(rows)-1].ID + 1
	}

	if seen != cand.Count {
		return "", 0, fmt.Errorf(
			"auditretention: sealed %d rows but the plan said %d — the table changed under the seal", seen, cand.Count)
	}
	if lastRow != cand.BoundaryHash {
		return "", 0, fmt.Errorf(
			"auditretention: boundary row %d changed under the seal", cand.ThroughID)
	}

	// Durability before deletion is the whole contract: the rows may only be
	// removed once this file is guaranteed to survive a power loss.
	if err := tmp.Sync(); err != nil {
		return "", 0, fmt.Errorf("auditretention: sync seal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", 0, fmt.Errorf("auditretention: close seal: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", 0, fmt.Errorf("auditretention: publish seal: %w", err)
	}
	if dh, derr := os.Open(filepath.Dir(path)); derr == nil {
		_ = dh.Sync()
		dh.Close() //nolint:errcheck
	}
	return hex.EncodeToString(hasher.Sum(nil)), counter.n, nil
}

// countingWriter counts bytes so the anchor can record the seal's size without
// a second stat, which could observe a file someone had already replaced.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// SealStatus is the result of re-checking one anchor's export against the
// digest recorded when it was written.
type SealStatus struct {
	Anchor statedb.AuditAnchor
	// Present is false when the file is missing — which is not necessarily
	// wrong (archives get moved to cold storage on purpose) but is always
	// worth saying out loud.
	Present bool
	OK      bool
	Actual  string
	Err     error
}

// VerifySeals re-hashes every anchor's export and compares it to the digest in
// the anchor.
//
// This is the check that reaches outside the database. VerifyAuditChain can
// only prove the surviving rows are consistent with what the anchors claim,
// and an attacker able to rewrite audit_events can rewrite audit_anchors too.
// The seal files are the part of the record that can be copied somewhere the
// hub cannot write, and this is what compares the two.
func VerifySeals(db *statedb.DB) ([]SealStatus, error) {
	anchors, err := db.ListAuditAnchors()
	if err != nil {
		return nil, err
	}
	out := make([]SealStatus, 0, len(anchors))
	for _, a := range anchors {
		st := SealStatus{Anchor: a}
		if a.ExportPath == "" {
			st.Err = errors.New("anchor records no export path")
			out = append(out, st)
			continue
		}
		f, err := os.Open(a.ExportPath)
		if err != nil {
			st.Err = err
			out = append(out, st)
			continue
		}
		st.Present = true
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			f.Close() //nolint:errcheck
			st.Err = err
			out = append(out, st)
			continue
		}
		f.Close() //nolint:errcheck
		st.Actual = hex.EncodeToString(h.Sum(nil))
		st.OK = st.Actual == a.ExportSHA256
		if !st.OK {
			st.Err = fmt.Errorf("digest mismatch: anchor %s, file %s",
				shortHash(a.ExportSHA256), shortHash(st.Actual))
		}
		out = append(out, st)
	}
	return out, nil
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
