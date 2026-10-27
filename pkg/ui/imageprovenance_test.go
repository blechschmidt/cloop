package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/state"
)

const harnessDigest = "sha256:" + "3ad7a636d68631752784810d823b827a1747022840f3c8877af15decc831b213"

func harnessProvenance(s imagepolicy.ProvenanceStatus) *imagepolicy.Provenance {
	p := &imagepolicy.Provenance{Image: executor.DefaultHarnessImage,
		Ref: "ghcr.io/blechschmidt/cloop-harness@" + harnessDigest, Digest: harnessDigest, Status: s,
		CheckedAt: time.Now()}
	if s != imagepolicy.ProvenanceVerified {
		p.Warning = executor.DefaultHarnessImage + " ran without a signature on edge-1: Error: no signatures found."
	}
	return p
}

// TestTheVerifiedDigestReachesTheRunsRecord: the verdict on one of cloop's own
// images and the digest verified are written onto the record every task
// artifact and task.dispatch row of the run are stamped from (Task 20453).
func TestTheVerifiedDigestReachesTheRunsRecord(t *testing.T) {
	dir := t.TempDir()
	h := executor.Handle{ID: "h1", StartedAt: time.Now(),
		Image: "ghcr.io/blechschmidt/cloop-harness@" + harnessDigest, ImageProvenance: harnessProvenance(imagepolicy.ProvenanceVerified)}
	recordSandboxProvenance(dir, nil, nil, h, "alice", "run_1", nil)
	rec, ok := artifact.LoadSandboxRun(dir)
	if !ok || rec.ImageProvenance != "verified" || rec.VerifiedDigest != harnessDigest || rec.PinnedImage != h.Image {
		t.Fatalf("record = %+v", rec)
	}

	// A device that ran its own copy of an unverified tag: the handle names no
	// image, and the record claims none — the registry's digest, which the hub
	// checked, need not be the device's copy.
	h = executor.Handle{ID: "h2", StartedAt: time.Now(), ImageProvenance: harnessProvenance(imagepolicy.ProvenanceUnsigned)}
	recordSandboxProvenance(dir, nil, nil, h, "alice", "run_2", nil)
	rec, _ = artifact.LoadSandboxRun(dir)
	if rec.ImageProvenance != "unsigned" || rec.VerifiedDigest != "" || rec.PinnedImage != "" {
		t.Fatalf("unverified record = %+v", rec)
	}
}

// TestAnUnverifiedCloopImageIsJournaledOncePerDigest: the run's journal says an
// image of cloop's ran unverified, once per image digest and verdict, not once
// per task; a verified one says nothing.
func TestAnUnverifiedCloopImageIsJournaledOncePerDigest(t *testing.T) {
	dir := setupProjectDir(t, "provenance journal", nil)
	newTestServer(t, dir, nil)
	ex := &plainExec{id: "edge-1"}
	journalImageProvenance(dir, ex, executor.Handle{ImageProvenance: harnessProvenance(imagepolicy.ProvenanceVerified)})
	unsigned := executor.Handle{ImageProvenance: harnessProvenance(imagepolicy.ProvenanceUnsigned)}
	journalImageProvenance(dir, ex, unsigned)
	journalImageProvenance(dir, ex, unsigned)
	journalImageProvenance(dir, ex, executor.Handle{})
	rows, err := state.ListEventsOfType(dir, state.EventImageProvenance, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "without a signature") {
		t.Fatalf("rows = %+v", rows)
	}
}
