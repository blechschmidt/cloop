package statedb

import (
	"strconv"
	"strings"
	"testing"
)

// TestTaskDispatchRecordsTheVerifiedDigest: the dispatch row says what the
// hub found when it checked one of cloop's own images (Task 20453) — the
// verdict, and the digest cosign verified — so "did this run on a verified
// image" is answerable from audit_events alone. An image that is not cloop's
// carries neither key: no check was made, and an empty one would read as one.
func TestTaskDispatchRecordsTheVerifiedDigest(t *testing.T) {
	db := newAuditDB(t)
	digest := "sha256:" + strings.Repeat("3a", 32)
	AuditTaskDispatch(db, TaskDispatchInput{
		TaskID: 7, ProjectPath: "/srv/app", RunID: "run_cloop",
		PinnedImage:     "ghcr.io/blechschmidt/cloop-harness@" + digest,
		ImageProvenance: "verified", VerifiedDigest: digest,
	})
	AuditTaskDispatch(db, TaskDispatchInput{
		TaskID: 8, ProjectPath: "/srv/app", RunID: "run_other",
		PinnedImage: "ghcr.io/acme/tools@" + digest,
	})
	for id, want := range map[int]map[string]any{
		7: {"image_provenance": "verified", "verified_digest": digest},
		8: {},
	} {
		rows, _, err := db.ListAuditEvents(AuditFilter{EntityType: "task", EntityID: strconv.Itoa(id),
			EventType: "task.dispatch"})
		if err != nil || len(rows) != 1 {
			t.Fatalf("task %d: %d rows, %v", id, len(rows), err)
		}
		p := decodeAuditPayload(rows[0].Payload)
		for _, key := range []string{"image_provenance", "verified_digest"} {
			if got, ok := p[key]; ok != (want[key] != nil) || (ok && got != want[key]) {
				t.Errorf("task %d: %s = %v (present %t), want %v", id, key, got, ok, want[key])
			}
		}
	}
}
