package knowledge

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// reconcilingConnector is a fake connector that is also a Reconciler: it
// answers with the documents it would list now.
type reconcilingConnector struct {
	*fakeConnector
	reconciles int
	fail       bool
	// extra is added to the answer, to make it too large.
	extra int
}

func (r *reconcilingConnector) Reconcile(_ context.Context, req ReconcileRequest) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reconciles++
	r.scopes = append(r.scopes, "reconcile:"+req.Scope)
	if r.fail {
		return nil, fmt.Errorf("GET https://wiki.example/search?token=%s: 503", req.Credential.Value())
	}
	var ids []string
	for _, d := range r.docs {
		if !d.Deleted {
			ids = append(ids, d.ExternalID)
		}
	}
	for i := 0; i < r.extra; i++ {
		ids = append(ids, fmt.Sprintf("extra-%d", i))
	}
	return ids, nil
}

// reconcileFixture is a fixture whose service reads a reconciling connector
// on a clock the test moves, reconciling every six hours.
type reconcileFixture struct {
	*fixture
	rec *reconcilingConnector
	now time.Time
}

func newReconcileFixture(t *testing.T, opts ...Option) *reconcileFixture {
	t.Helper()
	f := newFixture(t)
	rf := &reconcileFixture{fixture: f, now: time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC),
		rec: &reconcilingConnector{fakeConnector: &fakeConnector{kind: "rec", matches: map[string][]string{}}}}
	reg := NewRegistry()
	if err := reg.Register(rf.rec); err != nil {
		t.Fatal(err)
	}
	secrets := fakeSecrets{"wiki-bot": {"", "org-token-value-123"}}
	all := append([]Option{WithRegistry(reg), WithCredentials(secrets), WithClock(func() time.Time { return rf.now }),
		WithReconcileEvery(6 * time.Hour), WithChunking(ChunkOptions{MaxTokens: 64, OverlapTokens: 8})}, opts...)
	f.svc = New(f.db, all...)
	return rf
}

func (rf *reconcileFixture) source(t *testing.T) Source {
	t.Helper()
	admin := rf.svc.For(as(t, "root@corp.example", "admins"))
	src := mustCreate(t, admin, SourceInput{Kind: "rec", Name: "Wiki", Scope: ScopeOrg, Config: wikiConfig, SecretRef: "wiki-bot"})
	if _, _, err := admin.Bind(context.Background(), projectA, src.ID, Filter{}); err != nil {
		t.Fatal(err)
	}
	return src
}

func (rf *reconcileFixture) documents(t *testing.T, id int64) int {
	t.Helper()
	counts, err := rf.db.CountKnowledge(id)
	if err != nil {
		t.Fatal(err)
	}
	return counts[id].Documents
}

// TestSyncReconcilesWhenDue: a Reconciler is asked what its source holds once
// per interval — not by the sync that ran a full listing, whose sweep counts as
// one — and what its answer leaves out is removed; a failed reconciliation
// fails the sync, scrubbed of the credential, and is tried again next time.
func TestSyncReconcilesWhenDue(t *testing.T) {
	rf := newReconcileFixture(t)
	ctx := context.Background()
	src := rf.source(t)
	rf.rec.docs = pageOfDocs("d", 3)
	report, err := rf.svc.Sync(ctx, src.ID)
	if err != nil || report.Created != 3 || report.Reconciled || rf.rec.reconciles != 0 {
		t.Fatalf("the first sync = %+v, %v (%d reconciliations)", report, err, rf.rec.reconciles)
	}
	row, _ := rf.db.GetKnowledgeSource(src.ID)
	if !row.ReconciledAt.Equal(rf.now) {
		t.Fatalf("the first full listing did not count as a reconciliation: %v", row.ReconciledAt)
	}

	// The remote drops d-1 without saying so: the cursor is past it.
	rf.rec.docs = []Document{rf.rec.docs[0], rf.rec.docs[2]}
	rf.now = rf.now.Add(time.Hour)
	if report, err := rf.svc.Sync(ctx, src.ID); err != nil || report.Reconciled {
		t.Fatalf("a sync before the interval = %+v, %v", report, err)
	}
	if n := rf.documents(t, src.ID); n != 3 {
		t.Fatalf("%d documents before the reconciliation, want 3", n)
	}

	rf.now = rf.now.Add(5*time.Hour + time.Minute)
	report, err = rf.svc.Sync(ctx, src.ID)
	if err != nil || !report.Reconciled || report.Removed != 1 {
		t.Fatalf("the sync a reconciliation is due at = %+v, %v", report, err)
	}
	if n := rf.documents(t, src.ID); n != 2 {
		t.Fatalf("%d documents after the reconciliation, want 2", n)
	}
	admin := rf.svc.For(as(t, "root@corp.example", "admins"))
	got, _, err := admin.Source(ctx, src.ID)
	if err != nil || !got.Sync.ReconciledAt.Equal(rf.now) {
		t.Fatalf("the source's reconciliation = %v, %v", got.Sync.ReconciledAt, err)
	}

	rf.now = rf.now.Add(time.Hour)
	if report, err := rf.svc.Sync(ctx, src.ID); err != nil || report.Reconciled || rf.rec.reconciles != 1 {
		t.Fatalf("a sync an hour later = %+v, %v (%d reconciliations)", report, err, rf.rec.reconciles)
	}

	rf.now = rf.now.Add(6 * time.Hour)
	rf.rec.fail = true
	_, err = rf.svc.Sync(ctx, src.ID)
	if err == nil || !strings.Contains(err.Error(), "reconcile") || strings.Contains(err.Error(), "org-token-value-123") {
		t.Fatalf("a failed reconciliation = %v", err)
	}
	row, _ = rf.db.GetKnowledgeSource(src.ID)
	if row.SyncStatus != "error" || strings.Contains(row.SyncError, "org-token-value-123") || row.ReconciledAt.Equal(rf.now) {
		t.Fatalf("after a failed reconciliation: status %q error %q reconciled %v", row.SyncStatus, row.SyncError, row.ReconciledAt)
	}
	rf.rec.fail = false
	rf.now = rf.now.Add(time.Minute)
	if report, err := rf.svc.Sync(ctx, src.ID); err != nil || !report.Reconciled {
		t.Fatalf("the sync after a failed reconciliation = %+v, %v", report, err)
	}
}

// TestReconcileAnswersAreBounded: an answer over the bound fails the sync and
// removes nothing.
func TestReconcileAnswersAreBounded(t *testing.T) {
	rf := newReconcileFixture(t)
	ctx := context.Background()
	src := rf.source(t)
	rf.rec.docs = pageOfDocs("d", 2)
	if _, err := rf.svc.Sync(ctx, src.ID); err != nil {
		t.Fatal(err)
	}
	rf.rec.docs = rf.rec.docs[:1]
	rf.rec.extra = maxReconciledDocuments
	rf.now = rf.now.Add(7 * time.Hour)
	if _, err := rf.svc.Sync(ctx, src.ID); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("an answer over the bound = %v", err)
	}
	if n := rf.documents(t, src.ID); n != 2 {
		t.Fatalf("%d documents after a refused answer, want both kept", n)
	}
}

// TestReconcilingCanBeTurnedOff: a reconciliation interval of zero never asks.
func TestReconcilingCanBeTurnedOff(t *testing.T) {
	rf := newReconcileFixture(t, WithReconcileEvery(0))
	src := rf.source(t)
	rf.rec.docs = pageOfDocs("d", 2)
	for i := 0; i < 3; i++ {
		if _, err := rf.svc.Sync(context.Background(), src.ID); err != nil {
			t.Fatal(err)
		}
		rf.now = rf.now.Add(24 * time.Hour)
	}
	if rf.rec.reconciles != 0 {
		t.Fatalf("%d reconciliations with reconciling off", rf.rec.reconciles)
	}
}

// TestRequestsCarryTheSourceScope: every request names the scope of the source
// it is for, so a connector can hold a personal source to public addresses.
func TestRequestsCarryTheSourceScope(t *testing.T) {
	rf := newReconcileFixture(t)
	ctx := context.Background()
	org := rf.source(t)
	alice := rf.svc.For(as(t, "alice@corp.example", "operators"))
	// The fixture's secrets know only the org token; alice's source signs in
	// with none.
	mine := mustCreate(t, alice, SourceInput{Kind: "rec", Name: "Mine", Scope: ScopePersonal, Config: wikiConfig})
	rf.rec.docs = pageOfDocs("d", 1)
	for _, id := range []int64{org.ID, mine.ID} {
		if _, err := rf.svc.Sync(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	rf.now = rf.now.Add(7 * time.Hour)
	if _, err := rf.svc.Sync(ctx, org.ID); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rf.rec.scopes, ",")
	for _, want := range []string{"validate:org", "validate:personal", "list:org", "list:personal", "reconcile:org"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the requests named %q; none was %q", got, want)
		}
	}
}

// TestAncestorsAreCleaned: a document's ancestors are kept as one-line titles,
// scrubbed like a title, the empty ones dropped and the innermost
// MaxAncestors kept — and a search hit carries them.
func TestAncestorsAreCleaned(t *testing.T) {
	f := newFixture(t)
	src := orgSource(t, f, "Wiki", projectA)
	token := "ghp_" + strings.Repeat("aB3", 12)
	var deep []string
	for i := 0; i < MaxAncestors+5; i++ {
		deep = append(deep, fmt.Sprintf("Level %d", i))
	}
	index(t, f, src.ID, Document{ExternalID: "p1", Title: "Leaf", Body: "aardvark",
		Ancestors: append([]string{"  ", "Engi\nneering", strings.Repeat("x", MaxTitleBytes+50), "Keys " + token}, deep...)})
	row, found, err := f.db.GetKnowledgeDocument(src.ID, "p1")
	if err != nil || !found {
		t.Fatal(err)
	}
	if len(row.Ancestors) != MaxAncestors || row.Ancestors[len(row.Ancestors)-1] != fmt.Sprintf("Level %d", MaxAncestors+4) {
		t.Fatalf("%d ancestors kept, ending %q", len(row.Ancestors), row.Ancestors[len(row.Ancestors)-1])
	}
	index(t, f, src.ID, Document{ExternalID: "p2", Title: "Other", Body: "aardvark",
		Ancestors: []string{"  ", "Engi\nneering", strings.Repeat("x", MaxTitleBytes+50), "Keys " + token}})
	row, _, _ = f.db.GetKnowledgeDocument(src.ID, "p2")
	if len(row.Ancestors) != 3 || row.Ancestors[0] != "Engi neering" || len(row.Ancestors[1]) != MaxTitleBytes ||
		strings.Contains(row.Ancestors[2], token) {
		t.Fatalf("ancestors = %q", row.Ancestors)
	}
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	hits, err := admin.Search(context.Background(), projectA, "aardvark", 10)
	if err != nil || len(hits) != 2 {
		t.Fatalf("search = %d hits, %v", len(hits), err)
	}
	for _, h := range hits {
		if h.ExternalID == "p2" && h.Ancestors[0] != "Engi neering" {
			t.Fatalf("the hit's ancestors = %q", h.Ancestors)
		}
	}
}
