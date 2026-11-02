package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

func pageOfDocs(prefix string, n int) []Document {
	var out []Document
	for i := 0; i < n; i++ {
		out = append(out, Document{ExternalID: fmt.Sprintf("%s-%d", prefix, i), Title: fmt.Sprintf("%s %d", prefix, i),
			Body: fmt.Sprintf("searchable body number %d of %s", i, prefix)})
	}
	return out
}

// TestSyncPagesResumesAndSweeps: a sync pages through the source storing its
// cursor; a failing page leaves the cursor at the last good one, and the next
// sync resumes there; a full listing from the beginning removes what the
// source no longer holds; deletions are applied.
func TestSyncPagesResumesAndSweeps(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	src := orgSource(t, f, "Wiki", projectA)
	f.conn.docs = pageOfDocs("doc", 5)
	f.conn.pageSize = 2
	f.conn.failAfter = 2 // the third page fails

	_, err := f.svc.Sync(ctx, src.ID)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("a failing page = %v", err)
	}
	row, _ := f.db.GetKnowledgeSource(src.ID)
	if row.SyncStatus != "error" || row.SyncCursor != "4" || !strings.Contains(row.SyncError, "503") {
		t.Fatalf("after the failure: status %q cursor %q error %q", row.SyncStatus, row.SyncCursor, row.SyncError)
	}
	counts, _ := f.db.CountKnowledge()
	if counts[src.ID].Documents != 4 {
		t.Fatalf("%d documents indexed before the failure, want the first two pages' 4", counts[src.ID].Documents)
	}

	f.conn.failAfter = 0
	report, err := f.svc.Sync(ctx, src.ID)
	if err != nil || report.Created != 1 || !report.Complete || !report.Full || report.Swept != 0 {
		t.Fatalf("the resumed sync = %+v, %v; want the last document, finishing the full listing", report, err)
	}
	row, _ = f.db.GetKnowledgeSource(src.ID)
	if row.SyncStatus != "ok" || row.SyncError != "" || row.SyncCursor != "5" {
		t.Fatalf("after the resumed sync: %+v", row)
	}

	// The source drops doc-0 and doc-1 without saying so, and deletes doc-2
	// explicitly. An incremental sync sees only the deletion; a sync from the
	// beginning sweeps the rest.
	f.conn.docs = []Document{{ExternalID: "doc-2", Deleted: true}, f.conn.docs[3], f.conn.docs[4]}
	if err := f.db.SetKnowledgeSyncCursor(src.ID, row.UpdatedAt, "0"); err != nil {
		t.Fatal(err)
	}
	report, err = f.svc.Sync(ctx, src.ID)
	if err != nil || report.Deleted != 1 || report.Unchanged != 2 || report.Swept != 0 {
		t.Fatalf("incremental sync = %+v, %v", report, err)
	}
	if err := f.db.SetKnowledgeSyncCursor(src.ID, row.UpdatedAt, ""); err != nil {
		t.Fatal(err)
	}
	report, err = f.svc.Sync(ctx, src.ID)
	if err != nil || report.Swept != 2 || !report.Complete {
		t.Fatalf("a sync from the beginning = %+v, %v; want doc-0 and doc-1 swept", report, err)
	}
	counts, _ = f.db.CountKnowledge()
	if counts[src.ID].Documents != 2 {
		t.Fatalf("%d documents after the sweep, want 2", counts[src.ID].Documents)
	}
}

// TestSyncFetchesPartialDocuments: a document listed without its body is
// fetched before it is indexed.
func TestSyncFetchesPartialDocuments(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	src := orgSource(t, f, "Wiki", projectA)
	f.conn.docs = pageOfDocs("p", 3)
	f.conn.partial = true
	report, err := f.svc.Sync(ctx, src.ID)
	if err != nil || report.Created != 3 || f.conn.fetches != 3 {
		t.Fatalf("sync = %+v, %v, %d fetches", report, err, f.conn.fetches)
	}
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	if hits, _ := admin.Search(ctx, projectA, "searchable", 10); len(hits) != 3 {
		t.Fatalf("the fetched bodies are not searchable: %d hits", len(hits))
	}
}

// TestSyncKeepsTheCredentialOnTheHub: the connector receives the source's
// secret, the source and its errors never carry it, and the hub's copy is
// wiped when the sync ends.
func TestSyncKeepsTheCredentialOnTheHub(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	src := orgSource(t, f, "Wiki", projectA)
	f.conn.docs = pageOfDocs("d", 1)
	if _, err := f.svc.Sync(ctx, src.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.conn.creds) != 1 || f.conn.creds[0] != "org-token-value-123" {
		t.Fatalf("the connector was handed %q", f.conn.creds)
	}

	f.conn.failAfter = 1
	f.conn.leakCredentialInError = true
	_, err := f.svc.Sync(ctx, src.ID)
	if err == nil {
		t.Fatal("the failing sync succeeded")
	}
	if strings.Contains(err.Error(), "org-token-value-123") {
		t.Fatalf("the sync's error carries the credential: %v", err)
	}
	row, _ := f.db.GetKnowledgeSource(src.ID)
	if strings.Contains(row.SyncError, "org-token-value-123") || row.SyncStatus != "error" {
		t.Fatalf("the recorded error carries the credential: %q", row.SyncError)
	}
	for _, s := range []string{fmt.Sprint(NewCredential([]byte("v"))), fmt.Sprintf("%#v", ListRequest{Credential: NewCredential([]byte("v"))})} {
		if strings.Contains(s, `"v"`) || strings.Contains(s, "[118]") {
			t.Fatalf("a credential printed its value: %s", s)
		}
	}
	if _, err := json.Marshal(ListRequest{Credential: NewCredential([]byte("v"))}); err == nil {
		t.Fatal("a credential was serialized")
	}
	c := NewCredential([]byte("wipe me"))
	b := c.Value()
	c.wipe()
	if string(b) != "\x00\x00\x00\x00\x00\x00\x00" || !c.IsZero() {
		t.Fatalf("wipe left %q", b)
	}
}

// TestSyncRefusesWhatItCannotDo: a disabled source is not synced; a source
// whose connector is gone, or whose secret is, records why.
func TestSyncRefusesWhatItCannotDo(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	src := orgSource(t, f, "Wiki", projectA)
	if _, err := admin.UpdateSource(ctx, src.ID, SourceUpdate{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.Sync(ctx, src.ID)
	wantErr(t, "syncing a disabled source", err, ErrDisabled)

	// A source of a kind this build has no connector for.
	other := New(f.db, WithRegistry(NewRegistry()), WithCredentials(fakeSecrets{}))
	if _, err := admin.UpdateSource(ctx, src.ID, SourceUpdate{Enabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	_, err = other.Sync(ctx, src.ID)
	wantErr(t, "syncing with no connector", err, ErrUnavailable)
	row, _ := f.db.GetKnowledgeSource(src.ID)
	if row.SyncStatus != "error" || !strings.Contains(row.SyncError, "no connector") {
		t.Fatalf("recorded %q %q", row.SyncStatus, row.SyncError)
	}

	// A secret that is gone.
	gone := New(f.db, WithRegistry(f.svc.registry), WithCredentials(fakeSecrets{}))
	_, err = gone.Sync(ctx, src.ID)
	if err == nil || !strings.Contains(err.Error(), "wiki-bot") {
		t.Fatalf("syncing without the secret = %v", err)
	}
	// No secret store at all.
	_, err = New(f.db, WithRegistry(f.svc.registry)).Sync(ctx, src.ID)
	wantErr(t, "syncing with no secret store", err, ErrUnavailable)
	_, err = f.svc.Sync(ctx, 999)
	wantErr(t, "syncing a source that does not exist", err, ErrNotFound)
}

// TestSyncStopsWhenTheSourceIsReconfigured: a sync that outlives a change to
// its source does not write the old configuration's cursor back.
func TestSyncStopsWhenTheSourceIsReconfigured(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	src := orgSource(t, f, "Wiki", projectA)
	f.conn.docs = pageOfDocs("d", 4)
	f.conn.pageSize = 2
	reconfigure := &reconfiguringConnector{fakeConnector: f.conn, change: func() {
		if _, err := admin.UpdateSource(ctx, src.ID, SourceUpdate{Config: json.RawMessage(`{"base_url":"https://new.example"}`)}); err != nil {
			t.Error(err)
		}
	}}
	reg := NewRegistry()
	if err := reg.Register(reconfigure); err != nil {
		t.Fatal(err)
	}
	svc := New(f.db, WithRegistry(reg), WithCredentials(fakeSecrets{"wiki-bot": {"", "t"}}))
	_, err := svc.Sync(ctx, src.ID)
	wantErr(t, "a sync across a reconfiguration", err, statedb.ErrKnowledgeSourceChanged)
	row, _ := f.db.GetKnowledgeSource(src.ID)
	if row.SyncCursor != "" {
		t.Fatalf("the old sync wrote its cursor %q over the reconfiguration", row.SyncCursor)
	}
}

// reconfiguringConnector changes its source during its first List.
type reconfiguringConnector struct {
	*fakeConnector
	change func()
	done   bool
}

func (r *reconfiguringConnector) List(ctx context.Context, req ListRequest) (Page, error) {
	if !r.done {
		r.done = true
		r.change()
	}
	return r.fakeConnector.List(ctx, req)
}

// TestRegistry: kinds are validated and unique.
func TestRegistry(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&fakeConnector{kind: "confluence"}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"confluence", "Bad", "", "with space", strings.Repeat("a", 33)} {
		if err := r.Register(&fakeConnector{kind: kind}); err == nil {
			t.Errorf("registering kind %q was accepted", kind)
		}
	}
	if err := r.Register(nil); err == nil {
		t.Error("a nil connector was accepted")
	}
	if got := r.Kinds(); len(got) != 1 || got[0] != "confluence" {
		t.Fatalf("kinds = %v", got)
	}
	if _, ok := r.Lookup("jira"); ok {
		t.Fatal("an unregistered kind was found")
	}
	if !errors.Is((&ForbiddenError{}), ErrForbidden) {
		t.Fatal("ForbiddenError does not match ErrForbidden")
	}
}

// TestAnInterruptedFullListingStillSweeps: a source reconfigured to show less
// is listed from the beginning, and when that listing ends — in a later sync
// than the one that began it, after a failure — what it no longer reaches is
// removed. So is what the remote dropped without saying, at the periodic full
// listing.
func TestAnInterruptedFullListingStillSweeps(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc := New(f.db, WithRegistry(f.svc.registry), WithCredentials(fakeSecrets{"wiki-bot": {"", "t"}}),
		WithClock(clock), WithFullListingEvery(24*time.Hour))
	src := orgSource(t, f, "Wiki", projectA)
	f.conn.docs = pageOfDocs("d", 6)
	f.conn.pageSize = 2
	if r, err := svc.Sync(ctx, src.ID); err != nil || r.Created != 6 || !r.Full {
		t.Fatalf("first sync = %+v, %v", r, err)
	}

	// The configuration narrows to what holds d-0 … d-3, and the first sync of
	// the new configuration fails part way.
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	if _, err := admin.UpdateSource(ctx, src.ID, SourceUpdate{Config: json.RawMessage(`{"base_url":"https://narrower.example"}`)}); err != nil {
		t.Fatal(err)
	}
	f.conn.docs = f.conn.docs[:4]
	f.conn.lists, f.conn.failAfter = 0, 1
	now = now.Add(time.Minute)
	if _, err := svc.Sync(ctx, src.ID); err == nil {
		t.Fatal("the failing sync succeeded")
	}
	f.conn.failAfter = 0
	now = now.Add(time.Minute)
	r, err := svc.Sync(ctx, src.ID)
	if err != nil || !r.Full || !r.Complete || r.Swept != 2 {
		t.Fatalf("the resumed listing = %+v, %v; want d-4 and d-5 swept", r, err)
	}

	// Incremental syncs see no deletion the remote does not report...
	f.conn.docs = f.conn.docs[:3]
	now = now.Add(time.Hour)
	if r, err := svc.Sync(ctx, src.ID); err != nil || r.Full || r.Swept != 0 {
		t.Fatalf("an incremental sync = %+v, %v", r, err)
	}
	counts, _ := f.db.CountKnowledge(src.ID)
	if counts[src.ID].Documents != 4 {
		t.Fatalf("%d documents before the periodic listing, want 4", counts[src.ID].Documents)
	}
	// ...and the periodic full listing does.
	now = now.Add(25 * time.Hour)
	if r, err := svc.Sync(ctx, src.ID); err != nil || !r.Full || r.Swept != 1 {
		t.Fatalf("the periodic full listing = %+v, %v; want d-3 swept", r, err)
	}
}

// TestNarrowingThatFailsClearsItsBinding: the binding whose query the
// connector could not answer serves nothing it narrows; the others are still
// answered — even when the listing itself failed.
func TestNarrowingThatFailsClearsItsBinding(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	src := orgSource(t, f, "Jira")
	f.conn.docs = []Document{
		{ExternalID: "A-1", Title: "Outage", Body: "outage report"},
		{ExternalID: "A-2", Title: "Outage two", Body: "outage report again"},
	}
	f.conn.matches["good"] = []string{"A-1"}
	f.conn.matches["bad"] = []string{"A-2"}
	if _, _, err := admin.Bind(ctx, projectA, src.ID, Filter{Query: "good"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := admin.Bind(ctx, projectB, src.ID, Filter{Query: "bad"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Sync(ctx, src.ID); err != nil {
		t.Fatal(err)
	}
	ids := func(p Project) string {
		hits, err := admin.Search(ctx, p, "outage", 10)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, h := range hits {
			out = append(out, h.ExternalID)
		}
		return strings.Join(out, ",")
	}
	if ids(projectA) != "A-1" || ids(projectB) != "A-2" {
		t.Fatalf("after the first sync: A %q, B %q", ids(projectA), ids(projectB))
	}

	// The listing fails, the "bad" query fails; "good" now matches A-2.
	f.conn.failAfter = f.conn.lists
	f.conn.narrowFails = map[string]bool{"bad": true}
	f.conn.matches["good"] = []string{"A-2"}
	_, err := f.svc.Sync(ctx, src.ID)
	if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "narrow binding") {
		t.Fatalf("the sync = %v; want both the listing's and the narrowing's failure", err)
	}
	if got := ids(projectA); got != "A-2" {
		t.Fatalf("the binding that was answered serves %q, want A-2", got)
	}
	if got := ids(projectB); got != "" {
		t.Fatalf("the binding that could not be answered still serves %q", got)
	}
}

// TestCredentialNeverFormatsItsBytes: no fmt verb prints the secret.
func TestCredentialNeverFormatsItsBytes(t *testing.T) {
	c := NewCredential([]byte("hunter2"))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%c", "%U", "%p"} {
		got := fmt.Sprintf(verb, c)
		if strings.Contains(got, "hunter2") || strings.Contains(got, "104") || strings.Contains(got, "68756e") {
			t.Errorf("%s formats the credential as %q", verb, got)
		}
		if got := fmt.Sprintf(verb, ListRequest{Credential: c}); strings.Contains(got, "hunter2") || strings.Contains(got, "104 117") {
			t.Errorf("%s formats a request carrying the credential as %q", verb, got)
		}
	}
}
