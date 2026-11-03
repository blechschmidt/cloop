package knowledge

// Test connection (Task 20473): who may try what, what a try lists, and that
// nothing it says — or the audit trail says of it — carries the credential.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// lastTestAudit returns the newest knowledge.source.test row's payload.
func lastTestAudit(t *testing.T, db *statedb.DB) (statedb.AuditEvent, map[string]any) {
	t.Helper()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionKnowledgeSourceTest)})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("no knowledge.source.test row was written")
	}
	ev := evs[0]
	for _, e := range evs {
		if e.ID > ev.ID {
			ev = e
		}
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(ev.Payload), &payload); err != nil {
		t.Fatalf("payload %s: %v", ev.Payload, err)
	}
	return ev, payload
}

func TestConnectionTestListsOnePageAndIndexesNothing(t *testing.T) {
	f := newFixture(t)
	for i := range 9 {
		f.conn.docs = append(f.conn.docs, Document{ExternalID: string(rune('a' + i)), Title: "Runbook " + string(rune('A'+i)),
			Body: "how to ship"})
	}
	f.conn.docs[1].Deleted = true
	f.conn.pageSize = 4
	alice := f.svc.For(as(t, "alice@corp.example", "operators"))
	ref := "alice-wiki"
	res, err := alice.TestConnection(context.Background(), ConnectionTest{Kind: "fake", Name: "Alice's wiki",
		Config: json.RawMessage(`{"base_url":"https://wiki.example"}`), SecretRef: &ref})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Documents != 3 || res.Withheld != 1 || !res.More {
		t.Fatalf("result = %+v, want 3 listed, 1 withheld, more to come", res)
	}
	if strings.Join(res.Titles, "|") != "Runbook A|Runbook C|Runbook D" {
		t.Errorf("titles = %q", res.Titles)
	}
	if got := f.conn.creds[len(f.conn.creds)-1]; got != "alice-token-value-456" {
		t.Errorf("the connector was handed %q, not alice's credential", got)
	}
	if got := f.conn.scopes[len(f.conn.scopes)-1]; got != "list:personal" {
		t.Errorf("the listing named scope %q: a person's test is a personal source's", got)
	}
	counts, err := f.db.CountKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 0 {
		t.Errorf("a test indexed something: %+v", counts)
	}
	_, p := lastTestAudit(t, f.db)
	if p["outcome"] != "ok" || p["scope"] != ScopePersonal || p["owner"] != "alice@corp.example" ||
		p["signs_in_with"] != "alice-wiki" || p["name"] != "Alice's wiki" || p["documents"] != float64(3) {
		t.Errorf("audit payload = %v", p)
	}
}

func TestConnectionTestScrubsTheCredentialFromAFailure(t *testing.T) {
	f := newFixture(t)
	// Every List fails, with the credential in its error.
	f.conn.leakCredentialInError = true
	f.conn.failAfter = 1
	f.conn.lists = 1
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	ref := "wiki-bot"
	res, err := admin.TestConnection(context.Background(), ConnectionTest{Kind: "fake", Scope: ScopeOrg,
		Config: json.RawMessage(`{"base_url":"https://wiki.example"}`), SecretRef: &ref})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Reason != TestFailedConnector {
		t.Fatalf("result = %+v, want a connector failure", res)
	}
	if strings.Contains(res.Error, "org-token-value-123") || !strings.Contains(res.Error, redact.Marker) {
		t.Errorf("the failure = %q: the credential must be scrubbed out of it", res.Error)
	}
	ev, p := lastTestAudit(t, f.db)
	if strings.Contains(ev.Payload, "org-token-value-123") {
		t.Errorf("the audit row carries the credential: %s", ev.Payload)
	}
	if p["outcome"] != "failed" || p["reason"] != TestFailedConnector || p["owner"] != "" {
		t.Errorf("audit payload = %v", p)
	}
}

func TestConnectionTestOfACredentialThatWillNotOpen(t *testing.T) {
	f := newFixture(t)
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	src := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Wiki", Scope: ScopeOrg,
		Config: json.RawMessage(`{"base_url":"https://wiki.example"}`), SecretRef: "wiki-bot"})
	// The secret goes away after the source names it.
	delete(f.svc.credentials.(fakeSecrets), "wiki-bot")
	res, err := admin.TestConnection(context.Background(), ConnectionTest{SourceID: src.ID})
	// The stored reference is checked like a new one, so it is refused before
	// anything is opened.
	if err == nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("testing a source whose secret is gone = %+v, %v; want ErrInvalid", res, err)
	}
}

// TestConnectionTestFollowsTheSourceRules: a test sends a credential where a
// configuration points, so it is allowed exactly where saving that
// configuration would be.
func TestConnectionTestFollowsTheSourceRules(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cfg := json.RawMessage(`{"base_url":"https://wiki.example"}`)
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	alice := f.svc.For(as(t, "alice@corp.example", "operators"))
	bob := f.svc.For(as(t, "bob@corp.example", "operators"))
	viewer := f.svc.For(as(t, "vic@corp.example", "viewers"))
	org := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Org wiki", Scope: ScopeOrg, Config: cfg, SecretRef: "wiki-bot"})
	mine := mustCreate(t, alice, SourceInput{Kind: "fake", Name: "Alice's", Scope: ScopePersonal, Config: cfg, SecretRef: "alice-wiki"})
	ref := func(s string) *string { return &s }

	cases := []struct {
		name string
		acc  *Access
		in   ConnectionTest
		want error
	}{
		{"an operator may not try an organisation source", alice, ConnectionTest{Kind: "fake", Scope: ScopeOrg, Config: cfg}, ErrForbidden},
		{"nor an existing one", alice, ConnectionTest{SourceID: org.ID}, ErrForbidden},
		{"another person's source is not found", bob, ConnectionTest{SourceID: mine.ID}, ErrNotFound},
		{"an admin may not point a person's source anywhere", admin, ConnectionTest{SourceID: mine.ID, Config: cfg}, ErrForbidden},
		{"a viewer may connect nothing", viewer, ConnectionTest{Kind: "fake", Config: cfg}, ErrForbidden},
		{"a personal source signs in with its owner's secret only", alice,
			ConnectionTest{Kind: "fake", Config: cfg, SecretRef: ref("bob-wiki")}, ErrInvalid},
		{"nor with a shared one", alice, ConnectionTest{Kind: "fake", Config: cfg, SecretRef: ref("wiki-bot")}, ErrInvalid},
		{"a configuration the connector refuses", alice, ConnectionTest{Kind: "fake", Config: json.RawMessage(`{"base_url":"http://x"}`)}, ErrInvalid},
		{"a configuration holding a credential", alice, ConnectionTest{Kind: "fake",
			Config: json.RawMessage(`{"base_url":"https://wiki.example","api_token":"abc"}`)}, ErrInvalid},
		{"an unknown kind", alice, ConnectionTest{Kind: "gopher", Config: cfg}, ErrInvalid},
	}
	before := 0
	if evs, _, err := f.db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionKnowledgeSourceTest)}); err == nil {
		before = len(evs)
	}
	for _, c := range cases {
		_, err := c.acc.TestConnection(ctx, c.in)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if evs, _, _ := f.db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionKnowledgeSourceTest)}); len(evs) != before {
		t.Errorf("refused tests wrote %d audit rows; a refusal tries nothing and writes none", len(evs)-before)
	}

	// What is allowed: the owner tries their source with a change, the admin
	// the organisation's as it is.
	for _, ok := range []struct {
		acc *Access
		in  ConnectionTest
	}{
		{alice, ConnectionTest{SourceID: mine.ID, Config: json.RawMessage(`{"base_url":"https://other.example"}`)}},
		{admin, ConnectionTest{SourceID: org.ID}},
	} {
		res, err := ok.acc.TestConnection(ctx, ok.in)
		if err != nil || !res.OK {
			t.Errorf("TestConnection(%+v) = %+v, %v", ok.in, res, err)
		}
	}
	// A try of a change is a try, not a change.
	got, _, err := alice.Source(ctx, mine.ID)
	if err != nil || !strings.Contains(string(got.Config), "wiki.example") {
		t.Errorf("after a test of a change the source is %s, %v", got.Config, err)
	}
}

func TestConnectionTestRecoversAConnectorPanic(t *testing.T) {
	db := newFixture(t).db
	reg := NewRegistry()
	if err := reg.Register(panickyConnector{}); err != nil {
		t.Fatal(err)
	}
	svc := New(db, WithRegistry(reg), WithCredentials(fakeSecrets{"wiki-bot": {"", "s3cret-panic-value"}}))
	admin := svc.For(as(t, "root@corp.example", "admins"))
	ref := "wiki-bot"
	res, err := admin.TestConnection(context.Background(), ConnectionTest{Kind: "panicky", Scope: ScopeOrg,
		Config: json.RawMessage(`{}`), SecretRef: &ref})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || !strings.Contains(res.Error, "connector failed") || strings.Contains(res.Error, "s3cret-panic-value") {
		t.Errorf("a panicking connector's test = %+v", res)
	}
	if res.Duration <= 0 || res.Duration > time.Minute {
		t.Errorf("duration %s", res.Duration)
	}
}

// panickyConnector panics in List with the credential in the value.
type panickyConnector struct{}

func (panickyConnector) Kind() string                   { return "panicky" }
func (panickyConnector) Validate(ValidateRequest) error { return nil }
func (panickyConnector) List(_ context.Context, req ListRequest) (Page, error) {
	panic("boom with " + string(req.Credential.Value()))
}
func (panickyConnector) Fetch(context.Context, FetchRequest) (Document, error) {
	return Document{}, errors.New("no")
}

// TestPeekAndCanSee: the hub's fan-out reads a source once and asks each
// recipient's Access whether they may see it — the rule Sources lists by.
func TestPeekAndCanSee(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cfg := json.RawMessage(`{"base_url":"https://wiki.example"}`)
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	alice := f.svc.For(as(t, "alice@corp.example", "operators"))
	bob := f.svc.For(as(t, "bob@corp.example", "operators"))
	viewer := f.svc.For(as(t, "vic@corp.example", "viewers"))
	org := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Org wiki", Scope: ScopeOrg, Config: cfg})
	mine := mustCreate(t, alice, SourceInput{Kind: "fake", Name: "Alice's", Scope: ScopePersonal, Config: cfg})
	if _, err := f.svc.Index(org.ID, Document{ExternalID: "1", Title: "One", Body: "a body"}); err != nil {
		t.Fatal(err)
	}

	peeked, err := f.svc.Peek(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	listed, _, err := admin.Source(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if peeked.Name != listed.Name || peeked.Counts != listed.Counts || peeked.Counts.Documents != 1 {
		t.Errorf("Peek = %+v, Source = %+v", peeked.Counts, listed.Counts)
	}
	if _, err := f.svc.Peek(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("Peek of nothing = %v", err)
	}

	personal, err := f.svc.Peek(ctx, mine.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		who  string
		acc  *Access
		src  Source
		want bool
	}{
		{"admin, org", admin, peeked, true}, {"admin, alice's", admin, personal, true},
		{"alice, org", alice, peeked, true}, {"alice, hers", alice, personal, true},
		{"bob, org", bob, peeked, true}, {"bob, alice's", bob, personal, false},
		{"viewer, org", viewer, peeked, false}, {"viewer, alice's", viewer, personal, false},
	} {
		if got := c.acc.CanSee(c.src); got != c.want {
			t.Errorf("%s: CanSee = %v, want %v", c.who, got, c.want)
		}
		_, _, err := c.acc.Source(ctx, c.src.ID)
		if (err == nil) != c.want {
			t.Errorf("%s: CanSee says %v but Source answers %v", c.who, c.want, err)
		}
	}
}
