package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var wikiConfig = json.RawMessage(`{"base_url":"https://wiki.example","space_key":"ENG"}`)

func ptr[T any](v T) *T { return &v }

// fakeGitHubToken is shaped like a classic GitHub token — mixed case, as the
// redact registry requires before it calls a run a token — and assembled at
// run time, so no literal in the tree looks like a credential.
func fakeGitHubToken() string { return "gh" + "p_" + strings.Repeat("Ab3dE5fG7h", 4)[:36] }

// TestOnlyAdminsCreateOrgSources: connecting an organisation source takes
// knowledge.admin; an operator may connect a personal one of their own, with
// their own secret; a viewer neither.
func TestOnlyAdminsCreateOrgSources(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	alice := f.svc.For(as(t, "alice@corp.example", "operators"))
	viewer := f.svc.For(as(t, "vic@corp.example", "viewers"))
	nobody := f.svc.For(as(t, "eve@corp.example"))

	org := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Eng wiki", Scope: ScopeOrg, Config: wikiConfig, SecretRef: "wiki-bot"})
	if org.Scope != ScopeOrg || org.Owner != "" || !org.Enabled {
		t.Fatalf("org source = %+v", org)
	}

	_, err := alice.CreateSource(ctx, SourceInput{Kind: "fake", Name: "Mine", Scope: ScopeOrg, Config: wikiConfig})
	wantErr(t, "an operator connecting an org source", err, ErrForbidden)
	var fe *ForbiddenError
	if !errors.As(err, &fe) || fe.Permission != authz.PermKnowledgeAdmin {
		t.Fatalf("the refusal does not name knowledge.admin: %v", err)
	}

	// The default scope for a signed-in person is personal.
	mine := mustCreate(t, alice, SourceInput{Kind: "fake", Name: "Alice notes", Config: wikiConfig, SecretRef: "alice-wiki"})
	if mine.Scope != ScopePersonal || mine.Owner != "alice@corp.example" {
		t.Fatalf("alice's source = %+v", mine)
	}

	for name, a := range map[string]*Access{"viewer": viewer, "unmapped": nobody} {
		_, err := a.CreateSource(ctx, SourceInput{Kind: "fake", Name: "x", Config: wikiConfig})
		wantErr(t, name+" connecting a personal source", err, ErrForbidden)
		_, err = a.Sources(ctx)
		wantErr(t, name+" listing sources", err, ErrForbidden)
	}

	// Credentials follow ownership: an org source cannot sign in with a
	// person's secret, a personal one not with the organisation's or another
	// person's.
	_, err = admin.CreateSource(ctx, SourceInput{Kind: "fake", Name: "o2", Scope: ScopeOrg, Config: wikiConfig, SecretRef: "alice-wiki"})
	wantErr(t, "an org source on a personal secret", err, ErrInvalid)
	_, err = alice.CreateSource(ctx, SourceInput{Kind: "fake", Name: "p2", Config: wikiConfig, SecretRef: "wiki-bot"})
	wantErr(t, "a personal source on the org's secret", err, ErrInvalid)
	_, err = alice.CreateSource(ctx, SourceInput{Kind: "fake", Name: "p3", Config: wikiConfig, SecretRef: "bob-wiki"})
	wantErr(t, "a personal source on bob's secret", err, ErrInvalid)

	// Names are unique per owner; kinds must be registered; configs are the
	// connector's to accept.
	_, err = admin.CreateSource(ctx, SourceInput{Kind: "fake", Name: "Eng wiki", Scope: ScopeOrg, Config: wikiConfig})
	wantErr(t, "a second org source named Eng wiki", err, ErrConflict)
	_, err = admin.CreateSource(ctx, SourceInput{Kind: "nope", Name: "n", Scope: ScopeOrg, Config: wikiConfig})
	wantErr(t, "an unknown kind", err, ErrInvalid)
	_, err = admin.CreateSource(ctx, SourceInput{Kind: "fake", Name: "n", Scope: ScopeOrg, Config: json.RawMessage(`{"base_url":"http://x"}`)})
	wantErr(t, "a config the connector refuses", err, ErrInvalid)
}

// TestPersonalSourcesNeedAPerson: with no signed-in identity — a hub without
// single sign-on, where everyone holds everything — a personal source has no
// owner and is refused, and an org source is allowed.
func TestPersonalSourcesNeedAPerson(t *testing.T) {
	f := newFixture(t)
	local := f.svc.For(PrincipalFor(false, nil, nil, "", "local"))
	_, err := local.CreateSource(context.Background(), SourceInput{Kind: "fake", Name: "p", Scope: ScopePersonal, Config: wikiConfig})
	wantErr(t, "a personal source with no identity", err, ErrInvalid)
	src := mustCreate(t, local, SourceInput{Kind: "fake", Name: "o", Config: wikiConfig})
	if src.Scope != ScopeOrg {
		t.Fatalf("with no identity the default scope is %q, want org", src.Scope)
	}
	// An SSO hub with no subject under an enforced policy grants nothing.
	none := f.svc.For(PrincipalFor(true, testResolver(t), nil, "", "anonymous"))
	_, err = none.Sources(context.Background())
	wantErr(t, "a caller with no subject listing", err, ErrForbidden)
	// A principal with no decision at all fails closed.
	_, err = f.svc.For(Principal{Identity: "x@corp.example"}).Sources(context.Background())
	wantErr(t, "a principal without Decide", err, ErrForbidden)
}

// TestWhoSeesAndManagesWhat: a personal source is invisible to everyone but
// its owner and admins; an admin may delete it but not change where it
// points; nobody but an admin changes an org source.
func TestWhoSeesAndManagesWhat(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	alice := f.svc.For(as(t, "alice@corp.example", "operators"))
	bob := f.svc.For(as(t, "bob@corp.example", "operators"))

	org := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Org", Scope: ScopeOrg, Config: wikiConfig, SecretRef: "wiki-bot"})
	mine := mustCreate(t, alice, SourceInput{Kind: "fake", Name: "Alice", Config: wikiConfig, SecretRef: "alice-wiki"})

	names := func(a *Access) string {
		srcs, err := a.Sources(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range srcs {
			out = append(out, s.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(bob); got != "Org" {
		t.Fatalf("bob sees %q, want only the org source", got)
	}
	if got := names(alice); got != "Org,Alice" {
		t.Fatalf("alice sees %q", got)
	}
	if got := names(admin); got != "Org,Alice" {
		t.Fatalf("the admin sees %q", got)
	}

	_, _, err := bob.Source(ctx, mine.ID)
	wantErr(t, "bob reading alice's source", err, ErrNotFound)
	_, err = bob.UpdateSource(ctx, mine.ID, SourceUpdate{Name: ptr("mine now")})
	wantErr(t, "bob changing alice's source", err, ErrNotFound)
	_, _, err = bob.DeleteSource(ctx, mine.ID)
	wantErr(t, "bob deleting alice's source", err, ErrNotFound)

	_, err = alice.UpdateSource(ctx, org.ID, SourceUpdate{Enabled: ptr(false)})
	wantErr(t, "an operator changing the org source", err, ErrForbidden)
	_, _, err = alice.DeleteSource(ctx, org.ID)
	wantErr(t, "an operator deleting the org source", err, ErrForbidden)
	if src, bindings, err := alice.Source(ctx, org.ID); err != nil || src.Name != "Org" || bindings != nil {
		t.Fatalf("alice reading the org source = %+v, %v, %v; want it without its bindings", src, bindings, err)
	}
	if alice.CanManage(org) || !alice.CanManage(mine) || admin.CanManage(mine) || !admin.CanManage(org) {
		t.Fatal("CanManage disagrees with the rules")
	}

	// The admin may not repoint alice's source — that would send her
	// credential elsewhere — but may delete it.
	_, err = admin.UpdateSource(ctx, mine.ID, SourceUpdate{Config: json.RawMessage(`{"base_url":"https://attacker.example"}`)})
	wantErr(t, "the admin repointing alice's source", err, ErrForbidden)
	updated, err := alice.UpdateSource(ctx, mine.ID, SourceUpdate{Name: ptr("Alice's wiki"), Config: json.RawMessage(`{"base_url":"https://other.example"}`)})
	if err != nil || updated.Name != "Alice's wiki" || string(updated.Config) != `{"base_url":"https://other.example"}` {
		t.Fatalf("alice changing her source = %+v, %v", updated, err)
	}
	if _, _, err := admin.DeleteSource(ctx, mine.ID); err != nil {
		t.Fatalf("the admin deleting alice's source: %v", err)
	}
}

// TestBindingRules: binding needs project.write on the project, and the
// source must be the organisation's (with knowledge.admin) or the caller's
// own; unbinding needs project.write; a caller who cannot read the project is
// told it does not exist.
func TestBindingRules(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	// alice: operator hub-wide, maintainer of project A only.
	alice := f.svc.For(as(t, "alice@corp.example", "operators", "proj-a-maintainers"))
	// carol maintains A too, and owns nothing.
	carol := f.svc.For(as(t, "carol@corp.example", "operators", "proj-a-maintainers"))
	// vic reads B and nothing else.
	viewerB := f.svc.For(as(t, "vic@corp.example", "proj-b-viewers"))

	org := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Org", Scope: ScopeOrg, Config: wikiConfig, SecretRef: "wiki-bot"})
	mine := mustCreate(t, alice, SourceInput{Kind: "fake", Name: "Alice", Config: wikiConfig, SecretRef: "alice-wiki"})

	// A maintainer of A cannot bind the organisation's source without
	// knowledge.admin.
	_, _, err := alice.Bind(ctx, projectA, org.ID, Filter{})
	wantErr(t, "a project maintainer binding the org source", err, ErrForbidden)
	var fe *ForbiddenError
	if !errors.As(err, &fe) || fe.Permission != authz.PermKnowledgeAdmin {
		t.Fatalf("the refusal does not name knowledge.admin: %v", err)
	}
	// She can bind her own to A, which she maintains...
	b, created, err := alice.Bind(ctx, projectA, mine.ID, Filter{Spaces: []string{"ENG", " ENG", "OPS"}})
	if err != nil || !created || strings.Join(b.Filter.Spaces, ",") != "ENG,OPS" || b.Project != projectA.Path {
		t.Fatalf("alice binding her source to A = %+v, %v, %v", b, created, err)
	}
	// ...but not to B, which she may read, as an operator, and not write.
	_, _, err = alice.Bind(ctx, projectB, mine.ID, Filter{})
	wantErr(t, "alice binding to a project she only reads", err, ErrForbidden)
	if !errors.As(err, &fe) || fe.Permission != authz.PermProjectWrite {
		t.Fatalf("the refusal does not name project.write: %v", err)
	}
	// A reader of B is forbidden rather than told B does not exist; to a
	// caller who cannot read A, A does not exist.
	_, _, err = viewerB.Bind(ctx, projectB, org.ID, Filter{})
	wantErr(t, "a viewer of B binding to B", err, ErrForbidden)
	_, _, err = viewerB.Bind(ctx, projectA, org.ID, Filter{})
	wantErr(t, "a caller who cannot read A binding to A", err, ErrNotFound)
	// The admin binds the org source anywhere, and may not bind alice's.
	if _, _, err := admin.Bind(ctx, projectB, org.ID, Filter{}); err != nil {
		t.Fatalf("the admin binding the org source to B: %v", err)
	}
	_, _, err = admin.Bind(ctx, projectB, mine.ID, Filter{})
	wantErr(t, "the admin binding alice's source", err, ErrForbidden)
	// Carol may write A, and still cannot see alice's source at all.
	_, _, err = carol.Bind(ctx, projectA, mine.ID, Filter{})
	wantErr(t, "carol binding alice's source", err, ErrNotFound)

	// A query narrowing is the connector's to accept, and only a connector
	// that narrows accepts one.
	_, _, err = admin.Bind(ctx, projectA, org.ID, Filter{Query: "x ORDER BY y"})
	wantErr(t, "a query the connector refuses", err, ErrInvalid)
	plain := mustCreate(t, admin, SourceInput{Kind: "plain", Name: "Plain", Scope: ScopeOrg, Config: wikiConfig})
	_, _, err = admin.Bind(ctx, projectA, plain.ID, Filter{Query: "labels = x"})
	wantErr(t, "a query on a connector that cannot narrow", err, ErrInvalid)

	// Unbinding: alice maintains A and may take a binding off it — but only a
	// binding of A.
	orgB := mustBindingOf(t, f, org.ID, projectB.Path)
	_, err = alice.Unbind(ctx, projectA, orgB.ID)
	wantErr(t, "unbinding B's binding through A", err, ErrNotFound)
	if _, err := alice.Unbind(ctx, projectA, b.ID); err != nil {
		t.Fatalf("alice unbinding from A: %v", err)
	}
	_, err = viewerB.Unbind(ctx, projectB, orgB.ID)
	wantErr(t, "a viewer unbinding", err, ErrForbidden)

	// Search and the bound list take project.read.
	_, err = viewerB.Search(ctx, projectA, "anything", 5)
	wantErr(t, "a caller with no role on A searching it", err, ErrNotFound)
	_, err = viewerB.ProjectSources(ctx, projectA)
	wantErr(t, "a caller with no role on A listing its sources", err, ErrNotFound)
	if _, err := viewerB.Search(ctx, projectB, "anything", 5); err != nil {
		t.Fatalf("a viewer of B searching B: %v", err)
	}
	bound, err := viewerB.ProjectSources(ctx, projectB)
	if err != nil || len(bound) != 1 || bound[0].Source.Name != "Org" {
		t.Fatalf("B's bound sources = %+v, %v", bound, err)
	}
	if bound[0].Source.SecretRef != "" || bound[0].Source.Config != nil {
		t.Fatalf("a project member sees a source's configuration or secret reference: %+v", bound[0].Source)
	}
}

func mustBindingOf(t *testing.T, f *fixture, sourceID int64, project string) statedb.KnowledgeBindingRow {
	t.Helper()
	rows, err := f.db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{SourceID: sourceID, ProjectPath: project})
	if err != nil || len(rows) != 1 {
		t.Fatalf("binding of %d to %s: %v, %v", sourceID, project, rows, err)
	}
	return rows[0]
}

// TestConfigsNeverHoldCredentials: a configuration naming a credential, or
// holding something shaped like one, is refused before it is stored.
func TestConfigsNeverHoldCredentials(t *testing.T) {
	f := newFixture(t)
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	for _, cfg := range []string{
		`{"base_url":"https://wiki.example","api_token":"x"}`,
		`{"base_url":"https://wiki.example","auth":{"password":"hunter2"}}`,
		`{"base_url":"https://wiki.example","headers":[{"Authorization":"Basic eDp5"}]}`,
		`{"base_url":"https://wiki.example","note":"` + fakeGitHubToken() + `"}`,
		`{"base_url":"https://wiki.example","PAT":"abc"}`,
		`{"base_url":"https://wiki.example","api-key":"abc"}`,
		`{"base_url":"https://wiki.example","apiToken":"abc"}`,
		`{"base_url":"https://wiki.example","AccessKey":"abc"}`,
		`{"base_url":"https://wiki.example","note":"` + strings.Replace(fakeGitHubToken(), "_", `\u005f`, 1) + `"}`,
		`["not","an","object"]`,
		`{"base_url":` + strings.Repeat(" ", MaxConfigBytes) + `"https://x"}`,
	} {
		_, err := admin.CreateSource(context.Background(), SourceInput{Kind: "fake", Name: "x", Scope: ScopeOrg, Config: json.RawMessage(cfg)})
		wantErr(t, "config "+cfg[:min(len(cfg), 60)], err, ErrInvalid)
	}
	// What a connector is configured with is fine.
	src := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "ok", Scope: ScopeOrg,
		Config: json.RawMessage(`{"base_url": "https://wiki.example", "space_key": "ENG", "project_key": "OPS", "max_tokens": 10}`)})
	if string(src.Config) != `{"base_url":"https://wiki.example","space_key":"ENG","project_key":"OPS","max_tokens":10}` {
		t.Fatalf("stored config %s, want it compacted", src.Config)
	}
}

// TestUpdatingConfigurationResyncs: a changed configuration clears the sync
// cursor; an unchanged update writes nothing.
func TestUpdatingConfigurationResyncs(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	src := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Org", Scope: ScopeOrg, Config: wikiConfig})
	row, _ := f.db.GetKnowledgeSource(src.ID)
	if err := f.db.SetKnowledgeSyncCursor(src.ID, row.UpdatedAt, "7"); err != nil {
		t.Fatal(err)
	}
	same, err := admin.UpdateSource(ctx, src.ID, SourceUpdate{Config: wikiConfig, Enabled: ptr(true), Name: ptr("Org")})
	if err != nil || !same.Sync.Resumes {
		t.Fatalf("an update changing nothing = %+v, %v; the cursor must stay", same, err)
	}
	moved, err := admin.UpdateSource(ctx, src.ID, SourceUpdate{Config: json.RawMessage(`{"base_url":"https://new.example"}`)})
	if err != nil || moved.Sync.Resumes {
		t.Fatalf("a new configuration = %+v, %v; the next sync must start over", moved, err)
	}
	_, err = admin.UpdateSource(ctx, src.ID, SourceUpdate{SecretRef: ptr("alice-wiki")})
	wantErr(t, "repointing an org source at a personal secret", err, ErrInvalid)
	_, err = admin.UpdateSource(ctx, src.ID, SourceUpdate{SecretRef: ptr("has space")})
	wantErr(t, "a malformed secret reference", err, ErrInvalid)
}
