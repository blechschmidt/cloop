package knowledge

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// orgSource creates an org source and binds it to projects, as an admin.
func orgSource(t *testing.T, f *fixture, name string, projects ...Project) Source {
	t.Helper()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	src := mustCreate(t, admin, SourceInput{Kind: "fake", Name: name, Scope: ScopeOrg, Config: wikiConfig, SecretRef: "wiki-bot"})
	for _, p := range projects {
		if _, _, err := admin.Bind(context.Background(), p, src.ID, Filter{}); err != nil {
			t.Fatalf("bind %s to %s: %v", name, p.Path, err)
		}
	}
	return src
}

func index(t *testing.T, f *fixture, sourceID int64, doc Document) statedb.KnowledgeIndexOutcome {
	t.Helper()
	out, err := f.svc.Index(sourceID, doc)
	if err != nil {
		t.Fatalf("index %s: %v", doc.ExternalID, err)
	}
	return out
}

// TestSearchNeverCrossesProjects is the isolation property end to end through
// the service: project B, searching for words only a source bound to A holds,
// finds nothing of A's — as a member of both, as an admin, under any query.
func TestSearchNeverCrossesProjects(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := orgSource(t, f, "A wiki", projectA)
	b := orgSource(t, f, "B wiki", projectB)
	index(t, f, a.ID, Document{ExternalID: "a1", Title: "Merger", Body: "Project Bluebird acquires Initech in Q3."})
	index(t, f, b.ID, Document{ExternalID: "b1", Title: "Handbook", Body: "Laptops are ordered through IT."})

	for _, who := range []Principal{
		as(t, "root@corp.example", "admins"),
		as(t, "vic@corp.example", "proj-b-viewers"),
	} {
		acc := f.svc.For(who)
		for _, q := range []string{"Initech", "bluebird acquires", `"Project Bluebird"`, "initech*", "Q3 merger laptops"} {
			hits, err := acc.Search(ctx, projectB, q, MaxResults)
			if err != nil {
				t.Fatalf("%s searching B for %q: %v", who.Identity, q, err)
			}
			for _, h := range hits {
				if h.Source.ID != b.ID {
					t.Fatalf("%s searching project B for %q got %q from source %d, bound only to A",
						who.Identity, q, h.Title, h.Source.ID)
				}
			}
		}
	}
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	hits, err := admin.Search(ctx, projectA, "initech", 5)
	if err != nil || len(hits) != 1 || hits[0].Source.Name != "A wiki" || hits[0].Title != "Merger" {
		t.Fatalf("A's own search = %+v, %v", hits, err)
	}
	if !strings.Contains(hits[0].Snippet, SnippetOpen+"Initech"+SnippetClose) {
		t.Fatalf("snippet %q does not mark the match", hits[0].Snippet)
	}
	if hits[0].Rank != 1 {
		t.Fatalf("the only hit ranks %d, want 1", hits[0].Rank)
	}
	// A project bound to nothing, and a feature-like path beside A, find nothing.
	for _, p := range []Project{{Path: "/srv/projects/c", Name: "c"}, {Path: projectA.Path + "/.cloop/features/x", Name: "a"}} {
		hits, err := admin.Search(ctx, p, "initech", 5)
		if err != nil || len(hits) != 0 {
			t.Fatalf("%s found %+v, %v", p.Path, hits, err)
		}
	}
}

// TestACLHintsDoNotDecideWhoReads pins a residual the security model states
// (docs/security/model.md, "What is not mitigated"): who may read an indexed
// document is decided by the bindings alone. A connector's ACL hints — here
// those a Confluence page restricted to a group carries when its source sets
// include_restricted — are stored with the document and enforced nowhere, so
// every viewer of a bound project reads it whether or not the site would have
// shown it to them. A change that enforces the hints changes this test.
func TestACLHintsDoNotDecideWhoReads(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	src := orgSource(t, f, "Wiki", projectB)
	acl := []string{"space:FIN", "restricted", "group:finance"}
	index(t, f, src.ID, Document{ExternalID: "payroll", Title: "Payroll schedule", Space: "FIN",
		Body: "The zeppelin payroll runs on the last Friday.", ACL: acl})
	row, found, err := f.db.GetKnowledgeDocument(src.ID, "payroll")
	if err != nil || !found || !slices.Equal(slices.Sorted(slices.Values(row.ACL)), slices.Sorted(slices.Values(acl))) {
		t.Fatalf("stored document = %+v (found %v, %v); want its ACL hints %v kept", row, found, err, acl)
	}
	// vic views project B and is in no finance group.
	viewer := f.svc.For(as(t, "vic@corp.example", "proj-b-viewers"))
	hits, err := viewer.Search(ctx, projectB, "zeppelin", 5)
	if err != nil || len(hits) != 1 || hits[0].Title != "Payroll schedule" {
		t.Fatalf("a viewer of the bound project searching for the restricted page = %+v, %v; want it found — "+
			"if the ACL hints are enforced now, rewrite the residual in docs/security/model.md", hits, err)
	}
}

// TestSearchRanksAndBounds: BM25 puts the best chunk first, k bounds the
// answer, and a query with nothing to search is refused.
func TestSearchRanksAndBounds(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	src := orgSource(t, f, "Wiki", projectA)
	index(t, f, src.ID, Document{ExternalID: "runbook", Title: "Rollback runbook", Body: "How to roll back a release."})
	index(t, f, src.ID, Document{ExternalID: "notes", Title: "Release notes", Body: "We improved rollback speed."})
	for i := 0; i < 20; i++ {
		index(t, f, src.ID, Document{ExternalID: "filler" + string(rune('a'+i)), Title: "Filler", Body: "release train schedule"})
	}
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	hits, err := admin.Search(ctx, projectA, "rollback", 0)
	if err != nil || len(hits) != 2 || hits[0].ExternalID != "runbook" {
		t.Fatalf("ranking = %+v, %v; the title match should lead", hits, err)
	}
	many, err := admin.Search(ctx, projectA, "release", 3)
	if err != nil || len(many) != 3 {
		t.Fatalf("k=3 returned %d, %v", len(many), err)
	}
	all, err := admin.Search(ctx, projectA, "release", 1000)
	if err != nil || len(all) != 22 {
		t.Fatalf("k=1000 returned %d, want all 22 (under MaxResults)", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].Rank != i+1 {
			t.Fatalf("hit %d ranks %d", i, all[i].Rank)
		}
	}
	_, err = admin.Search(ctx, projectA, `"" ***`, 5)
	wantErr(t, "an empty query", err, ErrInvalid)
}

// TestIndexNeverRechunksAnUnchangedDocument: the content hash is what decides;
// metadata still follows the source.
func TestIndexNeverRechunksAnUnchangedDocument(t *testing.T) {
	f := newFixture(t)
	chunked := 0
	f.svc.onChunk = func() { chunked++ }
	src := orgSource(t, f, "Wiki", projectA)
	doc := Document{ExternalID: "p", Title: "Page", Body: "# A\nalpha\n\n# B\nbeta", Space: "ENG", URL: "https://wiki.example/p"}
	if out := index(t, f, src.ID, doc); out != statedb.KnowledgeIndexCreated || chunked != 1 {
		t.Fatalf("first index = %s, chunked %d", out, chunked)
	}
	doc.Space, doc.URL, doc.ACL = "OPS", "https://wiki.example/moved", []string{"group:eng"}
	if out := index(t, f, src.ID, doc); out != statedb.KnowledgeIndexUnchanged || chunked != 1 {
		t.Fatalf("same content again = %s, chunked %d; want unchanged and no chunking", out, chunked)
	}
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	hits, _ := admin.Search(context.Background(), projectA, "beta", 5)
	if len(hits) != 1 || hits[0].Space != "OPS" || hits[0].URL != "https://wiki.example/moved" || hits[0].Heading != "B" {
		t.Fatalf("metadata after an unchanged re-index: %+v", hits)
	}
	doc.Body += "\n\ngamma"
	if out := index(t, f, src.ID, doc); out != statedb.KnowledgeIndexUpdated || chunked != 2 {
		t.Fatalf("changed content = %s, chunked %d", out, chunked)
	}
}

// TestIndexBoundsAndCleans: a body past MaxBodyBytes is cut and marked, a
// credential in a page never reaches the index, a link that is not http(s)
// is dropped, and a document without an id is refused.
func TestIndexBoundsAndCleans(t *testing.T) {
	f := newFixture(t)
	src := orgSource(t, f, "Wiki", projectA)
	token := fakeGitHubToken()
	index(t, f, src.ID, Document{
		ExternalID: "leaky", Title: "Setup " + token, URL: "javascript:alert(1)",
		Body: "Use the token " + token + " to clone.",
	})
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	hits, err := admin.Search(context.Background(), projectA, "clone", 5)
	if err != nil || len(hits) != 1 {
		t.Fatalf("search = %+v, %v", hits, err)
	}
	if strings.Contains(hits[0].Snippet+hits[0].Title, token) {
		t.Fatalf("a credential in the page reached the index: %+v", hits[0])
	}
	if hits[0].URL != "" {
		t.Fatalf("a javascript: URL was kept: %q", hits[0].URL)
	}
	text, err := f.db.KnowledgeChunkText(hits[0].ChunkID)
	if err != nil || strings.Contains(text, token) {
		t.Fatalf("stored chunk %q, %v", text, err)
	}

	// The largest chunks keep this to a few hundred rows under -race.
	wide := New(f.db, WithRegistry(f.svc.registry), WithChunking(ChunkOptions{MaxTokens: 2048}))
	big := strings.Repeat("lorem ipsum ", MaxBodyBytes/12+100)
	if _, err := wide.Index(src.ID, Document{ExternalID: "big", Title: "Big", Body: big}); err != nil {
		t.Fatal(err)
	}
	row, found, err := f.db.GetKnowledgeDocument(src.ID, "big")
	if err != nil || !found {
		t.Fatalf("the big document: %v, found=%v", err, found)
	}
	if !row.Truncated || row.BodyBytes > MaxBodyBytes || row.ChunkCount == 0 {
		t.Fatalf("a %d-byte body stored as %+v", len(big), row)
	}

	if _, err := f.svc.Index(src.ID, Document{Title: "no id"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a document without an external id = %v", err)
	}
}

// TestNarrowedBindingServesOnlyItsMatches: spaces narrow at once; a query
// narrows only to what a sync recorded, and serves nothing before.
func TestNarrowedBindingServesOnlyItsMatches(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	src := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Jira", Scope: ScopeOrg, Config: wikiConfig, SecretRef: "wiki-bot"})
	f.conn.docs = []Document{
		{ExternalID: "ENG-1", Title: "Login bug", Space: "ENG", Body: "login fails"},
		{ExternalID: "OPS-1", Title: "Login alert", Space: "OPS", Body: "login alerting"},
		{ExternalID: "HR-1", Title: "Payroll login", Space: "HR", Body: "payroll login"},
	}
	f.conn.matches["labels = public"] = []string{"OPS-1"}
	if _, _, err := admin.Bind(ctx, projectA, src.ID, Filter{Spaces: []string{"ENG", "OPS"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := admin.Bind(ctx, projectB, src.ID, Filter{Query: "labels = public"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Sync(ctx, src.ID); err != nil {
		t.Fatal(err)
	}
	ids := func(p Project) string {
		hits, err := admin.Search(ctx, p, "login", 10)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, h := range hits {
			out = append(out, h.ExternalID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(projectA); got == "" || strings.Contains(got, "HR-1") {
		t.Fatalf("a binding narrowed to ENG and OPS found %q", got)
	}
	if got := ids(projectB); got != "OPS-1" {
		t.Fatalf("a binding narrowed by query found %q, want OPS-1", got)
	}
	// A new query forgets the old matches until the next sync answers it.
	if _, _, err := admin.Bind(ctx, projectB, src.ID, Filter{Query: "labels = hr"}); err != nil {
		t.Fatal(err)
	}
	if got := ids(projectB); got != "" {
		t.Fatalf("a changed query served %q before any sync answered it", got)
	}
	f.conn.matches["labels = hr"] = []string{"HR-1"}
	report, err := f.svc.Sync(ctx, src.ID)
	if err != nil || report.Narrowed != 1 {
		t.Fatalf("sync = %+v, %v", report, err)
	}
	if got := ids(projectB); got != "HR-1" {
		t.Fatalf("after the sync the query binding found %q, want HR-1", got)
	}
}
