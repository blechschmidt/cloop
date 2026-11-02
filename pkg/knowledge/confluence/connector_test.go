package confluence

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledge/internal/atlassian"
)

// sleeps records the waits a connector asked for, and waits none of them.
type sleeps struct {
	mu    sync.Mutex
	waits []time.Duration
}

func (s *sleeps) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.waits = append(s.waits, d)
	s.mu.Unlock()
	return ctx.Err()
}

func (s *sleeps) all() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.waits...)
}

// testConnector is a connector that may talk to an httptest server, and never
// really sleeps.
func testConnector(t *testing.T) (*Connector, *sleeps) {
	t.Helper()
	s := &sleeps{}
	return New(Options{AllowInsecure: true, Sleep: s.sleep, RequestTimeout: 10 * time.Second}), s
}

// mode is one way a source reads a site.
type mode struct {
	name   string
	cloud  bool
	cql    bool
	bearer bool
}

// v2 reports a mode listed through REST API v2.
func (m mode) v2() bool { return m.cloud && !m.cql }

var modes = []mode{
	{name: "cloud spaces (v2, email and API token)", cloud: true},
	{name: "cloud cql (v1 search, OAuth bearer)", cloud: true, cql: true, bearer: true},
	{name: "datacenter spaces (PAT)", bearer: true},
	{name: "datacenter cql (PAT)", cql: true, bearer: true},
}

// site makes a site for m, with spaces ENG and OPS.
func (m mode) site(t *testing.T) *fakeSite {
	t.Helper()
	ctx := "/confluence"
	if m.cloud {
		ctx = "/wiki"
	}
	f := newFakeSite(t, m.cloud, ctx)
	if m.cloud && !m.bearer {
		f.email = "wiki-bot@corp.example"
	}
	f.addSpace("ENG")
	f.addSpace("OPS")
	f.addSpace("HR")
	return f
}

// config is m's configuration for f, scoped to ENG and OPS.
func (m mode) config(f *fakeSite, extra map[string]any) json.RawMessage {
	c := map[string]any{"base_url": f.baseURL(), "deployment": DeploymentDataCenter}
	if m.cloud {
		c["deployment"] = DeploymentCloud
	}
	if f.email != "" {
		c["email"] = f.email
	}
	if m.cql {
		c["cql"] = `space in ("ENG", "OPS")`
	} else {
		c["spaces"] = []string{"ENG", "OPS"}
	}
	for k, v := range extra {
		c[k] = v
	}
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return b
}

func cred(f *fakeSite) knowledge.Credential { return knowledge.NewCredential([]byte(f.token)) }

// pass lists from cursor until a page says no more follows, as a sync does,
// and returns the documents, the cursor after, and how many List calls it
// took.
func pass(t *testing.T, c *Connector, config json.RawMessage, scope string, credential knowledge.Credential, cursor string) ([]knowledge.Document, string, int) {
	t.Helper()
	var docs []knowledge.Document
	for calls := 1; ; calls++ {
		if calls > 500 {
			t.Fatal("the listing never ended")
		}
		page, err := c.List(context.Background(), knowledge.ListRequest{Config: config, Credential: credential,
			Scope: scope, Cursor: cursor, PageSize: 7})
		if err != nil {
			t.Fatalf("list after %d calls: %v", calls, err)
		}
		if page.More && page.Cursor == cursor {
			t.Fatal("another page follows, but the cursor did not move")
		}
		docs = append(docs, page.Documents...)
		cursor = page.Cursor
		if !page.More {
			return docs, cursor, calls
		}
	}
}

func ids(docs []knowledge.Document) []string {
	out := make([]string, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.ExternalID)
	}
	sort.Strings(out)
	return out
}

func liveIDs(docs []knowledge.Document) []string {
	var live []knowledge.Document
	for _, d := range docs {
		if !d.Deleted {
			live = append(live, d)
		}
	}
	return ids(live)
}

func byID(docs []knowledge.Document) map[string]knowledge.Document {
	out := map[string]knowledge.Document{}
	for _, d := range docs {
		out[d.ExternalID] = d
	}
	return out
}

func idsOf(cs ...*fakeContent) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}

func sameIDs(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

// TestAuthentication: each deployment signs in the way it takes — Cloud with
// an email and API token as basic auth, or an OAuth bearer token; Data Center
// with a personal access token — and a refused credential is an error that
// says so, without the credential in it.
func TestAuthentication(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			welcome := f.add("page", "ENG", "Welcome", "", "<p>hello</p>")
			c, _ := testConnector(t)
			docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "")
			sameIDs(t, "documents", liveIDs(docs), idsOf(welcome))

			wrong := "wrong-token-" + strings.Repeat("Z9", 10)
			_, err := c.List(context.Background(), knowledge.ListRequest{Config: m.config(f, nil),
				Credential: knowledge.NewCredential([]byte(wrong)), Scope: knowledge.ScopeOrg})
			if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "refused the credential") {
				t.Fatalf("a wrong token = %v, want a 401 that names the credential", err)
			}
			if strings.Contains(err.Error(), wrong) {
				t.Fatalf("the refusal carries the token: %v", err)
			}
			if !atlassian.IsStatus(err, http.StatusUnauthorized) {
				t.Fatalf("the refusal does not report its status: %v", err)
			}
		})
	}
}

// TestListingReadsEverythingInScope: a first pass pages through every page and
// blog post in the source's spaces — and nothing in the space it does not
// name — with each document's title, web URL, space, ancestors and body.
func TestListingReadsEverythingInScope(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			root := f.add("page", "ENG", "Engineering", "", "<h1>Engineering</h1><p>Home of the team.</p>")
			runbooks := f.add("page", "ENG", "Runbooks", root.ID, "<p>All runbooks.</p>")
			var want []*fakeContent
			want = append(want, root, runbooks)
			for i := 0; i < 23; i++ {
				want = append(want, f.add("page", "ENG", fmt.Sprintf("Runbook %d", i), runbooks.ID,
					fmt.Sprintf("<h2>Steps</h2><ol><li>step one of %d</li></ol>", i)))
			}
			for i := 0; i < 9; i++ {
				want = append(want, f.add("blogpost", "OPS", fmt.Sprintf("Weekly %d", i), "", "<p>news</p>"))
			}
			f.add("page", "HR", "Salaries", "", "<p>not in scope</p>")

			c, _ := testConnector(t)
			docs, cursor, calls := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "")
			sameIDs(t, "first pass", ids(docs), idsOf(want...))
			if calls < 5 {
				t.Fatalf("%d documents in %d calls: the listing did not page", len(docs), calls)
			}
			if cursor == "" || !strings.HasPrefix(cursor, cursorPrefix) {
				t.Fatalf("the pass ended without a cursor to resume from: %q", cursor)
			}
			got := byID(docs)
			doc := got[want[5].ID]
			if doc.Title != "Runbook 3" || doc.Space != "ENG" || doc.Deleted {
				t.Fatalf("a runbook = %+v", doc)
			}
			if strings.Join(doc.Ancestors, " › ") != "Engineering › Runbooks" {
				t.Fatalf("the runbook's ancestors = %q", doc.Ancestors)
			}
			if !strings.Contains(doc.Body, "## Steps") || !strings.Contains(doc.Body, "1. step one of 3") {
				t.Fatalf("the runbook's body = %q", doc.Body)
			}
			if want := f.baseURL() + f.webui(want[5]); doc.URL != want {
				t.Fatalf("the runbook's URL = %q, want %q", doc.URL, want)
			}
			if !doc.UpdatedAt.Equal(want[5].Modified) {
				t.Fatalf("the runbook's time = %v, want %v", doc.UpdatedAt, want[5].Modified)
			}
			if strings.Join(doc.ACL, ",") != "space:ENG" {
				t.Fatalf("an unrestricted page's ACL hints = %q", doc.ACL)
			}
			if blog := got[want[len(want)-1].ID]; blog.Space != "OPS" || len(blog.Ancestors) != 0 {
				t.Fatalf("a blog post = %+v", blog)
			}
		})
	}
}

// TestIncrementalCursor: after a pass, the next one lists only what changed
// since — the edited and the new — and the newest document of the last pass,
// which the overlap lists again; then nothing at all changes and nearly
// nothing is listed.
func TestIncrementalCursor(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			var pages []*fakeContent
			for i := 0; i < 20; i++ {
				space := "ENG"
				if i%3 == 0 {
					space = "OPS"
				}
				pages = append(pages, f.add("page", space, fmt.Sprintf("Page %d", i), "", "<p>v1</p>"))
			}
			blog := f.add("blogpost", "ENG", "Launch", "", "<p>v1</p>")
			c, _ := testConnector(t)
			config := m.config(f, nil)
			first, cursor, _ := pass(t, c, config, knowledge.ScopeOrg, cred(f), "")
			if len(first) != 21 {
				t.Fatalf("the first pass listed %d documents, want 21", len(first))
			}

			f.edit(pages[2], func(p *fakeContent) { p.Body = "<p>v2</p>" })
			f.edit(pages[9], func(p *fakeContent) { p.Title = "Page 9, renamed" })
			added := f.add("page", "OPS", "New page", "", "<p>new</p>")
			before := len(f.requestLog())
			second, cursor2, _ := pass(t, c, config, knowledge.ScopeOrg, cred(f), cursor)
			// What changed, and the newest document the last pass listed,
			// which the overlap lists again: the blog post, the newest of
			// all — and, where v2 lists pages and blog posts apart, the
			// newest page too.
			want := idsOf(pages[2], pages[9], added, blog)
			if m.v2() {
				want = idsOf(pages[2], pages[9], added, blog, pages[19])
			}
			sameIDs(t, "second pass", ids(second), want)
			if got := byID(second)[pages[9].ID].Title; got != "Page 9, renamed" {
				t.Fatalf("the renamed page's title = %q", got)
			}
			if n := len(f.requestLog()) - before; n > 12 {
				t.Fatalf("an incremental pass of 3 changes took %d requests", n)
			}

			third, _, _ := pass(t, c, config, knowledge.ScopeOrg, cred(f), cursor2)
			if len(third) > 2 {
				t.Fatalf("a pass with nothing changed listed %v", ids(third))
			}
		})
	}
}

// TestAPassResumesFromItsCursor: a pass interrupted after some pages resumes
// where it stopped, and a page changed meanwhile is listed again rather than
// skipped.
func TestAPassResumesFromItsCursor(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			var pages []*fakeContent
			for i := 0; i < 30; i++ {
				pages = append(pages, f.add("page", "ENG", fmt.Sprintf("Page %d", i), "", "<p>x</p>"))
			}
			c, _ := testConnector(t)
			config := m.config(f, nil)
			page, err := c.List(context.Background(), knowledge.ListRequest{Config: config, Credential: cred(f),
				Scope: knowledge.ScopeOrg, PageSize: 10})
			if err != nil || !page.More || len(page.Documents) != 10 {
				t.Fatalf("the first page = %d documents, more %v, %v", len(page.Documents), page.More, err)
			}
			// An older page, not listed yet, is edited between two pages of
			// the pass: it moves to the front, where the pass has been.
			f.edit(pages[3], func(p *fakeContent) { p.Body = "<p>edited</p>" })
			rest, cursor, _ := pass(t, c, config, knowledge.ScopeOrg, cred(f), page.Cursor)
			all := append(append([]knowledge.Document(nil), page.Documents...), rest...)
			seen := map[string]bool{}
			for _, d := range all {
				seen[d.ExternalID] = true
			}
			for _, p := range pages {
				if !seen[p.ID] && p != pages[3] {
					t.Fatalf("%s was skipped by a pass that resumed", p.Title)
				}
			}
			next, _, _ := pass(t, c, config, knowledge.ScopeOrg, cred(f), cursor)
			if d, ok := byID(next)[pages[3].ID]; !ok || !strings.Contains(d.Body, "edited") {
				t.Fatalf("the page edited during the pass is not in the next one: %v", ids(next))
			}
		})
	}
}

// TestRestrictedPages: a page with a view restriction — its own, a parent's,
// a grandparent's; for a person or a group — is reported deleted rather than
// indexed, unless the source includes restricted pages, when it is indexed
// with its restrictions in its ACL hints. A restriction the site did not
// report counts as one.
func TestRestrictedPages(t *testing.T) {
	type tc struct {
		name              string
		setup             func(f *fakeSite) (target *fakeContent)
		includeRestricted bool
		wantSkipped       bool
		wantACL           []string
	}
	cases := []tc{
		{name: "unrestricted", setup: func(f *fakeSite) *fakeContent {
			return f.add("page", "ENG", "Open", "", "<p>open</p>")
		}, wantACL: []string{"space:ENG"}},
		{name: "restricted to a person", setup: func(f *fakeSite) *fakeContent {
			p := f.add("page", "ENG", "Mine", "", "<p>mine</p>")
			p.ReadUsers = []string{"557058:alice"}
			return p
		}, wantSkipped: true},
		{name: "restricted to a group", setup: func(f *fakeSite) *fakeContent {
			p := f.add("page", "ENG", "Leads", "", "<p>leads</p>")
			p.ReadGroups = []string{"eng-leads"}
			return p
		}, wantSkipped: true},
		{name: "under a restricted parent", setup: func(f *fakeSite) *fakeContent {
			parent := f.add("page", "ENG", "Reorg", "", "<p>reorg</p>")
			parent.ReadGroups = []string{"hr"}
			return f.add("page", "ENG", "Reorg plan", parent.ID, "<p>plan</p>")
		}, wantSkipped: true},
		{name: "under a restricted grandparent", setup: func(f *fakeSite) *fakeContent {
			top := f.add("page", "ENG", "Board", "", "<p>board</p>")
			top.ReadUsers = []string{"557058:ceo"}
			mid := f.add("page", "ENG", "Minutes", top.ID, "<p>minutes</p>")
			return f.add("page", "ENG", "October", mid.ID, "<p>october</p>")
		}, wantSkipped: true},
		{name: "restricted, and the source includes restricted pages", setup: func(f *fakeSite) *fakeContent {
			parent := f.add("page", "ENG", "Security", "", "<p>sec</p>")
			parent.ReadGroups = []string{"security"}
			p := f.add("page", "ENG", "Incident", parent.ID, "<p>incident</p>")
			p.ReadUsers = []string{"557058:bob"}
			return p
		}, includeRestricted: true, wantACL: []string{"space:ENG", "restricted", "user:557058:bob", "group:security"}},
		{name: "restrictions not reported", setup: func(f *fakeSite) *fakeContent {
			f.noRestrict = true
			return f.add("page", "ENG", "Unknown", "", "<p>unknown</p>")
		}, wantSkipped: true},
	}
	for _, m := range modes {
		for _, c := range cases {
			t.Run(m.name+"/"+c.name, func(t *testing.T) {
				f := m.site(t)
				target := c.setup(f)
				conn, _ := testConnector(t)
				extra := map[string]any{}
				if c.includeRestricted {
					extra["include_restricted"] = true
				}
				docs, _, _ := pass(t, conn, m.config(f, extra), knowledge.ScopeOrg, cred(f), "")
				doc, ok := byID(docs)[target.ID]
				if !ok {
					t.Fatalf("%s was not listed at all: %v", target.Title, ids(docs))
				}
				if doc.Deleted != c.wantSkipped {
					t.Fatalf("%s: deleted %v, want %v (%+v)", target.Title, doc.Deleted, c.wantSkipped, doc)
				}
				if c.wantSkipped {
					if doc.Body != "" || doc.Title != "" {
						t.Fatalf("a skipped page carries its content: %+v", doc)
					}
					return
				}
				got, want := append([]string(nil), doc.ACL...), append([]string(nil), c.wantACL...)
				sort.Strings(got)
				sort.Strings(want)
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Fatalf("ACL hints = %q, want %q", doc.ACL, c.wantACL)
				}
			})
		}
	}
}

// TestPlacementSurvivesASearchIndexThatLags: v2 lists a page the site's search
// index does not have yet; its ancestors and restrictions are looked up on
// their own instead, and a restricted one is still skipped.
func TestPlacementSurvivesASearchIndexThatLags(t *testing.T) {
	m := modes[0]
	f := m.site(t)
	parent := f.add("page", "ENG", "Parent", "", "<p>p</p>")
	open := f.add("page", "ENG", "Fresh", parent.ID, "<p>fresh</p>")
	secret := f.add("page", "ENG", "Fresh secret", parent.ID, "<p>secret</p>")
	secret.ReadUsers = []string{"557058:carol"}
	f.searchLag[open.ID], f.searchLag[secret.ID] = true, true
	c, _ := testConnector(t)
	docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "")
	got := byID(docs)
	if d := got[open.ID]; d.Deleted || strings.Join(d.Ancestors, ",") != "Parent" {
		t.Fatalf("the fresh page = %+v", d)
	}
	if !got[secret.ID].Deleted {
		t.Fatalf("the fresh restricted page was indexed: %+v", got[secret.ID])
	}
	var single int
	for _, r := range f.requestLog() {
		if strings.HasPrefix(r, "/wiki/rest/api/content/"+open.ID+"?") || strings.HasPrefix(r, "/wiki/rest/api/content/"+secret.ID+"?") {
			single++
		}
	}
	if single != 2 {
		t.Fatalf("%d single lookups for the two pages search does not have, want 2", single)
	}
}

// TestRateLimits: a 429 or 503 is retried after the site's Retry-After —
// seconds or a date — or after a bounded backoff when it names none; a site
// that asks for longer than a sync waits, or never stops refusing, fails the
// call with the refusal; a cancelled context ends the wait.
func TestRateLimits(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		faults    []fakeFault
		retries   int
		wantErr   string
		wantWaits []time.Duration
		// backoff checks the waits fall in the backoff's jittered window.
		backoff bool
	}{
		{name: "429 with seconds", faults: []fakeFault{{429, "7"}, {429, "2"}},
			wantWaits: []time.Duration{7 * time.Second, 2 * time.Second}},
		{name: "503 with a date", faults: []fakeFault{{503, now.Add(90 * time.Second).Format(http.TimeFormat)}},
			wantWaits: []time.Duration{90 * time.Second}},
		{name: "429 without Retry-After backs off", faults: []fakeFault{{429, ""}, {429, ""}, {503, ""}}, backoff: true},
		{name: "502 and 504 are retried", faults: []fakeFault{{502, ""}, {504, ""}}, backoff: true},
		{name: "retries run out", faults: []fakeFault{{429, "1"}, {429, "1"}, {429, "1"}}, retries: 2,
			wantErr: "429", wantWaits: []time.Duration{time.Second, time.Second}},
		{name: "a wait longer than a sync's", faults: []fakeFault{{429, "600"}},
			wantErr: "longer than a sync waits"},
		{name: "a 500 is not retried", faults: []fakeFault{{500, ""}}, wantErr: "500"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := modes[2]
			f := m.site(t)
			f.add("page", "ENG", "Doc", "", "<p>x</p>")
			f.fail(c.faults...)
			s := &sleeps{}
			retries := c.retries
			if retries == 0 {
				retries = 5
			}
			conn := New(Options{AllowInsecure: true, Sleep: s.sleep, Now: func() time.Time { return now }, MaxRetries: retries})
			_, err := conn.List(context.Background(), knowledge.ListRequest{Config: m.config(f, nil),
				Credential: cred(f), Scope: knowledge.ScopeOrg})
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("list = %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("list = %v, want an error naming %q", err, c.wantErr)
			}
			waits := s.all()
			if c.backoff {
				if len(waits) != len(c.faults) {
					t.Fatalf("waited %v for %d refusals", waits, len(c.faults))
				}
				for i, w := range waits {
					top := min(atlassian.BackoffBase<<i, atlassian.BackoffMax)
					if w < top/2 || w > top {
						t.Fatalf("backoff %d waited %v, want within [%v, %v]", i, w, top/2, top)
					}
				}
				return
			}
			if fmt.Sprint(waits) != fmt.Sprint(c.wantWaits) {
				t.Fatalf("waited %v, want %v", waits, c.wantWaits)
			}
		})
	}

	t.Run("a cancelled context ends the wait", func(t *testing.T) {
		m := modes[2]
		f := m.site(t)
		f.fail(fakeFault{429, "30"})
		ctx, cancel := context.WithCancel(context.Background())
		conn := New(Options{AllowInsecure: true, Sleep: func(ctx context.Context, d time.Duration) error {
			cancel()
			<-ctx.Done()
			return ctx.Err()
		}})
		_, err := conn.List(ctx, knowledge.ListRequest{Config: m.config(f, nil), Credential: cred(f), Scope: knowledge.ScopeOrg})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("list = %v, want the context's cancellation", err)
		}
	})
}

// TestTheTokenNeverLeaves: whatever a refusal echoes — the Authorization
// header a proxy reflected, the token in a message — the connector's error
// does not carry the credential in any form it was sent in.
func TestTheTokenNeverLeaves(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			f.echoAuth = true
			wrong := "ATATT3xFfGF0" + strings.Repeat("k3Y", 20)
			c, _ := testConnector(t)
			config := m.config(f, nil)
			_, err := c.List(context.Background(), knowledge.ListRequest{Config: config,
				Credential: knowledge.NewCredential([]byte(wrong)), Scope: knowledge.ScopeOrg})
			if err == nil {
				t.Fatal("a refused token listed")
			}
			forms := []string{wrong, base64.StdEncoding.EncodeToString([]byte(f.email + ":" + wrong))}
			for _, form := range forms {
				if strings.Contains(err.Error(), form) || strings.Contains(fmt.Sprintf("%+v", err), form) {
					t.Fatalf("the error carries the credential: %v", err)
				}
			}
			if !strings.Contains(err.Error(), "Received: ") {
				t.Fatalf("the refusal's own words were lost too: %v", err)
			}
		})
	}
}

// TestRedirectsAreNotFollowed: a site that answers with a redirect gets no
// second request, credential and all, at wherever it points.
func TestRedirectsAreNotFollowed(t *testing.T) {
	m := modes[0]
	f := m.site(t)
	f.redirect = true
	c, _ := testConnector(t)
	_, err := c.List(context.Background(), knowledge.ListRequest{Config: m.config(f, nil), Credential: cred(f), Scope: knowledge.ScopeOrg})
	if err == nil || !strings.Contains(err.Error(), "redirect") || !strings.Contains(err.Error(), "follows none") {
		t.Fatalf("list against a redirecting site = %v", err)
	}
	if n := len(f.requestLog()); n != 1 {
		t.Fatalf("%d requests to a redirecting site, want 1", n)
	}
}

// TestALargeAnswerIsAskedForInSmallerPages: an answer over the size the
// connector reads is asked for again, half as many documents at a time; a
// single page too large even alone is indexed by its title.
func TestALargeAnswerIsAskedForInSmallerPages(t *testing.T) {
	saved := maxResponseBytes
	t.Cleanup(func() { maxResponseBytes = saved })
	maxResponseBytes = 64 << 10
	for _, m := range []mode{modes[0], modes[2]} {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			for i := 0; i < 12; i++ {
				f.add("page", "ENG", fmt.Sprintf("Page %d", i), "", "<p>"+strings.Repeat("words ", 2000)+"</p>")
			}
			huge := f.add("page", "ENG", "Huge", "", "<p>"+strings.Repeat("enormous ", 20000)+"</p>")
			c, _ := testConnector(t)
			docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "")
			if len(docs) != 13 {
				t.Fatalf("listed %d documents, want 13", len(docs))
			}
			got := byID(docs)
			if d := got[huge.ID]; d.Deleted || d.Title != "Huge" || d.Body != "" {
				t.Fatalf("the page too large to read = title %q, %d bytes of body", d.Title, len(d.Body))
			}
			for _, d := range docs {
				if d.ExternalID != huge.ID && !strings.Contains(d.Body, "words words") {
					t.Fatalf("%s lost its body", d.Title)
				}
			}
		})
	}
}

// TestNextLinksStayOnTheSite: a next-page link to another host, or to another
// endpoint of the site, is refused rather than followed with the credential.
func TestNextLinksStayOnTheSite(t *testing.T) {
	c, _ := testConnector(t)
	f := modes[2].site(t)
	s, err := c.parseConfig(modes[2].config(f, nil), knowledge.ScopeOrg)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := c.newClient(s, cred(f))
	if err != nil {
		t.Fatal(err)
	}
	ss := &session{s: s, cl: cl}
	for _, bad := range []string{
		"https://evil.example/confluence/rest/api/content/search?start=25",
		"//evil.example/rest/api/content/search?start=25",
		"/rest/api/user/current?start=25",
		"/rest/api/content/search",
	} {
		if _, err := ss.nextRef(bad, pathSearch); err == nil {
			t.Errorf("next link %q was accepted", bad)
		}
	}
	for _, good := range []string{
		"/rest/api/content/search?cql=x&start=25",
		f.baseURL() + "/rest/api/content/search?cql=x&start=25",
		"/confluence/rest/api/content/search?cql=x&start=25",
	} {
		if ref, err := ss.nextRef(good, pathSearch); err != nil || ref != "/rest/api/content/search?cql=x&start=25" {
			t.Errorf("next link %q = %q, %v", good, ref, err)
		}
	}
}

// TestACursorThatDoesNotDecodeStartsOver: a cursor from another version, or
// garbage, lists from the beginning rather than failing every sync.
func TestACursorThatDoesNotDecodeStartsOver(t *testing.T) {
	m := modes[2]
	f := m.site(t)
	f.add("page", "ENG", "A", "", "<p>a</p>")
	f.add("page", "OPS", "B", "", "<p>b</p>")
	c, _ := testConnector(t)
	for _, cursor := range []string{"garbage", "cf1.!!!", cursorPrefix + "e30", "cf0.abc"} {
		docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), cursor)
		if len(docs) != 2 {
			t.Fatalf("cursor %q listed %d documents, want both", cursor, len(docs))
		}
	}
}

// TestSpacesThatAreGoneHoldNothing: a configured space the site does not have
// lists nothing, and the others still list.
func TestSpacesThatAreGoneHoldNothing(t *testing.T) {
	for _, m := range []mode{modes[0], modes[2]} {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			p := f.add("page", "ENG", "Here", "", "<p>x</p>")
			c, _ := testConnector(t)
			docs, _, _ := pass(t, c, m.config(f, map[string]any{"spaces": []string{"ENG", "GONE"}}),
				knowledge.ScopeOrg, cred(f), "")
			sameIDs(t, "documents", ids(docs), idsOf(p))
			docs, _, _ = pass(t, c, m.config(f, map[string]any{"spaces": []string{"GONE"}}), knowledge.ScopeOrg, cred(f), "")
			if len(docs) != 0 {
				t.Fatalf("a source of no space listed %v", ids(docs))
			}
		})
	}
}

// TestFetch: one document, by id, in scope — or a deletion when it is out of
// scope, restricted or gone.
func TestFetch(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			parent := f.add("page", "ENG", "Parent", "", "<p>p</p>")
			p := f.add("page", "ENG", "Child", parent.ID, "<p>child text</p>")
			hidden := f.add("page", "ENG", "Hidden", "", "<p>h</p>")
			hidden.ReadGroups = []string{"x"}
			outside := f.add("page", "HR", "Outside", "", "<p>o</p>")
			c, _ := testConnector(t)
			fetch := func(id string) knowledge.Document {
				t.Helper()
				d, err := c.Fetch(context.Background(), knowledge.FetchRequest{Config: m.config(f, nil), Credential: cred(f),
					Scope: knowledge.ScopeOrg, ExternalID: id})
				if err != nil {
					t.Fatalf("fetch %s: %v", id, err)
				}
				return d
			}
			if d := fetch(p.ID); d.Deleted || !strings.Contains(d.Body, "child text") || strings.Join(d.Ancestors, ",") != "Parent" {
				t.Fatalf("fetch of a page = %+v", d)
			}
			for _, id := range []string{hidden.ID, outside.ID, "999999"} {
				if d := fetch(id); !d.Deleted {
					t.Fatalf("fetch of %s = %+v, want a deletion", id, d)
				}
			}
			if _, err := c.Fetch(context.Background(), knowledge.FetchRequest{Config: m.config(f, nil), Credential: cred(f),
				Scope: knowledge.ScopeOrg, ExternalID: "1 or 1=1"}); err == nil {
				t.Fatal("an id that is not a number was put in a query")
			}
		})
	}
}
