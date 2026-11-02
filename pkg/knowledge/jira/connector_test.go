package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
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

// rewrite sends every request to a test server, whatever host it names: what
// lets a source configured for api.atlassian.com talk to a fake.
type rewrite struct{ to *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host, out.Host = r.to.Scheme, r.to.Host, r.to.Host
	return http.DefaultTransport.RoundTrip(out)
}

// mode is one way a source reads a site.
type mode struct {
	name    string
	cloud   bool
	gateway bool // a Cloud site through api.atlassian.com
	bearer  bool
	jql     bool
}

var modes = []mode{
	{name: "cloud, projects (email and API token)", cloud: true},
	{name: "cloud through the gateway, jql (OAuth bearer)", cloud: true, gateway: true, bearer: true, jql: true},
	{name: "datacenter, projects (PAT)", bearer: true},
	{name: "datacenter, jql (PAT)", bearer: true, jql: true},
}

const gatewayContext = "/ex/jira/0a1b2c3d-9e8f-4a5b-8c7d-6e5f4a3b2c1d"

// site makes a site for m, with projects ENG, OPS and HR.
func (m mode) site(t *testing.T) *fakeJira {
	t.Helper()
	f := newFakeJira(t, m.cloud)
	if m.gateway {
		f.context = gatewayContext
	}
	if m.cloud && !m.bearer {
		f.email = "jira-bot@corp.example"
	}
	f.addProject("ENG", "Engineering")
	f.addProject("OPS", "Operations")
	f.addProject("HR", "People")
	return f
}

// config is m's configuration for f, scoped to ENG and OPS.
func (m mode) config(f *fakeJira, extra map[string]any) json.RawMessage {
	c := map[string]any{"base_url": f.baseURL(), "deployment": DeploymentDataCenter}
	if m.cloud {
		c["deployment"] = DeploymentCloud
	}
	if m.gateway {
		c["base_url"] = "https://" + gatewayHost + gatewayContext
	}
	if f.email != "" {
		c["email"] = f.email
	}
	if m.jql {
		c["jql"] = "project in (ENG, OPS)"
	} else {
		c["projects"] = []string{"ENG", "OPS"}
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return b
}

// connector is a connector that may talk to f, and never really sleeps.
func (m mode) connector(t *testing.T, f *fakeJira) (*Connector, *sleeps) {
	t.Helper()
	s := &sleeps{}
	opts := Options{AllowInsecure: true, Sleep: s.sleep, RequestTimeout: 10 * time.Second,
		Now: func() time.Time { return time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC) }}
	if m.gateway {
		u, err := url.Parse(f.srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		opts.Transport = rewrite{to: u}
	}
	return New(opts), s
}

// web is where m's issues are read.
func (m mode) web(f *fakeJira) string {
	if m.gateway {
		return "https://corp.atlassian.net"
	}
	return f.baseURL()
}

// rich is text as m's site writes rich text: ADF on Cloud, wiki markup on
// Data Center.
func (m mode) rich(paragraphs ...string) any {
	if !m.cloud {
		return strings.Join(paragraphs, "\n\n")
	}
	var content []any
	for _, p := range paragraphs {
		content = append(content, adfPara(adfText(p)))
	}
	return adfDoc(content...)
}

func cred(f *fakeJira) knowledge.Credential { return knowledge.NewCredential([]byte(f.token)) }

// pass lists from cursor until a page says no more follows, as a sync does,
// and returns the documents, the cursor after, and how many List calls it
// took.
func pass(t *testing.T, c *Connector, config json.RawMessage, scope string, credential knowledge.Credential, cursor string, pageSize int) ([]knowledge.Document, string, int) {
	t.Helper()
	var docs []knowledge.Document
	for calls := 1; ; calls++ {
		if calls > 500 {
			t.Fatal("the listing never ended")
		}
		page, err := c.List(context.Background(), knowledge.ListRequest{Config: config, Credential: credential,
			Scope: scope, Cursor: cursor, PageSize: pageSize})
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

func idsOf(issues ...*fakeIssue) []string {
	out := make([]string, 0, len(issues))
	for _, is := range issues {
		out = append(out, is.ID)
	}
	sort.Strings(out)
	return out
}

func sameIDs(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

func byID(docs []knowledge.Document) map[string]knowledge.Document {
	out := map[string]knowledge.Document{}
	for _, d := range docs {
		out[d.ExternalID] = d
	}
	return out
}

// TestAuthentication: each deployment signs in the way it takes — Cloud with
// an email and API token as basic auth, or an OAuth bearer token; Data Center
// with a personal access token — and a refused credential is an error that
// says so, without the credential in it.
func TestAuthentication(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			is := f.add("ENG", "Welcome", m.rich("hello"))
			c, _ := m.connector(t, f)
			docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "", 10)
			sameIDs(t, "documents", liveIDs(docs), idsOf(is))

			wrong := "wrong-token-" + strings.Repeat("Z9", 10)
			_, err := c.List(context.Background(), knowledge.ListRequest{Config: m.config(f, nil),
				Credential: knowledge.NewCredential([]byte(wrong)), Scope: knowledge.ScopeOrg})
			if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "refused the credential") {
				t.Fatalf("a wrong token = %v, want a 401 that names the credential", err)
			}
			if strings.Contains(err.Error(), wrong) || !atlassian.IsStatus(err, http.StatusUnauthorized) {
				t.Fatalf("the refusal carries the token, or lost its status: %v", err)
			}
		})
	}
}

// TestListingReadsEverythingInScope: a first pass lists every issue the
// source's scope holds — and none of the project it leaves out — each with
// its key and summary as the title, its browse URL, its project as the space,
// its project and parent as ancestors, and a body of its header, its
// description and its comments. A linked issue and a parent are named by key
// alone: their summaries never reach the document.
func TestListingReadsEverythingInScope(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			epic := f.add("ENG", "Payments epic", nil, func(is *fakeIssue) { is.Type = "Epic" })
			bug := f.add("ENG", "Login fails on Safari", m.rich("Users on Safari 17 cannot sign in."), func(is *fakeIssue) {
				is.Type, is.Status, is.Priority, is.Resolution = "Bug", "In Progress", "High", ""
				is.Labels, is.Components, is.FixVersions = []string{"auth", "safari"}, []string{"Web"}, []string{"2.4"}
				is.Parent = epic.Key
				is.Links = []fakeLink{{Type: "Blocks", Inward: "is blocked by", Outward: "blocks", To: "OPS-9", Outbound: true},
					{Type: "Blocks", Inward: "is blocked by", Outward: "blocks", To: "ENG-77"}}
			})
			f.comment(bug, "Alice Smith", m.rich("I can reproduce this."), "")
			ops := f.add("OPS", "Rotate certificates", m.rich("Every 90 days."), func(is *fakeIssue) { is.Resolution = "Done" })
			hr := f.add("HR", "Salaries", m.rich("not in scope"))
			c, _ := m.connector(t, f)
			docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "", 10)
			sameIDs(t, "documents", ids(docs), idsOf(epic, bug, ops))
			got := byID(docs)
			if _, ok := got[hr.ID]; ok {
				t.Fatal("an issue outside the source's scope was listed")
			}
			d := got[bug.ID]
			wantURL := m.web(f) + "/browse/" + bug.Key
			if d.Title != "ENG-2 Login fails on Safari" || d.URL != wantURL || d.Space != "ENG" || d.Deleted ||
				strings.Join(d.Ancestors, " › ") != "Engineering › ENG-1" || !d.UpdatedAt.Equal(bug.Updated) {
				t.Fatalf("the bug = %+v (want URL %s)", d, wantURL)
			}
			for _, want := range []string{
				"Project: Engineering (ENG)\nType: Bug\nStatus: In Progress\nPriority: High\nLabels: auth, safari\n" +
					"Components: Web\nFix versions: 2.4\nParent: ENG-1\nLinks: blocks OPS-9; is blocked by ENG-77",
				"# Description\n\nUsers on Safari 17 cannot sign in.",
				"# Comments\n\n## Alice Smith, 2026-10-01 11:01 UTC\n\nI can reproduce this.",
			} {
				if !strings.Contains(d.Body, want) {
					t.Fatalf("the bug's body lacks %q:\n%s", want, d.Body)
				}
			}
			for _, leak := range []string{"PARENT-SUMMARY-SECRET", "LINKED-SUMMARY-SECRET"} {
				if strings.Contains(d.Body, leak) || strings.Contains(strings.Join(d.Ancestors, " "), leak) {
					t.Fatalf("another issue's summary reached the document: %s", d.Body)
				}
			}
			if !strings.Contains(got[ops.ID].Body, "Resolution: Done") || strings.Join(got[ops.ID].ACL, ",") != "project:OPS" {
				t.Fatalf("the ops issue = %+v", got[ops.ID])
			}
			if e := got[epic.ID]; e.Title != "ENG-1 Payments epic" || strings.Contains(e.Body, "# Description") {
				t.Fatalf("an issue without a description = %+v", e)
			}
		})
	}
}

// TestPagination: a listing pages through a site's search — Cloud by its
// nextPageToken, Data Center by startAt, from a few issues back to cover a
// result that moved — and lists every issue exactly once.
func TestPagination(t *testing.T) {
	for _, m := range []mode{modes[0], modes[2]} {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			var want []*fakeIssue
			for i := 0; i < 23; i++ {
				want = append(want, f.add([]string{"ENG", "OPS"}[i%2], fmt.Sprintf("Issue %d", i), m.rich("body")))
			}
			c, _ := m.connector(t, f)
			docs, _, calls := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "", 7)
			sameIDs(t, "documents", ids(docs), idsOf(want...))
			if len(docs) != 23 || calls < 4 {
				t.Fatalf("%d documents in %d calls, want 23, each once, in at least 4", len(docs), calls)
			}
			var tokens, starts []string
			for _, b := range f.bodies {
				if tok, ok := b["nextPageToken"].(string); ok {
					tokens = append(tokens, tok)
				}
				if s, ok := b["startAt"].(float64); ok {
					starts = append(starts, strconv.Itoa(int(s)))
				}
			}
			if m.cloud && len(tokens) != calls-1 {
				t.Fatalf("%d calls sent %d tokens", calls, len(tokens))
			}
			if !m.cloud && strings.Join(starts, ",") != "0,4,8,12,16" {
				t.Fatalf("pages started at %v, want each three issues before where the last one ended", starts)
			}
		})
	}
}

// TestIncrementalCursor: after a first pass, a pass lists only what changed
// since, by appending "updated >= <ms>" — milliseconds since the epoch, which
// JQL reads the same in every time zone — to the source's query: the newest
// change the last pass saw, less the overlap. An issue changed since is
// listed; one that is not, is not.
func TestIncrementalCursor(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			var all []*fakeIssue
			for i := 0; i < 5; i++ {
				all = append(all, f.add("ENG", fmt.Sprintf("Issue %d", i), m.rich("v1")))
			}
			c, _ := m.connector(t, f)
			config := m.config(f, nil)
			docs, cursor, _ := pass(t, c, config, knowledge.ScopeOrg, cred(f), "", 10)
			sameIDs(t, "first pass", ids(docs), idsOf(all...))
			first := f.searches()[0]
			if strings.Contains(first, "updated >=") || !strings.HasSuffix(first, " ORDER BY updated DESC, key DESC") {
				t.Fatalf("the first pass searched %q", first)
			}

			// Nothing changed: the pass lists only the overlap — the newest
			// issue, changed less than its width before the bound.
			newest := all[4].Updated
			docs, cursor, _ = pass(t, c, config, knowledge.ScopeOrg, cred(f), cursor, 10)
			sameIDs(t, "a pass with nothing changed", ids(docs), idsOf(all[4]))
			searches := f.searches()
			bound := newest.Add(-overlap).UnixMilli()
			if q := searches[len(searches)-1]; !strings.Contains(q, ") AND updated >= "+strconv.FormatInt(bound, 10)+" ORDER BY") {
				t.Fatalf("the incremental pass searched %q, want updated >= %d (the newest change less %v)", q, bound, overlap)
			}

			f.edit(all[1], func(is *fakeIssue) { is.Description = m.rich("v2") })
			docs, _, _ = pass(t, c, config, knowledge.ScopeOrg, cred(f), cursor, 10)
			sameIDs(t, "a pass after an edit", ids(docs), idsOf(all[1], all[4]))
			if d := byID(docs)[all[1].ID]; !strings.Contains(d.Body, "v2") {
				t.Fatalf("the edited issue = %q", d.Body)
			}
		})
	}
}

// TestAPassResumesFromItsCursor: a pass stopped between pages resumes where
// it stopped — the same query, the next page — and a Cloud page token that
// lapsed between syncs begins the pass again rather than failing every sync.
func TestAPassResumesFromItsCursor(t *testing.T) {
	for _, m := range []mode{modes[0], modes[2]} {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			var all []*fakeIssue
			for i := 0; i < 9; i++ {
				all = append(all, f.add("ENG", fmt.Sprintf("Issue %d", i), m.rich("x")))
			}
			c, _ := m.connector(t, f)
			config := m.config(f, nil)
			page, err := c.List(context.Background(), knowledge.ListRequest{Config: config, Credential: cred(f),
				Scope: knowledge.ScopeOrg, PageSize: 4})
			if err != nil || !page.More || len(page.Documents) != 4 {
				t.Fatalf("first page = %d documents, more %t, %v", len(page.Documents), page.More, err)
			}
			rest, _, _ := pass(t, c, config, knowledge.ScopeOrg, cred(f), page.Cursor, 4)
			sameIDs(t, "the whole pass", ids(append(page.Documents, rest...)), idsOf(all...))
			if len(rest) != 5 {
				t.Fatalf("the resumed pass listed %d documents, want the 5 it had not", len(rest))
			}
			if !m.cloud {
				return
			}
			f.lapse()
			docs, _, _ := pass(t, c, config, knowledge.ScopeOrg, cred(f), page.Cursor, 4)
			sameIDs(t, "a pass whose token lapsed", ids(docs), idsOf(all...))
		})
	}
}

// TestADataCenterPassSurvivesIssuesLeavingIt: issues that leave a Data Center
// pass's results between its pages — deleted, or changed out of its scope —
// shift the issues behind them forward; a page asked for from a few issues
// back still lists every one that remains.
func TestADataCenterPassSurvivesIssuesLeavingIt(t *testing.T) {
	m := modes[2]
	f := m.site(t)
	var all []*fakeIssue
	for i := 0; i < 12; i++ {
		all = append(all, f.add("ENG", fmt.Sprintf("Issue %d", i), m.rich("x")))
	}
	// Newest first: the first page of four is issues 11 to 8. Before the
	// second, two of them go.
	f.beforePage = func(n int) {
		if n == 2 {
			f.remove(all[11])
			f.remove(all[10])
		}
	}
	c, _ := m.connector(t, f)
	docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "", 4)
	sameIDs(t, "documents", ids(docs), idsOf(all...))
}

// TestSecuredIssues: an issue with a security level is reported deleted
// rather than indexed, and a comment restricted to a group or a role is left
// out of its issue — unless the source sets include_secured, when both are
// indexed and marked so in the ACL hints and the text.
func TestSecuredIssues(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			open := f.add("ENG", "Open issue", m.rich("anyone may read this"))
			f.comment(open, "Alice", m.rich("a public comment"), "")
			f.comment(open, "Bob", m.rich("ROLE-ONLY-REMARK"), "role:Developers")
			f.comment(open, "Carol", m.rich("GROUP-ONLY-REMARK"), "group:jira-admins")
			secured := f.add("ENG", "Embargoed CVE", m.rich("EMBARGOED-DETAILS"), func(is *fakeIssue) { is.Security = "Security team" })
			c, _ := m.connector(t, f)

			docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "", 10)
			got := byID(docs)
			if d := got[secured.ID]; !d.Deleted || d.Body != "" || d.Title != "" {
				t.Fatalf("a secured issue was indexed: %+v", d)
			}
			body := got[open.ID].Body
			if !strings.Contains(body, "a public comment") || strings.Contains(body, "ROLE-ONLY") || strings.Contains(body, "GROUP-ONLY") {
				t.Fatalf("the open issue's comments = %s", body)
			}
			reconciled, err := c.Reconcile(context.Background(), knowledge.ReconcileRequest{Config: m.config(f, nil),
				Credential: cred(f), Scope: knowledge.ScopeOrg})
			if err != nil {
				t.Fatal(err)
			}
			sameIDs(t, "reconciled", sortedIDs(reconciled), idsOf(open))

			included := m.config(f, map[string]any{"include_secured": true})
			docs, _, _ = pass(t, c, included, knowledge.ScopeOrg, cred(f), "", 10)
			got = byID(docs)
			d := got[secured.ID]
			if d.Deleted || !strings.Contains(d.Body, "EMBARGOED-DETAILS") || !strings.Contains(d.Body, "Security level: Security team") ||
				strings.Join(d.ACL, ",") != "project:ENG,secured,security:Security team" {
				t.Fatalf("an included secured issue = %+v", d)
			}
			body = got[open.ID].Body
			if !strings.Contains(body, "## Bob, 2026-10-01 10:02 UTC (restricted to role Developers)\n\nROLE-ONLY-REMARK") ||
				!strings.Contains(body, "GROUP-ONLY-REMARK") {
				t.Fatalf("included restricted comments = %s", body)
			}
			reconciled, err = c.Reconcile(context.Background(), knowledge.ReconcileRequest{Config: included,
				Credential: cred(f), Scope: knowledge.ScopeOrg})
			if err != nil {
				t.Fatal(err)
			}
			sameIDs(t, "reconciled, secured included", sortedIDs(reconciled), idsOf(open, secured))
		})
	}
}

// TestASecurityFieldWithoutANameIsALevel: a security field the connector
// cannot read a name or an id from still marks the issue secured; only a
// field that is absent or null says it has none.
func TestASecurityFieldWithoutANameIsALevel(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"id":"1","fields":{"security":{}}}`:                 true,
		`{"id":"1","fields":{"security":{"id":"10100"}}}`:     true,
		`{"id":"1","fields":{"security":{"name":"Staff"}}}`:   true,
		`{"id":"1","fields":{"security":null}}`:               false,
		`{"id":"1","fields":{"summary":"no security field"}}`: false,
	} {
		var is issue
		if err := json.Unmarshal([]byte(raw), &is); err != nil || is.secured() != want {
			t.Errorf("%s: secured = %t, %v; want %t", raw, is.secured(), err, want)
		}
	}
}

func sortedIDs(v []string) []string {
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}

// TestCommentsBeyondWhatTheSearchEmbeds: an issue whose search answer embeds
// only some of its comments has the rest read from its comment pages, and an
// issue that went between the search and that read is reported deleted.
func TestCommentsBeyondWhatTheSearchEmbeds(t *testing.T) {
	for _, m := range []mode{modes[0], modes[2]} {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			f.embed = 3
			chatty := f.add("ENG", "Long thread", m.rich("start"))
			for i := 0; i < 130; i++ {
				f.comment(chatty, fmt.Sprintf("User %d", i), m.rich(fmt.Sprintf("remark number %d", i)), "")
			}
			quiet := f.add("ENG", "Quiet", m.rich("start"))
			f.comment(quiet, "Dana", m.rich("only one"), "")
			c, _ := m.connector(t, f)
			docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "", 10)
			body := byID(docs)[chatty.ID].Body
			for _, want := range []string{"remark number 0", "remark number 64", "remark number 129"} {
				if !strings.Contains(body, want) {
					t.Fatalf("the long thread lacks %q", want)
				}
			}
			if n := strings.Count(body, "\n## User "); n != 130 {
				t.Fatalf("the long thread has %d comments, want 130", n)
			}
			var commentReads int
			for _, r := range f.requestLog() {
				if strings.Contains(r, "/comment?") {
					commentReads++
				}
			}
			if commentReads != 2 {
				t.Fatalf("%d comment pages were read, want 2 — one issue, 130 comments, 100 a page", commentReads)
			}

			// Gone between the search and its comment pages: a deletion.
			f.set(func() { f.embed = 1 })
			f.comment(quiet, "Eve", m.rich("second"), "")
			f.set(func() { f.beforeComments = func() { f.remove(quiet) } })
			docs, _, _ = pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "", 10)
			if d, ok := byID(docs)[quiet.ID]; !ok || !d.Deleted {
				t.Fatalf("an issue deleted while its comments were read = %+v", d)
			}
		})
	}
}

// TestRateLimits: a site that answers 429 or 503 is retried after the wait it
// names — seconds or a date — or after a bounded backoff when it names none;
// a site that asks for longer than a sync waits fails the call instead.
func TestRateLimits(t *testing.T) {
	m := modes[0]
	for _, tc := range []struct {
		name    string
		faults  []fakeFault
		waits   []time.Duration
		backoff bool
		fails   bool
	}{
		{name: "429 with Retry-After seconds", faults: []fakeFault{{429, "3"}, {429, "1"}}, waits: []time.Duration{3 * time.Second, time.Second}},
		{name: "503 with a date", faults: []fakeFault{{503, "Mon, 02 Nov 2026 08:00:07 GMT"}}, waits: []time.Duration{7 * time.Second}},
		{name: "429 without Retry-After backs off", faults: []fakeFault{{429, ""}, {429, ""}, {503, ""}}, backoff: true},
		{name: "502 and 504 are retried", faults: []fakeFault{{502, ""}, {504, ""}}, backoff: true},
		{name: "a wait longer than a sync's fails the call", faults: []fakeFault{{429, "3600"}}, fails: true},
		{name: "too many retries fail the call", faults: []fakeFault{{429, "1"}, {429, "1"}, {429, "1"}, {429, "1"}, {429, "1"}, {429, "1"}}, fails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := m.site(t)
			is := f.add("ENG", "One", m.rich("x"))
			c, s := m.connector(t, f)
			f.fail(tc.faults...)
			page, err := c.List(context.Background(), knowledge.ListRequest{Config: m.config(f, nil), Credential: cred(f),
				Scope: knowledge.ScopeOrg})
			if tc.fails {
				if err == nil || !atlassian.IsStatus(err, http.StatusTooManyRequests) {
					t.Fatalf("list = %v, want the 429", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			sameIDs(t, "documents", ids(page.Documents), idsOf(is))
			waits := s.all()
			if tc.backoff {
				if len(waits) != len(tc.faults) {
					t.Fatalf("waits = %v", waits)
				}
				for i, w := range waits {
					top := min(atlassian.BackoffBase<<i, atlassian.BackoffMax)
					if w < top/2 || w > top {
						t.Fatalf("backoff %d waited %v, want within [%v, %v]", i, w, top/2, top)
					}
				}
				return
			}
			if fmt.Sprint(waits) != fmt.Sprint(tc.waits) {
				t.Fatalf("waits = %v, want %v", waits, tc.waits)
			}
		})
	}
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
			c, _ := m.connector(t, f)
			_, err := c.List(context.Background(), knowledge.ListRequest{Config: m.config(f, nil),
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
	for _, m := range []mode{modes[0], modes[2]} {
		f := m.site(t)
		f.redirect = true
		c, _ := m.connector(t, f)
		_, err := c.List(context.Background(), knowledge.ListRequest{Config: m.config(f, nil), Credential: cred(f), Scope: knowledge.ScopeOrg})
		if err == nil || !strings.Contains(err.Error(), "redirect") || !strings.Contains(err.Error(), "follows none") {
			t.Fatalf("%s: list against a redirecting site = %v", m.name, err)
		}
		if n := len(f.requestLog()); n != 1 {
			t.Fatalf("%s: %d requests to a redirecting site, want 1", m.name, n)
		}
	}
}

// TestALargeAnswerIsAskedForInSmallerPages: an answer over the size the
// connector reads is asked for again, half as many issues at a time; a single
// issue too large even alone is indexed by its title and header.
func TestALargeAnswerIsAskedForInSmallerPages(t *testing.T) {
	saved := maxResponseBytes
	t.Cleanup(func() { maxResponseBytes = saved })
	maxResponseBytes = 64 << 10
	for _, m := range []mode{modes[0], modes[2]} {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			for i := 0; i < 12; i++ {
				f.add("ENG", fmt.Sprintf("Issue %d", i), m.rich(strings.Repeat("words ", 2000)))
			}
			huge := f.add("ENG", "Huge", m.rich(strings.Repeat("enormous ", 20000)), func(is *fakeIssue) { is.Status = "Open" })
			c, _ := m.connector(t, f)
			docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "", 25)
			if len(docs) != 13 {
				t.Fatalf("listed %d documents, want 13", len(docs))
			}
			got := byID(docs)
			if d := got[huge.ID]; d.Deleted || d.Title != "ENG-13 Huge" || strings.Contains(d.Body, "enormous") ||
				!strings.Contains(d.Body, "Status: Open") {
				t.Fatalf("the issue too large to read = title %q, body %.120q", d.Title, d.Body)
			}
			for _, d := range docs {
				if d.ExternalID != huge.ID && !strings.Contains(d.Body, "words words") {
					t.Fatalf("%s lost its description", d.Title)
				}
			}
		})
	}
}

// TestACursorThatDoesNotDecodeStartsOver: a cursor from another version, or
// garbage, lists from the beginning rather than failing every sync.
func TestACursorThatDoesNotDecodeStartsOver(t *testing.T) {
	m := modes[2]
	f := m.site(t)
	a := f.add("ENG", "A", m.rich("a"))
	b := f.add("OPS", "B", m.rich("b"))
	c, _ := m.connector(t, f)
	bogusTail := cursor{Mid: true, Start: 1, Tail: []string{"not-an-id"}}.encode()
	for _, cur := range []string{"garbage", "jr1.!!!", cursorPrefix + "e30", "cf1.abc", bogusTail,
		cursor{Mid: true, Start: -4}.encode(), cursor{Mid: true, Token: "x\x00y"}.encode()} {
		docs, _, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), cur, 10)
		if cur == bogusTail {
			// A position it wrote, with a tail it did not: the page is read,
			// without skipping anything.
			continue
		}
		sameIDs(t, "documents after cursor "+cur, ids(docs), idsOf(a, b))
	}
}

// TestFetch: one issue, by id, in scope — or a deletion when it is out of
// scope, secured, or gone, which JQL refuses to name.
func TestFetch(t *testing.T) {
	for _, m := range []mode{modes[1], modes[3]} {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			in := f.add("ENG", "In scope", m.rich("here"))
			out := f.add("HR", "Out of scope", m.rich("there"))
			secured := f.add("OPS", "Secured", m.rich("hidden"), func(is *fakeIssue) { is.Security = "Staff" })
			gone := f.add("ENG", "Gone soon", m.rich("bye"))
			f.remove(gone)
			c, _ := m.connector(t, f)
			fetch := func(id string) (knowledge.Document, error) {
				return c.Fetch(context.Background(), knowledge.FetchRequest{Config: m.config(f, nil), Credential: cred(f),
					Scope: knowledge.ScopeOrg, ExternalID: id})
			}
			d, err := fetch(in.ID)
			if err != nil || d.Deleted || d.Title != "ENG-1 In scope" || d.URL != m.web(f)+"/browse/ENG-1" || !strings.Contains(d.Body, "here") {
				t.Fatalf("fetch in scope = %+v, %v", d, err)
			}
			for _, id := range []string{out.ID, secured.ID, gone.ID} {
				if d, err := fetch(id); err != nil || !d.Deleted || d.ExternalID != id {
					t.Fatalf("fetch %s = %+v, %v, want a deletion", id, d, err)
				}
			}
			if _, err := fetch("ENG-1) OR (project = HR"); err == nil {
				t.Fatal("an id that is not one was looked up")
			}
		})
	}
}

// TestReconcileAndNarrow: a reconciliation names every issue in scope, and a
// narrowing every issue in scope that a binding's query matches, paging
// through all of them; a query the site refuses is an error, not an empty
// answer.
func TestReconcileAndNarrow(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			var all, runbooks []*fakeIssue
			for i := 0; i < 2500; i++ {
				is := f.add([]string{"ENG", "OPS"}[i%2], fmt.Sprintf("Issue %d", i), nil, func(is *fakeIssue) {
					if i%7 == 0 {
						is.Labels = []string{"runbook"}
					}
				})
				all = append(all, is)
				if i%7 == 0 {
					runbooks = append(runbooks, is)
				}
			}
			f.add("HR", "Not in scope", nil, func(is *fakeIssue) { is.Labels = []string{"runbook"} })
			// Sites cap a page below what was asked: 2,500 issues, 300 a page.
			f.maxResults = 300
			c, _ := m.connector(t, f)
			got, err := c.Reconcile(context.Background(), knowledge.ReconcileRequest{Config: m.config(f, nil),
				Credential: cred(f), Scope: knowledge.ScopeOrg})
			if err != nil {
				t.Fatal(err)
			}
			sameIDs(t, "reconciled", sortedIDs(got), idsOf(all...))
			if q := f.searches()[0]; !strings.HasSuffix(q, " ORDER BY created ASC, key ASC") {
				t.Fatalf("reconciliation searched %q", q)
			}
			narrowed, err := c.Narrow(context.Background(), knowledge.NarrowRequest{Config: m.config(f, nil),
				Credential: cred(f), Scope: knowledge.ScopeOrg, Query: "labels = runbook"})
			if err != nil {
				t.Fatal(err)
			}
			sameIDs(t, "narrowed", sortedIDs(narrowed), idsOf(runbooks...))
			if _, err := c.Narrow(context.Background(), knowledge.NarrowRequest{Config: m.config(f, nil),
				Credential: cred(f), Scope: knowledge.ScopeOrg, Query: "labels = runbook ORDER BY created"}); err == nil {
				t.Fatal("a binding query with ORDER BY narrowed")
			}
			if _, err := c.Narrow(context.Background(), knowledge.NarrowRequest{Config: m.config(f, nil),
				Credential: cred(f), Scope: knowledge.ScopeOrg, Query: "labels =="}); err == nil ||
				!strings.Contains(err.Error(), "Error in the JQL Query") {
				t.Fatalf("a query the site refuses = %v", err)
			}
		})
	}
}

// TestADataCenterIDListingThatMissesIssuesFails: a reconciliation whose
// results moved under it so far that its pages could not cover it reads
// fewer issues than the search matches, and fails rather than answer — an
// answer that leaves an issue out takes it out of the index.
func TestADataCenterIDListingThatMissesIssuesFails(t *testing.T) {
	m := modes[2]
	f := m.site(t)
	var all []*fakeIssue
	for i := 0; i < 2200; i++ {
		all = append(all, f.add("ENG", fmt.Sprintf("Issue %d", i), nil))
	}
	f.beforePage = func(n int) {
		if n == 2 {
			// Oldest first: the first page held these; with them gone, the
			// rest shift by more than a page's overlap.
			for _, is := range all[:200] {
				f.remove(is)
			}
		}
	}
	c, _ := m.connector(t, f)
	_, err := c.Reconcile(context.Background(), knowledge.ReconcileRequest{Config: m.config(f, nil), Credential: cred(f),
		Scope: knowledge.ScopeOrg})
	if err == nil || !strings.Contains(err.Error(), "changed while they were read") {
		t.Fatalf("a reconciliation that missed issues = %v", err)
	}
}

// TestAFutureChangeDoesNotHoldTheCursor: an issue dated far in the future —
// an import that set it, a clock gone wrong — does not set where the next
// pass begins, or every later pass would see nothing.
func TestAFutureChangeDoesNotHoldTheCursor(t *testing.T) {
	m := modes[2]
	f := m.site(t)
	normal := f.add("ENG", "Normal", m.rich("x"))
	f.add("ENG", "From the future", m.rich("y"), func(is *fakeIssue) { is.Updated = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC) })
	c, _ := m.connector(t, f)
	_, cur, _ := pass(t, c, m.config(f, nil), knowledge.ScopeOrg, cred(f), "", 10)
	if got, want := decodeCursor(cur).Since, normal.Updated.Add(-overlap).UnixMilli(); got != want {
		t.Fatalf("the next pass begins at %d, want %d", got, want)
	}
}

// TestTheConnectorIsRegistered: the hub's registry has the connector, which
// pkg/ui's blank import brings into the hub build.
func TestTheConnectorIsRegistered(t *testing.T) {
	c, ok := knowledge.DefaultRegistry().Lookup(Kind)
	if !ok || c.Kind() != Kind {
		t.Fatal("no jira connector in the default registry")
	}
	if _, ok := c.(knowledge.Reconciler); !ok {
		t.Fatal("the jira connector does not reconcile")
	}
}
