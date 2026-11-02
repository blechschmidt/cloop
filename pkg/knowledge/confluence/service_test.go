package confluence

// The connector through pkg/knowledge's sync, into the hub's database and out
// of its search: what a project member finds, and what leaves the index.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// siteSecrets is a secret store holding one shared secret, the site's token.
type siteSecrets struct{ token string }

func (s siteSecrets) CheckSourceCredential(ref, owner string) error {
	if ref != "wiki-token" || owner != "" {
		return secretbroker.ErrSecretNotFound
	}
	return nil
}

func (s siteSecrets) SourceCredential(ref, owner string) ([]byte, error) {
	if err := s.CheckSourceCredential(ref, owner); err != nil {
		return nil, err
	}
	return []byte(s.token), nil
}

var project = knowledge.Project{Path: "/srv/projects/app", Name: "app"}

// hub is a knowledge service over a fresh hub database, reading f through a
// test connector, on a clock the test moves.
type hub struct {
	svc *knowledge.Service
	acc *knowledge.Access
	now time.Time
}

func newHub(t *testing.T, f *fakeSite) *hub {
	t.Helper()
	return newHubWithToken(t, f.token)
}

// newHubWithToken is newHub with token in the hub's secret store.
func newHubWithToken(t *testing.T, token string) *hub {
	t.Helper()
	db := statedbtest.Open(t).AsControlPlane()
	reg := knowledge.NewRegistry()
	conn, _ := testConnector(t)
	if err := reg.Register(conn); err != nil {
		t.Fatal(err)
	}
	h := &hub{now: time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)}
	h.svc = knowledge.New(db, knowledge.WithRegistry(reg), knowledge.WithCredentials(siteSecrets{token}),
		knowledge.WithClock(func() time.Time { return h.now }), knowledge.WithReconcileEvery(6*time.Hour))
	// No sign-in: every caller holds everything, as on a hub without SSO.
	h.acc = h.svc.For(knowledge.PrincipalFor(false, nil, nil, "", "test"))
	return h
}

func (h *hub) source(t *testing.T, m mode, f *fakeSite, extra map[string]any) knowledge.Source {
	t.Helper()
	src, err := h.acc.CreateSource(context.Background(), knowledge.SourceInput{
		Kind: Kind, Name: "Wiki", Scope: knowledge.ScopeOrg, Config: m.config(f, extra), SecretRef: "wiki-token",
	})
	if err != nil {
		t.Fatalf("create the source: %v", err)
	}
	if _, _, err := h.acc.Bind(context.Background(), project, src.ID, knowledge.Filter{}); err != nil {
		t.Fatalf("bind it: %v", err)
	}
	return src
}

func (h *hub) sync(t *testing.T, id int64) knowledge.SyncReport {
	t.Helper()
	report, err := h.svc.Sync(context.Background(), id)
	if err != nil {
		t.Fatalf("sync: %v (%+v)", err, report)
	}
	return report
}

// found returns the titles a search of the project finds for query.
func (h *hub) found(t *testing.T, query string) []string {
	t.Helper()
	hits, err := h.acc.Search(context.Background(), project, query, 50)
	if err != nil {
		t.Fatalf("search %q: %v", query, err)
	}
	var out []string
	for _, hit := range hits {
		out = append(out, hit.Title)
	}
	return out
}

// TestSyncIndexesAndCites: a sync indexes the source's pages and blog posts,
// and a search hit carries what a citation needs — the title, the web URL,
// the space and the pages above it.
func TestSyncIndexesAndCites(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			root := f.add("page", "ENG", "Platform", "", "<p>The platform team.</p>")
			guides := f.add("page", "ENG", "Guides", root.ID, "<p>Guides.</p>")
			deploy := f.add("page", "ENG", "Deploying the hub", guides.ID,
				`<h1>Deploying</h1><p>Run <code>make deploy</code> from a clean checkout.</p>`+
					`<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">bash</ac:parameter>`+
					`<ac:plain-text-body><![CDATA[kubectl rollout status deploy/hub]]></ac:plain-text-body></ac:structured-macro>`)
			f.add("blogpost", "OPS", "Rollout notes", "", "<p>The rollout went fine.</p>")
			h := newHub(t, f)
			src := h.source(t, m, f, nil)
			report := h.sync(t, src.ID)
			if report.Created != 4 || !report.Complete || !report.Full {
				t.Fatalf("the first sync = %+v", report)
			}
			hits, err := h.acc.Search(context.Background(), project, "rollout", 10)
			if err != nil || len(hits) != 2 {
				t.Fatalf("search = %d hits, %v", len(hits), err)
			}
			var hit knowledge.Hit
			for _, x := range hits {
				if x.Title == deploy.Title {
					hit = x
				}
			}
			if hit.URL != f.baseURL()+f.webui(deploy) || hit.Space != "ENG" ||
				strings.Join(hit.Ancestors, " › ") != "Platform › Guides" || hit.Heading != "Deploying" {
				t.Fatalf("the hit = %+v", hit)
			}
			if !strings.Contains(hit.Snippet, "rollout") {
				t.Fatalf("the snippet does not show the match: %q", hit.Snippet)
			}
		})
	}
}

// TestReconciliationRemovesWhatTheListingCannotSee: a page deleted, one
// moved to a space the source does not read, one restricted and one under it
// — none of them edited — stay indexed through incremental syncs, which list
// only changes, until a reconciliation is due and removes them.
func TestReconciliationRemovesWhatTheListingCannotSee(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			parent := f.add("page", "ENG", "Handbook", "", "<p>handbook zebra</p>")
			deleted := f.add("page", "ENG", "Old process", "", "<p>zebra crossing</p>")
			moved := f.add("page", "ENG", "Moving page", "", "<p>zebra stripes</p>")
			f.add("page", "ENG", "Handbook chapter", parent.ID, "<p>zebra chapter</p>")
			stays := f.add("page", "OPS", "Stays", "", "<p>zebra herd</p>")
			h := newHub(t, f)
			src := h.source(t, m, f, nil)
			h.sync(t, src.ID)
			if got := h.found(t, "zebra"); len(got) != 5 {
				t.Fatalf("after the first sync the search finds %q", got)
			}

			f.set(func() {
				delete(f.content, deleted.ID)
				moved.Space = "HR"
				parent.ReadGroups = []string{"people-team"}
			})
			// An incremental sync lists changes; none of these is one.
			h.now = h.now.Add(time.Hour)
			if report := h.sync(t, src.ID); report.Reconciled || report.Deleted != 0 {
				t.Fatalf("an incremental sync before reconciliation is due = %+v", report)
			}
			if got := h.found(t, "zebra"); len(got) != 5 {
				t.Fatalf("an incremental sync removed what it cannot see: %q", got)
			}

			// Six hours after the first sync's full listing, which counted
			// as a reconciliation, the next one is due.
			h.now = h.now.Add(5*time.Hour + time.Minute)
			report := h.sync(t, src.ID)
			if !report.Reconciled || report.Removed != 4 {
				t.Fatalf("the reconciling sync = %+v, want the deleted, moved and restricted pages removed", report)
			}
			if got := strings.Join(h.found(t, "zebra"), ","); got != stays.Title {
				t.Fatalf("after reconciliation the search finds %q", got)
			}
			h.now = h.now.Add(time.Hour)
			if report := h.sync(t, src.ID); report.Reconciled {
				t.Fatalf("a sync an hour after a reconciliation reconciled again: %+v", report)
			}
		})
	}
}

// TestReconciliationKeepsWhatAListingJustIndexed: v2 lists a page the site's
// search index does not have yet, and the reconciliation's answer, read from
// that index, leaves it out; a page a sync listed within the hour is kept.
func TestReconciliationKeepsWhatAListingJustIndexed(t *testing.T) {
	m := modes[0]
	f := m.site(t)
	f.add("page", "ENG", "Old", "", "<p>okapi old</p>")
	h := newHub(t, f)
	src := h.source(t, m, f, nil)
	h.sync(t, src.ID)
	fresh := f.add("page", "ENG", "Fresh", "", "<p>okapi fresh</p>")
	f.searchLag[fresh.ID] = true
	// A newer page, which the next pass's overlap lists again: the fresh
	// one is not.
	f.add("page", "ENG", "Newer", "", "<p>okapi newer</p>")
	// Listed by a sync before a reconciliation is due...
	h.now = h.now.Add(5*time.Hour + 45*time.Minute)
	if report := h.sync(t, src.ID); report.Reconciled || report.Created != 2 {
		t.Fatalf("the sync that lists the fresh page = %+v", report)
	}
	// ...and left out of the answer of the one half an hour later.
	h.now = h.now.Add(30 * time.Minute)
	report := h.sync(t, src.ID)
	if !report.Reconciled || report.Removed != 0 {
		t.Fatalf("the reconciling sync = %+v", report)
	}
	if got := h.found(t, "okapi"); len(got) != 3 {
		t.Fatalf("the search finds %q, want the fresh page kept", got)
	}
}

// TestAnEditedPageThatBecameRestrictedLeavesAtOnce: a page restricted and
// edited is listed as a deletion by the next incremental sync, without
// waiting for a reconciliation.
func TestAnEditedPageThatBecameRestrictedLeavesAtOnce(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			p := f.add("page", "ENG", "Layoffs", "", "<p>quarterly plan</p>")
			h := newHub(t, f)
			src := h.source(t, m, f, nil)
			h.sync(t, src.ID)
			if len(h.found(t, "quarterly")) != 1 {
				t.Fatal("the page was not indexed")
			}
			f.edit(p, func(c *fakeContent) { c.ReadUsers = []string{"557058:cfo"}; c.Body = "<p>quarterly plan v2</p>" })
			h.now = h.now.Add(time.Minute)
			report := h.sync(t, src.ID)
			if report.Deleted != 1 || report.Reconciled {
				t.Fatalf("the sync after the restriction = %+v", report)
			}
			if got := h.found(t, "quarterly"); len(got) != 0 {
				t.Fatalf("the restricted page is still found: %q", got)
			}
		})
	}
}

// TestABindingNarrowedByCQL: a binding's CQL admits only what it matches.
func TestABindingNarrowedByCQL(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			a := f.add("page", "ENG", "Runbook: deploy", "", "<p>giraffe deploy</p>")
			a.Labels = []string{"runbook"}
			f.add("page", "ENG", "Design notes", "", "<p>giraffe design</p>")
			h := newHub(t, f)
			src, err := h.acc.CreateSource(context.Background(), knowledge.SourceInput{
				Kind: Kind, Name: "Wiki", Scope: knowledge.ScopeOrg, Config: m.config(f, nil), SecretRef: "wiki-token",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := h.acc.Bind(context.Background(), project, src.ID, knowledge.Filter{Query: "label ORDER BY x"}); err == nil {
				t.Fatal("a binding query with ORDER BY was accepted")
			}
			if _, _, err := h.acc.Bind(context.Background(), project, src.ID, knowledge.Filter{Query: `label = "runbook"`}); err != nil {
				t.Fatal(err)
			}
			report := h.sync(t, src.ID)
			if report.Narrowed != 1 {
				t.Fatalf("the sync = %+v", report)
			}
			if got := h.found(t, "giraffe"); len(got) != 1 || got[0] != a.Title {
				t.Fatalf("the narrowed binding finds %q", got)
			}
		})
	}
}

// TestAFailedSyncRecordsNoToken: a sync the site refuses records why on the
// source — without the credential, which the refusal echoed.
func TestAFailedSyncRecordsNoToken(t *testing.T) {
	m := modes[0]
	f := m.site(t)
	f.echoAuth = true
	stale := "stale-" + strings.Repeat("Ab3", 10)
	h := newHubWithToken(t, stale)
	src := h.source(t, m, f, nil)
	if _, err := h.svc.Sync(context.Background(), src.ID); err == nil || strings.Contains(err.Error(), stale) {
		t.Fatalf("a refused sync = %v", err)
	}
	got, _, err := h.acc.Source(context.Background(), src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sync.Status != "error" || !strings.Contains(got.Sync.Error, "401") || !strings.Contains(got.Sync.Error, "Received") {
		t.Fatalf("the recorded sync = %+v", got.Sync)
	}
	if strings.Contains(got.Sync.Error, "Ab3Ab3") {
		t.Fatalf("the recorded error carries the token: %q", got.Sync.Error)
	}
}
