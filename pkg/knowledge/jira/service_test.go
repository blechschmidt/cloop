package jira

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
	if ref != "jira-token" || owner != "" {
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

// hub is a knowledge service over a fresh hub database, reading a site
// through a test connector, on a clock the test moves.
type hub struct {
	svc *knowledge.Service
	acc *knowledge.Access
	now time.Time
}

func newHub(t *testing.T, m mode, f *fakeJira) *hub {
	t.Helper()
	return newHubWithToken(t, m, f, f.token)
}

// newHubWithToken is newHub with token in the hub's secret store.
func newHubWithToken(t *testing.T, m mode, f *fakeJira, token string) *hub {
	t.Helper()
	db := statedbtest.Open(t).AsControlPlane()
	reg := knowledge.NewRegistry()
	conn, _ := m.connector(t, f)
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

func (h *hub) source(t *testing.T, m mode, f *fakeJira, extra map[string]any) knowledge.Source {
	t.Helper()
	src, err := h.acc.CreateSource(context.Background(), knowledge.SourceInput{
		Kind: Kind, Name: "Tracker", Scope: knowledge.ScopeOrg, Config: m.config(f, extra), SecretRef: "jira-token",
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

func (h *hub) hits(t *testing.T, query string) []knowledge.Hit {
	t.Helper()
	hits, err := h.acc.Search(context.Background(), project, query, 50)
	if err != nil {
		t.Fatalf("search %q: %v", query, err)
	}
	return hits
}

// found returns the titles a search of the project finds for query, each
// once.
func (h *hub) found(t *testing.T, query string) []string {
	t.Helper()
	var out []string
	seen := map[string]bool{}
	for _, hit := range h.hits(t, query) {
		if !seen[hit.Title] {
			seen[hit.Title] = true
			out = append(out, hit.Title)
		}
	}
	return out
}

// TestSyncIndexesAndCites: a sync indexes the source's issues, and a search
// hit carries what a citation needs — the key and summary, the browse URL,
// the project and parent, and the section of the issue it matched.
func TestSyncIndexesAndCites(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			epic := f.add("ENG", "Checkout revamp", m.rich("The epic."))
			bug := f.add("ENG", "Card declined twice", m.rich("Customers are charged twice when a card is declined."),
				func(is *fakeIssue) { is.Parent, is.Type = epic.Key, "Bug" })
			f.comment(bug, "Alice", m.rich("The retry loop in the payment gateway is the culprit."), "")
			f.add("OPS", "Renew TLS", m.rich("Renew before expiry."))
			f.add("HR", "Offsite", m.rich("gateway offsite planning"))
			h := newHub(t, m, f)
			src := h.source(t, m, f, nil)
			report := h.sync(t, src.ID)
			if report.Created != 3 || !report.Complete || !report.Full {
				t.Fatalf("first sync = %+v", report)
			}
			hits := h.hits(t, "gateway")
			if len(hits) != 1 {
				t.Fatalf("a search for gateway = %+v, want the bug's comment alone (HR is out of scope)", hits)
			}
			hit := hits[0]
			if hit.Title != "ENG-2 Card declined twice" || hit.URL != m.web(f)+"/browse/ENG-2" || hit.Space != "ENG" ||
				strings.Join(hit.Ancestors, " › ") != "Engineering › ENG-1" || hit.Source.Kind != Kind ||
				!strings.HasPrefix(hit.Heading, "Comments › Alice, 2026-10-01") {
				t.Fatalf("the hit = %+v", hit)
			}
			if !strings.Contains(hit.Snippet, knowledge.SnippetOpen+"gateway"+knowledge.SnippetClose) {
				t.Fatalf("the snippet = %q", hit.Snippet)
			}
			if got := h.found(t, "Bug"); len(got) != 1 || got[0] != hit.Title {
				t.Fatalf("a search of the header finds %q", got)
			}
			// Nothing changed: an incremental sync re-lists only the overlap,
			// and chunks nothing again.
			h.now = h.now.Add(time.Hour)
			if report := h.sync(t, src.ID); report.Full || report.Created != 0 || report.Updated != 0 || report.Listed > 1 {
				t.Fatalf("an incremental sync with nothing changed = %+v", report)
			}
		})
	}
}

// TestReconciliationRemovesWhatTheListingCannotSee: an issue deleted, one
// moved to a project the source does not read, and one given a security level
// — none of them, as far as their updated time says, changed — stay indexed
// through incremental syncs, which list only changes, until a reconciliation
// is due and removes them.
func TestReconciliationRemovesWhatTheListingCannotSee(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			deleted := f.add("ENG", "Old process", m.rich("walrus crossing"))
			moved := f.add("ENG", "Moving issue", m.rich("walrus stripes"))
			secured := f.add("ENG", "Becomes secret", m.rich("walrus secret"))
			stays := f.add("OPS", "Stays", m.rich("walrus herd"))
			h := newHub(t, m, f)
			src := h.source(t, m, f, nil)
			h.sync(t, src.ID)
			if got := h.found(t, "walrus"); len(got) != 4 {
				t.Fatalf("after the first sync the search finds %q", got)
			}

			f.remove(deleted)
			f.set(func() {
				moved.Project, moved.Key = "HR", "HR-1"
				secured.Security = "Legal"
			})
			// An incremental sync lists changes; none of these is one.
			h.now = h.now.Add(time.Hour)
			if report := h.sync(t, src.ID); report.Reconciled || report.Deleted != 0 {
				t.Fatalf("an incremental sync before reconciliation is due = %+v", report)
			}
			if got := h.found(t, "walrus"); len(got) != 4 {
				t.Fatalf("an incremental sync removed what it cannot see: %q", got)
			}

			// Six hours after the first sync's full listing, which counted as
			// a reconciliation, the next one is due.
			h.now = h.now.Add(5*time.Hour + time.Minute)
			report := h.sync(t, src.ID)
			if !report.Reconciled || report.Removed != 3 {
				t.Fatalf("the reconciling sync = %+v, want the deleted, moved and secured issues removed", report)
			}
			if got := strings.Join(h.found(t, "walrus"), ","); got != "OPS-1 Stays" || stays.Key != "OPS-1" {
				t.Fatalf("after reconciliation the search finds %q", got)
			}
		})
	}
}

// TestAnIssueSecuredWithAnEditLeavesAtOnce: setting a security level is an
// edit of the issue, so the next incremental sync lists it — as a deletion,
// without waiting for a reconciliation; and a comment restricted to a role
// leaves the index with the sync that lists it.
func TestAnIssueSecuredWithAnEditLeavesAtOnce(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			is := f.add("ENG", "Reorg", m.rich("quarterly plan"))
			other := f.add("ENG", "Roadmap", m.rich("public roadmap"))
			h := newHub(t, m, f)
			src := h.source(t, m, f, nil)
			h.sync(t, src.ID)
			if len(h.found(t, "quarterly")) != 1 {
				t.Fatal("the issue was not indexed")
			}
			f.edit(is, func(is *fakeIssue) { is.Security = "Leadership" })
			f.comment(other, "Mallory", m.rich("internal okapi remark"), "group:leads")
			h.now = h.now.Add(time.Minute)
			report := h.sync(t, src.ID)
			if report.Deleted != 1 || report.Reconciled {
				t.Fatalf("the sync after the security level = %+v", report)
			}
			if got := h.found(t, "quarterly"); len(got) != 0 {
				t.Fatalf("the secured issue is still found: %q", got)
			}
			if got := h.found(t, "okapi"); len(got) != 0 {
				t.Fatalf("a restricted comment is found: %q", got)
			}
			if got := h.found(t, "roadmap"); len(got) != 1 {
				t.Fatalf("the issue with the restricted comment is gone: %q", got)
			}
		})
	}
}

// TestABindingNarrowedByJQL: a binding's JQL admits only what it matches.
func TestABindingNarrowedByJQL(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			runbook := f.add("ENG", "Runbook: deploy", m.rich("giraffe deploy"), func(is *fakeIssue) { is.Labels = []string{"runbook"} })
			f.add("ENG", "Design notes", m.rich("giraffe design"))
			h := newHub(t, m, f)
			src, err := h.acc.CreateSource(context.Background(), knowledge.SourceInput{
				Kind: Kind, Name: "Tracker", Scope: knowledge.ScopeOrg, Config: m.config(f, nil), SecretRef: "jira-token",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := h.acc.Bind(context.Background(), project, src.ID, knowledge.Filter{Query: "labels = x ORDER BY key"}); err == nil {
				t.Fatal("a binding query with ORDER BY was accepted")
			}
			if _, _, err := h.acc.Bind(context.Background(), project, src.ID, knowledge.Filter{Query: `labels = "runbook"`}); err != nil {
				t.Fatal(err)
			}
			report := h.sync(t, src.ID)
			if report.Narrowed != 1 {
				t.Fatalf("the sync = %+v", report)
			}
			if got := h.found(t, "giraffe"); len(got) != 1 || got[0] != runbook.Key+" Runbook: deploy" {
				t.Fatalf("the narrowed binding finds %q", got)
			}
		})
	}
}

// TestAFailedSyncRecordsNoToken: a sync the site refuses records why on the
// source — without the credential, which the refusal echoed.
func TestAFailedSyncRecordsNoToken(t *testing.T) {
	for _, m := range []mode{modes[0], modes[2]} {
		t.Run(m.name, func(t *testing.T) {
			f := m.site(t)
			f.echoAuth = true
			stale := "stale-" + strings.Repeat("Ab3", 10)
			h := newHubWithToken(t, m, f, stale)
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
		})
	}
}
