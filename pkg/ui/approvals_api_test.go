package ui

// The approvals inbox, per identity (Task 20427): what each caller is shown is
// exactly what the decision routes would let them decide — and the decision
// route refuses what the inbox withholds.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// getJSONAs reads one JSON answer with a signed-in client.
func getJSONAs(t *testing.T, c *http.Client, url string, out any) int {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK && out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			t.Fatalf("GET %s: decode %s: %v", url, body, err)
		}
	}
	return resp.StatusCode
}

// seedRequests writes access requests straight into the control plane, the
// rows a filing would have left.
func seedRequests(t *testing.T, dir string, reqs ...secretbroker.AccessRequest) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reqs {
		if err := store.PutAccessRequest(r); err != nil {
			t.Fatalf("seed %s: %v", r.ID, err)
		}
	}
}

// pendingRequest is a request filed now, waiting days for a decision.
func pendingRequest(id, by, subject string, now time.Time) secretbroker.AccessRequest {
	sub, err := secretbroker.ParseSubject(subject)
	if err != nil {
		panic(err)
	}
	return secretbroker.AccessRequest{
		ID: id, RequestedBy: by, SecretID: "sec_" + id, SecretName: "acme-app", Kind: secretbroker.KindGitHubApp,
		Subject: sub, Constraints: secretbroker.Constraints{Repos: []string{"acme/api"}},
		TTL: 24 * time.Hour, Justification: "ship API-412", State: secretbroker.RequestPending,
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour),
	}
}

// approvalsFixture is a hub with a role policy and the requests every
// identity's inbox is judged against.
type approvalsFixture struct {
	srv          *Server
	idp          *uiFakeIdP
	hts          *httptest.Server
	ts           string
	projA, projB string
}

func newApprovalsFixture(t *testing.T) approvalsFixture {
	t.Helper()
	// A hub with requests has the key its broker needs: without one, the
	// inbox offers nothing to decide (TestApprovalsInboxNeedsTheBrokerKey).
	t.Setenv("CLOOP_SECRET_KEY", "approvals-inbox-test-passphrase")
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	projA, projB := t.TempDir(), t.TempDir()
	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimEmail, Value: "admin@example.com", Role: authz.RoleAdmin},
			// A maintainer across the hub, whom an incident has since
			// denied project B.
			{Claim: authz.ClaimEmail, Value: "maint@example.com", Role: authz.RoleMaintainer},
			// A maintainer of project A alone.
			{Claim: authz.ClaimEmail, Value: "pm-a@example.com", Role: authz.RoleMaintainer, Project: projA},
			{Claim: authz.ClaimEmail, Value: "dev@example.com", Role: authz.RoleOperator},
			{Claim: authz.ClaimEmail, Value: "viewer@example.com", Role: authz.RoleViewer},
		},
		Runtime: staticRuntime{{Claim: authz.ClaimEmail, Value: "maint@example.com", Deny: true, Project: projB}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver

	now := time.Now()
	approved := pendingRequest("req_done", "dev@example.com", "project:"+projA, now)
	approved.State, approved.DecidedBy, approved.DecidedAt = secretbroker.RequestApproved, "admin@example.com", now.Add(-time.Minute)
	lapsed := pendingRequest("req_lapsed", "dev@example.com", "project:"+projA, now)
	lapsed.CreatedAt, lapsed.ExpiresAt = now.Add(-73*time.Hour), now.Add(-time.Hour)
	seedRequests(t, srv.WorkDir,
		pendingRequest("req_a", "dev@example.com", "project:"+projA, now),
		pendingRequest("req_b", "dev@example.com", "project:"+projB, now),
		pendingRequest("req_maint_own", "maint@example.com", "project:"+projA, now),
		pendingRequest("req_fleet", "dev@example.com", "project:*", now),
		approved, lapsed,
	)
	return approvalsFixture{srv: srv, idp: idp, hts: ts, ts: ts.URL, projA: projA, projB: projB}
}

// as signs a fresh client in as email.
func (f approvalsFixture) as(t *testing.T, email string) *http.Client {
	t.Helper()
	f.idp.email, f.idp.sub = email, "sub-"+strings.Split(email, "@")[0]
	c := jarClient(t)
	login(t, c, f.hts)
	return c
}

func inboxIDs(v approvalsView) []string {
	var ids []string
	for _, it := range v.Items {
		ids = append(ids, it.ID)
	}
	sort.Strings(ids)
	return ids
}

// TestApprovalsInboxListsOnlyWhatTheCallerMayDecide: an administrator sees
// every pending request but their own; a hub-wide maintainer denied project B
// sees neither B's request, nor their own, nor the fleet-wide ask only an
// administrator may approve; a maintainer of project A alone, a viewer and the
// requester see nothing to decide — and the count says the same as the list.
func TestApprovalsInboxListsOnlyWhatTheCallerMayDecide(t *testing.T) {
	f := newApprovalsFixture(t)
	for _, tc := range []struct {
		who  string
		want []string
	}{
		{"admin@example.com", []string{"req_a", "req_b", "req_fleet", "req_maint_own"}},
		{"maint@example.com", []string{"req_a"}},
		{"pm-a@example.com", nil},
		{"viewer@example.com", nil},
		{"dev@example.com", nil},
	} {
		t.Run(tc.who, func(t *testing.T) {
			c := f.as(t, tc.who)
			var v approvalsView
			if code := getJSONAs(t, c, f.ts+"/api/approvals", &v); code != http.StatusOK {
				t.Fatalf("GET /api/approvals = %d", code)
			}
			if got := inboxIDs(v); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("%s's inbox = %v, want %v", tc.who, got, tc.want)
			}
			var n approvalsCountView
			if code := getJSONAs(t, c, f.ts+"/api/approvals/count", &n); code != http.StatusOK {
				t.Fatalf("GET /api/approvals/count = %d", code)
			}
			if n.Count != len(tc.want) || n.GrantRequests != len(tc.want) || v.Count != len(tc.want) {
				t.Fatalf("%s's count = %+v (list count %d), want %d", tc.who, n, v.Count, len(tc.want))
			}
			for _, it := range v.Items {
				if it.Request == nil || it.Request.RequestedBy == tc.who || it.Deadline == "" {
					t.Errorf("%s was shown %+v: a request of their own, or one with no deadline", tc.who, it)
				}
				if !it.Request.Decidable {
					t.Errorf("%s's inbox item %s is not marked decidable", tc.who, it.ID)
				}
			}
			if len(tc.want) > 0 && n.NextDeadline == "" {
				t.Errorf("%s's count names no next deadline", tc.who)
			}
		})
	}
}

// TestApprovalsInboxShowsTheRequesterTheirAnswers: what a requester has asked
// for comes back to them — waiting, decided and lapsed — and the count names
// their pending ids, which is how the dashboard says "approved" when the
// broadcast arrives.
func TestApprovalsInboxShowsTheRequesterTheirAnswers(t *testing.T) {
	f := newApprovalsFixture(t)
	c := f.as(t, "dev@example.com")
	var v approvalsView
	getJSONAs(t, c, f.ts+"/api/approvals", &v)
	states := map[string]string{}
	for _, m := range v.Mine {
		states[m.ID] = m.State
	}
	for id, want := range map[string]string{
		"req_a": "pending", "req_b": "pending", "req_fleet": "pending", "req_done": "approved", "req_lapsed": "expired",
	} {
		if states[id] != want {
			t.Errorf("the requester sees %s as %q, want %q (all: %v)", id, states[id], want, states)
		}
	}
	if _, ok := states["req_maint_own"]; ok {
		t.Error("somebody else's request is listed among the caller's own")
	}
	var n approvalsCountView
	getJSONAs(t, c, f.ts+"/api/approvals/count", &n)
	sort.Strings(n.MinePending)
	if got := strings.Join(n.MinePending, ","); got != "req_a,req_b,req_fleet" {
		t.Fatalf("mine_pending = %q, want the three waiting requests", got)
	}
}

// TestApprovalsInboxAndDecisionRouteAgree: what the inbox withholds from a
// maintainer denied project B, the decision route refuses — with a 403 naming
// the scope, before the broker is reached — while a request the inbox lists
// gets past that check.
func TestApprovalsInboxAndDecisionRouteAgree(t *testing.T) {
	f := newApprovalsFixture(t)
	c := f.as(t, "maint@example.com")

	// The Secrets panel's list offers the same: no button on B's request.
	var list struct {
		Requests []requestView `json:"requests"`
	}
	if code := getJSONAs(t, c, f.ts+"/api/grant-requests?state=pending", &list); code != http.StatusOK {
		t.Fatalf("GET /api/grant-requests = %d", code)
	}
	decidable := map[string]bool{}
	for _, v := range list.Requests {
		decidable[v.ID] = v.Decidable
	}
	if !decidable["req_a"] || decidable["req_b"] {
		t.Fatalf("the request list marks decidable %v; want project A's request and not project B's", decidable)
	}

	status, body := do(t, c, http.MethodPost, f.ts+"/api/grant-requests/req_b/deny", `{"note":"no"}`)
	if status != http.StatusForbidden || !strings.Contains(body, "project=") {
		t.Fatalf("denying project B's request as a maintainer denied project B = %d %s, want a 403 naming the scope", status, body)
	}
	status, body = do(t, c, http.MethodPost, f.ts+"/api/grant-requests/req_a/deny", `{"note":"narrow it to acme/api"}`)
	if status != http.StatusOK {
		t.Fatalf("denying project A's request = %d %s, want 200", status, body)
	}
}

// TestApprovalsInboxListsWaitingTokensForAdministrators: a token minted with
// no role policy in force waits for an administrator holding its roles, so it
// is in their inbox — with its deadline — and in no maintainer's; approving it
// takes it off.
func TestApprovalsInboxListsWaitingTokensForAdministrators(t *testing.T) {
	f := newApprovalsFixture(t)
	mgr, err := f.srv.tokenManager()
	if err != nil {
		t.Fatal(err)
	}
	minted, err := mgr.Mint(apitoken.MintOptions{
		Name: "old-ci", Roles: []string{"operator"}, CreatedBy: "someone@example.com",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), MintedUnder: apitoken.MintedUnderNoPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := minted.Token.ID

	admin := f.as(t, "admin@example.com")
	var v approvalsView
	getJSONAs(t, admin, f.ts+"/api/approvals", &v)
	var tok *approvalItem
	for i := range v.Items {
		if v.Items[i].Kind == "api_token" {
			tok = &v.Items[i]
		}
	}
	if tok == nil || tok.ID != id || tok.Token == nil || tok.Token.Name != "old-ci" || tok.Deadline == "" {
		t.Fatalf("the administrator's inbox does not list the waiting token with its deadline: %+v", v.Items)
	}
	if v.APITokens != 1 {
		t.Fatalf("api_tokens = %d, want 1", v.APITokens)
	}
	raw, _ := json.Marshal(tok)
	if strings.Contains(string(raw), minted.Plaintext) || strings.Contains(string(raw), minted.Token.Hash) {
		t.Fatalf("the inbox item carries the token's secret: %s", raw)
	}

	maint := f.as(t, "maint@example.com")
	var m approvalsCountView
	getJSONAs(t, maint, f.ts+"/api/approvals/count", &m)
	if m.APITokens != 0 {
		t.Fatalf("a maintainer is offered %d token(s) to approve; approving takes token.admin", m.APITokens)
	}

	if status, body := do(t, admin, http.MethodPost, f.ts+"/api/tokens/"+id+"/approve", `{}`); status != http.StatusOK {
		t.Fatalf("approve = %d %s", status, body)
	}
	var after approvalsCountView
	getJSONAs(t, admin, f.ts+"/api/approvals/count", &after)
	if after.APITokens != 0 {
		t.Fatalf("an approved token is still counted: %+v", after)
	}
}

// TestApprovalsInboxNeedsTheBrokerKey: on a hub without the root key its
// secret broker needs, every route that decides a request answers 503, so the
// inbox and the badge offer none of the rows the control plane still holds.
func TestApprovalsInboxNeedsTheBrokerKey(t *testing.T) {
	f := newApprovalsFixture(t)
	admin := f.as(t, "admin@example.com")
	t.Setenv("CLOOP_SECRET_KEY", "")
	var n approvalsCountView
	if code := getJSONAs(t, admin, f.ts+"/api/approvals/count", &n); code != http.StatusOK {
		t.Fatalf("GET /api/approvals/count = %d", code)
	}
	if n.GrantRequests != 0 {
		t.Fatalf("a hub without its key counts %d request(s) nobody can decide", n.GrantRequests)
	}
}
