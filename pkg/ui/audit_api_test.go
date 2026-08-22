package ui

// Tests for the RBAC-gated Audit endpoints (Task 20167).
//
// The security property under test is narrow and important: reading the audit
// trail requires admin, and every role below it — including maintainer, which
// *can* broker credentials to executors — is refused. A maintainer who could
// read the trail could watch their own oversight, so that row of the table is
// the one that matters most.

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/state"

	_ "modernc.org/sqlite"
)

// newAuditFixture builds an OIDC-enabled dashboard with one signed-in client
// per role. It declares its own policy rather than reusing rbacPolicy()
// because the maintainer tier — absent there — is the interesting case here:
// maintainer can broker credentials, and must still not be able to read the
// record of having done so.
func newAuditFixture(t *testing.T) (*Server, string, map[string]*http.Client) {
	t.Helper()

	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "readers", Role: authz.RoleViewer},
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
			{Claim: authz.ClaimGroup, Value: "leads", Role: authz.RoleMaintainer},
			{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	loginAs := func(groups []string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}

	clients := map[string]*http.Client{
		"viewer":     loginAs([]string{"readers"}),
		"operator":   loginAs([]string{"engineers"}),
		"maintainer": loginAs([]string{"leads"}),
		"admin":      loginAs([]string{"owners"}),
		"unmapped":   loginAs([]string{"contractors-with-no-binding"}),
	}
	return srv, ts.URL, clients
}

// getFull issues a GET and reads the entire body, unlike the package's `do`
// helper which caps at one 4 KiB Read — an audit page is bigger than that.
func getFull(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}

// seedAudit appends deterministic rows to the server's own journal.
func seedAudit(t *testing.T, workDir string) {
	t.Helper()
	log, err := eventlog.Open(workDir)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer log.Close()

	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	rows := []eventlog.AuditEvent{
		{Timestamp: base, Actor: "alice@seeded.test", EventType: "executor.enroll", EntityType: "executor", EntityID: "edge-1", Payload: `{"name":"edge one"}`},
		{Timestamp: base.Add(time.Minute), Actor: "bob@seeded.test", EventType: "secret.lease", EntityType: "secret", EntityID: "gh-pat", Payload: `{"decision":"allow"}`},
		{Timestamp: base.Add(2 * time.Minute), Actor: "alice@seeded.test", EventType: "task.delete", EntityType: "task", EntityID: "7", Payload: `{"id":7}`},
	}
	for i := range rows {
		ev := rows[i]
		if err := log.Append(&ev); err != nil {
			t.Fatalf("append seed row %d: %v", i, err)
		}
	}
}

// TestAuditReadRequiresAdmin is the core authorization assertion.
func TestAuditReadRequiresAdmin(t *testing.T) {
	srv, base, clients := newAuditFixture(t)
	seedAudit(t, srv.WorkDir)

	for _, path := range []string{"/api/audit", "/api/audit/verify"} {
		for _, role := range []string{"viewer", "operator", "maintainer", "unmapped"} {
			t.Run(role+" denied "+path, func(t *testing.T) {
				code, body := getFull(t, clients[role], base+path)
				if code != http.StatusForbidden {
					t.Fatalf("%s GET %s = %d, want 403\nbody: %s", role, path, code, body)
				}
				var env struct {
					Error struct {
						Code    string         `json:"code"`
						Details map[string]any `json:"details"`
					} `json:"error"`
				}
				if err := json.Unmarshal([]byte(body), &env); err != nil {
					t.Fatalf("403 body is not the structured error shape: %v\nbody: %s", err, body)
				}
				if env.Error.Code != "FORBIDDEN" {
					t.Errorf("error.code = %q, want FORBIDDEN", env.Error.Code)
				}
				if got := env.Error.Details["required_permission"]; got != string(authz.PermAuditRead) {
					t.Errorf("required_permission = %v, want %q", got, authz.PermAuditRead)
				}
				// A denial must not leak the trail it refused to show.
				if strings.Contains(body, "edge-1") || strings.Contains(body, "secret.lease") {
					t.Errorf("denial body leaked audit content: %s", body)
				}
			})
		}

		t.Run("admin allowed "+path, func(t *testing.T) {
			code, body := getFull(t, clients["admin"], base+path)
			if code != http.StatusOK {
				t.Fatalf("admin GET %s = %d, want 200\nbody: %s", path, code, body)
			}
		})
	}
}

// TestMaintainerCannotReadTrailDespiteBrokeringSecrets states the intent
// behind the role placement explicitly, so a future widening of the
// maintainer bundle trips a test that explains why it should not.
func TestMaintainerCannotReadTrailDespiteBrokeringSecrets(t *testing.T) {
	perms := authz.RoleMaintainer.Permissions()
	has := func(p authz.Permission) bool {
		for _, got := range perms {
			if got == p {
				return true
			}
		}
		return false
	}
	if !has(authz.PermSecretGrant) {
		t.Fatal("precondition changed: maintainer no longer grants secrets")
	}
	if has(authz.PermAuditRead) {
		t.Error("maintainer holds audit.read — the role that brokers credentials " +
			"must not also be able to read the record of having done so")
	}
	if !contains(authz.RoleAdmin.Permissions(), authz.PermAuditRead) {
		t.Error("admin must hold audit.read, or nobody can read the trail")
	}
}

func contains(perms []authz.Permission, want authz.Permission) bool {
	for _, p := range perms {
		if p == want {
			return true
		}
	}
	return false
}

// TestAuditListFiltersServerSide asserts the filters narrow the result set in
// SQLite rather than being ignored and left to the browser.
func TestAuditListFiltersServerSide(t *testing.T) {
	srv, base, clients := newAuditFixture(t)
	seedAudit(t, srv.WorkDir)
	admin := clients["admin"]

	decode := func(t *testing.T, url string) auditListResponse {
		t.Helper()
		code, body := getFull(t, admin, url)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d\nbody: %s", url, code, body)
		}
		var resp auditListResponse
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatalf("decode %s: %v\nbody: %s", url, err, body)
		}
		return resp
	}

	all := decode(t, base+"/api/audit")
	if len(all.Events) < 3 {
		t.Fatalf("expected at least the 3 seeded rows, got %d", len(all.Events))
	}
	// Default ordering is newest-first: the panel answers "what just
	// happened", so page one must hold the most recent rows.
	if len(all.Events) >= 2 && all.Events[0].ID < all.Events[1].ID {
		t.Errorf("default order is ascending; want descending (got ids %d then %d)",
			all.Events[0].ID, all.Events[1].ID)
	}

	byActor := decode(t, base+"/api/audit?actor=alice@seeded.test")
	if len(byActor.Events) != 2 {
		t.Errorf("actor filter returned %d rows, want 2", len(byActor.Events))
	}
	for _, ev := range byActor.Events {
		if ev.Actor != "alice@seeded.test" {
			t.Errorf("actor filter leaked a row from %q", ev.Actor)
		}
	}
	if byActor.Total != 2 {
		t.Errorf("total = %d, want the filtered count 2", byActor.Total)
	}
	if byActor.All < 3 {
		t.Errorf("all = %d, want the unfiltered table count", byActor.All)
	}

	byType := decode(t, base+"/api/audit?event_type=secret.lease")
	if len(byType.Events) != 1 || byType.Events[0].EntityID != "gh-pat" {
		t.Errorf("event_type filter = %+v, want the single secret.lease row", byType.Events)
	}

	byEntity := decode(t, base+"/api/audit?entity_type=executor&entity_id=edge-1")
	if len(byEntity.Events) != 1 {
		t.Errorf("entity filter returned %d rows, want 1", len(byEntity.Events))
	}

	// Paging: one row per page, and has_more set until the last.
	page := decode(t, base+"/api/audit?limit=1")
	if len(page.Events) != 1 {
		t.Errorf("limit=1 returned %d rows", len(page.Events))
	}
	if !page.HasMore {
		t.Error("has_more should be true when more rows match than were returned")
	}
	if page.Limit != 1 {
		t.Errorf("echoed limit = %d, want 1", page.Limit)
	}

	// The facets that drive the filter dropdowns must be present.
	if len(all.Actors) == 0 || len(all.EntityTypes) == 0 {
		t.Errorf("filter facets missing: actors=%v entity_types=%v", all.Actors, all.EntityTypes)
	}

	// A search term that matches nothing returns an empty list, not an error.
	none := decode(t, base+"/api/audit?q=no-such-payload-anywhere")
	if len(none.Events) != 0 {
		t.Errorf("impossible search returned %d rows", len(none.Events))
	}
}

func TestAuditListRejectsMalformedParams(t *testing.T) {
	_, base, clients := newAuditFixture(t)
	admin := clients["admin"]

	for _, q := range []string{
		"?limit=abc",
		"?offset=not-a-number",
		"?since=yesterday-ish",
		"?until=%3F%3F%3F",
		"?since=2026-03-02&until=2026-03-01", // inverted window
	} {
		t.Run(q, func(t *testing.T) {
			code, body := getFull(t, admin, base+"/api/audit"+q)
			if code != http.StatusBadRequest {
				t.Errorf("GET /api/audit%s = %d, want 400\nbody: %s", q, code, body)
			}
		})
	}
}

func TestAuditListClampsOversizedLimit(t *testing.T) {
	srv, base, clients := newAuditFixture(t)
	seedAudit(t, srv.WorkDir)

	code, body := getFull(t, clients["admin"], base+"/api/audit?limit=999999")
	if code != http.StatusOK {
		t.Fatalf("= %d, want 200\nbody: %s", code, body)
	}
	var resp auditListResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Limit != auditPageMax {
		t.Errorf("limit = %d, want it clamped to %d", resp.Limit, auditPageMax)
	}
}

func TestAuditVerifyReportsIntactChain(t *testing.T) {
	srv, base, clients := newAuditFixture(t)
	seedAudit(t, srv.WorkDir)

	code, body := getFull(t, clients["admin"], base+"/api/audit/verify")
	if code != http.StatusOK {
		t.Fatalf("= %d, want 200\nbody: %s", code, body)
	}
	var resp auditVerifyResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, body)
	}
	if !resp.OK {
		t.Fatalf("chain reported broken on an untouched log: %s", resp.Reason)
	}
	if resp.Total == 0 {
		t.Error("total = 0, want the seeded rows counted")
	}
	if resp.CheckedAt == "" {
		t.Error("checked_at missing — the badge needs to say when it last ran")
	}
}

// TestAuditVerifyReportsBrokenChainAsSuccess pins the decision that a broken
// chain is a 200 with ok=false, not a 500: the badge must be able to render
// red, which it cannot do if the endpoint looks like it is down.
func TestAuditVerifyReportsBrokenChainAsSuccess(t *testing.T) {
	srv, base, clients := newAuditFixture(t)
	seedAudit(t, srv.WorkDir)
	tamperAuditRow(t, srv.WorkDir)

	code, body := getFull(t, clients["admin"], base+"/api/audit/verify")
	if code != http.StatusOK {
		t.Fatalf("= %d, want 200 even for a broken chain\nbody: %s", code, body)
	}
	var resp auditVerifyResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, body)
	}
	if resp.OK {
		t.Fatal("tampered chain verified clean")
	}
	if resp.BreakAtID == 0 {
		t.Error("break_at_id = 0, want the offending row named")
	}
	if resp.ExpectedHash == "" || resp.ActualHash == "" {
		t.Errorf("expected/actual hashes missing (%q / %q) — the operator needs both to act",
			resp.ExpectedHash, resp.ActualHash)
	}
	if resp.ExpectedHash == resp.ActualHash {
		t.Error("expected and actual hashes are equal on a reported break")
	}
}

// tamperAuditRow edits a row behind cloop's back — opening the SQLite file
// directly rather than going through any cloop API, which is exactly the
// threat the hash chain exists to detect.
func tamperAuditRow(t *testing.T, workDir string) {
	t.Helper()

	db, err := sql.Open("sqlite", state.DBPath(workDir))
	if err != nil {
		t.Fatalf("open sqlite directly: %v", err)
	}
	defer db.Close()

	var id int64
	if err := db.QueryRow(`SELECT id FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("read chain tip: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE audit_events SET payload = ? WHERE id = ?`,
		`{"tampered":true}`, id,
	); err != nil {
		t.Fatalf("tamper: %v", err)
	}
}

// TestAuditRoutesDeclareAuditReadPermission guards the wiring: a future edit
// that re-registers these routes under a weaker permission should fail here
// rather than in production.
func TestAuditRoutesDeclareAuditReadPermission(t *testing.T) {
	srv, _, _ := newAuditFixture(t)

	want := map[string]bool{"GET /api/audit": false, "GET /api/audit/verify": false}
	for _, rs := range srv.routeTable() {
		if _, tracked := want[rs.Pattern]; !tracked {
			continue
		}
		want[rs.Pattern] = true
		if rs.Perm != authz.PermAuditRead {
			t.Errorf("%s declares %q, want %q", rs.Pattern, rs.Perm, authz.PermAuditRead)
		}
		if rs.Scope != scopeGlobal {
			t.Errorf("%s is not global-scoped; the trail spans projects", rs.Pattern)
		}
		if len(rs.MethodPerms) != 0 {
			t.Errorf("%s overrides its permission per method, which would open a read path", rs.Pattern)
		}
	}
	for pattern, found := range want {
		if !found {
			t.Errorf("route %s is not registered", pattern)
		}
	}
}

// TestAuditEndpointsRejectNonGET keeps the read-only contract explicit.
func TestAuditEndpointsRejectNonGET(t *testing.T) {
	_, base, clients := newAuditFixture(t)
	admin := clients["admin"]

	for _, path := range []string{"/api/audit", "/api/audit/verify"} {
		for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
			req, err := http.NewRequest(method, base+path, strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := admin.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Errorf("%s %s = 200; the audit trail must be read-only over HTTP\nbody: %s",
					method, path, string(body))
			}
		}
	}
}
