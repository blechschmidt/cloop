package ui

// End-to-end coverage for API-token authentication and the three endpoints
// (Task 20175).
//
// The property that matters most here is the one the unit tests cannot reach:
// that a scoped token is contained by the *route table*, not by anything this
// file asserts directly. Every check below goes through a real http.Handler
// with the real middleware chain, so a regression that moved the enforcement
// out of the gate would fail these even if pkg/apitoken still behaved.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

// tokenFixture is a two-project hub plus a helper for minting tokens straight
// into its store, bypassing HTTP — which is what a `cloop hub token create` on
// the box would do, and lets a test start from a credential that exists.
type tokenFixture struct {
	srv    *Server
	ts     *httptest.Server
	dirA   string
	dirB   string
	nameA  string
	nameB  string
	tokens *apitoken.Manager
}

func newTokenFixture(t *testing.T) *tokenFixture {
	t.Helper()

	dirA := setupProjectDir(t, "project A goal", nil)
	dirB := setupProjectDir(t, "project B goal", nil)

	srv := New(dirA, 0, "")
	srv.Projects = []string{dirA, dirB}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.closeTokenManager()
	})

	mgr, err := srv.tokenManager()
	if err != nil {
		t.Fatalf("tokenManager: %v", err)
	}

	f := &tokenFixture{srv: srv, ts: ts, dirA: dirA, dirB: dirB, tokens: mgr}
	// Resolve the registry names the hub actually reports, so scoping a token
	// uses the same identifier an operator would see in the UI.
	for i, e := range srv.allProjectEntries() {
		switch e.Path {
		case dirA:
			f.nameA = e.Name
		case dirB:
			f.nameB = e.Name
		}
		_ = i
	}
	return f
}

// idxOf returns the ?project_idx a caller with the unfiltered view would use
// for path.
func (f *tokenFixture) idxOf(t *testing.T, path string) int {
	t.Helper()
	for i, e := range f.srv.allProjectEntries() {
		if e.Path == path {
			return i
		}
	}
	t.Fatalf("project %s is not registered", path)
	return -1
}

func (f *tokenFixture) mint(t *testing.T, opts apitoken.MintOptions) string {
	t.Helper()
	if opts.Name == "" {
		opts.Name = "test-token"
	}
	minted, err := f.tokens.Mint(opts)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return minted.Plaintext
}

// do issues a request bearing tok and returns the status and body.
func (f *tokenFixture) do(t *testing.T, tok, method, path, body string) (int, string) {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req, err := http.NewRequest(method, f.ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil || len(buf) > 1<<20 {
			break
		}
	}
	return resp.StatusCode, string(buf)
}

// ---------------------------------------------------------------------------
// authentication
// ---------------------------------------------------------------------------

// TestValidTokenAuthenticates is the baseline: a token good enough to read.
func TestValidTokenAuthenticates(t *testing.T) {
	f := newTokenFixture(t)
	tok := f.mint(t, apitoken.MintOptions{Roles: []string{"viewer"}})

	code, body := f.do(t, tok, http.MethodGet, "/api/state", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/state with a viewer token = %d, want 200\nbody: %s", code, body)
	}
}

func TestInvalidTokensAreRejected(t *testing.T) {
	f := newTokenFixture(t)
	good := f.mint(t, apitoken.MintOptions{Roles: []string{"viewer"}})
	id, secret, ok := apitoken.Parse(good)
	if !ok {
		t.Fatal("minted token does not parse")
	}

	revoked := f.mint(t, apitoken.MintOptions{Name: "revoked", Roles: []string{"viewer"}})
	rid, _, _ := apitoken.Parse(revoked)
	if err := f.tokens.Revoke(rid); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	expired := f.mint(t, apitoken.MintOptions{
		Name: "expiring", Roles: []string{"viewer"},
		ExpiresAt: time.Now().Add(50 * time.Millisecond),
	})
	time.Sleep(80 * time.Millisecond)

	cases := map[string]string{
		"garbage":       apitoken.Prefix + "not-a-token",
		"wrong secret":  apitoken.Prefix + id + "_" + strings.Repeat("0", len(secret)),
		"unknown id":    apitoken.Prefix + strings.Repeat("a", len(id)) + "_" + secret,
		"revoked token": revoked,
		"expired token": expired,
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			code, body := f.do(t, tok, http.MethodGet, "/api/state", "")
			if code != http.StatusUnauthorized {
				t.Fatalf("= %d, want 401\nbody: %s", code, body)
			}
			// Every rejection must look identical from outside: the reason
			// goes to the audit trail, not to the caller.
			if strings.Contains(strings.ToLower(body), "revoked") ||
				strings.Contains(strings.ToLower(body), "expired") {
				t.Errorf("401 body leaks why the token failed: %s", body)
			}
		})
	}
}

// TestTokenRolesAreEnforcedOnAHubWithoutOIDC is the regression that matters
// most for single-tenant deployments: with OIDC off the route gate normally
// short-circuits to "allow everything", and a viewer token must not inherit
// that.
func TestTokenRolesAreEnforcedOnAHubWithoutOIDC(t *testing.T) {
	f := newTokenFixture(t)
	if f.srv.authzActive() {
		t.Fatal("fixture precondition: this hub should have RBAC inactive (no OIDC)")
	}
	viewer := f.mint(t, apitoken.MintOptions{Roles: []string{"viewer"}})

	// A viewer may read.
	if code, body := f.do(t, viewer, http.MethodGet, "/api/state", ""); code != http.StatusOK {
		t.Fatalf("viewer GET /api/state = %d, want 200\nbody: %s", code, body)
	}
	// But must not start a run, mutate tasks, or touch the token store.
	denied := []struct{ method, path, body string }{
		{http.MethodPost, "/api/run", `{}`},
		{http.MethodPost, "/api/tasks", `{"title":"x"}`},
		{http.MethodGet, "/api/tokens", ""},
		{http.MethodPost, "/api/tokens", `{"name":"x","roles":["admin"]}`},
		{http.MethodGet, "/api/secrets", ""},
		{http.MethodPost, "/api/executors/enroll", `{}`},
	}
	for _, tc := range denied {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			code, body := f.do(t, viewer, tc.method, tc.path, tc.body)
			if code != http.StatusForbidden {
				t.Fatalf("= %d, want 403 — a viewer token inherited more than its role\nbody: %s", code, body)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// project scope — the containment property
// ---------------------------------------------------------------------------

// TestProjectScopedTokenCannotReachAnotherProject is the headline assertion:
// a token scoped to project A gets 403/404 on project B, on both read and
// mutate, whether it addresses B by index or falls through to it.
func TestProjectScopedTokenCannotReachAnotherProject(t *testing.T) {
	f := newTokenFixture(t)
	if f.nameA == "" || f.nameB == "" {
		t.Fatalf("fixture precondition: both projects need registry names (got %q, %q)", f.nameA, f.nameB)
	}
	// An *admin* token deliberately: the scope must contain it regardless of
	// how strong its roles are.
	tok := f.mint(t, apitoken.MintOptions{
		Name: "scoped-to-A", Roles: []string{"admin"}, ProjectScope: []string{f.nameA},
	})

	idxA := f.idxOf(t, f.dirA)
	idxB := f.idxOf(t, f.dirB)
	if idxA == idxB {
		t.Fatal("fixture precondition: the two projects must occupy distinct indices")
	}

	// The visible list is filtered, so B has no index this token can name.
	code, body := f.do(t, tok, http.MethodGet, "/api/projects", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/projects = %d, want 200\nbody: %s", code, body)
	}
	if strings.Contains(body, f.dirB) {
		t.Errorf("the project list disclosed the out-of-scope project %q:\n%s", f.dirB, body)
	}
	if !strings.Contains(body, f.dirA) {
		t.Errorf("the project list omitted the in-scope project %q:\n%s", f.dirA, body)
	}

	// Addressing B by the index it occupies in the *unfiltered* registry must
	// not resolve. The index space is per-identity, so this is either out of
	// range (404) or resolves to an in-scope project — never to B.
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/state?project_idx=" + strconv.Itoa(idxB), ""},
		{http.MethodGet, "/api/tasks?project_idx=" + strconv.Itoa(idxB), ""},
		{http.MethodPost, "/api/tasks?project_idx=" + strconv.Itoa(idxB), `{"title":"pwn"}`},
		{http.MethodPost, "/api/run?project_idx=" + strconv.Itoa(idxB), `{}`},
	} {
		t.Run("idx "+tc.method+" "+tc.path, func(t *testing.T) {
			code, body := f.do(t, tok, tc.method, tc.path, tc.body)
			if code == http.StatusOK {
				// Only acceptable if the index landed on the in-scope project,
				// which the filtered list makes possible for index 0.
				if strings.Contains(body, f.dirB) || strings.Contains(body, "project B goal") {
					t.Fatalf("a token scoped to %q reached project B: %s", f.nameA, body)
				}
				return
			}
			if code != http.StatusNotFound && code != http.StatusForbidden {
				t.Fatalf("= %d, want 404 or 403\nbody: %s", code, body)
			}
		})
	}
}

// TestProjectScopedTokenIsDeniedTheHubsOwnWorkdir covers the fall-through
// case: with no ?project_idx, resolveWorkDir returns the server's own
// directory. A token scoped elsewhere must not silently inherit it.
func TestProjectScopedTokenIsDeniedTheHubsOwnWorkdir(t *testing.T) {
	f := newTokenFixture(t)
	// Scope to B only; the hub's own WorkDir is A.
	tok := f.mint(t, apitoken.MintOptions{
		Name: "scoped-to-B", Roles: []string{"admin"}, ProjectScope: []string{f.nameB},
	})

	code, body := f.do(t, tok, http.MethodGet, "/api/state", "")
	if code != http.StatusNotFound && code != http.StatusForbidden {
		t.Fatalf("unscoped GET /api/state with a B-scoped token = %d, want 404/403\nbody: %s", code, body)
	}
	if strings.Contains(body, "project A goal") {
		t.Error("the response disclosed the out-of-scope project's state")
	}
}

// TestUnscopedTokenSeesEveryProject is the control for the test above: the
// filtering must be caused by the scope, not by the token mechanism.
func TestUnscopedTokenSeesEveryProject(t *testing.T) {
	f := newTokenFixture(t)
	tok := f.mint(t, apitoken.MintOptions{Name: "unscoped", Roles: []string{"viewer"}})

	code, body := f.do(t, tok, http.MethodGet, "/api/projects", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/projects = %d, want 200\nbody: %s", code, body)
	}
	for _, want := range []string{f.dirA, f.dirB} {
		if !strings.Contains(body, want) {
			t.Errorf("an unscoped token could not see %q:\n%s", want, body)
		}
	}
}

// ---------------------------------------------------------------------------
// the endpoints
// ---------------------------------------------------------------------------

func TestTokenCreateReturnsThePlaintextExactlyOnce(t *testing.T) {
	f := newTokenFixture(t)
	admin := f.mint(t, apitoken.MintOptions{Name: "bootstrap", Roles: []string{"admin"}})

	code, body := f.do(t, admin, http.MethodPost, "/api/tokens",
		`{"name":"ci","roles":["operator"],"expires_in_days":30}`)
	if code != http.StatusOK {
		t.Fatalf("POST /api/tokens = %d, want 200\nbody: %s", code, body)
	}
	var created struct {
		Token struct {
			ID     string `json:"id"`
			Prefix string `json:"prefix"`
		} `json:"token"`
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("decode create response: %v\nbody: %s", err, body)
	}
	if created.Plaintext == "" {
		t.Fatal("create returned no plaintext — the credential would be unusable")
	}
	// It works.
	if code, b := f.do(t, created.Plaintext, http.MethodGet, "/api/state", ""); code != http.StatusOK {
		t.Fatalf("the freshly minted token does not authenticate: %d\nbody: %s", code, b)
	}

	// And it is never shown again, in any field of any later response.
	_, listBody := f.do(t, admin, http.MethodGet, "/api/tokens", "")
	_, secret, _ := apitoken.Parse(created.Plaintext)
	if strings.Contains(listBody, created.Plaintext) || strings.Contains(listBody, secret) {
		t.Fatalf("GET /api/tokens disclosed a token secret:\n%s", listBody)
	}
	if !strings.Contains(listBody, created.Token.Prefix) {
		t.Errorf("the list should identify the token by its prefix %q:\n%s", created.Token.Prefix, listBody)
	}
	// No hash either — it is not a secret, but it is a verifier, and nothing
	// in the panel needs it.
	if strings.Contains(listBody, "hmac-sha256$") {
		t.Errorf("GET /api/tokens disclosed the stored hash:\n%s", listBody)
	}
}

// TestTokenCreateRefusesRolesTheCallerLacks is the privilege-escalation gate
// as reached over HTTP.
func TestTokenCreateRefusesRolesTheCallerLacks(t *testing.T) {
	f := newTokenFixture(t)
	// A token that holds token.admin via the admin role would be able to mint
	// anything, so use a *narrower* minter: operator plus token.admin is not
	// expressible in the ladder, which is precisely the point — only admin
	// reaches the create endpoint, and admin may mint admin. The meaningful
	// HTTP case is therefore the reverse: a non-admin is refused at the gate.
	operator := f.mint(t, apitoken.MintOptions{Name: "op", Roles: []string{"operator"}})
	maintainer := f.mint(t, apitoken.MintOptions{Name: "maint", Roles: []string{"maintainer"}})

	for name, tok := range map[string]string{"operator": operator, "maintainer": maintainer} {
		t.Run(name+" cannot mint", func(t *testing.T) {
			code, body := f.do(t, tok, http.MethodPost, "/api/tokens",
				`{"name":"escalate","roles":["admin"]}`)
			if code != http.StatusForbidden {
				t.Fatalf("= %d, want 403 — %s minted an admin token\nbody: %s", code, name, body)
			}
		})
	}
}

// TestScopedAdminTokenCannotWidenItsOwnScope closes the second escalation
// path: an admin token limited to one project must not mint an unscoped one.
func TestScopedAdminTokenCannotWidenItsOwnScope(t *testing.T) {
	f := newTokenFixture(t)
	scoped := f.mint(t, apitoken.MintOptions{
		Name: "scoped-admin", Roles: []string{"admin"}, ProjectScope: []string{f.nameA},
	})

	// Widening to every project: refused.
	code, body := f.do(t, scoped, http.MethodPost, "/api/tokens",
		`{"name":"wide","roles":["operator"]}`)
	if code != http.StatusForbidden {
		t.Fatalf("minting an unscoped token from a scoped one = %d, want 403\nbody: %s", code, body)
	}
	// Naming another project: refused.
	code, body = f.do(t, scoped, http.MethodPost, "/api/tokens",
		`{"name":"other","roles":["operator"],"project_scope":["`+f.nameB+`"]}`)
	if code != http.StatusForbidden {
		t.Fatalf("minting a token for another project = %d, want 403\nbody: %s", code, body)
	}
	// Staying inside its own scope: allowed.
	code, body = f.do(t, scoped, http.MethodPost, "/api/tokens",
		`{"name":"narrower","roles":["viewer"],"project_scope":["`+f.nameA+`"]}`)
	if code != http.StatusOK {
		t.Fatalf("minting within its own scope = %d, want 200\nbody: %s", code, body)
	}
}

func TestTokenRevokeEndpoint(t *testing.T) {
	f := newTokenFixture(t)
	admin := f.mint(t, apitoken.MintOptions{Name: "bootstrap", Roles: []string{"admin"}})

	victim := f.mint(t, apitoken.MintOptions{Name: "ci", Roles: []string{"viewer"}})
	vid, _, _ := apitoken.Parse(victim)

	if code, _ := f.do(t, victim, http.MethodGet, "/api/state", ""); code != http.StatusOK {
		t.Fatal("precondition: the victim token should work before revocation")
	}
	if code, body := f.do(t, admin, http.MethodDelete, "/api/tokens/"+vid, ""); code != http.StatusOK {
		t.Fatalf("DELETE /api/tokens/%s = %d, want 200\nbody: %s", vid, code, body)
	}
	// Revocation takes effect on the very next request — no cache to expire.
	if code, body := f.do(t, victim, http.MethodGet, "/api/state", ""); code != http.StatusUnauthorized {
		t.Fatalf("after revocation = %d, want 401\nbody: %s", code, body)
	}
	// The admin token is untouched: revocation is per credential.
	if code, _ := f.do(t, admin, http.MethodGet, "/api/tokens", ""); code != http.StatusOK {
		t.Error("revoking one token disturbed another")
	}
	// Unknown id.
	if code, _ := f.do(t, admin, http.MethodDelete, "/api/tokens/deadbeefdeadbeef", ""); code != http.StatusNotFound {
		t.Errorf("revoking an unknown id = %d, want 404", code)
	}
}

// TestTokenAuthDoesNotDisturbTheStaticToken checks the migration path: a hub
// running both keeps accepting the static credential.
func TestTokenAuthDoesNotDisturbTheStaticToken(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "static-secret")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.closeTokenManager() })

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/state", nil)
	req.Header.Set("Authorization", "Bearer static-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the static token stopped working: %d", resp.StatusCode)
	}
}

// TestNonTokenCredentialsFallThrough verifies the classification: a bearer
// value that is not shaped like a PAT must not be routed into the token store
// at all, or every static-token deployment would pay a database read per
// request.
func TestNonTokenCredentialsFallThrough(t *testing.T) {
	f := newTokenFixture(t)
	// This hub has no static token, so an unrelated bearer is simply ignored
	// and the request proceeds as an anonymous local one.
	if code, body := f.do(t, "", http.MethodGet, "/api/state", ""); code != http.StatusOK {
		t.Fatalf("anonymous GET = %d, want 200 on an open hub\nbody: %s", code, body)
	}
	code, body := f.do(t, "some-other-scheme-token", http.MethodGet, "/api/state", "")
	if code != http.StatusOK {
		t.Fatalf("a non-PAT bearer on an open hub = %d, want 200\nbody: %s", code, body)
	}
}

// compile-time guard: the fixture depends on the registry shape.
var _ = multiui.ProjectEntry{}
