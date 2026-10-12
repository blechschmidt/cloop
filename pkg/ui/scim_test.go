package ui

// SCIM 2.0 provisioning through a real hub (Task 20415).
//
// pkg/provision proves what each request means. What only a running hub can
// show is here: that deactivating an account at the identity provider ends
// what that person holds open on the hub — the dashboard socket, the API
// token, the sandbox lease — within the one request that says so; that the
// SCIM credential opens /scim/v2 and nothing else, and nothing else opens it;
// and that a provisioned group's removal demotes on the very next request.
//
// None of these starts a run.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/provision"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// scimFixture is credFixture — single sign-on, a static token, the hooks
// `cloop ui` installs, root signed in — with the runtime role store and the
// SCIM directory wired into the resolver as `cloop ui` wires them, and a SCIM
// credential minted.
type scimFixture struct {
	*credFixture
	token  string
	credID string
}

func newSCIMFixture(t *testing.T, policy authz.Config) *scimFixture {
	t.Helper()
	return newSCIMFixtureWith(t, policy, config.SCIMConfig{})
}

// newSCIMFixtureWith is newSCIMFixture with a provisioning policy.
func newSCIMFixtureWith(t *testing.T, policy authz.Config, cfg config.SCIMConfig) *scimFixture {
	t.Helper()
	f := newCredFixture(t)
	roles, err := f.srv.OpenRoleStore()
	if err != nil {
		t.Fatalf("OpenRoleStore: %v", err)
	}
	t.Cleanup(f.srv.closeRoleStore)
	dir, err := f.srv.OpenSCIM(cfg)
	if err != nil {
		t.Fatalf("OpenSCIM: %v", err)
	}
	t.Cleanup(f.srv.closeSCIM)
	policy.Runtime, policy.Directory = roles, dir
	if len(policy.AdminEmails) == 0 {
		policy.AdminEmails = []string{rootEmail}
	}
	r, err := authz.New(policy)
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	f.srv.Authz = r

	db, closer, err := f.srv.openControlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	minted, err := provision.MintCredential(db, "entra", provision.AdminContext{Actor: rootEmail, Reason: "tests"}, time.Now())
	if err != nil {
		t.Fatalf("MintCredential: %v", err)
	}
	return &scimFixture{credFixture: f, token: minted.Plaintext, credID: minted.Row.ID}
}

// scimDo sends one SCIM request presenting hdr, and returns the status and
// the decoded body.
func (f *scimFixture) scimDo(t *testing.T, method, path, body string, hdr http.Header) (int, map[string]any, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, resp.Header
}

// scim sends one SCIM request with the fixture's credential.
func (f *scimFixture) scim(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	status, out, _ := f.scimDo(t, method, path, body, bearerHeader(f.token))
	return status, out
}

// provisionAlice creates alice at the identity provider and returns her id.
func (f *scimFixture) provisionAlice(t *testing.T) string {
	t.Helper()
	status, out := f.scim(t, "POST", "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"alice@example.com","externalId":"a1","active":true,
		"emails":[{"primary":true,"type":"work","value":"alice@example.com"}]}`)
	if status != http.StatusCreated {
		t.Fatalf("provisioning alice: %d %v", status, out)
	}
	return out["id"].(string)
}

// ownedProject registers a project alice owns, in this test binary's isolated
// registry, for as long as the test runs.
func ownedProject(t *testing.T, owner string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "alice-project")
	if err := multiui.AddPathsOwned([]string{dir}, owner); err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(dir)
	t.Cleanup(func() { _ = multiui.RemovePath(abs) })
	return abs
}

// TestSCIM_DeactivationEndsSocketTokenAndLeaseInOneRequest is the end-to-end
// property: one PATCH from the identity provider — Entra's own, with the
// string "False" — and alice's open dashboard WebSocket, her API token and the
// sandbox lease held for her project have all ended. No administrator, no
// second request, no refresh interval.
func TestSCIM_DeactivationEndsSocketTokenAndLeaseInOneRequest(t *testing.T) {
	f := newSCIMFixture(t, authz.Config{})
	id := f.provisionAlice(t)

	// What alice holds open: a signed-in dashboard with its socket...
	alice := f.signIn(t, aliceEmail, "sub-alice")
	ls := f.openWS(t, "/api/ws?scope=global", alice, nil)
	waitMember(t, "the socket to register", func() bool { return len(f.srv.openStreamCredentials()) == 1 })
	f.srv.deliverToAll(wsMessage{Type: "members_update", Data: json.RawMessage(`{}`)})
	ls.awaitMessage(t, "members_update")
	// ...an API token minted for her...
	tok, err := f.mgr.Mint(apitoken.MintOptions{Name: "alice-ci", Roles: []string{"operator"}, CreatedBy: rootEmail,
		Owner: &apitoken.Owner{Sub: "sub-alice", Email: aliceEmail}, ExpiresAt: f.clk.now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if status := f.call(t, http.DefaultClient, "GET", "/api/me", bearerHeader(tok.Plaintext)); status != http.StatusOK {
		t.Fatalf("her token does not work to begin with: %d", status)
	}
	// ...and a lease a sandbox holds for her project.
	project := ownedProject(t, aliceEmail)
	sl := &secretLease{lease: &secretbroker.Lease{ID: "lease-alice-scim", ExecutorID: "edge-1", ProjectID: project,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Minute)}, expiry: time.Now().Add(15 * time.Minute)}
	liveLeases.add(sl)
	t.Cleanup(func() { liveLeases.remove("lease-alice-scim") })

	// The one request.
	status, out := f.scim(t, "PATCH", "/scim/v2/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
	if status != http.StatusOK || out["active"] != false {
		t.Fatalf("the deactivation answered %d %v", status, out)
	}

	// The lease is gone by the time the response arrived.
	if leaseIsRegistered("lease-alice-scim") {
		t.Fatal("the sandbox lease outlived the deactivation")
	}
	// The token is refused at its next use.
	if status := f.call(t, http.DefaultClient, "GET", "/api/me", bearerHeader(tok.Plaintext)); status != http.StatusUnauthorized {
		t.Fatalf("her API token answered %d after the deactivation", status)
	}
	// The socket was told and closed — pushed, not left for a keepalive.
	got := ls.awaitEnd(t, 5*time.Second)
	if got.told == nil || got.told["reason"] != "session_ended" {
		t.Fatalf("the socket ended as %+v", got)
	}
	// Her session is gone, and signing in again gets her nothing.
	if status := f.call(t, alice, "GET", "/api/me", nil); status == http.StatusOK {
		t.Fatal("her browser session survived")
	}
	again := f.signIn(t, aliceEmail, "sub-alice")
	if status := f.call(t, again, "GET", "/api/projects", nil); status == http.StatusOK {
		t.Fatal("a fresh sign-in after the deactivation was served")
	}
}

// TestSCIM_TheCredentialOpensSCIMAndNothingElse: the provider's credential is
// not an API token, and no credential of the hub's is a SCIM credential.
func TestSCIM_TheCredentialOpensSCIMAndNothingElse(t *testing.T) {
	f := newSCIMFixture(t, authz.Config{})

	if status, _ := f.scim(t, "GET", "/scim/v2/Users", ""); status != http.StatusOK {
		t.Fatalf("the SCIM credential on /scim/v2: %d", status)
	}
	// Not on the dashboard's API.
	for _, path := range []string{"/api/me", "/api/projects", "/api/scim"} {
		if status := f.call(t, http.DefaultClient, "GET", path, bearerHeader(f.token)); status != http.StatusUnauthorized {
			t.Errorf("the SCIM credential on %s: %d, want 401", path, status)
		}
	}
	// Nothing else opens /scim/v2: an API token, the static token, a session,
	// nothing at all. Each case starts with a clean failure count: the
	// lockout is tested on its own below.
	resetLockout := func() {
		f.srv.authMu.Lock()
		f.srv.authFails = map[string]*authFailEntry{}
		f.srv.authMu.Unlock()
	}
	pat := f.mintToken(t)
	for name, hdr := range map[string]http.Header{
		"api token":    bearerHeader(pat.Plaintext),
		"static token": bearerHeader(credStaticToken),
		"nothing":      nil,
		"query token":  nil,
	} {
		resetLockout()
		path := "/scim/v2/Users"
		if name == "query token" {
			path += "?token=" + f.token
		}
		status, out, h := f.scimDo(t, "GET", path, "", hdr)
		if status != http.StatusUnauthorized {
			t.Errorf("%s on /scim/v2: %d, want 401", name, status)
		}
		if out["schemas"] == nil || out["status"] != "401" {
			t.Errorf("%s: the refusal is not a SCIM error: %v", name, out)
		}
		if !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: no WWW-Authenticate challenge", name)
		}
	}
	// Wrong credentials count toward the address's SCIM lockout, which turns
	// the next wrong one away with 429 — and never the right one (Task 20422,
	// TestSCIM_ALockedOutAddressStillAdmitsTheProvider).
	resetLockout()
	for i := 0; i < authMaxFailures; i++ {
		f.scimDo(t, "GET", "/scim/v2/Users", "", bearerHeader(pat.Plaintext))
	}
	if status, _, _ := f.scimDo(t, "GET", "/scim/v2/Users", "", bearerHeader(pat.Plaintext)); status != http.StatusTooManyRequests {
		t.Fatalf("after %d wrong credentials from one address: %d, want 429", authMaxFailures, status)
	}
	if status, _ := f.scim(t, "GET", "/scim/v2/Users", ""); status != http.StatusOK {
		t.Fatalf("the right credential from the locked-out address: %d, want 200", status)
	}
	resetLockout()
	// The root's browser session does not open it either.
	req, _ := http.NewRequest("GET", f.ts.URL+"/scim/v2/Users", nil)
	resp, err := f.root.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a session cookie on /scim/v2: %d", resp.StatusCode)
	}
	// A revoked credential stops at the next request.
	db, closer, _ := f.srv.openControlPlaneDB()
	if _, _, err := provision.RevokeCredential(db, "entra", provision.AdminContext{Actor: rootEmail}, time.Now()); err != nil {
		t.Fatal(err)
	}
	closer()
	if status, out := f.scim(t, "GET", "/scim/v2/Users", ""); status != http.StatusUnauthorized {
		t.Fatalf("a revoked credential: %d %v", status, out)
	}
	// Unknown paths under /scim/v2 are SCIM errors, never the dashboard.
	status, out, h := f.scimDo(t, "GET", "/scim/v2/Bulk", "", nil)
	if status != http.StatusUnauthorized || !strings.Contains(h.Get("Content-Type"), "scim+json") {
		t.Fatalf("an unknown SCIM path without a credential: %d %v", status, out)
	}
}

// scimWrongCredential is shaped like a SCIM credential and is nobody's.
var scimWrongCredential = provision.CredentialPrefix + strings.Repeat("a", 16) + "_" + strings.Repeat("b", 64)

// TestSCIM_ALockedOutAddressStillAdmitsTheProvider is the defect Task 20422
// closed: SCIM answered 429 before it verified the bearer, so an address
// locked by five wrong guesses — the identity provider's shared egress, or,
// behind a proxy the hub does not trust, everybody's — kept provisioning out,
// and every suspension the provider sent with it. The credential is verified
// first now: the right one is served from a locked address, and serving it
// neither counts nor lifts the lockout the wrong ones earned.
func TestSCIM_ALockedOutAddressStillAdmitsTheProvider(t *testing.T) {
	f := newSCIMFixture(t, authz.Config{})
	wrong := bearerHeader(scimWrongCredential)
	for i := 0; i < authMaxFailures; i++ {
		if status, _, _ := f.scimDo(t, "GET", "/scim/v2/Users", "", wrong); status != http.StatusUnauthorized {
			t.Fatalf("wrong credential %d: %d, want 401", i+1, status)
		}
	}
	status, _, h := f.scimDo(t, "GET", "/scim/v2/Users", "", wrong)
	if status != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Fatalf("a wrong credential past the threshold: %d (Retry-After %q), want 429 with one", status, h.Get("Retry-After"))
	}

	// The provider, from the same address, provisions and deactivates.
	id := f.provisionAlice(t)
	status, out := f.scim(t, "PATCH", "/scim/v2/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"Replace","path":"active","value":false}]}`)
	if status != http.StatusOK || out["active"] != false {
		t.Fatalf("the provider's deactivation from a locked address answered %d %v", status, out)
	}
	// The lockout still holds for the guesses.
	if status, _, _ := f.scimDo(t, "GET", "/scim/v2/Users", "", wrong); status != http.StatusTooManyRequests {
		t.Fatalf("the provider's requests lifted the lockout: a wrong credential got %d", status)
	}
	db, closer, _ := f.srv.openControlPlaneDB()
	defer closer()
	var lockedOut int
	for _, r := range scimAuditRows(t, db, "scim.request_refused") {
		if r["reason"] == "locked_out" {
			lockedOut++
			if r["client"] != "" && r["client"] != nil {
				t.Errorf("a locked-out refusal names client %v: only a verified credential has one", r["client"])
			}
		}
	}
	if lockedOut != 2 {
		t.Fatalf("%d locked_out refusals recorded, want the 2 wrong credentials past the threshold", lockedOut)
	}
}

// TestSCIM_FailuresKeepTheirOwnBucket: SCIM's lockout and the dashboard's
// sign-in lockout count apart (Task 20422). Wrong static tokens from the
// provider's address neither lock SCIM nor refuse its credential, and a SCIM
// client failing beside the dashboard locks nobody out of it.
func TestSCIM_FailuresKeepTheirOwnBucket(t *testing.T) {
	f := newSCIMFixture(t, authz.Config{})
	pat := f.mintToken(t)
	reset := func() {
		f.srv.authMu.Lock()
		f.srv.authFails = map[string]*authFailEntry{}
		f.srv.authMu.Unlock()
	}

	// The dashboard's bucket, filled with wrong static tokens.
	for i := 0; i < authMaxFailures; i++ {
		f.call(t, http.DefaultClient, "GET", "/api/projects", bearerHeader("not-the-static-token"))
	}
	if status := f.call(t, http.DefaultClient, "GET", "/api/projects", bearerHeader(pat.Plaintext)); status != http.StatusTooManyRequests {
		t.Fatalf("the dashboard's lockout did not engage: an API token got %d", status)
	}
	if status, _, _ := f.scimDo(t, "GET", "/scim/v2/Users", "", bearerHeader(scimWrongCredential)); status != http.StatusUnauthorized {
		t.Fatalf("a wrong SCIM credential under the dashboard's lockout: %d, want 401 — SCIM counts its own", status)
	}
	if status, _ := f.scim(t, "GET", "/scim/v2/Users", ""); status != http.StatusOK {
		t.Fatalf("the provider under the dashboard's lockout: %d", status)
	}

	// SCIM's bucket, filled, leaves the dashboard alone.
	reset()
	for i := 0; i <= authMaxFailures; i++ {
		f.scimDo(t, "GET", "/scim/v2/Users", "", bearerHeader(scimWrongCredential))
	}
	if status, _, _ := f.scimDo(t, "GET", "/scim/v2/Users", "", bearerHeader(scimWrongCredential)); status != http.StatusTooManyRequests {
		t.Fatalf("SCIM's own lockout did not engage: %d", status)
	}
	if status := f.call(t, http.DefaultClient, "GET", "/api/projects", bearerHeader(pat.Plaintext)); status != http.StatusOK {
		t.Fatalf("an API token beside a failing SCIM client: %d, want 200", status)
	}
	if status := f.call(t, http.DefaultClient, "GET", "/api/projects", bearerHeader(credStaticToken)); status != http.StatusOK {
		t.Fatalf("the static token beside a failing SCIM client: %d, want 200", status)
	}
}

// TestSCIM_UnknownPathsAreSCIMErrors: everything under /scim/v2 answers in
// SCIM's error dialect.
func TestSCIM_UnknownPathsAreSCIMErrors(t *testing.T) {
	f := newSCIMFixture(t, authz.Config{})
	for _, path := range []string{"/scim/v2/Bulk", "/scim/v2/Me", "/scim/v2/Users/"} {
		status, out := f.scim(t, "GET", path, "")
		if status != http.StatusNotFound || out["status"] != "404" {
			t.Errorf("%s: %d %v", path, status, out)
		}
	}
	status, out := f.scim(t, "GET", "/scim/v2/ServiceProviderConfig", "")
	if status != http.StatusOK || out["patch"] == nil {
		t.Fatalf("ServiceProviderConfig: %d %v", status, out)
	}
	if !strings.HasPrefix(out["meta"].(map[string]any)["location"].(string), f.ts.URL+"/scim/v2/") {
		t.Errorf("locations are not absolute: %v", out["meta"])
	}
}

// TestSCIM_RefusesWithoutSingleSignOn: provisioning matches users to the
// identities that sign in, so a hub without single sign-on has none.
func TestSCIM_RefusesWithoutSingleSignOn(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	req, _ := http.NewRequest("GET", ts.URL+"/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer "+provision.CredentialPrefix+strings.Repeat("a", 16)+"_"+strings.Repeat("b", 64))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(resp.Header.Get("Content-Type"), "scim+json") {
		t.Fatalf("a hub without single sign-on: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

// TestSCIM_EachCredentialIsRateLimited: past its budget a credential is told
// to slow down, with Retry-After, and the refusal is audited.
func TestSCIM_EachCredentialIsRateLimited(t *testing.T) {
	f := newSCIMFixture(t, authz.Config{})
	f.srv.scim.mu.Lock()
	f.srv.scim.limiter = provision.NewRateLimiter(10)
	f.srv.scim.mu.Unlock()
	var limited http.Header
	for i := 0; i < 30; i++ {
		status, _, h := f.scimDo(t, "GET", "/scim/v2/ServiceProviderConfig", "", bearerHeader(f.token))
		if status == http.StatusTooManyRequests {
			limited = h
			break
		}
	}
	if limited == nil {
		t.Fatal("the credential was never limited")
	}
	if limited.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	db, closer, _ := f.srv.openControlPlaneDB()
	defer closer()
	rows := scimAuditRows(t, db, "scim.request_refused")
	found := false
	for _, r := range rows {
		if r["reason"] == "rate_limited" && r["client"] == "entra" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the rate-limited request was not audited: %v", rows)
	}
}

// TestSCIM_GroupRemovalDemotesOnTheNextRequest: a role mapping grants a
// provisioned group admin; the identity provider removes alice, and her very
// next request is refused — no claim refresh in between.
func TestSCIM_GroupRemovalDemotesOnTheNextRequest(t *testing.T) {
	f := newSCIMFixture(t, authz.Config{
		DefaultRole: authz.RoleViewer,
		Bindings:    []authz.Binding{{Claim: authz.ClaimSCIMGroup, Value: "cloop-admins", Role: authz.RoleAdmin}},
	})
	id := f.provisionAlice(t)
	status, g := f.scim(t, "POST", "/scim/v2/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName":"cloop-admins","members":[{"value":"`+id+`"}]}`)
	if status != http.StatusCreated {
		t.Fatalf("group: %d %v", status, g)
	}
	alice := f.signIn(t, aliceEmail, "sub-alice")
	if status := f.call(t, alice, "GET", "/api/audit", nil); status != http.StatusOK {
		t.Fatalf("a provisioned admin reading the audit trail: %d", status)
	}
	status, _ = f.scim(t, "PATCH", "/scim/v2/Groups/"+g["id"].(string),
		`{"Operations":[{"op":"remove","path":"members[value eq \"`+id+`\"]"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("removal: %d", status)
	}
	if status := f.call(t, alice, "GET", "/api/audit", nil); status != http.StatusForbidden {
		t.Fatalf("after the removal her next request answered %d, want 403", status)
	}
	// She is still a viewer: removal from a group is not a deactivation.
	if status := f.call(t, alice, "GET", "/api/me", nil); status != http.StatusOK {
		t.Fatalf("a demoted member's session: %d", status)
	}
}

// TestSCIM_SettingsAdministerTheCredential: mint, rotate and revoke from the
// dashboard, gated on user.manage, the secret returned once.
func TestSCIM_SettingsAdministerTheCredential(t *testing.T) {
	f := newSCIMFixture(t, authz.Config{DefaultRole: authz.RoleViewer})
	post := func(c *http.Client, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest("POST", f.ts.URL+path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	status, out := post(f.root, "/api/scim/credentials", `{"name":"okta"}`)
	if status != http.StatusOK {
		t.Fatalf("mint: %d %v", status, out)
	}
	token, _ := out["token"].(string)
	if !strings.HasPrefix(token, provision.CredentialPrefix) {
		t.Fatalf("mint returned no token: %v", out)
	}
	credID := out["credential"].(map[string]any)["id"].(string)
	if status, _, _ := f.scimDo(t, "GET", "/scim/v2/Users", "", bearerHeader(token)); status != http.StatusOK {
		t.Fatalf("the minted credential: %d", status)
	}
	// The status view never carries a secret.
	req, _ := http.NewRequest("GET", f.ts.URL+"/api/scim", nil)
	resp, err := f.root.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(raw), token[len(provision.CredentialPrefix)+17:]) ||
		strings.Contains(string(raw), "hmac-sha256") {
		t.Fatalf("GET /api/scim: %d %s", resp.StatusCode, raw)
	}
	// Rotation without grace ends the old secret.
	status, out = post(f.root, "/api/scim/credentials/"+credID+"/rotate", `{"grace_minutes":0,"reason":"rotation"}`)
	if status != http.StatusOK {
		t.Fatalf("rotate: %d %v", status, out)
	}
	if status, _, _ := f.scimDo(t, "GET", "/scim/v2/Users", "", bearerHeader(token)); status != http.StatusUnauthorized {
		t.Fatalf("the rotated-out secret: %d", status)
	}
	status, _ = post(f.root, "/api/scim/credentials/"+credID+"/revoke", `{"reason":"done"}`)
	if status != http.StatusOK {
		t.Fatalf("revoke: %d", status)
	}
	// A non-admin may do none of it.
	bob := f.signIn(t, "bob@example.com", "sub-bob")
	if status, _ := post(bob, "/api/scim/credentials", `{"name":"bobs"}`); status != http.StatusForbidden &&
		status != http.StatusUnauthorized {
		t.Fatalf("a non-admin minted a SCIM credential: %d", status)
	}
}

// TestSCIM_APreRBACHubKeepsTheCredentialToAdministrators: a hub with single
// sign-on and no role policy grants every signed-in user user.manage — and
// still not this.
func TestSCIM_APreRBACHubKeepsTheCredentialToAdministrators(t *testing.T) {
	f := newSCIMFixture(t, authz.Config{})
	bob := f.signIn(t, "bob@example.com", "sub-bob")
	for _, path := range []string{"/api/scim/credentials", "/api/users/holds"} {
		if status := f.call(t, bob, "POST", path, nil); status != http.StatusForbidden {
			t.Errorf("a signed-in non-admin on a pre-RBAC hub, POST %s: %d, want 403", path, status)
		}
	}
	if status := f.call(t, f.root, "GET", "/api/scim", nil); status != http.StatusOK {
		t.Fatalf("the administrator: %d", status)
	}
}

// scimAuditRows decodes the payloads of every control-plane row of one action.
func scimAuditRows(t *testing.T, db *statedb.DB, action string) []map[string]any {
	t.Helper()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: action, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]map[string]any, 0, len(evs))
	for _, ev := range evs {
		var p map[string]any
		_ = json.Unmarshal([]byte(ev.Payload), &p)
		if p == nil {
			p = map[string]any{}
		}
		p["_actor"] = ev.Actor
		out = append(out, p)
	}
	return out
}
