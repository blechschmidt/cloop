package ui

// API tokens minted while no role policy was in force (Task 20422).
//
// A token minted from the dashboard has no owner: its authority is its stamped
// roles, bounded at mint by the minter's own. With single sign-on and no role
// policy every signed-in identity holds every role, so any of them could mint
// an admin token — and it stayed admin, for up to a year, once the policy was
// switched on. These tests drive that whole story through a real hub: the mint
// records what governed it, the policy suspends the token, the enforce dialog
// names it beforehand, and only an administrator holding its roles, under the
// policy, brings it back.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
)

const (
	approvalMaintainer = "maint@example.com"
	approvalUser       = "mallory@example.com"
)

// approvalJSON sends a request with body and decodes the JSON answer.
func (f *credFixture) approvalJSON(t *testing.T, c *http.Client, method, path, body string, hdr http.Header) (int, map[string]any) {
	t.Helper()
	if body == "" {
		body = "{}"
	}
	req, err := http.NewRequest(method, f.ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// enforcePolicy puts a deny-by-default role policy in force, as the restart
// after Enforce deny-by-default does: root administers, the maintainer
// maintains, everybody else gets nothing.
func (f *credFixture) enforcePolicy(t *testing.T) {
	t.Helper()
	r, err := authz.New(authz.Config{
		DefaultRole: authz.RoleNone,
		AdminEmails: []string{rootEmail},
		Bindings: []authz.Binding{
			{Claim: authz.ClaimEmail, Value: approvalMaintainer, Role: authz.RoleMaintainer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !authz.Enforced(true, r) {
		t.Fatal("the fixture's policy is not one authz.Enforced recognises")
	}
	f.srv.Authz = r
}

// tokenRow finds one token in GET /api/tokens.
func tokenRow(t *testing.T, list map[string]any, id string) map[string]any {
	t.Helper()
	rows, _ := list["tokens"].([]any)
	for _, r := range rows {
		if m, ok := r.(map[string]any); ok && m["id"] == id {
			return m
		}
	}
	t.Fatalf("token %s is not listed: %v", id, list)
	return nil
}

// TestTokens_APolicyEnforcedAfterTheMintSuspendsTheToken is the whole defect:
// with single sign-on and no policy, somebody who will hold nothing under the
// policy mints an admin token from the dashboard; the policy is enforced; the
// token is refused until an administrator approves it, and works again after.
func TestTokens_APolicyEnforcedAfterTheMintSuspendsTheToken(t *testing.T) {
	f := newCredFixture(t)
	if f.srv.authzActive() {
		t.Fatal("the fixture hub enforces a policy already")
	}
	mallory := f.signIn(t, approvalUser, "sub-mallory")
	status, out := f.approvalJSON(t, mallory, "POST", "/api/tokens",
		`{"name":"mallory-admin","roles":["admin"],"expires_in_days":365}`, nil)
	if status != http.StatusOK {
		t.Fatalf("a signed-in user minting an admin token with no policy in force: %d %v", status, out)
	}
	tok, _ := out["token"].(map[string]any)
	plaintext, _ := out["plaintext"].(string)
	id, _ := tok["id"].(string)
	if tok["minted_under"] != apitoken.MintedUnderNoPolicy || tok["awaits_approval"] != true || tok["status"] != "active" {
		t.Fatalf("the mint recorded %v", tok)
	}
	if status := f.call(t, http.DefaultClient, "GET", "/api/audit", bearerHeader(plaintext)); status != http.StatusOK {
		t.Fatalf("the admin token before any policy: %d", status)
	}

	// Before the restart, the enforce dialog names it.
	_, view := f.approvalJSON(t, f.root, "GET", "/api/config/oidc", "", nil)
	rbac, _ := view["rbac"].(map[string]any)
	waiting, _ := rbac["awaiting_approval"].([]any)
	if len(waiting) != 1 || waiting[0].(map[string]any)["id"] != id || waiting[0].(map[string]any)["created_by"] == "" {
		t.Fatalf("the enforce dialog's view names %v, want the one token", rbac["awaiting_approval"])
	}

	f.enforcePolicy(t)

	// Suspended: refused with the remedy, listed as such, its refusal audited.
	status, refused := f.approvalJSON(t, http.DefaultClient, "GET", "/api/audit", "", bearerHeader(plaintext))
	if status != http.StatusForbidden || !strings.Contains(approvalErrorText(refused), "approve") {
		t.Fatalf("the admin token under the policy: %d %v, want 403 naming the approval", status, refused)
	}
	_, list := f.approvalJSON(t, f.root, "GET", "/api/tokens", "", nil)
	if row := tokenRow(t, list, id); row["status"] != "suspended" {
		t.Fatalf("listed as %v, want suspended", row["status"])
	}
	if !auditHasTokenRow(t, f, "api_token.auth_failed", "awaiting_approval") {
		t.Fatal("the refusal was not audited as awaiting_approval")
	}

	// Its minter cannot clear it — they hold nothing now — nor can a
	// maintainer, who does not hold admin.
	if status, out := f.approvalJSON(t, mallory, "POST", "/api/tokens/"+id+"/approve", "", nil); status != http.StatusForbidden {
		t.Fatalf("the minter approving their own token: %d %v", status, out)
	}
	maint := f.signIn(t, approvalMaintainer, "sub-maint")
	if status, out := f.approvalJSON(t, maint, "POST", "/api/tokens/"+id+"/approve", "", nil); status != http.StatusForbidden {
		t.Fatalf("a maintainer approving an admin token: %d %v", status, out)
	}

	// An administrator who holds admin approves it, once.
	status, approved := f.approvalJSON(t, f.root, "POST", "/api/tokens/"+id+"/approve", "", nil)
	if status != http.StatusOK || approved["status"] != "active" || approved["approved_by"] == "" {
		t.Fatalf("root approving: %d %v", status, approved)
	}
	if status := f.call(t, http.DefaultClient, "GET", "/api/audit", bearerHeader(plaintext)); status != http.StatusOK {
		t.Fatalf("the approved token: %d", status)
	}
	if status, out := f.approvalJSON(t, f.root, "POST", "/api/tokens/"+id+"/approve", "", nil); status != http.StatusConflict {
		t.Fatalf("a second approval: %d %v, want 409", status, out)
	}
	if !auditHasTokenRow(t, f, "api_token.approved", "") {
		t.Fatal("the approval was not audited")
	}
	_, view = f.approvalJSON(t, f.root, "GET", "/api/config/oidc", "", nil)
	if rbac, _ := view["rbac"].(map[string]any); rbac["awaiting_approval"] != nil {
		t.Fatalf("an approved token is still named: %v", rbac["awaiting_approval"])
	}
}

// TestTokens_WhatIsNeverSuspended: a token minted under the policy, one minted
// at the control plane, and one that acts for an owner — whose authority the
// policy decides — all keep working when a policy is enforced. A token minted
// before the hub recorded how is suspended: nobody can say.
func TestTokens_WhatIsNeverSuspended(t *testing.T) {
	f := newCredFixture(t)
	mint := func(opts apitoken.MintOptions) string {
		t.Helper()
		opts.Name, opts.Roles, opts.ExpiresAt = "t-"+opts.MintedUnder, []string{"viewer"}, f.clk.now().Add(time.Hour)
		m, err := f.mgr.Mint(opts)
		if err != nil {
			t.Fatal(err)
		}
		return m.Plaintext
	}
	operator := mint(apitoken.MintOptions{MintedUnder: apitoken.MintedByOperator})
	owned := mint(apitoken.MintOptions{MintedUnder: apitoken.MintedUnderNoPolicy,
		Owner: &apitoken.Owner{Email: approvalMaintainer, Sub: "sub-maint"}})
	unknown := mint(apitoken.MintOptions{})

	f.enforcePolicy(t)
	status, out := f.approvalJSON(t, f.root, "POST", "/api/tokens",
		`{"name":"under-policy","roles":["viewer"],"expires_in_days":1}`, nil)
	if status != http.StatusOK {
		t.Fatalf("minting under the policy: %d %v", status, out)
	}
	if tok := out["token"].(map[string]any); tok["minted_under"] != apitoken.MintedUnderPolicy || tok["awaits_approval"] == true {
		t.Fatalf("a token minted under the policy recorded %v", tok)
	}
	underPolicy := out["plaintext"].(string)

	for name, want := range map[string]struct {
		cred string
		code int
	}{
		"minted under the policy":       {underPolicy, http.StatusOK},
		"minted at the control plane":   {operator, http.StatusOK},
		"acting for an owner":           {owned, http.StatusOK},
		"minted before it was recorded": {unknown, http.StatusForbidden},
	} {
		if status := f.call(t, http.DefaultClient, "GET", "/api/projects", bearerHeader(want.cred)); status != want.code {
			t.Errorf("%s: %d, want %d", name, status, want.code)
		}
	}
}

// TestTokens_NoApprovalWithoutAPolicy: on a hub that enforces no policy every
// signed-in identity holds token.admin, so an approval there would be anyone's
// — the minter's own included — and is refused.
func TestTokens_NoApprovalWithoutAPolicy(t *testing.T) {
	f := newCredFixture(t)
	m, err := f.mgr.Mint(apitoken.MintOptions{Name: "early", Roles: []string{"admin"},
		MintedUnder: apitoken.MintedUnderNoPolicy, ExpiresAt: f.clk.now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if status, out := f.approvalJSON(t, f.root, "POST", "/api/tokens/"+m.Token.ID+"/approve", "", nil); status != http.StatusConflict {
		t.Fatalf("approving with no policy in force: %d %v, want 409", status, out)
	}
	got, err := f.mgr.Get(m.Token.ID)
	if err != nil || !got.AwaitsApproval() {
		t.Fatalf("the refused approval was recorded: %+v %v", got, err)
	}
}

// approvalErrorText reads either of the hub's error dialects.
func approvalErrorText(body map[string]any) string {
	switch e := body["error"].(type) {
	case string:
		return e
	case map[string]any:
		s, _ := e["message"].(string)
		return s
	}
	return ""
}

// auditHasTokenRow reports whether the hub's trail holds an action row whose
// payload carries reason (any, when "").
func auditHasTokenRow(t *testing.T, f *credFixture, action, reason string) bool {
	t.Helper()
	db, closer, err := f.srv.openControlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	for _, r := range scimAuditRows(t, db, action) {
		if reason == "" || r["reason"] == reason {
			return true
		}
	}
	return false
}
