package ui

// Sudo mode on a control plane two hub processes serve (Task 20448).
//
// When the person behind a session last signed in is stored on the durable
// session row, so the member a privileged request lands on reads the same
// answer as the member that took the sign-in. A process-local copy would let a
// load balancer that sends the confirm-it's-you callback to one member and
// the retried request to another refuse the request the person just signed in
// for — or, the other way round, keep honouring a sign-in another member never
// saw.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestClusterMemberHonoursAFreshSignInMadeOnAnother: a stale session is
// refused on member B; its owner confirms it is them through B, the provider's
// callback landing on A (the load balancer's choice) and forwarded back to B,
// which holds the login; and member A, which never cached the fresh session,
// lets its privileged request through on what the shared row says.
func TestClusterMemberHonoursAFreshSignInMadeOnAnother(t *testing.T) {
	_, a, b := clusterPair(t)
	idp := newUIFakeIdP(t)
	clk := &clusterRenewClock{}
	withClusterOIDC(t, a, idp, a.ts.URL, clk)
	withClusterOIDC(t, b, idp, a.ts.URL, clk)

	// The provider's own sign-in is three hours old: the dashboard sign-in it
	// answers is silent, so the session is not recent.
	idp.setSignedInAt(time.Now().Add(-3 * time.Hour))
	c := jarClient(t)
	req, _ := http.NewRequest(http.MethodGet, b.ts.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in chain ended with %d at %s", resp.StatusCode, resp.Request.URL)
	}

	// A privileged action, on either member: refused for want of a recent
	// sign-in. (On a hub with sign-on and no role policy every identity holds
	// token.admin, so the only thing between it and the handler is this.)
	for _, m := range []*clusterMember{a, b} {
		if status, code := clusterPrivileged(t, c, m); status != http.StatusUnauthorized || code != "REAUTH_REQUIRED" {
			t.Fatalf("a stale session's privileged request on %s = %d %s, want 401 REAUTH_REQUIRED", m.ts.URL, status, code)
		}
	}

	res, err := c.Get(b.ts.URL + "/auth/login?reauth=window")
	if err != nil {
		t.Fatalf("confirm it's you: %v", err)
	}
	doc, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(doc), "granted") {
		t.Fatalf("the confirm-it's-you sign-in ended with %d:\n%s", res.StatusCode, doc)
	}
	if n := idp.loginPromptCount(); n != 1 {
		t.Fatalf("the provider saw %d prompt=login requests, want 1", n)
	}

	// Both members now let it through: B took the sign-in, A reads the row.
	for _, m := range []*clusterMember{a, b} {
		if status, code := clusterPrivileged(t, c, m); status != http.StatusNotFound {
			t.Fatalf("after signing in again, the privileged request on %s = %d %s, want the handler's 404", m.ts.URL, status, code)
		}
	}
}

// clusterPrivileged revokes an API token that does not exist, as c, on member
// m: past the gate, the handler answers 404; refused by it, the gate's code.
func clusterPrivileged(t *testing.T, c *http.Client, m *clusterMember) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, m.ts.URL+"/api/tokens/tok_doesnotexist", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("DELETE on %s: %v", m.ts.URL, err)
	}
	defer resp.Body.Close()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &env)
	return resp.StatusCode, env.Error.Code
}
