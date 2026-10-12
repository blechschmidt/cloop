package kubeguard

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// writeEverything is the widest grant a session can carry: every verb, every
// namespace, every resource. Whatever it still refuses is refused by rule.
func writeEverything() Policy {
	p := Policy{Verbs: allVerbs()}
	p.Normalize()
	return p
}

// TestTokenRequestIsRefusedUnderEveryGrant is Task 20416's guard rule: a
// ServiceAccount shared for self-renewal may create its own token, so through
// the monitor the TokenRequest API must be closed to the sandbox whatever the
// grant allows — or a workload could mint itself a credential the monitor
// never sees again. Checked at the proxy, against an upstream that records
// what reached it: a 403 that still forwarded would pass a policy-only test.
func TestTokenRequestIsRefusedUnderEveryGrant(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy Policy
	}{
		{"read-only", ReadOnlyPolicy()},
		{"write everywhere", writeEverything()},
		{"write in the ServiceAccount's own namespace", func() Policy {
			p := writeEverything()
			p.Namespaces = []string{"cloop-shares"}
			p.Resources = []string{"serviceaccounts"}
			p.Normalize()
			return p
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.policy)
			for _, req := range []struct{ method, path string }{
				// kubectl create token cloop-aks-dev-3f9c2a1b -n cloop-shares
				{http.MethodPost, "/api/v1/namespaces/cloop-shares/serviceaccounts/cloop-aks-dev-3f9c2a1b/token"},
				{http.MethodPost, "/api/v1/namespaces/cloop-shares/serviceaccounts/default/token"},
				// Path tricks resolve to the same request.
				{http.MethodPost, "/api/v1/namespaces/cloop-shares/serviceaccounts/x/../cloop-aks-dev-3f9c2a1b/token"},
				{http.MethodPost, "//api/v1//namespaces/cloop-shares/serviceaccounts/cloop-aks-dev-3f9c2a1b/token/"},
				{http.MethodGet, "/api/v1/namespaces/cloop-shares/serviceaccounts/cloop-aks-dev-3f9c2a1b/token"},
				{http.MethodPut, "/api/v1/namespaces/cloop-shares/serviceaccounts/cloop-aks-dev-3f9c2a1b/token"},
			} {
				resp := h.do(t, req.method, req.path, strings.NewReader(`{"spec":{"expirationSeconds":3600}}`),
					"Content-Type", "application/json")
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("%s %s: status %d, want 403", req.method, req.path, resp.StatusCode)
				}
				st := decodeStatus(t, resp)
				if msg, _ := st["message"].(string); !strings.Contains(msg, "serviceaccounts/token") ||
					!strings.Contains(msg, "every grant") {
					t.Errorf("%s %s: message %q does not say why", req.method, req.path, msg)
				}
				if ev := h.lastDenial(t); ev.Reason != DenyDangerousSubresource {
					t.Errorf("%s %s: denial reason %q", req.method, req.path, ev.Reason)
				}
			}
			if n := h.api.count(); n != 0 {
				t.Fatalf("the cluster saw %d token requests; a refused TokenRequest must never be forwarded", n)
			}
			// The same session still reads and, where its grant says so,
			// writes ServiceAccounts themselves: only the credential is closed.
			resp := h.do(t, http.MethodGet, "/api/v1/namespaces/cloop-shares/serviceaccounts", nil)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("listing serviceaccounts: status %d", resp.StatusCode)
			}
		})
	}
}

func TestParseMarksTheTokenSubresourceAsMintingACredential(t *testing.T) {
	r := mustParse(t, http.MethodPost, "/api/v1/namespaces/a/serviceaccounts/sa/token")
	if !r.MintsCredential() || !r.Dangerous() {
		t.Fatalf("serviceaccounts/token: %+v", r)
	}
	for _, path := range []string{
		"/api/v1/namespaces/a/serviceaccounts/sa",           // the ServiceAccount object
		"/api/v1/namespaces/a/serviceaccounts",              // the collection
		"/api/v1/namespaces/a/secrets/token",                // a Secret named token
		"/apis/apps/v1/namespaces/a/deployments/token",      // a Deployment named token
		"/api/v1/namespaces/a/pods/token/log",               // a Pod named token
		"/apis/example.com/v1/namespaces/a/widgets/w/scale", // another subresource
	} {
		if mustParse(t, http.MethodPost, path).MintsCredential() {
			t.Errorf("%s is marked as minting a credential", path)
		}
	}
}

// TestUpdateUpstreamSwapsTheCredentialOfALiveSession: after the hub renews a
// shared ServiceAccount's token, a session already handed to a sandbox
// presents the new token from its next request, with no new session and no
// change to anything else.
func TestUpdateUpstreamSwapsTheCredentialOfALiveSession(t *testing.T) {
	h := newHarness(t, ReadOnlyPolicy())
	h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil)
	if got := h.api.last().Header.Get("Authorization"); got != "Bearer "+testClusterToken {
		t.Fatalf("before: upstream Authorization = %q", got)
	}

	renewed := strings.Replace(string(testInsecureKubeconfig(h.api.srv.URL)), testClusterToken, "renewed-cluster-token", 1)
	changed, err := h.reg.UpdateUpstream(h.sess.ID, []byte(renewed))
	if err != nil || !changed {
		t.Fatalf("UpdateUpstream = %v, %v", changed, err)
	}
	h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil)
	if got := h.api.last().Header.Get("Authorization"); got != "Bearer renewed-cluster-token" {
		t.Fatalf("after: upstream Authorization = %q, want the renewed token", got)
	}
	// The same token again is no change.
	if changed, err := h.reg.UpdateUpstream(h.sess.ID, []byte(renewed)); err != nil || changed {
		t.Errorf("an unchanged credential: %v, %v", changed, err)
	}

	// Anything but the credential changing is a different grant, not a renewal.
	moved := strings.Replace(renewed, h.api.srv.URL, "https://elsewhere.example.com", 1)
	if _, err := h.reg.UpdateUpstream(h.sess.ID, []byte(moved)); err == nil || !strings.Contains(err.Error(), "elsewhere") {
		t.Errorf("a kubeconfig naming another server: err = %v", err)
	}
	trusting := strings.Replace(renewed, "    insecure-skip-tls-verify: true\n", "", 1)
	if _, err := h.reg.UpdateUpstream(h.sess.ID, []byte(trusting)); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Errorf("a kubeconfig with other TLS trust: err = %v", err)
	}
	plugin := strings.Replace(renewed, "    token: renewed-cluster-token", "    exec: {command: kubelogin}", 1)
	if _, err := h.reg.UpdateUpstream(h.sess.ID, []byte(plugin)); err == nil || !strings.Contains(err.Error(), "exec") {
		t.Errorf("a kubeconfig with an exec plugin: err = %v", err)
	}
	h.do(t, http.MethodGet, "/api/v1/namespaces/app/pods", nil)
	if got := h.api.last().Header.Get("Authorization"); got != "Bearer renewed-cluster-token" {
		t.Errorf("a refused update changed the credential: %q", got)
	}

	if _, err := h.reg.UpdateUpstream("no-such-session", []byte(renewed)); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("an unknown session: err = %v", err)
	}
	h.reg.Close(h.sess.ID, "lease released")
	if _, err := h.reg.UpdateUpstream(h.sess.ID, []byte(renewed)); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("a closed session: err = %v", err)
	}
}
