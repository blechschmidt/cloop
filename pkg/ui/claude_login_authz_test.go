package ui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// claudeAuthMutatingRoutes are the four per-user Claude credential endpoints.
// Listed once: the defect applied to all of them, and a fix that reached only
// the one named in the bug report would leave the panel half working.
var claudeAuthMutatingRoutes = []string{
	"/api/claudecode/auth/login",
	"/api/claudecode/auth/login/code",
	"/api/claudecode/auth/login/cancel",
	"/api/claudecode/auth/logout",
}

// newStaleClaimHub builds an OIDC hub whose claim-freshness bound is tight
// enough that every session's claims are already stale, and which retains no
// refresh token to re-check them with.
//
// This reproduces the live :8888 hub rather than inventing a corner. That
// deployment runs OIDC with max_claim_age unset — so DefaultMaxClaimAge, five
// minutes — and its unit sets no CLOOP_SECRET_KEY, so no refresh token is ever
// sealed. Five minutes after signing in, every permission above the operator
// tier becomes permanently unexercisable, because there is nothing left to
// revalidate the claims with. A 1ns bound reaches that state deterministically
// without a clock hook, and the fake IdP issues no refresh token by default,
// which is the same condition the hub is in.
func newStaleClaimHub(t *testing.T, role authz.Role) (*Server, *httptest.Server) {
	t.Helper()

	// Host execution off, which is both what an enterprise hub runs with and
	// what keeps this test quick: these handlers otherwise shell out to
	// `claude auth login` and block for ~30s each waiting for an OAuth URL
	// that never arrives. denyHostSideEffect sits *inside* the handler, so a
	// request that reaches it has already cleared the authorization middleware
	// — which is the only thing these tests are about.
	prevHost := executor.SetAllowHostExecution(false)
	t.Cleanup(func() { executor.SetAllowHostExecution(prevHost) })

	idp := newUIFakeIdP(t)
	srv := New(setupProjectDir(t, cloopGoal, nil), 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:     true,
		Issuer:      idp.server.URL,
		ClientID:    "cloop-dashboard",
		RedirectURL: ts.URL + "/auth/callback",
		MaxClaimAge: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimEmail, Value: idp.email, Role: role},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	if srv.OIDC.MaxClaimAge() <= 0 {
		t.Fatal("test setup: the claim-freshness bound is disabled, so this proves nothing")
	}
	return srv, ts
}

// postAs performs a POST carrying c's session cookie and returns status+body.
func postAs(t *testing.T, c *http.Client, ts *httptest.Server, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}

// signedIn logs a fresh jar client into ts.
func signedIn(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	c := jarClient(t)
	login(t, c, ts)
	return c
}

// Signing in to one's own Claude account must not be gated on a hub-wide
// configuration permission.
//
// This is the defect behind "Sign in with Claude.ai returns [object Object]"
// on the :8888 hub. Since Task 20241 a Claude login is per-user: it writes to
// the caller's own CLAUDE_CONFIG_DIR and touches nothing another user can
// observe. The route's permission was never revisited when that changed, so it
// still demanded config.write — which sits above the operator tier, which is
// precisely the set pkg/authz requires recently-confirmed claims for. On a hub
// that retains no refresh token those claims can never be confirmed, so the
// call is refused for every role including admin, permanently.
//
// Asserted through the HTTP surface rather than against require() directly,
// because the bug was in the route table: a unit test of the checker would have
// passed throughout.
func TestClaudeLoginIsNotGatedOnHubConfigWrite(t *testing.T) {
	_, ts := newStaleClaimHub(t, authz.RoleAdmin)
	c := signedIn(t, ts)

	for _, path := range claudeAuthMutatingRoutes {
		status, body := postAs(t, c, ts, path, `{"code":"x"}`)
		if status == http.StatusForbidden {
			t.Errorf("POST %s: 403 for the hub's own admin — a per-user Claude "+
				"credential action is gated on a permission above the operator "+
				"tier, so it cannot be exercised on a hub that retains no "+
				"refresh token. Body: %s", path, body)
		}
		// Name the claim-freshness refusal specifically, so an unrelated future
		// 403 is not silently accepted as this one.
		if strings.Contains(body, "claims") && strings.Contains(body, "refresh token") {
			t.Errorf("POST %s: refused because claims could not be refreshed. Body: %s", path, body)
		}
	}
}

// An operator must be able to bring their own Claude account. On a multi-user
// hub the operator is the role that runs tasks, so an operator who cannot sign
// in to Claude is an operator whose tasks cannot use the claudecode provider at
// all — while the credential itself is theirs alone and confers nothing over
// the hub.
func TestClaudeLoginIsReachableByAnOperator(t *testing.T) {
	_, ts := newStaleClaimHub(t, authz.RoleOperator)
	c := signedIn(t, ts)

	for _, path := range claudeAuthMutatingRoutes {
		status, body := postAs(t, c, ts, path, `{"code":"x"}`)
		if status == http.StatusForbidden || status == http.StatusNotFound {
			t.Errorf("an operator cannot manage their own Claude credential: POST %s → %d %s",
				path, status, body)
		}
	}
}

// A viewer must still be refused. The permission this route moved to is held
// from operator up, and the point of the move was to match the action's blast
// radius — not to stop checking. A viewer cannot start a run, so a credential
// stored under their name is one nothing they can do would ever spend.
func TestClaudeLoginIsRefusedForAViewer(t *testing.T) {
	_, ts := newStaleClaimHub(t, authz.RoleViewer)
	c := signedIn(t, ts)

	for _, path := range claudeAuthMutatingRoutes {
		status, body := postAs(t, c, ts, path, `{"code":"x"}`)
		if status != http.StatusForbidden {
			t.Errorf("POST %s as a viewer → %d, want 403: %s", path, status, body)
		}
	}
}

// Whatever one of these endpoints refuses, the refusal has to arrive carrying
// text a human can read.
//
// The dashboard used to interpolate response.error straight into HTML, so a
// pkg/apierror body — which nests the sentence under error.message — reached
// the user as the literal "[object Object]", taking with it a message that
// names the two config changes fixing the hub. The frontend now normalises both
// dialects through errText() (see claude_login_frontend_test.go, which asserts
// the rendered panel).
//
// This is the server half of that contract, and it deliberately does *not*
// demand a bare string. The nested envelope is pkg/apierror's documented wire
// format: the code and details are part of the API contract, pkg/apiserver
// clients read them, and flattening it here would break them to paper over a
// rendering bug. What the frontend actually needs is weaker and is what is
// pinned: an error is either a non-empty string, or an object carrying a
// non-empty message. An object with no message is the one shape no amount of
// frontend care can render.
func TestClaudeAuthErrorsCarryReadableText(t *testing.T) {
	// A viewer, so every route reliably produces the structured authz refusal.
	_, ts := newStaleClaimHub(t, authz.RoleViewer)
	c := signedIn(t, ts)

	for _, path := range claudeAuthMutatingRoutes {
		_, body := postAs(t, c, ts, path, `{"code":"x"}`)
		var envelope map[string]any
		if err := json.Unmarshal([]byte(body), &envelope); err != nil {
			t.Errorf("POST %s: body is not JSON (%v): %s", path, err, body)
			continue
		}
		raw, ok := envelope["error"]
		if !ok {
			continue
		}
		switch e := raw.(type) {
		case string:
			if strings.TrimSpace(e) == "" {
				t.Errorf("POST %s: error is an empty string, so the panel shows "+
					"a blank box. Body: %s", path, body)
			}
		case map[string]any:
			msg, _ := e["message"].(string)
			if strings.TrimSpace(msg) == "" {
				t.Errorf("POST %s: error is an object with no message — there is "+
					"nothing for the dashboard to display, which is how this "+
					"surfaces as \"[object Object]\". Body: %s", path, body)
			}
		default:
			t.Errorf("POST %s: error is %T, which is neither a string nor an "+
				"object with a message. Body: %s", path, raw, body)
		}
	}
}
