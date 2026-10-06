package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// FuzzOIDCCallbackRoutes closes the loop between the rule that decides whether
// a redirect_url is acceptable and the router that has to serve it: every
// redirect_url oidcauth.New accepts must register in this hub's real route
// table, and a browser coming back to it must reach the callback handler.
//
// The two used to disagree. New admitted any path under /auth/, while net/http
// panics on registering an unclean pattern ("/auth//cb", "/auth/../api"),
// malformed wildcard syntax ("/auth/cb{"), or a second GET /auth/login. Each of
// those passed New — and therefore the Settings panel, which validates through
// it — and then stopped the hub at its next start, with a panic instead of an
// error, on a box whose only repair is a shell (Task 20387).
func FuzzOIDCCallbackRoutes(f *testing.F) {
	for _, seed := range []string{
		"https://cloop.example.com/auth/callback",
		"https://cloop.example.com/auth/oidc",
		"https://cloop.example.com/auth/sso/return",
		"https://cloop.example.com/auth/callback/",
		"https://cloop.example.com/auth/login/",
		"https://cloop.example.com/auth/%61b",
		"https://cloop.example.com/auth/a%2Fb",
		"https://cloop.example.com/auth//cb",
		"https://cloop.example.com/auth/../api",
		"https://cloop.example.com/auth/./cb",
		"https://cloop.example.com/auth/cb{",
		"https://cloop.example.com/auth/{x}",
		"https://cloop.example.com/auth/{$}",
		"https://cloop.example.com/auth/login",
		"https://cloop.example.com/auth/renew",
		"https://cloop.example.com/auth/logout",
		"https://cloop.example.com/auth/callback ",
		"/auth/callback",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, redirect string) {
		auth, err := oidcauth.New(oidcauth.Config{
			Enabled:     true,
			Issuer:      "https://idp.example.com",
			ClientID:    "cloop",
			RedirectURL: redirect,
		})
		if err != nil {
			return // refused: startup reports it as an error, which is the contract
		}

		srv := &Server{OIDC: auth}
		mux := http.NewServeMux()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("oidcauth.New accepted redirect_url %q, but registering the route table "+
						"panicked, so the hub would not start: %v", redirect, r)
				}
			}()
			srv.registerRoutes(mux)
		}()

		// The browser comes back to the URL the issuer was given, as written.
		u, err := url.Parse(redirect)
		if err != nil {
			t.Fatalf("oidcauth.New accepted %q, which net/url cannot parse: %v", redirect, err)
		}
		req := httptest.NewRequest(http.MethodGet, "http://cloop.example.com"+u.EscapedPath()+"?code=c&state=s", nil)
		if _, pattern := mux.Handler(req); pattern != "GET "+auth.CallbackPath() {
			t.Fatalf("a browser returning to %q is routed to %q, not the callback %q",
				redirect, pattern, "GET "+auth.CallbackPath())
		}
	})
}
