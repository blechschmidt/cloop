package hubdoctor

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// FuzzRedirectVerdictMatchesStartup is the property Task 20387 restored: for
// any ui.oidc.redirect_url, the doctor reports that the hub will not start
// exactly when the hub's own constructor refuses the URL — and when the
// constructor accepts it, on a deployment whose external URL agrees, the
// doctor passes it.
//
// The doctor used to hold its own copy of the path rule ("the callback is
// /auth/callback") and failed a working hub registered at /auth/oidc, telling
// its operator to break a correct IdP registration. The copy is gone; this is
// what stops one coming back, in either direction.
//
// Everything in the config except the redirect is valid (hubCfg), so a refusal
// from oidcauth.New can only be about the redirect URL.
func FuzzRedirectVerdictMatchesStartup(f *testing.F) {
	for _, seed := range []string{
		"https://cloop.example.com/auth/callback",
		"https://cloop.example.com/auth/oidc", // the :8888 registration
		"https://cloop.example.com/auth/sso/return",
		"https://cloop.example.com/auth/callback/",
		"https://cloop.example.com/auth/callback?x=1#y",
		"https://cloop.example.com/callback",
		"https://cloop.example.com/",
		"https://cloop.example.com",
		"https://cloop.example.com/auth/",
		"https://cloop.example.com/auth//cb",
		"https://cloop.example.com/auth/../api",
		"https://cloop.example.com/auth/cb{",
		"https://cloop.example.com/auth/%7Bx%7D",
		"https://cloop.example.com/auth/login",
		"https://cloop.example.com/auth/renew/",
		" https://cloop.example.com/auth/callback",
		"https://cloop.example.com/auth/callback ",
		"https://other.example.com/auth/oidc",
		"http://cloop.example.com/auth/oidc",
		"http://localhost:8080/auth/callback",
		"/auth/callback",
		"callback",
		"",
		"%",
		"https://[::1]:8443/auth/oidc",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, redirect string) {
		cfg := hubCfg()
		cfg.UI.OIDC.RedirectURL = redirect
		_, startErr := oidcauth.New(cfg.UI.OIDC.AuthConfig())
		hubRefuses := startErr != nil

		findings := oidcFindings(cfg)
		doctorRefuses := false
		for _, f := range findings {
			if f.Check == "oidc.redirect_uri" && f.Severity == SeverityFail &&
				strings.Contains(f.Message, "will not start") {
				doctorRefuses = true
			}
		}
		if doctorRefuses != hubRefuses {
			t.Fatalf("redirect_url %q: oidcauth.New refuses=%v (%v), but the doctor says the hub "+
				"will not start=%v; findings: %+v", redirect, hubRefuses, startErr, doctorRefuses, findings)
		}
		if hubRefuses {
			return
		}
		for _, f := range findings {
			if strings.Contains(f.Message, "will not start") {
				t.Fatalf("redirect_url %q is accepted by oidcauth.New, yet %s says the hub will not start: %q",
					redirect, f.Check, f.Message)
			}
		}

		// Pass otherwise: put the hub at the redirect's own https origin, so
		// every cross-check the doctor makes on top of the hub's rule holds,
		// and the path the hub accepted must not fail on any other ground.
		u, err := url.Parse(redirect)
		if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
			return
		}
		ext := "https://" + u.Host
		if e, err := url.Parse(ext); err != nil || e.Host != u.Host {
			return // a host that does not survive the round trip proves nothing here
		}
		cfg.UI.ExternalURL = ext
		for _, f := range oidcFindings(cfg) {
			if f.Check == "oidc.redirect_uri" && f.Severity != SeverityPass {
				t.Fatalf("redirect_url %q is accepted by the hub and matches ui.external_url %q, "+
					"but the doctor reports %s: %q", redirect, ext, f.Severity, f.Message)
			}
		}
	})
}

// oidcFindings runs the identity checks alone, offline.
func oidcFindings(cfg *config.Config) []Finding {
	var out []Finding
	checkOIDC(context.Background(), cfg, Options{Offline: true}, func(f Finding) { out = append(out, f) })
	return out
}
