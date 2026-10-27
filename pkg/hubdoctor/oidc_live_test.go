package hubdoctor

// The issuer checks of a hub diagnosing itself (Task 20446): read from what
// the hub's own sign-in client holds of the issuer, never resolved again per
// report; resolved over the network only for an issuer that client is not
// using, and then at most once per interval.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// TestIdPStateFindings: each state the sign-in client can be in reads as the
// finding a sign-in would earn — and a key set it failed to refresh while it
// still holds keys is a warning, not the failure an unreachable issuer is.
func TestIdPStateFindings(t *testing.T) {
	at := time.Date(2026, 10, 27, 4, 0, 0, 0, time.UTC)
	disc := &oidcauth.PreflightResult{Issuer: "https://idp.example.com", AuthorizationEndpoint: "https://idp.example.com/auth",
		TokenEndpoint: "https://idp.example.com/token", JWKSURI: "https://idp.example.com/keys", SigningKeys: 2}
	unreachable := &oidcauth.PreflightError{Issuer: "https://idp.example.com", Stage: oidcauth.StageDiscovery,
		URL: "https://idp.example.com/.well-known/openid-configuration", Status: 503, Reason: oidcauth.PreflightUnreachable}
	keysDown := &oidcauth.PreflightError{Issuer: "https://idp.example.com", Stage: oidcauth.StageJWKS,
		URL: "https://idp.example.com/keys", Status: 502, Reason: oidcauth.PreflightUnreachable}
	cases := []struct {
		name           string
		st             oidcauth.IdPState
		disc, jwks     Severity // "" for no finding
		discMsg, jwMsg string
	}{
		{name: "resolved", st: oidcauth.IdPState{Discovery: disc, DiscoveredAt: at, SigningKeys: 2, KeysFetchedAt: at, Ready: true},
			disc: SeverityPass, jwks: SeverityPass, discMsg: "resolved the issuer at 2026-10-27T04:00:00Z",
			jwMsg: "holds 2 usable signing key(s) from https://idp.example.com/keys"},
		{name: "never tried", st: oidcauth.IdPState{}, disc: SeverityWarn, discMsg: "has not resolved the issuer"},
		{name: "discovery unreachable", st: oidcauth.IdPState{LastError: unreachable, LastErrorAt: at},
			disc: SeverityFail, discMsg: "returned HTTP 503"},
		{name: "discovery failed otherwise", st: oidcauth.IdPState{LastError: errors.New("dial tcp: refused"), LastErrorAt: at},
			disc: SeverityFail, discMsg: "dial tcp: refused"},
		{name: "keys held, refresh failed", st: oidcauth.IdPState{Discovery: disc, DiscoveredAt: at, SigningKeys: 2,
			KeysFetchedAt: at, Ready: true, LastError: keysDown, LastErrorAt: at.Add(time.Hour)},
			disc: SeverityPass, jwks: SeverityWarn, jwMsg: "its last refresh, at 2026-10-27T05:00:00Z, failed"},
		{name: "no keys, fetch failed", st: oidcauth.IdPState{Discovery: disc, DiscoveredAt: at, LastError: keysDown, LastErrorAt: at},
			disc: SeverityPass, jwks: SeverityFail, jwMsg: "returned HTTP 502"},
		{name: "no keys yet", st: oidcauth.IdPState{Discovery: disc, DiscoveredAt: at},
			disc: SeverityPass, jwks: SeverityWarn, jwMsg: "has not fetched its key set yet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string][]Finding{}
			checkIdPState(tc.st, func(f Finding) { got[f.Check] = append(got[f.Check], f) })
			d := only(t, got, "oidc.discovery")
			wantSeverity(t, d, tc.disc)
			if !strings.Contains(d.Message, tc.discMsg) {
				t.Errorf("oidc.discovery says %q, want it to mention %q", d.Message, tc.discMsg)
			}
			if tc.jwks == "" {
				if len(got["oidc.jwks"]) != 0 {
					t.Errorf("oidc.jwks = %+v, want none before discovery resolved", got["oidc.jwks"])
				}
				return
			}
			k := only(t, got, "oidc.jwks")
			wantSeverity(t, k, tc.jwks)
			if !strings.Contains(k.Message, tc.jwMsg) {
				t.Errorf("oidc.jwks says %q, want it to mention %q", k.Message, tc.jwMsg)
			}
			for _, f := range []Finding{d, k} {
				if f.Severity != SeverityPass && f.Remediation == "" {
					t.Errorf("%s is %s with no remedy", f.Check, f.Severity)
				}
			}
		})
	}
}

// countingIssuer is an OIDC issuer that counts what it is asked for.
func countingIssuer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var disc, keys atomic.Int32
	var srv *httptest.Server
	jwks := signingJWK(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		disc.Add(1)
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL +
			`/auth","token_endpoint":"` + srv.URL + `/token","jwks_uri":"` + srv.URL + `/jwks"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		keys.Add(1)
		_, _ = w.Write([]byte(jwks))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &disc, &keys
}

// TestLiveReadsTheIssuerFromTheSignInClient: a hub whose sign-in client is for
// the configured issuer reports it from the client, however many reports it
// makes and online; one whose client is for another issuer resolves the
// configured one once and reuses that for the interval, saying the process
// does not sign in with it; `cloop hub doctor` resolves it every time.
func TestLiveReadsTheIssuerFromTheSignInClient(t *testing.T) {
	issuer, disc, keys := countingIssuer(t)
	cfg := hubCfg()
	cfg.UI.OIDC.Issuer = issuer.URL
	now := time.Now()
	state := oidcauth.IdPState{Issuer: issuer.URL + "/", Ready: true, DiscoveredAt: now, SigningKeys: 1, KeysFetchedAt: now,
		Discovery: &oidcauth.PreflightResult{Issuer: issuer.URL, AuthorizationEndpoint: issuer.URL + "/auth",
			TokenEndpoint: issuer.URL + "/token", JWKSURI: issuer.URL + "/jwks", SigningKeys: 1}}
	online := func(self *Self) LiveOptions {
		o := liveOpts()
		o.Offline, o.HTTPClient, o.Self, o.Generation = false, issuer.Client(), self, "g1"
		return o
	}

	var l Live
	for i := 0; i < 3; i++ {
		lr := l.Run(context.Background(), t.TempDir(), cfg, online(&Self{SSO: true, IdP: &state}))
		got := findingsOf(&lr.Report)
		wantSeverity(t, only(t, got, "oidc.discovery"), SeverityPass)
		wantSeverity(t, only(t, got, "oidc.jwks"), SeverityPass)
		if len(got["oidc.running"]) != 0 {
			t.Errorf("oidc.running = %+v for the issuer the hub signs in with", got["oidc.running"])
		}
	}
	if disc.Load() != 0 || keys.Load() != 0 {
		t.Fatalf("three reports of a hub signing in with this issuer asked it for %d discovery and %d key-set document(s)",
			disc.Load(), keys.Load())
	}

	// Started for another issuer: the configured one is resolved, once.
	other := state
	other.Issuer = "https://old-idp.example.com"
	var m Live
	for i := 0; i < 3; i++ {
		lr := m.Run(context.Background(), t.TempDir(), cfg, online(&Self{SSO: true, IdP: &other}))
		got := findingsOf(&lr.Report)
		wantSeverity(t, only(t, got, "oidc.discovery"), SeverityPass)
		if r := only(t, got, "oidc.running"); r.Severity != SeverityWarn || !strings.Contains(r.Message, "old-idp.example.com") {
			t.Errorf("oidc.running = %+v", r)
		}
		want := StepFinished
		if i > 0 {
			want = StepReused
		}
		if s := stepOf(t, lr, "oidc.preflight"); s.Outcome != want {
			t.Errorf("report %d's oidc.preflight ended %s, want %s", i+1, s.Outcome, want)
		}
	}
	if disc.Load() != 1 || keys.Load() != 1 {
		t.Errorf("three reports of a hub signing in elsewhere resolved the configured issuer %d/%d time(s), want once",
			disc.Load(), keys.Load())
	}
	// A hub that started without single sign-on at all is the same case.
	lr := (&Live{}).Run(context.Background(), t.TempDir(), cfg, online(&Self{SSO: false}))
	if r := only(t, findingsOf(&lr.Report), "oidc.running"); !strings.Contains(r.Message, "started without it") {
		t.Errorf("a hub without a sign-in client: oidc.running = %+v", r)
	}

	// The shell's doctor resolves it every time it runs.
	before := disc.Load()
	for i := 0; i < 2; i++ {
		got := findingsFor(t, t.TempDir(), cfg, Options{HTTPClient: issuer.Client()})
		wantSeverity(t, only(t, got, "oidc.discovery"), SeverityPass)
		if len(got["oidc.running"]) != 0 {
			t.Errorf("`cloop hub doctor` reported oidc.running: %+v", got["oidc.running"])
		}
	}
	if d := disc.Load() - before; d != 2 {
		t.Errorf("two runs of `cloop hub doctor` resolved the issuer %d time(s), want 2", d)
	}
}
