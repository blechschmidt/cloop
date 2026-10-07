package hubdoctor

// Tests for the hub diagnosis.
//
// The load-bearing one is TestEveryNonPassCarriesRemediation: the whole premise
// of this command is that a finding names its own fix, and a finding that
// reports a problem and stops is the exact failure the command exists to
// remove. It is asserted across a fixture set chosen to make every check fire.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/globalbudget"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// findingsFor runs a diagnosis and indexes the results by check id. Several
// checks can emit more than one finding under the same id (one per executor,
// one per registry), so the value is a slice.
func findingsFor(t *testing.T, dir string, cfg *config.Config, opts Options) map[string][]Finding {
	t.Helper()
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.GlobalBudget == nil {
		// The machine running the suite may have host-wide caps of its own.
		opts.GlobalBudget = func() (globalbudget.GlobalBudgetConfig, error) {
			return globalbudget.GlobalBudgetConfig{}, nil
		}
	}
	rep := Run(context.Background(), dir, cfg, opts)
	out := map[string][]Finding{}
	for _, f := range rep.Findings {
		out[f.Check] = append(out[f.Check], f)
	}
	return out
}

// only returns the single finding for a check, failing if there is not exactly
// one — an assertion that a check did not silently emit twice.
func only(t *testing.T, got map[string][]Finding, check string) Finding {
	t.Helper()
	fs := got[check]
	if len(fs) != 1 {
		t.Fatalf("check %q: want exactly 1 finding, got %d", check, len(fs))
	}
	return fs[0]
}

func wantSeverity(t *testing.T, f Finding, want Severity) {
	t.Helper()
	if f.Severity != want {
		t.Errorf("check %q: want severity %s, got %s (%s)", f.Check, want, f.Severity, f.Message)
	}
}

// hubCfg is a config that is correct in every respect the offline checks can
// see, so a test can break exactly one thing and attribute the finding to it.
func hubCfg() *config.Config {
	cfg := config.Default()
	cfg.Executors.SetHostProcessAllowed(false)
	cfg.UI.ExternalURL = "https://cloop.example.com"
	cfg.UI.OIDC = config.OIDCConfig{
		Enabled:      true,
		Issuer:       "https://idp.example.com",
		ClientID:     "cloop-hub",
		RedirectURL:  "https://cloop.example.com/auth/callback",
		Scopes:       []string{"openid", "profile", "email", "groups"},
		DefaultRole:  "none",
		RoleMappings: []config.RoleMapping{{Claim: "group", Value: "platform", Role: "admin"}},
	}
	return cfg
}

// ── Structural contract ─────────────────────────────────────────────────────

// TestEveryNonPassCarriesRemediation is the contract the package documents.
func TestEveryNonPassCarriesRemediation(t *testing.T) {
	broken := config.Default()
	broken.UI.ExternalURL = "http://cloop.example.com"
	broken.UI.OIDC = config.OIDCConfig{
		Enabled:     true,
		Issuer:      "https://idp.example.com",
		RedirectURL: "https://elsewhere.example.com/callback",
		DefaultRole: "admin",
		RoleMappings: []config.RoleMapping{
			{Claim: "group", Value: "eng", Role: "viewer"},
			{Claim: "group", Value: "eng", Role: "operator"},
		},
	}
	broken.UI.Quotas = config.QuotasConfig{
		Defaults: map[string]float64{"max_projects": 0},
		Bindings: []config.QuotaBinding{{Claim: "group", Value: "eng"}},
	}

	// Single sign-on with no role policy: rbac.enforced fails (Task 20395).
	noPolicy := hubCfg()
	noPolicy.UI.OIDC.DefaultRole = ""
	noPolicy.UI.OIDC.RoleMappings = nil
	noPolicy.UI.OIDC.RequireRBAC = true

	fixtures := []struct {
		name string
		cfg  *config.Config
	}{
		{"nil config", nil},
		{"default config", config.Default()},
		{"well-formed hub", hubCfg()},
		{"comprehensively broken", broken},
		{"SSO without a role policy", noPolicy},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			rep := Run(context.Background(), t.TempDir(), fx.cfg, Options{Offline: true})
			if len(rep.Findings) == 0 {
				t.Fatal("no findings produced")
			}
			for _, f := range rep.Findings {
				if f.Check == "" || f.Title == "" || f.Message == "" {
					t.Errorf("finding is missing an id, title or message: %+v", f)
				}
				if f.Severity != SeverityPass && strings.TrimSpace(f.Remediation) == "" {
					t.Errorf("check %q is %s with no remediation: %s", f.Check, f.Severity, f.Message)
				}
			}
		})
	}
}

// TestReportJSONIsStable pins the wire shape --json emits, because a CI
// pipeline greps the check ids and renaming one is a breaking change.
func TestReportJSONIsStable(t *testing.T) {
	rep := Run(context.Background(), t.TempDir(), hubCfg(), Options{Offline: true})
	raw, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var decoded struct {
		Dir        string `json:"dir"`
		StrictMode bool   `json:"strict_mode"`
		Offline    bool   `json:"offline"`
		Findings   []struct {
			Check       string `json:"check"`
			Severity    string `json:"severity"`
			Message     string `json:"message"`
			Remediation string `json:"remediation"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("emitted JSON does not decode: %v", err)
	}
	if !decoded.StrictMode || !decoded.Offline {
		t.Errorf("strict_mode/offline not carried into JSON: %+v", decoded)
	}
	if len(decoded.Findings) == 0 {
		t.Fatal("no findings in JSON")
	}
	for _, f := range decoded.Findings {
		switch Severity(f.Severity) {
		case SeverityPass, SeverityWarn, SeverityFail:
		default:
			t.Errorf("check %q has unknown severity %q", f.Check, f.Severity)
		}
	}
}

// TestExitCodeIgnoresWarnings: a gate that goes red on deployment choices gets
// switched off, which is the reason warnings do not fail.
func TestExitCodeIgnoresWarnings(t *testing.T) {
	warnOnly := &Report{Findings: []Finding{
		{Check: "a", Severity: SeverityPass},
		{Check: "b", Severity: SeverityWarn},
	}}
	if got := warnOnly.ExitCode(); got != 0 {
		t.Errorf("warnings must not fail the command: exit %d", got)
	}
	withFail := &Report{Findings: append(warnOnly.Findings, Finding{Check: "c", Severity: SeverityFail})}
	if got := withFail.ExitCode(); got != 1 {
		t.Errorf("a failure must fail the command: exit %d", got)
	}
	if got := withFail.Worst(); got != SeverityFail {
		t.Errorf("Worst() = %s, want fail", got)
	}
}

// ── Identity ────────────────────────────────────────────────────────────────

// signingJWK renders a real RSA public key as a JWK.
//
// A fixture with kty=RSA and no key material would do for a check that only
// reads kty, and that is exactly why it will not do here: the probe is now
// oidcauth's own, which parses the modulus and exponent because that is what
// verifying a token requires. A key it cannot parse is a key the hub cannot
// verify with, and the fixture has to be honest about the difference.
func signingJWK(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	pub := &key.PublicKey
	return `{"keys":[{"kid":"a","kty":"RSA","alg":"RS256","use":"sig","n":"` +
		base64.RawURLEncoding.EncodeToString(pub.N.Bytes()) + `","e":"` +
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()) + `"}]}`
}

// TestOIDCDiscoveryAndJWKS drives the two network checks against a stand-in
// issuer, including the spec requirement that the document agree on its own
// issuer name.
func TestOIDCDiscoveryAndJWKS(t *testing.T) {
	usable := signingJWK(t)

	cases := []struct {
		name        string
		issuerInDoc string // "" means: use the server's own URL
		jwks        string
		wantDisc    Severity
		wantJWKS    Severity
	}{
		{
			name:     "healthy",
			jwks:     usable,
			wantDisc: SeverityPass, wantJWKS: SeverityPass,
		},
		{
			name:        "issuer disagrees with its own document",
			issuerInDoc: "https://somewhere-else.example.com",
			jwks:        usable,
			wantDisc:    SeverityFail,
		},
		{
			name:     "empty key set",
			jwks:     `{"keys":[]}`,
			wantDisc: SeverityPass, wantJWKS: SeverityFail,
		},
		{
			name:     "no verifiable key types",
			jwks:     `{"keys":[{"kid":"a","kty":"oct","alg":"HS256"}]}`,
			wantDisc: SeverityPass, wantJWKS: SeverityFail,
		},
		{
			// The case the doctor used to pass and the hub used to reject:
			// an RSA entry with no modulus announces a signing key and
			// supplies nothing to verify with.
			name:     "RSA entry carrying no key material",
			jwks:     `{"keys":[{"kid":"a","kty":"RSA","alg":"RS256","use":"sig"}]}`,
			wantDisc: SeverityPass, wantJWKS: SeverityFail,
		},
		{
			name:     "key set is not a JWK set",
			jwks:     `not json at all`,
			wantDisc: SeverityPass, wantJWKS: SeverityFail,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			var srv *httptest.Server
			mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
				issuer := tc.issuerInDoc
				if issuer == "" {
					issuer = srv.URL
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"issuer": "` + issuer + `",
					"authorization_endpoint": "` + srv.URL + `/auth",
					"token_endpoint": "` + srv.URL + `/token",
					"jwks_uri": "` + srv.URL + `/jwks"
				}`))
			})
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.jwks))
			})
			srv = httptest.NewServer(mux)
			defer srv.Close()

			cfg := hubCfg()
			cfg.UI.OIDC.Issuer = srv.URL

			got := findingsFor(t, t.TempDir(), cfg, Options{HTTPClient: srv.Client()})
			wantSeverity(t, only(t, got, "oidc.discovery"), tc.wantDisc)
			if tc.wantJWKS != "" {
				wantSeverity(t, only(t, got, "oidc.jwks"), tc.wantJWKS)
			}
		})
	}
}

// TestOIDCUnreachableIssuerFails: a hub whose issuer does not resolve must fail
// loudly, not be reported as merely unverified.
func TestOIDCUnreachableIssuerFails(t *testing.T) {
	cfg := hubCfg()
	// Reserved by RFC 6761 for documentation; guaranteed not to resolve to a
	// live OIDC provider.
	cfg.UI.OIDC.Issuer = "https://idp.invalid"

	got := findingsFor(t, t.TempDir(), cfg, Options{Timeout: time.Second})
	wantSeverity(t, only(t, got, "oidc.discovery"), SeverityFail)
	if len(got["oidc.jwks"]) != 0 {
		t.Error("JWKS must not be probed when discovery failed")
	}
}

func TestRedirectURIChecks(t *testing.T) {
	cases := []struct {
		name        string
		external    string
		redirect    string
		wantCheck   string
		wantSeverit Severity
	}{
		{"matching", "https://cloop.example.com", "https://cloop.example.com/auth/callback",
			"oidc.redirect_uri", SeverityPass},
		{"different origin", "https://cloop.example.com", "https://other.example.com/auth/callback",
			"oidc.redirect_uri", SeverityFail},
		{"wrong path", "https://cloop.example.com", "https://cloop.example.com/callback",
			"oidc.redirect_uri", SeverityFail},
		// The IdP decides the path, and the hub serves any it can route under
		// /auth/ — Entra SPA registrations are commonly /auth/oidc (Task 20387).
		{"registered elsewhere under /auth/", "https://cloop.example.com", "https://cloop.example.com/auth/oidc",
			"oidc.redirect_uri", SeverityPass},
		{"nested under /auth/", "https://cloop.example.com", "https://cloop.example.com/auth/sso/return",
			"oidc.redirect_uri", SeverityPass},
		{"a path the router cannot register", "https://cloop.example.com", "https://cloop.example.com/auth//cb",
			"oidc.redirect_uri", SeverityFail},
		{"the hub's own login route", "https://cloop.example.com", "https://cloop.example.com/auth/login",
			"oidc.redirect_uri", SeverityFail},
		{"empty", "https://cloop.example.com", "",
			"oidc.redirect_uri", SeverityFail},
		{"not a URL", "https://cloop.example.com", "callback",
			"oidc.redirect_uri", SeverityFail},
		{"plaintext to a public host", "http://cloop.example.com", "http://cloop.example.com/auth/callback",
			"oidc.redirect_uri", SeverityFail},
		{"loopback plaintext is fine", "http://localhost:8080", "http://localhost:8080/auth/callback",
			"oidc.redirect_uri", SeverityPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hubCfg()
			cfg.UI.ExternalURL = tc.external
			cfg.UI.OIDC.RedirectURL = tc.redirect

			got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
			fs := got[tc.wantCheck]
			if len(fs) == 0 {
				t.Fatalf("no %s finding", tc.wantCheck)
			}
			// The path and origin checks can both fire; the test asserts on
			// the worst, which is what an operator acts on first.
			worst := SeverityPass
			for _, f := range fs {
				if f.Severity.rank() > worst.rank() {
					worst = f.Severity
				}
			}
			if worst != tc.wantSeverit {
				t.Errorf("want %s, got %s from %d finding(s)", tc.wantSeverit, worst, len(fs))
			}
		})
	}
}

// TestRedirectPathOutsideAuthSaysTheHubWillNotStart: the one path finding
// left is the hub's own refusal, and it is reported as what it is — a hub that
// does not start — with a remediation that keeps the operator's origin.
func TestRedirectPathOutsideAuthSaysTheHubWillNotStart(t *testing.T) {
	cfg := hubCfg()
	cfg.UI.OIDC.RedirectURL = "https://cloop.example.com/oidc/callback"
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "oidc.redirect_uri")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Message, "will not start") || !strings.Contains(f.Message, "/auth/") {
		t.Errorf("the refusal should say the hub will not start and name the /auth/ rule: %q", f.Message)
	}
	if !strings.Contains(f.Remediation, "https://cloop.example.com/auth/callback") {
		t.Errorf("remediation should propose a servable URL at the hub's origin: %q", f.Remediation)
	}
	// Reported once: the startup check asks about the rest of the block.
	start := only(t, got, "oidc.startup")
	wantSeverity(t, start, SeverityPass)
	if strings.Contains(start.Message, "redirect_url path") {
		t.Errorf("the redirect refusal is reported twice: %q", start.Message)
	}
}

// TestRedirectAtAuthOIDCWithoutExternalURLPasses is :8888's own configuration
// (Task 20387): an Entra SPA registration at /auth/oidc and no ui.external_url.
// The doctor used to FAIL it and advise moving the registration to
// /auth/callback, which would have broken a working sign-in.
func TestRedirectAtAuthOIDCWithoutExternalURLPasses(t *testing.T) {
	cfg := hubCfg()
	cfg.UI.ExternalURL = ""
	cfg.UI.OIDC.RedirectURL = "https://aiden.blechschmidt.io:8888/auth/oidc"
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "oidc.redirect_uri")
	wantSeverity(t, f, SeverityPass)
	if !strings.Contains(f.Message, "/auth/oidc") || !strings.Contains(f.Message, "not cross-checked") {
		t.Errorf("the pass should name the served path and what was not checked: %q", f.Message)
	}
	ext := only(t, got, "oidc.external_url")
	wantSeverity(t, ext, SeverityWarn)
	if !strings.Contains(ext.Remediation, "https://aiden.blechschmidt.io:8888") {
		t.Errorf("remediation should propose the redirect's own origin: %q", ext.Remediation)
	}
}

// TestRedirectOriginRemediationKeepsTheRegisteredPath: when the origin is
// wrong the fix is the origin, not the path the issuer already holds.
func TestRedirectOriginRemediationKeepsTheRegisteredPath(t *testing.T) {
	cfg := hubCfg()
	cfg.UI.ExternalURL = "https://cloop.example.com/"
	cfg.UI.OIDC.RedirectURL = "https://old-name.example.com/auth/oidc"
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "oidc.redirect_uri")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Remediation, "https://cloop.example.com/auth/oidc") {
		t.Errorf("remediation should be ui.external_url plus the configured path: %q", f.Remediation)
	}
}

// TestOIDCStartupIsTheConstructorsVerdict: whether the hub starts is asked of
// oidcauth.New on the builder `cloop ui` uses, so every rule New enforces is
// reported — including the ones the doctor never restated, which used to pass
// offline and then stop the hub at its next restart.
func TestOIDCStartupIsTheConstructorsVerdict(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*config.OIDCConfig)
		want   string // substring of the refusal; "" means accepted
	}{
		{"valid", func(*config.OIDCConfig) {}, ""},
		{"plaintext issuer", func(o *config.OIDCConfig) { o.Issuer = "http://idp.example.com" }, "https"},
		{"loopback plaintext issuer is development", func(o *config.OIDCConfig) { o.Issuer = "http://127.0.0.1:5556" }, ""},
		{"unknown cookie mode", func(o *config.OIDCConfig) { o.CookieSecure = "sometimes" }, "cookie_secure"},
		{"clock skew past the ceiling", func(o *config.OIDCConfig) { o.ClockSkewSeconds = 3600 }, "clock_skew"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hubCfg()
			tc.mutate(&cfg.UI.OIDC)
			f := only(t, findingsFor(t, t.TempDir(), cfg, Options{Offline: true}), "oidc.startup")
			if tc.want == "" {
				wantSeverity(t, f, SeverityPass)
				return
			}
			wantSeverity(t, f, SeverityFail)
			if !strings.Contains(f.Message, "will not start") || !strings.Contains(f.Message, tc.want) {
				t.Errorf("want a refusal naming %q, got %q", tc.want, f.Message)
			}
		})
	}
}

// TestOIDCStartupReportsEveryRefusal: New stops at its first refusal, so each
// is set aside and New asked again — a bad issuer no longer hides an empty
// client id, which keeps its own check id, oidc.client_id (Task 20387).
func TestOIDCStartupReportsEveryRefusal(t *testing.T) {
	cfg := hubCfg()
	cfg.UI.OIDC.Issuer = "http://idp.example.com"
	cfg.UI.OIDC.ClientID = ""
	cfg.UI.OIDC.CookieSecure = "sometimes"
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})

	id := only(t, got, "oidc.client_id")
	wantSeverity(t, id, SeverityFail)
	if !strings.Contains(id.Message, "client_id is required") {
		t.Errorf("oidc.client_id: %q", id.Message)
	}
	start := only(t, got, "oidc.startup")
	wantSeverity(t, start, SeverityFail)
	for _, want := range []string{"https", "cookie_secure"} {
		if !strings.Contains(start.Message, want) {
			t.Errorf("oidc.startup should name the %s refusal too: %q", want, start.Message)
		}
	}
	if strings.Contains(start.Message, "client_id") {
		t.Errorf("the client id is reported twice: %q", start.Message)
	}

	// The client id alone: its own finding, and the rest of the block passes.
	cfg = hubCfg()
	cfg.UI.OIDC.ClientID = ""
	got = findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	wantSeverity(t, only(t, got, "oidc.client_id"), SeverityFail)
	wantSeverity(t, only(t, got, "oidc.startup"), SeverityPass)
}

// TestClientSecretFromConfigIsAWarning: config.yaml is committed in every
// topology cloop documents, so a secret in it is a secret in git.
func TestClientSecretSource(t *testing.T) {
	t.Run("from environment", func(t *testing.T) {
		t.Setenv(config.EnvOIDCClientSecret, "s3cret-from-the-env")
		cfg := hubCfg()
		cfg.UI.OIDC.ClientSecret = "s3cret-from-the-env" // as Load would have set it
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "oidc.client_secret"), SeverityPass)
	})
	t.Run("from config file", func(t *testing.T) {
		t.Setenv(config.EnvOIDCClientSecret, "")
		cfg := hubCfg()
		cfg.UI.OIDC.ClientSecret = "written-into-the-yaml"
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "oidc.client_secret"), SeverityWarn)
	})
	// Absent is a configuration, not a defect: it is the public-client hub
	// the Terraform module provisions by default, where PKCE authenticates
	// the code exchange. Reporting it as a failure told operators their
	// working hub was broken (Task 20314).
	t.Run("absent is a public client, not a failure", func(t *testing.T) {
		t.Setenv(config.EnvOIDCClientSecret, "")
		got := findingsFor(t, t.TempDir(), hubCfg(), Options{Offline: true})
		f := only(t, got, "oidc.client_secret")
		wantSeverity(t, f, SeverityPass)
		if !strings.Contains(f.Message, "PKCE") {
			t.Errorf("a secretless hub should be told what authenticates it instead; got %q", f.Message)
		}
	})
}

// ── Transport ───────────────────────────────────────────────────────────────

// TestTLSCertificateChecks generates real key material with the same code path
// `cloop hub tls-init` uses, then varies the clock and the hostname.
func TestTLSCertificateChecks(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if _, err := tlsconf.GenerateSelfSigned(certPath, keyPath, tlsconf.SelfSignedOptions{
		Hosts:    []string{"cloop.example.com", "127.0.0.1"},
		ValidFor: 90 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	base := hubCfg()
	base.UI.TLS = config.TLSConfig{CertFile: certPath, KeyFile: keyPath, MinVersion: "1.2"}

	t.Run("valid material", func(t *testing.T) {
		got := findingsFor(t, dir, base, Options{Offline: true})
		wantSeverity(t, only(t, got, "tls.material"), SeverityPass)
		wantSeverity(t, only(t, got, "tls.expiry"), SeverityPass)
		wantSeverity(t, only(t, got, "tls.san"), SeverityPass)
		wantSeverity(t, only(t, got, "tls.key_permissions"), SeverityPass)
		// Self-signed is a warning, not a pass: nothing trusts it by default.
		wantSeverity(t, only(t, got, "tls.chain"), SeverityWarn)
	})

	t.Run("expiring soon", func(t *testing.T) {
		soon := time.Now().Add(80 * 24 * time.Hour)
		got := findingsFor(t, dir, base, Options{Offline: true, Now: func() time.Time { return soon }})
		wantSeverity(t, only(t, got, "tls.expiry"), SeverityWarn)
	})

	t.Run("expired", func(t *testing.T) {
		past := time.Now().Add(120 * 24 * time.Hour)
		got := findingsFor(t, dir, base, Options{Offline: true, Now: func() time.Time { return past }})
		wantSeverity(t, only(t, got, "tls.expiry"), SeverityFail)
	})

	t.Run("does not cover the external hostname", func(t *testing.T) {
		cfg := *base
		cfg.UI.ExternalURL = "https://elsewhere.example.com"
		cfg.UI.OIDC.RedirectURL = "https://elsewhere.example.com/auth/callback"
		got := findingsFor(t, dir, &cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "tls.san"), SeverityFail)
	})

	t.Run("key does not match certificate", func(t *testing.T) {
		otherDir := t.TempDir()
		otherKey := filepath.Join(otherDir, "key.pem")
		if _, err := tlsconf.GenerateSelfSigned(filepath.Join(otherDir, "cert.pem"), otherKey,
			tlsconf.SelfSignedOptions{Hosts: []string{"cloop.example.com"}, ValidFor: time.Hour}); err != nil {
			t.Fatalf("generate second certificate: %v", err)
		}
		cfg := *base
		cfg.UI.TLS = config.TLSConfig{CertFile: certPath, KeyFile: otherKey}
		got := findingsFor(t, dir, &cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "tls.material"), SeverityFail)
	})

	t.Run("half configured", func(t *testing.T) {
		cfg := *base
		cfg.UI.TLS = config.TLSConfig{CertFile: certPath}
		got := findingsFor(t, dir, &cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "tls.material"), SeverityFail)
	})

	// The material is judged by tlsconf.LoadServerConfig, the listener's own
	// loader, so a config with two faults is reported at the one startup stops
	// on — the floor, which it parses before it loads the pair (Task 20387).
	t.Run("an unsupported floor stops startup before the pair is read", func(t *testing.T) {
		otherKey := filepath.Join(t.TempDir(), "key.pem")
		if _, err := tlsconf.GenerateSelfSigned(filepath.Join(filepath.Dir(otherKey), "cert.pem"), otherKey,
			tlsconf.SelfSignedOptions{Hosts: []string{"cloop.example.com"}, ValidFor: time.Hour}); err != nil {
			t.Fatalf("generate second certificate: %v", err)
		}
		cfg := *base
		cfg.UI.TLS = config.TLSConfig{CertFile: certPath, KeyFile: otherKey, MinVersion: "1.0"}
		got := findingsFor(t, dir, &cfg, Options{Offline: true})
		f := only(t, got, "tls.min_version")
		wantSeverity(t, f, SeverityFail)
		if !strings.Contains(f.Message, "will not start") {
			t.Errorf("a floor startup refuses should say so: %q", f.Message)
		}
		if len(got["tls.material"]) != 0 {
			t.Errorf("reported the pair, which startup never reaches: %+v", got["tls.material"])
		}
	})

	// The server presents every CERTIFICATE block it loaded and parses only
	// the leaf. Re-reading the file and skipping what did not parse used to
	// pass a chain whose intermediate breaks every client that needs it.
	t.Run("an intermediate that does not parse is presented anyway", func(t *testing.T) {
		leafPEM, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		bad := append(append([]byte{}, leafPEM...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")})...)
		badChain := filepath.Join(t.TempDir(), "chain.pem")
		if err := os.WriteFile(badChain, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := *base
		cfg.UI.TLS = config.TLSConfig{CertFile: badChain, KeyFile: keyPath}
		got := findingsFor(t, dir, &cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "tls.material"), SeverityPass)
		wantSeverity(t, only(t, got, "tls.chain"), SeverityFail)
	})
}

// TestTLSTerminationFollowsTheAgentsEndpointRule: with no certificate of its
// own, the hub's transport is classified by tlsconf.ParseEndpoint — the rule an
// edge agent applies to the same URL when it dials in — rather than by a list
// of three loopback names the doctor once kept, which failed hubs that every
// agent connects to without --insecure-transport (Task 20387).
func TestTLSTerminationFollowsTheAgentsEndpointRule(t *testing.T) {
	cases := []struct {
		external string
		want     Severity
	}{
		{"https://cloop.example.com", SeverityPass},
		{"wss://cloop.example.com", SeverityPass},
		{"http://localhost:8080", SeverityPass},
		{"http://127.0.1.1:8080", SeverityPass},
		{"http://[::1]:8080", SeverityPass},
		{"http://hub.localhost:8080", SeverityPass},
		{"http://cloop.example.com", SeverityFail},
		{"http://localhost.example.com", SeverityFail},
		{"ftp://cloop.example.com", SeverityFail},
	}
	for _, tc := range cases {
		t.Run(tc.external, func(t *testing.T) {
			if _, _, err := tlsconf.CheckEndpoint(tc.external, false); (err == nil) != (tc.want == SeverityPass) {
				t.Fatalf("premise: an agent's verdict on %s is err=%v", tc.external, err)
			}
			cfg := hubCfg()
			cfg.UI.ExternalURL = tc.external
			cfg.UI.OIDC.Enabled = false
			got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
			wantSeverity(t, only(t, got, "tls.termination"), tc.want)
		})
	}
}

// TestTLSTerminationAtProxy: no certificate is correct behind a proxy and
// wrong when the hub is directly reachable over plaintext.
func TestTLSTermination(t *testing.T) {
	cases := []struct {
		external string
		want     Severity
	}{
		{"https://cloop.example.com", SeverityPass},
		{"http://localhost:8080", SeverityPass},
		{"http://cloop.example.com", SeverityFail},
		{"", SeverityWarn},
	}
	for _, tc := range cases {
		t.Run(tc.external, func(t *testing.T) {
			cfg := hubCfg()
			cfg.UI.ExternalURL = tc.external
			cfg.UI.OIDC.Enabled = false // isolate the transport finding
			got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
			wantSeverity(t, only(t, got, "tls.termination"), tc.want)
		})
	}
}

// ── Secrets ─────────────────────────────────────────────────────────────────

func TestSealingKey(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		check string
		want  Severity
	}{
		{"generated", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWo", "secret_key.entropy", SeverityPass},
		{"placeholder from the docs", "eval-only-not-a-real-key-change-me", "secret_key.entropy", SeverityFail},
		{"too short", "hunter2", "secret_key.entropy", SeverityFail},
		{"repetitive passphrase", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "secret_key.entropy", SeverityWarn},
		{"absent", "", "secret_key.present", SeverityWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CLOOP_SECRET_KEY", tc.key)
			got := findingsFor(t, t.TempDir(), hubCfg(), Options{Offline: true})
			wantSeverity(t, only(t, got, tc.check), tc.want)
		})
	}
}

// TestSealingKeyAbsentWithSealedMaterialFails: no key plus sealed secrets is an
// outage, not a warning — the hub cannot open what it already holds.
func TestSealingKeyAbsentWithSealedMaterialFails(t *testing.T) {
	t.Setenv("CLOOP_SECRET_KEY", "")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "secrets.enc"), []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
	wantSeverity(t, only(t, got, "secret_key.present"), SeverityFail)
}

// ── Authorization ───────────────────────────────────────────────────────────

// TestNoGroupMapsToAdmin is the finding this file exists for: correct
// authorization, zero runtime symptom, unusable hub.
func TestNoGroupMapsToAdmin(t *testing.T) {
	cfg := hubCfg()
	cfg.UI.OIDC.RoleMappings = []config.RoleMapping{
		{Claim: "group", Value: "eng", Role: "operator"},
		{Claim: "group", Value: "sre", Role: "maintainer"},
	}
	cfg.UI.OIDC.AdminEmails = nil

	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "rbac.admin")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Message, "admin") {
		t.Errorf("the message must name the missing role: %q", f.Message)
	}
}

// TestProjectScopedAdminIsNotHubAdmin: admin *of a project* grants none of the
// hub-management permissions, so counting it would produce a green line on a
// hub nobody can administer.
func TestProjectScopedAdminIsNotHubAdmin(t *testing.T) {
	cfg := hubCfg()
	cfg.UI.OIDC.RoleMappings = []config.RoleMapping{
		{Claim: "group", Value: "eng", Role: "admin", Project: "/srv/one"},
	}
	cfg.UI.OIDC.AdminEmails = nil

	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	wantSeverity(t, only(t, got, "rbac.admin"), SeverityFail)
}

// TestAdminRoutesAreCountedOnce: an address in admin_emails that an email
// mapping also makes admin is one way in. On :8888's own configuration the
// finding said "2 route(s)" and named the one address twice (Task 20387).
func TestAdminRoutesAreCountedOnce(t *testing.T) {
	cfg := hubCfg()
	cfg.UI.OIDC.AdminEmails = []string{"ops@example.com"}
	cfg.UI.OIDC.RoleMappings = []config.RoleMapping{{Claim: "email", Value: "ops@example.com", Role: "admin"}}

	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "rbac.admin")
	wantSeverity(t, f, SeverityPass)
	if !strings.HasPrefix(f.Message, "1 route(s)") || f.Details["granted_by"] != "email=ops@example.com" {
		t.Errorf("one address made admin twice is one route: %q, granted_by %v", f.Message, f.Details["granted_by"])
	}
}

func TestRBACChecks(t *testing.T) {
	t.Run("default_role admin", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.DefaultRole = "admin"
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "rbac.default_role"), SeverityFail)
	})
	t.Run("default_role viewer", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.DefaultRole = "viewer"
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "rbac.default_role"), SeverityWarn)
	})
	t.Run("invalid role name", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.RoleMappings = []config.RoleMapping{{Claim: "group", Value: "eng", Role: "superuser"}}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "rbac.policy"), SeverityFail)
	})
	t.Run("group mappings without the groups scope", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.Scopes = []string{"openid", "email"}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "rbac.scopes"), SeverityFail)
	})
	t.Run("duplicate bindings", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.RoleMappings = append(cfg.UI.OIDC.RoleMappings,
			config.RoleMapping{Claim: "group", Value: "platform", Role: "viewer"})
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "rbac.duplicates"), SeverityWarn)
	})
	t.Run("mappings with SSO off", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.Enabled = false
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "rbac.policy"), SeverityWarn)
	})
}

// TestRBACJudgesThePolicyTheResolverHolds: authz.New normalizes a binding —
// claim and role lowercased, values trimmed, a group path's leading "/"
// dropped, sub kept exact — and the hub decides with that. The doctor judged
// the YAML, and failed a hub whose admin mapping said "role: Admin" (Task 20387).
func TestRBACJudgesThePolicyTheResolverHolds(t *testing.T) {
	t.Run("a capitalized admin role is admin", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.AdminEmails = nil
		cfg.UI.OIDC.RoleMappings = []config.RoleMapping{{Claim: "group", Value: "platform", Role: " Admin "}}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "rbac.admin"), SeverityPass)
	})
	t.Run("a capitalized group claim still needs the groups scope", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.Scopes = []string{"openid", "email"}
		cfg.UI.OIDC.RoleMappings = []config.RoleMapping{{Claim: "Group", Value: "platform", Role: "admin"}}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "rbac.scopes"), SeverityFail)
	})
	t.Run("a group path and its bare name are one value", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.RoleMappings = []config.RoleMapping{
			{Claim: "group", Value: "/ops", Role: "admin"},
			{Claim: "group", Value: "ops", Role: "viewer"},
		}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "rbac.duplicates"), SeverityWarn)
	})
	t.Run("subjects differing in case are two subjects", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.RoleMappings = append(cfg.UI.OIDC.RoleMappings,
			config.RoleMapping{Claim: "sub", Value: "ABC", Role: "viewer"},
			config.RoleMapping{Claim: "sub", Value: "abc", Role: "operator"})
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		if fs := got["rbac.duplicates"]; len(fs) != 0 {
			t.Errorf("sub is compared exactly, so these are not duplicates: %+v", fs)
		}
	})
	t.Run("an admin email repeated as a mapping is not dead policy", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.AdminEmails = []string{"ops@example.com"}
		cfg.UI.OIDC.RoleMappings = append(cfg.UI.OIDC.RoleMappings,
			config.RoleMapping{Claim: "email", Value: "ops@example.com", Role: "admin"})
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		if fs := got["rbac.duplicates"]; len(fs) != 0 {
			t.Errorf("flagged the :8888 shape, an admin email and the same mapping: %+v", fs)
		}
	})
}

// ── Image trust ─────────────────────────────────────────────────────────────

func TestImagePolicyChecks(t *testing.T) {
	t.Run("executor enabled with no policy", func(t *testing.T) {
		cfg := hubCfg()
		cfg.Executors.Container.Enabled = true
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "images.policy"), SeverityWarn)
	})

	t.Run("require_signature with no cosign", func(t *testing.T) {
		cfg := hubCfg()
		cfg.Executors.Container.Enabled = true // a driver that verifies
		cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{
			AllowedRegistries: []string{"ghcr.io"},
			RequireSignature:  true,
			CosignPublicKeys:  []string{"/etc/cloop/cosign.pub"},
		}
		got := findingsFor(t, t.TempDir(), cfg, Options{
			Offline:  true,
			LookPath: func(string) (string, error) { return "", os.ErrNotExist },
		})
		wantSeverity(t, only(t, got, "images.signature"), SeverityFail)
	})

	// require_signature with no key or identity is rejected by the policy's
	// own validator, so it surfaces as an invalid policy rather than as a
	// verification finding — asserted here so the two checks cannot silently
	// swap responsibility.
	t.Run("require_signature with nothing to verify against", func(t *testing.T) {
		cfg := hubCfg()
		cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{
			AllowedRegistries: []string{"ghcr.io"},
			RequireSignature:  true,
		}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "images.policy"), SeverityFail)
		if len(got["images.signature"]) != 0 {
			t.Error("an invalid policy must not also produce a signature finding")
		}
	})

	// The drivers never apply the policy to the operator's own image
	// (container.Options.ImagePolicy), so it is not "refused by this hub's
	// own policy" — the doctor used to say it was (Task 20387). What is true
	// is that a project naming the same image would be.
	t.Run("the hub's own image runs whatever the policy says", func(t *testing.T) {
		cfg := hubCfg()
		cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{
			AllowedRegistries: []string{"ghcr.io"},
			RequireDigest:     true,
		}
		cfg.Executors.Container.Enabled = true
		cfg.Executors.Container.Image = "docker.io/library/alpine:3"
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		f := only(t, got, "images.configured")
		wantSeverity(t, f, SeverityPass)
		if !strings.Contains(f.Message, "runs as configured") || f.Details["refused_for_projects"] == nil {
			t.Errorf("want the exemption and what it would mean for a project: %q %v", f.Message, f.Details)
		}
	})

	t.Run("a policy that admits any registry says so", func(t *testing.T) {
		for _, pol := range []config.ImagePolicyConfig{
			{RequireDigest: true},
			{AllowedRegistries: []string{"*"}, RequireDigest: true},
			// A bare repo beside "*" is that path on any registry.
			{AllowedRegistries: []string{"*"}, AllowedRepos: []string{"acme/tools"}},
		} {
			cfg := hubCfg()
			cfg.Sandbox.ImagePolicy = pol
			got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
			f := only(t, got, "images.policy")
			wantSeverity(t, f, SeverityWarn)
			if strings.Contains(f.Message, "deny-by-default") {
				t.Errorf("%+v was called deny-by-default: %q", pol, f.Message)
			}
		}
		cfg := hubCfg()
		cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{AllowedRegistries: []string{"ghcr.io"}}
		wantSeverity(t, only(t, findingsFor(t, t.TempDir(), cfg, Options{Offline: true}), "images.policy"),
			SeverityPass)
	})

	t.Run("a cosign key nobody can read verifies nothing", func(t *testing.T) {
		cfg := hubCfg()
		cfg.Executors.Container.Enabled = true
		cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{
			AllowedRegistries: []string{"ghcr.io"},
			RequireSignature:  true,
			CosignPublicKeys:  []string{filepath.Join(t.TempDir(), "absent.pub")},
		}
		got := findingsFor(t, t.TempDir(), cfg, Options{
			Offline:  true,
			LookPath: func(string) (string, error) { return "/usr/bin/cosign", nil },
		})
		f := only(t, got, "images.signature")
		wantSeverity(t, f, SeverityFail)
		if !strings.Contains(f.Message, "every project image is refused") {
			t.Errorf("want the consequence, got %q", f.Message)
		}
	})

	t.Run("a KMS key is cosign's to resolve", func(t *testing.T) {
		cfg := hubCfg()
		cfg.Executors.Container.Enabled = true
		cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{
			AllowedRegistries: []string{"ghcr.io"},
			RequireSignature:  true,
			CosignPublicKeys:  []string{"awskms:///arn:aws:kms:eu-west-1:000000000000:key/x", "k8s://cloop/cosign"},
		}
		got := findingsFor(t, t.TempDir(), cfg, Options{
			Offline:  true,
			LookPath: func(string) (string, error) { return "/usr/bin/cosign", nil },
		})
		wantSeverity(t, only(t, got, "images.signature"), SeverityPass)
	})

	// A device in container mode runs the images projects name; the hub
	// checks them against the allowlists before dispatch, and no device
	// verifies a signature.
	t.Run("devices whose sandbox runs a container run project images", func(t *testing.T) {
		// Host mode runs no image, so the policy decides nothing a device
		// in it runs.
		dir := t.TempDir()
		seedEnrolledAgent(t, dir, "edge-01")
		cfg := hubCfg()
		got := findingsFor(t, dir, cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "images.policy"), SeverityPass)

		setDeviceSandbox(t, dir, "edge-01", executor.SandboxSettings{Mode: executor.SandboxModeContainer, Image: "alpine:3"})
		got = findingsFor(t, dir, cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "images.policy"), SeverityWarn)

		cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{
			AllowedRegistries: []string{"ghcr.io"},
			RequireSignature:  true,
			CosignPublicKeys:  []string{"/etc/cloop/cosign.pub"},
		}
		got = findingsFor(t, dir, cfg, Options{Offline: true})
		f := only(t, got, "images.signature")
		wantSeverity(t, f, SeverityWarn)
		if !strings.Contains(f.Message, "no device verifies a signature") {
			t.Errorf("want the device gap named, got %q", f.Message)
		}
	})
}

// TestRegistryProbesAreThePolicysRegistries: the registries probed are the
// ones imagepolicy reads out of the policy. "acme/tools" names a repository on
// an allowed registry, not a registry called acme — the doctor used to probe
// https://acme/v2/ and fail the hub (Task 20387).
func TestRegistryProbesAreThePolicysRegistries(t *testing.T) {
	var probed []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		probed = append(probed, r.URL.Host)
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody, Request: r}, nil
	})}
	cfg := hubCfg()
	cfg.UI.OIDC.Enabled = false
	cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{
		AllowedRegistries: []string{"ghcr.io", "docker.io"},
		AllowedRepos:      []string{"acme/tools", "quay.io/org/img"},
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{HTTPClient: client})
	sort.Strings(probed)
	want := []string{"ghcr.io", "quay.io", "registry-1.docker.io"}
	if strings.Join(probed, ",") != strings.Join(want, ",") {
		t.Errorf("probed %v, want %v", probed, want)
	}
	for _, f := range got["images.registry"] {
		wantSeverity(t, f, SeverityPass)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// setDeviceSandbox records a device's sandbox settings the way the Executors
// panel does, with the device's executor row beside it.
func setDeviceSandbox(t *testing.T, dir, id string, s executor.SandboxSettings) {
	t.Helper()
	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: id, Name: id, Kind: executor.KindRemoteAgent,
		Status: statedb.ExecutorStatusOnline, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
	if err := db.SetExecutorSandbox(id, s, "test"); err != nil {
		t.Fatalf("SetExecutorSandbox: %v", err)
	}
}

// seedEnrolledAgent stores an enrolled, unrevoked agent the way enrollment does.
func seedEnrolledAgent(t *testing.T, dir, name string) {
	t.Helper()
	db, err := statedb.Open(mustInitStateDB(t, dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	store, err := executorstore.New(db)
	if err != nil {
		t.Fatalf("executorstore.New: %v", err)
	}
	if err := store.PutAgent(remote.AgentRecord{AgentID: name, Name: name, SecretHash: "00",
		CreatedAt: time.Now()}); err != nil {
		t.Fatalf("PutAgent: %v", err)
	}
}

// TestRegistryReachability: an authenticated registry challenging an anonymous
// probe proves reachability, so 401 is a pass and unreachable is a failure.
func TestRegistryReachability(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	cfg := hubCfg()
	cfg.UI.OIDC.Enabled = false
	cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{AllowedRegistries: []string{host}}

	// The probe dials https://<host>/v2/ and this server speaks plaintext, so
	// the connection fails: the assertion is that an unreachable registry is a
	// failure rather than silence.
	got := findingsFor(t, t.TempDir(), cfg, Options{Timeout: time.Second})
	fs := got["images.registry"]
	if len(fs) != 1 {
		t.Fatalf("want one registry finding, got %d", len(fs))
	}
	wantSeverity(t, fs[0], SeverityFail)
	if fs[0].Remediation == "" {
		t.Error("an unreachable registry must carry a remediation")
	}
}

// ── Executors ───────────────────────────────────────────────────────────────

// TestStrictModeWithNoIsolatingExecutorFails reproduces the deployment hole:
// correct refusals, green process, nothing can run.
func TestStrictModeWithNoIsolatingExecutorFails(t *testing.T) {
	prev := executor.SetAllowHostExecution(false)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })
	if len(executor.IsolatedIDs()) > 0 {
		t.Skip("another test left an isolating executor in the default registry")
	}

	got := findingsFor(t, t.TempDir(), hubCfg(), Options{Offline: true})
	f := only(t, got, "executors.available")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Remediation, "enroll") {
		t.Errorf("the remediation must name enrollment as a way out: %q", f.Remediation)
	}
}

// TestPermissiveModeReportsCapabilities: the capability report is the point,
// so it must be populated rather than an empty map.
func TestExecutorCapabilityReport(t *testing.T) {
	prev := executor.SetAllowHostExecution(true)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })

	cfg := hubCfg()
	cfg.Executors.SetHostProcessAllowed(true)

	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	if len(got["executors.health"]) == 0 {
		t.Skip("no executor registered in this process")
	}
	for _, f := range got["executors.health"] {
		for _, key := range []string{"kind", "isolation", "workspace", "write_back"} {
			if _, ok := f.Details[key]; !ok {
				t.Errorf("%s: capability report is missing %q: %v", f.Title, key, f.Details)
			}
		}
	}
}

// ── Storage ─────────────────────────────────────────────────────────────────

// TestSchemaAheadOfBinaryFails is the rollback case: a database written by a
// newer cloop that this one will fail on, at some later and unrelated moment.
func TestStorageSchemaChecks(t *testing.T) {
	t.Run("no database yet", func(t *testing.T) {
		got := findingsFor(t, t.TempDir(), hubCfg(), Options{Offline: true})
		wantSeverity(t, only(t, got, "storage.database"), SeverityWarn)
		if len(got["storage.schema"]) != 0 {
			t.Error("the schema check must not run without a database")
		}
	})

	t.Run("freshly migrated database", func(t *testing.T) {
		dir := t.TempDir()
		mustInitStateDB(t, dir)
		got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
		wantSeverity(t, only(t, got, "storage.integrity"), SeverityPass)
		wantSeverity(t, only(t, got, "storage.schema"), SeverityPass)
	})

	t.Run("schema written by a newer binary", func(t *testing.T) {
		dir := t.TempDir()
		mustInitStateDB(t, dir)
		recordFutureMigration(t, dir)
		got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
		f := only(t, got, "storage.schema")
		wantSeverity(t, f, SeverityFail)
		if !strings.Contains(f.Message, "ahead") {
			t.Errorf("the message must say the database is ahead: %q", f.Message)
		}
		// The diagnosis has to point at an image tag, not just a number —
		// otherwise the operator knows they are stuck but not what to deploy.
		if !strings.Contains(f.Message, futureBuild) {
			t.Errorf("the message must name the build that applied the newer schema: %q", f.Message)
		}
		if !strings.Contains(f.Remediation, statedb.EnvAllowSchemaDowngrade) {
			t.Errorf("the remediation must offer the opt-out: %q", f.Remediation)
		}
		// Details carry both numbers for anything parsing --json.
		if f.Details["db_version"] == nil || f.Details["binary_version"] == nil {
			t.Errorf("details must carry both versions: %+v", f.Details)
		}
		// The guard is on, so the guard finding must be absent.
		if len(got["storage.schema_guard"]) != 0 {
			t.Error("storage.schema_guard reported while the guard is enabled")
		}
	})

	// The schema check has to keep working on the one database the hub itself
	// refuses to open, or `cloop hub doctor` becomes useless exactly when an
	// operator needs it (Task 20226). The subtest above already proves it —
	// this one states why, by asserting the hub would in fact refuse.
	t.Run("the hub refuses what the doctor can still read", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := mustInitStateDB(t, dir)
		recordFutureMigration(t, dir)

		if _, err := statedb.Open(dbPath); !errors.Is(err, statedb.ErrSchemaTooNew) {
			t.Fatalf("statedb.Open: want ErrSchemaTooNew, got %v", err)
		}
		got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
		f := only(t, got, "storage.schema")
		if strings.Contains(f.Message, "could not open") {
			t.Errorf("the doctor fell back to a generic open failure: %q", f.Message)
		}
	})
}

// TestSchemaGuardOptOutIsItselfReported: an exemption nobody can see outlives
// its reason. Setting CLOOP_ALLOW_SCHEMA_DOWNGRADE must show up in the
// diagnosis — as a warning on its own, as a failure when it is actually
// suppressing a live skew.
func TestSchemaGuardOptOutIsItselfReported(t *testing.T) {
	t.Run("set with matching schemas", func(t *testing.T) {
		t.Setenv(statedb.EnvAllowSchemaDowngrade, "1")
		dir := t.TempDir()
		mustInitStateDB(t, dir)
		got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
		wantSeverity(t, only(t, got, "storage.schema"), SeverityPass)
		wantSeverity(t, only(t, got, "storage.schema_guard"), SeverityWarn)
	})

	// The hub's guard opens a database ahead only by migrations recorded as
	// additive; the doctor failed it anyway, and told the operator to roll
	// forward or restore a backup (Task 20387).
	t.Run("ahead only by an additive migration", func(t *testing.T) {
		t.Setenv(statedb.EnvAllowSchemaDowngrade, "")
		dir := t.TempDir()
		mustInitStateDB(t, dir)
		recordFutureAdditiveMigration(t, dir)
		if err := statedb.CheckSchemaAhead(filepath.Join(dir, ".cloop", "state.db")); err != nil {
			t.Fatalf("premise: the guard opens this database: %v", err)
		}
		got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
		f := only(t, got, "storage.schema")
		wantSeverity(t, f, SeverityPass)
		if !strings.Contains(f.Message, "additive") {
			t.Errorf("the pass should say why the guard opens it: %q", f.Message)
		}
	})

	t.Run("set while the database is ahead", func(t *testing.T) {
		t.Setenv(statedb.EnvAllowSchemaDowngrade, "1")
		dir := t.TempDir()
		mustInitStateDB(t, dir)
		recordFutureMigration(t, dir)
		got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
		f := only(t, got, "storage.schema_guard")
		wantSeverity(t, f, SeverityFail)
		if !strings.Contains(f.Message, "does not fully know") {
			t.Errorf("the message must say the hub is running on an unknown schema: %q", f.Message)
		}
	})

	t.Run("unset", func(t *testing.T) {
		t.Setenv(statedb.EnvAllowSchemaDowngrade, "")
		dir := t.TempDir()
		mustInitStateDB(t, dir)
		got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
		if len(got["storage.schema_guard"]) != 0 {
			t.Error("storage.schema_guard reported while the guard is enabled")
		}
	})
}

// ── Admission ───────────────────────────────────────────────────────────────

func TestAdmissionChecks(t *testing.T) {
	t.Run("multi-tenant with no quotas", func(t *testing.T) {
		got := findingsFor(t, t.TempDir(), hubCfg(), Options{Offline: true})
		wantSeverity(t, only(t, got, "quotas.policy"), SeverityWarn)
		wantSeverity(t, only(t, got, "budget.limits"), SeverityWarn)
	})

	t.Run("single-tenant with no quotas", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.OIDC.Enabled = false
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "quotas.policy"), SeverityPass)
		wantSeverity(t, only(t, got, "budget.limits"), SeverityPass)
	})

	// Judged as quota.New holds the policy: a negative ceiling is unlimited
	// and dropped, so this block is no policy at all — it used to pass as
	// "1 default limit(s)" (Task 20387).
	t.Run("a policy of unlimited ceilings is no policy", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.Quotas = config.QuotasConfig{Defaults: map[string]float64{"max_concurrent_tasks": -1}}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "quotas.policy"), SeverityWarn)
	})

	t.Run("a policy of max_sessions: 0 alone bounds nothing", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.Quotas = config.QuotasConfig{Defaults: map[string]float64{"max_sessions": 0}}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "quotas.policy"), SeverityWarn)
	})

	// The hub reads max_sessions: 0 as no cap (quota.SessionCap), so there is
	// no refusal to warn about.
	t.Run("zero sessions is no cap, not a refusal", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.Quotas = config.QuotasConfig{Defaults: map[string]float64{"max_sessions": 0, "max_projects": 3}}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		if fs := got["quotas.zero_limits"]; len(fs) != 0 {
			t.Errorf("warned about a zero the hub reads as unlimited: %+v", fs)
		}
	})

	// budget.EffectiveLimits is what a run is held to: monthly_usd is not in
	// it, and the host-wide caps are.
	t.Run("monthly_usd alone bounds nothing", func(t *testing.T) {
		cfg := hubCfg()
		cfg.Budget.MonthlyUSD = 500
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		f := only(t, got, "budget.limits")
		wantSeverity(t, f, SeverityWarn)
		if !strings.Contains(f.Message, "enforced nowhere") {
			t.Errorf("the message should say monthly_usd is not enforced: %q", f.Message)
		}
	})
	// budget.Enforce runs inside `cloop run`, which on an isolating executor
	// is the sandboxed workload: the host-wide caps in ~/.config/cloop do not
	// reach it, so they bound only host runs, and say so.
	t.Run("a host-wide cap holds back host runs only", func(t *testing.T) {
		got := findingsFor(t, t.TempDir(), hubCfg(), Options{Offline: true,
			GlobalBudget: func() (globalbudget.GlobalBudgetConfig, error) {
				return globalbudget.GlobalBudgetConfig{DailyUSDLimit: 20}, nil
			}})
		f := only(t, got, "budget.limits")
		wantSeverity(t, f, SeverityWarn)
		if !strings.Contains(f.Message, "an isolated run is not given them") {
			t.Errorf("the message should say where the host-wide cap applies: %q", f.Message)
		}
	})
	t.Run("a project cap holds every run back", func(t *testing.T) {
		cfg := hubCfg()
		cfg.Budget.DailyUSDLimit = 25
		wantSeverity(t, only(t, findingsFor(t, t.TempDir(), cfg, Options{Offline: true}), "budget.limits"),
			SeverityPass)
	})
	// Runs read config.yaml, never an overlay, so a budget the merged view
	// carries and config.yaml does not holds nothing back.
	t.Run("a budget runs never read is no budget", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(config.ConfigPath(dir), []byte("provider: claudecode\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := hubCfg()
		cfg.Budget.DailyUSDLimit = 25 // as if from config.ui-<port>.yaml
		wantSeverity(t, only(t, findingsFor(t, dir, cfg, Options{Offline: true}), "budget.limits"), SeverityWarn)
	})

	t.Run("zero means none allowed, not unlimited", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.Quotas = config.QuotasConfig{Defaults: map[string]float64{"max_projects": 0}}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "quotas.zero_limits"), SeverityWarn)
	})

	// quota.New rejects a binding with no limits, so it is an invalid policy
	// rather than a hygiene warning.
	t.Run("binding with no limits", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.Quotas = config.QuotasConfig{
			Defaults: map[string]float64{"max_projects": 3},
			Bindings: []config.QuotaBinding{{Claim: "group", Value: "eng"}},
		}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "quotas.policy"), SeverityFail)
	})

	t.Run("unknown resource", func(t *testing.T) {
		cfg := hubCfg()
		cfg.UI.Quotas = config.QuotasConfig{Defaults: map[string]float64{"max_widgets": 5}}
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "quotas.policy"), SeverityFail)
	})
}

// ── Execution policy ────────────────────────────────────────────────────────

func TestExecutionPolicyFinding(t *testing.T) {
	t.Run("unset is permissive and says so", func(t *testing.T) {
		got := findingsFor(t, t.TempDir(), config.Default(), Options{Offline: true})
		f := only(t, got, "policy.host_execution")
		wantSeverity(t, f, SeverityWarn)
		if !strings.Contains(f.Message, "unset") {
			t.Errorf("unset must be distinguished from an explicit true: %q", f.Message)
		}
	})
	t.Run("explicitly permissive", func(t *testing.T) {
		cfg := config.Default()
		cfg.Executors.SetHostProcessAllowed(true)
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "policy.host_execution"), SeverityWarn)
	})
	t.Run("strict", func(t *testing.T) {
		got := findingsFor(t, t.TempDir(), hubCfg(), Options{Offline: true})
		wantSeverity(t, only(t, got, "policy.host_execution"), SeverityPass)
	})
}

func TestNilConfigIsDiagnosedNotFatal(t *testing.T) {
	rep := Run(context.Background(), t.TempDir(), nil, Options{Offline: true})
	if len(rep.Findings) != 1 {
		t.Fatalf("want a single finding for a missing config, got %d", len(rep.Findings))
	}
	wantSeverity(t, rep.Findings[0], SeverityFail)
	if rep.ExitCode() != 1 {
		t.Error("a hub with no readable config must fail the command")
	}
}

// TestForwardedProtoIsRequiredOnlyWhereTheCookieFollowsTheRequest: the session
// cookie's Secure flag comes from X-Forwarded-Proto only when cookie_secure is
// auto or unset (oidcauth.CookieSecureFollowsRequest); with always or never the
// header changes nothing, and the doctor used to say it was required anyway.
func TestForwardedProtoIsRequiredOnlyWhereTheCookieFollowsTheRequest(t *testing.T) {
	for mode, want := range map[string]bool{"": true, "auto": true, "always": false, "never": false} {
		cfg := hubCfg()
		cfg.UI.OIDC.CookieSecure = mode
		f := only(t, findingsFor(t, t.TempDir(), cfg, Options{Offline: true}), "tls.termination")
		if _, got := f.Details["requires"]; got != want {
			t.Errorf("cookie_secure %q: requires-detail present=%v, want %v", mode, got, want)
		}
	}
}
