package hubdoctor

// Tests for the hub diagnosis.
//
// The load-bearing one is TestEveryNonPassCarriesRemediation: the whole premise
// of this command is that a finding names its own fix, and a finding that
// reports a problem and stops is the exact failure the command exists to
// remove. It is asserted across a fixture set chosen to make every check fire.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
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

	fixtures := []struct {
		name string
		cfg  *config.Config
	}{
		{"nil config", nil},
		{"default config", config.Default()},
		{"well-formed hub", hubCfg()},
		{"comprehensively broken", broken},
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

// TestOIDCDiscoveryAndJWKS drives the two network checks against a stand-in
// issuer, including the spec requirement that the document agree on its own
// issuer name.
func TestOIDCDiscoveryAndJWKS(t *testing.T) {
	cases := []struct {
		name        string
		issuerInDoc string // "" means: use the server's own URL
		jwks        string
		wantDisc    Severity
		wantJWKS    Severity
	}{
		{
			name:     "healthy",
			jwks:     `{"keys":[{"kid":"a","kty":"RSA","alg":"RS256","use":"sig"}]}`,
			wantDisc: SeverityPass, wantJWKS: SeverityPass,
		},
		{
			name:        "issuer disagrees with its own document",
			issuerInDoc: "https://somewhere-else.example.com",
			jwks:        `{"keys":[{"kid":"a","kty":"RSA"}]}`,
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
	t.Run("absent", func(t *testing.T) {
		t.Setenv(config.EnvOIDCClientSecret, "")
		got := findingsFor(t, t.TempDir(), hubCfg(), Options{Offline: true})
		wantSeverity(t, only(t, got, "oidc.client_secret"), SeverityFail)
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

	t.Run("the hub's own image would be refused", func(t *testing.T) {
		cfg := hubCfg()
		cfg.Sandbox.ImagePolicy = config.ImagePolicyConfig{
			AllowedRegistries: []string{"ghcr.io"},
			RequireDigest:     true,
		}
		cfg.Executors.Container.Enabled = true
		cfg.Executors.Container.Image = "docker.io/library/alpine:3"
		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		wantSeverity(t, only(t, got, "images.configured"), SeverityWarn)
	})
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
