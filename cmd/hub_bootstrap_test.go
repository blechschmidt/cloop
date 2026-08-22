package cmd

// The property under test throughout: `cloop hub bootstrap` renders commented
// YAML from a text template rather than marshalling a struct, which buys
// readability and costs a compile-time guarantee. A field rename in
// pkg/config cannot break the template, so these tests are what stands in for
// the type checker — they load the rendered file back and assert the security
// settings survived the round trip as values, not as text.

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/config"
)

// bootstrapInto runs the command against dir and returns the loaded config.
func bootstrapInto(t *testing.T, dir string, args ...string) *config.Config {
	t.Helper()
	if err := runBootstrap(t, dir, args...); err != nil {
		t.Fatalf("hub bootstrap: %v", err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("config.Load of the generated file: %v", err)
	}
	return cfg
}

// runBootstrap invokes the command with a fresh flag set so tests do not leak
// flag state into each other.
func runBootstrap(t *testing.T, dir string, args ...string) error {
	t.Helper()
	cmd := &cobra.Command{Use: "bootstrap", RunE: runHubBootstrap, SilenceErrors: true}
	registerHubBootstrapFlags(cmd)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append([]string{"--dir", dir}, args...))
	return cmd.Execute()
}

func TestHubBootstrap_GeneratesAConfigThatLoads(t *testing.T) {
	dir := t.TempDir()
	cfg := bootstrapInto(t, dir, "--external-url", "https://hub.example.com")

	// The whole point of the hosted profile.
	if cfg.Executors.HostProcessAllowed() {
		t.Error("host execution is allowed; bootstrap must disable it")
	}
	if !cfg.Executors.HostProcessExplicit() {
		t.Error("allow_host_process is unset rather than explicitly false — " +
			"the Executors tab reports those differently and only one is hardened")
	}
	if got, want := cfg.UI.OIDC.DefaultRole, "none"; got != want {
		t.Errorf("default_role = %q, want %q (deny-by-default)", got, want)
	}
	if got, want := cfg.UI.ExternalURL, "https://hub.example.com"; got != want {
		t.Errorf("external_url = %q, want %q", got, want)
	}
	if len(cfg.UI.AllowedWSOrigins) != 1 || cfg.UI.AllowedWSOrigins[0] != "https://hub.example.com" {
		t.Errorf("allowed_ws_origins = %v, want the external URL pinned", cfg.UI.AllowedWSOrigins)
	}
	if cfg.UI.OIDC.CookieSecure != "always" {
		t.Errorf("cookie_secure = %q, want always", cfg.UI.OIDC.CookieSecure)
	}
	if err := config.ValidateExecutors(cfg.Executors); err != nil {
		t.Errorf("generated executors section is invalid: %v", err)
	}
}

func TestHubBootstrap_WritesSecretsSeparatelyAt0600(t *testing.T) {
	dir := t.TempDir()
	if err := runBootstrap(t, dir); err != nil {
		t.Fatalf("hub bootstrap: %v", err)
	}

	envPath := filepath.Join(dir, ".cloop", hubEnvFile)
	body, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read hub.env: %v", err)
	}

	key := envValue(string(body), "CLOOP_SECRET_KEY")
	if len(key) < 40 {
		t.Errorf("CLOOP_SECRET_KEY = %q, want 32 random bytes base64url-encoded", key)
	}
	if tok := envValue(string(body), "CLOOP_UI_TOKEN"); len(tok) < 40 {
		t.Errorf("CLOOP_UI_TOKEN = %q, want a generated token — an unauthenticated hub is not secure-by-default", tok)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(envPath)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("hub.env mode = %#o, want 0600", perm)
		}
	}

	// The master key must not also be in the config, which is the file
	// operators commit and template.
	cfgBody, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfgBody), key) {
		t.Error("the secret-broker key leaked into config.yaml")
	}
}

// Two runs must not produce the same key material.
func TestHubBootstrap_KeysAreNotDeterministic(t *testing.T) {
	read := func() string {
		dir := t.TempDir()
		if err := runBootstrap(t, dir); err != nil {
			t.Fatalf("hub bootstrap: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(dir, ".cloop", hubEnvFile))
		if err != nil {
			t.Fatal(err)
		}
		return envValue(string(b), "CLOOP_SECRET_KEY")
	}
	if a, b := read(), read(); a == b {
		t.Fatal("two bootstraps produced the same CLOOP_SECRET_KEY")
	}
}

func TestHubBootstrap_OIDCWiring(t *testing.T) {
	dir := t.TempDir()
	cfg := bootstrapInto(t, dir,
		"--external-url", "https://hub.example.com",
		"--oidc-issuer", "https://idp.example.com/realms/main/",
		"--oidc-client-id", "cloop-hub",
		"--admin-email", "a@example.com",
		"--admin-email", "b@example.com")

	if !cfg.UI.OIDC.Enabled {
		t.Error("oidc.enabled is false despite an issuer being supplied")
	}
	// The trailing slash must be trimmed: discovery appends
	// /.well-known/openid-configuration and a double slash 404s at some IdPs.
	if got, want := cfg.UI.OIDC.Issuer, "https://idp.example.com/realms/main"; got != want {
		t.Errorf("issuer = %q, want %q", got, want)
	}
	if got, want := cfg.UI.OIDC.RedirectURL, "https://hub.example.com/auth/callback"; got != want {
		t.Errorf("redirect_url = %q, want %q", got, want)
	}
	if len(cfg.UI.OIDC.AdminEmails) != 2 {
		t.Errorf("admin_emails = %v, want both addresses", cfg.UI.OIDC.AdminEmails)
	}
	// Even with SSO on, an unmatched user gets nothing.
	if cfg.UI.OIDC.DefaultRole != "none" {
		t.Errorf("default_role = %q, want none", cfg.UI.OIDC.DefaultRole)
	}
	if cfg.UI.OIDC.ClientSecret != "" {
		t.Error("a client secret was written into config.yaml; it must come from the environment")
	}
}

func TestHubBootstrap_OIDCIssuerWithoutClientIDIsRefused(t *testing.T) {
	err := runBootstrap(t, t.TempDir(), "--oidc-issuer", "https://idp.example.com")
	if err == nil {
		t.Fatal("accepted an issuer with no client ID")
	}
	if !strings.Contains(err.Error(), "client-id") {
		t.Errorf("error does not name the missing flag: %v", err)
	}
}

func TestHubBootstrap_BehindProxyLeavesTLSToTheProxy(t *testing.T) {
	dir := t.TempDir()
	cfg := bootstrapInto(t, dir, "--behind-proxy", "--external-url", "https://hub.example.com")

	if cfg.UI.TLS.CertFile != "" || cfg.UI.TLS.KeyFile != "" {
		t.Errorf("ui.tls = %+v, want empty when the proxy terminates TLS", cfg.UI.TLS)
	}
	// The header requirement is the whole risk of this mode, so the generated
	// file has to say so.
	body, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "X-Forwarded-Proto") {
		t.Error("the generated config does not mention X-Forwarded-Proto, " +
			"which the proxy must set for the session cookie to be Secure")
	}
}

func TestHubBootstrap_BehindProxyConflictsWithTLSPaths(t *testing.T) {
	err := runBootstrap(t, t.TempDir(), "--behind-proxy", "--tls-cert", "/etc/tls/cert.pem")
	if err == nil {
		t.Fatal("accepted --behind-proxy together with --tls-cert")
	}
}

func TestHubBootstrap_DefaultTLSPathsAreUnderTheStateDir(t *testing.T) {
	dir := t.TempDir()
	cfg := bootstrapInto(t, dir)

	wantCert := filepath.Join(dir, ".cloop", "tls", "cert.pem")
	if cfg.UI.TLS.CertFile != wantCert {
		t.Errorf("cert_file = %q, want %q", cfg.UI.TLS.CertFile, wantCert)
	}
	if cfg.UI.TLS.MinVersion == "" {
		t.Error("min_version is unset; the hub would accept whatever Go defaults to")
	}
}

// Plain http off-loopback would put the session cookie, the bearer token and
// the OIDC authorization code on the wire in the clear.
func TestHubBootstrap_RefusesPlaintextOnANonLoopbackHost(t *testing.T) {
	err := runBootstrap(t, t.TempDir(), "--external-url", "http://hub.example.com")
	if err == nil {
		t.Fatal("accepted a plain-http external URL on a public host")
	}
	if !strings.Contains(err.Error(), "clear") {
		t.Errorf("error does not explain the exposure: %v", err)
	}

	// Loopback is the development case and stays allowed.
	if err := runBootstrap(t, t.TempDir(), "--external-url", "http://localhost:8080"); err != nil {
		t.Errorf("refused http on localhost: %v", err)
	}
}

func TestHubBootstrap_RejectsMalformedExternalURL(t *testing.T) {
	for _, bad := range []string{"hub.example.com", "ftp://hub.example.com", "https://"} {
		if err := runBootstrap(t, t.TempDir(), "--external-url", bad); err == nil {
			t.Errorf("accepted external URL %q", bad)
		}
	}
}

// Re-bootstrapping over a live deployment would mint a new master key, and a
// new key cannot open payloads sealed with the old one. Refusing is the only
// safe default because the damage is not reversible.
func TestHubBootstrap_RefusesToClobberWithoutForce(t *testing.T) {
	dir := t.TempDir()
	if err := runBootstrap(t, dir); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, ".cloop", hubEnvFile))
	if err != nil {
		t.Fatal(err)
	}

	err = runBootstrap(t, dir)
	if err == nil {
		t.Fatal("second bootstrap overwrote an existing deployment")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error does not name the escape hatch: %v", err)
	}

	after, err := os.ReadFile(filepath.Join(dir, ".cloop", hubEnvFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the refused bootstrap still modified hub.env")
	}

	if err := runBootstrap(t, dir, "--force"); err != nil {
		t.Fatalf("--force bootstrap: %v", err)
	}
	forced, err := os.ReadFile(filepath.Join(dir, ".cloop", hubEnvFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(forced) == string(before) {
		t.Error("--force did not regenerate the key material")
	}
}

func TestHubBootstrap_SystemdUnitConfinesTheHub(t *testing.T) {
	o := &hubBootstrapOpts{
		Dir:         "/srv/cloop",
		CloopDir:    "/srv/cloop/.cloop",
		Port:        8080,
		ServiceUser: "cloop",
	}
	unit := systemdUnit(o)

	// Each of these is the systemd equivalent of something the container
	// image gets for free, and the unit is the only place a bare-metal
	// deployment gets it at all.
	for _, want := range []string{
		"User=cloop",
		"WorkingDirectory=/srv/cloop",
		"EnvironmentFile=/srv/cloop/.cloop/hub.env",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"CapabilityBoundingSet=",
		"ReadWritePaths=/srv/cloop/.cloop",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("systemd unit is missing %q", want)
		}
	}
	// ProtectSystem=strict without a ReadWritePaths for the state directory
	// produces a hub that starts and cannot write, so the two must travel
	// together.
	if strings.Contains(unit, "ProtectSystem=strict") && !strings.Contains(unit, "ReadWritePaths=") {
		t.Error("ProtectSystem=strict with no ReadWritePaths: the hub could not write its database")
	}
}

// envValue reads KEY=value out of an env file, ignoring comments.
func envValue(body, key string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	return ""
}
