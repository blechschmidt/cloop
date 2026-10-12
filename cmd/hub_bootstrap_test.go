package cmd

// The property under test throughout: `cloop hub bootstrap` renders commented
// YAML from a text template rather than marshalling a struct, which buys
// readability and costs a compile-time guarantee. A field rename in
// pkg/config cannot break the template, so these tests are what stands in for
// the type checker — they load the rendered file back and assert the security
// settings survived the round trip as values, not as text.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/rootkey"
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

	// The root key is in a file of its own, beside .cloop/ and not in the
	// environment file (Task 20425).
	key := readKeyFile(t, filepath.Join(dir, hubKeyFile))
	if len(key) < 40 {
		t.Errorf("the root key = %q, want 32 random bytes base64url-encoded", key)
	}
	if v := envValue(string(body), "CLOOP_SECRET_KEY"); v != "" || strings.Contains(string(body), key) {
		t.Error("the root key is in hub.env, where it ends up in the hub's environment")
	}
	if !strings.Contains(string(body), filepath.Join(dir, hubKeyFile)) {
		t.Error("hub.env does not say where the root key went")
	}
	if tok := envValue(string(body), "CLOOP_UI_TOKEN"); len(tok) < 40 {
		t.Errorf("CLOOP_UI_TOKEN = %q, want a generated token — an unauthenticated hub is not secure-by-default", tok)
	}

	if runtime.GOOS != "windows" {
		for _, p := range []string{envPath, filepath.Join(dir, hubKeyFile)} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if perm := fi.Mode().Perm(); perm != 0o600 {
				t.Errorf("%s mode = %#o, want 0600", filepath.Base(p), perm)
			}
		}
	}

	// The hub reads the file it was given exactly as written.
	t.Setenv(rootkey.EnvKey, "")
	t.Setenv(rootkey.EnvKeyFile, filepath.Join(dir, hubKeyFile))
	roots, err := rootkey.Resolve()
	if err != nil {
		t.Fatalf("the hub would refuse the key file bootstrap wrote: %v", err)
	}
	if roots.Current.Value != key || roots.Current.Source != rootkey.SourceFile {
		t.Errorf("resolved %s, want the key file's key", roots.Current.Describe())
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
		return readKeyFile(t, filepath.Join(dir, hubKeyFile))
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
	keyBefore := readKeyFile(t, filepath.Join(dir, hubKeyFile))

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
	if readKeyFile(t, filepath.Join(dir, hubKeyFile)) != keyBefore {
		t.Error("the refused bootstrap still replaced the root key")
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
	if readKeyFile(t, filepath.Join(dir, hubKeyFile)) == keyBefore {
		t.Error("--force did not regenerate the root key")
	}
}

// A key file left by an earlier bootstrap is a deployment too: a bootstrap
// that kept the config but replaced the key would leave every sealed secret
// unopenable.
func TestHubBootstrap_RefusesToReplaceAKeyFileWithoutForce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, hubKeyFile), []byte("an existing key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runBootstrap(t, dir); err == nil || !strings.Contains(err.Error(), hubKeyFile) {
		t.Fatalf("bootstrap over an existing key file: %v", err)
	}
	if got := readKeyFile(t, filepath.Join(dir, hubKeyFile)); got != "an existing key" {
		t.Errorf("the key file now holds %q", got)
	}
}

// The hub refuses a key file inside .cloop/, so bootstrap refuses to write one
// there rather than produce a hub that will not start.
func TestHubBootstrap_RefusesAKeyFileInsideTheStateDir(t *testing.T) {
	dir := t.TempDir()
	err := runBootstrap(t, dir, "--key-file", filepath.Join(dir, ".cloop", "key"))
	if err == nil || !strings.Contains(err.Error(), ".cloop/") {
		t.Fatalf("bootstrap with a key file inside .cloop/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop", "key")); err == nil {
		t.Error("the key was written anyway")
	}
}

// Where systemd-creds can encrypt it, the key is only ever written encrypted,
// and the unit loads it with LoadCredentialEncrypted=.
func TestHubBootstrap_EncryptsTheKeyWithSystemdCreds(t *testing.T) {
	var sealed []byte
	stubSystemdCreds(t, func(name string, key []byte, path string) error {
		if name != rootkey.Credential {
			t.Errorf("credential name %q, want %q", name, rootkey.Credential)
		}
		sealed = append([]byte(nil), key...)
		return os.WriteFile(path, []byte("Whxqht+dQJax1aZeCGLxmiAAAAABAAAADAAAABAAAAB-encrypted"), 0o600)
	})
	dir := t.TempDir()
	if err := runBootstrap(t, dir); err != nil {
		t.Fatalf("hub bootstrap: %v", err)
	}
	if len(sealed) < 40 {
		t.Fatalf("systemd-creds was given %q", sealed)
	}
	if _, err := os.Stat(filepath.Join(dir, hubKeyFile)); err == nil {
		t.Error("a plaintext key file was written beside the credential")
	}
	cred := filepath.Join(dir, hubKeyFile+hubKeyCredSuffix)
	if _, err := os.Stat(cred); err != nil {
		t.Fatalf("no credential: %v", err)
	}
	env, _ := os.ReadFile(filepath.Join(dir, ".cloop", hubEnvFile))
	if !strings.Contains(string(env), cred) || strings.Contains(string(env), string(sealed)) {
		t.Error("hub.env does not point at the credential, or holds the key")
	}
	o := &hubBootstrapOpts{Dir: dir, CloopDir: filepath.Join(dir, ".cloop"), Port: 8080, ServiceUser: "cloop",
		KeyFile: filepath.Join(dir, hubKeyFile), KeyEncrypted: true}
	if unit := systemdUnit(o); !strings.Contains(unit, "LoadCredentialEncrypted="+rootkey.Credential+":"+cred) {
		t.Errorf("the unit does not load the credential:\n%s", unit)
	}
}

// --systemd-creds always means encrypted or nothing: a host that cannot is
// told so, and no plaintext key is left behind in its place.
func TestHubBootstrap_SystemdCredsAlwaysRefusesWhereItCannot(t *testing.T) {
	stubSystemdCreds(t, func(string, []byte, string) error { return errors.New("no TPM and no host key") })
	dir := t.TempDir()
	err := runBootstrap(t, dir, "--systemd-creds", "always")
	if err == nil || !strings.Contains(err.Error(), "no TPM and no host key") {
		t.Fatalf("--systemd-creds always on a host that cannot: %v", err)
	}
	for _, p := range []string{filepath.Join(dir, hubKeyFile), filepath.Join(dir, hubKeyFile+hubKeyCredSuffix)} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was written", p)
		}
	}
}

func stubSystemdCreds(t *testing.T, fn func(name string, key []byte, path string) error) {
	t.Helper()
	prev := systemdCredsEncrypt
	systemdCredsEncrypt = fn
	t.Cleanup(func() { systemdCredsEncrypt = prev })
}

// readKeyFile reads a key file as the hub does: one trailing newline is not
// part of the key.
func readKeyFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSuffix(string(b), "\n")
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
		// The root key as a credential, never an EnvironmentFile line.
		"LoadCredential=cloop-secret-key:/srv/cloop/cloop-secret-key",
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
