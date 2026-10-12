package cmd

// hub_bootstrap.go turns "I want to host cloop" into a directory that is safe
// to point a process at.
//
// The problem it solves is not "writing YAML is hard". It is that every
// security control in this codebase is opt-in, and the defaults are the ones
// a single developer on a laptop wants: host execution allowed, no TLS, no
// authentication, no RBAC. Each of those is right for `cloop run` in a git
// checkout and wrong for a hub with users. An operator who starts from
// `config.Default()` and adds what they notice will end up with a hub that
// works and is open, because nothing about a working hub tells you the
// executor policy is permissive.
//
// So bootstrap inverts the default for a *hosted* deployment specifically:
// host execution off, deny-by-default RBAC, TLS paths filled in, a real
// secret-broker key generated rather than left to `export CLOOP_SECRET_KEY=
// hunter2`, and a bearer token minted so the dashboard is never briefly
// reachable by anyone who can route to the port.
//
// Two deliberate choices:
//
//   - The config is rendered as commented YAML rather than marshalled from
//     the struct. yaml.Marshal produces a correct file that explains nothing,
//     and the whole value of a bootstrap is that the operator can read what
//     was decided for them and change it. The rendered file is loaded back
//     and validated before the command reports success, so the comments
//     cannot drift into a file that does not parse.
//
//   - Secrets go into a separate .cloop/hub.env at 0600, not into config.yaml.
//     That file is directly consumable by systemd's EnvironmentFile= and by
//     `docker compose --env-file`, and keeping it separate means config.yaml
//     can be committed, diffed and templated without leaking a token.
//
//   - The root key is not one of them (Task 20425). It goes into a credential
//     file of its own beside .cloop/, never in it — encrypted by systemd-creds
//     where that works, so a TPM or the host's credential secret is needed to
//     read it — and the printed unit loads it with LoadCredential(Encrypted)=.
//     In an environment variable it would be in /proc/<pid>/environ, in
//     `systemctl show`, and in every child process not scrubbed of it; and in
//     .cloop/ it would travel with every backup and snapshot of the database
//     it protects.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/rootkey"
)

// hubEnvFile holds the generated secrets. Separate from config.yaml so the
// config can be version-controlled and this cannot.
const hubEnvFile = "hub.env"

// hubKeyFile is the root key's file in the hub's directory, beside .cloop/ —
// never in it, where the hub refuses to read a key from. Named like the systemd
// credential it is loaded as.
const hubKeyFile = rootkey.Credential

// hubKeyCredSuffix marks the systemd-creds encrypted form of the key file.
const hubKeyCredSuffix = ".cred"

// systemdCredsEncrypt seals key as the systemd credential name into path. A
// variable so tests stand in for systemd-creds, which creates the host's
// credential secret the first time it runs as root.
var systemdCredsEncrypt = func(name string, key []byte, path string) error {
	bin, err := exec.LookPath("systemd-creds")
	if err != nil {
		return fmt.Errorf("systemd-creds is not installed")
	}
	if fi, err := os.Stat("/run/systemd/system"); err != nil || !fi.IsDir() {
		return fmt.Errorf("systemd is not this host's init")
	}
	cmd := exec.Command(bin, "encrypt", "--name="+name, "-", path)
	cmd.Stdin = bytes.NewReader(key)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemd-creds encrypt: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return os.Chmod(path, 0o600)
}

var hubBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Generate a secure-by-default hub configuration",
	Long: `Create a .cloop directory configured for hosting, not for a laptop.

cloop's defaults are the single-developer ones: the host-process executor is
allowed, there is no TLS, no authentication and no RBAC. Each is correct for
` + "`cloop run`" + ` in a checkout and wrong for a hub other people reach.
Nothing about a *working* hub reveals that the executor policy is permissive,
so this command sets the hosted defaults explicitly rather than leaving them
to be noticed:

  executors.allow_host_process: false   no run ever forks on the hub host
  executors.git_proxy, kube_guard       on, tls: auto — forge and cluster
                                        credentials stay on the hub
  ui.oidc.default_role: none            deny-by-default; no claim, no access
  ui.tls.*                              TLS paths filled in and required
  ui.allowed_ws_origins                 WebSocket origin pinned to the URL
  CLOOP_SECRET_KEY                      256 bits from crypto/rand, in a key
                                        file beside .cloop/, never in it
  CLOOP_UI_TOKEN                        so the dashboard is never open

The git interception proxy and the Kubernetes access monitor are enabled with
tls: auto: the hub issues their certificates from a CA of its own, minted at
first start and sealed under CLOOP_SECRET_KEY, and tells every sandbox to trust
it for those two URLs only. Their advertise URLs are derived from
--external-url; executors must be able to reach both ports there.

The root key, CLOOP_SECRET_KEY, is written to its own file — --key-file,
cloop-secret-key in --dir by default — encrypted with systemd-creds when this
host can (--systemd-creds), so the printed unit loads it with
LoadCredentialEncrypted=; otherwise as a plain file, mode 0600, which the unit
loads with LoadCredential= and a shell names with CLOOP_SECRET_KEY_FILE. Never
an environment variable: those are readable in /proc/<pid>/environ.

The other secrets are written to .cloop/hub.env (mode 0600), never into
config.yaml — so the config can be committed and the env file cannot. The env
file is consumable as-is by systemd's EnvironmentFile= and by docker compose
--env-file.

Bootstrap does not start anything, does not touch an existing config unless
--force is given, and writes no certificate: pair it with ` + "`cloop hub tls-init`" + `
for development or point --tls-cert/--tls-key at a real one.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runHubBootstrap,
}

// hubBootstrapOpts is the resolved, validated flag set.
type hubBootstrapOpts struct {
	Dir         string
	CloopDir    string
	ExternalURL string
	Port        int
	// GitProxyPort and KubeGuardPort are where the two credential monitors
	// listen, and GitProxyURL and KubeGuardURL where sandboxes reach them:
	// --external-url's host on those ports.
	GitProxyPort  int
	KubeGuardPort int
	GitProxyURL   string
	KubeGuardURL  string
	TLSCert       string
	TLSKey        string
	BehindProxy   bool
	OIDCIssuer    string
	OIDCClient    string
	AdminEmails   []string
	ServiceUser   string
	Force         bool
	// KeyFile is where the root key is written; SystemdCreds is auto, always
	// or never, and KeyEncrypted says the file holds a systemd-creds
	// credential rather than the key.
	KeyFile      string
	SystemdCreds string
	KeyEncrypted bool
	// KeyNote says why an auto bootstrap did not encrypt the key.
	KeyNote string
}

func runHubBootstrap(cmd *cobra.Command, _ []string) error {
	opts, err := resolveHubBootstrapOpts(cmd)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(opts.CloopDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", opts.CloopDir, err)
	}

	configPath := config.ConfigPath(opts.Dir)
	envPath := filepath.Join(opts.CloopDir, hubEnvFile)

	// Refuse before generating anything. A partial bootstrap that replaced
	// the key but not the config would leave every sealed secret in the
	// store unopenable, which is a worse outcome than doing nothing.
	if !opts.Force {
		for _, p := range []string{configPath, envPath, opts.KeyFile, opts.KeyFile + hubKeyCredSuffix} {
			if _, statErr := os.Stat(p); statErr == nil {
				return fmt.Errorf("%s already exists.\n"+
					"Bootstrap generates a new root key, and a new root key "+
					"cannot derive the keys that opened the existing payloads.\n"+
					"To roll the sealing keys without re-minting anything, run "+
					"'cloop hub key rotate' instead; to change the root key itself, the runbook's "+
					"\"Changing CLOOP_SECRET_KEY itself\" does it online with "+
					"'cloop hub key rotate --retire-previous'.\n"+
					"Pass --force only if this deployment has no secrets worth keeping", p)
			}
		}
	}

	secretKey, err := randomToken(32)
	if err != nil {
		return fmt.Errorf("generate secret-broker key: %w", err)
	}
	uiToken, err := randomToken(32)
	if err != nil {
		return fmt.Errorf("generate dashboard token: %w", err)
	}

	rendered, err := renderHubConfig(opts)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(configPath, rendered, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", configPath, err)
	}
	if err := writeHubKey(opts, []byte(secretKey)); err != nil {
		return err
	}
	if err := atomicfile.Write(envPath, []byte(renderHubEnv(hubKeyPath(opts), uiToken)), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", envPath, err)
	}

	// Prove the rendered file is not just well-formed but acceptable. A
	// bootstrap that emits a config the very next `cloop ui` rejects is worse
	// than no bootstrap, because the operator now trusts it.
	loaded, err := config.Load(opts.Dir)
	if err != nil {
		return fmt.Errorf("the generated config at %s does not load — this is a bug in `cloop hub bootstrap`: %w",
			configPath, err)
	}
	if err := config.ValidateExecutors(loaded.Executors); err != nil {
		return fmt.Errorf("the generated config at %s is invalid — this is a bug in `cloop hub bootstrap`: %w",
			configPath, err)
	}

	printHubBootstrapSummary(opts, configPath, envPath, loaded)
	return nil
}

// resolveHubBootstrapOpts reads flags and applies the defaults that depend on
// each other (the redirect URL is derived from the external URL, the external
// URL's default is derived from the port).
func resolveHubBootstrapOpts(cmd *cobra.Command) (*hubBootstrapOpts, error) {
	o := &hubBootstrapOpts{}
	o.Dir, _ = cmd.Flags().GetString("dir")
	o.ExternalURL, _ = cmd.Flags().GetString("external-url")
	o.Port, _ = cmd.Flags().GetInt("port")
	o.GitProxyPort, _ = cmd.Flags().GetInt("git-proxy-port")
	o.KubeGuardPort, _ = cmd.Flags().GetInt("kube-guard-port")
	o.TLSCert, _ = cmd.Flags().GetString("tls-cert")
	o.TLSKey, _ = cmd.Flags().GetString("tls-key")
	o.BehindProxy, _ = cmd.Flags().GetBool("behind-proxy")
	o.OIDCIssuer, _ = cmd.Flags().GetString("oidc-issuer")
	o.OIDCClient, _ = cmd.Flags().GetString("oidc-client-id")
	o.AdminEmails, _ = cmd.Flags().GetStringSlice("admin-email")
	o.ServiceUser, _ = cmd.Flags().GetString("service-user")
	o.Force, _ = cmd.Flags().GetBool("force")

	if strings.TrimSpace(o.Dir) == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("determine working directory: %w", err)
		}
		o.Dir = wd
	}
	abs, err := filepath.Abs(o.Dir)
	if err != nil {
		return nil, fmt.Errorf("resolve --dir %q: %w", o.Dir, err)
	}
	o.Dir = abs
	o.CloopDir = filepath.Join(o.Dir, ".cloop")

	if o.Port < 1 || o.Port > 65535 {
		return nil, fmt.Errorf("--port must be between 1 and 65535 (got %d)", o.Port)
	}

	if strings.TrimSpace(o.ExternalURL) == "" {
		o.ExternalURL = fmt.Sprintf("https://localhost:%d", o.Port)
	}
	o.ExternalURL = strings.TrimRight(strings.TrimSpace(o.ExternalURL), "/")
	u, err := url.Parse(o.ExternalURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("--external-url must be an absolute http(s) URL (got %q)", o.ExternalURL)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		// Not a style preference: over plain HTTP the session cookie and the
		// bearer token cross the network in the clear, and the OIDC
		// authorization code with them.
		return nil, fmt.Errorf("--external-url is plain http on a non-loopback host (%q).\n"+
			"Session cookies, the dashboard token and the OIDC authorization code would all "+
			"travel in the clear. Use https, or terminate TLS at a proxy and pass its https URL here",
			o.ExternalURL)
	}

	// The credential monitors' ports, and the URLs sandboxes reach them at:
	// the external URL's host, because that is the name this hub is known by.
	// Each monitor speaks TLS itself with a certificate the hub issues
	// (tls: auto), so these are always https, whatever scheme the dashboard
	// is served with. A port must differ from the dashboard's --port and from
	// the external URL's, or the advertised URL would name the dashboard —
	// `--external-url https://hub:8443` behind a proxy is common enough that a
	// default which collides moves rather than fails.
	taken := map[int]string{o.Port: "the dashboard's --port"}
	extPort := 443
	if u.Scheme == "http" {
		extPort = 80
	}
	if p := u.Port(); p != "" {
		extPort, _ = strconv.Atoi(p)
	}
	if _, dup := taken[extPort]; !dup {
		taken[extPort] = "the port in --external-url, where browsers reach the dashboard"
	}
	var err2 error
	if o.GitProxyPort, err2 = monitorPort(cmd, "git-proxy-port", o.GitProxyPort, taken); err2 != nil {
		return nil, err2
	}
	taken[o.GitProxyPort] = "--git-proxy-port"
	if o.KubeGuardPort, err2 = monitorPort(cmd, "kube-guard-port", o.KubeGuardPort, taken); err2 != nil {
		return nil, err2
	}
	o.GitProxyURL = "https://" + net.JoinHostPort(u.Hostname(), strconv.Itoa(o.GitProxyPort))
	o.KubeGuardURL = "https://" + net.JoinHostPort(u.Hostname(), strconv.Itoa(o.KubeGuardPort))

	if o.BehindProxy {
		if strings.TrimSpace(o.TLSCert) != "" || strings.TrimSpace(o.TLSKey) != "" {
			return nil, fmt.Errorf("--behind-proxy means the proxy terminates TLS, " +
				"so --tls-cert/--tls-key have nothing to configure; drop one of them")
		}
	} else {
		if strings.TrimSpace(o.TLSCert) == "" {
			o.TLSCert = filepath.Join(o.CloopDir, "tls", "cert.pem")
		}
		if strings.TrimSpace(o.TLSKey) == "" {
			o.TLSKey = filepath.Join(o.CloopDir, "tls", "key.pem")
		}
	}

	o.OIDCIssuer = strings.TrimRight(strings.TrimSpace(o.OIDCIssuer), "/")
	o.OIDCClient = strings.TrimSpace(o.OIDCClient)
	if o.OIDCIssuer != "" && o.OIDCClient == "" {
		return nil, fmt.Errorf("--oidc-issuer was given without --oidc-client-id; " +
			"an issuer alone cannot complete a login")
	}
	if strings.TrimSpace(o.ServiceUser) == "" {
		o.ServiceUser = "cloop"
	}

	o.KeyFile, _ = cmd.Flags().GetString("key-file")
	o.SystemdCreds, _ = cmd.Flags().GetString("systemd-creds")
	if strings.TrimSpace(o.KeyFile) == "" {
		o.KeyFile = filepath.Join(o.Dir, hubKeyFile)
	}
	if o.KeyFile, err = filepath.Abs(o.KeyFile); err != nil {
		return nil, fmt.Errorf("resolve --key-file: %w", err)
	}
	if rootkey.InsideCloopDir(o.KeyFile) {
		// The hub refuses to read a key from there: a key kept beside the
		// database it protects travels with every backup and snapshot of it.
		return nil, fmt.Errorf("--key-file %s is inside a .cloop/ directory, where the hub refuses to read a key "+
			"from; keep it beside .cloop/, not in it", o.KeyFile)
	}
	switch o.SystemdCreds {
	case "auto", "always", "never":
	default:
		return nil, fmt.Errorf("--systemd-creds must be auto, always or never (got %q)", o.SystemdCreds)
	}
	return o, nil
}

// writeHubKey writes the root key: as a systemd-creds credential when
// --systemd-creds allows and this host can encrypt one, as a plain 0600 file
// otherwise. The plaintext and the credential are never both left behind.
func writeHubKey(o *hubBootstrapOpts, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(o.KeyFile), 0o700); err != nil {
		return fmt.Errorf("create the directory of %s: %w", o.KeyFile, err)
	}
	if o.SystemdCreds != "never" {
		credPath := o.KeyFile + hubKeyCredSuffix
		err := systemdCredsEncrypt(rootkey.Credential, key, credPath)
		switch {
		case err == nil:
			o.KeyEncrypted = true
			_ = os.Remove(o.KeyFile) // a plaintext copy from an earlier --force run
			return nil
		case o.SystemdCreds == "always":
			_ = os.Remove(credPath)
			return fmt.Errorf("--systemd-creds always: %w", err)
		default:
			_ = os.Remove(credPath)
			o.KeyNote = err.Error()
		}
	}
	if err := atomicfile.Write(o.KeyFile, key, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", o.KeyFile, err)
	}
	_ = os.Remove(o.KeyFile + hubKeyCredSuffix)
	return nil
}

// hubKeyPath is the file the root key was written to.
func hubKeyPath(o *hubBootstrapOpts) string {
	if o.KeyEncrypted {
		return o.KeyFile + hubKeyCredSuffix
	}
	return o.KeyFile
}

// monitorPort settles one monitor's port. One the operator named must be free
// of every port in taken; a default that is not moves up by a thousand, so
// 8443 becomes 9443 beside a dashboard reached at :8443, until one is.
func monitorPort(cmd *cobra.Command, flag string, port int, taken map[int]string) (int, error) {
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("--%s must be between 1 and 65535 (got %d)", flag, port)
	}
	if what, dup := taken[port]; dup {
		if cmd.Flags().Changed(flag) {
			return 0, fmt.Errorf("--%s %d is %s; each listener needs its own port", flag, port, what)
		}
		for p := port + 1000; p <= 65535; p += 1000 {
			if _, dup := taken[p]; !dup {
				return p, nil
			}
		}
		return 0, fmt.Errorf("--%s: no free default port; name one", flag)
	}
	return port, nil
}

func isLoopbackHost(h string) bool {
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

// randomToken returns n bytes of crypto/rand as unpadded base64url.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hubConfigTemplate is the generated config.yaml.
//
// Every security-relevant line carries the reason it is there, because the
// operator who eventually flips one of them will be reading this file and not
// this source.
const hubConfigTemplate = `# cloop hub configuration — generated by ` + "`cloop hub bootstrap`" + `.
#
# This file is the hosted profile: the settings below are deliberately
# stricter than cloop's built-in defaults, which target a single developer in
# a git checkout. Loosening one is a decision, not a cleanup.
#
# Secrets live in .cloop/hub.env (mode 0600), never here, so this file is safe
# to commit and template.

# ── Execution policy ────────────────────────────────────────────────────────
executors:
  # The control: with this false, no run can ever fork a harness on the hub
  # host. Requests to start one are refused with 409 naming the alternatives
  # rather than silently falling back. Every executor below, and every remote
  # agent that enrolls, is an isolated one.
  #
  # Leaving it unset is NOT the same as true-with-intent: the Executors tab
  # reports "unset (permissive)" so an unhardened hub is visible at a glance.
  allow_host_process: false

  # Container sandbox on the hub host. Off by default even here — a hub that
  # can run containers can run them as whatever the image says, so enabling it
  # is a decision about this host's blast radius.
  # container:
  #   enabled: true
  #   runtime: podman        # empty auto-detects; podman preferred (rootless)
  #   image: ghcr.io/blechschmidt/cloop:latest
  #   network: none          # grant egress per-project via the egress broker
  #   cpus: 2
  #   memory: 4g

  # Ephemeral-Pod executor. in_cluster authenticates as the hub Pod's own
  # ServiceAccount and is what deploy/helm/cloop-hub configures; on bare metal
  # leave it false and grant a kubeconfig through the secret broker instead.
  # kubernetes:
  #   enabled: true
  #   in_cluster: true
  #   namespace: cloop-workloads   # NOT the hub's own namespace
  #   image: ghcr.io/blechschmidt/cloop:latest
  #   cpu_limit: "2"
  #   memory_limit: 4Gi

  # ── Credential monitors ───────────────────────────────────────────────────
  # With these two on, a GitHub token or a kubeconfig granted to a project
  # stays on this hub. The sandbox gets a session token worth nothing anywhere
  # else, and a process it does not control decides every push (branch and
  # repository allowlists) and every Kubernetes API request (verbs,
  # namespaces). With them off, the credential itself is delivered into the
  # sandbox and its limits are enforced by code the sandbox runs.
  #
  # tls: auto has the hub issue both certificates from a CA of its own,
  # minted at first start and sealed under CLOOP_SECRET_KEY in the
  # control-plane database: short-lived leaves for the advertised names,
  # renewed before they expire. Every sandbox is told to trust that CA for
  # these two URLs and nothing else, so no image needs it baked in.
  #
  # Executors must reach both ports at the advertised name: a container on
  # this host through its network or firewall, an edge device over its link.
  # Both terminate their own TLS — route them to this host directly, not
  # through a TLS-terminating reverse proxy.
  git_proxy:
    enabled: true
    tls: auto
    listen_addr: 0.0.0.0:{{.GitProxyPort}}
    advertise_url: {{.GitProxyURL}}
  kube_guard:
    enabled: true
    tls: auto
    listen_addr: 0.0.0.0:{{.KubeGuardPort}}
    advertise_url: {{.KubeGuardURL}}

  # Scoped egress: lease the hub's Internet connection to sandboxes that have
  # none, per host and with byte quotas, instead of giving them a network.
  # egress:
  #   enabled: true
  #   # Every interface: a container sandbox reaches the proxy at its bridge's
  #   # gateway, and is refused it on a loopback bind. The per-session
  #   # credential is what protects the proxy.
  #   listen_addr: 0.0.0.0:8899
  #   max_session_minutes: 15

# ── HTTP surface ────────────────────────────────────────────────────────────
ui:
  # The public URL. Used to build OIDC redirects and to decide which origins
  # may open a WebSocket, so it must match what a browser actually types.
  external_url: {{.ExternalURL}}

  # A WebSocket is exempt from the same-origin policy, so an unpinned hub can
  # be driven by any page the operator's browser happens to load. Pinned.
  allowed_ws_origins:
    - {{.ExternalURL}}

  # Where the dashboard listens; the port is --port. Unset, a hub with sign-in
  # (this one has CLOOP_UI_TOKEN, and SSO once enabled) listens on every
  # interface, and one without listens on 127.0.0.1 only. When TLS terminates
  # at a proxy on this host, pin it to loopback so nothing else reaches the
  # plaintext port — ` + "`cloop hub doctor`" + ` reports ui.exposure until you do:
  # listen: 127.0.0.1

{{- if .BehindProxy}}
  # TLS terminates at a reverse proxy or Ingress, so the hub itself speaks
  # plain HTTP and must never be published directly.
  #
  # The proxy MUST set X-Forwarded-Proto: https. That header is what tells
  # cloop the browser's connection was encrypted. It is believed only from
  # loopback and from ui.trusted_proxies: a proxy on another host goes there,
  # or the hub treats its requests as plaintext — install.sh is refused and
  # enrollment offers no one-line installer.
  # trusted_proxies: [10.0.0.5]
  tls: {}
{{- else}}
  tls:
    # Generate a development pair with ` + "`cloop hub tls-init`" + `, or point these
    # at a real certificate. Terminating TLS at a proxy instead? Re-run with
    # --behind-proxy, which empties this block and documents the header the
    # proxy then has to set.
    cert_file: {{.TLSCert}}
    key_file: {{.TLSKey}}
    min_version: "1.2"
{{- end}}

  # Bound the resources one client can consume before authenticating.
  max_websocket_conns: 256
  max_websocket_conns_per_ip: 16
  max_request_body_bytes: 10485760

  oidc:
{{- if .OIDCIssuer}}
    enabled: true
    issuer: {{.OIDCIssuer}}
    client_id: {{.OIDCClient}}
    # No client_secret: PKCE (S256) authenticates the code exchange, so a
    # public-client registration needs none. If this client is registered as
    # confidential, set CLOOP_OIDC_CLIENT_SECRET in .cloop/hub.env instead.
    redirect_url: {{.ExternalURL}}/auth/callback
{{- else}}
    # No identity provider was given to ` + "`cloop hub bootstrap`" + `. Until this is
    # enabled the dashboard is protected by CLOOP_UI_TOKEN alone — one shared
    # bearer token, no per-user identity, and therefore no usable audit trail.
    # Fill in the three required fields and set enabled: true.
    enabled: false
    # issuer: https://idp.example.com/realms/main
    # client_id: cloop-hub
    # A client_secret is optional: without one the hub signs in as a public
    # client and PKCE (S256) authenticates the code exchange. For a
    # confidential registration set CLOOP_OIDC_CLIENT_SECRET in .cloop/hub.env.
    redirect_url: {{.ExternalURL}}/auth/callback
{{- end}}
    scopes: [openid, profile, email, groups]

    # Deny-by-default. A user who authenticates but matches no mapping below
    # gets "none" and can read nothing. The alternative — a default of viewer
    # — means everyone in the IdP is inside the hub the moment SSO is turned
    # on, which is rarely what anyone means by "we enabled SSO".
    default_role: none
{{if .AdminEmails}}
    admin_emails:
{{- range .AdminEmails}}
      - {{.}}
{{- end}}
{{- else}}
    # Break-glass administrators, matched case-insensitively on the email
    # claim. Keep this list short; prefer a group mapping below.
    # admin_emails:
    #   - you@example.com
{{- end}}

    # Claim → role bindings. Roles form a ladder:
    #   viewer     read projects and executors
    #   operator   + start/stop runs, mutate tasks
    #   maintainer + grant/revoke secrets, write config
    #   admin      + manage executors and users, read the audit trail
    #
    # A binding may be pinned to one project or one executor, and the most
    # specific match wins, so a group can be operator everywhere and
    # maintainer on one project.
    role_mappings:
      # - {claim: group, value: platform-admins, role: admin}
      # - {claim: group, value: engineering,     role: operator}
      # - {claim: group, value: contractors,     role: viewer, project: sandbox}
      []

    session_ttl_hours: 12
    cookie_secure: always

# ── Rate limiting ───────────────────────────────────────────────────────────
# Per-IP token bucket in front of every route except /healthz and /readyz,
# which must answer even while a client is being throttled or an orchestrator
# will restart a hub that is merely busy.
rate_limit:
  requests_per_second: 20
  burst: 50

# ── Providers ───────────────────────────────────────────────────────────────
# API keys are read from the environment (ANTHROPIC_API_KEY, OPENAI_API_KEY),
# not from this file. Set them in .cloop/hub.env alongside the other secrets.
provider: anthropic
anthropic:
  model: claude-opus-4-6
`

// hubEnvTemplate is .cloop/hub.env: everything that must not be committed.
const hubEnvTemplate = `# cloop hub secrets — generated by ` + "`cloop hub bootstrap`" + `. Mode 0600.
#
# Never commit this file. Load it with:
#   systemd     EnvironmentFile=/path/to/.cloop/hub.env
#   compose     docker compose --env-file .cloop/hub.env up
#   shell       set -a; . .cloop/hub.env; set +a

# The root key, CLOOP_SECRET_KEY, is NOT in this file. It is in
#   %s
# beside .cloop/ rather than in it, so a backup of the database does not carry
# the key that opens it. The systemd unit loads it as the credential
# cloop-secret-key; a shell names it with CLOOP_SECRET_KEY_FILE=<that file>.
# Never put it back here as an environment variable: those are readable in
# /proc/<pid>/environ and inherited by every child process.
#
# Losing it means every sealed secret becomes unopenable. Once the hub has
# started, escrow it under a passphrase:
#   cloop hub key escrow export --output /path/off/this/host/cloop-hub.escrow
# Keep that file where you keep root credentials, the passphrase somewhere
# else again, and rehearse recovery with ` + "`cloop hub key escrow verify`" + `.
# ` + "`cloop hub doctor`" + ` warns until an escrow is recorded.
#
# Rotating the *sealing keys* does not change it: "cloop hub key rotate".
# Changing it is online too — the runbook's "Changing CLOOP_SECRET_KEY itself".

# Static bearer token for the dashboard and REST API. This is what keeps the
# hub closed before an identity provider is wired up, and what API automation
# keeps using afterwards. Send it as ` + "`Authorization: Bearer <token>`" + `.
CLOOP_UI_TOKEN=%s

# OIDC client secret. Only needed when the client is registered at your
# identity provider as a CONFIDENTIAL client — a public-client registration
# needs none, because PKCE (S256) authenticates the code exchange on its own,
# and that is the default the bundled Terraform module provisions. The value
# belongs to the registration, so it is not generated here.
#CLOOP_OIDC_CLIENT_SECRET=

# Model provider credentials. Read from the environment rather than
# config.yaml so the config stays committable.
#ANTHROPIC_API_KEY=
#OPENAI_API_KEY=
`

func renderHubConfig(o *hubBootstrapOpts) ([]byte, error) {
	tmpl, err := template.New("hubconfig").Parse(hubConfigTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse hub config template: %w", err)
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, o); err != nil {
		return nil, fmt.Errorf("render hub config: %w", err)
	}
	return []byte(sb.String()), nil
}

func renderHubEnv(keyPath, uiToken string) string {
	return fmt.Sprintf(hubEnvTemplate, keyPath, uiToken)
}

// systemdUnitTemplate is printed rather than installed. Writing into
// /etc/systemd/system needs root, and a bootstrap that silently acquired a
// system service would be a poor trade for saving one copy-paste.
const systemdUnitTemplate = `[Unit]
Description=cloop hub (control plane)
Documentation=https://github.com/blechschmidt/cloop/blob/main/deploy/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%[1]s
Group=%[1]s
WorkingDirectory=%[2]s
EnvironmentFile=%[3]s
# The root key, as the credential cloop-secret-key in $CREDENTIALS_DIRECTORY:
# read by systemd, never in the hub's environment.
%[7]s
ExecStart=%[4]s ui --port %[5]d --no-browser
Restart=on-failure
RestartSec=5s

# The hub must not be able to do on this host what executors.allow_host_process
# already forbids it from doing on purpose. These make that structural rather
# than a config value someone can flip.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=

# ProtectSystem=strict makes everything read-only; this is the one exception.
ReadWritePaths=%[6]s

[Install]
WantedBy=multi-user.target
`

func printHubBootstrapSummary(o *hubBootstrapOpts, configPath, envPath string, loaded *config.Config) {
	header := color.New(color.FgCyan, color.Bold)
	warn := color.New(color.FgYellow, color.Bold)
	dim := color.New(color.Faint)

	header.Println("Bootstrapped a cloop hub")
	fmt.Printf("  config:   %s\n", configPath)
	fmt.Printf("  secrets:  %s (mode 0600)\n", envPath)
	if o.KeyEncrypted {
		fmt.Printf("  root key: %s (encrypted with systemd-creds; only systemd on this host can read it)\n", hubKeyPath(o))
	} else {
		fmt.Printf("  root key: %s (mode 0600)\n", hubKeyPath(o))
	}
	fmt.Printf("  url:      %s\n\n", o.ExternalURL)

	fmt.Println("Applied:")
	fmt.Println("  ✔ host execution disabled — no run can fork a harness on this host")
	fmt.Println("  ✔ git proxy and Kubernetes monitor on (tls: auto) — forge and cluster credentials stay on the hub")
	fmt.Println("  ✔ RBAC deny-by-default — an authenticated user with no mapping gets nothing")
	fmt.Println("  ✔ WebSocket origin pinned to the external URL")
	if o.KeyEncrypted {
		fmt.Println("  ✔ CLOOP_SECRET_KEY generated (256 bits, crypto/rand) and sealed with systemd-creds")
	} else {
		fmt.Println("  ✔ CLOOP_SECRET_KEY generated (256 bits, crypto/rand) into a key file, never an environment variable")
		if o.KeyNote != "" {
			warn.Printf("  ! not encrypted with systemd-creds (%s): the unit loads it with LoadCredential= instead\n",
				o.KeyNote)
		}
	}
	fmt.Println("  ✔ CLOOP_UI_TOKEN generated — the hub is closed before SSO exists")
	if o.OIDCIssuer != "" {
		fmt.Printf("  ✔ OIDC configured against %s\n", o.OIDCIssuer)
	} else {
		fmt.Println("  • OIDC left disabled — pass --oidc-issuer/--oidc-client-id to configure it")
	}
	fmt.Println()

	for _, w := range config.ExecutorWarnings(loaded.Executors) {
		warn.Printf("  ! %s\n", w)
	}
	if o.BehindProxy {
		warn.Println("  ! TLS terminates at your proxy. It MUST set X-Forwarded-Proto: https, and the")
		warn.Println("    hub believes it only from loopback or ui.trusted_proxies — add the proxy's")
		warn.Println("    address there if it runs on another host.")
	} else if _, err := os.Stat(o.TLSCert); err != nil {
		warn.Printf("  ! %s does not exist yet — the hub will not start until it does.\n", o.TLSCert)
		dim.Printf("    Development: cloop hub tls-init --dir %s\n", filepath.Dir(o.TLSCert))
		dim.Println("    Production:  point ui.tls at a certificate your clients already trust.")
	}
	fmt.Println()

	header.Println("Ports executors must reach")
	fmt.Printf("  git proxy            %s   (TCP %d on this host)\n", o.GitProxyURL, o.GitProxyPort)
	fmt.Printf("  Kubernetes monitor   %s   (TCP %d on this host)\n", o.KubeGuardURL, o.KubeGuardPort)
	dim.Println("  Both serve a certificate the hub issues itself; sandboxes are told to trust its CA for")
	dim.Println("  these URLs only. Open them to your executors' networks, and route them to this host")
	dim.Println("  directly rather than through a TLS-terminating proxy.")
	if u, err := url.Parse(o.ExternalURL); err == nil && isLoopbackHost(u.Hostname()) {
		warn.Printf("  ! %s is a loopback name: only a sandbox sharing this host's network namespace\n", u.Hostname())
		warn.Println("    reaches the monitors there. Re-run with --external-url set to a name your executors resolve.")
	}
	fmt.Println()

	fmt.Println("Start it:")
	if o.KeyEncrypted {
		dim.Printf("\n  Under the systemd unit below: only systemd can decrypt %s.\n"+
			"  For a one-off run from a shell, as root:\n"+
			"  systemd-run --pty --uid=%s --working-directory=%s -p EnvironmentFile=%s \\\n"+
			"    -p LoadCredentialEncrypted=%s:%s %s ui --port %d --no-browser\n\n",
			hubKeyPath(o), o.ServiceUser, o.Dir, envPath, rootkey.Credential, hubKeyPath(o), hubBinaryPath(), o.Port)
	} else {
		dim.Printf("\n  set -a; . %s; set +a\n  cd %s && %s=%s cloop ui --port %d --no-browser\n\n",
			envPath, o.Dir, rootkey.EnvKeyFile, hubKeyPath(o), o.Port)
		if u, err := user.Lookup(o.ServiceUser); err == nil && u.Uid != strconv.Itoa(os.Getuid()) {
			dim.Printf("  The unit below loads %s as root, so it may stay yours; to name it with %s from\n"+
				"  the %s account instead, `chown %s %s` — the hub reads only a key file it owns, mode 0400 or 0600.\n\n",
				hubKeyPath(o), rootkey.EnvKeyFile, o.ServiceUser, o.ServiceUser, hubKeyPath(o))
		}
	}

	fmt.Printf("Then escrow the root key, so losing %s is not the end of every secret:\n", hubKeyPath(o))
	dim.Printf("\n  cloop hub key escrow export --output /path/off/this/host/cloop-hub.escrow\n\n")

	header.Println("systemd unit for a bare-metal host")
	fmt.Printf("Write this to /etc/systemd/system/cloop-hub.service, then\n"+
		"`systemctl daemon-reload && systemctl enable --now cloop-hub`.\n"+
		"It assumes a %s user that owns %s and a binary at %s.\n\n",
		o.ServiceUser, o.Dir, hubBinaryPath())
	fmt.Print(systemdUnit(o))
}

// hubBinaryPath is the ExecStart path for the generated unit: this binary's
// own location when it can be resolved, so the unit refers to the thing the
// operator just ran rather than to a guess.
func hubBinaryPath() string {
	if p, err := os.Executable(); err == nil {
		if abs, aerr := filepath.Abs(p); aerr == nil {
			return abs
		}
	}
	return "/usr/local/bin/cloop"
}

func systemdUnit(o *hubBootstrapOpts) string {
	load := "LoadCredential"
	if o.KeyEncrypted {
		load = "LoadCredentialEncrypted"
	}
	keyPath := hubKeyPath(o)
	if o.KeyFile == "" {
		keyPath = filepath.Join(o.Dir, hubKeyFile)
	}
	return fmt.Sprintf(systemdUnitTemplate,
		o.ServiceUser,
		o.Dir,
		filepath.Join(o.CloopDir, hubEnvFile),
		hubBinaryPath(),
		o.Port,
		o.CloopDir,
		load+"="+rootkey.Credential+":"+keyPath,
	)
}

// registerHubBootstrapFlags declares the flag set on cmd.
//
// A function rather than a block inside init() so tests can build a command
// with *its own* flags. pflag stores values on the Flag objects themselves, so
// sharing one FlagSet between invocations carries --behind-proxy from one test
// into the next — which shows up as a set of unrelated failures that look like
// bugs in the parsing.
func registerHubBootstrapFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.String("dir", "",
		"directory to bootstrap (default: the current directory)")
	f.String("external-url", "",
		"public URL browsers reach the hub at (default: https://localhost:<port>)")
	f.Int("port", 8080, "port the hub listens on")
	f.Int("git-proxy-port", 8443,
		"port the git interception proxy listens on; sandboxes reach it at the external URL's host")
	f.Int("kube-guard-port", 8444,
		"port the Kubernetes access monitor listens on; sandboxes reach it at the external URL's host")
	f.String("tls-cert", "",
		"TLS certificate path to record in the config (default: .cloop/tls/cert.pem)")
	f.String("tls-key", "",
		"TLS key path to record in the config (default: .cloop/tls/key.pem)")
	f.Bool("behind-proxy", false,
		"TLS terminates at a reverse proxy or Ingress; leave ui.tls empty and serve plain HTTP")
	f.String("oidc-issuer", "",
		"OIDC issuer URL; given, SSO is enabled in the generated config")
	f.String("oidc-client-id", "",
		"OIDC client ID registered for this hub")
	f.StringSlice("admin-email", nil,
		"email claim granted the admin role (repeatable)")
	f.String("service-user", "cloop",
		"UNIX user the printed systemd unit runs as")
	f.Bool("force", false,
		"overwrite an existing config and key (invalidates every sealed secret)")
	f.String("key-file", "",
		"where to write the root key, outside .cloop/ (default: "+hubKeyFile+" in --dir)")
	f.String("systemd-creds", "auto",
		"encrypt the root key with systemd-creds: auto (when this host can), always, or never")
}

func init() {
	registerHubBootstrapFlags(hubBootstrapCmd)
	hubCmd.AddCommand(hubBootstrapCmd)
}
