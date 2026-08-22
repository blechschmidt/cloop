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
//     can be committed, diffed and templated without leaking the key.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/config"
)

// hubEnvFile holds the generated secrets. Separate from config.yaml so the
// config can be version-controlled and this cannot.
const hubEnvFile = "hub.env"

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
  ui.oidc.default_role: none            deny-by-default; no claim, no access
  ui.tls.*                              TLS paths filled in and required
  ui.allowed_ws_origins                 WebSocket origin pinned to the URL
  CLOOP_SECRET_KEY                      256 bits from crypto/rand, mode 0600
  CLOOP_UI_TOKEN                        so the dashboard is never open

Secrets are written to .cloop/hub.env (mode 0600), never into config.yaml —
so the config can be committed and the env file cannot. The env file is
consumable as-is by systemd's EnvironmentFile= and by docker compose
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
	TLSCert     string
	TLSKey      string
	BehindProxy bool
	OIDCIssuer  string
	OIDCClient  string
	AdminEmails []string
	ServiceUser string
	Force       bool
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
		for _, p := range []string{configPath, envPath} {
			if _, statErr := os.Stat(p); statErr == nil {
				return fmt.Errorf("%s already exists.\n"+
					"Bootstrap generates a new secret-broker passphrase, and a new passphrase "+
					"cannot derive the keys that opened the existing payloads.\n"+
					"To roll the sealing keys without re-minting anything, run "+
					"'cloop hub key rotate' instead.\n"+
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
	if err := atomicfile.Write(envPath, []byte(renderHubEnv(secretKey, uiToken)), 0o600); err != nil {
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
	return o, nil
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

  # Scoped egress: lease the hub's Internet connection to sandboxes that have
  # none, per host and with byte quotas, instead of giving them a network.
  # egress:
  #   enabled: true
  #   listen_addr: 127.0.0.1:8899
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

{{- if .BehindProxy}}
  # TLS terminates at a reverse proxy or Ingress, so the hub itself speaks
  # plain HTTP and must never be published directly.
  #
  # The proxy MUST set X-Forwarded-Proto: https. That header is what tells
  # cloop the browser's connection was encrypted, and therefore what marks
  # the session cookie Secure. Without it every login issues a cookie that a
  # downgrade attack can replay over http.
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
    # client_secret comes from CLOOP_OIDC_CLIENT_SECRET in .cloop/hub.env.
    redirect_url: {{.ExternalURL}}/auth/callback
{{- else}}
    # No identity provider was given to `+"`cloop hub bootstrap`"+`. Until this is
    # enabled the dashboard is protected by CLOOP_UI_TOKEN alone — one shared
    # bearer token, no per-user identity, and therefore no usable audit trail.
    # Fill in the four required fields and set enabled: true.
    enabled: false
    # issuer: https://idp.example.com/realms/main
    # client_id: cloop-hub
    # client_secret comes from CLOOP_OIDC_CLIENT_SECRET in .cloop/hub.env.
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

# Passphrase protecting every payload in the secret broker: kubeconfigs,
# GitHub PATs, egress credentials. 256 bits from crypto/rand.
#
# Losing it means every sealed secret becomes unopenable — there is no
# recovery path and no escrow. Back it up wherever you keep root credentials.
# Changing it has the same effect as losing it.
#
# Rotating the *sealing keys* is a different operation and does not need this
# value to change: run "cloop hub key rotate". Every key-encryption key is
# derived from this passphrase, so rotation bounds the lifetime of a key, not
# of the passphrase it comes from.
CLOOP_SECRET_KEY=%s

# Static bearer token for the dashboard and REST API. This is what keeps the
# hub closed before an identity provider is wired up, and what API automation
# keeps using afterwards. Send it as `+"`Authorization: Bearer <token>`"+`.
CLOOP_UI_TOKEN=%s

# OIDC client secret, when ui.oidc.enabled is true. The value belongs to the
# client registration at your identity provider, so it is not generated here.
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

func renderHubEnv(secretKey, uiToken string) string {
	return fmt.Sprintf(hubEnvTemplate, secretKey, uiToken)
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
	fmt.Printf("  config:  %s\n", configPath)
	fmt.Printf("  secrets: %s (mode 0600)\n", envPath)
	fmt.Printf("  url:     %s\n\n", o.ExternalURL)

	fmt.Println("Applied:")
	fmt.Println("  ✔ host execution disabled — no run can fork a harness on this host")
	fmt.Println("  ✔ RBAC deny-by-default — an authenticated user with no mapping gets nothing")
	fmt.Println("  ✔ WebSocket origin pinned to the external URL")
	fmt.Println("  ✔ CLOOP_SECRET_KEY generated (256 bits, crypto/rand)")
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
		warn.Println("  ! TLS terminates at your proxy. It MUST set X-Forwarded-Proto: https —")
		warn.Println("    without it the session cookie is issued without the Secure attribute.")
	} else if _, err := os.Stat(o.TLSCert); err != nil {
		warn.Printf("  ! %s does not exist yet — the hub will not start until it does.\n", o.TLSCert)
		dim.Printf("    Development: cloop hub tls-init --dir %s\n", filepath.Dir(o.TLSCert))
		dim.Println("    Production:  point ui.tls at a certificate your clients already trust.")
	}
	fmt.Println()

	fmt.Println("Start it:")
	dim.Printf("\n  set -a; . %s; set +a\n  cd %s && cloop ui --port %d --no-browser\n\n", envPath, o.Dir, o.Port)

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
	return fmt.Sprintf(systemdUnitTemplate,
		o.ServiceUser,
		o.Dir,
		filepath.Join(o.CloopDir, hubEnvFile),
		hubBinaryPath(),
		o.Port,
		o.CloopDir,
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
}

func init() {
	registerHubBootstrapFlags(hubBootstrapCmd)
	hubCmd.AddCommand(hubBootstrapCmd)
}
