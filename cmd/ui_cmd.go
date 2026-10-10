package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/exposure"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/sameorigin"
	"github.com/blechschmidt/cloop/pkg/ui"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// defaultUIPort is the port `cloop ui` serves on without --port, and so the hub
// `cloop hub doctor` diagnoses without one: the two have to agree on which hub
// that is, or the doctor reads a different overlay from the hub it reports on.
const defaultUIPort = 8080

var (
	uiPort       int
	uiNoBrowser  bool
	uiToken      string
	uiProjects   []string
	uiScan       string
	uiRateLimit  float64
	uiRateBurst  int
	uiTLSCert    string
	uiTLSKey     string
	uiRequireIdP bool
	// uiAdvertiseURL is how other hub processes serving the same control
	// plane reach this one (Task 20354).
	uiAdvertiseURL string
	// uiListen is the address the dashboard binds, without the port
	// (Task 20393). Empty defers to ui.listen, then to the default for the
	// hub's authentication.
	uiListen string
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Start a local web dashboard for monitoring and controlling cloop",
	Long: `Start a web server that serves a real-time dashboard on port 8080.

The dashboard shows the project goal, status, step history with outputs,
task list (PM mode), live progress via SSE, and run/stop controls.

  cloop ui                            # single-project mode (cwd)
  cloop ui --port 9090                # use a custom port
  cloop ui --no-browser               # don't open the browser automatically
  cloop ui --projects /a /b /c        # multi-project overview dashboard
  cloop ui --scan /root/Projects      # auto-discover cloop projects under dir
  cloop ui --tls-cert c.pem --tls-key k.pem   # serve HTTPS directly
  cloop ui --listen 0.0.0.0           # every interface (needs sign-in)

Where it listens depends on whether it can tell people apart. A hub with no
sign-in — no ui.oidc and no CLOOP_UI_TOKEN — lets anyone who reaches it start
agent runs on this host, so it listens on 127.0.0.1 only. A hub with sign-in
listens on every interface. --listen (or ui.listen) names an address instead;
one beyond loopback is refused on a hub without sign-in unless
ui.allow_unauthenticated_network is true. Remote executor agents need to reach
the hub, so a hub that serves them over the network needs SSO or a token.

TLS may also be configured under ui.tls in .cloop/config.yaml; the flags win
when both are present. Run ` + "`cloop hub tls-init`" + ` for a development
certificate. Without either, the dashboard serves plaintext, which is correct
for loopback use and for a deployment that terminates TLS in a reverse proxy —
but not for anything reachable from a network.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Load .cloop/config.yaml. A parse failure is fatal, not a warning:
		// every security-relevant setting the dashboard has — TLS, the origin
		// allowlist, the WebSocket caps, and OIDC itself — lives in this file,
		// so a one-character YAML typo would otherwise start a hardened
		// deployment in plaintext with no authentication and only a line on
		// stderr to say so. Load returns defaults with a nil error when the
		// file is absent, so the no-config case is unaffected.
		//
		// Read through LoadUIInstance so a host running two dashboards out of
		// one working directory can say something to this one alone — see
		// pkg/config/uiinstance.go for why the overlay is a separate file and
		// not a section. It is named on stdout when it applies: a setting
		// whose source is invisible is the one an operator edits in the wrong
		// file.
		//
		// Read first, before the control plane is touched: whether this
		// process joins the others serving it or fences them out is decided
		// here (ui.cluster).
		cfg, overlay, err := config.LoadUIInstance(workdir, uiPort)
		if err != nil {
			return fmt.Errorf("could not load %s: %w", config.ConfigPath(workdir), err)
		}
		if overlay != "" {
			fmt.Printf("Instance config: %s merged over %s\n", overlay, config.ConfigPath(workdir))
		}
		if cfg != nil {
			if err := cfg.UI.Cluster.Validate(); err != nil {
				return err
			}
			// Fatal like the cluster block: an entry that does not parse
			// would otherwise be dropped, and the proxy it named would see
			// every browser behind it judged as plaintext from the proxy's
			// own address (Task 20394).
			if _, err := sameorigin.ParseProxies(cfg.UI.TrustedProxies); err != nil {
				return err
			}
			// Fatal while in force (Task 20397): an egress_filter allowlist
			// that contains a cloud metadata service without naming it is
			// compiled with the service closed, so it reads as reaching a range
			// it does not wholly reach — and a reader of the file, or of the
			// next change to it, cannot tell which part. A section that is
			// switched off is only warned about, like every other problem in
			// one: it confines nothing either way.
			if err := refuseMetadataExposures(cfg, os.Stderr); err != nil {
				return err
			}
		}

		token := uiToken
		if token == "" {
			token = os.Getenv("CLOOP_UI_TOKEN")
		}

		// Where to listen (Task 20393), decided before the control plane is
		// touched: a hub refused an address leaves no member row, lease or
		// reconciled executor behind. Run decides again from what the server
		// holds, and reaches the same answer because it is given the same
		// request.
		listenReq := uiListenRequest(cfg, token)
		listen, err := exposure.Decide(listenReq)
		if err != nil {
			return err
		}

		// Join the control plane before anything touches it. This is the
		// first thing done to state.db on purpose: ui.New reconciles executors
		// and sweeps orphaned sessions, and doing that without knowing which
		// other hub processes are serving would reap their work.
		//
		// Two modes (Task 20354). By default this process becomes a member of
		// the cluster serving workdir's control plane — alone, or beside the
		// processes already serving it — and several `cloop ui` behind one
		// load balancer share it. With ui.cluster.exclusive it takes the
		// control plane alone instead, as every hub did before Task 20354, and
		// refuses while any other hub serves it (Task 20214).
		//
		// Released by Server.Shutdown once requests have drained. If this
		// returns before then — a config error, a bad TLS certificate — the
		// deferred release stops a failed start from holding the fence.
		var (
			lease *hublease.Lease
			node  *hubcluster.Node
		)
		if cfg != nil && cfg.UI.Cluster.Exclusive {
			lease, err = acquireExclusiveHub(workdir, listen)
			if err != nil {
				return err
			}
			defer lease.Release()
		} else {
			node, err = joinHubCluster(workdir, cfg, listen)
			if err != nil {
				return err
			}
			defer node.Close()
		}

		if token != "" {
			warnStaticTokenDeprecated()
		}

		// Resolve project list from --projects and/or --scan flags.
		var projectPaths []string
		projectPaths = append(projectPaths, uiProjects...)
		if uiScan != "" {
			scanned, err := multiui.Scan(uiScan)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: scan %s: %v\n", uiScan, err)
			} else {
				projectPaths = append(projectPaths, scanned...)
			}
		}

		// Persist newly discovered projects into the registry.
		if len(projectPaths) > 0 {
			if err := multiui.AddPaths(projectPaths); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not save project registry: %v\n", err)
			}
		}

		srv := ui.NewInCluster(workdir, uiPort, token, node)
		srv.Lease = lease
		srv.ListenHost = listenReq.Listen
		srv.AllowUnauthenticatedNetwork = listenReq.AllowUnauthenticatedNetwork
		srv.Projects = projectPaths
		srv.RPS = uiRateLimit
		srv.Burst = uiRateBurst

		if cfg != nil {
			srv.MaxWebSocketConns = cfg.UI.MaxWebSocketConns
			srv.MaxWebSocketConnsPerIP = cfg.UI.MaxWebSocketConnsPerIP
			srv.AllowedWSOrigins = cfg.UI.AllowedWSOrigins
			srv.AllowedOrigins = cfg.UI.AllowedOrigins
			srv.ExternalURL = cfg.UI.ExternalURL
			// Validated above. Whose X-Forwarded-* the hub believes, and the
			// names a hub without sign-in answers to (Task 20394).
			srv.TrustedProxies, _ = sameorigin.ParseProxies(cfg.UI.TrustedProxies)
			srv.AllowedHosts = cfg.UI.AllowedHosts
			for _, w := range unusableOriginEntries(cfg.UI) {
				fmt.Fprintf(os.Stderr, "warning: %s\n", w)
			}
			// TLS: flags override config so an operator can point a running
			// deployment at a renewed certificate without editing YAML.
			if err := cfg.UI.TLS.Validate(); err != nil {
				return err
			}
			srv.TLSCertFile = cfg.UI.TLS.CertFile
			srv.TLSKeyFile = cfg.UI.TLS.KeyFile
			srv.TLSMinVersion = cfg.UI.TLS.MinVersion

			// Optional OIDC single sign-on (ui.oidc.* — Task 20152). Unlike
			// the caps above this is fail-closed: a dashboard configured to
			// require SSO must not silently start wide open, so an invalid
			// OIDC config aborts startup with a descriptive error.
			if cfg.UI.OIDC.Enabled {
				// Durable sessions (Task 20176). A failure to open the store is
				// reported and degraded to process-local sessions rather than
				// aborted: a hub that cannot reach its session table should
				// still let people in, it should just be honest that a restart
				// will sign them out again.
				store, storeWarn := srv.OpenSessionStore()
				if storeWarn != nil {
					fmt.Printf("warning: sessions are process-local (%v) — a restart will sign every user out\n", storeWarn)
				}
				refreshMinutes := cfg.UI.OIDC.EffectiveRefreshIntervalMinutes()
				// The static fields come from config.OIDCConfig.AuthConfig
				// rather than being spelled out here, because the Settings
				// panel validates a prospective block by handing the same
				// builder's output to the same constructor (Task 20308), and
				// `cloop hub doctor` does the same to say whether this start
				// will succeed (Task 20387). Two construction sites would let
				// the panel accept a configuration this line then refuses —
				// and refusing here is fatal, so the symptom would be a hub
				// that will not start.
				authCfg := cfg.UI.OIDC.AuthConfig()
				authCfg.Store = store
				authCfg.Audit = srv.SessionAuditSink()
				// Per-identity session cap (Task 20182). Resolved live rather
				// than captured, so an admin lowering somebody's quota takes
				// effect at their next sign-in without a restart.
				authCfg.SessionLimit = srv.SessionLimitFor
				// Names the authority a user lost when the IdP narrows their
				// claims mid-session (Task 20249). Resolved live against
				// srv.Authz, which is assigned just below — a method value, so
				// the nil resolver here is never read.
				authCfg.EffectiveRole = srv.EffectiveRoleFor
				// On a control plane several hub processes serve (Task
				// 20354): a login's callback is routed to the process that
				// began it, a session ended on one stops working on all of
				// them at once, and two of them never redeem one refresh
				// token together. A no-op for a standalone hub.
				srv.ClusterOIDCConfig(&authCfg)
				// Counts the silent renewals a dashboard runs to keep its
				// claims current (Task 20359). The renewal completes inside
				// oidcauth, where hubmetrics is not reachable.
				authCfg.RenewObserver = ui.RecordRenewOutcome
				// cookie_secure "auto" believes X-Forwarded-Proto from the
				// proxies the hub does, and nowhere else (Task 20394).
				authCfg.RequestIsTLS = srv.RequestIsTLS
				auth, oidcErr := oidcauth.New(authCfg)
				if oidcErr != nil {
					return fmt.Errorf("ui.oidc is enabled but invalid: %w", oidcErr)
				}
				srv.OIDC = auth

				// Claim-based RBAC (ui.oidc.role_mappings — Task 20164).
				// Fail-closed for the same reason: a typo in a role name
				// must not silently degrade to a binding that never
				// matches (and therefore a user who is denied everything,
				// or worse, a default_role that was meant to be narrower).
				// Runtime role bindings (Task 20248) — the layer an operator
				// writes with `cloop hub role` during an incident, read live
				// rather than at startup. Fatal on failure, unlike the session
				// store above: a hub that cannot read this table comes up
				// having silently dropped every demotion somebody wrote.
				roleSource, roleErr := srv.OpenRoleStore()
				if roleErr != nil {
					return fmt.Errorf("could not open runtime role bindings: %w", roleErr)
				}
				// Project memberships (Task 20366): who besides its owner may
				// reach a project. Fatal like the role store: a hub that cannot
				// read this table would come up having silently un-shared every
				// project on it.
				if _, memberErr := srv.OpenMemberStore(); memberErr != nil {
					return fmt.Errorf("could not open project memberships: %w", memberErr)
				}
				resolver, authzErr := authz.New(cfg.UI.OIDC.AuthzConfig(roleSource))
				if authzErr != nil {
					return fmt.Errorf("ui.oidc role mappings are invalid: %w", authzErr)
				}
				srv.Authz = resolver

				fmt.Printf("OIDC authentication enabled (issuer: %s)\n", cfg.UI.OIDC.Issuer)
				// Whether RBAC is in force, asked of authz.Enforced (Task
				// 20395); a hub running SSO without a policy warns on stderr,
				// or refuses to start under ui.oidc.require_rbac.
				if err := reportRBAC(os.Stdout, os.Stderr, cfg.UI.OIDC, resolver); err != nil {
					return err
				}
				fmt.Printf("Sessions: %s absolute / %s idle, %s\n",
					time.Duration(cfg.UI.OIDC.EffectiveSessionTTLHours())*time.Hour,
					time.Duration(cfg.UI.OIDC.EffectiveIdleTimeoutHours())*time.Hour,
					describeRevalidation(refreshMinutes, srv.SessionStoreSealsRefreshTokens()))

				// Resolve the issuer now rather than at the first sign-in
				// (Task 20247). The flag wins over the config key so an
				// operator can demand a hard failure for one start — a
				// rollout, a smoke test — without editing the ConfigMap.
				srv.RequireIdP = cfg.UI.OIDC.RequireIdP || uiRequireIdP
				if err := srv.PreflightIdP(cmd.Context()); err != nil {
					return err
				}
			}

			// Per-identity quotas (ui.quotas — Task 20182). Fail-closed like
			// the role mappings above and for the same reason: a typo in a
			// resource name produces a binding that matches nothing, and
			// "the quota I configured is not being enforced" is the failure
			// an admission-control system can least afford to have silently.
			//
			// Installed even when no policy is configured, because an admin
			// can still cap one identity from the panel and that override
			// needs somewhere to live. With neither, every admission
			// succeeds and a single-tenant hub is unchanged.
			quotaResolver, quotaErr := quota.New(cfg.UI.Quotas.QuotaConfig())
			if quotaErr != nil {
				return fmt.Errorf("ui.quotas is invalid: %w", quotaErr)
			}
			srv.SetQuotaPolicy(quotaResolver)
			if cfg.UI.Quotas.Configured() {
				fmt.Printf("Quotas: %d binding(s), %d default limit(s)\n",
					len(cfg.UI.Quotas.Bindings), len(cfg.UI.Quotas.Defaults))
			}
		}

		// Rebuild the gauge counters from what actually exists, before the
		// listener binds. A persisted counter is a claim nothing else
		// corrects: a hub killed mid-run comes back believing that tenant
		// still holds the slot, forever. Doing it here — synchronously, not
		// in a goroutine — means the first admission after startup is
		// evaluated against reconciled numbers rather than racing them.
		srv.ReconcileQuotas()

		if uiTLSCert != "" || uiTLSKey != "" {
			srv.TLSCertFile, srv.TLSKeyFile = uiTLSCert, uiTLSKey
		}

		// Open the browser only after the scheme is settled, so the URL
		// matches what the server will actually speak. Opening http:// against
		// an HTTPS listener produces an empty tab and a confusing bug report.
		if !uiNoBrowser {
			listen.TLS = srv.TLSEnabled()
			go openBrowser(listen.URL())
		}

		return srv.Start()
	},
}

// unusableOriginEntries names the origin settings that cannot be read as an
// origin and therefore match nothing (Task 20394): origins are matched
// exactly now, so an entry that does not parse is not a looser match — it is
// no match at all, and an operator who wrote one expects it to do something.
func unusableOriginEntries(u config.UIConfig) []string {
	var out []string
	check := func(key string, entries []string) {
		if _, bad := sameorigin.ParseEntries(entries); len(bad) > 0 {
			out = append(out, fmt.Sprintf("%s: %q is not an origin (https://host[:port], or host[:port] for https) "+
				"and matches nothing", key, bad))
		}
	}
	if ext := strings.TrimSpace(u.ExternalURL); ext != "" {
		check("ui.external_url", []string{ext})
	}
	check("ui.allowed_origins", u.AllowedOrigins)
	check("ui.allowed_ws_origins", u.AllowedWSOrigins)
	for _, h := range u.AllowedHosts {
		if _, _, err := sameorigin.SplitHostPort(h); err != nil || strings.Contains(h, "://") {
			out = append(out, fmt.Sprintf("ui.allowed_hosts: %q is not a host name or host:port and matches nothing", h))
		}
	}
	return out
}

// refuseMetadataExposures stops a start while an egress_filter allowlist in
// force contains a cloud metadata service without naming it (Task 20397), and
// writes a warning to warn for each one in a section that is switched off.
//
// Every exposure in force is named, not the first: an operator fixing one line
// should not learn about the next by restarting again.
func refuseMetadataExposures(cfg *config.Config, warn io.Writer) error {
	var fatal []string
	for _, x := range cfg.Executors.MetadataExposures() {
		if x.InForce {
			fatal = append(fatal, x.Error())
			continue
		}
		fmt.Fprintf(warn, "warning: %s — the section is switched off, so it opens nothing today; "+
			"`cloop ui` will refuse to start once it is switched on\n", x.Error())
	}
	if len(fatal) == 0 {
		return nil
	}
	return fmt.Errorf("refusing to start: an egress_filter allowlist opens a cloud metadata service it does "+
		"not name. The compiled filter would keep the service closed, but the allowlist would not mean what it "+
		"says:\n  %s", strings.Join(fatal, "\n  "))
}

// uiListenRequest gathers what pkg/exposure decides the dashboard's address
// from (Task 20393): --listen over ui.listen, the browser credentials this
// start will have, and the acknowledgement. token is the static token as
// resolved from --token and CLOOP_UI_TOKEN.
//
// SSO counts as configured when ui.oidc.enabled is set: an enabled block that
// does not validate stops the start before the hub serves anything, so a hub
// that gets as far as listening has the sign-in this assumed.
func uiListenRequest(cfg *config.Config, token string) exposure.Request {
	r := exposure.Request{
		Listen:      strings.TrimSpace(uiListen),
		Source:      "--listen",
		Port:        uiPort,
		StaticToken: token != "",
		TLS:         strings.TrimSpace(uiTLSCert) != "",
	}
	if cfg == nil {
		return r
	}
	if r.Listen == "" {
		r.Listen, r.Source = strings.TrimSpace(cfg.UI.Listen), "ui.listen"
	}
	r.SSO = cfg.UI.OIDC.Enabled
	r.AllowUnauthenticatedNetwork = cfg.UI.AllowUnauthenticatedNetwork
	r.TLS = r.TLS || strings.TrimSpace(cfg.UI.TLS.CertFile) != ""
	r.ExternalURL, r.ExternalURLKey = cfg.UI.PublicURL()
	return r
}

// describeRuntimeBindings annotates the RBAC startup line with the runtime
// layer, and says nothing when there is none.
//
// Worth a line on a hub that has any: a deny binding is an authorization
// decision that no reviewed, deployed file records, so an operator reading
// startup output to answer "what policy is this process enforcing?" would
// otherwise be shown a complete-looking answer that is missing the part
// somebody added under pressure at 3am and may well have meant to remove.
func describeRuntimeBindings(bindings []authz.Binding) string {
	if len(bindings) == 0 {
		return ""
	}
	denies := 0
	for _, b := range bindings {
		if b.Deny {
			denies++
		}
	}
	return fmt.Sprintf(", plus %d runtime binding(s) (%d deny) — see `cloop hub role list`",
		len(bindings), denies)
}

// describeRevalidation renders the IdP-revocation state for the startup
// banner.
//
// It is spelled out rather than left implicit because the difference matters
// operationally and is otherwise invisible: on a hub with no CLOOP_SECRET_KEY
// there is no refresh token to redeem, so disabling a user at the identity
// provider does not end their cloop session until a timeout does. An operator
// should learn that at startup, not during an incident.
func describeRevalidation(refreshMinutes int, sealsRefreshTokens bool) string {
	if refreshMinutes < 0 {
		return "IdP revalidation disabled by config (refresh_interval_minutes: -1)"
	}
	if !sealsRefreshTokens {
		return "IdP revalidation unavailable (no CLOOP_SECRET_KEY — refresh tokens are not retained)"
	}
	return fmt.Sprintf("IdP revalidation every %s", time.Duration(refreshMinutes)*time.Minute)
}

// openBrowser opens the given URL in the default system browser.
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open browser: %v\n", err)
	}
}

// warnStaticTokenDeprecated prints the migration notice for the unscoped
// static bearer token (Task 20175).
//
// The token still works and will keep working — a hub that goes silent because
// its one credential was retired under it is a worse outcome than a shared
// secret. But it is genuinely worse than a PAT in three ways an operator
// should be told about at the moment they use it, rather than discovering in a
// post-mortem: it bypasses RBAC entirely, it sees every project on the hub, and
// it cannot be revoked for one caller without breaking all of them.
//
// Written to stderr so it survives a redirected stdout and does not corrupt a
// piped listing.
func warnStaticTokenDeprecated() {
	warn := color.New(color.FgYellow)
	dim := color.New(color.Faint)
	warn.Fprintln(os.Stderr, "warning: --token / CLOOP_UI_TOKEN is deprecated.")
	dim.Fprintln(os.Stderr,
		"  The static token bypasses RBAC, sees every project on this hub, and cannot be\n"+
			"  revoked for one caller without breaking every other. Scoped API tokens replace\n"+
			"  it: they carry roles, can be limited to specific projects, expire, and are\n"+
			"  revocable one at a time.\n"+
			"\n"+
			"    cloop hub token create ci --role operator --project my-app --expires-in 30d\n"+
			"\n"+
			"  Then drop --token / CLOOP_UI_TOKEN. See docs/security/model.md.")
}

func init() {
	uiCmd.Flags().IntVar(&uiPort, "port", defaultUIPort, "Port to listen on")
	uiCmd.Flags().StringVar(&uiListen, "listen", "",
		"Address to listen on, without the port: 127.0.0.1, 0.0.0.0, :: or one interface's address "+
			"(overrides ui.listen). Default: every interface with sign-in (ui.oidc or a token), "+
			"127.0.0.1 without; beyond loopback without sign-in needs ui.allow_unauthenticated_network")
	uiCmd.Flags().BoolVar(&uiNoBrowser, "no-browser", false, "Do not open the browser automatically")
	uiCmd.Flags().StringVar(&uiToken, "token", "",
		"DEPRECATED: unscoped static auth token (also reads CLOOP_UI_TOKEN). "+
			"Bypasses RBAC and sees every project — use `cloop hub token create` instead")
	uiCmd.Flags().StringArrayVar(&uiProjects, "projects", nil, "Additional project directories to include in the multi-project dashboard")
	uiCmd.Flags().StringVar(&uiScan, "scan", "", "Scan this directory for cloop projects and add them to the dashboard")
	uiCmd.Flags().Float64Var(&uiRateLimit, "rate-limit", 0, "Requests per second per IP (default 20; 0 = use default)")
	uiCmd.Flags().IntVar(&uiRateBurst, "rate-burst", 0, "Burst size per IP for rate limiter (default 50; 0 = use default)")
	uiCmd.Flags().StringVar(&uiTLSCert, "tls-cert", "", "PEM certificate chain to serve HTTPS with (overrides ui.tls.cert_file)")
	uiCmd.Flags().StringVar(&uiTLSKey, "tls-key", "", "PEM private key matching --tls-cert (overrides ui.tls.key_file)")
	uiCmd.Flags().StringVar(&uiAdvertiseURL, "advertise-url", "",
		"URL other hub processes serving this control plane reach this one at, e.g. "+
			"http://10.0.3.17:8080 (also CLOOP_CLUSTER_ADVERTISE_URL, CLOOP_CLUSTER_ADVERTISE_HOST for "+
			"just the host, or ui.cluster.advertise_url; default http(s)://127.0.0.1:<port>)")
	uiCmd.Flags().BoolVar(&uiRequireIdP, "require-idp", false,
		"Refuse to start when the OIDC issuer cannot be resolved, instead of warning and "+
			"retrying at the first sign-in (also settable as ui.oidc.require_idp)")
	rootCmd.AddCommand(uiCmd)
}
