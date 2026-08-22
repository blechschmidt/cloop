package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	uiPort      int
	uiNoBrowser bool
	uiToken     string
	uiProjects  []string
	uiScan      string
	uiRateLimit float64
	uiRateBurst int
	uiTLSCert   string
	uiTLSKey    string
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Start a local web dashboard for monitoring and controlling cloop",
	Long: `Start a local web server that serves a real-time dashboard on http://localhost:8080.

The dashboard shows the project goal, status, step history with outputs,
task list (PM mode), live progress via SSE, and run/stop controls.

  cloop ui                            # single-project mode (cwd)
  cloop ui --port 9090                # use a custom port
  cloop ui --no-browser               # don't open the browser automatically
  cloop ui --projects /a /b /c        # multi-project overview dashboard
  cloop ui --scan /root/Projects      # auto-discover cloop projects under dir
  cloop ui --tls-cert c.pem --tls-key k.pem   # serve HTTPS directly

TLS may also be configured under ui.tls in .cloop/config.yaml; the flags win
when both are present. Run ` + "`cloop hub tls-init`" + ` for a development
certificate. Without either, the dashboard serves plaintext, which is correct
for loopback use and for a deployment that terminates TLS in a reverse proxy —
but not for anything reachable from a network.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		token := uiToken
		if token == "" {
			token = os.Getenv("CLOOP_UI_TOKEN")
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

		srv := ui.New(workdir, uiPort, token)
		srv.Projects = projectPaths
		srv.RPS = uiRateLimit
		srv.Burst = uiRateBurst

		// Load .cloop/config.yaml. A parse failure is fatal, not a warning:
		// every security-relevant setting the dashboard has — TLS, the origin
		// allowlist, the WebSocket caps, and OIDC itself — lives in this file,
		// so a one-character YAML typo would otherwise start a hardened
		// deployment in plaintext with no authentication and only a line on
		// stderr to say so. Load returns defaults with a nil error when the
		// file is absent, so the no-config case is unaffected.
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("could not load %s: %w", config.ConfigPath(workdir), err)
		}
		if cfg != nil {
			srv.MaxWebSocketConns = cfg.UI.MaxWebSocketConns
			srv.MaxWebSocketConnsPerIP = cfg.UI.MaxWebSocketConnsPerIP
			srv.AllowedWSOrigins = cfg.UI.AllowedWSOrigins
			srv.AllowedOrigins = cfg.UI.AllowedOrigins
			srv.ExternalURL = cfg.UI.ExternalURL
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
				auth, oidcErr := oidcauth.New(oidcauth.Config{
					Enabled:      true,
					Issuer:       cfg.UI.OIDC.Issuer,
					ClientID:     cfg.UI.OIDC.ClientID,
					ClientSecret: cfg.UI.OIDC.ClientSecret,
					RedirectURL:  cfg.UI.OIDC.RedirectURL,
					Scopes:       cfg.UI.OIDC.Scopes,
					AdminEmails:  cfg.UI.OIDC.AdminEmails,
					SessionTTL:   time.Duration(cfg.UI.OIDC.EffectiveSessionTTLHours()) * time.Hour,
					CookieSecure: cfg.UI.OIDC.CookieSecure,
				})
				if oidcErr != nil {
					return fmt.Errorf("ui.oidc is enabled but invalid: %w", oidcErr)
				}
				srv.OIDC = auth

				// Claim-based RBAC (ui.oidc.role_mappings — Task 20164).
				// Fail-closed for the same reason: a typo in a role name
				// must not silently degrade to a binding that never
				// matches (and therefore a user who is denied everything,
				// or worse, a default_role that was meant to be narrower).
				resolver, authzErr := authz.New(authz.Config{
					DefaultRole: authz.Role(cfg.UI.OIDC.DefaultRole),
					Bindings:    roleMappingsToBindings(cfg.UI.OIDC.RoleMappings),
					AdminEmails: cfg.UI.OIDC.AdminEmails,
				})
				if authzErr != nil {
					return fmt.Errorf("ui.oidc role mappings are invalid: %w", authzErr)
				}
				srv.Authz = resolver

				fmt.Printf("OIDC authentication enabled (issuer: %s)\n", cfg.UI.OIDC.Issuer)
				fmt.Printf("RBAC: %d role mapping(s), default role %q\n",
					len(cfg.UI.OIDC.RoleMappings), effectiveDefaultRole(cfg.UI.OIDC.DefaultRole))
			}
		}

		if uiTLSCert != "" || uiTLSKey != "" {
			srv.TLSCertFile, srv.TLSKeyFile = uiTLSCert, uiTLSKey
		}

		// Open the browser only after the scheme is settled, so the URL
		// matches what the server will actually speak. Opening http:// against
		// an HTTPS listener produces an empty tab and a confusing bug report.
		if !uiNoBrowser {
			scheme := "http"
			if srv.TLSEnabled() {
				scheme = "https"
			}
			go openBrowser(scheme + "://localhost:" + strconv.Itoa(uiPort))
		}

		return srv.Start()
	},
}

// roleMappingsToBindings converts the YAML shape into the authz model.
// Validation (unknown roles, unknown claim kinds, empty values) happens in
// authz.New so there is exactly one place that decides what is well-formed.
func roleMappingsToBindings(mappings []config.RoleMapping) []authz.Binding {
	if len(mappings) == 0 {
		return nil
	}
	bindings := make([]authz.Binding, 0, len(mappings))
	for _, m := range mappings {
		bindings = append(bindings, authz.Binding{
			Claim:    authz.ClaimKind(m.Claim),
			Value:    m.Value,
			Role:     authz.Role(m.Role),
			Project:  m.Project,
			Executor: m.Executor,
		})
	}
	return bindings
}

// effectiveDefaultRole renders the configured default for the startup
// banner, substituting the deny-by-default that an empty setting means.
func effectiveDefaultRole(configured string) string {
	if configured == "" {
		return string(authz.RoleNone)
	}
	return configured
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

func init() {
	uiCmd.Flags().IntVar(&uiPort, "port", 8080, "Port to listen on")
	uiCmd.Flags().BoolVar(&uiNoBrowser, "no-browser", false, "Do not open the browser automatically")
	uiCmd.Flags().StringVar(&uiToken, "token", "", "Auth token (also reads CLOOP_UI_TOKEN env var); if set, all API requests must supply it")
	uiCmd.Flags().StringArrayVar(&uiProjects, "projects", nil, "Additional project directories to include in the multi-project dashboard")
	uiCmd.Flags().StringVar(&uiScan, "scan", "", "Scan this directory for cloop projects and add them to the dashboard")
	uiCmd.Flags().Float64Var(&uiRateLimit, "rate-limit", 0, "Requests per second per IP (default 20; 0 = use default)")
	uiCmd.Flags().IntVar(&uiRateBurst, "rate-burst", 0, "Burst size per IP for rate limiter (default 50; 0 = use default)")
	uiCmd.Flags().StringVar(&uiTLSCert, "tls-cert", "", "PEM certificate chain to serve HTTPS with (overrides ui.tls.cert_file)")
	uiCmd.Flags().StringVar(&uiTLSKey, "tls-key", "", "PEM private key matching --tls-cert (overrides ui.tls.key_file)")
	rootCmd.AddCommand(uiCmd)
}
