package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/apiserver"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/spf13/cobra"
)

var (
	servePort      int
	serveToken     string
	serveRateLimit float64
	serveRateBurst int
	serveTLSCert   string
	serveTLSKey    string
	serveListen    string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a REST API server exposing all cloop functionality",
	Long: `Start a standalone HTTP REST API server that exposes cloop over HTTP.

Designed for CI/CD integration, external dashboards, and scripting without
the TUI or Web UI. An OpenAPI 3.0 specification is always available at
/openapi.json regardless of authentication settings.

Routes:
  GET    /plan                  Current plan (goal + tasks)
  PATCH  /tasks/{id}            Update a task (status, title, priority, tags)
  POST   /run/start             Start a 'cloop run' subprocess
  POST   /run/stop              Stop the running subprocess
  GET    /status                Lightweight status summary
  GET    /metrics               Run metrics (Prometheus text or JSON)
  GET    /artifacts/{taskId}    Task output artifact (Markdown or JSON)
  GET    /openapi.json          OpenAPI 3.0 specification (always public)

Authentication:
  If --token is provided (or CLOOP_API_TOKEN env var is set), every request
  must include "Authorization: Bearer <token>" or "?token=<token>".

  Without a token anyone who reaches the server can start runs on this host,
  so it then listens on 127.0.0.1 only; with one it listens on every
  interface. --listen names an address instead, and one beyond loopback is
  refused without a token unless ui.allow_unauthenticated_network is true.

Examples:
  cloop serve                          # start on default port 8081
  cloop serve --port 9000              # custom port
  cloop serve --token mysecret         # enable bearer-token auth (every interface)
  cloop serve --listen 127.0.0.1 --token mysecret   # loopback only, behind a proxy
  CLOOP_API_TOKEN=abc cloop serve      # token via env var

  # CI/CD usage
  curl http://localhost:8081/status
  curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/plan
  curl -X POST http://localhost:8081/run/start -d '{"pm":true}'
  curl -X PATCH http://localhost:8081/tasks/3 -d '{"status":"done"}'

TLS: pass --tls-cert/--tls-key, or configure ui.tls in .cloop/config.yaml
(the same block cloop ui uses). The bearer token is sent on every request and
grants the ability to start runs, so a network-reachable API server should
never speak plaintext. See ` + "`cloop hub tls-init`" + ` for a development
certificate.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		token := serveToken
		if token == "" {
			token = os.Getenv("CLOOP_API_TOKEN")
		}

		srv := apiserver.New(workdir, servePort, token)
		srv.RPS = serveRateLimit
		srv.Burst = serveRateBurst
		srv.ListenHost = serveListen

		// Unlike cloop ui this command was flags-only; it now reads the shared
		// ui.tls block so a deployment configures TLS once and both servers
		// pick it up. Failure to load config stays non-fatal, but a config
		// that asks for TLS and cannot deliver it does not.
		// A parse failure is fatal rather than a warning: silently ignoring a
		// broken config would serve the bearer token — which can start runs —
		// over plaintext, with only a line on stderr to say so. Load returns
		// defaults with a nil error when the file is absent.
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("could not load %s: %w", config.ConfigPath(workdir), err)
		}
		if cfg != nil {
			if err := cfg.UI.TLS.Validate(); err != nil {
				return err
			}
			srv.TLSCertFile = cfg.UI.TLS.CertFile
			srv.TLSKeyFile = cfg.UI.TLS.KeyFile
			srv.TLSMinVersion = cfg.UI.TLS.MinVersion
			// The acknowledgement is the dashboard's key, from the same shared
			// ui block: one decision about serving without a credential, not one
			// per server (Task 20393).
			srv.AllowUnauthenticatedNetwork = cfg.UI.AllowUnauthenticatedNetwork
		}
		if serveTLSCert != "" || serveTLSKey != "" {
			srv.TLSCertFile, srv.TLSKeyFile = serveTLSCert, serveTLSKey
		}
		return srv.Start()
	},
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 8081, "Port to listen on")
	serveCmd.Flags().StringVar(&serveListen, "listen", "",
		"Address to listen on, without the port: 127.0.0.1, 0.0.0.0, :: or one interface's address. "+
			"Default: every interface with a token, 127.0.0.1 without; beyond loopback without a token "+
			"needs ui.allow_unauthenticated_network")
	serveCmd.Flags().StringVar(&serveToken, "token", "", "Bearer auth token (also reads CLOOP_API_TOKEN env var)")
	serveCmd.Flags().Float64Var(&serveRateLimit, "rate-limit", 0, "Requests per second per IP (default 20; 0 = use default)")
	serveCmd.Flags().IntVar(&serveRateBurst, "rate-burst", 0, "Burst size per IP for rate limiter (default 50; 0 = use default)")
	serveCmd.Flags().StringVar(&serveTLSCert, "tls-cert", "", "PEM certificate chain to serve HTTPS with (overrides ui.tls.cert_file)")
	serveCmd.Flags().StringVar(&serveTLSKey, "tls-key", "", "PEM private key matching --tls-cert (overrides ui.tls.key_file)")
	rootCmd.AddCommand(serveCmd)
}
