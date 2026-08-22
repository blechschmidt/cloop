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

Examples:
  cloop serve                          # start on default port 8081
  cloop serve --port 9000              # custom port
  cloop serve --token mysecret         # enable bearer-token auth
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
		}
		if serveTLSCert != "" || serveTLSKey != "" {
			srv.TLSCertFile, srv.TLSKeyFile = serveTLSCert, serveTLSKey
		}
		return srv.Start()
	},
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 8081, "Port to listen on")
	serveCmd.Flags().StringVar(&serveToken, "token", "", "Bearer auth token (also reads CLOOP_API_TOKEN env var)")
	serveCmd.Flags().Float64Var(&serveRateLimit, "rate-limit", 0, "Requests per second per IP (default 20; 0 = use default)")
	serveCmd.Flags().IntVar(&serveRateBurst, "rate-burst", 0, "Burst size per IP for rate limiter (default 50; 0 = use default)")
	serveCmd.Flags().StringVar(&serveTLSCert, "tls-cert", "", "PEM certificate chain to serve HTTPS with (overrides ui.tls.cert_file)")
	serveCmd.Flags().StringVar(&serveTLSKey, "tls-key", "", "PEM private key matching --tls-cert (overrides ui.tls.key_file)")
	rootCmd.AddCommand(serveCmd)
}
