package cmd

import (
	"os"

	"github.com/blechschmidt/cloop/pkg/apiserver"
	"github.com/spf13/cobra"
)

var (
	servePort      int
	serveToken     string
	serveRateLimit float64
	serveRateBurst int
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
  curl -X PATCH http://localhost:8081/tasks/3 -d '{"status":"done"}'`,

	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		token := serveToken
		if token == "" {
			token = os.Getenv("CLOOP_API_TOKEN")
		}

		srv := apiserver.New(workdir, servePort, token)
		srv.RPS = serveRateLimit
		srv.Burst = serveRateBurst
		return srv.Start()
	},
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 8081, "Port to listen on")
	serveCmd.Flags().StringVar(&serveToken, "token", "", "Bearer auth token (also reads CLOOP_API_TOKEN env var)")
	serveCmd.Flags().Float64Var(&serveRateLimit, "rate-limit", 0, "Requests per second per IP (default 20; 0 = use default)")
	serveCmd.Flags().IntVar(&serveRateBurst, "rate-burst", 0, "Burst size per IP for rate limiter (default 50; 0 = use default)")
	rootCmd.AddCommand(serveCmd)
}
