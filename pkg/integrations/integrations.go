// Package integrations provides a unified health dashboard for all external
// service integrations configured in a cloop project. It checks connectivity
// and validity for GitHub, Slack/Discord webhooks, generic webhooks, the
// Prometheus metrics endpoint, plugins, and MCP.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/plugin"
)

// IntegrationStatus is the result of a single integration health check.
type IntegrationStatus struct {
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
	Healthy    bool   `json:"healthy"`
	Detail     string `json:"detail"`
}

// httpClient is shared across all HTTP checks with a short timeout.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// Check runs all integration health checks and returns the results.
// Integrations that are not configured are included with Configured=false.
func Check(ctx context.Context, workDir string, cfg *config.Config) []IntegrationStatus {
	var statuses []IntegrationStatus

	statuses = append(statuses, checkGitHub(ctx, cfg)...)
	statuses = append(statuses, checkSlackWebhook(ctx, cfg))
	statuses = append(statuses, checkDiscordWebhook(ctx, cfg))
	statuses = append(statuses, checkGenericWebhook(ctx, cfg))
	statuses = append(statuses, checkPrometheusMetrics(workDir))
	statuses = append(statuses, checkMCP())
	statuses = append(statuses, checkPlugins(workDir)...)

	return statuses
}

// ----------------------------------------------------------------------------
// GitHub
// ----------------------------------------------------------------------------

func checkGitHub(ctx context.Context, cfg *config.Config) []IntegrationStatus {
	token := cfg.GitHub.Token
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	tokenStatus := checkGitHubToken(ctx, token)
	results := []IntegrationStatus{tokenStatus}

	if cfg.GitHub.Repo != "" {
		results = append(results, checkGitHubRepo(ctx, token, cfg.GitHub.Repo))
	}

	return results
}

func checkGitHubToken(ctx context.Context, token string) IntegrationStatus {
	if token == "" {
		return IntegrationStatus{
			Name:       "GitHub token",
			Configured: false,
			Detail:     "not configured (set github.token or GITHUB_TOKEN)",
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return IntegrationStatus{
			Name:       "GitHub token",
			Configured: true,
			Detail:     fmt.Sprintf("error building request: %v", err),
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := httpClient.Do(req)
	if err != nil {
		return IntegrationStatus{
			Name:       "GitHub token",
			Configured: true,
			Detail:     fmt.Sprintf("request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	if resp.StatusCode == http.StatusOK {
		var user struct {
			Login string `json:"login"`
		}
		if err := json.Unmarshal(body, &user); err == nil && user.Login != "" {
			return IntegrationStatus{
				Name:       "GitHub token",
				Configured: true,
				Healthy:    true,
				Detail:     fmt.Sprintf("authenticated as %s", user.Login),
			}
		}
		return IntegrationStatus{
			Name:       "GitHub token",
			Configured: true,
			Healthy:    true,
			Detail:     "token valid",
		}
	}

	var apiErr struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &apiErr)
	detail := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if apiErr.Message != "" {
		detail += ": " + apiErr.Message
	}
	return IntegrationStatus{
		Name:       "GitHub token",
		Configured: true,
		Detail:     detail,
	}
}

func checkGitHubRepo(ctx context.Context, token, repo string) IntegrationStatus {
	url := "https://api.github.com/repos/" + repo
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return IntegrationStatus{
			Name:       "GitHub repo " + repo,
			Configured: true,
			Detail:     fmt.Sprintf("error building request: %v", err),
		}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := httpClient.Do(req)
	if err != nil {
		return IntegrationStatus{
			Name:       "GitHub repo " + repo,
			Configured: true,
			Detail:     fmt.Sprintf("request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	if resp.StatusCode == http.StatusOK {
		var r struct {
			FullName    string `json:"full_name"`
			Private     bool   `json:"private"`
			Permissions struct {
				Push bool `json:"push"`
			} `json:"permissions"`
		}
		_ = json.Unmarshal(body, &r)
		detail := "accessible"
		if r.Permissions.Push {
			detail = "accessible (write access)"
		} else if r.FullName != "" {
			detail = "accessible (read-only)"
		}
		return IntegrationStatus{
			Name:       "GitHub repo " + repo,
			Configured: true,
			Healthy:    true,
			Detail:     detail,
		}
	}

	var apiErr struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &apiErr)
	detail := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if apiErr.Message != "" {
		detail += ": " + apiErr.Message
	}
	return IntegrationStatus{
		Name:       "GitHub repo " + repo,
		Configured: true,
		Detail:     detail,
	}
}

// ----------------------------------------------------------------------------
// Slack webhook
// ----------------------------------------------------------------------------

func checkSlackWebhook(ctx context.Context, cfg *config.Config) IntegrationStatus {
	url := cfg.Notify.SlackWebhook
	if url == "" {
		return IntegrationStatus{
			Name:       "Slack webhook",
			Configured: false,
			Detail:     "not configured (set notify.slack_webhook)",
		}
	}
	return checkWebhookURL(ctx, "Slack webhook", url)
}

// ----------------------------------------------------------------------------
// Discord webhook
// ----------------------------------------------------------------------------

func checkDiscordWebhook(ctx context.Context, cfg *config.Config) IntegrationStatus {
	url := cfg.Notify.DiscordWebhook
	if url == "" {
		return IntegrationStatus{
			Name:       "Discord webhook",
			Configured: false,
			Detail:     "not configured (set notify.discord_webhook)",
		}
	}
	return checkWebhookURL(ctx, "Discord webhook", url)
}

// ----------------------------------------------------------------------------
// Generic webhook
// ----------------------------------------------------------------------------

func checkGenericWebhook(ctx context.Context, cfg *config.Config) IntegrationStatus {
	url := cfg.Webhook.URL
	if url == "" {
		return IntegrationStatus{
			Name:       "Generic webhook",
			Configured: false,
			Detail:     "not configured (set webhook.url)",
		}
	}
	return checkWebhookURL(ctx, "Generic webhook", url)
}

// checkWebhookURL performs a lightweight reachability check against a webhook URL.
// We send a HEAD request; many endpoints return 405 for HEAD which is fine.
// A 5xx or connection error indicates unhealthy.
func checkWebhookURL(ctx context.Context, name, url string) IntegrationStatus {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return IntegrationStatus{
			Name:       name,
			Configured: true,
			Detail:     fmt.Sprintf("invalid URL: %v", err),
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Network error — try a minimal POST to see if endpoint is up.
		postReq, perr := http.NewRequestWithContext(ctx, http.MethodPost, url,
			bytes.NewBufferString(`{}`))
		if perr != nil {
			return IntegrationStatus{
				Name:       name,
				Configured: true,
				Detail:     fmt.Sprintf("unreachable: %v", err),
			}
		}
		postReq.Header.Set("Content-Type", "application/json")
		postResp, postErr := httpClient.Do(postReq)
		if postErr != nil {
			return IntegrationStatus{
				Name:       name,
				Configured: true,
				Detail:     fmt.Sprintf("unreachable: %v", err),
			}
		}
		postResp.Body.Close()
		if postResp.StatusCode < 500 {
			return IntegrationStatus{
				Name:       name,
				Configured: true,
				Healthy:    true,
				Detail:     fmt.Sprintf("reachable (POST HTTP %d)", postResp.StatusCode),
			}
		}
		return IntegrationStatus{
			Name:       name,
			Configured: true,
			Detail:     fmt.Sprintf("server error (POST HTTP %d)", postResp.StatusCode),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return IntegrationStatus{
			Name:       name,
			Configured: true,
			Detail:     fmt.Sprintf("server error (HTTP %d)", resp.StatusCode),
		}
	}
	return IntegrationStatus{
		Name:       name,
		Configured: true,
		Healthy:    true,
		Detail:     fmt.Sprintf("reachable (HTTP %d)", resp.StatusCode),
	}
}

// ----------------------------------------------------------------------------
// Prometheus metrics
// ----------------------------------------------------------------------------

// checkPrometheusMetrics checks whether the Prometheus metrics integration
// is active. Since the metrics HTTP server is started at runtime via
// --metrics-addr, we check whether .cloop/metrics.json exists (indicating
// metrics have been collected) and whether its content is valid JSON.
func checkPrometheusMetrics(workDir string) IntegrationStatus {
	metricsPath := filepath.Join(workDir, ".cloop", "metrics.json")
	data, err := os.ReadFile(metricsPath)
	if os.IsNotExist(err) {
		return IntegrationStatus{
			Name:       "Prometheus metrics",
			Configured: false,
			Detail:     "not configured (run with --metrics-addr to enable)",
		}
	}
	if err != nil {
		return IntegrationStatus{
			Name:       "Prometheus metrics",
			Configured: true,
			Detail:     fmt.Sprintf("cannot read metrics.json: %v", err),
		}
	}
	if !json.Valid(data) {
		return IntegrationStatus{
			Name:       "Prometheus metrics",
			Configured: true,
			Detail:     "metrics.json contains invalid JSON",
		}
	}

	// Parse timestamp to report freshness.
	var summary struct {
		Timestamp time.Time `json:"timestamp"`
	}
	detail := "metrics.json present"
	if err := json.Unmarshal(data, &summary); err == nil && !summary.Timestamp.IsZero() {
		age := time.Since(summary.Timestamp).Round(time.Second)
		detail = fmt.Sprintf("metrics.json present (last run: %s ago)", age)
	}
	return IntegrationStatus{
		Name:       "Prometheus metrics",
		Configured: true,
		Healthy:    true,
		Detail:     detail,
	}
}

// ----------------------------------------------------------------------------
// MCP server
// ----------------------------------------------------------------------------

// checkMCP checks whether the MCP (Model Context Protocol) server can be used.
// MCP runs over stdio so there is no network endpoint to ping. Instead we
// verify that the cloop binary itself is executable (it is, since we're running)
// and that any required dependencies are present.
func checkMCP() IntegrationStatus {
	// The MCP server is built into cloop — it's always "configured" if cloop runs.
	// We verify the claude binary for the claudecode backend since MCP features
	// often interact with it.
	_, err := exec.LookPath("claude")
	if err != nil {
		return IntegrationStatus{
			Name:       "MCP server (stdio)",
			Configured: true,
			Detail:     "not tested: MCP runs over stdio; claude CLI not found in PATH (optional for non-claudecode providers)",
		}
	}
	return IntegrationStatus{
		Name:       "MCP server (stdio)",
		Configured: true,
		Healthy:    true,
		Detail:     "cloop MCP server ready; claude CLI found in PATH",
	}
}

// ----------------------------------------------------------------------------
// Plugins
// ----------------------------------------------------------------------------

func checkPlugins(workDir string) []IntegrationStatus {
	plugins, err := plugin.Discover(workDir)
	if err != nil {
		return []IntegrationStatus{{
			Name:       "plugins",
			Configured: true,
			Detail:     fmt.Sprintf("discovery failed: %v", err),
		}}
	}

	if len(plugins) == 0 {
		return []IntegrationStatus{{
			Name:       "plugins",
			Configured: false,
			Detail:     "no plugins found (.cloop/plugins/ or ~/.cloop/plugins/)",
		}}
	}

	var results []IntegrationStatus
	for _, p := range plugins {
		results = append(results, checkPlugin(p))
	}
	return results
}

func checkPlugin(p *plugin.Plugin) IntegrationStatus {
	name := fmt.Sprintf("plugin: %s (%s)", p.Name, p.Scope)

	// Verify the plugin is still present and executable.
	info, err := os.Stat(p.Path)
	if err != nil {
		return IntegrationStatus{
			Name:       name,
			Configured: true,
			Detail:     fmt.Sprintf("not found: %v", err),
		}
	}
	if info.Mode()&0o111 == 0 {
		return IntegrationStatus{
			Name:       name,
			Configured: true,
			Detail:     "file exists but is not executable",
		}
	}

	// Run `<plugin> describe` with a short timeout to verify health.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, p.Path, "describe").Output()
	if err != nil {
		return IntegrationStatus{
			Name:       name,
			Configured: true,
			Detail:     fmt.Sprintf("describe failed: %v", err),
		}
	}

	desc := strings.TrimSpace(string(out))
	if desc == "" {
		desc = "(no description)"
	}
	return IntegrationStatus{
		Name:       name,
		Configured: true,
		Healthy:    true,
		Detail:     desc,
	}
}
