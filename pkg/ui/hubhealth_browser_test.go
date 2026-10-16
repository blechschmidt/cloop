package ui

// Settings → Hub health and the header's indicator in a real browser (Task
// 20434): a hub with credentials in its configured URLs, markup in what its
// checks report, one check that never returns and one that panics. The
// administrator presses the indicator and lands on the section, the findings
// grouped by severity with their remedies and documentation; nothing secret
// is anywhere in the document and nothing a check wrote runs. A viewer's page
// never asks for the report and shows neither the indicator nor the section.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubdoctor"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

type hubHealthBrowserView struct {
	SectionShown bool     `json:"section_shown"`
	InSettings   bool     `json:"in_settings"`
	SectionTop   *int     `json:"section_top"`
	Viewport     int      `json:"viewport"`
	Groups       []string `json:"groups"`
	Findings     []string `json:"findings"`
	Links        []string `json:"links"`
	Injected     int      `json:"injected"`
	Member       string   `json:"member"`
	Status       string   `json:"status"`
	BadgeShown   bool     `json:"badge_shown"`
	BadgeText    string   `json:"badge_text"`
	Fetched      []string `json:"fetched"`
	CSP          []string `json:"csp"`
	XSS          *string  `json:"xss"`
	Before       int      `json:"before"`
}

type hubHealthBrowserResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	AtError       *hubHealthBrowserView `json:"at_error"`
	AdminBefore   hubHealthBrowserView  `json:"admin_before"`
	Admin         hubHealthBrowserView  `json:"admin"`
	AdminSecrets  []string              `json:"admin_secrets"`
	AdminRerun    hubHealthBrowserView  `json:"admin_rerun"`
	Viewer        hubHealthBrowserView  `json:"viewer"`
	ConsoleErrors []string              `json:"console_errors"`
}

func TestHubHealth_PanelInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot drive the panel")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	const (
		issuerPass   = "issuer-password-Br71k"
		clientSecret = "client-secret-value-Br72m"
		envSecret    = "environment-secret-Br73n"
		apiKey       = "anthropic-config-key-Br74p"
	)
	markup := `<img src=x onerror="window.__xss='finding'">`
	t.Setenv("CLOOP_TEST_HEALTH_TOKEN", envSecret)
	// A registry of its own, so this is a single-project hub whatever other
	// tests registered: a multi-project boot lands on the Projects tab.
	t.Setenv(multiui.EnvRoot, t.TempDir())

	dir := setupProjectDir(t, "hub health in a browser", nil)
	writeHubConfig(t, config.ConfigPath(dir), `
anthropic:
  api_key: `+apiKey+`
ui:
  oidc:
    enabled: true
    issuer: https://admin:`+issuerPass+`@idp.example.invalid/realms/main
    client_id: cloop
    client_secret: `+clientSecret+`
    redirect_url: https://hub.example.com/auth/callback
`)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv := New(dir, 0, "")
	// Two dashboard loads and their pushes come from one address, which is the
	// per-IP limiter's to measure, not this test's.
	srv.RPS, srv.Burst = 1e6, 1e6
	srv.hubHealth.extra = []hubdoctor.Check{
		{ID: "test.fixture", Title: "A check that quotes " + markup, Run: func(_ context.Context, add func(hubdoctor.Finding)) {
			add(hubdoctor.Finding{Check: "executors.health", Title: "Executor " + markup, Severity: hubdoctor.SeverityFail,
				Message: "unreachable at https://admin:" + issuerPass + "@idp.example.invalid " + markup +
					" with " + envSecret + " and " + clientSecret + " javascript:window.__xss='message'",
				Remediation: "Restart the agent " + markup,
				Details:     map[string]any{"names": []string{markup, apiKey}}})
		}},
		{ID: "test.hang", Title: "A check that never returns", Timeout: time.Second,
			Run: func(context.Context, func(hubdoctor.Finding)) { <-release }},
		{ID: "test.boom", Title: "A check that panics",
			Run: func(context.Context, func(hubdoctor.Finding)) { panic("a check's own bug") }},
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mgr, err := srv.tokenManager()
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := mgr.Mint(apitoken.MintOptions{Name: "health-viewer", Roles: []string{"viewer"},
		CreatedBy: "test@example.com", ExpiresAt: time.Now().Add(time.Hour), MintedUnder: apitoken.MintedUnderNoPolicy})
	if err != nil {
		t.Fatal(err)
	}
	// The token is the viewer's whole authority on this hub: confirm the hub
	// refuses it the report before asking the page not to request one.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/hub/health", nil)
	req.Header.Set("Authorization", "Bearer "+viewer.Plaintext)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the viewer token's GET /api/hub/health = %v %v, want 403", resp, err)
	} else {
		resp.Body.Close()
	}

	secrets := []string{issuerPass, clientSecret, envSecret, apiKey}
	cfgPath := filepath.Join(t.TempDir(), "driver.json")
	raw, _ := json.Marshal(map[string]any{"base": ts.URL, "viewerToken": viewer.Plaintext, "secrets": secrets})
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/hubhealth_browser.js"), chrome, cfgPath).Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var got hubHealthBrowserResults
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("driver output is not JSON: %v\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("driver failed in the browser:\n%s\nthe page showed: %+v", got.Error.Message, got.AtError)
	}

	// The indicator, before it is pressed: in the header, counting failures.
	if !got.AdminBefore.BadgeShown || !strings.Contains(got.AdminBefore.BadgeText, "⚠") {
		t.Errorf("the administrator's header shows the indicator as %v %q", got.AdminBefore.BadgeShown, got.AdminBefore.BadgeText)
	}
	a := got.Admin
	if !a.SectionShown || !a.InSettings || a.SectionTop == nil || *a.SectionTop < -2 || *a.SectionTop > a.Viewport/2 {
		t.Errorf("pressing the indicator left the section %+v (top %v of %d): want it on screen in Settings",
			a.SectionShown, a.SectionTop, a.Viewport)
	}
	if len(a.Groups) != 3 || !strings.HasPrefix(a.Groups[0], "Failing (") || !strings.HasPrefix(a.Groups[1], "Warnings (") ||
		!strings.HasPrefix(a.Groups[2], "Passing (") {
		t.Errorf("the findings are grouped as %q, want failing, warnings, passing", a.Groups)
	}
	if !strings.HasSuffix(got.AdminBefore.BadgeText, " "+strings.TrimSuffix(strings.TrimPrefix(a.Groups[0], "Failing ("), ")")) {
		t.Errorf("the indicator says %q while the panel lists %q", got.AdminBefore.BadgeText, a.Groups[0])
	}
	text := strings.Join(a.Findings, "\n")
	for _, want := range []string{markup, "Restart the agent " + markup, "A check that never returns", "did not finish within 1s",
		"A check that panics", "a check's own bug", "[redacted]"} {
		if !strings.Contains(text, want) {
			t.Errorf("the findings do not show %q as text:\n%s", want, text)
		}
	}
	if host, _ := os.Hostname(); !strings.Contains(a.Member, host) {
		t.Errorf("the panel does not say which member answered: %q", a.Member)
	}
	if len(a.Links) == 0 {
		t.Error("no finding links to its documentation")
	}
	for _, l := range a.Links {
		if !strings.HasPrefix(l, hubHealthDocsBase+"#") {
			t.Errorf("a finding links to %q, not the runbook", l)
		}
	}
	if a.Injected != 0 || a.XSS != nil || len(a.CSP) != 0 {
		t.Errorf("markup a check wrote became page content: %d element(s), __xss %v, violations %v", a.Injected, a.XSS, a.CSP)
	}
	if len(got.AdminSecrets) != 0 {
		t.Errorf("the page carries %v", got.AdminSecrets)
	}
	if r := got.AdminRerun; len(r.Fetched) <= r.Before || len(r.Findings) == 0 {
		t.Errorf("Run the checks again made %d request(s) after %d and shows %d finding(s)", len(r.Fetched), r.Before, len(r.Findings))
	}

	v := got.Viewer
	if len(v.Fetched) != 0 || v.BadgeShown || v.SectionShown {
		t.Errorf("a viewer's page asked for the report %d time(s) (%v), shows the indicator %v and the section %v",
			len(v.Fetched), v.Fetched, v.BadgeShown, v.SectionShown)
	}
	if len(got.ConsoleErrors) > 0 {
		t.Errorf("the page threw: %v", got.ConsoleErrors)
	}
}
