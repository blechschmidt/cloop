package ui

// Settings → Notifications (Task 20427): the webhook URL is write-only, a save
// is validated whole and audited without the URL, a test reaches only a
// configured webhook, and only an administrator may do any of it.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
)

// putJSONAs sends a PUT with a signed-in client and returns status and body.
func putJSONAs(t *testing.T, c *http.Client, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestNotificationSettingsKeepTheWebhookURLWriteOnly(t *testing.T) {
	f := newApprovalsFixture(t)
	rec := newWebhookReceiver(t)
	admin := f.as(t, "admin@example.com")
	secretPath := "/services/T0SECRET/B0SECRET/abcdefghijklmnop"
	hookURL := rec.srv.URL + secretPath

	body, _ := json.Marshal(map[string]any{
		"dashboard_url": "https://hub.example.com",
		"webhooks": []map[string]any{{
			"name": "approvers", "type": "json", "url": hookURL, "allow_addresses": []string{"127.0.0.1"},
			"ca_file": rec.caFile, "events": []string{"request.filed", "request.reminder"},
		}},
	})
	status, resp := putJSONAs(t, admin, f.ts+"/api/config/notifications", string(body))
	if status != http.StatusOK {
		t.Fatalf("PUT = %d %s", status, resp)
	}
	if strings.Contains(resp, "T0SECRET") {
		t.Fatalf("the save's answer repeats the webhook URL: %s", resp)
	}

	var view notificationsSettingsView
	if code := getJSONAs(t, admin, f.ts+"/api/config/notifications", &view); code != http.StatusOK {
		t.Fatalf("GET = %d", code)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "T0SECRET") {
		t.Fatalf("GET returns the webhook URL: %s", raw)
	}
	if len(view.Webhooks) != 1 || !view.Webhooks[0].URLSet || view.Webhooks[0].Destination != rec.srv.URL ||
		view.Link != "https://hub.example.com/?approvals=1" {
		t.Fatalf("view = %+v", view)
	}

	// A save that leaves the URL out keeps the stored one.
	body, _ = json.Marshal(map[string]any{"webhooks": []map[string]any{{
		"name": "approvers", "type": "json", "allow_addresses": []string{"127.0.0.1"}, "ca_file": rec.caFile,
	}}})
	if status, resp := putJSONAs(t, admin, f.ts+"/api/config/notifications", string(body)); status != http.StatusOK {
		t.Fatalf("PUT keeping the URL = %d %s", status, resp)
	}
	cfg, err := f.srv.loadHubConfig()
	if err != nil {
		t.Fatal(err)
	}
	if hooks := cfg.Notifications.Webhooks; len(hooks) != 1 || hooks[0].URL != hookURL || len(hooks[0].Events) != 0 {
		t.Fatalf("stored webhooks after a URL-less save = %+v", hooks)
	}

	// The test message goes to the configured webhook, through the guarded
	// client; a name that is not configured reaches nothing.
	if status, resp := do(t, admin, http.MethodPost, f.ts+"/api/config/notifications/test", `{"name":"approvers"}`); status != http.StatusOK {
		t.Fatalf("test = %d %s", status, resp)
	}
	rec.mu.Lock()
	n := len(rec.got)
	event := ""
	if n > 0 {
		event, _ = rec.got[n-1]["event"].(string)
	}
	rec.mu.Unlock()
	if n != 1 || event != "test" {
		t.Fatalf("the receiver got %d message(s), last %q; want one test message", n, event)
	}
	if status, _ := do(t, admin, http.MethodPost, f.ts+"/api/config/notifications/test", `{"name":"nope"}`); status != http.StatusNotFound {
		t.Fatalf("testing an unconfigured name = %d, want 404", status)
	}

	// Refused whole, with the reason, and nothing stored.
	for _, bad := range []string{
		`{"webhooks":[{"name":"p","type":"json","url":"http://collector.internal/hook"}]}`,
		`{"webhooks":[{"name":"new","type":"slack"}]}`,
		`{"webhooks":[{"name":"m","type":"json","url":"https://example.com/x","allow_addresses":["169.254.169.254"]}]}`,
	} {
		if status, resp := putJSONAs(t, admin, f.ts+"/api/config/notifications", bad); status != http.StatusBadRequest {
			t.Errorf("PUT %s = %d %s, want 400", bad, status, resp)
		}
	}

	// Audited, by host, never by URL.
	rows := auditRowsOf(t, f.srv.WorkDir, auditaction.ActionNotificationsConfigUpdated)
	if len(rows) != 2 {
		t.Fatalf("%d notifications.config.updated row(s), want 2 (the URL-less save changed the events)", len(rows))
	}
	for _, r := range rows {
		if strings.Contains(r.Payload, "T0SECRET") || !strings.Contains(r.Payload, "approvers (json) "+rec.srv.URL) ||
			r.Actor != "admin@example.com" {
			t.Fatalf("audit row = actor %s payload %s", r.Actor, r.Payload)
		}
	}

	// A maintainer may do none of it.
	maint := f.as(t, "maint@example.com")
	if code := getJSONAs(t, maint, f.ts+"/api/config/notifications", nil); code != http.StatusForbidden {
		t.Fatalf("a maintainer reading the notification settings = %d, want 403", code)
	}
	if status, _ := do(t, maint, http.MethodPost, f.ts+"/api/config/notifications/test", `{"name":"approvers"}`); status != http.StatusForbidden {
		t.Fatalf("a maintainer sending a test = %d, want 403", status)
	}
}

// TestApprovalsLinkPrefersTheConfiguredDashboard: a message links to
// notifications.dashboard_url, then the hub's external URL, then the origin
// people sign in at, and to nothing rather than a loopback listener.
func TestApprovalsLinkPrefersTheConfiguredDashboard(t *testing.T) {
	s := &Server{}
	cfg := &config.Config{}
	if got := s.approvalsLink(cfg); got != "" {
		t.Fatalf("with no address known the link is %q, want none", got)
	}
	cfg.UI.OIDC.Enabled, cfg.UI.OIDC.RedirectURL = true, "https://sso.example.com/auth/oidc"
	if got := s.approvalsLink(cfg); got != "https://sso.example.com/?approvals=1" {
		t.Fatalf("from the redirect URL: %q", got)
	}
	s.ExternalURL = "https://hub.example.com/cloop/"
	if got := s.approvalsLink(cfg); got != "https://hub.example.com/cloop/?approvals=1" {
		t.Fatalf("from the external URL: %q", got)
	}
	cfg.Notifications.DashboardURL = "https://approvals.example.com"
	if got := s.approvalsLink(cfg); got != "https://approvals.example.com/?approvals=1" {
		t.Fatalf("from dashboard_url: %q", got)
	}
}

// TestNotificationSettingsTakeTheURLFromTheEnvironment: url_env names a
// CLOOP_NOTIFY_* variable of the hub process — shown by name, with whether
// this member has it set, never its value — and no other variable; and a
// webhook removed in Settings loses its delivery cursor at once, so adding it
// back does not replay what it missed.
func TestNotificationSettingsTakeTheURLFromTheEnvironment(t *testing.T) {
	f := newApprovalsFixture(t)
	admin := f.as(t, "admin@example.com")
	t.Setenv("CLOOP_NOTIFY_APPROVERS", "https://hooks.example.com/services/T0ENVSECRET")

	put := func(body string) (int, string) { return putJSONAs(t, admin, f.ts+"/api/config/notifications", body) }
	if status, resp := put(`{"webhooks":[{"name":"approvers","type":"slack","url_env":"CLOOP_NOTIFY_APPROVERS"},` +
		`{"name":"unset","type":"json","url_env":"CLOOP_NOTIFY_NOWHERE"}]}`); status != http.StatusOK {
		t.Fatalf("PUT = %d %s", status, resp)
	}
	var view notificationsSettingsView
	getJSONAs(t, admin, f.ts+"/api/config/notifications", &view)
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "T0ENVSECRET") {
		t.Fatalf("the settings return the URL the environment holds: %s", raw)
	}
	byName := map[string]notificationWebhookView{}
	for _, w := range view.Webhooks {
		byName[w.Name] = w
	}
	if w := byName["approvers"]; w.URLEnv != "CLOOP_NOTIFY_APPROVERS" || !w.URLEnvSet || w.URLSet ||
		w.Destination != "env:CLOOP_NOTIFY_APPROVERS" {
		t.Fatalf("approvers = %+v", w)
	}
	if w := byName["unset"]; w.URLEnvSet {
		t.Fatalf("a variable this member does not have is reported set: %+v", w)
	}
	for _, bad := range []string{"CLOOP_SECRET_KEY", "ANTHROPIC_API_KEY", "cloop_notify_x"} {
		if status, _ := put(`{"webhooks":[{"name":"x","type":"json","url_env":"` + bad + `"}]}`); status != http.StatusBadRequest {
			t.Errorf("url_env %s = %d, want 400: a webhook reads only a variable set for it", bad, status)
		}
	}

	// A cursor the notifier made for "unset", then the webhook removed.
	db, err := f.srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InitApprovalNotifyCursor("unset", 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if status, resp := put(`{"webhooks":[{"name":"approvers","type":"slack"}]}`); status != http.StatusOK {
		t.Fatalf("PUT removing a webhook = %d %s", status, resp)
	}
	db, err = f.srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, ok, _ := db.ApprovalNotifyCursorFor("unset"); ok {
		t.Fatal("a webhook removed in Settings kept its delivery cursor")
	}
	cfg, err := f.srv.loadHubConfig()
	if err != nil {
		t.Fatal(err)
	}
	if hooks := cfg.Notifications.Webhooks; len(hooks) != 1 || hooks[0].URLEnv != "CLOOP_NOTIFY_APPROVERS" {
		t.Fatalf("a save leaving url_env out did not keep it: %+v", hooks)
	}
}
