package config

import (
	"os"
	"strings"
	"testing"
)

// TestNotificationWebhookValidation is the rule a webhook is held to at load,
// by `cloop config set` and `cloop config validate`, and by the Settings panel
// (Task 20427).
func TestNotificationWebhookValidation(t *testing.T) {
	ok := []NotificationWebhook{
		{Name: "slack", Type: NotifySlack, URL: "https://hooks.slack.com/services/T0/B0/xyz"},
		{Name: "teams", Type: NotifyTeams, URL: "https://prod-1.westeurope.logic.azure.com:443/workflows/a/triggers/manual/paths/invoke?api-version=2016-06-01&sig=abc"},
		{Name: "discord", Type: NotifyDiscord, URLEnv: "CLOOP_NOTIFY_DISCORD"},
		{Name: "siem", Type: NotifyJSON, URLEnv: "CLOOP_NOTIFY_SIEM_2", Events: []string{NotifyEventRequestFiled, NotifyEventTokenWaiting},
			AllowAddresses: []string{"10.20.0.15", "192.168.0.0/24"}, CAFile: "/etc/ssl/internal.pem", Timeout: "5s"},
	}
	for _, w := range ok {
		if err := ValidateNotificationWebhook(w); err != nil {
			t.Errorf("%s: %v", w.Name, err)
		}
	}
	bad := map[string]struct {
		w    NotificationWebhook
		want string
	}{
		"plaintext":      {NotificationWebhook{Name: "a", Type: NotifySlack, URL: "http://hooks.slack.com/x"}, "https"},
		"loopback http":  {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "http://127.0.0.1:9000/x"}, "https"},
		"userinfo":       {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "https://u:p@example.com/x"}, "password"},
		"both":           {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "https://example.com/x", URLEnv: "CLOOP_NOTIFY_A"}, "one place"},
		"any variable":   {NotificationWebhook{Name: "a", Type: NotifyJSON, URLEnv: "CLOOP_SECRET_KEY"}, "CLOOP_NOTIFY_"},
		"lower-case env": {NotificationWebhook{Name: "a", Type: NotifyJSON, URLEnv: "cloop_notify_a"}, "CLOOP_NOTIFY_"},
		"bare prefix":    {NotificationWebhook{Name: "a", Type: NotifyJSON, URLEnv: "CLOOP_NOTIFY_"}, "CLOOP_NOTIFY_"},
		"neither":        {NotificationWebhook{Name: "a", Type: NotifyJSON}, "needs its URL"},
		"type":           {NotificationWebhook{Name: "a", Type: "email", URL: "https://example.com/x"}, "not one of"},
		"name":           {NotificationWebhook{Name: "Ops Channel", Type: NotifyJSON, URL: "https://example.com/x"}, "lower-case"},
		"event":          {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "https://example.com/x", Events: []string{"request.created"}}, "not one of"},
		"everything":     {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "https://example.com/x", AllowAddresses: []string{"0.0.0.0/0"}}, "every address"},
		"metadata range": {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "https://example.com/x", AllowAddresses: []string{"169.254.0.0/16"}}, "metadata"},
		"metadata host":  {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "https://example.com/x", AllowAddresses: []string{"169.254.169.254"}}, "metadata"},
		"not an address": {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "https://example.com/x", AllowAddresses: []string{"intranet"}}, "not an IP"},
		"relative ca":    {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "https://example.com/x", CAFile: "ca.pem"}, "absolute"},
		"timeout":        {NotificationWebhook{Name: "a", Type: NotifyJSON, URL: "https://example.com/x", Timeout: "10m"}, "outside"},
	}
	for name, tc := range bad {
		err := ValidateNotificationWebhook(tc.w)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
	}
}

// TestNotificationsLoadDropsWhatValidationRefuses: Load drops a refused
// webhook and records the switch-off, never repairing it into a destination
// nobody configured; the strict validators refuse the same file outright.
func TestNotificationsLoadDropsWhatValidationRefuses(t *testing.T) {
	file := `notifications:
  dashboard_url: https://hub.example.com
  webhooks:
    - name: slack
      type: slack
      url: https://hooks.slack.com/services/T0/B0/xyz
    - name: plain
      type: json
      url: http://collector.internal/hook
    - name: slack
      type: discord
      url: https://discord.com/api/webhooks/1/abc
`
	dir := writeConfigs(t, file, "", 0)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Notifications.Webhooks) != 1 || cfg.Notifications.Webhooks[0].Name != "slack" ||
		cfg.Notifications.Webhooks[0].Type != NotifySlack {
		t.Fatalf("webhooks kept at load = %+v, want the first slack alone", cfg.Notifications.Webhooks)
	}
	off := map[string]string{}
	for _, r := range cfg.LoadRepairs() {
		if r.SwitchedOff != "" {
			off[r.SwitchedOff] = r.Detail
		}
	}
	if !strings.Contains(off["notifications.webhooks.plain"], "https") {
		t.Errorf("the plaintext webhook was not recorded as switched off: %v", off)
	}
	if !strings.Contains(off["notifications.webhooks.slack"], "earlier webhook") {
		t.Errorf("the duplicate name was not recorded as switched off: %v", off)
	}

	raw := &Config{Notifications: NotificationsConfig{Webhooks: []NotificationWebhook{
		{Name: "plain", Type: NotifyJSON, URL: "http://collector.internal/hook"},
	}}}
	if err := raw.ValidateNumeric(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("ValidateNumeric = %v, want the https refusal", err)
	}
}

// TestNotificationsOverlayReplacesTheList: the Settings panel writes the whole
// section into a hub's overlay, so removing every webhook there stops config.yaml's
// from showing through.
func TestNotificationsOverlayReplacesTheList(t *testing.T) {
	base := `notifications:
  webhooks:
    - name: shared
      type: json
      url: https://hooks.example.com/shared
`
	dir := writeConfigs(t, base, "", 0)
	overlay := UIInstanceConfigPath(dir, 8888)
	if err := SaveUIInstanceNotifications(overlay, NotificationsConfig{Webhooks: []NotificationWebhook{
		{Name: "mine", Type: NotifyTeams, URLEnv: "CLOOP_NOTIFY_TEAMS", Events: []string{NotifyEventRequestFiled}},
	}}); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := LoadUIInstance(dir, 8888)
	if err != nil || path == "" {
		t.Fatalf("LoadUIInstance = %v (%s)", err, path)
	}
	if hooks := cfg.Notifications.Webhooks; len(hooks) != 1 || hooks[0].Name != "mine" || hooks[0].URLEnv != "CLOOP_NOTIFY_TEAMS" {
		t.Fatalf("merged webhooks = %+v, want the overlay's alone", hooks)
	}
	if err := SaveUIInstanceNotifications(overlay, NotificationsConfig{}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err = LoadUIInstance(dir, 8888)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Notifications.Webhooks) != 0 {
		t.Fatalf("an emptied overlay let config.yaml's webhooks through: %+v", cfg.Notifications.Webhooks)
	}
	data, _ := os.ReadFile(overlay)
	if !strings.Contains(string(data), "notifications:") {
		t.Fatalf("the overlay does not hold the section:\n%s", data)
	}
}
