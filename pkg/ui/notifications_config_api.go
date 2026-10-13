package ui

// The Settings block that edits notifications (Task 20427).
//
//	GET  /api/config/notifications        the webhooks, where each posts, and
//	                                      how its deliveries are going
//	PUT  /api/config/notifications        change them
//	POST /api/config/notifications/test   send one test message to one
//
// All three are admin-only (user.manage), for the reason the telemetry block
// is: a webhook decides where a stream of who-asked-for-which-credential and
// which-token-waits leaves the hub, and the role that brokers credentials must
// not be able to route its own oversight somewhere of its choosing.
//
// # The URL is write-only
//
// A Slack, Teams or Discord webhook URL is the credential for its channel:
// anyone holding it can post there. So no response carries one. GET says where
// a webhook posts by scheme and host alone; PUT takes a new URL, or none to
// keep the stored one, the way the identity block treats its client secret. A
// url_env — the URL kept in the hub's own environment, the form for a config
// file in version control — is shown by name, with whether this member has it
// set, never its value.
//
// A save is in force at the leader's next pass: the notifier reads the hub's
// configuration (overlay included) every pass, so nothing restarts.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/approvalnotify"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/logger"
)

// notificationStatusView is how a webhook's deliveries are going, from its
// cursor in the control plane.
type notificationStatusView struct {
	Delivered       int64  `json:"delivered"`
	Dropped         int64  `json:"dropped"`
	Failures        int64  `json:"failures"`
	Backlog         int64  `json:"backlog"`
	NextAttemptAt   string `json:"next_attempt_at,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	LastErrorAt     string `json:"last_error_at,omitempty"`
	LastDeliveredAt string `json:"last_delivered_at,omitempty"`
}

// notificationWebhookView is one webhook, without its URL.
type notificationWebhookView struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Destination is the scheme and host an inline URL posts to, or
	// "secret:<name>" for one kept in the secret store.
	Destination string `json:"destination"`
	// URLSet says an inline URL is stored; URLEnv names the environment
	// variable holding it otherwise, and URLEnvSet whether it is set on the
	// member that answered.
	URLSet         bool                    `json:"url_set"`
	URLEnv         string                  `json:"url_env,omitempty"`
	URLEnvSet      bool                    `json:"url_env_set,omitempty"`
	Events         []string                `json:"events"`
	AllowAddresses []string                `json:"allow_addresses"`
	CAFile         string                  `json:"ca_file,omitempty"`
	Timeout        string                  `json:"timeout,omitempty"`
	Status         *notificationStatusView `json:"status,omitempty"`
}

// notificationsSettingsView is GET /api/config/notifications.
type notificationsSettingsView struct {
	DashboardURL string `json:"dashboard_url"`
	// Link is the address messages carry, as resolved now; empty when the
	// hub knows no address people reach it at.
	Link     string                    `json:"link"`
	Webhooks []notificationWebhookView `json:"webhooks"`
	// Refused are the webhooks the configuration names and the loader
	// switched off, with why.
	Refused       []string `json:"refused,omitempty"`
	Events        []string `json:"events"`
	Types         []string `json:"types"`
	ReminderHours int      `json:"reminder_hours"`
	MaxWebhooks   int      `json:"max_webhooks"`
}

// handleNotificationsSettings serves GET /api/config/notifications.
func (s *Server) handleNotificationsSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadHubConfig()
	if err != nil || cfg == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
		return
	}
	jsonOK(w, s.notificationsViewOf(cfg))
}

func (s *Server) notificationsViewOf(cfg *config.Config) notificationsSettingsView {
	n := cfg.Notifications
	view := notificationsSettingsView{
		DashboardURL:  n.DashboardURL,
		Link:          s.approvalsLink(cfg),
		Webhooks:      []notificationWebhookView{},
		Events:        config.NotificationEvents(),
		Types:         config.NotificationTypes(),
		ReminderHours: int(config.NotificationReminderLead / time.Hour),
		MaxWebhooks:   config.NotificationsMaxWebhooks,
	}
	for _, rep := range cfg.LoadRepairs() {
		if name, ok := strings.CutPrefix(rep.SwitchedOff, "notifications.webhooks"); ok {
			view.Refused = append(view.Refused, strings.TrimPrefix(name, ".")+": "+rep.Detail)
		}
	}
	status := s.notificationStatus()
	for _, hook := range n.Webhooks {
		v := notificationWebhookView{
			Name: hook.Name, Type: hook.Type, Destination: hook.Endpoint(),
			URLSet: strings.TrimSpace(hook.URL) != "", URLEnv: strings.TrimSpace(hook.URLEnv),
			URLEnvSet: envSet(hook.URLEnv),
			Events:    append([]string{}, hook.Events...), AllowAddresses: append([]string{}, hook.AllowAddresses...),
			CAFile: hook.CAFile, Timeout: hook.Timeout,
		}
		if st, ok := status[hook.Name]; ok {
			v.Status = &st
		}
		view.Webhooks = append(view.Webhooks, v)
	}
	return view
}

// notificationStatus reads every webhook's cursor. Missing — no pass has run
// since the webhook was added — is no entry, not an error.
func (s *Server) notificationStatus() map[string]notificationStatusView {
	out := map[string]notificationStatusView{}
	db, err := s.controlPlaneDB()
	if err != nil {
		return out
	}
	defer db.Close()
	cursors, err := db.ApprovalNotifyCursors()
	if err != nil {
		return out
	}
	head, _ := db.MaxApprovalNoticeID()
	stamp := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	for _, c := range cursors {
		out[c.Sink] = notificationStatusView{
			Delivered: c.Delivered, Dropped: c.Dropped, Failures: c.Failures,
			Backlog:       max(head-c.AckedID, 0),
			NextAttemptAt: stamp(c.NextAttemptAt), LastError: c.LastError,
			LastErrorAt: stamp(c.LastErrorAt), LastDeliveredAt: stamp(c.LastDeliveredAt),
		}
	}
	return out
}

// envSet reports whether the environment variable a webhook reads its URL
// from is set on this member. Only ever a yes or no, and only for a name
// config.ValidateNotificationWebhook admits (CLOOP_NOTIFY_*).
func envSet(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	v, ok := os.LookupEnv(name)
	return ok && strings.TrimSpace(v) != ""
}

// notificationWebhookInput is one webhook as the panel posts it.
type notificationWebhookInput struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// URL replaces the stored URL; empty keeps it. Setting it clears a
	// url_env, and setting URLEnv clears an inline URL.
	URL            string   `json:"url"`
	URLEnv         string   `json:"url_env"`
	Events         []string `json:"events"`
	AllowAddresses []string `json:"allow_addresses"`
	CAFile         string   `json:"ca_file"`
	Timeout        string   `json:"timeout"`
}

// notificationsSaveRequest is a partial update: an absent field keeps what is
// stored, and webhooks, when present, is the whole list.
type notificationsSaveRequest struct {
	DashboardURL *string                     `json:"dashboard_url"`
	Webhooks     *[]notificationWebhookInput `json:"webhooks"`
}

// handleNotificationsSettingsSave serves PUT /api/config/notifications.
func (s *Server) handleNotificationsSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req notificationsSaveRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}

	hubConfigMu.Lock()
	// Where this hub reads, as the telemetry block writes: its overlay once
	// it has one, config.yaml otherwise (Task 20318).
	save, err := s.beginHubSettingsSave()
	if err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
		return
	}
	cfg := save.Config
	was := cloneNotifications(cfg.Notifications)
	next, err := applyNotificationsRequest(cfg.Notifications, req)
	if err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	cfg.Notifications = next
	if err := save.commit(func(overlay string) error {
		return config.SaveUIInstanceNotifications(overlay, next)
	}); err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	hubConfigMu.Unlock()

	s.auditNotificationsConfig(r, was, next)
	s.forgetRemovedWebhooks(was, next)
	s.nudgeApprovalNotify()
	saved, err := s.loadHubConfig()
	if err != nil || saved == nil {
		saved = cfg
	}
	jsonOK(w, s.notificationsViewOf(saved))
}

// forgetRemovedWebhooks drops the delivery cursor of every webhook a save
// removed, so one added again under its name hears what happens from then on
// rather than the backlog. A webhook dropped from a file, not through here, is
// forgotten by the notifier a day later (approvalnotify's forgetRemovedAfter).
func (s *Server) forgetRemovedWebhooks(was, now config.NotificationsConfig) {
	kept := map[string]bool{}
	for _, w := range now.Webhooks {
		kept[w.Name] = true
	}
	var removed []string
	for _, w := range was.Webhooks {
		if !kept[w.Name] {
			removed = append(removed, w.Name)
		}
	}
	if len(removed) == 0 {
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		return
	}
	defer db.Close()
	for _, name := range removed {
		if err := db.DeleteApprovalNotifyCursor(name); err != nil {
			s.log().Warn(logger.EventAuthz, 0, "notifications: forget a removed webhook",
				map[string]interface{}{"webhook": name, "error": err.Error()})
		}
	}
}

func cloneNotifications(n config.NotificationsConfig) config.NotificationsConfig {
	out := config.NotificationsConfig{DashboardURL: n.DashboardURL}
	for _, w := range n.Webhooks {
		w.Events = append([]string(nil), w.Events...)
		w.AllowAddresses = append([]string(nil), w.AllowAddresses...)
		out.Webhooks = append(out.Webhooks, w)
	}
	return out
}

// applyNotificationsRequest overlays the request on what is stored and
// validates the result whole, with the strict check `cloop config set` uses:
// a refusal names the field, where saving and letting the loader switch the
// webhook off would leave the panel showing a webhook that never posts.
func applyNotificationsRequest(cur config.NotificationsConfig, req notificationsSaveRequest) (config.NotificationsConfig, error) {
	next := cloneNotifications(cur)
	if req.DashboardURL != nil {
		next.DashboardURL = strings.TrimSpace(*req.DashboardURL)
	}
	if req.Webhooks != nil {
		stored := map[string]config.NotificationWebhook{}
		for _, w := range cur.Webhooks {
			stored[w.Name] = w
		}
		next.Webhooks = nil
		for _, in := range *req.Webhooks {
			hook := config.NotificationWebhook{
				Name:           strings.ToLower(strings.TrimSpace(in.Name)),
				Type:           strings.ToLower(strings.TrimSpace(in.Type)),
				Events:         cleanList(in.Events),
				AllowAddresses: cleanList(in.AllowAddresses),
				CAFile:         strings.TrimSpace(in.CAFile),
				Timeout:        strings.TrimSpace(in.Timeout),
			}
			switch url, env := strings.TrimSpace(in.URL), strings.TrimSpace(in.URLEnv); {
			case url != "":
				hook.URL = url
			case env != "":
				hook.URLEnv = env
			default:
				old, ok := stored[hook.Name]
				if !ok {
					return cur, errors.New("webhook " + hook.Name + ": give its URL (or url_env, naming the " +
						"environment variable that holds it) — there is no stored one to keep")
				}
				hook.URL, hook.URLEnv = old.URL, old.URLEnv
			}
			next.Webhooks = append(next.Webhooks, hook)
		}
	}
	if err := config.ValidateNotifications(next); err != nil {
		return cur, err
	}
	return next, nil
}

// auditNotificationsConfig records a change to where approval notices go.
//
// Worth a row for the reason telemetry's switch is: a webhook decides where a
// stream about who asked for which credential leaves the hub, so "since when,
// and who decided that" has to be answerable afterwards. The payload says
// where each webhook posts by host, and names those whose URL changed without
// saying to what — the URL is the channel's credential.
func (s *Server) auditNotificationsConfig(r *http.Request, was, now config.NotificationsConfig) {
	describe := func(n config.NotificationsConfig) []string {
		out := make([]string, 0, len(n.Webhooks))
		for _, w := range n.Webhooks {
			d := w.Name + " (" + w.Type + ") " + w.Endpoint()
			if len(w.Events) > 0 {
				d += " events=" + strings.Join(w.Events, ",")
			}
			if len(w.AllowAddresses) > 0 {
				d += " allow=" + strings.Join(w.AllowAddresses, ",")
			}
			out = append(out, d)
		}
		return out
	}
	before, after := describe(was), describe(now)
	var changedURL []string
	prev := map[string]config.NotificationWebhook{}
	for _, w := range was.Webhooks {
		prev[w.Name] = w
	}
	for _, w := range now.Webhooks {
		if old, ok := prev[w.Name]; ok && !sameWebhookAddress(old, w) {
			changedURL = append(changedURL, w.Name)
		}
	}
	if sameStrings(before, after) && len(changedURL) == 0 && was.DashboardURL == now.DashboardURL {
		return
	}
	blob, err := json.Marshal(map[string]any{
		"webhooks":          after,
		"was_webhooks":      before,
		"url_changed":       changedURL,
		"dashboard_url":     now.DashboardURL,
		"was_dashboard_url": was.DashboardURL,
	})
	if err != nil {
		return
	}
	actor := s.auditActor(r)
	if actor == "" {
		actor = "anonymous"
	}
	log, logErr := eventlog.Open(s.WorkDir)
	if logErr != nil {
		if logErr != eventlog.ErrNoProject {
			s.log().Warn(logger.EventAuthz, 0, "notifications config audit: open event log",
				map[string]interface{}{"error": logErr.Error()})
		}
		return
	}
	defer log.Close()
	if err := log.Append(&eventlog.AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionNotificationsConfigUpdated),
		EntityType: "config",
		EntityID:   "notifications",
		Payload:    string(blob),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "notifications config audit: append",
			map[string]interface{}{"error": err.Error()})
	}
}

// sameWebhookAddress reports whether two webhooks post to the same place. The
// URL is the channel's credential, so it is compared in constant time, as every
// credential is (tests/security's TestSecretComparisonsAreConstantTime).
func sameWebhookAddress(a, b config.NotificationWebhook) bool {
	return subtle.ConstantTimeCompare([]byte(a.URL), []byte(b.URL)) == 1 &&
		subtle.ConstantTimeCompare([]byte(a.URLEnv), []byte(b.URLEnv)) == 1
}

// handleNotificationsTest serves POST /api/config/notifications/test: one
// fixed message to one configured webhook, so an operator learns a URL works
// before an approver depends on it. It sends nowhere the configuration does
// not name, through the same guarded client the notifier uses.
func (s *Server) handleNotificationsTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	cfg, err := s.loadHubConfig()
	if err != nil || cfg == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	var hook *config.NotificationWebhook
	for i := range cfg.Notifications.Webhooks {
		if cfg.Notifications.Webhooks[i].Name == name {
			hook = &cfg.Notifications.Webhooks[i]
		}
	}
	if hook == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no webhook named "+req.Name+" is configured"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), hook.EffectiveTimeout()+10*time.Second)
	defer cancel()
	if err := approvalnotify.Test(ctx, *hook, s.approvalsLink(cfg), time.Now()); err != nil {
		hubmetrics.ApprovalNotifications.Inc(hook.Name, approvalnotify.EventTest, hubmetrics.ApprovalNotifyFailed)
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the test message was not delivered: "+err.Error()))
		return
	}
	hubmetrics.ApprovalNotifications.Inc(hook.Name, approvalnotify.EventTest, hubmetrics.ApprovalNotifyDelivered)
	jsonOK(w, map[string]any{"ok": true, "name": hook.Name})
}
