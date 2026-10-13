package config

// notifications: telling the people who can decide that a decision is waiting
// on them (Task 20427).
//
// Two decisions wait on an administrator: a self-service grant request (Task
// 20271) and an API token a role policy suspends until it is approved (Task
// 20422). The dashboard lists both, but only to someone who happens to open the
// right tab, and a request lapses undecided after three days. A webhook here is
// how the hub reaches them where they already are: a Slack or Discord channel, a
// Microsoft Teams Workflows trigger, or anything that takes a JSON POST.
//
// The cluster leader sends (pkg/approvalnotify): when a request is filed, twelve
// hours before it lapses, when it is decided, withdrawn or lapses, and when a
// token starts waiting. What a message says is identities, secret names,
// subjects and a link to the dashboard — never a credential, never the
// requester's free-text justification.
//
// The rules enforced here, at load, rather than at the first send:
//
//   - https only. A webhook URL is a bearer credential for the channel it posts
//     to (Slack, Teams and Discord all put the secret in the URL), so it never
//     crosses the network in the clear, loopback included.
//   - The URL lives in exactly one place: inline (url, which the Settings panel
//     writes and no API ever returns), or in the hub's own environment (url_env,
//     a CLOOP_NOTIFY_* variable holding it — the form for a config file kept in
//     version control). Not in the hub's secret store: a maintainer may delete
//     and re-mint a shared secret, and a URL is where the stream goes, so
//     keeping it there would hand the role that brokers credentials the choice
//     of who hears about them. Only whoever runs the hub process sets its
//     environment.
//   - A receiver on a private, loopback or link-local address is reached only
//     when allow_addresses names it, and a cloud metadata service never is: the
//     sender checks the address it actually dials, after DNS, so a public name
//     that resolves inside the network is refused too.
//
// Load drops a webhook that fails validation and records the switch-off
// (LoadRepair.SwitchedOff), which `cloop hub doctor` reports, rather than
// repairing it into a destination nobody configured.

import (
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
)

// Bounds and defaults for notifications.
const (
	// NotificationsMaxWebhooks bounds how many webhooks a hub sends to. Each
	// one is a delivery cursor and a label value on the delivery counter, so
	// the bound keeps the metric's cardinality closed.
	NotificationsMaxWebhooks = 8

	// How long one webhook POST may take before it counts as failed.
	NotificationTimeoutDefault = 10 * time.Second
	NotificationTimeoutLower   = time.Second
	NotificationTimeoutUpper   = time.Minute

	// NotificationReminderLead is how long before a pending request lapses its
	// reminder goes out.
	NotificationReminderLead = 12 * time.Hour

	// notificationMaxAllowAddresses bounds allow_addresses per webhook.
	notificationMaxAllowAddresses = 16
)

// notificationURLEnvRE is the shape of url_env.
var notificationURLEnvRE = regexp.MustCompile(`^CLOOP_NOTIFY_[A-Z0-9_]{1,64}$`)

// Webhook types: what the body looks like.
const (
	// NotifySlack posts a Slack incoming-webhook message (blocks, mrkdwn).
	NotifySlack = "slack"
	// NotifyTeams posts a Microsoft Teams Workflows message carrying an
	// Adaptive Card ("Post to a channel when a webhook request is received").
	NotifyTeams = "teams"
	// NotifyDiscord posts a Discord webhook message with one embed and every
	// mention disabled.
	NotifyDiscord = "discord"
	// NotifyJSON posts the notice as one JSON object.
	NotifyJSON = "json"
)

// NotificationTypes lists the webhook types in display order.
func NotificationTypes() []string {
	return []string{NotifySlack, NotifyTeams, NotifyDiscord, NotifyJSON}
}

// Events a webhook can be sent. They are also the `event` label of
// cloop_approval_notifications_total.
const (
	NotifyEventRequestFiled     = "request.filed"
	NotifyEventRequestReminder  = "request.reminder"
	NotifyEventRequestApproved  = "request.approved"
	NotifyEventRequestDenied    = "request.denied"
	NotifyEventRequestWithdrawn = "request.withdrawn"
	NotifyEventRequestLapsed    = "request.lapsed"
	NotifyEventTokenWaiting     = "token.waiting"
)

// NotificationEvents lists every event in the order a request lives through
// them, the token's last.
func NotificationEvents() []string {
	return []string{
		NotifyEventRequestFiled, NotifyEventRequestReminder, NotifyEventRequestApproved,
		NotifyEventRequestDenied, NotifyEventRequestWithdrawn, NotifyEventRequestLapsed,
		NotifyEventTokenWaiting,
	}
}

// IsNotificationEvent reports whether name is one of NotificationEvents.
func IsNotificationEvent(name string) bool {
	for _, e := range NotificationEvents() {
		if e == name {
			return true
		}
	}
	return false
}

// NotificationsConfig is the notifications section.
type NotificationsConfig struct {
	// Webhooks receive the approval notices.
	Webhooks []NotificationWebhook `yaml:"webhooks,omitempty"`

	// DashboardURL is the dashboard a message links to. Empty means
	// ui.external_url, then the origin of ui.oidc.redirect_url; with neither,
	// messages carry no link.
	DashboardURL string `yaml:"dashboard_url,omitempty"`
}

// NotificationWebhook is one destination.
type NotificationWebhook struct {
	// Name identifies the webhook: its delivery cursor, its metric label and
	// its line in the Settings panel. Lower-case letters, digits, '-' and '_'.
	Name string `yaml:"name"`

	// Type is slack, teams, discord or json.
	Type string `yaml:"type"`

	// URL is the webhook's address, https only. It is a credential for the
	// channel it posts to: no API returns it, and the Settings panel shows its
	// host alone. Exactly one of URL and URLEnv.
	URL string `yaml:"url,omitempty"`

	// URLEnv names the environment variable of the hub process holding the
	// URL, CLOOP_NOTIFY_ followed by upper-case letters, digits and '_'. Read
	// at every send, so a rotated URL needs only a restart with the new value;
	// the prefix keeps a webhook from being pointed at a variable that holds
	// something else.
	URLEnv string `yaml:"url_env,omitempty"`

	// Events narrows what is sent; empty sends every event.
	Events []string `yaml:"events,omitempty"`

	// AllowAddresses are the IP addresses or CIDR prefixes a receiver on a
	// private, loopback or link-local address may be reached at. Nothing here
	// reaches a cloud metadata service.
	AllowAddresses []string `yaml:"allow_addresses,omitempty"`

	// CAFile adds a PEM bundle to the system roots, for a receiver with an
	// internal CA.
	CAFile string `yaml:"ca_file,omitempty"`

	// Timeout bounds one POST, as a Go duration. Empty means
	// NotificationTimeoutDefault.
	Timeout string `yaml:"timeout,omitempty"`
}

// Wants reports whether the webhook is sent event.
func (w NotificationWebhook) Wants(event string) bool {
	if len(w.Events) == 0 {
		return true
	}
	for _, e := range w.Events {
		if strings.EqualFold(strings.TrimSpace(e), event) {
			return true
		}
	}
	return false
}

// EffectiveTimeout bounds one POST.
func (w NotificationWebhook) EffectiveTimeout() time.Duration {
	d, err := parseBoundedDuration(w.Timeout, NotificationTimeoutLower, NotificationTimeoutUpper)
	if err != nil || d == 0 {
		return NotificationTimeoutDefault
	}
	return d
}

// AllowedPrefixes parses AllowAddresses; entries that do not parse are left
// out (validation refuses them).
func (w NotificationWebhook) AllowedPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range w.AllowAddresses {
		if p, err := parseAllowAddress(raw); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// Endpoint names where the webhook posts without saying anything that would
// let someone else post there: the scheme and host of an inline URL, or the
// secret its URL is kept in.
func (w NotificationWebhook) Endpoint() string {
	if name := strings.TrimSpace(w.URLEnv); name != "" {
		return "env:" + name
	}
	return WebhookHost(w.URL)
}

// WebhookHost renders a webhook URL as its scheme and host alone, the most of
// one that is ever shown.
func WebhookHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}

// ValidateWebhookURL is the URL rule, applied at load and again where the URL
// is used — a URL read from the environment has passed no loader.
func ValidateWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("the webhook URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("the webhook URL is not an absolute https:// URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("the webhook URL must be https:// — it is a credential for the channel it posts to, " +
			"and it is never sent in the clear")
	}
	if u.User != nil {
		return fmt.Errorf("the webhook URL carries a user name or password; webhooks authenticate by the URL alone")
	}
	if u.Fragment != "" {
		return fmt.Errorf("the webhook URL has a fragment, which is never sent")
	}
	return nil
}

// parseAllowAddress reads one allow_addresses entry: a prefix, or a bare
// address meaning that address alone.
func parseAllowAddress(raw string) (netip.Prefix, error) {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR prefix", raw)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR prefix", raw)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ValidateNotificationWebhook is the strict check of one webhook.
func ValidateNotificationWebhook(w NotificationWebhook) error {
	if !auditSinkNameRE.MatchString(strings.TrimSpace(w.Name)) {
		return fmt.Errorf("name %q must be 1-32 lower-case letters, digits, '-' or '_', starting with a letter or digit", w.Name)
	}
	switch strings.ToLower(strings.TrimSpace(w.Type)) {
	case NotifySlack, NotifyTeams, NotifyDiscord, NotifyJSON:
	case "":
		return fmt.Errorf("type is required: slack, teams, discord or json")
	default:
		return fmt.Errorf("type %q is not one of slack, teams, discord, json", w.Type)
	}
	inline, env := strings.TrimSpace(w.URL), strings.TrimSpace(w.URLEnv)
	switch {
	case inline == "" && env == "":
		return fmt.Errorf("a webhook needs its URL: url, or url_env naming the environment variable that holds it")
	case inline != "" && env != "":
		return fmt.Errorf("url and url_env are both set; keep the URL in one place")
	case inline != "":
		if err := ValidateWebhookURL(inline); err != nil {
			return err
		}
	default:
		if !notificationURLEnvRE.MatchString(env) {
			return fmt.Errorf("url_env %q must be CLOOP_NOTIFY_ followed by upper-case letters, digits or '_' "+
				"(at most 64 of them): a webhook reads its URL from a variable set for that purpose, never "+
				"from one holding something else", env)
		}
	}
	seen := map[string]bool{}
	for _, e := range w.Events {
		name := strings.ToLower(strings.TrimSpace(e))
		if !IsNotificationEvent(name) {
			return fmt.Errorf("event %q is not one of %s", e, strings.Join(NotificationEvents(), ", "))
		}
		if seen[name] {
			return fmt.Errorf("event %q is listed twice", e)
		}
		seen[name] = true
	}
	if len(w.AllowAddresses) > notificationMaxAllowAddresses {
		return fmt.Errorf("allow_addresses lists %d entries, at most %d", len(w.AllowAddresses), notificationMaxAllowAddresses)
	}
	for _, raw := range w.AllowAddresses {
		p, err := parseAllowAddress(raw)
		if err != nil {
			return fmt.Errorf("allow_addresses: %w", err)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("allow_addresses: %q allows every address, which would switch the private-address "+
				"guard off; name the receiver's address or its network", raw)
		}
		// The sender never dials a metadata service, so naming one — or a
		// prefix containing one — could only mislead whoever reads the file
		// into thinking it does.
		if svc, ok := cloudmeta.LookupDialed(p.Addr()); ok && p.IsSingleIP() {
			return fmt.Errorf("allow_addresses: %q is the cloud metadata service %s, which a webhook is never sent to",
				raw, svc.Describe())
		}
		if svcs := cloudmeta.Within(p); len(svcs) > 0 {
			return fmt.Errorf("allow_addresses: %q contains the cloud metadata service %s, which a webhook is never "+
				"sent to; name a narrower prefix", raw, svcs[0].Describe())
		}
	}
	if w.CAFile != "" && !filepath.IsAbs(w.CAFile) {
		return fmt.Errorf("ca_file %q must be an absolute path", w.CAFile)
	}
	if _, err := parseBoundedDuration(w.Timeout, NotificationTimeoutLower, NotificationTimeoutUpper); err != nil {
		return fmt.Errorf("timeout: %w", err)
	}
	return nil
}

// validateDashboardURL checks notifications.dashboard_url.
func validateDashboardURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%q is not an absolute http(s) URL", raw)
	}
	if u.User != nil {
		return fmt.Errorf("%q carries credentials, which every message would repeat", u.Redacted())
	}
	return nil
}

// notificationWebhookKey names a webhook in a load repair: by name when it has
// a usable one, by position otherwise.
func notificationWebhookKey(i int, w NotificationWebhook) string {
	if n := strings.TrimSpace(w.Name); auditSinkNameRE.MatchString(n) {
		return "notifications.webhooks." + n
	}
	return fmt.Sprintf("notifications.webhooks[%d]", i)
}

// ValidateNotifications is the strict check of the notifications section,
// shared by `cloop config set`, `cloop config validate` and the Settings panel.
func ValidateNotifications(c NotificationsConfig) error {
	if len(c.Webhooks) > NotificationsMaxWebhooks {
		return fmt.Errorf("notifications.webhooks: %d webhooks configured, at most %d", len(c.Webhooks), NotificationsMaxWebhooks)
	}
	seen := map[string]bool{}
	for i, w := range c.Webhooks {
		key := notificationWebhookKey(i, w)
		if err := ValidateNotificationWebhook(w); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		name := strings.TrimSpace(w.Name)
		if seen[name] {
			return fmt.Errorf("%s: the name is used by an earlier webhook", key)
		}
		seen[name] = true
	}
	if err := validateDashboardURL(c.DashboardURL); err != nil {
		return fmt.Errorf("notifications.dashboard_url: %w", err)
	}
	return nil
}

// clampNotifications is Load's repair of the section. A webhook that fails
// validation is dropped and recorded as switched off — never repaired into a
// destination nobody configured, and never sent to over plaintext.
func (c *Config) clampNotifications(path string, warn func(field, msg string)) {
	n := &c.Notifications
	if err := validateDashboardURL(n.DashboardURL); err != nil {
		warn("notifications.dashboard_url", err.Error()+"; messages link to ui.external_url instead")
		n.DashboardURL = ""
	}
	if len(n.Webhooks) == 0 {
		return
	}
	kept := make([]NotificationWebhook, 0, len(n.Webhooks))
	seen := map[string]bool{}
	for i, w := range n.Webhooks {
		key := notificationWebhookKey(i, w)
		err := ValidateNotificationWebhook(w)
		switch {
		case err != nil:
		case seen[strings.TrimSpace(w.Name)]:
			err = fmt.Errorf("the name is used by an earlier webhook")
		case len(kept) >= NotificationsMaxWebhooks:
			err = fmt.Errorf("at most %d webhooks are sent to", NotificationsMaxWebhooks)
		}
		if err != nil {
			detail := "refused at load: " + err.Error() + "; the webhook is disabled"
			warn(key, detail)
			c.loadRepairs = append(c.loadRepairs, LoadRepair{
				File: path, Field: key, SwitchedOff: key, Detail: detail,
			})
			continue
		}
		w.Name = strings.TrimSpace(w.Name)
		w.Type = strings.ToLower(strings.TrimSpace(w.Type))
		seen[w.Name] = true
		kept = append(kept, w)
	}
	n.Webhooks = kept
}

// SaveUIInstanceNotifications writes the notifications section into an overlay
// file, leaving every other key in it untouched (Task 20427). The section is
// hub-scope: it says whom this hub tells, not anything about a project.
//
// Both keys are written even at their zero value, because the overlay is
// merged over config.yaml key by key: a webhooks list left out would let
// config.yaml's webhooks show through a save that removed them, and the hub
// would keep posting to a channel the panel says it no longer posts to.
func SaveUIInstanceNotifications(path string, n NotificationsConfig) error {
	hooks := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, w := range n.Webhooks {
		encoded, err := yaml.Marshal(w)
		if err != nil {
			return fmt.Errorf("could not encode notifications.webhooks.%s: %w", w.Name, err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(encoded, &doc); err != nil {
			return fmt.Errorf("could not re-read notifications.webhooks.%s: %w", w.Name, err)
		}
		hooks.Content = append(hooks.Content, documentRoot(&doc))
	}
	if len(hooks.Content) == 0 {
		hooks.Style = yaml.FlowStyle
	}
	block := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		yamlScalar("!!str", "dashboard_url"), yamlScalar("!!str", strings.TrimSpace(n.DashboardURL)),
		yamlScalar("!!str", "webhooks"), hooks,
	}}
	return saveUIInstanceKeys(path, nil, []overlayKey{{"notifications", block}})
}
