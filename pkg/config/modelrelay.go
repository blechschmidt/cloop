package config

// modelrelay.go: executors.model_relay, the hub's model relay for sandboxed
// runs (Task 20435).

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"
)

// ModelRelayConfig keeps a sandboxed run's Claude credential on the hub.
//
// Without it, a run on an executor that isolates from the hub — a container, a
// Kubernetes Pod, an enrolled device, a virtual executor — is handed its
// harness credential as a leased environment variable, CLAUDE_CODE_OAUTH_TOKEN
// or ANTHROPIC_API_KEY. The workload holds the plaintext for the whole run: it
// can print it, commit it or send it anywhere, a revocation cannot take it
// out of a running device task, and the spend the hub charges is whatever the
// run says it spent.
//
// With it on, the run's lease still names the grant, but the credential is
// withheld from what the sandbox is given. The sandbox gets ANTHROPIC_BASE_URL
// pointing at the relay and a session token worth only the run's model calls;
// the hub spends the credential upstream, meters each response's usage from
// the API's own counts, charges it to the identity that started the run, and
// refuses a call that would pass that identity's daily budget. The session
// ends with the run's lease, at once when its grant is revoked.
//
// Off by default: turning it on changes the endpoint every sandboxed harness
// talks to, which is an operator's decision. Read from the hub's own
// configuration only — a project's config.yaml is authored by whoever can push
// to it, and must not be able to switch the relay, widen its model list or
// spend the hub's own key.
type ModelRelayConfig struct {
	// Enabled routes the model calls of every claudecode or anthropic run on
	// an isolating executor through the relay, for the credential kinds the
	// relay has been proven against the real API with (see the security
	// docs); any other keeps today's delivery and the project's Claude
	// credential card says so.
	Enabled bool `yaml:"enabled,omitempty"`

	// Listener is where sandboxes reach the relay. "git_proxy" (the default)
	// serves it on the git interception proxy's listener at
	// <advertise_url>/_anthropic, so a sandbox reaches it exactly where it
	// reaches the git proxy — the firewall rules that allow one allow the
	// other — over TLS it verifies: with git_proxy.tls: auto the hub's own
	// CA, handed to the harness in a file of its own through
	// NODE_EXTRA_CA_CERTS. It needs executors.git_proxy enabled. "dashboard"
	// serves it on the hub's own listener at <ui.external_url>/_anthropic,
	// which must be https with a certificate the sandbox's own trust store
	// accepts; nothing is added to the sandbox's trust.
	Listener string `yaml:"listener,omitempty"`

	// Models is the hub's model allowlist for relayed runs, as globs
	// ("claude-sonnet-*"). A project's maintainers may narrow it for their
	// project and never widen it. Empty allows every Claude model
	// (DefaultModelRelayModels): the credential is the project's own, and
	// what the relay adds is custody and metering, not a model policy nobody
	// asked for. Name a narrower list to have one.
	Models []string `yaml:"models,omitempty"`

	// MaxOutputTokens clamps max_tokens on every relayed call, as the CI
	// relay does — and with it any extended-thinking budget it would leave
	// at or above max_tokens, which the API refuses. 0 uses the CI relay's
	// default of 32000.
	MaxOutputTokens int `yaml:"max_output_tokens,omitempty"`

	// UpstreamBaseURL overrides https://api.anthropic.com, for a deployment
	// that fronts the API with a gateway of its own. https, or a loopback
	// address; no path.
	UpstreamBaseURL string `yaml:"upstream_base_url,omitempty"`

	// HubCredential names where the hub's own anthropic.api_key may be spent
	// for a run that has no Claude credential granted: "project:<path>" for
	// a project (a feature through its parent), "executor:<id>" for every
	// run placed on that executor. Empty — the default — spends it nowhere:
	// the hub's key is the operator's, and lending it to a project is a
	// decision an administrator makes for that project, not a fallback.
	HubCredential []string `yaml:"hub_credential,omitempty"`

	// Broken is why Load could not take the section as written — a listener,
	// model allowlist or upstream it cannot run with — or "". Never read
	// from a file. An enabled relay that is broken is not switched off,
	// because off is the run's credential delivered into its sandbox again:
	// the hub starts no relay and refuses the runs it would have relayed
	// until the section loads.
	Broken string `yaml:"-" json:"-"`
}

// Model relay listeners.
const (
	ModelRelayListenerGitProxy  = "git_proxy"
	ModelRelayListenerDashboard = "dashboard"
)

// Model relay bounds.
const (
	// ModelRelayMaxModels bounds the allowlist.
	ModelRelayMaxModels = 64
	// ModelRelayMaxOutputTokensUpper bounds max_output_tokens: past every
	// model's own output limit, so a typo is caught rather than relayed.
	ModelRelayMaxOutputTokensUpper = 1_000_000
	// maxModelRelayHubCredential bounds hub_credential.
	maxModelRelayHubCredential = 256
)

// DefaultModelRelayModels is the allowlist of a hub that names none.
var DefaultModelRelayModels = []string{"claude-*"}

// ListenerName is the effective listener.
func (m ModelRelayConfig) ListenerName() string {
	if v := strings.ToLower(strings.TrimSpace(m.Listener)); v != "" {
		return v
	}
	return ModelRelayListenerGitProxy
}

// EffectiveModels is the hub's allowlist: Models, or the default.
func (m ModelRelayConfig) EffectiveModels() []string {
	out := make([]string, 0, len(m.Models))
	for _, p := range m.Models {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultModelRelayModels...)
	}
	return out
}

// HubCredentialAllowed reports whether the hub's own key may be spent for a
// run of the project at projectPath (its policy path: a feature's parent)
// placed on executorID.
func (m ModelRelayConfig) HubCredentialAllowed(projectPath, executorID string) bool {
	for _, s := range m.HubCredential {
		kind, val, _ := strings.Cut(strings.TrimSpace(s), ":")
		switch kind {
		case "project":
			if projectPath != "" && filepath.Clean(val) == filepath.Clean(projectPath) {
				return true
			}
		case "executor":
			if executorID != "" && val == executorID {
				return true
			}
		}
	}
	return false
}

// ValidateModelRelayConfig checks the section as `cloop config set` and the
// dashboard write it.
func ValidateModelRelayConfig(m ModelRelayConfig) error {
	switch m.ListenerName() {
	case ModelRelayListenerGitProxy, ModelRelayListenerDashboard:
	default:
		return fmt.Errorf("executors.model_relay.listener: %q is not a listener; use %q or %q",
			m.Listener, ModelRelayListenerGitProxy, ModelRelayListenerDashboard)
	}
	if err := validateModelPatterns("executors.model_relay.models", m.Models); err != nil {
		return err
	}
	if m.MaxOutputTokens < 0 || m.MaxOutputTokens > ModelRelayMaxOutputTokensUpper {
		return fmt.Errorf("executors.model_relay.max_output_tokens: %d is outside 0..%d (0 uses the default of 32000)",
			m.MaxOutputTokens, ModelRelayMaxOutputTokensUpper)
	}
	if err := validateRelayUpstream(m.UpstreamBaseURL); err != nil {
		return fmt.Errorf("executors.model_relay.upstream_base_url: %w", err)
	}
	return validateHubCredentialSubjects(m.HubCredential)
}

// validateModelPatterns checks a model allowlist: globs path.Match accepts,
// with no surrounding space — a pattern with a space matches nothing, so the
// operator who wrote it would believe a model allowed that is not.
func validateModelPatterns(key string, models []string) error {
	if len(models) > ModelRelayMaxModels {
		return fmt.Errorf("%s: %d patterns; at most %d", key, len(models), ModelRelayMaxModels)
	}
	for _, p := range models {
		if p == "" || strings.TrimSpace(p) != p || len(p) > 128 {
			return fmt.Errorf("%s: %q is not a model pattern", key, p)
		}
		if _, err := path.Match(p, "probe"); err != nil {
			return fmt.Errorf("%s: %q is not a valid glob: %v", key, p, err)
		}
	}
	return nil
}

// ValidateModelRelayModels checks a project's model allowlist the way the
// hub's is checked.
func ValidateModelRelayModels(models []string) error {
	return validateModelPatterns("models", models)
}

// validateRelayUpstream checks an upstream base URL: https, or loopback for
// tests and local gateways; a host; no path, query or userinfo.
func validateRelayUpstream(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not a URL", raw)
	}
	host := u.Hostname()
	loopback := host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return fmt.Errorf("%q must use https: the run's credential travels on it", raw)
	}
	if strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%q must be an origin, with no path, query or credentials", raw)
	}
	return nil
}

// validateHubCredentialSubjects checks hub_credential entries.
func validateHubCredentialSubjects(subjects []string) error {
	if len(subjects) > maxModelRelayHubCredential {
		return fmt.Errorf("executors.model_relay.hub_credential: %d entries; at most %d",
			len(subjects), maxModelRelayHubCredential)
	}
	for _, s := range subjects {
		kind, val, ok := strings.Cut(strings.TrimSpace(s), ":")
		val = strings.TrimSpace(val)
		switch {
		case !ok || val == "" || len(s) > 4096:
			return fmt.Errorf("executors.model_relay.hub_credential: %q is not \"project:<path>\" or \"executor:<id>\"", s)
		case kind == "project" && !filepath.IsAbs(val):
			return fmt.Errorf("executors.model_relay.hub_credential: %q names a project by a relative path", s)
		case kind == "executor" && (len(val) > 128 || strings.ContainsAny(val, " \t\n/")):
			return fmt.Errorf("executors.model_relay.hub_credential: %q is not an executor id", s)
		case kind != "project" && kind != "executor":
			return fmt.Errorf("executors.model_relay.hub_credential: %q is not \"project:<path>\" or \"executor:<id>\"", s)
		}
	}
	return nil
}

// clampModelRelayConfig fixes what Load can fix and marks the section Broken
// where it cannot, saying why. What it cannot fix is kept as written rather
// than reset: an allowlist reset to the default would allow every Claude
// model, wider than the one written, and a later pass over the merged result
// — an overlay's — must find the same fault again rather than a default that
// loads.
func clampModelRelayConfig(m *ModelRelayConfig) []string {
	var changed, broken []string
	switch m.ListenerName() {
	case ModelRelayListenerGitProxy, ModelRelayListenerDashboard:
	default:
		broken = append(broken, fmt.Sprintf("executors.model_relay.listener: %q is not a listener", m.Listener))
	}
	if err := validateModelPatterns("executors.model_relay.models", m.Models); err != nil {
		broken = append(broken, err.Error())
	}
	if err := validateRelayUpstream(m.UpstreamBaseURL); err != nil {
		broken = append(broken, fmt.Sprintf("executors.model_relay.upstream_base_url: %v", err))
	}
	m.Broken = strings.Join(broken, "; ")
	changed = append(changed, broken...)
	if m.MaxOutputTokens < 0 || m.MaxOutputTokens > ModelRelayMaxOutputTokensUpper {
		changed = append(changed, fmt.Sprintf("executors.model_relay.max_output_tokens: value %d outside [0, %d]",
			m.MaxOutputTokens, ModelRelayMaxOutputTokensUpper))
		m.MaxOutputTokens = 0
	}
	if err := validateHubCredentialSubjects(m.HubCredential); err != nil {
		// Dropped rather than half-kept: an allowance nobody can read is
		// one nobody granted.
		changed = append(changed, err.Error())
		m.HubCredential = nil
	}
	return changed
}

// modelRelayWarnings is advice about a valid-but-unusable relay.
func modelRelayWarnings(e ExecutorsConfig) []string {
	m := e.ModelRelay
	if !m.Enabled {
		return nil
	}
	if m.ListenerName() == ModelRelayListenerGitProxy && !e.GitProxy.Enabled {
		return []string{"executors.model_relay is on with listener git_proxy, but executors.git_proxy is " +
			"off, so the relay has nowhere to listen and every run it would relay is refused; enable " +
			"the git proxy, or set executors.model_relay.listener: dashboard."}
	}
	return nil
}
