package hubdoctor

// ui.exposure: can the network reach a hub that cannot tell people apart?
// (Task 20393)
//
// A hub with no sign-in — no ui.oidc, no static token — lets anyone who
// reaches it list its projects, queue tasks and start agent runs on its host.
// `cloop ui` now keeps such a hub on loopback (pkg/exposure), but that only
// governs a process started by a build that has the rule, with this
// configuration and no flag overriding it. So the check answers from what is
// actually there whenever it can:
//
//   - The socket table says where the process on the hub's port listens
//     (listeners.go) — loopback only, or beyond it.
//   - The hub itself, asked GET /api/projects with no credentials, says
//     whether it requires sign-in: 200 is open, 401/403 is not.
//
// Only when nothing listens on the port, or the table cannot be read, does it
// fall back to predicting what `cloop ui --port N` would do with this
// configuration — through pkg/exposure, the code that makes the decision, so
// the prediction cannot drift from the hub.
//
// Severities: a hub without sign-in reachable beyond loopback fails, observed
// or predicted, acknowledged or not — it is exactly the exposure this check
// exists to find, and an acknowledgement says somebody chose it, not that it is
// safe. A hub with sign-in that serves plaintext beyond loopback while its
// external URL is https warns: TLS terminates in front of it, and anything that
// reaches the port directly skips the terminator.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/exposure"
)

// envUIToken is the static dashboard token `cloop ui` reads when --token is
// not given. The doctor reads it from its own environment, the way it reads
// CLOOP_SECRET_KEY: an operator runs it with the hub's environment exported.
const envUIToken = "CLOOP_UI_TOKEN"

// exposureProbePath is what the probe asks for: a read every hub build has
// served since the multi-project dashboard, refused without a credential by
// every hub that has one.
const exposureProbePath = "/api/projects"

// probeKind is what the unauthenticated probe established.
type probeKind int

const (
	probeSkipped probeKind = iota // --offline, or nothing beyond loopback to ask
	probeOpen                     // answered 2xx with JSON: no sign-in
	probeSignIn                   // answered 401 or 403: sign-in required
	probeTLS                      // the listener speaks TLS
	probeUnknown                  // anything else: not a hub we recognise, or no answer
)

// probeResult is one unauthenticated request to the hub.
type probeResult struct {
	Kind   probeKind
	Target string // host:port dialled
	Status int
	Err    error
}

func (p probeResult) describe() string {
	switch p.Kind {
	case probeSkipped:
		return "not asked"
	case probeTLS:
		return fmt.Sprintf("GET %s on %s: the listener speaks TLS", exposureProbePath, p.Target)
	case probeUnknown:
		if p.Err != nil {
			return fmt.Sprintf("GET %s on %s failed: %v", exposureProbePath, p.Target, p.Err)
		}
		return fmt.Sprintf("GET %s on %s answered %d, which is not a hub's answer", exposureProbePath, p.Target, p.Status)
	default:
		return fmt.Sprintf("GET %s on %s answered %d without credentials", exposureProbePath, p.Target, p.Status)
	}
}

// listeners returns the sockets listening on port, through the injected
// reader when a test supplies one.
func (o Options) listeners(port int) ([]netip.AddrPort, error) {
	if o.Listeners != nil {
		return o.Listeners(port)
	}
	return procListeners(port)
}

func checkExposure(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn) {
	req := exposure.Request{
		Listen:                      cfg.UI.Listen,
		Source:                      "ui.listen",
		Port:                        opts.Port,
		SSO:                         cfg.UI.OIDC.Enabled,
		StaticToken:                 os.Getenv(envUIToken) != "",
		AllowUnauthenticatedNetwork: cfg.UI.AllowUnauthenticatedNetwork,
		TLS:                         strings.TrimSpace(cfg.UI.TLS.CertFile) != "",
	}
	req.ExternalURL, req.ExternalURLKey = cfg.UI.PublicURL()
	plan, planErr := exposure.Decide(req)
	where := configFileFor(dir, opts.Port)

	if opts.Port <= 0 {
		add(predictedExposure(plan, planErr, req, where,
			"with this configuration, `cloop ui`", map[string]any{}))
		return
	}
	socks, err := opts.listeners(opts.Port)
	if err != nil {
		add(predictedExposure(plan, planErr, req, where,
			fmt.Sprintf("the sockets on :%d could not be read (%v); with this configuration, `cloop ui --port %d`",
				opts.Port, err, opts.Port),
			map[string]any{"port": opts.Port, "observed": false}))
		return
	}
	if len(socks) == 0 {
		add(predictedExposure(plan, planErr, req, where,
			fmt.Sprintf("nothing listens on :%d now; started with this configuration, `cloop ui --port %d`",
				opts.Port, opts.Port),
			map[string]any{"port": opts.Port, "observed": true, "listening": []string{}}))
		return
	}
	add(observedExposure(ctx, plan, planErr, req, where, socks, opts))
}

// configFileFor names the file an operator should edit for the hub on port:
// its instance overlay when it has one, config.yaml otherwise.
func configFileFor(dir string, port int) string {
	if port > 0 {
		overlay := config.UIInstanceConfigPath(dir, port)
		if _, err := os.Stat(overlay); err == nil {
			return ".cloop/config.ui-" + strconv.Itoa(port) + ".yaml"
		}
	}
	return ".cloop/config.yaml"
}

// observedExposure judges the process actually listening on the port.
func observedExposure(ctx context.Context, plan exposure.Plan, planErr error, req exposure.Request,
	where string, socks []netip.AddrPort, opts Options) Finding {
	scope, widest := socketScope(socks)
	shown := describeSockets(socks)
	details := map[string]any{"port": opts.Port, "observed": true, "listening": shownList(socks)}
	if planErr == nil {
		details["this_build_would_bind"] = plan.String()
	}

	var probe probeResult
	if scope != exposure.ScopeLoopback && !opts.Offline {
		probe = probeHub(ctx, opts, widest)
		details["probe"] = probe.describe()
	}

	// Sign-in, from the hub's own answer when it gave one; otherwise from
	// the configuration, and the message says which.
	open := !req.SSO && !req.StaticToken
	evidence := "(by its configuration: ui.oidc " + onOff(req.SSO) + ", " + envUIToken + " " +
		setOrNot(req.StaticToken) + " in this shell)"
	switch probe.Kind {
	case probeOpen:
		open, evidence = true, "("+probe.describe()+")"
	case probeSignIn:
		open, evidence = false, "("+probe.describe()+")"
	}
	plaintext := probe.Kind == probeOpen || probe.Kind == probeSignIn ||
		(probe.Kind != probeTLS && !req.TLS)
	// From the request, not the plan: a configuration Decide refuses leaves
	// the plan empty, and the process on the port still has a public URL.
	publicHTTPS := isHTTPSURL(req.ExternalURL)

	if scope == exposure.ScopeLoopback {
		msg := fmt.Sprintf("listens on %s only, so nothing beyond this machine reaches it", shown)
		if open {
			msg += "; it has no sign-in, so every local user and process can drive it"
		}
		return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityPass,
			Message: msg, Details: details}
	}

	if open {
		msg := fmt.Sprintf("a hub without sign-in listens on %s %s, so anyone who can reach this host on "+
			"tcp/%d can list its projects, queue tasks and start agent runs on it", shown, evidence, opts.Port)
		var refused *exposure.RefusalError
		switch {
		case plan.Acknowledged:
			msg += "; " + exposure.AckKey + " says it may"
		case planErr == nil && !plan.BeyondLoopback():
			msg += fmt.Sprintf("; with this configuration this build would listen on %s, so the process on "+
				"the port is an older build or was started with --listen", plan)
		case errors.As(planErr, &refused):
			msg += "; with this configuration this build would refuse to start, so the process on the port " +
				"is an older build"
		}
		return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityFail,
			Message: msg,
			Remediation: fmt.Sprintf("Stop it or drop non-loopback traffic to tcp/%d now; then configure "+
				"ui.oidc or %s, or run this build without ui.listen/--listen and %s, which listens on %s",
				opts.Port, envUIToken, exposure.AckKey, exposure.LoopbackHost),
			Details: details}
	}

	if plaintext && publicHTTPS {
		return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityWarn,
			Message: fmt.Sprintf("requires sign-in %s, but serves plaintext on %s while %s is %s: a client "+
				"that reaches tcp/%d directly skips the TLS terminator in front of it, and a sign-in, session "+
				"cookie or API token sent there crosses the network in the clear",
				evidence, shown, req.ExternalURLKey, strings.TrimSpace(req.ExternalURL), opts.Port),
			Remediation: plaintextRemediation(where, opts.Port),
			Details:     details}
	}
	return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityPass,
		Message: fmt.Sprintf("requires sign-in on %s %s", shown, evidence), Details: details}
}

// predictedExposure judges what `cloop ui` would do with this configuration,
// for a port nothing is listening on (or that cannot be observed). prefix
// says which of those it is, and ends with the subject of "would".
func predictedExposure(plan exposure.Plan, planErr error, req exposure.Request, where, prefix string,
	details map[string]any) Finding {
	cred := "ui.oidc is " + onOff(req.SSO) + " and " + envUIToken + " is " + setOrNot(req.StaticToken) +
		" in this shell"
	var refusal *exposure.RefusalError
	switch {
	case errors.As(planErr, &refusal):
		return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityFail,
			Message: fmt.Sprintf("%s would refuse to start: ui.listen asks for %s, beyond loopback, and the hub "+
				"has no sign-in (%s)", prefix, refusal.Plan, cred),
			Remediation: fmt.Sprintf("Configure ui.oidc or %s, or remove ui.listen from %s (the hub then listens "+
				"on %s); %s: true serves it without sign-in anyway", envUIToken, where, exposure.LoopbackHost,
				exposure.AckKey),
			Details: details}
	case planErr != nil:
		return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityFail,
			Message: fmt.Sprintf("%s would refuse to start: %v", prefix, planErr),
			Remediation: fmt.Sprintf("Set ui.listen in %s to a host without a port — %s, 0.0.0.0, :: or one "+
				"interface's address — or remove it", where, exposure.LoopbackHost),
			Details: details}
	}
	details["would_bind"] = plan.String()
	switch {
	case plan.Open() && plan.BeyondLoopback():
		return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityFail,
			Message: fmt.Sprintf("%s would serve without sign-in on %s, because %s is set: anyone who can "+
				"reach it could list its projects, queue tasks and start agent runs on this host",
				prefix, plan, exposure.AckKey),
			Remediation: fmt.Sprintf("Configure ui.oidc or %s, or remove ui.listen and %s from %s",
				envUIToken, exposure.AckKey, where),
			Details: details}
	case plan.Open():
		return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityPass,
			Message: fmt.Sprintf("%s would listen on %s only: it has no sign-in (%s), so nothing beyond this "+
				"machine may reach it", prefix, plan, cred),
			Details: details}
	case plan.PlaintextBehindHTTPS():
		return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityWarn,
			Message: fmt.Sprintf("%s would serve plaintext on %s while %s is %s: a client that reaches the "+
				"port directly skips the TLS terminator in front of it, and a sign-in, session cookie or API "+
				"token sent there crosses the network in the clear", prefix, plan, plan.ExternalURLKey,
				plan.ExternalURL),
			Remediation: plaintextRemediation(where, plan.Port),
			Details:     details}
	}
	return Finding{Check: "ui.exposure", Title: "Network exposure", Severity: SeverityPass,
		Message: fmt.Sprintf("%s would listen on %s behind sign-in (%s)", prefix, plan, cred),
		Details: details}
}

func plaintextRemediation(where string, port int) string {
	p := "the port"
	if port > 0 {
		p = "tcp/" + strconv.Itoa(port)
	}
	return fmt.Sprintf("If the TLS proxy runs on this host, set ui.listen: %s in %s; otherwise firewall %s to "+
		"the proxy, or serve TLS here with ui.tls", exposure.LoopbackHost, where, p)
}

// socketScope reports how far the widest of socks reaches, and that socket.
func socketScope(socks []netip.AddrPort) (exposure.Scope, netip.AddrPort) {
	scope, widest := exposure.ScopeLoopback, socks[0]
	for _, s := range socks {
		switch a := s.Addr(); {
		case a.IsUnspecified():
			return exposure.ScopeEvery, s
		case !a.IsLoopback() && scope == exposure.ScopeLoopback:
			scope, widest = exposure.ScopeAddress, s
		}
	}
	return scope, widest
}

// shownList renders each socket as `ss` does: "*:8080" for a wildcard.
func shownList(socks []netip.AddrPort) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range socks {
		text := s.String()
		if s.Addr().IsUnspecified() {
			text = "*:" + strconv.Itoa(int(s.Port()))
		}
		if !seen[text] {
			seen[text] = true
			out = append(out, text)
		}
	}
	sort.Strings(out)
	return out
}

func describeSockets(socks []netip.AddrPort) string {
	return strings.Join(shownList(socks), ", ")
}

// probeHub asks the listener for the project list with no credentials. A
// wildcard socket is asked on loopback, which it also accepts.
func probeHub(ctx context.Context, opts Options, sock netip.AddrPort) probeResult {
	host := sock.Addr()
	if host.IsUnspecified() {
		host = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		if sock.Addr().Is6() {
			host = netip.IPv6Loopback()
		}
	}
	target := netip.AddrPortFrom(host, sock.Port()).String()
	res := probeResult{Target: target}

	ctx, cancel := context.WithTimeout(ctx, opts.dialTimeout())
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:             nil, // the hub on this machine, never via a proxy
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return opts.dial(ctx, addr)
			},
		},
		// A redirect is an answer about sign-in, not a place to go.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+exposureProbePath, nil)
	if err != nil {
		res.Kind, res.Err = probeUnknown, err
		return res
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cloop-hub-doctor")
	resp, err := client.Do(req)
	if err != nil {
		res.Kind, res.Err = probeUnknown, err
		return res
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		strings.Contains(resp.Header.Get("Content-Type"), "json"):
		res.Kind = probeOpen
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		res.Kind = probeSignIn
	case resp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), "HTTPS server"):
		res.Kind = probeTLS
	default:
		res.Kind = probeUnknown
	}
	return res
}

// isHTTPSURL reports an https URL with a host.
func isHTTPSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.EqualFold(u.Scheme, "https") && u.Host != ""
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func setOrNot(b bool) string {
	if b {
		return "set"
	}
	return "not set"
}
