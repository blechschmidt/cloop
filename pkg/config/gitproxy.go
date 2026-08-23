package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// GitProxySessionMinutesUpper bounds a git-proxy session.
//
// A session is a live credential for one repository, so its ceiling is a
// security control rather than a convenience. Twelve hours is
// gitproxy.MaxSessionTTL, and the reasoning there applies here: a git-proxy
// session that lives longer than a working day is indistinguishable from
// having handed the sandbox the forge credential outright.
const GitProxySessionMinutesUpper = int(gitproxy.MaxSessionTTL / 60e9)

// ValidateGitProxyConfig returns a non-nil error describing the first problem
// found in g. It does not mutate.
//
// Like the other executor validators it runs even when the section is
// disabled, so a broken value is reported when it is written rather than
// discovered at the moment someone flips enabled to true.
func ValidateGitProxyConfig(g GitProxyConfig) error {
	if g.SessionMinutes < 0 || g.SessionMinutes > GitProxySessionMinutesUpper {
		return fmt.Errorf("executors.git_proxy.session_minutes must be between 0 and %d (got %d)",
			GitProxySessionMinutesUpper, g.SessionMinutes)
	}
	if err := validateGitProxyListenAddr(g.ListenAddr); err != nil {
		return err
	}
	if err := validateGitProxyAdvertiseURL(g.AdvertiseURL); err != nil {
		return err
	}
	if v := strings.TrimSpace(g.MinTLSVersion); v != "" {
		if _, err := tlsconf.ParseMinVersion(v); err != nil {
			return fmt.Errorf("executors.git_proxy.min_tls_version: %w", err)
		}
	}
	// The allowlist is validated through the same code the proxy enforces
	// with, so a pattern that would silently match nothing is refused here
	// rather than read as a working allowlist that denies everything.
	if len(g.AllowedRefs) > 0 {
		pol := gitproxy.Policy{
			AllowedRefs: append([]string(nil), g.AllowedRefs...),
			AllowCreate: true, AllowUpdate: true, AllowFetch: true,
		}
		pol.Normalize()
		if err := pol.Validate(); err != nil {
			return fmt.Errorf("executors.git_proxy.allowed_refs: %w", err)
		}
	}
	// Only when enabled: TLS material that does not exist yet is an ordinary
	// state for a section an operator is still writing, and refusing to load
	// the whole config over it would be worse than starting without a proxy.
	if g.Enabled {
		cert, key := strings.TrimSpace(g.CertFile), strings.TrimSpace(g.KeyFile)
		if cert == "" || key == "" {
			return fmt.Errorf("executors.git_proxy is enabled but cert_file and key_file are " +
				"not both set; the session token rides an Authorization header on every " +
				"request and cleartext would publish it rather than deliver it")
		}
	}
	return nil
}

// validateGitProxyListenAddr checks the bind address. A port is required
// because net.Listen needs one; an empty value means "ephemeral loopback".
func validateGitProxyListenAddr(addr string) error {
	a := strings.TrimSpace(addr)
	if a == "" {
		return nil
	}
	if strings.Contains(a, "://") || strings.ContainsAny(a, "/?#@ \t") {
		return fmt.Errorf("executors.git_proxy.listen_addr must be host:port, not a URL (got %q)", a)
	}
	_, port, err := net.SplitHostPort(a)
	if err != nil {
		return fmt.Errorf("executors.git_proxy.listen_addr must be host:port (got %q)", a)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("executors.git_proxy.listen_addr port must be between 0 and 65535 (got %q)", port)
	}
	return nil
}

// validateGitProxyAdvertiseURL checks the URL sandboxes are pointed at.
//
// It is a URL rather than a host:port because it becomes a git remote, and it
// must be https for the same reason gitproxy.NewRegistry insists: the session
// token is presented on every request, and a loopback listener is no
// exception — a sandbox is by construction something that may share a host
// with whatever else is listening on loopback.
func validateGitProxyAdvertiseURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("executors.git_proxy.advertise_url is not a URL (got %q): %w", s, err)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("executors.git_proxy.advertise_url must be an https:// URL (got %q)", s)
	case u.Host == "":
		return fmt.Errorf("executors.git_proxy.advertise_url has no host (got %q)", s)
	case u.User != nil:
		return fmt.Errorf("executors.git_proxy.advertise_url must not embed credentials")
	case strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("executors.git_proxy.advertise_url must be a bare base URL with no "+
			"path, query or fragment (got %q)", s)
	}
	return nil
}

// clampGitProxyConfig repairs out-of-range values in place and reports what it
// changed, so Load can warn once per field.
//
// Every repair resets to the zero value, which is read as "use the default",
// and every default is the tighter one: a shorter session, a loopback bind,
// the built-in write-back allowlist. The exception is Enabled itself, which is
// switched *off* when the section could only start an unusable or unsafe
// proxy — a listen address nobody chose, an advertise URL a sandbox would send
// a token to in cleartext, or missing TLS material.
//
// Disabling is the safe repair here precisely because the proxy is not a
// fallback: with it off, a workspace is provisioned the way it was before
// interception existed, which is the documented pre-Task-20184 behaviour
// rather than a new failure mode.
func clampGitProxyConfig(g *GitProxyConfig) []string {
	var changed []string

	if g.SessionMinutes < 0 || g.SessionMinutes > GitProxySessionMinutesUpper {
		changed = append(changed, fmt.Sprintf("executors.git_proxy.session_minutes: value %d outside [0, %d]",
			g.SessionMinutes, GitProxySessionMinutesUpper))
		g.SessionMinutes = 0
	}
	if v := strings.TrimSpace(g.MinTLSVersion); v != "" {
		if _, err := tlsconf.ParseMinVersion(v); err != nil {
			changed = append(changed, fmt.Sprintf("executors.git_proxy.min_tls_version: %v", err))
			g.MinTLSVersion = ""
		}
	}
	if len(g.AllowedRefs) > 0 {
		pol := gitproxy.Policy{
			AllowedRefs: append([]string(nil), g.AllowedRefs...),
			AllowCreate: true, AllowUpdate: true, AllowFetch: true,
		}
		pol.Normalize()
		if err := pol.Validate(); err != nil {
			// Reset to the built-in write-back namespace rather than dropping
			// the bad pattern and keeping the rest: a half-applied allowlist
			// is a policy nobody wrote, and the default is narrower than any
			// override an operator was reaching for.
			changed = append(changed, fmt.Sprintf("executors.git_proxy.allowed_refs: %v", err))
			g.AllowedRefs = nil
		}
	}
	if err := validateGitProxyListenAddr(g.ListenAddr); err != nil {
		changed = append(changed, fmt.Sprintf("executors.git_proxy.listen_addr: %v", err))
		g.ListenAddr = ""
		g.Enabled = false
	}
	if err := validateGitProxyAdvertiseURL(g.AdvertiseURL); err != nil {
		changed = append(changed, fmt.Sprintf("executors.git_proxy.advertise_url: %v", err))
		g.AdvertiseURL = ""
		g.Enabled = false
	}
	if g.Enabled && (strings.TrimSpace(g.CertFile) == "" || strings.TrimSpace(g.KeyFile) == "") {
		changed = append(changed, "executors.git_proxy.cert_file: enabled without TLS material, "+
			"which would carry every session token in cleartext")
		g.Enabled = false
	}
	return changed
}

// SessionTTLMinutes returns the effective session length, applying the default
// for an unset value. It does not clamp: an out-of-range value is repaired by
// clampGitProxyConfig at load, and silently narrowing here would hide it.
func (g GitProxyConfig) SessionTTLMinutes() int {
	if g.SessionMinutes <= 0 {
		return int(gitproxy.DefaultSessionTTL / 60e9)
	}
	return g.SessionMinutes
}

// Policy renders the configured allowlist as the policy the proxy enforces.
//
// Fetch is always permitted: with a proxy interposed the provisioning clone
// goes through it too, and that is the point — it is what keeps the forge
// credential off the sandbox for both halves of the round trip, not just the
// push.
func (g GitProxyConfig) Policy() gitproxy.Policy {
	pol := gitproxy.Policy{
		AllowedRefs: append([]string(nil), g.AllowedRefs...),
		AllowCreate: true,
		AllowUpdate: true,
		AllowDelete: g.AllowDelete,
		AllowFetch:  true,
	}
	pol.Normalize()
	return pol
}
