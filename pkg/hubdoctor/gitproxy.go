package hubdoctor

// Git interception proxy checks: is a sandbox that pushes a work product
// holding a forge credential, or a session token that can only reach the
// write-back namespace?
//
// This is worth its own check because both states look identical from
// everywhere else. A hub with the proxy off runs, dispatches, provisions and
// pushes exactly like one with it on; the difference is only visible in what a
// sandbox could do if it tried something it was not asked to. Nothing fails,
// so nothing reports — which is precisely the shape of finding this command
// exists to surface.
//
// What the checks do NOT do is dial the proxy. A doctor run happens on the host
// and often before the listener is up, and the interesting question is not
// "does this port answer" but "will a sandbox, on its own network, reach the
// URL it is about to be handed" — which cannot be answered from here. Reading
// the config is the narrower and more honest answer.

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// checkGitProxy reports whether git pushes from sandboxes are brokered.
func checkGitProxy(cfg *config.Config, add addFn) {
	g := cfg.Executors.GitProxy

	if !g.Enabled {
		// A warning rather than a pass only when there is something to protect.
		// A single-machine install whose executors share the host filesystem
		// never provisions a git workspace at all, so telling its operator to
		// stand up a TLS proxy would be advice for a problem they do not have.
		if !gitWorkspacesLikely(cfg) {
			add(Finding{
				Check:    "gitproxy.enabled",
				Title:    "Git interception proxy",
				Severity: SeverityPass,
				Message: "disabled, and no configured executor provisions a git workspace, " +
					"so no forge credential is delivered into a sandbox",
			})
			return
		}
		add(Finding{
			Check:    "gitproxy.enabled",
			Title:    "Git interception proxy",
			Severity: SeverityWarn,
			Message: "disabled while executors that clone the project source are configured, " +
				"so a sandbox is handed the GitHub PAT and the cloop/ branch rule is enforced " +
				"only by code the sandbox itself runs",
			Remediation: "Set executors.git_proxy.enabled: true with cert_file, key_file and " +
				"advertise_url, so the credential stays on the hub and the branch allowlist " +
				"is enforced on the push. See docs/git-interception-proxy.md",
		})
		return
	}

	// --- enabled: is it usable? ---------------------------------------------

	for label, path := range map[string]string{"cert_file": g.CertFile, "key_file": g.KeyFile} {
		p := strings.TrimSpace(path)
		if p == "" {
			add(Finding{
				Check:    "gitproxy.tls",
				Title:    "Git proxy TLS material",
				Severity: SeverityFail,
				Message: fmt.Sprintf("executors.git_proxy is enabled but %s is not set, so the "+
					"proxy will not start and git workspaces will be refused", label),
				Remediation: "Set executors.git_proxy." + label + ", or set enabled: false",
			})
			continue
		}
		if _, err := os.Stat(p); err != nil {
			add(Finding{
				Check:    "gitproxy.tls",
				Title:    "Git proxy TLS material",
				Severity: SeverityFail,
				Message:  fmt.Sprintf("executors.git_proxy.%s is %s, which cannot be read: %v", label, p, err),
				Remediation: "Point executors.git_proxy." + label + " at a readable file, or " +
					"generate one with `cloop hub bootstrap`",
			})
		}
	}

	// The advertise URL is the single most common way this is misconfigured,
	// because the wrong value works perfectly on the machine it was written on.
	adv := strings.TrimSpace(g.AdvertiseURL)
	switch {
	case adv == "":
		add(Finding{
			Check:    "gitproxy.advertise_url",
			Title:    "Git proxy advertised URL",
			Severity: SeverityWarn,
			Message: "not set, so sandboxes are pointed at the hub's own bound address — " +
				"correct only when the sandbox shares the host's network namespace",
			Remediation: "Set executors.git_proxy.advertise_url to a URL the sandbox can reach " +
				"(a Service name for Kubernetes, a hub address the edge device routes to)",
		})
	case isLoopbackURL(adv) && gitWorkspacesLikely(cfg):
		add(Finding{
			Check:    "gitproxy.advertise_url",
			Title:    "Git proxy advertised URL",
			Severity: SeverityWarn,
			Message: fmt.Sprintf("advertises %s, which a Pod or an edge device cannot reach — "+
				"their clone and write-back push will fail to connect", adv),
			Remediation: "Set executors.git_proxy.advertise_url to an address reachable from " +
				"the sandbox's network, not from the hub's",
		})
	}

	// A widened allowlist is legitimate and deliberate, and worth saying out
	// loud: it is the one setting that decides which branches a sandbox can
	// reach, and its default is the reason the subsystem is a boundary at all.
	pol := g.Policy()
	if widened := widenedRefs(pol.AllowedRefs); len(widened) > 0 {
		add(Finding{
			Check:    "gitproxy.allowed_refs",
			Title:    "Git proxy branch allowlist",
			Severity: SeverityWarn,
			Message: fmt.Sprintf("allows %s, which reaches outside the cloop/ write-back "+
				"namespace, so a sandbox may push to branches a human owns",
				strings.Join(widened, ", ")),
			Remediation: "Remove the widened patterns from executors.git_proxy.allowed_refs " +
				"unless a workload genuinely needs them; the default is " + gitproxy.DefaultAllowedRef,
			Details: map[string]any{"allowed_refs": pol.AllowedRefs},
		})
	}
	if g.AllowDelete {
		add(Finding{
			Check:    "gitproxy.allow_delete",
			Title:    "Git proxy delete authority",
			Severity: SeverityWarn,
			Message: "executors.git_proxy.allow_delete is on, so a sandbox may delete the " +
				"branches it can write — a write-back never needs this",
			Remediation: "Set executors.git_proxy.allow_delete: false",
		})
	}

	add(Finding{
		Check:    "gitproxy.enabled",
		Title:    "Git interception proxy",
		Severity: SeverityPass,
		Message: fmt.Sprintf("enabled; the forge credential stays on the hub and pushes are "+
			"limited to %s for %d minutes per session",
			strings.Join(pol.AllowedRefs, ", "), g.SessionTTLMinutes()),
		Details: map[string]any{
			"advertise_url":   adv,
			"allowed_refs":    pol.AllowedRefs,
			"session_minutes": g.SessionTTLMinutes(),
		},
	})
}

// gitWorkspacesLikely reports whether any configured executor would clone the
// project rather than find it already on disk.
//
// Only the Kubernetes driver and enrolled edge devices provision a git
// workspace; the container driver bind-mounts and the host driver is the host.
// Edge devices arrive at runtime over an outbound connection and so cannot be
// seen in a config file — strict mode is the closest available signal that a
// hub expects them, and it is the mode under which they are the only way work
// runs at all.
func gitWorkspacesLikely(cfg *config.Config) bool {
	return cfg.Executors.Kubernetes.Enabled || !cfg.Executors.HostProcessAllowed()
}

// isLoopbackURL reports whether a URL names this machine and nowhere else.
func isLoopbackURL(raw string) bool {
	s := strings.ToLower(raw)
	for _, host := range []string{"//127.0.0.1", "//localhost", "//[::1]", "//0.0.0.0"} {
		if strings.Contains(s, host) {
			return true
		}
	}
	return false
}

// widenedRefs returns the patterns that reach outside the write-back namespace.
//
// The comparison is a prefix test against the default rather than an attempt to
// decide what a glob can match, because the honest question is "did somebody
// add something", not "is this pattern dangerous" — and a check that tried to
// prove the latter would either miss cases or cry wolf.
func widenedRefs(patterns []string) []string {
	const namespace = "refs/heads/cloop/"
	var out []string
	for _, p := range patterns {
		if !strings.HasPrefix(p, namespace) {
			out = append(out, p)
		}
	}
	return out
}
