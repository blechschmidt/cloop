package hubdoctor

// Kubernetes access monitor checks: is a sandbox that talks to a cluster
// holding that cluster's credential, or a session token that can only do what
// its grant says?
//
// This is worth its own check for the reason checkGitProxy is: the two states
// look identical from everywhere else. A hub with the monitor off leases,
// dispatches and runs `kubectl` exactly like one with it on — the difference
// is only visible in what a sandbox could do if it tried something it was not
// asked to. Nothing fails, so nothing reports.
//
// There is one asymmetry with the git proxy worth naming, and it drives the
// severities below. A git grant's allowlist is at least *checked* by a
// credential helper inside the sandbox when the proxy is off, so the
// unmonitored state is weak enforcement. A kubeconfig grant's namespace list
// is checked by nothing at all when the monitor is off — it is a `namespace:`
// line in a file that `kubectl -n` overrides — and its verbs are not checked
// even in principle. So an unmonitored kubeconfig grant is not weaker
// enforcement; it is the absence of any, and the finding says so plainly.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
)

// checkKubeGuard reports whether kubeconfig grants are brokered through the
// monitor.
func checkKubeGuard(ctx context.Context, cfg *config.Config, opts Options, add addFn) {
	k := cfg.Executors.KubeGuard

	if !k.Enabled {
		// A warning rather than a pass only when there is a kubeconfig grant
		// to protect. Telling an operator with no cluster credential in the
		// store to stand up a TLS proxy would be advice for a problem they do
		// not have.
		if !kubeconfigGrantsLikely(cfg) {
			add(Finding{
				Check:    "kubeguard.enabled",
				Title:    "Kubernetes access monitor",
				Severity: SeverityPass,
				Message: "disabled, and no Kubernetes executor or kubeconfig secret is " +
					"configured, so no cluster credential is delivered into a sandbox",
			})
			return
		}
		add(Finding{
			Check:    "kubeguard.enabled",
			Title:    "Kubernetes access monitor",
			Severity: SeverityWarn,
			Message: "disabled while Kubernetes access is configured, so a kubeconfig grant " +
				"delivers the cluster credential into the sandbox: its namespace list is only " +
				"the default kubectl uses without -n, and its verbs are not enforced at all",
			Remediation: "Set executors.kube_guard.enabled: true with cert_file, key_file and " +
				"advertise_url, so the credential stays on the hub and every API request is " +
				"decided before it reaches the cluster. See " +
				"docs/architecture/kubernetes-access.md",
		})
		return
	}

	// --- enabled: is it usable? ---------------------------------------------

	for label, path := range map[string]string{"cert_file": k.CertFile, "key_file": k.KeyFile} {
		p := strings.TrimSpace(path)
		if p == "" {
			add(Finding{
				Check:    "kubeguard.tls",
				Title:    "Kubernetes monitor TLS material",
				Severity: SeverityFail,
				Message: fmt.Sprintf("executors.kube_guard is enabled but %s is not set, so the "+
					"monitor will not start and every kubeconfig lease will be refused", label),
				Remediation: "Set executors.kube_guard." + label + ", or set enabled: false",
			})
			continue
		}
		if _, err := os.Stat(p); err != nil {
			add(Finding{
				Check:    "kubeguard.tls",
				Title:    "Kubernetes monitor TLS material",
				Severity: SeverityFail,
				Message:  fmt.Sprintf("executors.kube_guard.%s is %s, which cannot be read: %v", label, p, err),
				Remediation: "Point executors.kube_guard." + label + " at a readable file, or " +
					"generate one with `cloop hub bootstrap`",
			})
		}
	}
	// ca_file is optional — the serving certificate is used when it is unset —
	// but a path that was typed and cannot be read is a mistake, not a choice.
	if p := strings.TrimSpace(k.CAFile); p != "" {
		if _, err := os.Stat(p); err != nil {
			add(Finding{
				Check:    "kubeguard.tls",
				Title:    "Kubernetes monitor TLS material",
				Severity: SeverityFail,
				Message: fmt.Sprintf("executors.kube_guard.ca_file is %s, which cannot be read: %v; "+
					"the monitor will not start", p, err),
				Remediation: "Point executors.kube_guard.ca_file at a readable PEM bundle, or " +
					"remove it to embed the serving certificate instead",
			})
		}
	}

	// The advertise URL is the most common misconfiguration, because the wrong
	// value works perfectly on the machine it was written on. It is worse here
	// than for git: it becomes the `server:` field of a kubeconfig, so a wrong
	// one produces "connection refused" from kubectl inside someone's task.
	adv := strings.TrimSpace(k.AdvertiseURL)
	switch {
	case adv == "":
		add(Finding{
			Check:    "kubeguard.advertise_url",
			Title:    "Kubernetes monitor advertised URL",
			Severity: SeverityWarn,
			Message: "not set, so sandboxes are pointed at the hub's own bound address — " +
				"correct only when the sandbox shares the host's network namespace",
			Remediation: "Set executors.kube_guard.advertise_url to a URL the sandbox can reach " +
				"(a Service name for Kubernetes, a hub address the edge device routes to)",
		})
	case isLoopbackURL(adv):
		add(Finding{
			Check:    "kubeguard.advertise_url",
			Title:    "Kubernetes monitor advertised URL",
			Severity: SeverityWarn,
			Message: fmt.Sprintf("advertises %s, which a Pod or an edge device cannot reach — "+
				"kubectl inside the sandbox will fail to connect", adv),
			Remediation: "Set executors.kube_guard.advertise_url to an address reachable from " +
				"the sandbox's network, not from the hub's",
		})
	}

	if adv != "" {
		target, err := dialTarget(adv)
		if err != nil {
			add(Finding{
				Check:    "kubeguard.advertise_reachable",
				Title:    "Kubernetes monitor reachability",
				Severity: SeverityWarn,
				Message: fmt.Sprintf("executors.kube_guard.advertise_url %q could not be turned into "+
					"an address to dial: %v", adv, err),
				Remediation: "Set executors.kube_guard.advertise_url to an absolute URL such as " +
					"https://cloop-kubeguard.cloop.svc:8444",
			})
		} else {
			add(reachFinding("kubeguard.advertise_reachable", "Kubernetes monitor reachability",
				"the Kubernetes access monitor", "executors.kube_guard.advertise_url",
				probeReach(ctx, opts, target), opts))
		}
	}

	// A floor that permits writing is legitimate and deliberate, and worth
	// saying out loud: it is the setting that decides whether any project on
	// this hub can change a cluster, and its default is the reason the
	// subsystem is a boundary at all.
	pol := k.Policy()
	if !pol.ReadOnly() {
		add(Finding{
			Check:    "kubeguard.verbs",
			Title:    "Kubernetes monitor verb floor",
			Severity: SeverityWarn,
			Message: fmt.Sprintf("executors.kube_guard.verbs allows %s, so a grant on this hub may "+
				"be given authority to change a cluster; leaving it unset holds every project "+
				"to get, list and watch regardless of what its grant asks for",
				strings.Join(pol.Verbs, ", ")),
			Remediation: "Remove executors.kube_guard.verbs unless a workload genuinely needs to " +
				"write, and grant the write verbs per project with `cloop secret grant --verbs`",
			Details: map[string]any{"verbs": pol.Verbs},
		})
	}

	add(Finding{
		Check:    "kubeguard.enabled",
		Title:    "Kubernetes access monitor",
		Severity: SeverityPass,
		Message: fmt.Sprintf("enabled; the cluster credential stays on the hub and sessions are "+
			"held to %s for %d minutes", pol.Summary(), k.SessionTTLMinutes()),
		Details: map[string]any{
			"advertise_url":   adv,
			"verbs":           pol.Verbs,
			"namespaces":      pol.Namespaces,
			"session_minutes": k.SessionTTLMinutes(),
		},
	})
}

// kubeconfigGrantsLikely reports whether this hub plausibly delivers a
// kubeconfig into a sandbox.
//
// Config is the only thing available here — the secret store is a separate
// database this check does not open — so this is a heuristic, and it is
// deliberately the inclusive one. A Kubernetes executor means cluster
// credentials are in play; strict mode means every workload is isolated and so
// anything it needs arrives by lease. Over-reporting costs an operator a
// warning they can dismiss; under-reporting costs them the finding this check
// exists for.
func kubeconfigGrantsLikely(cfg *config.Config) bool {
	return cfg.Executors.Kubernetes.Enabled || !cfg.Executors.HostProcessAllowed()
}
