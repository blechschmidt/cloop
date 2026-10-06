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
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// checkKubeGuard reports whether kubeconfig grants are brokered through the
// monitor.
func checkKubeGuard(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn) {
	k := cfg.Executors.KubeGuard

	if !k.Enabled {
		if f, ok := switchedOffFinding(cfg, "executors.kube_guard", "kubeguard.enabled", "Kubernetes access monitor",
			"the hub runs without the monitor, and a kubeconfig grant delivers the cluster credential "+
				"into the sandbox"); ok {
			add(f)
			return
		}
		// A warning rather than a pass only when there is a kubeconfig grant
		// to protect. Telling an operator with no cluster credential in the
		// store to stand up a TLS proxy would be advice for a problem they do
		// not have.
		if !kubeconfigGrantsLikely(dir, cfg) {
			add(Finding{
				Check:    "kubeguard.enabled",
				Title:    "Kubernetes access monitor",
				Severity: SeverityPass,
				Message: "disabled, and no Kubernetes executor or kubeconfig grant is " +
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

	// --- enabled: does it start, and where does it point sandboxes? ---------

	refusal := "every kubeconfig lease is refused rather than handed the cluster credential"
	starts := proxyTLS("kubeguard.tls", "Kubernetes monitor TLS material", "executors.kube_guard",
		k.CertFile, k.KeyFile, k.MinTLSVersion, refusal, add)
	// The trust anchor a sandbox's kubectl is given, read by the method the
	// hub reads it with: ca_file when set — a path that was typed and cannot
	// be read is a mistake, not a choice — else the serving certificate.
	if starts {
		if _, err := k.CABundle(); err != nil {
			starts = false
			add(Finding{
				Check: "kubeguard.tls", Title: "Kubernetes monitor TLS material", Severity: SeverityFail,
				Message: fmt.Sprintf("the monitor will not start: %v — executors.kube_guard is enabled, "+
					"so %s", err, refusal),
				Remediation: "Point executors.kube_guard.ca_file at a readable PEM bundle, or " +
					"remove it to embed the serving certificate instead",
			})
		}
	}

	// The advertise URL is the most common misconfiguration, because the wrong
	// value works perfectly on the machine it was written on. It is worse here
	// than for git: it becomes the `server:` field of a kubeconfig, so a wrong
	// one produces "connection refused" from kubectl inside someone's task.
	ep, err := resolveProxyEndpoint(k.AdvertiseURL, k.ListenAddr, kubeguard.DefaultListenAddr, opts.Offline,
		kubeguard.AdvertisedBaseURL, kubeguard.NormalizeBaseURL)
	if err != nil && strings.TrimSpace(k.AdvertiseURL) != "" {
		starts = false
		add(Finding{
			Check: "kubeguard.advertise_url", Title: "Kubernetes monitor advertised URL", Severity: SeverityFail,
			Message: fmt.Sprintf("the monitor will not start: %v — executors.kube_guard is enabled, so %s",
				err, refusal),
			Remediation: "Set executors.kube_guard.advertise_url to an https:// base with a host and no path, " +
				"such as https://cloop-kubeguard.cloop.svc:8444",
		})
	} else {
		// Reported whatever this hub's executors are: a monitor that is on is
		// there to be reached from a sandbox.
		reportProxyEndpoint(ctx, opts, ep, err, true, proxyLabels{
			advertiseCheck: "kubeguard.advertise_url", advertiseTitle: "Kubernetes monitor advertised URL",
			reachCheck: "kubeguard.advertise_reachable", reachTitle: "Kubernetes monitor reachability",
			what: "the Kubernetes access monitor", key: "executors.kube_guard.advertise_url",
			consequence: "kubectl inside the sandbox will fail to connect",
			example:     "https://cloop-kubeguard.cloop.svc:8444",
		}, add)
	}

	// The verb ceiling is worth reporting either way, because both states are
	// legitimate and neither is visible anywhere else.
	//
	// Deliberately *not* a warning when it is unset. Unset is the default and
	// means "each grant decides", and a grant that names no verbs is
	// read-only — so warning about it would fire on every correctly-configured
	// hub. What is worth a note is a ceiling that has been widened past the
	// read set, since that is someone deciding the fleet may write and is the
	// only setting here that can be wrong in the dangerous direction.
	pol := k.Policy()
	if len(pol.Verbs) > 0 && !pol.ReadOnly() {
		add(Finding{
			Check:    "kubeguard.verbs",
			Title:    "Kubernetes monitor verb ceiling",
			Severity: SeverityWarn,
			Message: fmt.Sprintf("executors.kube_guard.verbs raises the fleet-wide ceiling to %s; "+
				"it is a cap on what a grant may ask for, not a grant, so setting it wider than "+
				"the read set only matters if some grant also asks to write",
				strings.Join(pol.Verbs, ", ")),
			Remediation: "Leave executors.kube_guard.verbs unset to let each grant decide, or set " +
				"it to get,list,watch to forbid writes fleet-wide; authorise writes per project " +
				"with `cloop secret grant --verbs`",
			Details: map[string]any{"verbs": pol.Verbs},
		})
	}

	if !starts {
		return // the failure above is the verdict
	}
	add(Finding{
		Check:    "kubeguard.enabled",
		Title:    "Kubernetes access monitor",
		Severity: SeverityPass,
		Message: fmt.Sprintf("enabled; the cluster credential stays on the hub and sessions are "+
			"held to at most %s for %d minutes (a grant may narrow it further)", pol.Summary(), k.SessionTTLMinutes()),
		Details: map[string]any{
			"advertise_url":   ep.base,
			"verbs":           pol.Verbs,
			"namespaces":      pol.Namespaces,
			"session_minutes": k.SessionTTLMinutes(),
		},
	})
}

// kubeconfigGrantsLikely reports whether this hub plausibly delivers a
// kubeconfig into a sandbox: a Kubernetes executor means cluster credentials
// are in play, strict mode means every workload is isolated and anything it
// needs arrives by lease, and an active kubeconfig grant is one being
// delivered. Deliberately the inclusive reading: over-reporting costs an
// operator a warning they can dismiss; under-reporting costs them the finding
// this check exists for. The grants are read from the store, so the pass that
// says "no kubeconfig grant" has looked.
func kubeconfigGrantsLikely(dir string, cfg *config.Config) bool {
	if cfg.Executors.Kubernetes.Enabled || !cfg.Executors.HostProcessAllowed() {
		return true
	}
	grants, known := activeGrants(dir, secretbroker.KindKubeconfig)
	return len(grants) > 0 || !known
}
