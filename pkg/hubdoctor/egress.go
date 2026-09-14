package hubdoctor

// Egress broker checks: when a sandbox is confined to a network with no route
// off the host, this proxy is the only way out — so the address it is reached
// at is load-bearing in a way a bound listener never is.
//
// The failure this exists to catch is the same one checkGitProxy has, and for
// the same reason. executors.egress.advertise_addr is written into a sandbox's
// environment and dialled from inside the sandbox's network; the hub never
// contacts it. A value that is right on the hub and unroutable from a Pod is
// therefore invisible: the broker starts, the config validates, the grant is
// minted, and the first workload to make a request hangs. Probing it is not
// proof — see reachability.go on what a dial from here can settle — but it
// separates "nothing is listening" from "this was never checked", and those
// were previously the same green line.

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
)

// checkEgressBroker reports whether the brokered Internet path is usable.
func checkEgressBroker(ctx context.Context, cfg *config.Config, opts Options, add addFn) {
	e := cfg.Executors.Egress

	if !e.Enabled {
		// Not a defect on its own — most deployments do not lease the hub's
		// connection — but it is one when a sandbox has been confined to an
		// internal network, because then the broker was its only way out and
		// its absence turns every outbound request into a timeout.
		if cfg.Executors.Container.Enabled && cfg.Executors.Container.EgressFilter.Enabled &&
			cfg.Executors.Container.EgressFilter.Internal {
			add(Finding{
				Check:    "egress.enabled",
				Title:    "Egress broker",
				Severity: SeverityWarn,
				Message: "disabled while executors.container.egress_filter.internal is on, so sandboxes " +
					"are on a network with no route off the host and nothing to proxy through — " +
					"every outbound request will hang",
				Remediation: "Set executors.egress.enabled: true and grant per-project access with " +
					"`cloop egress grant`, or set executors.container.egress_filter.internal: false",
			})
			return
		}
		add(Finding{
			Check:    "egress.enabled",
			Title:    "Egress broker",
			Severity: SeverityPass,
			Message:  "disabled; no sandbox is leased the hub's Internet connection",
		})
		return
	}

	adv := strings.TrimSpace(e.AdvertiseAddr)
	switch {
	case adv == "":
		add(Finding{
			Check:    "egress.advertise_addr",
			Title:    "Egress broker advertised address",
			Severity: SeverityWarn,
			Message: "not set, so sandboxes are pointed at the broker's own bound address — " +
				"correct only when the sandbox shares the host's network namespace",
			Remediation: "Set executors.egress.advertise_addr to a host:port the sandbox can reach " +
				"(the bridge address for a container executor, a Service name for Kubernetes)",
		})
	case isLoopbackHostPort(adv) && !cfg.Executors.HostProcessAllowed():
		add(Finding{
			Check:    "egress.advertise_addr",
			Title:    "Egress broker advertised address",
			Severity: SeverityWarn,
			Message: fmt.Sprintf("advertises %s, which resolves to the hub itself inside every sandbox "+
				"that has its own network namespace — their proxy requests will never leave the sandbox", adv),
			Remediation: "Set executors.egress.advertise_addr to an address reachable from the " +
				"sandbox's network, not from the hub's",
		})
	}

	if adv == "" {
		return
	}
	target, err := addrTarget(adv)
	if err != nil {
		add(Finding{
			Check:    "egress.advertise_reachable",
			Title:    "Egress broker reachability",
			Severity: SeverityWarn,
			Message: fmt.Sprintf("executors.egress.advertise_addr %q %v, so whether a sandbox can "+
				"reach the broker is unknown", adv, err),
			Remediation: "Write executors.egress.advertise_addr as host:port to have " +
				"`cloop hub doctor` probe it",
		})
		return
	}
	add(reachFinding("egress.advertise_reachable", "Egress broker reachability",
		"the egress broker", "executors.egress.advertise_addr",
		probeReach(ctx, opts, target), opts))
}

// isLoopbackHostPort reports whether a host:port names this machine only.
//
// Separate from isLoopbackURL because the two inputs differ in shape, and
// parsing a bare host:port as a URL succeeds while producing nonsense — the
// host lands in the scheme or the path depending on what it looks like.
func isLoopbackHostPort(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		host = strings.TrimSpace(addr)
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	// The unspecified address is included: a broker bound to 0.0.0.0 is
	// reachable, but a sandbox told to *dial* 0.0.0.0 dials itself.
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}
