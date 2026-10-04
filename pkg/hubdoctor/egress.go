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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// checkEgressBroker reports whether the brokered Internet path is usable.
func checkEgressBroker(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn) {
	e := cfg.Executors.Egress

	if !e.Enabled {
		// A hub whose per-instance overlay enables the proxy still reports it
		// here when this run read a configuration without that overlay: what
		// the running hubs did outranks what this file says they would do.
		checkEgressHosting(dir, add, false)
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

	// What the running hubs did with the section — the one thing the file
	// cannot say. A proxy that would not bind leaves the configuration valid
	// and every run that needs it refused.
	checkEgressHosting(dir, add, true)

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

// checkEgressHosting reports where each running hub's egress proxy listens,
// or why it does not, from the status every hub records when it starts the
// proxy (Task 20378): "listening on X, advertised as Y", or the bind failure.
//
// Read through a read-only handle, like `cloop hub cluster status`: a doctor
// must never migrate a live hub's database by looking at it. A row whose hub
// process is gone — on this machine, by its pid; in a cluster, by its
// membership — is skipped: it describes a proxy nobody is serving.
//
// required says the configuration enables the proxy, so finding none running
// is worth a warning; otherwise only the hubs that do host one are reported.
func checkEgressHosting(dir string, add addFn, required bool) {
	const check, title = "egress.hosted", "Egress proxy"
	path := state.DBPath(dir)
	if _, err := os.Stat(path); err != nil {
		if !required {
			return
		}
		add(Finding{
			Check: check, Title: title, Severity: SeverityWarn,
			Message:     "there is no control-plane database yet, so no hub has started the proxy here",
			Remediation: "Start the hub; it binds executors.egress.listen_addr at startup and records the result",
		})
		return
	}
	members, rows, err := statedb.PeekHubCluster(path, egressbroker.HostedStatusKind)
	if err != nil {
		if !required {
			return
		}
		add(Finding{
			Check: check, Title: title, Severity: SeverityWarn,
			Message:     fmt.Sprintf("the hubs' egress proxy status could not be read: %v", err),
			Remediation: "Run `cloop db verify` on the control plane, and check the hub's log for the proxy",
		})
		return
	}
	self := hublease.LocalIdentity()
	now := time.Now()
	alive := map[string]bool{}
	for _, m := range members {
		alive[m.InstanceID] = hubcluster.RowAlive(m, now)
	}
	type hosted struct {
		key string
		st  egressbroker.HostedStatus
	}
	var live []hosted
	for _, r := range rows {
		var st egressbroker.HostedStatus
		if json.Unmarshal([]byte(r.Meta), &st) != nil {
			continue
		}
		if up, member := alive[r.InstanceID]; member && !up {
			continue
		}
		if st.Hostname != "" && st.Hostname == self.Hostname && hublease.SameBoot(st.BootID, self.BootID) &&
			!pidAlive(st.PID) {
			continue
		}
		live = append(live, hosted{key: r.Key, st: st})
	}
	sort.Slice(live, func(i, j int) bool { return live[i].key < live[j].key })
	if len(live) == 0 {
		if !required {
			return
		}
		add(Finding{
			Check: check, Title: title, Severity: SeverityWarn,
			Message: "executors.egress is enabled, but no running hub has reported hosting the proxy — " +
				"the hub is stopped, or runs a build that predates hosting it",
			Remediation: "Start the hub (or upgrade it and restart); it binds executors.egress.listen_addr " +
				"at startup and records where it listens",
		})
		return
	}
	for _, h := range live {
		who := hostedBy(h.key, h.st)
		if h.st.Error != "" {
			add(Finding{
				Check: check, Title: title, Severity: SeverityFail,
				Message: fmt.Sprintf("%s could not start its egress proxy: %s — runs whose %s names an egress "+
					"grant are refused, and the rest get no proxy session", who, h.st.Error, ".cloop/sandbox.yaml"),
				Remediation: "Fix executors.egress — listen_addr must be free and bindable by the hub — and restart " +
					"that hub",
				Details: map[string]any{"hub": h.key, "error": h.st.Error},
			})
			continue
		}
		add(Finding{
			Check: check, Title: title, Severity: SeverityPass,
			Message: fmt.Sprintf("%s: listening on %s, advertised as %s", who, h.st.Listening, h.st.Advertised),
			Details: map[string]any{"hub": h.key, "listening": h.st.Listening, "advertised": h.st.Advertised},
		})
	}
}

// hostedBy names the hub a status row came from, for a sentence.
func hostedBy(key string, st egressbroker.HostedStatus) string {
	switch {
	case st.HubPort > 0 && st.Hostname != "":
		return fmt.Sprintf("the hub on %s port %d", st.Hostname, st.HubPort)
	case st.Hostname != "":
		return "the hub on " + st.Hostname
	}
	return "hub " + key
}

// pidAlive reports whether pid names a live process on this machine. EPERM
// is a process that exists under another account, so it counts as alive.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
