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
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/secretstore"
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
		if f, ok := switchedOffFinding(cfg, "executors.egress", "egress.enabled", "Egress broker",
			"the hub hosts no egress proxy: runs whose .cloop/sandbox.yaml names an egress grant are "+
				"refused, and the rest get no proxy session"); ok {
			add(f)
			return
		}
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
	checkEgressRoutes(ctx, dir, cfg, opts, add)
}

// checkEgressRoutes reports how each kind of workload this hub runs reaches
// the proxy, or why it cannot, by the rules the hub dispatches with:
// executor.ContainerEgressRoute for a container on its own engine, and
// executor.AdvertisedEgressRoute for Pods and devices, which are handed
// advertise_addr. A kind that is refused a route has every run that names an
// egress grant refused, so that is a failure for an executor the hub has, and
// a warning for devices it merely expects.
//
// This used to be a guess: advertise_addr unset was always a warning, and a
// loopback one was flagged only in strict mode — so a Kubernetes hub that
// allowed host execution passed with 127.0.0.1, which the hub refuses for every
// Pod, and the remediation recommended a Service name, which it refuses too
// (Task 20387).
func checkEgressRoutes(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn) {
	e := cfg.Executors.Egress
	listen := strings.TrimSpace(e.ListenAddr)
	if listen == "" {
		listen = egressbroker.DefaultListenAddr
	}
	bound, err := boundAddr(listen, opts.Offline)
	if err != nil {
		add(Finding{
			Check: "egress.listen_addr", Title: "Egress broker listen address", Severity: SeverityWarn,
			Message: fmt.Sprintf("the address the proxy binds could not be determined (%v), so no "+
				"sandbox's route to it was checked", err),
			Remediation: "Write executors.egress.listen_addr as an address and port, e.g. 0.0.0.0:8899",
		})
		return
	}
	// The port, when the hub picks it at startup, is not knowable here. The
	// rules judge the host; a port taken from the listener is valid by
	// construction, so any valid one stands in for it where a route needs one.
	ephemeral := bound.Port == 0
	routePort := bound.Port
	if ephemeral {
		routePort = 65535
	}

	// The hub resolves advertise_addr before it serves anything, and a value
	// it cannot resolve means no proxy at all — for every kind of sandbox,
	// not only the ones that read it.
	advertised, advErr := executor.EgressAdvertised(e.AdvertiseAddr, routePort)
	if advErr != nil {
		add(Finding{
			Check: "egress.advertise_addr", Title: "Egress broker advertised address", Severity: SeverityFail,
			Message: fmt.Sprintf("the proxy will not start: %v, so every run that names an egress grant "+
				"is refused", advErr),
			Remediation: "Write executors.egress.advertise_addr as host:port, or remove it",
		})
		return
	}

	// A refused route costs a run only when it names an egress grant, so it
	// is a failure while one is in force and a warning until then. A grant
	// store that cannot be read counts as holding one.
	grants, known := activeEgressGrants(dir)
	costs := func(certain bool) (Severity, string) {
		switch {
		case !certain:
			return SeverityWarn, " — when one enrolls"
		case grants > 0 || !known:
			return SeverityFail, ""
		}
		return SeverityWarn, " — none does yet, as no egress grant is active"
	}

	if cfg.Executors.Container.Enabled {
		if route, why, remedy := executor.ContainerEgressRoute(bound); why != "" {
			sev, when := costs(true)
			add(Finding{
				Check: "egress.listen_addr", Title: "Egress broker listen address", Severity: sev,
				Message: "container sandboxes are refused the proxy: " + why +
					", so every container run that names an egress grant is refused" + when,
				Remediation: remedy,
			})
		} else {
			add(Finding{
				Check: "egress.listen_addr", Title: "Egress broker listen address", Severity: SeverityPass,
				Message: "container sandboxes reach the proxy at " + routeShown(route, ephemeral),
			})
		}
	}

	// who is the hub's own word for the workloads, in its reason; label is
	// the doctor's, in a sentence about all of them.
	routeFor := func(who, label, remedy string, certain bool) {
		route, why := executor.AdvertisedEgressRoute(advertised, bound.String(), who)
		if why != "" {
			sev, when := costs(certain)
			add(Finding{
				Check: "egress.advertise_addr", Title: "Egress broker advertised address", Severity: sev,
				Message: fmt.Sprintf("%s are refused the proxy: %s, so their runs that name an egress "+
					"grant are refused%s", label, why, when),
				Remediation: remedy,
			})
			return
		}
		add(Finding{
			Check: "egress.advertise_addr", Title: "Egress broker advertised address", Severity: SeverityPass,
			Message: fmt.Sprintf("%s are pointed at %s", label, routeShown(route, ephemeral)),
		})
	}
	if cfg.Executors.Kubernetes.Enabled {
		routeFor("Pods", "Pods", executor.EgressRemedyPods, true)
	}
	// Devices reach the proxy the way Pods do. They are certain once one is
	// enrolled, and expected when strict mode leaves nothing else to run work.
	devicesOnly := !cfg.Executors.HostProcessAllowed() && !cfg.Executors.Container.Enabled &&
		!cfg.Executors.Kubernetes.Enabled
	agents, agentsKnown := enrolledAgentsKnown(dir)
	switch {
	case len(agents) > 0 || !agentsKnown:
		routeFor("a device", "Devices", executor.EgressRemedyDevices, true)
	case devicesOnly:
		routeFor("a device", "Devices", executor.EgressRemedyDevices, false)
	}

	// The probe, separately: whether anything answers at the advertised
	// address, which no rule above can say.
	adv := strings.TrimSpace(e.AdvertiseAddr)
	if adv == "" {
		return
	}
	if ephemeral && !hasExplicitPort(adv) {
		add(Finding{
			Check: "egress.advertise_reachable", Title: "Egress broker reachability", Severity: SeverityWarn,
			Message: fmt.Sprintf("executors.egress.advertise_addr %q takes its port from the listener, which "+
				"picks one at startup, so there was nothing to dial and whether a sandbox can reach the "+
				"broker is unknown", adv),
			Remediation: "Give executors.egress.listen_addr or advertise_addr an explicit port to have " +
				"`cloop hub doctor` probe it",
		})
		return
	}
	add(reachFinding("egress.advertise_reachable", "Egress broker reachability",
		"the egress broker", "executors.egress.advertise_addr",
		probeReach(ctx, opts, advertised), opts))
}

// activeEgressGrants counts the egress grants in force, from the grant store
// the hub's proxy decides with. known is false when the database exists and
// could not be read.
func activeEgressGrants(dir string) (n int, known bool) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return 0, true
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return 0, false
	}
	defer func() { _ = db.Close() }()
	store, err := secretstore.NewEgressStore(db)
	if err != nil {
		return 0, false
	}
	grants, err := store.ListGrants()
	if err != nil {
		return 0, false
	}
	now := time.Now()
	for _, g := range grants {
		if g.Active(now) {
			n++
		}
	}
	return n, true
}

// routeShown renders a route for a message, without a port the doctor made up.
func routeShown(r executor.EgressProxyRoute, ephemeral bool) string {
	host := r.Host
	if r.Gateway {
		host += " (pinned to the sandbox's bridge gateway)"
	}
	if ephemeral {
		return host + " on the port the proxy picks at startup"
	}
	return fmt.Sprintf("%s, port %d", host, r.Port)
}

// hasExplicitPort reports whether advertise_addr names its own, non-zero port.
func hasExplicitPort(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	return err == nil && port != "" && port != "0"
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
