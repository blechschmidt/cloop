package cmd

// ui_cluster.go: how `cloop ui` takes its place in the control plane at its
// working directory (Task 20354) — as one member of the cluster serving it, or
// alone when ui.cluster.exclusive asks for the pre-cluster guarantee.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/exposure"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// envClusterAdvertiseURL sets the advertise URL per process, which is what a
// Kubernetes Deployment needs: every Pod has its own IP and the same config.
const envClusterAdvertiseURL = "CLOOP_CLUSTER_ADVERTISE_URL"

// envClusterAdvertiseHost names only the host, for a deployment that knows
// each process's address but cannot spell it into a URL: a Pod IP from the
// downward API may be IPv6, and "http://$(POD_IP):8080" is then no URL at
// all. The scheme and port are this process's own.
const envClusterAdvertiseHost = "CLOOP_CLUSTER_ADVERTISE_HOST"

// joinHubCluster makes this process a member of the cluster serving workdir's
// control plane. listen is where this process will serve (Task 20393): its
// display address, and where on this machine the others reach it by default.
// roots are the fingerprints of the root keys it holds, which its member row
// advertises (Task 20425).
func joinHubCluster(workdir string, cfg *config.Config, listen exposure.Plan, roots map[string]string) (*hubcluster.Node, error) {
	advertise, err := clusterAdvertiseURL(cfg, listen.LocalHost())
	if err != nil {
		return nil, err
	}
	peer, err := clusterPeerOptions(cfg)
	if err != nil {
		return nil, err
	}
	// Where this process keeps per-user Claude homes, so an offboarding can
	// tell a stopped member's tree from the ones it reached (Task 20400), and
	// `cloop hub doctor` finds a denied identity's home left in it (Task 20422).
	endpoints := map[string]string{}
	if root := ui.ClaudeHomesRoot(); root != "" {
		endpoints[offboard.ClaudeHomesEndpoint] = root
	}
	// Which root keys this member holds, by fingerprint: `cloop hub key rotate
	// --retire-previous` retires the old root's keys only once every live
	// member advertises the new one as its current root (Task 20425).
	for name, fp := range roots {
		endpoints[name] = fp
	}
	node, err := hubcluster.Join(hubcluster.Options{
		DBPath:       state.DBPath(workdir),
		Address:      listen.String(),
		AdvertiseURL: advertise,
		Version:      Version(),
		Endpoints:    endpoints,
		Peer:         peer,
		// Ask every peer whether it answers, not only whether it heartbeats
		// (Task 20419): a member that heartbeats while its requests hang has
		// its runs adopted and is no longer forwarded to.
		ProbeInterval: hubcluster.DefaultProbeInterval,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "cluster: "+format+"\n", args...)
		},
	})
	if err != nil {
		return nil, err
	}
	peers := node.Peers()
	for _, p := range peers {
		if p.AdvertiseURL == advertise {
			fmt.Fprintf(os.Stderr, "warning: hub cluster member %s (pid %d on %s) advertises %s too. A request "+
				"forwarded to either member reaches whichever process answers there. Give each process its own "+
				"address (--advertise-url, %s or %s) — unless %s is a predecessor of this process that has not "+
				"timed out yet.\n", p.ID, p.PID, p.Hostname, advertise, envClusterAdvertiseURL, envClusterAdvertiseHost, p.ID)
		}
	}
	if len(peers) == 0 {
		fmt.Printf("Hub cluster: serving as member %s (the only one; advertised at %s)\n", node.ID(), advertise)
	} else {
		fmt.Printf("Hub cluster: joined as member %s beside %d other(s) (advertised at %s)\n",
			node.ID(), len(peers), advertise)
	}
	return node, nil
}

// clusterAdvertiseURL resolves where peers reach this process: the flag, then
// the environment (a URL, then a host), then ui.cluster.advertise_url, then
// this machine's way to the listener on this port — local, which is the bound
// address, or 127.0.0.1 for every interface (exposure.Plan.LocalHost). A hub
// that binds one interface address is not reachable at 127.0.0.1, so the
// default follows the bind rather than assuming loopback (Task 20393).
func clusterAdvertiseURL(cfg *config.Config, local string) (string, error) {
	scheme := "http"
	if uiTLSCert != "" || (cfg != nil && cfg.UI.TLS.CertFile != "") {
		scheme = "https"
	}
	u := strings.TrimSpace(uiAdvertiseURL)
	if u == "" {
		u = strings.TrimSpace(os.Getenv(envClusterAdvertiseURL))
	}
	if u == "" {
		if host := strings.Trim(strings.TrimSpace(os.Getenv(envClusterAdvertiseHost)), "[]"); host != "" {
			u = scheme + "://" + net.JoinHostPort(host, strconv.Itoa(uiPort))
		}
	}
	if u == "" && cfg != nil {
		u = strings.TrimSpace(cfg.UI.Cluster.AdvertiseURL)
	}
	if u == "" {
		if local = strings.Trim(strings.TrimSpace(local), "[]"); local == "" {
			local = exposure.LoopbackHost
		}
		u = scheme + "://" + net.JoinHostPort(local, strconv.Itoa(uiPort))
	}
	if err := config.ValidateAdvertiseURL(u); err != nil {
		return "", fmt.Errorf("hub cluster advertise URL: %w", err)
	}
	return strings.TrimRight(u, "/"), nil
}

// clusterPeerOptions builds the TLS trust peers are verified with: the system
// roots, this process's own certificate — members of one deployment usually
// share it, and trusting it is what makes a self-signed one work between them —
// and ui.cluster.peer_ca_file.
func clusterPeerOptions(cfg *config.Config) (hubcluster.PeerOptions, error) {
	var opts hubcluster.PeerOptions
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	add := func(path, what string) error {
		path = strings.TrimSpace(path)
		if path == "" {
			return nil
		}
		pem, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("hub cluster: read %s %s: %w", what, path, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("hub cluster: %s %s holds no PEM certificate", what, path)
		}
		return nil
	}
	cert := uiTLSCert
	if cert == "" && cfg != nil {
		cert = cfg.UI.TLS.CertFile
	}
	if err := add(cert, "TLS certificate"); err != nil {
		return opts, err
	}
	if cfg != nil {
		if err := add(cfg.UI.Cluster.PeerCAFile, "ui.cluster.peer_ca_file"); err != nil {
			return opts, err
		}
		opts.ServerName = strings.TrimSpace(cfg.UI.Cluster.PeerServerName)
		if opts.ServerName == "" {
			if ext, err := url.Parse(strings.TrimSpace(cfg.UI.ExternalURL)); err == nil && ext.Hostname() != "" &&
				net.ParseIP(ext.Hostname()) == nil {
				opts.ServerName = ext.Hostname()
			}
		}
	}
	opts.RootCAs = pool
	return opts, nil
}

// acquireExclusiveHub takes the control plane alone (ui.cluster.exclusive):
// the pre-cluster fence, plus a refusal when members are serving without a
// leader at this instant — they would not see this process's lease as theirs.
func acquireExclusiveHub(workdir string, listen exposure.Plan) (*hublease.Lease, error) {
	lease, err := hublease.Acquire(hublease.Options{
		DBPath:  state.DBPath(workdir),
		Address: listen.String(),
		Version: Version(),
	})
	if err != nil {
		return nil, err
	}
	live, err := hubcluster.LiveMemberRows(state.DBPath(workdir), time.Now())
	if err != nil {
		_ = lease.Release()
		return nil, err
	}
	if len(live) > 0 {
		_ = lease.Release()
		return nil, fmt.Errorf("ui.cluster.exclusive is set, but %d hub process(es) are serving this "+
			"control plane (first: %s on %s, advertised at %s) — stop them, or remove "+
			"ui.cluster.exclusive to join them", len(live), live[0].InstanceID, live[0].Hostname,
			live[0].AdvertiseURL)
	}
	return lease, nil
}

// announceRoots says where the hub's roots come from, and returns what the
// member row advertises: rootkey.EndpointCurrent, the name of the root new
// sealing keys come from — the root key's fingerprint, or the KMS's name
// (Task 20433) — and EndpointPrevious during a change of root. Never a key.
func announceRoots(keys rootkey.Roots, roots kms.Roots) map[string]string {
	out := map[string]string{}
	current, previous := "", ""
	if !roots.Current.IsZero() {
		name, err := secretbroker.RootName(roots.Current)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: name the root key: %v\n", err)
			return out
		}
		current = name
		if roots.Current.IsKMS() {
			fmt.Printf("Sealing keys: held by the KMS %s\n", current)
		} else {
			fmt.Printf("Root key: %s, from %s\n", current, keys.Current.Describe())
		}
	}
	if !roots.Previous.IsZero() {
		name, err := secretbroker.RootName(roots.Previous)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: name the previous root: %v\n", err)
		} else {
			previous = name
			from := "the KMS of secrets.kms_previous"
			switch {
			case roots.Previous.IsKMS():
			case roots.Current.IsKMS():
				from = keys.Current.Describe() + ", named by secrets.previous_root"
			default:
				from = keys.Previous.Describe()
			}
			fmt.Printf("Previous root: %s, from %s — a change of root is in progress; finish it with "+
				"`cloop hub key rotate --retire-previous` once every member runs on %s\n", previous, from, current)
		}
	}
	if current != "" {
		out[rootkey.EndpointCurrent] = current
	}
	if previous != "" {
		out[rootkey.EndpointPrevious] = previous
	}
	return out
}

// scrubRetiredKeys destroys the KMS ciphertext retired sealing keys still
// carry before the hub serves (ui.ScrubRetiredKMSKeys): a build from before
// Task 20433 leaves it behind when it retires a KMS-held key. Whatever roots
// this member has — the key may have been retired part-way through a move off
// the KMS.
func scrubRetiredKeys(workdir string) {
	dbPath := state.DBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return // the hub's own open reports it, with more context
	}
	defer db.Close()
	ui.ScrubRetiredKMSKeys(db, "ui")
}

// checkHubRoots applies the rule a hub starts by (Task 20425), before it joins
// the cluster or serves anything: every live sealing key in the control plane
// opens with a root this process holds — derives from its root key, or unwraps
// through its KMS (Task 20433). A member started with a mistyped key — or with
// only the old root after `cloop hub key rotate --retire-previous` retired it,
// or with a KMS it cannot reach or that refuses it — stops here, naming the
// keys and why, instead of serving a dashboard on which every secret, session
// and hub CA key fails.
//
// Read-only: it mints nothing and attributes nothing, so a refused start leaves
// the control plane as it found it. A hub with no root at all is the
// documented degraded mode and is not refused; one with no database yet has no
// registry to check.
func checkHubRoots(workdir string, roots kms.Roots) error {
	if roots.Current.IsZero() {
		return nil
	}
	dbPath := state.DBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil // the hub's own open reports it, with more context
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		return nil
	}
	kr, err := secretbroker.OpenKeyring(store, secretbroker.WithoutKeyCreation(),
		secretbroker.WithKeyringRootSet(roots.Current, roots.Previous))
	if err != nil {
		return fmt.Errorf("the hub's roots: %w", err)
	}
	bad := kr.Underivable()
	if len(bad) == 0 {
		return nil
	}
	reasons := kr.UnderivableReasons()
	named := make([]string, 0, len(bad))
	sentinel := secretbroker.ErrKeyUnavailable
	for _, id := range bad {
		named = append(named, id+" "+reasons[id])
		if errors.Is(kr.UnderivableErr(id), secretbroker.ErrKMSUnavailable) {
			sentinel = secretbroker.ErrKMSUnavailable
		}
	}
	return fmt.Errorf("%w: the sealing key(s) %s open with no root this hub holds (%s). It is the wrong key, "+
		"this member was not given the root a change of root moved everything onto, or its KMS cannot be "+
		"reached or refuses it: start it with the roots every other member runs on (`cloop hub key list` names "+
		"the keys each root opens; `cloop hub doctor` reports the KMS under secrets.kms)",
		sentinel, strings.Join(named, "; "), strings.Join(kr.RootLabels(), ", "))
}
