package cmd

// ui_cluster.go: how `cloop ui` takes its place in the control plane at its
// working directory (Task 20354) — as one member of the cluster serving it, or
// alone when ui.cluster.exclusive asks for the pre-cluster guarantee.

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/state"
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
// control plane.
func joinHubCluster(workdir string, cfg *config.Config) (*hubcluster.Node, error) {
	advertise, err := clusterAdvertiseURL(cfg)
	if err != nil {
		return nil, err
	}
	peer, err := clusterPeerOptions(cfg)
	if err != nil {
		return nil, err
	}
	node, err := hubcluster.Join(hubcluster.Options{
		DBPath:       state.DBPath(workdir),
		Address:      ":" + strconv.Itoa(uiPort),
		AdvertiseURL: advertise,
		Version:      Version(),
		Peer:         peer,
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
// loopback on this port.
func clusterAdvertiseURL(cfg *config.Config) (string, error) {
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
		u = scheme + "://127.0.0.1:" + strconv.Itoa(uiPort)
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
func acquireExclusiveHub(workdir string) (*hublease.Lease, error) {
	lease, err := hublease.Acquire(hublease.Options{
		DBPath:  state.DBPath(workdir),
		Address: ":" + strconv.Itoa(uiPort),
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
