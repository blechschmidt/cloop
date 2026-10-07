package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestClusterAdvertiseURL pins where a hub process tells the other members of
// its cluster to reach it (Task 20354): per-process sources first, because the
// config file is shared by every member and cannot name one of them.
func TestClusterAdvertiseURL(t *testing.T) {
	prevPort, prevURL, prevCert := uiPort, uiAdvertiseURL, uiTLSCert
	t.Cleanup(func() { uiPort, uiAdvertiseURL, uiTLSCert = prevPort, prevURL, prevCert })
	uiPort = 8080

	withConfig := func(u string) *config.Config {
		cfg := &config.Config{}
		cfg.UI.Cluster.AdvertiseURL = u
		return cfg
	}
	cases := []struct {
		name, flag, envURL, envHost, cert string
		// local is where this machine reaches the listener
		// (exposure.Plan.LocalHost); empty reads as loopback.
		local   string
		cfg     *config.Config
		want    string
		wantErr bool
	}{
		{name: "loopback on this port by default", want: "http://127.0.0.1:8080"},
		{name: "loopback for a hub on every interface", local: "127.0.0.1", want: "http://127.0.0.1:8080"},
		// Task 20393: a hub bound to one interface is not listening on
		// 127.0.0.1, so its peers on this machine are sent to the bind.
		{name: "the bound address when the hub binds one", local: "10.0.0.5", want: "http://10.0.0.5:8080"},
		{name: "a bound IPv6 address is bracketed", local: "::1", cert: "/c", want: "https://[::1]:8080"},
		{name: "a configured URL beats the bound address", local: "10.0.0.5",
			cfg: withConfig("http://10.0.0.9:8080"), want: "http://10.0.0.9:8080"},
		{name: "https when serving TLS", cert: "/etc/cloop/tls.crt", want: "https://127.0.0.1:8080"},
		{name: "config", cfg: withConfig("http://10.0.0.9:8080/"), want: "http://10.0.0.9:8080"},
		{name: "a host beats the config", envHost: "10.1.2.3", cfg: withConfig("http://10.0.0.9:8080"),
			want: "http://10.1.2.3:8080"},
		// The case the host variable exists for: a Pod IP from the downward
		// API, which cannot be pasted into a URL unbracketed.
		{name: "an IPv6 host is bracketed", envHost: "fd00:10:244::17", want: "http://[fd00:10:244::17]:8080"},
		{name: "an already bracketed host is not doubled", envHost: "[fd00::1]", cert: "/c",
			want: "https://[fd00::1]:8080"},
		{name: "a URL beats a host", envURL: "https://hub-0.internal:9443", envHost: "10.1.2.3",
			want: "https://hub-0.internal:9443"},
		{name: "the flag beats everything", flag: "http://192.0.2.1:8080", envURL: "http://198.51.100.1:8080",
			envHost: "10.1.2.3", cfg: withConfig("http://10.0.0.9:8080"), want: "http://192.0.2.1:8080"},
		{name: "a path is refused", envURL: "http://10.0.0.1:8080/hub", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uiAdvertiseURL, uiTLSCert = tc.flag, tc.cert
			t.Setenv(envClusterAdvertiseURL, tc.envURL)
			t.Setenv(envClusterAdvertiseHost, tc.envHost)
			got, err := clusterAdvertiseURL(tc.cfg, tc.local)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("clusterAdvertiseURL = %q, want an error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("clusterAdvertiseURL = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestHubClusterStatusJSON pins what `cloop hub cluster status --json` prints:
// the field names GET /api/cluster uses, liveness judged the way members judge
// each other, and the leader from the lease.
func TestHubClusterStatusJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".cloop", "state.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	statedbtest.Seed(t, path)
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, r := range []statedb.HubMemberRow{
		{InstanceID: "hub_serving", Hostname: "node-a", PID: 7, BootID: "b", Address: ":8080",
			AdvertiseURL: "http://10.0.0.7:8080", Version: "v1", HeartbeatAt: now},
		{InstanceID: "hub_silent", Hostname: "node-b", PID: 8, BootID: "b", HeartbeatAt: now.Add(-time.Hour)},
	} {
		if err := db.JoinHubMember(r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hublease.Acquire(hublease.Options{
		Store: db, InstanceID: "hub_serving",
		Identity: hublease.Identity{Hostname: "node-a", PID: 7, BootID: "b"},
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	out, err := captureStdout(t, func() error { return printHubClusterStatus(path, true) })
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var got struct {
		Leader  string `json:"leader"`
		Members []struct {
			ID           string `json:"id"`
			AdvertiseURL string `json:"advertise_url"`
			Alive        bool   `json:"alive"`
			Leader       bool   `json:"leader"`
		} `json:"members"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.Leader != "hub_serving" || len(got.Members) != 2 {
		t.Fatalf("status = %+v", got)
	}
	for _, m := range got.Members {
		switch m.ID {
		case "hub_serving":
			if !m.Alive || !m.Leader || m.AdvertiseURL != "http://10.0.0.7:8080" {
				t.Fatalf("serving member = %+v", m)
			}
		case "hub_silent":
			if m.Alive || m.Leader {
				t.Fatalf("a member silent for an hour = %+v", m)
			}
		default:
			t.Fatalf("unexpected member %q", m.ID)
		}
	}
}
