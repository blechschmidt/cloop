package hubdoctor

// The probes exist because a sandbox-facing address is the one config value a
// hub cannot be wrong about loudly: it is never dialled by the code that reads
// it. These tests pin the three things that make the probe trustworthy rather
// than merely present — that it dials the address a sandbox would dial, that
// every inconclusive outcome degrades to a warning, and that --offline is
// reported rather than silently skipped.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fakeDial returns a dialer that records what it was asked to reach and
// answers with err. A nil err yields a usable connection.
func fakeDial(seen *[]string, err error) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _, addr string) (net.Conn, error) {
		*seen = append(*seen, addr)
		if err != nil {
			return nil, err
		}
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
}

// refused is the error a kernel returns when the packet arrived and nothing
// was listening — the one failure that proves the address routes.
var refused = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}

// unresolved is what a Kubernetes Service name does on the hub, which is the
// case the probe must not treat as a defect.
var unresolved = &net.DNSError{Err: "no such host", Name: "cloop-gitproxy.cloop.svc", IsNotFound: true}

func gitProxyCfg(advertiseURL string) *config.Config {
	cfg := &config.Config{}
	cfg.Executors.Kubernetes.Enabled = true
	cfg.Executors.GitProxy.Enabled = true
	cfg.Executors.GitProxy.AdvertiseURL = advertiseURL
	return cfg
}

func TestGitProxyProbeDialsWhatASandboxWouldDial(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"explicit port", "https://hub.internal:8443", "hub.internal:8443"},
		{"https default port", "https://hub.internal", "hub.internal:443"},
		{"ipv6 literal", "https://[2001:db8::1]:8443", "[2001:db8::1]:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			findingsFor(t, t.TempDir(), gitProxyCfg(tc.url), Options{
				DialContext: fakeDial(&seen, nil),
			})
			if len(seen) != 1 || seen[0] != tc.want {
				t.Errorf("dialed %v, want exactly [%s]", seen, tc.want)
			}
		})
	}
}

// TestGitProxyAdvertiseURLTheRegistryRefusesFails: the base sandboxes are
// pointed at is what gitproxy.NormalizeBaseURL accepts, because that is what
// the registry the proxy starts with applies. A value it refuses means no
// proxy — reported as that, not dialled as if it would be served (Task 20387).
func TestGitProxyAdvertiseURLTheRegistryRefusesFails(t *testing.T) {
	cert, key := gitProxyTLS(t)
	for _, adv := range []string{"http://hub.internal", "https://:8443", "https://hub.internal/git"} {
		t.Run(adv, func(t *testing.T) {
			var seen []string
			cfg := gitProxyCfg(adv)
			cfg.Executors.GitProxy.CertFile, cfg.Executors.GitProxy.KeyFile = cert, key
			got := findingsFor(t, t.TempDir(), cfg, Options{DialContext: fakeDial(&seen, nil)})
			f := only(t, got, "gitproxy.advertise_url")
			wantSeverity(t, f, SeverityFail)
			if !strings.Contains(f.Message, "will not start") {
				t.Errorf("want the startup consequence, got %q", f.Message)
			}
			if len(seen) != 0 {
				t.Errorf("dialled %v, an address no sandbox is given", seen)
			}
			if fs := got["gitproxy.enabled"]; len(fs) != 0 {
				t.Errorf("a proxy that will not start was also passed: %+v", fs)
			}
		})
	}
}

func TestGitProxyProbeSeveritiesNeverFail(t *testing.T) {
	cases := []struct {
		name     string
		dialErr  error
		want     Severity
		contains string
	}{
		{"listening", nil, SeverityPass, "answers at"},
		{"refused", refused, SeverityWarn, "nothing is listening"},
		{"does not resolve", unresolved, SeverityWarn, "correct when the address is meant to resolve"},
		{"timed out", context.DeadlineExceeded, SeverityWarn, "could not be reached"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			got := findingsFor(t, t.TempDir(), gitProxyCfg("https://hub.internal:8443"), Options{
				DialContext: fakeDial(&seen, tc.dialErr),
			})
			f := only(t, got, "gitproxy.advertise_reachable")
			if f.Severity != tc.want {
				t.Errorf("severity = %q, want %q (message: %s)", f.Severity, tc.want, f.Message)
			}
			if !strings.Contains(f.Message, tc.contains) {
				t.Errorf("message %q does not contain %q", f.Message, tc.contains)
			}
		})
	}
}

// A loopback URL is the case where the two gitproxy checks must disagree:
// unreachable-for-a-sandbox by inspection, perfectly dialable from the hub.
// Collapsing them would lose exactly the finding an operator needs.
func TestLoopbackAdvertiseURLWarnsEvenWhenItAnswers(t *testing.T) {
	var seen []string
	got := findingsFor(t, t.TempDir(), gitProxyCfg("https://127.0.0.1:8443"), Options{
		DialContext: fakeDial(&seen, nil),
	})
	if f := only(t, got, "gitproxy.advertise_url"); f.Severity != SeverityWarn {
		t.Errorf("loopback advertise_url severity = %q, want warn", f.Severity)
	}
	if f := only(t, got, "gitproxy.advertise_reachable"); f.Severity != SeverityPass {
		t.Errorf("reachability of a listening loopback = %q, want pass", f.Severity)
	}
}

func TestOfflineReportsTheProbeWasSkippedRatherThanPassing(t *testing.T) {
	var seen []string
	got := findingsFor(t, t.TempDir(), gitProxyCfg("https://hub.internal:8443"), Options{
		Offline:     true,
		DialContext: fakeDial(&seen, nil),
	})
	f := only(t, got, "gitproxy.advertise_reachable")
	if f.Severity != SeverityWarn {
		t.Errorf("severity = %q, want warn — absence is not a pass", f.Severity)
	}
	if !strings.Contains(f.Message, "--offline") {
		t.Errorf("message does not say why it was skipped: %s", f.Message)
	}
	if len(seen) != 0 {
		t.Errorf("--offline dialed %v", seen)
	}
}

// An advertise_url that cannot be turned into an address is a config error,
// not a network one, and must not be reported as unreachable.
// TestUndialableAdvertiseURLIsReportedAsConfig: a scheme-less advertise_url
// is not a base gitproxy.NormalizeBaseURL accepts, so the proxy would not
// start — reported as that, and never dialled.
func TestUndialableAdvertiseURLIsReportedAsConfig(t *testing.T) {
	var seen []string
	got := findingsFor(t, t.TempDir(), gitProxyCfg("hub.internal:8443"), Options{
		DialContext: fakeDial(&seen, nil),
	})
	wantSeverity(t, only(t, got, "gitproxy.advertise_url"), SeverityFail)
	if len(got["gitproxy.advertise_reachable"]) != 0 {
		t.Errorf("probed a base the hub would refuse: %+v", got["gitproxy.advertise_reachable"])
	}
	if len(seen) != 0 {
		t.Errorf("dialed %v for an unparseable URL", seen)
	}
}

func egressCfg(advertiseAddr string) *config.Config {
	cfg := &config.Config{}
	cfg.Executors.Egress.Enabled = true
	cfg.Executors.Egress.AdvertiseAddr = advertiseAddr
	return cfg
}

func TestEgressBrokerProbe(t *testing.T) {
	t.Run("dials the advertised address", func(t *testing.T) {
		var seen []string
		got := findingsFor(t, t.TempDir(), egressCfg("10.7.0.2:8118"), Options{
			DialContext: fakeDial(&seen, nil),
		})
		if len(seen) != 1 || seen[0] != "10.7.0.2:8118" {
			t.Errorf("dialed %v, want [10.7.0.2:8118]", seen)
		}
		if f := only(t, got, "egress.advertise_reachable"); f.Severity != SeverityPass {
			t.Errorf("severity = %q, want pass", f.Severity)
		}
	})

	t.Run("a bare host is unprobeable, not unreachable", func(t *testing.T) {
		var seen []string
		got := findingsFor(t, t.TempDir(), egressCfg("broker.internal"), Options{
			DialContext: fakeDial(&seen, nil),
		})
		f := only(t, got, "egress.advertise_reachable")
		if f.Severity != SeverityWarn {
			t.Errorf("severity = %q, want warn", f.Severity)
		}
		if len(seen) != 0 {
			t.Errorf("dialed %v for an address with no port", seen)
		}
	})

	t.Run("loopback is flagged only when sandboxes have their own namespace", func(t *testing.T) {
		var seen []string
		strict := egressCfg("127.0.0.1:8118")
		allowHost := false
		strict.Executors.AllowHostProcess = &allowHost

		got := findingsFor(t, t.TempDir(), strict, Options{DialContext: fakeDial(&seen, nil)})
		if f := only(t, got, "egress.advertise_addr"); f.Severity != SeverityWarn {
			t.Errorf("strict-mode loopback severity = %q, want warn", f.Severity)
		}

		permissive := egressCfg("127.0.0.1:8118")
		allowed := true
		permissive.Executors.AllowHostProcess = &allowed
		got = findingsFor(t, t.TempDir(), permissive, Options{DialContext: fakeDial(&seen, nil)})
		if len(got["egress.advertise_addr"]) != 0 {
			t.Errorf("loopback flagged on a hub whose sandboxes share its network namespace: %+v",
				got["egress.advertise_addr"])
		}
	})

	// The combination that produces a sandbox with no way out at all: confined
	// to a network with no route off the host, and no broker to proxy through.
	t.Run("internal filter with no broker is called out", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Executors.Container.Enabled = true
		cfg.Executors.Container.EgressFilter.Enabled = true
		cfg.Executors.Container.EgressFilter.Internal = true

		got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
		f := only(t, got, "egress.enabled")
		if f.Severity != SeverityWarn {
			t.Errorf("severity = %q, want warn", f.Severity)
		}
		if !strings.Contains(f.Message, "no route off the host") {
			t.Errorf("message does not explain the trap: %s", f.Message)
		}
	})

	t.Run("a disabled broker is otherwise unremarkable", func(t *testing.T) {
		got := findingsFor(t, t.TempDir(), &config.Config{}, Options{Offline: true})
		if f := only(t, got, "egress.enabled"); f.Severity != SeverityPass {
			t.Errorf("severity = %q, want pass", f.Severity)
		}
		if len(got["egress.advertise_reachable"]) != 0 {
			t.Error("probed an address for a disabled broker")
		}
	})
}

// The probe must not be able to hang a doctor run. A dialer that never returns
// has to be cut off by the bounded context, not by the test timing out.
func TestProbeIsBounded(t *testing.T) {
	block := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan reachResult, 1)
	go func() {
		done <- probeReach(context.Background(), Options{
			Timeout: 50 * time.Millisecond, DialContext: block,
		}, "hub.internal:8443")
	}()
	select {
	case res := <-done:
		if res.Outcome != reachUnproven {
			t.Errorf("outcome = %v, want unproven", res.Outcome)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probeReach ignored its timeout")
	}
}

// TestEgressRoutesFollowTheHubsRules: how a sandbox reaches the egress proxy
// is decided by executor.ContainerEgressRoute and executor.AdvertisedEgressRoute,
// the functions the hub dispatches with. The doctor used to guess: it passed a
// loopback advertise_addr on a Kubernetes hub that allowed host execution and
// recommended a Service name, both of which the hub refuses for every Pod, and
// warned about an unset advertise_addr on a container hub whose sandboxes do
// not use it (Task 20387).
func TestEgressRoutesFollowTheHubsRules(t *testing.T) {
	allow := true
	cases := []struct {
		name        string
		mutate      func(*config.Config)
		check       string
		want        Severity
		mentions    string
		noAdvertise bool // no egress.advertise_addr finding at all
	}{
		{"pods refuse loopback whatever the host policy", func(c *config.Config) {
			c.Executors.AllowHostProcess = &allow
			c.Executors.Kubernetes.Enabled = true
			c.Executors.Egress.AdvertiseAddr = "127.0.0.1:8899"
		}, "egress.advertise_addr", SeverityFail, "loopback", false},
		{"pods refuse a cluster-internal name", func(c *config.Config) {
			c.Executors.Kubernetes.Enabled = true
			c.Executors.Egress.AdvertiseAddr = "cloop-egress.cloop.svc:8899"
		}, "egress.advertise_addr", SeverityFail, "cluster-internal", false},
		{"pods take an address", func(c *config.Config) {
			c.Executors.Kubernetes.Enabled = true
			c.Executors.Egress.AdvertiseAddr = "10.0.0.7:8899"
		}, "egress.advertise_addr", SeverityPass, "10.0.0.7", false},
		{"containers cannot reach a loopback bind, advertised or not", func(c *config.Config) {
			c.Executors.Container.Enabled = true
			c.Executors.Egress.ListenAddr = "127.0.0.1:8899"
			c.Executors.Egress.AdvertiseAddr = "host.containers.internal:8899"
		}, "egress.listen_addr", SeverityFail, "loopback", false},
		{"containers use the bridge gateway, not advertise_addr", func(c *config.Config) {
			c.Executors.Container.Enabled = true
			c.Executors.Egress.ListenAddr = "0.0.0.0:8899"
		}, "egress.listen_addr", SeverityPass, "gateway", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Executors.Egress.Enabled = true
			tc.mutate(cfg)
			dir := t.TempDir()
			seedEgressGrant(t, dir) // a refusal costs a run only once a grant is in force
			got := findingsFor(t, dir, cfg, Options{Offline: true})
			f := only(t, got, tc.check)
			wantSeverity(t, f, tc.want)
			if !strings.Contains(f.Message, tc.mentions) {
				t.Errorf("message should mention %q: %q", tc.mentions, f.Message)
			}
			if tc.noAdvertise && len(got["egress.advertise_addr"]) != 0 {
				t.Errorf("advertise_addr judged for sandboxes that do not use it: %+v", got["egress.advertise_addr"])
			}
		})
	}
}

// TestEgressProbeDialsTheAddressTheHubAdvertises: a bare host, or a port of
// 0, takes the listener's port (executor.EgressAdvertised), so with an
// explicit listen port there is an address to dial.
func TestEgressProbeDialsTheAddressTheHubAdvertises(t *testing.T) {
	var seen []string
	cfg := egressCfg("broker.internal")
	cfg.Executors.Egress.ListenAddr = "0.0.0.0:8118"
	got := findingsFor(t, t.TempDir(), cfg, Options{DialContext: fakeDial(&seen, nil)})
	if len(seen) != 1 || seen[0] != "broker.internal:8118" {
		t.Errorf("dialled %v, want the advertised host on the listener's port", seen)
	}
	wantSeverity(t, only(t, got, "egress.advertise_reachable"), SeverityPass)
}

// TestEgressAdvertiseTheHubCannotResolveStopsEveryRoute: the hub resolves
// advertise_addr before it serves anything, so one it refuses means no proxy
// for containers too — not a container route reported as fine beside it.
func TestEgressAdvertiseTheHubCannotResolveStopsEveryRoute(t *testing.T) {
	cfg := &config.Config{}
	cfg.Executors.Egress = config.EgressConfig{Enabled: true, ListenAddr: "0.0.0.0:8899", AdvertiseAddr: ":8899"}
	cfg.Executors.Container.Enabled = true
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "egress.advertise_addr")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Message, "will not start") {
		t.Errorf("want the startup consequence, got %q", f.Message)
	}
	if fs := got["egress.listen_addr"]; len(fs) != 0 {
		t.Errorf("a container route was judged for a proxy that never starts: %+v", fs)
	}
}

// seedEgressGrant stores one active egress grant, the way `cloop egress grant`
// does.
func seedEgressGrant(t *testing.T, dir string) {
	t.Helper()
	db, err := statedb.Open(mustInitStateDB(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store, err := secretstore.NewEgressStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutGrant(egressbroker.Grant{ID: "egress_1", Hosts: []string{"pypi.org"}, Ports: []int{443},
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
		CreatedAt: time.Now()}); err != nil {
		t.Fatalf("PutGrant: %v", err)
	}
}

// TestARefusedEgressRouteCostsNothingWithoutAGrant: the hub refuses only the
// runs that name an egress grant, so a refused route with none in force is a
// warning about the first one, not a failure of a hub that runs fine.
func TestARefusedEgressRouteCostsNothingWithoutAGrant(t *testing.T) {
	cfg := &config.Config{}
	cfg.Executors.Egress.Enabled = true
	cfg.Executors.Container.Enabled = true // the default bind is loopback
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "egress.listen_addr")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Message, "no egress grant is active") {
		t.Errorf("want the reason it is only a warning, got %q", f.Message)
	}
}
