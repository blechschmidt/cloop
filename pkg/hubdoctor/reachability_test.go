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
		{"http default port", "http://hub.internal", "hub.internal:80"},
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
func TestUndialableAdvertiseURLIsReportedAsConfig(t *testing.T) {
	var seen []string
	got := findingsFor(t, t.TempDir(), gitProxyCfg("hub.internal:8443"), Options{
		DialContext: fakeDial(&seen, nil),
	})
	f := only(t, got, "gitproxy.advertise_reachable")
	if f.Severity != SeverityWarn {
		t.Errorf("severity = %q, want warn", f.Severity)
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
