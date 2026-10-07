package hubdoctor

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// procLine renders one /proc/net/tcp row the way the kernel writes it: each
// 32-bit word of the network-order address printed as a native-endian integer.
func procLine(addr netip.AddrPort, state string) string {
	raw := addr.Addr().AsSlice()
	var b strings.Builder
	for w := 0; w < len(raw); w += 4 {
		fmt.Fprintf(&b, "%08X", binary.NativeEndian.Uint32(raw[w:w+4]))
	}
	return fmt.Sprintf("   0: %s:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000     0        0 4242 1",
		b.String(), addr.Port(), state)
}

// TestParseProcNetTCPReadsTheKernelsTable: listening sockets on the port, in
// both tables' encodings, and nothing else — not another port, not an
// established connection on the right one.
func TestParseProcNetTCPReadsTheKernelsTable(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	v4 := strings.Join([]string{header,
		procLine(netip.MustParseAddrPort("127.0.0.1:8080"), tcpListen),
		procLine(netip.MustParseAddrPort("0.0.0.0:8080"), tcpListen),
		procLine(netip.MustParseAddrPort("203.0.113.9:8080"), tcpListen),
		procLine(netip.MustParseAddrPort("0.0.0.0:9090"), tcpListen), // another port
		procLine(netip.MustParseAddrPort("127.0.0.1:8080"), "01"),    // ESTABLISHED
		"   9: garbage that is not a row",
	}, "\n")
	got := parseProcNetTCP([]byte(v4), 8080)
	want := []string{"127.0.0.1:8080", "0.0.0.0:8080", "203.0.113.9:8080"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("socket %d = %v, want %s", i, got[i], want[i])
		}
	}

	v6 := strings.Join([]string{header,
		procLine(netip.MustParseAddrPort("[::]:8081"), tcpListen),
		procLine(netip.MustParseAddrPort("[::1]:8081"), tcpListen),
		procLine(netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), 8081), tcpListen),
	}, "\n")
	got = parseProcNetTCP([]byte(v6), 8081)
	if len(got) != 3 || !got[0].Addr().IsUnspecified() || !got[1].Addr().IsLoopback() ||
		got[2].Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("parsed %v from tcp6, want [::]:8081, [::1]:8081 and the mapped 127.0.0.1:8081", got)
	}
	// What the kernel prints for 127.0.0.1 on this machine, literally: a
	// fixture made by the same encoder as the parser would prove nothing
	// about the byte order.
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 { // little-endian
		if ip, ok := decodeProcAddr("0100007F"); !ok || ip.String() != "127.0.0.1" {
			t.Errorf("decodeProcAddr(0100007F) = %v, %v; want 127.0.0.1", ip, ok)
		}
	}
	if _, ok := decodeProcAddr(hex.EncodeToString([]byte{1, 2, 3})); ok {
		t.Error("a 3-byte address decoded")
	}
}

// exposureHub is an httptest server standing in for a hub on 127.0.0.1, and
// the Options that make the doctor see it listening on wildcard (or on
// whatever socks says) at its port.
func exposureHub(t *testing.T, status int, body string) (port int, opts Options) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != exposureProbePath || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("probe sent %s %s with credentials %q %q", r.Method, r.URL.Path,
				r.Header.Get("Authorization"), r.Header.Get("Cookie"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	port = srv.Listener.Addr().(*net.TCPAddr).Port
	return port, Options{Port: port, Listeners: func(p int) ([]netip.AddrPort, error) {
		if p != port {
			return nil, nil
		}
		return []netip.AddrPort{netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(p))}, nil
	}}
}

// exposureFinding runs the check alone and returns its one finding.
func exposureFinding(t *testing.T, cfg *config.Config, opts Options) Finding {
	t.Helper()
	var got []Finding
	checkExposure(context.Background(), t.TempDir(), cfg, opts, func(f Finding) { got = append(got, f) })
	if len(got) != 1 || got[0].Check != "ui.exposure" {
		t.Fatalf("checkExposure produced %+v, want one ui.exposure finding", got)
	}
	if got[0].Severity != SeverityPass && strings.TrimSpace(got[0].Remediation) == "" {
		t.Errorf("a %s finding without a remediation: %s", got[0].Severity, got[0].Message)
	}
	return got[0]
}

// TestExposureFailsAnOpenHubOnTheNetwork is the live :8080 case: whatever the
// configuration predicts, a process on the port that listens on every
// interface and hands out the project list without credentials fails — and
// the finding says this build would not have done it.
func TestExposureFailsAnOpenHubOnTheNetwork(t *testing.T) {
	t.Setenv(envUIToken, "")
	_, opts := exposureHub(t, http.StatusOK, `[{"name":"p"}]`)
	f := exposureFinding(t, config.Default(), opts)
	if f.Severity != SeverityFail {
		t.Fatalf("severity %s, want fail: %s", f.Severity, f.Message)
	}
	for _, want := range []string{"without sign-in", "*:", "answered 200 without credentials",
		"this build would listen on 127.0.0.1", "older build"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message does not say %q: %s", want, f.Message)
		}
	}
	if !strings.Contains(f.Remediation, "tcp/") {
		t.Errorf("remediation does not name the port to firewall: %s", f.Remediation)
	}
}

// TestExposureWarnsOfPlaintextBehindHTTPS is the live :8081 case: SSO, a 401
// to the probe, plaintext on every interface, and an https public URL — here
// the SSO callback, since that hub sets no ui.external_url.
func TestExposureWarnsOfPlaintextBehindHTTPS(t *testing.T) {
	t.Setenv(envUIToken, "")
	_, opts := exposureHub(t, http.StatusUnauthorized, `{"error":"authentication required"}`)
	cfg := config.Default()
	cfg.UI.OIDC.Enabled = true
	cfg.UI.OIDC.RedirectURL = "https://hub.example.com:8888/auth/oidc"

	f := exposureFinding(t, cfg, opts)
	if f.Severity != SeverityWarn {
		t.Fatalf("severity %s, want warn: %s", f.Severity, f.Message)
	}
	for _, want := range []string{"requires sign-in", "answered 401", "plaintext on *:",
		"ui.oidc.redirect_url is https://hub.example.com:8888/auth/oidc"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message does not say %q: %s", want, f.Message)
		}
	}
	if !strings.Contains(f.Remediation, "ui.listen: 127.0.0.1") {
		t.Errorf("remediation = %q", f.Remediation)
	}

	// ui.external_url outranks the callback, and is named when it is set.
	cfg.UI.ExternalURL = "https://cloop.example.com"
	if f := exposureFinding(t, cfg, opts); f.Severity != SeverityWarn ||
		!strings.Contains(f.Message, "ui.external_url is https://cloop.example.com") {
		t.Errorf("with an external URL: %s %s", f.Severity, f.Message)
	}

	// No public URL at all: nothing says TLS terminates in front, so there is
	// no terminator to bypass — signed-in and every interface passes.
	plain := config.Default()
	plain.UI.OIDC.Enabled = true
	if f := exposureFinding(t, plain, opts); f.Severity != SeverityPass ||
		!strings.Contains(f.Message, "requires sign-in on *:") {
		t.Errorf("without a public URL: %s %s", f.Severity, f.Message)
	}
}

// TestExposureJudgesTheProcessWhenTheConfigurationDoesNotParse: a ui.listen
// this build refuses leaves no plan to predict with, but the process on the
// port is still judged — open, the finding says this build would not have
// started; signed in behind an https URL, the plaintext warning still holds.
func TestExposureJudgesTheProcessWhenTheConfigurationDoesNotParse(t *testing.T) {
	t.Setenv(envUIToken, "")
	_, open := exposureHub(t, http.StatusOK, `[]`)
	cfg := config.Default()
	cfg.UI.Listen = "0.0.0.0"
	if f := exposureFinding(t, cfg, open); f.Severity != SeverityFail ||
		!strings.Contains(f.Message, "this build would refuse to start") {
		t.Errorf("open hub, refused configuration: %s %s", f.Severity, f.Message)
	}

	_, signedIn := exposureHub(t, http.StatusUnauthorized, `{}`)
	cfg = config.Default()
	cfg.UI.Listen = "0.0.0.0:8080" // malformed: a port
	cfg.UI.OIDC.Enabled = true
	cfg.UI.ExternalURL = "https://cloop.example.com"
	if f := exposureFinding(t, cfg, signedIn); f.Severity != SeverityWarn ||
		!strings.Contains(f.Message, "ui.external_url is https://cloop.example.com") {
		t.Errorf("signed-in hub, malformed configuration: %s %s", f.Severity, f.Message)
	}
}

// TestExposurePassesLoopbackWithoutAsking: a hub on loopback only reaches
// nobody beyond this machine, open or not, so the probe is not needed — and
// it is not sent.
func TestExposurePassesLoopbackWithoutAsking(t *testing.T) {
	t.Setenv(envUIToken, "")
	asked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { asked = true }))
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	opts := Options{Port: port, Listeners: func(int) ([]netip.AddrPort, error) {
		return []netip.AddrPort{netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)),
			netip.MustParseAddrPort(fmt.Sprintf("[::1]:%d", port))}, nil
	}}
	f := exposureFinding(t, config.Default(), opts)
	if f.Severity != SeverityPass || !strings.Contains(f.Message, "only, so nothing beyond this machine") ||
		!strings.Contains(f.Message, "no sign-in") {
		t.Errorf("%s: %s", f.Severity, f.Message)
	}
	if asked {
		t.Error("the probe asked a loopback-only hub")
	}
}

// TestExposureFallsBackOnTheConfigurationWhenTheHubDoesNotSay: --offline (no
// probe) and a TLS listener (a plaintext probe cannot read its answer) both
// leave sign-in to the configuration, and the message says that is where it
// came from.
func TestExposureFallsBackOnTheConfigurationWhenTheHubDoesNotSay(t *testing.T) {
	t.Setenv(envUIToken, "")
	_, opts := exposureHub(t, http.StatusOK, `[]`)
	opts.Offline = true
	f := exposureFinding(t, config.Default(), opts)
	if f.Severity != SeverityFail || !strings.Contains(f.Message, "by its configuration") {
		t.Errorf("offline, open by configuration: %s %s", f.Severity, f.Message)
	}

	// A token in the doctor's environment is the hub's token: --offline with
	// it set is a hub with sign-in.
	t.Setenv(envUIToken, "tok")
	if f := exposureFinding(t, config.Default(), opts); f.Severity != SeverityPass ||
		!strings.Contains(f.Message, "CLOOP_UI_TOKEN set") {
		t.Errorf("offline, token in the environment: %s %s", f.Severity, f.Message)
	}

	t.Setenv(envUIToken, "")
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(tlsSrv.Close)
	port := tlsSrv.Listener.Addr().(*net.TCPAddr).Port
	tlsOpts := Options{Port: port, Listeners: func(int) ([]netip.AddrPort, error) {
		return []netip.AddrPort{netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port))}, nil
	}}
	cfg := config.Default()
	cfg.UI.OIDC.Enabled = true
	cfg.UI.ExternalURL = "https://cloop.example.com"
	f = exposureFinding(t, cfg, tlsOpts)
	if f.Severity != SeverityPass || !strings.Contains(f.Details["probe"].(string), "speaks TLS") {
		t.Errorf("TLS listener with SSO: %s %s %v", f.Severity, f.Message, f.Details)
	}
}

// TestExposurePredictsAStoppedHub: with nothing on the port, the check says
// what `cloop ui --port N` would do with this configuration — the decision
// pkg/exposure makes at startup, not a restatement of it.
func TestExposurePredictsAStoppedHub(t *testing.T) {
	t.Setenv(envUIToken, "")
	none := Options{Port: 18093, Listeners: func(int) ([]netip.AddrPort, error) { return nil, nil }}
	cases := []struct {
		name     string
		mutate   func(*config.Config)
		opts     Options
		severity Severity
		contains []string
	}{
		{name: "open default", opts: none, severity: SeverityPass,
			contains: []string{"nothing listens on :18093", "would listen on 127.0.0.1:18093 only"}},
		{name: "open, every interface, unacknowledged", opts: none, severity: SeverityFail,
			mutate:   func(c *config.Config) { c.UI.Listen = "0.0.0.0" },
			contains: []string{"would refuse to start", "*:18093", "no sign-in"}},
		{name: "open, every interface, acknowledged", opts: none, severity: SeverityFail,
			mutate: func(c *config.Config) {
				c.UI.Listen, c.UI.AllowUnauthenticatedNetwork = "0.0.0.0", true
			},
			contains: []string{"would serve without sign-in on *:18093", "ui.allow_unauthenticated_network"}},
		{name: "malformed listen", opts: none, severity: SeverityFail,
			mutate:   func(c *config.Config) { c.UI.Listen = "0.0.0.0:8080" },
			contains: []string{"would refuse to start", "without a :port"}},
		{name: "SSO behind an https proxy", opts: none, severity: SeverityWarn,
			mutate: func(c *config.Config) {
				c.UI.OIDC.Enabled, c.UI.ExternalURL = true, "https://cloop.example.com"
			},
			contains: []string{"would serve plaintext on *:18093", "ui.external_url is https://cloop.example.com"}},
		{name: "SSO behind an https proxy, loopback", opts: none, severity: SeverityPass,
			mutate: func(c *config.Config) {
				c.UI.OIDC.Enabled, c.UI.ExternalURL, c.UI.Listen = true, "https://cloop.example.com", "127.0.0.1"
			},
			contains: []string{"would listen on 127.0.0.1:18093 behind sign-in"}},
		{name: "no port: the configuration alone", opts: Options{}, severity: SeverityFail,
			mutate:   func(c *config.Config) { c.UI.Listen = "192.0.2.4" },
			contains: []string{"with this configuration, `cloop ui` would refuse to start"}},
		{name: "unreadable socket table", severity: SeverityPass,
			opts: Options{Port: 18093, Listeners: func(int) ([]netip.AddrPort, error) {
				return nil, errListenersUnavailable
			}},
			contains: []string{"could not be read", "would listen on 127.0.0.1:18093 only"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			if tc.mutate != nil {
				tc.mutate(cfg)
			}
			f := exposureFinding(t, cfg, tc.opts)
			if f.Severity != tc.severity {
				t.Errorf("severity %s, want %s: %s", f.Severity, tc.severity, f.Message)
			}
			for _, want := range tc.contains {
				if !strings.Contains(f.Message, want) {
					t.Errorf("message does not say %q: %s", want, f.Message)
				}
			}
		})
	}
}

// TestExposureNamesTheOverlayToEdit: the file an operator edits for the hub
// on a port is its instance overlay when it has one.
func TestExposureNamesTheOverlayToEdit(t *testing.T) {
	dir := t.TempDir()
	if got := configFileFor(dir, 8081); got != ".cloop/config.yaml" {
		t.Errorf("without an overlay: %s", got)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.UIInstanceConfigPath(dir, 8081), []byte("ui: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := configFileFor(dir, 8081); got != ".cloop/config.ui-8081.yaml" {
		t.Errorf("with an overlay: %s", got)
	}
	if got := configFileFor(dir, 0); got != ".cloop/config.yaml" {
		t.Errorf("without a port: %s", got)
	}
}

// TestProbeHubIsNotAHubWhenTheAnswerIsNot: a 404, a redirect or an HTML page
// is not the answer of a hub, so it decides nothing about sign-in.
func TestProbeHubIsNotAHubWhenTheAnswerIsNot(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusFound, http.StatusTooManyRequests} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(status)
		}))
		sock := netip.MustParseAddrPort(srv.Listener.Addr().String())
		if res := probeHub(context.Background(), Options{}, sock); res.Kind != probeUnknown {
			t.Errorf("a %d answer was read as %v", status, res.Kind)
		}
		srv.Close()
	}
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>"))
	}))
	defer html.Close()
	if res := probeHub(context.Background(), Options{}, netip.MustParseAddrPort(html.Listener.Addr().String())); res.Kind != probeUnknown {
		t.Errorf("an HTML 200 was read as %v", res.Kind)
	}
	refused := probeHub(context.Background(), Options{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}, netip.MustParseAddrPort("127.0.0.1:1"))
	if refused.Kind != probeUnknown || refused.Err == nil {
		t.Errorf("a refused dial: %+v", refused)
	}
}
