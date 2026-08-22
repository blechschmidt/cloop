package agent

// transport_test.go exercises the agent's transport policy against a real TLS
// server rather than a mocked one.
//
// That matters here more than it usually does. The pin check runs inside
// crypto/tls via VerifyPeerCertificate, and the guarantee under test — "a
// pinned agent will not complete a handshake with a server holding a different
// key" — is a property of the handshake, not of a predicate we could call
// directly. A unit test over PinSet.Matches (which pkg/tlsconf has) proves the
// comparison is right; only a real handshake proves it is actually wired into
// the dial.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// tlsHub is a TLS server that accepts a WebSocket and immediately closes it.
// Everything after the upgrade is out of scope here; what is being tested is
// whether the handshake happens at all.
type tlsHub struct {
	server  *httptest.Server
	certPEM string
	pin     string
	wsURL   string
}

// newTLSHub starts an HTTPS server with a freshly generated key pair and
// returns its pin. hosts must include the address the test dials, or hostname
// verification fails before pinning is ever consulted — which would make a
// broken pin check look like a passing test.
func newTLSHub(t *testing.T) *tlsHub {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	pin, err := tlsconf.GenerateSelfSigned(certPath, keyPath, tlsconf.SelfSignedOptions{
		Hosts: []string{"localhost", "127.0.0.1", "::1"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		c.Close(websocket.StatusNormalClosure, "test")
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &tlsHub{
		server:  srv,
		certPEM: certPath,
		pin:     pin,
		wsURL:   "wss" + strings.TrimPrefix(srv.URL, "https") + "/api/executors/connect",
	}
}

// newAgentFor builds an agent pointed at hub. credentialPath lands in a temp
// dir so the developer's real ~/.cloop/agent.json is never read or written.
func newAgentFor(t *testing.T, hub *tlsHub, mutate func(*Config)) (*Agent, error) {
	t.Helper()
	cfg := Config{
		Server:         hub.wsURL,
		Token:          "clet1.aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc",
		CredentialPath: filepath.Join(t.TempDir(), "agent.json"),
		WorkDirRoot:    t.TempDir(),
		RootCAFile:     hub.certPEM,
		Logf:           func(string, ...any) {},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg)
}

// TestDialWithMatchingPinSucceeds is the positive control. Without it, a pin
// check that rejected everything would pass every negative test below.
func TestDialWithMatchingPinSucceeds(t *testing.T) {
	t.Parallel()
	hub := newTLSHub(t)
	a, err := newAgentFor(t, hub, func(c *Config) { c.Pin = hub.pin })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !a.pinned {
		t.Fatal("agent did not record itself as pinned")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := a.dial(ctx, "token")
	if err != nil {
		t.Fatalf("dial with the correct pin failed: %v", err)
	}
	_ = conn.Close("done")
}

// TestDialWithMismatchedPinFails is the case pinning exists for: a server that
// presents a perfectly valid certificate for the right hostname, holding a key
// the device was not told to expect. Ordinary PKI verification accepts that;
// pinning is what does not.
func TestDialWithMismatchedPinFails(t *testing.T) {
	t.Parallel()
	hub := newTLSHub(t)
	other := newTLSHub(t) // a different key, valid for the same hostnames

	a, err := newAgentFor(t, hub, func(c *Config) { c.Pin = other.pin })
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := a.dial(ctx, "token")
	if err == nil {
		_ = conn.Close("unexpected")
		t.Fatal("dial succeeded against a server whose key does not match the pin")
	}
	if !isPinMismatch(err) {
		t.Fatalf("error = %v, want a pin mismatch", err)
	}
	// The operator has to be able to tell "the key changed" from "the network
	// is down", because the responses are opposite: re-pin versus wait.
	msg := err.Error()
	for _, want := range []string{"rotated its certificate", "not your control plane"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message does not mention %q: %s", want, msg)
		}
	}
}

// TestDialAfterKeyRotationFails covers the rotated-cert case end to end: the
// hub is replaced by one on a new key while the device keeps the old pin. The
// device must refuse, because from its side this is indistinguishable from
// something impersonating the hub.
func TestDialAfterKeyRotationFails(t *testing.T) {
	t.Parallel()
	original := newTLSHub(t)
	a, err := newAgentFor(t, original, func(c *Config) { c.Pin = original.pin })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := a.dial(ctx, "token")
	if err != nil {
		t.Fatalf("baseline dial failed: %v", err)
	}
	_ = conn.Close("done")

	// The hub rotates onto a new key. Same hostnames, same everything else.
	rotated := newTLSHub(t)
	if rotated.pin == original.pin {
		t.Fatal("test bug: the rotated hub has the same key")
	}
	stale, err := newAgentFor(t, rotated, func(c *Config) { c.Pin = original.pin })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if conn, err := stale.dial(ctx, "token"); err == nil {
		_ = conn.Close("unexpected")
		t.Fatal("a device holding the pre-rotation pin connected to the rotated hub")
	} else if !isPinMismatch(err) {
		t.Fatalf("error = %v, want a pin mismatch", err)
	}

	// Staging both pins is how a rotation is rolled out without a flag day.
	staged, err := newAgentFor(t, rotated, func(c *Config) { c.Pin = original.pin + "," + rotated.pin })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err = staged.dial(ctx, "token")
	if err != nil {
		t.Fatalf("a device pinned to both keys could not reach the rotated hub: %v", err)
	}
	_ = conn.Close("done")
}

// TestDialUnpinnedStillVerifiesTheChain guards the invariant that pinning is
// additive. An unpinned agent must still refuse a certificate no trust store
// vouches for — otherwise "no pin" would silently mean "no verification", and
// the majority of deployments (which will not set a pin) would have no
// transport authenticity at all.
func TestDialUnpinnedStillVerifiesTheChain(t *testing.T) {
	t.Parallel()
	hub := newTLSHub(t)
	a, err := newAgentFor(t, hub, func(c *Config) {
		c.Pin = ""
		c.RootCAFile = "" // do not trust the self-signed certificate
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := a.dial(ctx, "token")
	if err == nil {
		_ = conn.Close("unexpected")
		t.Fatal("an unpinned agent accepted a certificate signed by nothing in its trust store")
	}
	if isPinMismatch(err) {
		t.Fatalf("failure came from pinning, not chain verification: %v", err)
	}
}

// TestAgentTLSConfigNeverSkipsVerification asserts the property directly on
// the client the agent will use, across every combination of pin and CA file.
func TestAgentTLSConfigNeverSkipsVerification(t *testing.T) {
	t.Parallel()
	hub := newTLSHub(t)
	for _, c := range []struct {
		name string
		mut  func(*Config)
	}{
		{"pinned with CA", func(c *Config) { c.Pin = hub.pin }},
		{"pinned without CA", func(c *Config) { c.Pin = hub.pin; c.RootCAFile = "" }},
		{"unpinned with CA", func(c *Config) { c.Pin = "" }},
		{"unpinned without CA", func(c *Config) { c.Pin = ""; c.RootCAFile = "" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, err := newAgentFor(t, hub, c.mut)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			tr, ok := a.httpClient.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport is %T, expected *http.Transport", a.httpClient.Transport)
			}
			if tr.TLSClientConfig == nil {
				t.Fatal("no TLSClientConfig on the agent's transport")
			}
			if tr.TLSClientConfig.InsecureSkipVerify {
				t.Fatal("the agent's outbound dial disables certificate verification")
			}
			if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
				t.Errorf("MinVersion = %#x, below the TLS 1.2 floor", tr.TLSClientConfig.MinVersion)
			}
		})
	}
}

// TestNewRefusesPlaintextToPublicHost pins the second half of the transport
// policy: an unattended agent does not hand its credential to a plaintext
// endpoint it cannot vouch for, and the refusal happens at construction —
// before any token is spent.
func TestNewRefusesPlaintextToPublicHost(t *testing.T) {
	t.Parallel()
	base := func() Config {
		return Config{
			Token:          "clet1.aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc",
			CredentialPath: filepath.Join(t.TempDir(), "agent.json"),
			WorkDirRoot:    t.TempDir(),
			Logf:           func(string, ...any) {},
		}
	}

	cfg := base()
	cfg.Server = "ws://hub.example.com/api/executors/connect"
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New accepted plaintext ws:// to a non-loopback host")
	}
	if !errors.Is(err, tlsconf.ErrInsecureTransport) {
		t.Fatalf("error = %v, want ErrInsecureTransport", err)
	}
	// The message must name the way out, or the operator's next move is to
	// find the check and delete it.
	if !strings.Contains(err.Error(), "--insecure-transport") {
		t.Errorf("refusal does not mention the override flag: %v", err)
	}

	cfg = base()
	cfg.Server = "http://hub.example.com/api/executors/connect"
	if _, err := New(cfg); err == nil {
		t.Fatal("New accepted plaintext http:// to a non-loopback host")
	}
}

// TestNewAllowsPlaintextToLoopback keeps local development working: there is
// no network hop to intercept, so requiring TLS there would be ceremony.
func TestNewAllowsPlaintextToLoopback(t *testing.T) {
	t.Parallel()
	for _, server := range []string{
		"ws://localhost:8080/api/executors/connect",
		"ws://127.0.0.1:8080/api/executors/connect",
		"ws://[::1]:8080/api/executors/connect",
	} {
		a, err := New(Config{
			Server:         server,
			Token:          "clet1.aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc",
			CredentialPath: filepath.Join(t.TempDir(), "agent.json"),
			WorkDirRoot:    t.TempDir(),
			Logf:           func(string, ...any) {},
		})
		if err != nil {
			t.Fatalf("New(%q): %v", server, err)
		}
		if a.insecureWarning != "" {
			t.Errorf("New(%q) warned about a loopback link: %s", server, a.insecureWarning)
		}
	}
}

// TestNewInsecureTransportWarnsLoudly checks the override works and is not
// silent. A flag that disables a protection without leaving a trace is how a
// temporary workaround becomes a permanent posture.
func TestNewInsecureTransportWarnsLoudly(t *testing.T) {
	t.Parallel()
	var logged []string
	a, err := New(Config{
		Server:            "ws://hub.example.com/api/executors/connect",
		Token:             "clet1.aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc",
		CredentialPath:    filepath.Join(t.TempDir(), "agent.json"),
		WorkDirRoot:       t.TempDir(),
		InsecureTransport: true,
		Logf:              func(f string, args ...any) { logged = append(logged, fmt.Sprintf(f, args...)) },
	})
	if err != nil {
		t.Fatalf("New with --insecure-transport: %v", err)
	}
	if a.insecureWarning == "" {
		t.Fatal("no warning recorded for an insecure transport override")
	}
	if !strings.Contains(a.insecureWarning, "INSECURE") {
		t.Errorf("warning is not loud: %q", a.insecureWarning)
	}
	if !strings.Contains(a.TransportSummary(), "PLAINTEXT") {
		t.Errorf("TransportSummary hides the downgrade: %q", a.TransportSummary())
	}

	// The warning must repeat per attempt, not once at startup: a single line
	// in a journal is gone within minutes on a device that reconnects often.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = a.dial(ctx, "token") // fails to connect; we only care that it warned
	found := false
	for _, l := range logged {
		if strings.Contains(l, "INSECURE TRANSPORT") {
			found = true
		}
	}
	if !found {
		t.Error("dial did not re-emit the insecure-transport warning")
	}
}

// TestNewRejectsPinOnPlaintext: a pin against ws:// is not a weaker guarantee,
// it is none — there is no certificate to compare. Accepting it silently would
// let an operator believe the device was pinned.
func TestNewRejectsPinOnPlaintext(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		Server:         "ws://127.0.0.1:8080/api/executors/connect",
		Token:          "clet1.aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc",
		Pin:            tlsconf.FingerprintSPKI([]byte("whatever")),
		CredentialPath: filepath.Join(t.TempDir(), "agent.json"),
		WorkDirRoot:    t.TempDir(),
		Logf:           func(string, ...any) {},
	})
	if err == nil {
		t.Fatal("New accepted a pin on a plaintext URL")
	}
	if !strings.Contains(err.Error(), "no certificate to pin") {
		t.Errorf("error does not explain why: %v", err)
	}
}

func TestNewRejectsMalformedPin(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		Server:         "wss://hub.example.com/api/executors/connect",
		Token:          "clet1.aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc",
		Pin:            "sha256:not-base64!!",
		CredentialPath: filepath.Join(t.TempDir(), "agent.json"),
		WorkDirRoot:    t.TempDir(),
		Logf:           func(string, ...any) {},
	})
	if err == nil {
		t.Fatal("New accepted a malformed pin")
	}
	if !strings.Contains(err.Error(), "--pin") {
		t.Errorf("error does not name the offending flag: %v", err)
	}
}

// TestPinPersistsAcrossRestart is what makes pinning cover the device's whole
// life rather than only its first connection. The credential file is the only
// state that survives a restart, so the pin has to live there — otherwise
// every reconnect after the first is unpinned, which is the overwhelming
// majority of connections an edge device ever makes.
func TestPinPersistsAcrossRestart(t *testing.T) {
	t.Parallel()
	credPath := filepath.Join(t.TempDir(), "agent.json")
	pin := tlsconf.FingerprintSPKI([]byte("hub-key"))

	if err := SaveCredential(credPath, Credential{
		Server:      "wss://hub.example.com/api/executors/connect",
		AgentID:     "edge-1",
		Credential:  "clac1.aaaa.bbbb.cccc",
		Pin:         pin,
		WorkDirRoot: t.TempDir(),
		EnrolledAt:  time.Now(),
	}); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	// No --pin flag: the stored one must be picked up.
	a, err := New(Config{CredentialPath: credPath, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !a.pinned {
		t.Fatal("a restarted agent lost its pin; every reconnect would be unpinned")
	}
	if a.cfg.Pin != pin {
		t.Errorf("Pin = %q, want %q", a.cfg.Pin, pin)
	}

	// An explicit flag must win, so an operator can re-pin after a rotation
	// without deleting the credential and re-enrolling the device.
	newPin := tlsconf.FingerprintSPKI([]byte("rotated-key"))
	a, err = New(Config{CredentialPath: credPath, Pin: newPin, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("New with override: %v", err)
	}
	if a.cfg.Pin != newPin {
		t.Errorf("Pin = %q, want the override %q", a.cfg.Pin, newPin)
	}

	// And the re-pin must be written back. persistCredential only runs at
	// enrollment, so without an explicit save here the new pin would apply to
	// this process and vanish on restart — the device would come back
	// UNPINNED while reporting success, which is the worst of both outcomes.
	stored, err := LoadCredential(credPath)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if stored.Pin != newPin {
		t.Fatalf("stored pin = %q, want %q — the re-pin did not survive the restart",
			stored.Pin, newPin)
	}
	// Everything else about the credential must be untouched by that write.
	if stored.AgentID != "edge-1" || stored.Credential != "clac1.aaaa.bbbb.cccc" {
		t.Errorf("re-pinning damaged the credential: %+v", stored)
	}

	restarted, err := New(Config{CredentialPath: credPath, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("New after re-pin: %v", err)
	}
	if restarted.cfg.Pin != newPin || !restarted.pinned {
		t.Errorf("after restart Pin = %q pinned = %v, want %q true",
			restarted.cfg.Pin, restarted.pinned, newPin)
	}
}

func TestTransportSummary(t *testing.T) {
	t.Parallel()
	hub := newTLSHub(t)

	pinned, err := newAgentFor(t, hub, func(c *Config) { c.Pin = hub.pin })
	if err != nil {
		t.Fatal(err)
	}
	if got := pinned.TransportSummary(); !strings.Contains(got, "pinned") {
		t.Errorf("pinned summary = %q", got)
	}

	unpinned, err := newAgentFor(t, hub, func(c *Config) { c.Pin = "" })
	if err != nil {
		t.Fatal(err)
	}
	if got := unpinned.TransportSummary(); !strings.Contains(got, "no pin") {
		t.Errorf("unpinned summary = %q", got)
	}
}
