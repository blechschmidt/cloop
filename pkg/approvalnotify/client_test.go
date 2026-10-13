package approvalnotify

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// tlsReceiver is a webhook receiver on loopback, and a CA file trusting it.
func tlsReceiver(t *testing.T, h http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	if err := os.WriteFile(ca, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, ca
}

func loopback() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")} }

// TestClientRefusesCloudMetadataEvenWhenAllowed: no allow_addresses entry
// opens a metadata service, and the refusal comes at the connect — a URL
// naming the address, or any name resolving to it, never reaches it.
func TestClientRefusesCloudMetadataEvenWhenAllowed(t *testing.T) {
	for _, addr := range []string{"169.254.169.254", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254"} {
		ip := netip.MustParseAddr(addr)
		allow := []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}
		if err := CheckAddress(ip, allow); !errors.Is(err, ErrMetadataAddress) {
			t.Errorf("CheckAddress(%s) allowing it = %v, want the metadata refusal", addr, err)
		}
	}
	c, err := NewClient([]netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")}, "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Post(context.Background(), "https://169.254.169.254/latest/meta-data/iam/security-credentials/", []byte(`{}`))
	if !errors.Is(err, ErrMetadataAddress) || !IsPermanent(err) {
		t.Fatalf("a webhook aimed at the metadata service = %v, want a permanent metadata refusal", err)
	}
}

// TestClientRefusesNonPublicAddressesUnlessAllowed: loopback, private,
// link-local and carrier-grade NAT receivers need allow_addresses.
func TestClientRefusesNonPublicAddressesUnlessAllowed(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.9", "169.254.10.1", "100.64.0.1", "::1", "fd12::1", "0.0.0.0"} {
		ip := netip.MustParseAddr(addr)
		if err := CheckAddress(ip, nil); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("CheckAddress(%s) = %v, want a refusal", addr, err)
		}
	}
	if err := CheckAddress(netip.MustParseAddr("10.1.2.3"), []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); err != nil {
		t.Errorf("an allowed private receiver was refused: %v", err)
	}
	if err := CheckAddress(netip.MustParseAddr("140.82.112.3"), nil); err != nil {
		t.Errorf("a public receiver was refused: %v", err)
	}

	var hits atomic.Int32
	srv, ca := tlsReceiver(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	refused, err := NewClient(nil, ca, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := refused.Post(context.Background(), srv.URL+"/hook", []byte(`{}`)); !errors.Is(err, ErrBlockedAddress) || !IsPermanent(err) {
		t.Fatalf("a loopback receiver not named in allow_addresses = %v, want a permanent refusal", err)
	}
	// A name is judged by what it resolves to, at the connect: localhost is
	// no more reachable than 127.0.0.1, so a public-looking name that
	// resolves inside the network is refused the same way.
	byName := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if err := refused.Post(context.Background(), byName+"/hook", []byte(`{}`)); !errors.Is(err, ErrBlockedAddress) || !IsPermanent(err) {
		t.Fatalf("a name resolving to loopback = %v, want a permanent refusal", err)
	}
	allowed, err := NewClient(loopback(), ca, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := allowed.Post(context.Background(), srv.URL+"/hook", []byte(`{}`)); err != nil {
		t.Fatalf("an allowed loopback receiver: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("the receiver saw %d request(s), want 1 — the refused one must never have connected", hits.Load())
	}
}

// TestClientNeverFollowsARedirect: a 3xx is a failed send, and whatever it
// points at is never contacted — not with the message, not with the URL that
// authorised it.
func TestClientNeverFollowsARedirect(t *testing.T) {
	var elsewhere atomic.Int32
	target, _ := tlsReceiver(t, func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) })
	srv, ca := tlsReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusTemporaryRedirect)
	})
	c, err := NewClient(loopback(), ca, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Post(context.Background(), srv.URL+"/hook", []byte(`{}`))
	if !errors.Is(err, ErrRedirect) || !IsPermanent(err) {
		t.Fatalf("a redirecting webhook = %v, want the permanent redirect refusal", err)
	}
	if elsewhere.Load() != 0 {
		t.Fatal("the redirect was followed")
	}
}

// TestClientRefusesPlaintextAndBoundsTheExchange: http:// is refused before
// any connection; a body over the bound is refused; a receiver that does not
// answer in time fails the send, transiently; 429 and 5xx are transient, other
// 4xx permanent.
func TestClientRefusesPlaintextAndBoundsTheExchange(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a plaintext webhook was contacted")
	}))
	defer plain.Close()
	c, err := NewClient(loopback(), "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Post(context.Background(), plain.URL, []byte(`{}`)); err == nil || !IsPermanent(err) {
		t.Fatalf("http:// = %v, want a permanent refusal", err)
	}
	if err := c.Post(context.Background(), "https://example.com/x", make([]byte, MaxBodyBytes+1)); err == nil || !IsPermanent(err) {
		t.Fatalf("an oversized body = %v, want a permanent refusal", err)
	}

	release := make(chan struct{})
	slow, ca := tlsReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	// Registered after the receiver, so it runs before the receiver's Close
	// waits for this handler.
	t.Cleanup(func() { close(release) })
	sc, err := NewClient(loopback(), ca, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := sc.Post(context.Background(), slow.URL, []byte(`{}`)); err == nil || IsPermanent(err) {
		t.Fatalf("a receiver past the timeout = %v, want a transient failure", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the send took %s, past its bound", time.Since(start))
	}

	var status atomic.Int32
	srv, ca2 := tlsReceiver(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(int(status.Load())) })
	cc, err := NewClient(loopback(), ca2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for code, permanent := range map[int]bool{429: false, 500: false, 503: false, 400: true, 404: true, 410: true} {
		status.Store(int32(code))
		err := cc.Post(context.Background(), srv.URL, []byte(`{}`))
		if err == nil || IsPermanent(err) != permanent {
			t.Errorf("status %d = %v, want permanent=%v", code, err, permanent)
		}
	}
}

// TestClientErrorsNeverRepeatTheURL: Go's HTTP client puts the URL in its
// errors, and a webhook URL is the channel's credential — every error the
// client returns is stored and logged.
func TestClientErrorsNeverRepeatTheURL(t *testing.T) {
	srv, ca := tlsReceiver(t, func(http.ResponseWriter, *http.Request) {})
	srv.Close() // nothing listening any more
	c, err := NewClient(loopback(), ca, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	secret := "T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX"
	err = c.Post(context.Background(), srv.URL+"/services/"+secret, []byte(`{}`))
	if err == nil {
		t.Fatal("a send to a closed port succeeded")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "/services/") {
		t.Fatalf("the error repeats the webhook URL: %v", err)
	}
}

// TestClientRefusesACAFileThatIsNotABundle: ca_file is read on every send, so
// a device, a FIFO or an outsized file named there is refused at once — not
// read to exhaustion, and not waited on.
func TestClientRefusesACAFileThatIsNotABundle(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, make([]byte, maxCAFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"a device": "/dev/zero", "a FIFO": fifo, "an outsized file": big, "a directory": dir} {
		done := make(chan error, 1)
		go func() {
			_, err := NewClient(nil, path, time.Second)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s as ca_file was accepted", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s as ca_file held NewClient", name)
		}
	}
}
