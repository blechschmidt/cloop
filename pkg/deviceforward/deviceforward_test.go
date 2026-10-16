package deviceforward

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// fakeSource is an in-memory device: every Open returns a connection to a
// goroutine that greets, then echoes. It lets the whole forwarder↔hub data
// path be tested with no kernel.
type fakeSource struct {
	dev       ForwardedDevice
	available bool
	openErr   error

	mu    sync.Mutex
	opens int
}

func (s *fakeSource) Device() ForwardedDevice { return s.dev }

func (s *fakeSource) Probe(context.Context) (bool, string, *executor.USBDevice) {
	if !s.available {
		return false, "device not plugged in", nil
	}
	return true, "", nil
}

func (s *fakeSource) Open(context.Context) (io.ReadWriteCloser, error) {
	s.mu.Lock()
	s.opens++
	s.mu.Unlock()
	if s.openErr != nil {
		return nil, s.openErr
	}
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		_, _ = far.Write([]byte("GREETING"))
		buf := make([]byte, 4096)
		for {
			n, err := far.Read(buf)
			if n > 0 {
				echo := strings.ToUpper(string(buf[:n]))
				if _, werr := far.Write([]byte(echo)); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return near, nil
}

func (s *fakeSource) Close() error { return nil }

func usbDevice() ForwardedDevice {
	return ForwardedDevice{
		Kind:  KindUSB,
		USB:   &executor.USBMatch{VendorID: "1050", ProductID: "0030", Serial: "0031650425"},
		Label: "YubiHSM",
	}
}

// startHub mounts a Hub on an httptest server and returns it plus the ws URL.
func startHub(t *testing.T, store Store) (*Hub, string) {
	t.Helper()
	hub, err := NewHub(HubOptions{Store: store, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(hub)
	t.Cleanup(ts.Close)
	return hub, "ws" + strings.TrimPrefix(ts.URL, "http") + "/connect"
}

func runForwarder(t *testing.T, ctx context.Context, cfg ForwarderConfig) *Forwarder {
	t.Helper()
	f, err := NewForwarder(cfg)
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	go func() { _ = f.Run(ctx) }()
	return f
}

// waitConnected blocks until the hub reports exactly one connected forwarder.
func waitConnected(t *testing.T, hub *Hub, want int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c := hub.Connected()
		if len(c) == want {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d connected forwarders, have %v", want, hub.Connected())
	return nil
}

func TestEnrollConnectAndStream(t *testing.T) {
	store := newMemStore()
	token, _, err := Mint(store, MintOptions{Name: "bench", Device: usbDevice()})
	if err != nil {
		t.Fatal(err)
	}
	hub, url := startHub(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &fakeSource{dev: usbDevice(), available: true}
	credPath := filepath.Join(t.TempDir(), "forwarder.json")
	runForwarder(t, ctx, ForwarderConfig{
		Server:         url,
		Token:          token,
		CredentialPath: credPath,
		Source:         src,
		Logf:           t.Logf,
	})

	ids := waitConnected(t, hub, 1)
	fwdID := ids[0]

	// The credential was persisted on enrollment.
	if _, ok, err := LoadCredential(credPath); err != nil || !ok {
		t.Fatalf("credential not saved: ok=%v err=%v", ok, err)
	}

	// Open a stream and exercise the data path both ways.
	stream, err := hub.OpenStream(ctx, fwdID, "test")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	got := make([]byte, len("GREETING"))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if string(got) != "GREETING" {
		t.Fatalf("greeting = %q, want GREETING", got)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len("HELLO"))
	if _, err := io.ReadFull(stream, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != "HELLO" {
		t.Fatalf("echo = %q, want HELLO", echo)
	}
}

func TestReconnectWithSavedCredential(t *testing.T) {
	store := newMemStore()
	token, _, err := Mint(store, MintOptions{Name: "bench", Device: usbDevice()})
	if err != nil {
		t.Fatal(err)
	}
	hub, url := startHub(t, store)
	credPath := filepath.Join(t.TempDir(), "forwarder.json")

	// First run: enroll, then stop.
	ctx1, cancel1 := context.WithCancel(context.Background())
	runForwarder(t, ctx1, ForwarderConfig{
		Server: url, Token: token, CredentialPath: credPath,
		Source: &fakeSource{dev: usbDevice(), available: true}, Logf: t.Logf,
	})
	waitConnected(t, hub, 1)
	cancel1()
	// Wait for the session to drop.
	deadline := time.Now().Add(3 * time.Second)
	for len(hub.Connected()) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Second run: no token at all, only the saved credential.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	runForwarder(t, ctx2, ForwarderConfig{
		Server: url, CredentialPath: credPath,
		Source: &fakeSource{dev: usbDevice(), available: true}, Logf: t.Logf,
	})
	waitConnected(t, hub, 1)
}

func TestOpenRefusedWhenDeviceUnavailable(t *testing.T) {
	store := newMemStore()
	token, _, _ := Mint(store, MintOptions{Name: "bench", Device: usbDevice()})
	hub, url := startHub(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := &fakeSource{dev: usbDevice(), available: false, openErr: errors.New("device is unplugged")}
	runForwarder(t, ctx, ForwarderConfig{
		Server: url, Token: token, CredentialPath: filepath.Join(t.TempDir(), "c.json"),
		Source: src, Logf: t.Logf,
	})
	ids := waitConnected(t, hub, 1)

	_, err := hub.OpenStream(ctx, ids[0], "test")
	if err == nil {
		t.Fatal("expected OpenStream to fail when the device cannot be opened")
	}
	if !errors.Is(err, ErrChannelRefused) {
		t.Fatalf("error = %v, want ErrChannelRefused", err)
	}
	if !strings.Contains(err.Error(), "unplugged") {
		t.Fatalf("error %q should carry the forwarder's reason", err)
	}
}

func TestRevokeDropsSession(t *testing.T) {
	store := newMemStore()
	token, _, _ := Mint(store, MintOptions{Name: "bench", Device: usbDevice()})
	hub, url := startHub(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runForwarder(t, ctx, ForwarderConfig{
		Server: url, Token: token, CredentialPath: filepath.Join(t.TempDir(), "c.json"),
		Source: &fakeSource{dev: usbDevice(), available: true}, Logf: t.Logf,
	})
	ids := waitConnected(t, hub, 1)

	if err := hub.Revoke(ids[0]); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(hub.Connected()) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(hub.Connected()) != 0 {
		t.Fatalf("session still present after revoke: %v", hub.Connected())
	}
}

func TestConnectRejectsBadCredential(t *testing.T) {
	store := newMemStore()
	_, url := startHubHandler(t, store)
	// A credential-shaped string that was never issued.
	req, _ := http.NewRequest("GET", strings.Replace(url, "ws", "http", 1), nil)
	req.Header.Set("Authorization", "Bearer "+credentialPrefix+".deadbeef.deadbeef.deadbeef")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func startHubHandler(t *testing.T, store Store) (*Hub, string) {
	t.Helper()
	hub, err := NewHub(HubOptions{Store: store, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(hub)
	t.Cleanup(ts.Close)
	return hub, "ws" + strings.TrimPrefix(ts.URL, "http") + "/connect"
}
