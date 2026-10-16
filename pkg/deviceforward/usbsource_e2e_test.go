//go:build linux

package deviceforward

// Real end-to-end USB forward, exercising both kernels' halves on one box: a
// forwarder exports a host USB device to usbip-host through usbip_sockfd, the
// hub opens a stream to it, and ImportUSB attaches that stream to this host's
// vhci_hcd through the controller's attach file — no usbipd, no `usbip
// attach`, and no listening socket anywhere (Task 20430).
//
// Opt-in, because it needs root, the usbip tool (for the forwarder's bind),
// the usbip-host and vhci_hcd modules, and a real USB device to bind:
//
//	CLOOP_FORWARD_USB_E2E=1 CLOOP_FORWARD_USB_BUSID=1-1 \
//	  CLOOP_FORWARD_USB_VID=0627 CLOOP_FORWARD_USB_PID=0001 \
//	  go test ./pkg/deviceforward -run TestUSBForwardEndToEnd -v
//
// It binds the named device to usbip-host for the duration and restores it,
// and it detaches only the vhci port it attached: a device an operator
// imported by hand stays exactly where it is.

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestUSBForwardEndToEnd(t *testing.T) {
	if os.Getenv("CLOOP_FORWARD_USB_E2E") == "" {
		t.Skip("set CLOOP_FORWARD_USB_E2E=1 (needs root, usbip, a real device) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to bind a device to usbip-host and attach to vhci_hcd")
	}
	if _, err := exec.LookPath("usbip"); err != nil {
		t.Skip("usbip tool not installed")
	}
	busid := envOr("CLOOP_FORWARD_USB_BUSID", "1-1")
	vid := envOr("CLOOP_FORWARD_USB_VID", "0627")
	pid := envOr("CLOOP_FORWARD_USB_PID", "0001")

	store := newMemStore()
	match := executor.USBMatch{VendorID: vid, ProductID: pid, Port: busid}
	token, _, err := Mint(store, MintOptions{Name: "bench", Device: ForwardedDevice{Kind: KindUSB, USB: &match}})
	if err != nil {
		t.Fatal(err)
	}
	hub, url := startHub(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src, err := NewUSBSource(match, USBSourceOptions{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	runForwarder(t, ctx, ForwarderConfig{
		Server: url, Token: token, CredentialPath: t.TempDir() + "/c.json",
		Source: src, Logf: t.Logf,
	})
	ids := waitConnected(t, hub, 1)
	t.Cleanup(func() { _ = exec.Command("usbip", "unbind", "-b", busid).Run() })

	before := vhciPortsInUse(t)

	stream, err := hub.OpenDevice(ctx, ids[0], "attach")
	if err != nil {
		t.Fatalf("OpenDevice: %v", err)
	}
	if stream.Exported.BusID != busid {
		t.Fatalf("the forwarder's acknowledgement names bus id %q, want %q", stream.Exported.BusID, busid)
	}
	ledger, err := OpenLedger(t.TempDir(), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	ictx, icancel := context.WithTimeout(ctx, 30*time.Second)
	defer icancel()
	imp, err := ImportUSB(ictx, stream, stream.Exported.BusID, ImportOptions{Ledger: ledger, Logf: t.Logf})
	if err != nil {
		t.Fatalf("ImportUSB: %v", err)
	}
	t.Cleanup(func() { _ = imp.Close() })

	if before[imp.Port] {
		t.Fatalf("the import took vhci port %d, which was already in use before it", imp.Port)
	}
	if imp.Device.VendorID != vid || imp.Device.ProductID != pid {
		t.Fatalf("the imported device enumerated as %s:%s, want %s:%s", imp.Device.VendorID, imp.Device.ProductID, vid, pid)
	}
	if _, err := os.Stat(imp.Device.Node); err != nil {
		t.Fatalf("the imported device's usbfs node %s is not on this host: %v", imp.Device.Node, err)
	}
	if got := len(ledger.Entries()); got != 1 {
		t.Fatalf("the ledger records %d attachments, want 1", got)
	}
	t.Logf("imported %s at vhci port %d as %s (%s)", imp.Device.Label(), imp.Port, imp.Device.Port, imp.Device.Node)

	// Closing detaches exactly the port the import attached, and nothing else.
	if err := imp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && vhciPortsInUse(t)[imp.Port] {
		time.Sleep(100 * time.Millisecond)
	}
	after := vhciPortsInUse(t)
	if after[imp.Port] {
		t.Fatalf("vhci port %d is still in use after Close", imp.Port)
	}
	for p := range before {
		if !after[p] {
			t.Fatalf("vhci port %d, in use before the test, was detached by it", p)
		}
	}
	if got := len(ledger.Entries()); got != 0 {
		t.Fatalf("the ledger still records %d attachments after Close", got)
	}
}

// vhciPortsInUse lists the vhci ports that hold a device right now.
func vhciPortsInUse(t *testing.T) map[int]bool {
	t.Helper()
	ps, err := VHCI{}.ports()
	if err != nil {
		t.Fatalf("read vhci status: %v", err)
	}
	out := map[int]bool{}
	for _, p := range ps {
		if p.State != vdevStateNull {
			out[p.Port] = true
		}
	}
	return out
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
