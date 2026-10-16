//go:build linux

package deviceforward

// Real end-to-end USB forward, exercising the kernel path: a forwarder exports
// a host USB device, the hub presents a loopback import endpoint, and the
// standard `usbip attach` imports the device onto this host's vhci — the same
// chain a cloud consumer would use, collapsed onto one box.
//
// Opt-in, because it needs root, the usbip tool, the usbip-host and vhci_hcd
// modules, and a real USB device to bind:
//
//	CLOOP_FORWARD_USB_E2E=1 CLOOP_FORWARD_USB_BUSID=1-1 \
//	  CLOOP_FORWARD_USB_VID=0627 CLOOP_FORWARD_USB_PID=0001 \
//	  go test ./pkg/deviceforward -run TestUSBForwardEndToEnd -v
//
// It binds the named device to usbip-host for the duration and restores it.

import (
	"context"
	"os"
	"os/exec"
	"strconv"
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
		t.Skip("needs root to bind a device to usbip-host")
	}
	if _, err := exec.LookPath("usbip"); err != nil {
		t.Skip("usbip tool not installed")
	}
	busid := envOr("CLOOP_FORWARD_USB_BUSID", "1-1")
	vid := envOr("CLOOP_FORWARD_USB_VID", "0627")
	pid := envOr("CLOOP_FORWARD_USB_PID", "0001")

	store := newMemStore()
	match := executor.USBMatch{VendorID: vid, ProductID: pid}
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

	ep, err := hub.ListenUSB(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()

	// Attach, then make sure we always detach and the device is restored.
	t.Cleanup(func() {
		out, _ := exec.Command("usbip", "port").CombinedOutput()
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Port ") {
				port := strings.TrimSuffix(strings.Fields(line)[1], ":")
				_ = exec.Command("usbip", "detach", "-p", port).Run()
			}
		}
		_ = exec.Command("usbip", "unbind", "-b", busid).Run()
	})

	attachCtx, acancel := context.WithTimeout(ctx, 20*time.Second)
	defer acancel()
	out, err := exec.CommandContext(attachCtx, "usbip", "--tcp-port", strconv.Itoa(ep.Port()),
		"attach", "-r", "127.0.0.1", "-b", busid).CombinedOutput()
	if err != nil {
		t.Fatalf("usbip attach failed: %v: %s", err, out)
	}
	t.Logf("usbip attach: %s", out)

	// Give the kernel a moment, then confirm the device is imported.
	deadline := time.Now().Add(5 * time.Second)
	var portOut string
	for time.Now().Before(deadline) {
		b, _ := exec.Command("usbip", "port").CombinedOutput()
		portOut = string(b)
		if strings.Contains(strings.ToLower(portOut), strings.ToLower(vid+":"+pid)) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(strings.ToLower(portOut), strings.ToLower(vid+":"+pid)) {
		t.Fatalf("imported device %s:%s not found in usbip port:\n%s", vid, pid, portOut)
	}
	t.Logf("device imported over the forwarder:\n%s", portOut)
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
