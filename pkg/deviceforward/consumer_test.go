//go:build linux

package deviceforward

// Unit tests for the consumer side of a forward (Task 20430), against fixture
// trees rather than a kernel: the vhci status parser, the rule that only a
// port this process attached is ever detached, the ledger and its sweep, the
// USB/IP client codec, and the forwarder's answer to a device list.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// fakeVHCI lays out a vhci_hcd platform directory with the status given.
func fakeVHCI(t *testing.T, status string) VHCI {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vhci_hcd.0")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"status": status, "attach": "", "detach": ""} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return VHCI{Root: root}
}

// The layout on the host this was built on: an operator's own import (a
// hardware security module) on hs port 0, the rest free.
const statusWithOperatorImport = `hub port sta spd dev      sockfd local_busid
hs  0000 006 002 00030002 000003 3-1
hs  0001 004 000 00000000 000000 0-0
hs  0002 004 000 00000000 000000 0-0
ss  0008 004 000 00000000 000000 0-0
ss  0009 004 000 00000000 000000 0-0
`

func TestVHCIStatusAndFreePorts(t *testing.T) {
	v := fakeVHCI(t, statusWithOperatorImport)
	ps, err := v.ports()
	if err != nil || len(ps) != 5 {
		t.Fatalf("ports = %d, %v; want 5", len(ps), err)
	}
	if p := ps[0]; p.Hub != "hs" || p.State != vdevStateUsed || p.DevID != 0x00030002 || p.LocalBusID != "3-1" {
		t.Fatalf("port 0 parsed as %+v", p)
	}
	// A full-speed device takes the first free USB 2 port, never the
	// operator's; a SuperSpeed one the first free USB 3 port.
	if p, err := v.freePort(2); err != nil || p != 1 {
		t.Fatalf("free hs port = %d, %v; want 1", p, err)
	}
	if p, err := v.freePort(usbSpeedSuper); err != nil || p != 8 {
		t.Fatalf("free ss port = %d, %v; want 8", p, err)
	}
	full := fakeVHCI(t, "hub port sta spd dev      sockfd local_busid\nhs  0000 006 002 00030002 000003 3-1\n")
	if _, err := full.freePort(2); err == nil {
		t.Fatal("a controller with no free port offered one")
	}
}

// TestDetachTouchesOnlyWhatThisProcessAttached: a port is detached only while
// it still carries the device id recorded for it — the operator's own import
// on port 0 is never touched, nor a free port, nor a port re-used by another
// device since.
func TestDetachTouchesOnlyWhatThisProcessAttached(t *testing.T) {
	v := fakeVHCI(t, statusWithOperatorImport)
	detach := filepath.Join(v.Root, "detach")
	for _, c := range []struct {
		name  string
		port  int
		devid uint32
	}{
		{"the operator's port, under another device id", 0, 0x00010002},
		{"a free port", 1, 0x00010002},
		{"a port not listed", 12, 0x00010002},
	} {
		ok, err := v.detachIfOurs(c.port, c.devid)
		if err != nil || ok {
			t.Errorf("%s: detached=%v err=%v", c.name, ok, err)
		}
		if b, _ := os.ReadFile(detach); len(b) != 0 {
			t.Fatalf("%s: wrote %q to detach", c.name, b)
		}
	}
	// The port and device id this process recorded: detached.
	if ok, err := v.detachIfOurs(0, 0x00030002); err != nil || !ok {
		t.Fatalf("detaching the recorded port = %v, %v", ok, err)
	}
	if b, _ := os.ReadFile(detach); string(b) != "0" {
		t.Fatalf("detach file = %q, want the port", b)
	}
}

func TestLedgerRecordsAndSweepsOnlyTheDead(t *testing.T) {
	dir := t.TempDir()
	v := fakeVHCI(t, strings.Replace(statusWithOperatorImport, "hs  0001 004 000 00000000 000000 0-0",
		"hs  0001 006 002 00010002 000009 3-2", 1))

	// This process's own ledger: never swept while it lives.
	l, err := OpenLedger(dir, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	id := l.Add(LedgerEntry{Kind: LedgerVHCI, VHCIRoot: v.Root, VHCIPort: 1, DevID: 0x00010002})
	if got := l.Entries(); len(got) != 1 || got[0].VHCIPort != 1 {
		t.Fatalf("ledger = %+v", got)
	}
	if rep := SweepLedgers(dir, t.Logf); len(rep.Detached) != 0 {
		t.Fatalf("a live process's ledger was swept: %+v", rep)
	}

	// A dead process's ledger naming port 1 (still its device) and port 0
	// (the operator's, under another id): only port 1 is detached.
	dead := ledgerFile{PID: 1 << 22, StartTime: 1, Entries: []LedgerEntry{
		{ID: "1", Kind: LedgerVHCI, VHCIRoot: v.Root, VHCIPort: 1, DevID: 0x00010002},
		{ID: "2", Kind: LedgerVHCI, VHCIRoot: v.Root, VHCIPort: 0, DevID: 0x00010005},
		{ID: "3", Kind: LedgerTAP, TAP: "cfwdnotthere0"},
	}}
	b, _ := json.Marshal(dead)
	path := filepath.Join(dir, ledgerName(dead.PID, dead.StartTime))
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	rep := SweepLedgers(dir, t.Logf)
	if len(rep.Detached) != 1 || rep.Detached[0] != "port 1" || len(rep.Errors) != 0 {
		t.Fatalf("sweep = %+v; want port 1 alone detached", rep)
	}
	if out, _ := os.ReadFile(filepath.Join(v.Root, "detach")); string(out) != "1" {
		t.Fatalf("detach file = %q, want port 1", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the dead process's ledger was left behind")
	}
	l.Remove(id)
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("an empty ledger left %d files", len(entries))
	}
}

func TestUSBIPClientCodec(t *testing.T) {
	req := buildOpReqImport("1-1")
	got, n, ok, err := parseUSBIPRequest(req)
	if err != nil || !ok || n != len(req) || got.Code != opReqImport || got.BusID != "1-1" {
		t.Fatalf("an import request does not parse back: %+v %d %v %v", got, n, ok, err)
	}
	dev := usbipDevice{Path: "/sys/devices/x/1-1", BusID: "1-1", BusNum: 1, DevNum: 2, Speed: 2,
		IDVendor: 0x0627, IDProduct: 0x0001, BNumInterfaces: 1}
	back, err := readOpRepImport(bytes.NewReader(buildOpRepImport(dev, 0)))
	if err != nil || back.BusID != "1-1" || back.BusNum != 1 || back.DevNum != 2 || back.IDVendor != 0x0627 {
		t.Fatalf("an import reply does not parse back: %+v %v", back, err)
	}
	if _, err := readOpRepImport(bytes.NewReader(buildOpRepImport(usbipDevice{}, 1))); err == nil {
		t.Fatal("a refused import read as accepted")
	}
	list := buildOpRepDevlist([]exportedUSB{{Device: dev, Interfaces: []usbipInterface{{Class: 3}}}})
	devs, err := readOpRepDevlist(bytes.NewReader(list))
	if err != nil || len(devs) != 1 || devs[0].Device.BusID != "1-1" || len(devs[0].Interfaces) != 1 || devs[0].Interfaces[0].Class != 3 {
		t.Fatalf("a device list does not parse back: %+v %v", devs, err)
	}
	huge := make([]byte, opCommonSize+4)
	binary.BigEndian.PutUint16(huge[0:2], usbipVersion)
	binary.BigEndian.PutUint16(huge[2:4], opRepDevlist)
	binary.BigEndian.PutUint32(huge[opCommonSize:], 1<<20)
	if _, err := readOpRepDevlist(bytes.NewReader(huge)); err == nil {
		t.Fatal("a device list claiming a million devices was read")
	}
}

// fakeUSBTree lays out one USB device in a sysfs fixture.
func fakeUSBTree(t *testing.T, busid, vid, pid string, onVHCI bool) string {
	t.Helper()
	root := t.TempDir()
	parent := filepath.Join(root, "devices", "pci0000:00", "usb1")
	if onVHCI {
		parent = filepath.Join(root, "devices", "platform", "vhci_hcd.0", "usb3")
	}
	dev := filepath.Join(parent, busid)
	iface := filepath.Join(dev, busid+":1.0")
	if err := os.MkdirAll(iface, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"idVendor": vid, "idProduct": pid, "busnum": "1", "devnum": "2",
		"speed": "12", "bConfigurationValue": "1", "bNumInterfaces": " 1", "bNumConfigurations": "1"} {
		_ = os.WriteFile(filepath.Join(dev, name), []byte(v+"\n"), 0o644)
	}
	_ = os.WriteFile(filepath.Join(iface, "bInterfaceClass"), []byte("03\n"), 0o644)
	links := filepath.Join(root, "bus", "usb", "devices")
	_ = os.MkdirAll(links, 0o755)
	if err := os.Symlink(dev, filepath.Join(links, busid)); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestForwarderAnswersADeviceListWithoutBinding: the probe behind the
// dashboard's Test button reads the one device the forwarder carries, and binds
// nothing — no usbip tool is run, so none needs to exist.
func TestForwarderAnswersADeviceListWithoutBinding(t *testing.T) {
	root := fakeUSBTree(t, "1-1", "0627", "0001", false)
	src, err := NewUSBSource(executor.USBMatch{VendorID: "0627", ProductID: "0001"},
		USBSourceOptions{SysfsRoot: root, UsbipBinary: filepath.Join(t.TempDir(), "no-usbip-here")})
	if err != nil {
		t.Fatal(err)
	}
	st, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if e := st.(*usbStream).Exported(); e.BusID != "1-1" || e.VendorID != "0627" {
		t.Fatalf("the open describes %+v", e)
	}
	res, err := ProbeUSB(context.Background(), st)
	if err != nil {
		t.Fatalf("ProbeUSB: %v", err)
	}
	if res.BusID != "1-1" || res.VendorID != "0627" || res.ProductID != "0001" || res.Interfaces != 1 {
		t.Fatalf("probe = %+v", res)
	}
	// The source is free again for a consumer.
	st2, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("a second open after the probe: %v", err)
	}
	_ = st2.Close()
}

// TestForwarderNeverCarriesAnImportedDevice: a device attached to this host
// over USB/IP — the operator's own import, another forwarder's device — is not
// a device this forwarder can carry.
func TestForwarderNeverCarriesAnImportedDevice(t *testing.T) {
	root := fakeUSBTree(t, "3-1", "1050", "0030", true)
	src, err := NewUSBSource(executor.USBMatch{VendorID: "1050", ProductID: "0030"}, USBSourceOptions{SysfsRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if ok, detail, _ := src.Probe(context.Background()); ok {
		t.Fatalf("a vhci-imported device resolved as forwardable (%s)", detail)
	}
	if _, err := src.Open(context.Background()); err == nil {
		t.Fatal("a vhci-imported device was opened for forwarding")
	}
}
