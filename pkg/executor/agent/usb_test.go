package agent

// Tests for the device-side half of virtual executors (Task 20345): reading the
// USB inventory from sysfs, resolving a selection against it, and translating
// a firewall into the container driver's filter.
//
// The sysfs trees are fixtures built to the kernel's real layout, modelled on
// the sgx executor host: a YubiHSM attached over USB/IP, whose /sys entry is a
// symlink into /sys/devices/platform/vhci_hcd.0.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// fixtureUSB is one device to lay out in a fake sysfs.
type fixtureUSB struct {
	port, vendor, product, bus, dev, manufacturer, productName, serial, class string
	// children maps a relative path under the device dir to a uevent body,
	// e.g. "1-2:1.0/tty/ttyACM0" → "DEVNAME=ttyACM0".
	children map[string]string
}

// writeSysfs builds root/bus/usb/devices with each device as a symlink into
// root/devices/..., the way the kernel lays it out.
func writeSysfs(t *testing.T, devs ...fixtureUSB) string {
	t.Helper()
	root := t.TempDir()
	busDir := filepath.Join(root, "bus", "usb", "devices")
	if err := os.MkdirAll(busDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		real := filepath.Join(root, "devices", "platform", "vhci_hcd.0", "usb"+d.bus, d.port)
		if err := os.MkdirAll(real, 0o755); err != nil {
			t.Fatal(err)
		}
		attrs := map[string]string{
			"idVendor": d.vendor, "idProduct": d.product, "busnum": d.bus, "devnum": d.dev,
			"manufacturer": d.manufacturer, "product": d.productName, "serial": d.serial,
			"bDeviceClass": d.class, "speed": "12",
			"uevent": "DEVNAME=bus/usb/00" + d.bus + "/00" + d.dev,
		}
		for name, v := range attrs {
			if v == "" {
				continue
			}
			if err := os.WriteFile(filepath.Join(real, name), []byte(v+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for rel, uevent := range d.children {
			dir := filepath.Join(real, rel)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "uevent"), []byte(uevent+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(real, filepath.Join(busDir, d.port)); err != nil {
			t.Fatal(err)
		}
	}
	// A root hub and an interface entry, both of which must be skipped.
	for _, extra := range []string{"usb1", "1-1:1.0"} {
		dir := filepath.Join(root, "devices", "extra", extra)
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "idVendor"), []byte("1d6b\n"), 0o644)
		_ = os.Symlink(dir, filepath.Join(busDir, extra))
	}
	return root
}

var sgxYubiHSM = fixtureUSB{
	port: "1-1", vendor: "1050", product: "0030", bus: "1", dev: "2",
	manufacturer: "Yubico", productName: "YubiHSM", serial: "0031650425", class: "00",
}

func TestScanUSBReadsTheInventory(t *testing.T) {
	acm := fixtureUSB{
		port: "1-2", vendor: "2341", product: "0043", bus: "1", dev: "5",
		manufacturer: "Arduino", productName: "Uno", class: "02",
		children: map[string]string{
			"1-2:1.0/tty/ttyACM0": "MAJOR=166\nMINOR=0\nDEVNAME=ttyACM0",
			// A node name that tries to leave /dev must never be reported.
			"1-2:1.1/evil/evil0": "DEVNAME=../etc/shadow",
		},
	}
	hostile := fixtureUSB{
		port: "1-3", vendor: "dead", product: "beef", bus: "1", dev: "9",
		manufacturer: "Evil\x1b[2J", productName: "<img src=x onerror=alert(1)>", class: "00",
	}
	root := writeSysfs(t, sgxYubiHSM, acm, hostile)

	got := scanUSB(root, t.TempDir())
	if len(got) != 3 {
		t.Fatalf("scanUSB found %d devices, want 3 (root hub and interface skipped): %+v", len(got), got)
	}
	hsm := got[0]
	if hsm.Port != "1-1" || hsm.VendorID != "1050" || hsm.ProductID != "0030" ||
		hsm.Serial != "0031650425" || hsm.Node != "/dev/bus/usb/001/002" || hsm.Product != "YubiHSM" {
		t.Errorf("YubiHSM entry = %+v", hsm)
	}
	if len(hsm.Nodes) != 0 {
		t.Errorf("the YubiHSM has no kernel driver and should list no interface nodes, got %+v", hsm.Nodes)
	}
	if n := got[1].Nodes; len(n) != 1 || n[0].Path != "/dev/ttyACM0" || n[0].Subsystem != "tty" {
		t.Errorf("the CDC-ACM device's interface nodes = %+v, want only /dev/ttyACM0", n)
	}
	if got[2].Manufacturer != "Evil[2J" || strings.ContainsAny(got[2].Manufacturer, "\x1b") {
		t.Errorf("a firmware string was not sanitised: %q", got[2].Manufacturer)
	}
	if err := executor.ValidateUSBInventory(got); err != nil {
		t.Errorf("the inventory the agent produces does not validate on the hub: %v", err)
	}
}

func TestScanUSBOnAHostWithoutUSB(t *testing.T) {
	if got := scanUSB(t.TempDir(), t.TempDir()); got != nil {
		t.Fatalf("a host with no /sys/bus/usb reported %+v", got)
	}
}

// TestScanUSBReportsNodePermissionsWhenVisible: with /dev visible the node's
// mode and group are reported, which is what lets the device infer the group a
// sandbox needs. Under PrivateDevices they are simply absent.
func TestScanUSBReportsNodePermissionsWhenVisible(t *testing.T) {
	root := writeSysfs(t, sgxYubiHSM)
	devRoot := t.TempDir()
	node := filepath.Join(devRoot, "bus", "usb", "001", "002")
	if err := os.MkdirAll(filepath.Dir(node), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(node, nil, 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(node, 0o664); err != nil {
		t.Fatal(err)
	}
	got := scanUSB(root, devRoot)
	if len(got) != 1 || got[0].Mode != "0664" || got[0].GID == nil {
		t.Fatalf("node permissions not reported: %+v", got)
	}
	hidden := scanUSB(root, t.TempDir())
	if hidden[0].Mode != "" || hidden[0].GID != nil {
		t.Errorf("permissions invented for a node the agent cannot see: %+v", hidden[0])
	}
}

func TestResolveVirtualDevices(t *testing.T) {
	root := writeSysfs(t, sgxYubiHSM)
	hsm := executor.DeviceSelector{
		Name: "yubihsm",
		USB:  &executor.USBMatch{VendorID: "1050", ProductID: "0030", Serial: "0031650425"},
	}

	got, err := resolveVirtualDevices([]executor.DeviceSelector{hsm}, root, t.TempDir())
	if err != nil {
		t.Fatalf("resolveVirtualDevices: %v", err)
	}
	if len(got.Devices) != 1 || got.Devices[0].Source != "/dev/bus/usb/001/002" ||
		got.Devices[0].Target != "/dev/bus/usb/001/002" {
		t.Fatalf("devices = %+v", got.Devices)
	}
	if len(got.Groups) != 0 {
		t.Errorf("groups %v inferred for a node the agent cannot see", got.Groups)
	}

	// An explicit numeric group is honoured; root's is refused.
	hsm.Group = "46"
	got, err = resolveVirtualDevices([]executor.DeviceSelector{hsm}, root, t.TempDir())
	if err != nil || strings.Join(got.Groups, ",") != "46" {
		t.Fatalf("group 46: %v %v", got.Groups, err)
	}
	hsm.Group = "0"
	if _, err := resolveVirtualDevices([]executor.DeviceSelector{hsm}, root, t.TempDir()); err == nil {
		t.Error("root's group was accepted")
	}

	// Unplugged: the start must fail, naming the device.
	gone := executor.DeviceSelector{Name: "gone", USB: &executor.USBMatch{VendorID: "1050", ProductID: "0407"}}
	if _, err := resolveVirtualDevices([]executor.DeviceSelector{gone}, root, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "gone") {
		t.Errorf("an unplugged device resolved: %v", err)
	}
}

func TestEgressFilterFor(t *testing.T) {
	if f, network := egressFilterFor(nil); f.Enabled || network != "" {
		t.Errorf("no firewall produced %+v / %q", f, network)
	}
	// A firewall that reaches nothing is no network, not an empty filter the
	// container driver would refuse.
	if f, network := egressFilterFor(&executor.FirewallRules{DenyCIDRs: []string{"10.0.0.0/8"}}); f.Enabled ||
		network != container.NetworkNone {
		t.Errorf("a deny-only firewall produced %+v / %q", f, network)
	}
	f, network := egressFilterFor(&executor.FirewallRules{
		AllowPublicInternet: true,
		DenyCIDRs:           []string{"203.0.113.0/24"},
		Resolvers:           []string{"1.1.1.1:53"},
	})
	if !f.Enabled || network != container.NetworkBridge || !f.AllowAllPorts || len(f.DenyCIDRs) != 1 {
		t.Fatalf("filter = %+v / %q", f, network)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("the translated filter does not validate: %v", err)
	}
	f, _ = egressFilterFor(&executor.FirewallRules{AllowCIDRs: []string{"10.8.0.0/24"}, AllowPorts: []int{443}})
	if f.AllowAllPorts {
		t.Error("an explicit port list was widened to every port")
	}
}

// TestVirtualDriversAreKeyedByExecutor: two virtual executors with identical
// settings still get two drivers, because each names its own bridge and table.
func TestVirtualDriversAreKeyedByExecutor(t *testing.T) {
	s := executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker"}
	a := virtualDriverKey(s, &remote.VirtualStart{ID: "vx-aaaa"}, nil)
	b := virtualDriverKey(s, &remote.VirtualStart{ID: "vx-bbbb"}, nil)
	if a == b {
		t.Error("two virtual executors share a driver key")
	}
	fw := &executor.FirewallRules{AllowPublicInternet: true}
	c := virtualDriverKey(s, &remote.VirtualStart{ID: "vx-aaaa", Firewall: fw}, nil)
	if a == c {
		t.Error("changing the firewall does not change the driver")
	}
	if virtualDriverKey(s, &remote.VirtualStart{ID: "vx-aaaa"}, []string{"46"}) == a {
		t.Error("changing the device groups does not change the driver")
	}
}

// TestVirtualDriverRevalidates: the device re-checks what the hub sent, and a
// device list under gVisor is refused here too.
func TestVirtualDriverRevalidates(t *testing.T) {
	c := newDriverCache()
	s := executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker", Runtime: "runsc"}
	v := &remote.VirtualStart{ID: "vx-test", Devices: []executor.DeviceSelector{{Name: "z", Path: "/dev/zero"}}}
	if _, err := c.virtualDriverFor(s, v, nil, ""); err == nil || !strings.Contains(err.Error(), "runsc") {
		t.Fatalf("a device list under runsc was accepted: %v", err)
	}
	if _, err := c.virtualDriverFor(executor.SandboxSettings{Mode: executor.SandboxModeHost},
		&remote.VirtualStart{ID: "vx-test"}, nil, ""); err == nil {
		t.Fatal("host mode was accepted for a virtual executor")
	}
	if _, err := c.virtualDriverFor(s, &remote.VirtualStart{ID: "Bad ID"}, nil, ""); err == nil {
		t.Fatal("a malformed virtual executor id was accepted")
	}
}

// TestDetectReportsProbes: the probes are opt-in, and when supplied their
// answers reach the hello.
func TestDetectReportsProbes(t *testing.T) {
	lookPath := func(name string) (string, error) {
		if name == "docker" {
			return "/usr/bin/docker", nil
		}
		return "", os.ErrNotExist
	}
	caps := Detect(DetectOptions{LookPath: lookPath, SysfsRoot: writeSysfs(t, sgxYubiHSM), DevRoot: t.TempDir()})
	if caps.PacketFilter || caps.PacketFilterIssue != "" || len(caps.OCIRuntimes) != 0 {
		t.Errorf("probes ran without being asked: %+v", caps)
	}
	if len(caps.USBDevices) != 1 {
		t.Errorf("USB inventory not reported: %+v", caps.USBDevices)
	}
	caps = Detect(DetectOptions{
		LookPath:          lookPath,
		SysfsRoot:         t.TempDir(),
		ProbePacketFilter: func() (bool, string) { return false, "no CAP_NET_ADMIN" },
		ProbeOCIRuntimes:  func(string) []string { return []string{"runsc", "runc"} },
	})
	if caps.PacketFilter || caps.PacketFilterIssue != "no CAP_NET_ADMIN" ||
		strings.Join(caps.OCIRuntimes, ",") != "runc,runsc" {
		t.Errorf("probe answers not reported: %+v", caps)
	}
}
