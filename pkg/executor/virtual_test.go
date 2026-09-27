package executor

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// --- firewall rules ----------------------------------------------------------

func TestFirewallRulesNormalize(t *testing.T) {
	got, err := FirewallRules{
		AllowPublicInternet: true,
		AllowCIDRs:          []string{" 10.1.2.3/8 ", "192.168.7.9", "10.0.0.0/8", "", "::ffff:172.16.0.0/108"},
		DenyCIDRs:           []string{"203.0.113.9", "0.0.0.0/0", "2001:db8::/32"},
		AllowPorts:          []int{443, 22, 443},
		Resolvers:           []string{"1.1.1.1", "[2606:4700:4700::1111]:53", "1.1.1.1:53"},
	}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := FirewallRules{
		AllowPublicInternet: true,
		// Masked, deduplicated (10.1.2.3/8 == 10.0.0.0/8), v4-mapped unmapped,
		// bare addresses read as hosts.
		AllowCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.7.9/32"},
		DenyCIDRs:  []string{"0.0.0.0/0", "203.0.113.9/32", "2001:db8::/32"},
		AllowPorts: []int{22, 443},
		Resolvers:  []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize:\n got %+v\nwant %+v", got, want)
	}
}

func TestFirewallRulesRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		rules FirewallRules
		want  string
	}{
		"allow /0":        {FirewallRules{AllowCIDRs: []string{"0.0.0.0/0"}}, "allow_cidrs[0]"},
		"allow garbage":   {FirewallRules{AllowCIDRs: []string{"10.0.0.0/8", "ten"}}, "allow_cidrs[1]"},
		"deny garbage":    {FirewallRules{DenyCIDRs: []string{"10.0.0.0/33"}}, "deny_cidrs[0]"},
		"port zero":       {FirewallRules{AllowPorts: []int{0}}, "allow_ports[0]"},
		"port too big":    {FirewallRules{AllowPorts: []int{80, 70000}}, "allow_ports[1]"},
		"resolver name":   {FirewallRules{Resolvers: []string{"dns.google"}}, "resolvers[0]"},
		"resolver port 0": {FirewallRules{Resolvers: []string{"1.1.1.1:0"}}, "resolvers[0]"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.rules.Normalize()
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, ErrInvalidSpec) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

func TestFirewallRulesBounds(t *testing.T) {
	many := make([]string, MaxFirewallCIDRs+1)
	for i := range many {
		many[i] = "10.0.0.1"
	}
	if _, err := (FirewallRules{DenyCIDRs: many}).Normalize(); err == nil {
		t.Fatal("accepted an over-long deny list")
	}
}

// --- USB inventory and resolution -------------------------------------------

func yubiHSM(port string, dev int, serial string) USBDevice {
	return USBDevice{
		Port: port, Bus: 1, Dev: dev, VendorID: "1050", ProductID: "0030",
		Manufacturer: "Yubico", Product: "YubiHSM", Serial: serial,
		Node: USBNodePath(1, dev),
	}
}

func TestResolveUSB(t *testing.T) {
	inv := []USBDevice{
		{Port: "1-2", Bus: 1, Dev: 3, VendorID: "0403", ProductID: "6001", Node: USBNodePath(1, 3)},
		yubiHSM("1-1", 2, "0031650425"),
	}
	got, err := ResolveUSB(inv, USBMatch{VendorID: "1050", ProductID: "0030"})
	if err != nil {
		t.Fatalf("ResolveUSB: %v", err)
	}
	if got.Node != "/dev/bus/usb/001/002" {
		t.Fatalf("resolved node %q", got.Node)
	}

	// Unplugged: refused, and recognisably.
	if _, err := ResolveUSB(inv, USBMatch{VendorID: "1050", ProductID: "0030", Serial: "999"}); !errors.Is(err, ErrUSBDeviceNotFound) {
		t.Fatalf("a missing serial resolved: %v", err)
	}

	// Two identical units: ambiguous without a serial or port, exact with one.
	inv = append(inv, yubiHSM("1-3", 7, "0031650999"))
	if _, err := ResolveUSB(inv, USBMatch{VendorID: "1050", ProductID: "0030"}); err == nil ||
		!strings.Contains(err.Error(), "1-1") || !strings.Contains(err.Error(), "1-3") {
		t.Fatalf("an ambiguous match was not refused naming both ports: %v", err)
	}
	got, err = ResolveUSB(inv, USBMatch{VendorID: "1050", ProductID: "0030", Port: "1-3"})
	if err != nil || got.Serial != "0031650999" {
		t.Fatalf("port pin resolved %+v, %v", got, err)
	}
}

func TestUSBMatchNormalize(t *testing.T) {
	m, err := USBMatch{VendorID: "0x1050", ProductID: "0030 ", Port: " 1-1.4"}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if m.VendorID != "1050" || m.ProductID != "0030" || m.Port != "1-1.4" {
		t.Fatalf("Normalize = %+v", m)
	}
	for _, bad := range []USBMatch{
		{VendorID: "105", ProductID: "0030"},
		{VendorID: "1050", ProductID: "zzzz"},
		{VendorID: "1050", ProductID: "0030", Port: "1-1:1.0"},
		{VendorID: "1050", ProductID: "0030", Serial: "a\x1bb"},
	} {
		if _, err := bad.Normalize(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestUSBInventoryValidation(t *testing.T) {
	ok := yubiHSM("1-1", 2, "0031650425")
	ok.Nodes = []USBNode{{Path: "/dev/hidraw0", Subsystem: "hidraw"}}
	if err := ValidateUSBInventory([]USBDevice{ok}); err != nil {
		t.Fatalf("a well-formed inventory was refused: %v", err)
	}
	for name, mutate := range map[string]func(*USBDevice){
		"node mismatch":   func(d *USBDevice) { d.Node = "/dev/bus/usb/001/009" },
		"escape in name":  func(d *USBDevice) { d.Product = "Yubi\x1b[2JHSM" },
		"bad port":        func(d *USBDevice) { d.Port = "../1" },
		"child outside":   func(d *USBDevice) { d.Nodes = []USBNode{{Path: "/etc/shadow", Subsystem: "tty"}} },
		"child traversal": func(d *USBDevice) { d.Nodes = []USBNode{{Path: "/dev/../etc", Subsystem: "tty"}} },
	} {
		t.Run(name, func(t *testing.T) {
			d := ok
			mutate(&d)
			if err := ValidateUSBInventory([]USBDevice{d}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSanitizeUSBString(t *testing.T) {
	if got := SanitizeUSBString(" Yubi\x00co‮ \x1b[31mHSM\t"); got != "Yubico [31mHSM" {
		t.Fatalf("SanitizeUSBString = %q", got)
	}
	if got := SanitizeUSBString(strings.Repeat("a", 500)); len(got) != maxUSBString {
		t.Fatalf("an over-long string was not bounded: %d", len(got))
	}
}

func TestUSBHostDevices(t *testing.T) {
	d := yubiHSM("1-1", 2, "0031650425")
	d.Nodes = []USBNode{{Path: "/dev/hidraw3", Subsystem: "hidraw"}}
	sel := DeviceSelector{Name: "yubihsm", USB: &USBMatch{VendorID: "1050", ProductID: "0030"}}

	got := USBHostDevices(sel, d)
	if len(got) != 2 || got[0].Source != d.Node || got[0].Target != d.Node || got[1].Name != "yubihsm-hidraw3" {
		t.Fatalf("USBHostDevices = %+v", got)
	}
	if err := ValidateDevices(got); err != nil {
		t.Fatalf("the rendered devices do not validate: %v", err)
	}
	sel.SkipInterfaceNodes = true
	if got := USBHostDevices(sel, d); len(got) != 1 {
		t.Fatalf("SkipInterfaceNodes still passed %d nodes", len(got))
	}
}

// --- virtual spec -------------------------------------------------------------

func TestVirtualSpecRequiresContainerMode(t *testing.T) {
	for _, mode := range []SandboxMode{SandboxModeDefault, SandboxModeHost} {
		if err := (VirtualSpec{Sandbox: SandboxSettings{Mode: mode}}).Validate(); err == nil {
			t.Errorf("mode %q was accepted for a virtual executor", mode)
		}
	}
	if err := (VirtualSpec{Sandbox: SandboxSettings{Mode: SandboxModeContainer}}).Validate(); err != nil {
		t.Errorf("a plain container spec was refused: %v", err)
	}
}

func TestVirtualSpecFirewallOwnsTheNetwork(t *testing.T) {
	fw := &FirewallRules{AllowPublicInternet: true, Resolvers: []string{"1.1.1.1"}}
	got, err := VirtualSpec{
		Sandbox:  SandboxSettings{Mode: SandboxModeContainer, Network: "bridge"},
		Firewall: fw,
	}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got.Sandbox.Network != "" {
		t.Errorf("network %q survived a firewall, which owns it", got.Sandbox.Network)
	}
	for _, network := range []string{"none", "lab-segment"} {
		if err := (VirtualSpec{
			Sandbox:  SandboxSettings{Mode: SandboxModeContainer, Network: network},
			Firewall: fw,
		}).Validate(); err == nil {
			t.Errorf("a firewall on network %q was accepted", network)
		}
	}
	if !got.NetworkEgress() || !got.FilteredEgress() {
		t.Errorf("egress flags wrong for %s", got.Describe())
	}
	none := VirtualSpec{Sandbox: SandboxSettings{Mode: SandboxModeContainer}}
	if none.NetworkEgress() || none.FilteredEgress() {
		t.Error("a spec with no network and no firewall claims egress")
	}
}

func TestVirtualSpecDevices(t *testing.T) {
	usb := DeviceSelector{Name: "yubihsm", USB: &USBMatch{VendorID: "1050", ProductID: "0030"}, Group: "plugdev"}
	base := VirtualSpec{Sandbox: SandboxSettings{Mode: SandboxModeContainer, Engine: "docker"}, Devices: []DeviceSelector{usb}}
	if err := base.Validate(); err != nil {
		t.Fatalf("a USB device on runc was refused: %v", err)
	}

	// Measured on sgx: gVisor opens fail with ENXIO. Kata has no passthrough.
	for _, rt := range []string{"runsc", "kata-qemu"} {
		spec := base
		spec.Sandbox.Runtime = rt
		if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), rt) {
			t.Errorf("devices under %s were accepted: %v", rt, err)
		}
	}

	for name, sel := range map[string]DeviceSelector{
		"both":          {Name: "x", USB: usb.USB, Path: "/dev/ttyS0"},
		"neither":       {Name: "x"},
		"forbidden":     {Name: "x", Path: "/dev/mem"},
		"not dev":       {Name: "x", Path: "/etc/passwd"},
		"root group":    {Name: "x", Path: "/dev/ttyS0", Group: "root"},
		"gid 0":         {Name: "x", Path: "/dev/ttyS0", Group: "0"},
		"group syntax":  {Name: "x", Path: "/dev/ttyS0", Group: "a b"},
		"bad perms":     {Name: "x", Path: "/dev/ttyS0", Permissions: "mr"},
		"bad name":      {Name: "-x", Path: "/dev/ttyS0"},
		"usb malformed": {Name: "x", USB: &USBMatch{VendorID: "1", ProductID: "2"}},
	} {
		t.Run(name, func(t *testing.T) {
			spec := VirtualSpec{Sandbox: base.Sandbox, Devices: []DeviceSelector{sel}}
			if err := spec.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	dup := VirtualSpec{Sandbox: base.Sandbox, Devices: []DeviceSelector{usb, usb}}
	if err := dup.Validate(); err == nil {
		t.Error("a device listed twice was accepted")
	}
}
