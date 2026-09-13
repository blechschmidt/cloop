package secretbroker

// Tests for KindHostDevice (Task 20236).
//
// The inventory parser is the security boundary here: it is the last place an
// operator's typo can be caught by the person who typed it, and the first place a
// path that would waive the sandbox's isolation can be refused.

import (
	"strings"
	"testing"
)

func TestParseDeviceInventoryAcceptsTheDocumentedForms(t *testing.T) {
	payload := `
# the lab bench
serial0=/dev/ttyUSB0
serial1=/dev/ttyUSB1:r
gpu0=/dev/nvidia0:rw
remapped=/dev/ttyUSB2:/dev/accel0
remapped_ro=/dev/ttyUSB3:/dev/accel1:r
tun=/dev/net/tun:rwm
`
	got, err := ParseDeviceInventory([]byte(payload))
	if err != nil {
		t.Fatalf("ParseDeviceInventory: %v", err)
	}
	want := []GrantedDevice{
		{Name: "serial0", Source: "/dev/ttyUSB0", Target: "/dev/ttyUSB0", Permissions: "rw"},
		{Name: "serial1", Source: "/dev/ttyUSB1", Target: "/dev/ttyUSB1", Permissions: "r"},
		{Name: "gpu0", Source: "/dev/nvidia0", Target: "/dev/nvidia0", Permissions: "rw"},
		{Name: "remapped", Source: "/dev/ttyUSB2", Target: "/dev/accel0", Permissions: "rw"},
		{Name: "remapped_ro", Source: "/dev/ttyUSB3", Target: "/dev/accel1", Permissions: "r"},
		{Name: "tun", Source: "/dev/net/tun", Target: "/dev/net/tun", Permissions: "rwm"},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d devices, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("device %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestParseDeviceInventoryDefaultsToReadWrite pins the default, because the
// runtime's own default is rwm — which additionally allows mknod on the device's
// major:minor, a second handle on the same hardware that no operator asked for by
// leaving a field blank.
func TestParseDeviceInventoryDefaultsToReadWrite(t *testing.T) {
	got, err := ParseDeviceInventory([]byte("d=/dev/ttyUSB0\n"))
	if err != nil {
		t.Fatalf("ParseDeviceInventory: %v", err)
	}
	if got[0].Permissions != devicePermReadWrite {
		t.Errorf("Permissions = %q, want %q", got[0].Permissions, devicePermReadWrite)
	}
}

// TestParseDeviceInventoryRefusesHostSurrender is the check that matters most. An
// operator who grants /dev/mem has handed over physical memory including kernel
// text, and no layer below this can recover from it.
func TestParseDeviceInventoryRefusesHostSurrender(t *testing.T) {
	for _, path := range []string{
		"/dev/mem", "/dev/kmem", "/dev/kcore", "/dev/port", "/dev/msr", "/dev/cpu",
		"/dev/sda", "/dev/nvme0n1", "/dev/vda",
	} {
		_, err := ParseDeviceInventory([]byte("d=" + path + "\n"))
		if err == nil {
			t.Errorf("accepted an inventory entry for %s", path)
			continue
		}
		if !strings.Contains(err.Error(), "isolation") {
			t.Errorf("error for %s (%v) does not say what granting it would cost", path, err)
		}
	}
}

func TestParseDeviceInventoryRejectsBadEntries(t *testing.T) {
	cases := map[string]string{
		"empty payload":         "",
		"only comments":         "# nothing here\n",
		"no equals":             "/dev/ttyUSB0\n",
		"empty name":            "=/dev/ttyUSB0\n",
		"relative source":       "d=dev/ttyUSB0\n",
		"non-canonical source":  "d=/dev/../etc/shadow\n",
		"outside /dev":          "d=/etc/shadow\n",
		"target outside /dev":   "d=/dev/ttyUSB0:/etc/shadow\n",
		"unknown mode":          "d=/dev/ttyUSB0:/dev/ttyUSB0:x\n",
		"too many fields":       "d=/dev/a:/dev/b:rw:extra\n",
		"duplicate name":        "d=/dev/ttyUSB0\nd=/dev/ttyUSB1\n",
		"duplicate target":      "a=/dev/ttyUSB0\nb=/dev/ttyUSB1:/dev/ttyUSB0\n",
		"name with a slash":     "a/b=/dev/ttyUSB0\n",
		"name with a colon":     "a:b=/dev/ttyUSB0\n",
		"backslash in path":     "d=/dev/tty\\USB0\n",
		"newline smuggled name": "d\n=/dev/ttyUSB0\n",
	}
	for name, payload := range cases {
		if _, err := ParseDeviceInventory([]byte(payload)); err == nil {
			t.Errorf("%s: accepted %q", name, payload)
		}
	}
}

// TestHostDeviceGrantNeedsAnAllowlist: there is no safe default for "which of
// this host's devices may this project reach", so the operator has to say, even
// if what they say is "*".
func TestHostDeviceGrantNeedsAnAllowlist(t *testing.T) {
	if err := (Constraints{}).ValidateFor(KindHostDevice); err == nil {
		t.Fatal("a host_device grant with no device allowlist was accepted; it would fall " +
			"open to every device in the inventory")
	}
	if err := (Constraints{Devices: []string{"serial0"}}).ValidateFor(KindHostDevice); err != nil {
		t.Errorf("a well-formed host_device grant was refused: %v", err)
	}
}

// TestDeviceAllowlistIsRefusedOnOtherKinds keeps a constraint from being set
// where nothing enforces it, which would read as a scope that is not one.
func TestDeviceAllowlistIsRefusedOnOtherKinds(t *testing.T) {
	c := Constraints{Repos: []string{"*"}, Devices: []string{"serial0"}}
	if err := c.ValidateFor(KindGitHubPAT); err == nil {
		t.Fatal("a github_pat grant accepted a device allowlist")
	}
}

// TestHostDeviceIsARegisteredKind covers the three places a kind has to be
// listed; missing one makes the kind unusable from the CLI or, worse, storable
// and undeliverable.
func TestHostDeviceIsARegisteredKind(t *testing.T) {
	if !KindHostDevice.Valid() {
		t.Error("KindHostDevice is not Valid(), so a stored grant would fail at lease time")
	}
	got, err := ParseKind("host_device")
	if err != nil || got != KindHostDevice {
		t.Errorf("ParseKind(\"host_device\") = %q, %v", got, err)
	}
	var listed bool
	for _, k := range Kinds() {
		if k == KindHostDevice {
			listed = true
		}
	}
	if !listed {
		t.Error("KindHostDevice is missing from Kinds(), so it is invisible in CLI help")
	}
}

// TestGrantedDeviceValidateGuardsATamperedMaterial is the second line of
// defence: Materialize re-checks rather than trusting the Material it was handed,
// because the two can be separated by a store round trip and this material hands
// a host path to a root-privileged runtime CLI.
func TestGrantedDeviceValidateGuardsATamperedMaterial(t *testing.T) {
	ok := GrantedDevice{Name: "d", Source: "/dev/ttyUSB0", Target: "/dev/ttyUSB0", Permissions: "rw"}
	if err := ok.validate(); err != nil {
		t.Fatalf("a well-formed device was refused: %v", err)
	}
	bad := map[string]GrantedDevice{
		"forbidden source": {Name: "d", Source: "/dev/mem", Target: "/dev/mem", Permissions: "r"},
		"outside /dev":     {Name: "d", Source: "/etc/shadow", Target: "/etc/shadow", Permissions: "r"},
		"bad mode":         {Name: "d", Source: "/dev/ttyUSB0", Target: "/dev/ttyUSB0", Permissions: "rwx"},
		"empty mode":       {Name: "d", Source: "/dev/ttyUSB0", Target: "/dev/ttyUSB0"},
		"traversal":        {Name: "d", Source: "/dev/../etc/shadow", Target: "/dev/x", Permissions: "r"},
	}
	for name, d := range bad {
		if err := d.validate(); err == nil {
			t.Errorf("%s: validate accepted %+v", name, d)
		}
	}
}

// TestHostDeviceMaterialNarrowsToTheAllowlist is the grant doing its job: one
// inventory, several projects, each seeing only its slice.
func TestHostDeviceMaterialNarrowsToTheAllowlist(t *testing.T) {
	b := &Broker{}
	inventory := []byte("serial0=/dev/ttyUSB0\nserial1=/dev/ttyUSB1\ngpu0=/dev/nvidia0\n")

	mat, err := b.hostDeviceMaterial(Material{
		SecretName:  "lab",
		Kind:        KindHostDevice,
		Constraints: Constraints{Devices: []string{"serial*"}, Writable: true},
		Env:         map[string]string{},
	}, inventory)
	if err != nil {
		t.Fatalf("hostDeviceMaterial: %v", err)
	}
	if len(mat.Devices) != 2 {
		t.Fatalf("delivered %d devices, want 2 (serial0, serial1): %+v", len(mat.Devices), mat.Devices)
	}
	for _, d := range mat.Devices {
		if d.Name == "gpu0" {
			t.Error("the glob 'serial*' delivered gpu0")
		}
	}
	if got := mat.Env["CLOOP_HOST_DEVICES"]; got != "serial0,serial1" {
		t.Errorf("CLOOP_HOST_DEVICES = %q, want %q", got, "serial0,serial1")
	}
	// Names, never paths: the host's hardware layout is not something every
	// process in the sandbox needs to be told.
	for _, v := range mat.Env {
		if strings.Contains(v, "/dev/") {
			t.Errorf("an environment value leaks a host device path: %q", v)
		}
	}
}

// TestHostDeviceGrantNarrowsWritableToRead is the direction invariant: a
// constraint may take access away and never add it.
func TestHostDeviceGrantNarrowsWritableToRead(t *testing.T) {
	b := &Broker{}
	// The inventory says rw; the grant is not writable, so read is what arrives.
	mat, err := b.hostDeviceMaterial(Material{
		SecretName:  "lab",
		Kind:        KindHostDevice,
		Constraints: Constraints{Devices: []string{"*"}},
		Env:         map[string]string{},
	}, []byte("serial0=/dev/ttyUSB0:rw\n"))
	if err != nil {
		t.Fatalf("hostDeviceMaterial: %v", err)
	}
	if got := mat.Devices[0].Permissions; got != devicePermRead {
		t.Errorf("a non-writable grant delivered %q access; it must narrow to %q",
			got, devicePermRead)
	}

	// And the converse: a writable grant cannot promote an entry the inventory
	// recorded as read-only.
	mat, err = b.hostDeviceMaterial(Material{
		SecretName:  "lab",
		Kind:        KindHostDevice,
		Constraints: Constraints{Devices: []string{"*"}, Writable: true},
		Env:         map[string]string{},
	}, []byte("serial0=/dev/ttyUSB0:r\n"))
	if err != nil {
		t.Fatalf("hostDeviceMaterial: %v", err)
	}
	if got := mat.Devices[0].Permissions; got != devicePermRead {
		t.Errorf("a writable grant promoted a read-only inventory entry to %q", got)
	}
}

// TestHostDeviceMaterialRefusesAnEmptyMatch: the grant asserts this hardware is
// reachable, so delivering nothing would start a harness that discovers the
// problem as an ENOENT minutes later.
func TestHostDeviceMaterialRefusesAnEmptyMatch(t *testing.T) {
	b := &Broker{}
	_, err := b.hostDeviceMaterial(Material{
		SecretName:  "lab",
		Kind:        KindHostDevice,
		Constraints: Constraints{Devices: []string{"nosuch"}},
		Env:         map[string]string{},
	}, []byte("serial0=/dev/ttyUSB0\n"))
	if err == nil {
		t.Fatal("a grant matching no device delivered an empty device list")
	}
}

// TestHostDeviceMaterialIsDeterministic: the list reaches an audit row and a Spec
// that executorstore persists, so two identical runs must not differ.
func TestHostDeviceMaterialIsDeterministic(t *testing.T) {
	b := &Broker{}
	inventory := []byte("zebra=/dev/ttyUSB9\nalpha=/dev/ttyUSB0\nmid=/dev/ttyUSB5\n")
	for i := 0; i < 5; i++ {
		mat, err := b.hostDeviceMaterial(Material{
			SecretName:  "lab",
			Kind:        KindHostDevice,
			Constraints: Constraints{Devices: []string{"*"}},
			Env:         map[string]string{},
		}, inventory)
		if err != nil {
			t.Fatalf("hostDeviceMaterial: %v", err)
		}
		if got := mat.Env["CLOOP_HOST_DEVICES"]; got != "alpha,mid,zebra" {
			t.Fatalf("iteration %d: CLOOP_HOST_DEVICES = %q, want sorted order", i, got)
		}
	}
}
