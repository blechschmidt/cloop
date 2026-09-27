package executor

// usb.go describes the USB hardware attached to an executor's host, and turns
// an admin's choice of one device into the device nodes a sandbox is given
// (Task 20345).
//
// # Why devices are chosen by identity, not by path
//
// A USB device's node is /dev/bus/usb/BBB/DDD, and DDD is an enumeration
// counter: unplug the device, or reattach it over USB/IP, and it comes back
// under a new number. A configuration that stored the path would be naming
// whatever happened to enumerate there next — at best nothing, at worst a
// different device. So a selection records what identifies the hardware
// (vendor, product, serial, and optionally the port it is plugged into) and
// the device resolves that to a path at dispatch, from its own view of sysfs,
// every time.
//
// # Why the inventory's strings are treated as hostile
//
// Manufacturer, product and serial are strings the *device firmware* reports.
// Any USB stick can claim to be "<script>" from vendor "\x1b[2J". They travel
// from an edge device to the control plane, into a database, an audit row and
// a dashboard, so they are bounded and stripped of control characters at the
// source — and the dashboard escapes them again, because a sanitised string is
// still not markup.

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// MaxUSBDevices bounds an inventory. A host with more attached devices than
// this is a hub farm, not an executor, and an agent reporting one has a bug.
const MaxUSBDevices = 128

// maxUSBString bounds a descriptor string. USB string descriptors hold at most
// 126 UTF-16 code units; anything longer did not come from a descriptor.
const maxUSBString = 128

// USBDevice is one device in an executor host's USB inventory.
type USBDevice struct {
	// Port is the kernel's topology name for where the device is plugged in
	// ("1-1", "3-2.4"). Stable across re-enumeration for as long as the device
	// stays in the same port, which is why a selection may pin it.
	Port string `json:"port"`
	// Bus and Dev are the current bus and device numbers. Dev changes on every
	// re-enumeration; see the file comment.
	Bus int `json:"bus"`
	Dev int `json:"dev"`
	// VendorID and ProductID are the four-digit lowercase hex IDs lsusb shows.
	VendorID  string `json:"vendor_id"`
	ProductID string `json:"product_id"`
	// Manufacturer, Product and Serial are the device's own descriptor
	// strings, sanitised. Serial is empty for the many devices that have none.
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	Serial       string `json:"serial,omitempty"`
	// Class is bDeviceClass as two hex digits; "09" is a hub.
	Class string `json:"class,omitempty"`
	// Speed is the link speed in Mbit/s as the kernel reports it ("12", "480").
	Speed string `json:"speed,omitempty"`
	// Node is the usbfs character device a userspace driver such as libusb
	// opens: /dev/bus/usb/BBB/DDD.
	Node string `json:"node"`
	// Nodes are the other device nodes the kernel created for this device's
	// interfaces — a CDC-ACM serial line, a HID endpoint — which is how most
	// hardware is actually talked to when no userspace driver is involved.
	Nodes []USBNode `json:"nodes,omitempty"`
	// Mode, UID and GID describe Node's permissions as the agent saw them.
	// Empty when the agent cannot see /dev at all, which is the norm under
	// the hardened service unit (PrivateDevices=yes): the container engine
	// resolves the node in the real /dev, but the agent never does.
	Mode string `json:"mode,omitempty"`
	UID  *int   `json:"uid,omitempty"`
	GID  *int   `json:"gid,omitempty"`
	// Group is GID's name on the device, when it has one.
	Group string `json:"group,omitempty"`
}

// USBNode is one interface device node belonging to a USB device.
type USBNode struct {
	// Path is the node under /dev ("/dev/ttyACM0", "/dev/hidraw2").
	Path string `json:"path"`
	// Subsystem is the kernel class that created it ("tty", "hidraw").
	Subsystem string `json:"subsystem"`
}

// IsHub reports whether the device is a USB hub. Passing a hub's node through
// does not pass what is plugged into it, so the dashboard does not offer it.
func (d USBDevice) IsHub() bool { return d.Class == "09" }

// Label renders the device the way an admin recognises it.
func (d USBDevice) Label() string {
	name := strings.TrimSpace(strings.TrimSpace(d.Manufacturer) + " " + strings.TrimSpace(d.Product))
	if name == "" {
		name = "USB device"
	}
	s := fmt.Sprintf("%s (%s:%s)", name, d.VendorID, d.ProductID)
	if d.Serial != "" {
		s += " serial " + d.Serial
	}
	return s
}

// hexID matches a canonical four-digit USB vendor or product ID.
var hexID = regexp.MustCompile(`^[0-9a-f]{4}$`)

// usbPortPattern matches a kernel USB topology name: bus, dash, then one or
// more dot-separated port numbers. Deliberately excludes interface suffixes
// ("1-1:1.0"), which name an interface rather than a device.
var usbPortPattern = regexp.MustCompile(`^[0-9]{1,3}-[0-9]{1,3}(\.[0-9]{1,3}){0,6}$`)

// NormalizeUSBID lowercases and validates a vendor or product ID. "0x1050"
// and "1050" are both accepted, because both are how people write them.
func NormalizeUSBID(s string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	v = strings.TrimPrefix(v, "0x")
	if !hexID.MatchString(v) {
		return "", fmt.Errorf("%q is not a four-digit hex USB ID (like 1050)", s)
	}
	return v, nil
}

// SanitizeUSBString bounds a descriptor string and removes anything that is
// not a printable character. See the file comment for why this is not
// optional.
func SanitizeUSBString(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxUSBString {
			break
		}
		switch {
		case r == ' ':
			b.WriteRune(r)
		case unicode.IsControl(r), !unicode.IsPrint(r):
			// dropped: terminal escapes, NULs, bidi overrides
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// USBNodePath is where usbfs puts a device's node.
func USBNodePath(bus, dev int) string {
	return fmt.Sprintf("/dev/bus/usb/%03d/%03d", bus, dev)
}

// Validate checks an inventory entry that arrived from a device. The control
// plane stores and renders these, so an entry that is not the shape the agent
// is supposed to produce is refused rather than displayed.
func (d USBDevice) Validate() error {
	if !usbPortPattern.MatchString(d.Port) {
		return fmt.Errorf("usb device port %q is not a kernel topology name", d.Port)
	}
	if !hexID.MatchString(d.VendorID) || !hexID.MatchString(d.ProductID) {
		return fmt.Errorf("usb device %s has a malformed id %q:%q", d.Port, d.VendorID, d.ProductID)
	}
	if d.Bus < 1 || d.Bus > 999 || d.Dev < 1 || d.Dev > 999 {
		return fmt.Errorf("usb device %s has bus/device numbers out of range", d.Port)
	}
	if d.Node != USBNodePath(d.Bus, d.Dev) {
		return fmt.Errorf("usb device %s node %q does not match its bus/device numbers", d.Port, d.Node)
	}
	for _, s := range []string{d.Manufacturer, d.Product, d.Serial, d.Class, d.Speed, d.Mode, d.Group} {
		if s != SanitizeUSBString(s) {
			return fmt.Errorf("usb device %s carries an unsanitised string", d.Port)
		}
	}
	if len(d.Nodes) > MaxDevices {
		return fmt.Errorf("usb device %s lists %d interface nodes, at most %d are allowed",
			d.Port, len(d.Nodes), MaxDevices)
	}
	for _, n := range d.Nodes {
		if err := validateDevicePath(d.Port, "interface node", n.Path); err != nil {
			return err
		}
		if !isDevPath(n.Path) {
			return fmt.Errorf("usb device %s interface node %q is not under /dev", d.Port, n.Path)
		}
		if n.Subsystem != SanitizeUSBString(n.Subsystem) {
			return fmt.Errorf("usb device %s carries an unsanitised subsystem", d.Port)
		}
	}
	return nil
}

// ValidateUSBInventory checks a whole inventory as received.
func ValidateUSBInventory(devs []USBDevice) error {
	if len(devs) > MaxUSBDevices {
		return fmt.Errorf("usb inventory lists %d devices, at most %d are allowed", len(devs), MaxUSBDevices)
	}
	for _, d := range devs {
		if err := d.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// USBMatch identifies one USB device independently of where it enumerated.
type USBMatch struct {
	VendorID  string `json:"vendor_id"`
	ProductID string `json:"product_id"`
	// Serial narrows the match to one physical unit. Empty matches any serial,
	// which is fine for the common case of one such device per host and is
	// refused as ambiguous when there are two.
	Serial string `json:"serial,omitempty"`
	// Port narrows the match to the device plugged into one port — the only
	// way to tell apart two identical devices that report no serial.
	Port string `json:"port,omitempty"`
}

// Normalize canonicalises and validates the match.
func (m USBMatch) Normalize() (USBMatch, error) {
	var err error
	out := USBMatch{Serial: strings.TrimSpace(m.Serial), Port: strings.TrimSpace(m.Port)}
	if out.VendorID, err = NormalizeUSBID(m.VendorID); err != nil {
		return USBMatch{}, fmt.Errorf("vendor_id: %w", err)
	}
	if out.ProductID, err = NormalizeUSBID(m.ProductID); err != nil {
		return USBMatch{}, fmt.Errorf("product_id: %w", err)
	}
	if out.Serial != SanitizeUSBString(out.Serial) {
		return USBMatch{}, fmt.Errorf("serial %q contains characters no device reports", m.Serial)
	}
	if out.Port != "" && !usbPortPattern.MatchString(out.Port) {
		return USBMatch{}, fmt.Errorf("port %q is not a kernel topology name (like 1-1 or 3-2.4)", m.Port)
	}
	return out, nil
}

// Matches reports whether d is the device m describes.
func (m USBMatch) Matches(d USBDevice) bool {
	if d.VendorID != m.VendorID || d.ProductID != m.ProductID {
		return false
	}
	if m.Serial != "" && d.Serial != m.Serial {
		return false
	}
	if m.Port != "" && d.Port != m.Port {
		return false
	}
	return true
}

// String renders the match for a message.
func (m USBMatch) String() string {
	s := m.VendorID + ":" + m.ProductID
	if m.Serial != "" {
		s += " serial " + m.Serial
	}
	if m.Port != "" {
		s += " on port " + m.Port
	}
	return s
}

// ErrUSBDeviceNotFound reports that no attached device matches a selection.
var ErrUSBDeviceNotFound = fmt.Errorf("executor: selected USB device is not attached")

// ResolveUSB finds the one device in an inventory that m describes.
//
// Zero matches and several matches are both refusals. Zero is the device being
// unplugged, which must fail the start rather than run a hardware task without
// its hardware; several is the selection being ambiguous, and picking one
// would be guessing which physical unit a task talks to.
func ResolveUSB(inventory []USBDevice, m USBMatch) (USBDevice, error) {
	var found []USBDevice
	for _, d := range inventory {
		if m.Matches(d) {
			found = append(found, d)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return USBDevice{}, fmt.Errorf("%w: no USB device %s is attached to this host", ErrUSBDeviceNotFound, m)
	default:
		ports := make([]string, len(found))
		for i, d := range found {
			ports[i] = d.Port
		}
		return USBDevice{}, fmt.Errorf("%w: %d USB devices match %s (ports %s); select one by serial "+
			"or port", ErrInvalidSpec, len(found), m, strings.Join(ports, ", "))
	}
}

// deviceNodeName derives a HostDevice name for one of a USB device's nodes.
func deviceNodeName(base, nodePath string) string {
	leaf := path.Base(nodePath)
	name := base + "-" + leaf
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// USBHostDevices turns a resolved USB device into the device nodes a sandbox is
// given: the usbfs node, at the same path so libusb's sysfs-derived lookup
// finds it, and — unless the selection opts out — every interface node.
func USBHostDevices(sel DeviceSelector, d USBDevice) []HostDevice {
	perms := sel.Permissions
	out := []HostDevice{{
		Name:        sel.Name,
		Source:      d.Node,
		Target:      d.Node,
		Permissions: perms,
	}}
	if sel.SkipInterfaceNodes {
		return out
	}
	for _, n := range d.Nodes {
		out = append(out, HostDevice{
			Name:        deviceNodeName(sel.Name, n.Path),
			Source:      n.Path,
			Target:      n.Path,
			Permissions: perms,
		})
	}
	return out
}

// ParseGroupID reads a numeric group ID, refusing root.
//
// Root's group is refused outright rather than accepted with a warning: on a
// rootful engine GID 0 inside the sandbox is GID 0 on the host for every file
// the sandbox can see through a bind mount, and the device-access problem it
// would "solve" has a narrow fix — a udev rule giving the node a group of its
// own.
func ParseGroupID(s string) (int, bool, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false, nil
	}
	if n <= 0 {
		return 0, true, fmt.Errorf("group %d is root's; give the device node a group of its own with a "+
			"udev rule and name that", n)
	}
	return n, true, nil
}
