package agent

// usb.go reads this device's USB inventory out of sysfs (Task 20345).
//
// sysfs rather than lsusb, for three reasons. It is always there — usbutils is
// not installed on half the minimal images an edge device runs. It survives
// the hardened service unit: PrivateDevices=yes hides /dev from the agent, but
// /sys stays readable, and everything needed to name a device and derive its
// node lives there. And it can be pointed at a fixture tree, which is what
// makes the parsing testable on a machine with no hardware.
//
// Everything read here is either kernel-formatted (numbers, IDs) or supplied
// by the device's firmware (descriptor strings). The second kind is sanitised
// before it leaves this file; see executor.SanitizeUSBString.

import (
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// defaultSysfsRoot is where the kernel mounts sysfs.
const defaultSysfsRoot = "/sys"

// usbDeviceName matches a USB *device* entry in /sys/bus/usb/devices ("1-1",
// "3-2.4"), as opposed to a root hub ("usb1") or an interface ("1-1:1.0").
var usbDeviceName = regexp.MustCompile(`^[0-9]+-[0-9]+(\.[0-9]+)*$`)

// maxUSBWalkDepth bounds the walk for interface nodes below a device. The
// deepest real layout — device, interface, HID collection, hidraw class dir,
// node — is five levels; the bound is there so a pathological tree cannot turn
// an inventory into a filesystem crawl.
const maxUSBWalkDepth = 6

// scanUSB returns the USB devices under sysfsRoot, sorted by port. devRoot is
// where their nodes are stat'ed for permissions ("/dev" in production).
//
// It never fails: a device whose attributes cannot be read is skipped, and a
// host with no USB at all — most cloud VMs — yields nil.
func scanUSB(sysfsRoot, devRoot string) []executor.USBDevice {
	if sysfsRoot == "" {
		sysfsRoot = defaultSysfsRoot
	}
	if devRoot == "" {
		devRoot = "/dev"
	}
	base := filepath.Join(sysfsRoot, "bus", "usb", "devices")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []executor.USBDevice
	for _, e := range entries {
		if len(out) >= executor.MaxUSBDevices {
			break
		}
		name := e.Name()
		if !usbDeviceName.MatchString(name) {
			continue
		}
		// The entry is a symlink into /sys/devices; resolve it once so the
		// interface walk below stays inside the device's own subtree.
		dir, err := filepath.EvalSymlinks(filepath.Join(base, name))
		if err != nil {
			continue
		}
		d, ok := readUSBDevice(name, dir, devRoot)
		if !ok {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// readUSBDevice builds one inventory entry from a device's sysfs directory.
func readUSBDevice(port, dir, devRoot string) (executor.USBDevice, bool) {
	vendor, err := executor.NormalizeUSBID(readAttr(dir, "idVendor"))
	if err != nil {
		return executor.USBDevice{}, false
	}
	product, err := executor.NormalizeUSBID(readAttr(dir, "idProduct"))
	if err != nil {
		return executor.USBDevice{}, false
	}
	bus, err1 := strconv.Atoi(readAttr(dir, "busnum"))
	dev, err2 := strconv.Atoi(readAttr(dir, "devnum"))
	if err1 != nil || err2 != nil || bus < 1 || dev < 1 || bus > 999 || dev > 999 {
		return executor.USBDevice{}, false
	}
	d := executor.USBDevice{
		Port:         port,
		Bus:          bus,
		Dev:          dev,
		VendorID:     vendor,
		ProductID:    product,
		Manufacturer: executor.SanitizeUSBString(readAttr(dir, "manufacturer")),
		Product:      executor.SanitizeUSBString(readAttr(dir, "product")),
		Serial:       executor.SanitizeUSBString(readAttr(dir, "serial")),
		Class:        executor.SanitizeUSBString(strings.ToLower(readAttr(dir, "bDeviceClass"))),
		Speed:        executor.SanitizeUSBString(readAttr(dir, "speed")),
		Node:         executor.USBNodePath(bus, dev),
	}
	d.Nodes = interfaceNodes(dir, d.Node)
	statNode(&d, devRoot)
	if d.Validate() != nil {
		return executor.USBDevice{}, false
	}
	return d, true
}

// interfaceNodes finds the device nodes the kernel created for a device's
// interfaces — a CDC-ACM tty, a HID hidraw — by walking the device's own
// subtree for uevent files naming a DEVNAME.
//
// Child *devices* (what is plugged into a hub) are separate inventory entries
// and are not descended into, and symlinks are never followed, so the walk
// cannot wander out of the device it describes.
func interfaceNodes(dir, ownNode string) []executor.USBNode {
	var out []executor.USBNode
	seen := map[string]bool{ownNode: true}
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		if depth > maxUSBWalkDepth || len(out) >= executor.MaxDevices {
			return
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return
		}
		for _, e := range entries {
			if len(out) >= executor.MaxDevices {
				return
			}
			child := filepath.Join(p, e.Name())
			if e.Type()&os.ModeSymlink != 0 {
				continue
			}
			if e.Name() == "uevent" && depth > 0 {
				if n, ok := nodeFromUevent(child); ok && !seen[n.Path] {
					seen[n.Path] = true
					out = append(out, n)
				}
				continue
			}
			if !e.IsDir() || usbDeviceName.MatchString(e.Name()) {
				continue
			}
			walk(child, depth+1)
		}
	}
	walk(dir, 0)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// nodeFromUevent reads DEVNAME from a uevent file and names its subsystem from
// the class directory it sits in.
func nodeFromUevent(path string) (executor.USBNode, bool) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return executor.USBNode{}, false
	}
	var devname string
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "DEVNAME="); ok {
			devname = strings.TrimSpace(v)
			break
		}
	}
	if devname == "" || strings.Contains(devname, "..") || strings.HasPrefix(devname, "/") {
		return executor.USBNode{}, false
	}
	node := filepath.Join("/dev", devname)
	// The class is the directory two up from uevent: .../hidraw/hidraw0/uevent.
	subsystem := filepath.Base(filepath.Dir(filepath.Dir(path)))
	return executor.USBNode{Path: node, Subsystem: executor.SanitizeUSBString(subsystem)}, true
}

// statNode records the usbfs node's permissions when the agent can see /dev.
// Under PrivateDevices it cannot, and the fields stay empty — the engine that
// starts the sandbox resolves the node in the real /dev regardless.
func statNode(d *executor.USBDevice, devRoot string) {
	rel := strings.TrimPrefix(d.Node, "/dev/")
	fi, err := os.Stat(filepath.Join(devRoot, rel))
	if err != nil {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	d.Mode = "0" + strconv.FormatUint(uint64(fi.Mode().Perm()), 8)
	uid, gid := int(st.Uid), int(st.Gid)
	d.UID, d.GID = &uid, &gid
	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		d.Group = executor.SanitizeUSBString(g.Name)
	}
}

// readAttr reads one sysfs attribute, trimmed, or "" when it is absent. The
// read is bounded: an attribute is a line, and a file that is not is not one.
func readAttr(dir, name string) string {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}
