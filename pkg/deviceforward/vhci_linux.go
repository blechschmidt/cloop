//go:build linux

package deviceforward

// vhci_linux.go is the consumer's handle on the kernel's USB/IP virtual host
// controller, vhci_hcd (Task 20430).
//
// The kernel interface is four sysfs files under the controller's platform
// device. status (and status.1, status.2… for further controllers) lists every
// virtual port: its hub (hs for USB 2 and below, ss for USB 3), its state, and
// for a used port the remote device id and the local bus id it enumerated as.
// attach takes "port sockfd devid speed" — the fd of a connected stream socket
// in the writing process — and detach takes a port. That is all `usbip attach`
// does once it has a TCP connection; a consumer here does the same with one
// end of an anonymous socketpair instead, so no port is ever opened.
//
// Ports are shared with everything else on the host. This host's own operator
// may have imported a device by hand (the test rig this was built on has a
// hardware security module attached at vhci port 0), so nothing here ever
// detaches a port it did not attach: callers detach by the port and the remote
// device id they recorded, and a port whose device id no longer matches is
// left alone.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Port states, from the kernel's enum usbip_device_status.
const (
	vdevStateNull        = 4 // VDEV_ST_NULL: free
	vdevStateNotAssigned = 5 // VDEV_ST_NOTASSIGNED: attached, not yet enumerated
	vdevStateUsed        = 6 // VDEV_ST_USED: enumerated
	vdevStateError       = 7 // VDEV_ST_ERROR
)

// Kernel usb_device_speed values that live on the SuperSpeed hub.
const (
	usbSpeedSuper     = 5
	usbSpeedSuperPlus = 6
)

// DefaultVHCIRoot is the platform-device directory of the first controller.
const DefaultVHCIRoot = "/sys/devices/platform/vhci_hcd.0"

// VHCI is one host's virtual host controller.
type VHCI struct {
	// Root is the platform-device directory holding attach, detach and
	// status. Empty means DefaultVHCIRoot.
	Root string
}

func (v VHCI) root() string {
	if v.Root != "" {
		return v.Root
	}
	return DefaultVHCIRoot
}

// vhciPort is one line of the status file.
type vhciPort struct {
	Hub        string // "hs" or "ss"
	Port       int
	State      int
	Speed      int
	DevID      uint32
	SockFD     int
	LocalBusID string
}

// Available reports whether vhci_hcd is loaded and this process can attach.
func (v VHCI) Available() error {
	root := v.root()
	if _, err := os.Stat(filepath.Join(root, "status")); err != nil {
		return fmt.Errorf("the vhci_hcd kernel module is not loaded (no %s); run `modprobe vhci-hcd`", filepath.Join(root, "status"))
	}
	f, err := os.OpenFile(filepath.Join(root, "attach"), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot write %s (attaching a USB/IP device needs root): %v", filepath.Join(root, "attach"), err)
	}
	_ = f.Close()
	return nil
}

// ports reads every controller's status file.
func (v VHCI) ports() ([]vhciPort, error) {
	root := v.root()
	files := []string{filepath.Join(root, "status")}
	more, _ := filepath.Glob(filepath.Join(root, "status.*"))
	sort.Strings(more)
	files = append(files, more...)
	var out []vhciPort
	for i, f := range files {
		ps, err := parseVHCIStatus(f)
		if err != nil {
			if i == 0 {
				return nil, err
			}
			continue
		}
		out = append(out, ps...)
	}
	return out, nil
}

// parseVHCIStatus reads one status file:
//
//	hub port sta spd dev      sockfd local_busid
//	hs  0000 006 002 00030002 000003 3-1
func parseVHCIStatus(path string) ([]vhciPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("deviceforward: read %s: %w", path, err)
	}
	defer f.Close()
	var out []vhciPort
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 7 || fields[0] == "hub" {
			continue
		}
		port, err1 := strconv.Atoi(fields[1])
		state, err2 := strconv.Atoi(fields[2])
		speed, err3 := strconv.Atoi(fields[3])
		devid, err4 := strconv.ParseUint(fields[4], 16, 32)
		sockfd, err5 := strconv.Atoi(fields[5])
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
			continue
		}
		out = append(out, vhciPort{
			Hub: fields[0], Port: port, State: state, Speed: speed,
			DevID: uint32(devid), SockFD: sockfd, LocalBusID: fields[6],
		})
	}
	return out, sc.Err()
}

// port returns one port's current line.
func (v VHCI) port(n int) (vhciPort, bool, error) {
	ps, err := v.ports()
	if err != nil {
		return vhciPort{}, false, err
	}
	for _, p := range ps {
		if p.Port == n {
			return p, true, nil
		}
	}
	return vhciPort{}, false, nil
}

// hubFor names the root hub a device of this speed attaches to.
func hubFor(speed uint32) string {
	if speed == usbSpeedSuper || speed == usbSpeedSuperPlus {
		return "ss"
	}
	return "hs"
}

// freePort picks the lowest free port on the hub a device of this speed
// needs.
func (v VHCI) freePort(speed uint32) (int, error) {
	ps, err := v.ports()
	if err != nil {
		return -1, err
	}
	hub := hubFor(speed)
	for _, p := range ps {
		if p.Hub == hub && p.State == vdevStateNull {
			return p.Port, nil
		}
	}
	return -1, fmt.Errorf("deviceforward: every %s port of vhci_hcd is in use", hub)
}

// attach hands the kernel a connected stream socket for a virtual port.
func (v VHCI) attach(port, sockfd int, devid, speed uint32) error {
	path := filepath.Join(v.root(), "attach")
	line := fmt.Sprintf("%d %d %d %d", port, sockfd, devid, speed)
	if err := os.WriteFile(path, []byte(line), 0o200); err != nil {
		return fmt.Errorf("deviceforward: attach to vhci port %d (%s): %w", port, path, err)
	}
	return nil
}

// detach disconnects a virtual port.
func (v VHCI) detach(port int) error {
	path := filepath.Join(v.root(), "detach")
	if err := os.WriteFile(path, []byte(strconv.Itoa(port)), 0o200); err != nil {
		return fmt.Errorf("deviceforward: detach vhci port %d (%s): %w", port, path, err)
	}
	return nil
}

// detachIfOurs detaches a port only while it still carries the remote device
// id this process attached there. A port that is free, or that now holds
// something else, is not ours and is left alone.
func (v VHCI) detachIfOurs(port int, devid uint32) (bool, error) {
	p, ok, err := v.port(port)
	if err != nil || !ok {
		return false, err
	}
	if p.State == vdevStateNull || p.DevID != devid {
		return false, nil
	}
	if err := v.detach(port); err != nil {
		// Racing the kernel's own teardown — the stream ended and it freed
		// the port first — is success, not failure.
		if q, ok2, _ := v.port(port); ok2 && (q.State == vdevStateNull || q.DevID != devid) {
			return true, nil
		}
		return false, err
	}
	return true, nil
}
