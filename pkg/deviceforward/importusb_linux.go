//go:build linux

package deviceforward

// importusb_linux.go attaches a forwarded USB device to this host's kernel
// without a TCP listener (Task 20430).
//
// The consumer is handed a byte stream that ends at the forwarder's device —
// on an executor agent, a channel of its own tunnel to the hub; on the hub, a
// stream from its forwarder tunnel. It speaks the client half of the USB/IP
// opening handshake on that stream itself (OP_REQ_IMPORT for the bus id the
// forwarder exports), then gives vhci_hcd one end of an anonymous AF_UNIX
// socketpair by writing its descriptor to the controller's attach file, and
// relays the other end to the stream. That is the mirror image of the
// forwarder handing its end to usbip-host through usbip_sockfd: the kernels
// at the two ends move every URB, and this process only copies bytes.
//
// Nothing listens anywhere, so nothing on the consumer's host can import the
// device by connecting to something — the defect a loopback import endpoint
// had. The device appears on the host as a vhci-attached USB device, and the
// existing passthrough gives its nodes to one sandbox.
//
// The attachment ends when the stream does (the forwarder or the hub went
// away, a revocation closed it, the run ended) or when the caller closes it:
// the relay stops, the kernel's end of the socketpair sees EOF, and the port is
// detached — by port and recorded device id, so a port this process did not
// attach is never touched.

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ImportOptions configures an import, with seams for tests.
type ImportOptions struct {
	// VHCI is the controller to attach to. Zero means the host's first.
	VHCI VHCI
	// SysfsRoot and DevRoot locate /sys and /dev, for resolving the device
	// once it has enumerated. Empty means the host's.
	SysfsRoot string
	DevRoot   string
	// Ledger, when set, records the attachment so a successor process can
	// sweep it if this one dies holding it.
	Ledger *Ledger
	// EnumerateTimeout bounds the wait for the kernel to enumerate the device
	// after the attach. Zero means 15 seconds.
	EnumerateTimeout time.Duration
	// Logf receives operational messages.
	Logf func(string, ...any)
}

func (o ImportOptions) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// USBImport is a forwarded USB device attached to this host's vhci_hcd.
type USBImport struct {
	opts   ImportOptions
	stream io.ReadWriteCloser
	conn   net.Conn // our end of the socketpair, relayed to stream

	// Port is the vhci port the device is attached to, and DevID the remote
	// device id the kernel recorded for it.
	Port  int
	DevID uint32
	// Remote is what the forwarder exported.
	Remote usbipDevice
	// Device is the device as it enumerated on this host.
	Device executor.USBDevice

	ledgerID  string
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// Done is closed once the attachment has ended, for any reason.
func (u *USBImport) Done() <-chan struct{} { return u.done }

// HostDevices are the device nodes a sandbox is given for this device: the
// usbfs node and its interface nodes, named after name.
func (u *USBImport) HostDevices(name string) []executor.HostDevice {
	return executor.USBHostDevices(executor.DeviceSelector{Name: name}, u.Device)
}

// ImportUSB imports the device behind stream onto this host. busid is the
// forwarder's bus id for it, which OP_REQ_IMPORT must name. On success the
// device has enumerated on this host and u.Device describes it; the stream is
// owned by the import from then on and closed with it. On failure the stream
// is closed too.
func ImportUSB(ctx context.Context, stream io.ReadWriteCloser, busid string, opts ImportOptions) (_ *USBImport, err error) {
	if stream == nil {
		return nil, fmt.Errorf("deviceforward: import a USB device: no stream")
	}
	defer func() {
		if err != nil {
			_ = stream.Close()
		}
	}()
	if busid == "" {
		return nil, fmt.Errorf("%w: the forwarder did not say which bus id it exports", ErrProtocol)
	}
	if err := opts.VHCI.Available(); err != nil {
		return nil, fmt.Errorf("deviceforward: cannot import a USB device on this host: %w", err)
	}

	// The handshake: one request out, one reply back, both small. Bounded by
	// ctx through a watcher that closes the stream, since the stream itself
	// has no deadline.
	stop := closeOnDone(ctx, stream)
	if _, err := stream.Write(buildOpReqImport(busid)); err != nil {
		stop()
		return nil, fmt.Errorf("deviceforward: send the USB/IP import request: %w", err)
	}
	remote, err := readOpRepImport(stream)
	stop()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("deviceforward: USB/IP import: %w", ctx.Err())
		}
		return nil, err
	}

	speed := remote.Speed
	devid := remote.BusNum<<16 | remote.DevNum
	port, err := opts.VHCI.freePort(speed)
	if err != nil {
		return nil, err
	}

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("deviceforward: socketpair: %w", err)
	}
	kernelFD := fds[0]
	fb := os.NewFile(uintptr(fds[1]), "vhci-relay")
	conn, err := net.FileConn(fb) // dups fds[1]
	_ = fb.Close()
	if err != nil {
		syscall.Close(kernelFD)
		return nil, fmt.Errorf("deviceforward: wrap socketpair: %w", err)
	}

	u := &USBImport{
		opts: opts, stream: stream, conn: conn,
		Port: port, DevID: devid, Remote: remote,
		done: make(chan struct{}),
	}
	// On record before the kernel holds anything: a process that dies between
	// the attach and the ledger write would leave a port no successor knows.
	if opts.Ledger != nil {
		u.ledgerID = opts.Ledger.Add(LedgerEntry{Kind: LedgerVHCI, VHCIRoot: opts.VHCI.root(), VHCIPort: port, DevID: devid})
	}
	if err := opts.VHCI.attach(port, kernelFD, devid, speed); err != nil {
		syscall.Close(kernelFD)
		_ = conn.Close()
		u.forget()
		return nil, err
	}
	// The kernel took its own reference with the attach; drop ours, so the
	// kernel's end closes when the kernel lets go of it.
	syscall.Close(kernelFD)

	go func() {
		splice(stream, conn)
		_ = u.Close()
	}()

	d, err := u.waitEnumerated(ctx)
	if err != nil {
		_ = u.Close()
		return nil, err
	}
	u.Device = d
	opts.logf("imported USB device %s (%04x:%04x) from the forwarder's %s onto vhci port %d as %s (%s)",
		d.Label(), remote.IDVendor, remote.IDProduct, busid, port, d.Port, d.Node)
	return u, nil
}

// waitEnumerated waits for the kernel to finish enumerating the attached
// device and reads it back from sysfs.
func (u *USBImport) waitEnumerated(ctx context.Context) (executor.USBDevice, error) {
	timeout := u.opts.EnumerateTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	deadline := time.Now().Add(timeout)
	sysfs := u.opts.SysfsRoot
	if sysfs == "" {
		sysfs = "/sys"
	}
	var last string
	for {
		select {
		case <-u.done:
			return executor.USBDevice{}, fmt.Errorf("deviceforward: the USB/IP stream ended before the device enumerated on this host")
		default:
		}
		p, ok, err := u.opts.VHCI.port(u.Port)
		switch {
		case err != nil:
			last = err.Error()
		case !ok:
			last = fmt.Sprintf("vhci port %d is not listed", u.Port)
		case p.State == vdevStateError:
			return executor.USBDevice{}, fmt.Errorf("deviceforward: vhci port %d went into error before the device enumerated", u.Port)
		case p.State == vdevStateUsed && p.LocalBusID != "" && p.LocalBusID != "0-0":
			if d, found := readEnumerated(sysfs, u.opts.DevRoot, p.LocalBusID); found {
				// Interface nodes (hidraw, ttyACM) appear as drivers bind, a
				// moment after the device itself; give them that moment.
				settleInterfaces(sysfs, p.LocalBusID, 2*time.Second)
				if d2, ok2 := readEnumerated(sysfs, u.opts.DevRoot, p.LocalBusID); ok2 {
					d = d2
				}
				return d, nil
			}
			last = fmt.Sprintf("device %s is not in sysfs yet", p.LocalBusID)
		default:
			last = fmt.Sprintf("vhci port %d state %d", u.Port, p.State)
		}
		if time.Now().After(deadline) {
			return executor.USBDevice{}, fmt.Errorf("deviceforward: the device did not enumerate on this host within %s (%s)", timeout, last)
		}
		select {
		case <-ctx.Done():
			return executor.USBDevice{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// readEnumerated reads one device from sysfs by its local bus id.
func readEnumerated(sysfsRoot, devRoot, busid string) (executor.USBDevice, bool) {
	for _, d := range executor.ScanUSB(sysfsRoot, devRoot) {
		if d.Port == busid {
			return d, true
		}
	}
	return executor.USBDevice{}, false
}

// settleInterfaces waits, up to max, until every interface of the device's
// active configuration has a driver bound or the wait runs out. It never
// fails: a device whose interfaces no driver claims (most userspace-driven
// hardware) is simply used through its usbfs node.
func settleInterfaces(sysfsRoot, busid string, max time.Duration) {
	dir := filepath.Join(sysfsRoot, "bus", "usb", "devices", busid)
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		n, _ := strconv.Atoi(readSysAttr(dir, "bNumInterfaces"))
		cfg := readSysAttr(dir, "bConfigurationValue")
		if n == 0 || cfg == "" {
			return
		}
		bound := 0
		for i := 0; i < n; i++ {
			if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("%s:%s.%d", busid, cfg, i), "driver")); err == nil {
				bound++
			}
		}
		if bound == n {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Close ends the attachment: the relay stops, the port is detached if it still
// holds this device, and the stream is closed. Idempotent; safe to call from
// any goroutine.
func (u *USBImport) Close() error {
	u.closeOnce.Do(func() {
		_ = u.conn.Close()
		_ = u.stream.Close()
		if _, err := u.opts.VHCI.detachIfOurs(u.Port, u.DevID); err != nil {
			u.closeErr = err
			u.opts.logf("detach vhci port %d: %v", u.Port, err)
		}
		u.forget()
		close(u.done)
	})
	return u.closeErr
}

func (u *USBImport) forget() {
	if u.opts.Ledger != nil && u.ledgerID != "" {
		u.opts.Ledger.Remove(u.ledgerID)
		u.ledgerID = ""
	}
}
