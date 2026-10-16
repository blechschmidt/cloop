//go:build linux

package deviceforward

// usbsource_linux.go is the on-prem endpoint of a USB forwarder: it resolves
// the configured USB identity to a device on this host, and when the hub opens
// a stream it makes that device available to the consumer over USB/IP.
//
// The data path is the kernel's, not ours. The forwarder binds the device to
// the usbip-host driver, answers the client's OP_REQ_IMPORT itself, and then
// hands the connection to the kernel by writing one end of an anonymous
// socketpair to the device's usbip_sockfd sysfs attribute. From that point the
// kernel's usbip-host does every URB; the forwarder only copies bytes between
// its end of the socketpair and the tunnel. That is why there is no usbipd
// here and no port open on any interface — the whole exposure is the one
// authenticated, outbound tunnel the forwarder already holds.

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// USBSourceOptions configures a USB source, with seams for tests.
type USBSourceOptions struct {
	// SysfsRoot defaults to /sys.
	SysfsRoot string
	// UsbipBinary is the usbip(8) tool used to bind/unbind the device to the
	// usbip-host driver. Defaults to "usbip" resolved on PATH.
	UsbipBinary string
	// Logf receives operational messages.
	Logf func(string, ...any)
}

// USBSource forwards one USB device.
type USBSource struct {
	match executor.USBMatch
	opts  USBSourceOptions

	mu     sync.Mutex
	active bool
	bound  string // busid currently bound to usbip-host, "" if none
}

// NewUSBSource builds a USB source for a device identity.
func NewUSBSource(match executor.USBMatch, opts USBSourceOptions) (*USBSource, error) {
	m, err := match.Normalize()
	if err != nil {
		return nil, err
	}
	if opts.SysfsRoot == "" {
		opts.SysfsRoot = "/sys"
	}
	if opts.UsbipBinary == "" {
		opts.UsbipBinary = "usbip"
	}
	return &USBSource{match: m, opts: opts}, nil
}

func (s *USBSource) logf(format string, args ...any) {
	if s.opts.Logf != nil {
		s.opts.Logf(format, args...)
	}
}

// Device reports the descriptor this source serves.
func (s *USBSource) Device() ForwardedDevice {
	m := s.match
	return ForwardedDevice{Kind: KindUSB, USB: &m}
}

// Probe resolves the identity and reports whether the device is attached.
func (s *USBSource) Probe(ctx context.Context) (bool, string, *executor.USBDevice) {
	info, _, err := s.resolve()
	if err != nil {
		return false, err.Error(), nil
	}
	d := executor.USBDevice{
		Port:      info.BusID,
		Bus:       int(info.BusNum),
		Dev:       int(info.DevNum),
		VendorID:  s.match.VendorID,
		ProductID: s.match.ProductID,
		Serial:    s.match.Serial,
		Node:      executor.USBNodePath(int(info.BusNum), int(info.DevNum)),
	}
	return true, "", &d
}

// Open binds the device and returns a stream that performs the USB/IP
// handshake and then relays the kernel's URB traffic.
func (s *USBSource) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return nil, fmt.Errorf("%w: this USB device is already attached to a consumer", ErrChannelRefused)
	}
	info, devDir, err := s.resolve()
	if err != nil {
		return nil, err
	}
	if err := s.bind(ctx, info.BusID); err != nil {
		return nil, err
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		s.unbind(context.Background(), info.BusID)
		return nil, fmt.Errorf("deviceforward: socketpair: %w", err)
	}
	fdA, fdB := fds[0], fds[1]
	fb := os.NewFile(uintptr(fdB), "usbip-fdB")
	conn, err := net.FileConn(fb) // dups fdB
	_ = fb.Close()
	if err != nil {
		syscall.Close(fdA)
		s.unbind(context.Background(), info.BusID)
		return nil, fmt.Errorf("deviceforward: wrap socketpair: %w", err)
	}
	s.active = true
	s.bound = info.BusID
	st := &usbStream{
		src:       s,
		info:      info,
		devDir:    devDir,
		allowed:   info.BusID,
		fdA:       fdA,
		conn:      conn,
		respReady: make(chan struct{}),
	}
	return st, nil
}

// Close ensures the device is no longer bound to usbip-host.
func (s *USBSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bound != "" {
		s.unbind(context.Background(), s.bound)
		s.bound = ""
	}
	return nil
}

// streamClosed is called by a stream when it is done.
func (s *USBSource) streamClosed(busid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
	if s.bound == busid {
		s.unbind(context.Background(), busid)
		s.bound = ""
	}
}

// handoff gives the kernel one end of the socketpair for a device.
func (s *USBSource) handoff(devDir string, fd int) error {
	path := filepath.Join(devDir, "usbip_sockfd")
	if err := os.WriteFile(path, []byte(strconv.Itoa(fd)), 0o644); err != nil {
		return fmt.Errorf("deviceforward: hand the device to the kernel (%s): %w", path, err)
	}
	return nil
}

func (s *USBSource) bind(ctx context.Context, busid string) error {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, s.opts.UsbipBinary, "bind", "-b", busid).CombinedOutput()
	if err != nil {
		// Already bound is fine; usbip reports it as an error we can accept.
		if strings.Contains(string(out), "already bound") {
			return nil
		}
		return fmt.Errorf("deviceforward: bind %s to usbip-host (needs root and the usbip tool): %w: %s",
			busid, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *USBSource) unbind(ctx context.Context, busid string) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, s.opts.UsbipBinary, "unbind", "-b", busid).CombinedOutput(); err != nil {
		s.logf("unbind %s: %v: %s", busid, err, strings.TrimSpace(string(out)))
	}
}

// resolve finds the one attached device matching the configured identity and
// builds its usbip descriptor. Zero or several matches are both refusals, for
// the reasons executor.ResolveUSB gives.
func (s *USBSource) resolve() (usbipDevice, string, error) {
	base := filepath.Join(s.opts.SysfsRoot, "bus", "usb", "devices")
	entries, err := os.ReadDir(base)
	if err != nil {
		return usbipDevice{}, "", fmt.Errorf("deviceforward: read %s: %w", base, err)
	}
	var matches []usbipDevice
	var dirs []string
	for _, e := range entries {
		name := e.Name()
		if !usbDeviceDirName(name) {
			continue
		}
		dir := filepath.Join(base, name)
		vendor := readSysAttr(dir, "idVendor")
		product := readSysAttr(dir, "idProduct")
		if !strings.EqualFold(vendor, s.match.VendorID) || !strings.EqualFold(product, s.match.ProductID) {
			continue
		}
		serial := readSysAttr(dir, "serial")
		if s.match.Serial != "" && serial != s.match.Serial {
			continue
		}
		if s.match.Port != "" && name != s.match.Port {
			continue
		}
		info := readUsbipDevice(name, dir)
		matches = append(matches, info)
		dirs = append(dirs, dir)
	}
	switch len(matches) {
	case 1:
		return matches[0], dirs[0], nil
	case 0:
		return usbipDevice{}, "", fmt.Errorf("%w: no USB device %s is attached to this host",
			executor.ErrUSBDeviceNotFound, s.match.String())
	default:
		return usbipDevice{}, "", fmt.Errorf("%w: %d USB devices match %s; narrow the selection by serial or port",
			ErrInvalidSpec, len(matches), s.match.String())
	}
}

// readUsbipDevice builds the descriptor from a device's sysfs directory.
func readUsbipDevice(busid, dir string) usbipDevice {
	d := usbipDevice{
		Path:  dir,
		BusID: busid,
	}
	d.BusNum = uint32(atoiSafe(readSysAttr(dir, "busnum")))
	d.DevNum = uint32(atoiSafe(readSysAttr(dir, "devnum")))
	d.Speed = usbSpeedCode(readSysAttr(dir, "speed"))
	d.IDVendor = uint16(hexSafe(readSysAttr(dir, "idVendor")))
	d.IDProduct = uint16(hexSafe(readSysAttr(dir, "idProduct")))
	d.BcdDevice = uint16(hexSafe(readSysAttr(dir, "bcdDevice")))
	d.BDeviceClass = uint8(hexSafe(readSysAttr(dir, "bDeviceClass")))
	d.BDeviceSubClass = uint8(hexSafe(readSysAttr(dir, "bDeviceSubClass")))
	d.BDeviceProtocol = uint8(hexSafe(readSysAttr(dir, "bDeviceProtocol")))
	d.BConfigurationValue = uint8(atoiSafe(readSysAttr(dir, "bConfigurationValue")))
	d.BNumConfigurations = uint8(atoiSafe(readSysAttr(dir, "bNumConfigurations")))
	d.BNumInterfaces = uint8(atoiSafe(readSysAttr(dir, "bNumInterfaces")))
	return d
}

func readSysAttr(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func hexSafe(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 16, 64)
	return n
}

// usbDeviceDirName reports whether a sysfs entry names a USB device ("1-1",
// "3-2.4") rather than a root hub ("usb1") or an interface ("1-1:1.0").
func usbDeviceDirName(name string) bool {
	if !strings.Contains(name, "-") || strings.Contains(name, ":") {
		return false
	}
	return name[0] >= '0' && name[0] <= '9'
}

// usbStream is one open USB/IP stream: it answers the client's import, hands
// the connection to the kernel, then relays URB bytes.
type usbStream struct {
	src     *USBSource
	info    usbipDevice
	devDir  string
	allowed string

	fdA  int      // kernel's end of the socketpair, closed after handoff
	conn net.Conn // our end, relayed to the tunnel after handoff

	mu        sync.Mutex
	reqbuf    []byte
	opResp    []byte
	opDone    bool
	respReady chan struct{}
	closed    bool
	closeOnce sync.Once
}

func (s *usbStream) signalResp() {
	select {
	case <-s.respReady:
	default:
		close(s.respReady)
	}
}

func (s *usbStream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.opResp) > 0 {
			n := copy(p, s.opResp)
			s.opResp = s.opResp[n:]
			s.mu.Unlock()
			return n, nil
		}
		if s.closed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		relay := s.opDone
		ready := s.respReady
		s.mu.Unlock()
		if relay {
			return s.conn.Read(p)
		}
		<-ready
	}
}

func (s *usbStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if s.opDone {
		conn := s.conn
		s.mu.Unlock()
		return conn.Write(p)
	}
	s.reqbuf = append(s.reqbuf, p...)
	req, consumed, ok, err := parseUSBIPRequest(s.reqbuf)
	if err != nil {
		s.mu.Unlock()
		return 0, err
	}
	if !ok {
		if len(s.reqbuf) >= opReqImportSize {
			s.mu.Unlock()
			return 0, fmt.Errorf("%w: USB/IP opening request did not parse", ErrProtocol)
		}
		s.mu.Unlock()
		return len(p), nil
	}
	if cerr := checkImport(req, s.allowed); cerr != nil {
		// Tell the client no, then fail the write so the stream tears down.
		s.opResp = buildOpRepImport(usbipDevice{}, 1)
		s.signalResp()
		s.mu.Unlock()
		return 0, cerr
	}
	extra := append([]byte(nil), s.reqbuf[consumed:]...)
	if err := s.src.handoff(s.devDir, s.fdA); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	// The kernel holds its own reference now; drop ours.
	syscall.Close(s.fdA)
	s.fdA = -1
	s.opResp = buildOpRepImport(s.info, 0)
	s.opDone = true
	s.signalResp()
	s.mu.Unlock()
	if len(extra) > 0 {
		if _, werr := s.conn.Write(extra); werr != nil {
			return 0, werr
		}
	}
	return len(p), nil
}

func (s *usbStream) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.fdA >= 0 {
			syscall.Close(s.fdA)
			s.fdA = -1
		}
		s.signalResp()
		s.mu.Unlock()
		if s.conn != nil {
			_ = s.conn.Close()
		}
		s.src.streamClosed(s.info.BusID)
	})
	return nil
}
