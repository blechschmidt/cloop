package agent

// devices.go is the device half of forwarded devices (Task 20430, protocol
// v22): attaching, on this device's host, a device that a device forwarder
// carries from somewhere else, and giving it to the sandbox of the run whose
// project it is bound to.
//
// The hub opens a device channel on this agent's tunnel for a workload about
// to start, spliced to the forwarder's stream. For a USB device the agent
// speaks the client half of the USB/IP handshake on the channel itself and
// hands vhci_hcd one end of an anonymous socketpair; for an L2 segment it
// creates a TAP fed by the channel. Neither opens a listener: nothing on this
// host can reach the device except through what the agent hands the sandbox.
// When the start frame arrives it names the channels its sandbox is given, and
// the device's nodes (or the TAP) join the Spec's Devices (or Interfaces),
// which the container driver passes through like any other.
//
// A device is detached when its run ends, when the hub or the forwarder closes
// the channel (a binding or forwarder revoked, a forwarder gone), when this
// agent's connection drops, and — for a channel no start ever claimed — after
// unclaimedDeviceTTL. What the agent attaches is recorded in a ledger under
// its work root, which the next agent process sweeps on start: a vhci port or
// TAP left by an agent that died is undone, and nothing else is touched.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// CodeDeviceUnavailable is the error code an agent answers device_open with
// when it cannot attach the device.
const CodeDeviceUnavailable = "device_unavailable"

// unclaimedDeviceTTL bounds how long an attached device waits for the start
// frame that names it. The hub sends the start right after device_opened, so
// a device still unclaimed after this is one whose start was lost or refused.
const unclaimedDeviceTTL = 2 * time.Minute

// deviceAttachTimeout bounds one attach, which includes the USB/IP handshake
// through the hub and the device's enumeration on this host.
const deviceAttachTimeout = 45 * time.Second

// ledgerDirName is where the agent records what it attached, under its work
// root, for the next process to sweep.
const ledgerDirName = ".cloop-forwarded"

// DeviceAttacher attaches a forwarded device's stream on this host. The real
// one uses vhci_hcd and TAP (hostDeviceAttacher); tests substitute one that
// needs no kernel.
type DeviceAttacher interface {
	// Support reports whether this host can attach each kind, and why not.
	Support() (usb bool, usbIssue string, l2 bool, l2Issue string)
	// AttachUSB imports the USB device behind stream, whose forwarder exports
	// it as busid. The attachment owns the stream from then on.
	AttachUSB(ctx context.Context, stream io.ReadWriteCloser, busid string) (AttachedDevice, error)
	// AttachL2 bridges stream to a new TAP named tap.
	AttachL2(stream io.ReadWriteCloser, tap string) (AttachedDevice, error)
}

// AttachedDevice is one device attached on this host.
type AttachedDevice interface {
	// Done is closed once the attachment has ended.
	Done() <-chan struct{}
	// Close detaches it. Idempotent.
	Close() error
	// Opened describes it for the device_opened answer.
	Opened() remote.DeviceOpenedPayload
	// Give is what a sandbox is given for it: device nodes for USB, an
	// interface for L2. name is the sandbox-facing handle; iface is the
	// segment's sandbox-side shape.
	Give(name string, iface executor.HostInterface) ([]executor.HostDevice, *executor.HostInterface)
}

// agentDevice is one device channel on this agent.
type agentDevice struct {
	id       string
	handleID string
	payload  remote.DeviceOpenPayload
	stream   *remote.DeviceStream

	mu       sync.Mutex
	attached AttachedDevice
	claimed  bool
	closed   bool
	timer    *time.Timer
}

// deviceTable is the agent's live device channels.
type deviceTable struct {
	reg remote.DeviceRegistry

	mu   sync.Mutex
	devs map[string]*agentDevice
}

func (t *deviceTable) add(d *agentDevice) bool {
	if !t.reg.Add(d.stream) {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.devs == nil {
		t.devs = map[string]*agentDevice{}
	}
	t.devs[d.id] = d
	return true
}

func (t *deviceTable) get(id string) *agentDevice {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.devs[id]
}

func (t *deviceTable) remove(id string) {
	t.reg.Remove(id)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.devs, id)
}

// forHandle returns the devices opened for one workload.
func (t *deviceTable) forHandle(handleID string) []*agentDevice {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*agentDevice
	for _, d := range t.devs {
		if d.handleID == handleID {
			out = append(out, d)
		}
	}
	return out
}

// all returns every device.
func (t *deviceTable) all() []*agentDevice {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*agentDevice, 0, len(t.devs))
	for _, d := range t.devs {
		out = append(out, d)
	}
	return out
}

// close ends one device: its attachment, then its channel.
func (a *Agent) closeDevice(d *agentDevice, reason string) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	att := d.attached
	if d.timer != nil {
		d.timer.Stop()
	}
	d.mu.Unlock()
	if att != nil {
		_ = att.Close()
	}
	d.stream.Abort(reason)
	a.devices.remove(d.id)
	a.cfg.logf("forwarded device %s (%s) for workload %s detached: %s", d.payload.Name, d.payload.Label, d.handleID, reason)
}

// closeDevicesFor ends every device opened for a workload.
func (a *Agent) closeDevicesFor(handleID, reason string) {
	for _, d := range a.devices.forHandle(handleID) {
		a.closeDevice(d, reason)
	}
}

// closeAllDevices ends every device, for a connection that has dropped.
func (a *Agent) closeAllDevices(reason string) {
	for _, d := range a.devices.all() {
		a.closeDevice(d, reason)
	}
}

// handleDeviceOpen registers the channel inline — so device_data the hub
// sends right behind the open finds it — and attaches in its own goroutine,
// since an attach waits on a USB device's enumeration.
func (a *Agent) handleDeviceOpen(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	p, err := remote.DecodeDeviceOpen(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	usb, usbIssue, l2, l2Issue := a.deviceAttacher().Support()
	switch {
	case p.Kind == executor.ForwardedUSB && !usb:
		a.replyError(ctx, sess, frame.ID, CodeDeviceUnavailable, "this device cannot attach a forwarded USB device: "+usbIssue)
		return
	case p.Kind == executor.ForwardedL2 && !l2:
		a.replyError(ctx, sess, frame.ID, CodeDeviceUnavailable, "this device cannot attach a forwarded network segment: "+l2Issue)
		return
	}
	if a.devices.get(p.ChannelID) != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, "device channel "+p.ChannelID+" is already open")
		return
	}
	d := &agentDevice{id: p.ChannelID, handleID: frame.Handle, payload: p}
	d.stream = remote.NewDeviceStream(p.ChannelID, a.deviceSender(sess, frame.Handle), func() { a.devices.remove(p.ChannelID) })
	if !a.devices.add(d) {
		d.stream.Finish("too many device channels")
		a.replyError(ctx, sess, frame.ID, remote.CodeBusy, "this device already holds the most device channels it carries")
		return
	}
	go a.attachDevice(ctx, sess, frame, d)
}

// attachDevice attaches one device and answers device_opened.
func (a *Agent) attachDevice(ctx context.Context, sess *deviceSession, frame remote.Frame, d *agentDevice) {
	defer func() {
		if r := recover(); r != nil {
			a.closeDevice(d, fmt.Sprintf("panic while attaching: %v", r))
			a.replyError(ctx, sess, frame.ID, CodeDeviceUnavailable, fmt.Sprintf("panic while attaching: %v", r))
		}
	}()
	actx, cancel := context.WithTimeout(ctx, deviceAttachTimeout)
	defer cancel()
	var (
		att AttachedDevice
		err error
	)
	switch d.payload.Kind {
	case executor.ForwardedUSB:
		att, err = a.deviceAttacher().AttachUSB(actx, d.stream, d.payload.BusID)
	case executor.ForwardedL2:
		att, err = a.deviceAttacher().AttachL2(d.stream, tapNameFor(d.id))
	default:
		err = fmt.Errorf("unknown device kind %q", d.payload.Kind)
	}
	if err != nil {
		a.closeDevice(d, "attach failed: "+err.Error())
		a.replyError(ctx, sess, frame.ID, CodeDeviceUnavailable, fmt.Sprintf("attach %s on %s: %v", d.payload.Name, deviceName(), err))
		return
	}
	d.mu.Lock()
	if d.closed {
		// The channel ended while the device attached: a revocation, the
		// forwarder gone. Give it back and say so.
		d.mu.Unlock()
		_ = att.Close()
		a.replyError(ctx, sess, frame.ID, CodeDeviceUnavailable, "the device channel ended while the device was attached")
		return
	}
	d.attached = att
	d.timer = time.AfterFunc(unclaimedDeviceTTL, func() {
		d.mu.Lock()
		claimed := d.claimed
		d.mu.Unlock()
		if !claimed {
			a.closeDevice(d, "no workload claimed it")
		}
	})
	d.mu.Unlock()
	// When the attachment ends on its own — the forwarder or the hub closed
	// the stream — the channel and the record go with it.
	go func() {
		<-att.Done()
		a.closeDevice(d, "the device stream ended")
	}()
	opened := att.Opened()
	opened.ChannelID = d.id
	a.cfg.logf("forwarded device %s (%s) attached for workload %s: %s", d.payload.Name, d.payload.Label, d.handleID, describeOpened(opened))
	a.reply(ctx, sess, remote.TypeDeviceOpened, frame.ID, frame.Handle, opened)
}

func describeOpened(o remote.DeviceOpenedPayload) string {
	if o.TAP != "" {
		return "TAP " + o.TAP
	}
	return fmt.Sprintf("vhci port %d as %s (%s)", o.VHCIPort, o.LocalBusID, o.Node)
}

// handleDeviceData delivers one chunk; it never blocks the frame loop.
func (a *Agent) handleDeviceData(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	p, err := remote.DecodeDeviceData(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	if d := a.devices.get(p.ChannelID); d != nil {
		d.stream.Deliver(p.Data)
	}
}

// handleDeviceClose ends a channel the hub closed: a revocation, the
// forwarder gone, the run over. The stream finishes, which ends the
// attachment's relay; the device is detached right away rather than when the
// relay notices.
func (a *Agent) handleDeviceClose(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	p, err := remote.DecodeDeviceClose(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	d := a.devices.get(p.ChannelID)
	if d == nil {
		return
	}
	reason := strings.TrimSpace(p.Reason)
	if reason == "" {
		reason = "the hub closed the device channel"
	}
	if len(reason) > 512 {
		reason = reason[:512]
	}
	d.stream.Finish(reason)
	go a.closeDevice(d, reason)
}

// claimDevices hands a starting workload the devices its start frame names:
// each must be attached and opened for this handle. What they become in the
// sandbox is returned for the Spec, with the entries of
// executor.ForwardedDevicesEnv that tell the workload where they are.
func (a *Agent) claimDevices(handleID string, ids []string) ([]executor.HostDevice, []executor.HostInterface, []string, error) {
	var (
		nodes  []executor.HostDevice
		ifaces []executor.HostInterface
		env    []string
	)
	for _, id := range ids {
		d := a.devices.get(id)
		if d == nil || d.handleID != handleID {
			return nil, nil, nil, fmt.Errorf("the start names device channel %s, which this device does not hold for workload %s", id, handleID)
		}
		d.mu.Lock()
		att, closed := d.attached, d.closed
		if att != nil && !closed {
			d.claimed = true
			if d.timer != nil {
				d.timer.Stop()
			}
		}
		d.mu.Unlock()
		if att == nil || closed {
			return nil, nil, nil, fmt.Errorf("forwarded device %s is not attached on this device", d.payload.Name)
		}
		iface := executor.HostInterface{}
		if d.payload.Interface != nil {
			iface = *d.payload.Interface
		}
		n, i := att.Give(d.payload.Name, iface)
		nodes = append(nodes, n...)
		if len(n) > 0 {
			env = append(env, executor.ForwardedEnvEntry(d.payload.Name, d.payload.Kind, n[0].EffectiveTarget()))
		}
		if i != nil {
			ifaces = append(ifaces, *i)
			env = append(env, executor.ForwardedEnvEntry(d.payload.Name, d.payload.Kind, i.EffectiveTarget()))
		}
	}
	return nodes, ifaces, env, nil
}

// deviceSender writes a device frame on this session, at its negotiated
// version.
func (a *Agent) deviceSender(sess *deviceSession, handleID string) func(remote.FrameType, any) error {
	return func(t remote.FrameType, payload any) error {
		f, err := sess.frame(t, "", handleID, payload)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return sess.write(ctx, f)
	}
}

// tapNameFor derives a TAP name from a channel id: short enough for IFNAMSIZ,
// unpredictable to anything that cannot see the id, and prefixed so an
// operator reading `ip link` knows what made it.
func tapNameFor(channelID string) string {
	sum := sha256.Sum256([]byte(channelID))
	return "cfwd" + hex.EncodeToString(sum[:])[:10]
}

// deviceAttacher is the configured attacher or the host's own.
func (a *Agent) deviceAttacher() DeviceAttacher {
	if a.cfg.Devices != nil {
		return a.cfg.Devices
	}
	return hostDeviceAttacher{a: a}
}

// openDeviceLedger sweeps what a previous agent process left attached and
// opens this process's ledger. Never fatal: an agent that cannot keep a ledger
// still attaches devices, and loses only the sweep after a crash.
func (a *Agent) openDeviceLedger() {
	dir := filepath.Join(a.root, ledgerDirName)
	rep := deviceforward.SweepLedgers(dir, a.cfg.logf)
	if n := len(rep.Detached) + len(rep.Removed); n > 0 {
		a.cfg.logf("swept %d forwarded-device attachment(s) a previous agent left: %s", n,
			strings.Join(append(append([]string(nil), rep.Detached...), rep.Removed...), ", "))
	}
	for _, e := range rep.Errors {
		a.cfg.logf("warning: could not sweep a forwarded-device attachment a previous agent left: %s", e)
	}
	l, err := deviceforward.OpenLedger(dir, a.cfg.logf)
	if err != nil {
		a.cfg.logf("warning: forwarded devices will not be swept after a crash: %v", err)
		return
	}
	a.ledger = l
}

// hostDeviceAttacher attaches through this host's kernel.
type hostDeviceAttacher struct{ a *Agent }

func (h hostDeviceAttacher) Support() (bool, string, bool, string) {
	usb, usbIssue := true, ""
	if err := (deviceforward.VHCI{}).Available(); err != nil {
		usb, usbIssue = false, err.Error()
	}
	l2, l2Issue := true, ""
	switch {
	case os.Geteuid() != 0:
		l2, l2Issue = false, "moving a TAP into a sandbox's network namespace needs the agent to run as root"
	default:
		if f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0); err != nil {
			l2, l2Issue = false, fmt.Sprintf("cannot open /dev/net/tun: %v", err)
		} else {
			_ = f.Close()
			for _, tool := range []string{"ip", "nsenter"} {
				if _, err := exec.LookPath(tool); err != nil {
					l2, l2Issue = false, tool+" is not installed"
					break
				}
			}
		}
	}
	return usb, usbIssue, l2, l2Issue
}

func (h hostDeviceAttacher) AttachUSB(ctx context.Context, stream io.ReadWriteCloser, busid string) (AttachedDevice, error) {
	imp, err := deviceforward.ImportUSB(ctx, stream, busid, deviceforward.ImportOptions{
		SysfsRoot: h.a.cfg.SysfsRoot,
		DevRoot:   h.a.cfg.DevRoot,
		Ledger:    h.a.ledger,
		Logf:      h.a.cfg.logf,
	})
	if err != nil {
		return nil, err
	}
	return usbAttached{imp}, nil
}

func (h hostDeviceAttacher) AttachL2(stream io.ReadWriteCloser, tap string) (AttachedDevice, error) {
	id := h.a.ledger.Add(deviceforward.LedgerEntry{Kind: deviceforward.LedgerTAP, TAP: tap})
	b, err := deviceforward.BridgeTAP(stream, tap)
	if err != nil {
		h.a.ledger.Remove(id)
		return nil, err
	}
	go func() {
		<-b.Done()
		h.a.ledger.Remove(id)
	}()
	return l2Attached{b}, nil
}

// usbAttached is an imported USB device.
type usbAttached struct{ imp *deviceforward.USBImport }

func (u usbAttached) Done() <-chan struct{} { return u.imp.Done() }
func (u usbAttached) Close() error          { return u.imp.Close() }
func (u usbAttached) Opened() remote.DeviceOpenedPayload {
	return remote.DeviceOpenedPayload{VHCIPort: u.imp.Port, LocalBusID: u.imp.Device.Port, Node: u.imp.Device.Node}
}
func (u usbAttached) Give(name string, _ executor.HostInterface) ([]executor.HostDevice, *executor.HostInterface) {
	return u.imp.HostDevices(name), nil
}

// l2Attached is a TAP bridged to a forwarded segment.
type l2Attached struct{ b *deviceforward.TAPBridge }

func (l l2Attached) Done() <-chan struct{} { return l.b.Done() }
func (l l2Attached) Close() error          { return l.b.Close() }
func (l l2Attached) Opened() remote.DeviceOpenedPayload {
	return remote.DeviceOpenedPayload{TAP: l.b.Name()}
}
func (l l2Attached) Give(name string, iface executor.HostInterface) ([]executor.HostDevice, *executor.HostInterface) {
	iface.Name = name
	iface.Source = l.b.Name()
	if iface.Target == "" {
		iface.Target = "fwd0"
	}
	return nil, &iface
}
