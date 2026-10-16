package remote

// devicemux.go is the hub half of forwarded devices on an executor agent (Task
// 20430): opening a device channel for a workload about to start, splicing it
// to the forwarder's stream, and routing the channel's frames.

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// deviceOpenTimeout bounds one device_open round trip. The agent's side
// includes the USB/IP handshake through the forwarder and the device's
// enumeration on the agent's host, which is seconds, not milliseconds.
const deviceOpenTimeout = 60 * time.Second

// deviceWriteTimeout bounds one device_data frame write, so a wedged uplink
// ends the channel rather than pinning the relay.
const deviceWriteTimeout = 15 * time.Second

// CanTakeForwardedDevices implements executor.ForwardedDeviceTaker for the
// device's own executor.
func (e *Executor) CanTakeForwardedDevices(kinds []string) error {
	sess := e.currentSession()
	if sess == nil {
		return fmt.Errorf("%w: agent %s (%s) is not connected", ErrAgentUnreachable, e.id, e.name)
	}
	sandbox, err := e.opts.sandboxSettings()
	if err != nil {
		return fmt.Errorf("%w: agent %s (%s): %w", ErrSandboxModeUnavailable, e.id, e.name, err)
	}
	return e.canTakeForwardedDevices(sess, kinds, sandbox.Normalize())
}

// CanTakeForwardedDevices implements executor.ForwardedDeviceTaker for a
// virtual executor: its sandbox, its parent's device.
func (v *Virtual) CanTakeForwardedDevices(kinds []string) error {
	sess := v.parent.currentSession()
	if sess == nil {
		return fmt.Errorf("%w: agent %s (%s), the device of virtual executor %s, is not connected",
			ErrAgentUnreachable, v.parent.id, v.parent.name, v.id)
	}
	spec, err := v.Spec()
	if err != nil {
		return err
	}
	return v.parent.canTakeForwardedDevices(sess, kinds, spec.Sandbox.Normalize())
}

// canTakeForwardedDevices is the placement rule for a dispatch carrying
// forwarded devices of these kinds, under this sandbox.
func (e *Executor) canTakeForwardedDevices(sess *Session, kinds []string, sandbox executor.SandboxSettings) error {
	if !SupportsForwardedDevices(sess.Version()) {
		return fmt.Errorf("%w: %s", ErrForwardedDevicesUnsupported, executor.NeedsProtocol(
			e.subject(), sess.Version(), MinForwardedDeviceVersion,
			"to attach a device a device forwarder carries to this project's sandbox",
			"Or unbind the forwarder from this project."))
	}
	if sandbox.Mode != executor.SandboxModeContainer {
		return fmt.Errorf("%w: %s runs payloads on the device's host, so a forwarded device would be "+
			"attached to the whole machine rather than given to one sandbox; set the executor's sandbox "+
			"mode to container, or bind the project to a virtual executor of this device",
			ErrForwardedDevicesUnsupported, e.subject())
	}
	if executor.IsKernelIsolatedRuntime(sandbox.Runtime) {
		return fmt.Errorf("%w: %s runs sandboxes under %q, which cannot be given a host device or "+
			"interface; choose runc for the executor this project uses",
			ErrForwardedDevicesUnsupported, e.subject(), sandbox.Runtime)
	}
	caps := sess.Capabilities()
	for _, k := range kinds {
		switch k {
		case executor.ForwardedUSB:
			if !caps.ForwardedUSB {
				return fmt.Errorf("%w: %s cannot attach a forwarded USB device: %s",
					ErrForwardedDevicesUnsupported, e.subject(), orUnknown(caps.ForwardedUSBIssue))
			}
		case executor.ForwardedL2:
			if !caps.ForwardedL2 {
				return fmt.Errorf("%w: %s cannot attach a forwarded network segment: %s",
					ErrForwardedDevicesUnsupported, e.subject(), orUnknown(caps.ForwardedL2Issue))
			}
		}
	}
	return nil
}

func orUnknown(issue string) string {
	if strings.TrimSpace(issue) == "" {
		return "the device did not say why"
	}
	return issue
}

// openForwardedDevices opens one device channel per forwarded device for
// handleID and waits until the agent has attached each. On any failure every
// channel opened so far is closed and the error names the device.
func (e *Executor) openForwardedDevices(ctx context.Context, sess *Session, handleID string, devs []executor.ForwardedDevice) ([]*DeviceStream, error) {
	var opened []*DeviceStream
	fail := func(err error) ([]*DeviceStream, error) {
		for _, d := range opened {
			d.Abort("the workload did not start")
		}
		return nil, err
	}
	for _, fd := range devs {
		ds, err := e.openForwardedDevice(ctx, sess, handleID, fd)
		if err != nil {
			return fail(fmt.Errorf("%w: %s: %w", ErrForwardedDevicesUnsupported, fd.Describe(), err))
		}
		opened = append(opened, ds)
	}
	return opened, nil
}

func (e *Executor) openForwardedDevice(ctx context.Context, sess *Session, handleID string, fd executor.ForwardedDevice) (*DeviceStream, error) {
	octx, cancel := context.WithTimeout(ctx, deviceOpenTimeout)
	defer cancel()
	stream, err := fd.Open(octx)
	if err != nil {
		return nil, fmt.Errorf("open the forwarder's device: %w", err)
	}
	p := DeviceOpenPayload{
		ChannelID:   newCorrelationID(),
		Kind:        fd.Kind,
		Name:        fd.Name,
		Label:       fd.Label,
		ForwarderID: fd.ForwarderID,
		BindingID:   fd.BindingID,
	}
	switch fd.Kind {
	case executor.ForwardedUSB:
		p.BusID = stream.BusID
	case executor.ForwardedL2:
		iface := fd.Interface
		iface.Name = fd.Name
		p.Interface = &iface
	}
	if err := p.Validate(); err != nil {
		_ = stream.Close()
		return nil, err
	}
	ds, _, err := sess.openDevice(octx, handleID, p, stream)
	if err != nil {
		return nil, err
	}
	return ds, nil
}

// openDevice registers a device channel, splices stream into it, and sends
// device_open, waiting for the agent's device_opened. The channel is spliced
// before the request goes out because the device's protocol starts at once —
// the agent's USB/IP import request, a segment's frames — and must find it.
func (s *Session) openDevice(ctx context.Context, handleID string, p DeviceOpenPayload, stream io.ReadWriteCloser) (*DeviceStream, DeviceOpenedPayload, error) {
	ds := NewDeviceStream(p.ChannelID, s.deviceSender(handleID), func() { s.devices.remove(p.ChannelID) })
	if !s.devices.add(ds) {
		_ = stream.Close()
		ds.Finish("too many device channels on this connection")
		return nil, DeviceOpenedPayload{}, fmt.Errorf("%w: this agent connection already carries %d device channels",
			ErrAgentBusy, maxDeviceChannelsPerConnection)
	}
	go spliceDevice(ds, stream)

	frame, err := s.frame(TypeDeviceOpen, newCorrelationID(), handleID, p)
	if err != nil {
		ds.Abort("the device channel could not be opened")
		return nil, DeviceOpenedPayload{}, err
	}
	reply, err := s.request(ctx, frame, TypeDeviceOpened)
	if err != nil {
		ds.Abort("the agent did not attach the device")
		return nil, DeviceOpenedPayload{}, err
	}
	opened, err := DecodeDeviceOpened(reply)
	if err != nil {
		ds.Abort("the agent's answer did not parse")
		return nil, DeviceOpenedPayload{}, err
	}
	select {
	case <-ds.Done():
		// The relay ended while the agent attached: the forwarder went away,
		// or a revocation closed it. The device is not there to start with.
		return nil, DeviceOpenedPayload{}, fmt.Errorf("the device channel ended before the workload started: %s", ds.Reason())
	default:
	}
	return ds, opened, nil
}

// deviceSender writes a device frame for handleID on this session.
func (s *Session) deviceSender(handleID string) func(FrameType, any) error {
	return func(t FrameType, payload any) error {
		f, err := s.frame(t, "", handleID, payload)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), deviceWriteTimeout)
		defer cancel()
		return s.write(ctx, f)
	}
}

// handleDeviceFrame routes one inbound device frame. Unknown channel ids are
// dropped, as attach drops unknown session ids: the expected shape of a race,
// and an answer would tell a device that guessed an id whether it was right.
func (s *Session) handleDeviceFrame(ctx context.Context, f Frame) {
	switch f.Type {
	case TypeDeviceData:
		p, err := DecodeDeviceData(f)
		if err != nil {
			writeError(ctx, s.conn, f.ID, CodeProtocol, err.Error())
			return
		}
		if ds := s.devices.get(p.ChannelID); ds != nil {
			ds.Deliver(p.Data)
		}
	case TypeDeviceClose:
		p, err := DecodeDeviceClose(f)
		if err != nil {
			writeError(ctx, s.conn, f.ID, CodeProtocol, err.Error())
			return
		}
		if ds := s.devices.get(p.ChannelID); ds != nil {
			reason := strings.TrimSpace(p.Reason)
			if reason == "" {
				reason = "the agent closed the device channel"
			}
			ds.Finish(clipText(reason, 512))
		}
	case TypeDeviceOpened:
		s.deliver(f)
	}
}

// closeDeviceChannels ends every device channel on this connection.
func (s *Session) closeDeviceChannels(reason string) {
	for _, ds := range s.devices.drain() {
		ds.Finish(reason)
	}
}

// spliceDevice relays between a device channel and the forwarder's stream
// until either ends, then closes both.
func spliceDevice(ds *DeviceStream, stream io.ReadWriteCloser) {
	var once sync.Once
	stop := func(reason string) {
		once.Do(func() {
			_ = stream.Close()
			ds.Abort(reason)
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, ds)
		stop(relayEndReason("the agent's side"))
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ds, stream)
		// The hub ends the forwarder's side on purpose — a revocation, the
		// run's end — and a stream that knows why says so, so the agent's
		// log and the device_close name the cause rather than an EOF.
		if r, ok := stream.(interface{ EndReason() string }); ok {
			if why := r.EndReason(); why != "" {
				stop(why)
				return
			}
		}
		stop(relayEndReason("the forwarder's side"))
	}()
	wg.Wait()
}

// relayEndReason says which side ended a relay. The transport's own error is
// left out: a stream closed on purpose surfaces as whatever the closed
// connection happened to report ("context canceled", "use of closed network
// connection"), which says nothing to the operator reading the device's log;
// a stream that knows why it was ended says so through EndReason instead.
func relayEndReason(side string) string {
	return side + " ended the device stream"
}
