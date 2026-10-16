package remote_test

// Forwarded devices over the agent tunnel (Task 20430, protocol v22), with a
// real hub and a real agent and nothing else real: the forwarder is one end of
// a pipe the test holds, the agent's kernel attach is a fake that echoes, and
// its sandbox driver records what it was given. What is under test is the
// device channel — opened before the start, given to the sandbox, carrying
// bytes both ways, and torn down when the hub closes it mid-run, when the run
// ends, and for an agent too old to have one.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// fakeAttacher attaches devices with no kernel: each attachment answers PING
// with PONG on its stream.
type fakeAttacher struct {
	mu       sync.Mutex
	attached []*fakeAttachment
	usb      bool
}

func (f *fakeAttacher) Support() (bool, string, bool, string) {
	if !f.usb {
		return false, "vhci_hcd is not loaded", false, "no TAP"
	}
	return true, "", true, ""
}

func (f *fakeAttacher) AttachUSB(ctx context.Context, stream io.ReadWriteCloser, busid string) (agent.AttachedDevice, error) {
	a := &fakeAttachment{busid: busid, stream: stream, done: make(chan struct{})}
	go a.serve()
	f.mu.Lock()
	f.attached = append(f.attached, a)
	f.mu.Unlock()
	return a, nil
}

func (f *fakeAttacher) AttachL2(stream io.ReadWriteCloser, tap string) (agent.AttachedDevice, error) {
	return nil, errors.New("not in this test")
}

func (f *fakeAttacher) only(t *testing.T) *fakeAttachment {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.attached)
		var a *fakeAttachment
		if n > 0 {
			a = f.attached[0]
		}
		f.mu.Unlock()
		if n == 1 {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the agent attached no device")
	return nil
}

type fakeAttachment struct {
	busid  string
	stream io.ReadWriteCloser
	done   chan struct{}
	once   sync.Once
	closed atomic.Bool
}

func (a *fakeAttachment) serve() {
	buf := make([]byte, 64)
	for {
		n, err := a.stream.Read(buf)
		if n > 0 && bytes.Contains(buf[:n], []byte("PING")) {
			_, _ = a.stream.Write([]byte("PONG"))
		}
		if err != nil {
			a.end()
			return
		}
	}
}

func (a *fakeAttachment) end()                  { a.once.Do(func() { close(a.done) }) }
func (a *fakeAttachment) Done() <-chan struct{} { return a.done }
func (a *fakeAttachment) Close() error {
	a.closed.Store(true)
	_ = a.stream.Close()
	a.end()
	return nil
}
func (a *fakeAttachment) Opened() remote.DeviceOpenedPayload {
	return remote.DeviceOpenedPayload{VHCIPort: 7, LocalBusID: "9-9", Node: "/dev/bus/usb/009/009"}
}
func (a *fakeAttachment) Give(name string, _ executor.HostInterface) ([]executor.HostDevice, *executor.HostInterface) {
	return []executor.HostDevice{{Name: name, Source: "/dev/null", Target: "/dev/fwd-under-test"}}, nil
}

// recordingSandbox is the agent's "container driver": a host process, which
// records the devices the sandbox would have been given.
type recordingSandbox struct {
	*localprocess.Executor
	mu      sync.Mutex
	devices []executor.HostDevice
}

func (r *recordingSandbox) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	r.mu.Lock()
	r.devices = append(r.devices, spec.Devices...)
	r.mu.Unlock()
	spec.Devices = nil
	return r.Executor.Start(ctx, spec)
}

func (r *recordingSandbox) given() []executor.HostDevice {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]executor.HostDevice(nil), r.devices...)
}

// deviceLoopback is a hub whose executor runs payloads in a "container", and
// an agent that attaches devices with attacher.
func deviceLoopback(t *testing.T, attacher *fakeAttacher) (*loopback, *recordingSandbox) {
	t.Helper()
	sandbox := &recordingSandbox{Executor: localprocess.New("device-test")}
	lb := newLoopbackHub(t, func(o *remote.HubOptions) {
		o.SandboxSource = func(string) func() (executor.SandboxSettings, error) {
			return func() (executor.SandboxSettings, error) {
				return executor.SandboxSettings{Mode: executor.SandboxModeContainer}, nil
			}
		}
	}, func(c *agent.Config) {
		c.Devices = attacher
		c.ContainerDriver = func(executor.SandboxSettings) (executor.Executor, error) { return sandbox, nil }
	})
	lb.waitConnected(t)
	return lb, sandbox
}

// forwardedSpec is a workload with one forwarded USB device whose forwarder
// is the returned pipe end.
func forwardedSpec(argv ...string) (executor.Spec, net.Conn, *atomic.Int32) {
	hubEnd, fwdEnd := net.Pipe()
	opens := &atomic.Int32{}
	spec := executor.Spec{
		WorkDir: "device-target",
		Argv:    argv,
		ForwardedDevices: []executor.ForwardedDevice{{
			BindingID: "fbd_test", ForwarderID: "fwd-test", Name: "fwd-tablet", Kind: executor.ForwardedUSB,
			Label: "QEMU tablet",
			Open: func(context.Context) (executor.ForwardedStream, error) {
				opens.Add(1)
				return executor.ForwardedStream{ReadWriteCloser: hubEnd, BusID: "1-1"}, nil
			},
		}},
	}
	return spec, fwdEnd, opens
}

// TestForwardedDeviceReachesTheSandboxOverTheAgentTunnel: the agent attaches
// the device before the start, with the bus id the forwarder exports, gives it
// to the sandbox, and the device's bytes cross the tunnel both ways.
func TestForwardedDeviceReachesTheSandboxOverTheAgentTunnel(t *testing.T) {
	attacher := &fakeAttacher{usb: true}
	lb, sandbox := deviceLoopback(t, attacher)
	spec, fwd, opens := forwardedSpec("/bin/sh", "-c", "exec sleep 60")
	defer fwd.Close()

	ex := lb.executor(t)
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(context.Background(), h.ID, executor.SignalKill) })

	a := attacher.only(t)
	if a.busid != "1-1" || opens.Load() != 1 {
		t.Fatalf("attached bus id %q after %d opens; want the forwarder's 1-1, opened once", a.busid, opens.Load())
	}
	given := sandbox.given()
	if len(given) != 1 || given[0].Name != "fwd-tablet" || given[0].Target != "/dev/fwd-under-test" {
		t.Fatalf("the sandbox was given %+v; want the attached device under the binding's name", given)
	}

	if _, err := fwd.Write([]byte("PING")); err != nil {
		t.Fatalf("write from the forwarder: %v", err)
	}
	_ = fwd.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(fwd, got); err != nil || string(got) != "PONG" {
		t.Fatalf("the device's answer = %q, %v; want PONG back across the tunnel", got, err)
	}
}

// TestRevokedDeviceDetachesMidRun: the hub closing the forwarder's stream — a
// binding or forwarder revoked — detaches the device on the agent within
// seconds, while the run itself goes on.
func TestRevokedDeviceDetachesMidRun(t *testing.T) {
	attacher := &fakeAttacher{usb: true}
	lb, _ := deviceLoopback(t, attacher)
	spec, fwd, _ := forwardedSpec("/bin/sh", "-c", "exec sleep 60")

	ex := lb.executor(t)
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(context.Background(), h.ID, executor.SignalKill) })
	a := attacher.only(t)

	revokedAt := time.Now()
	_ = fwd.Close()
	// Detached means the agent closed the attachment — what takes the device
	// off its host — not merely that the attachment's stream ended.
	if !waitTrue(5*time.Second, a.closed.Load) {
		t.Fatal("the agent kept the device attached after the hub closed its stream")
	}
	t.Logf("detached %s after the stream closed", time.Since(revokedAt).Round(time.Millisecond))
	st, err := ex.Status(context.Background(), h.ID)
	if err != nil || st.State.Terminal() {
		t.Fatalf("the run ended with its device (%v, %v); only the device should go", st.State, err)
	}
}

// TestRunEndDetachesTheDeviceOnTheAgent: a workload that exits gives its
// device back on the agent and closes the stream to the forwarder.
func TestRunEndDetachesTheDeviceOnTheAgent(t *testing.T) {
	attacher := &fakeAttacher{usb: true}
	lb, _ := deviceLoopback(t, attacher)
	spec, fwd, _ := forwardedSpec("/bin/sh", "-c", "sleep 1; exit 0")
	defer fwd.Close()

	if _, err := lb.executor(t).Start(context.Background(), spec); err != nil {
		t.Fatalf("Start: %v", err)
	}
	a := attacher.only(t)
	if !waitTrue(15*time.Second, a.closed.Load) {
		t.Fatal("the agent kept the device after the run ended")
	}
	_ = fwd.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := fwd.Read(make([]byte, 8)); err == nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("the forwarder's stream stayed open after the run ended: %v", err)
	}
}

// TestAgentThatCannotAttachIsRefusedTheDevice: a device whose agent says it
// cannot attach USB is refused at dispatch, in the agent's words, and the
// forwarder's stream is never opened.
func TestAgentThatCannotAttachIsRefusedTheDevice(t *testing.T) {
	attacher := &fakeAttacher{usb: false}
	lb, _ := deviceLoopback(t, attacher)
	spec, fwd, opens := forwardedSpec("/bin/sh", "-c", "exit 0")
	defer fwd.Close()
	_, err := lb.executor(t).Start(context.Background(), spec)
	if !errors.Is(err, remote.ErrForwardedDevicesUnsupported) || !strings.Contains(err.Error(), "vhci_hcd") {
		t.Fatalf("Start = %v; want a refusal naming the agent's reason", err)
	}
	if opens.Load() != 0 {
		t.Fatal("the forwarder's stream was opened for a dispatch that was refused")
	}
}

// TestOldAgentIsRefusedForwardedDevices: an agent older than the device
// channel would ignore the start's device list and run the sandbox without the
// hardware, so the dispatch is refused naming the upgrade.
func TestOldAgentIsRefusedForwardedDevices(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeContainer}, nil)
	hello := helloAt(remote.MinForwardedDeviceVersion - 1)
	hello.Capabilities.ForwardedUSB = true
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	defer sess.Close()
	spec, fwd, opens := forwardedSpec("/bin/sh", "-c", "true")
	defer fwd.Close()
	spec.WorkDir = t.TempDir()
	_, err := ex.Start(context.Background(), spec)
	if !errors.Is(err, remote.ErrForwardedDevicesUnsupported) {
		t.Fatalf("Start = %v, want ErrForwardedDevicesUnsupported", err)
	}
	for _, want := range []string{"edge-1", "v21", "v22"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q: %q", want, err)
		}
	}
	if opens.Load() != 0 {
		t.Fatal("the forwarder's stream was opened for an agent that cannot take it")
	}
}

// TestHostModeExecutorIsRefusedForwardedDevices: an executor that runs
// payloads on the device's host has no sandbox to give a device to.
func TestHostModeExecutorIsRefusedForwardedDevices(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	hello := helloAt(remote.ProtocolVersion)
	hello.Capabilities.ForwardedUSB = true
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	defer sess.Close()
	spec, fwd, _ := forwardedSpec("/bin/sh", "-c", "true")
	defer fwd.Close()
	spec.WorkDir = t.TempDir()
	if _, err := ex.Start(context.Background(), spec); !errors.Is(err, remote.ErrForwardedDevicesUnsupported) ||
		!strings.Contains(err.Error(), "container") {
		t.Fatalf("Start = %v; want a refusal saying a container sandbox is needed", err)
	}
}

// waitTrue polls cond until it holds or d passes.
func waitTrue(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}
