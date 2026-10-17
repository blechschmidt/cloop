package remote_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// sgx's own kernel and what runc and runsc served a sandbox there, as the
// probe read them (pkg/isolationprobe/testdata holds the full captures).
var (
	sgxKernel = isolationprobe.Evidence{
		Schema: 1, Release: "6.8.0-79-generic", Version: "#79-Ubuntu SMP PREEMPT_DYNAMIC Tue Aug 12 14:42:46 UTC 2025",
		BootID: "2d725fb0-4ac8-4443-b68c-8c50313f7439", UptimeSeconds: 14460005, Hypervisor: true,
		DMIVendor: "Alibaba Cloud", DMIProduct: "Alibaba Cloud ECS",
	}
	sgxRunsc = isolationprobe.Evidence{
		Schema: 1, Release: "4.19.0-gvisor", Version: isolationprobe.GVisorBuildString,
		BootID: "e4bdf59a-6ddf-4e29-912c-36f0bd406295", UptimeSeconds: 0.04, Hypervisor: true,
		DMIProduct: "Alibaba Cloud ECS", GVisor: []string{"boot log \"Starting gVisor...\""},
	}
)

// answerIsolationProbe replies to the next isolation_probe request with what
// answer returns for it, and hands the test the request.
func answerIsolationProbe(t *testing.T, p *peer, answer func(remote.IsolationProbeRequest) remote.IsolationEvidencePayload) chan remote.IsolationProbeRequest {
	t.Helper()
	got := make(chan remote.IsolationProbeRequest, 1)
	go func() {
		f := p.readUntil(remote.TypeIsolationProbe)
		req, err := remote.DecodeIsolationProbeRequest(f)
		if err != nil {
			t.Errorf("decode isolation probe request: %v", err)
			close(got)
			return
		}
		got <- req
		reply, err := remote.NewFrameAt(remote.ProtocolVersion, remote.TypeIsolationEvidence, f.ID, "", answer(req))
		if err != nil {
			t.Errorf("build evidence frame: %v", err)
			return
		}
		p.write(reply)
	}()
	return got
}

func probeCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestIsolationProbe_ADeviceWhoseKataIsRunc: the device is told its sandboxes
// run under "kata", and the probe it runs reads the device's own boot ID. The
// hub gets back exactly what classifies that as the host kernel.
func TestIsolationProbe_ADeviceWhoseKataIsRunc(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeContainer, Runtime: "kata",
		Image: "ghcr.io/blechschmidt/cloop-harness:latest"}, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	if rt, ok := ex.IsolationRuntime(); !ok || rt != "kata" {
		t.Fatalf("IsolationRuntime = %q, %v", rt, ok)
	}

	reqs := answerIsolationProbe(t, p, func(remote.IsolationProbeRequest) remote.IsolationEvidencePayload {
		runc := sgxKernel // runc shares the host's kernel, boot ID and all
		host := sgxKernel
		return remote.IsolationEvidencePayload{Evidence: &runc, Host: &host, EngineKernel: sgxKernel.Release,
			Engine: "docker", Image: "ghcr.io/blechschmidt/cloop-harness@sha256:" + strings.Repeat("b", 64)}
	})
	probe, err := ex.ProbeIsolation(probeCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	req := <-reqs
	if req.Sandbox.Runtime != "kata" || req.Sandbox.Mode != executor.SandboxModeContainer {
		t.Errorf("the request named %+v, want the executor's own sandbox", req.Sandbox)
	}
	if v := probe.Verdict(); v.Kind != isolationprobe.KindHostKernel {
		t.Fatalf("verdict = %s (%s), want host-kernel", v.Kind, v.Detail)
	}
	if probe.Reference.Source != isolationprobe.SourceAgent || probe.Runtime != "kata" ||
		!strings.Contains(probe.Image, "@sha256:") {
		t.Errorf("probe = %+v", probe)
	}
}

// TestIsolationProbe_AVirtualExecutorProbesItsOwnRuntime: a virtual executor's
// sandbox is its own, so its probe names its runtime, not its parent's.
func TestIsolationProbe_AVirtualExecutorProbesItsOwnRuntime(t *testing.T) {
	parent := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	p, _ := connect(t, parent, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	if _, ok := parent.IsolationRuntime(); ok {
		t.Error("a device in host mode claims a sandbox runtime")
	}
	v, err := remote.NewVirtual(parent, "virt-1", "gvisor box", func() (executor.VirtualSpec, error) {
		return executor.VirtualSpec{Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer, Runtime: "runsc"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	reqs := answerIsolationProbe(t, p, func(remote.IsolationProbeRequest) remote.IsolationEvidencePayload {
		ev, host := sgxRunsc, sgxKernel
		return remote.IsolationEvidencePayload{Evidence: &ev, Host: &host, EngineKernel: sgxKernel.Release}
	})
	probe, err := v.ProbeIsolation(probeCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if req := <-reqs; req.Sandbox.Runtime != "runsc" {
		t.Errorf("the request named runtime %q, want the virtual executor's runsc", req.Sandbox.Runtime)
	}
	if got := probe.Verdict().Kind; got != isolationprobe.KindUserspaceKernel {
		t.Fatalf("verdict = %s, want userspace-kernel", got)
	}
}

// TestIsolationProbe_AnOlderAgentIsNotAsked: a v25 agent has no handler and
// would never answer. The hub does not ask, and says what is needed.
func TestIsolationProbe_AnOlderAgentIsNotAsked(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeContainer, Runtime: "kata"}, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.MinIsolationProbeVersion-1), nil)
	_, err := ex.ProbeIsolation(probeCtx(t))
	if !errors.Is(err, remote.ErrIsolationProbeUnavailable) {
		t.Fatalf("err = %v, want ErrIsolationProbeUnavailable", err)
	}
	if !strings.Contains(err.Error(), "speaks protocol v25, and the hub needs v26") {
		t.Errorf("error %q should name both protocols", err)
	}
	// Nothing was sent: a heartbeat round trip is the only traffic.
	hb, _ := remote.NewFrame(remote.TypeHeartbeat, "hb", "", remote.HeartbeatPayload{})
	p.write(hb)
	if f := p.readUntil(remote.TypeHeartbeatAck); f.Type != remote.TypeHeartbeatAck {
		t.Fatalf("unexpected %s", f.Type)
	}
}

// TestIsolationProbe_FailuresAreNotEvidence: an answer carrying an error is a
// failed probe, never a verdict; so is a device that is not connected, and one
// whose payloads run on its host.
func TestIsolationProbe_FailuresAreNotEvidence(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeContainer, Runtime: "kata"}, nil)
	if _, err := ex.ProbeIsolation(probeCtx(t)); !errors.Is(err, remote.ErrAgentUnreachable) {
		t.Fatalf("disconnected: err = %v", err)
	}
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	answerIsolationProbe(t, p, func(remote.IsolationProbeRequest) remote.IsolationEvidencePayload {
		return remote.IsolationEvidencePayload{Error: "docker: unknown runtime specified kata"}
	})
	if _, err := ex.ProbeIsolation(probeCtx(t)); err == nil || !strings.Contains(err.Error(), "unknown runtime") {
		t.Fatalf("err = %v, want the device's reason", err)
	}

	host := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	if _, err := host.ProbeIsolation(probeCtx(t)); !errors.Is(err, remote.ErrIsolationProbeUnavailable) {
		t.Fatalf("host mode: err = %v", err)
	}
}

// TestIsolationProbeRequestNamesASandboxNotAProgram: the request may say which
// sandbox to probe in and nothing about what runs there — the agent's own
// binary in probe mode is fixed on the device. A field added here that could
// carry a program, an argument or an environment fails this test.
func TestIsolationProbeRequestNamesASandboxNotAProgram(t *testing.T) {
	typ := reflect.TypeOf(remote.IsolationProbeRequest{})
	if typ.NumField() != 1 || typ.Field(0).Type != reflect.TypeOf(executor.SandboxSettings{}) {
		t.Fatalf("IsolationProbeRequest has fields %v; it may carry the sandbox settings and nothing else", typ)
	}
	for i := 0; i < reflect.TypeOf(executor.SandboxSettings{}).NumField(); i++ {
		name := strings.ToLower(reflect.TypeOf(executor.SandboxSettings{}).Field(i).Name)
		for _, bad := range []string{"argv", "arg", "command", "env", "script", "entrypoint"} {
			if name == bad {
				t.Errorf("SandboxSettings.%s would let a probe request choose what the device runs", name)
			}
		}
	}
	// And the agent refuses a request for host mode outright.
	f, _ := remote.NewFrame(remote.TypeIsolationProbe, "x", "", remote.IsolationProbeRequest{
		Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeHost}})
	if _, err := remote.DecodeIsolationProbeRequest(f); err == nil {
		t.Error("a host-mode probe request decoded")
	}
}

// TestDecodeIsolationEvidenceBoundsTheAnswer: a device's answer is stored and
// rendered by the hub.
func TestDecodeIsolationEvidenceBoundsTheAnswer(t *testing.T) {
	ev := sgxRunsc
	ev.Release = "4.19.0-gvisor\x1b[2J" + strings.Repeat("x", 5000)
	f, _ := remote.NewFrame(remote.TypeIsolationEvidence, "x", "", remote.IsolationEvidencePayload{
		Evidence: &ev, Error: "", Image: strings.Repeat("i", 4000), EngineKernel: "6.8\n0"})
	p, err := remote.DecodeIsolationEvidence(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(p.Evidence.Release, '\x1b') || len(p.Evidence.Release) > 512 ||
		len(p.Image) > 512 || strings.Contains(p.EngineKernel, "\n") {
		t.Fatalf("answer not bounded: %+v", p)
	}
	empty, _ := remote.NewFrame(remote.TypeIsolationEvidence, "x", "", remote.IsolationEvidencePayload{})
	if _, err := remote.DecodeIsolationEvidence(empty); !errors.Is(err, remote.ErrProtocol) {
		t.Fatalf("an answer with neither evidence nor an error: err = %v", err)
	}
}

// TestHelloCarriesTheHostKernel: the device's kernel reaches the hub at hello,
// sanitized, and a reading naming no kernel is dropped.
func TestHelloCarriesTheHostKernel(t *testing.T) {
	h := defaultHello()
	k := sgxKernel
	k.DMIVendor = "Alibaba\x00Cloud"
	h.Capabilities.HostKernel = &k
	f, _ := remote.NewFrame(remote.TypeHello, "hello", "", h)
	got, err := remote.DecodeHello(f)
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities.HostKernel == nil || got.Capabilities.HostKernel.BootID != sgxKernel.BootID ||
		strings.ContainsRune(got.Capabilities.HostKernel.DMIVendor, 0) {
		t.Fatalf("HostKernel = %+v", got.Capabilities.HostKernel)
	}
	h.Capabilities.HostKernel = &isolationprobe.Evidence{Unreadable: []string{"uname: not Linux"}}
	f, _ = remote.NewFrame(remote.TypeHello, "hello", "", h)
	if got, _ := remote.DecodeHello(f); got.Capabilities.HostKernel != nil {
		t.Fatalf("an empty reading survived: %+v", got.Capabilities.HostKernel)
	}
}
