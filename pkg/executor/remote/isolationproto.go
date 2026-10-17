package remote

// isolationproto.go lets the hub verify the runtime a device's sandboxes run
// under (Task 20439, protocol v26).
//
// A device's Virtualized and KernelIsolated come from the runtime name an admin
// typed into its sandbox settings, and from /dev/kvm being openable. Neither
// says what the runtime is: a daemon.json entry called "kata" whose path is
// runc passes both. So the hub asks the device to run `cloop isolation-probe`
// in a sandbox under the runtime it names, and compares what the kernel serving
// that sandbox says about itself with the device's own kernel, which the agent
// reads beside it.
//
// What the device runs is fixed on the device. The request names a sandbox —
// engine, runtime, image, the settings a start frame for the same executor
// carries — and never an argv: the agent binds its own binary into that sandbox
// read-only and runs it in probe mode, so neither the hub nor the image chooses
// what executes there.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

const (
	// TypeIsolationProbe (control plane → agent) asks the device to run the
	// isolation probe in a sandbox. Added in v26.
	TypeIsolationProbe FrameType = "isolation_probe"
	// TypeIsolationEvidence (agent → control plane) answers with what the
	// probe saw, or why it could not run.
	TypeIsolationEvidence FrameType = "isolation_evidence"
)

// MinIsolationProbeVersion is the first protocol whose agents answer the
// isolation probe and report their own kernel at hello.
//
// Gated on the hub's side: an older agent has no case for the request and
// would never answer it, so the hub does not ask, and records the device's
// runtime as unverified with the upgrade named.
const MinIsolationProbeVersion = 26

// SupportsIsolationProbe reports whether an agent speaking this protocol
// version answers the isolation probe.
func SupportsIsolationProbe(version int) bool { return version >= MinIsolationProbeVersion }

// IsolationProbeTimeout bounds a probe on the device: a Kata VM's boot or a
// gVisor sandbox's start, and the probe itself.
const IsolationProbeTimeout = 3 * time.Minute

// IsolationProbeRequest names the sandbox to probe in.
type IsolationProbeRequest struct {
	// Sandbox is the executor's sandbox settings: its own for a device, a
	// virtual executor's for one of those. The agent refuses anything but
	// container mode — host mode has no runtime to verify.
	Sandbox executor.SandboxSettings `json:"sandbox"`
}

// IsolationEvidencePayload is the device's answer.
type IsolationEvidencePayload struct {
	// Evidence is what the probe read inside the sandbox; nil when Error is
	// set.
	Evidence *isolationprobe.Evidence `json:"evidence,omitempty"`
	// Host is the device's own kernel, read when the probe ran.
	Host *isolationprobe.Evidence `json:"host,omitempty"`
	// EngineKernel is the kernel release the device's container engine
	// reports for its machine.
	EngineKernel string `json:"engine_kernel,omitempty"`
	// Engine and Image are what the sandbox ran through and in.
	Engine string `json:"engine,omitempty"`
	Image  string `json:"image,omitempty"`
	// Error is why the probe could not run.
	Error string `json:"error,omitempty"`
}

// maxIsolationText bounds the free-text fields of an answer.
const maxIsolationText = 2048

// DecodeIsolationProbeRequest decodes a probe request, normalizing and
// validating its sandbox: the agent treats it as it treats a start frame's.
func DecodeIsolationProbeRequest(f Frame) (IsolationProbeRequest, error) {
	var p IsolationProbeRequest
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	p.Sandbox = p.Sandbox.Normalize()
	if err := p.Sandbox.Validate(); err != nil {
		return p, fmt.Errorf("%w: isolation probe sandbox: %v", ErrProtocol, err)
	}
	if p.Sandbox.Mode != executor.SandboxModeContainer {
		return p, fmt.Errorf("%w: an isolation probe runs in a container sandbox, and the request names "+
			"mode %q", ErrProtocol, p.Sandbox.Mode)
	}
	return p, nil
}

// DecodeIsolationEvidence decodes and bounds a device's answer. Its strings
// come from a sandbox's kernel and a device's engine, and are stored and
// rendered by the hub.
func DecodeIsolationEvidence(f Frame) (IsolationEvidencePayload, error) {
	var p IsolationEvidencePayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	p.Evidence = cleanHostKernel(p.Evidence)
	p.Host = cleanHostKernel(p.Host)
	p.EngineKernel = boundText(p.EngineKernel, 128)
	p.Engine = boundText(p.Engine, 64)
	p.Image = boundText(p.Image, 512)
	p.Error = boundText(p.Error, maxIsolationText)
	if p.Error == "" && p.Evidence == nil {
		return p, fmt.Errorf("%w: an isolation_evidence frame carries neither evidence nor an error", ErrProtocol)
	}
	return p, nil
}

// cleanHostKernel sanitizes evidence a device reported, and drops evidence
// that names no kernel at all.
func cleanHostKernel(e *isolationprobe.Evidence) *isolationprobe.Evidence {
	if e == nil {
		return nil
	}
	c := e.Sanitize()
	if c.IsZero() {
		return nil
	}
	return &c
}

// boundText trims s, drops control characters and bounds it.
func boundText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > n {
		s = s[:n]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// ErrIsolationProbeUnavailable reports a device the hub cannot probe: too old
// to be asked, or with no sandbox runtime to ask about.
var ErrIsolationProbeUnavailable = errors.New("remote: isolation probe unavailable")

// IsolationRuntime implements executor.IsolationClaimer: the runtime this
// device's sandboxes run under, and false when its payloads run on its host.
func (e *Executor) IsolationRuntime() (string, bool) {
	sandbox, err := e.opts.sandboxSettings()
	if err != nil || sandbox.Mode != executor.SandboxModeContainer {
		return "", false
	}
	return sandbox.Runtime, true
}

// ProbeIsolation implements executor.IsolationProber for the device itself.
func (e *Executor) ProbeIsolation(ctx context.Context) (executor.IsolationProbe, error) {
	sandbox, err := e.opts.sandboxSettings()
	if err != nil {
		return executor.IsolationProbe{}, fmt.Errorf("remote: read %s's sandbox settings: %w", e.id, err)
	}
	return e.probeIsolationWith(ctx, sandbox, e.subject())
}

// probeIsolationWith asks the device to probe a sandbox with these settings.
func (e *Executor) probeIsolationWith(ctx context.Context, sandbox executor.SandboxSettings, subject string) (executor.IsolationProbe, error) {
	sandbox = sandbox.Normalize()
	out := executor.IsolationProbe{Runtime: sandbox.Runtime, Image: sandbox.Image}
	if sandbox.Mode != executor.SandboxModeContainer {
		return out, fmt.Errorf("%w: %s runs payloads on the device's host, so there is no sandbox runtime "+
			"to probe", ErrIsolationProbeUnavailable, subject)
	}
	sess := e.currentSession()
	if sess == nil {
		return out, fmt.Errorf("%w: %s (%s) is not connected, so its runtime cannot be probed",
			ErrAgentUnreachable, e.id, e.name)
	}
	if v := sess.Version(); !SupportsIsolationProbe(v) {
		return out, fmt.Errorf("%w: %s", ErrIsolationProbeUnavailable, executor.NeedsProtocol(
			subject, v, MinIsolationProbeVersion, "to probe what its sandbox runtime really is", ""))
	}
	frame, err := sess.frame(TypeIsolationProbe, newCorrelationID(), "", IsolationProbeRequest{Sandbox: sandbox})
	if err != nil {
		return out, fmt.Errorf("remote: build isolation probe request for %s: %w", e.id, err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, IsolationProbeTimeout)
	defer cancel()
	reply, err := sess.request(reqCtx, frame, TypeIsolationEvidence)
	if err != nil {
		return out, fmt.Errorf("remote: ask %s (%s) to probe its runtime: %w", e.id, e.name, err)
	}
	p, err := DecodeIsolationEvidence(reply)
	if err != nil {
		return out, fmt.Errorf("remote: decode isolation evidence from %s: %w", e.id, err)
	}
	if p.Image != "" {
		out.Image = p.Image
	}
	out.Engine = p.Engine
	if p.Error != "" {
		return out, fmt.Errorf("the device could not run the probe: %s", p.Error)
	}
	host := p.Host
	if host == nil {
		// The hello's reading, when the answer carried none: the same kernel
		// unless the device rebooted, which would have reconnected the agent.
		host = e.AgentCapabilities().HostKernel
	}
	out.Evidence = *p.Evidence
	out.Reference = isolationprobe.Reference{Kernel: host, Source: isolationprobe.SourceAgent, EngineKernel: p.EngineKernel}
	return out, nil
}

// IsolationRuntime implements executor.IsolationClaimer for a virtual
// executor: its own runtime, always in a container.
func (v *Virtual) IsolationRuntime() (string, bool) {
	spec, err := v.Spec()
	if err != nil {
		return "", false
	}
	return spec.Sandbox.Runtime, spec.Sandbox.Mode == executor.SandboxModeContainer
}

// ProbeIsolation implements executor.IsolationProber for a virtual executor:
// the probe runs on its parent under the virtual executor's own sandbox
// settings.
func (v *Virtual) ProbeIsolation(ctx context.Context) (executor.IsolationProbe, error) {
	spec, err := v.Spec()
	if err != nil {
		return executor.IsolationProbe{}, fmt.Errorf("remote: read virtual executor %s's definition: %w", v.id, err)
	}
	return v.parent.probeIsolationWith(ctx, spec.Sandbox, fmt.Sprintf("virtual executor %s's device %s", v.id, v.parent.subject()))
}
