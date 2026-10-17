package agent

// isolation.go answers the hub's isolation probe (Task 20439, protocol v26):
// run `cloop isolation-probe` in a sandbox under the runtime the hub names and
// send back what the kernel serving it said, with this machine's own kernel
// beside it.
//
// The sandbox is built by the same driver a start frame for those settings
// gets, so the probe measures the runtime the device's workloads really run
// under. What runs in it is this agent's own binary, bound in read-only by the
// container driver — the request names a sandbox and nothing else.

import (
	"context"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// isolationProber is what a container driver offers the probe.
type isolationProber interface {
	RunIsolationProbe(ctx context.Context, po container.ProbeOptions) (executor.IsolationProbe, error)
	Runtime() container.Runtime
}

// hostKernel is this machine's own kernel for the hello, or nil off Linux.
func hostKernel() *isolationprobe.Evidence {
	e := isolationprobe.Collect()
	if e.IsZero() {
		return nil
	}
	return &e
}

// handleIsolationProbe answers one isolation_probe frame.
func (a *Agent) handleIsolationProbe(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	defer func() {
		if r := recover(); r != nil {
			a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, fmt.Sprintf("panic: %v", r))
		}
	}()
	req, err := remote.DecodeIsolationProbeRequest(frame)
	if err != nil {
		a.reply(ctx, sess, remote.TypeIsolationEvidence, frame.ID, "", remote.IsolationEvidencePayload{
			Error: "refusing the probe request: " + err.Error(),
		})
		return
	}
	a.reply(ctx, sess, remote.TypeIsolationEvidence, frame.ID, "", a.runIsolationProbe(ctx, req.Sandbox))
}

// runIsolationProbe runs the probe in a sandbox with these settings.
func (a *Agent) runIsolationProbe(ctx context.Context, s executor.SandboxSettings) remote.IsolationEvidencePayload {
	if a.cfg.IsolationProbe != nil {
		return a.cfg.IsolationProbe(ctx, s)
	}
	out := remote.IsolationEvidencePayload{Engine: s.Engine, Image: s.Image}
	d, err := a.drivers.driverFor(s, a.local)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	prober, ok := d.(isolationProber)
	if !ok {
		out.Error = fmt.Sprintf("this device's driver for %s cannot run the isolation probe", s.Describe())
		return out
	}
	out.Engine = prober.Runtime().Name
	// The agent's own work root, because the engine must see the probe's
	// throwaway directory at the same path, and a service unit's /tmp is its
	// own (PrivateTmp).
	p, err := prober.RunIsolationProbe(ctx, container.ProbeOptions{
		Source:   isolationprobe.SourceAgent,
		StageDir: a.root,
	})
	if p.Image != "" {
		out.Image = p.Image
	}
	if err != nil {
		out.Error = err.Error()
		return out
	}
	ev := p.Evidence
	out.Evidence = &ev
	out.Host = p.Reference.Kernel
	out.EngineKernel = p.Reference.EngineKernel
	return out
}
