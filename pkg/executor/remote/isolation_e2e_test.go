package remote_test

import (
	"context"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// TestLoopbackIsolationProbeReachesTheAgent drives the frame pair end to end
// over a real WebSocket: the hub asks a real agent to probe its configured
// runtime, the agent answers through its probe — here a capture of gVisor on
// sgx, since a test machine's engine is not this test's subject — and the hub
// classifies what came back.
func TestLoopbackIsolationProbeReachesTheAgent(t *testing.T) {
	var (
		mu  sync.Mutex
		got []executor.SandboxSettings
	)
	sandbox := executor.SandboxSettings{Mode: executor.SandboxModeContainer, Runtime: "runsc", Engine: "docker"}
	lb := newLoopbackHub(t, func(o *remote.HubOptions) {
		o.SandboxSource = func(string) func() (executor.SandboxSettings, error) {
			return func() (executor.SandboxSettings, error) { return sandbox, nil }
		}
	}, func(c *agent.Config) {
		c.IsolationProbe = func(_ context.Context, s executor.SandboxSettings) remote.IsolationEvidencePayload {
			mu.Lock()
			got = append(got, s)
			mu.Unlock()
			ev, host := sgxRunsc, sgxKernel
			return remote.IsolationEvidencePayload{Evidence: &ev, Host: &host, EngineKernel: sgxKernel.Release,
				Engine: "docker"}
		}
	})
	ex := lb.executor(t)
	probe, err := ex.ProbeIsolation(probeCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if v := probe.Verdict(); v.Kind != isolationprobe.KindUserspaceKernel {
		t.Fatalf("verdict = %s (%s), want userspace-kernel", v.Kind, v.Detail)
	}
	if isolationprobe.Judge(executor.IsolationClaim("runsc"), probe.Verdict().Kind) != isolationprobe.StatusVerified {
		t.Error("runsc found to be gVisor must verify its claim")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Runtime != "runsc" || got[0].Engine != "docker" {
		t.Fatalf("the agent was asked to probe %+v", got)
	}
}
