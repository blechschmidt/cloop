package agent

// Tests for the device-side driver selection (Task 20307).
//
// The test that matters is TestDriverFor_ContainerModeWithoutAnEngineRefuses. The
// rest of this feature is plumbing; that one is the security property. If a
// future change makes the driver fall back to the host process when a container
// cannot be started, every layer above goes on reporting the containment an admin
// selected while payloads run with the agent's own privileges — and nothing in
// the transcript, the fleet view or the audit trail would say so.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
)

// hostDriver is a stand-in for the agent's localprocess executor. Using the real
// one would work, but these tests never start anything — they are about which
// driver is chosen — and a fake makes "the host driver was returned" an identity
// check rather than a type assertion.
type hostDriver struct{ payloadDriver }

func TestDriverFor_HostAndUnsetBothUseTheHostDriver(t *testing.T) {
	t.Parallel()
	cache := newDriverCache()
	host := &hostDriver{}

	for _, s := range []executor.SandboxSettings{
		{},                               // unset: whatever the device did before
		{Mode: executor.SandboxModeHost}, // chosen explicitly
	} {
		got, err := cache.driverFor(s, host)
		if err != nil {
			t.Fatalf("driverFor(%+v) = %v, want the host driver", s, err)
		}
		if got != payloadDriver(host) {
			t.Errorf("driverFor(%+v) returned a different driver; host and unset must both "+
				"resolve to the caller's host executor", s)
		}
	}
}

// TestDriverFor_ContainerModeWithoutAnEngineRefuses is the point of the feature.
//
// PATH is emptied so no container engine can be resolved, which is the state of
// an edge device that has none installed — exactly the case where a silent
// fallback would remove a boundary an admin believes in.
func TestDriverFor_ContainerModeWithoutAnEngineRefuses(t *testing.T) {
	// Not parallel: it mutates PATH for the process.
	t.Setenv("PATH", t.TempDir())

	cache := newDriverCache()
	host := &hostDriver{}

	got, err := cache.driverFor(executor.SandboxSettings{
		Mode: executor.SandboxModeContainer,
	}, host)

	if err == nil {
		t.Fatalf("driverFor returned a driver (%T) for container mode on a device with no "+
			"container engine — a payload started on it would run on the host while the hub "+
			"reports containment", got)
	}
	if got != nil {
		t.Errorf("driverFor returned both a driver and an error; the caller checks the error " +
			"but a non-nil driver invites a future caller not to")
	}
	// The message travels back to the hub as the start failure an operator reads,
	// and the fix is on a device they may not be logged in to, so it has to name
	// both what was asked for and what to do.
	for _, want := range []string{"container", "host"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q; an operator cannot act on it", err, want)
		}
	}
}

// TestDriverFor_RevalidatesWhatTheHubSent covers the trust boundary. The hub
// validates before storing and again before sending, but this side is a machine
// taking instructions over a socket: the engine name becomes a program it
// executes, so "the sender checked" is not a property it may rely on.
func TestDriverFor_RevalidatesWhatTheHubSent(t *testing.T) {
	t.Parallel()
	cache := newDriverCache()
	host := &hostDriver{}

	for _, s := range []executor.SandboxSettings{
		{Mode: executor.SandboxModeContainer, Engine: "/usr/bin/anything"},
		{Mode: executor.SandboxModeContainer, Runtime: "../../bin/sh"},
		{Mode: executor.SandboxModeContainer, Runtime: "--privileged"},
		{Mode: executor.SandboxModeContainer, Image: "-v/:/host"},
		{Mode: executor.SandboxMode("hypervisor")},
	} {
		if _, err := cache.driverFor(s, host); err == nil {
			t.Errorf("driverFor(%+v) accepted a configuration it must refuse", s)
		}
	}
}

// TestDriverFor_CachesPerConfiguration pins the cache key. Two starts under the
// same configuration must share a driver — a driver per task would give each
// workload its own handle map, so the second one's rehydrate could adopt the
// first one's running container — and a changed runtime must produce a new one,
// because the old driver's argv is baked into its options.
func TestDriverFor_CachesPerConfiguration(t *testing.T) {
	engine := fakeEngineOnPath(t)

	cache := newDriverCache()
	host := &hostDriver{}
	base := executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: engine}

	first, err := cache.driverFor(base, host)
	if err != nil {
		t.Fatalf("driverFor: %v", err)
	}
	again, err := cache.driverFor(base, host)
	if err != nil {
		t.Fatalf("driverFor (second call): %v", err)
	}
	if first != again {
		t.Error("the same configuration built two drivers; each would keep its own handle map " +
			"and could adopt the other's running container")
	}

	// A different OCI runtime is a different driver: the flag is fixed in the
	// driver's options, and a container started under the old one must keep being
	// addressed by the driver that started it.
	other := base
	other.Runtime = "runsc"
	third, err := cache.driverFor(other, host)
	if err != nil {
		t.Fatalf("driverFor with a different runtime: %v", err)
	}
	if third == first {
		t.Error("changing the OCI runtime reused the old driver, whose --runtime is already fixed")
	}
}

func TestContainerDriverID_NamesTheConfiguration(t *testing.T) {
	t.Parallel()
	got := containerDriverID(executor.SandboxSettings{
		Mode: executor.SandboxModeContainer, Engine: "podman", Runtime: "kata",
	})
	for _, want := range []string{"podman", "kata"} {
		if !strings.Contains(got, want) {
			t.Errorf("containerDriverID = %q, want it to mention %q so two configurations "+
				"produce two legible IDs in the device's log", got, want)
		}
	}
}

// TestWorkloadRunnerIsSeededSoStatusCannotPanic guards the nil case. A status
// request can arrive while a workload is still fetching its source tree, before
// any driver has started it — and handleStatusReq does not check for that,
// because the workload is constructed with a driver already in place.
func TestWorkloadRunnerIsSeededSoStatusCannotPanic(t *testing.T) {
	t.Parallel()
	local := localprocess.New("test-local")
	wl := &workload{handleID: "h1", driver: local}

	runner := wl.runner()
	if runner == nil {
		t.Fatal("a workload's runner must never be nil: handleStatusReq calls it without a " +
			"guard, so a nil here is a panic on the device")
	}
	// The unlaunched case answers with an error the caller already falls back
	// from, which is exactly what it did before the driver became a field.
	if _, err := runner.Status(context.Background(), ""); err == nil {
		t.Error("an empty handle must produce an error, so the caller uses its snapshot")
	}
}

// fakeEngineOnPath puts an executable named like a real container engine on PATH
// and returns its name.
//
// container.New only resolves the binary and rehydrates; it runs nothing. So a
// stub file is enough to exercise driver construction and caching without docker
// or podman being installed, and without this test depending on which of them the
// host happens to have.
func fakeEngineOnPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	const name = "podman"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake engine: %v", err)
	}
	t.Setenv("PATH", dir)
	return name
}
