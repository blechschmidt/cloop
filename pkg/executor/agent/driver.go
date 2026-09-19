package agent

// driver.go decides what actually runs a payload on this device.
//
// # What it replaced
//
// One field: `local *localprocess.Executor`, built in New and used at every
// call site unconditionally. That was the whole of the device's sandboxing
// story, and it was invisible from the control plane. The agent detects
// docker, podman and nerdctl on PATH and reports them in
// AgentCapabilities.ContainerRuntimes; the fleet view renders them as chips
// beside an "isolation: remote" badge — and then the harness ran as a child of
// this process, with this process's uid, on this filesystem, able to read the
// agent's own long-lived enrollment credential.
//
// Nothing was lying on purpose. "Remote" is true and is the only thing the
// control plane could honestly say, because containment on the far side of the
// link was not a thing anyone could configure. This file makes it configurable,
// which is what lets the hub say something stronger and mean it.
//
// # The rule that makes it a boundary rather than a preference
//
// A requested container mode this device cannot provide fails the start.
//
// That is the entire security value of the feature, and it is worth being blunt
// about the alternative, because the alternative is what a reasonable person
// writes first: fall back to the host process, log a warning, run the task. The
// task would succeed. The transcript would look normal. The fleet view would go
// on showing the container mode the admin selected. Every layer above would
// believe in a boundary that was removed by a `docker` binary not being
// installed — and the only record would be a warning line on an edge device
// nobody reads.
//
// The container driver states the same rule for its own construction, and this
// file is that sentence applied one machine further out:
//
//	// A missing runtime is reported as an error rather than swallowed: an
//	// operator who configured a container executor and silently got host
//	// execution would believe they had an isolation boundary they do not have.
//
// # Why drivers are cached per configuration
//
// container.New resolves the engine binary on PATH and rehydrates any handles a
// previous process left behind. Doing that per task would re-probe the
// filesystem on every start and — worse — give each workload its own handle map,
// so two tasks under the same configuration would not see each other's
// containers and the second one's rehydrate could adopt the first one's running
// workload. One driver per distinct configuration, built once and kept, is both
// cheaper and the only correct arrangement.
//
// The cache key is the configuration, not the executor: an admin who switches
// the OCI runtime from runc to kata gets a new driver, because the old one's
// argv is baked into its Options and a container started under the old runtime
// must keep being addressed by the driver that started it.

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
)

// payloadDriver is the slice of executor.Executor the agent needs from whatever
// runs a payload: start it, watch it, read it, signal it.
//
// An interface rather than a concrete type so localprocess and container are
// interchangeable here, and deliberately narrower than executor.Executor — the
// agent never asks a driver for its capabilities or health, because the device
// reports those itself and a driver's answer would describe the inner driver
// rather than the device the hub is scheduling.
type payloadDriver interface {
	Start(ctx context.Context, spec executor.Spec) (executor.Handle, error)
	Status(ctx context.Context, handleID string) (executor.Status, error)
	Stream(ctx context.Context, handleID string) (<-chan executor.LogLine, error)
	Signal(ctx context.Context, handleID string, sig executor.Signal) error
}

// driverKey identifies one distinct payload-driver configuration.
type driverKey struct {
	mode    executor.SandboxMode
	engine  string
	runtime string
	image   string
}

func keyFor(s executor.SandboxSettings) driverKey {
	return driverKey{mode: s.Mode, engine: s.Engine, runtime: s.Runtime, image: s.Image}
}

// driverCache holds one driver per configuration the hub has asked for.
type driverCache struct {
	mu      sync.Mutex
	drivers map[driverKey]payloadDriver
}

func newDriverCache() *driverCache {
	return &driverCache{drivers: make(map[driverKey]payloadDriver)}
}

// driverFor returns the driver that should run a payload under s, building it on
// first use. host is the driver for host execution, supplied by the caller
// rather than built here so that the agent's single localprocess executor — the
// one its revocation and attach paths already know about — stays the one used
// for host mode.
//
// The error is the point of the function. A caller that receives one must fail
// the start; see the file comment.
func (c *driverCache) driverFor(s executor.SandboxSettings, host payloadDriver) (payloadDriver, error) {
	s = s.Normalize()
	if err := s.Validate(); err != nil {
		// Re-validated on receipt even though the hub validated before writing
		// the row and again before sending the frame. This is the boundary
		// between a machine an operator administers and one that takes
		// instructions over a socket: the engine name becomes a program this
		// device executes, so "the sender checked it" is not a property this
		// side may rely on.
		return nil, fmt.Errorf("agent: refusing sandbox configuration from the control plane: %w", err)
	}

	if s.Mode != executor.SandboxModeContainer {
		// Host and unset both mean the host process, and they mean it for
		// different reasons — one chosen, one inherited — which is why they are
		// distinct on the wire and identical here.
		return host, nil
	}

	key := keyFor(s)
	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.drivers[key]; ok {
		return d, nil
	}

	opts := container.Options{
		// Named for the configuration rather than "agent-container", so that two
		// runtimes configured in sequence produce two legible IDs in this
		// device's own logs instead of one name meaning different things at
		// different times.
		ID:         containerDriverID(s),
		Runtime:    s.Engine,
		OCIRuntime: s.Runtime,
		Image:      s.Image,
	}
	ex, err := container.New(opts)
	if err != nil {
		// The message names what was asked for and what is missing, because it
		// travels back to the hub as the start failure an operator reads — and
		// the fix is on this device, which they may not be logged in to.
		return nil, fmt.Errorf(
			"agent: this executor is configured to run payloads in a container (%s) but this device "+
				"cannot: %w — install the engine, or set the executor's sandbox mode to host",
			s.Describe(), err)
	}
	c.drivers[key] = ex
	return ex, nil
}

// containerDriverID names a container driver after the configuration it serves.
func containerDriverID(s executor.SandboxSettings) string {
	parts := []string{"agent-container"}
	if s.Engine != "" {
		parts = append(parts, s.Engine)
	}
	if s.Runtime != "" {
		parts = append(parts, s.Runtime)
	}
	return strings.Join(parts, "-")
}
