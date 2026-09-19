package agent

// The end-to-end half of the device's container mode (Task 20307).
//
// driver_test.go proves the *decisions*: which driver a configuration selects,
// that a container mode with no engine is refused rather than downgraded, that
// two configurations do not share a driver. All of that runs without a runtime
// installed, which is why it is the file CI relies on.
//
// It leaves one claim unproven, and it is the claim the whole feature makes: that
// when an admin sets container mode, a payload on that device really does run
// inside a container. Everything up to here could be correct while the container
// never starts — a wrong workdir, a spec the driver rejects, output that never
// comes back — and no unit test would notice.
//
// So this file runs one — behind CLOOP_AGENT_SANDBOX_E2E=1, the same opt-in shape
// tests/flagship uses, and for a reason measured rather than assumed. Starting a
// real container is seconds of heavy I/O, and this package also holds
// TestWorkloadFinishingOfflineReportsOnReconnect, which waits on a subprocess exit
// and a reconnect backoff inside a 20-second window. Left ungated, the podman
// churn starved it: `go test ./pkg/executor/agent` went red on this tree and green
// on its parent under identical concurrent load, and skipping only these tests
// made the difference — 22.3s green versus 40.8s red. A default-on test that
// destabilises a sibling costs more than it proves.
//
// It also needs a locally-present image and never pulls: a suite that silently
// downloads hundreds of megabytes is a suite people switch off. The image is
// deliberately *not* the harness image; the payload is `sh -c echo`, because what
// is being tested is the driver wiring rather than anything cloop-specific.
//
//	CLOOP_AGENT_SANDBOX_E2E=1 go test ./pkg/executor/agent -run TestIntegration_ContainerMode -v

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// sandboxE2EEnv opts in to the real-container proof. See the file comment for why
// it is not on by default.
const sandboxE2EEnv = "CLOOP_AGENT_SANDBOX_E2E"

// integrationImageEnv overrides the image, for a box whose local store has
// something else small.
const integrationImageEnv = "CLOOP_TEST_AGENT_IMAGE"

// candidateImages are tried in order. Tiny, and the ones this project's boxes
// already have for the container driver's own integration tests.
var candidateImages = []string{"alpine:latest", "docker.io/library/alpine:latest", "debian:stable-slim"}

// requireEngineAndImage finds an installed engine and an image already in its
// local store, skipping the test when either is missing.
//
// It shells out rather than reusing pkg/executor/container's requireRuntime and
// requireImage, which are unexported test helpers in that package. Duplicating
// ~20 lines is the lesser evil against exporting test scaffolding from a driver.
func requireEngineAndImage(t *testing.T) (engine, image string) {
	t.Helper()
	if os.Getenv(sandboxE2EEnv) != "1" {
		t.Skipf("set %s=1 to run the real-container proof (it starts a container and its I/O "+
			"destabilises this package's deadline-sensitive reconnect tests)", sandboxE2EEnv)
	}
	for _, name := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(name); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Unformatted, like the container driver's own probe: docker and podman
		// expose different info schemas, so a --format string would fail on one.
		if err := exec.CommandContext(ctx, name, "info").Run(); err != nil {
			continue
		}
		engine = name
		break
	}
	if engine == "" {
		t.Skip("no responding container engine (podman/docker); cannot prove a payload runs in a container")
	}

	wanted := candidateImages
	if override := strings.TrimSpace(os.Getenv(integrationImageEnv)); override != "" {
		wanted = []string{override}
	}
	for _, ref := range wanted {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, err := exec.CommandContext(ctx, engine, "image", "inspect", ref).CombinedOutput()
		cancel()
		if err == nil {
			return engine, ref
		}
		_ = out
	}
	t.Skipf("none of %v is in %s's local store; the driver never pulls implicitly and neither "+
		"does this test (set %s to one you have)", wanted, engine, integrationImageEnv)
	return "", ""
}

// unprivilegedDir returns a workspace the container driver will accept.
//
// The driver derives the sandbox uid from the directory's owner and refuses uid 0
// outright: root in a container defeats `--cap-drop=ALL`, so any runtime escape
// becomes host root. That rule is correct and this test must satisfy it rather
// than switch it off — so the directory is chowned to an unprivileged uid, which
// is what the error message tells an operator to do and what a real device
// already has, since the agent's install unit runs it as a dedicated user.
//
// Skips rather than fails when the chown is not permitted: an unprivileged runner
// cannot give a directory away, and its TempDir is already non-root, so there is
// nothing to do and nothing wrong.
func unprivilegedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat temp dir: %v", err)
	}
	if os.Geteuid() != 0 {
		return dir // already owned by an unprivileged user
	}
	// 65534 is nobody on Debian and Alpine both, and needs no account to exist:
	// the container only reads /bin/sh and writes nothing.
	const nobody = 65534
	if err := os.Chown(dir, nobody, nobody); err != nil {
		t.Skipf("cannot chown the workspace away from root (%v); the container driver refuses "+
			"uid 0 and this test will not disable that rule", err)
	}
	_ = st
	return dir
}

// TestIntegration_ContainerModeRunsThePayloadInAContainer is the claim.
//
// The payload prints a marker and reports its own PID 1. Both assertions matter
// and they are different: the marker proves the workload ran and its output came
// back through the driver the agent selected, and `pid 1` proves it ran in its own
// PID namespace — which a host process started by this test process could not.
func TestIntegration_ContainerModeRunsThePayloadInAContainer(t *testing.T) {
	engine, image := requireEngineAndImage(t)

	cache := newDriverCache()
	// The host driver is passed but must not be used: the whole point is that a
	// container configuration does not resolve to it.
	host := &hostDriver{}

	settings := executor.SandboxSettings{
		Mode:   executor.SandboxModeContainer,
		Engine: engine,
		Image:  image,
	}
	driver, err := cache.driverFor(settings, host)
	if err != nil {
		t.Fatalf("driverFor(%s): %v", settings.Describe(), err)
	}
	if driver == payloadDriver(host) {
		t.Fatal("container mode resolved to the host driver")
	}

	const marker = "cloop-sandbox-marker-20307"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	handle, err := driver.Start(ctx, executor.Spec{
		// A real directory, because the container driver bind-mounts WorkDir as
		// the workspace — which is exactly how the agent hands over a tree it has
		// already fetched. See provisionedWorkspace.
		WorkDir: unprivilegedDir(t),
		Argv:    []string{"/bin/sh", "-c", "echo " + marker + "; echo pid=$$"},
		Image:   image,
	})
	if err != nil {
		t.Fatalf("Start in a container: %v", err)
	}

	lines, err := driver.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var out strings.Builder
	for line := range lines {
		out.WriteString(line.Text)
		out.WriteString("\n")
	}
	got := out.String()

	if !strings.Contains(got, marker) {
		t.Errorf("the payload's output never came back through the container driver.\ngot:\n%s", got)
	}
	// The sandbox's own PID namespace. A host process spawned by the test binary
	// would be some four- or five-digit pid; only a container's init is 1.
	if !strings.Contains(got, "pid=1") {
		t.Errorf("the payload did not run as pid 1, so it was not in its own PID namespace — "+
			"container mode did not contain it.\ngot:\n%s", got)
	}

	status, err := driver.Status(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.State.Terminal() {
		t.Errorf("state = %q after the stream closed, want terminal", status.State)
	}
	if status.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0.\noutput:\n%s", status.ExitCode, got)
	}
}
