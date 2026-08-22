package container

// container_test.go has two halves.
//
// The pure half (options, request construction, exit classification, error
// explanation) runs everywhere, including CI machines with no container
// runtime, because it constructs an Executor struct directly instead of going
// through New.
//
// The integration half runs a real container and is skipped — cleanly, with a
// reason — when no runtime or no test image is available. It exists because
// the argv tests prove we *ask* for confinement and only an actual run proves
// we *get* it: TestIntegration_NetworkIsolation and
// TestIntegration_OnlyWorkspaceIsVisible would both pass against a driver
// whose flags the runtime silently ignored.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// testImageEnv lets CI override the image used by the integration tests.
const testImageEnv = "CLOOP_TEST_CONTAINER_IMAGE"

// defaultTestImage is a small image present on most developer machines. It is
// musl-based, which is fine for the shell-based assertions; the smoke test
// needs glibc and looks for glibcTestImage instead.
const defaultTestImage = "alpine:latest"

// glibcTestImage is used by the smoke test, which executes the control
// plane's own dynamically-linked binary inside the sandbox.
const glibcTestImage = "debian:stable-slim"

// requireRuntime skips the test unless a container runtime is installed and
// responding. Returning the Runtime rather than a bool keeps each test's
// setup to one line.
func requireRuntime(t *testing.T) Runtime {
	t.Helper()
	rt, err := DetectRuntime("")
	if err != nil {
		if errors.Is(err, ErrNoRuntime) {
			t.Skip("no container runtime installed (podman/docker); skipping integration test")
		}
		t.Skipf("container runtime unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Unformatted: docker and podman expose different info schemas, so a
	// --format string would fail on one of them and skip every test.
	res, err := runCLI(ctx, rt, nil, "info")
	if err != nil || res.ExitCode != 0 {
		t.Skipf("%s is installed but not responding (is the daemon running?); skipping", rt.Name)
	}
	return rt
}

// requireImage skips unless the named image is present locally. The driver
// never pulls implicitly, so a test must not either — a test suite that
// silently downloads hundreds of megabytes is a test suite people disable.
func requireImage(t *testing.T, rt Runtime, image string) string {
	t.Helper()
	if override := strings.TrimSpace(os.Getenv(testImageEnv)); override != "" {
		image = override
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := runCLI(ctx, rt, nil, "image", "inspect", image)
	if err != nil || res.ExitCode != 0 {
		t.Skipf("image %s is not present locally; run `%s pull %s` to enable this test", image, rt.Name, image)
	}
	return image
}

// newTestExecutor builds an executor against a real runtime and the given
// image, and registers cleanup that reaps anything it leaves behind.
func newTestExecutor(t *testing.T, image string, mutate func(*Options)) *Executor {
	t.Helper()
	rt := requireRuntime(t)
	image = requireImage(t, rt, image)

	opts := Options{
		ID:    "test-container",
		Image: image,
		// The integration suite runs wherever CI puts it, including as root
		// with a root-owned t.TempDir(). Production refuses that combination
		// (Options.AllowRootUser) so a root sandbox is never accidental; here
		// it is deliberate, because these tests are about container lifecycle
		// and not about the UID policy. The policy itself is asserted in
		// tests/security and in TestBuildRunArgs_RefusesRootUser.
		AllowRootUser: true,
	}
	if mutate != nil {
		mutate(&opts)
	}
	ex, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for _, id := range ex.Handles() {
			_ = ex.Signal(ctx, id, executor.SignalKill)
		}
		// Reap regardless: a failed assertion can leave a container behind,
		// and a test suite that litters the developer's machine gets run
		// less often.
		_, _ = ex.ReapOrphans(ctx)
	})
	return ex
}

// runInSandbox runs argv to completion and returns the trimmed output.
func runInSandbox(t *testing.T, ex *Executor, workDir string, argv []string, env []string) (executor.RunResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return executor.Run(ctx, ex, executor.Spec{WorkDir: workDir, Argv: argv, Env: env})
}

// --- pure tests -------------------------------------------------------

// fakeExecutor builds an Executor without touching the host, so the
// request-construction logic is testable on a machine with no runtime.
func fakeExecutor(t *testing.T, opts Options) *Executor {
	t.Helper()
	norm, err := opts.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	return &Executor{
		id:      norm.ID,
		opts:    norm,
		rt:      Runtime{Name: RuntimeDocker, Path: "/usr/bin/docker"},
		handles: make(map[string]*record),
	}
}

func TestOptionsNormalize(t *testing.T) {
	t.Run("zero value is usable and confined", func(t *testing.T) {
		got, err := Options{}.Normalize()
		if err != nil {
			t.Fatalf("zero Options must normalize, got %v", err)
		}
		if got.ID != DefaultID {
			t.Errorf("ID = %q, want %q", got.ID, DefaultID)
		}
		if got.Image != DefaultImage {
			t.Errorf("Image = %q, want %q", got.Image, DefaultImage)
		}
		if got.Network != NetworkNone {
			t.Errorf("Network = %q, want %q — an unset network must not mean 'bridge'", got.Network, NetworkNone)
		}
		if got.PIDsLimit != defaultPIDsLimit {
			t.Errorf("PIDsLimit = %d, want the default %d", got.PIDsLimit, defaultPIDsLimit)
		}
	})

	rejected := map[string]Options{
		"negative cpus":            {CPUs: -1},
		"negative memory":          {MemoryMB: -1},
		"host network":             {Network: "host"},
		"bad selinux label":        {SELinuxLabel: "q"},
		"image that parses a flag": {Image: "-rm"},
		"denied extra arg":         {ExtraArgs: []string{"--privileged"}},
		"allow_hosts without net":  {AllowHosts: []string{"a:1.2.3.4"}},
		"malformed allow_hosts":    {Network: NetworkBridge, AllowHosts: []string{"nope"}},
	}
	for name, opts := range rejected {
		t.Run(name, func(t *testing.T) {
			if _, err := opts.Normalize(); err == nil {
				t.Fatalf("Options%+v must be rejected", opts)
			}
		})
	}

	t.Run("does not mutate the caller's struct", func(t *testing.T) {
		orig := Options{}
		if _, err := orig.Normalize(); err != nil {
			t.Fatal(err)
		}
		if orig.Image != "" || orig.Network != "" || orig.PIDsLimit != 0 {
			t.Fatalf("Normalize mutated its receiver: %+v", orig)
		}
	})
}

func TestBuildRequest_SpecOverridesExecutorDefaults(t *testing.T) {
	ex := fakeExecutor(t, Options{CPUs: 1, MemoryMB: 256, PIDsLimit: 64})
	spec := executor.Spec{
		WorkDir: "/srv/proj",
		Argv:    []string{"cloop", "run"},
		ResourceLimits: executor.ResourceLimits{
			CPUMillis: 2500,
			MemoryMB:  1024,
			PIDs:      128,
		},
	}
	req, err := ex.buildRequest(spec, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.CPUs != 2.5 {
		t.Errorf("CPUs = %v, want 2.5 (spec must override the executor default)", req.CPUs)
	}
	if req.MemoryMB != 1024 {
		t.Errorf("MemoryMB = %d, want 1024", req.MemoryMB)
	}
	if req.PIDsLimit != 128 {
		t.Errorf("PIDsLimit = %d, want 128", req.PIDsLimit)
	}
}

func TestBuildRequest_FallsBackToExecutorDefaults(t *testing.T) {
	ex := fakeExecutor(t, Options{CPUs: 1, MemoryMB: 256, PIDsLimit: 64})
	req, err := ex.buildRequest(executor.Spec{Argv: []string{"x"}}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.CPUs != 1 || req.MemoryMB != 256 || req.PIDsLimit != 64 {
		t.Fatalf("expected the executor defaults, got cpus=%v mem=%d pids=%d", req.CPUs, req.MemoryMB, req.PIDsLimit)
	}
}

func TestBuildRequest_RejectsDiskQuota(t *testing.T) {
	// Accepting a limit the driver cannot enforce is worse than refusing it:
	// the caller would believe a guarantee it does not have.
	ex := fakeExecutor(t, Options{})
	_, err := ex.buildRequest(executor.Spec{
		Argv:           []string{"x"},
		ResourceLimits: executor.ResourceLimits{DiskMB: 100},
	}, "/srv/proj", nil)
	if err == nil {
		t.Fatal("expected a disk quota request to be rejected")
	}
	if !errors.Is(err, executor.ErrUnsupported) {
		t.Fatalf("error should wrap ErrUnsupported so callers can branch on it, got %v", err)
	}
}

func TestBuildRequest_PropagatesSELinuxLabel(t *testing.T) {
	ex := fakeExecutor(t, Options{SELinuxLabel: "z"})
	extra := []mount{{HostPath: "/usr/local/bin/cloop", TargetPath: ContainerCloopPath, ReadOnly: true}}
	req, err := ex.buildRequest(executor.Spec{Argv: []string{"x"}}, "/srv/proj", extra)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.Workspace.SELinuxLabel != "z" {
		t.Errorf("workspace label = %q, want z", req.Workspace.SELinuxLabel)
	}
	if len(req.ExtraMounts) != 1 || req.ExtraMounts[0].SELinuxLabel != "z" {
		t.Errorf("extra mount did not inherit the SELinux label: %+v", req.ExtraMounts)
	}
}

func TestBuildRequest_EnvNamesOnly(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	spec := executor.Spec{
		Argv: []string{"x"},
		Env:  []string{"ANTHROPIC_API_KEY=secret", "PATH=/usr/bin"},
	}
	req, err := ex.buildRequest(spec, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	want := []string{"ANTHROPIC_API_KEY", "PATH"}
	if diff := diffArgs(want, req.EnvNames); diff != "" {
		t.Fatalf("EnvNames mismatch:\n%s", diff)
	}
	for _, n := range req.EnvNames {
		if strings.Contains(n, "=") {
			t.Fatalf("EnvNames must carry names only, got %q", n)
		}
	}
}

func TestBuildRequest_NilEnvForwardsNothing(t *testing.T) {
	// The divergence from os/exec semantics documented in the package doc:
	// inheriting the control plane's environment would hand the sandbox
	// every credential the server holds.
	ex := fakeExecutor(t, Options{})
	req, err := ex.buildRequest(executor.Spec{Argv: []string{"x"}}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if len(req.EnvNames) != 0 {
		t.Fatalf("a nil Spec.Env must forward nothing, got %v", req.EnvNames)
	}
	if req.Env != nil {
		t.Fatalf("no runtime env override expected, got %d entries", len(req.Env))
	}
}

func TestBuildRequest_SpecLabelsAreNamespaced(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	spec := executor.Spec{
		Argv:   []string{"x"},
		Labels: map[string]string{"component": "web-ui", LabelManaged: "false"},
	}
	req, err := ex.buildRequest(spec, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if got := req.Labels[LabelManaged]; got != "true" {
		t.Fatalf("a Spec label must not be able to overwrite %s (got %q) — reaping depends on it", LabelManaged, got)
	}
	if got := req.Labels["cloop.spec.component"]; got != "web-ui" {
		t.Fatalf("spec label not namespaced: %v", req.Labels)
	}
}

func TestResolveWorkDir(t *testing.T) {
	ex := fakeExecutor(t, Options{})

	t.Run("empty is rejected", func(t *testing.T) {
		// Unlike localprocess, a container must bind-mount something;
		// defaulting to the control plane's cwd would expose it.
		_, err := ex.resolveWorkDir("")
		if err == nil {
			t.Fatal("expected an empty work_dir to be rejected")
		}
		if !errors.Is(err, executor.ErrInvalidSpec) {
			t.Fatalf("error should wrap ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("missing directory is rejected", func(t *testing.T) {
		if _, err := ex.resolveWorkDir(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Fatal("expected a missing work_dir to be rejected")
		}
	})

	t.Run("a file is rejected", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ex.resolveWorkDir(f); err == nil {
			t.Fatal("expected a file work_dir to be rejected")
		}
	})

	t.Run("returns an absolute path", func(t *testing.T) {
		dir := t.TempDir()
		got, err := ex.resolveWorkDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !filepath.IsAbs(got) {
			t.Fatalf("resolveWorkDir returned a relative path %q", got)
		}
	})
}

func TestClassifyExit(t *testing.T) {
	cases := []struct {
		name      string
		code      int
		detail    inspectDetail
		wantState executor.State
		wantMsg   string // substring, empty means "no message required"
	}{
		{name: "clean exit", code: 0, wantState: executor.StateExited},
		{name: "ordinary failure", code: 1, wantState: executor.StateExited},
		{name: "runtime could not start it", code: 125, wantState: executor.StateFailed, wantMsg: "runtime itself"},
		{name: "not executable", code: 126, wantState: executor.StateFailed, wantMsg: "could not be invoked"},
		{name: "command not found", code: 127, wantState: executor.StateFailed, wantMsg: "not found in the image"},
		{name: "sigkill", code: 137, wantState: executor.StateKilled, wantMsg: "SIGKILL"},
		{name: "sigterm", code: 143, wantState: executor.StateKilled, wantMsg: "SIGTERM"},
		{name: "other signal", code: 139, wantState: executor.StateKilled, wantMsg: "signal 11"},
		{name: "oom beats the exit code", code: 137, detail: inspectDetail{OOMKilled: true, Found: true},
			wantState: executor.StateKilled, wantMsg: "memory limit"},
		{name: "oom on a zero exit is still an oom", code: 0, detail: inspectDetail{OOMKilled: true, Found: true},
			wantState: executor.StateKilled, wantMsg: "memory limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, msg := classifyExit(tc.code, tc.detail)
			if state != tc.wantState {
				t.Errorf("classifyExit(%d) state = %q, want %q", tc.code, state, tc.wantState)
			}
			if tc.wantMsg != "" && !strings.Contains(msg, tc.wantMsg) {
				t.Errorf("classifyExit(%d) message %q does not mention %q", tc.code, msg, tc.wantMsg)
			}
		})
	}
}

// TestExplainRunFailure checks that each recognised runtime error becomes an
// actionable message, and — more importantly — that an unrecognised one still
// carries the raw text instead of being swallowed.
func TestExplainRunFailure(t *testing.T) {
	rt := Runtime{Name: RuntimeDocker, Path: "/usr/bin/docker"}
	cases := []struct {
		name   string
		stderr string
		want   string
	}{
		{"missing image", "Error response from daemon: No such image: alpine:latest", "docker pull"},
		{"podman missing image", "Error: alpine: image not known", "docker pull"},
		{"socket permission", "permission denied while trying to connect to the Docker daemon socket", "socket"},
		{"daemon down", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock", "start it and retry"},
		{"name collision", `container name "cloop-a-b" is already in use`, "reap"},
		{"cgroup", "invalid argument: cgroup subsystem cpu not mounted", "cgroup v2 delegation"},
		{"unrecognised keeps the raw text", "flux capacitor desynchronised", "flux capacitor desynchronised"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := explainRunFailure(rt, "alpine:latest", cliResult{Stderr: tc.stderr, ExitCode: 125})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}

	t.Run("falls back to stdout when stderr is empty", func(t *testing.T) {
		err := explainRunFailure(rt, "img", cliResult{Stdout: "something on stdout", ExitCode: 1})
		if !strings.Contains(err.Error(), "something on stdout") {
			t.Fatalf("stdout should be used when stderr is empty, got %v", err)
		}
	})
}

// TestIsNameCollision guards the branch that decides whether Start's
// failure-path cleanup is safe to run. A false negative here means Start
// deletes a container belonging to someone else's live run.
func TestIsNameCollision(t *testing.T) {
	collisions := []string{
		`docker: Error response from daemon: Conflict. The container name "/cloop-a-b" is already in use by container "abc".`,
		`Error: creating container storage: the container name "cloop-a-b" is already in use by ...`,
		`NAME IS ALREADY IN USE`,
	}
	for _, s := range collisions {
		if !isNameCollision(s) {
			t.Errorf("isNameCollision(%q) = false, want true — Start would delete an unrelated container", s)
		}
	}
	others := []string{
		"Error response from daemon: No such image: alpine:latest",
		"permission denied",
		"",
	}
	for _, s := range others {
		if isNameCollision(s) {
			t.Errorf("isNameCollision(%q) = true, want false", s)
		}
	}
}

// TestIntegration_NameCollisionDoesNotDeleteTheIncumbent is the behavioural
// half: a start that loses a name race must leave the existing container
// running.
func TestIntegration_NameCollisionDoesNotDeleteTheIncumbent(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dir := t.TempDir()
	handleID := "c-" + strings.Repeat("ab", 6)
	name := ContainerName(mustAbs(dir), handleID)

	// Occupy the name with a long-running container outside the driver.
	res, err := runCLITimeout(ctx, ex.rt, shortCmdTimeout,
		"run", "--detach", "--name", name, "--network=none",
		ex.opts.Image, "/bin/sh", "-c", "sleep 120")
	if err != nil || res.ExitCode != 0 {
		t.Skipf("could not stage a name collision: %v %s", err, res.Stderr)
	}
	defer func() { _, _ = runCLITimeout(context.Background(), ex.rt, shortCmdTimeout, "rm", "--force", name) }()

	// Drive Start through the same name by pre-seeding the request.
	req, err := ex.buildRequest(executor.Spec{Argv: []string{"/bin/true"}}, mustAbs(dir), nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	req.Name = name
	built, err := buildRunArgs(req)
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	collided, err := runCLI(ctx, ex.rt, built.Env, built.Args...)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if collided.ExitCode == 0 {
		t.Fatal("expected the second run to fail on the name collision")
	}
	if !isNameCollision(collided.Stderr) {
		t.Fatalf("collision not recognised, so Start would have removed the incumbent. stderr: %s", collided.Stderr)
	}

	// The incumbent must still be running.
	inspect, err := runCLITimeout(ctx, ex.rt, shortCmdTimeout, "inspect", "--format", "{{.State.Running}}", name)
	if err != nil || inspect.ExitCode != 0 {
		t.Fatalf("the incumbent container was destroyed by the failed start: %v %s", err, inspect.Stderr)
	}
	if strings.TrimSpace(inspect.Stdout) != "true" {
		t.Fatalf("incumbent is no longer running: %q", strings.TrimSpace(inspect.Stdout))
	}
}

func TestDetectRuntime_RejectsArbitraryBinaries(t *testing.T) {
	// Config must not be able to point cloop at an arbitrary executable:
	// that executable is invoked with the workload's environment, which
	// holds the caller's secrets.
	for _, name := range []string{"bash", "/bin/sh", "curl", "../../bin/sh", "kubectl"} {
		if _, err := DetectRuntime(name); err == nil {
			t.Errorf("DetectRuntime(%q) must be rejected: not an allowlisted runtime", name)
		} else if errors.Is(err, ErrNoRuntime) {
			t.Errorf("DetectRuntime(%q) should reject the *name*, not report it as missing: %v", name, err)
		}
	}
}

func TestDetectRuntime_MissingRuntimeIsIdentifiable(t *testing.T) {
	// A configured-but-absent runtime must be distinguishable from a
	// rejected one so tests and callers can skip rather than fail.
	if _, err := exec.LookPath("podman"); err != nil {
		if _, derr := DetectRuntime("podman"); !errors.Is(derr, ErrNoRuntime) {
			t.Fatalf("expected ErrNoRuntime for an absent podman, got %v", derr)
		}
	}
}

func TestCapabilitiesReflectConfiguration(t *testing.T) {
	t.Run("no network means no egress", func(t *testing.T) {
		ex := fakeExecutor(t, Options{})
		caps := ex.Capabilities()
		if caps.NetworkEgress {
			t.Error("NetworkEgress must be false when the network is 'none'")
		}
		if caps.Isolation != executor.IsolationContainer {
			t.Errorf("Isolation = %q, want %q", caps.Isolation, executor.IsolationContainer)
		}
		if !caps.SupportsResourceLimits {
			t.Error("the container driver does enforce resource limits")
		}
	})

	t.Run("bridge means egress", func(t *testing.T) {
		// Over-claiming isolation is the dangerous direction to be wrong in,
		// so this must track the configuration honestly.
		ex := fakeExecutor(t, Options{Network: NetworkBridge})
		if !ex.Capabilities().NetworkEgress {
			t.Error("NetworkEgress must be true when a network is attached")
		}
	})

	t.Run("no workspace provisioning, because there is nothing to provision", func(t *testing.T) {
		caps := fakeExecutor(t, Options{}).Capabilities()
		if caps.SupportsWorkspaceProvisioning {
			t.Error("SupportsWorkspaceProvisioning must be false: the project directory is bind-mounted")
		}
		if !caps.SharesHostFilesystem {
			t.Error("SharesHostFilesystem must be true, which is *why* provisioning is not needed")
		}
	})
}

// TestBuildRequest_RefusesGitWorkspace: the bind mount means the clone target
// is the operator's own checkout. `git init` over their .git and a detached
// checkout over their uncommitted work is not a degraded outcome, it is data
// loss on the machine they are sitting at — so it is refused, not attempted.
func TestBuildRequest_RefusesGitWorkspace(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	_, err := ex.buildRequest(executor.Spec{
		Argv: []string{"x"},
		Workspace: executor.Workspace{
			Kind: executor.WorkspaceGit,
			Repo: "https://example.com/acme/app.git",
			Ref:  "main",
		},
	}, "/srv/proj", nil)
	if err == nil {
		t.Fatal("a git workspace must be refused by a driver that bind-mounts the host path")
	}
	if !errors.Is(err, executor.ErrUnsupported) {
		t.Fatalf("error should wrap ErrUnsupported so callers can branch on it, got %v", err)
	}
	// The message has to say what a clone would destroy and where to send the
	// workload instead; "unsupported" alone sends the reader looking for a bug.
	for _, want := range []string{"overwrite", "/srv/proj"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q; got %v", want, err)
		}
	}
}

// TestBuildRequest_AcceptsNonGitWorkspaces is the other half: bind, none and
// the unspecified zero value ask this driver for nothing, so none of them may
// become a refusal.
func TestBuildRequest_AcceptsNonGitWorkspaces(t *testing.T) {
	for _, kind := range []executor.WorkspaceKind{
		executor.WorkspaceUnspecified,
		executor.WorkspaceBind,
		executor.WorkspaceNone,
	} {
		ex := fakeExecutor(t, Options{})
		_, err := ex.buildRequest(executor.Spec{
			Argv:      []string{"x"},
			Workspace: executor.Workspace{Kind: kind},
		}, "/srv/proj", nil)
		if err != nil {
			t.Errorf("workspace kind %q must build unchanged: %v", kind, err)
		}
	}
}

// TestStart_RefusesGitWorkspace pins the refusal at the entry point callers
// actually use, and before anything touches a container runtime — a driver that
// only rejected this deep inside buildRequest would still be correct, but a
// future reordering could move the runtime call in front of it.
func TestStart_RefusesGitWorkspace(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	_, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"cloop", "run"},
		Workspace: executor.Workspace{
			Kind: executor.WorkspaceGit,
			Repo: "https://example.com/acme/app.git",
		},
	})
	if !errors.Is(err, executor.ErrUnsupported) {
		t.Fatalf("Start with a git workspace = %v, want it to wrap ErrUnsupported", err)
	}
}

func TestSanitizeLabelKeySegment(t *testing.T) {
	cases := map[string]string{
		"component":  "component",
		"task id":    "task_id",
		"a/b":        "a_b",
		"":           "unnamed",
		"--injected": "--injected", // dashes are legal inside a namespaced key
	}
	for in, want := range cases {
		if got := sanitizeLabelKeySegment(in); got != want {
			t.Errorf("sanitizeLabelKeySegment(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeLabelKeySegment(strings.Repeat("x", 100)); len(got) != 64 {
		t.Errorf("long key not truncated: len = %d", len(got))
	}
}

func TestNewHandleIDIsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := newHandleID()
		if !strings.HasPrefix(id, "c-") {
			t.Fatalf("handle ID %q lacks the c- prefix", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate handle ID %q after %d draws", id, i)
		}
		seen[id] = struct{}{}
	}
}

// --- integration tests ------------------------------------------------

func TestIntegration_RunCollectsOutputAndExitCode(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	dir := t.TempDir()

	res, err := runInSandbox(t, ex, dir, []string{"/bin/sh", "-c", "echo hello from sandbox"}, nil)
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, res.Output)
	}
	if got := strings.TrimSpace(string(res.Output)); got != "hello from sandbox" {
		t.Fatalf("output = %q, want %q", got, "hello from sandbox")
	}
	if res.Status.State != executor.StateExited || res.Status.ExitCode != 0 {
		t.Fatalf("status = %+v, want exited/0", res.Status)
	}
	if res.Dropped {
		t.Error("output was reported as dropped for a tiny workload")
	}
}

func TestIntegration_NonZeroExitIsReported(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	res, err := runInSandbox(t, ex, t.TempDir(), []string{"/bin/sh", "-c", "echo oops >&2; exit 7"}, nil)
	if err == nil {
		t.Fatal("expected a non-zero exit to be reported as an error")
	}
	if res.Status.ExitCode != 7 {
		t.Fatalf("ExitCode = %d, want 7", res.Status.ExitCode)
	}
	if !strings.Contains(string(res.Output), "oops") {
		t.Fatalf("stderr should be merged into the output stream, got %q", res.Output)
	}
}

// TestIntegration_NetworkIsolation is the assertion the argv tests cannot
// make: that --network=none is actually honoured by the runtime.
func TestIntegration_NetworkIsolation(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	res, err := runInSandbox(t, ex, t.TempDir(), []string{"/bin/sh", "-c", "ls /sys/class/net"}, nil)
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, res.Output)
	}
	ifaces := strings.Fields(string(res.Output))
	for _, iface := range ifaces {
		if iface != "lo" {
			t.Fatalf("sandbox has network interface %q; expected loopback only (got %v)", iface, ifaces)
		}
	}
	if len(ifaces) == 0 {
		t.Fatalf("expected at least the loopback interface, got none")
	}
}

// TestIntegration_OnlyWorkspaceIsVisible proves the bind-mount boundary: the
// project directory is present and writable, and a sibling directory on the
// host is not visible at all.
func TestIntegration_OnlyWorkspaceIsVisible(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)

	root := t.TempDir()
	project := filepath.Join(root, "project")
	secret := filepath.Join(root, "not-the-project")
	for _, d := range []string{project, secret} {
		if err := os.MkdirAll(d, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "inside.txt"), []byte("visible"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "outside.txt"), []byte("must not leak"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runInSandbox(t, ex, project, []string{"/bin/sh", "-c",
		`cat /workspace/inside.txt; echo; ls ` + secret + ` 2>&1 | head -1`}, nil)
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, res.Output)
	}
	out := string(res.Output)
	if !strings.Contains(out, "visible") {
		t.Fatalf("the project directory should be readable at %s, got %q", ContainerWorkspace, out)
	}
	if strings.Contains(out, "outside.txt") {
		t.Fatalf("a host directory outside the project leaked into the sandbox: %q", out)
	}
}

// TestIntegration_WorkspaceIsWritableAndOwnedCorrectly checks the other half
// of the mount contract: the workload can write, and what it writes is usable
// on the host afterwards.
func TestIntegration_WorkspaceIsWritableAndOwnedCorrectly(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}

	res, err := runInSandbox(t, ex, dir, []string{"/bin/sh", "-c", "echo written-by-sandbox > /workspace/out.txt"}, nil)
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, res.Output)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatalf("the host cannot read what the sandbox wrote: %v", err)
	}
	if strings.TrimSpace(string(data)) != "written-by-sandbox" {
		t.Fatalf("file contents = %q", data)
	}
}

// TestIntegration_SecretsReachTheSandboxButNotTheProcessTable is the
// end-to-end version of TestBuildRunArgs_SecretsNeverInArgv.
func TestIntegration_SecretsReachTheSandbox(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	const secret = "sk-test-not-a-real-key"

	res, err := runInSandbox(t, ex, t.TempDir(),
		[]string{"/bin/sh", "-c", "echo got:$ANTHROPIC_API_KEY"},
		[]string{"ANTHROPIC_API_KEY=" + secret})
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, res.Output)
	}
	if !strings.Contains(string(res.Output), "got:"+secret) {
		t.Fatalf("the secret did not reach the sandbox environment (output: %q)", res.Output)
	}
}

// TestIntegration_HostEnvironmentIsNotInherited pins the deliberate
// divergence from os/exec semantics.
func TestIntegration_HostEnvironmentIsNotInherited(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	t.Setenv("CLOOP_HOST_ONLY_SECRET", "leaked")

	res, err := runInSandbox(t, ex, t.TempDir(),
		[]string{"/bin/sh", "-c", "echo value:[$CLOOP_HOST_ONLY_SECRET]"}, nil)
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, res.Output)
	}
	if strings.Contains(string(res.Output), "leaked") {
		t.Fatalf("the control plane's environment leaked into the sandbox: %q", res.Output)
	}
}

func TestIntegration_SignalStopsAWorkload(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	handle, err := ex.Start(ctx, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "sleep 300"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Subscribe before signalling so the close is observable.
	lines, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	if err := ex.Signal(ctx, handle.ID, executor.SignalKill); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	select {
	case <-drain(lines):
	case <-time.After(60 * time.Second):
		t.Fatal("the stream did not close within 60s of a kill")
	}

	status, err := ex.Status(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != executor.StateKilled {
		t.Fatalf("state = %q, want %q (status: %+v)", status.State, executor.StateKilled, status)
	}

	// Signalling an already-finished handle is a no-op success: the caller
	// wanted it stopped and it is stopped.
	if err := ex.Signal(ctx, handle.ID, executor.SignalKill); err != nil {
		t.Fatalf("signalling a finished handle should succeed, got %v", err)
	}
}

func TestIntegration_TimeoutKillsTheWorkload(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Spec.TimeoutMinutes is minutes-granular, so this exercises the timer
	// path with the smallest value the API allows.
	handle, err := ex.Start(ctx, executor.Spec{
		WorkDir:        t.TempDir(),
		Argv:           []string{"/bin/sh", "-c", "sleep 600"},
		TimeoutMinutes: 1,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lines, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	select {
	case <-drain(lines):
	case <-time.After(150 * time.Second):
		t.Fatal("the workload outlived its 1-minute timeout")
	}
	status, _ := ex.Status(ctx, handle.ID)
	if status.State != executor.StateKilled {
		t.Fatalf("state = %q, want killed after a timeout", status.State)
	}
	if !strings.Contains(status.Error, "timeout") {
		t.Errorf("status should explain the timeout, got %q", status.Error)
	}
}

func TestIntegration_MissingImageIsActionable(t *testing.T) {
	rt := requireRuntime(t)
	// AllowRootUser for the same reason as newTestExecutor: this test is about
	// the missing-image message, and running as root would otherwise make the
	// UID refusal the first error and mask it.
	ex, err := New(Options{
		ID:            "test-missing",
		Image:         "cloop-test.invalid/definitely-not-pulled:v0",
		AllowRootUser: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/true"},
	})
	if err == nil {
		t.Fatal("expected starting a workload with an absent image to fail")
	}
	// The whole point of --pull=never is that this fails fast with a message
	// naming the fix, rather than hanging on a registry fetch.
	if !strings.Contains(err.Error(), "pull") {
		t.Fatalf("error should tell the operator to pull the image, got: %v", err)
	}
	_ = rt
}

func TestIntegration_ResourceLimitsAreApplied(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)

	res, err := executor.Run(context.Background(), ex, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "cat /sys/fs/cgroup/pids.max 2>/dev/null || echo cgroup-v1"},
		ResourceLimits: executor.ResourceLimits{
			MemoryMB: 256,
			PIDs:     64,
		},
	})
	if err != nil {
		t.Fatalf("Run with limits: %v (output: %s)", err, res.Output)
	}
	out := strings.TrimSpace(string(res.Output))
	if out == "cgroup-v1" {
		t.Skip("host uses cgroup v1; the pids.max assertion needs cgroup v2")
	}
	if out != "64" {
		t.Fatalf("pids.max inside the sandbox = %q, want 64 — the limit was not applied", out)
	}
}

func TestIntegration_ContainerIsRemovedAfterCompletion(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	ctx := context.Background()

	res, err := runInSandbox(t, ex, t.TempDir(), []string{"/bin/true"}, nil)
	if err != nil {
		t.Fatalf("Run: %v (output: %s)", err, res.Output)
	}
	name := ContainerName(mustAbs(t.TempDir()), res.Handle.ID)

	// A finished run must not leave a container behind, or a long-lived
	// control plane accumulates one per task forever.
	inspect, err := runCLITimeout(ctx, ex.rt, shortCmdTimeout, "inspect", name)
	if err == nil && inspect.ExitCode == 0 {
		t.Fatalf("container %s still exists after the run completed", name)
	}
}

func TestIntegration_ReapOrphansLeavesLiveContainersAlone(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	handle, err := ex.Start(ctx, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "sleep 120"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = ex.Signal(context.Background(), handle.ID, executor.SignalKill) }()

	removed, err := ex.ReapOrphans(ctx)
	if err != nil {
		t.Fatalf("ReapOrphans: %v", err)
	}
	for _, name := range removed {
		if strings.Contains(name, strings.TrimPrefix(handle.ID, "c-")) {
			t.Fatalf("ReapOrphans removed a running container %q", name)
		}
	}

	status, err := ex.Status(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Status after reap: %v", err)
	}
	if status.State != executor.StateRunning {
		t.Fatalf("the live workload was disturbed by reaping: state = %q", status.State)
	}
}

func TestIntegration_StreamReplaysForLateSubscribers(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	handle, err := ex.Start(ctx, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "echo early-output; sleep 2"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Subscribe deliberately late, after the workload has already printed.
	time.Sleep(3 * time.Second)
	lines, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var sb strings.Builder
	for line := range lines {
		sb.WriteString(line.Text)
	}
	if !strings.Contains(sb.String(), "early-output") {
		t.Fatalf("a late subscriber missed the replayed backlog, got %q", sb.String())
	}
}

func TestIntegration_HealthCheck(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	if err := ex.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck against a working runtime: %v", err)
	}
}

func TestIntegration_Preflight(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	dir := t.TempDir()

	report := ex.Preflight(context.Background(), dir)
	if !report.OK() {
		t.Fatalf("preflight failed against a working runtime and a present image: %v\nfindings: %+v",
			report.Err(), report.Findings)
	}

	byName := make(map[string]Finding, len(report.Findings))
	for _, f := range report.Findings {
		byName[f.Name] = f
	}
	for _, want := range []string{"runtime", "daemon", "image", "network", "workdir"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("preflight did not report on %q; findings: %+v", want, report.Findings)
		}
	}
	if byName["network"].Level != LevelOK {
		t.Errorf("a network-less executor should pass the network check, got %+v", byName["network"])
	}

	t.Run("missing image is a fatal finding with a fix", func(t *testing.T) {
		broken, err := New(Options{ID: "test-preflight-missing", Image: "cloop-test.invalid/nope:v0"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		rep := broken.Preflight(context.Background(), dir)
		if rep.OK() {
			t.Fatal("preflight must fail when the image is absent")
		}
		var imageFinding Finding
		for _, f := range rep.Findings {
			if f.Name == "image" {
				imageFinding = f
			}
		}
		if imageFinding.Level != LevelFail {
			t.Fatalf("image finding = %+v, want a failure", imageFinding)
		}
		if !strings.Contains(imageFinding.Fix, "pull") {
			t.Fatalf("the fix should name the pull command, got %q", imageFinding.Fix)
		}
	})
}

// TestIntegration_SmokeTest exercises the command behind `cloop executor
// test`: run the control plane's own binary inside the sandbox.
func TestIntegration_SmokeTest(t *testing.T) {
	// The control plane's binary is dynamically linked against glibc, so the
	// smoke test needs a glibc image rather than the musl-based default.
	ex := newTestExecutor(t, glibcTestImage, nil)

	result, err := ex.SmokeTest(context.Background(), "")
	if err != nil {
		t.Fatalf("SmokeTest: %v (output: %s)", err, result.Output)
	}
	if result.ExitCode != 0 {
		t.Fatalf("smoke test exit code = %d, want 0", result.ExitCode)
	}
	if result.MountedBinary == "" {
		t.Error("expected the control plane binary to be bind-mounted into the sandbox")
	}
	// `go test` builds a test binary, so the output is that binary's, not
	// cloop's. What matters is that the sandbox executed a host binary at
	// the expected path and produced something.
	if result.Output == "" {
		t.Error("the smoke test produced no output at all")
	}
}

// TestIntegration_ConcurrentRuns checks the driver's bookkeeping under
// concurrency, which is how the UI actually uses it (parallel PM mode runs
// several tasks at once).
func TestIntegration_ConcurrentRuns(t *testing.T) {
	ex := newTestExecutor(t, defaultTestImage, nil)
	const n = 4

	type outcome struct {
		out string
		err error
	}
	results := make(chan outcome, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			res, err := executor.Run(context.Background(), ex, executor.Spec{
				WorkDir: t.TempDir(),
				Argv:    []string{"/bin/sh", "-c", "echo worker-" + strconv.Itoa(i)},
			})
			results <- outcome{out: strings.TrimSpace(string(res.Output)), err: err}
		}(i)
	}

	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Errorf("concurrent run failed: %v", r.err)
				continue
			}
			if seen[r.out] {
				t.Errorf("duplicate output %q — handles are being confused between runs", r.out)
			}
			seen[r.out] = true
		case <-time.After(3 * time.Minute):
			t.Fatal("concurrent runs did not finish in time")
		}
	}
}

// drain consumes lines until the channel closes, signalling completion on the
// returned channel. Used by tests that care about the close, not the content.
func drain(lines <-chan executor.LogLine) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range lines {
		}
	}()
	return done
}
