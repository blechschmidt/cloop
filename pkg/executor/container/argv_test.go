package container

// argv_test.go is the security test suite for this driver.
//
// Every confinement guarantee the package doc advertises is an argument in a
// command line, so the only way to know a guarantee holds is to assert on the
// rendered argv. These tests therefore over-specify on purpose: they pin the
// exact flag list, the exact ordering around the `--` separator, and the
// exact set of arguments that must *never* appear. A refactor that quietly
// drops --cap-drop=ALL should fail loudly here rather than ship a sandbox
// that is a sandbox in name only.

import (
	"fmt"
	"strings"
	"testing"
)

// baseRequest is a minimal valid request: rootful runtime, no network, no
// limits. Tests mutate a copy.
func baseRequest() runRequest {
	return runRequest{
		Runtime: Runtime{Name: RuntimeDocker, Path: "/usr/bin/docker"},
		Image:   "example.com/cloop-harness:v1",
		Name:    "cloop-proj-abc123",
		Workspace: mount{
			HostPath:   "/srv/projects/proj",
			TargetPath: ContainerWorkspace,
		},
		User:    "1000:1000",
		Network: NetworkNone,
		Argv:    []string{"cloop", "run"},
		Labels:  map[string]string{LabelManaged: "true"},
	}
}

// mustBuild builds req or fails the test.
func mustBuild(t *testing.T, req runRequest) builtCommand {
	t.Helper()
	got, err := buildRunArgs(req)
	if err != nil {
		t.Fatalf("buildRunArgs: unexpected error: %v", err)
	}
	return got
}

// TestBuildRunArgs_FullCommandLine pins the complete rendering of a
// fully-populated request. It is deliberately a golden comparison rather than
// a set of "contains" assertions: ordering matters (every flag must precede
// `--`, the image must be the first positional), and a golden test is the
// only kind that catches a flag inserted in the wrong place.
func TestBuildRunArgs_FullCommandLine(t *testing.T) {
	req := baseRequest()
	req.Detach = true
	req.Network = NetworkBridge
	req.AddHosts = []string{"api.example.com:10.0.0.5"}
	req.CPUs = 1.5
	req.MemoryMB = 2048
	req.PIDsLimit = 512
	req.Workspace.SELinuxLabel = "z"
	req.ExtraMounts = []mount{{
		HostPath:   "/usr/local/bin/cloop",
		TargetPath: ContainerCloopPath,
		ReadOnly:   true,
		// Set explicitly: buildRunArgs renders what it is given, and it is
		// buildRequest that propagates the executor-wide SELinux label onto
		// extra mounts. TestBuildRequest_PropagatesSELinuxLabel covers that.
		SELinuxLabel: "z",
	}}
	req.EnvNames = []string{"ANTHROPIC_API_KEY", "GITHUB_TOKEN"}
	req.Env = []string{"ANTHROPIC_API_KEY=sk-ant-secret", "GITHUB_TOKEN=ghp_secret"}
	req.Labels = map[string]string{
		LabelManaged:  "true",
		LabelExecutor: "container",
		LabelHandle:   "c-abc123",
	}
	req.ExtraArgs = []string{"--dns=10.0.0.53"}

	want := []string{
		"run",
		"--detach",
		"--pull=never",
		"--name", "cloop-proj-abc123",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=512m",
		"--user", "1000:1000",
		"--network=bridge",
		"--add-host", "api.example.com:10.0.0.5",
		"--cpus", "1.5",
		"--memory", "2048m",
		"--memory-swap", "2048m",
		"--pids-limit", "512",
		"--workdir", "/workspace",
		"--volume", "/srv/projects/proj:/workspace:z",
		"--volume", "/usr/local/bin/cloop:/usr/local/bin/cloop:ro,z",
		"--label", "cloop.executor=container",
		"--label", "cloop.handle=c-abc123",
		"--label", "cloop.managed=true",
		"--env", "ANTHROPIC_API_KEY",
		"--env", "GITHUB_TOKEN",
		"--dns=10.0.0.53",
		"--",
		"example.com/cloop-harness:v1",
		"cloop", "run",
	}

	got := mustBuild(t, req)
	if diff := diffArgs(want, got.Args); diff != "" {
		t.Fatalf("argv mismatch:\n%s", diff)
	}
}

// TestBuildRunArgs_SecretsNeverInArgv is the single most important assertion
// in this file. Environment is forwarded by name so the runtime reads the
// value from its own environment; if a refactor switched to `--env K=V`, the
// secret would land in /proc/<pid>/cmdline where every user on the host can
// read it. That regression is invisible in behavioural tests — the workload
// still gets its variable — so it has to be tested here.
func TestBuildRunArgs_SecretsNeverInArgv(t *testing.T) {
	const secret = "sk-ant-super-secret-value"

	req := baseRequest()
	req.EnvNames = []string{"ANTHROPIC_API_KEY"}
	req.Env = []string{"ANTHROPIC_API_KEY=" + secret}

	got := mustBuild(t, req)

	for i, arg := range got.Args {
		if strings.Contains(arg, secret) {
			t.Fatalf("secret value leaked into argv at index %d: %q\nfull argv: %v", i, arg, got.Args)
		}
	}
	if !containsPair(got.Args, "--env", "ANTHROPIC_API_KEY") {
		t.Fatalf("expected bare `--env ANTHROPIC_API_KEY` passthrough, got %v", got.Args)
	}
	// The value must still reach the runtime, via its environment.
	if !contains(got.Env, "ANTHROPIC_API_KEY="+secret) {
		t.Fatalf("secret missing from runtime CLI environment: %v", redactEnv(got.Env))
	}
}

// TestBuildRunArgs_ConfinementFlagsAlwaysPresent asserts the non-negotiable
// flags survive every combination of optional settings. Table-driven over
// realistic configurations rather than one happy path, because a flag that is
// only emitted on some branch is the bug this catches.
func TestBuildRunArgs_ConfinementFlagsAlwaysPresent(t *testing.T) {
	variants := map[string]func(*runRequest){
		"minimal":            func(*runRequest) {},
		"detached":           func(r *runRequest) { r.Detach = true },
		"bridge network":     func(r *runRequest) { r.Network = NetworkBridge },
		"named network":      func(r *runRequest) { r.Network = "cloop-egress" },
		"rootless keep-id":   func(r *runRequest) { r.User = ""; r.KeepID = true },
		"with limits":        func(r *runRequest) { r.CPUs = 2; r.MemoryMB = 512; r.PIDsLimit = 64 },
		"unlimited pids":     func(r *runRequest) { r.PIDsLimit = -1 },
		"with env":           func(r *runRequest) { r.EnvNames = []string{"K"}; r.Env = []string{"K=v"} },
		"with extra args":    func(r *runRequest) { r.ExtraArgs = []string{"--dns=1.1.1.1"} },
		"with extra mounts":  func(r *runRequest) { r.ExtraMounts = []mount{{HostPath: "/a", TargetPath: "/b", ReadOnly: true}} },
		"with selinux label": func(r *runRequest) { r.Workspace.SELinuxLabel = "Z" },
	}

	// Flags whose absence silently removes a confinement guarantee.
	required := []string{
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pull=never",
	}

	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			req := baseRequest()
			mutate(&req)
			got := mustBuild(t, req)

			for _, flag := range required {
				if !contains(got.Args, flag) {
					t.Errorf("missing required confinement flag %q\nargv: %v", flag, got.Args)
				}
			}
			// Exactly one --workdir, always the fixed path.
			if !containsPair(got.Args, "--workdir", ContainerWorkspace) {
				t.Errorf("workload does not run in %s\nargv: %v", ContainerWorkspace, got.Args)
			}
			// A network flag is always explicit; relying on the runtime's
			// default would silently give the workload a bridge.
			if !hasPrefixArg(got.Args, "--network=") {
				t.Errorf("no explicit --network flag\nargv: %v", got.Args)
			}
		})
	}
}

// TestBuildRunArgs_DefaultsToNoNetwork verifies that an unset network is not
// merely undefined behaviour: the workload must end up with --network=none,
// because the runtime's own default is a bridge with full egress.
func TestBuildRunArgs_DefaultsToNoNetwork(t *testing.T) {
	req := baseRequest()
	req.Network = ""

	got := mustBuild(t, req)
	if !contains(got.Args, "--network=none") {
		t.Fatalf("empty network must render as --network=none, got %v", got.Args)
	}
}

// TestBuildRunArgs_SeparatorPrecedesImage pins the argv shape that stops an
// image reference or a workload argument from being re-read as a flag.
func TestBuildRunArgs_SeparatorPrecedesImage(t *testing.T) {
	req := baseRequest()
	req.Argv = []string{"cloop", "run", "--auto-evolve"}

	got := mustBuild(t, req)

	sep := indexOf(got.Args, "--")
	if sep < 0 {
		t.Fatalf("no `--` separator in argv: %v", got.Args)
	}
	if got.Args[sep+1] != req.Image {
		t.Fatalf("image must immediately follow `--`; got %q", got.Args[sep+1])
	}
	gotArgv := got.Args[sep+2:]
	if diff := diffArgs(req.Argv, gotArgv); diff != "" {
		t.Fatalf("workload argv mismatch after image:\n%s", diff)
	}
	// The workload's own --auto-evolve must appear only after the separator,
	// where the runtime cannot interpret it.
	if first := indexOf(got.Args, "--auto-evolve"); first < sep {
		t.Fatalf("workload flag appeared before the separator at %d (sep %d)", first, sep)
	}
}

// TestBuildRunArgs_UserMapping checks the two mutually exclusive UID
// strategies. Emitting both produces a container user with no mapping, where
// every file operation fails with a confusing EPERM.
func TestBuildRunArgs_UserMapping(t *testing.T) {
	t.Run("rootful uses explicit uid", func(t *testing.T) {
		req := baseRequest()
		req.User = "1000:1000"
		got := mustBuild(t, req)
		if !containsPair(got.Args, "--user", "1000:1000") {
			t.Fatalf("expected --user 1000:1000, got %v", got.Args)
		}
		if hasPrefixArg(got.Args, "--userns") {
			t.Fatalf("rootful run must not set --userns, got %v", got.Args)
		}
	})

	t.Run("rootless uses keep-id", func(t *testing.T) {
		req := baseRequest()
		req.User = ""
		req.KeepID = true
		got := mustBuild(t, req)
		if !contains(got.Args, "--userns=keep-id") {
			t.Fatalf("expected --userns=keep-id, got %v", got.Args)
		}
		if contains(got.Args, "--user") {
			t.Fatalf("keep-id run must not also set --user, got %v", got.Args)
		}
	})

	t.Run("both is rejected", func(t *testing.T) {
		req := baseRequest()
		req.User = "1000:1000"
		req.KeepID = true
		if _, err := buildRunArgs(req); err == nil {
			t.Fatal("expected --user + --userns=keep-id to be rejected")
		}
	})
}

// TestBuildRunArgs_ResourceLimits checks the rendering of each limit,
// including the swap pin without which a memory cap bounds nothing.
func TestBuildRunArgs_ResourceLimits(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*runRequest)
		want    []string
		notWant []string
	}{
		{
			name:    "no limits emits no limit flags",
			mutate:  func(*runRequest) {},
			notWant: []string{"--cpus", "--memory", "--memory-swap", "--pids-limit"},
		},
		{
			name:   "fractional cpus",
			mutate: func(r *runRequest) { r.CPUs = 0.5 },
			want:   []string{"--cpus", "0.5"},
		},
		{
			name:   "whole cpus render without trailing zeros",
			mutate: func(r *runRequest) { r.CPUs = 2 },
			want:   []string{"--cpus", "2"},
		},
		{
			name:   "memory pins swap to the same ceiling",
			mutate: func(r *runRequest) { r.MemoryMB = 512 },
			want:   []string{"--memory", "512m", "--memory-swap", "512m"},
		},
		{
			name:   "pids limit",
			mutate: func(r *runRequest) { r.PIDsLimit = 256 },
			want:   []string{"--pids-limit", "256"},
		},
		{
			name:   "explicitly unlimited pids",
			mutate: func(r *runRequest) { r.PIDsLimit = -1 },
			want:   []string{"--pids-limit", "-1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := baseRequest()
			tc.mutate(&req)
			got := mustBuild(t, req)
			for i := 0; i+1 < len(tc.want); i += 2 {
				if !containsPair(got.Args, tc.want[i], tc.want[i+1]) {
					t.Errorf("expected %q %q in argv, got %v", tc.want[i], tc.want[i+1], got.Args)
				}
			}
			for _, flag := range tc.notWant {
				if contains(got.Args, flag) {
					t.Errorf("unexpected %q in argv for a request with no limits: %v", flag, got.Args)
				}
			}
		})
	}
}

// TestBuildRunArgs_MountBoundary asserts the workspace is the only host path
// a caller can choose, and that nothing can shadow it.
func TestBuildRunArgs_MountBoundary(t *testing.T) {
	t.Run("workspace must target the fixed path", func(t *testing.T) {
		req := baseRequest()
		req.Workspace.TargetPath = "/somewhere-else"
		if _, err := buildRunArgs(req); err == nil {
			t.Fatal("expected a workspace mounted outside " + ContainerWorkspace + " to be rejected")
		}
	})

	t.Run("extra mount may not shadow the workspace", func(t *testing.T) {
		req := baseRequest()
		req.ExtraMounts = []mount{{HostPath: "/etc", TargetPath: ContainerWorkspace, ReadOnly: true}}
		if _, err := buildRunArgs(req); err == nil {
			t.Fatal("expected an extra mount targeting the workspace to be rejected")
		}
	})

	t.Run("empty workspace host path is rejected", func(t *testing.T) {
		req := baseRequest()
		req.Workspace.HostPath = ""
		if _, err := buildRunArgs(req); err == nil {
			t.Fatal("expected an empty workspace host path to be rejected")
		}
	})

	t.Run("read-only and selinux options render together", func(t *testing.T) {
		m := mount{HostPath: "/a", TargetPath: "/b", ReadOnly: true, SELinuxLabel: "z"}
		if got, want := m.String(), "/a:/b:ro,z"; got != want {
			t.Fatalf("mount.String() = %q, want %q", got, want)
		}
	})

	t.Run("only the configured mounts appear", func(t *testing.T) {
		req := baseRequest()
		got := mustBuild(t, req)
		var volumes []string
		for i, a := range got.Args {
			if a == "--volume" && i+1 < len(got.Args) {
				volumes = append(volumes, got.Args[i+1])
			}
		}
		if len(volumes) != 1 || volumes[0] != "/srv/projects/proj:/workspace" {
			t.Fatalf("expected exactly the workspace bind mount, got %v", volumes)
		}
	})
}

// TestBuildRunArgs_EnvValidation covers the ways a forwarded variable can be
// wrong. The unset case matters most: both runtimes silently omit a variable
// with no value, so a dropped API key would surface as an authentication
// failure inside the sandbox that looks nothing like its cause.
func TestBuildRunArgs_EnvValidation(t *testing.T) {
	cases := []struct {
		name     string
		envNames []string
		env      []string
		wantErr  string
	}{
		{
			name:     "forwarded but unset is rejected",
			envNames: []string{"ANTHROPIC_API_KEY"},
			env:      nil,
			wantErr:  "silently dropped",
		},
		{
			name:     "name containing = is rejected",
			envNames: []string{"FOO=BAR"},
			env:      []string{"FOO=BAR=baz"},
			wantErr:  "invalid character",
		},
		{
			name:     "empty name is rejected",
			envNames: []string{""},
			env:      []string{"=x"},
			wantErr:  "is empty",
		},
		{
			name:     "name starting with a digit is rejected",
			envNames: []string{"1PATH"},
			env:      []string{"1PATH=/x"},
			wantErr:  "invalid character",
		},
		{
			name:     "name with a space is rejected",
			envNames: []string{"MY VAR"},
			env:      []string{"MY VAR=x"},
			wantErr:  "invalid character",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := baseRequest()
			req.EnvNames = tc.envNames
			req.Env = tc.env
			_, err := buildRunArgs(req)
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}

	t.Run("duplicate names are forwarded once", func(t *testing.T) {
		req := baseRequest()
		req.EnvNames = []string{"TOKEN", "TOKEN"}
		req.Env = []string{"TOKEN=v"}
		got := mustBuild(t, req)
		if n := countPair(got.Args, "--env", "TOKEN"); n != 1 {
			t.Fatalf("expected TOKEN forwarded once, got %d times: %v", n, got.Args)
		}
	})

	t.Run("empty value is still forwarded", func(t *testing.T) {
		// An explicitly-empty variable is a legitimate signal (e.g.
		// NO_COLOR=""), distinct from an absent one.
		req := baseRequest()
		req.EnvNames = []string{"NO_COLOR"}
		req.Env = []string{"NO_COLOR="}
		got := mustBuild(t, req)
		if !containsPair(got.Args, "--env", "NO_COLOR") {
			t.Fatalf("expected NO_COLOR to be forwarded, got %v", got.Args)
		}
	})
}

// TestValidateExtraArgs_DenylistIsExhaustive walks every entry in the
// denylist and asserts both spellings are rejected. Writing the loop over the
// map rather than a hand-copied list means adding a flag to deniedExtraArgs
// automatically extends the test — the two cannot drift apart.
func TestValidateExtraArgs_DenylistIsExhaustive(t *testing.T) {
	if len(deniedExtraArgs) == 0 {
		t.Fatal("denylist is empty — the operator escape hatch is unguarded")
	}
	for flag, reason := range deniedExtraArgs {
		if reason == "" {
			t.Errorf("denied flag %q has no stated reason; the error message would be useless", flag)
		}
		for _, form := range []string{flag, flag + "=value"} {
			t.Run(form, func(t *testing.T) {
				err := ValidateExtraArgs([]string{form})
				if err == nil {
					t.Fatalf("extra arg %q must be rejected (%s)", form, reason)
				}
				if !strings.Contains(err.Error(), "not allowed") {
					t.Fatalf("error for %q should say it is not allowed, got: %v", form, err)
				}
			})
		}
	}
}

// TestValidateExtraArgs_SandboxEscapesRejected spells out the escapes that
// matter most, so the intent survives even if the denylist is restructured.
func TestValidateExtraArgs_SandboxEscapesRejected(t *testing.T) {
	escapes := map[string][]string{
		"privileged mode":       {"--privileged"},
		"capability re-add":     {"--cap-add=SYS_ADMIN"},
		"host network":          {"--network=host"},
		"arbitrary bind mount":  {"--volume=/:/host"},
		"short bind mount":      {"-v", "/:/host"},
		"host pid namespace":    {"--pid=host"},
		"host ipc namespace":    {"--ipc=host"},
		"device passthrough":    {"--device=/dev/kmsg"},
		"seccomp disable":       {"--security-opt=seccomp=unconfined"},
		"user override":         {"--user=0:0"},
		"userns override":       {"--userns=host"},
		"entrypoint override":   {"--entrypoint=/bin/sh"},
		"env injection":         {"--env=ANTHROPIC_API_KEY=stolen"},
		"env file injection":    {"--env-file=/etc/secrets"},
		"auto-remove":           {"--rm"},
		"name override":         {"--name=whatever"},
		"workdir override":      {"--workdir=/"},
		"implicit pull":         {"--pull=always"},
		"restart policy":        {"--restart=always"},
		"cgroup reparent":       {"--cgroup-parent=/"},
		"host cgroup namespace": {"--cgroupns=host"},
	}
	for name, args := range escapes {
		t.Run(name, func(t *testing.T) {
			if err := ValidateExtraArgs(args); err == nil {
				t.Fatalf("%v must be rejected: it dismantles the sandbox", args)
			}
		})
	}
}

// TestValidateExtraArgs_PositionalsRejected covers the subtle failure: a bare
// value in extra_args would be consumed by the runtime as the image
// reference, promoting the real image into the command position and running
// an operator-chosen image instead.
func TestValidateExtraArgs_PositionalsRejected(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"bare image reference", []string{"evil/image:latest"}},
		{"flag with detached value", []string{"--dns", "1.1.1.1"}},
		{"empty string", []string{""}},
		{"whitespace only", []string{"   "}},
		{"lone dash", []string{"-"}},
		{"lone double dash", []string{"--"}},
		{"newline injection", []string{"--dns=1.1.1.1\n--privileged"}},
		{"null byte", []string{"--dns=1.1.1.1\x00"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateExtraArgs(tc.args); err == nil {
				t.Fatalf("%q must be rejected", tc.args)
			}
		})
	}
}

// TestValidateExtraArgs_Allowed keeps the escape hatch usable: legitimate
// tuning flags in --flag=value form must pass.
func TestValidateExtraArgs_Allowed(t *testing.T) {
	allowed := [][]string{
		{"--dns=10.0.0.53"},
		{"--dns-search=corp.example.com"},
		{"--label=team=platform"},
		{"--ulimit=nofile=4096:8192"},
		{"--cap-drop=NET_RAW"}, // strictly more confined; fine
		{"--dns=10.0.0.53", "--dns-search=corp.example.com"},
		nil,
	}
	for _, args := range allowed {
		if err := ValidateExtraArgs(args); err != nil {
			t.Errorf("ValidateExtraArgs(%v) = %v, want nil", args, err)
		}
	}
}

// TestValidateExtraArgs_Bounded stops a config file from becoming an
// unbounded command line.
func TestValidateExtraArgs_Bounded(t *testing.T) {
	many := make([]string, maxExtraArgs+1)
	for i := range many {
		many[i] = fmt.Sprintf("--dns=10.0.0.%d", i)
	}
	if err := ValidateExtraArgs(many); err == nil {
		t.Fatalf("expected more than %d extra args to be rejected", maxExtraArgs)
	}
	if err := ValidateExtraArgs(many[:maxExtraArgs]); err != nil {
		t.Fatalf("exactly %d extra args should be accepted, got %v", maxExtraArgs, err)
	}
}

// TestValidateNetwork covers the modes and the escapes.
func TestValidateNetwork(t *testing.T) {
	valid := []string{"none", "bridge", "cloop-egress", "my_net.1"}
	for _, n := range valid {
		if err := ValidateNetwork(n); err != nil {
			t.Errorf("ValidateNetwork(%q) = %v, want nil", n, err)
		}
	}

	invalid := map[string]string{
		"host":            "removes network isolation entirely",
		"container:other": "joins another container's namespace",
		"-x":              "would be parsed as a flag",
		"net work":        "contains whitespace",
		"net;rm -rf":      "contains shell metacharacters",
	}
	for n, why := range invalid {
		if err := ValidateNetwork(n); err == nil {
			t.Errorf("ValidateNetwork(%q) must fail: %s", n, why)
		}
	}
}

// TestValidateImageRef guards the first positional argument.
func TestValidateImageRef(t *testing.T) {
	valid := []string{
		"alpine",
		"alpine:3.20",
		"ghcr.io/blechschmidt/cloop-harness:latest",
		"registry.example.com:5000/team/img@sha256:abc123",
	}
	for _, ref := range valid {
		if err := ValidateImageRef(ref); err != nil {
			t.Errorf("ValidateImageRef(%q) = %v, want nil", ref, err)
		}
	}

	invalid := map[string]string{
		"":                 "empty",
		"-privileged":      "would be parsed as a flag",
		"alpine; rm -rf /": "shell metacharacters",
		"alpine\nrun":      "newline",
		"img$(whoami)":     "command substitution",
		"img with space":   "whitespace",
	}
	for ref, why := range invalid {
		if err := ValidateImageRef(ref); err == nil {
			t.Errorf("ValidateImageRef(%q) must fail: %s", ref, why)
		}
	}
	if err := ValidateImageRef(strings.Repeat("a", 513)); err == nil {
		t.Error("an over-long image reference must be rejected")
	}
}

// TestValidateContainerName pins the runtimes' shared name grammar so a
// derived name can never be rejected at run time or parsed as a flag.
func TestValidateContainerName(t *testing.T) {
	valid := []string{"cloop-proj-abc123", "a", "A1_b.c-d"}
	for _, n := range valid {
		if err := validateContainerName(n); err != nil {
			t.Errorf("validateContainerName(%q) = %v, want nil", n, err)
		}
	}
	invalid := []string{"", "-leading-dash", ".leading-dot", "_leading-underscore", "has space", "has/slash", strings.Repeat("a", 129)}
	for _, n := range invalid {
		if err := validateContainerName(n); err == nil {
			t.Errorf("validateContainerName(%q) must fail", n)
		}
	}
}

// TestValidateAddHost covers the resolution pins.
func TestValidateAddHost(t *testing.T) {
	if err := validateAddHost("api.example.com:10.0.0.5"); err != nil {
		t.Errorf("valid add-host rejected: %v", err)
	}
	for _, bad := range []string{"api.example.com", "", ":10.0.0.5", "api.example.com:", "a:b:c", "-x:1.2.3.4", "a b:1.2.3.4"} {
		if err := validateAddHost(bad); err == nil {
			t.Errorf("validateAddHost(%q) must fail", bad)
		}
	}
}

// TestLabelHandling checks deterministic ordering (so the command line is
// diffable and testable) and that a hostile label value cannot break out of
// its argument.
func TestLabelHandling(t *testing.T) {
	t.Run("labels are sorted", func(t *testing.T) {
		req := baseRequest()
		req.Labels = map[string]string{"cloop.z": "1", "cloop.a": "2", "cloop.m": "3"}
		got := mustBuild(t, req)
		var labels []string
		for i, a := range got.Args {
			if a == "--label" && i+1 < len(got.Args) {
				labels = append(labels, got.Args[i+1])
			}
		}
		want := []string{"cloop.a=2", "cloop.m=3", "cloop.z=1"}
		if diff := diffArgs(want, labels); diff != "" {
			t.Fatalf("labels not deterministically ordered:\n%s", diff)
		}
	})

	t.Run("newlines in values are neutralised", func(t *testing.T) {
		req := baseRequest()
		req.Labels = map[string]string{"cloop.project": "/srv/a\nb"}
		got := mustBuild(t, req)
		for _, a := range got.Args {
			if strings.ContainsAny(a, "\n\r\x00") {
				t.Fatalf("control character survived into argv: %q", a)
			}
		}
	})

	t.Run("hostile label keys are rejected", func(t *testing.T) {
		req := baseRequest()
		req.Labels = map[string]string{"--privileged": "true"}
		if _, err := buildRunArgs(req); err == nil {
			t.Fatal("a label key that looks like a flag must be rejected")
		}
	})
}

// TestFormatCPUs pins the rendering used in argv.
func TestFormatCPUs(t *testing.T) {
	cases := map[float64]string{
		1:     "1",
		1.5:   "1.5",
		0.5:   "0.5",
		2.25:  "2.25",
		0.001: "0.001",
		16:    "16",
	}
	for in, want := range cases {
		if got := formatCPUs(in); got != want {
			t.Errorf("formatCPUs(%v) = %q, want %q", in, got, want)
		}
	}
}

// TestContainerName checks the deterministic naming that makes orphans
// reapable, including the hostile inputs a project directory name can carry.
func TestContainerName(t *testing.T) {
	cases := []struct {
		workDir string
		runID   string
		want    string
	}{
		{"/srv/projects/netgraph", "c-abc123", "cloop-netgraph-abc123"},
		{"/srv/projects/My Project", "c-deadbe", "cloop-my-project-deadbe"},
		{"/srv/projects/weird!!!name", "c-01", "cloop-weird-name-01"},
		{"/srv/projects/.hidden", "c-02", "cloop-hidden-02"},
		{"/", "c-03", "cloop-project-03"},
		{"", "c-04", "cloop-project-04"},
		{"/srv/projects/---", "c-05", "cloop-project-05"},
	}
	for _, tc := range cases {
		got := ContainerName(tc.workDir, tc.runID)
		if got != tc.want {
			t.Errorf("ContainerName(%q, %q) = %q, want %q", tc.workDir, tc.runID, got, tc.want)
		}
		// Whatever the input, the result must be a name the runtime accepts.
		if err := validateContainerName(got); err != nil {
			t.Errorf("ContainerName(%q, %q) produced an invalid name %q: %v", tc.workDir, tc.runID, got, err)
		}
	}
}

// TestContainerNameAlwaysValid fuzzes the slug generator with the kinds of
// directory names a real filesystem permits, since an invalid name would make
// every run in that project fail.
func TestContainerNameAlwaysValid(t *testing.T) {
	hostile := []string{
		"/a/éèê",                         // non-ASCII
		"/a/" + strings.Repeat("x", 200), // very long
		"/a/....",
		"/a/-",
		"/a/ ",
		"/a/\t",
		"/a/..",
		"/a/CAPS",
		"/a/123",
	}
	for _, dir := range hostile {
		name := ContainerName(dir, "c-abcdef")
		if err := validateContainerName(name); err != nil {
			t.Errorf("ContainerName(%q) = %q is not a valid container name: %v", dir, name, err)
		}
	}
}

// --- helpers ---------------------------------------------------------

func contains(haystack []string, needle string) bool { return indexOf(haystack, needle) >= 0 }

func indexOf(haystack []string, needle string) int {
	for i, s := range haystack {
		if s == needle {
			return i
		}
	}
	return -1
}

func hasPrefixArg(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func containsPair(args []string, flag, value string) bool { return countPair(args, flag, value) > 0 }

func countPair(args []string, flag, value string) int {
	n := 0
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			n++
		}
	}
	return n
}

// diffArgs renders a readable difference between two argument lists.
func diffArgs(want, got []string) string {
	if len(want) == len(got) {
		same := true
		for i := range want {
			if want[i] != got[i] {
				same = false
				break
			}
		}
		if same {
			return ""
		}
	}
	var b strings.Builder
	max := len(want)
	if len(got) > max {
		max = len(got)
	}
	for i := 0; i < max; i++ {
		w, g := "<missing>", "<missing>"
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		marker := "  "
		if w != g {
			marker = "->"
		}
		fmt.Fprintf(&b, "%s [%2d] want=%-45q got=%q\n", marker, i, w, g)
	}
	return b.String()
}

// redactEnv hides values so a failing assertion cannot print a secret into
// CI logs.
func redactEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			out = append(out, kv[:i]+"=<redacted>")
			continue
		}
		out = append(out, "<malformed>")
	}
	return out
}
