package security

// Guarantee 5: the container executor never builds a command line that
// dismantles its own sandbox.
//
// Every confinement property of this driver is a flag on one command line.
// There is no runtime check afterwards, no kernel enforcing cloop's intent —
// if `--privileged` appears, the sandbox is gone, and nothing in the system
// will say so. The container will start, the workload will run, the logs will
// look identical. That is the failure mode this file exists for: a security
// property whose absence is invisible.
//
// The assertions run against the real argv builder (container.AuditRunArgv,
// which calls the same buildRequest/buildRunArgs that Start calls) rather than
// a reimplementation, and they need no container runtime installed, so they
// run everywhere CI does.

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
)

// forbiddenFlagSubstrings are the argv fragments that would undo the sandbox.
// Matching on substrings rather than exact tokens catches the `--flag=value`
// spelling as well as `--flag value`.
var forbiddenFlagSubstrings = []struct {
	frag string
	why  string
}{
	{"--privileged", "grants all capabilities and disables seccomp/apparmor — a full host takeover from inside the container"},
	{"--net=host", "removes the network namespace: the workload reaches every service on the host's loopback, including cloop's own API"},
	{"--network=host", "same as --net=host"},
	{"--pid=host", "exposes every host process, making other tenants' command lines and /proc readable"},
	{"--ipc=host", "shares SysV IPC and shared memory with the host"},
	{"--uts=host", "shares the host's UTS namespace"},
	{"--userns=host", "disables user-namespace remapping, so container uid 0 is host uid 0"},
	{"--cap-add", "re-adds a capability that --cap-drop=ALL removed"},
	{"--security-opt=seccomp=unconfined", "disables the seccomp filter"},
	{"--security-opt=apparmor=unconfined", "disables the AppArmor profile"},
	{"docker.sock", "mounting the runtime socket is equivalent to giving the workload root on the host"},
	{"containerd.sock", "same as docker.sock"},
	{"podman.sock", "same as docker.sock"},
	{"/var/run/docker", "the runtime socket's directory"},
}

// auditSpec is a representative workload.
func auditSpec() executor.Spec {
	return executor.Spec{Argv: []string{"cloop", "run"}}
}

// nonRootWorkDir returns a temp directory owned by a non-root user.
//
// The UID the driver picks comes from the project directory's owner, so this
// choice is what the test is actually about. When the suite runs as root
// (containers in CI, and this project's own deployment) t.TempDir() is
// root-owned and the driver correctly refuses; chowning it to an unprivileged
// UID reproduces the configuration an operator is supposed to have.
func nonRootWorkDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if os.Geteuid() != 0 {
		return dir // already owned by an unprivileged user
	}
	const uid, gid = 1000, 1000
	if err := os.Chown(dir, uid, gid); err != nil {
		t.Skipf("running as root and cannot chown a temp dir to an unprivileged "+
			"uid (%v); the non-root-user assertions need one", err)
	}
	return dir
}

// TestContainerArgvNeverBreaksItsOwnSandbox is the core assertion.
func TestContainerArgvNeverBreaksItsOwnSandbox(t *testing.T) {
	workDir := nonRootWorkDir(t)

	// Sweep the option surface an operator can actually set. A flag that only
	// appears under one configuration is still a hole.
	cases := map[string]container.Options{
		"defaults":            {},
		"bridge networking":   {Network: "bridge"},
		"named network":       {Network: "cloop-egress"},
		"selinux relabel":     {SELinuxLabel: "z"},
		"resource limits":     {CPUs: 2, MemoryMB: 4096, PIDsLimit: 256},
		"pids unlimited":      {PIDsLimit: -1},
		"allow-hosts pinning": {Network: "bridge", AllowHosts: []string{"api.example.com:10.0.0.5"}},
		"extra args":          {ExtraArgs: []string{"--dns=10.0.0.53"}},
	}

	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			for _, rootless := range []bool{false, true} {
				rt := container.AuditRuntime{Name: "docker", Rootless: rootless}
				argv, err := container.AuditRunArgv(opts, rt, workDir, auditSpec())
				if err != nil {
					t.Fatalf("rootless=%v: AuditRunArgv: %v", rootless, err)
				}
				assertSandboxIntact(t, argv, rootless)
			}
		})
	}
}

func assertSandboxIntact(t *testing.T, argv []string, rootless bool) {
	t.Helper()
	joined := strings.Join(argv, " ")

	for _, bad := range forbiddenFlagSubstrings {
		if strings.Contains(joined, bad.frag) {
			t.Errorf("argv contains %q, which %s\nfull argv: %v", bad.frag, bad.why, argv)
		}
	}

	// Positive assertions: the flags that must always be there. Their absence
	// is exactly as dangerous as a forbidden flag's presence, and much easier
	// to introduce by accident.
	for _, required := range []struct{ flag, why string }{
		{"--cap-drop=ALL", "without it the container keeps the runtime's default capability set"},
		{"--security-opt=no-new-privileges", "without it a setuid binary in the image can undo --user"},
		{"--read-only", "without it a compromised workload can persist by rewriting the image's writable layer"},
	} {
		if !containsArg(argv, required.flag) {
			t.Errorf("argv is missing %s — %s\nfull argv: %v", required.flag, required.why, argv)
		}
	}

	assertNonRootUser(t, argv, rootless)
	assertNoHostRootBindMount(t, argv)
}

// assertNonRootUser checks the workload does not run as uid 0.
//
// Rootless podman gets there via --userns=keep-id, which maps the invoking
// (unprivileged) host user; every other configuration must name a numeric
// non-zero UID with --user.
func assertNonRootUser(t *testing.T, argv []string, rootless bool) {
	t.Helper()
	if rootless {
		if !containsArg(argv, "--userns=keep-id") {
			t.Errorf("rootless argv lacks --userns=keep-id, so the workload's uid "+
				"is whatever the image defaults to (usually root)\nargv: %v", argv)
		}
		return
	}
	user, ok := flagValue(argv, "--user")
	if !ok {
		t.Fatalf("argv has no --user flag: the workload runs as the image's "+
			"default user, which is root in almost every base image\nargv: %v", argv)
	}
	uidField, _, _ := strings.Cut(user, ":")
	uid, err := strconv.Atoi(uidField)
	if err != nil {
		t.Fatalf("--user %q is not a numeric uid; root-ness cannot be verified", user)
	}
	if uid == 0 {
		t.Errorf("--user %q runs the workload as root inside the container, which "+
			"defeats --cap-drop=ALL and turns a runtime escape into host root", user)
	}
}

// assertNoHostRootBindMount checks no bind mount exposes a host path that
// would hand the workload the host's filesystem.
func assertNoHostRootBindMount(t *testing.T, argv []string) {
	t.Helper()
	for i, a := range argv {
		if a != "--volume" && a != "-v" && a != "--mount" {
			continue
		}
		if i+1 >= len(argv) {
			t.Fatalf("%s is the last argument, with no value\nargv: %v", a, argv)
		}
		spec := argv[i+1]
		host, _, _ := strings.Cut(spec, ":")
		switch {
		case host == "/":
			t.Errorf("bind mount %q exposes the host root filesystem to the workload", spec)
		case host == "/etc" || strings.HasPrefix(host, "/etc/"):
			t.Errorf("bind mount %q exposes host system configuration", spec)
		case host == "/root" || strings.HasPrefix(host, "/root/"):
			t.Errorf("bind mount %q exposes the host root user's home directory", spec)
		case host == "/proc" || host == "/sys" || strings.HasPrefix(host, "/sys/"):
			t.Errorf("bind mount %q exposes host kernel interfaces", spec)
		case host == "/var/run" || host == "/run":
			t.Errorf("bind mount %q exposes host runtime sockets", spec)
		}
	}
}

// TestContainerRefusesRootUser proves the refusal is real and not merely a
// default that a caller can drift past. This is the configuration that
// produced a silent root sandbox before: a control plane running as root over
// a root-owned project directory.
func TestContainerRefusesRootUser(t *testing.T) {
	if os.Geteuid() != 0 {
		// The refusal is driven by the workdir owner, which we cannot forge
		// without privileges.
		t.Skip("needs root to create a root-owned project directory")
	}
	rootOwned := t.TempDir() // owned by root because we are root

	_, err := container.AuditRunArgv(container.Options{},
		container.AuditRuntime{Name: "docker"}, rootOwned, auditSpec())
	if err == nil {
		t.Fatal("a root-owned project directory produced a container spec without " +
			"complaint; the workload would have run as uid 0")
	}
	if !strings.Contains(err.Error(), "uid 0") {
		t.Errorf("refusal does not explain the problem: %v", err)
	}

	// And the opt-out must work, or an operator with a legitimately root-owned
	// deployment has no path forward and will disable the sandbox entirely.
	argv, err := container.AuditRunArgv(container.Options{AllowRootUser: true},
		container.AuditRuntime{Name: "docker"}, rootOwned, auditSpec())
	if err != nil {
		t.Fatalf("AllowRootUser did not permit a root sandbox: %v", err)
	}
	// Even with the opt-out, everything else must still hold.
	for _, required := range []string{"--cap-drop=ALL", "--read-only", "--security-opt=no-new-privileges"} {
		if !containsArg(argv, required) {
			t.Errorf("AllowRootUser also dropped %s\nargv: %v", required, argv)
		}
	}
}

// TestValidateNonRootUserRejectsRootSpellings covers the ways uid 0 can be
// written. A check that only catches "0" is defeated by "0:0" or "root".
func TestValidateNonRootUserRejectsRootSpellings(t *testing.T) {
	for _, tc := range []struct {
		user    string
		wantErr bool
	}{
		{"0", true},
		{"0:0", true},
		{"0:1000", true},
		{"root", true}, // non-numeric: cannot be verified, so refused
		{"root:root", true},
		{"", true}, // unset means the image default, which is root
		{"  ", true},
		{"1000", false},
		{"1000:1000", false},
		{"65534:65534", false},
	} {
		t.Run("user="+tc.user, func(t *testing.T) {
			err := container.ValidateNonRootUser(tc.user)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateNonRootUser(%q) error = %v, wantErr = %v",
					tc.user, err, tc.wantErr)
			}
		})
	}
}

// TestContainerRejectsHostNetworkSpellings pins the network refusal, including
// the container:<id> form that joins another container's namespace.
func TestContainerRejectsHostNetworkSpellings(t *testing.T) {
	for _, name := range []string{"host", "container:abc123"} {
		if err := container.ValidateNetwork(name); err == nil {
			t.Errorf("ValidateNetwork(%q) = nil, want an error: it removes the "+
				"network boundary the sandbox depends on", name)
		}
	}
	for _, name := range []string{"none", "bridge", "cloop-egress"} {
		if err := container.ValidateNetwork(name); err != nil {
			t.Errorf("ValidateNetwork(%q) = %v, want nil", name, err)
		}
	}
}

// TestContainerRejectsSandboxEscapingExtraArgs checks the operator-supplied
// passthrough cannot be used to add back what the driver removed. Config is
// attacker-adjacent in a multi-tenant deployment: whoever can edit a
// config.yaml would otherwise have a one-line container escape.
func TestContainerRejectsSandboxEscapingExtraArgs(t *testing.T) {
	workDir := nonRootWorkDir(t)

	escapes := []string{
		"--privileged",
		"--network=host",
		"--net=host",
		"--pid=host",
		"--cap-add=SYS_ADMIN",
		"--user=0:0",
		"--security-opt=seccomp=unconfined",
		"--volume=/:/host",
		"-v=/var/run/docker.sock:/var/run/docker.sock",
		"--userns=host",
		"--read-only=false",
	}
	for _, arg := range escapes {
		t.Run(arg, func(t *testing.T) {
			argv, err := container.AuditRunArgv(
				container.Options{ExtraArgs: []string{arg}},
				container.AuditRuntime{Name: "docker"}, workDir, auditSpec())
			if err != nil {
				return // rejected outright, which is the preferred outcome
			}
			// If it was accepted, it must at least not have reached argv.
			if containsArg(argv, arg) {
				t.Errorf("extra arg %q was passed through to the runtime and "+
					"dismantles the sandbox\nargv: %v", arg, argv)
			}
			assertSandboxIntact(t, argv, false)
		})
	}
}

// TestContainerSecretsNeverEnterArgv guards the process table. Environment is
// forwarded as bare `--env NAME` so the runtime CLI reads the value from its
// own environment; the `--env K=V` spelling would publish every brokered
// credential to any user who can read /proc on the host.
func TestContainerSecretsNeverEnterArgv(t *testing.T) {
	workDir := nonRootWorkDir(t)
	const secret = "ghp_conformanceSuiteCanaryValue0123456789"

	spec := auditSpec()
	spec.Env = []string{"GITHUB_TOKEN=" + secret, "ANTHROPIC_API_KEY=sk-ant-" + secret}

	argv, err := container.AuditRunArgv(container.Options{},
		container.AuditRuntime{Name: "docker"}, workDir, spec)
	if err != nil {
		t.Fatalf("AuditRunArgv: %v", err)
	}
	assertNoSecretLeak(t, strings.Join(argv, " "), secret, "container argv")

	// The name must still be forwarded, or the workload never sees the value.
	if !containsArg(argv, "GITHUB_TOKEN") {
		t.Errorf("GITHUB_TOKEN was not forwarded by name\nargv: %v", argv)
	}
}

func containsArg(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

// flagValue returns the value of `--flag value` or `--flag=value`.
func flagValue(argv []string, flag string) (string, bool) {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1], true
		}
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v, true
		}
	}
	return "", false
}
