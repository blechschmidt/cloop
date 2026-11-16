// Package isolation_test is the malicious-agent conformance suite (Task
// 20504): it proves, with the real cloop binary, that a run of one project
// can neither change another project nor read it unless the other project's
// readers list names it, on every kind of executor two projects can share.
//
// Each test starts a real hub (`cloop ui`, protected by a static token) that
// serves three projects besides its own directory:
//
//   - vault, the victim: a git checkout with a source file whose content is a
//     random canary, a file to delete, a .env, a canary in its .cloop, and a
//     run of its own held open while it is attacked, listening on a TCP port
//     and on a Unix socket in its own tree;
//   - mallory, the attacker, whose stand-in `claude` (testdata/hostile) is an
//     agent that has turned on the hub;
//   - library, whose readers list names mallory throughout: what mallory may
//     legitimately read, so that its run always holds a session to misuse and
//     every refusal below has a control that is not refused.
//
// mallory's agent is handed a plan in its task's description: the paths of
// vault's tree, its state database and canaries, the hub's control plane, the
// hub's and the victim run's processes and listeners, and the hub's routes.
// It tries to read, list, write, overwrite, append to, delete, move, re-mode,
// link to and plant a git hook in vault's tree, and to read and open for
// writing vault's .cloop/state.db and the hub's database, configuration and
// project registry; to read vault through a link and a hard link; to call
// /api/run/knowledge/search and /readonly/snapshot with its own session while
// naming vault, and every dashboard route that would read vault, add a task to
// it, run it or put mallory on its readers list, with its session and with no
// credential at all; and to reach vault's live run over TCP and its Unix
// socket, signal it and read its environment. The test then reads mallory's
// report, holds each verdict to what the platform promises, and checks that
// vault's tree, plan, canaries and the control plane's readers rows are as
// they were.
//
// That is done three times. With vault's readers list empty, every attempt on
// vault fails. After `cloop project readers add vault mallory`, mallory's run
// reads vault's source read-only where its executor puts it, and still cannot
// write it or reach its .cloop, .git or .env. After `cloop project readers rm`,
// every attempt fails again.
//
// The executors:
//
//   - TestAHostileRunOnTheHubsHostReachesNoOtherProject: the hub's own host,
//     where every run is kept to its project by the host sandbox once the hub
//     serves a second project — Landlock, under mount, PID and IPC namespaces
//     when the hub runs as root;
//   - TestAHostileRunOnADeviceReachesNoOtherProject: a remote device, a second
//     process speaking the agent protocol to the hub over a WebSocket, which
//     confines each host-mode payload to its project because both projects
//     are bound to it;
//   - TestAHostileRunInAContainerReachesNoOtherProject: the container
//     executor under Docker, with runc and, where Docker offers it, gVisor.
//
// The first two need only git and a kernel with Landlock (ABI 3, Linux 6.2):
// they run wherever `go test ./tests/isolation/` does, and skip, saying why,
// where Landlock is missing. The container test needs Docker and is opt-in:
//
//	CLOOP_ISOLATION_CONTAINER_E2E=1 go test ./tests/isolation/ -run Container -v
//
// CLOOP_ISOLATION_RUNTIMES (default "runc,runsc") names the OCI runtimes to
// try; one Docker does not list is skipped. CLOOP_ISOLATION_BIN (or
// CLOOP_FLAGSHIP_BIN, as CI's flagship job builds it) names the cloop to test,
// static for the container, and CLOOP_ISOLATION_HOSTILE_BIN a static build of
// testdata/hostile; otherwise the suite builds them, which needs Go and a
// writable build cache.
// CLOOP_ISOLATION_KEEP=1 keeps a test's directory, and CLOOP_ISOLATION_LOGS=1
// prints the hub's and the agent's logs even when a test passes.
//
// The host sandbox is a filesystem sandbox. It does not give a run a network
// of its own, so on the hub's host and on a device a run reaches another run's
// TCP listener and a Unix socket in its tree, and without namespaces it can
// change the mode of another project's files and, before Landlock ABI 6,
// signal its processes. These are the limits docs/security/model.md lists
// under "What is not mitigated"; the tests hold those probes to the same
// account, so a change in either is a change in both.
package isolation_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// goEnv is Go's cache locations as they were before TestMain moved HOME: the
// builds the suite makes would otherwise start cold in the isolated home and
// fill it with a gigabyte of objects.
var goEnv []string

func TestMain(m *testing.M) {
	for _, k := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "GOENV", "GOFLAGS", "GOTOOLCHAIN"} {
		if out, err := exec.Command("go", "env", k).Output(); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" {
				goEnv = append(goEnv, k+"="+v)
			}
		}
	}
	code := hometest.Isolate(m)
	for _, dir := range builtDirs {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

// repoRoot is the module's root.
func repoRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

var (
	buildMu   sync.Mutex
	built     = map[string]string{}
	builtErrs = map[string]error{}
	builtDirs []string
)

// build compiles pkg once per test binary, statically when static is set.
func build(t *testing.T, name, pkg string, static bool) string {
	t.Helper()
	key := fmt.Sprintf("%s|%s|%v", name, pkg, static)
	buildMu.Lock()
	defer buildMu.Unlock()
	if bin, ok := built[key]; ok {
		return bin
	}
	if err, ok := builtErrs[key]; ok {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "cloop-isolation-bin-*")
	if err != nil {
		t.Fatal(err)
	}
	builtDirs = append(builtDirs, dir)
	bin := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Dir = repoRoot()
	cmd.Env = append(append(os.Environ(), goEnv...), "CGO_ENABLED="+map[bool]string{true: "0", false: "1"}[static])
	if out, err := cmd.CombinedOutput(); err != nil {
		builtErrs[key] = fmt.Errorf("build %s: %v\n%s", pkg, err, out)
		t.Fatal(builtErrs[key])
	}
	built[key] = bin
	return bin
}

// cloopBinary is the cloop under test: the one the environment names, or one
// built from this checkout. A container gets it bind-mounted, so it must be
// static there; on the hub's host and a device the default build serves.
func cloopBinary(t *testing.T, static bool) string {
	t.Helper()
	for _, name := range []string{"CLOOP_ISOLATION_BIN", "CLOOP_FLAGSHIP_BIN"} {
		if bin := os.Getenv(name); bin != "" {
			if _, err := os.Stat(bin); err != nil {
				t.Fatalf("%s names %s: %v", name, bin, err)
			}
			return bin
		}
	}
	return build(t, "cloop", ".", static)
}

// hostileBinary is the hostile agent, testdata/hostile, built statically so
// one binary serves the hub's host, a device and a container image.
func hostileBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("CLOOP_ISOLATION_HOSTILE_BIN"); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("CLOOP_ISOLATION_HOSTILE_BIN names %s: %v", bin, err)
		}
		return bin
	}
	return build(t, "hostile", "./tests/isolation/testdata/hostile", true)
}
