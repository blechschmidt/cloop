// Package flagship_test runs cloop's headline claim end to end and checks it.
//
// The claim is the reason this project exists: the web UI never spawns a
// harness on the host — it runs the task in a sandbox, hands that sandbox only
// the credentials an operator granted it, takes the result back, and destroys
// the credential material afterwards. Every part of that was covered by unit
// tests against fakes, and the whole was covered by nothing. The container and
// Kubernetes suites all skip when no runtime is present, `cloop executor test`
// runs `cloop version` rather than a task, and deploy/eval/e2e.sh exercises the
// *remote agent* and is not wired into CI. So the flagship path was verified by
// hand, on one machine, by one person.
//
// This test boots the real circuit — bootstrap a hub, register a container
// executor, grant a repository-scoped credential against a throwaway local git
// remote, dispatch one task through POST /api/run — and then asserts the four
// things that actually matter:
//
//  1. no harness process was spawned on the control-plane host;
//  2. the task ran inside the container, under the configured uid, with
//     capabilities dropped and the configured network policy;
//  3. the commit the sandbox produced came back to the hub; and
//  4. the lease material is gone from the host afterwards.
//
// # What "came back" means for this driver
//
// The container driver reports SupportsWriteBack: false, and that is a design
// decision rather than a gap — see pkg/executor/container.Capabilities. Its
// /workspace *is* the hub's project directory, mounted through, so there is no
// tree to ship anywhere; Spec.WriteBack's push and bundle modes exist for the
// drivers whose filesystem dies with the workload, and placement would refuse
// a WriteBack spec on this executor rather than honour it.
//
// So the return path asserted here is the one this driver actually has: the
// sandbox commits and pushes to a bare repository it can reach *only* through
// the bind mount its local_repo grant produced. That is a stronger assertion
// than reading the shared workspace would be, because the shared workspace
// would be satisfied by a file the host could have written itself. The commit
// arriving in the remote proves both that the grant was delivered and that the
// result travelled.
//
// Building it found three defects that no other test could see. They are fixed
// in the same change and named here because each is a reason this test exists:
// state.Load followed a WorkDir persisted from the hub's filesystem into a
// sandbox where it named nothing; statedb then let the sandbox overwrite the
// hub's record of that path; and pkg/ui's applyLease seeded Spec.Env from
// os.Environ(), which forwarded the hub's entire environment — CLOOP_SECRET_KEY
// and CLOOP_UI_TOKEN included — into a container running model-authored code.
//
// # Determinism
//
// The container suites are known to flake under load, so nothing here waits on
// wall-clock time. Every wait is an explicit poll for a specific condition
// under a hard per-step deadline that fails naming the condition, the base
// image is pinned by digest, and the sandbox image is built locally and run
// with --pull=never so no registry is consulted while the circuit is live.
//
// The load-bearing evidence is collected *inside* the sandbox and travels out
// in the commit, rather than being scraped from `docker inspect` while the
// container happens to be up. A container that lives for a few hundred
// milliseconds is a race to observe; a commit is not.
package flagship_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/hometest"
)

func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }

// enableEnv opts this test in. It is off by default because it is not a unit
// test: it drives the machine's Docker daemon, stages files under /dev/shm and
// binds a TCP port, none of which belong in `go test ./...` on a developer's
// laptop or in the race suite. The CI job that owns it sets this.
const enableEnv = "CLOOP_FLAGSHIP_E2E"

// binEnv supplies a prebuilt, statically linked cloop. CI already built one;
// rebuilding it here would add a minute to the job for no gain. Absent, the
// test builds its own.
const binEnv = "CLOOP_FLAGSHIP_BIN"

// keepEnv leaves the tree and the hub log behind for debugging a failure.
const keepEnv = "CLOOP_FLAGSHIP_KEEP"

// root is a fixed path rather than t.TempDir(), for two reasons that are both
// about the sandbox rather than about the test.
//
// The hub dispatches its own binary as argv[0] (see pkg/ui.Server.selfExe), so
// the path the hub runs from has to exist inside the sandbox image too — which
// means it must be known when the image is built. A fresh temporary path per
// run would rebuild the image every time and defeat the layer cache.
//
// It is under /var/tmp and not /tmp because the container driver mounts a
// tmpfs over /tmp, which would hide anything the image had placed there.
//
// The cost is that two copies of this test cannot run on one machine at once.
// That is already true — it binds a fixed port and reads a machine-global
// /dev/shm — so a fixed root makes an existing constraint visible instead of
// pretending it is not there.
const root = "/var/tmp/cloop-flagship"

// hubPort is the port the hub under test listens on. High and fixed, for the
// same reason root is fixed.
const hubPort = 18099

// alpineDigest pins the sandbox image's base.
//
// The tag it corresponds to is alpine:3.20, the same base the repository's own
// Dockerfile uses for its executor stage. Pinning by digest is what stops this
// test's meaning from changing when the tag is repointed: the sandbox's uid,
// its shell and its git are part of what is being asserted.
//
// To move it: docker pull alpine:3.20 && docker image inspect alpine:3.20
// --format '{{index .RepoDigests 0}}'.
const alpineDigest = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

// harnessImage is the locally built sandbox image. It is never pushed and
// never pulled: the container driver passes --pull=never, so a run consults no
// registry at all.
const harnessImage = "cloop-harness:flagship"

// executorID is the id the container executor is registered under.
const executorID = "container"

// sandboxUID is the uid the workload runs as when this test runs as root.
//
// The container driver derives the sandbox user from the project directory's
// owner, so the way to configure it is to own the directory. Under a normal
// unprivileged CI runner the runner's own uid is already non-root and is used
// as-is; only when running as root does the test have to pick one, because
// root would otherwise be the answer and "runs as a non-root uid" would be
// vacuously false. 65532 matches the repository's images.
const sandboxUID = 65532

// Per-step deadlines. Each one is generous against its step's observed cost on
// an unloaded machine and still bounded, because the failure this guards
// against is a hang: a step that waits forever reports nothing, and a CI job
// that is killed at the job level reports it against the wrong step.
const (
	buildTimeout  = 6 * time.Minute  // go build + docker build, cold cache
	setupTimeout  = 90 * time.Second // git, bootstrap, config, grants
	readyTimeout  = 60 * time.Second // hub start to /readyz
	runTimeout    = 4 * time.Minute  // dispatch to task completion
	wipeTimeout   = 60 * time.Second // completion to lease material gone
	commandBudget = 60 * time.Second // any single short command
)

// pollInterval is how often a wait re-checks its condition. Small enough that
// a fast step is not padded, large enough not to spin.
const pollInterval = 20 * time.Millisecond

// sandboxEvidence is what the workload reported about itself from inside the
// sandbox, parsed from the file it committed.
//
// Every field is observed by the workload about its own process, which is why
// this is the primary evidence rather than `docker inspect`: it cannot be
// satisfied by a process running on the host, and reading it does not race
// with the container's lifetime.
type sandboxEvidence struct {
	UID           string
	GID           string
	CapEff        string
	NetIfs        string
	TaskID        string
	TaskStatus    string
	LocalRepos    string
	LeaseDir      string
	LeaseFiles    string
	SecretKeySeen string
	UITokenSeen   string
}

func TestFlagshipCircuit(t *testing.T) {
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this drives the Docker daemon and machine-global paths", enableEnv)
	}
	requireDocker(t)

	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("clear %s: %v", root, err)
	}
	t.Cleanup(func() {
		if os.Getenv(keepEnv) != "" {
			t.Logf("%s set: leaving %s in place", keepEnv, root)
			return
		}
		_ = os.RemoveAll(root)
	})

	env := buildWorld(t)
	runCircuit(t, env)
}

// world is everything the circuit needs to address itself.
type world struct {
	bin      string // the hub's binary, at a path the sandbox image also has
	hubDir   string // the control plane's directory (.cloop lives here)
	project  string // the project the task runs for
	origin   string // the throwaway bare repo the sandbox pushes to
	homeDir  string // an isolated HOME for every cloop invocation
	token    string // the dashboard token
	ownerUID int    // the uid the sandbox is expected to run as

	// cred drops every cloop and git invocation to ownerUID, and is nil unless
	// the test is running as root.
	//
	// It exists so that running this as root is the same test as running it as
	// a CI runner, rather than a differently-shaped one. In a real deployment
	// the hub runs as an unprivileged user that owns the projects, and the
	// container driver runs the workload as that same owner — so hub and
	// sandbox are one uid. Left as root, the hub would create state.db's WAL
	// sidecars root-owned and the sandbox could not open them: SQLite reports
	// that as a bare "disk I/O error", several layers from the cause.
	cred *syscall.Credential
}

// buildWorld provisions the hub, the sandbox image, the project, the throwaway
// remote and the grants. It asserts nothing about cloop's behaviour; a failure
// here is a broken fixture, and saying so plainly keeps it from being read as
// a failure of the claim under test.
func buildWorld(t *testing.T) *world {
	t.Helper()

	w := &world{
		bin:      filepath.Join(root, "bin", "cloop"),
		hubDir:   filepath.Join(root, "hub"),
		project:  filepath.Join(root, "project"),
		origin:   filepath.Join(root, "origin.git"),
		homeDir:  filepath.Join(root, "home"),
		ownerUID: os.Geteuid(),
	}
	// Decide the identity before anything is created, so everything is created
	// under it. See world.cred.
	if os.Geteuid() == 0 {
		w.ownerUID = sandboxUID
		w.cred = &syscall.Credential{Uid: uint32(sandboxUID), Gid: uint32(sandboxUID)}
		// The hub is what talks to the container runtime, so the identity it
		// runs as has to reach the Docker socket. A CI runner already does —
		// it is in the docker group — so granting it here is what makes the
		// privileged case the same test rather than a differently-shaped one.
		// Without it the hub comes up "degraded — container preflight failed"
		// and the dispatch is refused for a reason that has nothing to do with
		// the claim under test.
		if gid, ok := dockerSocketGroup(); ok {
			w.cred.Groups = []uint32{gid}
		} else {
			t.Skip("cannot determine the Docker socket's group, so the unprivileged hub " +
				"identity could not reach the runtime")
		}
	}
	for _, d := range []string{
		filepath.Dir(w.bin), w.hubDir, w.homeDir, w.project, w.origin, filepath.Join(root, "img"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	// Hand the tree to that identity up front. Every subprocess below runs as
	// it, so what they create is already correctly owned; this covers the
	// directories the test made itself.
	w.own(t, root)

	// Logged because the identity is the one thing that differs between a
	// developer running this as root and a CI runner running it as itself, and
	// it decides what uid the sandbox is expected to report. A failure of the
	// uid assertion is unreadable without knowing which case produced it.
	if w.cred != nil {
		t.Logf("running as root; hub and sandbox share uid %d (docker gid %v)",
			w.ownerUID, w.cred.Groups)
	} else {
		t.Logf("running unprivileged; hub and sandbox share uid %d", w.ownerUID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	provisionBinary(ctx, t, w)
	buildHarnessImage(ctx, t, w)

	ctx2, cancel2 := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel2()
	seedRepos(ctx2, t, w)
	bootstrapHub(ctx2, t, w)
	seedProject(ctx2, t, w)
	grantCredentials(ctx2, t, w)
	return w
}

// own gives a tree to the identity the hub and sandbox share. A no-op when the
// test is already running unprivileged, which is the CI case.
func (w *world) own(t *testing.T, dir string) {
	t.Helper()
	if w.cred == nil {
		return
	}
	if err := chownTree(dir, int(w.cred.Uid), int(w.cred.Gid)); err != nil {
		t.Fatalf("chown %s: %v", dir, err)
	}
}

// writeOwned writes a fixture file and hands it to the shared identity. The
// test process may be root; the things it writes must still be usable by the
// hub and the sandbox.
func (w *world) writeOwned(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if w.cred != nil {
		if err := os.Lchown(path, int(w.cred.Uid), int(w.cred.Gid)); err != nil {
			t.Fatalf("chown %s: %v", path, err)
		}
	}
}

// dockerSocketGroup returns the gid that owns the Docker socket.
//
// Read from the socket rather than by resolving the name "docker": the group
// is what the kernel checks, the name is a convention, and a host where they
// disagree is exactly the host where guessing would be wrong.
func dockerSocketGroup() (uint32, bool) {
	for _, sock := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		info, err := os.Stat(sock)
		if err != nil {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		return st.Gid, true
	}
	return 0, false
}

// asOwner applies the shared identity to a command. Used for cloop and git —
// everything that touches the owned trees — and deliberately not for docker,
// whose socket the unprivileged identity has no access to.
func (w *world) asOwner(cmd *exec.Cmd) *exec.Cmd {
	if w.cred != nil {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Credential = w.cred
	}
	return cmd
}

// provisionBinary puts a statically linked cloop at w.bin.
//
// CGO_ENABLED=0 is not optional: the sandbox is alpine (musl), and a
// dynamically linked binary fails there with "no such file or directory",
// which names neither the binary nor the reason.
func provisionBinary(ctx context.Context, t *testing.T, w *world) {
	t.Helper()
	if prebuilt := os.Getenv(binEnv); prebuilt != "" {
		data, err := os.ReadFile(prebuilt)
		if err != nil {
			t.Fatalf("read %s=%s: %v", binEnv, prebuilt, err)
		}
		if err := os.WriteFile(w.bin, data, 0o755); err != nil {
			t.Fatalf("install prebuilt binary: %v", err)
		}
		t.Logf("using prebuilt binary from %s", prebuilt)
		return
	}
	moduleRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", w.bin, ".")
	cmd.Dir = moduleRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cloop: %v\n%s", err, out)
	}
}

// buildHarnessImage builds the sandbox image.
//
// The image is the documented harness contract (see
// pkg/executor/container.DefaultImage): cloop at /usr/local/bin/cloop, git, a
// CA bundle, and no entrypoint of its own — the container driver denylists
// --entrypoint precisely so that the image cannot change what argv runs, which
// means the image must exec the argv it is handed.
//
// cloop is copied to w.bin as well because that is the path the hub dispatches
// as argv[0]; see the comment on root.
func buildHarnessImage(ctx context.Context, t *testing.T, w *world) {
	t.Helper()
	imgDir := filepath.Join(root, "img")
	data, err := os.ReadFile(w.bin)
	if err != nil {
		t.Fatalf("read binary for image: %v", err)
	}
	if err := os.WriteFile(filepath.Join(imgDir, "cloop"), data, 0o755); err != nil {
		t.Fatalf("stage binary for image: %v", err)
	}
	dockerfile := fmt.Sprintf(`FROM %s
RUN apk add --no-cache git ca-certificates
COPY cloop /usr/local/bin/cloop
COPY cloop %s
ENTRYPOINT []
`, alpineDigest, w.bin)
	if err := os.WriteFile(filepath.Join(imgDir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	mustRun(ctx, t, "docker build", exec.CommandContext(ctx,
		"docker", "build", "-q", "-t", harnessImage, imgDir))
}

// seedRepos creates the throwaway local git remote and the project checkout.
//
// The remote is a bare repository on the hub's own filesystem. That is the
// point: it is reachable from the sandbox only through the bind mount that the
// local_repo grant produces, so a commit arriving in it is proof the grant was
// delivered and not merely recorded.
func seedRepos(ctx context.Context, t *testing.T, w *world) {
	t.Helper()
	mustRun(ctx, t, "git init --bare", w.asOwner(
		exec.CommandContext(ctx, "git", "init", "--bare", "-q", w.origin)))
	git := func(args ...string) {
		full := append([]string{"-C", w.project, "-c", "user.email=ci@cloop.invalid", "-c", "user.name=cloop-ci"}, args...)
		mustRun(ctx, t, "git "+strings.Join(args, " "), w.asOwner(exec.CommandContext(ctx, "git", full...)))
	}
	git("init", "-q", "-b", "main")
	w.writeOwned(t, filepath.Join(w.project, "README.md"), []byte("# flagship\n"), 0o644)
	// .cloop is the project's state, not its source. Committing it would put
	// state.db into the tree the sandbox commits from.
	w.writeOwned(t, filepath.Join(w.project, ".gitignore"), []byte(".cloop/\n"), 0o644)
	git("add", "-A")
	git("commit", "-qm", "initial")
	git("push", "-q", w.origin, "main")
}

// bootstrapHub runs `cloop hub bootstrap` and enables the container executor.
//
// bootstrap is used rather than a hand-written config because it is the
// command an operator runs, and because it is what sets
// executors.allow_host_process=false. That setting is what makes the container
// executor the registry default: under strict mode the localprocess driver is
// refused registration, so no project can fall back to the host even by
// accident, and no explicit project→executor binding is needed.
func bootstrapHub(ctx context.Context, t *testing.T, w *world) {
	t.Helper()
	mustRun(ctx, t, "hub bootstrap", w.cloop(ctx, w.hubDir,
		"hub", "bootstrap", "--behind-proxy",
		"--port", strconv.Itoa(hubPort),
		"--external-url", fmt.Sprintf("http://127.0.0.1:%d", hubPort)))

	for _, kv := range [][2]string{
		{"executors.container.enabled", "true"},
		{"executors.container.id", executorID},
		{"executors.container.runtime", "docker"},
		{"executors.container.image", harnessImage},
		// No egress. The workload has a task to do and a repository bind-mounted
		// to do it against; anything it could reach over the network it has not
		// been granted.
		{"executors.container.network", "none"},
	} {
		mustRun(ctx, t, "config set "+kv[0], w.cloop(ctx, w.hubDir, "config", "set", kv[0], kv[1]))
	}

	w.token = readEnvFile(t, filepath.Join(w.hubDir, ".cloop", "hub.env"), "CLOOP_UI_TOKEN")
	if w.token == "" {
		t.Fatal("hub bootstrap wrote no CLOOP_UI_TOKEN")
	}
}

// hookScript is the work the task does, and it is the whole reason the
// evidence is trustworthy.
//
// It runs as a post-task hook, which the orchestrator executes with `sh -c`
// *inside the sandbox* after the provider reports the task done. So everything
// it records — the uid it runs as, its effective capabilities, the network
// interfaces it can see, the credential files the lease delivered — is the
// sandbox describing itself. It then commits that description and pushes it to
// the granted remote, which is how it reaches the hub.
//
// It deliberately re-reads CLOOP_SECRET_KEY and CLOOP_UI_TOKEN. Those are the
// hub's master sealing key and its RBAC-bypassing dashboard token; both used
// to be forwarded into every sandbox that held any grant, and recording their
// absence here is what stops that regressing.
const hookScript = `set -eu
cd /workspace
mkdir -p evidence
{
  echo "uid=$(id -u)"
  echo "gid=$(id -g)"
  echo "capeff=$(awk '/^CapEff/{print $2}' /proc/self/status)"
  echo "netifs=$(ls /sys/class/net 2>/dev/null | sort | tr '\n' ' ')"
  echo "task_id=${CLOOP_TASK_ID:-none}"
  echo "task_status=${CLOOP_TASK_STATUS:-none}"
  echo "local_repos=${CLOOP_LOCAL_REPOS:-none}"
  echo "lease_dir=${CLOOP_LEASE_DIR:-none}"
  echo "lease_files=$(ls -1 "${CLOOP_LEASE_DIR:-/nonexistent}" 2>/dev/null | sort | tr '\n' ' ')"
  echo "secret_key_present=$([ -n "${CLOOP_SECRET_KEY:-}" ] && echo yes || echo no)"
  echo "ui_token_present=$([ -n "${CLOOP_UI_TOKEN:-}" ] && echo yes || echo no)"
} > evidence/sandbox.txt
export HOME=/tmp
export GIT_AUTHOR_NAME=sandbox GIT_AUTHOR_EMAIL=sandbox@cloop.invalid
export GIT_COMMITTER_NAME=sandbox GIT_COMMITTER_EMAIL=sandbox@cloop.invalid
git add evidence
git commit -qm "flagship: sandbox evidence for task ${CLOOP_TASK_ID:-0}"
git push -q /repos/origin.git HEAD:refs/heads/` + writebackBranch + `
`

// writebackBranch is where the sandbox pushes its commit. A branch of its own,
// so the assertion is that *this run* delivered something rather than that the
// repository is non-empty.
const writebackBranch = "flagship"

// planYAML is the plan, imported rather than decomposed.
//
// Decomposition is an AI call, and the mock provider answers it with
// "TASK_DONE" — which is not a task list. Importing a fixed plan keeps the
// circuit offline and keeps the run deterministic: exactly one task, already
// pending, with auto-evolve off so the run ends when it completes.
const planYAML = `goal: Prove the flagship path end to end
tasks:
  - title: Emit sandbox evidence and push it back
    description: The post-task hook records the sandbox's identity and pushes a commit to the granted remote.
    priority: 1
    status: pending
`

// seedProject initialises the project, imports the plan, and configures the
// mock provider and the hook.
func seedProject(ctx context.Context, t *testing.T, w *world) {
	t.Helper()
	mustRun(ctx, t, "cloop init", w.cloop(ctx, w.project, "init", "Prove the flagship path end to end"))

	planPath := filepath.Join(root, "plan.yaml")
	w.writeOwned(t, planPath, []byte(planYAML), 0o644)
	mustRun(ctx, t, "plan import", w.cloop(ctx, w.project, "plan", "import", planPath, "--replace", "--yes"))

	hookPath := filepath.Join(w.project, ".cloop", "flagship-hook.sh")
	w.writeOwned(t, hookPath, []byte(hookScript), 0o755)
	// The hook is addressed by its path inside the sandbox: /workspace is where
	// the driver binds the project, and the hub's own path for it means nothing
	// there.
	mustRun(ctx, t, "config set provider", w.cloop(ctx, w.project, "config", "set", "provider", "mock"))
	appendProjectConfig(t, filepath.Join(w.project, ".cloop", "config.yaml"),
		"hooks:\n  post_task: sh /workspace/.cloop/flagship-hook.sh\n")
	// The hub and the sandbox share one uid; anything the test wrote directly
	// has to belong to it too.
	w.own(t, w.project)
}

// grantCredentials mints the two secrets this run needs and scopes each to
// this executor.
//
// Two kinds, because they exercise the two delivery mechanisms and the test
// needs both:
//
//   - local_repo becomes a bind mount at /repos/<name>, which is how the
//     sandbox reaches the throwaway remote at all; and
//   - github_pat is delivered as *files* staged on the host and bound
//     read-only into the sandbox, which is the material whose destruction is
//     the fourth assertion. A local_repo grant alone stages no files, so
//     "nothing is left behind" would be vacuously true.
func grantCredentials(ctx context.Context, t *testing.T, w *world) {
	t.Helper()

	mint := w.cloop(ctx, w.hubDir, "secret", "mint", "flagship-origin", "--kind", "local_repo", "--value", w.origin)
	mustRun(ctx, t, "secret mint local_repo", mint)
	mustRun(ctx, t, "secret grant local_repo", w.cloop(ctx, w.hubDir,
		"secret", "grant", "flagship-origin",
		"--to", "executor:"+executorID,
		"--repos", filepath.Base(w.origin),
		"--writable", "--ttl", "1h"))

	// Read from stdin rather than --value: --value puts the credential in this
	// process's argv, where /proc exposes it to every local user. The token is
	// fabricated, but the test should not model the wrong habit.
	pat := w.cloop(ctx, w.hubDir, "secret", "mint", "flagship-pat", "--kind", "github_pat")
	pat.Stdin = strings.NewReader("ghp_flagship_not_a_real_token_0123456789")
	mustRun(ctx, t, "secret mint github_pat", pat)
	mustRun(ctx, t, "secret grant github_pat", w.cloop(ctx, w.hubDir,
		"secret", "grant", "flagship-pat",
		"--to", "executor:"+executorID,
		"--repos", "example/flagship",
		"--permissions", "contents:read", "--ttl", "1h"))
}

// runCircuit starts the hub, dispatches one task, and checks the four claims.
func runCircuit(t *testing.T, w *world) {
	t.Helper()

	startHub(t, w)
	waitForHub(t, w)

	// Sampled for the whole run: a harness forked on the host would be a
	// process for as long as the task takes, so sampling can miss the sandbox
	// but cannot miss the violation this is looking for.
	watch := watchHostHarness(t, w)

	runCtx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	dispatch(runCtx, t, w)
	waitForTaskDone(runCtx, t, w)
	hostProcs := watch()

	evidence := readEvidenceFromRemote(runCtx, t, w)

	t.Run("no harness process was spawned on the host", func(t *testing.T) {
		if len(hostProcs) != 0 {
			t.Errorf("the hub forked a harness on the control-plane host, which strict mode "+
				"(executors.allow_host_process=false) exists to prevent:\n  %s",
				strings.Join(hostProcs, "\n  "))
		}
		// The positive half. A run that never happened would also spawn no host
		// process, so absence only means something next to proof it ran.
		if evidence.TaskStatus != "done" {
			t.Errorf("the task did not complete in the sandbox (status %q), so an empty host "+
				"process list proves nothing", evidence.TaskStatus)
		}
		// And the structural half, because the observational one is a sample.
		// The registry is what handleRun resolves against, so an entry that
		// declares no isolation is a host fork waiting for the next dispatch —
		// whether or not this run happened to take it.
		executors := registeredExecutors(runCtx, t, w)
		if len(executors) == 0 {
			t.Fatal("the hub has no executors registered at all")
		}
		sandboxed := false
		for id, isolation := range executors {
			if isolation == "none" {
				t.Errorf("executor %q declares isolation %q: the hub can still fork a harness "+
					"on its own host", id, isolation)
			}
			if isolation == "container" {
				sandboxed = true
			}
		}
		if !sandboxed {
			t.Errorf("no container executor is registered; the hub has %v", executors)
		}
	})

	t.Run("the task ran in the sandbox under the configured uid, caps and network", func(t *testing.T) {
		if got, want := evidence.UID, strconv.Itoa(w.ownerUID); got != want {
			t.Errorf("workload ran as uid %s, want %s (the project directory's owner, which is "+
				"how the container driver is configured)", got, want)
		}
		if evidence.UID == "0" {
			t.Error("workload ran as root inside the sandbox")
		}
		// CapEff is a hex bitmask of the effective capability set. --cap-drop=ALL
		// makes it zero; any bit set means a capability survived.
		if strings.Trim(evidence.CapEff, "0") != "" {
			t.Errorf("workload holds capabilities (CapEff=%s), want all dropped", evidence.CapEff)
		}
		// network: none leaves loopback and nothing else. An eth0 here means the
		// sandbox was on a bridge it was not configured for.
		if ifs := strings.Fields(evidence.NetIfs); len(ifs) != 1 || ifs[0] != "lo" {
			t.Errorf("sandbox network interfaces are %q, want loopback only "+
				"(executors.container.network=none)", evidence.NetIfs)
		}
		// A container-only path: the hub stages lease files under /dev/shm and
		// binds them somewhere else entirely inside the sandbox.
		if !strings.HasPrefix(evidence.LeaseDir, "/run/cloop/") {
			t.Errorf("lease directory inside the sandbox is %q, want a path under /run/cloop/",
				evidence.LeaseDir)
		}
	})

	t.Run("the granted credential reached the sandbox and nothing else did", func(t *testing.T) {
		if evidence.LocalRepos != filepath.Base(w.origin) {
			t.Errorf("CLOOP_LOCAL_REPOS is %q, want %q — the repository-scoped grant did not arrive",
				evidence.LocalRepos, filepath.Base(w.origin))
		}
		// The github_pat grant is delivered as files. All three, or the git
		// credential helper the sandbox would use is incomplete.
		for _, want := range []string{"git-credential-cloop", "gitconfig", "github-token"} {
			if !strings.Contains(evidence.LeaseFiles, want) {
				t.Errorf("lease delivered %q, missing %q", evidence.LeaseFiles, want)
			}
		}
		// The regression guard. Both of these were forwarded into every sandbox
		// holding any grant, which handed model-authored code the key that
		// unseals the whole secret store and a token that bypasses RBAC.
		if evidence.SecretKeySeen != "no" {
			t.Error("CLOOP_SECRET_KEY is set inside the sandbox: the hub's master sealing key, " +
				"which unseals every credential in the broker, leaked across the isolation boundary")
		}
		if evidence.UITokenSeen != "no" {
			t.Error("CLOOP_UI_TOKEN is set inside the sandbox: an RBAC-bypassing dashboard token " +
				"leaked across the isolation boundary")
		}
	})

	t.Run("the commit came back to the hub", func(t *testing.T) {
		// Read out of the bare repository, which the sandbox could only reach
		// through the bind mount its local_repo grant produced.
		sha := gitOut(runCtx, t, w.origin, "rev-parse", "refs/heads/"+writebackBranch)
		if sha == "" {
			t.Fatalf("no %s branch in the throwaway remote: the sandbox's commit never arrived",
				writebackBranch)
		}
		subject := gitOut(runCtx, t, w.origin, "log", "-1", "--format=%s", "refs/heads/"+writebackBranch)
		if !strings.HasPrefix(subject, "flagship: sandbox evidence") {
			t.Errorf("branch %s is at %q, not the sandbox's commit", writebackBranch, subject)
		}
		// And the commit carries the work, not just a ref. This is the same file
		// the assertions above were parsed from, which is the point: the evidence
		// arrived by travelling back through the write-back path.
		if body := gitOut(runCtx, t, w.origin, "show",
			"refs/heads/"+writebackBranch+":evidence/sandbox.txt"); !strings.Contains(body, "uid=") {
			t.Errorf("the returned commit does not carry evidence/sandbox.txt: %q", body)
		}
	})

	t.Run("the lease material is gone from the host", func(t *testing.T) {
		// The material demonstrably existed — the sandbox listed all three files
		// by name — so this is not vacuous.
		waitFor(t, wipeTimeout, "the host lease staging directories to be wiped", func() (bool, string) {
			left := leaseStagingDirs()
			if len(left) == 0 {
				return true, ""
			}
			return false, "still present: " + strings.Join(left, ", ")
		})
	})

	smokeTheOperatorsOwnHub(t, w)
}

// ── cloop hub doctor --smoke ────────────────────────────────────────────────

// smokeTheOperatorsOwnHub runs the dispatch smoke test against the hub this
// file has just proved, and checks that it agrees — and that it cleans up.
//
// It reuses this harness deliberately. The smoke test's own package tests
// drive a fake executor, which is right for stage ordering and attribution and
// cannot answer the question that actually matters here: does the command work
// against a *real* container runtime, a real image, a real broker and a real
// hub? Standing up a second harness to ask that would be a fork of everything
// above — the image build, the uid arrangement, the grants, the port — and the
// two would drift. So the smoke runs last, on the world the circuit already
// built, where the surrounding assertions have just established that this hub
// genuinely dispatches work.
//
// Running it *after* the circuit is also what makes the cleanup assertion
// meaningful: the staging directories were verified empty a moment ago, so
// anything present afterwards was left by the smoke run and nothing else.
func smokeTheOperatorsOwnHub(t *testing.T, w *world) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	before := sandboxContainers(ctx, t)

	// --json so the verdict is parsed rather than scraped, and the check ids
	// this asserts on are the ones a pipeline greps for.
	cmd := w.cloop(ctx, w.hubDir, "hub", "doctor", "--smoke", "--json")
	out, runErr := cmd.Output()

	var report struct {
		SmokeRan bool `json:"smoke_ran"`
		Smoke    []struct {
			ExecutorID   string   `json:"executor_id"`
			FirstFailure string   `json:"first_failure"`
			Leaked       []string `json:"leaked"`
			Stages       []struct {
				Stage       string `json:"stage"`
				Outcome     string `json:"outcome"`
				Message     string `json:"message"`
				Remediation string `json:"remediation"`
			} `json:"stages"`
		} `json:"smoke"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("`cloop hub doctor --smoke --json` did not emit parseable JSON: %v\nerr: %v\noutput:\n%s",
			err, runErr, tail(string(out), 40))
	}

	t.Run("the smoke test proves the circuit it just ran on", func(t *testing.T) {
		if !report.SmokeRan {
			t.Fatal("--smoke did not run the smoke check at all")
		}
		if len(report.Smoke) == 0 {
			t.Fatal("--smoke found no executor to dispatch to, on a hub that has just run a task")
		}
		for _, res := range report.Smoke {
			if res.FirstFailure != "" {
				// Print the whole stage table: the first failure is the
				// actionable line, and the rest is the context for it.
				for _, s := range res.Stages {
					t.Logf("  %-14s %-5s %s", s.Stage, s.Outcome, s.Message)
				}
				t.Errorf("executor %s failed the smoke at stage %q", res.ExecutorID, res.FirstFailure)
			}
			// The stages that must be *proved* here rather than skipped. On a
			// container executor with a real grant, a skip for either of these
			// would mean the smoke quietly checked nothing — which is the
			// failure mode a diagnostic is most likely to have and least
			// likely to reveal.
			for _, want := range []string{"dispatch", "logs"} {
				var outcome string
				for _, s := range res.Stages {
					if s.Stage == want {
						outcome = s.Outcome
					}
				}
				if outcome != "pass" {
					t.Errorf("stage %q on %s is %q, want pass: this hub demonstrably dispatches "+
						"work, so the smoke test must be able to show it", want, res.ExecutorID, outcome)
				}
			}
			// Every non-pass carries its fix, asserted against the real
			// command rather than only in the unit tests.
			for _, s := range res.Stages {
				if s.Outcome != "pass" && strings.TrimSpace(s.Remediation) == "" {
					t.Errorf("stage %q on %s is %q with no remediation",
						s.Stage, res.ExecutorID, s.Outcome)
				}
			}
		}
	})

	t.Run("the smoke test left nothing behind", func(t *testing.T) {
		for _, res := range report.Smoke {
			if len(res.Leaked) > 0 {
				t.Errorf("the smoke run reported leaks on %s: %s",
					res.ExecutorID, strings.Join(res.Leaked, "; "))
			}
		}

		// Checked against the runtime rather than only against the report,
		// because "did it clean up" must not be answered by the thing under
		// test. A container the smoke created and did not remove is visible
		// here whatever the report claims.
		after := sandboxContainers(ctx, t)
		for name := range after {
			if !before[name] {
				t.Errorf("the smoke run left a container behind: %s", name)
			}
		}

		// And no credential material. The circuit's own wipe assertion ran
		// before the smoke, so anything here is the smoke's.
		waitFor(t, wipeTimeout, "the smoke run's lease staging to be wiped", func() (bool, string) {
			left := leaseStagingDirs()
			if len(left) == 0 {
				return true, ""
			}
			return false, "still present: " + strings.Join(left, ", ")
		})

		// No workspace either. The smoke stages its throwaway trees under the
		// control plane's own .cloop/smoke, which should be empty or absent.
		smokeRoot := filepath.Join(w.hubDir, ".cloop", "smoke")
		if entries, err := os.ReadDir(smokeRoot); err == nil && len(entries) > 0 {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("the smoke run left workspaces under %s: %v", smokeRoot, names)
		}
	})
}

// sandboxContainers returns the names of cloop's sandbox containers, as a set.
//
// Filtered by cloop's own naming rather than counting everything, so a
// container belonging to another test or to the machine's normal workload
// cannot be mistaken for a leak — or mask one.
func sandboxContainers(ctx context.Context, t *testing.T) map[string]bool {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--format", "{{.Names}}")
	out, err := cmd.Output()
	if err != nil {
		// Not fatal: this is a corroborating check, and the report-based
		// assertion above still stands. Saying so beats failing the circuit
		// over a docker CLI hiccup.
		t.Logf("could not list containers to check for leaks: %v", err)
		return map[string]bool{}
	}
	names := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name != "" && strings.Contains(name, "cloop") {
			names[name] = true
		}
	}
	return names
}

// ── the hub process ─────────────────────────────────────────────────────────

// startHub launches `cloop ui`.
//
// It is started in its own process group so that stopping it cannot leave the
// container driver's children behind, and its output is written to a file so a
// failure has something to read.
//
// Teardown is a t.Cleanup rather than a call at the end of the circuit,
// because an assertion that fails with t.Fatal never reaches the end of the
// circuit — and a hub left running holds the fixed port, so the *next* run of
// this test would fail at readiness for a reason belonging to the previous one.
func startHub(t *testing.T, w *world) {
	t.Helper()
	logPath := filepath.Join(root, "hub.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create hub log: %v", err)
	}

	cmd := exec.Command(w.bin, "ui",
		"--port", strconv.Itoa(hubPort), "--no-browser", "--projects", w.project)
	cmd.Dir = w.hubDir
	cmd.Env = append(w.baseEnv(),
		"CLOOP_UI_TOKEN="+w.token,
		"CLOOP_SECRET_KEY="+readEnvFile(t, filepath.Join(w.hubDir, ".cloop", "hub.env"), "CLOOP_SECRET_KEY"),
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: w.cred}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start hub: %v", err)
	}
	t.Cleanup(func() {
		stopHub(cmd)
		_ = logFile.Close()
		if t.Failed() {
			if b, rerr := os.ReadFile(logPath); rerr == nil {
				t.Logf("── hub log ──\n%s", tail(string(b), 120))
			}
		}
	})
}

// stopHub signals the hub's whole process group: `cloop ui` is the parent of
// whatever the container driver still has open, and signalling only the leader
// would leave those behind.
func stopHub(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// waitForHub polls /readyz. Readiness is the hub's own answer to "can I accept
// work", which under strict mode includes having an executor to dispatch to —
// so this also proves the container executor reconciled into the registry.
func waitForHub(t *testing.T, w *world) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/readyz", hubPort)
	waitFor(t, readyTimeout, "the hub to report ready at "+url, func() (bool, string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "curl", "-s", "-o", "/dev/null",
			"-w", "%{http_code}", "--max-time", "2", url).Output()
		if err != nil {
			return false, "curl: " + err.Error()
		}
		if code := strings.TrimSpace(string(out)); code != "200" {
			return false, "HTTP " + code
		}
		return true, ""
	})
}

// dispatch posts to /api/run, which is the endpoint the dashboard's Run button
// calls. Going through HTTP rather than calling the orchestrator directly is
// the point: the claim under test is about what the *web UI* does.
func dispatch(ctx context.Context, t *testing.T, w *world) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/api/run?project_idx=%d", hubPort, w.projectIndex(ctx, t))
	out, err := exec.CommandContext(ctx, "curl", "-s", "-X", "POST",
		"-H", "Authorization: Bearer "+w.token, url).Output()
	if err != nil {
		t.Fatalf("POST /api/run: %v", err)
	}
	body := string(out)
	if strings.Contains(body, `"error"`) {
		t.Fatalf("POST /api/run was refused: %s", body)
	}
	t.Logf("dispatched: %s", strings.TrimSpace(body))
}

// projectIndex finds the project's position in the dashboard's list. The run
// endpoint addresses projects by index, so it has to be looked up rather than
// assumed — the hub's own directory is a project too.
func (w *world) projectIndex(ctx context.Context, t *testing.T) int {
	t.Helper()
	out, err := exec.CommandContext(ctx, "curl", "-s",
		"-H", "Authorization: Bearer "+w.token,
		fmt.Sprintf("http://127.0.0.1:%d/api/projects", hubPort)).Output()
	if err != nil {
		t.Fatalf("GET /api/projects: %v", err)
	}
	var payload struct {
		Projects []struct {
			Path string `json:"path"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("parse /api/projects (%s): %v", tail(string(out), 20), err)
	}
	for i, p := range payload.Projects {
		if sameDir(p.Path, w.project) {
			return i
		}
	}
	t.Fatalf("project %s is not in /api/projects: %s", w.project, out)
	return -1
}

// registeredExecutors returns the hub's executors as id → isolation.
//
// Read from the dashboard's own API rather than from the config file, because
// the config states an intent and the registry states the outcome — and it is
// the registry that handleRun resolves against.
func registeredExecutors(ctx context.Context, t *testing.T, w *world) map[string]string {
	t.Helper()
	out, err := exec.CommandContext(ctx, "curl", "-s",
		"-H", "Authorization: Bearer "+w.token,
		fmt.Sprintf("http://127.0.0.1:%d/api/executors", hubPort)).Output()
	if err != nil {
		t.Fatalf("GET /api/executors: %v", err)
	}
	var payload struct {
		Executors []struct {
			ID        string `json:"id"`
			Isolation string `json:"isolation"`
		} `json:"executors"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("parse /api/executors (%s): %v", tail(string(out), 20), err)
	}
	got := make(map[string]string, len(payload.Executors))
	for _, e := range payload.Executors {
		got[e.ID] = e.Isolation
	}
	return got
}

// waitForTaskDone waits for the run to finish, by watching the branch the
// sandbox pushes rather than the hub's own status.
//
// Deliberately: the hub's run flag flips when the workload exits, which can be
// before the write-back has been observed, and the assertions all read the
// returned commit. Waiting for the artefact the test actually consumes removes
// the gap rather than sleeping across it.
func waitForTaskDone(ctx context.Context, t *testing.T, w *world) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(runTimeout)
	}
	waitFor(t, time.Until(deadline), "the sandbox to push its commit to refs/heads/"+writebackBranch,
		func() (bool, string) {
			c, cancel := context.WithTimeout(context.Background(), commandBudget)
			defer cancel()
			if sha := gitQuiet(c, w.origin, "rev-parse", "--verify", "refs/heads/"+writebackBranch); sha != "" {
				return true, ""
			}
			return false, "branch not present yet"
		})
}

// ── observation ─────────────────────────────────────────────────────────────

// watchHostHarness samples /proc for a harness running on the control-plane
// host and returns a function that stops sampling and reports what it saw.
//
// It matches on the hub's own binary path followed by a `run` argument, which
// is exactly what pkg/ui's handleRun dispatches. The hub process itself is
// excluded by requiring the `run` argument — `cloop ui` does not have one.
func watchHostHarness(t *testing.T, w *world) func() []string {
	t.Helper()
	stop := make(chan struct{})
	found := make(chan []string, 1)

	go func() {
		seen := map[string]struct{}{}
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				out := make([]string, 0, len(seen))
				for s := range seen {
					out = append(out, s)
				}
				found <- out
				return
			case <-ticker.C:
				for _, cmdline := range hostHarnessProcesses(w.bin) {
					seen[cmdline] = struct{}{}
				}
			}
		}
	}()

	return func() []string {
		close(stop)
		select {
		case procs := <-found:
			return procs
		case <-time.After(10 * time.Second):
			t.Error("host process watcher did not stop")
			return nil
		}
	}
}

// hostHarnessProcesses returns the command lines of any process on this host
// that is the given binary invoked with a `run` subcommand.
//
// "On this host" is the whole difficulty, and the naive reading of it is
// wrong: a Docker container's processes are visible in the host's /proc, so
// scanning for the binary finds the *sandboxed* harness and reports the
// success case as a violation. The container is doing nothing unusual — it has
// a PID namespace of its own, but the host can still see into it.
//
// So the question has to be asked about namespaces rather than visibility. A
// harness forked by the hub is a child of the hub and shares its mount
// namespace, which is the test's own; a sandboxed one does not, and its cgroup
// names the runtime that started it. A process is only counted when there is
// no positive evidence of either, which is the conservative direction: a real
// regression forks the harness as the hub's own child, where both signals are
// readable.
func hostHarnessProcesses(bin string) []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	selfMountNS, _ := os.Readlink("/proc/self/ns/mnt")
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		procDir := filepath.Join("/proc", e.Name())
		raw, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
		if err != nil {
			continue // the process exited; not our business
		}
		argv := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		if len(argv) < 2 || argv[0] != bin || argv[1] != "run" {
			continue
		}
		if isContainerized(procDir, selfMountNS) {
			continue
		}
		out = append(out, strings.Join(argv, " "))
	}
	return out
}

// containerCgroupMarkers are the cgroup path fragments the common runtimes
// leave on a containerized process. Docker on a systemd host writes
// "0::/system.slice/docker-<id>.scope"; the others are here so this keeps
// meaning the same thing on a runner configured differently.
var containerCgroupMarkers = []string{"docker", "containerd", "podman", "kubepods", "libpod", "lxc"}

// isContainerized reports whether the process at procDir demonstrably runs
// inside a container rather than beside the control plane.
func isContainerized(procDir, selfMountNS string) bool {
	// The mount namespace is the direct answer, when it can be read: reading
	// /proc/<pid>/ns/* needs ptrace access, which a differently-owned process
	// does not grant.
	if selfMountNS != "" {
		if ns, err := os.Readlink(filepath.Join(procDir, "ns", "mnt")); err == nil && ns != selfMountNS {
			return true
		}
	}
	// The cgroup is world-readable and names the runtime, so it answers for
	// the processes the namespace link does not.
	cgroup, err := os.ReadFile(filepath.Join(procDir, "cgroup"))
	if err != nil {
		return false
	}
	line := strings.ToLower(string(cgroup))
	for _, marker := range containerCgroupMarkers {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

// leaseStagingDirs lists the host directories the container driver stages
// credential files into.
//
// The prefix and the locations mirror pkg/executor/container's secretDirPrefix
// and secretStageBase: a tmpfs when one is available, the system temp
// directory otherwise. Both are checked because which one is used depends on
// the machine, and a test that only looked at /dev/shm would pass on a host
// without it by looking in the wrong place.
func leaseStagingDirs() []string {
	var out []string
	for _, base := range []string{"/dev/shm", os.TempDir()} {
		matches, err := filepath.Glob(filepath.Join(base, "cloop-lease-*"))
		if err != nil {
			continue
		}
		out = append(out, matches...)
	}
	return out
}

// readEvidenceFromRemote reads the evidence file out of the commit that came
// back, and parses it.
//
// Out of the bare repository rather than off the project's working tree: the
// working copy is on the hub's filesystem and the sandbox shares it, so reading
// it there would prove only that a file exists. Reading it from the remote
// proves it travelled.
func readEvidenceFromRemote(ctx context.Context, t *testing.T, w *world) sandboxEvidence {
	t.Helper()
	body := gitOut(ctx, t, w.origin, "show", "refs/heads/"+writebackBranch+":evidence/sandbox.txt")
	if strings.TrimSpace(body) == "" {
		t.Fatal("the sandbox's commit carries no evidence file")
	}
	fields := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	t.Logf("── sandbox reported ──\n%s", body)
	return sandboxEvidence{
		UID:           fields["uid"],
		GID:           fields["gid"],
		CapEff:        fields["capeff"],
		NetIfs:        fields["netifs"],
		TaskID:        fields["task_id"],
		TaskStatus:    fields["task_status"],
		LocalRepos:    fields["local_repos"],
		LeaseDir:      fields["lease_dir"],
		LeaseFiles:    fields["lease_files"],
		SecretKeySeen: fields["secret_key_present"],
		UITokenSeen:   fields["ui_token_present"],
	}
}

// ── plumbing ────────────────────────────────────────────────────────────────

// baseEnv is the environment every cloop invocation gets: an isolated HOME so
// the multi-project registry and the global budget never touch the real user's
// files, and PATH so the binary can find git and docker.
func (w *world) baseEnv() []string {
	return []string{
		"HOME=" + w.homeDir,
		"PATH=" + os.Getenv("PATH"),
		// Keep the Go toolchain reachable for any subprocess that needs it, and
		// keep locale deterministic for anything that formats.
		"LANG=C",
	}
}

// cloop builds a cloop invocation rooted at dir with the isolated environment
// and the hub's secrets, which the broker commands need to unseal the store.
func (w *world) cloop(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := w.asOwner(exec.CommandContext(ctx, w.bin, args...))
	cmd.Dir = dir
	env := w.baseEnv()
	// hub.env does not exist until bootstrap has run; before that there is
	// nothing to load and the commands being run do not need it.
	if b, err := os.ReadFile(filepath.Join(w.hubDir, ".cloop", "hub.env")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			env = append(env, strings.Trim(line, `"`))
		}
	}
	cmd.Env = env
	return cmd
}

// mustRun executes cmd and fails the test with its full output on error. The
// output matters: a cloop subcommand that refuses explains why, and discarding
// that leaves only an exit status.
func mustRun(ctx context.Context, t *testing.T, what string, cmd *exec.Cmd) string {
	t.Helper()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			t.Fatalf("%s: timed out after the step budget: %v\n%s", what, ctx.Err(), out)
		}
		t.Fatalf("%s: %v\n%s", what, err, out)
	}
	return string(out)
}

// waitFor polls until cond reports true, and fails naming both the condition
// and the most recent reason it was not met.
//
// This is the only waiting primitive in this file, and the interval below is
// the only sleep in it. The distinction matters: sleeping between two checks
// of a condition costs at most one interval, whereas sleeping *instead* of
// checking encodes a guess about how long something takes — and every
// container flake this suite has had came from such a guess being wrong under
// load. Nothing here proceeds because time passed; it proceeds because a
// condition was observed to hold.
func waitFor(t *testing.T, budget time.Duration, what string, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(budget)
	var why string
	for time.Now().Before(deadline) {
		ok, reason := cond()
		if ok {
			return
		}
		why = reason
		time.Sleep(pollInterval)
	}
	t.Fatalf("timed out after %s waiting for %s (last: %s)", budget, what, why)
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed; the flagship circuit needs a container runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandBudget)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker is installed but not responding (%v): %s", err, tail(string(out), 5))
	}
}

// gitOut runs a read-only git command against a repository and fails on error.
//
// safe.directory is disabled wholesale because the repositories here are owned
// by the sandbox uid on purpose, and git's ownership check would otherwise
// refuse to read the very thing this test exists to inspect.
func gitOut(ctx context.Context, t *testing.T, repo string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "safe.directory=*", "-C", repo}, args...)
	out, err := exec.CommandContext(ctx, "git", full...).CombinedOutput() //nolint:gosec
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), repo, err, out)
	}
	return strings.TrimSpace(string(out))
}

// gitQuiet is gitOut for a command whose failure is an expected answer rather
// than an error — "the branch is not there yet" while polling.
func gitQuiet(ctx context.Context, repo string, args ...string) string {
	full := append([]string{"-c", "safe.directory=*", "-C", repo}, args...)
	out, err := exec.CommandContext(ctx, "git", full...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// readEnvFile pulls one KEY=VALUE out of a shell-style env file.
func readEnvFile(t *testing.T, path, key string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// appendProjectConfig adds a YAML block to a project's config.
//
// Appended as text rather than round-tripped through a YAML library on
// purpose: `cloop config set` owns this file, and re-marshalling it here would
// silently drop the comments bootstrap wrote for the operator.
func appendProjectConfig(t *testing.T, path, block string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString("\n" + block); err != nil {
		t.Fatalf("append to %s: %v", path, err)
	}
}

// chownTree recursively changes ownership. filepath.WalkDir rather than a
// shell-out so a failure names the path.
func chownTree(dir string, uid, gid int) error {
	return filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := os.Lchown(path, uid, gid); cerr != nil && !errors.Is(cerr, os.ErrNotExist) {
			return fmt.Errorf("%s: %w", path, cerr)
		}
		return nil
	})
}

// sameDir compares two paths after resolving symlinks, so /var/tmp and its
// resolved form compare equal.
func sameDir(a, b string) bool {
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		ra = a
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		rb = b
	}
	return filepath.Clean(ra) == filepath.Clean(rb)
}

// tail returns the last n lines, for log excerpts that should not bury the
// failure they accompany.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
