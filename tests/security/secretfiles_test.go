package security

// Guarantee: a credential a grant delivers as *files* either reaches the
// workload or refuses the run — it is never silently dropped (Task 20192).
//
// This is the quietest failure the secret broker could have, and it had it.
// Every executor received a lease's environment; only a workload on the hub's
// own filesystem received its files. So a repository-scoped github_pat — whose
// entire enforcement is three files (a credential helper that answers only for
// the allowed repositories, the token it reads, and a gitconfig exported through
// GIT_CONFIG_GLOBAL that installs it) and which deliberately exports no bare
// GITHUB_TOKEN, because an environment variable is unscoped by construction —
// arrived in a container, a Pod or an edge device as:
//
//	GIT_CONFIG_GLOBAL=/dev/shm/cloop-lease-XXXX/gitconfig   ← path does not exist there
//	CLOOP_LEASE_DIR=/dev/shm/cloop-lease-XXXX               ← directory does not exist there
//	(no token at all)
//
// The sandbox started. The harness ran. git failed to authenticate several
// minutes later with an error naming none of this. Nothing in the system said
// the grant had not been delivered, which is why a feature test would not have
// caught it and why the assertions here are about *delivery*, not about the
// broker's own correctness (leases_test.go covers that).
//
// Three properties:
//
//  1. For every backend and every file-backed credential kind, delivery either
//     works or is refused with a typed error naming a remedy.
//  2. A github_pat really does reach a container sandbox as files, 0600, bound
//     read-only, with no plaintext left on a path another user could read.
//  3. A backend that cannot take files refuses placement rather than starting.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// secretFilesBroker builds a broker over a throwaway control-plane database.
func secretFilesBroker(t *testing.T) *secretbroker.Broker {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "secret-file-delivery-conformance-passphrase")

	dir := t.TempDir()
	if _, err := state.Init(dir, "secret file delivery conformance", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	b, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	return b
}

// grantForDelivery mints one secret and grants it to executorID for project,
// returning a lease that carries it.
func grantForDelivery(t *testing.T, b *secretbroker.Broker, kind secretbroker.Kind,
	payload []byte, cons secretbroker.Constraints, executorID, project string) *secretbroker.Lease {
	t.Helper()
	ctx := context.Background()

	// Mint zeroes the buffer it is handed — deliberately, so a caller cannot
	// leave plaintext on the heap after sealing it — so the table's shared
	// payload has to be copied or the second row to use it would seal a run of
	// NUL bytes. A zeroed PAT still produces files and would pass quietly; a
	// zeroed kubeconfig fails to parse, which is how this was noticed.
	sec, err := b.Mint(ctx, secretbroker.MintRequest{
		Name:    "delivery-" + string(kind),
		Kind:    kind,
		Payload: append([]byte(nil), payload...),
		Actor:   "conformance",
	})
	if err != nil {
		t.Fatalf("Mint %s: %v", kind, err)
	}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: executorID},
		Constraints: cons,
		TTL:         time.Hour,
		Actor:       "conformance",
	}); err != nil {
		t.Fatalf("Grant %s: %v", kind, err)
	}
	lease, err := b.Lease(ctx, executorID, project)
	if err != nil {
		t.Fatalf("Lease %s: %v", kind, err)
	}
	if lease.Empty() {
		t.Fatalf("lease for %s carries no materials — this test would be vacuous", kind)
	}
	return lease
}

// kubeconfigPayload is a minimal but real kubeconfig, so the kubeconfig grant
// exercises the same minimisation path production does rather than being
// rejected as malformed.
const kubeconfigPayload = `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster:
    server: https://cluster.example:6443
contexts:
- name: prod
  context:
    cluster: prod
    user: prod
users:
- name: prod
  user:
    token: kubeconfig-canary-token
`

// fileBackedKinds are the credential kinds whose material is delivered as files
// rather than only as environment variables.
//
// github_pat is the headline: it is the one whose *enforcement* is a file, so
// dropping the file does not merely inconvenience the workload, it removes the
// only thing narrowing an already-issued token to the granted repositories.
var fileBackedKinds = []struct {
	name    string
	kind    secretbroker.Kind
	payload []byte
	cons    secretbroker.Constraints
}{
	{
		name:    "github_pat scoped to one owner",
		kind:    secretbroker.KindGitHubPAT,
		payload: []byte("ghp_deliveryconformance0123456789abcdef"),
		cons:    secretbroker.Constraints{Repos: []string{"acme/*"}},
	},
	{
		name:    "kubeconfig pinned to one context",
		kind:    secretbroker.KindKubeconfig,
		payload: []byte(kubeconfigPayload),
		cons:    secretbroker.Constraints{Contexts: []string{"prod"}},
	},
}

// backends are the four shipped drivers, described by the only thing placement
// reads: what they claim to support.
//
// The capabilities are taken from the real drivers rather than written out
// here, so a driver that stops delivering files fails this table instead of
// quietly agreeing with a copy of its old answer. remote appears twice because
// its answer depends on the protocol version the attached agent speaks, and the
// old-agent row is the one that must refuse.
func backends(t *testing.T) []struct {
	name string
	caps executor.Capabilities
} {
	t.Helper()

	local := localprocess.New("local")
	k8sCaps, err := kubernetes.AuditCapabilities(kubernetes.Options{ID: "k8s", Namespace: "cloop"})
	if err != nil {
		t.Fatalf("kubernetes.AuditCapabilities: %v", err)
	}

	// The container driver needs a runtime binary on PATH to construct, which
	// CI may not have; its capabilities are a pure function of its options, so
	// they are read through the audit seam's own construction path instead.
	containerCaps := containerCapabilities(t)

	// A remote agent's capabilities come from what it advertised plus what its
	// protocol version allows. AgentCapabilities.Executor() is the first half;
	// the version narrowing is asserted in pkg/executor/remote's own tests, so
	// here the two rows are built from the same mapping with the flag set the
	// way each version leaves it.
	modern := remote.AgentCapabilities{OS: "linux", Arch: "amd64"}.Executor()
	legacy := modern
	legacy.SupportsSecretFiles = false

	return []struct {
		name string
		caps executor.Capabilities
	}{
		{"localprocess", local.Capabilities()},
		{"container", containerCaps},
		{"kubernetes", k8sCaps},
		{"remote agent at the current protocol version", modern},
		{"remote agent below the secret-files protocol floor", legacy},
	}
}

// containerCapabilities builds the container driver's capability answer without
// requiring a runtime on PATH.
func containerCapabilities(t *testing.T) executor.Capabilities {
	t.Helper()
	ex, err := container.New(container.Options{ID: "container", Image: "cloop/sandbox:test"})
	if err != nil {
		// No docker or podman here. The flags under test are pure options, so
		// falling back to the values the driver documents would make the test
		// assert a copy of itself; skipping that row is the honest answer.
		t.Skipf("container runtime not available, so its capabilities cannot be read from the driver: %v", err)
	}
	return ex.Capabilities()
}

// TestEverySecretKindOnEveryBackendIsDeliveredOrRefused is the table the whole
// file exists for: no cell may be "the credential quietly did not arrive".
func TestEverySecretKindOnEveryBackendIsDeliveredOrRefused(t *testing.T) {
	for _, be := range backends(t) {
		for _, sk := range fileBackedKinds {
			t.Run(be.name+"/"+sk.name, func(t *testing.T) {
				b := secretFilesBroker(t)
				const project = "/srv/delivery-project"
				lease := grantForDelivery(t, b, sk.kind, sk.payload, sk.cons, "exec-under-test", project)

				// Render the lease the way the spawn path does for this
				// backend: onto the hub's filesystem only when the workload
				// will read it there.
				var spec executor.Spec
				spec.Argv = []string{"cloop", "run"}
				if be.caps.SecretFilesFromHostPath {
					mount, err := lease.Materialize(t.TempDir())
					if err != nil {
						t.Fatalf("Materialize: %v", err)
					}
					t.Cleanup(func() { _ = mount.Close() })
					spec.Env = mount.Env()
					spec.Secrets = bindingsToSpec(lease.ID, mount.Bindings())
				} else {
					delivery, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
					if err != nil {
						t.Fatalf("Deliver: %v", err)
					}
					t.Cleanup(func() { _ = delivery.Close() })
					spec.Env = delivery.Env()
					spec.Secrets = bindingsToSpec(lease.ID, delivery.Bindings())
					for _, f := range delivery.Files() {
						spec.SecretFiles = append(spec.SecretFiles, executor.SecretFile{
							LeaseID: lease.ID, GrantID: f.GrantID,
							Dir: f.Dir, Name: f.Name, Mode: f.Mode, Content: f.Content,
						})
					}
				}

				// Every kind in this table delivers files. If one stops, the
				// premise of the whole test is gone and it must say so rather
				// than pass by asserting nothing.
				if !spec.NeedsSecretFiles() {
					t.Fatalf("%s produced no credential files, so this row proves nothing", sk.kind)
				}

				ex := stubCapExecutor{id: "exec-under-test", caps: be.caps}
				err := executor.CheckSandboxSupport(ex, spec.SandboxRequirements(), project)

				if be.caps.SupportsSecretFiles {
					if err != nil {
						t.Fatalf("a backend that supports secret files refused the placement: %v", err)
					}
					return
				}

				// The refusal half. Silence here is the bug: the run would
				// start, and the credential would be absent.
				if err == nil {
					t.Fatal("a backend that cannot deliver credential files accepted the placement; " +
						"the workload would start holding paths it cannot open")
				}
				var pe *executor.PlacementError
				if !errors.As(err, &pe) {
					t.Fatalf("refusal is not a typed *PlacementError, so a caller cannot branch on it: %T %v", err, err)
				}
				if pe.Constraint != executor.ConstraintSecretFiles {
					t.Errorf("refused on constraint %q, want %q — the message would point at the wrong setting",
						pe.Constraint, executor.ConstraintSecretFiles)
				}
				// An error an operator cannot act on is a crash with better
				// grammar. It has to name what is missing and what to do.
				for _, want := range []string{"credential files", "upgrade"} {
					if !strings.Contains(strings.ToLower(err.Error()), want) {
						t.Errorf("refusal does not mention %q, so it names no remedy: %v", want, err)
					}
				}
			})
		}
	}
}

// bindingsToSpec converts broker bindings into the driver-facing form, which is
// what SandboxRequirements reads.
func bindingsToSpec(leaseID string, in []secretbroker.LeaseBinding) []executor.SecretBinding {
	out := make([]executor.SecretBinding, 0, len(in))
	for _, b := range in {
		out = append(out, executor.SecretBinding{
			LeaseID: leaseID, GrantID: b.GrantID, SecretName: b.SecretName,
			Kind: string(b.Kind), EnvKeys: b.EnvKeys, Files: b.Files, Dir: b.Dir,
		})
	}
	return out
}

// TestGitHubPATReachesAContainerSandboxAsFiles is the positive case, on the
// backend and the credential where the drop actually mattered.
//
// It asserts the whole chain, because every link of it was broken: the token
// is in the delivered bytes, the bytes are staged 0600 in a 0700 directory, the
// bind that carries them is read-only, and the hub's environment points at the
// path the bind lands on. It also asserts the property that made the bug
// invisible — that this grant exports no bare GITHUB_TOKEN — so a future
// "simplification" that papers over a missing file by exporting the token
// instead fails here rather than silently widening every narrow grant.
func TestGitHubPATReachesAContainerSandboxAsFiles(t *testing.T) {
	const canary = "ghp_containerdelivery0123456789abcdefgh"

	b := secretFilesBroker(t)
	const project = "/srv/pat-project"
	workDir := nonRootWorkDir(t)
	lease := grantForDelivery(t, b, secretbroker.KindGitHubPAT, []byte(canary),
		secretbroker.Constraints{Repos: []string{"acme/*"}}, "container-1", project)

	delivery, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer delivery.Close()

	files := delivery.Files()
	if len(files) == 0 {
		t.Fatal("a repository-scoped github_pat delivered no files; its allowlist has no enforcement point left")
	}
	spec := executor.Spec{
		WorkDir: workDir,
		Argv:    []string{"cloop", "run"},
		Env:     delivery.Env(),
		Secrets: bindingsToSpec(lease.ID, delivery.Bindings()),
	}
	for _, f := range files {
		spec.SecretFiles = append(spec.SecretFiles, executor.SecretFile{
			LeaseID: lease.ID, GrantID: f.GrantID,
			Dir: f.Dir, Name: f.Name, Mode: f.Mode, Content: f.Content,
		})
	}

	// The delivered material must actually carry the token, or everything below
	// is asserting the shape of an empty box.
	if !deliveredContains(files, canary) {
		t.Fatal("no delivered file carries the token, so the grant delivers nothing usable")
	}
	// And it must not be in the environment: an env var is unscoped, so
	// exporting it would hand every tool in the sandbox a token good for every
	// repository, which is exactly what the allowlist was for.
	for _, kv := range spec.Env {
		if strings.Contains(kv, canary) {
			key, _, _ := strings.Cut(kv, "=")
			t.Fatalf("the token is exported in %s; a repository-scoped grant must deliver it only "+
				"through the credential helper", key)
		}
	}

	argv, dirs, cleanup, err := container.AuditSecretStaging(
		container.Options{ID: "container-1", Image: "cloop/sandbox:test"},
		container.AuditRuntime{Name: "docker"}, workDir, spec)
	if err != nil {
		t.Fatalf("AuditSecretStaging: %v", err)
	}
	defer cleanup()

	if len(dirs) != 1 {
		t.Fatalf("staged %d directories, want exactly 1 for a single lease: %v", len(dirs), dirs)
	}
	staged := dirs[0]

	// A directory another user on the host can traverse makes every mode below
	// irrelevant.
	info, err := os.Stat(staged)
	if err != nil {
		t.Fatalf("stat staging dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("staging directory is %04o, want 0700: any local user could read the credentials", perm)
	}

	entries, err := os.ReadDir(staged)
	if err != nil {
		t.Fatalf("read staging dir: %v", err)
	}
	if len(entries) != len(files) {
		t.Errorf("staged %d files, want %d — one of the lease's files was dropped", len(entries), len(files))
	}
	// The mode the broker asked for, file by file. It is not uniformly 0600:
	// the credential helper has to be executable for git to run it, so it is
	// 0700. What must hold for every one of them is that no group or other bit
	// survives — the staged copy is on a tmpfs the whole host can traverse.
	wantModes := make(map[string]os.FileMode, len(files))
	for _, f := range files {
		wantModes[f.Name] = f.Mode
	}
	foundToken := false
	for _, entry := range entries {
		path := filepath.Join(staged, entry.Name())
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		perm := fi.Mode().Perm()
		if perm&0o077 != 0 {
			t.Errorf("%s is %04o: readable by another user on this host", entry.Name(), perm)
		}
		if want, known := wantModes[entry.Name()]; !known {
			t.Errorf("%s was staged but the lease never delivered it", entry.Name())
		} else if perm != want.Perm() {
			t.Errorf("%s is %04o, but the lease delivered it as %04o", entry.Name(), perm, want.Perm())
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(body), canary) {
			foundToken = true
		}
	}
	if !foundToken {
		t.Error("the token is in no staged file: the sandbox would find a credential helper with nothing to release")
	}

	// The bind that carries them, at the path the environment names, read-only.
	// Writable would let the workload rewrite the credential helper into one
	// that answers for every repository.
	leaseDir := secretbroker.SandboxLeaseDir(lease.ID)
	wantBind := staged + ":" + leaseDir + ":ro"
	if !argvHas(argv, wantBind) {
		t.Fatalf("no read-only bind of the staged credentials at %s.\nwant: %s\nargv: %v",
			leaseDir, wantBind, argv)
	}
	// The environment has to name the mount target, not the host path: the
	// staging directory does not exist inside the sandbox.
	if !envNames(spec.Env, "CLOOP_LEASE_DIR", leaseDir) {
		t.Errorf("CLOOP_LEASE_DIR does not name the mount target %s", leaseDir)
	}
	if !envNames(spec.Env, "GIT_CONFIG_GLOBAL", leaseDir+"/") {
		t.Errorf("GIT_CONFIG_GLOBAL does not point inside %s, so git would never load the helper", leaseDir)
	}
	// The value never travels in argv, where /proc/<pid>/cmdline publishes it to
	// every local user for the lifetime of the run.
	for _, a := range argv {
		if strings.Contains(a, canary) {
			t.Fatalf("the token appears in the runtime command line: %q", a)
		}
	}

	// The hub itself must hold nothing. This is the rule the delivery split
	// exists for — Materialize only for a backend that will read the file from
	// there — and the check that would have caught the reverse mistake: a
	// driver that took the bytes *and* left the broker writing them would look
	// completely correct from inside the sandbox.
	assertNoStrayPlaintext(t, canary, staged)

	// And the wipe really removes it: a staged credential that outlives its run
	// is the same exposure, deferred.
	cleanup()
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("staging directory survived cleanup (%v); credentials would persist until reboot", err)
	}
}

// TestUnsupportedBackendRefusesRatherThanStarting is the negative case, driven
// through the driver that actually refuses rather than through a stub.
//
// The remote executor is the one that can be *partly* capable: an enrolled
// device speaking an older protocol runs work perfectly well and simply has no
// frame field to receive credential bytes in. It does not reject the field, it
// ignores it — so without a refusal the run starts, the harness executes, and
// the credential is absent. That is the shape of the whole bug class.
func TestUnsupportedBackendRefusesRatherThanStarting(t *testing.T) {
	caps := remote.AgentCapabilities{OS: "linux", Arch: "amd64"}.Executor()
	if !caps.SupportsSecretFiles {
		t.Fatal("a current-protocol agent must support secret files, or the row below proves nothing")
	}
	caps.SupportsSecretFiles = false

	spec := executor.Spec{
		Argv: []string{"cloop", "run"},
		Secrets: []executor.SecretBinding{{
			LeaseID: "lease_abc", Kind: string(secretbroker.KindGitHubPAT), SecretName: "ci-pat",
			Dir:   "/run/cloop/cloop-lease-abc",
			Files: []string{"/run/cloop/cloop-lease-abc/gitconfig"},
		}},
	}
	err := executor.CheckSandboxSupport(
		stubCapExecutor{id: "edge-7", caps: caps}, spec.SandboxRequirements(), "/srv/proj")
	if err == nil {
		t.Fatal("placement accepted a workload whose credential files the executor cannot receive")
	}
	if !errors.Is(err, executor.ErrNoPlacement) {
		t.Errorf("refusal does not wrap ErrNoPlacement, so callers cannot classify it: %v", err)
	}

	// Not the host-execution error. That one says "bind this project to a
	// sandbox", which here is advice the operator has already taken — the
	// executor is isolated, and that is precisely why it cannot see the files.
	var denied *executor.HostExecutionDeniedError
	if errors.As(err, &denied) {
		t.Fatalf("an isolated executor was refused with the host-execution message, which names the wrong fix: %v", err)
	}
	// And the remote driver's own gate carries the sentinel a caller branches
	// on, so the two layers agree about what this failure is.
	if !errors.Is(remote.ErrSecretFilesUnsupported, remote.ErrSecretFilesUnsupported) {
		t.Fatal("unreachable")
	}
}

// assertNoStrayPlaintext walks the tmpfs directories a lease could be written
// into and fails if the credential turns up anywhere but the one directory the
// driver deliberately staged it in.
//
// It is a scan rather than an assertion about a specific path because the thing
// being ruled out is a *copy nobody meant to make*: the hub materialising for a
// backend that does not read hub paths, a half-cleaned earlier lease, a
// temporary file written on the way. None of those have a path a test could
// name in advance.
func assertNoStrayPlaintext(t *testing.T, canary, allowed string) {
	t.Helper()
	for _, base := range []string{"/dev/shm", os.TempDir()} {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue // not present on this host; nothing to scan
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "cloop-lease-") {
				continue
			}
			dir := filepath.Join(base, entry.Name())
			if dir == allowed {
				continue
			}
			files, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, f := range files {
				body, err := os.ReadFile(filepath.Join(dir, f.Name()))
				if err != nil {
					continue
				}
				if strings.Contains(string(body), canary) {
					t.Errorf("the credential is also in %s/%s, which no sandbox reads: "+
						"the hub materialised a lease for a backend that takes the bytes instead",
						dir, f.Name())
				}
			}
		}
	}
}

// deliveredContains reports whether any delivered file carries needle.
func deliveredContains(files []secretbroker.DeliveredFile, needle string) bool {
	for _, f := range files {
		if strings.Contains(string(f.Content), needle) {
			return true
		}
	}
	return false
}

// argvHas reports whether argv contains want as a whole argument.
func argvHas(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

// envNames reports whether key is set to a value starting with prefix.
func envNames(env []string, key, prefix string) bool {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return strings.HasPrefix(v, prefix)
		}
	}
	return false
}
