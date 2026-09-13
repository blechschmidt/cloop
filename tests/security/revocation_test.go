package security

// Guarantee 11: material handed to an executor can be taken back mid-run, and
// nothing writes it somewhere a revocation cannot reach.
//
// The second half is the one that is easy to get wrong. Revocation is a
// property of *every* copy of a credential, so a copy written to a place with
// no revoke path — a database row, a log, a serialised spec — silently voids
// the guarantee no matter how well the online path works. There is no frame
// that reaches a row in SQLite.
//
// The per-component behaviour (files unlinked, tasks killed, acks replayed) is
// asserted end-to-end in pkg/executor/remote and pkg/executor/agent, against a
// real agent running a real process. What is asserted here is the part that
// spans components and would otherwise belong to nobody.

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// leasedCredential is the canary. It is written into a dispatched spec and
// must not survive into any persisted or serialised form.
const leasedCredential = "ghp_persisted_canary_must_not_survive"

// dispatchedSpec is what pkg/ui hands an executor after applying a lease: the
// credential in Env, and a binding naming which variable it came from.
func dispatchedSpec() executor.Spec {
	return executor.Spec{
		WorkDir: "/srv/project",
		Argv:    []string{"cloop", "run"},
		Env: []string{
			"PATH=/usr/bin",
			"GITHUB_TOKEN=" + leasedCredential,
			"HOME=/home/cloop",
		},
		Secrets: []executor.SecretBinding{{
			LeaseID:    "lease_canary",
			GrantID:    "grant_canary",
			SecretName: "github-ci",
			Kind:       "github_pat",
			EnvKeys:    []string{"GITHUB_TOKEN"},
			ExpiresAt:  time.Now().Add(15 * time.Minute),
		}},
	}
}

// TestDispatchedSpecNeverPersistsLeasedCredentials is the durability half of
// the revocation guarantee.
//
// A dispatched spec is recorded in `executor_sessions` so a failed-over
// workload can be re-dispatched. Recorded verbatim, it would write a
// fifteen-minute credential into a table that outlives the lease, survives the
// revocation meant to withdraw it, and is copied into every backup of the
// control-plane database.
//
// Only the variables the lease contributed are redacted. The operator's own
// environment is not the broker's to touch, and blanking it would break
// failover for a reason unrelated to secrets.
func TestDispatchedSpecNeverPersistsLeasedCredentials(t *testing.T) {
	store := newSessionStore(t)

	sess := executor.Session{
		ID:          "sess_canary",
		ExecutorID:  "edge-01",
		HandleID:    "handle_canary",
		ProjectPath: "/srv/project",
		ClaimToken:  "tok",
		Attempt:     1,
		StartedAt:   time.Now(),
		Spec:        dispatchedSpec(),
	}
	if err := store.OpenSession(sess); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	running, err := store.RunningSessions("edge-01")
	if err != nil {
		t.Fatalf("RunningSessions: %v", err)
	}
	if len(running) != 1 {
		t.Fatalf("RunningSessions returned %d rows, want 1", len(running))
	}
	stored := running[0]

	joined := strings.Join(stored.Spec.Env, "\n")
	if strings.Contains(joined, leasedCredential) {
		t.Errorf("a leased credential was persisted into executor_sessions.\n"+
			"  A row in SQLite outlives its lease and no revoke frame can reach it.\n"+
			"  Redact leased Env values in executorstore.marshalSpec.\n"+
			"  stored env: %q", joined)
	}
	// The variable survives, marked — "this was withdrawn" and "this was never
	// set" call for different responses on failover.
	if !strings.Contains(joined, "GITHUB_TOKEN=") {
		t.Errorf("the variable itself should survive so failover can see it was redacted; got %q", joined)
	}
	// Everything the lease did not contribute is untouched.
	for _, want := range []string{"PATH=/usr/bin", "HOME=/home/cloop"} {
		if !strings.Contains(joined, want) {
			t.Errorf("redaction widened past the lease's own keys: %q is missing from %q", want, joined)
		}
	}
	if len(stored.Spec.Argv) != 2 {
		t.Errorf("redaction must not disturb the rest of the spec; argv = %v", stored.Spec.Argv)
	}
}

// TestSecretBindingCarriesNoMaterial pins the shape of the attribution that
// travels with a workload.
//
// SecretBinding is the one struct that crosses every boundary at once: it goes
// into a spec, over the wire in a start frame, into `executor_sessions`, and
// into audit rows. If it ever gains a field capable of holding a value, the
// credential follows it into all four at the same time — so the check is on
// the serialised form rather than on any single call site.
func TestSecretBindingCarriesNoMaterial(t *testing.T) {
	spec := dispatchedSpec()
	// Populate every field, including the ones a real binding often leaves
	// empty, so a value-shaped field cannot hide behind omitempty.
	spec.Secrets[0].Files = []string{"/dev/shm/cloop-lease-abc/token"}
	spec.Secrets[0].Dir = "/dev/shm/cloop-lease-abc"
	spec.Secrets[0].Egress = true

	encoded, err := json.Marshal(spec.Secrets[0])
	if err != nil {
		t.Fatalf("marshal binding: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal binding: %v", err)
	}

	// A closed, reviewed set. Adding a key here should require reading the
	// question "can this hold a credential?" and answering it.
	allowed := map[string]bool{
		"lease_id": true, "grant_id": true, "secret_name": true, "kind": true,
		"env_keys": true, "files": true, "dir": true, "egress": true,
		"expires_at": true,
	}
	for key := range decoded {
		if !allowed[key] {
			t.Errorf("SecretBinding gained an unreviewed JSON field %q.\n"+
				"  This struct is serialised into start frames, executor_sessions and audit rows.\n"+
				"  If it can hold a value, the credential reaches all three at once.", key)
		}
	}
	// env_keys are names. A "K=V" entry here would be a credential in a field
	// nobody thinks of as one.
	for _, k := range spec.Secrets[0].EnvKeys {
		if strings.Contains(k, "=") {
			t.Errorf("EnvKeys must carry names, not assignments; got %q", k)
		}
	}
	if strings.Contains(string(encoded), leasedCredential) {
		t.Errorf("the binding serialised a credential: %s", encoded)
	}
}

// TestRevocationStatesAreDistinct guards the honesty property the UI depends
// on.
//
// "Sent" is not "landed". If these ever collapse — if an unreachable agent
// were reported as revoked because the frame was written — an operator could
// close an incident on a credential that is still live on a machine the hub
// cannot reach. The distinction is only useful if it is preserved all the way
// to the response.
func TestRevocationStatesAreDistinct(t *testing.T) {
	states := []remote.RevokeState{
		remote.RevokeStatePending,
		remote.RevokeStateRevoked,
		remote.RevokeStateUnreachable,
		remote.RevokeStateFailed,
	}
	seen := map[remote.RevokeState]bool{}
	for _, s := range states {
		if seen[s] {
			t.Fatalf("two revocation states share the value %q; the UI cannot tell them apart", s)
		}
		seen[s] = true
	}

	// Exactly one state may be terminal. A terminal "unreachable" would stop
	// the reconnect replay; a non-terminal "revoked" would re-send forever.
	terminal := 0
	for _, s := range states {
		if s.Terminal() {
			terminal++
			if s != remote.RevokeStateRevoked {
				t.Errorf("%q must not be terminal: the material is still out there", s)
			}
		}
	}
	if terminal != 1 {
		t.Errorf("exactly one revocation state may be terminal, got %d", terminal)
	}
}

// TestRevocableMaterialRequiresARevocableAgent is the placement rule, asserted
// against the version constants rather than a live session.
//
// The promise "revoking this lease takes the credential away" must not depend
// on which devices in a fleet happen to be up to date. An agent that cannot
// honour the frame must not receive material that depends on it.
func TestRevocableMaterialRequiresARevocableAgent(t *testing.T) {
	if remote.SupportsRevocation(remote.MinRevocationVersion - 1) {
		t.Error("a protocol below MinRevocationVersion must not claim revocation support")
	}
	if !remote.SupportsRevocation(remote.MinRevocationVersion) {
		t.Error("MinRevocationVersion must itself support revocation")
	}
	if remote.ProtocolVersion < remote.MinRevocationVersion {
		t.Errorf("ProtocolVersion (%d) is below MinRevocationVersion (%d): "+
			"no agent could ever negotiate revocation",
			remote.ProtocolVersion, remote.MinRevocationVersion)
	}

	// A binding with nothing delivered is not revocable and must not trigger
	// the placement refusal — otherwise an empty lease would strand work on
	// older agents for no benefit.
	empty := executor.Spec{Argv: []string{"true"}, Secrets: []executor.SecretBinding{{LeaseID: "l"}}}
	if got := empty.RevocableSecrets(); len(got) != 0 {
		t.Errorf("a binding that delivered nothing must not count as revocable; got %v", got)
	}
	// And one with no lease ID cannot be targeted by a revoke, so it must not
	// pass as revocable either.
	orphan := executor.Spec{Argv: []string{"true"}, Secrets: []executor.SecretBinding{{EnvKeys: []string{"X"}}}}
	if got := orphan.RevocableSecrets(); len(got) != 0 {
		t.Errorf("a binding with no lease id cannot be revoked; got %v", got)
	}
	if got := dispatchedSpec().RevocableSecrets(); len(got) != 1 {
		t.Errorf("a real leased spec must report its revocable binding; got %v", got)
	}
}

// ---------------------------------------------------------------------------
// The guarantee is a property of the system, not of one driver
// ---------------------------------------------------------------------------

// TestEveryExecutorDriverImplementsRevoker is the gate that makes the rest of
// this file mean anything.
//
// Revocation was implemented in the remote driver alone for long enough that
// the gap became invisible: Spec.RevocableSecrets was consulted in exactly one
// file, the container and Kubernetes drivers accepted credentials they could
// not give back, and the Executors panel reported them as revocable anyway. The
// TTL and the push revocation were, on those backends, comments.
//
// Nothing about that was detectable by reading any single package, which is why
// the check is here rather than in a driver. The assertions below are on types
// rather than instances deliberately — constructing a container or Kubernetes
// executor needs a runtime or a cluster, and a guarantee that can only be
// checked where a cluster happens to exist is a guarantee that stops being
// checked.
func TestEveryExecutorDriverImplementsRevoker(t *testing.T) {
	revoker := reflect.TypeOf((*executor.Revoker)(nil)).Elem()

	drivers := map[string]reflect.Type{
		"localprocess": reflect.TypeOf((*localprocess.Executor)(nil)),
		"container":    reflect.TypeOf((*container.Executor)(nil)),
		"kubernetes":   reflect.TypeOf((*kubernetes.Executor)(nil)),
		"remote":       reflect.TypeOf((*remote.Executor)(nil)),
	}
	for name, typ := range drivers {
		if !typ.Implements(revoker) {
			t.Errorf("the %s driver does not implement executor.Revoker.\n"+
				"  A backend that cannot take a lease back must not be given one: the credential\n"+
				"  would outlive its revocation, and the lease TTL would be advisory on that backend.\n"+
				"  Implement Revoker, or accept that executor.RequireRevocable will refuse every\n"+
				"  workload carrying a brokered credential here.", name)
		}
	}
}

// TestNoDriverEscapesTheRevocationGate keeps the list above complete.
//
// The previous test can only check drivers someone remembered to add to it, and
// the failure this task fixed was precisely a backend nobody remembered. So the
// tree is scanned instead: any package under pkg/executor that implements the
// Executor interface — identified by declaring `func (e *Executor) Start(ctx
// context.Context, spec executor.Spec)` — must also declare RevokeLease.
//
// A driver author who skips it gets a build that passes and a test that names
// the omission, rather than a backend that quietly degrades. That is the whole
// of "a new backend must opt in explicitly, never degrade quietly".
func TestNoDriverEscapesTheRevocationGate(t *testing.T) {
	root := executorPackageRoot(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}

	checked := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		methods := executorMethods(t, dir)
		if !methods["Start"] {
			continue // not a driver
		}
		checked++
		for _, required := range []string{"RevokeLease", "HoldsLease", "Leases", "SupportsRevocation"} {
			if methods[required] {
				continue
			}
			t.Errorf("pkg/executor/%s implements executor.Executor but not executor.Revoker "+
				"(missing %s).\n"+
				"  Placement will refuse every workload carrying a brokered credential on this\n"+
				"  driver. If that is intended, say so here; if not, implement Revoker so a\n"+
				"  GitHub PAT or kubeconfig leased to it can actually be withdrawn mid-run.",
				entry.Name(), required)
		}
	}
	// A scan that silently matched nothing would pass forever. Four drivers
	// exist today; the floor guards a refactor that moves or renames them.
	if checked < 4 {
		t.Errorf("the driver scan found %d drivers under pkg/executor, want at least 4 — "+
			"the scan has stopped matching and is no longer gating anything", checked)
	}
}

// executorPackageRoot locates pkg/executor from the test's working directory.
func executorPackageRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// tests/security → repo root → pkg/executor
	root := filepath.Join(filepath.Dir(filepath.Dir(wd)), "pkg", "executor")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("locate pkg/executor from %s: %v", wd, err)
	}
	return root
}

// executorMethods returns the names of methods declared on *Executor in dir,
// excluding test files.
//
// Parsing rather than reflection because reflection cannot see a package that
// is not imported, and importing every driver to ask whether it exists is
// circular: the drivers this needs to catch are the ones nobody has wired up
// yet.
func executorMethods(t *testing.T, dir string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		// A directory that does not parse is not a silent pass: a driver
		// hidden behind a syntax error would skip the gate entirely.
		t.Fatalf("parse %s: %v", dir, err)
	}

	out := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
					continue
				}
				star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				ident, ok := star.X.(*ast.Ident)
				if !ok || ident.Name != "Executor" {
					continue
				}
				out[fn.Name.Name] = true
			}
		}
	}
	return out
}

// TestRevocableMaterialIsRefusedOnADriverThatCannotRevoke asserts the refusal
// itself, which is the mechanism that turns "this driver opted out" into
// something an operator sees.
//
// The diagnostic matters as much as the refusal. A placement that fails with
// "not supported" sends the operator to the wrong question; one that names the
// credential and the driver answers "which one, and what do I do about it" —
// the pattern the remote driver established and this generalises.
func TestRevocableMaterialIsRefusedOnADriverThatCannotRevoke(t *testing.T) {
	plain := &nonRevokingExecutor{id: "legacy-1", kind: "legacy"}

	err := executor.RequireRevocable(plain, dispatchedSpec())
	if err == nil {
		t.Fatal("a driver that cannot revoke accepted a workload carrying a revocable lease.\n" +
			"  The credential would be unwithdrawable for the life of the run.")
	}
	if !errors.Is(err, executor.ErrRevocationUnsupported) {
		t.Errorf("refusal does not match the sentinel callers filter on: %v", err)
	}
	for _, want := range []string{"legacy-1", "legacy", "github-ci"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot act on it: %v", want, err)
		}
	}

	// The refusal is about credentials, not about drivers. A deployment that
	// never configured the secret broker must be completely unaffected, or
	// this check becomes a reason not to ship it.
	bare := executor.Spec{WorkDir: "/srv/project", Argv: []string{"cloop", "run"}}
	if err := executor.RequireRevocable(plain, bare); err != nil {
		t.Errorf("a spec carrying no brokered credential was refused: %v", err)
	}

	// And a driver that can revoke is allowed the same spec that was refused
	// above, so the test cannot pass by refusing everything.
	if err := executor.RequireRevocable(&revokingExecutor{nonRevokingExecutor{id: "sandbox-1",
		kind: "container"}, true}, dispatchedSpec()); err != nil {
		t.Errorf("a revocation-capable driver was refused: %v", err)
	}

	// A driver that implements the interface but cannot honour a revocation
	// right now — an offline agent — is refused too. Implementing Revoker is a
	// property of the driver; being able to deliver is a property of the
	// moment, and placement has to respect the second one.
	offline := &revokingExecutor{nonRevokingExecutor{id: "edge-9", kind: "remote"}, false}
	if err := executor.RequireRevocable(offline, dispatchedSpec()); err == nil {
		t.Error("a driver reporting it cannot currently revoke was accepted anyway")
	}
}

// TestPlacementRefusesADriverThatCannotRevoke covers the other entry point.
//
// Resolve-then-Start is not the only way a workload is placed: failover picks a
// replacement through executor.Select, and a control that only guarded the
// first path would let a re-dispatch put the credential exactly where the
// original placement refused to.
func TestPlacementRefusesADriverThatCannotRevoke(t *testing.T) {
	candidates := []executor.Candidate{{
		Executor: &nonRevokingExecutor{id: "legacy-1", kind: "legacy"},
		Health:   executor.Health{State: executor.NodeReady},
	}}
	req := dispatchedSpec().SandboxRequirements()
	if !req.RequireRevocation {
		t.Fatal("a spec with a revocable binding must require revocation of its placement")
	}

	_, err := executor.Select(candidates, req)
	if err == nil {
		t.Fatal("placement chose a driver that cannot take the lease back")
	}
	var perr *executor.PlacementError
	if !errors.As(err, &perr) {
		t.Fatalf("Select error = %v, want a *PlacementError", err)
	}
	if perr.Constraint != executor.ConstraintRevocation {
		t.Errorf("rejected for %q, want %q — the operator needs to know it was revocation",
			perr.Constraint, executor.ConstraintRevocation)
	}

	// The same candidate is acceptable for work carrying no brokered
	// credential, so the constraint is not a blanket ban on the driver.
	bare := executor.Spec{Argv: []string{"true"}}
	if _, err := executor.Select(candidates, bare.SandboxRequirements()); err != nil {
		t.Errorf("an unleased workload was refused placement: %v", err)
	}
}

// nonRevokingExecutor is a driver that satisfies executor.Executor and nothing
// more — the shape a new backend has before its author thinks about
// revocation.
type nonRevokingExecutor struct {
	id   string
	kind string
}

func (e *nonRevokingExecutor) ID() string   { return e.id }
func (e *nonRevokingExecutor) Kind() string { return e.kind }
func (e *nonRevokingExecutor) Capabilities() executor.Capabilities {
	// Isolated, so the host-execution policy cannot be what rejects it and
	// mask the constraint under test.
	return executor.Capabilities{
		Isolation:      executor.IsolationContainer,
		SupportsStream: true,
		SupportsSignal: true,
	}
}
func (e *nonRevokingExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, nil
}
func (e *nonRevokingExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *nonRevokingExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e *nonRevokingExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, nil
}
func (e *nonRevokingExecutor) HealthCheck(context.Context) error { return nil }

// revokingExecutor adds the Revoker methods, with SupportsRevocation under the
// test's control so the "implements it but cannot deliver right now" case is
// reachable.
type revokingExecutor struct {
	nonRevokingExecutor
	canRevoke bool
}

func (e *revokingExecutor) SupportsRevocation() bool { return e.canRevoke }
func (e *revokingExecutor) HoldsLease(string) bool   { return false }
func (e *revokingExecutor) Leases() []string         { return nil }
func (e *revokingExecutor) RevokeLease(context.Context, executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{State: executor.RevokeStateRevoked}
}
func (e *revokingExecutor) Revocations() []executor.RevokeOutcome { return nil }

// newSessionStore returns a real SQLite-backed scheduling store.
//
// Real rather than in-memory because the redaction under test happens on the
// way *into* the row: a fake store that kept the struct in a map would hold
// the original pointer and pass while production wrote plaintext to disk.
func newSessionStore(t *testing.T) *executorstore.Scheduler {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		t.Fatalf("executorstore.NewScheduler: %v", err)
	}
	return sched
}

// ---------------------------------------------------------------------------
// The guarantee has to survive the control plane, not just the run
// ---------------------------------------------------------------------------

// restartLease writes a real credential file inside a real `cloop-lease-*`
// directory and returns the binding naming it.
//
// Real, because the property under test is that a *file on disk* stops being
// readable. A binding pointing at nothing would let a driver that wiped nothing
// report FilesRemoved 0 and still be scored as having revoked something — and
// the confinement rule in wipeBindingFiles means a path outside such a
// directory is refused, so a fake path would test the refusal instead.
func restartLease(t *testing.T, leaseID string) (executor.SecretBinding, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cloop-lease-"+leaseID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("stage lease dir: %v", err)
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte(leasedCredential), 0o600); err != nil {
		t.Fatalf("stage credential: %v", err)
	}
	return executor.SecretBinding{
		LeaseID:    leaseID,
		GrantID:    "grant_" + leaseID,
		SecretName: "github-ci",
		Kind:       "github_pat",
		EnvKeys:    []string{"GITHUB_TOKEN"},
		Files:      []string{token},
		Dir:        dir,
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}, token
}

// restartSpec is a long-running workload carrying one leased credential.
func restartSpec(t *testing.T, binding executor.SecretBinding) executor.Spec {
	t.Helper()
	return executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"sleep", "300"},
		Env:     []string{"PATH=/usr/bin:/bin", "GITHUB_TOKEN=" + leasedCredential},
		Secrets: []executor.SecretBinding{binding},
		Labels:  map[string]string{"task_id": "7"},
	}
}

// TestRevocationReachesAWorkloadThatOutlivedTheHub is the restart guarantee.
//
// Durable *identity* (Task 20191) let a restarted hub stream, signal and reap a
// workload it had forgotten it started. It did not let it revoke one: each
// driver's lease→handle index was built in Start and nowhere else, so a
// surviving workload answered HoldsLease with false, the fan-out in
// pkg/ui/secrets_revoke.go skipped that executor, and the aggregate came back
// `revoked`. An operator closing an incident on that answer would have been
// told a credential was withdrawn while the process holding it kept reading the
// file.
//
// The driver here is localprocess because it is the one backend that needs
// neither a container runtime nor a cluster, so this runs everywhere rather
// than only where a runtime happens to exist. The property is driver-independent
// — the index and the adoption rule are executor.LeaseIndex, shared by all four
// — and TestEveryExecutorDriverImplementsRevoker is what keeps that true.
func TestRevocationReachesAWorkloadThatOutlivedTheHub(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()
	binding, token := restartLease(t, "lease_restart")

	// The pre-restart control plane. It dispatches a workload holding the
	// lease and is then discarded without ever being closed — which is the
	// scenario: the hub died, the workload did not.
	first := localprocess.New("restart-revoke")
	first.AttachHandleStore(store)
	h, err := first.Start(ctx, restartSpec(t, binding))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = first.Signal(context.Background(), h.ID, executor.SignalKill) })
	if !first.HoldsLease(binding.LeaseID) {
		t.Fatal("the dispatching driver does not report itself as holding the lease it just placed; " +
			"the rest of this test would be vacuous")
	}

	// The negative control. A driver with no store knows nothing, so the
	// assertions below cannot pass merely because some driver answers yes to
	// every lease.
	blind := localprocess.New("restart-revoke")
	if blind.HoldsLease(binding.LeaseID) {
		t.Fatal("a driver with no handle store claims to hold a lease it was never given")
	}

	// The restart. `first` is deliberately never touched again.
	second := localprocess.New("restart-revoke")
	second.AttachHandleStore(store)

	if !second.HoldsLease(binding.LeaseID) {
		t.Fatal("a workload that survived the hub restart is not recognised as holding its lease.\n" +
			"  This is the bug: pkg/ui's fan-out skips an executor that answers HoldsLease false,\n" +
			"  so the revocation never reaches the process and the operator is told `revoked`.")
	}
	if leases := second.Leases(); len(leases) != 1 || leases[0] != binding.LeaseID {
		t.Errorf("Leases() after a restart = %v, want [%s]", leases, binding.LeaseID)
	}

	out := second.RevokeLease(ctx, executor.RevokeRequest{
		LeaseID: binding.LeaseID,
		Reason:  "credential rotated after the restart",
	})
	if out.State != executor.RevokeStateRevoked {
		t.Fatalf("RevokeLease after a restart = %q (%s), want %q",
			out.State, out.Error, executor.RevokeStateRevoked)
	}
	if out.Ack == nil || !out.Ack.Known {
		t.Fatalf("the revocation reported Known=false, i.e. nothing-to-revoke, for a workload that "+
			"is still running with the credential; ack = %+v", out.Ack)
	}
	if out.Ack.FilesRemoved < 1 {
		t.Errorf("FilesRemoved = %d, want at least 1 — the staged credential must actually be wiped",
			out.Ack.FilesRemoved)
	}

	// The property an operator actually cares about: the file is gone, so the
	// next read by the surviving process fails.
	if _, err := os.Stat(token); !os.IsNotExist(err) {
		t.Fatalf("the leased credential file %s still exists after the revocation (stat err = %v)", token, err)
	}
}

// TestAHubThatCannotRebuildABindingSaysSo is the honesty half.
//
// Persisting bindings closes the gap for rows written by a binary that records
// them. It cannot close it for a row written before that — an upgrade catches
// workloads mid-flight, and their rows say nothing about what they hold. The
// dangerous reading of such a row is the natural one: no bindings recorded, so
// no leases held, so a revocation has nothing to do and reports success.
//
// It must report a failure instead. "I cannot account for this workload" and
// "this workload holds nothing" have to stay distinguishable all the way to the
// operator, because only one of them means the incident is closed.
func TestAHubThatCannotRebuildABindingSaysSo(t *testing.T) {
	ctx := context.Background()
	store := executor.NewMemoryHandleStore()
	binding, token := restartLease(t, "lease_unrecorded")

	first := localprocess.New("unrecorded-revoke")
	first.AttachHandleStore(store)
	h, err := first.Start(ctx, restartSpec(t, binding))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = first.Signal(context.Background(), h.ID, executor.SignalKill) })

	// Rewrite the row as a pre-Task-20231 binary would have left it: identity
	// intact, bindings unrecorded. Mutating the stored row rather than faking a
	// driver is what makes this a test of the *reading* rule — the same rule
	// that fires on a row whose secrets_json cannot be decoded.
	rows, err := store.ListHandles("unrecorded-revoke")
	if err != nil || len(rows) != 1 {
		t.Fatalf("ListHandles = %d rows, %v; want exactly 1", len(rows), err)
	}
	legacy := rows[0]
	if !legacy.SecretsRecorded {
		t.Fatal("Start wrote a row with SecretsRecorded false; the positive guarantee is already broken")
	}
	legacy.Secrets, legacy.SecretsRecorded = nil, false
	if err := store.PutHandle(legacy); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	second := localprocess.New("unrecorded-revoke")
	second.AttachHandleStore(store)

	// It must still be *asked*. An executor that answers false here is skipped
	// by the fan-out, and a skipped executor contributes no outcome at all — so
	// the aggregate would read revoked no matter how loudly RevokeLease could
	// have complained.
	if !second.HoldsLease(binding.LeaseID) {
		t.Fatal("an executor running a workload whose bindings it cannot rebuild answered " +
			"HoldsLease false; the revocation fan-out will skip it entirely")
	}

	out := second.RevokeLease(ctx, executor.RevokeRequest{LeaseID: binding.LeaseID})
	if out.State == executor.RevokeStateRevoked {
		t.Fatalf("a hub that cannot account for a running workload reported the lease as %q.\n"+
			"  The credential is still on disk and still in the process's environment;\n"+
			"  reporting success here is how an incident gets closed on a live credential.\n"+
			"  ack = %+v", out.State, out.Ack)
	}
	if out.State != executor.RevokeStateFailed {
		t.Errorf("State = %q, want %q so the aggregate (which takes the worst) is not revoked",
			out.State, executor.RevokeStateFailed)
	}
	// The diagnostic has to name the handle and tell the operator what to do,
	// or "failed" is just an unactionable red badge.
	for _, want := range []string{h.ID, "rotate it at the source"} {
		if !strings.Contains(out.Error, want) {
			t.Errorf("the failure message must mention %q so an operator can act on it; got %q", want, out.Error)
		}
	}

	// And the doubt must clear once the workload it is about is gone, or one
	// pre-upgrade row would make every later revocation on this executor fail
	// for the life of the process.
	if err := second.Signal(ctx, h.ID, executor.SignalKill); err != nil {
		t.Fatalf("Signal on an adopted handle: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for second.HoldsLease("lease_unrelated") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if second.HoldsLease("lease_unrelated") {
		t.Error("the unresolved mark outlived the workload it described; every later revocation " +
			"on this executor would report a failure about a process that has exited")
	}
	_ = token
}

// TestPersistedBindingsCarryNoMaterialThroughSQLite is the durability half of
// the restart guarantee, asserted against a real database.
//
// executor_handles gained a secrets_json column so a revocation survives a
// restart, and a column that holds credential-adjacent data on the way to disk
// is exactly the shape of the mistake this file exists to catch: the row
// outlives the lease, survives the revocation, and is copied into every backup.
// SecretBinding is safe to persist *because* it carries no values, and the
// check is on the bytes that reach SQLite rather than on the struct, because
// the struct is what a future field would be added to.
//
// It also pins the three-state encoding the honesty guarantee depends on: ”
// (unrecorded) must not be stored or read back as '[]' (recorded, none).
func TestPersistedBindingsCarryNoMaterialThroughSQLite(t *testing.T) {
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handles, err := executorstore.NewHandles(db)
	if err != nil {
		t.Fatalf("executorstore.NewHandles: %v", err)
	}

	spec := dispatchedSpec()
	rec := executor.HandleRecord{
		HandleID:        "h-persist",
		ExecutorID:      "exec-persist",
		Driver:          executor.KindLocalProcess,
		ExternalID:      "4242",
		StartedAt:       time.Now(),
		Secrets:         spec.Secrets,
		SecretsRecorded: true,
	}
	if err := handles.PutHandle(rec); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	row, err := db.GetExecutorHandle(rec.HandleID)
	if err != nil {
		t.Fatalf("GetExecutorHandle: %v", err)
	}
	if strings.Contains(row.SecretsJSON, leasedCredential) {
		t.Fatalf("the leased credential reached executor_handles.secrets_json.\n"+
			"  That row outlives the lease and no revoke frame reaches SQLite.\n"+
			"  stored: %s", row.SecretsJSON)
	}
	if !strings.Contains(row.SecretsJSON, "lease_canary") {
		t.Errorf("the lease attribution did not survive the round trip; stored: %q", row.SecretsJSON)
	}

	// Read back through the adapter: the binding is restored and authoritative.
	back, err := handles.ListHandles("exec-persist")
	if err != nil || len(back) != 1 {
		t.Fatalf("ListHandles = %d rows, %v; want 1", len(back), err)
	}
	if !back[0].SecretsRecorded {
		t.Error("a row written with recorded bindings read back as unrecorded; every adopted " +
			"handle would be marked unresolved and every revocation would fail")
	}
	if len(back[0].Secrets) != 1 || back[0].Secrets[0].LeaseID != "lease_canary" {
		t.Fatalf("bindings did not round-trip: %+v", back[0].Secrets)
	}
	for _, env := range back[0].Secrets[0].EnvKeys {
		if strings.Contains(env, leasedCredential) {
			t.Errorf("EnvKeys carries a value, not a name: %q", env)
		}
	}

	// The three-state encoding. An unrecorded record must store '' and read
	// back unrecorded; a recorded-but-empty one must store '[]' and read back
	// recorded. Collapsing the two is the bug the honesty guarantee rests on.
	for _, tc := range []struct {
		name      string
		rec       executor.HandleRecord
		wantJSON  string
		wantKnown bool
	}{
		{"unrecorded", executor.HandleRecord{HandleID: "h-unknown", ExecutorID: "exec-persist",
			ExternalID: "1"}, "", false},
		{"recorded-empty", executor.HandleRecord{HandleID: "h-none", ExecutorID: "exec-persist",
			ExternalID: "2", SecretsRecorded: true}, "[]", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := handles.PutHandle(tc.rec); err != nil {
				t.Fatalf("PutHandle: %v", err)
			}
			got, err := db.GetExecutorHandle(tc.rec.HandleID)
			if err != nil {
				t.Fatalf("GetExecutorHandle: %v", err)
			}
			if got.SecretsJSON != tc.wantJSON {
				t.Errorf("secrets_json = %q, want %q", got.SecretsJSON, tc.wantJSON)
			}
			rows, err := handles.ListHandles("exec-persist")
			if err != nil {
				t.Fatalf("ListHandles: %v", err)
			}
			for _, r := range rows {
				if r.HandleID != tc.rec.HandleID {
					continue
				}
				if r.SecretsRecorded != tc.wantKnown {
					t.Errorf("SecretsRecorded = %v, want %v — '' and '[]' must not collapse",
						r.SecretsRecorded, tc.wantKnown)
				}
			}
		})
	}
}

// TestTheRemoteDriverAlsoRestoresBindingsOnRehydration extends the restart
// guarantee to the one other driver that can be built without a runtime.
//
// It matters separately from the localprocess case because the remote driver
// is the one whose credential is *not* on this machine. Its fan-out entry point
// (remote.Hub.RevokeLease, and LeaseHolders beside it) filters on HoldsLease
// exactly as pkg/ui's local walk does, so a rehydrated agent that answered
// false would be left holding a credential the operator had revoked and no
// queued frame would ever be replayed to it — the failure the offline-replay
// machinery exists to prevent, reintroduced through the restart door.
//
// NewExecutor rehydrates synchronously, so constructing one against a store
// that already has a row *is* the restart.
func TestTheRemoteDriverAlsoRestoresBindingsOnRehydration(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	rec := executor.HandleRecord{
		HandleID:        "h-remote-restart",
		ExecutorID:      "edge-1",
		Driver:          executor.KindRemoteAgent,
		ExternalID:      "h-remote-restart",
		StartedAt:       time.Now().Add(-time.Minute),
		Secrets:         dispatchedSpec().Secrets,
		SecretsRecorded: true,
	}
	if err := store.PutHandle(rec); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	// The negative control: same row, different executor. Rehydration is
	// scoped by executor id, and a driver that adopted every row would make
	// the positive assertion meaningless.
	other, err := remote.NewExecutor(remote.Options{ID: "edge-2", HandleStore: store})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if other.HoldsLease("lease_canary") {
		t.Error("a remote executor adopted another device's handle and claims its lease")
	}

	ex, err := remote.NewExecutor(remote.Options{ID: "edge-1", HandleStore: store})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if !ex.HoldsLease("lease_canary") {
		t.Fatal("a remote workload that survived the hub restart is not recognised as holding its lease.\n" +
			"  remote.Hub.RevokeLease filters on HoldsLease, so the revoke frame is never sent and\n" +
			"  never queued for replay — the device keeps the credential indefinitely.")
	}

	// With the agent offline the honest answer is `unreachable`, not
	// `revoked`: the credential is on a machine the hub cannot talk to. The
	// point of restoring the binding is that the revocation is now *queued*
	// for replay on reconnect instead of never being issued at all.
	out := ex.RevokeLease(context.Background(), executor.RevokeRequest{LeaseID: "lease_canary"})
	if out.State != executor.RevokeStateUnreachable {
		t.Errorf("RevokeLease against a rehydrated, disconnected agent = %q (%s), want %q",
			out.State, out.Error, executor.RevokeStateUnreachable)
	}
	if len(ex.Revocations()) == 0 {
		t.Error("the revocation was not retained, so nothing will be replayed when the device returns")
	}
}

// TestEveryDriverRehydratesItsLeaseBindings keeps the two wiring points above
// from being quietly dropped by the drivers this suite cannot construct.
//
// The container driver needs a runtime and the Kubernetes driver needs a
// cluster, so neither can be exercised here — and a guarantee that is only
// checked where a cluster happens to exist is a guarantee that stops being
// checked. The same reasoning produced the AST scan in
// TestNoDriverEscapesTheRevocationGate, and this is its counterpart for the
// restart half: persisting the bindings at dispatch, and restoring them on
// adoption. Miss either and the driver compiles, runs, and reports a
// revocation it did not perform.
func TestEveryDriverRehydratesItsLeaseBindings(t *testing.T) {
	root := executorPackageRoot(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}

	checked := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		if !executorMethods(t, dir)["Start"] {
			continue // not a driver
		}
		checked++
		src := driverSource(t, dir)

		if !strings.Contains(src, "SecretsRecorded") {
			t.Errorf("pkg/executor/%s never sets HandleRecord.SecretsRecorded.\n"+
				"  Its handle rows say nothing about which leases the workload holds, so after a\n"+
				"  restart every adopted workload is unaccounted for and every revocation on this\n"+
				"  driver reports a failure it cannot clear.", entry.Name())
		}
		if !strings.Contains(src, "leases.Adopt(") {
			t.Errorf("pkg/executor/%s never calls LeaseIndex.Adopt on rehydration.\n"+
				"  A workload that survives a hub restart will answer HoldsLease false, the\n"+
				"  revocation fan-out will skip this executor, and the operator will be told the\n"+
				"  credential was revoked while the workload keeps using it.", entry.Name())
		}
	}
	if checked < 4 {
		t.Errorf("the driver scan found %d drivers under pkg/executor, want at least 4 — "+
			"the scan has stopped matching and is no longer gating anything", checked)
	}
}

// driverSource concatenates a driver package's non-test Go sources.
//
// By directory rather than by loaded package, because the scan above walks
// pkg/executor's subdirectories and must see a driver that is not yet imported
// anywhere — which is exactly the driver most likely to have missed the wiring.
func driverSource(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var b strings.Builder
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b.Write(data)
	}
	if b.Len() == 0 {
		t.Fatalf("no source read for %s — the guard would silently pass", dir)
	}
	return b.String()
}
