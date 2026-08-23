package security

// Guarantee 7: materialising a project's source tree inside an isolated
// executor must not leak the credential that authorised the fetch, and must
// never silently degrade to running against an empty directory.
//
// Both halves are failure modes that look like success from the outside.
//
// A leaked token produces a run that works perfectly — the fetch succeeds, the
// task completes, and a long-lived GitHub credential is sitting in a Pod spec
// that anyone with `get pods` in the namespace can read, or in an artifact on
// the operator's disk. Nothing surfaces until it is used by someone else.
//
// An empty workspace is worse, because the harness cooperates: it starts, finds
// no code, and produces a plausible report about a repository it never saw. The
// bug this suite guards against is precisely that — before Task 20179 every
// non-local executor did it, and the Kubernetes driver's own comment conceded
// the tree was "expected" to be populated by something that did not exist.
//
// So the assertions here are deliberately about *absence*: the token is not in
// the Pod object, not in argv, not in the output, not on disk; and a fetch
// nobody can authorise is a refusal rather than a run.

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// conformanceToken is distinctive enough that a substring search for it cannot
// match anything a Pod object or a git transcript legitimately contains.
const conformanceToken = "ghp_CONFORMANCE0000SUITE0000SENTINEL0000"

// conformanceCredential is the credential every test here leases.
func conformanceCredential() executor.GitCredential {
	return executor.GitCredential{
		Username:   secretbroker.GitHubUsername,
		Password:   conformanceToken,
		LeaseID:    "lease-conformance",
		GrantID:    "grant-conformance",
		SecretName: "github-conformance",
	}
}

// leakVectors is every encoding of the token that a leak could take. Checking
// only the raw string would miss the case that actually matters: the token is
// delivered as base64 inside an Authorization header, so that encoding is the
// one most likely to end up echoed by a git error message.
func leakVectors() []string {
	c := conformanceCredential()
	vectors := append([]string{conformanceToken}, c.Secrets()...)
	seen := make(map[string]struct{}, len(vectors))
	out := vectors[:0]
	for _, v := range vectors {
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// assertNoLeak fails naming the vector that escaped, not just that one did.
func assertNoLeak(t *testing.T, what, body string) {
	t.Helper()
	for _, v := range leakVectors() {
		if strings.Contains(body, v) {
			t.Errorf("%s contains the leased credential (%s…): a workspace credential must "+
				"never reach it", what, v[:min(12, len(v))])
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- the Spec cannot carry a credential at all ------------------------------

// TestWorkspaceStructurallyCannotCarryACredential.
//
// The strongest form of "the token is never in the Spec" is not a check on a
// marshalled value — that only proves the current call sites are careful. It is
// that executor.Workspace has no field a token could be assigned to, so a
// future caller cannot put one there even by trying.
//
// A Spec is persisted by pkg/executorstore, marshalled across the remote
// executor boundary, and echoed into audit payloads. A credential field added
// here would become durable in three places before anything read it, which is
// why this test enumerates the permitted fields rather than merely scanning for
// suspicious names: a new field must be justified by editing this list.
func TestWorkspaceStructurallyCannotCarryACredential(t *testing.T) {
	allowed := map[string]bool{
		"Kind": true, "Repo": true, "Ref": true, "Depth": true,
		"CredentialGrant": true, "SizeLimitMB": true,
	}
	ty := reflect.TypeOf(executor.Workspace{})
	for i := 0; i < ty.NumField(); i++ {
		name := ty.Field(i).Name
		if !allowed[name] {
			t.Errorf("executor.Workspace gained field %q. A Spec is persisted, logged and "+
				"shipped to remote agents, so any new field must be shown not to be able to "+
				"carry credential material — then added to this list", name)
		}
	}

	// And the reference it does carry is a name, not material: a workspace
	// naming a grant must render without anything secret in it.
	w := executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git",
		Ref: "main", CredentialGrant: "github-conformance",
	}
	assertNoLeak(t, "Workspace.Describe()", w.Describe())

	spec := executor.Spec{Argv: []string{"cloop", "run"}, Workspace: w}
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	assertNoLeak(t, "the marshalled Spec", string(body))
	if !strings.Contains(string(body), "github-conformance") {
		t.Error("the marshalled Spec lost the grant name; the driver would have nothing to lease")
	}
}

// TestWorkspaceAuditEventCarriesNoCredential.
//
// Audit rows are the one artifact designed to be kept forever and read by
// people who were not there. The provisioning event names the grant and the
// lease so an incident can be reconstructed, and must name nothing that could
// still be used.
func TestWorkspaceAuditEventCarriesNoCredential(t *testing.T) {
	allowed := map[string]bool{
		"Phase": true, "ExecutorID": true, "ExecutorKind": true, "HandleID": true,
		"ProjectPath": true, "Workspace": true, "GrantID": true, "LeaseID": true,
		"DurationMS": true, "Err": true,
	}
	ty := reflect.TypeOf(executor.WorkspaceEvent{})
	for i := 0; i < ty.NumField(); i++ {
		if name := ty.Field(i).Name; !allowed[name] {
			t.Errorf("executor.WorkspaceEvent gained field %q; audit rows outlive every "+
				"credential in them, so a new field must be shown to carry none", name)
		}
	}
}

// --- Kubernetes: the token is not in the Pod object -------------------------

// TestWorkspaceTokenIsNotInThePodSpec.
//
// A Pod object is readable by every identity with `get pods` in the namespace,
// which on a shared cluster is a much larger set than the people entitled to
// the repository. So the credential reaches the init container by reference —
// a secretKeyRef naming a Secret — and the Pod itself must contain neither the
// token nor its base64 encoding.
//
// This drives the real Pod builder through the audit seam rather than
// reimplementing it, so a refactor that moves the token into an env value fails
// here instead of passing a test of a copy.
func TestWorkspaceTokenIsNotInThePodSpec(t *testing.T) {
	spec := executor.Spec{
		Argv:    []string{"/usr/local/bin/cloop", "run"},
		WorkDir: "/workspace",
		Workspace: executor.Workspace{
			Kind:            executor.WorkspaceGit,
			Repo:            "https://github.com/acme/tool.git",
			Ref:             "main",
			Depth:           1,
			CredentialGrant: "github-conformance",
		},
	}
	opts := kubernetes.Options{Image: "ghcr.io/acme/hub@" + allowedDigest}

	body, err := kubernetes.AuditPodJSON(context.Background(), opts, spec, "cloop-ws-conformance")
	if err != nil {
		t.Fatalf("build pod: %v", err)
	}
	assertNoLeak(t, "the Pod object", string(body))

	// Absence alone would also be satisfied by a Pod that simply never
	// authenticates, so assert the delivery mechanism is present and is the
	// indirect one.
	if !strings.Contains(string(body), "secretKeyRef") {
		t.Error("the Pod carries no secretKeyRef; a credentialed git workspace must reach the " +
			"init container by reference, and a Pod without one would fetch anonymously")
	}
	if !strings.Contains(string(body), "cloop-ws-conformance") {
		t.Error("the Pod does not name the workspace Secret the driver created")
	}
	if !strings.Contains(string(body), kubernetes.EnvWorkspaceToken) {
		t.Errorf("the Pod does not set %s; the provisioner would find no credential",
			kubernetes.EnvWorkspaceToken)
	}
}

// TestWorkspaceInitContainerIsAsConfinedAsTheHarness.
//
// The provisioning step runs attacker-adjacent input — a repository URL and a
// ref — inside the same Pod as the harness, before the harness exists. A less
// confined init container would be a way to obtain in the sandbox exactly the
// privileges the sandbox is there to deny.
func TestWorkspaceInitContainerIsAsConfinedAsTheHarness(t *testing.T) {
	spec := executor.Spec{
		Argv:    []string{"/usr/local/bin/cloop", "run"},
		WorkDir: "/workspace",
		Workspace: executor.Workspace{
			Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git", Ref: "main",
		},
	}
	body, err := kubernetes.AuditPodJSON(context.Background(),
		kubernetes.Options{Image: "ghcr.io/acme/hub@" + allowedDigest}, spec, "")
	if err != nil {
		t.Fatalf("build pod: %v", err)
	}

	var obj struct {
		Spec struct {
			InitContainers []json.RawMessage `json:"initContainers"`
			Containers     []json.RawMessage `json:"containers"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("decode pod: %v", err)
	}
	if len(obj.Spec.InitContainers) != 1 {
		t.Fatalf("expected exactly one init container for a git workspace, got %d",
			len(obj.Spec.InitContainers))
	}

	securityContextOf := func(raw json.RawMessage) map[string]any {
		var c struct {
			SecurityContext map[string]any `json:"securityContext"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("decode container: %v", err)
		}
		return c.SecurityContext
	}
	initCtx := securityContextOf(obj.Spec.InitContainers[0])
	harnessCtx := securityContextOf(obj.Spec.Containers[0])
	if len(initCtx) == 0 {
		t.Fatal("the workspace init container has no securityContext at all")
	}
	if !reflect.DeepEqual(initCtx, harnessCtx) {
		t.Errorf("the workspace init container is confined differently from the harness:\n"+
			"  init:    %v\n  harness: %v\n"+
			"It runs untrusted repository input in the same Pod, so any gap here is a way to "+
			"get privileges the sandbox exists to deny", initCtx, harnessCtx)
	}
}

// --- the token reaches exactly one process, by exactly one route ------------

// TestWorkspaceTokenReachesNoCommandLine.
//
// /proc/<pid>/cmdline is readable by every process on the box under the same
// uid, and a container's argv is additionally visible in the Pod object and in
// `docker inspect`. A credential passed as a flag or embedded in the clone URL
// would be published by all three, which is why the plan is built from a
// Workspace that structurally cannot hold one and the credential is applied
// only to an environment.
func TestWorkspaceTokenReachesNoCommandLine(t *testing.T) {
	w := executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git",
		Ref: "main", Depth: 1, CredentialGrant: "github-conformance",
	}
	plan, err := w.GitPlan("/workspace")
	if err != nil {
		t.Fatalf("GitPlan: %v", err)
	}
	if len(plan) == 0 {
		t.Fatal("a git workspace produced an empty plan; nothing would fetch the tree")
	}

	authenticated := 0
	for _, step := range plan {
		assertNoLeak(t, "argv of step "+step.Name, strings.Join(step.Argv, " "))
		if step.Authenticated {
			authenticated++
		}
	}
	// Exactly one, not "at least one": every additional step holding the
	// credential is another process whose environment carries it, for no gain.
	if authenticated != 1 {
		t.Errorf("%d steps are marked authenticated, want exactly 1 — the credential must "+
			"reach only the step that contacts the remote", authenticated)
	}

	env, err := executor.GitCredentialEnv(w, conformanceCredential())
	if err != nil {
		t.Fatalf("GitCredentialEnv: %v", err)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "extraHeader") {
		t.Error("the credential environment sets no http.extraHeader; nothing would authenticate")
	}
	// The header must be scoped to the repository's own origin. An unscoped
	// http.extraHeader is sent to whatever a redirect points at, which turns a
	// hostile or merely misconfigured redirect into credential exfiltration.
	if !strings.Contains(joined, "http."+w.BaseURL()+".extraHeader") {
		t.Errorf("the extraHeader is not scoped to %s; an unscoped one follows redirects to "+
			"third-party hosts and takes the credential with it\n%s", w.BaseURL(), joined)
	}
	// The base environment must be free of it, since every step runs with that.
	assertNoLeak(t, "the base git environment", strings.Join(executor.GitBaseEnv(), "\n"))
}

// --- end to end against a real git remote -----------------------------------

// TestWorkspaceProvisioningLeaksNothingOnSuccess drives the real provisioning
// engine against a real git server that demands the leased credential.
//
// The engine is the same one the remote agent and the Kubernetes init container
// both run, so this exercises the production path rather than a model of it.
func TestWorkspaceProvisioningLeaksNothingOnSuccess(t *testing.T) {
	cred := conformanceCredential()
	gs := startConformanceGitServer(t, cred.AuthorizationHeader(),
		map[string]string{"README.md": "hello from the conformance fixture\n"})

	dir := filepath.Join(t.TempDir(), "workspace")
	var out safeBuilder
	w := executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: gs.repo, Ref: "main", Depth: 1,
		CredentialGrant: "github-conformance",
	}
	if err := gitprovision.Provision(context.Background(), gitprovision.Request{
		Dir: dir, Workspace: w, Credential: cred, Emit: out.emit,
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// The tree really arrived. Without this the rest of the test would pass
	// trivially on a provisioner that did nothing — which is the original bug.
	body, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatalf("the workspace was not populated: %v", err)
	}
	if !strings.Contains(string(body), "conformance fixture") {
		t.Fatalf("unexpected workspace content %q", body)
	}

	// The credential was genuinely used, so the absence checks below are about
	// a token that existed rather than one that was never sent.
	if !gs.sawAuthorization(cred.AuthorizationHeader()) {
		t.Fatalf("the git server never received the leased credential; got %v", gs.authorizations())
	}

	assertNoLeak(t, "the provisioning transcript", out.String())
	for _, path := range leakedFiles(t, dir) {
		t.Errorf("%s contains the leased credential: provisioning must leave nothing on disk", path)
	}
	// Including git's own configuration, which is the file a credential helper
	// or an insteadOf rewrite would have been persisted into.
	for _, path := range leakedFiles(t, filepath.Join(dir, ".git")) {
		t.Errorf("%s contains the leased credential inside the checkout's git metadata", path)
	}
}

// TestWorkspaceProvisioningRedactsItsFailure.
//
// A rejected fetch is the case where git is most likely to quote the request
// back, and a failed run's error text goes further than a successful one's: it
// reaches the run panel, the task artifact, and usually a bug report.
func TestWorkspaceProvisioningRedactsItsFailure(t *testing.T) {
	cred := conformanceCredential()
	gs := startConformanceGitServer(t, "Basic something-else-entirely",
		map[string]string{"README.md": "unreachable\n"})

	dir := filepath.Join(t.TempDir(), "workspace")
	var out safeBuilder
	err := gitprovision.Provision(context.Background(), gitprovision.Request{
		Dir: dir,
		Workspace: executor.Workspace{
			Kind: executor.WorkspaceGit, Repo: gs.repo, Ref: "main", Depth: 1,
			CredentialGrant: "github-conformance",
		},
		Credential: cred,
		Emit:       out.emit,
	})
	if err == nil {
		t.Fatal("a fetch the server rejected reported success")
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("provisioning failure does not carry ErrWorkspaceUnavailable (%v); callers "+
			"cannot tell a missing tree from a failing harness", err)
	}
	assertNoLeak(t, "the provisioning error", err.Error())
	assertNoLeak(t, "the provisioning transcript", out.String())
	for _, path := range leakedFiles(t, filepath.Dir(dir)) {
		t.Errorf("%s contains the leased credential after a failed fetch", path)
	}
}

// --- a missing grant refuses rather than running empty -----------------------

// TestMissingGrantIsRefusedByName.
//
// This is the half of the guarantee that is not about secrecy. A workload whose
// fetch nobody can authorise must be refused, with the grant named, because the
// alternative is the failure this whole subsystem exists to remove: a harness
// that starts in an empty directory and reports confidently about code it never
// read.
func TestMissingGrantIsRefusedByName(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "conformance-suite-passphrase")
	broker, err := secretbroker.New(newMemStore(), secretbroker.WithAuditor(&recordingAuditor{}))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	src, err := gitcreds.New(broker, "k8s-prod", "conformance")
	if err != nil {
		t.Fatalf("gitcreds.New: %v", err)
	}

	w := executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git",
		Ref: "main", CredentialGrant: "github-conformance",
	}
	access, release, err := src.ForWorkspace(context.Background(), "/srv/acme", w)
	if release != nil {
		release()
	}
	if err == nil {
		t.Fatal("a workspace with no grant leased a credential")
	}
	if !access.Credential.Empty() {
		t.Fatal("a refused workspace still produced credential material")
	}
	if !errors.Is(err, executor.ErrWorkspaceGrantMissing) {
		t.Fatalf("refusal does not carry ErrWorkspaceGrantMissing: %v", err)
	}
	var grantErr *executor.WorkspaceGrantError
	if !errors.As(err, &grantErr) {
		t.Fatalf("refusal is not a *WorkspaceGrantError, so no caller can render the "+
			"remediation: %T", err)
	}
	// Naming the grant is the whole point of the typed error: "missing
	// credential" as a bare string is indistinguishable from a dozen other
	// refusals, and the operator's next question is always which one.
	if grantErr.Grant != "github-conformance" {
		t.Errorf("the error names grant %q, not the one the workspace asked for", grantErr.Grant)
	}
	if grantErr.RepoPath != "acme/tool" {
		t.Errorf("the error names repository %q, not acme/tool", grantErr.RepoPath)
	}
	if fix := grantErr.Remediation(); !strings.Contains(fix, "acme/tool") ||
		!strings.Contains(fix, "k8s-prod") {
		t.Errorf("the remediation %q does not name both the repository and the executor", fix)
	}
}

// TestExecutorThatCannotFetchIsRefusedAtPlacement.
//
// The credential check above happens at dispatch. This one happens earlier and
// covers the case where no credential is involved at all: an executor that
// cannot materialise a tree must not be handed a workload whose tree is not
// already there, whatever the repository's visibility.
func TestExecutorThatCannotFetchIsRefusedAtPlacement(t *testing.T) {
	spec := executor.Spec{
		Argv: []string{"cloop", "run"},
		Workspace: executor.Workspace{
			Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git", Ref: "main",
		},
	}
	req := spec.SandboxRequirements()
	if !req.RequireWorkspaceProvisioning {
		t.Fatal("a git workspace did not become a placement requirement, so nothing would " +
			"stop it being scheduled onto an executor that cannot fetch")
	}

	candidate := executor.Candidate{
		Executor: stubCapabilityExecutor{
			id: "no-fetch",
			caps: executor.Capabilities{
				Isolation:                     executor.IsolationContainer,
				SupportsWorkspaceProvisioning: false,
			},
		},
		Health: executor.Health{State: executor.NodeReady},
	}
	_, err := executor.Select([]executor.Candidate{candidate}, req)
	if err == nil {
		t.Fatal("an executor that cannot provision a workspace was selected for a git workload")
	}
	var placement *executor.PlacementError
	if !errors.As(err, &placement) {
		t.Fatalf("expected a *PlacementError naming the constraint, got %T: %v", err, err)
	}
	if placement.Constraint != executor.ConstraintWorkspace {
		t.Errorf("placement blamed %q rather than the workspace constraint", placement.Constraint)
	}

	// And the same requirement must hold on the binding path, which is a
	// separate entry point into "start a workload".
	bindErr := executor.CheckSandboxSupport(candidate.Executor, req, "/srv/acme")
	if bindErr == nil {
		t.Fatal("binding a git-workspace project to an executor that cannot fetch was allowed")
	}
	if !errors.Is(bindErr, executor.ErrNoPlacement) {
		t.Errorf("the binding refusal does not carry ErrNoPlacement: %v", bindErr)
	}
}

// stubCapabilityExecutor is an executor.Executor that exists only to advertise
// capabilities to the placement matcher. Every operation fails, because a test
// that reached one would be testing something else.
type stubCapabilityExecutor struct {
	id   string
	caps executor.Capabilities
}

func (s stubCapabilityExecutor) ID() string                          { return s.id }
func (s stubCapabilityExecutor) Kind() string                        { return "stub" }
func (s stubCapabilityExecutor) Capabilities() executor.Capabilities { return s.caps }
func (s stubCapabilityExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("stub executor cannot start workloads")
}
func (s stubCapabilityExecutor) Signal(context.Context, string, executor.Signal) error {
	return errors.New("stub")
}
func (s stubCapabilityExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, errors.New("stub")
}
func (s stubCapabilityExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("stub")
}
func (s stubCapabilityExecutor) HealthCheck(context.Context) error { return nil }

// --- fixtures ---------------------------------------------------------------

// conformanceGitServer is a real git remote over TLS that records the
// Authorization header of every request.
type conformanceGitServer struct {
	srv  *httptest.Server
	repo string

	mu       sync.Mutex
	receuved []string
}

func (g *conformanceGitServer) authorizations() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.receuved...)
}

func (g *conformanceGitServer) sawAuthorization(want string) bool {
	for _, got := range g.authorizations() {
		if got == want {
			return true
		}
	}
	return false
}

// startConformanceGitServer serves a fixture repository, demanding wantAuth on
// every request.
//
// It runs the real `git http-backend` over a real TLS listener rather than
// faking the transport, because the property under test is a property of how
// git itself carries the credential — a stub that accepted whatever the
// provisioner sent would prove nothing about where the token ends up.
func startConformanceGitServer(t *testing.T, wantAuth string, files map[string]string) *conformanceGitServer {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the workspace conformance tests drive a POSIX git installation")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; workspace provisioning cannot be exercised")
	}
	execPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git --exec-path failed: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git-http-backend is not installed at %s; cannot serve a real remote", backend)
	}

	root := t.TempDir()
	seedConformanceRepo(t, filepath.Join(root, "repo.git"), files)

	gs := &conformanceGitServer{}
	handler := &cgi.Handler{
		Path: backend,
		Env: []string{
			"GIT_PROJECT_ROOT=" + root,
			"GIT_HTTP_EXPORT_ALL=1",
		},
	}
	gs.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		gs.mu.Lock()
		gs.receuved = append(gs.receuved, auth)
		gs.mu.Unlock()
		if wantAuth != "" && auth != wantAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="cloop-conformance"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(gs.srv.Close)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gs.srv.Certificate().Raw})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	t.Setenv("GIT_SSL_CAINFO", caFile)

	gs.repo = gs.srv.URL + "/repo.git"
	return gs
}

// seedConformanceRepo builds a bare repository on branch main containing files.
func seedConformanceRepo(t *testing.T, bare string, files map[string]string) {
	t.Helper()
	run := func(dir string, args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_AUTHOR_NAME=cloop conformance", "GIT_AUTHOR_EMAIL=test@example.invalid",
			"GIT_COMMITTER_NAME=cloop conformance", "GIT_COMMITTER_EMAIL=test@example.invalid",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	work := filepath.Join(t.TempDir(), "seed")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("mkdir seed: %v", err)
	}
	run(work, "init", "--quiet", "--initial-branch=main")
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	run(work, "add", "-A")
	run(work, "commit", "--quiet", "-m", "conformance fixture")
	run(filepath.Dir(bare), "clone", "--quiet", "--bare", work, bare)
}

// safeBuilder collects emitted output from whatever goroutine produces it.
type safeBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuilder) emit(text string) {
	s.mu.Lock()
	s.b.WriteString(text)
	s.mu.Unlock()
}

func (s *safeBuilder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// leakedFiles returns every regular file under dir whose bytes contain any leak
// vector. A missing directory yields nothing, which is the right answer for the
// failure path where provisioning rolled its tree back.
func leakedFiles(t *testing.T, dir string) []string {
	t.Helper()
	vectors := leakVectors()
	var found []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || !d.Type().IsRegular() {
			return nil //nolint:nilerr // an unreadable entry cannot hold a leak we could act on
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		for _, v := range vectors {
			if strings.Contains(string(body), v) {
				found = append(found, path)
				return nil
			}
		}
		return nil
	})
	return found
}
