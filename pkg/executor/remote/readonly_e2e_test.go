package remote_test

// The other projects a run may read, on a device (Task 20501): a real agent
// behind a real WebSocket fetches each snapshot from the hub with the run's
// session token, unpacks it beneath its root, and gives it to the payload
// read-only — granted by the host sandbox to a confined host process, bound by
// the container driver otherwise — and removes it when the workload is gone.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/executor/readonlysnap"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
)

const readOnlyTestToken = knowledgerun.TokenPrefix + "0123456789abcdef01234567.secret-of-the-run"

// readOnlyHub serves the snapshot of project under the slug api to a request
// presenting the run's token, and refuses everything else as the hub refuses a
// project the run may no longer read.
func readOnlyHub(t *testing.T, project string) (*httptest.Server, *int32) {
	t.Helper()
	var served int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req knowledgerun.SnapshotRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.Header.Get("Authorization") != "Bearer "+readOnlyTestToken || req.Slug != "api" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no project this run may read is at that path"}`))
			return
		}
		mu.Lock()
		served++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/gzip")
		if _, err := readonlysnap.Build(r.Context(), project, w); err != nil {
			t.Errorf("Build: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &served
}

func readOnlyProjectDir(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := filepath.Join(t.TempDir(), "api")
	for rel, body := range map[string]string{"README.md": "api-readme\n", "src/api.go": "package api\n",
		".cloop/config.yaml": "api-control-secret\n", ".env": "api-env-secret\n"} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func readOnlySpec(workDir, url string, argv ...string) executor.Spec {
	ref := &executor.ReadOnlySnapshotRef{URL: url + knowledgerun.MountPath + knowledgerun.PathReadOnlySnapshot,
		TokenEnv: knowledgerun.EnvReadersToken}
	return executor.Spec{
		WorkDir: workDir,
		Argv:    argv,
		Env:     []string{"PATH=/usr/bin:/bin", "LANG=C", knowledgerun.EnvReadersToken + "=" + readOnlyTestToken},
		ReadOnly: []executor.ReadOnlyProject{
			{Slug: "api", Project: "/hub/projects/api", Name: "API", Snapshot: ref},
			// The hub refuses this one: its list no longer names the run's
			// project. It is left out, and the run is not told of it.
			{Slug: "gone", Project: "/hub/projects/gone", Snapshot: ref},
		},
	}
}

// readOnlyProbes reads the path the run's manifest gives api and tries what a
// run may and may not do there.
const readOnlyProbes = `p=$(printf '%s' "$CLOOP_READONLY_PROJECTS" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
echo "manifest=$CLOOP_READONLY_PROJECTS"
probe() { if out=$( eval "$2" 2>&1 ); then echo "$1:ok $out"; else echo "$1:denied $out"; fi; }
probe read "cat $p/src/api.go"
probe list "ls $p"
probe write "echo x > $p/README.md"
probe chmod-write "chmod u+w $p/README.md 2>/dev/null; echo x > $p/README.md"
probe create "touch $p/planted"
probe control "cat $p/.cloop/config.yaml"
probe env "cat $p/.env"
`

func TestLoopbackAConfinedHostRunReadsTheSnapshotItWasGivenAndCannotWriteIt(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox on this host: %v", err)
	}
	project := readOnlyProjectDir(t)
	hub, served := readOnlyHub(t, project)
	lb := newLoopback(t)
	ex := lb.executor(t)
	spec := readOnlySpec("proj-a-5e6f7a8b", hub.URL, "/bin/sh", "-c", readOnlyProbes)
	spec.ConfineToProject = true
	res, err := executor.Run(context.Background(), ex, spec)
	out := string(res.Output)
	if err != nil {
		t.Fatalf("run: %v (%q)", err, out)
	}
	t.Logf("payload said:\n%s", out)
	for _, want := range []string{"read:ok package api", "list:ok", "write:denied", "chmod-write:denied",
		"create:denied", "control:denied", "env:denied"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	for _, leak := range []string{"api-control-secret", "api-env-secret", "gone", readOnlyTestToken} {
		if strings.Contains(out, leak) {
			t.Errorf("the payload's output holds %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, filepath.Join(lb.root, ".cloop-readonly")) {
		t.Errorf("the manifest does not name where the agent placed the project:\n%s", out)
	}
	if *served != 1 {
		t.Errorf("the hub served %d snapshots, want 1", *served)
	}
	if b, _ := os.ReadFile(filepath.Join(project, "README.md")); string(b) != "api-readme\n" {
		t.Errorf("the hub's project changed: %q", b)
	}
	assertReadOnlyGone(t, lb.root)
}

// readOnlyRecorder is the agent's "container driver": a host process that
// records the read-only projects and the manifest the sandbox was given.
type readOnlyRecorder struct {
	*localprocess.Executor
	mu       sync.Mutex
	readOnly []executor.ReadOnlyProject
	manifest string
	present  map[string]bool
}

func (r *readOnlyRecorder) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	r.mu.Lock()
	r.readOnly = append([]executor.ReadOnlyProject(nil), spec.ReadOnly...)
	r.present = map[string]bool{}
	for _, p := range spec.ReadOnly {
		_, err := os.Stat(filepath.Join(p.Source, "src", "api.go"))
		r.present[p.Slug] = err == nil
	}
	for _, kv := range spec.Env {
		if v, ok := strings.CutPrefix(kv, executor.EnvReadOnlyProjects+"="); ok {
			r.manifest = v
		}
	}
	r.mu.Unlock()
	spec.ReadOnly = nil
	return r.Executor.Start(ctx, spec)
}

func TestLoopbackAContainerRunIsGivenTheSnapshotToBindAtReadonly(t *testing.T) {
	project := readOnlyProjectDir(t)
	hub, _ := readOnlyHub(t, project)
	rec := &readOnlyRecorder{Executor: localprocess.New("readonly-test")}
	lb := newLoopbackHub(t, func(o *remote.HubOptions) {
		o.SandboxSource = func(string) func() (executor.SandboxSettings, error) {
			return func() (executor.SandboxSettings, error) {
				return executor.SandboxSettings{Mode: executor.SandboxModeContainer}, nil
			}
		}
	}, func(c *agent.Config) {
		c.ContainerDriver = func(executor.SandboxSettings) (executor.Executor, error) { return rec, nil }
	})
	lb.waitConnected(t)
	ex := lb.executor(t)
	if got := ex.Capabilities().ReadOnlyProjects; got != executor.ReadOnlySnapshot {
		t.Fatalf("a current agent's capabilities say %q, want snapshot", got)
	}
	if res, err := executor.Run(context.Background(), ex, readOnlySpec("proj-a-5e6f7a8b", hub.URL, "/bin/true")); err != nil {
		t.Fatalf("run: %v (%q)", err, res.Output)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.readOnly) != 1 || rec.readOnly[0].Slug != "api" || rec.readOnly[0].Snapshot != nil ||
		!strings.HasPrefix(rec.readOnly[0].Source, filepath.Join(lb.root, ".cloop-readonly")+string(filepath.Separator)) {
		t.Fatalf("the container driver was given %+v; want api alone, placed beneath the agent's root", rec.readOnly)
	}
	if !rec.present["api"] {
		t.Fatal("the snapshot was not unpacked where the container driver was told to bind it from")
	}
	entries, err := executor.DecodeReadOnlyManifest(rec.manifest)
	if err != nil || len(entries) != 1 || entries[0].Path != "/readonly/api" {
		t.Fatalf("the manifest the sandbox was given = %q (%v); want api at /readonly/api", rec.manifest, err)
	}
	assertReadOnlyGone(t, lb.root)
}

// assertReadOnlyGone checks the agent removed every workload's read-only
// projects once its workloads were over.
// The agent forgets a workload once its final status is delivered, a moment
// after the run is over for the hub.
func assertReadOnlyGone(t *testing.T, root string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		entries, err := os.ReadDir(filepath.Join(root, ".cloop-readonly"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("the agent left read-only projects behind: %v", entries)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestReadOnlyProjectsNeedProtocol31: an agent below v31 ignores Spec.ReadOnly,
// so its sessions advertise no delivery — the hub gives its runs none — and a
// spec that carries some anyway is refused, naming the upgrade.
func TestReadOnlyProjectsNeedProtocol31(t *testing.T) {
	spec := plainSpec(t.TempDir())
	spec.ReadOnly = []executor.ReadOnlyProject{{Slug: "api", Project: "/hub/projects/api",
		Snapshot: &executor.ReadOnlySnapshotRef{URL: "https://hub.example/snap", TokenEnv: "T"}}}

	old := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess := connect(t, old, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloAt(remote.MinReadOnlyProjectsVersion-1), nil)
	if got := old.Capabilities().ReadOnlyProjects; got != executor.ReadOnlyNone {
		t.Errorf("a v%d session advertises read-only delivery %q", remote.MinReadOnlyProjectsVersion-1, got)
	}
	_, err := old.Start(context.Background(), spec)
	sess.Close()
	if !errors.Is(err, remote.ErrReadOnlyProjectsUnsupported) {
		t.Fatalf("Start = %v, want ErrReadOnlyProjectsUnsupported", err)
	}
	for _, want := range []string{"edge-1", "v30", "v31"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q: %v", want, err)
		}
	}

	current := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess = connect(t, current, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloAt(remote.MinReadOnlyProjectsVersion), nil)
	defer sess.Close()
	if got := current.Capabilities().ReadOnlyProjects; got != executor.ReadOnlySnapshot {
		t.Errorf("a v%d session advertises read-only delivery %q, want snapshot", remote.MinReadOnlyProjectsVersion, got)
	}
	if remote.SupportsReadOnlyProjects(remote.MinReadOnlyProjectsVersion-1) ||
		!remote.SupportsReadOnlyProjects(remote.ProtocolVersion) {
		t.Error("SupportsReadOnlyProjects disagrees with MinReadOnlyProjectsVersion")
	}
}
