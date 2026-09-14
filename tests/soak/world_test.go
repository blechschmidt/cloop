package soak

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// harnessPath is where the stand-in workload lives inside the sandbox image.
//
// The hub dispatches its own executable as argv[0] (Server.selfExe), so the
// image has to carry something at a path the hub can name. Overriding
// Server.SelfExe to this fixed path is what lets the suite substitute a
// predictable workload for the agent harness without teaching the hub about
// tests.
const harnessPath = "/opt/cloop-soak/harness"

// canaryFile is the per-project file the workload reads its canary out of,
// relative to the project directory.
//
// The canary is read from the workspace rather than passed in the environment
// on purpose: it makes the value the workload prints a function of the bind
// mount the executor set up, so a frame carrying tenant A's canary proves A's
// project directory was mounted into the container that produced it. An
// environment variable would only have proved the hub formatted a string.
var canaryFile = filepath.Join(".cloop", "soak-canary")

// linesPerTask is how many canary lines one dispatch emits.
//
// Enough that the chunk is split across several WebSocket frames — the
// broadcast path batches, and a leak that only shows up on a particular
// framing boundary is exactly the kind this suite is for.
const linesPerTask = 24

// buildHarnessScript renders the stand-in workload.
//
// It reports whether the leased credential arrived and how large it was, but
// never its contents: the soak asserts that no byte of that credential
// survives anywhere on disk, and a workload that published it into the log
// stream would be manufacturing the evidence it is supposed to be checked
// against.
//
// Written as a function rather than a constant so the canary path is
// interpolated from canaryFile rather than duplicated as literal text, which
// is how the two would drift.
func buildHarnessScript() string {
	return fmt.Sprintf(`#!/bin/sh
# cloop soak stand-in workload. See tests/soak/world_test.go.
set -eu

canary=$(cat /workspace/%s 2>/dev/null || echo MISSING-CANARY)

# Prove the leased credential arrived without publishing it: the soak asserts
# no byte of it survives on disk, so echoing it here would forge that evidence.
lease_files=0
lease_bytes=0
if [ -n "${CLOOP_LEASE_DIR:-}" ] && [ -d "${CLOOP_LEASE_DIR}" ]; then
  lease_files=$(ls -1 "${CLOOP_LEASE_DIR}" 2>/dev/null | wc -l | tr -d ' ')
  lease_bytes=$(cat "${CLOOP_LEASE_DIR}"/* 2>/dev/null | wc -c | tr -d ' ')
fi
echo "soak meta uid=$(id -u) lease_files=${lease_files} lease_bytes=${lease_bytes} canary=${canary}"

i=0
while [ "$i" -lt %d ]; do
  echo "soak line ${i} canary=${canary}"
  i=$((i+1))
done
`, canaryFile, linesPerTask)
}

// ensureImage builds the sandbox image the soak dispatches into, and returns
// its reference.
//
// The tag is derived from the script's own digest, so a change to the workload
// produces a new image rather than silently reusing a stale one, and an
// unchanged workload costs a layer-cache hit instead of a rebuild.
func ensureImage(t *testing.T, runtime string) string {
	t.Helper()
	if override := strings.TrimSpace(os.Getenv(imageEnv)); override != "" {
		t.Logf("using %s=%s; skipping image build", imageEnv, override)
		return override
	}

	script := buildHarnessScript()
	sum := sha256.Sum256([]byte(script))
	tag := "localhost/cloop-soak:" + hex.EncodeToString(sum[:])[:16]

	// Already built? An `image inspect` is a local store read; on a repeat run
	// this is the whole cost of this function.
	if err := exec.Command(runtime, "image", "inspect", tag).Run(); err == nil {
		t.Logf("sandbox image %s already present", tag)
		return tag
	}

	// Under /var/tmp rather than /tmp: the sandbox mounts a tmpfs over /tmp,
	// and a build context that vanishes mid-build is a confusing failure.
	ctxDir, err := os.MkdirTemp("/var/tmp", "cloop-soak-img-")
	if err != nil {
		t.Fatalf("image build context: %v", err)
	}
	defer os.RemoveAll(ctxDir)

	if err := os.WriteFile(filepath.Join(ctxDir, "harness"), []byte(script), 0o755); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	dockerfile := fmt.Sprintf(`FROM %s
RUN mkdir -p %s
COPY harness %s
RUN chmod 0755 %s
`, baseImage(), filepath.Dir(harnessPath), harnessPath, harnessPath)
	if err := os.WriteFile(filepath.Join(ctxDir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	buildCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(buildCtx, runtime, "build", "-t", tag, ctxDir).CombinedOutput()
	if err != nil {
		t.Skipf("cannot build the sandbox image (no registry access?): %v\n%s", err, out)
	}
	t.Logf("built sandbox image %s", tag)
	return tag
}

// baseImage is the base the sandbox image derives from. Small and boring: the
// workload is twelve lines of shell.
func baseImage() string {
	if b := strings.TrimSpace(os.Getenv("CLOOP_SOAK_BASE_IMAGE")); b != "" {
		return b
	}
	return "alpine:3.20"
}

// project is one tenant-owned project directory.
type project struct {
	name   string
	dir    string
	tenant *tenant
	// idx is this project's position in its owner's ?project_idx= space.
	// Under a project-scoped token that space contains only the token's own
	// projects, so it is an index into tenant.projects.
	idx int
	// secretSentinel is the unique byte string embedded in this project's
	// leased credential. Nothing may hold it after the soak.
	secretSentinel string

	mu sync.Mutex
	// dispatched counts tasks driven through this project.
	dispatched int
}

// tenant is one identity: a project-scoped API token, the projects it owns,
// and the subscribers watching them.
type tenant struct {
	name     string
	email    string
	sub      string
	token    string
	projects []*project
	subs     []*subscriber
}

// canaryFor returns the canary string planted for one task.
//
// It names the tenant, the project and the sequence number, so a frame that
// turns up on the wrong stream identifies all three without a lookup table.
// That is the difference between a soak that says "mismatch" and one that
// says which tenant leaked into which.
func canaryFor(p *project, seq int) string {
	return fmt.Sprintf("CLOOPSOAK~%s~%s~task%04d~", p.tenant.name, p.name, seq)
}

// world is the booted hub plus everything pointed at it.
type world struct {
	root       string
	hubDir     string
	executorID string
	runtime    string
	image      string
	srv        *ui.Server
	ts         *httptest.Server
	tenants    []*tenant
	projects   []*project

	// startedAt bounds the window that leak detection attributes to this run,
	// so a sibling hub's lease directory on a shared machine is not read as
	// this suite's leak.
	startedAt time.Time
}

// newWorld boots a hub with flagTenants identities, each owning
// flagProjectsPerTenant projects bound to a real container executor.
func newWorld(t *testing.T) *world {
	t.Helper()

	rt := detectRuntime(t)
	w := &world{
		root:    t.TempDir(),
		runtime: rt,
		image:   ensureImage(t, rt),
		// Unique per run so container inventory can attribute a container to
		// this soak and not to a sibling hub sharing the machine.
		executorID: fmt.Sprintf("soak-%d-%d", os.Getpid(), time.Now().UnixNano()%1e6),
		startedAt:  time.Now(),
	}
	w.hubDir = filepath.Join(w.root, "hub")

	// The sealing key for the secret broker. Set in this process's
	// environment because that is where the broker reads it from; the test
	// binary's environment is its own, and TestMain has already isolated
	// $HOME, so nothing outside this suite observes it.
	t.Setenv(secretbroker.EnvPassphraseKey, "soak-sealing-passphrase-"+w.executorID)

	w.writeHubConfig(t)

	// The hub's control plane is itself a project directory, and it is always
	// index 0 of the unfiltered project list. Tenants never address it: their
	// tokens are scoped away from it, which is exactly the boundary under test.
	if _, err := state.Init(w.hubDir, "cloop soak control plane", 0); err != nil {
		t.Fatalf("init hub control plane: %v", err)
	}

	w.buildTenants(t)

	// ui.New reconciles the configured executors into the registry, which is
	// what puts the container executor's row in the database — so it has to
	// happen before anything binds a project to it.
	w.srv = ui.New(w.hubDir, 0, "")
	w.srv.Projects = w.projectPaths()
	w.srv.SelfExe = harnessPath

	// Raise the per-IP WebSocket cap, which defaults to 8 and which this suite
	// trips at three tenants (each opening one stream per project plus a
	// global one) because every connection arrives from 127.0.0.1.
	//
	// Raised rather than worked around: the cap is a per-source denial-of-
	// service bound, and collapsing distinct tenants onto one source address
	// is an artefact of running the hub and its clients in one process. Left
	// at the default, the suite would be measuring the cap instead of the
	// isolation, and the first symptom — a dial failing with 429 — says
	// nothing about either.
	//
	// Worth an operator's attention rather than only a test's: a hub behind a
	// reverse proxy sees every client at the proxy's address unless the
	// deployment sets behind_proxy, so this same cap applies fleet-wide there.
	// That is a real multi-tenant consideration, and it is documented in
	// docs/operations/soak.md rather than silently patched here.
	w.srv.MaxWebSocketConnsPerIP = *flagTenants*(*flagProjectsPerTenant+1) + 8
	w.srv.MaxWebSocketConns = w.srv.MaxWebSocketConnsPerIP * 4

	w.provisionControlPlane(t)

	w.ts = httptest.NewServer(w.srv.Handler())
	t.Cleanup(w.ts.Close)

	w.openSubscribers(t)
	return w
}

// writeHubConfig lays down the hub's config.yaml.
//
// allow_host_process is false: the soak runs the hub in the posture the
// project goal describes, where the web UI cannot spawn a harness on the host
// at all. That is not decoration — with host execution permitted, a
// misconfiguration that made the container executor unusable would silently
// fall back to running the workload as a child of the test process, and every
// isolation assertion below would pass while proving nothing.
func (w *world) writeHubConfig(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(w.hubDir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir hub: %v", err)
	}
	cfg := config.Default()
	no := false
	cfg.Executors.AllowHostProcess = &no
	cfg.Executors.Container.Enabled = true
	cfg.Executors.Container.ID = w.executorID
	cfg.Executors.Container.Runtime = w.runtime
	cfg.Executors.Container.Image = w.image
	cfg.Executors.Container.Network = "none"
	cfg.Executors.Container.PIDsLimit = 256
	cfg.Executors.Container.Memory = "256m"
	// The workload's uid is derived from the project directory's owner. On a
	// root-owned checkout that is uid 0, which the driver refuses unless this
	// is set deliberately — correctly, since root in a container defeats
	// --cap-drop=ALL. CI runs unprivileged and takes the strict path; a
	// developer box that is uid 0 would otherwise be unable to run the suite
	// at all, which is worse than running it with this waived.
	cfg.Executors.Container.AllowRootUser = os.Geteuid() == 0
	if err := config.Save(w.hubDir, cfg); err != nil {
		t.Fatalf("save hub config: %v", err)
	}
}

// buildTenants creates each identity's projects on disk.
func (w *world) buildTenants(t *testing.T) {
	t.Helper()
	names := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"}
	for i := 0; i < *flagTenants; i++ {
		name := fmt.Sprintf("tenant%d", i)
		if i < len(names) {
			name = names[i]
		}
		tn := &tenant{
			name:  name,
			email: name + "@soak.invalid",
			sub:   "soak-sub-" + name,
		}
		for p := 0; p < *flagProjectsPerTenant; p++ {
			pname := fmt.Sprintf("%s-proj%d", name, p)
			pr := &project{
				name:   pname,
				dir:    filepath.Join(w.root, pname),
				tenant: tn,
				idx:    p,
				// Distinct per project, and distinct from the canary: a
				// credential that leaks and a log line that leaks are
				// different defects and must not be confusable in a failure.
				secretSentinel: fmt.Sprintf("CLOOPSOAKSECRET-%s-%s", name, pname),
			}
			if err := os.MkdirAll(filepath.Join(pr.dir, ".cloop"), 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", pr.dir, err)
			}
			if _, err := state.Init(pr.dir, "soak project "+pname, 0); err != nil {
				t.Fatalf("init %s: %v", pr.dir, err)
			}
			// Seed the canary so a dispatch that races ahead of plantCanary
			// still prints something attributable rather than MISSING-CANARY.
			if err := os.WriteFile(filepath.Join(pr.dir, canaryFile),
				[]byte(canaryFor(pr, 0)), 0o644); err != nil {
				t.Fatalf("seed canary %s: %v", pr.dir, err)
			}
			tn.projects = append(tn.projects, pr)
			w.projects = append(w.projects, pr)
		}
		w.tenants = append(w.tenants, tn)
	}
}

// provisionControlPlane mints each tenant's token, binds its projects to the
// container executor, and grants each project its own credential.
func (w *world) provisionControlPlane(t *testing.T) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(w.hubDir))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer db.Close()

	tokStore, err := apitoken.NewSQLStore(db)
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	tokens, err := apitoken.NewManager(tokStore)
	if err != nil {
		t.Fatalf("token manager: %v", err)
	}
	secStore, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secret store: %v", err)
	}
	broker, err := secretbroker.New(secStore, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("secret broker: %v", err)
	}

	ctx := context.Background()
	for _, tn := range w.tenants {
		scope := make([]string, 0, len(tn.projects))
		for _, p := range tn.projects {
			scope = append(scope, p.dir)
		}
		// The tenant boundary. A project-scoped token does not merely hide
		// the other tenants' projects from a listing: it removes them from
		// the ?project_idx= index space entirely, so there is no index this
		// token could name that resolves to someone else's project.
		minted, err := tokens.Mint(apitoken.MintOptions{
			Name:         "soak-" + tn.name,
			Roles:        []string{"operator"},
			ProjectScope: scope,
			CreatedBy:    tn.email,
			Owner:        &apitoken.Owner{Sub: tn.sub, Email: tn.email, Name: tn.name},
		})
		if err != nil {
			t.Fatalf("mint token for %s: %v", tn.name, err)
		}
		tn.token = minted.Plaintext

		for _, p := range tn.projects {
			if err := db.BindProjectExecutor(p.dir, w.executorID, "soak"); err != nil {
				t.Fatalf("bind %s to %s: %v", p.name, w.executorID, err)
			}
			w.grantSecret(ctx, t, broker, p)
		}
	}
}

// grantSecret gives one project a credential that materializes as a file.
//
// A kubeconfig rather than an env secret specifically because it is delivered
// as bytes on disk: that is the path the wipe guarantee of Task 20193 covers,
// and an env-only credential would leave this suite asserting nothing about it.
func (w *world) grantSecret(ctx context.Context, t *testing.T, broker *secretbroker.Broker, p *project) {
	t.Helper()
	payload := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: soak
  cluster:
    server: https://kubernetes.invalid:6443
contexts:
- name: soak
  context:
    cluster: soak
    user: soak
    namespace: soak-%s
current-context: soak
users:
- name: soak
  user:
    token: %s
`, p.name, p.secretSentinel)

	sec, err := broker.Mint(ctx, secretbroker.MintRequest{
		Name:    "soak-kubeconfig-" + p.name,
		Kind:    secretbroker.KindKubeconfig,
		Payload: []byte(payload),
		Actor:   p.tenant.email,
	})
	if err != nil {
		t.Fatalf("mint secret for %s: %v", p.name, err)
	}
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID,
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectProject, Value: p.dir},
		Constraints: secretbroker.Constraints{
			Namespaces: []string{"soak-" + p.name},
		},
		TTL:   2 * time.Hour,
		Actor: p.tenant.email,
	}); err != nil {
		t.Fatalf("grant secret for %s: %v", p.name, err)
	}
}

func (w *world) projectPaths() []string {
	paths := make([]string, 0, len(w.projects))
	for _, p := range w.projects {
		paths = append(paths, p.dir)
	}
	return paths
}

// url builds a hub URL carrying a tenant's credential and project index.
func (w *world) url(path string, tn *tenant, idx int) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%s%stoken=%s&project_idx=%d", w.ts.URL, path, sep, tn.token, idx)
}

// do issues an authenticated request as one tenant.
func (w *world) do(ctx context.Context, method, path string, tn *tenant, idx int) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, w.url(path, tn, idx), nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil || sb.Len() > 1<<20 {
			break
		}
	}
	return resp.StatusCode, sb.String(), nil
}
