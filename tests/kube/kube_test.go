// Package kube_test proves the git interception proxy and the Kubernetes access
// monitor end to end on a real cluster, against the hub the Helm chart
// installed (Task 20385).
//
// Before this, both were proven on Kubernetes only by unit tests against the
// objects the driver sends the API server. Two of the seven integration gaps
// Task 20347 found in the git proxy were Kubernetes-only — the session
// username missing from the cloop-ws-<handle> Secret, the credential helper
// projected without its execute bit — and both were found by reading the code.
// This test runs a Pod through them instead.
//
// # What it does
//
// Given a cluster whose release of deploy/helm/cloop-hub runs the in-cluster
// executor (CI's kind cluster), it:
//
//  1. builds two images and loads them into kind: a test forge
//     (pkg/secretbroker/secretbrokertest's, see ./forge) and a harness image
//     carrying cloop, git, kubectl and the stand-in claude that runs probe.sh;
//  2. records whether the cluster's CNI enforces NetworkPolicy, by the hub's
//     own probe (pkg/hubdoctor/netpol.go);
//  3. serves the forge in the cluster as github.com: the hub reaches it under
//     that name through a hostAliases entry and trusts the test CA through
//     extraCACerts, so a GitHub PAT grant takes its production path;
//  4. upgrades the release with executor.gitProxy and executor.kubeGuard on,
//     a self-signed monitor certificate — whose CA the chart delivers to the
//     workload Pods — and a per-Pod egress filter;
//  5. registers a project whose origin is github.com/acme/granted, grants it a
//     PAT limited to that repository and one branch pattern, a read-only
//     kubeconfig for a test namespace, and a harness credential;
//  6. dispatches its one task, which runs probe.sh in the Pod; and asserts the
//     probe's results, the forge's refs, the gitproxy.push_denied and
//     kubeguard audit rows, that the granted harness login is in the
//     container's environment but nowhere in the Pod object (Task 20401), and
//     that the run's Pod, Secrets and NetworkPolicy are gone afterwards.
//
// It changes the release it is pointed at and leaves the monitors on. Point it
// only at a throwaway cluster.
package kube_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// realHome is HOME before hometest.Isolate redirected it. The tools this test
// drives — go, docker, kind, helm, kubectl — read their own caches and
// credentials from it, and none of them writes cloop state; only the cloop
// CLI runs under the sandboxed HOME.
var realHome string

func TestMain(m *testing.M) {
	realHome = os.Getenv("HOME")
	os.Exit(hometest.Isolate(m))
}

// Environment the test reads. Only the first is required; it opts the test in.
const (
	// kubeconfigEnv names a kubeconfig with cluster-admin on a throwaway
	// cluster the chart is installed in.
	kubeconfigEnv = "CLOOP_KUBE_E2E_KUBECONFIG"
	// kindEnv names the kind cluster to load the test images into. Unset, the
	// images must already be on the nodes.
	kindEnv = "CLOOP_KUBE_E2E_KIND_CLUSTER"
	// importEnv is a shell command that reads an image tarball (docker save) on
	// stdin and loads it onto the cluster's nodes — for a cluster that is not
	// kind, e.g. "docker exec -i k3s ctr images import -".
	importEnv = "CLOOP_KUBE_E2E_IMAGE_IMPORT"
	// binEnv supplies a static cloop for the harness image; unset, one is built.
	binEnv = "CLOOP_KUBE_E2E_CLOOP_BIN"
	// releaseEnv and namespaceEnv locate the release: "cloop" in "cloop" by
	// default, which is what CI installs.
	releaseEnv   = "CLOOP_KUBE_E2E_RELEASE"
	namespaceEnv = "CLOOP_KUBE_E2E_NAMESPACE"
	// keepEnv leaves the forge, the target namespace and the helper Pod behind.
	keepEnv = "CLOOP_KUBE_E2E_KEEP"
)

const (
	// alpineDigest is alpine:3.20 by digest, the base tests/flagship pins and
	// the repository's Dockerfile uses for its executor stage.
	alpineDigest = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

	forgeImage   = "cloop-kube-e2e-forge:local"
	harnessImage = "cloop-kube-e2e-harness:local"

	grantedRepo = "acme/granted"
	otherRepo   = "acme/other"

	gitProxyPort  = 8443
	kubeGuardPort = 8444
)

//go:embed probe.sh
var probeScript string

// forgeNS and targetNS are this run's namespaces — the forge's, and the one
// the kubeconfig grant covers. Named per run: CI runs the test twice against
// one cluster, and the first run's namespaces are still terminating when the
// second starts.
var forgeNS, targetNS string

func TestGitProxyAndKubeGuardOnKubernetes(t *testing.T) {
	kubeconfig := os.Getenv(kubeconfigEnv)
	if kubeconfig == "" {
		t.Skipf("set %s to a throwaway cluster's kubeconfig to run this", kubeconfigEnv)
	}
	for _, bin := range []string{"kubectl", "helm", "docker"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s is not on PATH: %v", bin, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	x := tool{t: t, kubeconfig: kubeconfig}
	keep := os.Getenv(keepEnv) != ""

	release := envOr(releaseEnv, "cloop")
	ns := envOr(namespaceEnv, "cloop")
	fullname := release + "-cloop-hub"
	if strings.Contains(release, "cloop-hub") {
		fullname = release
	}
	values := releaseValues(ctx, x, release, ns)
	workloadNS := "cloop-workloads"
	if v, ok := dig(values, "executor", "kubernetes", "namespace").(string); ok && v != "" {
		workloadNS = v
	}
	if on, _ := dig(values, "executor", "kubernetes", "enabled").(bool); !on {
		t.Fatalf("release %s in %s does not run the Kubernetes executor; this test dispatches to it", release, ns)
	}
	t.Logf("release %s (%s) in %s, workloads in %s", release, fullname, ns, workloadNS)

	stamp := fmt.Sprintf("%d", time.Now().Unix())
	forgeNS, targetNS = "cloop-e2e-forge-"+stamp, "cloop-e2e-target-"+stamp
	replicas := x.out(ctx, "get", "deploy", "-n", ns, fullname, "-o", "jsonpath={.spec.replicas}")
	t.Logf("the hub runs %s replica(s)", replicas)
	allowed, denied := "cloop/e2e-allowed-"+stamp, "cloop/e2e-other-"+stamp
	branchRule := "cloop/e2e-allowed-*"
	pat := "ghp_" + randomAlnum(t, 36)
	// The harness login the run is granted. Fresh per run, so finding it in
	// the Pod object is unambiguous (Task 20401).
	harnessKey := "kube-e2e-harness-key-" + randomAlnum(t, 32)
	harnessKeySum := sha256.Sum256([]byte(harnessKey))

	// ── 1. Images ──────────────────────────────────────────────────────────
	buildImages(ctx, t, x)

	// ── 2. Does this CNI enforce NetworkPolicy? ────────────────────────────
	enforced, verdict := probeNetworkPolicy(ctx, t, x, ns, fullname)
	t.Logf("NetworkPolicy enforcement on this cluster (cloop hub doctor --probe-network-policy): %s", verdict)
	if !enforced {
		t.Logf("NOTE: this CNI does not enforce NetworkPolicy, so the per-task policy is created and " +
			"removed but egress blocking is NOT asserted")
	}

	// ── 3. The forge, as github.com ────────────────────────────────────────
	ca := secretbrokertest.NewCA(t)
	forgeHost := "forge." + forgeNS + ".svc"
	leaf := ca.Issue(t, "github.com", forgeHost, forgeHost+".cluster.local")
	if !keep {
		t.Cleanup(func() {
			x.run(context.Background(), nil, true, "kubectl", "delete", "namespace", forgeNS, targetNS, "--wait=false")
		})
	}
	forgeIP, forgePod := deployForge(ctx, t, x, leaf, pat)
	t.Logf("forge %s at %s serving %s and %s", forgePod, forgeIP, grantedRepo, otherRepo)

	// ── 4. A namespace the kubeconfig grant covers, and its credential ────
	kubeconfigPayload, clusterToken := targetKubeconfig(ctx, t, x)

	// ── 5. The release, with both monitors on ──────────────────────────────
	nodeCIDR := x.out(ctx, "get", "nodes", "-o", "jsonpath={.items[0].spec.podCIDR}")
	hubIP := x.out(ctx, "get", "svc", "-n", ns, fullname, "-o", "jsonpath={.spec.clusterIP}")
	if nodeCIDR == "" || hubIP == "" {
		t.Fatalf("could not read the pod CIDR (%q) or the hub's ClusterIP (%q)", nodeCIDR, hubIP)
	}
	x.apply(ctx, configMap("cloop-e2e-forge-ca", ns, map[string]string{"ca.crt": string(ca.CertPEM)}))
	upgradeRelease(ctx, t, x, release, ns, fullname, []string{
		"executor.gitProxy.enabled=true",
		"executor.kubeGuard.enabled=true",
		"executor.kubeGuard.auditAllowed=true",
		"executor.monitorTLS.selfSigned=true",
		"executor.kubernetes.image=" + harnessImage,
		"executor.kubernetes.egressFilter.enabled=true",
		"executor.kubernetes.egressFilter.cidrs[0]=" + nodeCIDR,
		"executor.kubernetes.egressFilter.cidrs[1]=" + hubIP + "/32",
		fmt.Sprintf("executor.kubernetes.egressFilter.ports[0]=%d", gitProxyPort),
		fmt.Sprintf("executor.kubernetes.egressFilter.ports[1]=%d", kubeGuardPort),
		"extraCACerts.configMap=cloop-e2e-forge-ca",
		"hostAliases[0].ip=" + forgeIP,
		"hostAliases[0].hostnames[0]=github.com",
	})

	// ── 6. The project: hub-side checkout, forge-side state ────────────────
	projectDir := "/var/lib/cloop/.cloop/e2e/kube-" + stamp
	helper := startStateHelper(ctx, t, x, ns, fullname, keep)
	registerProject(ctx, t, x, ns, helper, projectDir, "https://github.com/"+grantedRepo+".git")
	params := map[string]string{
		"REPO": grantedRepo, "OTHER_REPO": otherRepo, "STAMP": stamp,
		"ALLOWED": allowed, "DENIED": denied, "BRANCH_RULE": branchRule, "K8S_NS": targetNS,
		"FORGE_URL": "https://" + forgeHost, "EXPECT_EGRESS_BLOCKED": boolDigit(enforced),
		// A digest, not the key: the probe compares what its environment holds
		// against it without the value ever being written anywhere.
		"HARNESS_KEY_SHA256": hex.EncodeToString(harnessKeySum[:]),
	}
	seedForgeProject(ctx, t, x, forgePod, params)

	// ── 7. Grants, through the hub's API ───────────────────────────────────
	hub := hubClient{t: t, base: x.portForward(ns, fullname, 8080), http: &http.Client{Timeout: time.Minute}}
	hub.token = x.out(ctx, "exec", "-n", ns, "deploy/"+fullname, "--",
		"/usr/local/bin/cloop", "hub", "token", "create", "kube-e2e-"+stamp, "--role", "admin",
		"--expires-in", "2h", "--quiet")
	if !strings.HasPrefix(hub.token, "cloop_pat_") || strings.ContainsAny(hub.token, " \n") {
		t.Fatalf("cloop hub token create printed something other than a token (%d bytes)", len(hub.token))
	}
	idx := projectIndex(t, hub, projectDir)
	hub.must("POST", fmt.Sprintf("/api/init?project_idx=%d", idx), map[string]any{
		"goal": "Task 20385: prove the git proxy and the kube guard from a Pod", "provider": "claudecode",
	}, nil)
	hub.must("POST", "/api/secrets", map[string]any{
		"name": "kube-e2e-pat-" + stamp, "kind": "github_pat", "payload": pat, "personal": false,
	}, nil)
	hub.must("POST", fmt.Sprintf("/api/projects/%d/repositories", idx), map[string]any{
		"secret": "kube-e2e-pat-" + stamp, "repos": []string{grantedRepo}, "access": "write",
		"branches": []string{branchRule}, "ttl_minutes": 120,
	}, nil)
	hub.must("POST", "/api/secrets", map[string]any{
		"name": "kube-e2e-kubeconfig-" + stamp, "kind": "kubeconfig", "payload": kubeconfigPayload, "personal": false,
	}, nil)
	// No verbs: a kubeconfig grant without them is read-only.
	hub.must("POST", "/api/grants", map[string]any{
		"secret_ref": "kube-e2e-kubeconfig-" + stamp, "subject": "project:" + projectDir,
		"namespaces": []string{targetNS}, "ttl_minutes": 120,
	}, nil)
	hub.must("POST", fmt.Sprintf("/api/projects/%d/executor", idx), map[string]any{"executor_id": "kubernetes"}, nil)
	// The stand-in harness needs no Claude login, but the hub refuses to
	// dispatch to an isolating executor without one (Task 20379).
	hub.must("POST", "/api/secrets", map[string]any{
		"name": "kube-e2e-harness-" + stamp, "kind": "env",
		"payload": fmt.Sprintf(`{"ANTHROPIC_API_KEY":%q}`, harnessKey), "personal": false,
	}, nil)
	hub.must("POST", fmt.Sprintf("/api/projects/%d/harness-credential", idx), map[string]any{
		"secret": "kube-e2e-harness-" + stamp, "env_keys": []string{"ANTHROPIC_API_KEY"}, "ttl_minutes": 120,
	}, nil)

	// ── 8. Run ─────────────────────────────────────────────────────────────
	since := time.Now().Add(-time.Minute)
	hub.must("POST", fmt.Sprintf("/api/run?project_idx=%d", idx), map[string]any{}, nil)
	lines, podJSON, objects := awaitRun(ctx, t, x, hub, idx, workloadNS)
	results := parseResults(lines)

	// ── 9. What the Pod saw ────────────────────────────────────────────────
	for _, id := range append([]string{"A1", "H1", "T1", "C1", "WS1", "WS2", "P1", "B1", "B2", "R1", "K0", "K1", "K2", "K3"},
		conditional(enforced, "E1")...) {
		r, ok := results[id]
		switch {
		case !ok:
			t.Errorf("probe check %s never reported; the run's log:\n%s", id, strings.Join(lines, "\n"))
		case !r.pass:
			t.Errorf("probe check %s failed: %s", id, r.detail)
		default:
			t.Logf("%s PASS %s", id, r.detail)
		}
	}
	for id, r := range results {
		if !r.pass {
			t.Errorf("probe check %s failed: %s", id, r.detail)
		}
	}
	// The PAT never entered the Pod object either — not as an env value, not
	// in an annotation, not anywhere the API server stores.
	if strings.Contains(podJSON, pat) {
		t.Error("the workload Pod's object contains the PAT")
	}
	if strings.Contains(podJSON, clusterToken) {
		t.Error("the workload Pod's object contains the cluster's ServiceAccount token")
	}
	// Nor the harness login (Task 20401). A1 above proved the container's
	// environment holds it; the Pod object — readable by every identity with
	// `get pods` in the namespace — must hold only the reference to the run's
	// lease Secret it was read from.
	if strings.Contains(podJSON, harnessKey) ||
		strings.Contains(podJSON, base64.StdEncoding.EncodeToString([]byte(harnessKey))) {
		t.Error("the workload Pod's object contains the granted ANTHROPIC_API_KEY")
	}
	if !regexp.MustCompile(`"key":\s*"env\.ANTHROPIC_API_KEY"`).MatchString(podJSON) {
		t.Error("the workload Pod does not read ANTHROPIC_API_KEY from its lease Secret by reference")
	}
	// The refused write did not happen behind the refusal: the credential the
	// monitor holds may edit this namespace, so only the monitor stood between.
	if out, err := x.kubectlMay(ctx, "get", "configmap", "-n", targetNS, "e2e-"+stamp, "-o", "name"); err == nil {
		t.Errorf("configmap e2e-%s exists in %s (%s): the monitor's refusal did not stop the write", stamp, targetNS, out)
	}

	// ── 10. What the forge holds ───────────────────────────────────────────
	pushed := ""
	if m := regexp.MustCompile(`accepted at ([0-9a-f]{40})`).FindStringSubmatch(results["B1"].detail); m != nil {
		pushed = m[1]
	}
	refs := forgeRefs(ctx, t, x, forgePod, grantedRepo)
	if got := refs["refs/heads/"+allowed]; got == "" || got != pushed {
		t.Errorf("the forge's %s is %q, want the probe's commit %q", allowed, got, pushed)
	}
	if got := refs["refs/heads/"+denied]; got != "" {
		t.Errorf("the forge has %s at %s, which the grant's branch list does not admit", denied, got)
	}
	for ref := range forgeRefs(ctx, t, x, forgePod, otherRepo) {
		if ref != "refs/heads/main" {
			t.Errorf("%s gained %s, which no grant covers", otherRepo, ref)
		}
	}

	// ── 11. What the audit trail recorded ──────────────────────────────────
	assertAudit(t, hub, since, projectDir, denied, allowed)

	// ── 12. Nothing of the run is left in the cluster ──────────────────────
	// The long-lived ones were seen while the run lived — so their absence now
	// is a deletion, not a selector that never matched. The workspace Secret
	// lives only as long as the init container's fetch, usually less than a
	// poll, so it is not required to have been seen; the label sweep below
	// would still find it had it been left behind.
	for _, want := range []string{"pod/", "secret/cloop-lease-", "networkpolicy/cloop-egress-"} {
		seen := false
		for _, o := range objects {
			seen = seen || strings.HasPrefix(o, want)
		}
		if !seen {
			t.Errorf("no %s… object was seen while the run lived (saw %v)", want, objects)
		}
	}
	handle := handleOf(podJSON)
	if handle == "" {
		t.Fatal("the run's handle was never read from its Pod")
	}
	waitFor(t, "the run's Pod, Secrets and NetworkPolicy to be deleted", 3*time.Minute, func() (bool, string) {
		out, err := x.kubectlMay(ctx, "get", "pods,secrets,networkpolicies", "-n", workloadNS,
			"-l", "cloop.dev/handle-id="+handle, "-o", "name")
		if err != nil {
			return false, out
		}
		return strings.TrimSpace(out) == "", strings.Join(strings.Fields(out), ", ")
	})
	t.Logf("the run's %s are gone from %s", strings.Join(objects, ", "), workloadNS)
}

// ---------------------------------------------------------------------------
// steps
// ---------------------------------------------------------------------------

// buildImages builds the forge and harness images and loads them into kind.
func buildImages(ctx context.Context, t *testing.T, x tool) {
	t.Helper()
	root := repoRoot(t)
	kubectlBin, err := exec.LookPath("kubectl")
	if err != nil {
		t.Fatal(err)
	}
	cloopBin := os.Getenv(binEnv)
	if cloopBin == "" {
		cloopBin = filepath.Join(t.TempDir(), "cloop")
		goBuild(ctx, t, root, cloopBin, ".")
	}

	forgeCtx := t.TempDir()
	goBuild(ctx, t, root, filepath.Join(forgeCtx, "forge"), "./tests/kube/forge")
	copyFile(t, filepath.Join(root, "tests/kube/forge.Dockerfile"), filepath.Join(forgeCtx, "Dockerfile"))
	dockerBuild(ctx, t, x, forgeCtx, forgeImage)

	harnessCtx := t.TempDir()
	copyFile(t, cloopBin, filepath.Join(harnessCtx, "cloop"))
	copyFile(t, kubectlBin, filepath.Join(harnessCtx, "kubectl"))
	copyFile(t, filepath.Join(root, "scripts/e2e/gitproxy/claude"), filepath.Join(harnessCtx, "claude"))
	copyFile(t, filepath.Join(root, "tests/kube/harness.Dockerfile"), filepath.Join(harnessCtx, "Dockerfile"))
	dockerBuild(ctx, t, x, harnessCtx, harnessImage)

	cluster, importCmd := os.Getenv(kindEnv), os.Getenv(importEnv)
	for _, img := range []string{forgeImage, harnessImage} {
		switch {
		case cluster != "":
			x.run(ctx, nil, false, "kind", "load", "docker-image", img, "--name", cluster)
		case importCmd != "":
			tarball, err := exec.CommandContext(ctx, "docker", "save", img).Output()
			if err != nil {
				t.Fatalf("docker save %s: %v", img, err)
			}
			x.run(ctx, tarball, false, "sh", "-c", importCmd)
		default:
			continue // already on the nodes, the caller says
		}
		// The node has its own copy now; the daemon's is disk nobody needs.
		x.run(ctx, nil, true, "docker", "rmi", img)
	}
}

func goBuild(ctx context.Context, t *testing.T, root, out, pkg string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, pkg)
	cmd.Dir = root
	cmd.Env = append(toolEnv(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
}

func dockerBuild(ctx context.Context, t *testing.T, x tool, dir, tag string) {
	t.Helper()
	x.run(ctx, nil, false, "docker", "build", "--build-arg", "BASE="+alpineDigest, "-t", tag, dir)
}

// probeNetworkPolicy runs the hub's own enforcement probe and returns its
// verdict. Run before the upgrade, whose restart is what makes the hub read the
// recorded verdict.
func probeNetworkPolicy(ctx context.Context, t *testing.T, x tool, ns, fullname string) (bool, string) {
	t.Helper()
	// stdout alone: the probe's progress goes to stderr, and the report is the
	// one JSON document on stdout. The exit status is ignored because any
	// failing check — not only this one — makes it 1.
	//
	// The harness image is the probe's image: its Pods take the executor's pull
	// policy, which CI sets to Never, so the default busybox would never start.
	cmd := exec.CommandContext(ctx, "kubectl", "exec", "-n", ns, "deploy/"+fullname, "--",
		"/usr/local/bin/cloop", "hub", "doctor", "--probe-network-policy", "--executor", "kubernetes",
		"--probe-image", harnessImage, "--probe-timeout", "4m", "--json")
	cmd.Env = append(toolEnv(), "KUBECONFIG="+x.kubeconfig)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	out := stdout.String()
	var report struct {
		Findings []struct {
			Check, Severity, Message string
			Details                  map[string]any
		}
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Logf("hub doctor printed no report (%v):\n%s\n%s", err, tail(out, 20), tail(stderr.String(), 20))
	}
	for _, f := range report.Findings {
		if f.Check == "executors.network_policy_probe" {
			enforced, _ := f.Details["enforced"].(bool)
			return enforced, fmt.Sprintf("%s — %s", f.Severity, f.Message)
		}
	}
	t.Logf("the NetworkPolicy probe reported no verdict:\n%s", tail(stderr.String(), 30))
	return false, "no verdict (probe output above)"
}

// deployForge serves the forge in its own namespace as a Service on 443 and
// returns the Service's ClusterIP and the forge Pod's name.
//
// The Pod listens on 9443, a port the workloads' egress filter does not open:
// it opens the pod range on the monitors' ports only, so a forge on 8443 would
// be reachable from a workload directly and the egress check would mean
// nothing.
func deployForge(ctx context.Context, t *testing.T, x tool, leaf secretbrokertest.Leaf, pat string) (string, string) {
	t.Helper()
	crt, err := os.ReadFile(leaf.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(leaf.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"app": "cloop-e2e-forge"}
	nonRoot := map[string]any{
		"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532,
		"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
		"capabilities":   map[string]any{"drop": []string{"ALL"}},
		"seccompProfile": map[string]any{"type": "RuntimeDefault"},
	}
	x.apply(ctx,
		map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": forgeNS}},
		map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
			"metadata":   map[string]any{"name": "forge-tls", "namespace": forgeNS},
			"stringData": map[string]string{"tls.crt": string(crt), "tls.key": string(key)}},
		map[string]any{"apiVersion": "v1", "kind": "Secret",
			"metadata":   map[string]any{"name": "forge-pat", "namespace": forgeNS},
			"stringData": map[string]string{"token": pat}},
		map[string]any{"apiVersion": "apps/v1", "kind": "Deployment",
			"metadata": map[string]any{"name": "forge", "namespace": forgeNS},
			"spec": map[string]any{
				"replicas": 1,
				"selector": map[string]any{"matchLabels": labels},
				"template": map[string]any{
					"metadata": map[string]any{"labels": labels},
					"spec": map[string]any{
						"automountServiceAccountToken": false,
						"securityContext":              map[string]any{"fsGroup": 65532},
						"containers": []any{map[string]any{
							"name": "forge", "image": forgeImage, "imagePullPolicy": "Never",
							"args": []string{"--listen=:9443", "--root=/srv/git", "--home=/srv/home",
								"--repos=" + grantedRepo + "," + otherRepo, "--pat-file=/pat/token"},
							"ports":           []any{map[string]any{"containerPort": 9443, "name": "https"}},
							"securityContext": nonRoot,
							"readinessProbe": map[string]any{
								"tcpSocket": map[string]any{"port": 9443}, "periodSeconds": 2,
							},
							"volumeMounts": []any{
								map[string]any{"name": "tls", "mountPath": "/tls", "readOnly": true},
								map[string]any{"name": "pat", "mountPath": "/pat", "readOnly": true},
								map[string]any{"name": "srv", "mountPath": "/srv"},
								map[string]any{"name": "tmp", "mountPath": "/tmp"},
							},
						}},
						"volumes": []any{
							map[string]any{"name": "tls", "secret": map[string]any{"secretName": "forge-tls", "defaultMode": 0o440}},
							map[string]any{"name": "pat", "secret": map[string]any{"secretName": "forge-pat", "defaultMode": 0o440}},
							map[string]any{"name": "srv", "emptyDir": map[string]any{}},
							map[string]any{"name": "tmp", "emptyDir": map[string]any{}},
						},
					},
				},
			}},
		map[string]any{"apiVersion": "v1", "kind": "Service",
			"metadata": map[string]any{"name": "forge", "namespace": forgeNS},
			"spec": map[string]any{"selector": labels,
				"ports": []any{map[string]any{"name": "https", "port": 443, "targetPort": 9443}}}},
	)
	x.kubectl(ctx, "rollout", "status", "-n", forgeNS, "deploy/forge", "--timeout=3m")
	ip := x.out(ctx, "get", "svc", "-n", forgeNS, "forge", "-o", "jsonpath={.spec.clusterIP}")
	pod := x.out(ctx, "get", "pods", "-n", forgeNS, "-l", "app=cloop-e2e-forge",
		"--field-selector=status.phase=Running", "-o", "jsonpath={.items[0].metadata.name}")
	if ip == "" || pod == "" {
		t.Fatalf("the forge has no ClusterIP (%q) or running Pod (%q)", ip, pod)
	}
	return ip, pod
}

// targetKubeconfig makes the namespace the kubeconfig grant covers, a
// ServiceAccount that may *edit* it — so a refused write can only have been
// refused by the monitor — and returns a kubeconfig for that account as the
// hub Pod reaches the API server.
func targetKubeconfig(ctx context.Context, t *testing.T, x tool) (string, string) {
	t.Helper()
	x.apply(ctx,
		map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": targetNS}},
		map[string]any{"apiVersion": "v1", "kind": "ServiceAccount",
			"metadata": map[string]any{"name": "e2e-editor", "namespace": targetNS}},
		map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
			"metadata": map[string]any{"name": "e2e-editor", "namespace": targetNS},
			"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "edit"},
			"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": "e2e-editor", "namespace": targetNS}}},
	)
	token := x.out(ctx, "create", "token", "e2e-editor", "-n", targetNS, "--duration=2h")
	caData := x.out(ctx, "config", "view", "--raw", "--minify",
		"-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	if token == "" || caData == "" {
		t.Fatal("could not mint a token for e2e-editor or read the cluster's CA")
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: e2e
  cluster:
    server: https://kubernetes.default.svc
    certificate-authority-data: %s
users:
- name: e2e-editor
  user:
    token: %s
contexts:
- name: e2e
  context:
    cluster: e2e
    user: e2e-editor
    namespace: %s
current-context: e2e
`, caData, token, targetNS), token
}

// upgradeRelease turns the monitors on, keeping every value the release had.
func upgradeRelease(ctx context.Context, t *testing.T, x tool, release, ns, fullname string, sets []string) {
	t.Helper()
	args := []string{"upgrade", release, filepath.Join(repoRoot(t), "deploy/helm/cloop-hub"),
		"--namespace", ns, "--reuse-values", "--wait", "--timeout", "5m"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, _ := x.run(ctx, nil, false, "helm", args...)
	t.Logf("helm upgrade:\n%s", tail(out, 40))
	x.kubectl(ctx, "rollout", "status", "-n", ns, "deploy/"+fullname, "--timeout=5m")
}

// startStateHelper runs a Pod mounting the hub's state volume, which is how a
// project directory and the registry entry naming it get into a hub whose image
// has no shell. ReadWriteOnce admits it: it shares the hub's node.
func startStateHelper(ctx context.Context, t *testing.T, x tool, ns, fullname string, keep bool) string {
	t.Helper()
	name := "kube-e2e-state-helper"
	hubNode := x.out(ctx, "get", "pods", "-n", ns,
		"-l", "app.kubernetes.io/name=cloop-hub", "-o", "jsonpath={.items[0].spec.nodeName}")
	x.apply(ctx, map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"nodeName":                     hubNode,
			"automountServiceAccountToken": false,
			"restartPolicy":                "Never",
			"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532,
				"runAsGroup": 65532, "fsGroup": 65532},
			"containers": []any{map[string]any{
				"name": "helper", "image": harnessImage, "imagePullPolicy": "Never",
				"command":      []string{"sleep", "3600"},
				"volumeMounts": []any{map[string]any{"name": "state", "mountPath": "/var/lib/cloop/.cloop"}},
			}},
			"volumes": []any{map[string]any{"name": "state",
				"persistentVolumeClaim": map[string]any{"claimName": fullname + "-state"}}},
		}})
	if !keep {
		t.Cleanup(func() {
			x.run(context.Background(), nil, true, "kubectl", "delete", "pod", "-n", ns, name, "--wait=false")
		})
	}
	x.kubectl(ctx, "wait", "-n", ns, "--for=condition=Ready", "pod/"+name, "--timeout=2m")
	return name
}

// registerProject writes a checkout's worth of .git — the origin and HEAD the
// hub reads to decide the workspace — and adds the directory to the registry.
func registerProject(ctx context.Context, t *testing.T, x tool, ns, helper, dir, origin string) {
	t.Helper()
	script := fmt.Sprintf(`set -e
mkdir -p %[1]q/.git
printf '[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n\turl = %[2]s\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n' > %[1]q/.git/config
printf 'ref: refs/heads/main\n' > %[1]q/.git/HEAD
`, dir, origin)
	x.kubectlIn(ctx, []byte(script), "exec", "-i", "-n", ns, helper, "--", "sh", "-s")

	const registry = "/var/lib/cloop/.cloop/projects.json"
	current, _ := x.kubectlMay(ctx, "exec", "-n", ns, helper, "--", "cat", registry)
	var reg struct {
		Projects []map[string]any `json:"projects"`
	}
	if strings.HasPrefix(strings.TrimSpace(current), "{") {
		if err := json.Unmarshal([]byte(current), &reg); err != nil {
			t.Fatalf("the hub's registry is not JSON: %v\n%s", err, current)
		}
	}
	reg.Projects = append(reg.Projects, map[string]any{"name": filepath.Base(dir), "path": dir})
	b, _ := json.MarshalIndent(reg, "", "  ")
	x.kubectlIn(ctx, b, "exec", "-i", "-n", ns, helper, "--", "sh", "-c",
		"cat > "+registry+".tmp && mv "+registry+".tmp "+registry)
}

// seedForgeProject commits the project's state — one task, carrying the probe
// — into the granted repository on the forge. A Kubernetes run reads its
// project from the tree it fetched; nothing of the hub's copy reaches the Pod.
func seedForgeProject(ctx context.Context, t *testing.T, x tool, forgePod string, params map[string]string) {
	t.Helper()
	cloopBin := os.Getenv(binEnv)
	if cloopBin == "" {
		cloopBin = filepath.Join(t.TempDir(), "cloop")
		goBuild(ctx, t, repoRoot(t), cloopBin, ".")
	}
	work := t.TempDir()
	home := t.TempDir()
	cli := func(args ...string) {
		cmd := exec.CommandContext(ctx, cloopBin, args...)
		cmd.Dir = work
		// A clean environment: an agent's CLOOP_* and provider keys must not
		// shape a project that ships to a sandbox.
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8"}
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cloop %s: %v\n%s", args[0], err, b)
		}
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var script strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&script, "%s=%q\n", k, params[k])
	}
	script.WriteString(probeScript)
	b64 := base64.StdEncoding.EncodeToString([]byte(script.String()))

	cli("init", "Task 20385: prove the git proxy and the kube guard from a Pod")
	cli("task", "add", "Kubernetes git proxy and kube guard probe", "--no-ai", "--auto", "--desc",
		"Run the Kubernetes probe in this sandbox and report what it prints.\nE2E-SCRIPT-B64: "+b64)
	checkpoint(t, filepath.Join(work, ".cloop", "state.db"))

	tarball, err := exec.CommandContext(ctx, "tar", "-C", work, "-cf", "-", ".cloop").Output()
	if err != nil {
		t.Fatalf("tar the project state: %v", err)
	}
	seed := fmt.Sprintf(`set -e
export HOME=/srv/home GIT_CONFIG_NOSYSTEM=1
w=$(mktemp -d /tmp/seed.XXXXXX)
git clone -q /srv/git/%[1]s.git "$w"
tar -x -C "$w" -f /tmp/project.tar
cd "$w"
git add -f .cloop
git -c user.name=cloop-e2e -c user.email=e2e@example.invalid commit -qm "the project the Pod runs"
git push -q origin HEAD:refs/heads/main
cd / && rm -rf "$w" /tmp/project.tar
`, grantedRepo)
	x.kubectlIn(ctx, tarball, "exec", "-i", "-n", forgeNS, forgePod, "--", "sh", "-c",
		"cat > /tmp/project.tar && sh -c "+shellQuote(seed))
}

// checkpoint folds the write-ahead log into the database file, so the state
// committed to git is the state the CLI wrote.
func checkpoint(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatalf("checkpoint %s: %v", path, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, side := range []string{"-wal", "-shm"} {
		if err := os.Remove(path + side); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

func projectIndex(t *testing.T, hub hubClient, dir string) int {
	t.Helper()
	idx := -1
	waitFor(t, "the hub to list the project", time.Minute, func() (bool, string) {
		var resp struct {
			Projects []struct {
				Path string `json:"path"`
			} `json:"projects"`
		}
		hub.must("GET", "/api/projects", nil, &resp)
		for i, p := range resp.Projects {
			if p.Path == dir {
				idx = i
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d projects, none at %s", len(resp.Projects), dir)
	})
	return idx
}

// awaitRun waits for the dispatched run to finish and returns its live log,
// the workload Pod's object as it was while it ran, and every object the run's
// handle labelled ("pod/<name>", "secret/<name>", "networkpolicy/<name>").
func awaitRun(ctx context.Context, t *testing.T, x tool, hub hubClient, idx int, workloadNS string) ([]string, string, []string) {
	t.Helper()
	var lines []string
	podJSON, handle, initLog := "", "", ""
	objects := map[string]bool{}
	started := false
	begun := time.Now()
	waitFor(t, "the run to finish", 8*time.Minute, func() (bool, string) {
		if handle == "" {
			out, err := x.kubectlMay(ctx, "get", "pods", "-n", workloadNS,
				"-l", "cloop.dev/managed=true,cloop.dev/task-id!=probe", "-o", "json")
			var list struct {
				Items []struct {
					Metadata struct {
						Labels map[string]string `json:"labels"`
					} `json:"metadata"`
				} `json:"items"`
			}
			if err == nil && json.Unmarshal([]byte(out), &list) == nil && len(list.Items) > 0 {
				podJSON, handle = out, list.Items[0].Metadata.Labels["cloop.dev/handle-id"]
			}
		}
		if handle != "" {
			// The provisioner's output never reaches the hub's live log, and the
			// Pod is deleted with the run: keep the last of it seen.
			if out, err := x.kubectlMay(ctx, "logs", "-n", workloadNS, "-l", "cloop.dev/handle-id="+handle,
				"-c", "workspace", "--tail=80"); err == nil && strings.TrimSpace(out) != "" {
				initLog = out
			}
			out, _ := x.kubectlMay(ctx, "get", "pods,secrets,networkpolicies", "-n", workloadNS,
				"-l", "cloop.dev/handle-id="+handle, "-o", "name")
			for _, n := range strings.Fields(out) {
				// "networkpolicy.networking.k8s.io/x" names the same object as
				// "networkpolicy/x", which reads better in a failure.
				objects[strings.Replace(n, "networkpolicy.networking.k8s.io/", "networkpolicy/", 1)] = true
			}
		}
		var live struct {
			Running bool     `json:"running"`
			Lines   []string `json:"lines"`
		}
		hub.must("GET", fmt.Sprintf("/api/livelog?project_idx=%d", idx), nil, &live)
		// An entry is a chunk of the Pod's output, not a line: split them.
		lines = lines[:0]
		for _, chunk := range live.Lines {
			lines = append(lines, strings.Split(strings.TrimRight(chunk, "\n"), "\n")...)
		}
		if live.Running {
			started = true
		}
		if !live.Running && strings.Contains(strings.Join(live.Lines, "\n"), "SUMMARY kube") {
			return true, ""
		}
		if !live.Running && len(live.Lines) > 0 && (started || time.Since(begun) > 30*time.Second) {
			// Finished without a summary: the probe never ran. The log says why.
			return true, ""
		}
		return false, fmt.Sprintf("running=%v, %d lines, last: %s", live.Running, len(live.Lines), lastLine(live.Lines))
	})
	for _, l := range lines {
		t.Logf("run | %s", l)
	}
	for _, l := range strings.Split(strings.TrimRight(initLog, "\n"), "\n") {
		if l != "" {
			t.Logf("workspace init | %s", l)
		}
	}
	if !strings.Contains(strings.Join(lines, "\n"), "SUMMARY kube") {
		t.Fatalf("the run finished without the probe's SUMMARY line")
	}
	names := make([]string, 0, len(objects))
	for n := range objects {
		names = append(names, n)
	}
	sort.Strings(names)
	return lines, podJSON, names
}

// handleOf reads the run's cloop.dev/handle-id from the Pod list awaitRun
// captured.
func handleOf(podJSON string) string {
	var list struct {
		Items []struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(podJSON), &list) != nil || len(list.Items) == 0 {
		return ""
	}
	return list.Items[0].Metadata.Labels["cloop.dev/handle-id"]
}

type result struct {
	pass   bool
	detail string
}

// resultLine is one check's report, wherever the log prefixed it: an id of
// capitals and digits, then PASS or FAIL. Strict, because the task description
// is echoed into the same log.
var resultLine = regexp.MustCompile(`RESULT ([A-Z][A-Z0-9]*) (PASS|FAIL)(?: (.*))?$`)

// parseResults reads the probe's "RESULT <id> PASS|FAIL <detail>" lines.
func parseResults(lines []string) map[string]result {
	out := map[string]result{}
	for _, l := range lines {
		if m := resultLine.FindStringSubmatch(strings.TrimRight(l, " \r")); m != nil {
			out[m[1]] = result{pass: m[2] == "PASS", detail: m[3]}
		}
	}
	return out
}

// forgeRefs lists a repository's refs on the forge, read from its bare
// repository rather than through any path under test.
func forgeRefs(ctx context.Context, t *testing.T, x tool, forgePod, repo string) map[string]string {
	t.Helper()
	out := x.out(ctx, "exec", "-n", forgeNS, forgePod, "--", "git", "--git-dir=/srv/git/"+repo+".git",
		"for-each-ref", "--format=%(refname) %(objectname)")
	refs := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			refs[f[0]] = f[1]
		}
	}
	return refs
}

// assertAudit checks the trail holds the proxy's and the monitor's decisions
// for this run — every row is matched on the run's own project path, so a row
// an earlier run left within the window cannot stand in for one.
func assertAudit(t *testing.T, hub hubClient, since time.Time, projectDir, denied, allowed string) {
	t.Helper()
	type event struct {
		EventType string `json:"event_type"`
		Payload   string `json:"payload"`
	}
	read := func(entity string) []event {
		var resp struct {
			Events []event `json:"events"`
		}
		hub.must("GET", fmt.Sprintf("/api/audit?entity_type=%s&since=%s&limit=1000", entity,
			since.UTC().Format(time.RFC3339)), nil, &resp)
		return resp.Events
	}
	project := fmt.Sprintf(`"project_id":%q`, projectDir)
	has := func(events []event, typ string, needles ...string) bool {
		for _, e := range events {
			if e.EventType != typ || !strings.Contains(e.Payload, project) {
				continue
			}
			match := true
			for _, n := range needles {
				if !strings.Contains(e.Payload, n) {
					match = false
				}
			}
			if match {
				return true
			}
		}
		return false
	}
	summary := func(events []event) string {
		counts := map[string]int{}
		for _, e := range events {
			counts[e.EventType]++
		}
		b, _ := json.Marshal(counts)
		return string(b)
	}

	git := read("gitproxy")
	t.Logf("gitproxy audit rows since the run began: %s", summary(git))
	for _, c := range []struct {
		typ     string
		needles []string
		why     string
	}{
		{"gitproxy.push_denied", []string{denied}, "the push to " + denied},
		{"gitproxy.push_allowed", []string{allowed}, "the push to " + allowed},
		{"gitproxy.session_minted", nil, "a session minted for the run"},
	} {
		if !has(git, c.typ, c.needles...) {
			t.Errorf("no %s row for %s", c.typ, c.why)
		}
	}
	if !has(git, "gitproxy.rejected", otherRepo) && !has(git, "gitproxy.push_denied", otherRepo) {
		t.Errorf("no gitproxy row records the refusal of %s", otherRepo)
	}

	kube := read("kubeguard")
	t.Logf("kubeguard audit rows since the run began: %s", summary(kube))
	if !has(kube, "kubeguard.request_denied", "configmaps", `"namespace":"`+targetNS+`"`) {
		t.Error("no kubeguard.request_denied row for kubectl create configmap")
	}
	if !has(kube, "kubeguard.request_allowed", `"resource":"pods"`, `"verb":"list"`) {
		t.Error("no kubeguard.request_allowed row for kubectl get pods (executor.kubeGuard.auditAllowed is on)")
	}
}

// ---------------------------------------------------------------------------
// small things
// ---------------------------------------------------------------------------

func releaseValues(ctx context.Context, x tool, release, ns string) map[string]any {
	x.t.Helper()
	out := x.stdout(ctx, "helm", "get", "values", release, "-n", ns, "--all", "-o", "json")
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		x.t.Fatalf("helm get values %s: %v\n%s", release, err, tail(out, 10))
	}
	return v
}

func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func configMap(name, ns string, data map[string]string) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": name, "namespace": ns}, "data": data}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func randomAlnum(t *testing.T, n int) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func boolDigit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func conditional(on bool, ids ...string) []string {
	if on {
		return ids
	}
	return nil
}

func lastLine(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
