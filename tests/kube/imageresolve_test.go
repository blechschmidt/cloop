package kube_test

// imageresolve_test.go: a Pod runs the digest its image's tag resolved to at the
// registry, not whatever the tag names when a node gets round to pulling it, and
// under require_signature only a signed image is admitted (Task 20457). See
// README.md, "A Pod runs the digest its tag resolved to".

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

const (
	// registryName is the in-cluster registry as image references name it:
	// the hub reaches it through a hostAlias, a node's containerd through a
	// hosts.toml naming the Service's address.
	registryName = "registry.cloop-e2e.test"
	registryHost = registryName + ":5000"
	// registryImage serves the distribution API.
	registryImage = "registry:2"
	// certsDEnv names the directory a node's containerd reads registry hosts
	// from (its CRI registry config_path): /etc/containerd/certs.d on a kind
	// cluster created with tests/kube/kind.yaml, and
	// /var/lib/rancher/k3s/agent/etc/containerd/certs.d on k3s.
	certsDEnv = "CLOOP_KUBE_E2E_NODE_CERTS_D"
	// pinRepo is the repository the pinning half pushes its two images to.
	pinRepo = "acme/pin"
	// publishIdentity is the identity that signs cloop's published images
	// (provenance.ImagesIdentityRegexp), the signer the signature half admits.
	publishIssuer   = "https://token.actions.githubusercontent.com"
	publishIdentity = `^https://github\.com/blechschmidt/cloop/\.github/workflows/publish-images\.yml@refs/(heads/main|tags/v[^/]+)$`
)

// markerProbe reports which image the harness runs: the marker its image
// carries, which only the image's own build put there.
const markerProbe = `set -u
m=$(cat /etc/cloop-e2e-marker 2>/dev/null || echo none)
if [ "$m" = "$WANT" ]; then r=PASS; else r=FAIL; fi
printf 'RESULT M1 %s marker=%s want=%s\n' "$r" "$m" "$WANT"
if [ "$r" = PASS ]; then printf 'SUMMARY kube pass=1 fail=0\n'; else printf 'SUMMARY kube pass=0 fail=1\n'; fi
`

func TestAPodRunsTheDigestItsTagResolvedTo(t *testing.T) {
	kubeconfig := os.Getenv(kubeconfigEnv)
	if kubeconfig == "" {
		t.Skipf("set %s to a throwaway cluster's kubeconfig to run this", kubeconfigEnv)
	}
	for _, bin := range []string{"kubectl", "helm", "docker"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s is not on PATH: %v", bin, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 28*time.Minute)
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

	stamp := fmt.Sprintf("%d", time.Now().Unix())
	forgeNS = "cloop-e2e-pin-forge-" + stamp
	regNS := "cloop-e2e-registry-" + stamp
	pat := "ghp_" + randomAlnum(t, 36)

	// ── The images ─────────────────────────────────────────────────────────
	buildImages(ctx, t, x)
	loadImage(ctx, t, x, registryImage)
	imageA, imageB := "cloop-kube-e2e-pin:a-"+stamp, "cloop-kube-e2e-pin:b-"+stamp
	buildMarked(ctx, t, x, imageA, "A")
	buildMarked(ctx, t, x, imageB, "B")

	// ── The forge as github.com, and the registry ─────────────────────────
	ca := secretbrokertest.NewCA(t)
	forgeHost := "forge." + forgeNS + ".svc"
	if !keep {
		t.Cleanup(func() {
			x.run(context.Background(), nil, true, "kubectl", "delete", "namespace", forgeNS, regNS, "--wait=false")
		})
	}
	forgeIP, forgePod := deployForge(ctx, t, x, ca.Issue(t, "github.com", forgeHost, forgeHost+".cluster.local"),
		pat, pinRepo)
	head := forgeRefs(ctx, t, x, forgePod, pinRepo)["refs/heads/main"]
	if head == "" {
		t.Fatalf("the forge's %s has no main branch", pinRepo)
	}
	regIP := deployRegistry(ctx, t, x, regNS, ca.Issue(t, registryName))
	configureNodes(ctx, t, x, regIP)
	reg := newRegistryClient(t, x.portForward(regNS, "registry", 5000), ca.CertPEM)

	pushTag := func(local, repoTag string) {
		t.Helper()
		pushed := strings.Replace(reg.local, "https://", "", 1) + "/" + repoTag
		x.run(ctx, nil, false, "docker", "tag", local, pushed)
		x.run(ctx, nil, false, "docker", "push", "-q", pushed)
		x.run(ctx, nil, true, "docker", "rmi", pushed)
	}
	pinTag := "e2e/harness:pin-" + stamp
	pushTag(imageA, pinTag)
	pushTag(imageB, "e2e/harness:b-"+stamp)
	digestA := reg.digest(t, "e2e/harness", "pin-"+stamp)
	digestB := reg.digest(t, "e2e/harness", "b-"+stamp)
	if digestA == digestB {
		t.Fatalf("the two images share a digest (%s); the test proves nothing", digestA)
	}
	t.Logf("registry %s at %s: %s is A (%s), B is %s", registryHost, regIP, pinTag, digestA, digestB)
	// The node pulls through hosts.toml before a run depends on it: a
	// cluster whose containerd reads no hosts directory fails here, saying so.
	nodePull(ctx, t, x, registryHost+"/e2e/harness@"+digestA)

	// ── The release: the executor's image is the tag ──────────────────────
	tagRef := registryHost + "/" + pinTag
	x.apply(ctx, configMap("cloop-e2e-pin-ca", ns, map[string]string{"ca.crt": string(ca.CertPEM)}))
	upgradeRelease(ctx, t, x, release, ns, fullname, []string{
		"executor.gitProxy.enabled=true",
		"executor.monitorTLS.auto=true",
		"executor.kubernetes.image=" + tagRef,
		// Every container start asks the registry, so a tag in the Pod spec
		// would pull whatever the tag names at that moment.
		"executor.kubernetes.imagePullPolicy=Always",
		"sandbox.imagePolicy.allowedRegistries[0]=" + registryHost,
		"sandbox.imagePolicy.requireDigest=false",
		"sandbox.imagePolicy.requireSignature=false",
		"sandbox.imagePolicy.governOperatorImages=false",
		"extraCACerts.configMap=cloop-e2e-pin-ca",
		"hostAliases[0].ip=" + forgeIP,
		"hostAliases[0].hostnames[0]=github.com",
		"hostAliases[1].ip=" + regIP,
		"hostAliases[1].hostnames[0]=" + registryName,
	})

	hub := hubClient{t: t, base: x.portForward(ns, fullname, 8080), http: &http.Client{Timeout: 2 * time.Minute}}
	hub.token = x.out(ctx, "exec", "-n", ns, "deploy/"+fullname, "--",
		"/usr/local/bin/cloop", "hub", "token", "create", "kube-pin-"+stamp, "--role", "admin",
		"--expires-in", "2h", "--quiet")
	helper := startStateHelper(ctx, t, x, ns, fullname, keep)
	secrets := pinSecrets{pat: pat, harness: "kube-pin-harness-key-" + randomAlnum(t, 32), stamp: stamp}

	// ── 1. Dispatched while no node can take it; the tag moves; it runs ───
	pin := newPinProject(ctx, t, x, hub, ns, helper, "e2e-pin-"+stamp, secrets)
	firstTask := pin.addTask(t, "Report the image this Pod runs", "A")

	nodes := strings.Fields(x.out(ctx, "get", "nodes", "-o", "jsonpath={.items[*].metadata.name}"))
	uncordon := func() {
		for _, n := range nodes {
			x.run(context.Background(), nil, true, "kubectl", "uncordon", n)
		}
	}
	t.Cleanup(uncordon)
	for _, n := range nodes {
		x.kubectl(ctx, "cordon", n)
	}
	since := time.Now().Add(-time.Minute)
	hub.must("POST", fmt.Sprintf("/api/run?project_idx=%d", pin.idx), map[string]any{}, nil)
	podName, podImage := awaitPendingPod(ctx, t, x, workloadNS)
	if want := registryHost + "/e2e/harness@" + digestA; podImage != want {
		uncordon()
		t.Fatalf("the Pod was created with %q, want the digest the tag named at dispatch, %q", podImage, want)
	}
	t.Logf("pod %s is unschedulable with image %s; repointing %s to B", podName, podImage, pinTag)
	pushTag(imageB, pinTag)
	if got := reg.digest(t, "e2e/harness", "pin-"+stamp); got != digestB {
		uncordon()
		t.Fatalf("the tag names %s after the repoint, want B's %s", got, digestB)
	}
	uncordon()

	lines, podJSON, _ := awaitRun(ctx, t, x, hub, pin.idx, workloadNS)
	if r, ok := parseResults(lines)["M1"]; !ok || !r.pass {
		t.Errorf("the Pod that was pulled after the tag moved ran %q; want image A (%+v)", r.detail, r)
	}
	for _, id := range containerImageIDs(t, podJSON) {
		if !strings.HasSuffix(id, digestA) {
			t.Errorf("a container of the Pod ran image %s, want A's digest %s", id, digestA)
		}
	}
	joined := strings.Join(lines, "\n")
	if want := "[cloop] image " + tagRef + " resolved at " + registryHost + " to " + registryHost +
		"/e2e/harness@" + digestA; !strings.Contains(joined, want) {
		t.Errorf("the run's log does not say what the tag resolved to (%q)", want)
	}
	if st := hubTask(t, hub, pin.idx, firstTask); st.Status != "done" {
		t.Errorf("task %d is %q on the hub after the run, want done", firstTask, st.Status)
	}
	dispatch := dispatchRow(t, hub, pin.idx, since, firstTask)
	if dispatch["pinned_image"] != registryHost+"/e2e/harness@"+digestA || dispatch["image_digest"] != digestA ||
		dispatch["recorded_by"] != "hub" {
		t.Errorf("task %d's task.dispatch row = %v, want the digest A it ran, recorded by the hub", firstTask, dispatch)
	}

	// The next dispatch asks the registry again, and runs what the tag names
	// now: the tag still means what a tag means, only never past dispatch.
	secondTask := pin.addTask(t, "Report the image this Pod runs, again", "B")
	hub.must("POST", fmt.Sprintf("/api/run?project_idx=%d", pin.idx), map[string]any{}, nil)
	lines, _, _ = awaitRun(ctx, t, x, hub, pin.idx, workloadNS)
	if r, ok := parseResults(lines)["M1"]; !ok || !r.pass {
		t.Errorf("the second dispatch ran %q; want image B, which the tag names now", r.detail)
	}
	if st := hubTask(t, hub, pin.idx, secondTask); st.Status != "done" {
		t.Errorf("task %d is %q, want done", secondTask, st.Status)
	}

	// ── 2. require_signature: a signed image admitted, an unsigned refused ─
	// The executor's own image, held to the project rules by
	// govern_operator_images: a project naming one in .cloop/sandbox.yaml
	// would also have to be granted egress for its git fetch, which a spec
	// without one does not get.
	signed := copyCloopImage(ctx, t, reg, "e2e/signed", "s-"+stamp)
	signedTag := registryHost + "/e2e/signed:s-" + stamp
	t.Logf("cloop's own image %s, copied with its signature as %s", signed, signedTag)
	upgradeRelease(ctx, t, x, release, ns, fullname, []string{
		"sandbox.imagePolicy.requireSignature=true",
		"sandbox.imagePolicy.cosignIdentities[0].issuer=" + publishIssuer,
		"sandbox.imagePolicy.cosignIdentities[0].subjectRegexp=" + publishIdentity,
		"sandbox.imagePolicy.governOperatorImages=true",
		"executor.kubernetes.image=" + signedTag,
	})
	hub.base = x.portForward(ns, fullname, 8080)

	since = time.Now().Add(-time.Minute)
	good := newPinProject(ctx, t, x, hub, ns, helper, "e2e-signed-"+stamp, secrets)
	good.addTask(t, "Run in the signed image", "-")
	hub.must("POST", fmt.Sprintf("/api/run?project_idx=%d", good.idx), map[string]any{}, nil)
	wantSigned := registryHost + "/e2e/signed@" + signed
	if podImage = awaitPodImage(ctx, t, x, workloadNS, wantSigned); podImage != wantSigned {
		t.Errorf("the signed image's Pod carries %q, want the digest verified, %q", podImage, wantSigned)
	}
	// Its run fails — cloop's hub image is no harness: no git, no claude —
	// which is beside the point; the image was admitted and pinned.
	lines = awaitIdleRun(ctx, t, x, hub, good.idx, workloadNS)
	if want := "[cloop] image " + signedTag + " resolved at " + registryHost + " to " + wantSigned; !strings.Contains(
		strings.Join(lines, "\n"), want) {
		t.Errorf("the signed image's run does not say what its tag resolved to (%q)", want)
	}
	if denied := imageDenials(t, hub, good.idx, since); len(denied) != 0 {
		t.Errorf("the signed image was refused: %v", denied)
	}

	upgradeRelease(ctx, t, x, release, ns, fullname, []string{"executor.kubernetes.image=" + tagRef})
	hub.base = x.portForward(ns, fullname, 8080)
	since = time.Now().Add(-time.Minute)
	bad := newPinProject(ctx, t, x, hub, ns, helper, "e2e-unsigned-"+stamp, secrets)
	bad.addTask(t, "Run in the unsigned image", "-")
	code, raw := hub.call("POST", fmt.Sprintf("/api/run?project_idx=%d", bad.idx), map[string]any{}, nil)
	t.Logf("run with the unsigned image: HTTP %d %s", code, tail(raw, 5))
	var refusal map[string]any
	waitFor(t, "the unsigned image's refusal in the audit trail", 3*time.Minute, func() (bool, string) {
		denied := imageDenials(t, hub, bad.idx, since)
		if len(denied) == 0 {
			return false, "no sandbox.image_denied row yet"
		}
		refusal = denied[0]
		return true, ""
	})
	if refusal["rule"] != "signature-required" || !strings.Contains(fmt.Sprint(refusal["reason"]), "no signatures found") {
		t.Errorf("the unsigned image was refused with %v, want signature-required naming cosign's finding", refusal)
	}
	if pods := x.out(ctx, "get", "pods", "-n", workloadNS, "-l", "cloop.dev/managed=true", "-o",
		"jsonpath={.items[*].spec.containers[*].image}"); strings.Contains(pods, "/e2e/harness") {
		t.Errorf("a Pod runs the unsigned image: %s", pods)
	}
}

// pinSecrets are the credentials every project of this test is granted.
type pinSecrets struct {
	pat, harness, stamp string
}

// pinProject is one project of this test, registered on the hub.
type pinProject struct {
	ctx    context.Context
	x      tool
	hub    hubClient
	ns     string
	helper string
	dir    string
	idx    int
}

// newPinProject registers a project whose origin is the forge's acme/pin,
// granted a read-only PAT, a harness login and the kubernetes executor.
func newPinProject(ctx context.Context, t *testing.T, x tool, hub hubClient, ns, helper, name string,
	s pinSecrets) *pinProject {
	t.Helper()
	dir := "/var/lib/cloop/projects/" + name
	registerProject(ctx, t, x, ns, helper, dir, "https://github.com/"+pinRepo+".git")
	p := &pinProject{ctx: ctx, x: x, hub: hub, ns: ns, helper: helper, dir: dir, idx: projectIndex(t, hub, dir)}
	hub.must("POST", fmt.Sprintf("/api/init?project_idx=%d", p.idx), map[string]any{
		"goal": "Task 20457: a Pod runs the digest its tag resolved to", "provider": "claudecode",
	}, nil)
	pat, harness := "kube-pin-pat-"+name, "kube-pin-harness-"+name
	hub.must("POST", "/api/secrets", map[string]any{"name": pat, "kind": "github_pat", "payload": s.pat, "personal": false}, nil)
	hub.must("POST", fmt.Sprintf("/api/projects/%d/repositories", p.idx), map[string]any{
		"secret": pat, "repos": []string{pinRepo}, "access": "read", "ttl_minutes": 120,
	}, nil)
	hub.must("POST", fmt.Sprintf("/api/projects/%d/executor", p.idx), map[string]any{"executor_id": "kubernetes"}, nil)
	hub.must("POST", "/api/secrets", map[string]any{
		"name": harness, "kind": "env", "payload": fmt.Sprintf(`{"ANTHROPIC_API_KEY":%q}`, s.harness), "personal": false,
	}, nil)
	hub.must("POST", fmt.Sprintf("/api/projects/%d/harness-credential", p.idx), map[string]any{
		"secret": harness, "env_keys": []string{"ANTHROPIC_API_KEY"}, "ttl_minutes": 120,
	}, nil)
	return p
}

// addTask adds a task whose probe reports the marker of the image it runs in,
// passing when it is want.
func (p *pinProject) addTask(t *testing.T, title, want string) int {
	t.Helper()
	var added struct {
		Task struct {
			ID int `json:"id"`
		} `json:"task"`
	}
	p.hub.must("POST", fmt.Sprintf("/api/tasks?project_idx=%d", p.idx), map[string]any{
		"title": title,
		"description": "Run the check in this sandbox and report what it prints.\nE2E-SCRIPT-B64: " +
			base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("WANT=%q\n", want)+markerProbe)),
	}, &added)
	if added.Task.ID <= 0 {
		t.Fatal("the hub did not report the added task's id")
	}
	return added.Task.ID
}

// buildMarked builds the harness image with marker in /etc/cloop-e2e-marker.
func buildMarked(ctx context.Context, t *testing.T, x tool, tag, marker string) {
	t.Helper()
	dir := harnessContext(ctx, t)
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte(marker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "Dockerfile"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("\nCOPY marker /etc/cloop-e2e-marker\n")
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	dockerBuild(ctx, t, x, dir, tag)
	t.Cleanup(func() { x.run(context.Background(), nil, true, "docker", "rmi", tag) })
}

// loadImage puts image on the cluster's nodes the way buildImages does,
// pulling it first if the daemon does not hold it.
func loadImage(ctx context.Context, t *testing.T, x tool, image string) {
	t.Helper()
	if _, err := x.run(ctx, nil, true, "docker", "image", "inspect", image); err != nil {
		x.run(ctx, nil, false, "docker", "pull", "-q", image)
	}
	cluster, importCmd := os.Getenv(kindEnv), os.Getenv(importEnv)
	switch {
	case cluster != "":
		x.run(ctx, nil, false, "kind", "load", "docker-image", image, "--name", cluster)
	case importCmd != "":
		tarball, err := exec.CommandContext(ctx, "docker", "save", image).Output()
		if err != nil {
			t.Fatalf("docker save %s: %v", image, err)
		}
		x.run(ctx, tarball, false, "sh", "-c", importCmd)
	}
}

// deployRegistry serves the distribution API over TLS in ns and returns its
// Service's address.
func deployRegistry(ctx context.Context, t *testing.T, x tool, ns string, leaf secretbrokertest.Leaf) string {
	t.Helper()
	crt, err := os.ReadFile(leaf.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(leaf.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"app": "cloop-e2e-registry"}
	x.apply(ctx,
		map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns}},
		map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
			"metadata":   map[string]any{"name": "registry-tls", "namespace": ns},
			"stringData": map[string]string{"tls.crt": string(crt), "tls.key": string(key)}},
		map[string]any{"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": "registry", "namespace": ns, "labels": labels},
			"spec": map[string]any{
				"automountServiceAccountToken": false,
				"containers": []any{map[string]any{
					"name": "registry", "image": registryImage, "imagePullPolicy": "IfNotPresent",
					"env": []any{
						map[string]any{"name": "REGISTRY_HTTP_ADDR", "value": "0.0.0.0:5000"},
						map[string]any{"name": "REGISTRY_HTTP_TLS_CERTIFICATE", "value": "/tls/tls.crt"},
						map[string]any{"name": "REGISTRY_HTTP_TLS_KEY", "value": "/tls/tls.key"},
					},
					"ports":        []any{map[string]any{"containerPort": 5000}},
					"volumeMounts": []any{map[string]any{"name": "tls", "mountPath": "/tls", "readOnly": true}},
					"readinessProbe": map[string]any{
						"tcpSocket": map[string]any{"port": 5000}, "periodSeconds": 2},
				}},
				"volumes": []any{map[string]any{"name": "tls", "secret": map[string]any{"secretName": "registry-tls"}}},
			}},
		map[string]any{"apiVersion": "v1", "kind": "Service",
			"metadata": map[string]any{"name": "registry", "namespace": ns},
			"spec": map[string]any{"selector": labels,
				"ports": []any{map[string]any{"port": 5000, "targetPort": 5000}}}},
	)
	x.kubectl(ctx, "wait", "-n", ns, "--for=condition=Ready", "pod/registry", "--timeout=3m")
	ip := x.out(ctx, "get", "svc", "-n", ns, "registry", "-o", "jsonpath={.spec.clusterIP}")
	if ip == "" {
		t.Fatal("the registry Service has no ClusterIP")
	}
	return ip
}

// configureNodes tells every node's containerd where the registry is: a
// hosts.toml for registryHost naming the Service's address. The certificate is
// not checked on that hop — the node pulls by digest, which is checked — so the
// node needs no copy of the test CA; the hub, which resolves the tag, does.
func configureNodes(ctx context.Context, t *testing.T, x tool, regIP string) {
	t.Helper()
	certsD := envOr(certsDEnv, "/etc/containerd/certs.d")
	hosts := fmt.Sprintf("server = %q\n\n[host.%q]\n  capabilities = [\"pull\", \"resolve\"]\n  skip_verify = true\n",
		"https://"+registryHost, "https://"+regIP+":5000")
	// The content travels in the command, not on stdin: a node exec prefix
	// is `docker exec <node>`, which passes no stdin without -i.
	script := fmt.Sprintf("set -e\nmkdir -p %[1]q\necho %[2]s | base64 -d > %[1]q/hosts.toml\n",
		filepath.Join(certsD, registryHost), base64.StdEncoding.EncodeToString([]byte(hosts)))
	for _, node := range strings.Fields(x.out(ctx, "get", "nodes", "-o", "jsonpath={.items[*].metadata.name}")) {
		prefix := nodeExec(node)
		x.run(ctx, nil, false, prefix[0], append(prefix[1:], "sh", "-c", script)...)
		if os.Getenv(keepEnv) == "" {
			t.Cleanup(func() {
				p := nodeExec(node)
				x.run(context.Background(), nil, true, p[0], append(p[1:], "rm", "-rf",
					filepath.Join(certsD, registryHost))...)
			})
		}
	}
}

// nodeExec is the command prefix that runs a command on node: the
// CLOOP_KUBE_E2E_NODE_EXEC prefix, or `docker exec <node>`, which is a kind node.
func nodeExec(node string) []string {
	if p := strings.Fields(os.Getenv(nodeExecEnv)); len(p) > 0 {
		return p
	}
	return []string{"docker", "exec", node}
}

// nodePull pulls ref on every node through the CRI, as the kubelet will.
func nodePull(ctx context.Context, t *testing.T, x tool, ref string) {
	t.Helper()
	for _, node := range strings.Fields(x.out(ctx, "get", "nodes", "-o", "jsonpath={.items[*].metadata.name}")) {
		p := nodeExec(node)
		if out, err := x.run(ctx, nil, true, p[0], append(p[1:], "crictl", "pull", ref)...); err != nil {
			t.Fatalf("node %s cannot pull %s through %s (%v):\n%s\nIts containerd must read registry hosts from "+
				"a config_path (kind: create the cluster with tests/kube/kind.yaml; k3s: set %s to "+
				"/var/lib/rancher/k3s/agent/etc/containerd/certs.d)", node, ref, envOr(certsDEnv, "/etc/containerd/certs.d"),
				err, out, certsDEnv)
		}
	}
}

// awaitPendingPod waits for the run's Pod to be created and left unscheduled,
// and returns its name and the harness container's image.
func awaitPendingPod(ctx context.Context, t *testing.T, x tool, workloadNS string) (string, string) {
	t.Helper()
	var name, image string
	waitFor(t, "the run's Pod to wait for a node", 3*time.Minute, func() (bool, string) {
		out, err := x.kubectlMay(ctx, "get", "pods", "-n", workloadNS,
			"-l", "cloop.dev/managed=true,cloop.dev/task-id!=probe", "-o", "json")
		if err != nil {
			return false, err.Error()
		}
		var list podList
		if json.Unmarshal([]byte(out), &list) != nil || len(list.Items) == 0 {
			return false, "no Pod yet"
		}
		p := list.Items[0]
		name, image = p.Metadata.Name, p.harnessImage()
		for _, c := range p.Status.Conditions {
			if c.Type == "PodScheduled" && c.Status == "False" {
				return true, ""
			}
		}
		return false, fmt.Sprintf("pod %s is %s", name, p.Status.Phase)
	})
	return name, image
}

// awaitPodImage waits for the run's Pod and returns the harness image it was
// created with.
func awaitPodImage(ctx context.Context, t *testing.T, x tool, workloadNS, want string) string {
	t.Helper()
	var image string
	waitFor(t, "the run's Pod", 3*time.Minute, func() (bool, string) {
		out, err := x.kubectlMay(ctx, "get", "pods", "-n", workloadNS,
			"-l", "cloop.dev/managed=true,cloop.dev/task-id!=probe", "-o", "json")
		if err != nil {
			return false, err.Error()
		}
		var list podList
		if json.Unmarshal([]byte(out), &list) != nil {
			return false, "unreadable"
		}
		for _, p := range list.Items {
			if image = p.harnessImage(); image == want {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d Pods, none with %s", len(list.Items), want)
	})
	return image
}

// podList is the part of a Pod list this file reads.
type podList struct {
	Items []podItem `json:"items"`
}

type podItem struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Name  string `json:"name"`
			Image string `json:"image"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		ContainerStatuses []struct {
			ImageID string `json:"imageID"`
		} `json:"containerStatuses"`
		InitContainerStatuses []struct {
			ImageID string `json:"imageID"`
		} `json:"initContainerStatuses"`
	} `json:"status"`
}

// harnessImage is the image the Pod's harness container was created with.
func (p podItem) harnessImage() string {
	for _, c := range p.Spec.Containers {
		if c.Name == "harness" {
			return c.Image
		}
	}
	return ""
}

// containerImageIDs reads every container's imageID out of the Pod list
// awaitRun captured — what the kubelet actually pulled.
func containerImageIDs(t *testing.T, podJSON string) []string {
	t.Helper()
	var list podList
	if err := json.Unmarshal([]byte(podJSON), &list); err != nil || len(list.Items) == 0 {
		t.Fatalf("no Pod object was captured: %v", err)
	}
	var out []string
	for _, item := range list.Items {
		for _, c := range append(item.Status.InitContainerStatuses, item.Status.ContainerStatuses...) {
			if c.ImageID != "" {
				out = append(out, c.ImageID)
			}
		}
	}
	return out
}

// trailEvent is one row of the audit trail, as /api/audit lists it.
type trailEvent struct {
	EventType string `json:"event_type"`
	EntityID  string `json:"entity_id"`
	Payload   string `json:"payload"`
}

// projectTrail is the audit trail of the project at idx — its own rows and the
// hub's about it, merged (source=all) — since since.
func projectTrail(t *testing.T, hub hubClient, idx int, since time.Time) []trailEvent {
	t.Helper()
	var resp struct {
		Events []trailEvent `json:"events"`
	}
	hub.must("GET", fmt.Sprintf("/api/audit?project_idx=%d&source=all&since=%s&limit=1000", idx,
		since.UTC().Format(time.RFC3339)), nil, &resp)
	return resp.Events
}

func payloadOf(t *testing.T, e trailEvent) map[string]any {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal([]byte(e.Payload), &p); err != nil {
		t.Fatalf("%s payload: %v", e.EventType, err)
	}
	return p
}

// dispatchRow is the task.dispatch row for task since since.
func dispatchRow(t *testing.T, hub hubClient, idx int, since time.Time, task int) map[string]any {
	t.Helper()
	for _, e := range projectTrail(t, hub, idx, since) {
		if e.EventType == "task.dispatch" && e.EntityID == fmt.Sprint(task) {
			return payloadOf(t, e)
		}
	}
	return nil
}

// imageDenials are the sandbox.image_denied rows for the project since since.
func imageDenials(t *testing.T, hub hubClient, idx int, since time.Time) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, e := range projectTrail(t, hub, idx, since) {
		if e.EventType == "sandbox.image_denied" {
			out = append(out, payloadOf(t, e))
		}
	}
	return out
}

// registryClient pushes to and reads from the in-cluster registry through a
// port-forward, verifying it by the name image references use.
type registryClient struct {
	local string
	http  *http.Client
}

func newRegistryClient(t *testing.T, forwarded string, caPEM []byte) registryClient {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the test CA is not PEM")
	}
	return registryClient{
		local: strings.Replace(forwarded, "http://", "https://", 1),
		http: &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: registryName, MinVersion: tls.VersionTLS12},
		}},
	}
}

const manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

// digest is what the registry says repo:tag names now.
func (r registryClient) digest(t *testing.T, repo, tag string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodHead, r.local+"/v2/"+repo+"/manifests/"+tag, nil)
	req.Header.Set("Accept", manifestAccept)
	resp, err := r.http.Do(req)
	if err != nil {
		t.Fatalf("HEAD %s:%s: %v", repo, tag, err)
	}
	_ = resp.Body.Close()
	d := resp.Header.Get("Docker-Content-Digest")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(d, "sha256:") {
		t.Fatalf("HEAD %s:%s: HTTP %d, digest %q", repo, tag, resp.StatusCode, d)
	}
	return d
}

// copyCloopImage copies one platform of ghcr.io/blechschmidt/cloop:edge — this
// node's — into repo as tag, together with the Sigstore bundle its publishing
// workflow signed it with, and returns its digest. cosign verifies the copy as
// it verifies the original: the signature is over the digest, and the bundle
// sits under the referrers fallback tag sha256-<hex> beside it.
//
// By hand, because neither `cosign copy` (v2 or v3) carries a v3 bundle across;
// cosign's own help points at `oras copy -r`. Nothing is published anywhere:
// the image and its signature come from ghcr.io as they are.
func copyCloopImage(ctx context.Context, t *testing.T, dst registryClient, repo, tag string) string {
	t.Helper()
	src := &ghcr{t: t, repo: "blechschmidt/cloop", http: &http.Client{Timeout: 2 * time.Minute}}
	index, _ := src.manifest(ctx, "edge")
	var idx struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(index, &idx); err != nil {
		t.Fatalf("ghcr.io/blechschmidt/cloop:edge is not an index: %v", err)
	}
	platform := ""
	for _, m := range idx.Manifests {
		if m.Platform.OS == "linux" && m.Platform.Architecture == runtime.GOARCH {
			platform = m.Digest
		}
	}
	if platform == "" {
		t.Fatalf("ghcr.io/blechschmidt/cloop:edge has no linux/%s image", runtime.GOARCH)
	}
	copyManifest(ctx, t, src, dst, repo, platform, tag)
	fallback := "sha256-" + strings.TrimPrefix(platform, "sha256:")
	copyManifest(ctx, t, src, dst, repo, fallback, fallback)
	return platform
}

// copyManifest copies ref — and every manifest and blob it names — from src to
// dst's repo, tagging it tag.
func copyManifest(ctx context.Context, t *testing.T, src *ghcr, dst registryClient, repo, ref, tag string) {
	t.Helper()
	body, mediaType := src.manifest(ctx, ref)
	var m struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
		Config *struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("manifest %s: %v", ref, err)
	}
	for _, c := range m.Manifests {
		copyManifest(ctx, t, src, dst, repo, c.Digest, "")
	}
	blobs := make([]string, 0, len(m.Layers)+1)
	if m.Config != nil {
		blobs = append(blobs, m.Config.Digest)
	}
	for _, l := range m.Layers {
		blobs = append(blobs, l.Digest)
	}
	for _, b := range blobs {
		dst.putBlob(t, repo, b, src.blob(ctx, b))
	}
	sum := sha256.Sum256(body)
	for _, name := range []string{"sha256:" + hex.EncodeToString(sum[:]), tag} {
		if name == "" {
			continue
		}
		req, _ := http.NewRequest(http.MethodPut, dst.local+"/v2/"+repo+"/manifests/"+name, bytes.NewReader(body))
		req.Header.Set("Content-Type", mediaType)
		resp, err := dst.http.Do(req)
		if err != nil {
			t.Fatalf("PUT manifest %s: %v", name, err)
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("PUT manifest %s: HTTP %d %s", name, resp.StatusCode, msg)
		}
	}
}

// putBlob uploads one blob, monolithically, unless the registry holds it.
func (r registryClient) putBlob(t *testing.T, repo, digest string, body []byte) {
	t.Helper()
	if resp, err := r.http.Head(r.local + "/v2/" + repo + "/blobs/" + digest); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return
		}
	}
	resp, err := r.http.Post(r.local+"/v2/"+repo+"/blobs/uploads/", "application/octet-stream", nil)
	if err != nil {
		t.Fatalf("start upload of %s: %v", digest, err)
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusAccepted || loc == "" {
		t.Fatalf("start upload of %s: HTTP %d", digest, resp.StatusCode)
	}
	if strings.HasPrefix(loc, "/") {
		loc = r.local + loc
	} else if i := strings.Index(loc, "/v2/"); i >= 0 {
		// The registry names itself by the name the Pod knows it by, which
		// is not where the port-forward is.
		loc = r.local + loc[i:]
	}
	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	req, _ := http.NewRequest(http.MethodPut, loc+sep+"digest="+digest, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err = r.http.Do(req)
	if err != nil {
		t.Fatalf("upload %s: %v", digest, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload %s: HTTP %d", digest, resp.StatusCode)
	}
}

// ghcr reads one repository of ghcr.io anonymously.
type ghcr struct {
	t     *testing.T
	repo  string
	http  *http.Client
	token string
}

func (g *ghcr) get(ctx context.Context, path, accept string) ([]byte, string) {
	g.t.Helper()
	if g.token == "" {
		resp, err := g.http.Get("https://ghcr.io/token?scope=repository:" + g.repo + ":pull")
		if err != nil {
			g.t.Fatalf("ghcr.io token: %v", err)
		}
		var tok struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&tok)
		_ = resp.Body.Close()
		if tok.Token == "" {
			g.t.Fatal("ghcr.io issued no anonymous token")
		}
		g.token = tok.Token
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ghcr.io/v2/"+g.repo+path, nil)
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", accept)
	resp, err := g.http.Do(req)
	if err != nil {
		g.t.Fatalf("GET ghcr.io %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		g.t.Fatalf("GET ghcr.io %s: HTTP %d %v", path, resp.StatusCode, err)
	}
	return body, resp.Header.Get("Content-Type")
}

func (g *ghcr) manifest(ctx context.Context, ref string) ([]byte, string) {
	return g.get(ctx, "/manifests/"+ref, manifestAccept)
}

func (g *ghcr) blob(ctx context.Context, digest string) []byte {
	b, _ := g.get(ctx, "/blobs/"+digest, "*/*")
	return b
}
