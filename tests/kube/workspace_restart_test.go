package kube_test

// A Kubernetes Pod's workspace session survives the hub process that minted it
// (Task 20455), on a real cluster, against the hub the Helm chart installed.
//
// A Pod's init container fetches its workspace through a pinned git proxy
// session after the dispatch returned. Until Task 20455 that session lived in
// the memory of the hub process that minted it, standing on a lease nobody
// recorded, so a hub that stopped in between — a restart, a member's death, a
// rolling upgrade — took the session with it, and the init container's fetch
// got a 401.
//
// This test holds the init container before its fetch (the harness image's
// cloop, cloop-hold.sh, waits for a file when the repository is acme/held),
// SIGKILLs the hub's process from the node — no shutdown path runs, as for an
// OOM kill — and lets the kubelet start a new one in the same Pod, on the same
// database. Once the new process has adopted the run, taken the workspace
// lease over and restored the session, it releases the init container, and
// checks that the Pod provisions through the restored session, that the run
// completes, that its outcome reaches the hub's plan, and that the session was
// closed once the fetch was confirmed.
//
// It needs a release of one replica — the process it kills is the only one —
// and a way to run a command on the hub's node: `docker exec <node>` by
// default, which is a kind node's container, or CLOOP_KUBE_E2E_NODE_EXEC.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// nodeExecEnv is a command prefix that runs a command on the node the hub runs
// on, e.g. "docker exec k3s" for k3s in docker. Unset, it is "docker exec
// <node name>", which is what a kind node is.
const nodeExecEnv = "CLOOP_KUBE_E2E_NODE_EXEC"

const heldRepo = "acme/held"

// heldProbe is the task the stand-in harness runs once the Pod provisioned:
// one RESULT line per check, as probe.sh does. WANT_HEAD is prepended.
const heldProbe = `set -u
pass=0
fail=0
res() {
	printf 'RESULT %s %s %s\n' "$1" "$2" "$3"
	if [ "$2" = PASS ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
}
BASE=$(pwd)
if head=$(git -C "$BASE" rev-parse --verify -q HEAD); then
	if [ "$head" = "$WANT_HEAD" ]; then
		res HW1 PASS "the workspace is acme/held at the forge's main, $head"
	else
		res HW1 FAIL "the workspace is at $head, not the forge's main $WANT_HEAD"
	fi
	url=$(git -C "$BASE" config --get remote.origin.url)
	case $url in
	"${CLOOP_GIT_PROXY_URL:-no-proxy-url}"/*) res HW2 PASS "the workspace was provisioned through the proxy: origin $url" ;;
	*) res HW2 FAIL "the workspace's origin is $url, not the proxy ${CLOOP_GIT_PROXY_URL:-unset}" ;;
	esac
else
	res HW1 FAIL "the working directory is not a git checkout"
fi
printf 'SUMMARY held pass=%d fail=%d\n' "$pass" "$fail"
`

func TestAPodsWorkspaceSurvivesItsHubBeingKilled(t *testing.T) {
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
	if replicas := x.out(ctx, "get", "deploy", "-n", ns, fullname, "-o", "jsonpath={.spec.replicas}"); replicas != "1" {
		t.Fatalf("the hub runs %s replicas; this test kills the only hub process and needs one", replicas)
	}

	stamp := fmt.Sprintf("%d", time.Now().Unix())
	forgeNS = "cloop-e2e-held-forge-" + stamp
	pat := "ghp_" + randomAlnum(t, 36)

	// ── The images, the forge as github.com, the release ──────────────────
	buildImages(ctx, t, x)
	ca := secretbrokertest.NewCA(t)
	forgeHost := "forge." + forgeNS + ".svc"
	leaf := ca.Issue(t, "github.com", forgeHost, forgeHost+".cluster.local")
	if !keep {
		t.Cleanup(func() {
			x.run(context.Background(), nil, true, "kubectl", "delete", "namespace", forgeNS, "--wait=false")
		})
	}
	forgeIP, forgePod := deployForge(ctx, t, x, leaf, pat, heldRepo)
	head := forgeRefs(ctx, t, x, forgePod, heldRepo)["refs/heads/main"]
	if head == "" {
		t.Fatalf("the forge's %s has no main branch", heldRepo)
	}
	x.apply(ctx, configMap("cloop-e2e-forge-ca", ns, map[string]string{"ca.crt": string(ca.CertPEM)}))
	upgradeRelease(ctx, t, x, release, ns, fullname, []string{
		"executor.gitProxy.enabled=true",
		"executor.monitorTLS.auto=true",
		"executor.kubernetes.image=" + harnessImage,
		"extraCACerts.configMap=cloop-e2e-forge-ca",
		"hostAliases[0].ip=" + forgeIP,
		"hostAliases[0].hostnames[0]=github.com",
	})

	// ── The project, its grants, its task ─────────────────────────────────
	projectDir := "/var/lib/cloop/projects/e2e-held-" + stamp
	helper := startStateHelper(ctx, t, x, ns, fullname, keep)
	registerProject(ctx, t, x, ns, helper, projectDir, "https://github.com/"+heldRepo+".git")
	hub := hubClient{t: t, base: x.portForward(ns, fullname, 8080), http: &http.Client{Timeout: time.Minute}}
	hub.token = x.out(ctx, "exec", "-n", ns, "deploy/"+fullname, "--",
		"/usr/local/bin/cloop", "hub", "token", "create", "kube-held-"+stamp, "--role", "admin",
		"--expires-in", "2h", "--quiet")
	idx := projectIndex(t, hub, projectDir)
	hub.must("POST", fmt.Sprintf("/api/init?project_idx=%d", idx), map[string]any{
		"goal": "Task 20455: a Pod's workspace survives its hub being killed", "provider": "claudecode",
	}, nil)
	var added struct {
		Task struct {
			ID int `json:"id"`
		} `json:"task"`
	}
	hub.must("POST", fmt.Sprintf("/api/tasks?project_idx=%d", idx), map[string]any{
		"title": "Check the workspace a killed hub's session provisioned",
		"description": "Run the check in this sandbox and report what it prints.\nE2E-SCRIPT-B64: " +
			base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("WANT_HEAD=%q\n", head)+heldProbe)),
	}, &added)
	taskID := added.Task.ID
	if taskID <= 0 {
		t.Fatal("the hub did not report the added task's id")
	}
	hub.must("POST", "/api/secrets", map[string]any{
		"name": "kube-held-pat-" + stamp, "kind": "github_pat", "payload": pat, "personal": false,
	}, nil)
	hub.must("POST", fmt.Sprintf("/api/projects/%d/repositories", idx), map[string]any{
		"secret": "kube-held-pat-" + stamp, "repos": []string{heldRepo}, "access": "read", "ttl_minutes": 120,
	}, nil)
	hub.must("POST", fmt.Sprintf("/api/projects/%d/executor", idx), map[string]any{"executor_id": "kubernetes"}, nil)
	hub.must("POST", "/api/secrets", map[string]any{
		"name": "kube-held-harness-" + stamp, "kind": "env",
		"payload": fmt.Sprintf(`{"ANTHROPIC_API_KEY":%q}`, "kube-held-harness-key-"+randomAlnum(t, 32)), "personal": false,
	}, nil)
	hub.must("POST", fmt.Sprintf("/api/projects/%d/harness-credential", idx), map[string]any{
		"secret": "kube-held-harness-" + stamp, "env_keys": []string{"ANTHROPIC_API_KEY"}, "ttl_minutes": 120,
	}, nil)
	before := clusterSelf(t, hub)

	// ── The run, held before its fetch ────────────────────────────────────
	since := time.Now().Add(-time.Minute)
	hub.must("POST", fmt.Sprintf("/api/run?project_idx=%d", idx), map[string]any{}, nil)
	pod, handle := awaitHeldPod(ctx, t, x, workloadNS)
	session := secretValue(ctx, t, x, workloadNS, "cloop-ws-"+handle, "CLOOP_WORKSPACE_USER")
	if session == "" {
		t.Fatalf("the Pod's workspace Secret names no session")
	}
	t.Logf("pod %s (handle %s) is held before fetching through session %s, minted by %s", pod, handle, session, before)

	// ── SIGKILL the hub; the kubelet starts a new one ─────────────────────
	hubPod, restarts := hubContainer(ctx, t, x, ns)
	killHub(ctx, t, x, ns, hubPod)
	waitFor(t, "the kubelet to start the hub again", 3*time.Minute, func() (bool, string) {
		_, now := hubContainer(ctx, t, x, ns)
		ready := x.out(ctx, "get", "pod", "-n", ns, hubPod, "-o",
			`jsonpath={.status.containerStatuses[?(@.name=="hub")].ready}`)
		return now > restarts && ready == "true", fmt.Sprintf("restarts %d, ready %s", now, ready)
	})
	hub.base = x.portForward(ns, fullname, 8080)
	var after string
	waitFor(t, "the restarted hub to answer", 2*time.Minute, func() (bool, string) {
		code, _ := hub.call("GET", "/api/cluster", nil, nil)
		if code != http.StatusOK {
			return false, fmt.Sprintf("HTTP %d", code)
		}
		after = clusterSelf(t, hub)
		return after != "" && after != before, "member " + after
	})
	t.Logf("the hub runs again as %s", after)

	// ── The new process adopts the run, takes the lease over, restores the
	//    session ───────────────────────────────────────────────────────────
	var restored string
	waitFor(t, "the restarted hub to restore the Pod's workspace session", 4*time.Minute, func() (bool, string) {
		for _, e := range gitproxyAudit(t, hub, since) {
			if e.EventType == "gitproxy.session_restored" && strings.Contains(e.Payload, session) {
				restored = e.Payload
				return true, ""
			}
		}
		return false, "no gitproxy.session_restored row for " + session
	})
	if !strings.Contains(restored, before) {
		t.Errorf("the restored row does not name the killed process %s: %s", before, restored)
	}
	if owner := clusterOwner(t, hub, "run", projectDir); owner != after {
		t.Errorf("the run's owner row names %q, want the restarted process %s", owner, after)
	}

	// ── Released: the Pod provisions through the restored session ─────────
	x.kubectl(ctx, "exec", "-n", workloadNS, pod, "-c", "workspace", "--", "touch", "/tmp/cloop-e2e-release")
	exit := ""
	waitFor(t, "the Pod's workspace provisioner to finish", 3*time.Minute, func() (bool, string) {
		out, err := x.kubectlMay(ctx, "get", "pod", "-n", workloadNS, pod, "-o",
			"jsonpath={.status.initContainerStatuses[0].state.terminated.exitCode}")
		exit = strings.TrimSpace(out)
		return err == nil && exit != "", "not terminated yet"
	})
	if exit != "0" {
		logs, _ := x.kubectlMay(ctx, "logs", "-n", workloadNS, pod, "-c", "workspace", "--tail=40")
		t.Fatalf("the workspace provisioner exited %s after the hub was killed:\n%s", exit, logs)
	}

	// ── The run completes, and its outcome reaches the hub's plan ─────────
	var lines []string
	waitFor(t, "the run to finish", 8*time.Minute, func() (bool, string) {
		var live struct {
			Running bool     `json:"running"`
			Lines   []string `json:"lines"`
		}
		hub.must("GET", fmt.Sprintf("/api/livelog?project_idx=%d", idx), nil, &live)
		lines = logLines(live.Lines)
		joined := strings.Join(lines, "\n")
		return !live.Running && strings.Contains(joined, "SUMMARY held"), fmt.Sprintf("running=%v, %d lines, last: %s",
			live.Running, len(lines), lastLine(lines))
	})
	for _, l := range lines {
		t.Logf("run | %s", l)
	}
	results := parseResults(lines)
	for _, id := range []string{"HW1", "HW2"} {
		switch r, ok := results[id]; {
		case !ok:
			t.Errorf("check %s never reported", id)
		case !r.pass:
			t.Errorf("check %s failed: %s", id, r.detail)
		default:
			t.Logf("%s PASS %s", id, r.detail)
		}
	}
	var done hubTaskState
	waitFor(t, "the hub's plan to show the task done", 2*time.Minute, func() (bool, string) {
		done = hubTask(t, hub, idx, taskID)
		return done.Status == "done", fmt.Sprintf("task %d is %q", taskID, done.Status)
	})
	if done.ExecutorKind != "kubernetes" {
		t.Errorf("task %d is attributed to executor kind %q, want kubernetes", taskID, done.ExecutorKind)
	}

	// ── The session was closed once the fetch was confirmed ───────────────
	waitFor(t, "the restored session to be closed", 2*time.Minute, func() (bool, string) {
		for _, e := range gitproxyAudit(t, hub, since) {
			if e.EventType == "gitproxy.session_closed" && strings.Contains(e.Payload, session) {
				return true, ""
			}
		}
		return false, "no gitproxy.session_closed row for " + session
	})
}

// awaitHeldPod waits for the run's Pod to be held before its fetch: its
// workspace provisioner running, its harness not started. It returns the Pod
// and its handle.
func awaitHeldPod(ctx context.Context, t *testing.T, x tool, workloadNS string) (string, string) {
	t.Helper()
	var pod, handle string
	waitFor(t, "the run's Pod to wait in its workspace provisioner", 4*time.Minute, func() (bool, string) {
		out, err := x.kubectlMay(ctx, "get", "pods", "-n", workloadNS,
			"-l", "cloop.dev/managed=true,cloop.dev/task-id!=probe", "-o", "json")
		var list struct {
			Items []struct {
				Metadata struct {
					Name   string            `json:"name"`
					Labels map[string]string `json:"labels"`
				} `json:"metadata"`
				Status struct {
					InitContainerStatuses []struct {
						State map[string]json.RawMessage `json:"state"`
					} `json:"initContainerStatuses"`
				} `json:"status"`
			} `json:"items"`
		}
		if err != nil || json.Unmarshal([]byte(out), &list) != nil {
			return false, out
		}
		for _, p := range list.Items {
			if len(p.Status.InitContainerStatuses) == 1 && p.Status.InitContainerStatuses[0].State["running"] != nil {
				pod, handle = p.Metadata.Name, p.Metadata.Labels["cloop.dev/handle-id"]
				return handle != "", ""
			}
		}
		return false, fmt.Sprintf("%d pods, none waiting in its provisioner", len(list.Items))
	})
	return pod, handle
}

// secretValue reads one key of a Secret — the test's kubeconfig may; the
// hub's executor Role may not.
func secretValue(ctx context.Context, t *testing.T, x tool, ns, name, key string) string {
	t.Helper()
	enc := x.out(ctx, "get", "secret", "-n", ns, name, "-o", "jsonpath={.data."+key+"}")
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("secret %s/%s key %s is not base64: %v", ns, name, key, err)
	}
	return string(b)
}

// hubContainer returns the hub's Pod and how many times its container has
// restarted.
func hubContainer(ctx context.Context, t *testing.T, x tool, ns string) (string, int) {
	t.Helper()
	pod := x.out(ctx, "get", "pods", "-n", ns, "-l", "app.kubernetes.io/name=cloop-hub",
		"-o", "jsonpath={.items[0].metadata.name}")
	n := x.out(ctx, "get", "pod", "-n", ns, pod, "-o",
		`jsonpath={.status.containerStatuses[?(@.name=="hub")].restartCount}`)
	restarts, _ := strconv.Atoi(n)
	return pod, restarts
}

// killHub SIGKILLs the hub container's process from the node it runs on: no
// shutdown path runs, as for an OOM kill. The kubelet then starts the
// container again in the same Pod, on the same volume and database.
func killHub(ctx context.Context, t *testing.T, x tool, ns, pod string) {
	t.Helper()
	prefix := strings.Fields(os.Getenv(nodeExecEnv))
	if len(prefix) == 0 {
		node := x.out(ctx, "get", "pod", "-n", ns, pod, "-o", "jsonpath={.spec.nodeName}")
		prefix = []string{"docker", "exec", node}
	}
	script := fmt.Sprintf(`set -eu
sb=$(crictl pods --name '^%s$' --namespace '^%s$' --state Ready -q | head -n 1)
ctr=$(crictl ps --pod "$sb" --name '^hub$' --state Running -q | head -n 1)
pid=$(crictl inspect --output go-template --template '{{.info.pid}}' "$ctr")
kill -9 "$pid"
echo "killed the hub container $ctr, pid $pid"
`, pod, ns)
	out, _ := x.run(ctx, nil, false, prefix[0], append(prefix[1:], "sh", "-c", script)...)
	t.Logf("%s", strings.TrimSpace(out))
}

// hubClusterStatus is what the hub reports of its cluster.
type hubClusterStatus struct {
	Self   string `json:"self"`
	Owners []struct {
		Kind   string `json:"kind"`
		Key    string `json:"key"`
		Member string `json:"member"`
	} `json:"owners"`
}

func clusterStatusOf(t *testing.T, hub hubClient) hubClusterStatus {
	t.Helper()
	var st hubClusterStatus
	hub.must("GET", "/api/cluster", nil, &st)
	return st
}

// clusterSelf is the member id of the hub process answering.
func clusterSelf(t *testing.T, hub hubClient) string {
	t.Helper()
	return clusterStatusOf(t, hub).Self
}

// clusterOwner is the member owning kind/key.
func clusterOwner(t *testing.T, hub hubClient, kind, key string) string {
	t.Helper()
	for _, o := range clusterStatusOf(t, hub).Owners {
		if o.Kind == kind && o.Key == key {
			return o.Member
		}
	}
	return ""
}

// auditEvent is one row of the hub's audit trail.
type auditEvent struct {
	EventType string `json:"event_type"`
	Payload   string `json:"payload"`
}

// gitproxyAudit reads the git proxy's audit rows since.
func gitproxyAudit(t *testing.T, hub hubClient, since time.Time) []auditEvent {
	t.Helper()
	var resp struct {
		Events []auditEvent `json:"events"`
	}
	hub.must("GET", fmt.Sprintf("/api/audit?entity_type=gitproxy&since=%s&limit=1000",
		since.UTC().Format(time.RFC3339)), nil, &resp)
	return resp.Events
}
