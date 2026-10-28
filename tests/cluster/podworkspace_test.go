package cluster_test

// A Kubernetes Pod's workspace session is adopted by another member (Task
// 20455).
//
// Two real `cloop ui` members serve one control plane, each running the git
// proxy behind a TCP load balancer they both advertise, and each registering a
// Kubernetes executor whose cluster is a stand-in API server in this test
// (internal/drivertest): it keeps every Pod pending, so the test plays the
// Pod's init container itself. A project whose origin is github.com/acme/tool —
// a forge behind a CONNECT proxy, honouring one PAT — is granted that PAT and
// bound to the executor, and its run is dispatched through one member. The
// driver puts the pinned git proxy session that member minted into the Pod's
// cloop-ws Secret, and the member records the session and the lease under it.
//
// That member is SIGKILLed before the init container fetches. The survivor
// adopts the run: it takes the lease over and restores the session under the
// same id and token hash. Then the test fetches as the init container would —
// presenting the token from the Secret, at the URL the init container was
// given — and the survivor serves it. Once the Pod reports the fetch finished,
// the survivor closes the session and releases the lease.
//
// Opt in with CLOOP_CLUSTER_E2E=1, as for the rest of the package; it also
// needs git and git-http-backend.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/drivertest"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

const podWorkspacePAT = "ghp_" + "clusterPodWorkspace0123456789abcdefABCD"

func TestAPodsWorkspaceSessionIsAdoptedByAnotherMember(t *testing.T) {
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this builds cloop and runs a cluster of hub processes", enableEnv)
	}
	gitBin, _ := secretbrokertest.GitTools(t)
	// Before the world, so it closes after the world's cleanup has killed
	// the hubs holding watches open on it.
	api := drivertest.NewKubeAPI(t)
	w := newWorld(t)

	// The forge, as github.com behind a CONNECT proxy, honouring the PAT for
	// acme/tool; the stand-in cluster; and the members' git proxies behind a
	// balancer they advertise.
	ca := secretbrokertest.NewCA(t)
	gh := secretbrokertest.NewGitHub()
	gh.AcceptPAT(podWorkspacePAT, "acme/tool")
	forge := secretbrokertest.NewForgeWithCert(t, "127.0.0.1:0", gh, ca.Issue(t, "github.com").TLS, "acme/tool")
	connect := secretbrokertest.NewConnectProxy(t, "127.0.0.1:0", forge.Addr)
	local := ca.Issue(t, "127.0.0.1", "localhost")
	gitLB := startTCPBalancer(t)
	w.hubEnv = []string{"HTTPS_PROXY=http://" + connect.Addr, "https_proxy=http://" + connect.Addr,
		"SSL_CERT_FILE=" + ca.CertFile}
	w.overlay = func(int) string {
		gp := freePort(t)
		gitLB.add(fmt.Sprintf("127.0.0.1:%d", gp))
		return fmt.Sprintf("executors:\n    git_proxy:\n        listen_addr: 127.0.0.1:%d\n", gp)
	}

	w.initProjects()
	// The project is a checkout whose origin is the forge's repository: the
	// hub derives the Pod's workspace from it.
	for _, args := range [][]string{{"init", "-q", "-b", "main", w.projDir},
		{"-C", w.projDir, "remote", "add", "origin", "https://github.com/acme/tool.git"}} {
		if out, err := exec.Command(gitBin, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	cfg, err := os.OpenFile(filepath.Join(w.hubDir, ".cloop", "config.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(cfg, `
executors:
    git_proxy:
        enabled: true
        advertise_url: https://127.0.0.1:%d
        cert_file: %s
        key_file: %s
    kubernetes:
        enabled: true
        id: k8s-e2e
        namespace: cloop
        image: %s
        kubeconfig_secret: e2e-kube
`, gitLB.port(), local.CertFile, local.KeyFile, drivertest.Image)
	_ = cfg.Close()

	rest := api.REST()
	kubeFile := filepath.Join(w.root, "kubeconfig")
	if err := os.WriteFile(kubeFile, []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: c
clusters:
- name: c
  cluster:
    server: %s
    certificate-authority-data: %s
contexts:
- name: c
  context:
    cluster: c
    user: u
    namespace: cloop
users:
- name: u
  user:
    token: %s
`, rest.Server, base64.StdEncoding.EncodeToString(rest.CAData), rest.BearerToken)), 0o600); err != nil {
		t.Fatal(err)
	}
	w.run(w.hubDir, "secret", "mint", "e2e-kube", "--kind", "kubeconfig", "--file", kubeFile)
	w.run(w.hubDir, "secret", "grant", "e2e-kube", "--to", "executor:k8s-e2e", "--namespaces", "cloop", "--ttl", "2h")
	w.run(w.hubDir, "secret", "mint", "e2e-pat", "--kind", "github_pat", "--value", podWorkspacePAT)
	w.run(w.hubDir, "secret", "grant", "e2e-pat", "--to", "project:"+w.projDir, "--repos", "acme/tool", "--ttl", "2h")

	for i := 0; i < 2; i++ {
		w.startHub()
	}
	w.startLoadBalancer()
	st := w.waitCluster("two live members", func(s clusterStatus) bool { return s.live() == 2 && s.Leader != "" })
	for _, h := range w.hubs {
		h.id = w.memberFor(st, h.port)
	}
	projIdx := w.projectIndex()
	w.bindProject(projIdx, "k8s-e2e")

	// The run is dispatched through a member that is not the leader, so the
	// survivor is one that adopts it at once: the leader adopts a dead
	// member's runs on an executor no agent holds.
	dispatcher, survivor := w.hubs[0], w.hubs[1]
	if dispatcher.id == st.Leader {
		dispatcher, survivor = survivor, dispatcher
	}
	if r := w.startRun(dispatcher, projIdx); r.status != 200 {
		t.Fatalf("POST /api/run on hub %d = %d: %s", dispatcher.port, r.status, r.body)
	}
	pod := api.WaitWorkspacePod(t, true)
	handle := strings.TrimPrefix(api.WaitSecret(t, "cloop-ws-"), "cloop-ws-")
	data := api.SecretData("cloop-ws-" + handle)
	user, tok := string(data["CLOOP_WORKSPACE_USER"]), string(data["CLOOP_WORKSPACE_TOKEN"])
	repo := api.InitContainerArg(pod, "--repo")
	if user == "" || tok == "" || !strings.HasPrefix(repo, fmt.Sprintf("https://127.0.0.1:%d/", gitLB.port())) {
		t.Fatalf("the Pod's workspace is user %q (token %d bytes) at %q, not a session at the proxy", user, len(tok), repo)
	}
	sum := sha256.Sum256([]byte(tok))
	tokenSum := hex.EncodeToString(sum[:])
	leaseID := ""
	w.eventually("the dispatcher to record the session and the lease under it", 30*time.Second, func() bool {
		holder, _ := w.queryControlPlane(`SELECT holder FROM proxy_sessions WHERE kind = 'git' AND session_id = ?`, user)
		got, _ := w.queryControlPlane(`SELECT token_sha256 FROM proxy_sessions WHERE kind = 'git' AND session_id = ?`, user)
		leaseID, _ = w.queryControlPlane(`SELECT lease_id FROM proxy_sessions WHERE kind = 'git' AND session_id = ?`, user)
		return holder == dispatcher.id && got == tokenSum && leaseID != ""
	})
	if holder, _ := w.queryControlPlane(`SELECT holder FROM secret_leases WHERE lease_id = ?`, leaseID); holder != dispatcher.id {
		t.Fatalf("the Pod's workspace lease %s is held by %q, want the dispatcher %s", leaseID, holder, dispatcher.id)
	}
	if run, _ := w.queryControlPlane(`SELECT run_id FROM secret_leases WHERE lease_id = ?`, leaseID); run == "" {
		t.Fatal("the Pod's workspace lease names no run")
	}
	w.eventually("the run's owner row to name the workspace lease and its session", 30*time.Second, func() bool {
		meta, _ := w.queryControlPlane(`SELECT meta FROM hub_owners WHERE kind = 'run' AND key = ?`, w.projDir)
		return strings.Contains(meta, leaseID) && strings.Contains(meta, user)
	})

	// The member that minted the session dies before the init container
	// fetches; the survivor adopts the run, its lease and its session.
	w.kill(dispatcher, syscall.SIGKILL)
	w.waitClusterVia(survivor, "the run to be adopted by the survivor", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) == survivor.id
	})
	w.eventually("the survivor to take the lease over and restore the session", 60*time.Second, func() bool {
		lh, _ := w.queryControlPlane(`SELECT holder FROM secret_leases WHERE lease_id = ?`, leaseID)
		sh, _ := w.queryControlPlane(`SELECT holder FROM proxy_sessions WHERE kind = 'git' AND session_id = ?`, user)
		return lh == survivor.id && sh == survivor.id
	})
	if got, _ := w.queryControlPlane(`SELECT token_sha256 FROM proxy_sessions WHERE kind = 'git' AND session_id = ?`,
		user); got != tokenSum {
		t.Fatalf("the restored session's token hash is %q, want the one the Pod holds", got)
	}
	if closed, _ := w.queryControlPlane(`SELECT closed_at FROM proxy_sessions WHERE kind = 'git' AND session_id = ?`,
		user); closed != "" {
		t.Fatalf("the session was closed at %s before the Pod fetched", closed)
	}

	// The init container's fetch, presenting the token the dead member minted.
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+tok))
	clone := exec.Command(gitBin, "clone", "-q", repo, filepath.Join(w.root, "fetched"))
	clone.Env = []string{"HOME=" + w.root, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0", "GIT_SSL_CAINFO=" + ca.CertFile, "LC_ALL=C",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: " + auth}
	if out, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("the init container's fetch through the survivor: %v\n%s", err, out)
	}

	// The Pod reports the fetch finished: the survivor ends what it took over.
	api.FinishInitContainer(pod, 0)
	w.eventually("the survivor to close the session once the fetch is confirmed", 60*time.Second, func() bool {
		closed, _ := w.queryControlPlane(`SELECT closed_at FROM proxy_sessions WHERE kind = 'git' AND session_id = ?`, user)
		return closed != ""
	})
	w.eventually("the survivor to release the workspace lease", 60*time.Second, func() bool {
		n, _ := w.queryControlPlane(`SELECT COUNT(*) FROM secret_leases WHERE lease_id = ?`, leaseID)
		return n == "0"
	})
	if !api.SecretDeleted("cloop-ws-" + handle) {
		t.Error("the survivor left the workspace Secret after the fetch it served")
	}
	w.eventually("the run's owner row to stop naming the ended workspace lease", 30*time.Second, func() bool {
		meta, _ := w.queryControlPlane(`SELECT meta FROM hub_owners WHERE kind = 'run' AND key = ?`, w.projDir)
		return meta != "" && !strings.Contains(meta, leaseID)
	})
}
