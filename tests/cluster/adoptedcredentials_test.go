package cluster_test

// An adopted run keeps its push-scan and output-redaction coverage (Task
// 20454).
//
// Two real `cloop ui` members serve one control plane, each running the git
// proxy and the Kubernetes monitor behind a TCP load balancer they all
// advertise. A device run is granted a GitHub App, a kubeconfig and an env
// secret, and dispatched through the member holding the agent's connection.
// So the workload holds a git proxy session password and a Kubernetes monitor
// token that this member minted, of which the control plane keeps only
// hashes. The workload clones through its session and waits. The member that
// dispatched it is SIGKILLed, and the survivor adopts the run when the agent
// reconnects.
//
// The workload is then released. It prints each credential it holds, and the
// cluster token its kubeconfig named before the monitor took custody of it,
// and commits and pushes each through the git proxy. The survivor never held
// any of the minted tokens. It re-derives the cluster token and the env value
// from the grants, and it confirms the two session tokens against their
// recorded hashes. Every push must be refused, naming the grant's secret and
// never the value, and nothing it streams may carry one.
//
// Opt in with CLOOP_CLUSTER_E2E=1, as for the rest of the package; it also
// needs bash, git and git-http-backend.

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

const adoptedClusterToken = "cluster-e2e-upstream-cluster-token-0123456789"

// adoptedStub is the stand-in harness. It clones through the git proxy, says
// it is ready, and waits to be released. Then, for each credential it holds,
// it prints it and pushes a commit carrying it, recording what each push came
// to. It writes the values it read to a file of the test's, so the test can
// look for them in what the hub streamed.
const adoptedStub = `#!/bin/bash
cat >/dev/null
export GIT_SSL_CAINFO="@CA@" GIT_TERMINAL_PROMPT=0
res="@RESULTS@"
leasedir=$(dirname "$KUBECONFIG")
gitpw=$(sed -n 's/^password=//p' "$leasedir"/git-proxy-credential* 2>/dev/null | head -1)
kubetok=$(sed -n 's/^ *token: *//p' "$KUBECONFIG" | head -1)
printf 'git-session %s\nkube-session %s\ncluster-token %s\nenv-value %s\n' \
  "$gitpw" "$kubetok" "@CLUSTER@" "$ACME_API_KEY" > "$res.values"
work=$(mktemp -d)
if git clone -q https://github.com/acme/tool "$work/tool" 2>>"$res.err"; then
  echo "clone ok" >> "$res"
else
  echo "clone failed" >> "$res"
fi
echo "$$ ready" >> "@LOG@"
for i in $(seq 1 3000); do
  [ -f "@RELEASE@" ] && break
  sleep 0.2
done
cd "$work/tool" || exit 1
n=0
leak() {
  n=$((n+1))
  echo "LEAK $1 $2 end"
  echo "config = $2" > "leak-$n.txt"
  git add "leak-$n.txt"
  git -c user.email=e2e@example.com -c user.name=E2E commit -qm "leak $1" 2>>"$res.err"
  if git push origin "HEAD:refs/heads/cloop/leak-$n" > "$res.push-$1" 2>&1; then
    echo "pushed $1" >> "$res"
  else
    echo "refused $1" >> "$res"
  fi
  git reset -q --hard HEAD~1
}
leak git-session "$gitpw"
leak kube-session "$kubetok"
leak cluster-token "@CLUSTER@"
leak env-value "$ACME_API_KEY"
echo "done" >> "$res"
echo "TASK_DONE"
`

// tcpBalancer spreads connections over members' proxy listeners, skipping
// one that does not answer: what the members advertise, so a workload's git
// reaches whichever is alive.
type tcpBalancer struct {
	ln       net.Listener
	mu       sync.Mutex
	backends []string
	next     atomic.Uint64
}

func startTCPBalancer(t *testing.T) *tcpBalancer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lb := &tcpBalancer{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go lb.pipe(c)
		}
	}()
	return lb
}

func (lb *tcpBalancer) port() int { return lb.ln.Addr().(*net.TCPAddr).Port }

func (lb *tcpBalancer) add(addr string) {
	lb.mu.Lock()
	lb.backends = append(lb.backends, addr)
	lb.mu.Unlock()
}

func (lb *tcpBalancer) pipe(c net.Conn) {
	defer c.Close()
	lb.mu.Lock()
	backends := append([]string(nil), lb.backends...)
	lb.mu.Unlock()
	for i := 0; i < len(backends); i++ {
		up, err := net.DialTimeout("tcp", backends[int(lb.next.Add(1))%len(backends)], 2*time.Second)
		if err != nil {
			continue
		}
		defer up.Close()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, c); halfClose(up); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, up); halfClose(c); done <- struct{}{} }()
		<-done
		<-done
		return
	}
}

func halfClose(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func TestAnAdoptedRunsCredentialsStayOutOfItsPushesAndItsOutput(t *testing.T) {
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this builds cloop and runs a cluster of hub processes", enableEnv)
	}
	for _, tool := range []string{"bash", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required for the stand-in harness", tool)
		}
	}
	secretbrokertest.GitTools(t)
	w := newWorld(t)

	// The upstreams the members' proxies front, each over TLS under a CA of
	// the test's own: GitHub's App API, a forge answering as github.com
	// behind a CONNECT proxy, and a Kubernetes API server.
	ca := secretbrokertest.NewCA(t)
	gh := secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: "acme/tool"})
	forge := secretbrokertest.NewForgeWithCert(t, "127.0.0.1:0", gh, ca.Issue(t, "github.com").TLS, "acme/tool")
	connect := secretbrokertest.NewConnectProxy(t, "127.0.0.1:0", forge.Addr)
	local := ca.Issue(t, "127.0.0.1", "localhost")
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{local.TLS}}
	api := httptest.NewUnstartedServer(gh.APIHandler())
	api.TLS = tlsCfg.Clone()
	api.StartTLS()
	t.Cleanup(api.Close)
	kubeAPI := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+adoptedClusterToken {
			http.Error(rw, "fake api server: bad credential", http.StatusUnauthorized)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(rw, `{"kind":"PodList","items":[]}`)
	}))
	kubeAPI.TLS = tlsCfg.Clone()
	kubeAPI.StartTLS()
	t.Cleanup(kubeAPI.Close)
	gitLB, kubeLB := startTCPBalancer(t), startTCPBalancer(t)
	w.hubEnv = []string{"HTTPS_PROXY=http://" + connect.Addr, "https_proxy=http://" + connect.Addr,
		"SSL_CERT_FILE=" + ca.CertFile}
	w.overlay = func(int) string {
		gp, kg := freePort(t), freePort(t)
		gitLB.add(fmt.Sprintf("127.0.0.1:%d", gp))
		kubeLB.add(fmt.Sprintf("127.0.0.1:%d", kg))
		return fmt.Sprintf("executors:\n    git_proxy:\n        listen_addr: 127.0.0.1:%d\n"+
			"    kube_guard:\n        listen_addr: 127.0.0.1:%d\n", gp, kg)
	}

	w.initProjects()
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
    kube_guard:
        enabled: true
        advertise_url: https://127.0.0.1:%d
        cert_file: %s
        key_file: %s
        ca_file: %s
`, gitLB.port(), local.CertFile, local.KeyFile, kubeLB.port(), local.CertFile, local.KeyFile, ca.CertFile)
	_ = cfg.Close()

	var app map[string]any
	if err := json.Unmarshal(secretbrokertest.AppPayload(601, 602), &app); err != nil {
		t.Fatal(err)
	}
	app["base_url"] = api.URL
	payload, _ := json.Marshal(app)
	appFile := filepath.Join(w.root, "app.json")
	if err := os.WriteFile(appFile, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	w.run(w.hubDir, "secret", "mint", "e2e-app", "--kind", "github_app", "--file", appFile)
	w.run(w.hubDir, "secret", "grant", "e2e-app", "--to", "project:"+w.projDir,
		"--repos", "acme/tool", "--permissions", "contents:write", "--ttl", "2h")
	kubeFile := filepath.Join(w.root, "kubeconfig")
	if err := os.WriteFile(kubeFile, []byte(`apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: `+kubeAPI.URL+`
    certificate-authority-data: `+base64.StdEncoding.EncodeToString(ca.CertPEM)+`
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: prod-user
    namespace: app
users:
- name: prod-user
  user:
    token: `+adoptedClusterToken+`
`), 0o600); err != nil {
		t.Fatal(err)
	}
	w.run(w.hubDir, "secret", "mint", "e2e-kube", "--kind", "kubeconfig", "--file", kubeFile)
	w.run(w.hubDir, "secret", "grant", "e2e-kube", "--to", "project:"+w.projDir, "--namespaces", "app", "--ttl", "2h")
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	apiKey := "acme-api-key-" + hex.EncodeToString(key)
	w.run(w.hubDir, "secret", "mint", "e2e-api", "--kind", "env", "--value", `{"ACME_API_KEY":"`+apiKey+`"}`)
	w.run(w.hubDir, "secret", "grant", "e2e-api", "--to", "project:"+w.projDir, "--env-keys", "ACME_API_KEY", "--ttl", "2h")

	results := filepath.Join(w.root, "results")
	stub := strings.NewReplacer("@CA@", ca.CertFile, "@RESULTS@", results, "@LOG@", filepath.Join(w.root, "claude.log"),
		"@RELEASE@", w.release, "@CLUSTER@", adoptedClusterToken).Replace(adoptedStub)
	if err := os.WriteFile(filepath.Join(w.binDir, "claude"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		w.startHub()
	}
	w.startLoadBalancer()
	st := w.waitCluster("two live members", func(s clusterStatus) bool { return s.live() == 2 && s.Leader != "" })
	for _, h := range w.hubs {
		h.id = w.memberFor(st, h.port)
	}
	agentID := w.enrollAndStartAgent()
	st = w.waitCluster("the agent's socket to be recorded", func(s clusterStatus) bool {
		return s.owner("agent", agentID) != ""
	})
	holder := w.hubByID(st.owner("agent", agentID))
	survivor := w.hubs[0]
	if survivor == holder {
		survivor = w.hubs[1]
	}
	// Every member knows the agent before the project is bound to it: the
	// load balancer may hand the bind to either.
	for _, h := range w.hubs {
		w.eventually("hub "+h.id+" to register the agent", 30*time.Second, func() bool {
			r := w.do(http.MethodGet, h.url(), "/api/executors", nil)
			var list struct {
				Executors []struct {
					ID         string `json:"id"`
					Registered bool   `json:"registered"`
				} `json:"executors"`
			}
			if r.status != http.StatusOK || json.Unmarshal([]byte(r.body), &list) != nil {
				return false
			}
			for _, e := range list.Executors {
				if e.ID == agentID && e.Registered {
					return true
				}
			}
			return false
		})
	}
	projIdx := w.projectIndex()
	w.bindProject(projIdx, agentID)
	if r := w.startRun(holder, projIdx); r.status != http.StatusOK {
		t.Fatalf("POST /api/run on hub %d = %d: %s", holder.port, r.status, r.body)
	}
	w.eventually("the workload to clone through its session and wait", 90*time.Second, func() bool {
		data, _ := os.ReadFile(filepath.Join(w.root, "claude.log"))
		return strings.Contains(string(data), "ready")
	})
	if got, _ := os.ReadFile(results); !strings.Contains(string(got), "clone ok") {
		errs, _ := os.ReadFile(results + ".err")
		t.Fatalf("the clone through the dispatcher's session failed:\n%s\n%s", got, errs)
	}

	// The member that dispatched the run, and minted its tokens, dies.
	w.kill(holder, syscall.SIGKILL)
	w.waitClusterVia(survivor, "the run to be adopted by the survivor", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) == survivor.id && s.owner("agent", agentID) == survivor.id
	})
	w.eventually("the survivor to search the run's output and pushes for its minted tokens", 30*time.Second, func() bool {
		data, _ := os.ReadFile(survivor.log)
		return strings.Contains(string(data), "searched for the tokens its dispatcher minted")
	})
	ws := w.openStream(survivor, projIdx)
	defer ws.close()
	mark := ws.mark()
	if err := os.WriteFile(w.release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w.eventually("the workload to push every credential", 120*time.Second, func() bool {
		data, _ := os.ReadFile(results)
		return strings.Contains(string(data), "done")
	})
	ws.waitFor(t, mark, "the workload's output, streamed by the survivor", func(typ, data string) bool {
		return typ == "step_output" && strings.Contains(data, "LEAK env-value")
	})

	values := map[string]string{}
	raw, _ := os.ReadFile(results + ".values")
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if name, v, ok := strings.Cut(line, " "); ok && len(v) >= 8 {
			values[name] = v
		}
	}
	if len(values) != 4 {
		t.Fatalf("the workload held %d of the 4 credentials:\n%s", len(values), raw)
	}
	for name, prefix := range map[string]string{"git-session": "cloop_git1_", "kube-session": "cloop_kube1_"} {
		if !strings.HasPrefix(values[name], prefix) {
			t.Fatalf("the %s token the dispatcher minted carries no %s prefix", name, prefix)
		}
	}
	got, _ := os.ReadFile(results)
	secretOf := map[string]string{"git-session": "e2e-app", "kube-session": "e2e-kube",
		"cluster-token": "e2e-kube", "env-value": "e2e-api"}
	refOf := map[string]int{"git-session": 1, "kube-session": 2, "cluster-token": 3, "env-value": 4}
	for name, v := range values {
		out, _ := os.ReadFile(results + ".push-" + name)
		if !strings.Contains(string(got), "refused "+name) {
			t.Errorf("the push carrying the %s was not refused:\n%s", name, out)
			continue
		}
		if !strings.Contains(string(out), "cloop git proxy refused this push") ||
			!strings.Contains(string(out), fmt.Sprintf("secret %q", secretOf[name])) || !strings.Contains(string(out), "grant ") {
			t.Errorf("the refusal of the push carrying the %s does not name its grant and secret %q:\n%s",
				name, secretOf[name], out)
		}
		if strings.Contains(string(out), v) {
			t.Errorf("the refusal of the push carrying the %s quotes the value", name)
		}
		if ref := forge.Ref(t, "acme/tool", fmt.Sprintf("refs/heads/cloop/leak-%d", refOf[name])); ref != "" {
			t.Errorf("the refused push carrying the %s updated a ref on the forge", name)
		}
	}

	// Nothing the survivor streamed carries a value; the lines that did are
	// there, scrubbed.
	ws.mu.Lock()
	var streamed strings.Builder
	for _, f := range ws.frames[mark:] {
		if f.typ == "step_output" {
			streamed.WriteString(f.data)
		}
	}
	ws.mu.Unlock()
	for name, v := range values {
		if strings.Contains(streamed.String(), v) {
			t.Errorf("the survivor streamed the %s", name)
		}
		if !strings.Contains(streamed.String(), "LEAK "+name+" [redacted] end") {
			t.Errorf("the survivor's stream has no scrubbed line for the %s", name)
		}
	}
	w.waitTaskStatus(1, "done")
}
