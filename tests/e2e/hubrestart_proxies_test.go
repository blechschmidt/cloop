package e2e_test

// A device run's git proxy and Kubernetes monitor sessions survive its hub
// restarting (Task 20383).
//
// The scene of hubrestart_test.go — a real hub, a real agent in host mode, a
// stand-in claude blocked on a FIFO — with the hub's git proxy and Kubernetes
// monitor switched on, and the run granted a GitHub App and a kubeconfig. The
// App's installation tokens come from secretbrokertest's fake GitHub, served
// over HTTPS as the App's base_url; the forge they are good for answers as
// github.com, which the hub reaches through a CONNECT proxy, trusting the
// test's CA; the kubeconfig names a fake API server that demands its own
// token. So every credential the run spends is real to the processes that
// spend it, and none of them is the hub's own.
//
// The workload clones through the proxy before the restart. The hub is then
// killed (and, in the other subtest, stopped as systemd stops it) and started
// again; the agent reconnects; the new process adopts the run, takes its lease
// over, and restores the sessions. Then the harness is released and, holding
// the very session credentials the stopped process minted, pushes a branch
// through the git proxy and reads pods through the monitor. Both must work,
// and the trail must say who restored what.

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

const restartProxiesClusterToken = "e2e-restart-cluster-token-0123456789"

// restartProxiesStub clones through the git proxy before the restart, then,
// once released, pushes and calls the cluster. It records each outcome on a
// line of @RESULTS@ for the test to read.
const restartProxiesStub = `#!/bin/bash
prompt=$(cat)
export GIT_SSL_CAINFO="@CA@" GIT_TERMINAL_PROMPT=0
res="@RESULTS@"
work=$(mktemp -d)
if git clone -q https://github.com/acme/tool "$work/tool" 2>>"$res.err"; then
  echo "clone ok" >> "$res"
else
  echo "clone failed" >> "$res"
fi
# Logged only now: the test stops the hub as soon as it sees this line.
echo "$$ $(pwd)" >> "@LOG@"
exec 3<>"@FIFO@"
if ! read -r -t 600 -u 3 line; then
  echo "stub claude: never released" >&2
  exit 1
fi
cd "$work/tool" || exit 1
n=$(date +%s)-$$
echo "after the restart $n" > after.txt
git add after.txt
git -c user.email=e2e@example.com -c user.name=E2E commit -qm "after the restart" 2>>"$res.err"
if git push -q origin "HEAD:refs/heads/cloop/after-restart-$n" 2>>"$res.err"; then
  echo "push ok cloop/after-restart-$n" >> "$res"
else
  echo "push failed" >> "$res"
fi
server=$(sed -n 's/^ *server: *//p' "$KUBECONFIG" | head -1)
token=$(sed -n 's/^ *token: *//p' "$KUBECONFIG" | head -1)
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "@CA@" -H "Authorization: Bearer $token" "$server/api/v1/namespaces/app/pods")
echo "kube $code" >> "$res"
echo "stub claude: finished after the release"
echo TASK_DONE
`

// proxyUpstreams are the fakes the hub's proxies front.
type proxyUpstreams struct {
	ca          *secretbrokertest.CA
	gh          *secretbrokertest.GitHub
	forge       *secretbrokertest.Forge
	connect     *secretbrokertest.ConnectProxy
	api         *httptest.Server
	cluster     *httptest.Server
	clusterHits atomic.Int64
	local       secretbrokertest.Leaf
}

func newProxyUpstreams(t *testing.T) *proxyUpstreams {
	t.Helper()
	u := &proxyUpstreams{ca: secretbrokertest.NewCA(t)}
	u.gh = secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: "acme/tool"})
	u.forge = secretbrokertest.NewForgeWithCert(t, "127.0.0.1:0", u.gh, u.ca.Issue(t, "github.com").TLS, "acme/tool")
	u.connect = secretbrokertest.NewConnectProxy(t, "127.0.0.1:0", u.forge.Addr)
	u.local = u.ca.Issue(t, "127.0.0.1", "localhost")
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{u.local.TLS}}

	u.api = httptest.NewUnstartedServer(u.gh.APIHandler())
	u.api.TLS = tlsCfg.Clone()
	u.api.StartTLS()
	t.Cleanup(u.api.Close)

	u.cluster = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+restartProxiesClusterToken {
			http.Error(w, "fake api server: bad credential", http.StatusUnauthorized)
			return
		}
		u.clusterHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"kind":"PodList","items":[],"path":%q}`, r.URL.Path)
	}))
	u.cluster.TLS = tlsCfg.Clone()
	u.cluster.StartTLS()
	t.Cleanup(u.cluster.Close)
	return u
}

// newRestartProxiesScene is a restart scene whose hub runs a git proxy and a
// Kubernetes monitor, with the project granted a GitHub App and a kubeconfig.
func newRestartProxiesScene(t *testing.T) (*restartScene, *proxyUpstreams, string) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is required for the stand-in harness's kubectl")
	}
	secretbrokertest.GitTools(t)
	u := newProxyUpstreams(t)
	results := filepath.Join(t.TempDir(), "results")
	gitPort, kubePort := freePort(t), freePort(t)
	executors := fmt.Sprintf(`    git_proxy:
        enabled: true
        listen_addr: 127.0.0.1:%d
        cert_file: %s
        key_file: %s
    kube_guard:
        enabled: true
        listen_addr: 127.0.0.1:%d
        cert_file: %s
        key_file: %s
        ca_file: %s
`, gitPort, u.local.CertFile, u.local.KeyFile, kubePort, u.local.CertFile, u.local.KeyFile, u.ca.CertFile)
	s := newRestartSceneWith(t, restartOptions{
		executors: executors,
		stub:      restartProxiesStub,
		vars:      map[string]string{"CA": u.ca.CertFile, "RESULTS": results},
		hubEnv: []string{
			// The forge answers as github.com through the CONNECT proxy, with
			// a certificate the test's CA signed: the hub trusts that CA and
			// nothing else. Loopback — the App API, the cluster — is never
			// proxied.
			"HTTPS_PROXY=http://" + u.connect.Addr,
			"https_proxy=http://" + u.connect.Addr,
			"SSL_CERT_FILE=" + u.ca.CertFile,
		},
	})

	var app map[string]any
	if err := json.Unmarshal(secretbrokertest.AppPayload(501, 502), &app); err != nil {
		t.Fatal(err)
	}
	app["base_url"] = u.api.URL
	payload, _ := json.Marshal(app)
	appFile := filepath.Join(s.root, "app.json")
	writeTestFile(t, appFile, string(payload))
	s.cloop(s.hubDir, "secret", "mint", "e2e-restart-app", "--kind", "github_app", "--file", appFile)
	s.cloop(s.hubDir, "secret", "grant", "e2e-restart-app", "--to", "project:"+s.proj,
		"--repos", "acme/tool", "--permissions", "contents:write", "--ttl", "2h")

	kubeconfig := `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: ` + u.cluster.URL + `
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString(u.ca.CertPEM) + `
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: prod-user
    namespace: app
users:
- name: prod-user
  user:
    token: ` + restartProxiesClusterToken + `
`
	kubeFile := filepath.Join(s.root, "kubeconfig")
	writeTestFile(t, kubeFile, kubeconfig)
	s.cloop(s.hubDir, "secret", "mint", "e2e-restart-kube", "--kind", "kubeconfig", "--file", kubeFile)
	s.cloop(s.hubDir, "secret", "grant", "e2e-restart-kube", "--to", "project:"+s.proj,
		"--namespaces", "app", "--ttl", "2h")
	return s, u, results
}

func TestE2EDeviceRunKeepsItsProxySessionsAcrossAHubRestart(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGKILL, syscall.SIGTERM} {
		sig := sig
		t.Run(sig.String(), func(t *testing.T) {
			s, u, results := newRestartProxiesScene(t)
			s.cloop(s.proj, "task", "add", "Push after the restart", "--no-ai", "--auto")
			s.startHub()
			s.startAgent()
			s.bind()

			r := s.restartMidRun(sig, s.proj, func() {
				// Before the restart the workload cloned through the session
				// the stopped process minted.
				if got := readTestFile(t, results); !strings.Contains(string(got), "clone ok") {
					t.Fatalf("the clone before the restart failed:\n%s\n%s", got, readOptional(results+".err"))
				}
			}, func() {
				idx := s.projectIdx(s.proj)
				if code, body := s.call("POST", fmt.Sprintf("/api/run?project_idx=%d", idx), nil); code != http.StatusOK {
					t.Fatalf("start the run = %d %v", code, body)
				}
			})

			// The sessions came back with the lease, restored by the new process.
			sessions := s.query(s.hubDir, `SELECT kind, session_id, holder FROM proxy_sessions WHERE lease_id = ?`, r.lease)
			if len(sessions) != 2 {
				t.Fatalf("the run's lease feeds %d recorded sessions, want its git and kube ones: %v", len(sessions), sessions)
			}
			for _, row := range sessions {
				if row[2] != r.newMember {
					t.Errorf("%s session %s is held by %q, want the process that adopted the run", row[0], row[1], row[2])
				}
				action := "gitproxy.session_restored"
				if row[0] == "kube" {
					action = "kubeguard.session_restored"
				}
				restored := s.query(s.hubDir, `SELECT payload FROM audit_events WHERE event_type = ? AND entity_id = ?`, action, row[1])
				if len(restored) != 1 || !strings.Contains(restored[0][0], r.oldMember) {
					t.Errorf("%s rows for %s = %v, want one naming %s", action, row[1], restored, r.oldMember)
				}
			}

			s.waitFor("task 1 to be done in the hub's copy", 90*time.Second, func() bool {
				return s.taskStatus(s.proj, 1) == "done"
			})
			got := string(readTestFile(t, results))
			if !strings.Contains(got, "push ok") || !strings.Contains(got, "kube 200") {
				t.Fatalf("after the restart the workload's git and kubectl did not both work:\n%s\n%s",
					got, readOptional(results+".err"))
			}
			branch := ""
			for _, line := range strings.Split(got, "\n") {
				if b, ok := strings.CutPrefix(line, "push ok "); ok {
					branch = b
				}
			}
			if branch == "" || u.forge.Ref(t, "acme/tool", "refs/heads/"+branch) == "" {
				t.Fatalf("the push %q did not reach the forge", branch)
			}
			if u.clusterHits.Load() < 1 {
				t.Fatal("the fake cluster saw no request with its own token")
			}
			// The upstream App token behind the git session was minted again by
			// the new process, at the first one's scope.
			creates := u.gh.Creates()
			var scoped []secretbroker.InstallationTokenRequest
			for _, c := range creates {
				if len(c.Permissions) == 1 && c.Permissions["metadata"] == "read" {
					continue
				}
				scoped = append(scoped, c)
			}
			if len(scoped) < 2 {
				t.Fatalf("scoped mints = %d, want the dispatcher's and the restorer's", len(scoped))
			}
			first, last := scoped[0], scoped[len(scoped)-1]
			if fmt.Sprint(first.RepositoryIDs, first.Permissions) != fmt.Sprint(last.RepositoryIDs, last.Permissions) {
				t.Errorf("re-minted at %+v, first minted at %+v", last, first)
			}

			s.assertSettled(s.proj, 1, r)
			if open := s.query(s.hubDir, `SELECT kind, session_id FROM proxy_sessions WHERE closed_at = ''`); len(open) != 0 {
				t.Errorf("sessions left open after the run: %v", open)
			}
		})
	}
}

func readOptional(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}
