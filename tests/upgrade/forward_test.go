package upgrade_test

// The forward rehearsal: a cluster of release members serving a project, an
// agent and a run, joined by a member of the build under test, which then
// replaces them one at a time.

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/version"
)

// clusterToken is the credential the fake Kubernetes API server demands.
const clusterToken = "upgrade-rehearsal-cluster-token-0123456789"

// rehearsalStub stands in for Claude Code on the device. The first time it
// runs it clones through the git proxy, logs that it started — the test
// upgrades the cluster as soon as it sees that line — and blocks on the FIFO
// until the test releases it; then it pushes through the git proxy and lists
// pods through the Kubernetes monitor, with the session credentials the
// release member minted and the build under test restored, and records each
// outcome for the test. Any later task finishes at once.
const rehearsalStub = `#!/bin/bash
prompt=$(cat)
export GIT_SSL_CAINFO="@CA@" GIT_TERMINAL_PROMPT=0
res="@RESULTS@"
if [ -e "@BLOCKED@" ]; then
  echo "$$ quick" >> "@LOG@"
  echo "stub claude: nothing to wait for"
  echo TASK_DONE
  exit 0
fi
: > "@BLOCKED@"
work=$(mktemp -d)
if git clone -q https://github.com/acme/tool "$work/tool" 2>>"$res.err"; then
  echo "clone ok" >> "$res"
else
  echo "clone failed" >> "$res"
fi
echo "$$ $(pwd)" >> "@LOG@"
exec 3<>"@FIFO@"
if ! read -r -t 900 -u 3 line; then
  echo "stub claude: never released" >&2
  exit 1
fi
cd "$work/tool" || exit 1
n=$(date +%s)-$$
echo "after the upgrade $n" > after.txt
git add after.txt
git -c user.email=rehearsal@example.com -c user.name=Rehearsal commit -qm "after the upgrade" 2>>"$res.err"
if git push -q origin "HEAD:refs/heads/cloop/after-upgrade-$n" 2>>"$res.err"; then
  echo "push ok cloop/after-upgrade-$n" >> "$res"
else
  echo "push failed" >> "$res"
fi
server=$(sed -n 's/^ *server: *//p' "$KUBECONFIG" | head -1)
token=$(sed -n 's/^ *token: *//p' "$KUBECONFIG" | head -1)
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "@CA@" -H "Authorization: Bearer $token" "$server/api/v1/namespaces/app/pods")
echo "kube $code" >> "$res"
echo "stub claude: finished after the upgrade"
echo TASK_DONE
`

// scene is what a forward rehearsal runs against, besides the world.
type scene struct {
	*world

	ca          *secretbrokertest.CA
	gh          *secretbrokertest.GitHub
	forge       *secretbrokertest.Forge
	connect     *secretbrokertest.ConnectProxy
	apiSrv      *httptest.Server
	cluster     *httptest.Server
	clusterHits atomic.Int64
	local       secretbrokertest.Leaf
	gitLB       *tcpLB
	kubeLB      *tcpLB

	fifo, stubLog, results, blocked string
	checkpoints                     string

	projIdx, proj2Idx int
	executorID        string
	operator          *http.Client // the operator's browser, signed in through a release member
}

// newScene starts the fakes, writes the hub's configuration and creates the
// project with the release binary.
func newScene(t *testing.T) *scene {
	t.Helper()
	w := newWorld(t)
	secretbrokertest.GitTools(t)
	s := &scene{world: w, ca: secretbrokertest.NewCA(t)}
	s.fifo = filepath.Join(w.root, "release.fifo")
	s.stubLog = filepath.Join(w.root, "claude.log")
	s.results = filepath.Join(w.root, "results")
	s.blocked = filepath.Join(w.root, "blocked")
	s.checkpoints = filepath.Join(w.root, "audit-checkpoints.jsonl")
	if err := syscall.Mkfifo(s.fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	// The upstreams the hub's proxies front: GitHub's App API, a forge
	// answering as github.com through a CONNECT proxy, and a Kubernetes API
	// server that demands its own token — every one over TLS under a CA of
	// the test's own, which the hub trusts and nothing else.
	s.gh = secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: "acme/tool"})
	s.forge = secretbrokertest.NewForgeWithCert(t, "127.0.0.1:0", s.gh, s.ca.Issue(t, "github.com").TLS, "acme/tool")
	s.connect = secretbrokertest.NewConnectProxy(t, "127.0.0.1:0", s.forge.Addr)
	s.local = s.ca.Issue(t, "127.0.0.1", "localhost")
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{s.local.TLS}}
	s.apiSrv = httptest.NewUnstartedServer(s.gh.APIHandler())
	s.apiSrv.TLS = tlsCfg.Clone()
	s.apiSrv.StartTLS()
	t.Cleanup(s.apiSrv.Close)
	s.cluster = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+clusterToken {
			http.Error(rw, "fake api server: bad credential", http.StatusUnauthorized)
			return
		}
		s.clusterHits.Add(1)
		rw.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(rw, `{"kind":"PodList","items":[],"path":%q}`, r.URL.Path)
	}))
	s.cluster.TLS = tlsCfg.Clone()
	s.cluster.StartTLS()
	t.Cleanup(s.cluster.Close)
	s.gitLB, s.kubeLB = startTCPLB(t), startTCPLB(t)
	w.idp = ssohubtest.NewIdP(t)
	w.lb = startHTTPLB(t)
	t.Cleanup(w.lb.close)

	// The members reach the forge as github.com through the CONNECT proxy,
	// trusting the test's CA alone. Loopback — the identity provider, the App
	// API, the cluster — is never proxied.
	w.hubEnv = []string{
		"HTTPS_PROXY=http://" + s.connect.Addr,
		"https_proxy=http://" + s.connect.Addr,
		"SSL_CERT_FILE=" + s.ca.CertFile,
	}

	// ── what the release builds ────────────────────────────────────────────
	w.cli(buildRelease, w.hubDir, "init", "--provider", "mock", "--skip-clarify", "the hub's control plane")
	w.cli(buildRelease, w.proj, "init", "--provider", "claudecode", "--skip-clarify", "Survive a rolling upgrade")
	w.cli(buildRelease, w.proj, "task", "add", "Push after the upgrade", "--no-ai", "--auto")
	w.cli(buildRelease, w.proj, "task", "add", "Written by the release and finished", "--no-ai", "--auto")
	w.cli(buildRelease, w.proj, "task", "add", "Written by the release and skipped", "--no-ai", "--auto")
	w.cli(buildRelease, w.proj, "task", "done", "2")
	w.cli(buildRelease, w.proj, "task", "skip", "3")
	// A second project, for a run a release member dispatches and settles
	// on the migrated database while the upgrade is under way.
	w.cli(buildRelease, w.proj2, "init", "--provider", "claudecode", "--skip-clarify", "Run mid-upgrade")
	w.cli(buildRelease, w.proj2, "task", "add", "Finish on a release member mid-upgrade", "--no-ai", "--auto")

	appendFile(t, filepath.Join(w.hubDir, ".cloop", "config.yaml"), fmt.Sprintf(`
executors:
    allow_host_process: false
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
ui:
    oidc:
        enabled: true
        issuer: %s
        client_id: %s
        redirect_url: %s/auth/callback
        admin_emails: [%s]
        default_role: none
        role_mappings:
            - claim: group
              value: %s
              role: operator
audit:
    checkpoints:
        interval: 1m
        file: %s
`, s.gitLB.port(), s.local.CertFile, s.local.KeyFile,
		s.kubeLB.port(), s.local.CertFile, s.local.KeyFile, s.ca.CertFile,
		w.idp.URL(), ssohubtest.ClientID, w.lb.url(), adminEmail, operatorGroup, s.checkpoints))

	// The project's credentials, minted and granted by the release: the
	// Claude credential a device run is refused without, a GitHub App for
	// one repository and a kubeconfig for one namespace.
	claude := "sk-" + "ant-oat01-" + strings.Repeat("rehearsal", 4) + "Qx7_Lm2-Pz9"
	w.cli(buildRelease, w.hubDir, "secret", "mint", "rehearsal-claude", "--kind", "env",
		"--value", `{"CLAUDE_CODE_OAUTH_TOKEN":"`+claude+`"}`)
	for _, proj := range []string{w.proj, w.proj2} {
		w.cli(buildRelease, w.hubDir, "secret", "grant", "rehearsal-claude", "--to", "project:"+proj,
			"--env-keys", "CLAUDE_CODE_OAUTH_TOKEN", "--ttl", "2h")
	}
	var app map[string]any
	if err := json.Unmarshal(secretbrokertest.AppPayload(501, 502), &app); err != nil {
		t.Fatal(err)
	}
	app["base_url"] = s.apiSrv.URL
	payload, _ := json.Marshal(app)
	appFile := filepath.Join(w.root, "app.json")
	writeFile(t, appFile, string(payload), 0o600)
	w.cli(buildRelease, w.hubDir, "secret", "mint", "rehearsal-app", "--kind", "github_app", "--file", appFile)
	w.cli(buildRelease, w.hubDir, "secret", "grant", "rehearsal-app", "--to", "project:"+w.proj,
		"--repos", "acme/tool", "--permissions", "contents:write", "--ttl", "2h")
	kubeFile := filepath.Join(w.root, "kubeconfig")
	writeFile(t, kubeFile, `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: `+s.cluster.URL+`
    certificate-authority-data: `+base64.StdEncoding.EncodeToString(s.ca.CertPEM)+`
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: prod-user
    namespace: app
users:
- name: prod-user
  user:
    token: `+clusterToken+`
`, 0o600)
	w.cli(buildRelease, w.hubDir, "secret", "mint", "rehearsal-kube", "--kind", "kubeconfig", "--file", kubeFile)
	w.cli(buildRelease, w.hubDir, "secret", "grant", "rehearsal-kube", "--to", "project:"+w.proj,
		"--namespaces", "app", "--ttl", "2h")

	// The device: the stand-in harness, and the release's cloop as `cloop`,
	// which the agent runs a task with.
	stub := strings.NewReplacer("@CA@", s.ca.CertFile, "@RESULTS@", s.results, "@BLOCKED@", s.blocked,
		"@LOG@", s.stubLog, "@FIFO@", s.fifo).Replace(rehearsalStub)
	writeFile(t, filepath.Join(w.deviceBin, "claude"), stub, 0o755)
	if err := os.Symlink(w.rel.bin, filepath.Join(w.deviceBin, "cloop")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.releaseHarness(false) })
	return s
}

// overlay is a member's instance configuration: where its git proxy and
// Kubernetes monitor listen, which it also adds to the load balancers.
func (s *scene) overlay(port int) string {
	gp, kg := freePort(s.t), freePort(s.t)
	s.gitLB.add(fmt.Sprintf("127.0.0.1:%d", gp))
	s.kubeLB.add(fmt.Sprintf("127.0.0.1:%d", kg))
	return fmt.Sprintf("executors:\n    git_proxy:\n        listen_addr: 127.0.0.1:%d\n"+
		"    kube_guard:\n        listen_addr: 127.0.0.1:%d\n", gp, kg)
}

// join starts a member of build and puts it behind the load balancer.
func (s *scene) join(build string) *member {
	s.t.Helper()
	m := s.startMember(build, s.overlay)
	s.lb.add(m.url())
	return m
}

// startAgent enrolls the device through the load balancer and runs the
// release's agent in host mode, its work root out of the hub's sight so the
// run is carried out as a seed.
func (s *scene) startAgent() {
	s.t.Helper()
	bundle := filepath.Join(s.root, "enroll.bundle")
	server := strings.Replace(s.lb.url(), "http://", "ws://", 1) + "/api/executors/connect"
	s.cli(buildRelease, s.hubDir, "executor", "enroll", "--name", "edge-rehearsal", "--server", server,
		"--bundle-file", bundle)
	agentHome := filepath.Join(s.root, "device-home")
	work := filepath.Join(s.root, "device")
	for _, d := range []string{agentHome, work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			s.t.Fatal(err)
		}
	}
	s.agent = s.spawn("release-agent", s.root, s.baseEnv(s.deviceBin, agentHome), s.rel.bin,
		"executor", "agent", "--token-file", bundle,
		"--credential", filepath.Join(agentHome, "agent.json"), "--workdir-root", work)
	s.eventually("the agent to enroll", 60*time.Second, func() bool {
		for _, line := range strings.Split(readFile(s.agent.log), "\n") {
			if i := strings.Index(line, "enrolled as "); i >= 0 {
				rest := line[i+len("enrolled as "):]
				if j := strings.IndexAny(rest, "; "); j > 0 {
					s.executorID = rest[:j]
					return true
				}
			}
		}
		return false
	})
}

// executor is the device's row in a member's /api/executors.
type executor struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Registered bool   `json:"registered"`
	Inventory  *struct {
		AgentVersion  string `json:"agent_version"`
		BuildSequence int    `json:"build_sequence"`
		Live          bool   `json:"live"`
	} `json:"inventory"`
	VersionSkew *struct {
		Skew           string `json:"skew"`
		Material       bool   `json:"material"`
		HubVersion     string `json:"hub_version"`
		DeviceProtocol int    `json:"device_protocol"`
		HubProtocol    int    `json:"hub_protocol"`
		Note           string `json:"note"`
	} `json:"version_skew"`
	UpgradeTarget string `json:"upgrade_target"`
	UpgradeLabel  string `json:"upgrade_label"`
	UpgradeNote   string `json:"upgrade_note"`
	Health        string `json:"health"`
	Blocked       bool   `json:"blocked"`
	BlockedReason string `json:"blocked_reason"`
}

// device reads the device's row from m.
func (s *scene) device(m *member) (executor, bool) {
	r := s.api(m.url(), http.MethodGet, "/api/executors", nil)
	if r.status != http.StatusOK {
		return executor{}, false
	}
	var list struct {
		Executors []executor `json:"executors"`
	}
	if err := json.Unmarshal(r.body, &list); err != nil {
		s.t.Fatalf("decode %s's executor list: %v", m, err)
	}
	for _, e := range list.Executors {
		if e.ID == s.executorID {
			return e, true
		}
	}
	return executor{}, false
}

// projectIndex is a project's index in the members' project list.
func (s *scene) projectIndex(dir string) int {
	s.t.Helper()
	r := s.api(s.lb.url(), http.MethodGet, "/api/projects", nil)
	var out struct {
		Projects []struct {
			Path string `json:"path"`
		} `json:"projects"`
	}
	r.decode(s.t, &out)
	for i, p := range out.Projects {
		if p.Path == dir {
			return i
		}
	}
	s.t.Fatalf("project %s is not listed: %s", dir, r)
	return -1
}

// stubStarts counts the harness's invocations; blockedStarts the ones that
// waited on the FIFO.
func (s *scene) stubStarts() (all, blocked int) {
	for _, line := range strings.Split(readFile(s.stubLog), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			all++
			if f[1] != "quick" {
				blocked++
			}
		}
	}
	return all, blocked
}

// releaseHarness lets the blocked harness finish. With wait, it fails the
// test if none is blocked within the deadline.
func (s *scene) releaseHarness(wait bool) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		f, err := os.OpenFile(s.fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_, _ = f.Write([]byte("go\n"))
			_ = f.Close()
			return
		}
		if !wait || time.Now().After(deadline) {
			if wait {
				s.t.Fatalf("no harness was waiting to be released: %v", err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// runOwner returns the member holding the run claim on the project, and the
// claim's meta.
func (s *scene) runOwner() (string, map[string]any) { return s.runOwnerOf(s.proj) }

// runOwnerOf is runOwner for the project in dir.
func (s *scene) runOwnerOf(dir string) (string, map[string]any) {
	rows, err := s.tryQuery(s.hubDir, `SELECT instance_id, meta FROM hub_owners WHERE kind = 'run' AND key = ?`, dir)
	if err != nil || len(rows) == 0 {
		return "", nil
	}
	var meta map[string]any
	_ = json.Unmarshal([]byte(rows[0][1]), &meta)
	return rows[0][0], meta
}

// leaseHolder is the holder of a lease's durable record, "" when it has none.
func (s *scene) leaseHolder(lease string) string {
	rows, err := s.tryQuery(s.hubDir, `SELECT holder FROM secret_leases WHERE lease_id = ?`, lease)
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0][0]
}

// proxySessions lists the lease's git proxy and Kubernetes monitor sessions
// as (kind, session id, holder, closed_at).
func (s *scene) proxySessions(lease string) [][]string {
	rows, _ := s.tryQuery(s.hubDir, `SELECT kind, session_id, holder, closed_at FROM proxy_sessions WHERE lease_id = ? ORDER BY kind`, lease)
	return rows
}

func (s *scene) taskStatus(id int) string { return s.taskStatusIn(s.proj, id) }

func (s *scene) taskStatusIn(dir string, id int) string {
	rows, err := s.tryQuery(dir, `SELECT status FROM plan_tasks WHERE id = ?`, id)
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0][0]
}

func (s *scene) projectStatus() string { return s.projectStatusIn(s.proj) }

func (s *scene) projectStatusIn(dir string) string {
	rows, err := s.tryQuery(dir, `SELECT value FROM metadata WHERE key = 'status'`)
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0][0]
}

// auditRows returns the control plane's audit rows of one type for one lease
// as (row id, payload).
func (s *scene) auditRows(eventType, lease string) []auditRow {
	var out []auditRow
	for _, r := range s.query(s.hubDir, `SELECT id, payload FROM audit_events WHERE event_type = ? ORDER BY id`, eventType) {
		var p map[string]any
		_ = json.Unmarshal([]byte(r[1]), &p)
		if lease == "" || p["lease_id"] == lease {
			id, _ := strconv.Atoi(r[0])
			out = append(out, auditRow{id: id, payload: p})
		}
	}
	return out
}

type auditRow struct {
	id      int
	payload map[string]any
}

// ── the rehearsal ────────────────────────────────────────────────────────────

func TestRollingUpgradeFromTheLatestRelease(t *testing.T) {
	s := newScene(t)
	started := time.Now()

	// ── 1. Two release members, one cluster ───────────────────────────────
	a, b := s.join(buildRelease), s.join(buildRelease)
	st := s.waitCluster(s.lb.url(), "two live release members and a leader", func(c clusterStatus) bool {
		return c.live() == 2 && c.Leader != ""
	})
	// And in each member's own view, which the load balancer's answer — one
	// member's — does not show. A sign-in's callback reaches whichever member
	// the balancer picks, and one that has not yet seen the member that began
	// the login cannot forward it there: it answers 400, as for a login whose
	// member is gone.
	for _, m := range []*member{a, b} {
		s.waitCluster(m.url(), m.String()+" to see both release members", func(c clusterStatus) bool {
			return c.live() == 2 && c.Leader != ""
		})
	}
	s.identify(st, a, b)
	t.Logf("release members %s (%s) and %s (%s), leader %s", a, short(a.id), b, short(b.id), short(st.Leader))

	// ── 2. A signed-in person, an enrolled device, a bound project ────────
	s.operator = s.signIn(s.lb.url(), operatorEmail, operatorGroup)
	browser := s.operator
	s.startAgent()
	st = s.waitCluster(s.lb.url(), "the agent's connection to be held by a release member", func(c clusterStatus) bool {
		o := c.owner("agent", s.executorID)
		return o == a.id || o == b.id
	})
	// Every member registers the device once it hears of the enrollment
	// over the cluster's bus; a bind served by one that has not yet would
	// be refused as naming no executor.
	for _, m := range []*member{a, b} {
		m := m
		s.eventually(m.String()+" to register the enrolled device", 30*time.Second, func() bool {
			dev, ok := s.device(m)
			return ok && dev.Registered
		})
	}
	s.projIdx, s.proj2Idx = s.projectIndex(s.proj), s.projectIndex(s.proj2)
	for _, idx := range []int{s.projIdx, s.proj2Idx} {
		if r := s.api(s.lb.url(), http.MethodPost, fmt.Sprintf("/api/projects/%d/executor", idx),
			map[string]string{"executor_id": s.executorID}); r.status != http.StatusOK {
			t.Fatalf("bind project %d to %s: %s", idx, s.executorID, r)
		}
	}

	// ── 3. CI exchanges and quota counters, written by the release ────────
	// Federation is off, so each exchange is refused — and recorded.
	for i := 0; i < 2; i++ {
		if r := s.do(nil, s.lb.url(), http.MethodPost, "/api/ci/token", map[string]string{"token": "not-a-token"}, ""); r.status == http.StatusOK {
			t.Fatalf("a CI exchange with no federation was accepted: %s", r)
		}
	}

	// ── 4. A device run, started by the signed-in person ──────────────────
	if r := s.do(browser, s.lb.url(), http.MethodPost, fmt.Sprintf("/api/run?project_idx=%d", s.projIdx), nil, ""); r.status != http.StatusOK {
		t.Fatalf("start the run as %s: %s", operatorEmail, r)
	}
	s.eventually("the harness to be blocked on the device", 120*time.Second, func() bool {
		_, blocked := s.stubStarts()
		return blocked == 1
	})
	if got := readFile(s.results); !strings.Contains(got, "clone ok") {
		t.Fatalf("the workload's clone through the release member's git proxy failed:\n%s\n%s", got, readFile(s.results+".err"))
	}
	dispatcher, meta := s.runOwner()
	if dispatcher != a.id && dispatcher != b.id {
		t.Fatalf("the run is owned by %q, not by a release member", dispatcher)
	}
	if meta["seeded"] != true {
		t.Fatalf("the run was not carried out as a seed (owner meta %v)", meta)
	}
	handle := fmt.Sprint(meta["handle"])
	_, slotRecorded := meta["quota_slot"]
	leases, _ := meta["leases"].([]any)
	if len(leases) != 1 {
		t.Fatalf("the run's owner row names %d leases, want its one: %v", len(leases), meta)
	}
	lease := fmt.Sprint(leases[0])
	if got := s.leaseHolder(lease); got != dispatcher {
		t.Fatalf("lease %s is recorded as held by %q, want the dispatching member %s", lease, got, short(dispatcher))
	}
	sessions := s.proxySessions(lease)
	if len(sessions) != 2 || sessions[0][0] != "git" || sessions[1][0] != "kube" {
		t.Fatalf("the run's lease feeds sessions %v, want its git proxy and Kubernetes monitor ones", sessions)
	}
	for _, row := range sessions {
		if row[2] != dispatcher {
			t.Fatalf("the %s session %s is held by %q, want the dispatching member %s", row[0], row[1], row[2], short(dispatcher))
		}
	}
	t.Logf("run %s dispatched by %s, lease %s, sessions %s and %s", handle, short(dispatcher), lease, sessions[0][1], sessions[1][1])
	if n := len(s.query(s.hubDir, `SELECT id FROM ci_exchanges`)); n < 2 {
		t.Fatalf("the release recorded %d CI exchanges, want at least 2", n)
	}
	if n := len(s.query(s.hubDir, `SELECT identity FROM quota_counters`)); n == 0 {
		t.Fatal("the release recorded no quota counter for the run it admitted")
	}

	// What the release built, before anything of the build under test runs.
	releaseSchema := map[string]schema{
		"control plane":  s.schemaOf(s.hubDir),
		"project":        s.schemaOf(s.proj),
		"second project": s.schemaOf(s.proj2),
	}
	releaseTasks := s.query(s.proj, `SELECT id, title, description, status FROM plan_tasks ORDER BY id`)

	// ── 5. A member of the build under test joins, and migrates ───────────
	c := s.join(buildMain)
	st = s.waitCluster(c.url(), "the new member to join the release members", func(cs clusterStatus) bool {
		return cs.live() == 3
	})
	s.identify(st, c)
	t.Logf("%s joined as %s", c, short(c.id))
	for name, dir := range map[string]string{"control plane": s.hubDir, "project": s.proj, "second project": s.proj2} {
		dir := dir
		s.eventually("the "+name+" database to be migrated to schema "+strconv.Itoa(s.mainInfo.Schema), 60*time.Second, func() bool {
			return s.schemaVersion(dir) == s.mainInfo.Schema
		})
		s.checkVerdicts(name, dir, s.rel.info.Schema)
	}
	if got := s.query(s.proj, `SELECT id, title, description, status FROM plan_tasks ORDER BY id`); fmt.Sprint(got) != fmt.Sprint(releaseTasks) {
		t.Errorf("the migration changed the tasks the release saved:\nbefore %v\nafter  %v", releaseTasks, got)
	}

	// The release members go on serving the migrated database.
	for _, m := range []*member{a, b} {
		if r := s.api(m.url(), http.MethodGet, "/readyz", nil); r.status != http.StatusOK {
			t.Fatalf("%s is not ready on the migrated database: %s", m, r)
		}
		if r := s.api(m.url(), http.MethodGet, fmt.Sprintf("/api/state?project_idx=%d", s.projIdx), nil); r.status != http.StatusOK {
			t.Fatalf("%s cannot read the migrated project: %s", m, r)
		}
	}

	// ── 6. Every column the build under test added survives a save by a
	//       release member that does not know it ─────────────────────────────
	s.checkColumnsSurviveReleaseWrites(releaseSchema, a, b, c)

	// ── 7. The release members are stopped, one at a time ─────────────────
	// The one holding the run first, so the run is handed over while a
	// release member is still there to take it, as it would be in any
	// rollout that does not happen to stop the members in the best order.
	first, second := a, b
	if owner, _ := s.runOwner(); owner == b.id {
		first, second = b, a
	}
	for _, m := range []*member{first, second} {
		held, _ := s.runOwner()
		s.stopMember(m)
		t.Logf("stopped %s (it held the run: %v)", m, held == m.id)
		st = s.waitCluster(c.url(), "the run and the agent to be held by a live member after "+m.String()+" stopped",
			func(cs clusterStatus) bool {
				o := cs.owner("run", s.proj)
				return o != "" && o != m.id && cs.alive(o) && cs.owner("agent", s.executorID) == o
			})
	}
	st = s.waitCluster(c.url(), "the build under test to hold the run, the agent and the lead", func(cs clusterStatus) bool {
		return cs.owner("run", s.proj) == c.id && cs.owner("agent", s.executorID) == c.id && cs.Leader == c.id && cs.live() == 1
	})

	// The run's lease and sessions came with it.
	s.eventually("the build under test to hold the run's lease", 60*time.Second, func() bool {
		return s.leaseHolder(lease) == c.id
	})
	s.eventually("the build under test to hold the run's git proxy and Kubernetes monitor sessions", 60*time.Second, func() bool {
		rows := s.proxySessions(lease)
		if len(rows) != 2 {
			return false
		}
		for _, row := range rows {
			if row[2] != c.id || row[3] != "" {
				return false
			}
		}
		return true
	})
	takeover := 0
	for _, row := range s.auditRows("secret.renew", lease) {
		if row.payload["decision"] == "allow" && strings.Contains(fmt.Sprint(row.payload["reason"]), "taken over") {
			takeover = row.id
		}
	}
	if takeover == 0 {
		t.Errorf("the lease's trail records no takeover: %v", s.auditRows("secret.renew", lease))
	}

	// ── 8. The release's agent, under the build under test ────────────────
	s.checkReleaseAgentUnderMain(c)

	// ── 9. The run settles on the build under test ────────────────────────
	s.releaseHarness(true)
	s.eventually("task 1 to be done in the hub's copy of the project", 120*time.Second, func() bool {
		return s.taskStatus(1) == "done"
	})
	s.eventually("the project to be complete", 60*time.Second, func() bool { return s.projectStatus() == "complete" })
	got := readFile(s.results)
	if !strings.Contains(got, "push ok") || !strings.Contains(got, "kube 200") {
		t.Fatalf("after the upgrade the workload's git and kubectl did not both work through the sessions the "+
			"build under test restored:\n%s\n%s", got, readFile(s.results+".err"))
	}
	for _, line := range strings.Split(got, "\n") {
		if branch, ok := strings.CutPrefix(line, "push ok "); ok && s.forge.Ref(t, "acme/tool", "refs/heads/"+branch) == "" {
			t.Errorf("the push of %s did not reach the forge", branch)
		}
	}
	if s.clusterHits.Load() == 0 {
		t.Error("the fake cluster saw no request with its own token")
	}
	if all, blocked := s.stubStarts(); blocked != 1 {
		t.Errorf("the harness blocked %d times (%d starts): the run was started over, not handed over", blocked, all)
	}
	s.eventually("the run's control-plane rows to be cleared", 60*time.Second, func() bool {
		owner, _ := s.runOwner()
		rows, _ := s.tryQuery(s.hubDir, `SELECT handle_id FROM executor_handles`)
		return owner == "" && len(rows) == 0
	})
	if results := s.query(s.proj, `SELECT message FROM events WHERE type = 'project_result'`); len(results) != 1 {
		t.Errorf("project_result journal rows = %d, want exactly 1: %v", len(results), results)
	}
	s.eventually("the run's lease to be released", 60*time.Second, func() bool {
		return len(s.auditRows("secret.release", lease)) > 0
	})
	if rel := s.auditRows("secret.release", lease); len(rel) != 1 || rel[0].id < takeover {
		t.Errorf("lease %s was released %d time(s), want once and after its takeover (%d): %v", lease, len(rel), takeover, rel)
	}
	if rows := s.query(s.hubDir, `SELECT kind, session_id FROM proxy_sessions WHERE closed_at = ''`); len(rows) != 0 {
		t.Errorf("sessions left open after the run: %v", rows)
	}
	if rows := s.query(s.hubDir, `SELECT state FROM executor_sessions WHERE handle_id = ?`, handle); len(rows) != 1 || rows[0][0] != "finished" {
		t.Errorf("the run's executor sessions = %v, want one, finished", rows)
	}
	if got := s.query(s.proj, `SELECT id, title, status FROM plan_tasks WHERE id IN (2, 3) ORDER BY id`); len(got) != 2 ||
		got[0][2] != "done" || got[1][2] != "skipped" {
		t.Errorf("the release's finished and skipped tasks are now %v", got)
	}

	// The operator's concurrency slot comes back once the run is over —
	// given back by the member that settled it, whose owner row named it.
	// A release from before Task 20452 records no slot, so a run it
	// dispatched keeps the slot past a handover: say so rather than fail.
	held := s.query(s.hubDir, `SELECT CAST(COALESCE(SUM(value), 0) AS INTEGER) FROM quota_counters
		WHERE identity = ? AND resource = 'max_concurrent_tasks' AND bucket = ''`, operatorEmail)[0][0]
	if slotRecorded {
		s.eventually("the run's concurrency slot to be given back", 30*time.Second, func() bool {
			return s.query(s.hubDir, `SELECT CAST(COALESCE(SUM(value), 0) AS INTEGER) FROM quota_counters
				WHERE identity = ? AND resource = 'max_concurrent_tasks' AND bucket = ''`, operatorEmail)[0][0] == "0"
		})
	} else {
		t.Logf("%s dispatched the run without recording its concurrency slot on the owner row, so the members it "+
			"moved to could not give it back: %s still holds %s slot(s) until a member starting alone rebuilds the "+
			"gauges (fixed for runs a build from Task 20452 on dispatches)", s.rel.tag, operatorEmail, held)
	}

	// ── 10. The audit chains and their checkpoints ────────────────────────
	s.stopMember(c)
	s.checkAuditChains(map[string]string{a.id: a.String(), b.id: b.String(), c.id: c.String()})
	t.Logf("rehearsed %s → %s in %s", s.rel.tag, s.mainInfo.Version, time.Since(started).Round(time.Second))
}

// checkReleaseAgentUnderMain: the release's agent reconnected to the build
// under test, which lists it as what it is — a device on an older build, not
// a refused one — and offers it an upgrade.
func (s *scene) checkReleaseAgentUnderMain(c *member) {
	t := s.t
	var dev executor
	var raw string
	deadline := time.Now().Add(60 * time.Second)
	for {
		var ok bool
		dev, ok = s.device(c)
		if ok && dev.Status == "online" && dev.Inventory != nil && dev.Inventory.Live {
			break
		}
		if time.Now().After(deadline) {
			raw = string(s.api(c.url(), http.MethodGet, "/api/executors", nil).body)
			t.Fatalf("the build under test does not list the release's agent online and live after 60s: %s", raw)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if dev.Inventory.AgentVersion != s.rel.tag {
		t.Errorf("the agent reports %q, want the release %s", dev.Inventory.AgentVersion, s.rel.tag)
	}
	if dev.Blocked || dev.Health != "" {
		t.Errorf("the build under test refuses the release's agent: blocked %v (%s), health %q", dev.Blocked,
			dev.BlockedReason, dev.Health)
	}
	skew := dev.VersionSkew
	if skew == nil {
		t.Fatalf("the build under test does not compare the release's agent with itself: %+v", dev)
	}
	if skew.DeviceProtocol != s.rel.info.Protocol || skew.HubProtocol != s.mainInfo.Protocol {
		t.Errorf("protocols shown: device v%d, hub v%d; want v%d and v%d",
			skew.DeviceProtocol, skew.HubProtocol, s.rel.info.Protocol, s.mainInfo.Protocol)
	}
	switch {
	case s.rel.info.Protocol < s.mainInfo.Protocol:
		if !skew.Material || !strings.Contains(skew.Note, fmt.Sprintf("v%d", s.rel.info.Protocol)) {
			t.Errorf("a device on protocol v%d under a v%d hub is not shown as older: %+v",
				s.rel.info.Protocol, s.mainInfo.Protocol, *skew)
		}
	case skew.Skew == "older" || skew.Skew == "patch" || skew.Skew == "behind":
		// The same protocol, an earlier build: ordered by the place on main
		// both carry when the build under test is not a release, by their
		// versions when it is.
	default:
		t.Errorf("the release's agent (%s, sequence %d) under the build under test (%s, sequence %d) is "+
			"classified %q, not as an older build: %+v", s.rel.tag, s.rel.info.Sequence, s.mainInfo.Version,
			s.mainInfo.Sequence, skew.Skew, *skew)
	}
	// Upgrade offers it a way forward: a release its installer accepts —
	// never one earlier on main than the release it runs.
	switch seq, known := version.ReleaseSequence(dev.UpgradeTarget); {
	case dev.UpgradeTarget == "":
		t.Errorf("the Upgrade dialog offers the release's agent nothing: %s", dev.UpgradeNote)
	case known && seq > 0 && seq < s.rel.info.Sequence:
		t.Errorf("the Upgrade dialog offers the release's agent %s (sequence %d), earlier than the %s it runs (%d)",
			dev.UpgradeTarget, seq, s.rel.tag, s.rel.info.Sequence)
	default:
		t.Logf("Upgrade offers the release's agent %s: %s", dev.UpgradeTarget, dev.UpgradeNote)
	}
	t.Logf("the release's agent under the build under test: %s skew, protocol v%d against v%d: %s",
		skew.Skew, skew.DeviceProtocol, skew.HubProtocol, skew.Note)
}

// checkAuditChains verifies both chains against the checkpoints the members
// wrote — the release members' among them — with the build under test, and
// with the release too, which must still read a trail the newer build
// extended.
func (s *scene) checkAuditChains(members map[string]string) {
	t := s.t
	records := strings.Count(readFile(s.checkpoints), "\n")
	if records == 0 {
		t.Fatalf("no audit checkpoint was written to %s", s.checkpoints)
	}
	// Checkpoints sealed by both builds: the release members' (each writes
	// one when it stops while leading) and the build under test's.
	byBuild := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(readFile(s.checkpoints)), "\n") {
		var rec struct {
			Member string `json:"member"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			t.Errorf("an audit checkpoint record does not parse: %s", line)
			continue
		}
		name := members[rec.Member]
		if name == "" {
			name = "an unknown member " + rec.Member
		}
		byBuild[strings.Fields(name)[0]]++
	}
	t.Logf("audit checkpoints by build: %v", byBuild)
	if byBuild[buildRelease] == 0 || byBuild[buildMain] == 0 {
		t.Errorf("the checkpoints were not written by both builds: %v", byBuild)
	}
	for _, build := range []string{buildMain, buildRelease} {
		out, err := s.cliErr(build, s.root, nil, "hub", "audit", "verify", "--hub", s.hubDir,
			"--project", s.proj, "--checkpoints", s.checkpoints)
		if err != nil {
			t.Errorf("%s `cloop hub audit verify` over the rehearsed trail failed: %v\n%s", build, err, out)
			continue
		}
		if strings.Count(out, "OK ") < 2 {
			t.Errorf("%s `cloop hub audit verify` did not report both chains OK:\n%s", build, out)
		}
		t.Logf("%s audit verify (%d checkpoint records):\n%s", build, records, tail(out, 12))
	}
}
