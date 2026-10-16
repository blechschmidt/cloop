package e2e_test

// The hub's model relay for sandboxed runs, end to end (Task 20435).
//
// A real `cloop ui` serves its git proxy with a certificate it issued itself
// (tls: auto) and the model relay beside it; a real `cloop executor agent`
// runs the project's run in host mode, on a work root the hub cannot see; a
// stand-in `claude` makes Messages calls the way Claude Code does — to
// ANTHROPIC_BASE_URL with ANTHROPIC_AUTH_TOKEN, verifying the relay with the
// CA in NODE_EXTRA_CA_CERTS — and a stand-in for the Anthropic API answers
// them, recording what credential each presented. The run's project holds a
// granted CLAUDE_CODE_OAUTH_TOKEN, as a sandboxed run's would.
//
// It proves the task's five properties on real processes:
//
//  1. the credential's value is nowhere in the workload's environment, its
//     files or /proc — the harness, the `cloop run` above it, the agent;
//  2. what the hub charges the run's payer is what the API reported;
//  3. once the payer's daily budget is spent mid-run, the next call is
//     refused with a 403 naming the cap, and never reaches the API;
//  4. revoking the grant refuses the next call, with the reason;
//  5. a hub killed mid-run and started again keeps the session: the
//     harness's next call, made with the token it already holds, is served.
//
// About ten seconds; it needs bash, curl and git, and runs in CI's Build and
// Test job with the rest of tests/e2e. CLOOP_RESTART_E2E_LOGS=1 prints the
// hub's and the agent's logs.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// relayStub stands in for Claude Code. Each call retries what the harness
// retries — a refused connection while the hub restarts, a 5xx, a 401 while
// a restarted hub has not yet adopted the run — for up to two minutes, and is
// logged with its final status. It blocks on the scene's FIFO between phases.
const relayStub = `#!/bin/bash
prompt=$(cat)
echo "$$ $(pwd)" >> "@LOG@"
exec 3<>"@FIFO@"
env > "@ENVDUMP@"
call() {
  local deadline=$((SECONDS + 120)) code
  while :; do
    code=$(curl -sS -o "@OUT@.$1" -w '%{http_code}' --max-time 60 --cacert "$NODE_EXTRA_CA_CERTS" \
      -H "Authorization: Bearer $ANTHROPIC_AUTH_TOKEN" -H 'content-type: application/json' \
      -H 'anthropic-version: 2023-06-01' \
      -d '{"model":"claude-sonnet-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}' \
      "$ANTHROPIC_BASE_URL/v1/messages" 2>>"@OUT@.err")
    case "$code" in
      000|401|502|503|504|529) if [ $SECONDS -lt $deadline ]; then sleep 0.5; continue; fi ;;
    esac
    break
  done
  echo "call $1 $code" >> "@CALLS@"
}
wait_go() {
  if ! read -r -t 600 -u 3 line; then echo "stub claude: never released" >&2; exit 1; fi
}
call 1
wait_go
call 2
call 3
call 4
wait_go
call 5
echo "stub claude: done"
echo TASK_DONE
`

// relayAPIStandIn is the Anthropic API: every call spends relayCallTokens.
type relayAPIStandIn struct {
	srv  *httptest.Server
	mu   sync.Mutex
	auth []string
}

// relayCallTokens is what one answer reports: 400 in, 50 out, 3000 read from
// the cache, 50 written to it.
const relayCallTokens = 3500

func newRelayAPIStandIn(t *testing.T) *relayAPIStandIn {
	a := &relayAPIStandIn{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		a.mu.Lock()
		a.auth = append(a.auth, r.Header.Get("Authorization"))
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_e2e","type":"message","model":"claude-sonnet-5-20260901",` +
			`"content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":400,"output_tokens":50,` +
			`"cache_read_input_tokens":3000,"cache_creation_input_tokens":50}}`))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *relayAPIStandIn) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.auth...)
}

func TestE2EModelRelayKeepsTheCredentialOnTheHub(t *testing.T) {
	for _, tool := range []string{"curl", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	api := newRelayAPIStandIn(t)
	gpPort := freePort(t)
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	calls := filepath.Join(root, "calls.log")
	envDump := filepath.Join(root, "harness.env")
	out := filepath.Join(root, "call")
	// The payer's budget: two and a half calls' worth, so the third is
	// admitted with headroom left and the fourth is refused.
	budget := relayCallTokens * 5 / 2
	s := newRestartSceneWith(t, restartOptions{
		executors: "    git_proxy:\n" +
			"        enabled: true\n" +
			"        listen_addr: 127.0.0.1:" + strconv.Itoa(gpPort) + "\n" +
			"        advertise_url: https://127.0.0.1:" + strconv.Itoa(gpPort) + "\n" +
			"        tls: auto\n" +
			"    model_relay:\n" +
			"        enabled: true\n" +
			"        upstream_base_url: " + api.srv.URL + "\n" +
			"ui:\n" +
			"    quotas:\n" +
			"        defaults:\n" +
			"            daily_token_budget: " + strconv.Itoa(budget) + "\n",
		stub: relayStub,
		vars: map[string]string{"CALLS": calls, "ENVDUMP": envDump, "OUT": out},
	})
	credential := harnessCredentialToken()

	s.startHub()
	s.startAgent()
	s.bind()
	idx := s.projectIdx(s.proj)
	if code, body := s.call("POST", "/api/run?project_idx="+strconv.Itoa(idx), map[string]any{}); code != http.StatusOK {
		t.Fatalf("POST /api/run = %d %v", code, body)
	}
	callStatus := func(n int) string {
		data, _ := os.ReadFile(calls)
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) == 3 && f[0] == "call" && f[1] == strconv.Itoa(n) {
				return f[2]
			}
		}
		return ""
	}
	s.waitFor("the harness's first call", 90*time.Second, func() bool { return callStatus(1) != "" })
	if got := callStatus(1); got != "200" {
		body, _ := os.ReadFile(out + ".1")
		errs, _ := os.ReadFile(out + ".err")
		t.Fatalf("the first relayed call = %s: %s %s", got, body, errs)
	}

	// 1. The credential is nowhere the workload can read.
	dump, err := os.ReadFile(envDump)
	if err != nil {
		t.Fatal(err)
	}
	harnessEnv := map[string]string{}
	for _, line := range strings.Split(string(dump), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			harnessEnv[k] = v
		}
	}
	if !strings.HasPrefix(harnessEnv["ANTHROPIC_AUTH_TOKEN"], "cloop_relay_") ||
		harnessEnv["ANTHROPIC_BASE_URL"] != "https://127.0.0.1:"+strconv.Itoa(gpPort)+"/_anthropic" ||
		harnessEnv["NODE_EXTRA_CA_CERTS"] == "" {
		t.Fatalf("the harness was not pointed at the relay: base %q, token set %v, CA %q",
			harnessEnv["ANTHROPIC_BASE_URL"], harnessEnv["ANTHROPIC_AUTH_TOKEN"] != "", harnessEnv["NODE_EXTRA_CA_CERTS"])
	}
	if strings.Contains(string(dump), credential) || harnessEnv["CLAUDE_CODE_OAUTH_TOKEN"] != "" {
		t.Fatal("the credential is in the harness's environment")
	}
	pids := append(s.workloadPIDs(), s.stubPIDs()...)
	if s.agent != nil && s.agent.Process != nil {
		pids = append(pids, s.agent.Process.Pid)
	}
	if len(pids) < 2 {
		t.Fatalf("found %d workload processes to look in", len(pids))
	}
	for _, pid := range pids {
		for _, f := range []string{"environ", "cmdline"} {
			if b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), f)); err == nil &&
				strings.Contains(string(b), credential) {
				t.Fatalf("the credential is in /proc/%d/%s", pid, f)
			}
		}
	}
	dirs := []string{filepath.Join(s.root, "device"), filepath.Join(s.root, "device-home")}
	if d := harnessEnv["CLOOP_LEASE_DIR"]; d != "" {
		dirs = append(dirs, d)
	}
	for _, dir := range dirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || info.Size() > 64<<20 {
				return nil
			}
			if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), credential) {
				t.Errorf("the credential is in the workload's file %s", path)
			}
			return nil
		})
	}
	// The API was called with the grant's credential, and nothing else.
	if seen := api.seen(); len(seen) != 1 || seen[0] != "Bearer "+credential {
		t.Fatalf("the API saw %d calls; the first with the run's credential: %v", len(seen),
			len(seen) == 1 && seen[0] == "Bearer "+credential)
	}

	// 2. The payer was charged what the API reported.
	charged := func() int {
		rows := s.query(s.hubDir, `SELECT COALESCE(SUM(value), 0) FROM quota_counters WHERE resource = 'daily_token_budget'`)
		if len(rows) != 1 {
			return -1
		}
		n, _ := strconv.ParseFloat(rows[0][0], 64)
		return int(n)
	}
	s.waitFor("the first call to be charged", 10*time.Second, func() bool { return charged() == relayCallTokens })

	// 5. The hub is killed mid-run and started again: the harness's next
	// call, with the token it already holds, is served.
	s.stopHub(syscall.SIGKILL)
	s.startHub()
	s.releaseHarness(true)
	s.waitFor("the harness's calls after the restart", 4*time.Minute, func() bool { return callStatus(4) != "" })
	for n := 2; n <= 3; n++ {
		if got := callStatus(n); got != "200" {
			body, _ := os.ReadFile(out + "." + strconv.Itoa(n))
			t.Fatalf("call %d, after the restart = %s: %s", n, got, body)
		}
	}
	if got := charged(); got != 3*relayCallTokens {
		t.Fatalf("after three calls the payer was charged %d tokens, want %d", got, 3*relayCallTokens)
	}

	// 3. The budget was spent mid-run: the next call is refused, naming it.
	refusal, _ := os.ReadFile(out + ".4")
	if callStatus(4) != "403" || !strings.Contains(string(refusal), "daily_token_budget") {
		t.Fatalf("the call past the budget = %s: %s", callStatus(4), refusal)
	}
	if n := len(api.seen()); n != 3 {
		t.Fatalf("the API was reached %d times; the refused call reached it", n)
	}

	// 4. Revoking the grant refuses the next call.
	code, body := s.call("GET", "/api/grants", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/grants = %d %v", code, body)
	}
	grantID := ""
	grants, _ := body["grants"].([]any)
	for _, g := range grants {
		m, _ := g.(map[string]any)
		if strings.Contains(strings.ToLower(fmtAny(m["secret_name"])+fmtAny(m["secret_ref"])), "e2e-claude-credential") {
			grantID = fmtAny(m["id"])
		}
	}
	if grantID == "" {
		t.Fatalf("no grant of the credential in %v", body)
	}
	if code, body := s.call("DELETE", "/api/grants/"+grantID, nil); code != http.StatusOK {
		t.Fatalf("DELETE /api/grants/%s = %d %v", grantID, code, body)
	}
	s.releaseHarness(true)
	s.waitFor("the harness's call after the revocation", 2*time.Minute, func() bool { return callStatus(5) != "" })
	revoked, _ := os.ReadFile(out + ".5")
	if callStatus(5) != "403" || !strings.Contains(string(revoked), "grant "+grantID+" revoked by") {
		t.Fatalf("the call after the revocation = %s: %s", callStatus(5), revoked)
	}
	for i, a := range api.seen() {
		if a != "Bearer "+credential {
			t.Fatalf("API call %d presented something other than the run's credential", i+1)
		}
	}
	if n := len(api.seen()); n != 3 {
		t.Fatalf("the API was reached %d times; a revoked session reached it", n)
	}
	// The record of the session holds no credential either.
	for _, row := range s.query(s.hubDir, `SELECT scope_json || counters_json FROM proxy_sessions WHERE kind = 'model'`) {
		if strings.Contains(row[0], credential) {
			t.Fatal("the session's record holds the credential")
		}
	}
}

func fmtAny(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
