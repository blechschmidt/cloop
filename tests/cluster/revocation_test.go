package cluster_test

// A revocation outlives the member holding the lease (Task 20419).
//
// Two real `cloop ui` processes serve one control plane. A run is dispatched
// through the first, which so holds the run's secret lease; the first is
// SIGKILLed while the workload runs; and the lease is revoked, then its grant,
// through the survivor. Before Task 20419 the revoke answered 404 — no live
// member held the lease — and recorded nothing, and the survivor, adopting the
// run, took the lease over and kept the credential alive in the workload.
//
// Two workloads, because the credential lives in a different place in each:
//
//   - a container, whose credential files the dead member staged in a host
//     directory bind-mounted into it. The survivor must take them back — from
//     the container it adopts, through where the dead member's row says they
//     are staged — and never restore the lease;
//   - a host process, which outlives the member that forked it (it is
//     reparented, not killed) and reads its credential from that member's
//     /dev/shm. The survivor must wipe that directory as soon as it sees the
//     member die, rather than leave the plaintext for whichever member next
//     starts.
//
// The workload reports, from where it runs, whether its credential file is
// still there: a post-task hook loops on it, writing "present" or "gone" into
// the project directory, which the container shares with the host.
//
// Opt in with CLOOP_CLUSTER_E2E=1; the container scenario also needs Docker.
// CLOOP_CLUSTER_BIN points at a prebuilt hub binary; the container scenario
// builds a static one for its image regardless, since the image is Alpine.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// revokeAlpine pins the container scenario's base image: the digest the
// flagship circuit and CI's container steps already pull.
const revokeAlpine = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

// revokeImage is built locally and never pulled (the driver passes
// --pull=never).
const revokeImage = "cloop-harness:revoke-e2e"

// revokeExecutorID is the container executor's id.
const revokeExecutorID = "revoke-ctr"

// revokeSandboxUID is who the hubs and the sandbox run as when the test runs
// as root: the container driver runs the workload as the project's owner, and
// the hub has to be that same user for the sandbox to write the project's
// database (see tests/flagship).
const revokeSandboxUID = 65532

// holdHook keeps the task open after the mock provider reports it done, and
// reports whether the workload can read its credential file. Its paths are
// relative to the project directory, which is the working directory of the
// workload on the host and inside the container alike.
const holdHook = `set -u
echo "${CLOOP_LEASE_DIR:-none}" > .cloop/lease-dir
i=0
while [ ! -e .cloop/release ]; do
  if [ -r "${CLOOP_LEASE_DIR:-/nonexistent}/github-token" ]; then s=present; else s=gone; fi
  echo "$s" > .cloop/cred-state.tmp && mv .cloop/cred-state.tmp .cloop/cred-state
  i=$((i+1)); [ "$i" -gt 3000 ] && exit 0
  sleep 0.2
done
`

const revokePlan = `goal: Hold a leased credential while a hub member dies
tasks:
  - title: Hold the credential open
    description: The post-task hook keeps the run alive and reports whether the credential is readable.
    priority: 1
    status: pending
`

// revokeScene is one control plane, two hub members, one project.
type revokeScene struct {
	t         *testing.T
	root      string
	bin       string
	home      string
	cloopH    string
	hubDir    string
	projDir   string
	container bool
	// cred drops the hubs and every cloop invocation to revokeSandboxUID when
	// the test runs as root; nil otherwise.
	cred *syscall.Credential

	mu    sync.Mutex
	procs []*exec.Cmd
	hubs  []*hub
}

func newRevokeScene(t *testing.T, container bool) *revokeScene {
	t.Helper()
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this builds cloop and runs hub processes", enableEnv)
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is required for the workload's hook")
	}
	if container {
		if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
			t.Skipf("docker is unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	// Under /var/tmp, not /tmp: the container driver mounts a tmpfs over the
	// sandbox's /tmp, which would hide a binary the image placed there, and
	// the hub dispatches its own path as argv[0].
	root, err := os.MkdirTemp("/var/tmp", "cloop-revoke-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &revokeScene{
		t: t, root: root, container: container,
		bin:     filepath.Join(root, "bin", "cloop"),
		home:    filepath.Join(root, "home"),
		cloopH:  filepath.Join(root, "home", ".cloop"),
		hubDir:  filepath.Join(root, "hub"),
		projDir: filepath.Join(root, "proj"),
	}
	t.Cleanup(s.cleanup)
	for _, d := range []string{filepath.Dir(s.bin), s.home, s.cloopH, s.hubDir, s.projDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if container && os.Geteuid() == 0 {
		gid, ok := revokeDockerGroup()
		if !ok {
			t.Skip("cannot determine the Docker socket's group for the unprivileged hub identity")
		}
		s.cred = &syscall.Credential{Uid: revokeSandboxUID, Gid: revokeSandboxUID, Groups: []uint32{gid}}
	}
	s.provisionBinary()
	if container {
		s.buildImage()
	}
	s.own(root)
	return s
}

// revokeDockerGroup is the group that owns the Docker socket.
func revokeDockerGroup() (uint32, bool) {
	for _, sock := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if info, err := os.Stat(sock); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				return st.Gid, true
			}
		}
	}
	return 0, false
}

// own gives the tree to the identity the hubs run as.
func (s *revokeScene) own(dir string) {
	if s.cred == nil {
		return
	}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			_ = os.Lchown(path, int(s.cred.Uid), int(s.cred.Gid))
		}
		return nil
	})
}

func (s *revokeScene) moduleRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		s.t.Fatal("cannot locate the test source")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// provisionBinary puts the hub's binary at s.bin — copied, not linked, so its
// path is one the container image can also have.
func (s *revokeScene) provisionBinary() {
	t := s.t
	if prebuilt := os.Getenv(binEnv); prebuilt != "" {
		data, err := os.ReadFile(prebuilt)
		if err != nil {
			t.Fatalf("%s=%s: %v", binEnv, prebuilt, err)
		}
		if err := os.WriteFile(s.bin, data, 0o755); err != nil {
			t.Fatal(err)
		}
		return
	}
	s.build(s.bin, nil)
}

func (s *revokeScene) build(out string, extraEnv []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, ".")
	cmd.Dir = s.moduleRoot()
	cmd.Env = append(append(os.Environ(), goEnv...), extraEnv...)
	if b, err := cmd.CombinedOutput(); err != nil {
		s.t.Fatalf("build cloop: %v\n%s", err, b)
	}
}

// buildImage builds the sandbox image: Alpine, a static cloop at the path the
// hub dispatches as argv[0], and no entrypoint.
func (s *revokeScene) buildImage() {
	imgDir := filepath.Join(s.root, "img")
	if err := os.MkdirAll(imgDir, 0o755); err != nil {
		s.t.Fatal(err)
	}
	s.build(filepath.Join(imgDir, "cloop"), []string{"CGO_ENABLED=0"})
	dockerfile := fmt.Sprintf("FROM %s\nCOPY cloop /usr/local/bin/cloop\nCOPY cloop %s\nENTRYPOINT []\n",
		revokeAlpine, s.bin)
	if err := os.WriteFile(filepath.Join(imgDir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		s.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", revokeImage, imgDir).CombinedOutput(); err != nil {
		s.t.Fatalf("docker build: %v\n%s", err, out)
	}
}

func (s *revokeScene) env() []string {
	return []string{
		"HOME=" + s.home,
		"CLOOP_HOME=" + s.cloopH,
		"PATH=" + filepath.Dir(s.bin) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"CLOOP_UI_TOKEN=" + token,
		"CLOOP_SECRET_KEY=e2e-revoke-outlives-its-holder",
		"NO_COLOR=1",
	}
}

// cloop runs a subcommand to completion as the hubs' identity.
func (s *revokeScene) cloop(dir, stdin string, args ...string) string {
	s.t.Helper()
	cmd := exec.Command(s.bin, args...)
	cmd.Dir = dir
	cmd.Env = s.env()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if s.cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: s.cred}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.t.Fatalf("cloop %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (s *revokeScene) write(path, body string, mode os.FileMode) {
	s.t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		s.t.Fatal(err)
	}
	s.own(path)
}

// setup creates the control plane, the project and the grant.
func (s *revokeScene) setup() {
	s.cloop(s.hubDir, "", "init", "--provider", "mock", "--skip-clarify", "revocation e2e control plane")
	if s.container {
		for _, kv := range [][2]string{
			{"executors.allow_host_process", "false"},
			{"executors.container.enabled", "true"},
			{"executors.container.id", revokeExecutorID},
			{"executors.container.runtime", "docker"},
			{"executors.container.image", revokeImage},
			{"executors.container.network", "none"},
		} {
			s.cloop(s.hubDir, "", "config", "set", kv[0], kv[1])
		}
	}
	s.cloop(s.projDir, "", "init", "--provider", "mock", "--skip-clarify", "Hold a leased credential")
	plan := filepath.Join(s.root, "plan.yaml")
	s.write(plan, revokePlan, 0o644)
	s.cloop(s.projDir, "", "plan", "import", plan, "--replace", "--yes")
	s.write(filepath.Join(s.projDir, ".cloop", "hold.sh"), holdHook, 0o755)
	f, err := os.OpenFile(filepath.Join(s.projDir, ".cloop", "config.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := f.WriteString("\nhooks:\n  post_task: sh .cloop/hold.sh\n"); err != nil {
		s.t.Fatal(err)
	}
	_ = f.Close()

	executorID := "local"
	if s.container {
		executorID = revokeExecutorID
	}
	// A GitHub token, delivered as files — what the workload checks for. No
	// git proxy runs, so the token itself is among them.
	s.cloop(s.hubDir, "ghp_revoke_e2e_not_a_real_token_0123456789", "secret", "mint", "revoke-pat", "--kind", "github_pat")
	s.cloop(s.hubDir, "", "secret", "grant", "revoke-pat", "--to", "executor:"+executorID,
		"--repos", "example/revoke", "--permissions", "contents:read", "--ttl", "1h")
	s.own(s.root)
}

// startHub starts a member in its own process group.
func (s *revokeScene) startHub() *hub {
	s.t.Helper()
	port := freePort(s.t)
	h := &hub{port: port, log: filepath.Join(s.root, fmt.Sprintf("hub-%d.log", port))}
	logf, err := os.Create(h.log)
	if err != nil {
		s.t.Fatal(err)
	}
	cmd := exec.Command(s.bin, "ui", "--port", strconv.Itoa(port), "--no-browser", "--projects", s.projDir)
	cmd.Dir = s.hubDir
	cmd.Env = s.env()
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: s.cred}
	if err := cmd.Start(); err != nil {
		s.t.Fatalf("start hub: %v", err)
	}
	h.cmd, h.exited = cmd, make(chan struct{})
	go func() {
		_ = cmd.Wait()
		_ = logf.Close()
		close(h.exited)
	}()
	s.mu.Lock()
	s.procs = append(s.procs, cmd)
	s.hubs = append(s.hubs, h)
	s.mu.Unlock()
	s.eventually("hub "+strconv.Itoa(port)+" to answer", 60*time.Second, func() bool {
		resp, err := http.Get(h.url() + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	return h
}

// killHubOnly SIGKILLs the hub process alone, as a crash or an OOM kill does:
// a host process it forked is reparented and carries on.
func (s *revokeScene) killHubOnly(h *hub) {
	_ = syscall.Kill(h.cmd.Process.Pid, syscall.SIGKILL)
	select {
	case <-h.exited:
	case <-time.After(30 * time.Second):
		s.t.Fatalf("hub %d did not die", h.port)
	}
}

func (s *revokeScene) do(method, base, path string, body any) response {
	s.t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return response{status: 0, body: err.Error()}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, body: string(data), servedBy: resp.Header.Get("X-Cloop-Served-By")}
}

func (s *revokeScene) eventually(what string, limit time.Duration, cond func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	s.t.Fatalf("timed out after %s waiting for %s", limit, what)
}

func (s *revokeScene) clusterStatus(h *hub) (clusterStatus, bool) {
	r := s.do(http.MethodGet, h.url(), "/api/cluster", nil)
	if r.status != http.StatusOK {
		return clusterStatus{}, false
	}
	var st clusterStatus
	return st, json.Unmarshal([]byte(r.body), &st) == nil
}

func (s *revokeScene) projectIndex(h *hub) int {
	s.t.Helper()
	r := s.do(http.MethodGet, h.url(), "/api/projects", nil)
	var out struct {
		Projects []struct {
			Path string `json:"path"`
		} `json:"projects"`
	}
	if err := json.Unmarshal([]byte(r.body), &out); err != nil {
		s.t.Fatalf("GET /api/projects: %v (%s)", err, r.body)
	}
	for i, p := range out.Projects {
		if p.Path == s.projDir {
			return i
		}
	}
	s.t.Fatalf("project %s is not listed: %s", s.projDir, r.body)
	return -1
}

// query reads one column of the first row of a control-plane query.
func (s *revokeScene) query(q string, args ...any) (string, bool) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(s.hubDir, ".cloop", "state.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return "", false
	}
	defer db.Close()
	var v sql.NullString
	if err := db.QueryRow(q, args...).Scan(&v); err != nil {
		return "", false
	}
	return v.String, true
}

func (s *revokeScene) projectFile(name string) string {
	b, _ := os.ReadFile(filepath.Join(s.projDir, ".cloop", name))
	return strings.TrimSpace(string(b))
}

// leaseOf returns the one lease a hub lists, with its first grant.
func (s *revokeScene) leaseOf(h *hub) (leaseID, grantID string) {
	s.t.Helper()
	var out struct {
		Leases []struct {
			ID        string `json:"id"`
			Materials []struct {
				GrantID string `json:"grant_id"`
			} `json:"materials"`
		} `json:"leases"`
	}
	s.eventually("the run's lease to be listed", 30*time.Second, func() bool {
		r := s.do(http.MethodGet, h.url(), "/api/leases", nil)
		if json.Unmarshal([]byte(r.body), &out) != nil {
			return false
		}
		return len(out.Leases) == 1 && len(out.Leases[0].Materials) > 0
	})
	return out.Leases[0].ID, out.Leases[0].Materials[0].GrantID
}

func (s *revokeScene) cleanup() {
	s.mu.Lock()
	procs := append([]*exec.Cmd(nil), s.procs...)
	hubs := append([]*hub(nil), s.hubs...)
	s.mu.Unlock()
	_ = os.WriteFile(filepath.Join(s.projDir, ".cloop", "release"), nil, 0o644)
	for _, p := range procs {
		if p.Process != nil {
			_ = syscall.Kill(-p.Process.Pid, syscall.SIGKILL)
		}
	}
	// What the workloads left: the containers of this executor, and any host
	// process still working in the project.
	if s.container {
		if out, err := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.executor="+revokeExecutorID).Output(); err == nil {
			for _, id := range strings.Fields(string(out)) {
				_ = exec.Command("docker", "rm", "-f", id).Run()
			}
		}
	}
	for _, pid := range processesIn(s.projDir) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	if s.t.Failed() {
		for _, h := range hubs {
			if data, err := os.ReadFile(h.log); err == nil {
				s.t.Logf("── hub %d log (tail) ──\n%s", h.port, tail(string(data), 60))
			}
		}
	}
	if os.Getenv(keepEnv) != "" {
		s.t.Logf("%s set: leaving %s", keepEnv, s.root)
		return
	}
	_ = os.RemoveAll(s.root)
}

// processesIn finds the processes whose working directory is under dir.
func processesIn(dir string) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cwd, err := os.Readlink(filepath.Join("/proc", e.Name(), "cwd"))
		if err == nil && (cwd == dir || strings.HasPrefix(cwd, dir+string(os.PathSeparator))) {
			out = append(out, pid)
		}
	}
	return out
}

// twoMembers starts the members and waits until each sees the other.
func (s *revokeScene) twoMembers() (a, b *hub) {
	a = s.startHub()
	b = s.startHub()
	s.eventually("the two members to see each other", 45*time.Second, func() bool {
		st, ok := s.clusterStatus(b)
		return ok && st.live() == 2
	})
	stA, _ := s.clusterStatus(a)
	a.id = stA.Self
	stB, _ := s.clusterStatus(b)
	b.id = stB.Self
	return a, b
}

// dispatchOn starts the project's run through h and waits for the workload
// to report its credential readable.
func (s *revokeScene) dispatchOn(h *hub) {
	s.t.Helper()
	idx := s.projectIndex(h)
	if r := s.do(http.MethodPost, h.url(), fmt.Sprintf("/api/run?project_idx=%d", idx), nil); r.status != http.StatusOK {
		s.t.Fatalf("POST /api/run on hub %d = %d: %s", h.port, r.status, r.body)
	}
	s.eventually("the workload to read its credential", 3*time.Minute, func() bool {
		return s.projectFile("cred-state") == "present"
	})
}

// revokeThroughSurvivor revokes the lease through b and checks the answer. It
// reports whether the revocation was recorded: it is, unless the survivor had
// already adopted the run and ended the lease — a host process's, whose files
// it wiped — in which case nothing is left to take over, and the answer must
// say the material is gone.
func (s *revokeScene) revokeThroughSurvivor(b *hub, leaseID string) bool {
	s.t.Helper()
	r := s.do(http.MethodPost, b.url(), "/api/leases/"+leaseID+"/revoke",
		map[string]string{"reason": "e2e: token leaked while its hub member was down"})
	if r.status != http.StatusOK && r.status != http.StatusAccepted {
		s.t.Fatalf("revoking the dead member's lease through the survivor = %d: %s — "+
			"before Task 20419 this was a 404 that recorded nothing", r.status, r.body)
	}
	var out struct {
		Recorded bool   `json:"recorded"`
		State    string `json:"state"`
	}
	_ = json.Unmarshal([]byte(r.body), &out)
	s.t.Logf("lease revocation through the survivor: %d, recorded %v, state %s", r.status, out.Recorded, out.State)
	if out.Recorded && out.State != "revoke_pending" && out.State != "revoked" {
		// Revoked once the survivor reached the workload; pending while the
		// dead member is not yet judged so. Unreachable told the operator the
		// revocation was lost on the dead member, which the record prevents.
		s.t.Fatalf("a recorded revocation reports %q: %s", out.State, r.body)
	}
	if !out.Recorded {
		if _, still := s.query(`SELECT holder FROM secret_leases WHERE lease_id = ?`, leaseID); still || out.State != "revoked" {
			s.t.Fatalf("the revocation was not recorded although the lease is still recorded, or the "+
				"material is not reported gone: %s", r.body)
		}
	}
	return out.Recorded
}

// assertNeverRestored waits for the revocation to be enforced and checks the
// survivor holds nothing of the lease.
func (s *revokeScene) assertNeverRestored(b *hub, leaseID string, recorded bool) {
	s.t.Helper()
	if recorded {
		s.eventually("the revocation to be enforced", 90*time.Second, func() bool {
			enforced, ok := s.query(`SELECT enforced_at FROM secret_lease_revocations WHERE lease_id = ? AND grant_id = ''`, leaseID)
			return ok && enforced != ""
		})
	}
	s.eventually("the revoked lease's record to be gone", 30*time.Second, func() bool {
		_, still := s.query(`SELECT holder FROM secret_leases WHERE lease_id = ?`, leaseID)
		return !still
	})
	r := s.do(http.MethodGet, b.url(), "/api/leases", nil)
	if strings.Contains(r.body, leaseID) {
		s.t.Fatalf("the survivor lists the revoked lease: %s", r.body)
	}
	// Never taken over, not even for a moment before something else took it
	// back: the trail holds no takeover of it. A container's adopter asks to
	// take the lease over, so when the revocation was recorded before the run
	// was adopted the trail holds the refusal. A host process's adopter never
	// asks: it wipes the files and retires the record, and the trail holds
	// the wipe.
	const takeover = "%taken over by the hub process that adopted its run%"
	if n, _ := s.query(`SELECT COUNT(*) FROM audit_events WHERE event_type = 'secret.renew'
		AND (entity_id = ? OR payload LIKE ?) AND payload LIKE ?`, leaseID, "%"+leaseID+"%", takeover); n != "0" {
		s.t.Fatalf("the revoked lease was taken over by the member adopting its run (%s takeover row(s))", n)
	}
	switch {
	case s.container && recorded:
		if n, _ := s.query(`SELECT COUNT(*) FROM audit_events WHERE event_type = 'secret.renew'
			AND (entity_id = ? OR payload LIKE ?) AND payload LIKE '%cannot be taken over%'`, leaseID, "%"+leaseID+"%"); n == "0" || n == "" {
			s.t.Error("the trail does not record the takeover of the revoked lease refused")
		}
	case !s.container:
		if n, _ := s.query(`SELECT COUNT(*) FROM audit_events WHERE event_type = 'secret.lease.sweep'
			AND json_extract(payload, '$.wiped') >= 1`); n == "0" || n == "" {
			s.t.Error("the trail does not record the dead member's lease directory wiped")
		}
	}
	if n, _ := s.query(`SELECT COUNT(*) FROM proxy_sessions WHERE lease_id = ? AND closed_at = ''`, leaseID); n != "" && n != "0" {
		s.t.Fatalf("%s proxy session(s) of the revoked lease are open", n)
	}
}

// revokeGrant revokes the grant through b and checks nothing still holds it.
func (s *revokeScene) revokeGrant(b *hub, grantID string) {
	s.t.Helper()
	r := s.do(http.MethodDelete, b.url(), "/api/grants/"+grantID, nil)
	if r.status != http.StatusOK {
		s.t.Fatalf("revoking the grant through the survivor = %d: %s", r.status, r.body)
	}
	var out struct {
		State string `json:"state"`
	}
	_ = json.Unmarshal([]byte(r.body), &out)
	if out.State != "revoked" {
		s.t.Fatalf("the grant revocation reports %q: something still holds the revoked lease's grant: %s", out.State, r.body)
	}
}

// TestARevokedLeaseOfADeadMembersContainerIsTakenBackNotRestored is the
// container scenario.
func TestARevokedLeaseOfADeadMembersContainerIsTakenBackNotRestored(t *testing.T) {
	s := newRevokeScene(t, true)
	s.setup()
	a, b := s.twoMembers()
	s.dispatchOn(a)
	leaseID, grantID := s.leaseOf(a)

	// Where the dead member staged the credential: its row says so.
	stage, ok := s.query(`SELECT json_extract(meta_json, '$.secret_stage') FROM executor_handles WHERE executor_id = ?`, revokeExecutorID)
	if !ok || stage == "" {
		t.Fatal("the container's row does not record where its credential files are staged")
	}
	var layout struct {
		Dirs []struct {
			Host string `json:"host"`
		} `json:"dirs"`
	}
	if err := json.Unmarshal([]byte(stage), &layout); err != nil || len(layout.Dirs) == 0 {
		t.Fatalf("staging record %q: %v", stage, err)
	}
	staged := layout.Dirs[0].Host
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("the staging directory %s is not on the host: %v", staged, err)
	}

	// The member holding the lease dies.
	s.killHubOnly(a)
	recorded := s.revokeThroughSurvivor(b, leaseID)

	// The credential is gone from the sandbox: it reports so, or the sandbox
	// itself is gone — a container is removed when its credential came with
	// an environment variable, which no revocation can take out of a running
	// process — and the staged copy on the host is wiped either way.
	s.eventually("the credential to be gone from the sandbox", 90*time.Second, func() bool {
		if _, err := os.Stat(staged); err == nil {
			return false
		}
		if s.projectFile("cred-state") == "gone" {
			return true
		}
		out, err := exec.Command("docker", "ps", "-q", "--filter", "label=cloop.executor="+revokeExecutorID).Output()
		return err == nil && strings.TrimSpace(string(out)) == ""
	})
	s.assertNeverRestored(b, leaseID, recorded)
	s.revokeGrant(b, grantID)
}

// TestADeadMembersHostLeaseDirectoryIsWipedAndNotRestored is the host-process
// scenario.
func TestADeadMembersHostLeaseDirectoryIsWipedAndNotRestored(t *testing.T) {
	s := newRevokeScene(t, false)
	s.setup()
	a, b := s.twoMembers()
	s.dispatchOn(a)
	leaseID, grantID := s.leaseOf(a)
	dir := s.projectFile("lease-dir")
	if !strings.HasPrefix(filepath.Base(dir), "cloop-lease-") {
		t.Fatalf("the host process reads its credential from %q, not a lease directory", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "github-token")); err != nil {
		t.Fatalf("the credential is not where the host process reads it: %v", err)
	}

	// The member that forked it dies; the host process does not.
	s.killHubOnly(a)
	if len(processesIn(s.projDir)) == 0 {
		t.Fatal("the host process died with its member; this scenario is about one that outlives it")
	}
	s.eventually("the dead member's lease directory to be wiped", 60*time.Second, func() bool {
		_, err := os.Stat(dir)
		return os.IsNotExist(err)
	})
	s.eventually("the host process to find its credential gone", 30*time.Second, func() bool {
		return s.projectFile("cred-state") == "gone"
	})
	recorded := s.revokeThroughSurvivor(b, leaseID)
	s.assertNeverRestored(b, leaseID, recorded)
	s.revokeGrant(b, grantID)
}
