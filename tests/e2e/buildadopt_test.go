package e2e_test

// A long-lived run adopts the hub's newly deployed build at a task boundary
// (Task 20389), for real.
//
// The deploy at :8888 replaces the hub's binary and keeps runs alive, so a run
// in auto-evolve kept executing the build it started with — 132 builds behind
// the hub, on 2026-10-06. This proves the remedy end to end, the way a deploy
// happens: real binaries of this tree stamped with different sequences, a
// token-protected test hub with its own HOME and CLOOP_HOME started from a path
// the test then overwrites (atomically, as `install` does), a run the hub
// starts on the host from that path, and a stand-in `claude` that records which
// binary its parent — the run — is executing and waits for the test to let each
// task finish.
//
//   - TestBuildAdoption/adopts: the binary at the path is replaced while task 1
//     runs and adoption is requested through the hub's API. The request waits
//     for the boundary; then the run re-executes itself: same pid, same start
//     time, /proc/<pid>/exe the new file, task 2 run by the new build, the live
//     log one stream across the exec, and the journal, the run-owner record and
//     the audit trail saying what happened.
//   - TestBuildAdoption/refusals: an older build, the same build, a build with
//     no sequence, a broken binary and a build whose schema is behind the
//     database are each refused with a journalled reason, and the run carries
//     on on its own build.
//   - TestBuildAdoption/parallel: a request filed while a two-task round runs
//     is acted on only once both tasks have finished, and before the third
//     starts.
//
// About a minute in all, most of it linking the three builds; needs bash.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"database/sql"

	_ "modernc.org/sqlite"
)

const adoptToken = "e2e-build-adopt-token"

// adoptStub stands in for Claude Code: it logs its task, its pid, its parent
// (the run) and the inode and path of the binary the run executes, waits for
// the test's release file for its task, and finishes the task.
const adoptStub = `#!/bin/bash
prompt=$(cat)
id=$(printf '%s\n' "$prompt" | sed -n 's/^\*\*Task \([0-9][0-9]*\): .*/\1/p' | head -1)
ino=$(stat -L -c %i /proc/$PPID/exe 2>/dev/null)
exe=$(readlink /proc/$PPID/exe 2>/dev/null)
echo "start $id $$ $PPID $ino $exe" >> "@LOG@"
for _ in $(seq 1 6000); do
  [ -e "@REL@/release-$id" ] && break
  sleep 0.1
done
echo "end $id" >> "@LOG@"
echo "stub claude: did task $id"
echo TASK_DONE
`

// goCaches are the toolchain's caches, read when the test binary starts —
// before TestMain moves HOME. A `go build` under the tests' HOME would find an
// empty build cache and an empty module cache there: it would compile the world
// and download every module, minutes of a package whose CI step has five.
var goCaches = func() []string {
	out, err := exec.Command("go", "env", "GOCACHE", "GOMODCACHE", "GOPATH").Output()
	if err != nil {
		return nil
	}
	v := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(v) != 3 {
		return nil
	}
	return []string{"GOCACHE=" + v[0], "GOMODCACHE=" + v[1], "GOPATH=" + v[2]}
}()

// stampedBuild links this tree with its version stamped as a build of main at
// sequence seq.
func stampedBuild(t *testing.T, dir, name string, seq int) string {
	t.Helper()
	repo := filepath.Dir(binaryPath(t))
	out := filepath.Join(dir, name)
	letter := strings.Repeat(string(rune('a'+seq%26)), 40)
	const pkg = "github.com/blechschmidt/cloop/pkg/version"
	ld := fmt.Sprintf("-X %s.Version=dev+g%s -X %s.Sequence=%d -X %s.Commit=%s", pkg, letter[:7], pkg, seq, pkg, letter)
	cmd := exec.Command("go", "build", "-ldflags", ld, "-o", out, ".")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), goCaches...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", name, err, b)
	}
	return out
}

type adoptScene struct {
	t      *testing.T
	root   string
	proj   string
	bin    string // the path the hub starts runs from, which the test replaces
	rel    string
	log    string
	env    []string
	base   string
	hub    *exec.Cmd
	hubLog *strings.Builder
}

func newAdoptScene(t *testing.T, hubBuild string, tasks int) *adoptScene {
	t.Helper()
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	s := &adoptScene{t: t, root: root, proj: filepath.Join(root, "proj"), bin: filepath.Join(root, "bin", "cloop"),
		rel: filepath.Join(root, "release"), log: filepath.Join(root, "claude.log")}
	t.Cleanup(s.teardown)
	home := filepath.Join(root, "home")
	stubDir := filepath.Join(root, "stub")
	for _, d := range []string{s.proj, filepath.Dir(s.bin), s.rel, home, stubDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(stubDir, "claude"),
		strings.NewReplacer("@LOG@", s.log, "@REL@", s.rel).Replace(adoptStub))
	if err := os.Chmod(filepath.Join(stubDir, "claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.env = withPath(append(withoutCloopEnv(os.Environ()),
		"HOME="+home,
		"CLOOP_HOME="+filepath.Join(home, ".cloop"),
		"CLOOP_UI_TOKEN="+adoptToken,
		"NO_COLOR=1",
	), stubDir)

	s.place(hubBuild)
	s.cloop("init", "--provider", "claudecode", "--skip-clarify", "Adopt a newer build")
	for i := 1; i <= tasks; i++ {
		s.cloop("task", "add", fmt.Sprintf("Step %d", i), "--no-ai", "--auto")
	}

	port := strconv.Itoa(freePort(t))
	s.base = "http://127.0.0.1:" + port
	cmd := exec.Command(s.bin, "ui", "--port", port, "--no-browser")
	cmd.Dir = s.proj
	cmd.Env = s.env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	s.hubLog = &strings.Builder{}
	w := &syncWriter{w: s.hubLog}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.hub = cmd
	s.waitFor("the hub to answer", 60*time.Second, func() bool {
		resp, err := http.Get(s.base + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	return s
}

// place puts a copy of src at the path runs start from, replacing what was
// there with a new file in one rename — as a deploy does.
func (s *adoptScene) place(src string) {
	s.t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		s.t.Fatal(err)
	}
	s.placeBytes(data)
}

func (s *adoptScene) placeBytes(data []byte) {
	s.t.Helper()
	tmp := s.bin + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.Rename(tmp, s.bin); err != nil {
		s.t.Fatal(err)
	}
}

func (s *adoptScene) inode() uint64 {
	s.t.Helper()
	info, err := os.Stat(s.bin)
	if err != nil {
		s.t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

func (s *adoptScene) cloop(args ...string) string {
	s.t.Helper()
	cmd := exec.Command(s.bin, args...)
	cmd.Dir = s.proj
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.t.Fatalf("cloop %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (s *adoptScene) call(method, path string, body any) (int, map[string]any) {
	s.t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adoptToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (s *adoptScene) waitFor(what string, timeout time.Duration, cond func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out after %s waiting for %s\nstub log:\n%s", timeout, what, s.stubLog())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *adoptScene) stubLog() string {
	data, _ := os.ReadFile(s.log)
	return string(data)
}

// stubStart is one task's harness start, as the stub logged it.
type stubStart struct {
	task, pid, run int
	ino            uint64
	exe            string
}

func (s *adoptScene) starts() map[int]stubStart {
	out := map[int]stubStart{}
	for _, line := range strings.Split(s.stubLog(), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "start" {
			continue
		}
		var st stubStart
		st.task, _ = strconv.Atoi(f[1])
		st.pid, _ = strconv.Atoi(f[2])
		st.run, _ = strconv.Atoi(f[3])
		st.ino, _ = strconv.ParseUint(f[4], 10, 64)
		st.exe = strings.Join(f[5:], " ")
		out[st.task] = st
	}
	return out
}

func (s *adoptScene) waitStart(task int) stubStart {
	s.t.Helper()
	var st stubStart
	s.waitFor(fmt.Sprintf("task %d's harness to start", task), 90*time.Second, func() bool {
		var ok bool
		st, ok = s.starts()[task]
		return ok
	})
	return st
}

func (s *adoptScene) release(task int) {
	s.t.Helper()
	writeTestFile(s.t, filepath.Join(s.rel, "release-"+strconv.Itoa(task)), "go\n")
}

func (s *adoptScene) startRun() {
	s.t.Helper()
	if code, body := s.call("POST", "/api/run", map[string]any{}); code != http.StatusOK || body["ok"] != true {
		s.t.Fatalf("start the run = %d %v\nhub log:\n%s", code, body, tail(s.hubLog.String(), 4000))
	}
}

func (s *adoptScene) requestAdoption() map[string]any {
	s.t.Helper()
	code, body := s.call("POST", "/api/run/adopt-build", map[string]any{})
	if code != http.StatusOK || body["ok"] != true {
		s.t.Fatalf("request adoption = %d %v", code, body)
	}
	return body
}

// waitRunEnded waits for pid to be gone and the project to say so.
func (s *adoptScene) waitRunEnded(pid int) {
	s.t.Helper()
	s.waitFor("the run to end", 90*time.Second, func() bool {
		return syscall.Kill(pid, 0) != nil
	})
}

func (s *adoptScene) db() *sql.DB {
	s.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(s.proj, ".cloop", "state.db")+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { _ = db.Close() })
	return db
}

func (s *adoptScene) events(typ string) []string {
	s.t.Helper()
	rows, err := s.db().Query(`SELECT message FROM events WHERE type = ? ORDER BY id`, typ)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		_ = rows.Scan(&m)
		out = append(out, m)
	}
	return out
}

func (s *adoptScene) meta(key string) string {
	s.t.Helper()
	var v string
	_ = s.db().QueryRow(`SELECT value FROM metadata WHERE key = ?`, key).Scan(&v)
	return v
}

// runClaim is the hub's claim on the project's run: who holds it and since
// when.
func (s *adoptScene) runClaim() string {
	s.t.Helper()
	var instance string
	var claimed int64
	err := s.db().QueryRow(`SELECT instance_id, claimed_ms FROM hub_owners WHERE kind = 'run'`).Scan(&instance, &claimed)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s@%d", instance, claimed)
}

func (s *adoptScene) taskStatuses() map[string]string {
	s.t.Helper()
	rows, err := s.db().Query(`SELECT title, status FROM plan_tasks`)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var title, st string
		_ = rows.Scan(&title, &st)
		out[title] = st
	}
	return out
}

func (s *adoptScene) liveLog() string {
	s.t.Helper()
	_, body := s.call("GET", "/api/livelog", nil)
	raw, _ := body["lines"].([]any)
	var b strings.Builder
	for _, l := range raw {
		b.WriteString(fmt.Sprint(l))
	}
	return b.String()
}

// procStart is /proc/<pid>/stat field 22.
func procStart(t *testing.T, pid int) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	line := string(raw)
	f := strings.Fields(line[strings.LastIndexByte(line, ')')+1:])
	return f[19]
}

func (s *adoptScene) teardown() {
	for _, f := range []string{"1", "2", "3", "4", "5", "6", "7"} {
		_ = os.WriteFile(filepath.Join(s.rel, "release-"+f), []byte("go\n"), 0o644)
	}
	runs := map[int]bool{}
	for _, st := range s.starts() {
		runs[st.run] = true
	}
	if s.hub != nil && s.hub.Process != nil {
		_ = syscall.Kill(-s.hub.Process.Pid, syscall.SIGKILL)
		_ = s.hub.Wait()
	}
	for pid := range runs {
		if pid > 1 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	if s.t.Failed() {
		s.t.Logf("hub log:\n%s", tail(s.hubLog.String(), 8000))
	}
}

func TestBuildAdoption(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for the stand-in harness")
	}
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("adoption needs procfs")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go toolchain is needed to stamp builds")
	}
	builds := t.TempDir()
	older := stampedBuild(t, builds, "cloop-100", 100)
	newer := stampedBuild(t, builds, "cloop-101", 101)
	newest := stampedBuild(t, builds, "cloop-102", 102)

	t.Run("adopts", func(t *testing.T) {
		s := newAdoptScene(t, newer, 2) // the hub runs 101 ...
		s.place(older)                  // ... and starts the run from the path, now 100
		oldIno := s.inode()
		s.startRun()
		first := s.waitStart(1)
		run := first.run
		ticks := procStart(t, run)
		if first.ino != oldIno {
			t.Fatalf("task 1 ran under inode %d, want the older build's %d", first.ino, oldIno)
		}
		// What the dashboard shows while the run lags.
		_, st := s.call("GET", "/api/state", nil)
		rb, _ := st["run_build"].(map[string]any)
		if rb == nil || rb["live"] != true || rb["behind"] != float64(1) || rb["adoptable"] != true {
			t.Fatalf("/api/state run_build = %v", st["run_build"])
		}

		claim := s.runClaim()
		if claim == "" {
			t.Fatal("the hub holds no claim on the run")
		}

		// The deploy, then the request, both while task 1 is in flight.
		s.place(newer)
		newIno := s.inode()
		s.requestAdoption()
		time.Sleep(time.Second)
		if exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", run)); !strings.HasSuffix(exe, "(deleted)") {
			t.Fatalf("the run re-executed in the middle of task 1 (exe %q)", exe)
		}
		s.release(1)

		second := s.waitStart(2)
		if second.run != run {
			t.Fatalf("task 2 ran under pid %d, task 1 under %d: the run did not keep its process", second.run, run)
		}
		if got := procStart(t, run); got != ticks {
			t.Fatalf("the run's start time changed across the exec: %s → %s", ticks, got)
		}
		if second.ino != newIno || second.exe != s.bin {
			t.Fatalf("task 2 ran under %s (inode %d), want %s (inode %d)", second.exe, second.ino, s.bin, newIno)
		}
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", run))
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", run))
		if exe != s.bin || strings.TrimSpace(string(comm)) != "cloop" {
			t.Fatalf("after the exec: exe %q, comm %q", exe, comm)
		}
		// The hub never saw the run stop: its claim is the one it took at
		// dispatch, and it still streams the run.
		if got := s.runClaim(); got != claim {
			t.Fatalf("the hub's run claim changed across the exec:\n before %s\n after  %s", claim, got)
		}
		if _, body := s.call("GET", "/api/livelog", nil); body["running"] != true {
			t.Fatalf("the hub no longer tracks the run after the exec: %v", body["running"])
		}
		live := s.liveLog()
		if !strings.Contains(live, "Adopting dev+g") {
			t.Fatalf("the old image's last line is not in the live log:\n%s", tail(live, 3000))
		}
		if !strings.Contains(live, "Run re-executed") {
			t.Fatalf("the new image's output did not reach the same live log:\n%s", tail(live, 3000))
		}
		s.release(2)
		s.waitRunEnded(run)

		if got := s.taskStatuses(); got["Step 1"] != "done" || got["Step 2"] != "done" {
			t.Fatalf("tasks = %v", got)
		}
		re := s.events("run_reexecuted")
		if len(re) != 1 || !strings.Contains(re[0], "→") || !strings.Contains(re[0], "requested by") {
			t.Fatalf("run_reexecuted rows = %v", re)
		}
		var owner struct {
			PID      int                     `json:"pid"`
			Reexecs  int                     `json:"reexecs"`
			Build    struct{ Sequence int }  `json:"build"`
			Previous *struct{ Sequence int } `json:"previous"`
		}
		if err := json.Unmarshal([]byte(s.meta("run_owner")), &owner); err != nil {
			t.Fatal(err)
		}
		if owner.PID != run || owner.Reexecs != 1 || owner.Build.Sequence != 101 || owner.Previous == nil || owner.Previous.Sequence != 100 {
			t.Fatalf("run owner = %+v", owner)
		}
		var audits int
		_ = s.db().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type IN ('run.adopt_requested','run.reexecuted')`).Scan(&audits)
		if audits != 2 {
			t.Fatalf("audit rows for the request and the re-exec = %d, want 2", audits)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		s := newAdoptScene(t, newest, 6) // the hub runs 102 ...
		s.place(newer)                   // ... the run starts as 101
		s.startRun()
		run := s.waitStart(1).run
		runIno := s.inode()
		newestBytes, err := os.ReadFile(newest)
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name   string
			place  func()
			reason string
		}{
			{"older", func() { s.place(older) }, "older than this run's build"},
			{"equal", func() { s.place(newer) }, "same sequence"},
			{"no sequence", func() { s.place(binaryPath(t)) }, "carries no sequence"},
			{"broken", func() { s.placeBytes(newestBytes[:1<<20]) }, "version --json"},
			{"schema behind", func() {
				s.place(newest)
				db, err := sql.Open("sqlite", "file:"+filepath.Join(s.proj, ".cloop", "state.db")+"?_pragma=busy_timeout(10000)")
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at, name, applied_by, compat)
					SELECT MAX(version)+1, ?, 'future_test.sql', 'e2e', 'additive' FROM schema_migrations`,
					time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}, "behind the project database"},
		}
		for i, c := range cases {
			task := i + 1
			if i > 0 {
				if st := s.waitStart(task); st.run != run || st.ino != runIno {
					t.Fatalf("%s: task %d ran under pid %d inode %d, want the unchanged run %d inode %d",
						c.name, task, st.run, st.ino, run, runIno)
				}
			}
			c.place()
			s.requestAdoption()
			s.release(task)
			s.waitFor(c.name+" to be refused", 60*time.Second, func() bool { return len(s.events("run_adoption")) >= task })
			if got := s.events("run_adoption")[task-1]; !strings.Contains(got, c.reason) {
				t.Fatalf("%s: refusal = %q; want it to mention %q", c.name, got, c.reason)
			}
		}
		last := s.waitStart(6)
		if last.run != run || last.ino != runIno {
			t.Fatalf("task 6 ran under pid %d inode %d after five refusals", last.run, last.ino)
		}
		s.release(6)
		s.waitRunEnded(run)
		if re := s.events("run_reexecuted"); len(re) != 0 {
			t.Fatalf("a refused build was adopted: %v", re)
		}
		for title, st := range s.taskStatuses() {
			if st != "done" {
				t.Errorf("%s = %s", title, st)
			}
		}
	})

	t.Run("parallel", func(t *testing.T) {
		s := newAdoptScene(t, newer, 3)
		if code, body := s.call("POST", "/api/options/max-parallel", map[string]any{"value": 2}); code != http.StatusOK {
			t.Fatalf("max-parallel = %d %v", code, body)
		}
		if code, body := s.call("POST", "/api/options/toggle", map[string]any{"flag": "parallel", "value": true}); code != http.StatusOK {
			t.Fatalf("parallel = %d %v", code, body)
		}
		s.place(older)
		oldIno := s.inode()
		s.startRun()
		one, two := s.waitStart(1), s.waitStart(2)
		run := one.run
		if two.run != run {
			t.Fatalf("tasks 1 and 2 under pids %d and %d", one.run, two.run)
		}
		s.place(newer)
		newIno := s.inode()
		s.requestAdoption()
		s.release(2)
		s.waitFor("task 2 to finish", 60*time.Second, func() bool { return strings.Contains(s.stubLog(), "end 2") })
		// Task 1 is still running: the run neither moves nor dispatches.
		time.Sleep(1500 * time.Millisecond)
		if _, started := s.starts()[3]; started {
			t.Fatal("task 3 was dispatched while an adoption was pending")
		}
		if exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", run)); !strings.HasSuffix(exe, "(deleted)") {
			t.Fatalf("the run re-executed before its round drained (exe %q)", exe)
		}
		s.release(1)
		three := s.waitStart(3)
		if three.run != run || three.ino != newIno || three.ino == oldIno {
			t.Fatalf("task 3 ran under pid %d inode %d; want pid %d on the new build's inode %d", three.run, three.ino, run, newIno)
		}
		s.release(3)
		s.waitRunEnded(run)
		if re := s.events("run_reexecuted"); len(re) != 1 {
			t.Fatalf("run_reexecuted rows = %v", re)
		}
	})
}
