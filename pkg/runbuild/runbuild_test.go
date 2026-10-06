package runbuild

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as the "cloop" the candidate tests open and run.
// fakeCloop copies it to a temp path with a ".fake" file beside it; started
// from there it never runs tests, and takes what to do from files beside it,
// since the probe passes it almost no environment:
//
//	<exe>.report  what `version --json` prints
//	<exe>.sleep   how long it waits first
//	<exe>.accept  the arguments it accepts before --help
//	<exe>.env     where `version --json` records the environment it got
//
// In execChildEnv mode the test binary is the process that adopts; "adopted"
// is the new image reporting who it is.
const (
	execChildEnv  = "RUNBUILD_TEST_EXEC_CANDIDATE"
	execReportEnv = "RUNBUILD_TEST_EXEC_REPORT"
)

func TestMain(m *testing.M) {
	exe, err := os.Executable()
	if err == nil {
		if _, err := os.Stat(exe + ".fake"); err == nil {
			os.Exit(fakeMain(exe))
		}
	}
	if path := os.Getenv(execChildEnv); path != "" {
		// The old image: record who it is, then adopt path.
		os.Exit(runExecChild(path))
	}
	// A copy of this binary must never run the tests: every test starts more
	// copies, and a copy that ran them would start copies of its own, without
	// end. Only the binary go test built — named <pkg>.test — runs them.
	if !strings.HasSuffix(filepath.Base(exe), ".test") {
		fmt.Fprintf(os.Stderr, "runbuild tests: %s is not the test binary; not running tests\n", exe)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func fakeMain(exe string) int {
	args := os.Args[1:]
	switch {
	case len(args) == 2 && args[0] == "version" && args[1] == "--json":
		if raw, err := os.ReadFile(exe + ".sleep"); err == nil {
			if d, err := time.ParseDuration(strings.TrimSpace(string(raw))); err == nil {
				time.Sleep(d)
			}
		}
		_ = os.WriteFile(exe+".env", []byte(strings.Join(os.Environ(), "\n")), 0o600)
		report, _ := os.ReadFile(exe + ".report")
		fmt.Println(string(report))
		return 0
	case len(args) > 0 && args[len(args)-1] == "--help":
		raw, _ := os.ReadFile(exe + ".accept")
		known := map[string]bool{}
		for _, a := range strings.Fields(string(raw)) {
			known[a] = true
		}
		for _, a := range args[:len(args)-1] {
			if !known[a] {
				fmt.Fprintf(os.Stderr, "Error: unknown flag: %s\nUsage: ...\n", a)
				return 1
			}
		}
		fmt.Println("Usage: cloop run [flags]")
		return 0
	case len(args) == 1 && args[0] == "adopted":
		// The new image: say who this process is now.
		RestoreComm(os.Getenv("RUNBUILD_TEST_ARGV0"))
		id, err := SelfIdent()
		exePath, _ := os.Readlink("/proc/self/exe")
		comm, _ := os.ReadFile("/proc/self/comm")
		rep := map[string]any{"pid": id.PID, "ticks": id.StartTicks, "exe": exePath,
			"comm": strings.TrimSpace(string(comm)), "err": fmt.Sprint(err)}
		data, _ := json.Marshal(rep)
		_ = os.WriteFile(os.Getenv(execReportEnv), data, 0o600)
		return 0
	}
	fmt.Fprintf(os.Stderr, "fake cloop: unexpected arguments %q\n", args)
	return 2
}

func runExecChild(path string) int {
	id, err := SelfIdent()
	if err != nil {
		fmt.Fprintln(os.Stderr, "self ident:", err)
		return 2
	}
	fmt.Printf("before %d %d\n", id.PID, id.StartTicks)
	c, err := Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		return 3
	}
	env := append(withoutEnv(os.Environ(), execChildEnv), "RUNBUILD_TEST_ARGV0="+path)
	err = Exec(c, []string{path, "adopted"}, env)
	fmt.Fprintln(os.Stderr, "exec returned:", err)
	return 4
}

func withoutEnv(env []string, key string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// fakeCloop copies the test binary to a temp path, where it is a different
// file from the one running and answers `version --json` with report.
func fakeCloop(t *testing.T, report string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "cloop")
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{".fake": "", ".report": report} {
		if err := os.WriteFile(dst+name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func fakeSet(t *testing.T, fake, what, body string) {
	t.Helper()
	if err := os.WriteFile(fake+what, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBehind(t *testing.T) {
	cases := []struct {
		run, ref Build
		n        int
		ok       bool
		phrase   string
	}{
		{Build{Version: "dev+gaaaaaaa", Sequence: 831}, Build{Version: "dev+gbbbbbbb", Sequence: 963}, 132, true, "132 builds behind this hub"},
		{Build{Sequence: 962}, Build{Sequence: 963}, 1, true, "1 build behind this hub"},
		{Build{Sequence: 963}, Build{Sequence: 963}, 0, true, "level with this hub"},
		{Build{Sequence: 970}, Build{Sequence: 963}, 0, true, "7 builds ahead of this hub"},
		{Build{Version: "dev+g1", Commit: "abc"}, Build{Version: "dev+g1", Commit: "ABC"}, 0, true, "level with this hub"},
		{Build{Version: "dev+gaaaaaaa"}, Build{Version: "dev+gbbbbbbb", Sequence: 9}, 0, false, "not comparable with this hub (dev+gbbbbbbb)"},
		{Build{Version: "dev"}, Build{Version: "dev"}, 0, false, "not comparable with this hub (dev)"},
		{Build{Version: "v0.0.4"}, Build{Version: "v0.0.4"}, 0, true, "level with this hub"},
	}
	for i, c := range cases {
		n, ok := Behind(c.run, c.ref)
		if n != c.n || ok != c.ok {
			t.Errorf("%d: Behind = %d, %v; want %d, %v", i, n, ok, c.n, c.ok)
		}
		if got := BehindPhrase(c.run, c.ref, "this hub"); got != c.phrase {
			t.Errorf("%d: phrase = %q; want %q", i, got, c.phrase)
		}
	}
}

func TestParseStatReadsPastAHostileCommand(t *testing.T) {
	line := "4242 (evil ) 0 R 1 2 3) S 77 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10"
	st, err := parseStat(line)
	if err != nil {
		t.Fatal(err)
	}
	if st.state != "S" || st.ppid != 77 || st.startTicks != 987654 {
		t.Fatalf("parsed %+v", st)
	}
	if _, err := parseStat("garbage"); err == nil {
		t.Fatal("a line without a command field parsed")
	}
}

func TestIdentityOfThisAndOfAnEndedProcess(t *testing.T) {
	self, err := SelfIdent()
	if err != nil {
		t.Skipf("no procfs here: %v", err)
	}
	if running, known := Running(self); !running || !known {
		t.Fatalf("this process reads as running=%v known=%v", running, known)
	}
	other := self
	other.StartTicks++
	if running, _ := Running(other); running {
		t.Fatal("a different start time was accepted as the same process")
	}
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	gone := Ident{PID: cmd.Process.Pid, StartTicks: 1, BootID: self.BootID}
	if running, known := Running(gone); running || !known {
		t.Fatalf("an exited process reads as running=%v known=%v", running, known)
	}
}

func TestLiveChildrenSeesARunningChildAndNotAReapedOne(t *testing.T) {
	if _, err := SelfIdent(); err != nil {
		t.Skipf("no procfs here: %v", err)
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	kids, err := LiveChildren()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range kids {
		found = found || k.PID == cmd.Process.Pid
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if !found {
		t.Fatalf("the running child %d is not among %v", cmd.Process.Pid, kids)
	}
	kids, _ = LiveChildren()
	for _, k := range kids {
		if k.PID == cmd.Process.Pid {
			t.Fatalf("the reaped child %d is still listed", k.PID)
		}
	}
}

func TestStartPathFollowsArgv0WhileItIsThisBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "cloop")
	if err := os.Symlink(self, link); err != nil {
		t.Fatal(err)
	}
	got, err := resolveStartPath([]string{link}, os.Getwd, os.Stat, exec.LookPath)
	if err != nil || got != link {
		t.Fatalf("absolute argv[0] through a symlink: %q, %v; want %q", got, err, link)
	}
	wd := func() (string, error) { return dir, nil }
	if got, _ := resolveStartPath([]string{"./cloop"}, wd, os.Stat, exec.LookPath); got != link {
		t.Fatalf("relative argv[0]: %q; want %q", got, link)
	}
	look := func(string) (string, error) { return link, nil }
	if got, _ := resolveStartPath([]string{"cloop"}, wd, os.Stat, look); got != link {
		t.Fatalf("argv[0] from PATH: %q; want %q", got, link)
	}
	// An argv[0] that is some other file is not where this binary came from.
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, _ := resolveStartPath([]string{other}, wd, os.Stat, look); got != self {
		t.Fatalf("argv[0] naming another file: %q; want the executable %q", got, self)
	}
}

func TestParseReport(t *testing.T) {
	b, err := ParseReport([]byte(`{"version":"dev+g1234567","commit":"1234567890123456789012345678901234567890","sequence":964,"schema":59,"protocol":18}` + "\n"))
	if err != nil || b.Sequence != 964 || b.Schema != 59 || b.Version != "dev+g1234567" {
		t.Fatalf("ParseReport = %+v, %v", b, err)
	}
	for _, bad := range []string{"", "cloop dev\n", `{"sequence":5}`, `{"version":"x","sequence":-1}`} {
		if _, err := ParseReport([]byte(bad)); err == nil {
			t.Errorf("ParseReport(%q) accepted it", bad)
		}
	}
}

func TestJudge(t *testing.T) {
	self := Build{Version: "dev+gaaaaaaa", Sequence: 100, Schema: 59}
	ok := Build{Version: "dev+gbbbbbbb", Sequence: 101, Schema: 59}
	if err := Judge(self, ok, 59); err != nil {
		t.Fatalf("a newer build with the same schema was refused: %v", err)
	}
	if err := Judge(self, Build{Version: "v", Sequence: 101, Schema: 60}, 59); err != nil {
		t.Fatalf("a newer build with a newer schema was refused: %v", err)
	}
	cases := map[string]struct {
		self, cand Build
		db         int
		want       string
	}{
		"older":           {self, Build{Version: "o", Sequence: 99, Schema: 59}, 59, "older"},
		"equal":           {self, Build{Version: "e", Sequence: 100, Schema: 59}, 59, "same sequence"},
		"missing":         {self, Build{Version: "m", Schema: 59}, 59, "carries no sequence"},
		"no schema":       {self, Build{Version: "n", Sequence: 101}, 59, "does not report the schema"},
		"schema behind":   {self, Build{Version: "s", Sequence: 101, Schema: 58}, 59, "behind the project database"},
		"unsequenced run": {Build{Version: "dev+gccccccc"}, ok, 59, "this run's build"},
	}
	for name, c := range cases {
		err := Judge(c.self, c.cand, c.db)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Judge = %v; want a refusal mentioning %q", name, err, c.want)
		}
	}
}

func TestOpenRefusesWhatIsNotAnInstalledBinary(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	noexec := filepath.Join(dir, "noexec")
	if err := os.WriteFile(noexec, []byte("\x7fELF"), 0o644); err != nil {
		t.Fatal(err)
	}
	loose := fakeCloop(t, "{}")
	if err := os.Chmod(loose, 0o775); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	for path, want := range map[string]string{
		dir:                           "not a regular file",
		script:                        "not an ELF executable",
		noexec:                        "not executable",
		loose:                         "writable by its group",
		filepath.Join(dir, "missing"): "no such file",
	} {
		c, err := Open(path)
		if err == nil {
			_ = c.Close()
			t.Errorf("Open(%s) accepted it", path)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Open(%s) = %v; want %q", path, err, want)
		}
	}
	if _, err := Open(self); !errors.Is(err, ErrSameBinary) {
		t.Errorf("Open(the running binary) = %v; want ErrSameBinary", err)
	}
}

func TestProbeRunsTheHeldFileNotThePath(t *testing.T) {
	path := fakeCloop(t, `{"version":"dev+gbbbbbbb","sequence":101,"schema":59}`)
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Replace the path: the probe must still ask the file that was opened.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho '{\"version\":\"impostor\"}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := c.Probe(context.Background(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != "dev+gbbbbbbb" || b.Sequence != 101 || b.Schema != 59 {
		t.Fatalf("probe = %+v", b)
	}
}

func TestProbeGivesUpOnABinaryThatDoesNotAnswer(t *testing.T) {
	path := fakeCloop(t, `{"version":"slow","sequence":101,"schema":59}`)
	fakeSet(t, path, ".sleep", "30s")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_, err = c.Probe(context.Background(), 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("probe of a hung binary = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("the probe took %s to give up", time.Since(start))
	}
}

func TestProbeRefusesABinaryThatIsNotCloop(t *testing.T) {
	path := fakeCloop(t, "not json")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Probe(context.Background(), 30*time.Second); err == nil {
		t.Fatal("a binary printing no report was accepted")
	}
}

// TestExecKeepsTheProcess adopts for real, in a child: the child records its
// pid and start time, opens a copy of the test binary and executes it; the new
// image reports who it is.
func TestExecKeepsTheProcess(t *testing.T) {
	if !Supported {
		t.Skip("adoption needs Linux")
	}
	if _, err := SelfIdent(); err != nil {
		t.Skipf("no procfs here: %v", err)
	}
	cand := fakeCloop(t, "{}")
	report := filepath.Join(t.TempDir(), "report.json")
	self, _ := os.Executable()
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), execChildEnv+"="+cand, execReportEnv+"="+report)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("child: %v\n%s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	var pid int
	var ticks uint64
	if _, err := fmt.Sscanf(string(out), "before %d %d", &pid, &ticks); err != nil {
		t.Fatalf("child said %q: %v", out, err)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("the new image wrote no report: %v", err)
	}
	var got struct {
		PID   int    `json:"pid"`
		Ticks uint64 `json:"ticks"`
		Exe   string `json:"exe"`
		Comm  string `json:"comm"`
		Err   string `json:"err"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.PID != pid || got.Ticks != ticks || got.Err != "<nil>" {
		t.Fatalf("after the exec: pid %d ticks %d (%s); before: pid %d ticks %d", got.PID, got.Ticks, got.Err, pid, ticks)
	}
	if got.Exe != cand {
		t.Fatalf("/proc/<pid>/exe = %q; want the adopted file %q", got.Exe, cand)
	}
	if got.Comm != "cloop" {
		t.Fatalf("comm = %q after RestoreComm; want %q", got.Comm, "cloop")
	}
}

func TestHandoffIsSingleUseAndBoundToItsProcess(t *testing.T) {
	self, err := SelfIdent()
	if err != nil {
		t.Skipf("no procfs here: %v", err)
	}
	dir := filepath.Join(t.TempDir(), ".cloop")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := HandoffPath(dir, self.PID)
	h := Handoff{Run: self, Reason: "requested by alice", RunID: "run_1", ConsecutiveErrors: 2,
		ConsecutiveEmptyEvolves: 1, EvolveStep: 7, From: Build{Version: "a", Sequence: 1},
		To: Build{Version: "b", Sequence: 2, Schema: 59}, Exe: "/usr/local/bin/cloop"}
	if err := WriteHandoff(path, h); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("handoff file: %v, mode %v", err, info.Mode())
	}
	got, err := TakeHandoff(path, self, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.RunID != "run_1" || got.ConsecutiveErrors != 2 || got.To.Sequence != 2 || got.Format != HandoffFormat {
		t.Fatalf("round trip = %+v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the handoff survived being taken: %v", err)
	}

	other := self
	other.PID++
	if err := WriteHandoff(path, Handoff{Run: other}); err != nil {
		t.Fatal(err)
	}
	if _, err := TakeHandoff(path, self, time.Now()); err == nil || !strings.Contains(err.Error(), "pid "+strconv.Itoa(other.PID)) {
		t.Fatalf("another process's handoff = %v", err)
	}
	if err := WriteHandoff(path, Handoff{Run: self, WrittenAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := TakeHandoff(path, self, time.Now()); err == nil {
		t.Fatal("an hour-old handoff was taken")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a refused handoff was left behind")
	}
}

func TestRequestIsForOneProcess(t *testing.T) {
	id := Ident{PID: 10, StartTicks: 99, BootID: "b"}
	r := &Request{Run: id}
	if !r.For(id) {
		t.Fatal("a request did not match its own run")
	}
	later := id
	later.StartTicks = 100
	if r.For(later) || (*Request)(nil).For(id) || (&Request{}).For(Ident{}) {
		t.Fatal("a request matched a process it was not for")
	}
}

func TestAssess(t *testing.T) {
	self, err := SelfIdent()
	if err != nil {
		t.Skipf("no procfs here: %v", err)
	}
	o := &Owner{Ident: self, Host: Hostname(), Build: Build{Version: "dev+gaaaaaaa", Sequence: 831},
		Executor: "localprocess", Adoptable: true, Reexecs: 1, Previous: &Build{Version: "old", Sequence: 800}}
	st := Assess(o, Build{Version: "dev+gbbbbbbb", Sequence: 963})
	if !st.Live || !st.LiveKnown || st.Behind != 132 || !st.Comparable || !st.Adoptable || st.Previous.Sequence != 800 {
		t.Fatalf("Assess = %+v", st)
	}
	o.Host = "elsewhere.example"
	if st := Assess(o, Build{}); st.LiveKnown {
		t.Fatal("a run on another host was judged from here")
	}
	if Assess(nil, Build{}) != nil {
		t.Fatal("no record assessed as something")
	}
}

// CheckArgs parses the run's own command line with the new build: a flag it
// dropped is a refusal, not a run that dies the moment it is re-executed.
func TestCheckArgsAsksTheNewBuildToParseTheCommandLine(t *testing.T) {
	path := fakeCloop(t, "{}")
	fakeSet(t, path, ".accept", "run --follow-builds")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.CheckArgs(context.Background(), 30*time.Second, []string{"run", "--follow-builds"}); err != nil {
		t.Fatalf("a command line the build accepts: %v", err)
	}
	err = c.CheckArgs(context.Background(), 30*time.Second, []string{"run", "--gone"})
	if err == nil || !strings.Contains(err.Error(), "unknown flag: --gone") {
		t.Fatalf("CheckArgs(--gone) = %v", err)
	}
}

// The probe runs a binary nothing has vouched for yet: it gets none of the
// run's environment, which carries the run's credentials.
func TestProbeGetsNoneOfTheRunsEnvironment(t *testing.T) {
	path := fakeCloop(t, `{"version":"dev+gbbbbbbb","sequence":101,"schema":59}`)
	t.Setenv("RUNBUILD_TEST_SECRET", "s3cr3t")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Probe(context.Background(), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(path + ".env")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(env), "s3cr3t") {
		t.Fatalf("the probe saw the run's environment:\n%s", env)
	}
}

func TestOpenDoesNotBlockOnAFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "cloop")
	if err := syscall.Mkfifo(fifo, 0o755); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		c, err := Open(fifo)
		if err == nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("Open(fifo) = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Open blocked on a FIFO planted at the start path")
	}
}

func TestOpenRefusesABinaryAnotherUserOwns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing a file's owner needs root")
	}
	path := fakeCloop(t, "{}")
	if err := os.Chown(path, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if c, err := Open(path); err == nil {
		_ = c.Close()
		t.Fatal("a binary owned by uid 4242 was accepted by a root run")
	} else if !strings.Contains(err.Error(), "uid 4242") {
		t.Fatalf("Open = %v", err)
	}
}

// The handoff variable names a path; only a handoff this process could have
// written is read or removed.
func TestTakeHandoffOnlyTouchesItsOwnFile(t *testing.T) {
	self, err := SelfIdent()
	if err != nil {
		t.Skipf("no procfs here: %v", err)
	}
	victim := filepath.Join(t.TempDir(), "precious.txt")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := TakeHandoff(victim, self, time.Now()); err == nil {
		t.Fatal("a file that is no handoff was taken")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("TakeHandoff removed a file it had no business with: %v", err)
	}
}

func TestInstalledAtIsTheInodeChange(t *testing.T) {
	path := fakeCloop(t, "{}")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if Supported && time.Since(c.InstalledAt()) > time.Hour {
		t.Fatalf("InstalledAt = %s: a back-dated mtime made a fresh deploy look settled", c.InstalledAt())
	}
}
