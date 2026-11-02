package reqproof

// Red-green proofs against real git repositories (Task 20464): a test that
// shows the change, one that passes either way, one that fails on the change,
// the cases a proof cannot settle — and that the base's checkout is gone
// however the proof ends, the project's own checkout untouched.
//
// The "code" and the "tests" are shell scripts, so nothing here needs a
// toolchain beyond git and /bin/sh.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// repo is a git repository for a test.
type repo struct {
	t   *testing.T
	dir string
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	r := &repo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.git("config", "user.email", "proof@example.com")
	r.git("config", "user.name", "proof test")
	r.git("config", "commit.gpgsign", "false")
	// cloop's own state is never part of a change.
	r.write(".gitignore", ".cloop/\n")
	return r
}

func (r *repo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *repo) write(rel, content string) {
	r.t.Helper()
	p := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

func (r *repo) commit(msg string) string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

func req(id int, commands ...string) requirements.Requirement {
	q := requirements.Requirement{ID: id, Title: fmt.Sprintf("requirement %d", id)}
	for _, c := range commands {
		q.Tests = append(q.Tests, requirements.Test{Command: c, TimeoutSeconds: 60})
	}
	return q
}

// The base: greet says hello. The change: greet says hello, world — and
// three tests come with it.
const (
	oldLib = "greet() { echo hello; }\n"
	newLib = "greet() { echo 'hello, world'; }\n"
	// Shows the change: it fails while greet says only hello.
	provenTest = ". ./lib.sh\n[ \"$(greet)\" = 'hello, world' ]\n"
	// Passes whatever greet says.
	vacuousTest = ". ./lib.sh\ngreet >/dev/null\ntrue\n"
	// Fails on the change itself.
	brokenTest = ". ./lib.sh\n[ \"$(greet)\" = goodbye ]\n"
)

func baseAndChange(t *testing.T) (*repo, string, string) {
	r := newRepo(t)
	r.write("lib.sh", oldLib)
	r.write("README", "a project\n")
	base := r.commit("base")
	r.write("lib.sh", newLib)
	r.write("tests/proven_test.sh", provenTest)
	r.write("tests/vacuous_test.sh", vacuousTest)
	r.write("tests/broken_test.sh", brokenTest)
	change := r.commit("the change")
	return r, base, change
}

func proofOf(t *testing.T, rep requirements.ProofReport, id int) requirements.Proof {
	t.Helper()
	for _, p := range rep.Results {
		if p.RequirementID == id {
			return p
		}
	}
	t.Fatalf("no proof of R-%d in %+v", id, rep)
	return requirements.Proof{}
}

// assertClean checks that no proof checkout is left: not its directory, not
// the repository's record of it.
func assertClean(t *testing.T, r *repo) {
	t.Helper()
	if list := r.git("worktree", "list", "--porcelain"); strings.Count(list, "worktree ") != 1 {
		t.Fatalf("a proof checkout is still recorded:\n%s", list)
	}
	entries, _ := os.ReadDir(filepath.Join(r.dir, ".cloop", "worktrees"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "proof-") {
			t.Fatalf("a proof checkout is still on disk: %s", e.Name())
		}
	}
}

// TestProveTellsProvenVacuousAndBroken: the three statements a proof makes
// about a test, each from a real run on each side.
func TestProveTellsProvenVacuousAndBroken(t *testing.T) {
	r, base, change := baseAndChange(t)
	reqs := []requirements.Requirement{
		req(1, "sh tests/proven_test.sh"),
		req(2, "sh tests/vacuous_test.sh"),
		req(3, "sh tests/broken_test.sh"),
	}
	rep, err := Prove(context.Background(), reqs, Options{Dir: r.dir, Base: base, BaseFrom: requirements.BaseFromTask})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	proven := proofOf(t, rep, 1)
	if proven.Outcome != requirements.ProofProven {
		t.Fatalf("R-1 = %s (%s), want proven", proven.Outcome, proven.Summary)
	}
	if !proven.Fallback || !proven.CodeChanged || !proven.NewTests || proven.BaseFrom != requirements.BaseFromTask {
		t.Fatalf("R-1 facts: %+v", proven)
	}
	if proven.Before.Commit != base || proven.After.Commit != change || proven.After.Dirty {
		t.Fatalf("R-1 ran at base %s, change %s (dirty %v); want %s and %s", proven.Before.Commit,
			proven.After.Commit, proven.After.Dirty, base, change)
	}
	if len(proven.TestFiles) != 1 || proven.TestFiles[0] != (requirements.ProofFile{Path: "tests/proven_test.sh", Status: "A"}) {
		t.Fatalf("R-1's test files: %+v — the other tests are not R-1's", proven.TestFiles)
	}
	if proven.Before.Tests[0].Outcome != requirements.OutcomeFail || proven.After.Tests[0].Outcome != requirements.OutcomePass {
		t.Fatalf("R-1 before %+v after %+v", proven.Before.Tests, proven.After.Tests)
	}

	vacuous := proofOf(t, rep, 2)
	if vacuous.Outcome != requirements.ProofVacuous || !vacuous.NewTests {
		t.Fatalf("R-2 = %s new=%v (%s), want a vacuous new test", vacuous.Outcome, vacuous.NewTests, vacuous.Summary)
	}

	broken := proofOf(t, rep, 3)
	if broken.Outcome != requirements.ProofBroken {
		t.Fatalf("R-3 = %s (%s), want broken", broken.Outcome, broken.Summary)
	}
	if len(broken.Before.Tests) != 0 {
		t.Fatalf("a test broken on the change was run at the base too: %+v", broken.Before)
	}
	assertClean(t, r)

	// What the executor reported, read back through the hub's rules, says
	// the same.
	clean := requirements.SanitizeProofs(rep, reqs, nil, time.Now())
	for i, p := range clean.Results {
		if p.Outcome != rep.Results[i].Outcome {
			t.Fatalf("the hub reads R-%d as %s, the executor said %s", p.RequirementID, p.Outcome, rep.Results[i].Outcome)
		}
	}
}

// TestProveNeverTouchesTheProjectsCheckout: the change's uncommitted work,
// its index and its HEAD are what they were before the proof.
func TestProveNeverTouchesTheProjectsCheckout(t *testing.T) {
	r, base, change := baseAndChange(t)
	r.write("README", "uncommitted work\n")
	r.write("notes.txt", "untracked work\n")
	r.git("add", "notes.txt")
	statusBefore := r.git("status", "--porcelain")
	rep, err := Prove(context.Background(), []requirements.Requirement{req(1, "sh tests/proven_test.sh")},
		Options{Dir: r.dir, Base: base})
	if err != nil {
		t.Fatal(err)
	}
	if p := proofOf(t, rep, 1); p.Outcome != requirements.ProofProven || !p.After.Dirty {
		t.Fatalf("R-1 = %s dirty=%v (%s)", p.Outcome, p.After.Dirty, p.Summary)
	}
	if head := r.git("rev-parse", "HEAD"); head != change {
		t.Fatalf("HEAD moved to %s", head)
	}
	if got := r.git("status", "--porcelain"); got != statusBefore {
		t.Fatalf("the checkout changed:\n%s\nwas:\n%s", got, statusBefore)
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "README")); string(b) != "uncommitted work\n" {
		t.Fatalf("README is %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "lib.sh")); string(b) != newLib {
		t.Fatalf("lib.sh is %q", b)
	}
	assertClean(t, r)
}

// TestProveWithoutFallbackWhenTheTestPredatesTheChange: a test written first
// — red at the base as it is, its files untouched by the change — is proven
// without laying anything over the base.
func TestProveWithoutFallbackWhenTheTestPredatesTheChange(t *testing.T) {
	r := newRepo(t)
	r.write("lib.sh", oldLib)
	r.write("tests/tdd_test.sh", provenTest)
	base := r.commit("the test, first")
	r.write("lib.sh", newLib)
	r.commit("the implementation")
	rep, err := Prove(context.Background(), []requirements.Requirement{req(5, "sh tests/tdd_test.sh")},
		Options{Dir: r.dir, Base: base})
	if err != nil {
		t.Fatal(err)
	}
	p := proofOf(t, rep, 5)
	if p.Outcome != requirements.ProofProven || p.Fallback || p.NewTests || len(p.TestFiles) != 0 {
		t.Fatalf("R-5 = %s fallback=%v new=%v files=%v (%s)", p.Outcome, p.Fallback, p.NewTests, p.TestFiles, p.Summary)
	}
	if p.Before.Dirty {
		t.Fatal("nothing was laid over the base, yet its run says so")
	}
	assertClean(t, r)
}

// TestProveIsInconclusiveWhereItCannotTell: a change of tests alone has no
// code for them to fail without, and a test whose command needs more of the
// change than its test files does not run at the base at all.
func TestProveIsInconclusiveWhereItCannotTell(t *testing.T) {
	t.Run("tests only", func(t *testing.T) {
		r := newRepo(t)
		r.write("lib.sh", newLib)
		base := r.commit("base")
		r.write("tests/proven_test.sh", provenTest)
		r.commit("a test for what the code already does")
		rep, err := Prove(context.Background(), []requirements.Requirement{req(1, "sh tests/proven_test.sh")},
			Options{Dir: r.dir, Base: base})
		if err != nil {
			t.Fatal(err)
		}
		p := proofOf(t, rep, 1)
		if p.Outcome != requirements.ProofInconclusive || p.CodeChanged || len(p.Before.Tests) != 0 {
			t.Fatalf("R-1 = %s code=%v before=%+v (%s)", p.Outcome, p.CodeChanged, p.Before, p.Summary)
		}
		assertClean(t, r)
	})
	t.Run("command missing at the base", func(t *testing.T) {
		r := newRepo(t)
		r.write("lib.sh", oldLib)
		base := r.commit("base")
		r.write("lib.sh", newLib)
		r.write("tools/helper", "#!/bin/sh\n. ./lib.sh\n[ \"$(greet)\" = 'hello, world' ]\n")
		r.write("tests/helper_test.sh", "./tools/helper\n")
		r.commit("a test that needs a tool the change adds")
		rep, err := Prove(context.Background(), []requirements.Requirement{req(2, "sh tests/helper_test.sh")},
			Options{Dir: r.dir, Base: base})
		if err != nil {
			t.Fatal(err)
		}
		p := proofOf(t, rep, 2)
		if p.Outcome != requirements.ProofInconclusive || !p.Fallback || p.Before.Tests[0].ExitCode != 127 {
			t.Fatalf("R-2 = %s fallback=%v before=%+v (%s)", p.Outcome, p.Fallback, p.Before.Tests, p.Summary)
		}
		if !strings.Contains(p.Summary, "does not exist at the base") {
			t.Fatalf("R-2's summary: %s", p.Summary)
		}
		assertClean(t, r)
	})
}

// TestProveFindsTheCommitBeforeTheTestsImplementation: asked with no base, a
// proof starts from the commit before the one that implemented the test —
// or from HEAD while the test is uncommitted.
func TestProveFindsTheCommitBeforeTheTestsImplementation(t *testing.T) {
	r, base, _ := baseAndChange(t)
	r.write("README", "a later change\n")
	r.commit("something unrelated")
	rep, err := Prove(context.Background(), []requirements.Requirement{req(1, "sh tests/proven_test.sh")},
		Options{Dir: r.dir})
	if err != nil {
		t.Fatal(err)
	}
	p := proofOf(t, rep, 1)
	if p.BaseFrom != requirements.BaseFromTest || p.Before.Commit != base || p.Outcome != requirements.ProofProven {
		t.Fatalf("R-1 based on %s from %s = %s (%s); want %s from the test", p.Before.Commit, p.BaseFrom, p.Outcome,
			p.Summary, base)
	}

	// An uncommitted test: the change is the working tree, the base HEAD.
	head := r.git("rev-parse", "HEAD")
	r.write("tests/proven_test.sh", provenTest+"# still being written\n")
	rep, err = Prove(context.Background(), []requirements.Requirement{req(1, "sh tests/proven_test.sh")},
		Options{Dir: r.dir})
	if err != nil {
		t.Fatal(err)
	}
	if p := proofOf(t, rep, 1); p.BaseFrom != requirements.BaseFromWorktree || p.Before.Commit != head {
		t.Fatalf("an uncommitted test was based on %s from %s, want HEAD %s", p.Before.Commit, p.BaseFrom, head)
	}
	assertClean(t, r)
}

// TestProveOfATestCommittedOnItsOwn: a test committed before its
// implementation is proved from the commit that holds it and not yet the
// code; one committed for what the code already did is one a red-green proof
// cannot judge.
func TestProveOfATestCommittedOnItsOwn(t *testing.T) {
	t.Run("test first", func(t *testing.T) {
		r := newRepo(t)
		r.write("lib.sh", oldLib)
		r.commit("base")
		r.write("tests/tdd_test.sh", provenTest)
		testCommit := r.commit("the test, first")
		r.write("lib.sh", newLib)
		r.commit("the implementation")
		rep, err := Prove(context.Background(), []requirements.Requirement{req(1, "sh tests/tdd_test.sh")}, Options{Dir: r.dir})
		if err != nil {
			t.Fatal(err)
		}
		p := proofOf(t, rep, 1)
		if p.Outcome != requirements.ProofProven || p.Before.Commit != testCommit || p.Fallback {
			t.Fatalf("R-1 = %s at %s fallback=%v (%s); want proven at the test's commit %s", p.Outcome, p.Before.Commit,
				p.Fallback, p.Summary, testCommit)
		}
		assertClean(t, r)
	})
	t.Run("a test of what the code already did", func(t *testing.T) {
		r := newRepo(t)
		r.write("lib.sh", newLib)
		r.commit("base")
		r.write("tests/proven_test.sh", provenTest)
		r.commit("a test for existing behaviour")
		rep, err := Prove(context.Background(), []requirements.Requirement{req(1, "sh tests/proven_test.sh")}, Options{Dir: r.dir})
		if err != nil {
			t.Fatal(err)
		}
		if p := proofOf(t, rep, 1); p.Outcome != requirements.ProofInconclusive {
			t.Fatalf("R-1 = %s (%s), want inconclusive", p.Outcome, p.Summary)
		}
		assertClean(t, r)
	})
}

// TestProveOnlyChangedPassesOverUntouchedTests: proving what a change touched
// runs nothing for a requirement whose tests it left alone.
func TestProveOnlyChangedPassesOverUntouchedTests(t *testing.T) {
	r := newRepo(t)
	r.write("lib.sh", oldLib)
	r.write("tests/other_test.sh", "true\n")
	base := r.commit("base")
	r.write("lib.sh", newLib)
	r.write("tests/proven_test.sh", provenTest)
	r.commit("the change")
	reqs := []requirements.Requirement{req(1, "sh tests/proven_test.sh"), req(7, "sh tests/other_test.sh"),
		req(8, "sh tests/other_test.sh")}
	rep, err := Prove(context.Background(), reqs, Options{Dir: r.dir, Base: base, OnlyChanged: true,
		Changed: map[int]bool{8: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Untouched) != 1 || rep.Untouched[0] != 7 {
		t.Fatalf("untouched = %v, want R-7 only", rep.Untouched)
	}
	if p := proofOf(t, rep, 8); !p.NewTests || p.Outcome != requirements.ProofVacuous {
		t.Fatalf("R-8, whose command the change wrote, = %s new=%v (%s)", p.Outcome, p.NewTests, p.Summary)
	}
	if p := proofOf(t, rep, 1); p.Outcome != requirements.ProofProven {
		t.Fatalf("R-1 = %s (%s)", p.Outcome, p.Summary)
	}
}

// TestProveCleansUpWhenCancelled: a proof stopped while its base run is
// under way kills the test, removes the base's checkout and returns.
func TestProveCleansUpWhenCancelled(t *testing.T) {
	r := newRepo(t)
	r.write("lib.sh", oldLib)
	base := r.commit("base")
	r.write("lib.sh", newLib)
	// Quick on the change; at the base it says where it is and waits.
	r.write("tests/slow_test.sh", ". ./lib.sh\n"+
		"if [ \"$(greet)\" = hello ]; then echo $$ > \"$PROOF_MARK.pid\"; touch \"$PROOF_MARK.$CLOOP_PROOF\"; sleep 60; fi\n"+
		"[ \"$(greet)\" = 'hello, world' ]\n")
	r.commit("the change")
	mark := filepath.Join(t.TempDir(), "mark")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan requirements.ProofReport, 1)
	go func() {
		rep, _ := Prove(ctx, []requirements.Requirement{req(9, "sh tests/slow_test.sh"), req(10, "sh tests/slow_test.sh")},
			Options{Dir: r.dir, Base: base, Env: append(os.Environ(), "PROOF_MARK="+mark)})
		done <- rep
	}()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(mark + ".before"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the base run never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The checkout exists while the test runs, locked against any sweep.
	if list := r.git("worktree", "list", "--porcelain"); !strings.Contains(list, "locked cloop: requirement proof (pid") {
		t.Fatalf("the base's checkout is not locked while it runs:\n%s", list)
	}
	pidRaw, _ := os.ReadFile(mark + ".pid")
	cancel()
	var rep requirements.ProofReport
	select {
	case rep = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the proof did not return after it was cancelled")
	}
	p := proofOf(t, rep, 9)
	if p.Outcome != requirements.ProofError {
		t.Fatalf("a stopped proof = %s (%s), want error", p.Outcome, p.Summary)
	}
	if q := proofOf(t, rep, 10); q.Outcome != requirements.ProofError || !strings.Contains(q.Summary, "stopped") {
		t.Fatalf("the requirement not reached = %s (%s)", q.Outcome, q.Summary)
	}
	assertClean(t, r)
	if pid, err := strconv.Atoi(strings.TrimSpace(string(pidRaw))); err == nil {
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("the base run's test (pid %d) outlived the proof: %v", pid, err)
		}
	}
}

// TestProveSweepsWhatAKilledProofLeft: a proof checkout whose process is
// gone is removed by the next proof; one a live proof holds is not.
func TestProveSweepsWhatAKilledProofLeft(t *testing.T) {
	r, base, _ := baseAndChange(t)
	host, _ := os.Hostname()
	dead := 4194000
	for ; dead > 1000; dead-- {
		if errors.Is(syscall.Kill(dead, 0), syscall.ESRCH) {
			break
		}
	}
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	leftover := filepath.Join(r.dir, ".cloop", "worktrees", "proof-deadbeef0001")
	r.git("worktree", "add", "-q", "--detach", leftover, base)
	r.git("worktree", "lock", "--reason", fmt.Sprintf("cloop: requirement proof (pid %d on %s, until %s)", dead, host, until), leftover)
	live := filepath.Join(r.dir, ".cloop", "worktrees", "proof-deadbeef0002")
	r.git("worktree", "add", "-q", "--detach", live, base)
	r.git("worktree", "lock", "--reason", fmt.Sprintf("cloop: requirement proof (pid %d on %s, until %s)", os.Getpid(), host, until), live)

	if _, err := Prove(context.Background(), []requirements.Requirement{req(1, "sh tests/proven_test.sh")},
		Options{Dir: r.dir, Base: base}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("the dead proof's checkout survived: %v", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("a live proof's checkout was swept: %v", err)
	}
	if list := r.git("worktree", "list", "--porcelain"); strings.Contains(list, "proof-deadbeef0001") {
		t.Fatalf("the dead proof's checkout is still recorded:\n%s", list)
	}
}

// TestProveSaysWhyWhenItCannotRun: no git checkout, a base the checkout
// lacks, a requirement with no test.
func TestProveSaysWhyWhenItCannotRun(t *testing.T) {
	rep, _ := Prove(context.Background(), []requirements.Requirement{req(1, "true")}, Options{Dir: t.TempDir()})
	if p := proofOf(t, rep, 1); p.Outcome != requirements.ProofError || !strings.Contains(p.Summary, "not a git checkout") {
		t.Fatalf("outside a checkout: %s (%s)", p.Outcome, p.Summary)
	}
	r, _, _ := baseAndChange(t)
	rep, _ = Prove(context.Background(), []requirements.Requirement{req(1, "sh tests/proven_test.sh"),
		{ID: 2, Title: "untested"}}, Options{Dir: r.dir, Base: strings.Repeat("ab", 20)})
	if p := proofOf(t, rep, 1); p.Outcome != requirements.ProofError || !strings.Contains(p.Summary, "not in this checkout") {
		t.Fatalf("a missing base: %s (%s)", p.Outcome, p.Summary)
	}
	if p := proofOf(t, rep, 2); p.Outcome != requirements.ProofError || !strings.Contains(p.Summary, "no tests") {
		t.Fatalf("no tests: %s (%s)", p.Outcome, p.Summary)
	}
	assertClean(t, r)
}

// TestProveOfAProjectInASubdirectory: a project that is one directory of a
// larger repository runs its tests from that directory on both sides.
func TestProveOfAProjectInASubdirectory(t *testing.T) {
	r := newRepo(t)
	r.write("svc/lib.sh", oldLib)
	r.write("other/x", "1\n")
	base := r.commit("base")
	r.write("svc/lib.sh", newLib)
	r.write("svc/tests/proven_test.sh", provenTest)
	r.commit("the change")
	rep, err := Prove(context.Background(), []requirements.Requirement{req(1, "sh tests/proven_test.sh")},
		Options{Dir: filepath.Join(r.dir, "svc"), Base: base})
	if err != nil {
		t.Fatal(err)
	}
	p := proofOf(t, rep, 1)
	if p.Outcome != requirements.ProofProven || len(p.TestFiles) != 1 || p.TestFiles[0].Path != "tests/proven_test.sh" {
		t.Fatalf("R-1 = %s files=%v (%s)", p.Outcome, p.TestFiles, p.Summary)
	}
	assertClean(t, r)
}
