package donecheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// repo is a scratch git repository with one commit.
type repo struct {
	t   *testing.T
	dir string
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	r := &repo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.git("config", "user.email", "agent@example.com")
	r.git("config", "user.name", "agent")
	r.git("config", "commit.gpgsign", "false")
	r.write("README.md", "# test\n")
	r.write("main.go", "package main\n")
	r.git("add", "-A")
	r.git("commit", "-q", "-m", "initial")
	return r
}

func (r *repo) git(args ...string) string {
	r.t.Helper()
	return gitIn(r.t, r.dir, args...)
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *repo) write(name, body string) {
	r.t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *repo) commit(msg string) string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

func take(t *testing.T, dir string, carry *Carry) *Baseline {
	t.Helper()
	b, err := Take(context.Background(), dir, carry)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	return b
}

func check(t *testing.T, b *Baseline, opts Options) *Report {
	t.Helper()
	rep, err := Check(context.Background(), b, opts)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return rep
}

func paths(rep *Report) []string {
	var out []string
	for _, c := range rep.Uncommitted {
		out = append(out, c.Code+" "+c.Path)
	}
	return out
}

func TestNotARepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	_, err := Take(context.Background(), t.TempDir(), nil)
	if !errors.Is(err, ErrNotRepository) {
		t.Fatalf("Take outside a repository = %v, want ErrNotRepository", err)
	}
}

func TestAttemptLeavingChangesUncommittedIsBlamed(t *testing.T) {
	r := newRepo(t)
	b := take(t, r.dir, nil)

	r.write("main.go", "package main\n\nfunc main() {}\n")
	r.write("docs/new.md", "new\n")
	if err := os.Remove(filepath.Join(r.dir, "README.md")); err != nil {
		t.Fatal(err)
	}
	rep := check(t, b, Options{})
	got := strings.Join(paths(rep), "|")
	for _, want := range []string{" M main.go", "?? docs/new.md", " D README.md"} {
		if !strings.Contains(got, want) {
			t.Errorf("report lacks %q: %v", want, paths(rep))
		}
	}
	if rep.UncommittedCount != 3 || !rep.Outstanding() {
		t.Errorf("count = %d, outstanding = %v", rep.UncommittedCount, rep.Outstanding())
	}
	if !strings.Contains(rep.Summary(), "3 uncommitted paths") {
		t.Errorf("summary = %q", rep.Summary())
	}

	// Committing it all leaves nothing outstanding.
	r.commit("the task's work")
	if rep := check(t, b, Options{}); rep.Outstanding() {
		t.Errorf("after the commit: %v", paths(rep))
	}
}

// What was already dirty when the attempt started is not the task's, as long
// as the attempt left it alone.
func TestBaselineDirtIsNotBlamedUnlessTouched(t *testing.T) {
	r := newRepo(t)
	r.write("main.go", "package main // operator's edit\n")
	r.write("scratch.txt", "operator's notes\n")
	b := take(t, r.dir, nil)

	rep := check(t, b, Options{})
	if rep.Outstanding() {
		t.Fatalf("pre-existing changes were blamed: %v", paths(rep))
	}

	// The agent commits other work; the operator's edits stay unblamed.
	r.write("feature.go", "package main\n")
	r.git("add", "feature.go")
	r.git("commit", "-q", "-m", "feature")
	if rep := check(t, b, Options{}); rep.Outstanding() {
		t.Fatalf("an unrelated commit made the operator's edits the task's: %v", paths(rep))
	}

	// Changing a dirty file further makes it the task's.
	r.write("scratch.txt", "operator's notes\nand the agent's\n")
	rep = check(t, b, Options{})
	if got := paths(rep); len(got) != 1 || got[0] != "?? scratch.txt" {
		t.Errorf("after editing a dirty file: %v", got)
	}

	// So does staging one: the agent touched it and left it uncommitted.
	b2 := take(t, r.dir, nil)
	r.git("add", "main.go")
	rep = check(t, b2, Options{})
	if got := paths(rep); len(got) != 1 || got[0] != "M  main.go" {
		t.Errorf("after staging a dirty file: %v", got)
	}
}

// .cloop/ is cloop's own bookkeeping, and holds the task and feature worktrees,
// which are separate checkouts: none of it is the task's to commit, ignored by
// .gitignore or not.
func TestCloopDirectoryIsNeverBlamed(t *testing.T) {
	r := newRepo(t)
	b := take(t, r.dir, nil)
	r.write(".cloop/state.json", "{}")
	r.write(".cloop/artifacts/1_output.txt", "output")
	r.write(".cloop/features/f1/new.go", "package f1\n")
	if rep := check(t, b, Options{}); rep.Outstanding() {
		t.Fatalf(".cloop/ was blamed: %v", paths(rep))
	}

	// Even a feature worktree that is a real checkout of the repository.
	r.git("worktree", "add", "-q", "-b", "cloop/feature/f2", filepath.Join(r.dir, ".cloop", "features", "f2"))
	if err := os.WriteFile(filepath.Join(r.dir, ".cloop", "features", "f2", "x.go"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rep := check(t, b, Options{}); rep.Outstanding() {
		t.Fatalf("a feature worktree was blamed: %v", paths(rep))
	}
}

// A feature's own run checks its own worktree, which is a repository of its
// own as far as git status is concerned.
func TestAFeatureWorktreeIsCheckedOnItsOwn(t *testing.T) {
	r := newRepo(t)
	wt := filepath.Join(r.dir, ".cloop", "features", "f1")
	r.git("worktree", "add", "-q", "-b", "cloop/feature/f1", wt)
	b := take(t, wt, nil)
	if b.Top != wt {
		t.Fatalf("top = %s, want the feature worktree %s", b.Top, wt)
	}
	r.write("parent-only.txt", "the parent's change")
	if err := os.WriteFile(filepath.Join(wt, "feature.go"), []byte("package f1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := check(t, b, Options{})
	if got := paths(rep); len(got) != 1 || got[0] != "?? feature.go" {
		t.Errorf("feature check = %v, want only the feature's own file", got)
	}
}

// A project in a subdirectory of a repository is checked there, and its paths
// are named the way the agent standing in it would type them.
func TestASubdirectoryIsCheckedOnItsOwn(t *testing.T) {
	r := newRepo(t)
	r.write("svc/app.go", "package svc\n")
	r.commit("svc")
	dir := filepath.Join(r.dir, "svc")
	b := take(t, dir, nil)
	if b.Prefix != "svc/" {
		t.Fatalf("prefix = %q", b.Prefix)
	}
	r.write("elsewhere.txt", "not this project's")
	r.write("svc/app.go", "package svc // changed\n")
	r.write("svc/.cloop/state.json", "{}")
	rep := check(t, b, Options{})
	if got := paths(rep); len(got) != 1 || got[0] != " M app.go" {
		t.Errorf("subdirectory check = %v, want [\" M app.go\"]", got)
	}
}

// An attempt aborted for uncommitted work leaves that work in the tree, so the
// next attempt finds it dirty when it starts. The carry keeps it the task's.
func TestCarryKeepsAnAbortedAttemptsWorkTheTasks(t *testing.T) {
	r := newRepo(t)
	b1 := take(t, r.dir, nil)
	r.write("half.go", "package main // half done\n")
	rep := check(t, b1, Options{})
	if !rep.Outstanding() {
		t.Fatal("the first attempt's file was not blamed")
	}
	carryPath := filepath.Join(t.TempDir(), "artifacts", "7_uncommitted.json")
	if err := WriteCarry(carryPath, b1.Next(7, rep)); err != nil {
		t.Fatal(err)
	}

	// Without the carry the retry would let it through.
	if rep := check(t, take(t, r.dir, nil), Options{}); rep.Outstanding() {
		t.Fatalf("without a carry the file reads as pre-existing — test premise broken: %v", paths(rep))
	}

	carry, err := ReadCarry(carryPath, 7)
	if err != nil || carry == nil {
		t.Fatalf("ReadCarry = %+v, %v", carry, err)
	}
	b2 := take(t, r.dir, carry)
	rep = check(t, b2, Options{})
	if got := paths(rep); len(got) != 1 || got[0] != "?? half.go" {
		t.Fatalf("the retry was not held to the first attempt's work: %v", got)
	}

	// Another task's carry, an old one, or none at all does not apply.
	if c, _ := ReadCarry(carryPath, 8); c != nil {
		t.Error("task 8 read task 7's carry")
	}
	old := *carry
	old.At = time.Now().Add(-CarryMaxAge - time.Hour)
	if err := WriteCarry(carryPath, &old); err != nil {
		t.Fatal(err)
	}
	if c, _ := ReadCarry(carryPath, 7); c != nil {
		t.Error("a carry past CarryMaxAge was honoured")
	}
	if err := ClearCarry(carryPath); err != nil {
		t.Fatal(err)
	}
	if c, err := ReadCarry(carryPath, 7); c != nil || err != nil {
		t.Errorf("after ClearCarry: %+v, %v", c, err)
	}
	if err := ClearCarry(carryPath); err != nil {
		t.Errorf("clearing nothing: %v", err)
	}
}

// The carry lives where the agent can write. What it can make of one is a
// stricter check on its own task, never an escape from it.
func TestReadCarryRefusesWhatItCannotUse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "1_uncommitted.json")
	now := time.Now().UTC().Format(time.RFC3339)
	for name, body := range map[string]string{
		"junk":        "{",
		"bad head":    `{"format":1,"task_id":1,"top":"/r","head":"--output=/etc/passwd","at":"` + now + `"}`,
		"relative":    `{"format":1,"task_id":1,"top":"r","at":"` + now + `"}`,
		"too large":   `{"format":1,"task_id":1,"top":"/r","at":"` + now + `","paths":["` + strings.Repeat("a", maxCarryBytes) + `"]}`,
		"in a future": `{"format":1,"task_id":1,"top":"/r","at":"2999-01-01T00:00:00Z"}`,
	} {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if c, _ := ReadCarry(p, 1); c != nil {
			t.Errorf("%s: carry accepted: %+v", name, c)
		}
	}
	// Paths that leave the repository are dropped, the rest kept.
	body := `{"format":1,"task_id":1,"top":"/r","at":"` + now + `","paths":["ok.go","../escape","/abs","a/../b","sub/x.go"]}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := ReadCarry(p, 1)
	if err != nil || c == nil || strings.Join(c.Paths, ",") != "ok.go,sub/x.go" {
		t.Errorf("paths = %+v, %v", c, err)
	}
	// A FIFO in its place must not hang the reader.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("mkfifo", p).Run(); err == nil {
		done := make(chan struct{})
		go func() {
			_, _ = ReadCarry(p, 1)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("ReadCarry blocked on a FIFO")
		}
	}
}

// remote is a bare repository the scratch repository pushes to.
func withUpstream(t *testing.T, r *repo) string {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "remote.git")
	gitIn(t, filepath.Dir(bare), "init", "-q", "--bare", "-b", "main", bare)
	r.git("remote", "add", "origin", bare)
	r.git("push", "-q", "-u", "origin", "main")
	return bare
}

func TestUnpushedCommits(t *testing.T) {
	r := newRepo(t)
	withUpstream(t, r)
	b := take(t, r.dir, nil)

	r.write("a.go", "package main\n")
	sha := r.commit("add a")
	rep := check(t, b, Options{Pushed: true})
	if rep.UnpushedCount != 1 || len(rep.Unpushed) != 1 || rep.Unpushed[0].SHA != sha || rep.Unpushed[0].Subject != "add a" {
		t.Fatalf("unpushed = %+v (count %d)", rep.Unpushed, rep.UnpushedCount)
	}
	if rep.Upstream != "origin/main" || rep.Branch != "main" || !rep.Outstanding() {
		t.Errorf("report = %+v", rep)
	}
	if !strings.Contains(rep.Summary(), "1 commit not on origin/main") {
		t.Errorf("summary = %q", rep.Summary())
	}
	// Without Pushed the commit is enough.
	if rep := check(t, b, Options{}); rep.Outstanding() {
		t.Errorf("committed work is outstanding without Pushed: %+v", rep)
	}

	r.git("push", "-q")
	if rep := check(t, b, Options{Pushed: true}); rep.Outstanding() {
		t.Errorf("after the push: %+v", rep)
	}
}

// Commits that were already local when the attempt started are not its to
// publish — unless the carry says an earlier attempt of the same task made
// them.
func TestUnpushedCommitsBeforeTheAttemptAreNotBlamed(t *testing.T) {
	r := newRepo(t)
	withUpstream(t, r)
	r.write("wip.go", "package main\n")
	r.commit("operator's local commit")
	b := take(t, r.dir, nil)
	if rep := check(t, b, Options{Pushed: true}); rep.Outstanding() {
		t.Fatalf("a commit made before the attempt was blamed: %+v", rep)
	}

	// An attempt that commits and does not push, aborted: the retry starts
	// with that commit already on HEAD.
	r.write("task.go", "package main\n")
	r.commit("the task's commit")
	rep := check(t, b, Options{Pushed: true})
	if rep.UnpushedCount != 1 {
		t.Fatalf("the attempt's own commit: %+v", rep)
	}
	carry := b.Next(3, rep)
	if rep := check(t, take(t, r.dir, nil), Options{Pushed: true}); rep.Outstanding() {
		t.Fatalf("without a carry the retry's baseline swallows the commit — test premise broken: %+v", rep)
	}
	rep = check(t, take(t, r.dir, carry), Options{Pushed: true})
	if rep.UnpushedCount != 1 || rep.Unpushed[0].Subject != "the task's commit" {
		t.Errorf("the retry was not held to the first attempt's commit: %+v", rep)
	}
}

func TestNoUpstreamIsNotedNotFailed(t *testing.T) {
	r := newRepo(t)
	b := take(t, r.dir, nil)
	r.write("a.go", "package main\n")
	r.commit("add a")
	rep := check(t, b, Options{Pushed: true})
	if rep.Outstanding() {
		t.Fatalf("a branch with no upstream was failed: %+v", rep)
	}
	if len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "branch main has no upstream") {
		t.Errorf("notes = %v", rep.Notes)
	}

	r.git("checkout", "-q", "--detach")
	rep = check(t, b, Options{Pushed: true})
	if rep.Outstanding() || len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "detached") {
		t.Errorf("detached HEAD: %+v", rep)
	}

	rep = check(t, b, Options{Pushed: true, NoPush: "the review gate cannot hold pushes here"})
	if rep.Outstanding() || len(rep.Notes) != 1 || rep.Notes[0] != "the review gate cannot hold pushes here" {
		t.Errorf("NoPush: %+v", rep)
	}
}

// A push the review gate is holding is pending: the gate publishes it once the
// reviewer approves. Only what no held push covers is missing.
func TestHeldPushesArePendingNotMissing(t *testing.T) {
	r := newRepo(t)
	withUpstream(t, r)
	b := take(t, r.dir, nil)
	r.write("a.go", "package main\n")
	first := r.commit("add a")
	r.write("b.go", "package main\n")
	second := r.commit("add b")

	rep := check(t, b, Options{Pushed: true, Held: []string{first}})
	if rep.Pending != 1 || rep.UnpushedCount != 1 || rep.Unpushed[0].SHA != second {
		t.Fatalf("held the first of two: %+v", rep)
	}
	rep = check(t, b, Options{Pushed: true, Held: []string{second}})
	if rep.Pending != 2 || rep.Outstanding() {
		t.Errorf("held the tip: %+v", rep)
	}
	// What the hold file says is not trusted to be a commit name, or to be in
	// this repository.
	rep = check(t, b, Options{Pushed: true, Held: []string{"--all", "HEAD", strings.Repeat("ab", 20)}})
	if rep.UnpushedCount != 2 || rep.Pending != 0 {
		t.Errorf("junk held pushes: %+v", rep)
	}
}

// A directory entry — an untracked nested repository — is fingerprinted too,
// so one that was already there is left alone and one the agent changed is
// not.
func TestNestedRepositoryEntry(t *testing.T) {
	r := newRepo(t)
	nested := filepath.Join(r.dir, "vendor-clone")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, nested, "init", "-q")
	if err := os.WriteFile(filepath.Join(nested, "f"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := take(t, r.dir, nil)
	if rep := check(t, b, Options{}); rep.Outstanding() {
		t.Fatalf("an untouched nested repository was blamed: %v", paths(rep))
	}
	if err := os.WriteFile(filepath.Join(nested, "g"), []byte("2"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := check(t, b, Options{})
	if got := paths(rep); len(got) != 1 || got[0] != "?? vendor-clone/" {
		t.Errorf("changed nested repository: %v", got)
	}
}

// A file too large to hash is compared on its size and modification time.
func TestLargeFilesAreComparedByStat(t *testing.T) {
	r := newRepo(t)
	big := filepath.Join(r.dir, "big.bin")
	if err := os.WriteFile(big, make([]byte, maxHashFileBytes+10), 0o644); err != nil {
		t.Fatal(err)
	}
	b := take(t, r.dir, nil)
	if !strings.Contains(b.dirty["big.bin"], "\x00stat:") {
		t.Fatalf("big file fingerprint = %q", b.dirty["big.bin"])
	}
	if rep := check(t, b, Options{}); rep.Outstanding() {
		t.Fatalf("untouched big file blamed: %v", paths(rep))
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(big, future, future); err != nil {
		t.Fatal(err)
	}
	if rep := check(t, b, Options{}); !rep.Outstanding() {
		t.Error("a rewritten big file was not blamed")
	}
}

// A listing too long to read whole is cut, and what the baseline could not see
// is not blamed on the attempt — it is noted.
func TestTruncatedListing(t *testing.T) {
	r := newRepo(t)
	for i := 0; i < 50; i++ {
		r.write(filepath.Join("gen", strings.Repeat("x", 40)+string(rune('a'+i%26))+strings.Repeat("y", i)), "z")
	}
	old := maxStatusBytes
	maxStatusBytes = 600
	t.Cleanup(func() { maxStatusBytes = old })

	b := take(t, r.dir, nil)
	if !b.truncated {
		t.Fatal("the listing was not cut")
	}
	rep := check(t, b, Options{})
	if rep.Outstanding() {
		t.Errorf("pre-existing paths past the cut were blamed: %v", paths(rep))
	}
	if len(rep.Notes) == 0 {
		t.Error("the cut was not noted")
	}
}

func TestParseStatusRecords(t *testing.T) {
	out := strings.Join([]string{
		"1 .M N... 100644 100644 100644 aaaa aaaa a file.go",
		"2 R. N... 100644 100644 100644 bbbb bbbb R100 new name.go", "old name.go",
		"u UU N... 100644 100644 100644 100644 c1 c2 c3 conflict.go",
		"? untracked dir/file.txt",
		"? nested/",
		"1 .M SC.. 160000 160000 160000 dddd dddd sub",
		"# branch.oid ignored",
		"9 unknown record",
		"",
	}, "\x00")
	es := parseStatus([]byte(out))
	if len(es) != 6 {
		t.Fatalf("parsed %d entries: %+v", len(es), es)
	}
	want := []struct{ path, code string }{
		{"a file.go", " M"}, {"new name.go", "R "}, {"conflict.go", "UU"},
		{"untracked dir/file.txt", "??"}, {"nested/", "??"}, {"sub", " M"},
	}
	for i, w := range want {
		if es[i].path != w.path || es[i].code != w.code {
			t.Errorf("entry %d = %q %q, want %q %q", i, es[i].code, es[i].path, w.code, w.path)
		}
	}
	if !strings.Contains(es[1].state, "old name.go") {
		t.Errorf("a rename's source is not part of its state: %q", es[1].state)
	}
	if !es[4].dir || !es[5].dir || es[0].dir {
		t.Error("directory entries not recognised")
	}
}

func TestReportSummaryAndBounds(t *testing.T) {
	r := newRepo(t)
	b := take(t, r.dir, nil)
	for i := 0; i < MaxListed+5; i++ {
		r.write(fmt.Sprintf("gen/f%03d.txt", i), "x")
	}
	rep := check(t, b, Options{})
	if rep.UncommittedCount != MaxListed+5 || len(rep.Uncommitted) != MaxListed {
		t.Errorf("count %d listed %d", rep.UncommittedCount, len(rep.Uncommitted))
	}
	if s := rep.Summary(); !strings.HasPrefix(s, "45 uncommitted paths (gen/f000.txt, gen/f001.txt, gen/f002.txt, …)") {
		t.Errorf("summary = %q", s)
	}
	if len(b.Next(1, rep).Paths) != MaxListed+5 {
		t.Error("the carry does not remember every blamed path")
	}
	if (&Report{}).Summary() != "nothing outstanding" {
		t.Error("empty summary")
	}
}

func TestPruneCarries(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, age time.Duration) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	write("1_uncommitted.json", 8*24*time.Hour)
	write("2_uncommitted.json", time.Hour)
	write("3_verdict.json", 30*24*time.Hour)
	write("notes_uncommitted.json", 30*24*time.Hour)
	n, size, err := PruneCarries(dir, time.Now().Add(-CarryMaxAge), false)
	if err != nil || n != 1 || size != 2 {
		t.Fatalf("PruneCarries = %d, %d, %v", n, size, err)
	}
	for name, want := range map[string]bool{"1_uncommitted.json": false, "2_uncommitted.json": true,
		"3_verdict.json": true, "notes_uncommitted.json": true} {
		if _, err := os.Stat(filepath.Join(dir, name)); (err == nil) != want {
			t.Errorf("%s present = %v, want %v", name, err == nil, want)
		}
	}
	if n, _, err := PruneCarries(filepath.Join(dir, "missing"), time.Now(), false); n != 0 || err != nil {
		t.Errorf("a missing directory: %d, %v", n, err)
	}
}
