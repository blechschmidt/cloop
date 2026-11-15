package movegit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// git runs git in dir for a test's setup, failing the test on error.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// binary returns n bytes no text heuristic would mistake for text.
func binary(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31) ^ seed
	}
	b[0] = 0
	return b
}

// treeState is what a working tree holds outside .git and .cloop: every
// regular file's bytes and executable bit, every link's target.
func treeState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		first := strings.Split(filepath.ToSlash(rel), "/")[0]
		if first == ".git" || first == ".cloop" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out[filepath.ToSlash(rel)] = "link:" + target
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:]) + " exec=" + boolString(info.Mode()&0o111 != 0)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func boolString(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func diffStates(a, b map[string]string) []string {
	var out []string
	for k, v := range a {
		if b[k] != v {
			out = append(out, k+": "+v+" vs "+b[k])
		}
	}
	for k, v := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k+": absent vs "+v)
		}
	}
	sort.Strings(out)
	return out
}

// dirtyRepo builds a repository whose working tree holds every kind of change
// a move must carry: on branch work, with a second branch, a tag, a stash and
// an upstream that holds main; staged and unstaged edits, a rename, deletions
// (staged and unstaged), binary files changed, added and untracked, an
// executable bit flipped, a symbolic link, an ignored file, and a .cloop
// directory that is not part of the snapshot.
func dirtyRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "proj")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	write(t, filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644)
	write(t, filepath.Join(dir, "old-name.txt"), []byte("rename me\n"), 0o644)
	write(t, filepath.Join(dir, "gone.txt"), []byte("delete me\n"), 0o644)
	write(t, filepath.Join(dir, "gone-staged.txt"), []byte("delete me too\n"), 0o644)
	write(t, filepath.Join(dir, "img.bin"), binary(4096, 7), 0o644)
	write(t, filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o644)
	write(t, filepath.Join(dir, ".gitignore"), []byte("*.log\n"), 0o644)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "base")
	// An upstream that holds main, so main counts as pushed.
	bare := filepath.Join(root, "upstream.git")
	git(t, root, "init", "-q", "--bare", bare)
	git(t, dir, "remote", "add", "origin", "https://user:s3cr3t-token@example.com/acme/proj.git")
	git(t, dir, "push", "-q", bare, "main:main")
	git(t, dir, "update-ref", "refs/remotes/origin/main", "HEAD")
	git(t, dir, "tag", "-a", "v1", "-m", "first")
	git(t, dir, "branch", "side")
	git(t, dir, "checkout", "-q", "-b", "work")
	write(t, filepath.Join(dir, "README.md"), []byte("hello from work\n"), 0o644)
	git(t, dir, "commit", "-q", "-am", "work commit")
	// A stash entry.
	write(t, filepath.Join(dir, "README.md"), []byte("stashed edit\n"), 0o644)
	git(t, dir, "stash", "push", "-q", "-m", "keep this")

	// The uncommitted state.
	git(t, dir, "mv", "old-name.txt", "new-name.txt")                                    // staged rename
	write(t, filepath.Join(dir, "README.md"), []byte("staged edit\n"), 0o644)            // staged ...
	git(t, dir, "add", "README.md")                                                      //
	write(t, filepath.Join(dir, "README.md"), []byte("staged edit, then more\n"), 0o644) // ... then edited again
	if err := os.Remove(filepath.Join(dir, "gone.txt")); err != nil {                    // unstaged deletion
		t.Fatal(err)
	}
	git(t, dir, "rm", "-q", "gone-staged.txt")                                     // staged deletion
	write(t, filepath.Join(dir, "img.bin"), binary(8192, 9), 0o644)                // binary changed
	write(t, filepath.Join(dir, "added.bin"), binary(1000, 3), 0o644)              // binary added, staged
	git(t, dir, "add", "added.bin")                                                //
	write(t, filepath.Join(dir, "notes", "untracked.txt"), []byte("new\n"), 0o644) // untracked, in a new directory
	write(t, filepath.Join(dir, "untracked.bin"), binary(300, 5), 0o600)           // untracked binary
	write(t, filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755)  // executable bit flipped
	if err := os.Symlink("new-name.txt", filepath.Join(dir, "link")); err != nil { // untracked link
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "debug.log"), []byte("ignored\n"), 0o644) // ignored: not carried
	write(t, filepath.Join(dir, ".cloop", "artifacts", "1_output.txt"), []byte("hub's own\n"), 0o644)
	return dir
}

func TestCaptureLeavesTheBranchAndIndexAloneAndRestoresByteIdentical(t *testing.T) {
	ctx := context.Background()
	dir := dirtyRepo(t)
	indexBefore, err := os.ReadFile(filepath.Join(dir, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	headBefore := git(t, dir, "rev-parse", "HEAD")
	statusBefore := git(t, dir, "status", "--porcelain=v2")
	stateBefore := treeState(t, dir)

	store := t.TempDir()
	bundle := filepath.Join(store, "repo.bundle")
	m, err := Capture(ctx, CaptureOptions{MoveID: "m1", Dir: dir, BundlePath: bundle})
	if err != nil {
		t.Fatal(err)
	}

	// Nothing the user sees moved.
	indexAfter, _ := os.ReadFile(filepath.Join(dir, ".git", "index"))
	if !bytes.Equal(indexBefore, indexAfter) {
		t.Error("capture rewrote the index")
	}
	if got := git(t, dir, "rev-parse", "HEAD"); got != headBefore {
		t.Errorf("HEAD moved: %s -> %s", headBefore, got)
	}
	if got := git(t, dir, "symbolic-ref", "HEAD"); got != "refs/heads/work" {
		t.Errorf("HEAD left the branch: %s", got)
	}
	if got := git(t, dir, "status", "--porcelain=v2"); got != statusBefore {
		t.Errorf("status changed:\n%s\nvs\n%s", statusBefore, got)
	}
	if d := diffStates(stateBefore, treeState(t, dir)); len(d) > 0 {
		t.Errorf("the working tree changed: %v", d)
	}

	// What it recorded.
	if !m.Repository || m.Head.Branch != "refs/heads/work" || m.Head.Detached || m.Head.Unborn {
		t.Fatalf("head = %+v", m.Head)
	}
	if m.Snapshot == nil || !m.Snapshot.Dirty || m.Snapshot.Ref != "refs/cloop/move/m1" {
		t.Fatalf("snapshot = %+v", m.Snapshot)
	}
	if got := git(t, dir, "rev-parse", "refs/cloop/move/m1"); got != m.Snapshot.Commit {
		t.Errorf("hidden ref = %s, manifest says %s", got, m.Snapshot.Commit)
	}
	branches := map[string]Ref{}
	for _, b := range m.Branches {
		branches[b.Name] = b
	}
	if len(branches) != 3 || !branches["refs/heads/main"].Pushed || branches["refs/heads/work"].Pushed || !branches["refs/heads/side"].Pushed {
		t.Errorf("branches = %+v", m.Branches)
	}
	if len(m.Tags) != 1 || m.Tags[0].Name != "refs/tags/v1" || m.Tags[0].Object == m.Tags[0].Commit {
		t.Errorf("tags = %+v (an annotated tag names its tag object)", m.Tags)
	}
	if len(m.Stash) != 1 {
		t.Errorf("stash = %+v", m.Stash)
	}
	if len(m.Remotes) != 1 || strings.Contains(m.Remotes[0].URL, "s3cr3t") || m.Remotes[0].URL != "https://example.com/acme/proj.git" {
		t.Errorf("remotes = %+v: credentials must not reach the manifest", m.Remotes)
	}
	if m.Bundle == nil || m.Bundle.Bytes <= 0 {
		t.Fatalf("bundle = %+v", m.Bundle)
	}
	if err := VerifyFile(bundle, *m.Bundle); err != nil {
		t.Fatal(err)
	}

	// Rebuilt somewhere else, from the bundle alone.
	target := filepath.Join(t.TempDir(), "copy")
	if err := Restore(ctx, RestoreOptions{Dir: target, BundlePath: bundle, Manifest: m,
		Upstream: "https://hub.example/git/acme/proj.git"}); err != nil {
		t.Fatal(err)
	}
	// Everything but the ignored file, which does not travel.
	carried := map[string]string{}
	for k, v := range stateBefore {
		if k != "debug.log" {
			carried[k] = v
		}
	}
	if d := diffStates(carried, treeState(t, target)); len(d) > 0 {
		t.Errorf("the restored tree differs: %v", d)
	}
	if _, err := os.Lstat(filepath.Join(target, "debug.log")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an ignored file travelled: %v", err)
	}
	// The source's .cloop is the hub's bookkeeping, outside the snapshot.
	if got, want := git(t, target, "status", "--porcelain=v2"), withoutLine(statusBefore, "? .cloop/"); got != want {
		t.Errorf("the restored copy's status differs (staged vs unstaged):\n%s\nvs\n%s", got, want)
	}
	if got := git(t, target, "symbolic-ref", "HEAD"); got != "refs/heads/work" {
		t.Errorf("restored HEAD = %s", got)
	}
	if got := git(t, target, "config", "remote.origin.url"); got != "https://hub.example/git/acme/proj.git" {
		t.Errorf("origin = %s", got)
	}
	if got := git(t, target, "config", "cloop.upstream"); got != "https://hub.example/git/acme/proj.git" {
		t.Errorf("upstream = %s", got)
	}
	if got := git(t, target, "stash", "list"); got != "" {
		t.Logf("stash list on the copy: %q (the entries travel as refs)", got)
	}
	if got := git(t, target, "rev-parse", m.Stash[0].Name); got != m.Stash[0].Object {
		t.Errorf("stash ref = %s", got)
	}
	o, err := Inspect(ctx, target, InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if mm := Compare(m, o); len(mm) > 0 {
		t.Errorf("the restored copy does not match its manifest: %v", mm)
	}
	// The source itself still matches: nothing moved under it.
	o, err = Inspect(ctx, dir, InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if mm := Compare(m, o); len(mm) > 0 {
		t.Errorf("the source no longer matches: %v", mm)
	}
	if !bytes.Equal(indexBefore, mustRead(t, filepath.Join(dir, ".git", "index"))) {
		t.Error("inspect rewrote the source's index")
	}
}

func withoutLine(s, drop string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if l != drop {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCompareFindsWhatDiffers(t *testing.T) {
	ctx := context.Background()
	dir := dirtyRepo(t)
	bundle := filepath.Join(t.TempDir(), "repo.bundle")
	m, err := Capture(ctx, CaptureOptions{MoveID: "m2", Dir: dir, BundlePath: bundle})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "copy")
	if err := Restore(ctx, RestoreOptions{Dir: target, BundlePath: bundle, Manifest: m}); err != nil {
		t.Fatal(err)
	}
	// One byte of one untracked file, one branch moved.
	write(t, filepath.Join(target, "notes", "untracked.txt"), []byte("neW\n"), 0o644)
	git(t, target, "update-ref", "refs/heads/side", m.Snapshot.Commit)
	o, err := Inspect(ctx, target, InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, mm := range Compare(m, o) {
		got[mm.What] = true
	}
	if !got["the working tree"] || !got["branch refs/heads/side"] || !got["tree of branch refs/heads/side"] {
		t.Errorf("mismatches = %v", got)
	}
	if got["the index"] {
		t.Error("an unstaged edit was reported as an index change")
	}
}

func TestCaptureOfLinkedWorktreesAndADetachedHead(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dir := filepath.Join(root, "proj")
	_ = os.MkdirAll(dir, 0o755)
	git(t, dir, "init", "-q", "-b", "main")
	write(t, filepath.Join(dir, "a.txt"), []byte("a\n"), 0o644)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "a")
	feat := filepath.Join(dir, ".cloop", "features", "f1")
	git(t, dir, "worktree", "add", "-q", "-b", "cloop/feature/f1", feat)
	write(t, filepath.Join(feat, "a.txt"), []byte("feature edit\n"), 0o644)
	clean := filepath.Join(dir, ".cloop", "features", "f2")
	git(t, dir, "worktree", "add", "-q", "-b", "cloop/feature/f2", clean)
	// The main worktree detached, on a commit no branch holds.
	write(t, filepath.Join(dir, "a.txt"), []byte("orphan\n"), 0o644)
	git(t, dir, "checkout", "-q", "--detach")
	git(t, dir, "commit", "-q", "-am", "orphan")
	orphan := git(t, dir, "rev-parse", "HEAD")

	bundle := filepath.Join(t.TempDir(), "repo.bundle")
	m, err := Capture(ctx, CaptureOptions{MoveID: "m3", Dir: dir, BundlePath: bundle})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Head.Detached || m.Head.Commit != orphan {
		t.Fatalf("head = %+v", m.Head)
	}
	if m.Snapshot.Dirty {
		t.Errorf("a clean detached tree was recorded dirty: %+v", m.Snapshot)
	}
	if len(m.Worktrees) != 2 {
		t.Fatalf("worktrees = %+v", m.Worktrees)
	}
	if w := m.Worktrees[0]; w.Rel != ".cloop/features/f1" || !w.Dirty || w.Ref == "" || w.Head.Branch != "refs/heads/cloop/feature/f1" {
		t.Errorf("feature f1 = %+v", w)
	}
	if w := m.Worktrees[1]; w.Dirty || w.Ref != "" {
		t.Errorf("the clean feature f2 got a ref: %+v", w)
	}
	// The detached commit and the feature's changes are in the bundle: a
	// clone of it holds them.
	target := filepath.Join(t.TempDir(), "copy")
	if err := Restore(ctx, RestoreOptions{Dir: target, BundlePath: bundle, Manifest: m}); err != nil {
		t.Fatal(err)
	}
	if got := git(t, target, "rev-parse", "HEAD"); got != orphan {
		t.Errorf("detached HEAD = %s, want %s", got, orphan)
	}
	if got := git(t, target, "show", m.Worktrees[0].Ref+":a.txt"); got != "feature edit" {
		t.Errorf("the feature's change on its ref = %q", got)
	}
	o, err := Inspect(ctx, target, InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if mm := Compare(m, o); len(mm) > 0 {
		t.Errorf("mismatches: %v", mm)
	}
}

func TestCaptureOfAnUnbornRepositoryAndOfNoRepository(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "proj")
	_ = os.MkdirAll(dir, 0o755)
	m, err := Capture(ctx, CaptureOptions{MoveID: "m4", Dir: dir, BundlePath: filepath.Join(t.TempDir(), "b")})
	if err != nil || m.Repository {
		t.Fatalf("no .git: %+v, %v", m, err)
	}

	git(t, dir, "init", "-q", "-b", "trunk")
	write(t, filepath.Join(dir, "first.txt"), []byte("first\n"), 0o644)
	git(t, dir, "add", "first.txt")
	write(t, filepath.Join(dir, "loose.txt"), []byte("loose\n"), 0o644)
	bundle := filepath.Join(t.TempDir(), "repo.bundle")
	m, err = Capture(ctx, CaptureOptions{MoveID: "m4", Dir: dir, BundlePath: bundle})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Head.Unborn || m.Head.Branch != "refs/heads/trunk" || len(m.Branches) != 0 || !m.Snapshot.Dirty {
		t.Fatalf("unborn = %+v %+v", m.Head, m.Snapshot)
	}
	target := filepath.Join(t.TempDir(), "copy")
	if err := Restore(ctx, RestoreOptions{Dir: target, BundlePath: bundle, Manifest: m}); err != nil {
		t.Fatal(err)
	}
	if d := diffStates(treeState(t, dir), treeState(t, target)); len(d) > 0 {
		t.Errorf("differs: %v", d)
	}
	if got := git(t, target, "status", "--porcelain=v2", "--branch"); !strings.Contains(got, "branch.head trunk") ||
		!strings.Contains(got, "A. N... 000000 100644 100644") || !strings.Contains(got, "? loose.txt") {
		t.Errorf("status = %s", got)
	}
}

func TestCaptureRefusesWhatItMustNotRead(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	elsewhere := filepath.Join(root, "elsewhere")
	_ = os.MkdirAll(elsewhere, 0o755)
	git(t, elsewhere, "init", "-q")
	linked := filepath.Join(root, "linked")
	_ = os.MkdirAll(linked, 0o755)
	if err := os.Symlink(filepath.Join(elsewhere, ".git"), filepath.Join(linked, ".git")); err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(ctx, CaptureOptions{MoveID: "m5", Dir: linked, BundlePath: filepath.Join(root, "b")}); !errors.Is(err, ErrNotARepository) {
		t.Errorf("a .git link: %v", err)
	}
	// A project directory inside someone else's repository has no
	// repository of its own: nothing of the enclosing one is captured.
	inner := filepath.Join(elsewhere, "sub")
	_ = os.MkdirAll(inner, 0o755)
	if m, err := Capture(ctx, CaptureOptions{MoveID: "m5", Dir: inner, BundlePath: filepath.Join(root, "b")}); err != nil || m.Repository {
		t.Errorf("a subdirectory of another repository: %+v, %v", m, err)
	}
	if _, err := os.Stat(filepath.Join(root, "b")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a bundle was written for it: %v", err)
	}
	if _, err := Capture(ctx, CaptureOptions{MoveID: "../x", Dir: elsewhere, BundlePath: filepath.Join(root, "b")}); err == nil {
		t.Error("an id that is not a ref name was accepted")
	}
}

func TestCaptureRefusesABundleOverItsBound(t *testing.T) {
	ctx := context.Background()
	dir := dirtyRepo(t)
	bundle := filepath.Join(t.TempDir(), "repo.bundle")
	_, err := Capture(ctx, CaptureOptions{MoveID: "m6", Dir: dir, BundlePath: bundle, MaxBundleBytes: 512})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if _, err := os.Stat(bundle); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an oversized bundle was left at its path: %v", err)
	}
	if _, err := os.Stat(bundle + ".part"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the partial bundle was left behind: %v", err)
	}
	n, err := EstimateBytes(ctx, dir)
	if err != nil || n <= 0 {
		t.Errorf("estimate = %d, %v", n, err)
	}
}

func TestRestoreRefusesABundleThatIsNotTheOneCaptured(t *testing.T) {
	ctx := context.Background()
	dir := dirtyRepo(t)
	bundle := filepath.Join(t.TempDir(), "repo.bundle")
	m, err := Capture(ctx, CaptureOptions{MoveID: "m7", Dir: dir, BundlePath: bundle})
	if err != nil {
		t.Fatal(err)
	}
	data := mustRead(t, bundle)
	data[len(data)-1] ^= 0xff
	write(t, bundle, data, 0o600)
	err = Restore(ctx, RestoreOptions{Dir: filepath.Join(t.TempDir(), "c"), BundlePath: bundle, Manifest: m})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a tampered bundle: %v", err)
	}
}

func TestCarrierRoundTrip(t *testing.T) {
	ctx := context.Background()
	work := t.TempDir()
	a := filepath.Join(work, "a")
	b := filepath.Join(work, "b.bin")
	write(t, a, []byte("manifest"), 0o644)
	write(t, b, binary(5000, 1), 0o644)
	out := filepath.Join(work, "seed.bundle")
	c, err := BuildCarrier(ctx, work, "cloop/move/m8", []CarrierFile{{Name: "move.json", Path: a}, {Name: "repo.bundle", Path: b}}, out, 0)
	if err != nil {
		t.Fatal(err)
	}
	again, err := BuildCarrier(ctx, t.TempDir(), "cloop/move/m8", []CarrierFile{{Name: "repo.bundle", Path: b}, {Name: "move.json", Path: a}}, filepath.Join(t.TempDir(), "x"), 0)
	if err != nil || again.Head != c.Head {
		t.Errorf("the same files gave another carrier: %s vs %s (%v)", again.Head, c.Head, err)
	}
	// Received the way gitprovision receives a shipped branch.
	dst := filepath.Join(t.TempDir(), "dst")
	_ = os.MkdirAll(dst, 0o755)
	git(t, dst, "init", "-q")
	git(t, dst, "fetch", "-q", out, "+refs/heads/cloop/move/m8:refs/heads/cloop/move/m8")
	got := filepath.Join(t.TempDir(), "got")
	if err := ReadCarrierFile(ctx, dst, c.Head, "repo.bundle", got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustRead(t, got), mustRead(t, b)) {
		t.Error("the carried file came back different")
	}
	if err := ReadCarrierFile(ctx, dst, c.Head, "repo.bundle", got, 100); !errors.Is(err, ErrTooLarge) {
		t.Errorf("an oversized carried file: %v", err)
	}
	if _, err := BuildCarrier(ctx, t.TempDir(), "main", nil, out, 0); err == nil {
		t.Error("a carrier outside the cloop/ namespace was built")
	}
}

func TestStripCredentials(t *testing.T) {
	for in, want := range map[string]string{
		"https://x-access-token:ghs_abc@github.com/a/b.git": "https://github.com/a/b.git",
		"https://github.com/a/b":                            "https://github.com/a/b",
		"git@github.com:a/b.git":                            "git@github.com:a/b.git",
		"/srv/git/b.git":                                    "/srv/git/b.git",
	} {
		if got := StripCredentials(in); got != want {
			t.Errorf("StripCredentials(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCaptureStampsItsCommitsWithTheClock(t *testing.T) {
	ctx := context.Background()
	dir := dirtyRepo(t)
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	m, err := Capture(ctx, CaptureOptions{MoveID: "m9", Dir: dir, BundlePath: filepath.Join(t.TempDir(), "b"),
		Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339, git(t, dir, "log", "-1", "--format=%cI", m.Snapshot.Commit))
	if err != nil || !got.Equal(at) {
		t.Errorf("commit date = %v (%v), want %v", got, err, at)
	}
}
