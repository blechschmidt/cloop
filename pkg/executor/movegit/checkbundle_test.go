package movegit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// captured captures dir for move id, returning the manifest and the bundle.
func captured(t *testing.T, dir, id string) (Manifest, string) {
	t.Helper()
	bundle := filepath.Join(t.TempDir(), "repo.bundle")
	m, err := Capture(context.Background(), CaptureOptions{MoveID: id, Dir: dir, BundlePath: bundle})
	if err != nil {
		t.Fatal(err)
	}
	return m, bundle
}

func TestCheckBundleHoldsABundleToItsManifest(t *testing.T) {
	ctx := context.Background()
	m, bundle := captured(t, dirtyRepo(t), "m1")
	var kinds = map[string]int{}
	seen := map[string]bool{}
	err := CheckBundle(ctx, BundleCheck{BundlePath: bundle, Manifest: m, Scratch: t.TempDir(),
		Object: func(kind, id string, size int64, r io.Reader) error {
			b, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			if int64(len(b)) != size {
				t.Errorf("object %s: read %d bytes of %d", id, len(b), size)
			}
			kinds[kind]++
			seen[id] = true
			return nil
		}})
	if err != nil {
		t.Fatalf("the bundle a capture wrote: %v", err)
	}
	if kinds["commit"] == 0 || kinds["tree"] == 0 || kinds["blob"] == 0 || kinds["tag"] == 0 {
		t.Errorf("objects handed over by type: %v", kinds)
	}
	if !seen[m.Snapshot.Commit] {
		t.Error("the snapshot commit was not handed over")
	}

	// A manifest that leaves out a ref the bundle holds, or names one at
	// another object, is not the bundle's.
	short := m
	short.Branches = append([]Ref(nil), m.Branches[1:]...)
	err = CheckBundle(ctx, BundleCheck{BundlePath: bundle, Manifest: short, Scratch: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "does not name") {
		t.Errorf("a ref the manifest does not name: %v", err)
	}
	if strings.Contains(errString(err), m.Branches[0].Name) {
		t.Errorf("the error names the unnamed ref: %v", err)
	}
	moved := m
	moved.Branches = append([]Ref(nil), m.Branches...)
	moved.Branches[0].Object = m.Snapshot.Commit
	err = CheckBundle(ctx, BundleCheck{BundlePath: bundle, Manifest: moved, Scratch: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), m.Branches[0].Name) {
		t.Errorf("a ref the manifest names at another object: %v", err)
	}

	// An error from Object stops the check and is the check's.
	stop := errors.New("stop")
	if err := CheckBundle(ctx, BundleCheck{BundlePath: bundle, Manifest: m, Scratch: t.TempDir(),
		Object: func(string, string, int64, io.Reader) error { return stop }}); !errors.Is(err, stop) {
		t.Errorf("Object's error: %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// A value a delta builds from copied parts is in no insert of the pack, only
// in the object resolved: the check hands every object over whole.
func TestCheckBundleHandsOverObjectsWhole(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "proj")
	git(t, filepath.Dir(dir), "init", "-q", "-b", "main", dir)
	const secret = "corp-internal-api-key-7f3a9c2e1b"
	var pad strings.Builder
	for i := 0; i < 400; i++ {
		pad.WriteString("line of ordinary configuration that repeats\n")
	}
	half := len(secret) / 2
	// The first version holds the value with eight bytes in its middle;
	// the second drops them, so its delta against the first copies both
	// halves and inserts nothing.
	first := pad.String() + "key: " + secret[:half] + "XXXXXXXX" + secret[half:] + "\n" + pad.String()
	second := pad.String() + "key: " + secret + "\n" + pad.String()
	write(t, filepath.Join(dir, "config.txt"), []byte(first), 0o644)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "first")
	write(t, filepath.Join(dir, "config.txt"), []byte(second), 0o644)
	git(t, dir, "commit", "-q", "-am", "second")
	m, bundle := captured(t, dir, "m2")
	found, foundID, located := "", "", map[string]string{}
	err := CheckBundle(ctx, BundleCheck{BundlePath: bundle, Manifest: m, Scratch: t.TempDir(),
		Object: func(kind, id string, _ int64, r io.Reader) error {
			b, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			if bytes.Contains(b, []byte(secret)) {
				found, foundID = kind, id
			}
			return nil
		},
		Locate:  func() []string { return []string{foundID} },
		Located: func(id, path string) { located[id] = path },
	})
	if err != nil {
		t.Fatal(err)
	}
	if found != "blob" {
		t.Fatalf("the value the second version holds was not handed over in a blob (found in %q)", found)
	}
	if located[foundID] != "config.txt" {
		t.Errorf("the blob was located at %q", located[foundID])
	}
}

func TestReservedPathsAreRefused(t *testing.T) {
	ctx := context.Background()
	reserve := &Reserved{Dir: ".cloop", Allow: []string{"requirements.yaml", "sandbox.yaml"}}
	repo := func(t *testing.T, files map[string]string) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "proj")
		git(t, filepath.Dir(dir), "init", "-q", "-b", "main", dir)
		write(t, filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644)
		for name, content := range files {
			write(t, filepath.Join(dir, filepath.FromSlash(name)), []byte(content), 0o644)
		}
		git(t, dir, "add", "-A", "-f")
		git(t, dir, "commit", "-q", "-m", "base")
		return dir
	}

	// The specs a project commits by design pass, and restore.
	dir := repo(t, map[string]string{".cloop/requirements.yaml": "requirements: []\n", ".cloop/sandbox.yaml": "image: x\n"})
	m, bundle := captured(t, dir, "m3")
	if err := CheckBundle(ctx, BundleCheck{BundlePath: bundle, Manifest: m, Scratch: t.TempDir(), Reserve: reserve}); err != nil {
		t.Fatalf("the committed specs: %v", err)
	}
	target := filepath.Join(t.TempDir(), "hub")
	write(t, filepath.Join(target, ".cloop", "state.db"), []byte("the hub's"), 0o600)
	if err := Restore(ctx, RestoreOptions{Dir: target, BundlePath: bundle, Manifest: m, Reserve: reserve}); err != nil {
		t.Fatalf("restore the committed specs: %v", err)
	}
	if got := string(mustRead(t, filepath.Join(target, ".cloop", "requirements.yaml"))); got != "requirements: []\n" {
		t.Errorf("requirements.yaml = %q", got)
	}
	if got := string(mustRead(t, filepath.Join(target, ".cloop", "state.db"))); got != "the hub's" {
		t.Errorf("the hub's database = %q", got)
	}

	for name, files := range map[string]map[string]string{
		"the database":            {".cloop/state.db": "theirs"},
		"the configuration":       {".cloop/config.yaml": "executor: x\n"},
		"a nested file":           {".cloop/features/f/.cloop/env.yaml": "A: b\n"},
		"the directory as a file": {".cloop": "not a directory\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := repo(t, files)
			m, bundle := captured(t, dir, "m4")
			err := CheckBundle(ctx, BundleCheck{BundlePath: bundle, Manifest: m, Scratch: t.TempDir(), Reserve: reserve})
			if !errors.Is(err, ErrForbiddenPath) {
				t.Fatalf("check: %v", err)
			}
			target := filepath.Join(t.TempDir(), "hub")
			write(t, filepath.Join(target, ".cloop", "state.db"), []byte("the hub's"), 0o600)
			err = Restore(ctx, RestoreOptions{Dir: target, BundlePath: bundle, Manifest: m, Reserve: reserve})
			if !errors.Is(err, ErrForbiddenPath) {
				t.Fatalf("restore: %v", err)
			}
			if got := string(mustRead(t, filepath.Join(target, ".cloop", "state.db"))); got != "the hub's" {
				t.Errorf("the hub's database = %q", got)
			}
		})
	}
}

// An index holding unresolved conflicts is recorded as HEAD's with a note;
// any other failure to read it fails the capture rather than being taken for
// one.
func TestAConflictedIndexIsNotedAndOtherFailuresAreNot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proj")
	git(t, filepath.Dir(dir), "init", "-q", "-b", "main", dir)
	write(t, filepath.Join(dir, "f.txt"), []byte("a\n"), 0o644)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "a")
	git(t, dir, "checkout", "-q", "-b", "side")
	write(t, filepath.Join(dir, "f.txt"), []byte("b\n"), 0o644)
	git(t, dir, "commit", "-q", "-am", "b")
	git(t, dir, "checkout", "-q", "main")
	write(t, filepath.Join(dir, "f.txt"), []byte("c\n"), 0o644)
	git(t, dir, "commit", "-q", "-am", "c")
	cmd := exec.Command("git", "-c", "user.name=t", "-c", "user.email=t@example.com", "merge", "-q", "side")
	cmd.Dir = dir
	_ = cmd.Run() // conflicts, by design
	m, _ := captured(t, dir, "m5")
	if !strings.Contains(m.Snapshot.IndexNote, "unresolved conflicts") || m.Snapshot.IndexTree != m.Snapshot.BaseTree {
		t.Errorf("a conflicted index: note %q, index %s, base %s", m.Snapshot.IndexNote, m.Snapshot.IndexTree, m.Snapshot.BaseTree)
	}
	if !unmerged(&gitError{raw: "f.txt: unmerged (0123)\nfatal: git-write-tree: error building trees"}) ||
		unmerged(&gitError{raw: "fatal: index file open failed: Permission denied"}) || unmerged(errors.New("unmerged")) {
		t.Error("unmerged() misreads git's errors")
	}
}
