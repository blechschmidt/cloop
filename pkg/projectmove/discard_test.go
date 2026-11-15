package projectmove

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/movegit"
)

// discardOpts is what the hub sends the device for the copy rec captured.
func discardOpts(rec *CaptureRecord, id string) DiscardOptions {
	return DiscardOptions{MoveID: id, Snapshot: rec.Git.Snapshot.Commit, Refs: RefsDigest(rec.Git), Files: FilesDigest(rec.Files)}
}

// TestDiscardRemovesOnlyTheCopyTheMoveCaptured is the device's half of a
// verified move's cleanup (Task 20496): the copy a capture left goes, but only
// while it holds exactly what the capture recorded — and every way it could
// have come to hold something else keeps it whole.
func TestDiscardRemovesOnlyTheCopyTheMoveCaptured(t *testing.T) {
	ctx := context.Background()
	const id = "0123456789abcdef"

	// A copy captured and left as it was is removed, the directory kept — and
	// a link in it to somewhere else is removed, not followed.
	dir := dirtyProject(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	put(t, outside, []byte("not the copy's\n"), 0o644)
	if err := os.Symlink(outside, filepath.Join(dir, "link-to-outside")); err != nil {
		t.Fatal(err)
	}
	rec, _ := capture(t, dir, id)
	opts := discardOpts(rec, id)
	rep, err := DiscardWorkingCopy(ctx, dir, opts)
	if err != nil {
		t.Fatalf("DiscardWorkingCopy: %v", err)
	}
	if !rep.Empty || rep.Kept != "" || rep.Entries == 0 || len(rep.Examples) == 0 {
		t.Errorf("report = %+v", rep)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("the copy's directory holds %d entries (%v), want it empty and kept", len(entries), err)
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "not the copy's\n" {
		t.Errorf("a symbolic link's target was touched: %q %v", b, err)
	}
	// Again: nothing left to do.
	if rep, err := DiscardWorkingCopy(ctx, dir, opts); err != nil || !rep.Empty || rep.Entries != 0 {
		t.Errorf("a second discard = %+v, %v", rep, err)
	}
	// And a directory that is gone already.
	if rep, err := DiscardWorkingCopy(ctx, filepath.Join(t.TempDir(), "gone"), opts); err != nil || !rep.Empty {
		t.Errorf("a missing directory = %+v, %v", rep, err)
	}

	// Every way the copy can have come to hold something the move did not
	// carry keeps it whole.
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, dir string)
		kept   string
		says   string
	}{
		{"a file edited", func(t *testing.T, dir string) {
			put(t, filepath.Join(dir, "renamed.txt"), []byte("edited after the capture\n"), 0o644)
		}, KeptChanged, "files git tracks or would track differ"},
		{"a file added", func(t *testing.T, dir string) {
			put(t, filepath.Join(dir, "after.txt"), []byte("new\n"), 0o644)
		}, KeptChanged, "files git tracks or would track differ"},
		{"the index changed", func(t *testing.T, dir string) {
			runGit(t, dir, "add", "loose.bin")
		}, KeptChanged, "the index differs"},
		{"a commit", func(t *testing.T, dir string) {
			runGit(t, dir, "add", "-A")
			runGit(t, dir, "commit", "-q", "-m", "after the capture")
		}, KeptChanged, "HEAD is at"},
		{"a commit on another branch, HEAD back where it was", func(t *testing.T, dir string) {
			runGit(t, dir, "branch", "-f", "main", "topic")
		}, KeptChanged, "branches, tags, notes or stash differ"},
		{"a new branch", func(t *testing.T, dir string) {
			runGit(t, dir, "branch", "wip")
		}, KeptChanged, "branches, tags, notes or stash differ"},
		{"a note", func(t *testing.T, dir string) {
			runGit(t, dir, "notes", "add", "-m", "remember this")
		}, KeptChanged, "branches, tags, notes or stash differ"},
		{"a file under .cloop a move carries", func(t *testing.T, dir string) {
			put(t, filepath.Join(dir, ".cloop", "artifacts", "8_output.txt"), []byte("written after the capture\n"), 0o644)
		}, KeptChanged, "files under .cloop"},
		{"a linked worktree", func(t *testing.T, dir string) {
			runGit(t, dir, "worktree", "add", "-q", filepath.Join(t.TempDir(), "wt"), "main")
		}, KeptChanged, "linked worktree"},
		{"a file git ignores", func(t *testing.T, dir string) {
			put(t, filepath.Join(dir, ".git", "info", "exclude"), []byte("*.env\n"), 0o644)
			put(t, filepath.Join(dir, "secrets.env"), []byte("TOKEN=only-copy\n"), 0o600)
		}, KeptIgnored, "git ignores"},
		{"another move's snapshot under the ref", func(t *testing.T, dir string) {
			runGit(t, dir, "update-ref", movegit.SnapshotRefPrefix+id, "HEAD")
		}, KeptChanged, "rather than the snapshot"},
		{"the snapshot ref gone", func(t *testing.T, dir string) {
			runGit(t, dir, "update-ref", "-d", movegit.SnapshotRefPrefix+id)
		}, KeptChanged, "rather than the snapshot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := dirtyProject(t)
			rec, _ := capture(t, dir, id)
			tc.change(t, dir)
			before := files(t, dir)
			rep, err := DiscardWorkingCopy(ctx, dir, discardOpts(rec, id))
			if err != nil {
				t.Fatalf("DiscardWorkingCopy: %v", err)
			}
			if rep.Empty || rep.Kept != tc.kept || !strings.Contains(strings.Join(rep.Problems, "; "), tc.says) {
				t.Fatalf("report = %+v, want the copy kept (%s) saying %q", rep, tc.kept, tc.says)
			}
			if after := files(t, dir); len(after) != len(before) {
				t.Errorf("the copy lost files: %d before, %d after", len(before), len(after))
			}
			if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
				t.Errorf("the repository went: %v", err)
			}
		})
	}

	// Ignored files go only when asked for.
	ignoring := dirtyProject(t)
	put(t, filepath.Join(ignoring, ".git", "info", "exclude"), []byte("build/\n"), 0o644)
	put(t, filepath.Join(ignoring, "build", "out.o"), []byte("object\n"), 0o644)
	rec, _ = capture(t, ignoring, id)
	asked := discardOpts(rec, id)
	rep, err = DiscardWorkingCopy(ctx, ignoring, asked)
	if err != nil || rep.Kept != KeptIgnored || rep.Ignored != 1 || len(rep.Examples) != 1 || rep.Examples[0] != "build/" {
		t.Fatalf("a copy with build output = %+v, %v", rep, err)
	}
	asked.DiscardIgnored = true
	if rep, err := DiscardWorkingCopy(ctx, ignoring, asked); err != nil || !rep.Empty {
		t.Fatalf("with the ignored files let go = %+v, %v", rep, err)
	}

	// A discard cut off part-way — its marker written, the repository gone —
	// finishes when it runs again.
	cut := dirtyProject(t)
	rec, _ = capture(t, cut, id)
	opts = discardOpts(rec, id)
	put(t, filepath.Join(cut, discardMarker), []byte(id+" "+opts.Snapshot+"\n"), 0o600)
	if err := os.RemoveAll(filepath.Join(cut, ".git")); err != nil {
		t.Fatal(err)
	}
	if rep, err := DiscardWorkingCopy(ctx, cut, opts); err != nil || !rep.Empty {
		t.Fatalf("finishing a discard = %+v, %v", rep, err)
	}
	if entries, _ := os.ReadDir(cut); len(entries) != 0 {
		t.Errorf("after finishing, the copy holds %d entries", len(entries))
	}
	// A marker another move wrote is no licence.
	other := dirtyProject(t)
	rec, _ = capture(t, other, id)
	put(t, filepath.Join(other, discardMarker), []byte("ffffffffffffffff "+rec.Git.Snapshot.Commit+"\n"), 0o600)
	put(t, filepath.Join(other, "after.txt"), []byte("new\n"), 0o644)
	if rep, err := DiscardWorkingCopy(ctx, other, discardOpts(rec, id)); err != nil || rep.Kept == "" {
		t.Errorf("another move's marker = %+v, %v", rep, err)
	}

	// Another project's copy — no snapshot of this move at all.
	stranger := dirtyProject(t)
	head := runGit(t, stranger, "rev-parse", "HEAD")
	if rep, err := DiscardWorkingCopy(ctx, stranger, DiscardOptions{MoveID: id, Snapshot: head, Refs: opts.Refs, Files: opts.Files}); err != nil || rep.Kept != KeptChanged {
		t.Errorf("a copy this move never captured: %+v, %v", rep, err)
	}
	if _, err := os.Stat(filepath.Join(stranger, "a.txt")); err != nil {
		t.Errorf("a copy this move never captured lost a file: %v", err)
	}

	// Malformed arguments are refused before anything is read.
	for _, bad := range []DiscardOptions{
		{MoveID: "../x", Snapshot: opts.Snapshot, Refs: opts.Refs, Files: opts.Files},
		{MoveID: id, Snapshot: "HEAD", Refs: opts.Refs, Files: opts.Files},
		{MoveID: id, Snapshot: "--all", Refs: opts.Refs, Files: opts.Files},
		{MoveID: id, Snapshot: opts.Snapshot, Refs: "", Files: opts.Files},
		{MoveID: id, Snapshot: opts.Snapshot, Refs: opts.Refs, Files: "not-a-digest"},
	} {
		if _, err := DiscardWorkingCopy(ctx, stranger, bad); err == nil {
			t.Errorf("DiscardWorkingCopy(%+v) was accepted", bad)
		}
	}
	// A path that is a symbolic link is not a working copy to remove.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(stranger, link); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscardWorkingCopy(ctx, link, opts); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a symbolic link: %v", err)
	}
}

// TestReadSnapshotReadsBackWhatTheCaptureRecorded holds movegit.ReadSnapshot
// to the snapshot a capture writes, and refuses a commit of any other shape.
func TestReadSnapshotReadsBackWhatTheCaptureRecorded(t *testing.T) {
	ctx := context.Background()
	dir := dirtyProject(t)
	rec, _ := capture(t, dir, "fedcba9876543210")
	const rid = "fedcba9876543210"
	want := *rec.Git.Snapshot
	got, err := movegit.ReadSnapshot(ctx, dir, rid, want.Commit)
	if err != nil {
		t.Fatal(err)
	}
	if got.Base != want.Base || got.BaseTree != want.BaseTree || got.IndexTree != want.IndexTree ||
		got.WorktreeTree != want.WorktreeTree || got.Dirty != want.Dirty {
		t.Errorf("read back %+v, the capture recorded %+v", got, want)
	}
	// A plain commit is not a snapshot.
	if _, err := movegit.ReadSnapshot(ctx, dir, rid, runGit(t, dir, "rev-parse", "HEAD")); err == nil {
		t.Error("an ordinary commit was read as a snapshot")
	}
	// Nor is another move's snapshot.
	if _, err := movegit.ReadSnapshot(ctx, dir, "0000000000000000", want.Commit); err == nil {
		t.Error("another move's snapshot was read as this one's")
	}
	// Nor a name, or a revision expression.
	for _, c := range []string{"HEAD", "--output=/tmp/x", want.Commit + "^"} {
		if _, err := movegit.ReadSnapshot(ctx, dir, rid, c); err == nil {
			t.Errorf("ReadSnapshot(%q) was accepted", c)
		}
	}

	// An unborn branch's snapshot has no base.
	fresh := filepath.Join(t.TempDir(), "fresh")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, fresh, "init", "-q", "-b", "main")
	put(t, filepath.Join(fresh, "first.txt"), []byte("first\n"), 0o644)
	rec, _ = capture(t, fresh, "fedcba9876543211")
	got, err = movegit.ReadSnapshot(ctx, fresh, "fedcba9876543211", rec.Git.Snapshot.Commit)
	if err != nil {
		t.Fatal(err)
	}
	if got.Base != "" || got.BaseTree != movegit.EmptyTree || got.WorktreeTree != rec.Git.Snapshot.WorktreeTree {
		t.Errorf("unborn: %+v, recorded %+v", got, *rec.Git.Snapshot)
	}
}
