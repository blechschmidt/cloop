package movegit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// roundTrip is a project that left a hub for a device and is coming back:
// the hub's copy as the first move captured it (with a feature worktree
// registered in its repository), the device's copy seeded from that capture,
// and the bundle a capture of the device's copy will be written to.
type roundTrip struct {
	hub, device, feature string
	base                 Manifest
	store                string
}

func newRoundTrip(t *testing.T) *roundTrip {
	t.Helper()
	return newRoundTripWith(t, nil)
}

// newRoundTripWith is newRoundTrip with setup run on the hub's copy before the
// move away captures it.
func newRoundTripWith(t *testing.T, setup func(hub string)) *roundTrip {
	t.Helper()
	ctx := context.Background()
	r := &roundTrip{hub: dirtyRepo(t), store: t.TempDir()}
	// A feature's worktree, inside .cloop as the hub keeps them.
	r.feature = filepath.Join(r.hub, ".cloop", "features", "widget")
	git(t, r.hub, "worktree", "add", "-q", "-b", "cloop/feature/widget", r.feature, "main")
	write(t, filepath.Join(r.feature, "widget.txt"), []byte("widget\n"), 0o644)
	git(t, r.feature, "add", "widget.txt")
	git(t, r.feature, "commit", "-q", "-m", "widget")
	if setup != nil {
		setup(r.hub)
	}

	bundle := filepath.Join(r.store, "left.bundle")
	m, err := Capture(ctx, CaptureOptions{MoveID: "away", Dir: r.hub, BundlePath: bundle})
	if err != nil {
		t.Fatal(err)
	}
	r.base = m
	r.device = filepath.Join(t.TempDir(), "device")
	if err := Restore(ctx, RestoreOptions{Dir: r.device, BundlePath: bundle, Manifest: m}); err != nil {
		t.Fatal(err)
	}
	return r
}

// capture captures the device's copy for the move back.
func (r *roundTrip) capture(t *testing.T) (Manifest, string) {
	t.Helper()
	return r.captureAs(t, "back")
}

// captureAs captures the device's copy as move id.
func (r *roundTrip) captureAs(t *testing.T, id string) (Manifest, string) {
	t.Helper()
	bundle := filepath.Join(r.store, id+".bundle")
	m, err := Capture(context.Background(), CaptureOptions{MoveID: id, Dir: r.device, BundlePath: bundle})
	if err != nil {
		t.Fatal(err)
	}
	return m, bundle
}

func (r *roundTrip) restore(m Manifest, bundle string, resuming bool) ([]Ref, error) {
	return RestoreInto(context.Background(), RestoreOptions{Dir: r.hub, BundlePath: bundle, Manifest: m}, r.base, resuming)
}

// carriedState is treeState without the files git ignores in the fixture
// (dirtyRepo's debug.log): a move neither carries nor removes them.
func carriedState(t *testing.T, dir string) map[string]string {
	t.Helper()
	st := treeState(t, dir)
	delete(st, "debug.log")
	return st
}

func refsOf(t *testing.T, dir string) string {
	t.Helper()
	return git(t, dir, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags")
}

// TestRestoreIntoTheCopyLeftBehind: the device's work comes back into the
// hub's own repository — its working copy, its branches, a branch it
// deleted — while the feature branch the hub moved meanwhile, and the
// feature's worktree, stay the hub's.
func TestRestoreIntoTheCopyLeftBehind(t *testing.T) {
	ctx := context.Background()
	r := newRoundTrip(t)

	// Work on the device: a commit on the branch it is on, a new branch, a
	// deleted one, and uncommitted changes of every kind.
	git(t, r.device, "add", "-A")
	git(t, r.device, "commit", "-q", "-m", "committed on the device")
	git(t, r.device, "branch", "device-only")
	git(t, r.device, "branch", "-D", "side")
	write(t, filepath.Join(r.device, "README.md"), []byte("edited on the device\n"), 0o644)
	if err := os.Remove(filepath.Join(r.device, "new-name.txt")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(r.device, "device.bin"), binary(500, 11), 0o644)
	git(t, r.device, "add", "device.bin")
	write(t, filepath.Join(r.device, "scratch", "note.txt"), []byte("untracked on the device\n"), 0o644)
	// Meanwhile on the hub: the feature's branch moved on, as a feature run's
	// written-back work moves it.
	write(t, filepath.Join(r.feature, "widget.txt"), []byte("widget, written back\n"), 0o644)
	git(t, r.feature, "commit", "-q", "-am", "written back")
	featureTip := git(t, r.hub, "rev-parse", "refs/heads/cloop/feature/widget")

	m, bundle := r.capture(t)
	kept, err := r.restore(m, bundle, false)
	if err != nil {
		t.Fatalf("RestoreInto: %v", err)
	}
	if len(kept) != 1 || kept[0].Name != "refs/heads/cloop/feature/widget" || kept[0].Object != featureTip || kept[0].Tree == "" {
		t.Fatalf("kept = %+v, want the hub's feature branch at %s", kept, featureTip)
	}
	if d := diffStates(carriedState(t, r.device), carriedState(t, r.hub)); len(d) > 0 {
		t.Errorf("the hub's working tree is not the device's: %v", d)
	}
	if _, err := os.Stat(filepath.Join(r.hub, "debug.log")); err != nil {
		t.Errorf("the hub's ignored file was removed: %v", err)
	}
	if got, want := git(t, r.hub, "status", "--porcelain=v2", "--", ".", ":(exclude).cloop"),
		git(t, r.device, "status", "--porcelain=v2", "--", ".", ":(exclude).cloop"); got != want {
		t.Errorf("status on the hub:\n%s\nwant the device's:\n%s", got, want)
	}
	deviceFeature := git(t, r.device, "rev-parse", "refs/heads/cloop/feature/widget")
	want := strings.Replace(refsOf(t, r.device), "refs/heads/cloop/feature/widget "+deviceFeature,
		"refs/heads/cloop/feature/widget "+featureTip, 1)
	if got := refsOf(t, r.hub); got != want {
		t.Errorf("the hub's branches:\n%s\nwant:\n%s", got, want)
	}
	if got := git(t, r.hub, "symbolic-ref", "HEAD"); got != m.Head.Branch {
		t.Errorf("HEAD = %s, want %s", got, m.Head.Branch)
	}
	// The feature's worktree is still the hub's, registered and on its branch.
	if got := git(t, r.feature, "rev-parse", "HEAD"); got != featureTip {
		t.Errorf("the feature's worktree is at %s, want %s", got, featureTip)
	}
	if got := git(t, r.feature, "status", "--porcelain"); got != "" {
		t.Errorf("the feature's worktree is not clean: %s", got)
	}
	// Compared as a move's verification compares, with the kept ref expected.
	o, err := Inspect(ctx, r.hub, InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if mm := Compare(m.WithRefs(kept), o); len(mm) > 0 {
		t.Errorf("the restored copy does not match the capture: %v", mm)
	}
	for _, mm := range Compare(m, o) {
		if !strings.HasSuffix(mm.What, "refs/heads/cloop/feature/widget") {
			t.Errorf("against the capture alone, only the kept branch should differ: %v", mm)
		}
	}
	// Of the hidden refs, only the ones each capture wrote, in its own
	// namespaces.
	for _, ref := range strings.Split(git(t, r.hub, "for-each-ref", "--format=%(refname)", "refs/cloop/"), "\n") {
		if ref != "" && !strings.Contains(ref, "/away") && !strings.Contains(ref, "/back") {
			t.Errorf("the restore wrote a hidden ref of no capture: %s", ref)
		}
	}

	// Run again (a hub that stopped after the restore resumes it): nothing
	// changes, and the same branch is reported kept.
	again, err := r.restore(m, bundle, true)
	if err != nil {
		t.Fatalf("RestoreInto again: %v", err)
	}
	if len(again) != 1 || again[0].Object != featureTip {
		t.Errorf("kept on the second run = %+v", again)
	}
	if d := diffStates(carriedState(t, r.device), carriedState(t, r.hub)); len(d) > 0 {
		t.Errorf("a second run changed the tree: %v", d)
	}
}

// TestRestoreIntoRefusesWhatWouldLoseWork: a copy left behind that changed
// since, a branch both sides moved, and a branch the capture moved that a
// worktree here has checked out each refuse the restore, and the repository
// is left as it was.
func TestRestoreIntoRefusesWhatWouldLoseWork(t *testing.T) {
	t.Run("the copy changed", func(t *testing.T) {
		r := newRoundTrip(t)
		write(t, filepath.Join(r.hub, "README.md"), []byte("edited on the hub after it was left\n"), 0o644)
		before, state := refsOf(t, r.hub), treeState(t, r.hub)
		m, bundle := r.capture(t)
		if _, err := r.restore(m, bundle, false); !errors.Is(err, ErrLeftBehindChanged) || !strings.Contains(err.Error(), "files on disk changed") {
			t.Fatalf("RestoreInto = %v, want ErrLeftBehindChanged naming the files", err)
		}
		if refsOf(t, r.hub) != before || len(diffStates(state, treeState(t, r.hub))) > 0 {
			t.Error("a refused restore changed the hub's copy")
		}
		problems, err := LeftBehindProblems(context.Background(), r.hub, r.base, InspectOptions{})
		if err != nil || len(problems) != 1 {
			t.Errorf("LeftBehindProblems = %v, %v", problems, err)
		}
	})
	t.Run("a branch moved on both sides", func(t *testing.T) {
		r := newRoundTrip(t)
		git(t, r.hub, "branch", "-f", "side", "refs/heads/cloop/feature/widget")
		git(t, r.device, "branch", "-f", "side", "HEAD")
		before := refsOf(t, r.hub)
		m, bundle := r.capture(t)
		if _, err := r.restore(m, bundle, false); !errors.Is(err, ErrRefsDiverged) || !strings.Contains(err.Error(), "refs/heads/side") {
			t.Fatalf("RestoreInto = %v, want ErrRefsDiverged naming the branch", err)
		}
		if refsOf(t, r.hub) != before {
			t.Error("a refused restore moved the hub's branches")
		}
	})
	t.Run("a checked-out branch moved in the capture", func(t *testing.T) {
		r := newRoundTrip(t)
		git(t, r.device, "branch", "-f", "cloop/feature/widget", "HEAD")
		m, bundle := r.capture(t)
		if _, err := r.restore(m, bundle, false); !errors.Is(err, ErrRefsDiverged) || !strings.Contains(err.Error(), "checked out") {
			t.Fatalf("RestoreInto = %v, want ErrRefsDiverged naming the worktree", err)
		}
	})
	t.Run("nothing changed is a clean restore", func(t *testing.T) {
		r := newRoundTrip(t)
		m, bundle := r.capture(t)
		kept, err := r.restore(m, bundle, false)
		if err != nil || len(kept) != 0 {
			t.Fatalf("RestoreInto = %+v, %v", kept, err)
		}
		if d := diffStates(carriedState(t, r.device), carriedState(t, r.hub)); len(d) > 0 {
			t.Errorf("trees differ: %v", d)
		}
	})
}

// hubReserve is what the hub's own directory keeps for itself, as
// pkg/projectmove's HubTreeReserved says.
var hubReserve = &Reserved{Dir: ".cloop", Allow: []string{"requirements.yaml", "sandbox.yaml"}}

func (r *roundTrip) restoreReserved(m Manifest, bundle string, resuming bool) ([]Ref, error) {
	return RestoreInto(context.Background(), RestoreOptions{Dir: r.hub, BundlePath: bundle, Manifest: m, Reserve: hubReserve}, r.base, resuming)
}

// TestRestoreIntoLosesNothingTheCaptureDidNotRecord: the review's cases. A
// file in the capture where the hub has an ignored directory is refused, not
// written over it; a .cloop file the hub's repository tracks survives a
// capture that no longer does; HEAD never lands on a branch the hub kept; and
// the repository's own configuration cannot redirect what is read.
func TestRestoreIntoLosesNothingTheCaptureDidNotRecord(t *testing.T) {
	t.Run("an ignored directory where the capture has a file", func(t *testing.T) {
		r := newRoundTrip(t)
		write(t, filepath.Join(r.hub, "keys.log", "key.txt"), []byte("the hub's own, ignored\n"), 0o600)
		// The copy left behind is unchanged: the directory is ignored.
		write(t, filepath.Join(r.device, "keys.log"), []byte("a file on the device\n"), 0o644)
		git(t, r.device, "add", "-f", "keys.log")
		before := refsOf(t, r.hub)
		m, bundle := r.capture(t)
		_, err := r.restore(m, bundle, false)
		if !errors.Is(err, ErrLeftBehindChanged) || !strings.Contains(err.Error(), "write over") {
			t.Fatalf("RestoreInto = %v, want a refusal to write over the ignored directory", err)
		}
		if b, err := os.ReadFile(filepath.Join(r.hub, "keys.log", "key.txt")); err != nil || string(b) != "the hub's own, ignored\n" {
			t.Errorf("the ignored file = %q, %v", b, err)
		}
		if refsOf(t, r.hub) != before {
			t.Error("a refused restore moved the hub's branches")
		}
		if got := git(t, r.hub, "symbolic-ref", "HEAD"); got != r.base.Head.Branch {
			t.Errorf("a refused restore moved HEAD to %s", got)
		}
	})
	t.Run("a .cloop file the hub tracks", func(t *testing.T) {
		r := newRoundTripWith(t, func(hub string) {
			write(t, filepath.Join(hub, ".cloop", "config.yaml"), []byte("api_key: the hub's\n"), 0o600)
			git(t, hub, "add", "-f", ".cloop/config.yaml")
		})
		// What a capture's refusal tells the device's owner to do.
		git(t, r.device, "rm", "-q", "--cached", ".cloop/config.yaml")
		git(t, r.device, "commit", "-q", "-m", "stop tracking the configuration")
		m, bundle := r.capture(t)
		if _, err := r.restoreReserved(m, bundle, false); err != nil {
			t.Fatalf("RestoreInto: %v", err)
		}
		if b, err := os.ReadFile(filepath.Join(r.hub, ".cloop", "config.yaml")); err != nil || string(b) != "api_key: the hub's\n" {
			t.Errorf("the hub's configuration = %q, %v", b, err)
		}
	})
	t.Run("HEAD on a branch the hub moved", func(t *testing.T) {
		r := newRoundTrip(t)
		git(t, r.hub, "branch", "-f", "side", "refs/heads/cloop/feature/widget")
		git(t, r.device, "symbolic-ref", "HEAD", "refs/heads/side")
		before := refsOf(t, r.hub)
		m, bundle := r.capture(t)
		if _, err := r.restore(m, bundle, false); !errors.Is(err, ErrRefsDiverged) || !strings.Contains(err.Error(), "where HEAD goes") {
			t.Fatalf("RestoreInto = %v, want a refusal naming HEAD's branch", err)
		}
		if refsOf(t, r.hub) != before {
			t.Error("a refused restore moved the hub's branches")
		}
	})
	t.Run("the repository's configuration cannot redirect the read", func(t *testing.T) {
		r := newRoundTrip(t)
		other := filepath.Join(t.TempDir(), "other")
		git(t, filepath.Dir(other), "init", "-q", "-b", "main", other)
		write(t, filepath.Join(other, "x.txt"), []byte("other\n"), 0o644)
		git(t, other, "add", "x.txt")
		git(t, other, "commit", "-q", "-m", "other")
		m, bundle := r.capture(t)
		git(t, r.hub, "config", "url."+other+".insteadOf", bundle)
		if _, err := r.restore(m, bundle, false); err != nil {
			t.Fatalf("RestoreInto: %v", err)
		}
		if d := diffStates(carriedState(t, r.device), carriedState(t, r.hub)); len(d) > 0 {
			t.Errorf("the hub is not the device's copy: %v", d)
		}
		if _, err := os.Stat(filepath.Join(r.hub, "x.txt")); err == nil {
			t.Error("the restore read the repository a URL rewrite named")
		}
	})
	t.Run("a branch the capture moved on from where the hub has it", func(t *testing.T) {
		r := newRoundTrip(t)
		// A restore that went ahead once — and whose move then rolled back —
		// left the hub where the device was.
		m, bundle := r.capture(t)
		if _, err := r.restore(m, bundle, false); err != nil {
			t.Fatal(err)
		}
		git(t, r.device, "checkout", "-q", "-f", "side")
		write(t, filepath.Join(r.device, "side.txt"), []byte("more on side\n"), 0o644)
		git(t, r.device, "add", "side.txt")
		git(t, r.device, "commit", "-q", "-m", "more on side")
		git(t, r.device, "checkout", "-q", "-f", "work")
		m2, bundle2 := r.captureAs(t, "back2")
		if _, err := r.restore(m2, bundle2, true); err != nil {
			t.Fatalf("RestoreInto over the earlier restore: %v", err)
		}
		if got, want := git(t, r.hub, "rev-parse", "refs/heads/side"), git(t, r.device, "rev-parse", "refs/heads/side"); got != want {
			t.Errorf("side = %s, want the device's %s", got, want)
		}
	})
	t.Run("resumed after the files were written and before the branches", func(t *testing.T) {
		r := newRoundTrip(t)
		git(t, r.device, "add", "-A")
		git(t, r.device, "commit", "-q", "-m", "committed on the device")
		write(t, filepath.Join(r.device, "README.md"), []byte("edited after\n"), 0o644)
		m, bundle := r.capture(t)
		// What a restore killed between its merge and its ref updates leaves.
		git(t, r.hub, "bundle", "unbundle", bundle)
		git(t, r.hub, "read-tree", r.base.Snapshot.WorktreeTree)
		git(t, r.hub, "update-index", "-q", "--refresh")
		git(t, r.hub, "read-tree", "-m", "-u", r.base.Snapshot.WorktreeTree, m.Snapshot.WorktreeTree)
		if _, err := r.restore(m, bundle, true); err != nil {
			t.Fatalf("RestoreInto, resumed: %v", err)
		}
		if d := diffStates(carriedState(t, r.device), carriedState(t, r.hub)); len(d) > 0 {
			t.Errorf("the hub is not the device's copy: %v", d)
		}
		o, err := Inspect(context.Background(), r.hub, InspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if mm := Compare(m, o); len(mm) > 0 {
			t.Errorf("the resumed restore does not match the capture: %v", mm)
		}
	})
}
