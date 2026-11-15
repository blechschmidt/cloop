package projectmove_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// source is where a move starts: the working copy the project's runs use
// there.
type source struct {
	name string
	// dir is the working copy.
	dir string
	// feature is the feature's worktree, where it is one.
	feature string
	// remote says the source is a device, whose run keeps its plan there.
	remote bool
}

// prepared is what prepareSource left: the task whose run the move
// interrupts, and the snapshot of the source taken just before the move.
type prepared struct {
	hold   int
	before workingCopy
	// head is main's tip, with the commit no remote has.
	head string
	// featureHead is the feature branch's tip, with the commit no remote has.
	featureHead string
	// hubKeeps are refs the target is expected to hold at values of its own:
	// branches the hub moved on while the project was away, which a move
	// back keeps.
	hubKeeps map[string]string
}

// prepareSource leaves at src everything a move must carry: a run in
// progress on a task (which the move's quiesce stops), a commit on main no
// remote has, a feature branch commit no remote has, and a dirty tree — a
// modified, a deleted, a renamed (staged), an untracked and a binary file,
// plus a staged change with an unstaged one on top. k numbers the move, so
// each one's changes are its own.
func (s *scene) prepareSource(k int, src source) prepared {
	s.t.Helper()
	t := s.t
	p := prepared{hold: s.addTask(fmt.Sprintf("Move %d: %s", k, holdMarker))}

	// The run in progress: the stand-in holds its task while the hold file
	// exists where it runs.
	writeFile(t, filepath.Join(src.dir, ".cloop", "e2e-hold"), "hold\n")
	s.run()
	s.waitFor(fmt.Sprintf("task %d to be in progress on %s", p.hold, src.name), 3*time.Minute, func() bool {
		b, _ := os.ReadFile(filepath.Join(src.dir, ".cloop", "e2e-holding"))
		if !strings.HasSuffix(strings.TrimSpace(string(b)), fmt.Sprint(p.hold)) {
			return false
		}
		// A device's run keeps its plan on the device until it ends: the
		// hub sees the task in progress only where the run shares its tree.
		return src.remote || s.taskStatus(p.hold) == "in_progress"
	})

	// A commit on main that no remote has.
	if head := s.git(src.dir, "symbolic-ref", "--short", "HEAD"); head != "main" {
		t.Fatalf("%s: HEAD is on %s, not main", src.name, head)
	}
	writeFile(t, filepath.Join(src.dir, "src", fmt.Sprintf("move%d.go", k)), fmt.Sprintf("package main\n\n// move %d\nfunc move%d() {}\n", k, k))
	s.git(src.dir, "add", "src")
	s.git(src.dir, "commit", "-qm", fmt.Sprintf("move %d: a commit no remote has", k))
	p.head = s.git(src.dir, "rev-parse", "HEAD")

	// A commit on the feature's branch that no remote has.
	if src.feature != "" {
		writeFile(t, filepath.Join(src.feature, fmt.Sprintf("widget-%d.txt", k)), fmt.Sprintf("widget, move %d\n", k))
		s.git(src.feature, "add", fmt.Sprintf("widget-%d.txt", k))
		s.git(src.feature, "commit", "-qm", fmt.Sprintf("widget: move %d", k))
		p.featureHead = s.git(src.feature, "rev-parse", "HEAD")
		if src.remote {
			// The feature's worktree is the hub's, and its branch moved
			// there while the project was on the device: the move back
			// keeps the hub's commits.
			p.hubKeeps = map[string]string{"refs/heads/cloop/feature/widget": p.featureHead}
		}
	}

	// The dirty tree.
	appendFile(t, filepath.Join(src.dir, "README.md"), fmt.Sprintf("\nEdited before move %d, never committed.\n", k))
	deleted := filepath.Join(src.dir, "src", "util.go")
	if _, err := os.Stat(deleted); err == nil {
		if err := os.Remove(deleted); err != nil {
			t.Fatal(err)
		}
	}
	renamedFrom := "docs/old-name.md"
	if k > 1 {
		renamedFrom = fmt.Sprintf("docs/renamed-%d.md", k-1)
	}
	if _, err := os.Stat(filepath.Join(src.dir, filepath.FromSlash(renamedFrom))); err == nil {
		s.git(src.dir, "mv", renamedFrom, fmt.Sprintf("docs/renamed-%d.md", k))
	}
	writeFile(t, filepath.Join(src.dir, "notes", fmt.Sprintf("draft-%d.md", k)), fmt.Sprintf("an untracked draft, move %d\n", k))
	writeBytes(t, filepath.Join(src.dir, "assets", "logo.bin"), binaryBlob(byte(10+k), 6000+k))
	writeBytes(t, filepath.Join(src.dir, "assets", fmt.Sprintf("untracked-%d.bin", k)), binaryBlob(byte(20+k), 3000))
	// Staged, then changed again: the index and the disk disagree.
	writeFile(t, filepath.Join(src.dir, "src", "main.go"), fmt.Sprintf("package main\n\n// staged before move %d\nfunc main() {}\n", k))
	s.git(src.dir, "add", "src/main.go")
	writeFile(t, filepath.Join(src.dir, "src", "main.go"), fmt.Sprintf("package main\n\n// staged, then edited again before move %d\nfunc main() {}\n", k))
	// A run's output under .cloop, which the move delivers.
	writeFile(t, filepath.Join(src.dir, ".cloop", "artifacts", fmt.Sprintf("move-%d_output.txt", k)), fmt.Sprintf("output kept for move %d\n", k))

	p.before = s.snapshot(src.dir)
	if !strings.Contains(p.before.Index, fmt.Sprintf("docs/renamed-%d.md", k)) {
		t.Fatalf("%s: the rename is not staged:\n%s", src.name, p.before.Index)
	}
	return p
}

// afterMove checks what every move promises once it is done: the task the
// move interrupted is pending again, quiesce says it stopped the run, and the
// target holds exactly what the source held. sourceDir is where the source
// keeps its copy after the move ("" when it is targetDir itself).
func (s *scene) afterMove(m map[string]any, p prepared, targetDir, sourceDir string) {
	s.t.Helper()
	t := s.t
	s.requireDone(m)
	if st := s.taskStatus(p.hold); st != "pending" {
		t.Errorf("the task the move interrupted (%d) is %s, want pending", p.hold, st)
	}
	q, _ := dig(m, "detail", "quiesce").(map[string]any)
	stopped := fmt.Sprint(q["stopped"]) + fmt.Sprint(q["requeued"])
	if !strings.Contains(stopped, "the project") {
		t.Errorf("quiesce records stopping nothing: %v", q)
	}
	after := s.snapshot(targetDir)
	want := p.before
	if len(p.hubKeeps) > 0 {
		want.Refs = map[string]string{}
		for k, v := range p.before.Refs {
			want.Refs[k] = v
		}
		for k, v := range p.hubKeeps {
			want.Refs[k] = v
		}
	}
	// Stopping the run wrote the interrupted task's verdict and the end of
	// its output after the snapshot was taken: those are compared with the
	// source as the move left it, below, where there is one.
	interrupted := fmt.Sprintf("artifacts/%d_", p.hold)
	for _, d := range compareCopies(want, after, func(path string) bool { return strings.HasPrefix(path, interrupted) }) {
		t.Errorf("%s does not hold what the source held: %s", targetDir, d)
	}
	if sourceDir != "" {
		kept := s.snapshot(sourceDir)
		for k, v := range p.hubKeeps {
			kept.Refs[k] = v
		}
		for _, d := range compareCopies(kept, after, nil) {
			t.Errorf("%s does not hold what the source (%s) kept: %s", targetDir, sourceDir, d)
		}
	}
	if verdict := after.Extras[interrupted+"verdict.json"]; verdict == "" {
		t.Errorf("the interrupted task's verdict is not on the target: %v", after.Extras)
	}
	if got := after.Refs["refs/heads/main"]; got != p.head {
		t.Errorf("main on the target is %s, want the unpushed %s", got, p.head)
	}
	if p.featureHead != "" {
		if got := after.Refs["refs/heads/cloop/feature/widget"]; got != p.featureHead {
			t.Errorf("the feature's branch on the target is %s, want the unpushed %s", got, p.featureHead)
		}
	}
}

// runNext releases the hold, runs the interrupted task on the target and
// checks that it ran there, filed its attachment, and kept the earlier ones.
func (s *scene) runNext(p prepared, targetDir, where string, earlier map[int]map[string]string) {
	s.t.Helper()
	t := s.t
	for _, d := range []string{targetDir, s.proj} {
		_ = os.Remove(filepath.Join(d, ".cloop", "e2e-hold"))
	}
	s.runTo(p.hold, where)
	ran := filepath.Join(targetDir, fmt.Sprintf("ran-%d.txt", p.hold))
	if b, err := os.ReadFile(ran); err != nil {
		t.Errorf("task %d did not run in %s's working copy: %v", p.hold, where, err)
	} else {
		t.Logf("%s: %s", where, strings.TrimSpace(string(b)))
	}
	got := s.attachments(p.hold)
	if _, ok := got[fmt.Sprintf("report-%d.txt", p.hold)]; !ok {
		t.Errorf("task %d's report is not attached after its run on %s: %v", p.hold, where, got)
	}
	earlier[p.hold] = got
	for id, want := range earlier {
		now := s.attachments(id)
		for name, sum := range want {
			if now[name] != sum {
				t.Errorf("task %d's attachment %s changed or went missing after the move to %s", id, name, where)
			}
		}
	}
}

// TestMoveRoundTrip moves one project hub-local → container → device →
// hub-local, and proves after each move that nothing it held was lost.
func TestMoveRoundTrip(t *testing.T) {
	optIn(t)
	requireDocker(t)
	bin := cloopBinary(t)
	image := buildImage(t, bin)
	s := newScene(t, sceneOptions{hubConfig: fmt.Sprintf("executors:\n    container:\n        enabled: true\n"+
		"        runtime: docker\n        image: %s\n        network: none\n", image)})
	s.initProject()
	s.startHub()
	container := s.containerExecutor()
	device := s.startAgent()

	// A task run on the hub first, so the project has an attachment before
	// any move, and a feature with a branch of its own.
	first := s.addTask("Write the first report")
	s.runTo(first, "the hub")
	attached := map[int]map[string]string{first: s.attachments(first)}
	if len(attached[first]) == 0 {
		t.Fatal("the first task filed no attachment")
	}
	body := s.mustCall(http.StatusOK, "POST", fmt.Sprintf("/api/projects/%d/features", s.idx()),
		map[string]any{"name": "Widget", "description": "Build the widget"})
	featureDir := filepath.Join(s.proj, ".cloop", "features", fmt.Sprint(body["slug"]))
	if _, err := os.Stat(filepath.Join(featureDir, ".git")); err != nil {
		t.Fatalf("the hub created no feature worktree: %v (%v)", err, body)
	}

	// 1. hub-local → the container executor. The container works in the
	// hub's own directory for the project, so nothing moves: the move proves
	// that, and that nothing was lost on the way.
	p := s.prepareSource(1, source{name: "the hub", dir: s.proj, feature: featureDir})
	id := s.startMove(container)
	m := s.waitMove(id, 4*time.Minute)
	s.afterMove(m, p, s.proj, "")
	if c, _ := dig(m, "detail", "capture").(map[string]any); c["delivery"] != "same_tree" {
		t.Errorf("hub-local → container delivery = %v, want same_tree", c["delivery"])
	}
	s.ownProject()
	s.runNext(p, s.proj, "the container", attached)
	s.retainedThenCleaned(id, "")

	// 2. The container → the device, through `cloop executor move`.
	s.ownProject()
	p = s.prepareSource(2, source{name: "the container", dir: s.proj, feature: featureDir})
	out := s.cloop(s.root, "executor", "move", fmt.Sprint(s.idx()), "--to", device, "--yes",
		"--hub", s.base, "--token", hubToken)
	t.Logf("cloop executor move:\n%s", out)
	id = moveIDFrom(t, out)
	m, _ = s.moveView(id)
	s.afterMove(m, p, s.deviceCopy(), s.proj)
	if c, _ := dig(m, "detail", "capture").(map[string]any); c["delivery"] != "device" {
		t.Errorf("container → device delivery = %v, want device", c["delivery"])
	}
	// The hub keeps the copy the project left until the move is cleaned up.
	interrupted := fmt.Sprintf("artifacts/%d_", p.hold)
	for _, d := range compareCopies(p.before, s.snapshot(s.proj), func(path string) bool { return strings.HasPrefix(path, interrupted) }) {
		t.Errorf("the hub's copy changed after the move: %s", d)
	}
	s.runNext(p, s.deviceCopy(), "the device", attached)
	s.retainedThenCleaned(id, "")

	// 3. The device → hub-local. The hub's directory still holds the copy
	// move 2 left there, unchanged, and the feature's worktree registered in
	// its repository, whose branch moves on the hub meanwhile: the move puts
	// the device's working copy in place in that repository and keeps the
	// hub's feature branch.
	p = s.prepareSource(3, source{name: "the device", dir: s.deviceCopy(), feature: featureDir, remote: true})
	pre := s.mustCall(http.StatusOK, "GET", fmt.Sprintf("/api/projects/%d/move/preflight?target=local&quiesce=1", s.idx()), nil)
	if blocked, _ := pre["blocked"].(bool); blocked {
		t.Fatalf("the preflight blocks the move back to the hub: %v", pre["findings"])
	}
	if raw := fmt.Sprint(pre["findings"]); !strings.Contains(raw, "still holds the copy the project left there") {
		t.Errorf("the preflight does not say the hub's directory holds the copy the project left: %s", raw)
	}
	id = s.startMove("local")
	m = s.waitMove(id, 4*time.Minute)
	s.afterMove(m, p, s.proj, s.deviceCopy())
	if c, _ := dig(m, "detail", "capture").(map[string]any); c["delivery"] != "hub_tree" || c["left_behind"] == nil {
		t.Errorf("device → hub capture = %v, want hub_tree over the copy move 2 left", c)
	}
	if kept, _ := dig(m, "detail", "seed", "kept_refs").([]any); len(kept) != 1 {
		t.Errorf("the seed kept %v, want the hub's feature branch", kept)
	}
	if got := s.git(featureDir, "rev-parse", "HEAD"); got != p.featureHead {
		t.Errorf("the feature's worktree is at %s, want %s", got, p.featureHead)
	}
	if out := s.git(featureDir, "status", "--porcelain"); out != "" {
		t.Errorf("the feature's worktree is not clean after the move back: %s", out)
	}
	// The device keeps its copy, as it was, until the move is cleaned up.
	for _, d := range compareCopies(p.before, s.snapshot(s.deviceCopy()), func(path string) bool {
		return strings.HasPrefix(path, fmt.Sprintf("artifacts/%d_", p.hold))
	}) {
		t.Errorf("the device's copy changed after the move: %s", d)
	}
	s.runNext(p, s.proj, "the hub", attached)
	s.retainedThenCleaned(id, s.deviceCopy())
}

// retainedThenCleaned checks that an ended move keeps its store and hidden
// refs (and, from a device, the device's copy) until it is cleaned up, and
// lets them go when it is.
func (s *scene) retainedThenCleaned(id, deviceCopy string) {
	s.t.Helper()
	t := s.t
	m, plan := s.moveView(id)
	r, _ := dig(m, "detail", "retained").(map[string]any)
	if r == nil {
		t.Fatalf("move %s retains nothing: %v", id, m["detail"])
	}
	store := fmt.Sprint(r["store"])
	if _, err := os.Stat(store); err != nil {
		t.Errorf("move %s's store %s is gone before cleanup: %v", id, store, err)
	}
	refs, _ := r["refs"].([]any)
	if len(refs) == 0 {
		t.Errorf("move %s retains no hidden refs: %v", id, r)
	}
	for _, ref := range refs {
		if _, err := s.gitErr(s.proj, "rev-parse", "--verify", "-q", fmt.Sprint(ref)); err != nil && deviceCopy == "" {
			t.Errorf("move %s's hidden ref %v is gone before cleanup", id, ref)
		}
	}
	if allowed, _ := plan["allowed"].(bool); !allowed {
		t.Fatalf("move %s may not be cleaned up: %v", id, plan)
	}
	if deviceCopy != "" {
		if _, err := os.Stat(filepath.Join(deviceCopy, ".git")); err != nil {
			t.Errorf("the device's copy is gone before cleanup: %v", err)
		}
	}
	s.cleanup(id)
	if _, err := os.Stat(store); err == nil {
		t.Errorf("move %s's store %s outlived its cleanup", id, store)
	}
	for _, ref := range refs {
		if _, err := s.gitErr(s.proj, "rev-parse", "--verify", "-q", fmt.Sprint(ref)); err == nil {
			t.Errorf("move %s's hidden ref %v outlived its cleanup", id, ref)
		}
	}
	if _, err := os.Stat(filepath.Join(s.proj, ".cloop")); err != nil {
		t.Errorf("cleanup removed the project's own directory on the hub: %v", err)
	}
	if deviceCopy != "" {
		// A verified move from a device lets the device's copy go.
		// The discard empties the directory; the directory itself may stay.
		if entries, err := os.ReadDir(deviceCopy); err == nil && len(entries) > 0 {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("the device's copy outlived the cleanup of the verified move: %v", names)
		}
		m, _ = s.moveView(id)
		if dig(m, "detail", "retained", "source_removed") == nil {
			t.Errorf("the move does not record removing the device's copy: %v", dig(m, "detail", "retained"))
		}
	}
}

// moveIDFrom finds the move id `cloop executor move` printed.
func moveIDFrom(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "(move ")
	if i < 0 || len(out) < i+6+16 {
		t.Fatalf("cloop executor move printed no move id:\n%s", out)
	}
	return out[i+6 : i+6+16]
}
