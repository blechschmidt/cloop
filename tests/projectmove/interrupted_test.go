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

// seedGate stands in for cloop on the device: the first `cloop workspace
// move-seed` the device runs says it has started, in gate/seed-started, and
// waits for gate/release before it goes on; every other command, and every
// later move-seed, is the cloop under test straight away.
func seedGate(root, bin string) string {
	gate := filepath.Join(root, "seed-gate")
	return fmt.Sprintf(`#!/bin/sh
gate=%q
if [ "$1" = workspace ] && [ "$2" = move-seed ] && mkdir "$gate/first" 2>/dev/null; then
  echo $$ > "$gate/seed-started"
  while [ ! -e "$gate/release" ]; do sleep 0.2; done
fi
exec %q "$@"
`, gate, bin)
}

// TestMoveResumesAfterTheHubDiesMidSeed moves a project from the hub's own
// tree to a device and kills the hub — SIGKILL, as the kernel's OOM killer
// or a crash would — while the device is being seeded. A new hub process in
// the same directory takes the move up where its journal left it, seeds the
// device again, verifies it and finishes, with nothing lost. The seed the
// dead hub started, released afterwards, changes nothing.
func TestMoveResumesAfterTheHubDiesMidSeed(t *testing.T) {
	optIn(t)
	s := newScene(t, sceneOptions{deviceCloop: seedGate})
	gate := filepath.Join(s.root, "seed-gate")
	if err := os.MkdirAll(gate, 0o755); err != nil {
		t.Fatal(err)
	}
	s.initProject()
	s.startHub()
	device := s.startAgent()

	first := s.addTask("Write the first report")
	s.runTo(first, "the hub")
	attached := map[int]map[string]string{first: s.attachments(first)}
	body := s.mustCall(http.StatusOK, "POST", fmt.Sprintf("/api/projects/%d/features", s.idx()),
		map[string]any{"name": "Widget", "description": "Build the widget"})
	featureDir := filepath.Join(s.proj, ".cloop", "features", fmt.Sprint(body["slug"]))

	p := s.prepareSource(1, source{name: "the hub", dir: s.proj, feature: featureDir})
	id := s.startMove(device)
	s.waitFor("the device to be seeding", 3*time.Minute, func() bool {
		_, err := os.Stat(filepath.Join(gate, "seed-started"))
		return err == nil
	})
	if m, _ := s.moveView(id); m["phase"] != "seed" {
		t.Fatalf("the device is seeding and the move's journal says %v", m["phase"])
	}

	// The hub dies mid-seed, and a new process starts in its place.
	s.killHub()
	s.startHub()
	m := s.waitMove(id, 5*time.Minute)
	s.afterMove(m, p, s.deviceCopy(), s.proj)

	// The journal records a phase when it ends: the phases up to the switch
	// by the hub that died, the seed and the verification by the new one.
	earlier, later := map[string]bool{}, map[string]bool{}
	for _, step := range dig(m, "detail", "timeline").([]any) {
		st, _ := step.(map[string]any)
		switch st["phase"] {
		case "preflight", "quiesce", "capture", "switch":
			earlier[fmt.Sprint(st["member"])] = true
		case "seed", "verify":
			later[fmt.Sprint(st["member"])] = true
		}
	}
	if len(earlier) != 1 || len(later) != 1 {
		t.Errorf("the timeline's phases were run by %v, then %v: want one process each", earlier, later)
	}
	for member := range later {
		if earlier[member] {
			t.Errorf("the seed was finished by the process that started the move (%s), not a new one: %v",
				member, dig(m, "detail", "timeline"))
		}
	}

	// The seed the dead hub started finds the job done and changes nothing.
	before := s.snapshot(s.deviceCopy())
	writeFile(t, filepath.Join(gate, "release"), "go\n")
	s.waitFor("the dead hub's seed to finish on the device", time.Minute, func() bool {
		b, err := os.ReadFile(filepath.Join(gate, "seed-started"))
		if err != nil {
			return false
		}
		pid := strings.TrimSpace(string(b))
		_, err = os.Stat("/proc/" + pid)
		return err != nil
	})
	for _, d := range compareCopies(before, s.snapshot(s.deviceCopy()), nil) {
		t.Errorf("the dead hub's seed changed the device's copy after the move: %s", d)
	}

	s.runNext(p, s.deviceCopy(), "the device", attached)
	s.retainedThenCleaned(id, "")
}
