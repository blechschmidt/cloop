package alert_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/alert"
	"gopkg.in/yaml.v3"
)

func mkRule(name string) alert.Rule {
	return alert.Rule{
		Name:      name,
		Metric:    alert.MetricFailureRate,
		Op:        alert.OpGt,
		Threshold: 50,
		Notify:    "desktop",
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	want := []alert.Rule{mkRule("r1"), mkRule("r2")}
	if err := alert.Save(dir, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := alert.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(got))
	}
}

func TestAddRule_Replace(t *testing.T) {
	dir := t.TempDir()
	r := mkRule("dup")
	if err := alert.AddRule(dir, r); err != nil {
		t.Fatalf("add: %v", err)
	}
	r.Threshold = 99
	if err := alert.AddRule(dir, r); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got, _ := alert.Load(dir)
	if len(got) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(got))
	}
	if got[0].Threshold != 99 {
		t.Fatalf("expected threshold 99, got %v", got[0].Threshold)
	}
}

func TestRemoveRule(t *testing.T) {
	dir := t.TempDir()
	_ = alert.AddRule(dir, mkRule("a"))
	_ = alert.AddRule(dir, mkRule("b"))
	if err := alert.RemoveRule(dir, "a"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got, _ := alert.Load(dir)
	if len(got) != 1 || got[0].Name != "b" {
		t.Fatalf("unexpected after remove: %+v", got)
	}
	if err := alert.RemoveRule(dir, "ghost"); err == nil {
		t.Fatalf("expected error removing missing rule")
	}
}

// TestAddRule_ConcurrentNoLostUpdates exercises the lost-update fix:
// before alertsMu was added, two goroutines each running Load → append → Save
// would race — both reading the same one-element snapshot and the second's
// overwrite would clobber the first's append. Result: only one rule survives.
//
// With the fix, all N concurrent AddRule calls must end up in the file.
func TestAddRule_ConcurrentNoLostUpdates(t *testing.T) {
	dir := t.TempDir()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			if err := alert.AddRule(dir, mkRule(fmt.Sprintf("rule-%d", i))); err != nil {
				t.Errorf("add %d: %v", i, err)
			}
		}()
	}
	wg.Wait()

	got, err := alert.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != goroutines {
		t.Fatalf("expected %d rules after concurrent Add, got %d (lost-update race?)", goroutines, len(got))
	}
	seen := make(map[string]bool, goroutines)
	for _, r := range got {
		if seen[r.Name] {
			t.Fatalf("duplicate rule name %q in file", r.Name)
		}
		seen[r.Name] = true
	}
}

// TestAddRule_ReaderNeverSeesTornYAML spawns a writer that adds rules in a tight
// loop and a reader that calls Load() in parallel. With os.WriteFile (the old
// path) Load could race the truncate-then-write and see a partial file. The
// atomic-rename Save must always present a complete YAML document to readers.
func TestAddRule_ReaderNeverSeesTornYAML(t *testing.T) {
	dir := t.TempDir()
	if err := alert.AddRule(dir, mkRule("seed")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := alert.AddRule(dir, mkRule(fmt.Sprintf("r-%d", i))); err != nil {
				t.Errorf("add: %v", err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if _, err := alert.Load(dir); err != nil {
				t.Errorf("reader saw torn YAML: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

// TestSave_NoStaleTmpFiles confirms the writeAtomic cleanup defer fires —
// repeated saves should never accumulate ".tmp" staging files in .cloop/.
func TestSave_NoStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		if err := alert.AddRule(dir, mkRule(fmt.Sprintf("r-%d", i))); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if matched, _ := filepath.Match(".alerts.yaml.*.tmp", e.Name()); matched {
			t.Errorf("leftover staging file: %s", e.Name())
		}
	}
}

// TestSave_FileIsValidYAML sanity-checks the format the atomic write produces.
func TestSave_FileIsValidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := alert.AddRule(dir, mkRule("r")); err != nil {
		t.Fatalf("add: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".cloop", "alerts.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, data)
	}
}

// TestLoad_CorruptYAMLQuarantined ensures a malformed alerts.yaml no longer
// silently kills the alert subsystem. Previously a single bad edit returned
// `parse alerts.yaml: ...` and any caller (orchestrator post-task hook,
// `cloop alert list`) would receive that error and ignore alerts entirely.
// Now Load quarantines the bad file and returns an empty rule list, so the
// next `cloop alert add` re-creates a valid file from scratch.
func TestLoad_CorruptYAMLQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, ".cloop", "alerts.yaml")
	// YAML's structural rule violation: tab character at indentation, plus
	// unbalanced bracket. yaml.Unmarshal rejects this with a parse error.
	if err := os.WriteFile(path, []byte("rules:\n\t- name: [unbalanced"), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	rules, err := alert.Load(dir)
	if err != nil {
		t.Fatalf("Load on corrupt YAML should not return an error, got: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected empty rule list on corrupt file, got %d rules", len(rules))
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected corrupt %s to be moved aside, stat err = %v", path, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a .corrupt-* sibling preserving the bad bytes, dir contents: %v", entries)
	}
}

// TestLoad_ZeroByteAlertsRecovers covers the post-crash zero-byte case for
// alerts.yaml. yaml.Unmarshal of empty input is technically valid (yields a
// zero rulesFile), so this test pins that the empty-rules case stays
// graceful — the regression risk is a future change adding strict-mode
// parsing that rejects empty input. Either way, no error must reach callers.
func TestLoad_ZeroByteAlertsRecovers(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, ".cloop", "alerts.yaml")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	rules, err := alert.Load(dir)
	if err != nil {
		t.Fatalf("Load on empty file should not return an error, got: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected empty rule list, got %d rules", len(rules))
	}
}
