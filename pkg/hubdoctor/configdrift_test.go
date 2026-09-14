package hubdoctor

// Drift between config.yaml and the state.db mirror was detectable since Task
// 20109 and invisible to `cloop hub doctor` — which is the command an operator
// runs when a setting they changed did not take effect, i.e. the exact symptom
// drift produces.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/configdiff"
)

// sentinelProvider is a value chosen to appear nowhere else, so a test can
// tell "the finding named the key" from "the finding printed the value".
const sentinelProvider = "drift-sentinel-provider"

// syncedDir builds a hub directory whose YAML and mirror agree.
//
// Sync normalises config.yaml on the way through (it round-trips via
// config.Save), so seeding this way and then editing one key is what produces
// a diff of exactly that key — writing a terse config.yaml over a synced
// mirror would instead drift every defaulted field at once.
func syncedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustInitStateDB(t, dir)

	if err := os.WriteFile(config.ConfigPath(dir), []byte("provider: anthropic\n"), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
	if err := configdiff.Sync(dir, configdiff.FromYAML); err != nil {
		t.Fatalf("seed mirror: %v", err)
	}
	return dir
}

// driftedDir edits one key in the file behind the mirror's back — a hand-edit
// on a running hub, or a deploy that shipped a config.yaml onto an existing
// state.db.
func driftedDir(t *testing.T) string {
	t.Helper()
	dir := syncedDir(t)

	synced, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil {
		t.Fatalf("read synced config.yaml: %v", err)
	}
	edited := strings.Replace(string(synced), "provider: anthropic", "provider: "+sentinelProvider, 1)
	if edited == string(synced) {
		t.Fatalf("fixture did not edit anything; synced config.yaml was:\n%s", synced)
	}
	if err := os.WriteFile(config.ConfigPath(dir), []byte(edited), 0o600); err != nil {
		t.Fatalf("rewrite config.yaml: %v", err)
	}
	return dir
}

func TestDoctorReportsConfigDrift(t *testing.T) {
	dir := driftedDir(t)

	got := findingsFor(t, dir, &config.Config{}, Options{Offline: true})
	f := only(t, got, "config.drift")

	if f.Severity != SeverityWarn {
		t.Errorf("severity = %q, want warn (message: %s)", f.Severity, f.Message)
	}
	if !strings.Contains(f.Message, "provider") {
		t.Errorf("message does not name the drifted key: %s", f.Message)
	}
	if f.Remediation == "" {
		t.Error("no remediation on a non-pass finding")
	}
	// The values themselves stay out: a doctor report is pasted into issue
	// trackers and piped to log collectors far more often than `config diff`
	// is, and a key name is enough to act on. Asserting against a sentinel
	// rather than a plausible value is deliberate — "anthropic" is both a
	// value here and a legitimate key path, so it could not tell the two apart.
	if strings.Contains(f.Message, sentinelProvider) {
		t.Errorf("message leaks config values: %s", f.Message)
	}
	for _, d := range f.Details {
		if strings.Contains(fmtAny(d), sentinelProvider) {
			t.Errorf("details leak config values: %#v", f.Details)
		}
	}
}

func TestDoctorPassesWhenConfigAgrees(t *testing.T) {
	got := findingsFor(t, syncedDir(t), &config.Config{}, Options{Offline: true})
	if f := only(t, got, "config.drift"); f.Severity != SeverityPass {
		t.Errorf("severity = %q, want pass (message: %s)", f.Severity, f.Message)
	}
}

// A mirror that was never written is drift by configdiff's reckoning, and it
// must stay a warning: `cloop hub doctor` is a deployment gate, and a fresh
// install failing it would get the gate switched off.
func TestFreshInstallDoesNotFailTheGate(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	if err := os.WriteFile(config.ConfigPath(dir), []byte("provider: anthropic\n"), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	rep := Run(context.Background(), dir, &config.Config{}, Options{Offline: true})
	for _, f := range rep.Findings {
		if f.Check == "config.drift" && f.Severity == SeverityFail {
			t.Errorf("drift failed the run on a hub with no mirror yet: %s", f.Message)
		}
	}
}

// Many keys must not produce a wall of text; the count carries the magnitude
// and `cloop config diff` carries the detail. Details keeps the full list, so
// a machine consumer loses nothing to the truncation.
func TestDriftListIsBounded(t *testing.T) {
	dir := syncedDir(t)
	// A hand-written config.yaml over a synced mirror drifts every leaf it
	// disagrees with or omits — the shape a deploy produces when it ships its
	// own config onto an existing state.db.
	wide := "provider: " + sentinelProvider + "\nmax_parallel: 9\nmax_steps: 7\n" +
		"anthropic:\n  model: a\n  base_url: https://a.invalid\n" +
		"openai:\n  model: b\n  base_url: https://b.invalid\n" +
		"ollama:\n  model: c\n  base_url: https://c.invalid\n"
	if err := os.WriteFile(config.ConfigPath(dir), []byte(wide), 0o600); err != nil {
		t.Fatalf("rewrite config.yaml: %v", err)
	}

	got := findingsFor(t, dir, &config.Config{}, Options{Offline: true})
	f := only(t, got, "config.drift")

	paths, ok := f.Details["paths"].([]string)
	if !ok {
		t.Fatalf("details.paths missing or not a []string: %#v", f.Details["paths"])
	}
	if len(paths) <= maxDriftPathsListed {
		t.Fatalf("fixture drifted only %d keys; it cannot exercise truncation", len(paths))
	}

	want := fmt.Sprintf("(and %d more)", len(paths)-maxDriftPathsListed)
	if !strings.Contains(f.Message, want) {
		t.Errorf("message does not report the truncation as %q: %s", want, f.Message)
	}
	// Every listed key must be one that actually drifted, and only the first
	// maxDriftPathsListed of them may appear.
	for _, p := range paths[maxDriftPathsListed:] {
		if strings.Contains(f.Message, " "+p+",") || strings.HasSuffix(f.Message, " "+p) {
			t.Errorf("message lists %q beyond the cap: %s", p, f.Message)
		}
	}
}

// fmtAny renders a Details value for substring checks.
func fmtAny(v any) string { return fmt.Sprintf("%v", v) }
