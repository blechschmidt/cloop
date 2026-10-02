package config

// The collection policy for browser telemetry (Task 20311).
//
// The default is the whole point of these tests. It was on, it is now off, and
// the direction matters more than the mechanism: a regression here does not
// break a feature, it silently starts recording the URLs, user agents and
// addresses of everyone who opens the dashboard on a hub whose operator never
// asked for that.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestTelemetryDefaultsToOff is the one that must never go green by accident.
// A hub that has never heard of this setting collects nothing.
func TestTelemetryDefaultsToOff(t *testing.T) {
	t.Parallel()

	var zero TelemetryConfig
	if zero.Effective() {
		t.Error("the zero TelemetryConfig collects — an operator who has never configured " +
			"telemetry has not consented to it")
	}
	for _, src := range []string{"dashboard", "glasses", "anything"} {
		if zero.Collects(src) {
			t.Errorf("the zero TelemetryConfig collects %q", src)
		}
	}
}

// TestTelemetryDefaultSurvivesAFullConfigLoad checks the default through the
// path a deployment actually takes: a config file with no ui block at all.
// Effective() being correct is not much use if Load fills the field in.
func TestTelemetryDefaultSurvivesAFullConfigLoad(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfigFile(t, dir, "provider: claudecode\n")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UI.Telemetry.Effective() {
		t.Error("a config with no telemetry block collects — the default leaked back in")
	}
	if cfg.UI.Telemetry.Enabled != nil {
		t.Error("Enabled is non-nil for an absent block; the panel uses that pointer to tell " +
			"'never configured' from 'switched off'")
	}
}

func TestTelemetryEnabledExplicitly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfigFile(t, dir, "ui:\n  telemetry:\n    enabled: true\n")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.UI.Telemetry.Effective() {
		t.Fatal("enabled: true did not switch collection on")
	}
	for _, src := range []string{"dashboard", "glasses"} {
		if !cfg.UI.Telemetry.Collects(src) {
			t.Errorf("enabled with no source list refuses %q; an empty list means all", src)
		}
	}
}

// TestTelemetrySourcesNarrowCollection covers the posture the feature exists
// for: collect from the device that cannot report for itself, and leave
// ordinary browser sessions alone.
func TestTelemetrySourcesNarrowCollection(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfigFile(t, dir, "ui:\n  telemetry:\n    enabled: true\n    sources: [glasses]\n")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tel := cfg.UI.Telemetry
	if !tel.Collects("glasses") {
		t.Error("sources: [glasses] refuses the glasses")
	}
	if tel.Collects("dashboard") {
		t.Error("sources: [glasses] still collects the dashboard — the narrowing does nothing")
	}
}

// TestTelemetrySourcesAreCaseAndSpaceInsensitive: the list is hand-edited YAML
// as often as it is written by the panel, and " Glasses" refusing to match
// would look exactly like the feature being broken.
func TestTelemetrySourcesAreCaseAndSpaceInsensitive(t *testing.T) {
	t.Parallel()

	on := true
	tel := TelemetryConfig{Enabled: &on, Sources: []string{" Glasses "}}
	if !tel.Collects("glasses") {
		t.Error(`Collects("glasses") is false for sources: [" Glasses "]`)
	}
	if !tel.Collects("GLASSES") {
		t.Error("Collects is case-sensitive on its argument")
	}
}

// TestTelemetrySourcesCannotResurrectADisabledHub: Sources narrows, it never
// widens. A config carrying a stale source list with the switch off must
// collect nothing.
func TestTelemetrySourcesCannotResurrectADisabledHub(t *testing.T) {
	t.Parallel()

	off := false
	for _, tel := range []TelemetryConfig{
		{Sources: []string{"glasses"}},
		{Enabled: &off, Sources: []string{"glasses", "dashboard"}},
	} {
		if tel.Collects("glasses") || tel.Collects("dashboard") {
			t.Errorf("%+v collects with the master switch off", tel)
		}
	}
}

// TestTelemetryUnknownSourceIsRefused: an unrecognised name fails closed. The
// package deliberately does not validate against pkg/telemetry, so this is the
// property that makes that safe.
func TestTelemetryUnknownSourceIsRefused(t *testing.T) {
	t.Parallel()

	on := true
	tel := TelemetryConfig{Enabled: &on, Sources: []string{"dashbord"}} // typo
	if tel.Collects("dashboard") {
		t.Error("a misspelled source name still collects the dashboard")
	}
}

// TestTelemetryRoundTripsThroughYAML: the panel writes this block with
// config.Save, and a field that does not survive a round trip would appear to
// save and then silently revert on the next load.
func TestTelemetryRoundTripsThroughYAML(t *testing.T) {
	t.Parallel()

	on := true
	in := Config{}
	in.UI.Telemetry = TelemetryConfig{Enabled: &on, Sources: []string{"glasses"}}

	blob, err := yaml.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Config
	if err := yaml.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.UI.Telemetry.Effective() {
		t.Error("enabled did not survive the round trip")
	}
	if !out.UI.Telemetry.Collects("glasses") || out.UI.Telemetry.Collects("dashboard") {
		t.Errorf("sources did not survive the round trip: %v", out.UI.Telemetry.Sources)
	}
}

func writeConfigFile(t *testing.T, dir, body string) {
	t.Helper()
	path := ConfigPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// TestSaveUIInstanceTelemetryIsAuthoritative: the overlay is merged over
// config.yaml key by key, so the block the panel writes there has to carry
// both keys — an empty source list included — or a narrowing in config.yaml
// shows through a save that ticked every front end.
func TestSaveUIInstanceTelemetryIsAuthoritative(t *testing.T) {
	t.Parallel()

	dir := writeConfigs(t,
		"ui:\n    telemetry:\n        enabled: true\n        sources: [glasses]\n",
		"# The SSO block for this hub lives here.\nui:\n    allowed_origins:\n        - https://hub.example:8888\n",
		8081)
	path := UIInstanceConfigPath(dir, 8081)

	on := true
	if err := SaveUIInstanceTelemetry(path, TelemetryConfig{Enabled: &on}); err != nil {
		t.Fatalf("SaveUIInstanceTelemetry: %v", err)
	}
	cfg, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if !cfg.UI.Telemetry.Collects("dashboard") || !cfg.UI.Telemetry.Collects("glasses") {
		t.Errorf("an all-sources save left %v in force: config.yaml's narrowing showed through",
			cfg.UI.Telemetry.Sources)
	}
	if len(cfg.UI.AllowedOrigins) != 1 {
		t.Errorf("a sibling key in the overlay was lost: %v", cfg.UI.AllowedOrigins)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read overlay: %v", err)
	}
	if !strings.Contains(string(raw), "The SSO block for this hub lives here.") {
		t.Error("the operator's comment was lost")
	}

	off := false
	if err := SaveUIInstanceTelemetry(path, TelemetryConfig{Enabled: &off, Sources: []string{"glasses"}}); err != nil {
		t.Fatalf("SaveUIInstanceTelemetry off: %v", err)
	}
	cfg, _, err = LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if cfg.UI.Telemetry.Effective() {
		t.Error("switching collection off in the overlay left config.yaml's enabled: true in force")
	}
	if len(cfg.UI.Telemetry.Sources) != 1 || cfg.UI.Telemetry.Sources[0] != "glasses" {
		t.Errorf("sources = %v, want the narrowing kept while off", cfg.UI.Telemetry.Sources)
	}
}
