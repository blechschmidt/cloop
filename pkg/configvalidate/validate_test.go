package configvalidate

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// TestKnownTopLevelKeys_CoversEveryConfigSection guards the repair path.
//
// A key missing from this set is reported as "unknown — will be ignored by
// cloop" and then *deleted* by `cloop config validate --fix`. When the set
// was a hand-written literal it had already drifted past ui, executors,
// orchestrator, backup and step_timeout — so the tool's own suggested repair
// would have stripped a hosted deployment's entire execution policy and OIDC
// configuration. This asserts the reflection-derived set stays complete, and
// names the sections whose loss would be silent.
func TestKnownTopLevelKeys_CoversEveryConfigSection(t *testing.T) {
	for _, key := range []string{
		"provider", "anthropic", "openai", "ollama", "claudecode",
		"max_parallel", "step_timeout", "rate_limit", "tracing",
		"orchestrator", "ui", "backup", "executors",
	} {
		if !knownTopLevelKeys[key] {
			t.Errorf("%q is not a known top-level key: `config validate --fix` would delete it", key)
		}
	}

	// And the reverse: a genuinely unknown key must still be caught, or the
	// check stops being worth running.
	if knownTopLevelKeys["definitely_not_a_config_section"] {
		t.Error("an arbitrary key was treated as known")
	}
}

// A real hardened config — the shape `cloop hub bootstrap` and the Helm chart
// produce — must survive validation with nothing reported as unknown.
func TestCheckUnknownKeys_AcceptsAHardenedHubConfig(t *testing.T) {
	hardened := []byte(`
provider: anthropic
executors:
  allow_host_process: false
ui:
  external_url: https://cloop.example.com
  tls: {}
  oidc:
    enabled: true
    default_role: none
orchestrator:
  task_timeout_minutes: 0
rate_limit:
  requests_per_second: 20
`)
	if unknown := checkUnknownKeys(hardened); len(unknown) != 0 {
		t.Fatalf("a hardened hub config reported unknown keys %v — `--fix` would strip them", unknown)
	}
}

// TestCheckNumericBounds_FreeSpaceFloor: `cloop config validate` judges the
// operator's own text for orchestrator.min_free_disk_mb (Task 20381) — Load
// would quietly put a bad value back to the default, and a validator that only
// saw the repaired config would call the file healthy.
func TestCheckNumericBounds_FreeSpaceFloor(t *testing.T) {
	for _, tc := range []struct {
		v    *int
		bad  bool
		name string
	}{
		{nil, false, "unset"},
		{intPtr(0), false, "off"},
		{intPtr(2048), false, "in the band"},
		{intPtr(10), true, "below the band"},
		{intPtr(-1), true, "negative"},
	} {
		cfg := config.Default()
		cfg.Orchestrator.MinFreeDiskMB = tc.v
		var got []Finding
		checkNumericBounds(cfg, func(f Finding) { got = append(got, f) })
		flagged := false
		for _, f := range got {
			if f.Field == "config.orchestrator.min_free_disk_mb" && f.Severity == SeverityError {
				flagged = true
			}
		}
		if flagged != tc.bad {
			t.Errorf("%s: flagged = %v, want %v (%+v)", tc.name, flagged, tc.bad, got)
		}
	}
}

func intPtr(v int) *int { return &v }
