package configvalidate

import "testing"

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
