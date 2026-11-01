package config_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// config spells the gate's modes itself, since it cannot import pm; they must
// be the same list.
func TestRequirementsGateModesMatchPM(t *testing.T) {
	if !slices.Equal(config.RequirementsGateModes(), pm.RequirementsGateModes) {
		t.Fatalf("config %v, pm %v", config.RequirementsGateModes(), pm.RequirementsGateModes)
	}
	for _, m := range pm.RequirementsGateModes {
		got, err := config.NormalizeRequirementsGate(strings.ToUpper(m))
		if err != nil || got != m {
			t.Errorf("NormalizeRequirementsGate(%q) = %q, %v", m, got, err)
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRequirementsSectionLoads(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, "requirements:\n  gate: Linked-Must\n  assess: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Requirements.Gate != config.RequirementsGateLinkedMust || cfg.Requirements.Assess == nil || !*cfg.Requirements.Assess {
		t.Fatalf("requirements = %+v", cfg.Requirements)
	}
	if !cfg.Requirements.Declares() {
		t.Error("a declared gate does not declare")
	}
	if err := cfg.ValidateNumeric(); err != nil {
		t.Errorf("a valid section failed validation: %v", err)
	}
}

// A mode the build does not know declares nothing — the project's own setting
// stands — and says so, rather than switching the gate off or guessing.
func TestRequirementsSectionWithAnUnknownModeDeclaresNothing(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, "requirements:\n  gate: linked+should\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Requirements.Declares() {
		t.Fatalf("an unknown mode was kept: %+v", cfg.Requirements)
	}
	found := false
	for _, r := range cfg.LoadRepairs() {
		if r.Field == "requirements.gate" && strings.Contains(r.Detail, "project's own setting stands") {
			found = true
		}
	}
	if !found {
		t.Errorf("the repair was not recorded: %+v", cfg.LoadRepairs())
	}

	bad := config.Default()
	bad.Requirements.Gate = "sometimes"
	if err := bad.ValidateNumeric(); err == nil || !strings.Contains(err.Error(), "requirements.gate") {
		t.Errorf("strict validation = %v", err)
	}
}

// requirement.regression is opt-in: a webhook set up for approvals with no
// events list is not told about a project's tests unless it asks.
func TestRequirementRegressionNotificationIsOptIn(t *testing.T) {
	if !config.IsNotificationEvent(config.NotifyEventRequirementRegression) {
		t.Fatal("requirement.regression is not a notification event")
	}
	all := config.NotificationWebhook{Name: "approvals"}
	if all.Wants(config.NotifyEventRequirementRegression) || !all.Wants(config.NotifyEventRequestFiled) {
		t.Error("a webhook with no events list should get every event but the opt-in ones")
	}
	asked := config.NotificationWebhook{Name: "quality", Events: []string{"requirement.regression"}}
	if !asked.Wants(config.NotifyEventRequirementRegression) || asked.Wants(config.NotifyEventRequestFiled) {
		t.Error("a webhook naming requirement.regression should get it, and only it")
	}
}
