package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateModelRelayConfig(t *testing.T) {
	ok := []ModelRelayConfig{
		{},
		{Enabled: true},
		{Enabled: true, Listener: "dashboard", Models: []string{"claude-sonnet-*", "claude-haiku-4-5"}},
		{Listener: "GIT_PROXY", MaxOutputTokens: 64000, UpstreamBaseURL: "https://gw.example.com"},
		{UpstreamBaseURL: "http://127.0.0.1:9999", HubCredential: []string{"project:/srv/app", "executor:sgx"}},
	}
	for i, c := range ok {
		if err := ValidateModelRelayConfig(c); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
	}
	bad := map[string]ModelRelayConfig{
		"listener":            {Listener: "egress"},
		"blank model":         {Models: []string{""}},
		"padded model":        {Models: []string{" claude-*"}},
		"bad glob":            {Models: []string{"claude-["}},
		"negative cap":        {MaxOutputTokens: -1},
		"huge cap":            {MaxOutputTokens: ModelRelayMaxOutputTokensUpper + 1},
		"plaintext upstream":  {UpstreamBaseURL: "http://api.example.com"},
		"upstream with path":  {UpstreamBaseURL: "https://gw.example.com/v1"},
		"upstream userinfo":   {UpstreamBaseURL: "https://u:p@gw.example.com"},
		"relative project":    {HubCredential: []string{"project:srv/app"}},
		"unknown subject":     {HubCredential: []string{"label:gpu=true"}},
		"bare subject":        {HubCredential: []string{"/srv/app"}},
		"executor with slash": {HubCredential: []string{"executor:a/b"}},
	}
	for name, c := range bad {
		if err := ValidateModelRelayConfig(c); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
	many := ModelRelayConfig{}
	for i := 0; i <= ModelRelayMaxModels; i++ {
		many.Models = append(many.Models, "claude-*")
	}
	if err := ValidateModelRelayConfig(many); err == nil {
		t.Error("an allowlist past the bound was accepted")
	}
}

func TestModelRelayDefaults(t *testing.T) {
	var m ModelRelayConfig
	if m.ListenerName() != ModelRelayListenerGitProxy {
		t.Errorf("default listener %q", m.ListenerName())
	}
	if got := m.EffectiveModels(); len(got) != 1 || got[0] != "claude-*" {
		t.Errorf("default models %v", got)
	}
	m.Models = []string{" ", "claude-sonnet-*"}
	if got := m.EffectiveModels(); len(got) != 1 || got[0] != "claude-sonnet-*" {
		t.Errorf("models %v", got)
	}
}

func TestModelRelayHubCredentialAllowedIsExplicit(t *testing.T) {
	var m ModelRelayConfig
	if m.HubCredentialAllowed("/srv/app", "sgx") {
		t.Fatal("the hub's key is spent with no allowance")
	}
	m.HubCredential = []string{"project:/srv/app/", "executor:build-1"}
	cases := []struct {
		project, executor string
		want              bool
	}{
		{"/srv/app", "sgx", true},
		{"/srv/application", "sgx", false},
		{"/srv/other", "build-1", true},
		{"/srv/other", "build-10", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := m.HubCredentialAllowed(c.project, c.executor); got != c.want {
			t.Errorf("HubCredentialAllowed(%q, %q) = %v", c.project, c.executor, got)
		}
	}
}

// TestModelRelayLoadRefusesWhatItCannotRun: a section Load cannot run as
// written is not switched off — off would deliver every relayed run's Claude
// credential into its sandbox again — but kept on and marked Broken, its
// faulty values kept as written rather than reset to defaults wider than
// them. The repair is recorded, and dropped once an overlay mends the section.
func TestModelRelayLoadRefusesWhatItCannotRun(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	yaml := "executors:\n  model_relay:\n    enabled: true\n    models: [\"claude-[\"]\n" +
		"    hub_credential: [\"project:relative\"]\n    max_output_tokens: -5\n"
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := cfg.Executors.ModelRelay
	if !m.Enabled || !strings.Contains(m.Broken, "executors.model_relay.models") {
		t.Fatalf("a section that cannot run was not kept on and marked: %+v", m)
	}
	if len(m.Models) != 1 || m.Models[0] != "claude-[" {
		t.Fatalf("the allowlist was reset rather than kept as written: %q", m.Models)
	}
	// What can be fixed is: a dropped allowance and a default clamp are
	// narrower than what was written, never wider.
	if m.HubCredential != nil || m.MaxOutputTokens != 0 || strings.Contains(m.Broken, "hub_credential") {
		t.Fatalf("the repairable fields: %+v", m)
	}
	var said []string
	for _, r := range cfg.LoadRepairs() {
		if r.SwitchedOff == "executors.model_relay" {
			said = append(said, r.Detail)
		}
	}
	if len(said) != 1 || !strings.Contains(said[0], "refused rather than handed its Claude credential") {
		t.Fatalf("the repairs do not say the relay refuses: %v", cfg.LoadRepairs())
	}
	// An overlay mending the allowlist takes the mark and the repair away.
	overlay := "executors:\n  model_relay:\n    models: [\"claude-haiku-*\"]\n"
	if err := os.WriteFile(UIInstanceConfigPath(dir, 8081), []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	merged, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if mm := merged.Executors.ModelRelay; !mm.Enabled || mm.Broken != "" || len(mm.Models) != 1 || mm.Models[0] != "claude-haiku-*" {
		t.Fatalf("the mended section: %+v", mm)
	}
	for _, r := range merged.LoadRepairs() {
		if r.SwitchedOff == "executors.model_relay" {
			t.Fatalf("the mended section is still reported: %+v", r)
		}
	}

	// A disabled section is not marked: there is nothing to refuse.
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"),
		[]byte("executors:\n  model_relay:\n    listener: nowhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	off, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, r := range off.LoadRepairs() {
		if r.SwitchedOff == "executors.model_relay" {
			t.Fatalf("a disabled section was reported switched off: %+v", r)
		}
	}
}

func TestModelRelayWarnsWithoutItsListener(t *testing.T) {
	e := ExecutorsConfig{ModelRelay: ModelRelayConfig{Enabled: true}}
	if w := strings.Join(ExecutorWarnings(e), "\n"); !strings.Contains(w, "executors.model_relay") {
		t.Fatalf("no warning for a relay with no git proxy to listen on: %q", w)
	}
	e.GitProxy.Enabled = true
	if w := strings.Join(ExecutorWarnings(e), "\n"); strings.Contains(w, "executors.model_relay") {
		t.Fatalf("a warning for a relay with its listener: %q", w)
	}
	e.GitProxy.Enabled = false
	e.ModelRelay.Listener = ModelRelayListenerDashboard
	if w := strings.Join(ExecutorWarnings(e), "\n"); strings.Contains(w, "executors.model_relay") {
		t.Fatalf("a dashboard relay was warned about the git proxy: %q", w)
	}
}
