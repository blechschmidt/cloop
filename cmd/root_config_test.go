package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// TestLoadCommandConfigReadsTheUIOverlay: `cloop ui --port N` applies its
// host-execution policy, build floor and resource ceiling from the same merged
// view the hub starts from (Task 20364). Every other command reads config.yaml
// alone, because no other command reads an overlay.
func TestLoadCommandConfigReadsTheUIOverlay(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.ConfigPath(dir), []byte("provider: claudecode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := "executors:\n  allow_host_process: false\n  min_agent_build: v2.0.0\n"
	if err := os.WriteFile(config.UIInstanceConfigPath(dir, 8081), []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := uiPort
	uiPort = 8081
	t.Cleanup(func() { uiPort = prev })

	ui, err := loadCommandConfig(uiCmd, dir)
	if err != nil {
		t.Fatalf("loadCommandConfig(ui): %v", err)
	}
	if ui.Executors.HostProcessAllowed() || ui.Executors.MinAgentBuild != "v2.0.0" {
		t.Errorf("cloop ui --port 8081 read allow_host_process=%v min_agent_build=%q, want the overlay's",
			ui.Executors.HostProcessAllowed(), ui.Executors.MinAgentBuild)
	}

	other, err := loadCommandConfig(rootCmd, dir)
	if err != nil {
		t.Fatalf("loadCommandConfig(root): %v", err)
	}
	if !other.Executors.HostProcessAllowed() || other.Executors.MinAgentBuild != "" {
		t.Error("a command other than `cloop ui` read the dashboard's overlay")
	}

	// A different port is a different hub, with no overlay of its own.
	uiPort = 8080
	if cfg, err := loadCommandConfig(uiCmd, dir); err != nil || !cfg.Executors.HostProcessAllowed() {
		t.Errorf("cloop ui --port 8080 read another hub's overlay (err=%v)", err)
	}
}
