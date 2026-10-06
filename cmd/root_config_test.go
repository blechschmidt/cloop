package cmd

import (
	"os"
	"path/filepath"
	"strconv"
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

// TestLoadCommandConfigReadsTheDoctorsHub: `cloop hub doctor` reproduces the
// executor registry of the hub it diagnoses in its own process, so the
// ratchets the startup pass applies must come from that hub's view too. Before
// Task 20387 they came from config.yaml alone: a shared file forbidding host
// execution evicted the host driver an overlay allows, and the doctor failed
// that working hub with "no executor is registered at all".
func TestLoadCommandConfigReadsTheDoctorsHub(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	shared := "provider: claudecode\nexecutors:\n  allow_host_process: false\n"
	if err := os.WriteFile(config.ConfigPath(dir), []byte(shared), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{8081, defaultUIPort} {
		overlay := "executors:\n  allow_host_process: true\n"
		if err := os.WriteFile(config.UIInstanceConfigPath(dir, port), []byte(overlay), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setPort := func(v string) {
		t.Helper()
		if err := hubDoctorCmd.Flags().Set("port", v); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = hubDoctorCmd.Flags().Set("port", strconv.Itoa(defaultUIPort)) })

	for _, tc := range []struct {
		port      string
		wantAllow bool
		why       string
	}{
		{"8081", true, "--port 8081 must read that hub's overlay"},
		{strconv.Itoa(defaultUIPort), true, "a bare run must read the overlay a bare `cloop ui` reads"},
		{"0", false, "--port 0 is config.yaml alone"},
	} {
		setPort(tc.port)
		cfg, err := loadCommandConfig(hubDoctorCmd, dir)
		if err != nil {
			t.Fatalf("--port %s: %v", tc.port, err)
		}
		if got := cfg.Executors.HostProcessAllowed(); got != tc.wantAllow {
			t.Errorf("--port %s: allow_host_process=%v: %s", tc.port, got, tc.why)
		}
	}

	// The default is the hub `cloop ui` starts without --port, by construction.
	if def := hubDoctorCmd.Flags().Lookup("port").DefValue; def != uiCmd.Flags().Lookup("port").DefValue {
		t.Errorf("hub doctor defaults to --port %s but cloop ui serves on %s", def,
			uiCmd.Flags().Lookup("port").DefValue)
	}
}
