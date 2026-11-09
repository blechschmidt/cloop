package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"gopkg.in/yaml.v3"
)

// hostSandboxOff turns the host sandbox off on hub, for a test in which people
// work on the hub's own directory, which the sandbox refuses them, to test
// something the sandbox does not change: whose account a call runs on, what a
// requirement check reads. Call it after the test has written the hub's
// config.yaml, which it merges into.
func hostSandboxOff(t *testing.T, hub *ssohubtest.Hub) {
	t.Helper()
	path := filepath.Join(hub.Dir, ".cloop", "config.yaml")
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	executors, _ := doc["executors"].(map[string]any)
	if executors == nil {
		executors = map[string]any{}
	}
	executors["host_sandbox"] = map[string]any{"mode": "off"}
	doc["executors"] = executors
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
