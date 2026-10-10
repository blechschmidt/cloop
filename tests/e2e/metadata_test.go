package e2e_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestE2EUIRefusesAnAllowlistThatOpensAMetadataService is Task 20397 at config
// load, through the built binary: a container egress_filter whose allowlist
// contains the cloud metadata services without naming them stops `cloop ui`
// before it listens, with a sentence naming the key, the services and the way
// out, and `cloop hub doctor` fails the same allowlist; naming every service
// turns the doctor's finding to a pass.
func TestE2EUIRefusesAnAllowlistThatOpensAMetadataService(t *testing.T) {
	s := newExposureScene(t)
	cfgPath := filepath.Join(s.dir, ".cloop", "config.yaml")
	base, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	section := `
executors:
  container:
    enabled: true
    network: bridge
    egress_filter:
      enabled: true
      allow_cidrs: ["169.254.0.0/16"]
      allow_ports: [80]
      resolvers: ["1.1.1.1"]
`
	writeTestFile(t, cfgPath, string(base)+section)

	port := freePort(t)
	out, err := s.runErr(nil, "ui", "--port", strconv.Itoa(port), "--no-browser")
	if err == nil {
		t.Fatalf("cloop ui started with an allowlist that contains the metadata services:\n%s", out)
	}
	for _, want := range []string{
		"refusing to start",
		"executors.container.egress_filter.allow_cidrs: 169.254.0.0/16 contains 6 cloud metadata services",
		"169.254.169.254 (instance metadata on AWS",
		"Add their addresses (169.254.0.23/32,",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, out)
		}
	}
	if dialable(net.IPv4(127, 0, 0, 1), port) {
		t.Errorf("something listens on :%d after the refusal", port)
	}

	doctor, _ := s.runErrStdout(nil, "hub", "doctor", "--offline", "--json")
	var rep struct {
		Findings []struct{ Check, Severity, Message string } `json:"findings"`
	}
	if err := json.Unmarshal([]byte(doctor), &rep); err != nil {
		t.Fatalf("hub doctor --json: %v\n%s", err, doctor)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Check == "firewall.metadata" {
			found = true
			if f.Severity != "fail" || !strings.Contains(f.Message, "169.254.0.0/16 contains 6") {
				t.Errorf("hub doctor: %s: %s", f.Severity, f.Message)
			}
		}
	}
	if !found {
		t.Errorf("hub doctor reported no firewall.metadata finding:\n%s", doctor)
	}

	// Named, the allowlist says what it means and the refusal is gone.
	writeTestFile(t, cfgPath, string(base)+strings.Replace(section, `["169.254.0.0/16"]`,
		`["169.254.0.0/16", "169.254.0.23/32", "169.254.42.42/32", "169.254.169.252/32", "169.254.169.254/32", `+
			`"169.254.170.2/32", "169.254.170.23/32"]`, 1))
	doctor, _ = s.runErrStdout(nil, "hub", "doctor", "--offline", "--json")
	rep.Findings = nil
	if err := json.Unmarshal([]byte(doctor), &rep); err != nil {
		t.Fatalf("hub doctor --json: %v\n%s", err, doctor)
	}
	for _, f := range rep.Findings {
		if f.Check == "firewall.metadata" && f.Severity != "pass" {
			t.Errorf("with every service named, hub doctor still says %s: %s", f.Severity, f.Message)
		}
	}
}
