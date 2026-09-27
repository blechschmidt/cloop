package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDashboard_VirtualExecutorDialog drives the shipped bundle through the
// virtual-executor dialog (Task 20345): the device's USB devices reach the form,
// and what an admin ticks and types reaches the API as the spec the backend
// validates — the YubiHSM selected by identity, the firewall's allowlist and
// denylist split into lists, an empty port field sent as "every port".
func TestDashboard_VirtualExecutorDialog(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatal(err)
	}
	shim, _ := filepath.Abs("testdata/domshim.js")
	scenarios, _ := filepath.Abs("testdata/executor_virtual_scenarios.js")
	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("scenarios failed: %v\n%s\n%s", err, out, stderr)
	}
	var res map[string]struct {
		HTML  string `json:"html"`
		Body  string `json:"body"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, r := range res {
		if r.Error != "" {
			t.Fatalf("scenario %s threw: %s", name, r.Error)
		}
	}

	cards := res["cards"].HTML
	for _, want := range []string{"openExecutorVirtual(0)", "Virtual (1)", "firewall: on", "devices: 1",
		"Virtual executor on sgx", "openExecutorVirtual(1)"} {
		if !strings.Contains(cards, want) {
			t.Errorf("cards lack %q", want)
		}
	}
	if strings.Contains(cards, "revokeExecutor(1)") {
		t.Error("the virtual executor's card offers Revoke")
	}

	dialog := res["dialog"].HTML
	for _, want := range []string{"Yubico YubiHSM", "1050:0030", "0031650425", "/dev/bus/usb/001/002",
		"evxUsb0", "Denylist", "Allowlist", "runsc"} {
		if !strings.Contains(dialog, want) {
			t.Errorf("dialog lacks %q", want)
		}
	}
	if strings.Contains(dialog, "1d6b:0002") {
		t.Error("the dialog offers a USB hub, whose node passes nothing through")
	}

	var body struct {
		Name string `json:"name"`
		Spec struct {
			Sandbox  map[string]string `json:"sandbox"`
			Firewall struct {
				AllowPublicInternet bool     `json:"allow_public_internet"`
				AllowCIDRs          []string `json:"allow_cidrs"`
				DenyCIDRs           []string `json:"deny_cidrs"`
				AllowPorts          []int    `json:"allow_ports"`
				Resolvers           []string `json:"resolvers"`
			} `json:"firewall"`
			Devices []struct {
				Name  string            `json:"name"`
				Group string            `json:"group"`
				USB   map[string]string `json:"usb"`
			} `json:"devices"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(res["create"].Body), &body); err != nil {
		t.Fatalf("create posted %q: %v", res["create"].Body, err)
	}
	sp := body.Spec
	if body.Name != "HSM sandbox" || sp.Sandbox["mode"] != "container" || sp.Sandbox["runtime"] != "runc" ||
		sp.Sandbox["network"] != "" {
		t.Errorf("sandbox = %+v", sp.Sandbox)
	}
	fw := sp.Firewall
	if !fw.AllowPublicInternet || strings.Join(fw.AllowCIDRs, ",") != "10.8.0.0/24" ||
		strings.Join(fw.DenyCIDRs, ",") != "203.0.113.0/24,198.51.100.7" || len(fw.AllowPorts) != 0 ||
		strings.Join(fw.Resolvers, ",") != "1.1.1.1,9.9.9.9" {
		t.Errorf("firewall = %+v", fw)
	}
	if len(sp.Devices) != 1 || sp.Devices[0].USB["vendor_id"] != "1050" || sp.Devices[0].USB["serial"] != "0031650425" ||
		sp.Devices[0].Group != "plugdev" {
		t.Errorf("devices = %+v", sp.Devices)
	}
}
