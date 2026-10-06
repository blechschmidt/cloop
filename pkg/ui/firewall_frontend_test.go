package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestDashboard_FirewallPanels drives the shipped bundle through the firewall
// panels (Task 20363): a device's dialog from its card, the device's rules in
// the virtual-executor dialog, and a project's card on the Overview page.
func TestDashboard_FirewallPanels(t *testing.T) {
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
	scenarios, _ := filepath.Abs("testdata/firewall_scenarios.js")
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
	need := func(scenario, what, in string, wants ...string) {
		t.Helper()
		for _, w := range wants {
			if !strings.Contains(in, w) {
				t.Errorf("%s: %s lacks %q", scenario, what, w)
			}
		}
	}

	cards, dialog, _ := strings.Cut(res["device_dialog"].HTML, "\n----\n")
	// Through panelAct: the dialog is deferred (Task 20386).
	need("device_dialog", "the cards", cards, "panelAct('execadmin','openExecutorFirewall',0)")
	if strings.Contains(cards, "'openExecutorFirewall',1)") || strings.Contains(cards, "'openExecutorFirewall',2)") {
		t.Error("device_dialog: the host-process and virtual executors must not offer a device firewall")
	}
	need("device_dialog", "the dialog", dialog,
		"Set by admin@example.com",
		"runs payloads on its host", "Lab", "/srv/app", "(exceeds it)", "port 22 is not allowed",
		`data-act="clearExecutorFirewall"`, `data-act="saveExecutorFirewall"`)

	need("summary", "the sentence", res["summary"].HTML,
		"In effect: TCP to the public Internet on port 443; DNS via 1.1.1.1:53; never 203.0.113.0/24. "+
			"Everything else is dropped.",
		"In effect: no network: nothing is reachable.")

	var body map[string]any
	if err := json.Unmarshal([]byte(res["device_save"].Body), &body); err != nil {
		t.Fatalf("device_save: body %q: %v", res["device_save"].Body, err)
	}
	if body["allow_public_internet"] != false || fwJoin(body["allow_cidrs"]) != "10.8.0.0/24,140.82.112.0/20" ||
		fwJoin(body["deny_cidrs"]) != "10.8.0.9" || fwJoin(body["allow_ports"]) != "443,8443" ||
		fwJoin(body["resolvers"]) != "1.1.1.1" {
		t.Errorf("device_save: body = %v", body)
	}
	need("device_save", "the dialog after saving", res["device_save"].HTML,
		"Narrowed to fit", "/srv/app", "its ports were narrowed from 22, 443 to 443")

	need("device_refused", "the warning", res["device_refused"].HTML, "10.0.0.0/8 is outside the governing rule set")

	vx := res["virtual_dialog"].HTML
	need("virtual_dialog", "the dialog", vx, "<b>Device firewall</b>: TCP to the public Internet on port 443",
		"exceeds device firewall", "not available: the device’s firewall bounds every sandbox on it.")
	if !strings.Contains(vx, `id="evxNetOpen" disabled`) {
		t.Error("virtual_dialog: Unfiltered must be disabled under a device firewall")
	}

	pc := res["project_card"].HTML
	if !strings.HasPrefix(pc, "|") {
		t.Errorf("project_card: the panel must be shown, display = %q", strings.SplitN(pc, "|", 2)[0])
	}
	need("project_card", "the card", pc, "Governing rules", "device sgx-dev&#39;s firewall",
		"virtual executor vx-abcdefghij&#39;s firewall", "Together: <b>TCP to 1.1.1.0/24 on port 443",
		"None: runs get the governing rules.", ">1.1.1.0/24</textarea>")
	need("project_card", "the save", res["project_card"].Body, "/api/firewall", `"allow_cidrs":["1.1.1.0/25"]`,
		`"allow_ports":[443]`)
	// The shim has no tree, so the card's inner elements are stand-ins:
	// "kept" means the card's markup was not replaced, and pfwGov and pfwWarn
	// are what the refresh wrote to them.
	keeps := strings.Split(res["project_card_keeps_edits"].HTML, "\n----\n")
	if len(keeps) != 4 {
		t.Fatalf("project_card_keeps_edits: %d parts, want 4:\n%s", len(keeps), res["project_card_keeps_edits"].HTML)
	}
	for i, step := range []struct{ label, cidr string }{{"typed", "10.1.0.0/16"}, {"caret", "10.2.0.0/16"}} {
		need("project_card_keeps_edits", "a refresh while "+step.label, keeps[i], step.label+": kept",
			"TCP to "+step.cidr+" on port 443", "8.8.8.0/24 is outside the governing rule set")
	}
	need("project_card_keeps_edits", "a refresh of an idle card", keeps[2], "idle: drawn")
	need("project_card_keeps_edits", "the card drawn again", keeps[3], "TCP to 10.3.0.0/16 on port 443",
		`id="pfwGov"`, `id="pfwWarn"`, `id="pfwAllow"`)
	if got := res["project_card_viewer"].HTML; got != "none" {
		t.Errorf("project_card_viewer: the card must be hidden without config.write, display = %q", got)
	}
}

// fwJoin renders a decoded JSON list as "a,b,c".
func fwJoin(v any) string {
	xs, _ := v.([]any)
	out := make([]string, len(xs))
	for i, x := range xs {
		switch n := x.(type) {
		case float64:
			out[i] = strconv.FormatFloat(n, 'f', -1, 64)
		case string:
			out[i] = n
		}
	}
	return strings.Join(out, ",")
}
