package ui

// The Secrets panel's grant dialog, driven through the real dashboard bundle
// (Task 20329).
//
// This runs the bundle instead of grepping it because the bug it guards lived
// between four tables rather than in any one of them. `host_device` had a
// constraint entry, a fieldset mapping, an input in the HTML and a validator in
// the broker — every grep-able piece — and an operator still could not issue a
// device grant from the dashboard, because SEC_GRANT_KINDS did not list the
// kind and so it never appeared in the dropdown. Minting a device inventory
// from the panel and then having to reach for the CLI to hand it out is exactly
// the kind of gap a text search reports as covered.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type grantDialogResult struct {
	Kinds   []string `json:"kinds"`
	Visible []string `json:"visible"`
	Sent    bool     `json:"sent"`
	Body    string   `json:"body"`
	Error   string   `json:"error"`

	// writable_follows_the_kind returns a kind -> shown map rather than the
	// fields above.
	HostDevice    *bool `json:"host_device"`
	LocalRepo     *bool `json:"local_repo"`
	HostInterface *bool `json:"host_interface"`
	Kubeconfig    *bool `json:"kubeconfig"`
}

func runGrantDialogScenarios(t *testing.T) map[string]grantDialogResult {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}

	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/interfacegrant_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string]grantDialogResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, r := range results {
		if r.Error != "" {
			t.Fatalf("scenario %s threw: %s", name, r.Error)
		}
	}
	return results
}

// TestDashboard_GrantDialogCoversTheInventoryKinds is the regression that
// matters: every kind an operator can mint must also be grantable here.
//
// Read from the served page rather than through the shim, because the kind
// list is static markup and the shim deliberately does not parse HTML — it
// auto-vivifies elements, so every id resolves and every innerHTML is empty.
// Asserting through it would pass on a page with no <select> at all.
func TestDashboard_GrantDialogCoversTheInventoryKinds(t *testing.T) {
	page := loadAssets().page.contents
	start := strings.Index(page, `id="grantKind"`)
	if start < 0 {
		t.Fatal("the served page has no grant-kind picker")
	}
	end := strings.Index(page[start:], "</select>")
	if end < 0 {
		t.Fatal("the grant-kind picker is not closed")
	}
	picker := page[start : start+end]

	for _, want := range []string{"local_repo", "host_device", "host_interface"} {
		if !strings.Contains(picker, `value="`+want+`"`) {
			t.Errorf("the grant dialog does not offer %q, so a grant of that kind cannot be "+
				"issued from the dashboard at all — an operator can mint the inventory here "+
				"and then has to reach for the CLI to hand it out", want)
		}
	}
}

func TestDashboard_GrantDialogRevealsTheRightFieldset(t *testing.T) {
	res := runGrantDialogScenarios(t)

	visible := res["selecting_host_interface_reveals_its_fieldset"].Visible
	joined := strings.Join(visible, ",")
	if !strings.Contains(joined, "grantSet-hostinterface") {
		t.Fatalf("selecting host_interface does not reveal its allowlist field; visible: %v",
			visible)
	}
	// Exactly one kind fieldset. A dialog showing a neighbour's would collect a
	// constraint the broker rejects for this kind.
	for _, other := range []string{"grantSet-hostdevice", "grantSet-localrepo",
		"grantSet-github", "grantSet-kubeconfig"} {
		if strings.Contains(joined, other) {
			t.Errorf("%s is revealed alongside the host_interface fieldset; visible: %v",
				other, visible)
		}
	}
	// And writable is not offered: an interface is moved, not opened with an
	// access mode, so the broker refuses the constraint on this kind.
	if strings.Contains(joined, "grantSet-writable") {
		t.Errorf("the writable checkbox is offered for host_interface, which the broker "+
			"rejects; visible: %v", visible)
	}
}

func TestDashboard_GrantDialogWritableFollowsTheKind(t *testing.T) {
	r := runGrantDialogScenarios(t)["writable_follows_the_kind"]
	check := func(kind string, got *bool, want bool) {
		t.Helper()
		if got == nil {
			t.Fatalf("scenario did not report %s", kind)
		}
		if *got != want {
			t.Errorf("writable shown for %s = %v, want %v", kind, *got, want)
		}
	}
	check("host_device", r.HostDevice, true)
	check("local_repo", r.LocalRepo, true)
	check("host_interface", r.HostInterface, false)
	check("kubeconfig", r.Kubeconfig, false)
}

// TestDashboard_GrantDialogSendsTheAllowlist closes the loop at the wire. An
// allowlist the dialog collected but did not send produces "a host_interface
// grant needs an interface allowlist" from a form that plainly had one in it.
func TestDashboard_GrantDialogSendsTheAllowlist(t *testing.T) {
	res := runGrantDialogScenarios(t)

	iface := res["submit_sends_the_interface_allowlist"]
	if !iface.Sent {
		t.Fatal("submitting a host_interface grant issued no POST to /api/grants")
	}
	// A fresh map per document, never one reused across the three: json.Unmarshal
	// *merges* into a non-nil map instead of replacing it, so a shared one would
	// carry the device body's `writable` into the assertion below that no
	// writable was sent — reporting a bug that is entirely the test's.
	body := map[string]any{}
	if err := json.Unmarshal([]byte(iface.Body), &body); err != nil {
		t.Fatalf("grant body is not JSON: %v\n%s", err, iface.Body)
	}
	if got := body["interfaces"]; !jsonListEquals(got, []string{"dut", "can0"}) {
		t.Errorf("interfaces = %#v, want [dut can0] — the broker requires the allowlist "+
			"and refuses the grant without it", got)
	}
	if _, present := body["writable"]; present {
		t.Errorf("writable was sent for host_interface, which the broker rejects: %s", iface.Body)
	}

	dev := res["submit_sends_the_device_allowlist_and_writable"]
	if !dev.Sent {
		t.Fatal("submitting a host_device grant issued no POST to /api/grants")
	}
	devBody := map[string]any{}
	if err := json.Unmarshal([]byte(dev.Body), &devBody); err != nil {
		t.Fatalf("device grant body is not JSON: %v\n%s", err, dev.Body)
	}
	if got := devBody["devices"]; !jsonListEquals(got, []string{"serial0"}) {
		t.Errorf("devices = %#v, want [serial0]", got)
	}
	if devBody["writable"] != true {
		t.Errorf("writable was not sent for a device grant the operator ticked, so the "+
			"grant would be silently read-only: %s", dev.Body)
	}

	stale := res["submit_omits_writable_for_other_kinds"]
	staleBody := map[string]any{}
	if err := json.Unmarshal([]byte(stale.Body), &staleBody); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, stale.Body)
	}
	if _, present := staleBody["writable"]; present {
		t.Errorf("a checkbox left ticked by a previous kind rode along on a host_interface "+
			"grant, which the broker refuses outright: %s", stale.Body)
	}
}

// jsonListEquals compares a JSON-decoded []any against the expected strings.
// Named for the shape it reads rather than the comparison it makes, because
// pkg/ui already has an equalStrings over two []string.
func jsonListEquals(got any, want []string) bool {
	list, ok := got.([]any)
	if !ok || len(list) != len(want) {
		return false
	}
	for i, v := range list {
		if s, ok := v.(string); !ok || s != want[i] {
			return false
		}
	}
	return true
}
