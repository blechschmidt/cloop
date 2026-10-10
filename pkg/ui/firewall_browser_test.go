package ui

// Browser gate for the firewall panels (Task 20363): a device's rule set set
// from its card narrows what was saved under it, a project's card refuses a
// widening on the form and stores a narrowing, a fleet event's refresh takes
// neither an edit nor a refusal off the card, and the virtual-executor dialog
// shows the device's rules and offers no unfiltered network under them. The
// node scenarios cannot see any of it: testdata/domshim.js does not parse the
// forms these panels build, so every field there is a stand-in.
//
// It skips when Chrome or node is missing, like every browser gate here.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

func TestFirewallPanels_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	// A registry of its own, so the hub is single-project and lands on this
	// project's Overview (see pkg-ui test notes: the package-wide HOME collects
	// other tests' projects).
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "firewall panels", nil)
	const device = "sgx-fw-browser"
	seedFirewallDevice(t, dir, device)

	// Configured before the listener starts: requests from Chrome carry no
	// happens-before edge the race detector can see.
	srv := New(dir, 0, "")
	withControlPlaneDir(t, dir)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	vx := fwDo[virtualExecutorView](t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals",
		map[string]any{"name": "Lab", "spec": map[string]any{
			"sandbox": map[string]any{"mode": "container", "engine": "docker"},
			"firewall": map[string]any{"allow_public_internet": true, "allow_cidrs": []string{"10.20.0.0/16"},
				"resolvers": []string{"1.1.1.1"}}}}, http.StatusCreated)
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(vx.ID) })
	if code, body := virtualDo(t, ts, http.MethodPost, "/api/projects/0/executor",
		map[string]any{"executor_id": vx.ID}); code != http.StatusOK {
		t.Fatalf("bind = %d: %s", code, body)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	fwDo[projectFirewallView](t, ts, http.MethodPut, "/api/firewall?project_idx=0", map[string]any{
		"allow_cidrs": []string{"10.20.5.0/24", "140.82.112.0/20"}, "allow_ports": []int{22, 443},
		"resolvers": []string{"1.1.1.1"}}, http.StatusOK)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/firewall_browser.js"),
		chrome, ts.URL, device, os.Getenv("CLOOP_FIREWALL_SHOTS")).Output()
	var got struct {
		FirewallButtons     int                 `json:"firewall_buttons"`
		DeviceFieldsVisible bool                `json:"device_fields_visible"`
		DeviceSummary       string              `json:"device_summary"`
		DeviceAfter         string              `json:"device_after"`
		DeviceStored        deviceFirewallView  `json:"device_stored"`
		ProjectCard         string              `json:"project_card"`
		ProjectAllow        string              `json:"project_allow"`
		ProjectRefusal      string              `json:"project_refusal"`
		MetadataRefusal     string              `json:"project_metadata_refusal"`
		MetadataTyped       string              `json:"project_metadata_typed"`
		ProjectStored       projectFirewallView `json:"project_stored"`
		VirtualDialog       string              `json:"virtual_dialog"`
		UnfilteredDisabled  bool                `json:"unfiltered_disabled"`
		Error               string              `json:"error"`
	}
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		t.Fatalf("driving the browser failed: %v / %v\n%s", err, jerr, out)
	}
	if got.Error != "" {
		t.Fatalf("the driver reported an error: %s", got.Error)
	}

	if got.FirewallButtons != 1 {
		t.Errorf("%d cards offer a device firewall, want only the device's", got.FirewallButtons)
	}
	if !got.DeviceFieldsVisible {
		t.Error("the device dialog's fields are not all on screen")
	}
	if !strings.Contains(got.DeviceSummary, "In effect: TCP to the public Internet on port 443; DNS via 1.1.1.1") {
		t.Errorf("typing did not reach the summary through the fields' oninput: %q", got.DeviceSummary)
	}
	for _, want := range []string{"Narrowed to fit", "Lab", "10.20.0.0/16", dir} {
		if !strings.Contains(got.DeviceAfter, want) {
			t.Errorf("after saving, the device dialog lacks %q:\n%s", want, got.DeviceAfter)
		}
	}
	if !got.DeviceStored.Configured || strings.Join(intStrings(got.DeviceStored.Rules.AllowPorts), ",") != "443" {
		t.Errorf("the hub stored %+v for the device", got.DeviceStored.Rules)
	}

	for _, want := range []string{"Governing rules", "device " + device + "'s firewall",
		"virtual executor " + vx.ID + "'s firewall", "This project’s rules"} {
		if !strings.Contains(got.ProjectCard, want) {
			t.Errorf("the project card lacks %q:\n%s", want, got.ProjectCard)
		}
	}
	if got.ProjectAllow != "140.82.112.0/20" {
		t.Errorf("the project card's allowlist = %q, want what the device's save narrowed it to", got.ProjectAllow)
	}
	if !strings.Contains(got.ProjectRefusal, "port 22") {
		t.Errorf("a widening was not refused on the form, or a fleet event took the refusal away: %q",
			got.ProjectRefusal)
	}
	for _, want := range []string{"169.254.169.0/24 contains 2 cloud metadata services without naming them",
		"169.254.169.254 (instance metadata on AWS", "or to the denylist so they stay closed"} {
		if !strings.Contains(got.MetadataRefusal, want) {
			t.Errorf("the card does not show the hub's metadata refusal %q: %q", want, got.MetadataRefusal)
		}
	}
	if got.MetadataTyped != "169.254.169.0/24" {
		t.Errorf("the refused range was taken off the form: %q", got.MetadataTyped)
	}
	if r := got.ProjectStored.Rules; strings.Join(r.AllowCIDRs, ",") != "140.82.112.0/24" || !got.ProjectStored.Fits {
		t.Errorf("the narrowing typed on the card was stored as %+v", r)
	}

	if !strings.Contains(got.VirtualDialog, "Device firewall: TCP to the public Internet on port 443") {
		t.Errorf("the virtual-executor dialog does not show the device's rules:\n%s", got.VirtualDialog)
	}
	if !got.UnfilteredDisabled {
		t.Error("the virtual-executor dialog offers an unfiltered network under a device firewall")
	}
}

func intStrings(xs []int) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(x)
	}
	return out
}
