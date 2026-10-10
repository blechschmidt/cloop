package ui

// Handler tests for Task 20397: an allowlist entry that contains a cloud
// metadata service without naming it is refused at every API that saves a
// firewall — 400, with a sentence naming the service and both explicit
// alternatives — and a rule set stored before the rule is listed on its card,
// where it keeps loading.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// wantMetadataRefusal asserts a 400 whose message names the containing range,
// the service and both ways out.
func wantMetadataRefusal(t *testing.T, what string, code int, body []byte, rng, service string) {
	t.Helper()
	if code != http.StatusBadRequest {
		t.Fatalf("%s = %d %s, want 400", what, code, body)
	}
	for _, want := range []string{rng + " contains", service, "to the allowlist if a sandbox should reach",
		"or to the denylist so"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("%s: refusal %s lacks %q", what, body, want)
		}
	}
}

func TestFirewall_AnAllowlistContainingAMetadataServiceIsRefused(t *testing.T) {
	dir := setupProjectDir(t, "firewall metadata", nil)
	ts := newTestServer(t, dir, nil)
	withControlPlaneDir(t, dir)
	const device = "sgx-fw-md"
	seedFirewallDevice(t, dir, device)

	// The device's rule set.
	code, body := virtualDo(t, ts, http.MethodPut, "/api/executors/"+device+"/firewall",
		map[string]any{"allow_cidrs": []string{"169.254.0.0/16"}, "allow_ports": []int{80}})
	wantMetadataRefusal(t, "device save", code, body, "169.254.0.0/16", "169.254.169.254 (instance metadata")
	// Denying them is the other explicit answer, and is saved.
	deny := []string{"169.254.0.23", "169.254.42.42", "169.254.169.252", "169.254.169.254", "169.254.170.2",
		"169.254.170.23"}
	dv := fwDo[deviceFirewallView](t, ts, http.MethodPut, "/api/executors/"+device+"/firewall",
		map[string]any{"allow_cidrs": []string{"169.254.0.0/16", "fd00:ec2::254/128"}, "deny_cidrs": deny,
			"allow_ports": []int{80, 443}, "allow_public_internet": true, "resolvers": []string{"1.1.1.1"}},
		http.StatusOK)
	if len(dv.Metadata) != 0 {
		t.Errorf("a rule set that denies every service it contains is listed: %v", dv.Metadata)
	}

	// A virtual executor's, on create and on update.
	vxSpec := func(cidrs ...string) map[string]any {
		return map[string]any{"name": "lab", "spec": map[string]any{
			"sandbox":  map[string]any{"mode": "container", "engine": "docker"},
			"firewall": map[string]any{"allow_cidrs": cidrs, "allow_ports": []int{443}}}}
	}
	code, body = virtualDo(t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals", vxSpec("fc00::/7"))
	wantMetadataRefusal(t, "virtual executor create", code, body, "fc00::/7", "fd00:ec2::254 (AWS instance metadata over IPv6)")
	vx := fwDo[virtualExecutorView](t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals",
		vxSpec("fd00:ec2::254/128"), http.StatusCreated)
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(vx.ID) })
	code, body = virtualDo(t, ts, http.MethodPut, "/api/executors/"+vx.ID+"/virtual", vxSpec("fd00:ec2::/32"))
	wantMetadataRefusal(t, "virtual executor update", code, body, "fd00:ec2::/32", "fd00:ec2::23")

	// A project's.
	if code, body := virtualDo(t, ts, http.MethodPost, "/api/projects/0/executor",
		map[string]any{"executor_id": device}); code != http.StatusOK {
		t.Fatalf("bind = %d: %s", code, body)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	code, body = virtualDo(t, ts, http.MethodPut, "/api/firewall?project_idx=0",
		map[string]any{"allow_cidrs": []string{"169.254.169.0/24"}, "allow_ports": []int{80}})
	wantMetadataRefusal(t, "project save", code, body, "169.254.169.0/24", "169.254.169.252")

	// Nothing refused was stored.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, ok, _ := db.ProjectFirewall(dir); ok {
		t.Error("a refused project rule set was stored")
	}
	if got, _, _ := db.VirtualExecutor(vx.ID); got.Spec.Firewall == nil ||
		strings.Join(got.Spec.Firewall.AllowCIDRs, ",") != "fd00:ec2::254/128" {
		t.Errorf("a refused update was stored: %+v", got.Spec.Firewall)
	}
}

// TestFirewall_StoredRulesThatContainAServiceAreListedOnTheirCards: rule sets
// written before the rule load as they always did, and each card says what is
// wrong with its own — so an admin learns of it on the card rather than from a
// refused save.
func TestFirewall_StoredRulesThatContainAServiceAreListedOnTheirCards(t *testing.T) {
	dir := setupProjectDir(t, "firewall metadata stored", nil)
	ts := newTestServer(t, dir, nil)
	withControlPlaneDir(t, dir)
	const device = "sgx-fw-md2"
	seedFirewallDevice(t, dir, device)
	vx := fwDo[virtualExecutorView](t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals",
		map[string]any{"name": "lab", "spec": map[string]any{
			"sandbox":  map[string]any{"mode": "container", "engine": "docker"},
			"firewall": map[string]any{"allow_cidrs": []string{"10.20.0.0/16"}, "allow_ports": []int{443}}}},
		http.StatusCreated)
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(vx.ID) })
	if code, body := virtualDo(t, ts, http.MethodPost, "/api/projects/0/executor",
		map[string]any{"executor_id": device}); code != http.StatusOK {
		t.Fatalf("bind = %d: %s", code, body)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	// Below the API, the way a rule set saved before the rule is stored.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetExecutorFirewall(device, executor.FirewallRules{AllowPublicInternet: true,
		AllowCIDRs: []string{"100.64.0.0/10", "fc00::/7"}, AllowPorts: []int{443}}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetProjectFirewall(dir, executor.FirewallRules{AllowCIDRs: []string{"100.100.100.0/24"},
		AllowPorts: []int{443}}, "maintainer"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateFirewalls(func(tx *statedb.FirewallTx) error {
		return tx.SetVirtualExecutorSpec(vx.ID, executor.VirtualSpec{
			Sandbox:  executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker"},
			Firewall: &executor.FirewallRules{AllowCIDRs: []string{"100.64.0.0/10"}, AllowPorts: []int{443}}}, "admin")
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	dv := fwDo[deviceFirewallView](t, ts, http.MethodGet, "/api/executors/"+device+"/firewall", nil, http.StatusOK)
	if len(dv.Metadata) != 2 || !strings.Contains(strings.Join(dv.Metadata, " "), "100.100.100.200 (Alibaba Cloud") ||
		!strings.Contains(strings.Join(dv.Metadata, " "), "It stays closed") {
		t.Errorf("device card metadata = %v", dv.Metadata)
	}
	flagged := map[string]bool{}
	for _, c := range dv.Children {
		flagged[c.Kind] = len(c.Metadata) > 0
	}
	if !flagged["virtual"] || !flagged["project"] {
		t.Errorf("the device card does not flag its children: %+v", dv.Children)
	}

	pv := fwDo[projectFirewallView](t, ts, http.MethodGet, "/api/firewall?project_idx=0", nil, http.StatusOK)
	if len(pv.Metadata) != 1 || !strings.Contains(pv.Metadata[0], "100.100.100.0/24 contains") {
		t.Errorf("project card metadata = %v", pv.Metadata)
	}
	parent := fwDo[virtualParentView](t, ts, http.MethodGet, "/api/executors/"+device+"/virtuals", nil, http.StatusOK)
	for _, v := range parent.VirtualExecutors {
		if v.ID == vx.ID && (len(v.Metadata) != 1 || !strings.Contains(v.Metadata[0], "100.64.0.0/10 contains")) {
			t.Errorf("virtual executor card metadata = %v", v.Metadata)
		}
	}

	// And saving the same rules again is refused until they say what they mean.
	code, body := virtualDo(t, ts, http.MethodPut, "/api/firewall?project_idx=0",
		map[string]any{"allow_cidrs": []string{"100.100.100.0/24"}, "allow_ports": []int{443}})
	wantMetadataRefusal(t, "re-saving the stored project rules", code, body, "100.100.100.0/24", "100.100.100.200")
}
