// Handler tests for the stored firewall levels (Task 20363).
//
// The properties worth pinning:
//
//   - an admin sets a device's rule set, and a virtual executor or project
//     whose rules reach further is refused at save time with reasons naming
//     what is outside, so the error lands on the form;
//   - tightening a device narrows what was saved under it — virtual executors
//     and project rule sets alike — in the same transaction, and every
//     narrowing is audited and returned;
//   - a project's rule set is shown beside the levels that govern it, and the
//     dispatch step composes them onto the Spec;
//   - executors that cannot carry a device rule set refuse one.

package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedFirewallDevice registers an offline device that can install a packet
// filter and runs its own payloads in a container on an unfiltered bridge.
func seedFirewallDevice(t *testing.T, dir, id string) {
	t.Helper()
	caps := remote.AgentCapabilities{ContainerRuntimes: []string{"docker"}, OCIRuntimes: []string{"runc"},
		PacketFilter: true}
	dev, err := remote.NewExecutor(remote.Options{ID: id, Name: id, Capabilities: caps,
		Sandbox: func() (executor.SandboxSettings, error) {
			return executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker",
				Network: executor.SandboxNetworkBridge}, nil
		}})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if err := executor.DefaultRegistry.Register(dev); err != nil {
		t.Fatalf("Register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(id) })
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw, _ := json.Marshal(caps)
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: id, Name: id, Kind: executor.KindRemoteAgent,
		Capabilities: raw}); err != nil {
		t.Fatal(err)
	}
}

// fwDo sends one request and decodes the answer, failing unless it has the
// status wanted.
func fwDo[T any](t *testing.T, ts *httptest.Server, method, path string, body any, want int) T {
	t.Helper()
	code, out := virtualDo(t, ts, method, path, body)
	if code != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, out)
	}
	var v T
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("decode %s: %v", out, err)
	}
	return v
}

func firewallAuditRows(t *testing.T, dir, eventType string) []statedb.AuditEvent {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: eventType})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestFirewall_DeviceRulesBoundVirtualExecutorsAndProjects(t *testing.T) {
	dir := setupProjectDir(t, "firewall levels", nil)
	ts := newTestServer(t, dir, nil)
	withControlPlaneDir(t, dir)
	const device = "sgx-fw-1"
	seedFirewallDevice(t, dir, device)

	// A virtual executor with a firewall, saved while the device bounds nothing.
	vxBody := map[string]any{"name": "lab", "spec": map[string]any{
		"sandbox": map[string]any{"mode": "container", "engine": "docker"},
		"firewall": map[string]any{"allow_public_internet": true, "allow_cidrs": []string{"10.20.0.0/16"},
			"resolvers": []string{"1.1.1.1", "8.8.8.8"}},
	}}
	vx := fwDo[virtualExecutorView](t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals", vxBody, http.StatusCreated)
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(vx.ID) })

	// Bind the hub's own project to it and give the project rules of its own.
	if code, body := virtualDo(t, ts, http.MethodPost, "/api/projects/0/executor",
		map[string]any{"executor_id": vx.ID}); code != http.StatusOK {
		t.Fatalf("bind = %d: %s", code, body)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	projectRules := map[string]any{"allow_cidrs": []string{"10.20.5.0/24", "140.82.112.0/20"},
		"allow_ports": []int{22, 443}, "resolvers": []string{"8.8.8.8"}}
	pv := fwDo[projectFirewallView](t, ts, http.MethodPut, "/api/firewall?project_idx=0", projectRules, http.StatusOK)
	if !pv.Configured || !pv.Fits || pv.ExecutorID != vx.ID {
		t.Fatalf("project view after save = %+v", pv)
	}

	// The admin sets the device's rule set: the Internet on 443 only, one
	// resolver. Both rule sets underneath reach further and are narrowed.
	deviceRules := map[string]any{"allow_public_internet": true, "allow_ports": []int{443},
		"resolvers": []string{"1.1.1.1"}, "deny_cidrs": []string{"203.0.113.0/24"}}
	dv := fwDo[deviceFirewallView](t, ts, http.MethodPut, "/api/executors/"+device+"/firewall", deviceRules, http.StatusOK)
	if !dv.Configured || len(dv.Constrained) != 2 {
		t.Fatalf("device save = %+v, want both rule sets underneath narrowed", dv)
	}
	got := map[string]firewallChange{}
	for _, c := range dv.Constrained {
		got[c.Kind] = c
	}
	if c := got["virtual"]; c.Subject != vx.ID || !strings.Contains(strings.Join(c.Notes, " "), "10.20.0.0/16") {
		t.Errorf("virtual executor narrowing = %+v", c)
	}
	if c := got["project"]; c.Subject != dir || !strings.Contains(c.To, "ports 443") {
		t.Errorf("project narrowing = %+v", c)
	}
	for _, child := range dv.Children {
		if !child.Fits {
			t.Errorf("after the save every child must fit: %+v", child)
		}
	}

	// What was stored is what the narrowing said.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stored, _, _ := db.VirtualExecutor(vx.ID)
	devRec, _, _ := db.ExecutorFirewall(device)
	if r := fwpolicy.Permits(&devRec.Rules, *stored.Spec.Firewall); len(r) != 0 {
		t.Errorf("the stored virtual executor still exceeds the device: %v", r)
	}
	if strings.Join(stored.Spec.Firewall.Resolvers, ",") != "1.1.1.1:53" || len(stored.Spec.Firewall.AllowCIDRs) != 0 {
		t.Errorf("virtual executor firewall = %+v", stored.Spec.Firewall)
	}
	prj, _, _ := db.ProjectFirewall(dir)
	if strings.Join(prj.Rules.AllowCIDRs, ",") != "140.82.112.0/20" || len(prj.Rules.Resolvers) != 0 {
		t.Errorf("project rules after the narrowing = %+v", prj.Rules)
	}

	// Each change is on the trail: the device, the narrowed virtual executor,
	// and the project twice (its own save, then the narrowing).
	if rows := firewallAuditRows(t, dir, auditaction.ActionExecutorFirewall.String()); len(rows) != 1 ||
		!strings.Contains(rows[0].Payload, `"constrained":2`) {
		t.Errorf("executor.firewall rows = %+v", rows)
	}
	constrained := 0
	for _, row := range firewallAuditRows(t, dir, auditaction.ActionExecutorVirtual.String()) {
		if strings.Contains(row.Payload, `"action":"constrain"`) {
			constrained++
		}
	}
	if constrained != 1 {
		t.Errorf("executor.virtual constrain rows = %d, want 1", constrained)
	}
	if rows := firewallAuditRows(t, dir, auditaction.ActionProjectFirewall.String()); len(rows) != 2 ||
		!strings.Contains(rows[1].Payload, `"action":"constrain"`) || rows[1].EntityID != dir {
		t.Errorf("project.firewall rows = %+v", rows)
	}

	// The project's card shows the levels that govern it beside its own.
	pv = fwDo[projectFirewallView](t, ts, http.MethodGet, "/api/firewall?project_idx=0", nil, http.StatusOK)
	kinds := []string{}
	for _, l := range pv.Levels {
		kinds = append(kinds, l.Kind)
	}
	if strings.Join(kinds, ",") != "device,own" || pv.Governing == nil || !pv.Fits || !pv.Enforced {
		t.Errorf("project view = %+v (levels %v)", pv, kinds)
	}

	// A project save reaching beyond its virtual executor is refused, naming it.
	code, body := virtualDo(t, ts, http.MethodPut, "/api/firewall?project_idx=0",
		map[string]any{"allow_public_internet": true, "allow_ports": []int{22}})
	if code != http.StatusConflict || !strings.Contains(string(body), "port 22") ||
		!strings.Contains(string(body), "firewall_exceeds_bound") {
		t.Errorf("widening project save = %d: %s", code, body)
	}

	// So is a virtual executor reaching beyond the device …
	wide := map[string]any{"name": "wide", "spec": map[string]any{
		"sandbox":  map[string]any{"mode": "container", "engine": "docker"},
		"firewall": map[string]any{"allow_cidrs": []string{"10.0.0.0/8"}, "allow_ports": []int{443}},
	}}
	code, body = virtualDo(t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals", wide)
	if code != http.StatusConflict || !strings.Contains(string(body), "10.0.0.0/8") {
		t.Errorf("widening virtual executor = %d: %s", code, body)
	}
	// … and one asking for an unfiltered network on a bounded device.
	open := map[string]any{"name": "open", "spec": map[string]any{
		"sandbox": map[string]any{"mode": "container", "engine": "docker", "network": "bridge"},
	}}
	code, body = virtualDo(t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals", open)
	if code != http.StatusConflict || !strings.Contains(string(body), "unfiltered network") {
		t.Errorf("unfiltered virtual executor on a bounded device = %d: %s", code, body)
	}

	// The dispatch step composes the levels onto the Spec.
	ex, err := executor.Get(vx.ID)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := applyFirewall(executor.Spec{WorkDir: dir}, ex, dir)
	if err != nil {
		t.Fatalf("applyFirewall: %v", err)
	}
	if spec.EgressRules == nil || spec.EgressBound == nil ||
		strings.Join(spec.EgressRules.DenyCIDRs, ",") != "203.0.113.0/24" {
		t.Errorf("dispatch did not compose the levels: %+v", spec)
	}
}

func TestFirewall_TighteningReplacesAnUnfilteredVirtualNetwork(t *testing.T) {
	dir := setupProjectDir(t, "firewall unfiltered", nil)
	ts := newTestServer(t, dir, nil)
	withControlPlaneDir(t, dir)
	const device = "sgx-fw-2"
	seedFirewallDevice(t, dir, device)

	vx := fwDo[virtualExecutorView](t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals",
		map[string]any{"name": "open", "spec": map[string]any{
			"sandbox": map[string]any{"mode": "container", "engine": "docker", "network": "lab-net"}}}, http.StatusCreated)
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(vx.ID) })

	rules := map[string]any{"allow_cidrs": []string{"10.8.0.0/24"}, "allow_ports": []int{443}}
	dv := fwDo[deviceFirewallView](t, ts, http.MethodPut, "/api/executors/"+device+"/firewall", rules, http.StatusOK)
	if len(dv.Constrained) != 1 || !strings.Contains(strings.Join(dv.Constrained[0].Notes, " "), "lab-net") {
		t.Fatalf("constrained = %+v", dv.Constrained)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stored, _, _ := db.VirtualExecutor(vx.ID)
	if stored.Spec.Firewall == nil || stored.Spec.Sandbox.Network != "" ||
		strings.Join(stored.Spec.Firewall.AllowCIDRs, ",") != "10.8.0.0/24" {
		t.Errorf("an unfiltered network under a bounded device must become a firewalled bridge: %+v", stored.Spec)
	}

	// Clearing the device's rules widens nothing underneath and narrows nothing.
	dv = fwDo[deviceFirewallView](t, ts, http.MethodPut, "/api/executors/"+device+"/firewall", map[string]any{"clear": true}, http.StatusOK)
	if dv.Configured || len(dv.Constrained) != 0 {
		t.Errorf("after clear = %+v", dv)
	}
	if rows := firewallAuditRows(t, dir, auditaction.ActionExecutorFirewall.String()); len(rows) != 2 ||
		!strings.Contains(rows[1].Payload, `"cleared":true`) {
		t.Errorf("executor.firewall rows = %+v", rows)
	}
}

func TestFirewall_DeviceRulesSaveValidatesAndRefusesTheWrongExecutors(t *testing.T) {
	dir := setupProjectDir(t, "firewall validation", nil)
	ts := newTestServer(t, dir, nil)
	withControlPlaneDir(t, dir)
	const device = "sgx-fw-3"
	seedFirewallDevice(t, dir, device)

	for name, body := range map[string]map[string]any{
		"bad cidr":     {"allow_cidrs": []string{"10.0.0.0/33"}},
		"zero prefix":  {"allow_cidrs": []string{"0.0.0.0/0"}},
		"bad port":     {"allow_ports": []int{70000}},
		"hostname dns": {"resolvers": []string{"dns.example.com"}},
	} {
		if code, out := virtualDo(t, ts, http.MethodPut, "/api/executors/"+device+"/firewall", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	// An empty rule set is a legitimate save: the device reaches nothing.
	dv := fwDo[deviceFirewallView](t, ts, http.MethodPut, "/api/executors/"+device+"/firewall", map[string]any{}, http.StatusOK)
	if !dv.Configured || dv.Describe != "no network" {
		t.Errorf("empty save = %+v", dv)
	}

	if code, out := virtualDo(t, ts, http.MethodGet, "/api/executors/local/firewall", nil); code != http.StatusConflict {
		t.Errorf("host-process executor = %d %s, want 409", code, out)
	}
	if code, _ := virtualDo(t, ts, http.MethodGet, "/api/executors/nope/firewall", nil); code != http.StatusNotFound {
		t.Errorf("unknown executor = %d, want 404", code)
	}
	vx := fwDo[virtualExecutorView](t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals",
		map[string]any{"name": "none", "spec": map[string]any{
			"sandbox": map[string]any{"mode": "container", "engine": "docker"}}}, http.StatusCreated)
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(vx.ID) })
	if code, out := virtualDo(t, ts, http.MethodGet, "/api/executors/"+vx.ID+"/firewall", nil); code != http.StatusConflict ||
		!strings.Contains(string(out), "own dialog") {
		t.Errorf("virtual executor = %d %s, want 409", code, out)
	}

	// The dialog reads the device's rules back, read-only, with each virtual
	// executor's fit.
	pv := fwDo[virtualParentView](t, ts, http.MethodGet, "/api/executors/"+device+"/virtuals", nil, http.StatusOK)
	if pv.DeviceFirewall == nil || pv.DeviceFirewall.HasDestination() {
		t.Errorf("device_firewall = %+v, want the empty rule set", pv.DeviceFirewall)
	}
}
