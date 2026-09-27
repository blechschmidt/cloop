// Handler tests for virtual executors (Task 20345).
//
// The properties worth pinning:
//
//   - an admin can create, read, edit and delete a sub-executor of a device,
//     and every write is validated at the boundary — the firewall and device
//     lists end up in nftables and a container runtime's argv;
//   - a created virtual executor is a real executor: registered, bindable,
//     listed on the Executors panel with its parent and a summary;
//   - the device's USB inventory is served for the form to choose from, from
//     its last connect when it is offline;
//   - the device-wide sandbox route refuses a virtual executor, whose sandbox
//     is part of its own definition.

package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedDevice registers an offline remote executor with a stored inventory
// holding the sgx YubiHSM, and returns its ID.
func seedDevice(t *testing.T, dir, id string) string {
	t.Helper()
	parent, err := remote.NewExecutor(remote.Options{ID: id, Name: "sgx"})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if err := executor.DefaultRegistry.Register(parent); err != nil {
		t.Fatalf("Register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(id) })

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer db.Close()
	caps, _ := json.Marshal(remote.AgentCapabilities{
		ContainerRuntimes: []string{"docker"},
		OCIRuntimes:       []string{"runc", "runsc"},
		PacketFilter:      true,
		USBDevices: []executor.USBDevice{{
			Port: "1-1", Bus: 1, Dev: 2, VendorID: "1050", ProductID: "0030",
			Manufacturer: "Yubico", Product: "YubiHSM", Serial: "0031650425",
			Node: "/dev/bus/usb/001/002",
		}},
	})
	if err := db.UpsertExecutor(statedb.ExecutorRow{
		ID: id, Name: "sgx", Kind: executor.KindRemoteAgent, Capabilities: caps,
	}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
	return id
}

func virtualDo(t *testing.T, ts *httptest.Server, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func hsmRequest(name string) map[string]any {
	return map[string]any{
		"name": name,
		"spec": map[string]any{
			"sandbox": map[string]any{"mode": "container", "engine": "docker", "image": "ubuntu:24.04"},
			"firewall": map[string]any{
				"allow_public_internet": true,
				"deny_cidrs":            []string{"203.0.113.0/24", "10.0.0.0/8"},
				"resolvers":             []string{"1.1.1.1"},
			},
			"devices": []map[string]any{{
				"name": "yubihsm",
				"usb":  map[string]any{"vendor_id": "1050", "product_id": "0030", "serial": "0031650425"},
			}},
		},
	}
}

func TestVirtualExecutors_Lifecycle(t *testing.T) {
	dir := setupProjectDir(t, "virtual executors", nil)
	ts := newTestServer(t, dir, nil)
	parent := seedDevice(t, dir, "sgx-device-1")

	// The form's source material: the device's USB inventory, from its last
	// connect because it is offline, and what it can build a sandbox from.
	code, body := virtualDo(t, ts, http.MethodGet, "/api/executors/"+parent+"/virtuals", nil)
	if code != http.StatusOK {
		t.Fatalf("GET virtuals = %d: %s", code, body)
	}
	var list virtualParentView
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Connected || len(list.USBDevices) != 1 || list.USBDevices[0].Product != "YubiHSM" ||
		!list.PacketFilter || strings.Join(list.OCIRuntimes, ",") != "runc,runsc" {
		t.Fatalf("parent view = %+v", list)
	}

	// Create.
	code, body = virtualDo(t, ts, http.MethodPost, "/api/executors/"+parent+"/virtuals", hsmRequest("HSM sandbox"))
	if code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", code, body)
	}
	var created virtualExecutorView
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(created.ID) })
	if !strings.HasPrefix(created.ID, "vx-") || !created.Registered || created.ParentID != parent {
		t.Fatalf("created = %+v", created)
	}
	if got := created.Spec.Firewall.DenyCIDRs; strings.Join(got, ",") != "10.0.0.0/8,203.0.113.0/24" {
		t.Errorf("stored deny list = %v, want it normalized", got)
	}

	// It is a real executor: registered under its own ID, of the virtual kind,
	// on the Executors panel with its parent.
	ex, err := executor.Get(created.ID)
	if err != nil || ex.Kind() != executor.KindVirtual {
		t.Fatalf("registry: %v %v", ex, err)
	}
	var fleet executorsResponse
	if code, body := virtualDo(t, ts, http.MethodGet, "/api/executors", nil); code != http.StatusOK {
		t.Fatalf("GET executors = %d: %s", code, body)
	} else if err := json.Unmarshal(body, &fleet); err != nil {
		t.Fatal(err)
	}
	var card, parentCard *executorView
	for i := range fleet.Executors {
		switch fleet.Executors[i].ID {
		case created.ID:
			card = &fleet.Executors[i]
		case parent:
			parentCard = &fleet.Executors[i]
		}
	}
	if card == nil || card.Virtual == nil || card.Virtual.ParentID != parent || card.Kind != executor.KindVirtual {
		t.Fatalf("virtual executor card = %+v", card)
	}
	if !strings.Contains(card.Virtual.Firewall, "deny") || len(card.Virtual.Devices) != 1 {
		t.Errorf("card summary = %+v", card.Virtual)
	}
	if card.Enrolled {
		t.Error("the card offers Revoke/Upgrade for a virtual executor, which has neither")
	}
	if parentCard == nil || parentCard.VirtualCount != 1 {
		t.Errorf("the device's card does not count its virtual executor: %+v", parentCard)
	}

	// Edit: the firewall goes, the name changes.
	edit := hsmRequest("HSM sandbox (offline)")
	delete(edit["spec"].(map[string]any), "firewall")
	code, body = virtualDo(t, ts, http.MethodPut, "/api/executors/"+created.ID+"/virtual", edit)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", code, body)
	}
	var updated virtualExecutorView
	_ = json.Unmarshal(body, &updated)
	if updated.Name != "HSM sandbox (offline)" || updated.Spec.Firewall != nil {
		t.Errorf("updated = %+v", updated)
	}
	if vx, _ := executor.Get(created.ID); vx.(*remote.Virtual).Name() != "HSM sandbox (offline)" {
		t.Error("a rename did not reach the registered executor")
	}

	// The device-wide sandbox route refuses it: its sandbox is its definition.
	if code, _ := virtualDo(t, ts, http.MethodGet, "/api/executors/"+created.ID+"/sandbox", nil); code != http.StatusConflict {
		t.Errorf("GET sandbox for a virtual executor = %d, want 409", code)
	}

	// Delete: gone from the database and the registry.
	if code, body := virtualDo(t, ts, http.MethodDelete, "/api/executors/"+created.ID+"/virtual", nil); code != http.StatusOK {
		t.Fatalf("DELETE = %d: %s", code, body)
	}
	if _, err := executor.Get(created.ID); err == nil {
		t.Error("a deleted virtual executor is still registered")
	}
	if code, _ := virtualDo(t, ts, http.MethodGet, "/api/executors/"+created.ID+"/virtual", nil); code != http.StatusNotFound {
		t.Errorf("GET after delete = %d, want 404", code)
	}
}

func TestVirtualExecutors_ValidationAtTheBoundary(t *testing.T) {
	dir := setupProjectDir(t, "virtual executor validation", nil)
	ts := newTestServer(t, dir, nil)
	parent := seedDevice(t, dir, "sgx-device-2")

	for name, mutate := range map[string]func(spec map[string]any){
		"host mode": func(spec map[string]any) {
			spec["sandbox"] = map[string]any{"mode": "host"}
		},
		"bad deny cidr": func(spec map[string]any) {
			spec["firewall"].(map[string]any)["deny_cidrs"] = []string{"10.0.0.0/99"}
		},
		"allow everything": func(spec map[string]any) {
			spec["firewall"].(map[string]any)["allow_cidrs"] = []string{"0.0.0.0/0"}
		},
		"forbidden device": func(spec map[string]any) {
			spec["devices"] = []map[string]any{{"name": "mem", "path": "/dev/mem"}}
		},
		"devices under gvisor": func(spec map[string]any) {
			spec["sandbox"].(map[string]any)["runtime"] = "runsc"
		},
		"engine injection": func(spec map[string]any) {
			spec["sandbox"].(map[string]any)["engine"] = "/bin/sh"
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := hsmRequest("x")
			mutate(req["spec"].(map[string]any))
			code, body := virtualDo(t, ts, http.MethodPost, "/api/executors/"+parent+"/virtuals", req)
			if code != http.StatusBadRequest {
				t.Fatalf("POST = %d (%s), want 400", code, body)
			}
		})
	}

	// Not under something that is not an enrolled device.
	if code, _ := virtualDo(t, ts, http.MethodPost, "/api/executors/local/virtuals", hsmRequest("x")); code != http.StatusNotFound {
		t.Errorf("POST under a non-device = %d, want 404", code)
	}
}
