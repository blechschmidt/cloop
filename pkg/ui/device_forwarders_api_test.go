package ui

// Handler tests for the device-forwarder panel API (Task 20429). One test
// function with one server, because the forwarder hub is a process-wide
// singleton (like the executor hub) whose first use binds it to a WorkDir.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func jsonRequest(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestForwarderAPI(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Seed one forwarder row so the list has something real to show.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	dev := deviceforward.ForwardedDevice{
		Kind: deviceforward.KindUSB,
		USB:  &executor.USBMatch{VendorID: "1050", ProductID: "0030"},
	}
	devJSON, _ := json.Marshal(dev)
	if err := db.PutForwarder(statedb.ForwarderRow{
		ForwarderID: "fwd-seed-1",
		Name:        "bench-usb",
		SecretHash:  "deadbeef",
		DeviceJSON:  string(devJSON),
		CreatedAt:   time.Now(),
		Status:      "offline",
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// List shows the seeded forwarder with its device described.
	resp := jsonRequest(t, "GET", ts.URL+"/api/forwarders", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/forwarders = %d", resp.StatusCode)
	}
	var list struct {
		Forwarders []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Kind      string `json:"kind"`
			DeviceStr string `json:"device_str"`
			Connected bool   `json:"connected"`
		} `json:"forwarders"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Forwarders) != 1 || list.Forwarders[0].ID != "fwd-seed-1" {
		t.Fatalf("list = %+v, want one seeded forwarder", list.Forwarders)
	}
	if list.Forwarders[0].Kind != "usb" || list.Forwarders[0].Connected {
		t.Fatalf("seeded forwarder view wrong: %+v", list.Forwarders[0])
	}

	// Enroll mints a token and returns a bundle + a cloop forward command.
	resp = jsonRequest(t, "POST", ts.URL+"/api/forwarders/enroll", map[string]any{
		"name": "bench2", "kind": "usb", "usb": map[string]string{"vendor_id": "0403", "product_id": "6001"},
	})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("POST enroll = %d: %s", resp.StatusCode, b)
	}
	var enroll struct {
		ID      string `json:"id"`
		Bundle  string `json:"bundle"`
		Command string `json:"command"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&enroll)
	resp.Body.Close()
	if enroll.ID == "" || enroll.Bundle == "" {
		t.Fatalf("enroll response missing id/bundle: %+v", enroll)
	}
	if _, err := deviceforward.DecodeBundle(enroll.Bundle); err != nil {
		t.Fatalf("enroll bundle does not decode: %v", err)
	}

	// Enroll rejects a malformed device.
	resp = jsonRequest(t, "POST", ts.URL+"/api/forwarders/enroll", map[string]any{"name": "x", "kind": "usb"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("enroll with no USB identity = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Revoke the seeded forwarder.
	resp = jsonRequest(t, "DELETE", ts.URL+"/api/forwarders/fwd-seed-1", nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("DELETE = %d: %s", resp.StatusCode, b)
	}
	resp.Body.Close()

	// After revocation the row is marked revoked.
	db2, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	row, err := db2.GetForwarder("fwd-seed-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.RevokedAt.IsZero() {
		t.Fatal("forwarder was not marked revoked after DELETE")
	}
}
