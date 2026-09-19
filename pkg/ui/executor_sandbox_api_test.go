// Handler tests for the per-executor sandbox configuration API (Task 20307).
//
// What is worth pinning here is not the JSON shape but the three properties the
// endpoint exists for:
//
//   - the engine and runtime an admin submits are validated at the boundary,
//     because both end up as part of a command an executor runs;
//   - a write is durable and readable back, because the dispatch path reads the
//     row rather than anything this handler returns; and
//   - the options the form offers are the ones the backend accepts, so a
//     frontend cannot drift into offering a value that 400s.

package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// sandboxGET reads one executor's configuration.
func sandboxGET(t *testing.T, ts *httptest.Server, id string) executorSandboxView {
	t.Helper()
	resp, err := http.Get(ts.URL + "/api/executors/" + id + "/sandbox")
	if err != nil {
		t.Fatalf("GET sandbox: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET sandbox = HTTP %d: %s", resp.StatusCode, body)
	}
	var out executorSandboxView
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode sandbox view: %v", err)
	}
	return out
}

// sandboxPUT writes a configuration and returns the status and decoded body.
func sandboxPUT(t *testing.T, ts *httptest.Server, id string, body map[string]any) (int, map[string]any) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPut,
		ts.URL+"/api/executors/"+id+"/sandbox", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT sandbox: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestExecutorSandbox_GETDefaultsToUnconfigured(t *testing.T) {
	dir := setupProjectDir(t, "sandbox get", nil)
	ts := newTestServer(t, dir, nil)

	got := sandboxGET(t, ts, "edge-1")

	if got.Configured {
		t.Error("an executor nobody has configured must not report as configured — the panel " +
			"renders 'an admin chose this' differently from 'nobody has looked'")
	}
	if !got.Settings.IsZero() {
		t.Errorf("settings = %+v, want the zero value", got.Settings)
	}
	// The form's options come from the backend so the two cannot drift.
	if len(got.Modes) == 0 {
		t.Error("no modes offered; the form would render an empty selector")
	}
	if len(got.Engines) == 0 {
		t.Error("no engines offered; the form would render an empty selector")
	}
	for _, e := range got.Engines {
		if !executor.ValidContainerEngine(e) {
			t.Errorf("the API offers engine %q that its own validator refuses", e)
		}
	}
	for _, m := range got.Modes {
		if !executor.SandboxMode(m).Valid() {
			t.Errorf("the API offers mode %q that its own validator refuses", m)
		}
	}
}

func TestExecutorSandbox_PUTThenGETRoundTrip(t *testing.T) {
	dir := setupProjectDir(t, "sandbox put", nil)
	ts := newTestServer(t, dir, nil)

	code, _ := sandboxPUT(t, ts, "edge-1", map[string]any{
		"mode": "container", "engine": "podman", "runtime": "kata", "image": "ghcr.io/x/y:v1",
	})
	if code != http.StatusOK {
		t.Fatalf("PUT = HTTP %d, want 200", code)
	}

	got := sandboxGET(t, ts, "edge-1")
	if !got.Configured {
		t.Error("a written configuration must read back as configured")
	}
	want := executor.SandboxSettings{
		Mode: executor.SandboxModeContainer, Engine: "podman", Runtime: "kata", Image: "ghcr.io/x/y:v1",
	}
	if got.Settings != want {
		t.Errorf("settings = %+v, want %+v", got.Settings, want)
	}

	// Durable, not just echoed: the dispatch path reads the row, so a handler
	// that returned the right JSON without persisting would pass a weaker test
	// and change nothing about where payloads run.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer db.Close()
	stored, ok, err := db.ExecutorSandboxSettings("edge-1")
	if err != nil || !ok {
		t.Fatalf("read the stored row: ok=%v err=%v", ok, err)
	}
	if stored != want {
		t.Errorf("stored = %+v, want %+v", stored, want)
	}
}

// TestExecutorSandbox_PUTValidatesAtTheBoundary is the reason the endpoint does
// its own checking rather than trusting the form. Both the engine and the runtime
// become part of a command an executor runs.
func TestExecutorSandbox_PUTValidatesAtTheBoundary(t *testing.T) {
	dir := setupProjectDir(t, "sandbox validate", nil)
	ts := newTestServer(t, dir, nil)

	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"unknown mode", map[string]any{"mode": "hypervisor"}},
		{"engine as a path", map[string]any{"mode": "container", "engine": "/usr/bin/evil"}},
		{"engine off the allowlist", map[string]any{"mode": "container", "engine": "kubectl"}},
		{"runtime as a path", map[string]any{"mode": "container", "runtime": "../../bin/sh"}},
		{"runtime as a flag", map[string]any{"mode": "container", "runtime": "--privileged"}},
		{"image as a flag", map[string]any{"mode": "container", "image": "-v/:/host"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := sandboxPUT(t, ts, "edge-bad", tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("PUT %v = HTTP %d, want 400", tc.body, code)
			}
			if msg, _ := body["error"].(string); msg == "" {
				t.Error("a 400 must carry an error an admin can act on")
			}
		})
	}

	// And nothing was written on the way past.
	if got := sandboxGET(t, ts, "edge-bad"); got.Configured {
		t.Error("a refused write left a configuration behind")
	}
}

// TestExecutorSandbox_HostModeDropsContainerFields pins the normalization at the
// boundary. A runtime retained under host mode would be resurrected the moment
// someone switched the mode back, without anyone re-confirming it.
func TestExecutorSandbox_HostModeDropsContainerFields(t *testing.T) {
	dir := setupProjectDir(t, "sandbox normalize", nil)
	ts := newTestServer(t, dir, nil)

	code, _ := sandboxPUT(t, ts, "edge-1", map[string]any{
		"mode": "host", "engine": "podman", "runtime": "kata", "image": "img",
	})
	if code != http.StatusOK {
		t.Fatalf("PUT = HTTP %d, want 200", code)
	}
	got := sandboxGET(t, ts, "edge-1")
	if got.Settings.Mode != executor.SandboxModeHost {
		t.Errorf("mode = %q, want host", got.Settings.Mode)
	}
	if got.Settings.Engine != "" || got.Settings.Runtime != "" || got.Settings.Image != "" {
		t.Errorf("host mode kept container fields: %+v", got.Settings)
	}
}

func TestExecutorSandbox_Clear(t *testing.T) {
	dir := setupProjectDir(t, "sandbox clear", nil)
	ts := newTestServer(t, dir, nil)

	if code, _ := sandboxPUT(t, ts, "edge-1", map[string]any{
		"mode": "container", "engine": "docker",
	}); code != http.StatusOK {
		t.Fatalf("PUT = HTTP %d", code)
	}
	if code, _ := sandboxPUT(t, ts, "edge-1", map[string]any{"clear": true}); code != http.StatusOK {
		t.Fatalf("clear = HTTP %d, want 200", code)
	}
	got := sandboxGET(t, ts, "edge-1")
	if got.Configured {
		t.Error("after a clear the executor must read back as unconfigured")
	}
	if !got.Settings.IsZero() {
		t.Errorf("settings after clear = %+v, want the zero value", got.Settings)
	}
}

// TestExecutorSandbox_ExplicitDefaultIsConfigured keeps the two states the panel
// distinguishes distinguishable through the API as well as through the store.
func TestExecutorSandbox_ExplicitDefaultIsConfigured(t *testing.T) {
	dir := setupProjectDir(t, "sandbox explicit default", nil)
	ts := newTestServer(t, dir, nil)

	if code, _ := sandboxPUT(t, ts, "edge-1", map[string]any{"mode": ""}); code != http.StatusOK {
		t.Fatalf("PUT = HTTP %d", code)
	}
	got := sandboxGET(t, ts, "edge-1")
	if !got.Configured {
		t.Error("an admin who saved the default has made a decision; the panel needs to see it")
	}
	if got.SetBy == "" && got.SetAt == "" {
		t.Error("a configured record carries no provenance at all; the panel cannot say who " +
			"chose this executor's containment")
	}
}

// TestExecutorsList_CarriesTheSandboxMode is what makes the fleet view honest.
//
// The capability chips render `isolation: remote` for every enrolled device and
// render it identically whether that device contains its workloads or runs them
// as bare host processes. Without this field an admin scanning for the
// uncontained machines has nothing to scan.
func TestExecutorsList_CarriesTheSandboxMode(t *testing.T) {
	dir := setupProjectDir(t, "sandbox in list", nil)
	ts := newTestServer(t, dir, nil)

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	const agentID = "edge-list-1"
	if err := db.UpsertExecutor(statedb.ExecutorRow{
		ID: agentID, Name: agentID, Kind: executor.KindRemoteAgent,
		Status: statedb.ExecutorStatusOffline, CreatedAt: time.Now(),
	}); err != nil {
		_ = db.Close()
		t.Fatalf("seed executor: %v", err)
	}
	_ = db.Close()

	// Unconfigured first: nil, not a host-mode summary. "Nobody has decided" and
	// "an admin chose the host" are different facts and the card shows them
	// differently.
	before := executorsGET(t, ts, "")
	for _, v := range before.Executors {
		if v.ID == agentID && v.Sandbox != nil {
			t.Errorf("an unconfigured executor reports sandbox %+v, want nil", v.Sandbox)
		}
	}

	if code, _ := sandboxPUT(t, ts, agentID, map[string]any{
		"mode": "container", "engine": "podman", "runtime": "kata",
	}); code != http.StatusOK {
		t.Fatalf("PUT = HTTP %d", code)
	}

	after := executorsGET(t, ts, "")
	var found *executorSandboxSummary
	for i := range after.Executors {
		if after.Executors[i].ID == agentID {
			found = after.Executors[i].Sandbox
		}
	}
	if found == nil {
		t.Fatal("the configured executor's card carries no sandbox summary, so the fleet view " +
			"still cannot distinguish a contained device from an uncontained one")
	}
	if found.Mode != string(executor.SandboxModeContainer) {
		t.Errorf("card mode = %q, want container", found.Mode)
	}
	if found.Runtime != "kata" {
		t.Errorf("card runtime = %q, want kata — a container on runc and a container on kata "+
			"are different boundaries and the chip must not flatten them", found.Runtime)
	}
	if !found.Configured {
		t.Error("the summary does not report as configured")
	}
}

// TestExecutorSandbox_RejectsOtherMethods covers the prefix-less registration: the
// route accepts an unusual verb pair, so anything else has to be named rather
// than answered with a generic failure — or worse, answered successfully by a
// handler that ignored the method.
func TestExecutorSandbox_RejectsOtherMethods(t *testing.T) {
	dir := setupProjectDir(t, "sandbox methods", nil)
	ts := newTestServer(t, dir, nil)

	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/executors/edge-1/sandbox", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("DELETE = HTTP %d, want 405: %s", resp.StatusCode, body)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, "GET") {
		t.Errorf("Allow header = %q, want it to name the accepted verbs", allow)
	}
}

// TestExecutorSandbox_RequiresAnID stops a missing path segment being read as a
// configuration for the empty executor.
func TestExecutorSandbox_RequiresAnID(t *testing.T) {
	dir := setupProjectDir(t, "sandbox no id", nil)
	ts := newTestServer(t, dir, nil)

	code, _ := sandboxPUT(t, ts, "", map[string]any{"mode": "host"})
	// An empty segment does not match the pattern at all, so 404 is the honest
	// answer; what must not happen is a 200 that wrote a row keyed by "".
	if code == http.StatusOK {
		t.Error("a request with no executor id was accepted")
	}
}
