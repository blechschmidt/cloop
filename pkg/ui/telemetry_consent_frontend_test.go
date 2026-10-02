package ui

// Does the dashboard reporter ask before it sends? (Task 20311)
//
// Every other gate on the error boundary greps it as text. Text cannot answer
// this one: the claim is that on a hub which collects nothing, nothing is
// transmitted — which is a statement about which requests are issued and in
// what order. So this runs the real errboundary.js under testdata/domshim.js
// and reads the request log back.
//
// The failure this guards against is silent in the worst way. A reporter that
// posted first and let the hub answer 404 would look correct from the server
// side — no rows stored, the switch verifiably off — while every page load
// still shipped the user's URLs and view names across the network.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type consentRequest struct {
	URL          string `json:"url"`
	Method       string `json:"method"`
	CarriesEvent bool   `json:"carriesEvent"`
}

func TestErrorBoundary_AsksBeforeItSends(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the reporter")
	}

	dir := t.TempDir()
	boundary := filepath.Join(dir, "errboundary.js")
	if err := os.WriteFile(boundary, []byte(loadAssets().boundary), 0o644); err != nil {
		t.Fatalf("write boundary: %v", err)
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/telemetry_consent_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, boundary)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string][]consentRequest
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	if _, bad := results["error"]; bad {
		t.Fatalf("scenario threw in the browser shim:\n%s", out)
	}

	posts := func(reqs []consentRequest) []consentRequest {
		var got []consentRequest
		for _, r := range reqs {
			if r.Method == "POST" {
				got = append(got, r)
			}
		}
		return got
	}
	probes := func(reqs []consentRequest) int {
		n := 0
		for _, r := range reqs {
			if strings.HasPrefix(r.URL, "/api/telemetry/config") {
				n++
			}
		}
		return n
	}

	// The hub says yes: the trail arrives, and the probe came first.
	on, ok := results["collecting"]
	if !ok {
		t.Fatal("scenario `collecting` produced no result")
	}
	if len(on) == 0 || !strings.HasPrefix(on[0].URL, "/api/telemetry/config") {
		t.Fatalf("the first request was not the consent probe: %+v", on)
	}
	sent := posts(on)
	if len(sent) == 0 {
		t.Fatal("collection is on and the reporter never posted the trail")
	}
	if !sent[0].CarriesEvent {
		t.Errorf("the first POST does not carry the recorded event: %+v", sent[0])
	}
	if got := probes(on); got != 1 {
		t.Errorf("the reporter asked %d times; the answer is per page load, not per flush", got)
	}

	// The three ways the answer can be "no". Each must transmit nothing beyond
	// the probe itself — including the second event, which is what catches a
	// reporter that asks once and then ignores the answer.
	for _, name := range []string{"refused", "probe_failed", "no_policy_route"} {
		reqs, ok := results[name]
		if !ok {
			t.Errorf("scenario %q produced no result", name)
			continue
		}
		if sent := posts(reqs); len(sent) > 0 {
			t.Errorf("scenario %q: the reporter sent %d POST(s) on a hub that did not consent — "+
				"first was %s (carries the event: %v)",
				name, len(sent), sent[0].URL, sent[0].CarriesEvent)
		}
		for _, r := range reqs {
			if !strings.HasPrefix(r.URL, "/api/telemetry/config") {
				t.Errorf("scenario %q: unexpected request %s %s; only the probe should be issued",
					name, r.Method, r.URL)
			}
		}
	}
}
