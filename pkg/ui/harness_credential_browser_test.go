package ui

// Browser gate for the Claude credential card and dialog (Task 20379). See
// testdata/harness_credential_browser.js for what it drives and why a browser
// rather than the DOM shim. Like the other browser gates it skips when Chrome
// or node is missing.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

type harnessChipResult struct {
	Present bool   `json:"present"`
	Visible bool   `json:"visible"`
	Text    string `json:"text"`
	Sub     string `json:"sub"`
	Tone    string `json:"tone"`

	// run_refusal_opens_dialog
	Open        bool   `json:"open"`
	Refusal     string `json:"refusal"`
	Toast       string `json:"toast"`
	FocusInside bool   `json:"focus_inside"`
	PasteShown  bool   `json:"paste_shown"`
	Started     string `json:"started"`

	// paste_grants_amber
	FieldCleared bool   `json:"field_cleared"`
	State        string `json:"state"`
	Secret       string `json:"secret"`
	TokenOnPage  bool   `json:"token_on_page"`

	// pick_grants_green
	Options []string `json:"options"`

	// escape_closes
	Closed bool `json:"closed"`

	Message string `json:"message"`
}

func TestHarnessCredentialCardAndDialog_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot drive the card a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv(secretbroker.EnvPassphraseKey, "harness-credential-browser-passphrase")
	// A home of its own, so the project registry holds only this hub's project.
	t.Setenv("HOME", t.TempDir())

	dir := setupProjectDir(t, "harness credential", nil)
	// Configured before the server exists: requests from Chrome carry no
	// happens-before edge for the race detector.
	ex := newHarnessExec("harness-browser-device", executor.KindRemoteAgent, executor.IsolationRemote)
	registerStub(t, ex)
	if err := executor.Bind(dir, ex.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 1000, 1000
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token := fakeAnthropicToken("oat01", "browsertoken")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/harness_credential_browser.js"), chrome, ts.URL, token)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var got map[string]harnessChipResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	for _, name := range []string{"red_when_missing", "run_refusal_opens_dialog", "paste_grants_amber", "pick_grants_green", "escape_closes"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("scenario %s never ran\nraw:\n%s", name, out)
		}
	}

	t.Run("a project whose sandbox has no login shows a red chip", func(t *testing.T) {
		r := got["red_when_missing"]
		if !r.Visible || !strings.Contains(r.Text, "missing") || r.Tone != "red" || r.Sub != "none granted" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("the Run button's refusal opens the dialog and starts nothing", func(t *testing.T) {
		r := got["run_refusal_opens_dialog"]
		if !r.Open || !r.FocusInside || !r.PasteShown || r.Started != "missing" ||
			!strings.Contains(r.Refusal, "No active grant") || r.Toast == "" {
			t.Errorf("%+v", r)
		}
		if n := len(ex.started()); n != 0 {
			t.Errorf("the refused click started %d workload(s)", n)
		}
	})
	t.Run("a pasted token becomes a grant, the chip turns amber, and the field is emptied", func(t *testing.T) {
		r := got["paste_grants_amber"]
		if r.State != "ok" || !strings.HasPrefix(r.Secret, "claude-oauth-") || r.Tone != "amber" ||
			!strings.HasSuffix(strings.TrimSpace(r.Text), " h left") {
			t.Errorf("%+v", r)
		}
		if !r.FieldCleared || r.TokenOnPage {
			t.Errorf("the token outlived its request on the page: cleared %v, on page %v", r.FieldCleared, r.TokenOnPage)
		}
	})
	t.Run("granting an existing secret for longer turns the chip green", func(t *testing.T) {
		r := got["pick_grants_green"]
		if r.Tone != "green" || !strings.Contains(r.Text, "30 d left") {
			t.Errorf("%+v", r)
		}
		found := false
		for _, o := range r.Options {
			found = found || strings.Contains(o, "claude-oauth-")
		}
		if !found {
			t.Errorf("the dialog did not offer the stored secret: %v", r.Options)
		}
	})
	t.Run("Escape closes the dialog", func(t *testing.T) {
		if !got["escape_closes"].Closed {
			t.Errorf("%+v", got["escape_closes"])
		}
	})
	if strings.Contains(string(out), token) {
		t.Error("the driver's report carries the token, so the page handed it back somewhere")
	}
}
