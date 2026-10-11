package ui

// Frontend gate for Settings → Static admin token (Task 20406): the card draws
// the hub's verdicts and drives the Retire route — no request without a
// reason, a question first, and a forced retry only when the hub refuses to
// strand a token-only hub and the operator says yes. Behavioural, through the
// real bundle and testdata/static_token_scenarios.js.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type staticTokenCardResult struct {
	Badge              string           `json:"badge"`
	Body               string           `json:"body"`
	Actions            bool             `json:"actions"`
	PostsWithoutReason int              `json:"postsWithoutReason"`
	Posts              []map[string]any `json:"posts"`
	Asked              int              `json:"asked"`
	ReasonAfter        string           `json:"reasonAfter"`
	StrandsNote        string           `json:"strandsNote"`
	Error              string           `json:"error"`
}

func runStaticTokenCardScenarios(t *testing.T) map[string]staticTokenCardResult {
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
		t.Fatal(err)
	}
	scenarios, err := filepath.Abs("testdata/static_token_scenarios.js")
	if err != nil {
		t.Fatal(err)
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
	var results map[string]staticTokenCardResult
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

func TestDashboard_StaticTokenCard(t *testing.T) {
	results := runStaticTokenCardScenarios(t)

	t.Run("an accepted token shows its fingerprint and last use, and Retire", func(t *testing.T) {
		got := results["accepted_shows_fingerprint_use_and_retire"]
		if !strings.Contains(got.Badge, "accepted") || !got.Actions {
			t.Errorf("badge %q, actions shown %v", got.Badge, got.Actions)
		}
		for _, want := range []string{"3f9c1e7a2b5d", "203.0.113.7", "outside RBAC", "single sign-on works"} {
			if !strings.Contains(got.Body, want) {
				t.Errorf("the card does not say %q: %q", want, got.Body)
			}
		}
	})

	t.Run("Retire needs a reason, asks, then posts once", func(t *testing.T) {
		got := results["retire_needs_a_reason_then_asks_then_posts"]
		if got.PostsWithoutReason != 0 {
			t.Errorf("Retire without a reason posted %d time(s)", got.PostsWithoutReason)
		}
		if got.Asked != 1 || len(got.Posts) != 1 {
			t.Fatalf("asked %d, posted %v — want one question and one POST", got.Asked, got.Posts)
		}
		if got.Posts[0]["reason"] != "SSO is live, INC-4471" || got.Posts[0]["force"] != false {
			t.Errorf("POST body %v", got.Posts[0])
		}
		if !strings.Contains(got.Badge, "retired") || got.Actions ||
			!strings.Contains(got.Body, "ops@example.com") || !strings.Contains(got.Body, "Refused 3") {
			t.Errorf("after retiring: badge %q, actions %v, body %q", got.Badge, got.Actions, got.Body)
		}
		if got.ReasonAfter != "" {
			t.Errorf("the reason field kept %q", got.ReasonAfter)
		}
	})

	t.Run("a refusal to strand the hub is asked, and forced only on yes", func(t *testing.T) {
		got := results["a_refused_strand_is_asked_and_forced_on_yes"]
		if !strings.Contains(got.StrandsNote, "Nothing else can administer this hub") ||
			!strings.Contains(got.StrandsNote, "signed in with it") {
			t.Errorf("the stranding hub's card says %q", got.StrandsNote)
		}
		if len(got.Posts) != 2 || got.Posts[0]["force"] != false || got.Posts[1]["force"] != true {
			t.Fatalf("posts %v, want an unforced one refused, then a forced one", got.Posts)
		}
		if got.Asked != 2 || !strings.Contains(got.Badge, "retired") {
			t.Errorf("asked %d, badge %q", got.Asked, got.Badge)
		}
	})

	t.Run("a hub with no static token offers nothing to retire", func(t *testing.T) {
		got := results["none_configured_offers_nothing"]
		if got.Actions || !strings.Contains(got.Body, "no static token") {
			t.Errorf("actions %v, body %q", got.Actions, got.Body)
		}
	})
}
