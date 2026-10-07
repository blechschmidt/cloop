package ui

// Frontend gate for Settings → Single sign-on's RBAC state (Task 20395): the
// panel shows the saved default role as it is, renders the hub's verdict on
// whether RBAC is in force rather than working one out, and turns a save the
// hub refuses as an RBAC switch into a question. Behavioural, because "derives
// the state from default_role" and "renders the verdict" are both a few lines of
// JavaScript that a text search cannot tell apart — see
// testdata/oidc_rbac_scenarios.js.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

type oidcRBACPanelResult struct {
	// unset_role_shows_unset_and_saves_unset
	SelectValue    string `json:"selectValue"`
	Puts           int    `json:"puts"`
	PutDefaultRole string `json:"putDefaultRole"`
	PutConfirm     bool   `json:"putConfirm"`

	// off_warns_and_offers_enforce
	Note         string `json:"note"`
	NoteShown    bool   `json:"noteShown"`
	EnforceShown bool   `json:"enforceShown"`

	// verdict_is_the_hubs
	QuietNote    string `json:"quietNote"`
	QuietEnforce bool   `json:"quietEnforce"`
	LoudNote     string `json:"loudNote"`

	// enforce_asks_then_posts
	Asked             json.RawMessage `json:"asked"`
	PostsWhenDeclined int             `json:"postsWhenDeclined"`
	Posts             int             `json:"posts"`
	URL               string          `json:"url"`
	Body              string          `json:"body"`
	NoteAfter         string          `json:"noteAfter"`
	EnforceShownAfter bool            `json:"enforceShownAfter"`

	// rbac_switch_is_asked_and_resent_on_yes
	FirstConfirm  bool `json:"firstConfirm"`
	SecondConfirm bool `json:"secondConfirm"`

	Error string `json:"error"`
}

func runOIDCRBACPanelScenarios(t *testing.T) map[string]oidcRBACPanelResult {
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
	scenarios, err := filepath.Abs("testdata/oidc_rbac_scenarios.js")
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
	var results map[string]oidcRBACPanelResult
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

func TestDashboard_OIDCPanelShowsTheHubsRBACVerdict(t *testing.T) {
	results := runOIDCRBACPanelScenarios(t)
	off := config.RBACOff("https://idp.example.com/realms/main")

	t.Run("an unset default role shows unset and saves unset", func(t *testing.T) {
		got := results["unset_role_shows_unset_and_saves_unset"]
		if got.SelectValue != "" {
			t.Errorf("the select shows %q for an unset default role — the panel pre-selected "+
				"\"none\", and every save then wrote it and switched RBAC on", got.SelectValue)
		}
		if got.Puts != 1 || got.PutDefaultRole != "" || got.PutConfirm {
			t.Errorf("Save sent %d PUT(s), default_role %q, confirm %v — want one PUT carrying the "+
				"unset role and no confirmation", got.Puts, got.PutDefaultRole, got.PutConfirm)
		}
	})

	t.Run("RBAC off is said and enforcing is offered", func(t *testing.T) {
		got := results["off_warns_and_offers_enforce"]
		if !got.NoteShown || !strings.HasPrefix(got.Note, off) {
			t.Errorf("note (shown %v) = %q, want it to open with %q", got.NoteShown, got.Note, off)
		}
		if !got.EnforceShown {
			t.Error("Enforce deny-by-default is not offered on a hub whose RBAC is off")
		}
	})

	t.Run("the panel renders the hub's verdict, not its own", func(t *testing.T) {
		got := results["verdict_is_the_hubs"]
		if strings.Contains(got.QuietNote, "RBAC is off") || got.QuietEnforce {
			t.Errorf("no default role and no mappings, but the hub says enforced: the panel said %q "+
				"(enforce shown %v) — it worked the state out itself", got.QuietNote, got.QuietEnforce)
		}
		if !strings.Contains(got.QuietNote, "RBAC is in force") {
			t.Errorf("enforced hub: note = %q", got.QuietNote)
		}
		if !strings.HasPrefix(got.LoudNote, off) {
			t.Errorf("a default role and a mapping in the fields, but the hub says off: note = %q", got.LoudNote)
		}
	})

	t.Run("enforce asks, then posts to its own route", func(t *testing.T) {
		got := results["enforce_asks_then_posts"]
		if got.PostsWhenDeclined != 0 {
			t.Errorf("declining the question still posted %d time(s)", got.PostsWhenDeclined)
		}
		if got.Posts != 1 || got.URL != "/api/config/oidc/enforce" || got.Body != "{}" {
			t.Errorf("posts = %d to %q with %q", got.Posts, got.URL, got.Body)
		}
		if !strings.Contains(got.NoteAfter, "restart the hub") || got.EnforceShownAfter {
			t.Errorf("after enforcing: note %q, enforce still shown %v", got.NoteAfter, got.EnforceShownAfter)
		}
	})

	t.Run("an RBAC switch is asked and resent on yes", func(t *testing.T) {
		got := results["rbac_switch_is_asked_and_resent_on_yes"]
		var asked []string
		_ = json.Unmarshal(got.Asked, &asked)
		if len(asked) != 1 || !strings.HasPrefix(asked[0], "This save turns RBAC on") {
			t.Errorf("asked %q", asked)
		}
		if got.Puts != 2 || got.FirstConfirm || !got.SecondConfirm {
			t.Errorf("PUTs = %d, confirm_rbac first %v second %v — want the refusal, then one resend that confirms",
				got.Puts, got.FirstConfirm, got.SecondConfirm)
		}
		if n := results["rbac_switch_declined_sends_nothing_more"].Puts; n != 1 {
			t.Errorf("declined: %d PUTs, want the one the hub refused", n)
		}
	})
}
