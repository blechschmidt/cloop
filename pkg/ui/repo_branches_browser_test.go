package ui

// Browser gate for restricting a project's pushes to particular branches from
// the Repository Access panel (Task 20340). See testdata/repo_branches_browser.js
// for what it drives and why a browser rather than the DOM shim.
//
// Like the other browser gates it skips when Chrome or node is missing.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

type repoBranchesResult struct {
	// panel_shows_restriction
	PanelVisible    bool `json:"panel_visible"`
	NamesBranch     bool `json:"names_branch"`
	SaysNotEnforced bool `json:"says_not_enforced"`
	EditVisible     bool `json:"edit_visible"`

	// assign_form_follows_access
	HiddenForRead    bool `json:"hidden_for_read"`
	ShownForWrite    bool `json:"shown_for_write"`
	HintWarnsNoProxy bool `json:"hint_warns_no_proxy"`
	HiddenAgain      bool `json:"hidden_again"`

	// edit_replaces_grant
	Prefilled    string   `json:"prefilled"`
	Assignments  int      `json:"assignments"`
	NewGrant     bool     `json:"new_grant"`
	Branches     []string `json:"branches"`
	Access       string   `json:"access"`
	PanelUpdated bool     `json:"panel_updated"`

	Message string `json:"message"`
}

func TestRepositoryBranchRestriction_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot drive the panel a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	withNoGitProxy(t)
	t.Setenv(secretbroker.EnvPassphraseKey, "repo-branches-browser-passphrase")
	// A home of its own, so the project registry holds only this hub's project.
	// The package's shared home accumulates other tests' projects, and a hub
	// that reads as multi-project renders its Overview differently.
	t.Setenv("HOME", t.TempDir())

	dir := setupProjectDir(t, "repository branches", nil)

	// A shared PAT to grant from, and a connected App so the panel renders its
	// assign form. Minted straight into the hub's broker; nothing here talks to
	// GitHub, because nothing in these scenarios needs to.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		_ = db.Close()
		t.Fatalf("secretstore.New: %v", err)
	}
	broker, err := secretbroker.New(store)
	if err != nil {
		_ = db.Close()
		t.Fatalf("secretbroker.New: %v", err)
	}
	for _, m := range []secretbroker.MintRequest{
		{Name: "github-pat", Kind: secretbroker.KindGitHubPAT, Payload: []byte("ghp_browserBranchTestToken000000000")},
		{Name: "github-acme", Kind: secretbroker.KindGitHubApp, Payload: []byte(appPayload(t))},
	} {
		m.Actor = "ops"
		if _, err := broker.Mint(t.Context(), m); err != nil {
			_ = db.Close()
			t.Fatalf("mint %s: %v", m.Name, err)
		}
	}
	_ = db.Close()

	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// The starting state is a write assignment limited to cloop/*, made through
	// the same endpoint the panel uses so its subject is exactly the project.
	resp, err := http.Post(ts.URL+"/api/projects/0/repositories", "application/json", strings.NewReader(
		`{"secret":"github-pat","repos":["acme/api"],"access":"write","branches":["cloop/*"]}`))
	if err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed assignment = %d", resp.StatusCode)
	}

	cmd := exec.Command(node, mustAbs(t, "testdata/repo_branches_browser.js"), chrome, ts.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var got map[string]repoBranchesResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if e, ok := got["error"]; ok {
		t.Fatalf("the driver reported an error: %s\nraw:\n%s", e.Message, out)
	}
	for _, name := range []string{"panel_shows_restriction", "assign_form_follows_access", "edit_replaces_grant"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("scenario %s never ran\nraw:\n%s", name, out)
		}
	}

	t.Run("the panel shows the restriction and what it amounts to here", func(t *testing.T) {
		r := got["panel_shows_restriction"]
		if !r.PanelVisible || !r.NamesBranch || !r.SaysNotEnforced || !r.EditVisible {
			t.Errorf("%+v", r)
		}
	})
	t.Run("the assign form offers branches for write access only", func(t *testing.T) {
		r := got["assign_form_follows_access"]
		if !r.HiddenForRead || !r.ShownForWrite || !r.HiddenAgain {
			t.Errorf("branch field visibility did not follow the access level: %+v", r)
		}
		if !r.HintWarnsNoProxy {
			t.Error("with no git proxy, the form does not warn that a restricted grant is delivered read-only")
		}
	})
	t.Run("editing replaces the grant with the new branches", func(t *testing.T) {
		r := got["edit_replaces_grant"]
		if r.Prefilled != "cloop/*" {
			t.Errorf("the editor opened with %q, want the current list", r.Prefilled)
		}
		if !r.HiddenForRead || !r.ShownForWrite {
			t.Errorf("the editor's branch field did not follow its access level: %+v", r)
		}
		if r.Assignments != 1 || !r.NewGrant {
			t.Fatalf("after saving: %d assignments, replaced=%v; want exactly one new grant", r.Assignments, r.NewGrant)
		}
		if r.Access != "write" || !slices.Equal(r.Branches, []string{"feature/**", "release/*"}) {
			t.Errorf("saved access %q branches %q, want write [feature/** release/*]", r.Access, r.Branches)
		}
		if !r.PanelUpdated {
			t.Error("the panel was not re-rendered with the saved branches")
		}
	})
}
