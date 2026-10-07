package ui

// Browser gate for Settings → Single sign-on's RBAC notice (Task 20395).
//
// The domshim scenarios (oidc_rbac_frontend_test.go) hold the panel's logic;
// they cannot hold its markup, because the shim makes up an element for any id
// asked of it. This drives the assembled page in Chrome: the notice and the
// Enforce button exist and are visible, the select reads "unset", Save with
// nothing changed is not turned into an RBAC switch, and Enforce writes
// deny-by-default. Skips without a browser, like the other browser gates.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/rbactest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

type oidcRBACBrowserView struct {
	PanelVisible   bool   `json:"panel_visible"`
	NoteVisible    bool   `json:"note_visible"`
	Note           string `json:"note"`
	EnforceVisible bool   `json:"enforce_visible"`
	SelectValue    string `json:"select_value"`
	SelectText     string `json:"select_text"`
	RestartNote    string `json:"restart_note"`
}

type oidcRBACBrowserWrite struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	Body   string `json:"body"`
}

type oidcRBACBrowserResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Fresh            oidcRBACBrowserView  `json:"fresh"`
	Save             oidcRBACBrowserWrite `json:"save"`
	DialogsAfterSave []string             `json:"dialogs_after_save"`
	Enforce          oidcRBACBrowserWrite `json:"enforce"`
	AfterEnforce     oidcRBACBrowserView  `json:"after_enforce"`
	Dialogs          []string             `json:"dialogs"`
	ConsoleErrors    []string             `json:"console_errors"`
}

func TestOIDCPanelRBACNoticeInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot drive the panel")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// A hub whose saved ui.oidc turns single sign-on on with admin_emails and
	// no policy, running without it — so the page needs no sign-in, and the
	// panel shows what the next start would do. A registry of its own, so the
	// boot lands on a single-project hub whatever other tests registered.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := t.TempDir()
	cfg := config.Default()
	cfg.UI.OIDC = rbactest.Matrix()[2].OIDC // SSO + admin_emails
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	s := New(dir, 0, "")
	s.RPS, s.Burst = 1e6, 1e6
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/oidc_rbac_browser.js"), chrome, srv.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if os.Getenv("OIDC_RBAC_BROWSER_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}
	var res oidcRBACBrowserResults
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("driver output is not JSON: %v\n%s", err, out)
	}
	if res.Error != nil {
		t.Fatalf("driver failed: %s\n%s", res.Error.Message, out)
	}

	want := "Saved without a role policy — after a restart, " + config.RBACOff(rbactest.Issuer) + "."
	f := res.Fresh
	if !f.PanelVisible || !f.NoteVisible || !strings.HasPrefix(f.Note, want) {
		t.Errorf("notice: panel %v, shown %v, text %q — want it on screen opening with %q",
			f.PanelVisible, f.NoteVisible, f.Note, want)
	}
	if !f.EnforceVisible {
		t.Error("Enforce deny-by-default is not on screen")
	}
	if f.SelectValue != "" || !strings.HasPrefix(f.SelectText, "unset") {
		t.Errorf("default role select reads %q (%q), want the unset option", f.SelectValue, f.SelectText)
	}

	if res.Save.Method != "PUT" || res.Save.Status != 200 || len(res.DialogsAfterSave) != 0 {
		t.Errorf("Save with nothing changed: %+v, dialogs %q — want a plain 200 and no question",
			res.Save, res.DialogsAfterSave)
	}
	if !strings.Contains(res.Save.Body, `"default_role":""`) {
		t.Errorf("Save submitted %s, want the unset default role", res.Save.Body)
	}

	if len(res.Dialogs) != 1 || !strings.HasPrefix(res.Dialogs[0], "Enforce deny-by-default?") {
		t.Errorf("dialogs = %q, want the one Enforce asks", res.Dialogs)
	}
	if res.Enforce.Method != "POST" || res.Enforce.URL != "/api/config/oidc/enforce" || res.Enforce.Status != 200 {
		t.Errorf("enforce = %+v", res.Enforce)
	}
	if a := res.AfterEnforce; a.EnforceVisible || strings.Contains(a.Note, "RBAC is off") {
		t.Errorf("after enforcing: %+v", a)
	}
	if !strings.Contains(res.AfterEnforce.RestartNote, "Restart the hub") {
		t.Errorf("after enforcing, the restart note reads %q", res.AfterEnforce.RestartNote)
	}
	if len(res.ConsoleErrors) != 0 {
		t.Errorf("console errors: %q", res.ConsoleErrors)
	}

	saved, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.UI.OIDC.DefaultRole != "none" {
		t.Errorf("saved default_role = %q after Enforce, want none", saved.UI.OIDC.DefaultRole)
	}
	if rows := oidcAuditRows(t, s, auditaction.ActionOIDCRBACEnforced); len(rows) != 1 {
		t.Errorf("%d %s rows", len(rows), auditaction.ActionOIDCRBACEnforced)
	}
}
