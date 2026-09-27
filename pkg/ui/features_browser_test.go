package ui

// Browser gate for parallel features (Task 20341). See
// testdata/features_browser.js for what it drives and why a browser rather
// than the DOM shim. Skips when Chrome or node is missing, like the others.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/feature"
)

type featuresBrowserResult struct {
	Chips                 int    `json:"chips"`
	Cards                 int    `json:"cards"`
	BannerNamesBranch     bool   `json:"banner_names_branch"`
	FeaturesSectionHidden bool   `json:"features_section_hidden"`
	Rows                  int    `json:"rows"`
	BannerHidden          bool   `json:"banner_hidden"`
	Crumb                 string `json:"crumb"`
	Focused               string `json:"focused"`
	SlugHint              string `json:"slug_hint"`
	DialogClosed          bool   `json:"dialog_closed"`
	Banner                bool   `json:"banner"`
	Title                 string `json:"title"`
	Heading               string `json:"heading"`
	FocusInside           bool   `json:"focus_inside"`
	Closed                bool   `json:"closed"`
	Message               string `json:"message"`
}

func TestFeatures_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot drive the panels a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// Unstarted until stubCLI has run: see newUnstartedFeatureFixture.
	f := newUnstartedFeatureFixture(t)
	addFeature(t, f.parent, "login", time.Now().Add(-2*time.Hour), nil)
	addFeature(t, f.parent, "dark-mode", time.Now().Add(-time.Hour), nil)

	// What `cloop feature new` leaves behind, prepared elsewhere and copied into
	// place by the stub: a state database and a record.
	template := addFeature(t, t.TempDir(), "payments", time.Now(), nil)
	dest := feature.Path(f.parent, "payments")
	record, _ := json.Marshal(feature.Meta{Version: 1, Slug: "payments", Title: "Payments",
		Branch: feature.BranchName("payments"), Base: "main", Parent: f.parent, CreatedAt: time.Now()})
	extra := fmt.Sprintf("mkdir -p %q && cp %q/.cloop/state.db* %q/.cloop/ && printf '%%s' %q > %q",
		filepath.Join(dest, ".cloop"), template, dest, string(record), feature.MetaPath(dest))
	stubCLI(t, f.srv, extra, map[string]any{"ok": true, "feature": map[string]any{
		"slug": "payments", "branch": "cloop/feature/payments", "base": "main", "path": dest}}, 0)
	f.start(t)

	// Bounded: a Chrome that stalls must fail this test, not eat the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/features_browser.js"), chrome, f.ts.URL, filepath.Base(f.parent))
	out, err := cmd.Output()
	var got map[string]featuresBrowserResult
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, out, stderr)
	}
	if e, ok := got["error"]; ok {
		t.Fatalf("the driver reported an error: %s\nraw:\n%s", e.Message, out)
	}

	c := got["chip_opens_feature"]
	if c.Cards != 2 || c.Chips != 2 {
		t.Errorf("the grid shows %d cards and %d feature chips, want 2 and 2", c.Cards, c.Chips)
	}
	if !c.BannerNamesBranch || !c.FeaturesSectionHidden {
		t.Errorf("clicking a chip opened the feature without its banner, or with the parent's panel: %+v", c)
	}
	if b := got["banner_returns_to_parent"]; b.Rows != 2 || !b.BannerHidden {
		t.Errorf("back on the project: %+v", b)
	}
	if r := got["row_opens"]; r.Crumb == "" {
		t.Errorf("a row's Open did not navigate: %+v", r)
	}
	n := got["new_feature"]
	if n.Focused != "nfName" || n.SlugHint != "Branch: cloop/feature/payments" || !n.DialogClosed || !n.Banner {
		t.Errorf("new feature dialog: %+v", n)
	}
	p := got["pr_dialog"]
	if p.Title != "Feature login" || p.Heading != "Open pull request" || !p.FocusInside || !p.Closed {
		t.Errorf("pull request dialog: %+v", p)
	}
}
