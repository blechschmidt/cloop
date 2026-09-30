package ui

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// reviewGateBrowserResults mirrors what testdata/reviewgate_browser.js prints.
type reviewGateBrowserResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Dialog struct {
		Booted              bool     `json:"booted"`
		CardBefore          string   `json:"card_before"`
		Opened              bool     `json:"opened"`
		EnabledBefore       bool     `json:"enabled_before"`
		Focus               string   `json:"focus"`
		Models              []string `json:"models"`
		RoundsHiddenInBlock bool     `json:"rounds_hidden_in_block"`
		Closed              bool     `json:"closed"`
		CardUpdated         bool     `json:"card_updated"`
		CardAfter           string   `json:"card_after"`
		CardSubAfter        string   `json:"card_sub_after"`
		ErrorShown          bool     `json:"error_shown"`
	} `json:"dialog"`
	Reload struct {
		Booted       bool   `json:"booted"`
		Card         bool   `json:"card"`
		Opened       bool   `json:"opened"`
		Enabled      bool   `json:"enabled"`
		Provider     string `json:"provider"`
		Model        string `json:"model"`
		Mode         string `json:"mode"`
		Instructions string `json:"instructions"`
	} `json:"reload"`
	Task struct {
		Chip        bool   `json:"chip"`
		Details     bool   `json:"details"`
		DetailsText string `json:"details_text"`
	} `json:"task"`
}

// TestReviewGate_DashboardInBrowser drives the review gate's card, dialog and
// task rendering in Chrome (Task 20357): the settings a person picks are the
// settings the hub stores, and a blocked task says why in the places people
// look.
func TestReviewGate_DashboardInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv("HOME", t.TempDir())

	blocked := &pm.TaskReview{
		Verdict: pm.ReviewChangesRequested, Mode: pm.ReviewModeBlock, Blocked: true,
		Provider: "anthropic", Model: "claude-opus-5-5", Rounds: 1, Summary: "The handler divides by zero.",
		Findings:   []pm.ReviewFinding{{Severity: "major", File: "calc.go", Line: 12, Title: "division by zero", Detail: "guard the divisor"}},
		Published:  []pm.ReviewPublish{{Repo: ".", Remote: "origin", Ref: "refs/heads/main", Outcome: pm.PublishWithheld}},
		ReviewedAt: time.Now().UTC(),
	}
	dir := setupProjectDir(t, "review gate in the browser", []*pm.Task{
		{ID: 1, Title: "Add division", Status: pm.TaskFailed, Review: blocked, FailureDiagnosis: blocked.Diagnosis()},
	})
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/reviewgate_browser.js"), chrome, ts.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if os.Getenv("REVIEWGATE_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}
	var got reviewGateBrowserResults
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s", got.Error.Message)
	}

	d := got.Dialog
	if !d.Booted || d.CardBefore != "off" {
		t.Fatalf("before any setting the card reads %q (booted %v), want off", d.CardBefore, d.Booted)
	}
	if !d.Opened || d.EnabledBefore {
		t.Fatalf("clicking the card: opened %v, enabled already %v", d.Opened, d.EnabledBefore)
	}
	if d.Focus != "rgEnabled" {
		t.Errorf("focus went to %q, want the on/off switch", d.Focus)
	}
	if !containsString(d.Models, "claude-opus-5-5") {
		t.Errorf("choosing anthropic did not offer its models: %v", d.Models)
	}
	if !d.RoundsHiddenInBlock {
		t.Error("block mode still shows the fix-rounds field, which it never uses")
	}
	if !d.Closed || !d.CardUpdated || d.ErrorShown {
		t.Fatalf("saving: closed %v, card updated %v (%q), error shown %v", d.Closed, d.CardUpdated, d.CardAfter, d.ErrorShown)
	}
	if d.CardSubAfter != "anthropic · block" {
		t.Errorf("card subline = %q", d.CardSubAfter)
	}

	s, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := s.ReviewGate
	if !g.Active() || g.Provider != "anthropic" || g.Model != "claude-opus-5-5" || g.Mode != pm.ReviewModeBlock ||
		g.Instructions != "Reject changes to migrations." {
		t.Fatalf("the hub stored %+v", g)
	}

	r := got.Reload
	if !r.Booted || !r.Card || !r.Opened || !r.Enabled || r.Provider != "anthropic" || r.Model != "claude-opus-5-5" ||
		r.Mode != "block" || r.Instructions != "Reject changes to migrations." {
		t.Errorf("after a reload the dialog shows %+v", r)
	}

	if !got.Task.Chip {
		t.Error("the task list does not mark the blocked task")
	}
	if !got.Task.Details {
		t.Fatal("the task details do not show the review")
	}
	for _, want := range []string{"claude-opus-5-5", "nothing was pushed or merged", "division by zero", "calc.go:12", "withheld"} {
		if !strings.Contains(got.Task.DetailsText, want) {
			t.Errorf("task details lack %q:\n%s", want, got.Task.DetailsText)
		}
	}
}
