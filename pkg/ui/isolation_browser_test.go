package ui

// Browser gate for the isolation evidence on executor cards (Task 20439). The
// chip is drawn by the deferred execadmin script onto cards the bundle
// rendered, and redrawn after each refresh; testdata/domshim.js builds no DOM
// from markup, so only a browser can say whether a user sees it. Skips without
// Chrome or node, like the other browser gates.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

type isolationCardResult struct {
	Error            string `json:"error"`
	ChipDrawn        bool   `json:"chip_drawn"`
	Card             bool   `json:"card"`
	ChipText         string `json:"chip_text"`
	ChipNegative     bool   `json:"chip_negative"`
	ChipTitle        string `json:"chip_title"`
	ChipVisible      bool   `json:"chip_visible"`
	KataChipNegative bool   `json:"kata_chip_negative"`
	ReprobeButton    bool   `json:"reprobe_button"`
	ChipsAfterRedraw int    `json:"chips_after_redraw"`
	Clicked          bool   `json:"clicked"`
	ToastOK          bool   `json:"toast_ok"`
	DetailOpened     bool   `json:"detail_opened"`
}

// TestIsolationEvidence_OnTheCardInBrowser: a container executor whose runtime
// is named kata and whose probe found the host kernel. Its card must say so in
// words, turn its own "kata / VM" chip negative, keep exactly one verdict chip
// across a redraw, and offer Re-probe — which must start a probe and not open
// the card's drill-in.
func TestIsolationEvidence_OnTheCardInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot measure a card a user can actually see")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	dir := setupProjectDir(t, "isolation card", nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ex := &isoExec{id: "kata-alias", runtime: "kata", answer: runcNamedKata}
	registerIsoExec(t, ex)
	if _, err := activeIsolationVerifier().Probe(context.Background(), ex, executor.ProbePointReconcile); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/isolation_browser.js"), chrome, ts.URL, ex.id)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var got isolationCardResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("driver output is not JSON: %v\n%s", err, out)
	}
	if got.Error != "" {
		t.Fatalf("driver: %s", got.Error)
	}
	if !got.ChipDrawn || !got.ChipVisible {
		t.Fatalf("the verdict never appeared on the card: %+v", got)
	}
	if got.ChipText != "claims kata, runs on the host kernel" || !got.ChipNegative {
		t.Errorf("chip = %q (negative %v)", got.ChipText, got.ChipNegative)
	}
	if !strings.Contains(got.ChipTitle, "2d725fb0") || !strings.Contains(got.ChipTitle, "refused") {
		t.Errorf("the chip's tooltip does not carry the evidence and its consequence: %q", got.ChipTitle)
	}
	if !got.KataChipNegative {
		t.Error("the card's own \"kata / VM\" chip still reads as a positive claim")
	}
	if got.ChipsAfterRedraw != 1 {
		t.Errorf("after a redraw the card has %d verdict chips, want 1", got.ChipsAfterRedraw)
	}
	if !got.ReprobeButton || !got.Clicked || !got.ToastOK {
		t.Errorf("Re-probe: button %v, clicked %v, toast %v", got.ReprobeButton, got.Clicked, got.ToastOK)
	}
	if got.DetailOpened {
		t.Error("pressing Re-probe opened the card's drill-in")
	}
	activeIsolationVerifier().Wait()
	if n := ex.probes.Load(); n != 2 {
		t.Errorf("%d probes ran, want the first and the one Re-probe started", n)
	}
}
