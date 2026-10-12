package ui

import (
	"strings"
	"testing"
)

// TestDashboard_UnconfinedProjectIsFlagged: a registry row the hub refuses to
// run because of its directory (Task 20418) stays on the Projects tab — the
// list is the index space every project route addresses — and its card says
// why, escaped. Its neighbour carries no flag.
func TestDashboard_UnconfinedProjectIsFlagged(t *testing.T) {
	got := runPauseScenarios(t)["unconfined_card"]
	if !strings.Contains(got.HTML, "The hub will not run this project: its directory is inside the hub&#39;s control plane") {
		t.Fatalf("the card does not say why the hub will not run it:\n%s", got.HTML)
	}
	if !strings.Contains(got.HTML, "/srv/&lt;hub&gt;") || strings.Contains(got.HTML, "/srv/<hub>") {
		t.Fatalf("the server's sentence reached the card unescaped:\n%s", got.HTML)
	}
	if n := strings.Count(got.HTML, "will not run this project"); n != 1 {
		t.Fatalf("%d cards are flagged, want only the one whose directory breaks the rule:\n%s", n, got.HTML)
	}
	if !strings.Contains(got.HTML, `data-arg-name="fine"`) || !strings.Contains(got.HTML, `data-arg-name="nested"`) {
		t.Fatalf("a card is missing; flagged projects are listed, not dropped:\n%s", got.HTML)
	}
}
