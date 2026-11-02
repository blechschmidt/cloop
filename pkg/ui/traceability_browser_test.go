package ui

// Browser gate for the traceability matrix (Task 20465). See
// testdata/traceability_browser.js for what it drives. Skips when Chrome or
// node is missing, like the others; requirements_trace_api_test.go holds the
// HTTP and push checks that run everywhere.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/trace"
)

type traceabilityBrowserResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Card *struct {
		Value string `json:"value"`
		Sub   string `json:"sub"`
	} `json:"card"`
	Opened *struct {
		Rows     []int  `json:"rows"`
		Count    string `json:"count"`
		More     bool   `json:"more"`
		Coverage string `json:"coverage"`
		Pressed  string `json:"pressed"`
	} `json:"opened"`
	Paged *struct {
		First int      `json:"first"`
		All   []int    `json:"all"`
		More  bool     `json:"more"`
		Reads []string `json:"reads"`
	} `json:"paged"`
	Musts *struct {
		Rows []int  `json:"rows"`
		R1   string `json:"r1"`
		R2   string `json:"r2"`
	} `json:"musts"`
	Pushed *struct {
		Rows     []int  `json:"rows"`
		Reads    int    `json:"reads"`
		Coverage string `json:"coverage"`
		Card     string `json:"card"`
	} `json:"pushed"`
}

func TestTraceability_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot open the view a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// A registry of its own: a single-project hub, whose first project is this.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	done := time.Now().Add(-3 * time.Hour)
	dir := setupProjectDir(t, "trace the requirements", []*pm.Task{
		{ID: 1, Title: "Make it hold", Status: pm.TaskDone, CompletedAt: &done, Requirements: []int{1}},
		{ID: 2, Title: "Test the other", Status: pm.TaskPending, Requirements: []int{2}},
	})
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	// R-1 a tested must that holds, R-2 an untested must, and fifty-three
	// coulds nothing implements: more than a page of the unlinked gap.
	r1, err := db.AddRequirement(requirements.Requirement{Title: "Every dispatch is audited", Priority: requirements.PriorityMust,
		Tests: []requirements.Test{{Command: "go test ./audit"}}}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddRequirement(requirements.Requirement{Title: "Untested must", Priority: requirements.PriorityMust}, "alice"); err != nil {
		t.Fatal(err)
	}
	for i := 3; i <= 55; i++ {
		if _, err := db.AddRequirement(requirements.Requirement{Title: fmt.Sprintf("Could %d", i), Priority: requirements.PriorityCould}, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.RecordRequirementChecks(statedb.CheckRecord{RunID: "r1", Commit: "abcdef1234567890"}, []requirements.Result{{
		RequirementID: r1.ID, Fingerprint: r1.Fingerprint(), Method: requirements.MethodTests,
		Verdict: requirements.VerdictFulfilled, StartedAt: time.Now().Add(-time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := trace.WriteTraceJSON(dir, &trace.TraceMap{Entries: []trace.TraceEntry{
		{Hash: "fedcba9876543210", Subject: "feat: audit every dispatch (Task 1)", MatchedTaskID: 1, Confidence: trace.ConfidenceHigh}}}); err != nil {
		t.Fatal(err)
	}

	srv := New(dir, 0, "")
	// The driver waits on the page, and the page on the hub.
	srv.RPS, srv.Burst = 1000, 1000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	// The change the driver asks for: a third must, and the push the hub's
	// watcher would send for it (a server made by Handler runs no watcher).
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/change" {
			http.NotFound(w, r)
			return
		}
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = db.AddRequirement(requirements.Requirement{Title: "One more must", Priority: requirements.PriorityMust}, "bob")
		db.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		srv.pushCoverage(dir, nil)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(control.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/traceability_browser.js"), chrome, ts.URL, control.URL)
	out, err := cmd.Output()
	var got traceabilityBrowserResults
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, out, stderr)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s\nraw:\n%s", got.Error.Message, out)
	}
	if got.Card == nil || got.Opened == nil || got.Paged == nil || got.Musts == nil || got.Pushed == nil {
		t.Fatalf("a scenario did not run:\n%s", out)
	}

	t.Run("the Overview card shows the musts' coverage and opens the matrix", func(t *testing.T) {
		if got.Card.Value != "50% of musts pass" || got.Card.Sub != "tested 50% · proven 0% · linked 100%" {
			t.Errorf("the card reads %q / %q", got.Card.Value, got.Card.Sub)
		}
		if len(got.Opened.Rows) != 50 || got.Opened.Rows[0] != 1 || !got.Opened.More || got.Opened.Count != "50 of 55 shown" ||
			got.Opened.Pressed != "true" || !strings.Contains(got.Opened.Coverage, "Spec coverage of 2 must requirements") {
			t.Errorf("the view opened with %d rows, count %q, more %v, pressed %q, coverage %q",
				len(got.Opened.Rows), got.Opened.Count, got.Opened.More, got.Opened.Pressed, got.Opened.Coverage)
		}
	})
	t.Run("a gap filter narrows it and Load more brings the rest", func(t *testing.T) {
		if got.Paged.First != 50 || len(got.Paged.All) != 53 || got.Paged.All[0] != 3 || got.Paged.All[52] != 55 || got.Paged.More {
			t.Errorf("unlinked: %d, then %v (more %v)", got.Paged.First, got.Paged.All, got.Paged.More)
		}
		if len(got.Paged.Reads) != 2 || !strings.Contains(got.Paged.Reads[1], "after=52") {
			t.Errorf("the unlinked reads: %v", got.Paged.Reads)
		}
	})
	t.Run("a row shows its tasks, their commits and its verdict", func(t *testing.T) {
		for _, want := range []string{"R-1", "Every dispatch is audited", "#1", "done", "fedcba9876", "fulfilled", "tested"} {
			if !strings.Contains(got.Musts.R1, want) {
				t.Errorf("R-1's row lacks %q: %q", want, got.Musts.R1)
			}
		}
		for _, want := range []string{"#2", "pending", "never checked", "unverified", "open: untested, unchecked"} {
			if !strings.Contains(got.Musts.R2, want) {
				t.Errorf("R-2's row lacks %q: %q", want, got.Musts.R2)
			}
		}
	})
	t.Run("a pushed change is read once, with no poll", func(t *testing.T) {
		if fmt.Sprint(got.Pushed.Rows) != "[1 2 56]" || got.Pushed.Reads != 1 || !strings.Contains(got.Pushed.Coverage, "3 must requirements") ||
			got.Pushed.Card != "33% of musts pass" {
			t.Errorf("after the push: rows %v, %d reads, coverage %q, card %q", got.Pushed.Rows, got.Pushed.Reads,
				got.Pushed.Coverage, got.Pushed.Card)
		}
	})
}
