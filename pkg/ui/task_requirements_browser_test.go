package ui

// Browser gate for linking tasks to requirements in the dashboard (Task
// 20460). See testdata/task_requirements_browser.js for what it drives. Skips
// when Chrome or node is missing, like the others; task_requirements_api_test.go
// holds the HTTP checks that run everywhere.

import (
	"context"
	"encoding/json"
	"fmt"
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
)

type offeredRequirement struct {
	ID      int    `json:"id"`
	Checked bool   `json:"checked"`
	Label   string `json:"label"`
}

type taskReqsBrowserResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	Chips *struct {
		Task1 []string `json:"task1"`
		Task2 []string `json:"task2"`
	} `json:"chips"`
	Untouched *struct {
		Offered  []offeredRequirement `json:"offered"`
		SentKeys []string             `json:"sent_keys"`
	} `json:"untouched"`
	Link *struct {
		Offered []offeredRequirement `json:"offered"`
		Sent    []int                `json:"sent"`
		Chips   []string             `json:"chips"`
	} `json:"link"`
	Opened *struct {
		DetailsTasks []string `json:"details_tasks"`
		DetailsText  string   `json:"details_text"`
		TaskDetails  bool     `json:"task_details"`
		Implements   string   `json:"implements"`
	} `json:"opened"`
	Phone *struct {
		OverflowPx float64 `json:"overflow_px"`
		Fits       bool    `json:"fits"`
	} `json:"phone"`
}

func TestTaskRequirements_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot open the dialog a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// A registry of its own: a single-project hub, whose first project is this.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "requirements in the dialog", []*pm.Task{
		{ID: 1, Title: "Ship the parser", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "Keep the old flag", Status: pm.TaskPending, Priority: 2},
	})
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []requirements.Requirement{
		{Title: "Config errors exit non-zero", Tests: []requirements.Test{{Command: "go test ./pkg/config"}}},
		{Title: "A draft", Status: requirements.StatusDraft},
		{Title: "Retired flag", Status: requirements.StatusDeprecated},
		{Title: "Builds on every platform", Priority: requirements.PriorityMust},
	} {
		if _, err := db.AddRequirement(r, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	// Task 2 was linked to R-3 before it was deprecated.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan.TaskByID(2).Requirements = []int{3}
	if err := ps.SaveDirect(); err != nil {
		t.Fatal(err)
	}

	srv := New(dir, 0, "")
	// The driver polls; the per-IP limiter would measure itself instead.
	srv.RPS, srv.Burst = 1000, 1000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/task_requirements_browser.js"), chrome, ts.URL)
	out, err := cmd.Output()
	var got taskReqsBrowserResults
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
	if got.Chips == nil || got.Untouched == nil || got.Link == nil || got.Opened == nil || got.Phone == nil {
		t.Fatalf("a scenario did not run:\n%s", out)
	}

	ids := func(list []offeredRequirement) string {
		var s []string
		for _, r := range list {
			s = append(s, fmt.Sprintf("%d:%v", r.ID, r.Checked))
		}
		return strings.Join(s, ",")
	}
	t.Run("a task card shows a chip per requirement", func(t *testing.T) {
		if len(got.Chips.Task1) != 0 || strings.Join(got.Chips.Task2, ",") != "R-3" {
			t.Errorf("chips: task 1 %v, task 2 %v", got.Chips.Task1, got.Chips.Task2)
		}
	})
	t.Run("the dialog offers the approved requirements and the task's own", func(t *testing.T) {
		if s := ids(got.Untouched.Offered); s != "1:false,3:true,4:false" {
			t.Errorf("task 2's dialog offers %s, want R-1, R-3 ticked, R-4", s)
		}
		for _, r := range got.Untouched.Offered {
			if r.ID == 3 && !strings.Contains(r.Label, "deprecated") {
				t.Errorf("the deprecated requirement is not marked so: %q", r.Label)
			}
		}
		if s := ids(got.Link.Offered); s != "1:false,4:false" {
			t.Errorf("task 1's dialog offers %s, want R-1 and R-4", s)
		}
	})
	t.Run("a dialog saved untouched sends no requirements", func(t *testing.T) {
		for _, k := range got.Untouched.SentKeys {
			if k == "requirements" {
				t.Errorf("the untouched dialog sent requirements: %v", got.Untouched.SentKeys)
			}
		}
	})
	t.Run("ticking one links it", func(t *testing.T) {
		if fmt.Sprint(got.Link.Sent) != "[4]" || strings.Join(got.Link.Chips, ",") != "R-4" {
			t.Errorf("sent %v, chips afterwards %v", got.Link.Sent, got.Link.Chips)
		}
		ps, err := state.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		if l1, l2 := ps.Plan.TaskByID(1).Requirements, ps.Plan.TaskByID(2).Requirements; fmt.Sprint(l1) != "[4]" || fmt.Sprint(l2) != "[3]" {
			t.Errorf("the hub holds task 1 → %v, task 2 → %v; want [4] and [3]", l1, l2)
		}
	})
	t.Run("the chip opens the requirement, whose details open the task", func(t *testing.T) {
		if strings.Join(got.Opened.DetailsTasks, ",") != "#1" || !strings.Contains(got.Opened.DetailsText, "Ship the parser") ||
			!got.Opened.TaskDetails || got.Opened.Implements != "ImplementsR-4" {
			t.Errorf("R-4's details: %+v", got.Opened)
		}
	})
	t.Run("the dialog fits a phone", func(t *testing.T) {
		if got.Phone.OverflowPx > 0 || !got.Phone.Fits {
			t.Errorf("at 360px: %+v", got.Phone)
		}
	})
}
