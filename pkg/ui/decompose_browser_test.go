package ui

// Browser gate for Decompose (Task 20441), and for the Split dialog it moved
// off first paint. See testdata/decompose_browser.js for what it drives and
// why a browser. Skips when Chrome or node is missing, like the others;
// suggest_frontend_test.go holds the bundle-level scenarios that run wherever
// node does, and suggest_plan_test.go the hub's side.

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// splitFakeProviderName is the provider a Split proposal comes from here: the
// dialog asks the project's own provider.
const splitFakeProviderName = "split-fake"

type splitStubProvider struct{}

func (splitStubProvider) Name() string         { return splitFakeProviderName }
func (splitStubProvider) DefaultModel() string { return "fake-1" }
func (splitStubProvider) Complete(context.Context, string, provider.Options) (*provider.Result, error) {
	return &provider.Result{Provider: splitFakeProviderName, Output: `[` +
		`{"title":"Write the migration","description":"One file per table.","role":"backend","estimated_minutes":40},` +
		`{"title":"Backfill the old rows","description":"In batches."},` +
		`{"title":"Verify the row counts","description":"Before and after."}]`}, nil
}

type decomposeBox struct {
	Top    float64 `json:"top"`
	Left   float64 `json:"left"`
	Right  float64 `json:"right"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
	OnTop  bool    `json:"on_top"`
}

type decomposeLayout struct {
	BarWidth   float64       `json:"bar_width"`
	Decompose  *decomposeBox `json:"decompose"`
	Add        *decomposeBox `json:"add"`
	Title      *decomposeBox `json:"title"`
	Label      string        `json:"label"`
	Disabled   bool          `json:"disabled"`
	OverflowPx float64       `json:"overflow_px"`
	ViewportW  float64       `json:"viewport_w"`
}

type decomposeResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	DesktopLayout *decomposeLayout `json:"desktop_layout"`
	PhoneLayout   *decomposeLayout `json:"phone_layout"`

	Decompose *struct {
		PanelBefore   bool     `json:"panel_before"`
		PanelAfter    bool     `json:"panel_after"`
		Input         string   `json:"input"`
		Cards         []string `json:"cards"`
		Summary       string   `json:"summary"`
		Toast         string   `json:"toast"`
		CardsOnScreen bool     `json:"cards_on_screen"`
		AddToast      string   `json:"add_toast"`
	} `json:"decompose"`

	Split *struct {
		FetchedBeforeClick int    `json:"fetched_before_click"`
		FetchedAfter       int    `json:"fetched_after"`
		Title              string `json:"title"`
		FocusInside        bool   `json:"focus_inside"`
		Toast              string `json:"toast"`
		DroppedListed      bool   `json:"dropped_listed"`
	} `json:"split"`
}

func TestDecompose_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot press the buttons a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// A registry of its own, so this is a single-project hub whose plan is the
	// one read back below.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "decompose in a browser", []*pm.Task{
		{ID: 1, Title: "Write the design doc", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "Migrate the database", Description: "Move every table to the new schema.",
			Status: pm.TaskPending, Priority: 3},
	})
	provider.Register(splitFakeProviderName, func(provider.ProviderConfig) (provider.Provider, error) {
		return splitStubProvider{}, nil
	})
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"),
		[]byte("provider: "+splitFakeProviderName+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// Decompose's plan comes from the stand-in for `cloop suggest`.
	ts := newPlanServer(t, writePlanStub(t, loginPlan), dir)

	// Bounded: a Chrome that stalls must fail this test, not eat the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	args := []string{mustAbs(t, "testdata/decompose_browser.js"), chrome, ts.URL}
	if shots := os.Getenv("CLOOP_DECOMPOSE_SHOTS"); shots != "" {
		args = append(args, shots)
	}
	out, err := exec.CommandContext(ctx, node, args...).Output()
	var got decomposeResults
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
	// A scenario the driver never reached leaves a nil that would otherwise
	// read as a pass below.
	if got.DesktopLayout == nil || got.PhoneLayout == nil || got.Decompose == nil || got.Split == nil {
		t.Fatalf("a scenario did not run:\n%s", out)
	}

	t.Run("the button is beside Add Task and pressable", func(t *testing.T) {
		for name, l := range map[string]*decomposeLayout{"desktop": got.DesktopLayout, "phone": got.PhoneLayout} {
			if l.Label != "Decompose" || l.Disabled || l.Decompose == nil || l.Add == nil {
				t.Errorf("%s: the button reads %q, disabled %v (%+v)", name, l.Label, l.Disabled, l)
				continue
			}
			if !l.Decompose.OnTop || !l.Add.OnTop {
				t.Errorf("%s: a press on Decompose (%v) or Add Task (%v) lands on something else", name,
					l.Decompose.OnTop, l.Add.OnTop)
			}
			if l.OverflowPx > 1 {
				t.Errorf("%s: the page is %.0fpx wider than the %.0fpx screen", name, l.OverflowPx, l.ViewportW)
			}
		}
		d := got.DesktopLayout
		// On a desktop the two share a line, Decompose first.
		if math.Abs(d.Decompose.Top-d.Add.Top) > 1 || d.Decompose.Right > d.Add.Left {
			t.Errorf("desktop: Decompose %+v is not just before Add Task %+v on its line", *d.Decompose, *d.Add)
		}
		p := got.PhoneLayout
		if p.ViewportW != 360 {
			t.Fatalf("measured at %.0fpx, not the 360px phone the driver asks for", p.ViewportW)
		}
		// On a phone the form is a column of full-width controls.
		if math.Abs(p.Decompose.Width-p.BarWidth) > 1 || p.Add.Top <= p.Decompose.Top {
			t.Errorf("phone: Decompose %+v is not a full-width row above Add Task %+v in a %.0fpx form",
				*p.Decompose, *p.Add, p.BarWidth)
		}
	})

	t.Run("one click plans the typed task and Add all queues it", func(t *testing.T) {
		d := got.Decompose
		if d.PanelBefore || !d.PanelAfter {
			t.Errorf("the suggestions panel was open before %v, after %v: Decompose has to open it", d.PanelBefore, d.PanelAfter)
		}
		if d.Input != "Add OAuth login\n\nSign in with GitHub, and keep the session." {
			t.Errorf("the panel's request is %q", d.Input)
		}
		wantCards := []string{"Step 1 · Add provider config", "Step 2 · Callback handler",
			"Step 3 · Login button", "Step 4 · Document login"}
		if !reflect.DeepEqual(d.Cards, wantCards) {
			t.Errorf("cards = %q, want %q", d.Cards, wantCards)
		}
		if !strings.HasSuffix(d.Summary, "OAuth login in four steps\nEach task runs at priority 2 and waits for #1.") {
			t.Errorf("summary %q does not say where the tasks will go", d.Summary)
		}
		if d.Toast != "Planned 4 tasks — review below" || !d.CardsOnScreen {
			t.Errorf("toast %q, cards on screen %v", d.Toast, d.CardsOnScreen)
		}
		if d.AddToast != "Added 4 tasks" {
			t.Errorf("Add all toasted %q", d.AddToast)
		}

		// The hub, not the screen, is the witness to what was added.
		tasks := loadTasks(t, dir)
		for title, deps := range map[string][]int{
			"Add provider config": {1},
			"Callback handler":    {1, 3},
			"Login button":        {1, 3},
			"Document login":      {1, 4, 5},
		} {
			tk := tasks[title]
			if tk == nil {
				t.Errorf("the hub has no task %q", title)
				continue
			}
			if !reflect.DeepEqual(append([]int(nil), tk.DependsOn...), deps) || tk.Priority != 2 || tk.Status != pm.TaskPending {
				t.Errorf("%q: depends on %v, priority %d, %s; want %v, the typed 2, pending", title,
					tk.DependsOn, tk.Priority, tk.Status, deps)
			}
		}
		if tasks["Add OAuth login"] != nil {
			t.Error("the decomposed task was added as well as its plan")
		}
	})

	t.Run("the deferred Split dialog is fetched on use and applies", func(t *testing.T) {
		s := got.Split
		if s.FetchedBeforeClick != 0 || s.FetchedAfter != 1 {
			t.Errorf("the Split script was fetched %d times before the first Split and %d after; want 0 and 1",
				s.FetchedBeforeClick, s.FetchedAfter)
		}
		if s.Title != "Split Task #2 — Migrate the database" || !s.FocusInside {
			t.Errorf("dialog %q, focus inside %v", s.Title, s.FocusInside)
		}
		if s.Toast != "Task #2 split into 2 sub-tasks" {
			t.Errorf("toast %q", s.Toast)
		}
		if s.DroppedListed {
			t.Error("the sub-task the user dropped is in the list")
		}
		tasks := loadTasks(t, dir)
		if tk := tasks["Migrate the database"]; tk == nil || tk.Status != pm.TaskSkipped {
			t.Errorf("the split task is %+v, want skipped", tk)
		}
		first, second := tasks["Write the migration"], tasks["Verify the row counts"]
		if first == nil || second == nil || tasks["Backfill the old rows"] != nil {
			t.Fatalf("the hub holds the sub-tasks %v / %v, and the dropped one: %v", first, second, tasks["Backfill the old rows"] != nil)
		}
		if !reflect.DeepEqual(first.DependsOn, []int{2}) || !reflect.DeepEqual(second.DependsOn, []int{first.ID}) {
			t.Errorf("sub-tasks depend on %v and %v, want [2] and [%d]", first.DependsOn, second.DependsOn, first.ID)
		}
	})
}
