package ui

// Browser gate for the Tasks tab's multi-line description box (Task 20343).
// See testdata/add_task_browser.js for what it drives and why a browser rather
// than the DOM shim. Skips when Chrome or node is missing, like the others;
// add_task_form_test.go holds the markup check that runs everywhere.

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
)

type addTaskBox struct {
	Top    float64 `json:"top"`
	Bottom float64 `json:"bottom"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type addTaskLayout struct {
	Tag          string      `json:"tag"`
	BarWidth     float64     `json:"bar_width"`
	Title        *addTaskBox `json:"title"`
	Desc         *addTaskBox `json:"desc"`
	Priority     *addTaskBox `json:"priority"`
	Deps         *addTaskBox `json:"deps"`
	Add          *addTaskBox `json:"add"`
	VisibleLines float64     `json:"visible_lines"`
	OverflowPx   float64     `json:"overflow_px"`
	ViewportW    float64     `json:"viewport_w"`
	ViewportH    float64     `json:"viewport_h"`
}

type addTaskResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	DesktopLayout *addTaskLayout `json:"desktop_layout"`
	PhoneLayout   *addTaskLayout `json:"phone_layout"`

	EnterStartsANewLine *struct {
		Value   string `json:"value"`
		Title   string `json:"title"`
		Focused string `json:"focused"`
		Posts   int    `json:"posts"`
	} `json:"enter_starts_a_new_line"`

	CtrlEnterAdds *struct{} `json:"ctrl_enter_adds"`
	CmdEnterAdds  *struct{} `json:"cmd_enter_adds"`
	ButtonAdds    *struct{} `json:"button_adds"`

	EditShowsTheLines *struct {
		Tag   string `json:"tag"`
		Value string `json:"value"`
	} `json:"edit_shows_the_lines"`
}

func TestAddTaskDescription_MultilineInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot type into the form a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// A registry of its own, so this is a single-project hub: projects other
	// tests registered would make the dashboard multi-project, and the plan
	// read back below might not be the one the form added to.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "multi-line task descriptions", nil)
	ts := newTestServer(t, dir, nil)

	// Bounded: a Chrome that stalls must fail this test, not eat the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/add_task_browser.js"), chrome, ts.URL)
	out, err := cmd.Output()
	var got addTaskResults
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
	if got.DesktopLayout == nil || got.PhoneLayout == nil || got.EnterStartsANewLine == nil ||
		got.CtrlEnterAdds == nil || got.CmdEnterAdds == nil || got.ButtonAdds == nil ||
		got.EditShowsTheLines == nil {
		t.Fatalf("a scenario did not run:\n%s", out)
	}

	// The hub, not the screen, is the witness to what was added.
	stored := map[string][]string{}
	var st struct {
		Plan *struct {
			Tasks []struct {
				Title       string `json:"title"`
				Description string `json:"description"`
			} `json:"tasks"`
		} `json:"plan"`
	}
	resp, err := http.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatalf("GET /api/state: %v", err)
	}
	err = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if err != nil || st.Plan == nil {
		t.Fatalf("decoding /api/state: %v (plan present: %v)", err, st.Plan != nil)
	}
	for _, task := range st.Plan.Tasks {
		stored[task.Title] = append(stored[task.Title], task.Description)
	}

	t.Run("Enter starts a new line instead of adding the task", func(t *testing.T) {
		r := got.EnterStartsANewLine
		const want = "Summarise the changes since v0.0.1.\n\n- link each PR"
		if r.Value != want {
			t.Errorf("after typing three lines the box holds %q, want %q", r.Value, want)
		}
		if r.Posts != 0 || r.Title != "Write the release notes" || r.Focused != "newTaskDesc" {
			t.Errorf("Enter in the description submitted or left the form: %d add request(s), "+
				"title now %q, focus on %q", r.Posts, r.Title, r.Focused)
		}
	})

	t.Run("each way of adding stores the line breaks", func(t *testing.T) {
		for _, c := range []struct{ how, title, want string }{
			{"Ctrl+Enter", "Write the release notes", "Summarise the changes since v0.0.1.\n\n- link each PR"},
			{"Cmd+Enter", "Rotate the signing key", "Generate a new key.\nPublish it."},
			// Trailing blank lines are trimmed like the title; the ones between
			// lines are the point and stay.
			{"the Add Task button", "Tidy the flags", "Drop --legacy.\nKeep --json."},
		} {
			descs := stored[c.title]
			if len(descs) != 1 {
				t.Errorf("%s: the hub holds %d tasks titled %q, want 1", c.how, len(descs), c.title)
				continue
			}
			if descs[0] != c.want {
				t.Errorf("%s: stored description %q, want %q", c.how, descs[0], c.want)
			}
		}
		// A plain Enter that submitted would have added a fourth task, cut off
		// at its first line.
		if n := len(st.Plan.Tasks); n != 3 {
			t.Errorf("the plan holds %d tasks, want the 3 added: %v", n, stored)
		}
	})

	t.Run("the edit modal reopens the task with its lines", func(t *testing.T) {
		r := got.EditShowsTheLines
		if r.Tag != "TEXTAREA" || r.Value != "Summarise the changes since v0.0.1.\n\n- link each PR" {
			t.Errorf("edit modal description: <%s> %q", r.Tag, r.Value)
		}
	})

	checkLayout := func(t *testing.T, l *addTaskLayout) {
		t.Helper()
		if l.Tag != "TEXTAREA" {
			t.Fatalf("the description box is a <%s>, not a <textarea>", l.Tag)
		}
		if l.Title == nil || l.Desc == nil || l.Priority == nil || l.Deps == nil || l.Add == nil {
			t.Fatalf("a field of the form is missing: %+v", l)
		}
		if l.VisibleLines < 2 {
			t.Errorf("the description box shows %.1f lines — it reads as a one-line field", l.VisibleLines)
		}
		// 1px of tolerance for subpixel rounding throughout.
		if math.Abs(l.Desc.Width-l.BarWidth) > 1 {
			t.Errorf("the description box is %.0fpx wide in a %.0fpx form; it should have the line to itself",
				l.Desc.Width, l.BarWidth)
		}
		if l.Desc.Top < l.Title.Bottom-1 || l.Priority.Top < l.Desc.Bottom-1 {
			t.Errorf("the description box is not between the title and the other fields: "+
				"title %+v, description %+v, priority %+v", *l.Title, *l.Desc, *l.Priority)
		}
		// The one-line fields stay one line tall. On a desktop, sharing a line
		// with the box would stretch them to its height; on a phone, where the
		// form is a column, a fixed flex basis becomes a height.
		for _, f := range []struct {
			name string
			box  *addTaskBox
		}{{"priority", l.Priority}, {"dependencies", l.Deps}} {
			if math.Abs(f.box.Height-l.Title.Height) > 1 {
				t.Errorf("the %s field is %.0fpx tall, the title %.0fpx", f.name, f.box.Height, l.Title.Height)
			}
		}
	}

	t.Run("on a desktop the box has a line of its own", func(t *testing.T) {
		l := got.DesktopLayout
		checkLayout(t, l)
		// The remaining fields and the button share the line below it.
		if math.Abs(l.Add.Top-l.Priority.Top) > l.Title.Height {
			t.Errorf("the Add Task button (top %.0f) is not on the priority field's line (top %.0f)",
				l.Add.Top, l.Priority.Top)
		}
	})

	t.Run("on a phone the box stacks at full width", func(t *testing.T) {
		l := got.PhoneLayout
		if l.ViewportW != 390 {
			t.Fatalf("measured at %.0fpx, not the 390px phone the driver asks for", l.ViewportW)
		}
		checkLayout(t, l)
		// In the stacked column a 100% flex basis is a height.
		if l.Desc.Height > l.ViewportH/3 {
			t.Errorf("the description box is %.0fpx tall on an %.0fpx screen", l.Desc.Height, l.ViewportH)
		}
		// Only here: on a desktop the header's tab row is what decides this,
		// and the form's own width is checked above.
		if l.OverflowPx > 1 {
			t.Errorf("the page is %.0fpx wider than the %.0fpx screen, so it scrolls sideways",
				l.OverflowPx, l.ViewportW)
		}
	})
}
