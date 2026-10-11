package ui

// The five sites of Task 20408, held against the names that broke them.
//
// A project's name is the base name of a directory anybody with project.write
// may create, and five places put it into JavaScript inside an HTML attribute:
// onclick="openProject(3, "…")" with the name JSON-encoded and its quotes
// turned into &quot;. JSON does not escape '&', and the HTML parser decodes an
// attribute's character references before the handler is compiled — so a
// name holding the literal text &quot; closed the string, and the rest ran as
// code with the session of whoever clicked the card. A hub admin sees every
// project. The fix carries the name in a data attribute the action reads as
// data (testdata/xss_scenarios.js says how this test reads the markup).
//
// What it asserts, per site and per hostile name:
//   - the markup has no event-handler attribute and no element a name smuggled
//     in (an <img>, an <svg>, a <script>);
//   - each control's data-arg is the project's index and data-arg-name (and
//     data-arg-path) decode to exactly the project's name (and path);
//   - clicking it through the dispatcher acts on that project, with that name.
// Before the fix it failed on the first: every control carried an onclick.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type xssTag struct {
	Tag   string            `json:"tag"`
	Attrs map[string]string `json:"attrs"`
}

type xssEffect struct {
	Where      string `json:"where"`
	Action     string `json:"action"`
	Idx        int    `json:"idx"`
	Label      string `json:"label"`
	Breadcrumb string `json:"breadcrumb"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	DeleteIdx  string `json:"deleteIdx"`
	Post       string `json:"post"`
	Body       string `json:"body"`
}

type xssResult struct {
	Names      []string            `json:"names"`
	Containers map[string][]xssTag `json:"containers"`
	Effects    []xssEffect         `json:"effects"`
	Title      string              `json:"title"`
	XSS        *string             `json:"xss"`
}

// runXSSScenario runs one scenario of testdata/xss_scenarios.js against the
// real bundle and decodes what it returned into into.
func runXSSScenario(t *testing.T, name string, into any) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatal(err)
	}
	shim, _ := filepath.Abs("testdata/domshim.js")
	scenarios, _ := filepath.Abs("testdata/xss_scenarios.js")
	cmd := exec.Command(node, scenarios, shim, bundle, name)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\n%s\n%s", err, out, stderr)
	}
	var results map[string]json.RawMessage
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	raw, ok := results[name]
	if !ok {
		t.Fatalf("the scenario %s did not run", name)
	}
	var threw struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &threw); err == nil && threw.Error != "" {
		t.Fatalf("the scenario threw: %s", threw.Error)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decoding %s: %v\n%s", name, err, raw)
	}
}

func TestDashboard_HostileProjectNamesStayData(t *testing.T) {
	t.Parallel()
	var r xssResult
	runXSSScenario(t, "hostile_names", &r)
	n := len(r.Names)
	if n < 5 || !strings.Contains(r.Names[0], "&quot;+(document.title='PWNED')+&quot;") {
		t.Fatalf("the scenario's names are not the hostile set: %q", r.Names)
	}
	// The payload: shown at i, hidden at n+i, both named Names[i].
	nameOf := func(idx int) string { return r.Names[idx%n] }
	pathOf := func(idx int) string {
		if idx >= n {
			return "/srv/hidden/" + nameOf(idx)
		}
		return "/srv/work/" + nameOf(idx)
	}

	// Each site, the action its controls name, and how many there must be:
	// one per shown project, or per hidden one in the dialog.
	sites := []struct {
		container, action string
	}{
		{"projList", "openProject"},
		{"projList", "projectHide"},
		{"projList", "projectDelete"},
		{"multiProjectCards", "openProject"},
		{"projSelectorDropdown", "selectProjectFromDropdown"},
		{"hiddenProjectsList", "projectUnhide"},
	}
	for _, s := range sites {
		var seen []int
		for _, tag := range r.Containers[s.container] {
			if tag.Attrs["data-action"] != s.action {
				continue
			}
			idx, err := strconv.Atoi(tag.Attrs["data-arg"])
			if err != nil {
				t.Errorf("%s: %s carries data-arg %q, not an index", s.container, s.action, tag.Attrs["data-arg"])
				continue
			}
			seen = append(seen, idx)
			if got := tag.Attrs["data-arg-name"]; got != nameOf(idx) {
				t.Errorf("%s: %s for project %d carries name %q, want %q", s.container, s.action, idx, got, nameOf(idx))
			}
			if s.action == "projectDelete" && tag.Attrs["data-arg-path"] != pathOf(idx) {
				t.Errorf("%s: projectDelete for project %d carries path %q, want %q",
					s.container, idx, tag.Attrs["data-arg-path"], pathOf(idx))
			}
		}
		if len(seen) != n {
			t.Errorf("%s: %d %s control(s), want one per hostile name (%d) — the site is not exercised: %v",
				s.container, len(seen), s.action, n, seen)
		}
	}

	for container, tags := range r.Containers {
		for _, tag := range tags {
			switch tag.Tag {
			case "img", "svg", "script", "iframe", "object", "embed":
				t.Errorf("%s: a name became a <%s> element: %v", container, tag.Tag, tag.Attrs)
			}
			for a := range tag.Attrs {
				if strings.HasPrefix(a, "on") {
					t.Errorf("%s: <%s> carries the event-handler attribute %s=%q", container, tag.Tag, a, tag.Attrs[a])
				}
			}
		}
	}

	// And clicked, each acts on its own project under its own name.
	if len(r.Effects) != len(sites)*n {
		t.Errorf("clicked %d controls, want %d", len(r.Effects), len(sites)*n)
	}
	for _, e := range r.Effects {
		want := nameOf(e.Idx)
		switch e.Action {
		case "openProject", "selectProjectFromDropdown":
			if e.Label != want || e.Breadcrumb != want {
				t.Errorf("%s %s(%d): the header says %q / %q, want %q", e.Where, e.Action, e.Idx, e.Label, e.Breadcrumb, want)
			}
		case "projectDelete":
			if e.Name != want || e.Path != pathOf(e.Idx) || e.DeleteIdx != strconv.Itoa(e.Idx) {
				t.Errorf("projectDelete(%d) confirms %q at %q for #%s, want %q at %q", e.Idx, e.Name, e.Path, e.DeleteIdx, want, pathOf(e.Idx))
			}
		case "projectHide", "projectUnhide":
			wantURL := "/api/projects/" + strconv.Itoa(e.Idx) + "/hidden"
			wantBody := `{"hidden":` + strconv.FormatBool(e.Action == "projectHide") + `}`
			if e.Post != wantURL || e.Body != wantBody {
				t.Errorf("%s(%d) posted %q %s, want %q %s", e.Action, e.Idx, e.Post, e.Body, wantURL, wantBody)
			}
		}
	}
	if r.Title == "PWNED" || r.XSS != nil {
		t.Errorf("a name ran as code: title %q, __xss %v", r.Title, r.XSS)
	}
}

// TestDashboard_PassingEventsRunOnlyTheirOwnActions holds the dispatcher to
// its tables (00-core.js). mouseenter and the drag events run only what actOn
// registered for that very event, so markup injected over the page cannot
// fire a click's action as the pointer passes or a drag crosses it, and a
// click cannot run a drag's handler with arguments of its choosing. Each
// refusal is the dispatcher's throw for a name it does not hold, and sends
// nothing; the same action clicked is the control, and posts.
func TestDashboard_PassingEventsRunOnlyTheirOwnActions(t *testing.T) {
	t.Parallel()
	var r struct {
		Tried []struct {
			Type  string            `json:"type"`
			Attrs map[string]string `json:"attrs"`
			Error string            `json:"error"`
			Sent  []string          `json:"sent"`
		} `json:"tried"`
	}
	runXSSScenario(t, "passing_events", &r)
	if len(r.Tried) != 6 {
		t.Fatalf("tried %d events, want 6: %+v", len(r.Tried), r.Tried)
	}
	for _, a := range r.Tried[:5] {
		attr := "data-action"
		if a.Type != "click" {
			attr += "-" + a.Type
		}
		want := "no " + a.Type + " action is registered as \"" + a.Attrs[attr] + "\""
		if !strings.Contains(a.Error, want) {
			t.Errorf("%s on %s=%q: got error %q, want %q", a.Type, attr, a.Attrs[attr], a.Error, want)
		}
		if len(a.Sent) > 0 {
			t.Errorf("%s on %s=%q sent %v", a.Type, attr, a.Attrs[attr], a.Sent)
		}
	}
	if c := r.Tried[5]; c.Error != "" || len(c.Sent) != 1 || c.Sent[0] != "POST /api/projects/0/hidden" {
		t.Errorf("the control — projectHide clicked — threw %q and sent %v, want one POST /api/projects/0/hidden", c.Error, c.Sent)
	}
}
