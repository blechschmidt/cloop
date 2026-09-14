package ui

// Projects that will not load, driven through the real dashboard bundle
// (Task 20254).
//
// The reported symptom was "project state is broken and tasks are not shown".
// The cause was a schema guard refusing 18 databases; the reason it was
// reported that way is that the dashboard had no vocabulary for "could not
// load" and rendered the refusal as 18 empty-looking projects. These assert on
// the DOM rather than on the source, because whether a fault is visible is not
// a property any string in the bundle can express.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type projectFaultResult struct {
	Shown                bool   `json:"shown"`
	Text                 string `json:"text"`
	Occurrences          int    `json:"occurrences"`
	GridSaysCouldNotLoad int    `json:"gridSaysCouldNotLoad"`
	GridSaysNoGoal       bool   `json:"gridSaysNoGoal"`
	MentionsSkew         bool   `json:"mentionsSkew"`
	MentionsDenied       bool   `json:"mentionsDenied"`
	CountsTwo            bool   `json:"countsTwo"`
	RawScriptTag         bool   `json:"rawScriptTag"`
	RawImgTag            bool   `json:"rawImgTag"`
	EscapedSomething     bool   `json:"escapedSomething"`
	Error                string `json:"error"`
}

func runProjectFaultScenarios(t *testing.T) map[string]projectFaultResult {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}

	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/project_fault_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string]projectFaultResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, r := range results {
		if r.Error != "" {
			t.Fatalf("scenario %s threw: %s", name, r.Error)
		}
	}
	return results
}

// TestDashboard_SurfacesProjectsThatWillNotLoad is the regression for the
// outage: a refused database must produce a visible statement of the cause,
// not a card that reads as an empty project.
func TestDashboard_SurfacesProjectsThatWillNotLoad(t *testing.T) {
	r := runProjectFaultScenarios(t)["allFaultedForTheSameReason"]

	if !r.Shown {
		t.Fatal("every project failed to load and the dashboard showed no fault banner")
	}
	if r.Text == "" {
		t.Fatal("fault banner is visible but empty")
	}
	// The count is what distinguishes "one project is broken" from "the
	// deployment is broken", which are different problems with different fixes.
	if want := "3 projects could not be loaded"; !strings.Contains(r.Text, want) {
		t.Errorf("banner does not say how many failed: %q", r.Text)
	}
	if !strings.Contains(r.Text, "schema version 34") {
		t.Errorf("banner does not carry the underlying reason: %q", r.Text)
	}
	// Grouped, not repeated once per project — 18 copies of one sentence is
	// how a banner becomes unreadable at the exact moment it matters.
	if r.Occurrences != 1 {
		t.Errorf("the shared reason appears %d times, want 1 (grouped)", r.Occurrences)
	}
	// And the cards themselves must not read as ordinary empty projects.
	if r.GridSaysCouldNotLoad != 3 {
		t.Errorf("%d of 3 cards say they could not be loaded", r.GridSaysCouldNotLoad)
	}
}

// TestDashboard_HealthyProjectsRaiseNoFault. A banner that is always on is a
// banner nobody reads.
func TestDashboard_HealthyProjectsRaiseNoFault(t *testing.T) {
	r := runProjectFaultScenarios(t)["noFaults"]

	if r.Shown {
		t.Errorf("fault banner shown for healthy projects: %q", r.Text)
	}
	if r.GridSaysCouldNotLoad != 0 {
		t.Errorf("%d healthy cards claim they could not be loaded", r.GridSaysCouldNotLoad)
	}
}

// TestDashboard_UninitialisedProjectIsNotAFault keeps the distinction the
// server draws: a directory that was never `cloop init`ed is the normal state
// of a newly registered path, and flagging it would train users to ignore the
// banner.
func TestDashboard_UninitialisedProjectIsNotAFault(t *testing.T) {
	r := runProjectFaultScenarios(t)["emptyProjectIsNotAFault"]

	if r.Shown {
		t.Error("an uninitialised project was reported as a fault")
	}
	if !r.GridSaysNoGoal {
		t.Error("an uninitialised project no longer renders as 'no goal set'")
	}
}

// TestDashboard_DistinctFaultsStayDistinct. Collapsing two causes into one
// count hides which kind of problem you have.
func TestDashboard_DistinctFaultsStayDistinct(t *testing.T) {
	r := runProjectFaultScenarios(t)["distinctFaultsAreListedSeparately"]

	if !r.Shown {
		t.Fatal("no banner for a mix of faulted and healthy projects")
	}
	if !r.CountsTwo {
		t.Errorf("banner does not count exactly the two faulted projects: %q", r.Text)
	}
	if !r.MentionsSkew || !r.MentionsDenied {
		t.Errorf("banner dropped one of the two distinct causes: %q", r.Text)
	}
}

// TestDashboard_FaultTextIsEscaped. The message is composed server-side and
// embeds a filesystem path, so it reaches innerHTML from outside the page.
func TestDashboard_FaultTextIsEscaped(t *testing.T) {
	r := runProjectFaultScenarios(t)["faultTextIsEscaped"]

	if r.RawScriptTag {
		t.Error("a <script> tag in an error message reached the DOM unescaped")
	}
	if r.RawImgTag {
		t.Error("an <img onerror> in a project name reached the DOM unescaped")
	}
	if !r.EscapedSomething {
		t.Error("nothing was escaped — the scenario did not exercise the path it claims to")
	}
}
