package cmd

// Requirements as code (Task 20459), run as a person runs it, as a CI job with
// no hub runs it, and as the dashboard runs it: the real `cloop requirements
// validate --json` on the project's executor, dispatched by a hub with sign-on
// in this process, its file read there and parsed here.

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func specFileIn(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, requirements.SpecFileName))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func writeSpecFile(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, requirements.SpecFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func exitCode(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}

func projectRequirements(t *testing.T, dir string) []requirements.Requirement {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reqs, err := db.Requirements()
	if err != nil {
		t.Fatal(err)
	}
	return reqs
}

func TestRequirementsAsCodeByHand(t *testing.T) {
	exe := cliSelfExe(t)
	dir := reqTestProject(t)
	mustRun(t, exe, dir, "requirements", "add", "Builds", "--test", "true", "--priority", "must", "--tag", "ci")
	mustRun(t, exe, dir, "requirements", "add", "Is documented", "--status", "draft")

	if out := mustRun(t, exe, dir, "requirements", "export"); !strings.Contains(out, "Wrote "+requirements.SpecFileName) {
		t.Fatalf("export said:\n%s", out)
	}
	file := specFileIn(t, dir)
	f, err := requirements.ParseSpecFile([]byte(file))
	if err != nil || len(f.Requirements) != 2 || f.Requirements[1].Status != requirements.StatusDraft {
		t.Fatalf("the exported file: %v %+v\n%s", err, f, file)
	}
	if out := mustRun(t, exe, dir, "requirements", "export", "--file", "-"); out != file {
		t.Errorf("export --file - printed\n%s\nnot\n%s", out, file)
	}

	// A pull request approves R-2 and adds R-3; the hub meanwhile tags R-1.
	file = strings.Replace(file, "    status: draft\n", "    status: approved\n", 1)
	file += "  - id: R-3\n    title: Ships a changelog\n    status: approved\n    tests:\n      - command: test -f CHANGELOG.md\n        timeout: 30s\n"
	writeSpecFile(t, dir, file)
	mustRun(t, exe, dir, "requirements", "edit", "1", "--tag", "ci,release")
	if out := mustRun(t, exe, dir, "requirements", "validate"); !strings.Contains(out, "3 requirements — 3 approved") {
		t.Errorf("validate said:\n%s", out)
	}
	// The file has changes the hub does not: export will not overwrite them.
	out, err := runHelper(t, exe, dir, "requirements", "export")
	if exitCode(err) != 1 || !strings.Contains(string(out), "R-3") || !strings.Contains(string(out), "nothing was exported") {
		t.Fatalf("export over unimported changes: %v\n%s", err, out)
	}
	if out := mustRun(t, exe, dir, "requirements", "import", "--dry-run"); !strings.Contains(out, "Nothing was imported (--dry-run)") {
		t.Errorf("dry run:\n%s", out)
	}
	if reqs := projectRequirements(t, dir); len(reqs) != 2 {
		t.Fatalf("a dry run imported: %+v", reqs)
	}
	out2 := mustRun(t, exe, dir, "requirements", "import")
	for _, want := range []string{"Imported: 1 added, 1 updated", "changed in the hub: tags", "cloop requirements export"} {
		if !strings.Contains(out2, want) {
			t.Errorf("import output lacks %q:\n%s", want, out2)
		}
	}
	reqs := projectRequirements(t, dir)
	if len(reqs) != 3 || reqs[1].Status != requirements.StatusApproved || reqs[2].Tests[0].TimeoutSeconds != 30 ||
		strings.Join(reqs[0].Tags, ",") != "ci,release" {
		t.Fatalf("after the import: %+v", reqs)
	}
	// Now the hub is ahead, and export writes its change.
	mustRun(t, exe, dir, "requirements", "export")
	if !strings.Contains(specFileIn(t, dir), "tags: [ci, release]") {
		t.Errorf("the export did not write the hub's change:\n%s", specFileIn(t, dir))
	}

	// Both change R-1's title: a conflict, nothing imported until settled.
	writeSpecFile(t, dir, strings.Replace(specFileIn(t, dir), "title: Builds", "title: Builds, says the file", 1))
	mustRun(t, exe, dir, "requirements", "edit", "1", "--title", "Builds, says the hub")
	out, err = runHelper(t, exe, dir, "requirements", "import")
	if exitCode(err) != 1 || !strings.Contains(string(out), "CONFLICT") || !strings.Contains(string(out), "--resolve") {
		t.Fatalf("a conflict: %v\n%s", err, out)
	}
	if reqs := projectRequirements(t, dir); reqs[0].Title != "Builds, says the hub" {
		t.Fatalf("a conflicting import changed R-1: %+v", reqs[0])
	}
	if out, err := runHelper(t, exe, dir, "requirements", "import", "--resolve", "R-1=theirs"); err == nil {
		t.Errorf("a settlement that is neither file nor hub was taken:\n%s", out)
	}
	mustRun(t, exe, dir, "requirements", "import", "--prefer", "hub")
	if reqs := projectRequirements(t, dir); reqs[0].Title != "Builds, says the hub" {
		t.Fatalf("--prefer hub changed R-1: %+v", reqs[0])
	}
	// The hub's version is now what an export writes; --force is not needed.
	mustRun(t, exe, dir, "requirements", "export")
	if !strings.Contains(specFileIn(t, dir), "Builds, says the hub") {
		t.Errorf("after keeping the hub's:\n%s", specFileIn(t, dir))
	}

	// The import was audited, from the CLI.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionRequirementImport)})
	db.Close()
	if err != nil || len(rows) != 2 || !strings.Contains(rows[0].Payload, `"cli"`) {
		t.Errorf("import audit rows: %v %+v", err, rows)
	}

	// A file that does not validate names every problem, editor-style.
	writeSpecFile(t, dir, "version: 1\nrequirements:\n  - id: R-1\n    titel: x\n    status: approved\n")
	out, err = runHelper(t, exe, dir, "requirements", "validate")
	if exitCode(err) != 1 || !strings.Contains(string(out), requirements.SpecFileName+":3:5: R-1 has no title") ||
		!strings.Contains(string(out), requirements.SpecFileName+`:4:5: R-1 has an unknown key "titel" (did you mean "title"?)`) {
		t.Errorf("validate on a bad file: %v\n%s", err, out)
	}
	if out, err := runHelper(t, exe, dir, "requirements", "import"); exitCode(err) != 1 || !strings.Contains(string(out), ":3:5:") {
		t.Errorf("import of a bad file: %v\n%s", err, out)
	}
}

// TestCheckFileNeedsNoHubAndNoProject: what a plain CI job runs, in a checkout
// with no .cloop/state.db — and that leaves none behind.
func TestCheckFileNeedsNoHubAndNoProject(t *testing.T) {
	exe := cliSelfExe(t)
	dir := t.TempDir()
	spec := `version: 1
requirements:
  - id: R-1
    title: Passes
    status: approved
    tests:
      - command: test -n "$CLOOP_REQUIREMENT_ID"
  - id: R-2
    title: Fails
    status: approved
    tests:
      - name: the failing one
        command: echo broken >&2; exit 4
  - id: R-3
    title: Not agreed yet
    status: draft
    tests:
      - command: exit 9
  - id: R-4
    title: Gone
    status: deprecated
    tests:
      - command: exit 9
  - id: R-5
    title: Untested
    status: approved
`
	if err := os.WriteFile(filepath.Join(dir, "requirements.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runHelper(t, exe, dir, "requirements", "check", "--file", "requirements.yaml")
	if exitCode(err) != 1 {
		t.Fatalf("check --file exited %v:\n%s", err, out)
	}
	for _, want := range []string{"R-1    fulfilled", "R-2    unfulfilled", `"the failing one" failed (exit 4)`, "R-5    skipped",
		"Not checked: 1 deprecated (R-4) — name them", "Not checked: 1 draft (R-3) awaiting approval", "1 fulfilled, 1 unfulfilled"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("check --file output lacks %q:\n%s", want, out)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("check --file left %v behind in the checkout", names)
	}

	if out, err := runHelper(t, exe, dir, "requirements", "check", "--file", "requirements.yaml", "R-1", "4"); exitCode(err) != 1 ||
		!strings.Contains(string(out), "R-4    unfulfilled") || strings.Contains(string(out), "R-2") {
		t.Errorf("named requirements: %v\n%s", err, out)
	}
	// A draft is checked by nothing until a person approves it (Task
	// 20462), named or by status: its test never runs.
	for _, args := range [][]string{{"R-1", "3"}, {"--status", "draft"}} {
		out, err := runHelper(t, exe, dir, append([]string{"requirements", "check", "--file", "requirements.yaml"}, args...)...)
		if exitCode(err) != 1 || !strings.Contains(string(out), "not checked until a person approves it") ||
			strings.Contains(string(out), "fulfilled") {
			t.Errorf("checking the draft with %v: %v\n%s", args, err, out)
		}
	}
	// --json is the report, framed, for a tool: what the table says goes to
	// stderr as each requirement is checked, and the exit status is what it
	// is without --json. Until Task 20466 a CI job reading the JSON passed
	// whatever the report said.
	jsonCheck := exec.Command(exe, "requirements", "check", "--file", "requirements.yaml", "--all", "--json")
	jsonCheck.Dir = dir
	var stdout, stderr strings.Builder
	jsonCheck.Stdout, jsonCheck.Stderr = &stdout, &stderr
	if err := jsonCheck.Run(); exitCode(err) != 1 {
		t.Errorf("--json with R-2 unfulfilled exited %v:\n%s\n%s", err, stdout.String(), stderr.String())
	}
	var checked requirements.Report
	if err := clijson.Unmarshal([]byte(stdout.String()), &checked); err != nil || len(checked.Results) != 3 {
		t.Errorf("--all --json reported %+v (%v)", checked, err)
	}
	for _, r := range checked.Results {
		if r.RequirementID == 3 {
			t.Errorf("--all checked the draft R-3: %+v", r)
		}
	}
	for _, want := range []string{"R-1    checking    Passes\n", "R-1    fulfilled", "R-2    checking    Fails\n",
		`R-2    unfulfilled test "the failing one" failed (exit 4)`, "R-4    unfulfilled", "R-5    skipped",
		"1 fulfilled, 2 unfulfilled"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("--json's stderr lacks %q:\n%s", want, stderr.String())
		}
	}
	if strings.Contains(stdout.String(), "checking") || strings.Contains(stdout.String(), "fulfilled, ") {
		t.Errorf("--json printed the table on stdout beside the frame:\n%s", stdout.String())
	}
	if out, err := runHelper(t, exe, dir, "requirements", "check", "--file", "missing.yaml"); exitCode(err) != 1 ||
		!strings.Contains(string(out), "no requirements spec file at missing.yaml") {
		t.Errorf("a missing file: %v\n%s", err, out)
	}

	// validate --json is how the hub reads a checkout's file: the bytes,
	// framed, whatever they say.
	out, err = runHelper(t, exe, dir, "requirements", "validate", "--json", "--file", "requirements.yaml")
	var rep requirements.SpecFileReport
	if err != nil || clijson.Unmarshal(out, &rep) != nil || !rep.Found || string(rep.Content) != spec || !rep.Valid || rep.Count != 5 {
		t.Fatalf("validate --json: %v %+v\n%s", err, rep, out)
	}
	out, err = runHelper(t, exe, dir, "requirements", "validate", "--json")
	if err != nil || clijson.Unmarshal(out, &rep) != nil || rep.Found || rep.Path != requirements.SpecFileName {
		t.Fatalf("validate --json with no file: %v %+v\n%s", err, rep, out)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("validate left files behind: %d entries", len(entries))
	}
}

// TestTheDashboardReadsTheSpecFileOnTheExecutor is the whole chain: a hub with
// sign-on asks its executor — the real `cloop requirements validate`, in the
// project's directory — for the spec file, shows it changed, and imports it
// for an operator; a viewer may look and may do neither.
func TestTheDashboardReadsTheSpecFileOnTheExecutor(t *testing.T) {
	hub := ssohubtest.Start(t, ssohubtest.Options{SelfExe: cliSelfExe(t), AdminEmails: []string{rootEmail}})
	const alice, vic = "alice@example.com", "vic@example.com"
	op := hub.SignIn(t, alice, ssohubtest.GroupOperators)
	viewer := hub.SignIn(t, vic, ssohubtest.GroupViewers)

	code, raw := hubCall(t, hub, op, http.MethodPost, "/api/requirements",
		map[string]any{"title": "Builds", "tests": []map[string]any{{"command": "true"}}})
	if code != http.StatusOK {
		t.Fatalf("add = %d %s", code, raw)
	}
	writeSpecFile(t, hub.Dir, `version: 1
requirements:
  - id: R-1
    title: Builds
    status: approved
    tests:
      - command: "true"
  - id: R-2
    title: Ships a changelog
    status: approved
`)

	if code, _ := hubCall(t, hub, viewer, http.MethodPost, "/api/requirements/spec/read", map[string]any{}); code != http.StatusForbidden {
		t.Errorf("a viewer read the spec file: %d", code)
	}
	if code, raw := hubCall(t, hub, op, http.MethodPost, "/api/requirements/spec/read", map[string]any{}); code != http.StatusAccepted {
		t.Fatalf("read = %d %s", code, raw)
	}
	// The read runs on the executor; its end arrives as a push, and the
	// review says so once it has.
	deadline := time.Now().Add(2 * time.Minute)
	for {
		code, raw = hubCall(t, hub, op, http.MethodGet, "/api/requirements/spec", nil)
		if code != http.StatusOK || !strings.Contains(string(raw), `"reading":true`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the read is still running after two minutes: %s", raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var d struct {
		Spec struct {
			State   string `json:"state"`
			Imports int    `json:"imports"`
			InSync  int    `json:"in_sync"`
			Digest  string `json:"digest"`
			Read    struct {
				SHA256 string `json:"sha256"`
				ReadBy string `json:"read_by"`
			} `json:"read"`
		} `json:"spec"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &d) != nil {
		t.Fatalf("read = %d %s", code, raw)
	}
	if d.Spec.State != "changed" || d.Spec.Imports != 1 || d.Spec.InSync != 1 || d.Spec.Read.ReadBy != alice {
		t.Fatalf("the read found %s", raw)
	}
	// A viewer sees it, and may not import it.
	if code, raw := hubCall(t, hub, viewer, http.MethodGet, "/api/requirements", nil); code != http.StatusOK ||
		!strings.Contains(string(raw), `"state":"changed"`) {
		t.Errorf("a viewer's list = %d %s", code, raw)
	}
	body := map[string]any{"sha256": d.Spec.Read.SHA256, "digest": d.Spec.Digest}
	if code, _ := hubCall(t, hub, viewer, http.MethodPost, "/api/requirements/import", body); code != http.StatusForbidden {
		t.Errorf("a viewer imported: %d", code)
	}
	if code, raw := hubCall(t, hub, op, http.MethodPost, "/api/requirements/import", body); code != http.StatusOK {
		t.Fatalf("import = %d %s", code, raw)
	}
	reqs := projectRequirements(t, hub.Dir)
	if len(reqs) != 2 || reqs[1].Title != "Ships a changelog" || reqs[1].CreatedBy != alice {
		t.Fatalf("after the import: %+v", reqs)
	}
	db, err := statedb.Open(state.DBPath(hub.Dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionRequirementImport)})
	if err != nil || len(rows) != 1 || rows[0].Actor != alice || !strings.Contains(rows[0].Payload, `"dashboard"`) {
		t.Errorf("the import's audit rows: %v %+v", err, rows)
	}
}
