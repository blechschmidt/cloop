package cmd

// Tests for `cloop adr`.
//
// These drive the RunE bodies directly, which is the pattern the rest of the
// package uses, and assert against the files the commands leave behind rather
// than their printed output — the records are the artifact a user keeps, and
// the formatting is not a contract. The exceptions are --json, which is a
// contract, and the refusals, where the point is that nothing was written.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/adr"
)

// inTempProject chdirs into an empty directory for the duration of one test
// and restores the working directory afterwards, so a failure here cannot
// strand the rest of the package in a deleted temp dir.
func inTempProject(t *testing.T) string {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	resetAdrFlags(t)
	return dir
}

// resetAdrFlags clears the package-level flag variables. They are process
// globals, so without this a flag set by one test silently applies to the next.
func resetAdrFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		adrNewBody, adrNewDeciders, adrNewTags, adrNewStatus = "", "", "", ""
		adrListStatus, adrListJSON, adrShowJSON = "", false, false
		adrNewCmd.SetIn(nil)
	}
	reset()
	t.Cleanup(reset)
}

// captureStdout runs fn with output redirected and returns what it wrote.
//
// Both sinks have to be swapped. The commands print plain text with fmt to
// os.Stdout and coloured text with fatih/color, and color resolves its
// destination once at package init — so redirecting os.Stdout alone leaves
// every coloured line going to the real terminal, where an assertion on it
// silently looks for text the test never received.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prevStdout, prevColor := os.Stdout, color.Output
	os.Stdout, color.Output = w, w

	// Drain concurrently: a command writing more than the pipe buffer would
	// otherwise block forever on the write.
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	runErr := fn()

	os.Stdout, color.Output = prevStdout, prevColor
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out, runErr
}

func TestAdrNewCreatesARecord(t *testing.T) {
	dir := inTempProject(t)

	if _, err := captureStdout(t, func() error {
		return adrNewCmd.RunE(adrNewCmd, []string{"Use", "SQLite", "for", "state"})
	}); err != nil {
		t.Fatalf("adr new: %v", err)
	}

	path := filepath.Join(dir, adr.Dir, "0001-use-sqlite-for-state.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected record at %s: %v", path, err)
	}
	// Multi-word titles arrive as separate args and must be rejoined, not
	// truncated to the first word.
	if !strings.Contains(string(data), `title: "Use SQLite for state"`) {
		t.Errorf("frontmatter title is wrong:\n%s", data)
	}
	if !strings.Contains(string(data), "status: "+adr.StatusProposed) {
		t.Errorf("new record is not Proposed:\n%s", data)
	}
}

func TestAdrNewRecordsDecidersTagsAndStatus(t *testing.T) {
	dir := inTempProject(t)
	adrNewDeciders = "alice, bob"
	adrNewTags = "storage,core"
	adrNewStatus = "accepted" // lower case on purpose: it must canonicalise

	if _, err := captureStdout(t, func() error {
		return adrNewCmd.RunE(adrNewCmd, []string{"Adopt", "ADRs"})
	}); err != nil {
		t.Fatalf("adr new: %v", err)
	}

	got, err := adr.FindByID(dir, 1)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if strings.Join(got.Deciders, "|") != "alice|bob" {
		t.Errorf("Deciders = %v, want [alice bob] with surrounding space trimmed", got.Deciders)
	}
	if strings.Join(got.Tags, "|") != "storage|core" {
		t.Errorf("Tags = %v, want [storage core]", got.Tags)
	}
	if got.Status != adr.StatusAccepted {
		t.Errorf("Status = %q, want the canonical %q", got.Status, adr.StatusAccepted)
	}
}

func TestAdrNewReadsBodyFromStdin(t *testing.T) {
	dir := inTempProject(t)
	adrNewBody = "-"
	adrNewCmd.SetIn(strings.NewReader("# custom\n\nhand written body\n"))

	if _, err := captureStdout(t, func() error {
		return adrNewCmd.RunE(adrNewCmd, []string{"Piped"})
	}); err != nil {
		t.Fatalf("adr new: %v", err)
	}

	got, err := adr.FindByID(dir, 1)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if !strings.Contains(got.Body, "hand written body") {
		t.Errorf("body did not come from stdin: %q", got.Body)
	}
	if strings.Contains(got.Body, "## Consequences") {
		t.Error("the template was used even though a body was supplied")
	}
}

// TestAdrNewRejectsAnInvalidStatusWithoutWriting checks the ordering inside the
// handler: validation happens before Create, so a typo does not leave a
// stray record behind that the user then has to find and delete.
func TestAdrNewRejectsAnInvalidStatusWithoutWriting(t *testing.T) {
	dir := inTempProject(t)
	adrNewStatus = "acepted"

	_, err := captureStdout(t, func() error {
		return adrNewCmd.RunE(adrNewCmd, []string{"Typo"})
	})
	if err == nil {
		t.Fatal("adr new accepted an invalid status")
	}
	if !strings.Contains(err.Error(), adr.StatusAccepted) {
		t.Errorf("error %q does not list the valid statuses", err)
	}

	records, listErr := adr.List(dir)
	if listErr != nil {
		t.Fatalf("List: %v", listErr)
	}
	if len(records) != 0 {
		t.Errorf("a rejected `adr new` still wrote %d record(s)", len(records))
	}
}

func TestAdrListJSONIsMachineReadable(t *testing.T) {
	dir := inTempProject(t)
	for _, title := range []string{"First", "Second"} {
		if _, err := adr.Create(dir, title, ""); err != nil {
			t.Fatal(err)
		}
	}
	adrListJSON = true

	out, err := captureStdout(t, func() error { return adrListCmd.RunE(adrListCmd, nil) })
	if err != nil {
		t.Fatalf("adr list --json: %v", err)
	}

	var got []struct {
		ID     int    `json:"ID"`
		Title  string `json:"Title"`
		Status string `json:"Status"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON (%v):\n%s", err, out)
	}
	if len(got) != 2 || got[0].ID != 1 || got[0].Title != "First" || got[1].Title != "Second" {
		t.Errorf("decoded %+v, want the two records in ID order", got)
	}
}

func TestAdrListFiltersByStatus(t *testing.T) {
	dir := inTempProject(t)
	keep, err := adr.Create(dir, "Accepted one", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adr.Create(dir, "Proposed one", ""); err != nil {
		t.Fatal(err)
	}
	if err := keep.SetStatus(adr.StatusAccepted); err != nil {
		t.Fatal(err)
	}

	adrListJSON, adrListStatus = true, "accepted"
	out, err := captureStdout(t, func() error { return adrListCmd.RunE(adrListCmd, nil) })
	if err != nil {
		t.Fatalf("adr list: %v", err)
	}
	if !strings.Contains(out, "Accepted one") || strings.Contains(out, "Proposed one") {
		t.Errorf("--status did not filter:\n%s", out)
	}

	adrListStatus = "nonsense"
	if _, err := captureStdout(t, func() error { return adrListCmd.RunE(adrListCmd, nil) }); err == nil {
		t.Error("--status accepted an invalid value")
	}
}

func TestAdrListOnAnEmptyProjectIsNotAnError(t *testing.T) {
	inTempProject(t)

	out, err := captureStdout(t, func() error { return adrListCmd.RunE(adrListCmd, nil) })
	if err != nil {
		t.Fatalf("adr list with no records returned an error: %v", err)
	}
	// An empty list should point at the command that fixes it.
	if !strings.Contains(out, "cloop adr new") {
		t.Errorf("empty listing does not suggest how to create a record:\n%s", out)
	}
}

func TestAdrShow(t *testing.T) {
	dir := inTempProject(t)
	if _, err := adr.Create(dir, "Shown record", ""); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error { return adrShowCmd.RunE(adrShowCmd, []string{"1"}) })
	if err != nil {
		t.Fatalf("adr show: %v", err)
	}
	for _, want := range []string{"ADR-0001", "Shown record", adr.StatusProposed, "## Decision"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestAdrShowRejectsBadArguments(t *testing.T) {
	dir := inTempProject(t)
	if _, err := adr.Create(dir, "Only one", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := captureStdout(t, func() error {
		return adrShowCmd.RunE(adrShowCmd, []string{"not-a-number"})
	}); err == nil {
		t.Error("adr show accepted a non-numeric id")
	}
	if _, err := captureStdout(t, func() error {
		return adrShowCmd.RunE(adrShowCmd, []string{"99"})
	}); err == nil {
		t.Error("adr show accepted an unknown id")
	}
}

func TestAdrStatusCommandPersistsAndValidates(t *testing.T) {
	dir := inTempProject(t)
	if _, err := adr.Create(dir, "Decide me", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := captureStdout(t, func() error {
		return adrStatusCmd.RunE(adrStatusCmd, []string{"1", "DEPRECATED"})
	}); err != nil {
		t.Fatalf("adr status: %v", err)
	}
	got, err := adr.FindByID(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != adr.StatusDeprecated {
		t.Errorf("Status = %q, want %q", got.Status, adr.StatusDeprecated)
	}

	if _, err := captureStdout(t, func() error {
		return adrStatusCmd.RunE(adrStatusCmd, []string{"1", "banana"})
	}); err == nil {
		t.Error("adr status accepted an invalid status")
	}
	// The refused call must not have changed anything.
	after, _ := adr.FindByID(dir, 1)
	if after.Status != adr.StatusDeprecated {
		t.Errorf("a refused status change still mutated the record: %q", after.Status)
	}
}

func TestAdrSupersedeLinksBothRecords(t *testing.T) {
	dir := inTempProject(t)
	if _, err := adr.Create(dir, "Old way", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := adr.Create(dir, "New way", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := captureStdout(t, func() error {
		return adrSupersedeCmd.RunE(adrSupersedeCmd, []string{"2", "1"})
	}); err != nil {
		t.Fatalf("adr supersede: %v", err)
	}

	oldRec, err := adr.FindByID(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if oldRec.Status != adr.StatusSuperseded {
		t.Errorf("old record status = %q, want %q", oldRec.Status, adr.StatusSuperseded)
	}
	newRec, err := adr.FindByID(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(newRec.Supersedes) != 1 || newRec.Supersedes[0] != 1 {
		t.Errorf("new.Supersedes = %v, want [1]", newRec.Supersedes)
	}

	// A superseded record stays listed — the history is the point.
	adrListJSON = true
	out, listErr := captureStdout(t, func() error { return adrListCmd.RunE(adrListCmd, nil) })
	if listErr != nil {
		t.Fatalf("adr list: %v", listErr)
	}
	if !strings.Contains(out, "Old way") {
		t.Errorf("the superseded record vanished from the listing:\n%s", out)
	}
}

func TestAdrSupersedeRejectsBadArguments(t *testing.T) {
	dir := inTempProject(t)
	if _, err := adr.Create(dir, "Only one", ""); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{{"x", "1"}, {"1", "y"}, {"1", "1"}, {"1", "99"}} {
		if _, err := captureStdout(t, func() error {
			return adrSupersedeCmd.RunE(adrSupersedeCmd, args)
		}); err == nil {
			t.Errorf("adr supersede %v was accepted", args)
		}
	}
}

// TestAdrCommandIsReachable pins the wiring itself. pkg/adr sat in the tree
// with no consumer for months; the failure mode being guarded here is a
// backend that exists and a command that nobody can run.
func TestAdrCommandIsReachable(t *testing.T) {
	found, _, err := rootCmd.Find([]string{"adr"})
	if err != nil {
		t.Fatalf("rootCmd.Find(adr): %v", err)
	}
	if found.Name() != "adr" {
		t.Fatalf("resolved %q, want adr", found.Name())
	}
	if found.Hidden {
		t.Error("the adr command is hidden")
	}

	for _, sub := range []string{"new", "list", "show", "status", "supersede"} {
		cmd, _, err := rootCmd.Find([]string{"adr", sub})
		if err != nil {
			t.Errorf("rootCmd.Find(adr %s): %v", sub, err)
			continue
		}
		if cmd.Name() != sub {
			t.Errorf("adr %s resolved to %q", sub, cmd.Name())
		}
		if !cmd.Runnable() {
			t.Errorf("adr %s is not runnable", sub)
		}
	}
}
