package requirements

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleSpec = `# A comment the parser ignores.
version: 1
requirements:
  - id: R-3
    title: Config errors exit non-zero
    status: approved
    priority: must
    tags: [CLI, config, cli]
    details: |
      A malformed config.yaml makes every command exit 2
      and name the line.
    tests:
      - name: malformed config
        command: go test ./pkg/config -run TestMalformed
        timeout: 2m
      - command: |
          set -e
          make check
  - id: R-1
    title: "Rollbacks never lose a config"
    status: draft

  - id: R-12
    title: Old behaviour
    status: deprecated
    priority: could
    tags: []
    tests: []
`

func TestSpecFileReadsWhatItSays(t *testing.T) {
	f, err := ParseSpecFile([]byte(sampleSpec))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requirements) != 3 {
		t.Fatalf("read %d requirements: %+v", len(f.Requirements), f.Requirements)
	}
	r := f.Requirements[0]
	want := Requirement{
		ID: 3, Title: "Config errors exit non-zero", Status: StatusApproved, Priority: PriorityMust,
		Tags:        []string{"cli", "config"},
		Description: "A malformed config.yaml makes every command exit 2\nand name the line.",
		Tests: []Test{
			{Name: "malformed config", Command: "go test ./pkg/config -run TestMalformed", TimeoutSeconds: 120},
			{Command: "set -e\nmake check"},
		},
	}
	if !SameSpec(r, want) || r.ID != 3 {
		t.Errorf("R-3 reads\n%+v\nwant\n%+v", r, want)
	}
	if got := f.Requirements[1]; got.ID != 1 || got.Status != StatusDraft || got.Title != "Rollbacks never lose a config" {
		t.Errorf("R-1 reads %+v", got)
	}
	if got := f.Requirements[2]; got.ID != 12 || got.Status != StatusDeprecated || got.Tags != nil || got.Tests != nil {
		t.Errorf("R-12 reads %+v", got)
	}
	for id, line := range map[int]int{3: 4, 1: 19, 12: 23} {
		if got := f.Line(id); got != line {
			t.Errorf("%s is on line %d, the parser says %d", Key(id), line, got)
		}
	}
	if c := f.Counts(); c[StatusApproved] != 1 || c[StatusDraft] != 1 || c[StatusDeprecated] != 1 {
		t.Errorf("counts %v", c)
	}
}

// problem is one line-numbered message a broken file must produce.
type problem struct {
	line int
	text string
}

func TestSpecFileReportsEveryProblemWithItsLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
		want []problem
	}{
		{"unknown keys, at their lines, with a hint", `version: 1
requirements:
  - id: R-1
    title: t
    status: approved
    description: what it means
    test:
      - command: x
`, []problem{{6, `unknown key "description" (did you mean "details"?)`}, {7, `unknown key "test" (did you mean "tests"?)`}}},

		{"a transposed key", `version: 1
requirements:
  - id: R-1
    titel: t
    status: approved
`, []problem{{3, "R-1 has no title"}, {4, `unknown key "titel" (did you mean "title"?)`}}},

		{"an unknown key in a test, and in the file", `version: 1
extra: true
requirements:
  - id: R-1
    title: t
    status: approved
    tests:
      - command: x
        retries: 3
`, []problem{{2, `the file has an unknown key "extra"`}, {9, `R-1 test 1 has an unknown key "retries"`}}},

		{"a duplicate id names both lines", `version: 1
requirements:
  - id: R-4
    title: first
    status: approved
  - id: R-4
    title: second
    status: draft
`, []problem{{6, "R-4 is already the id of the requirement on line 3"}}},

		{"a key given twice", `version: 1
requirements:
  - id: R-1
    title: one
    title: two
    status: approved
`, []problem{{5, `R-1 gives "title" twice (first on line 4)`}}},

		{"what a requirement must have", `version: 1
requirements:
  - title: no id
    status: approved
  - id: R-2
    status: approved
  - id: R-3
    title: no status
`, []problem{{3, "requirement 1 has no id"}, {5, "R-2 has no title"}, {7, "R-3 has no status: draft, approved, deprecated"}}},

		{"ids, statuses and priorities", `version: 1
requirements:
  - id: R-07
    title: t
    status: approved
  - id: 8
    title: t
    status: done
  - id: R-9
    title: t
    status: approved
    priority: urgent
`, []problem{{3, `id "R-07" is not R-<number>: write R-7`}, {6, `id "8" is not R-<number>: write R-8`},
			{8, `status "done" is not one of draft, approved, deprecated`}, {12, `priority "urgent" is not one of must, should, could`}}},

		{"tags and tests", `version: 1
requirements:
  - id: R-1
    title: t
    status: approved
    tags: [ok, "not ok", ""]
    tests:
      - name: "two
          lines"
        command: echo
      - command: ""
      - command: sleep 1
        timeout: 120
      - command: sleep 1
        timeout: 3h
      - command: sleep 1
        timeout: 500ms
`, []problem{{6, `tag "not ok" may hold only`}, {6, "a tag cannot be empty"}, {11, "R-1 test 2: a test needs a command"},
			{13, `timeout "120" is not a duration such as 90s, 10m or 1h30m: write 120s`},
			{15, "a test may run for at most 2h"}, {17, "a timeout is a whole number of seconds, at least 1s"}}},

		{"the wrong shapes", `version: 1
requirements:
  - id: R-1
    title: [a, list]
    status: approved
    tags: cli
    tests: echo hi
  - just a string
`, []problem{{4, "title must be text, not a list"}, {6, "tags must be a list"}, {7, "tests must be a list"},
			{8, "requirement 2 must be a mapping"}}},

		{"anchors, aliases and tags", `version: 1
requirements:
  - &first {id: R-1, title: t, status: approved}
  - *first
  - {id: R-3, title: !!str 3, status: approved}
`, []problem{{3, "an anchor (&first) is not allowed"}, {4, "an alias (*first) is not allowed"}, {5, "a YAML tag (!!str) is not allowed"}}},

		{"a merge key is just an unknown key", `version: 1
requirements:
  - {id: R-1, title: t, status: approved, <<: {priority: must}}
`, []problem{{3, `unknown key "<<"`}}},

		{"YAML that does not parse", "version: 1\nrequirements:\n  - id: R-1\n    title: [unclosed\n",
			[]problem{{4, "not valid YAML"}}},
		{"a tab for indentation", "version: 1\nrequirements:\n\t- id: R-1\n", []problem{{3, "not valid YAML"}}},
		{"no version", "requirements: []\n", []problem{{1, "the file has no version"}}},
		{"a newer version", "version: 2\nrequirements: []\n", []problem{{1, "version 2 of the format, and this cloop reads version 1"}}},
		{"a version that is not a number", "version: one\nrequirements: []\n", []problem{{1, "version must be a number"}}},
		{"no requirements list", "version: 1\n", []problem{{1, "no `requirements:` list"}}},
		{"requirements that are not a list", "version: 1\nrequirements: {a: b}\n", []problem{{2, "requirements must be a list"}}},
		{"two documents", "version: 1\nrequirements: []\n---\nversion: 1\n", []problem{{4, "a second YAML document"}}},
		{"not a mapping at all", "- a\n- b\n", []problem{{1, "the file must be a mapping"}}},
		{"empty", "", []problem{{0, "the file is empty"}}},
		{"comments only", "# nothing yet\n", []problem{{0, "the file is empty"}}},
		{"not UTF-8", "version: 1\nrequirements:\n  - id: R-1\n    title: caf\xe9\n", []problem{{4, "not UTF-8"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSpecFile([]byte(tc.file))
			var errs SpecErrors
			if !errors.As(err, &errs) {
				t.Fatalf("got %v, want SpecErrors", err)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%v is not an ErrInvalid", err)
			}
			for _, w := range tc.want {
				found := false
				for _, e := range errs {
					if e.Line == w.line && strings.Contains(e.Message, w.text) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no problem on line %d saying %q; got:\n%v", w.line, w.text, err)
				}
			}
			if len(errs) != len(tc.want) {
				t.Errorf("%d problems, want %d:\n%v", len(errs), len(tc.want), err)
			}
		})
	}
}

// TestSpecFileBoundsAreTheDatabases: whatever the database refuses, the file
// refuses, and whatever it takes, the file takes — a bound at its limit and
// one past it, read both ways.
func TestSpecFileBoundsAreTheDatabases(t *testing.T) {
	long := func(n int) string { return strings.Repeat("é", n) }
	tags := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("t%d", i)
		}
		return out
	}
	tests := func(n int) []Test {
		out := make([]Test, n)
		for i := range out {
			out[i] = Test{Command: fmt.Sprintf("echo %d", i)}
		}
		return out
	}
	for _, tc := range []struct {
		name string
		ok   Requirement
		bad  Requirement
	}{
		{"title", Requirement{Title: long(MaxTitleRunes)}, Requirement{Title: long(MaxTitleRunes + 1)}},
		{"details", Requirement{Title: "t", Description: long(MaxDescriptionRunes)},
			Requirement{Title: "t", Description: long(MaxDescriptionRunes + 1)}},
		{"tag count", Requirement{Title: "t", Tags: tags(MaxTags)}, Requirement{Title: "t", Tags: tags(MaxTags + 1)}},
		{"tag length", Requirement{Title: "t", Tags: []string{strings.Repeat("a", MaxTagRunes)}},
			Requirement{Title: "t", Tags: []string{strings.Repeat("a", MaxTagRunes+1)}}},
		{"test count", Requirement{Title: "t", Tests: tests(MaxTests)}, Requirement{Title: "t", Tests: tests(MaxTests + 1)}},
		{"command length", Requirement{Title: "t", Tests: []Test{{Command: strings.Repeat("x", MaxCommandBytes)}}},
			Requirement{Title: "t", Tests: []Test{{Command: strings.Repeat("x", MaxCommandBytes+1)}}}},
		{"test name", Requirement{Title: "t", Tests: []Test{{Name: long(MaxTestNameRunes), Command: "x"}}},
			Requirement{Title: "t", Tests: []Test{{Name: long(MaxTestNameRunes + 1), Command: "x"}}}},
		{"timeout", Requirement{Title: "t", Tests: []Test{{Command: "x", TimeoutSeconds: 7200}}},
			Requirement{Title: "t", Tests: []Test{{Command: "x", TimeoutSeconds: 7201}}}},
		{"size sent to an executor", Requirement{Title: "t", Tests: tests(1)},
			Requirement{Title: "t", Description: long(4000), Tests: func() []Test {
				ts := tests(MaxTests)
				for i := range ts {
					ts[i].Command = strings.Repeat("y", MaxCommandBytes)
				}
				return ts
			}()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, side := range []struct {
				r      Requirement
				accept bool
			}{{tc.ok, true}, {tc.bad, false}} {
				r := side.r
				r.ID, r.Status = 5, StatusApproved
				db := r
				dbErr := db.Normalize()
				_, fileErr := ParseSpecFile([]byte(handWritten(r)))
				if (dbErr == nil) != side.accept || (fileErr == nil) != side.accept {
					t.Errorf("accept=%v: the database said %v, the file %v", side.accept, dbErr, fileErr)
				}
			}
		})
	}

	// A project's worth of requirements, and one more.
	var b strings.Builder
	b.WriteString("version: 1\nrequirements:\n")
	for i := 1; i <= MaxRequirements+1; i++ {
		fmt.Fprintf(&b, "  - {id: R-%d, title: t, status: approved}\n", i)
	}
	if _, err := ParseSpecFile([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "more than the 1000") {
		t.Errorf("1001 requirements: %v", err)
	}
	big := make([]byte, MaxSpecFileBytes+1)
	if _, err := ParseSpecFile(big); err == nil || !strings.Contains(err.Error(), "more than the") {
		t.Errorf("an oversized file: %v", err)
	}
}

// handWritten is r as a person might write it: block style, every field
// spelt out, without going through RenderSpecFile.
func handWritten(r Requirement) string {
	q := func(s string) string { return fmt.Sprintf("%q", s) }
	var b strings.Builder
	fmt.Fprintf(&b, "version: 1\nrequirements:\n  - id: %s\n    title: %s\n    status: %s\n", Key(r.ID), q(r.Title), r.CurrentStatus())
	if r.Description != "" {
		fmt.Fprintf(&b, "    details: %s\n", q(r.Description))
	}
	if len(r.Tags) > 0 {
		b.WriteString("    tags:\n")
		for _, t := range r.Tags {
			fmt.Fprintf(&b, "      - %s\n", q(t))
		}
	}
	if len(r.Tests) > 0 {
		b.WriteString("    tests:\n")
		for _, t := range r.Tests {
			fmt.Fprintf(&b, "      - command: %s\n", q(t.Command))
			if t.Name != "" {
				fmt.Fprintf(&b, "        name: %s\n", q(t.Name))
			}
			if t.TimeoutSeconds > 0 {
				fmt.Fprintf(&b, "        timeout: %ds\n", t.TimeoutSeconds)
			}
		}
	}
	return b.String()
}

func TestSpecFileRoundTrips(t *testing.T) {
	reqs := []Requirement{
		{ID: 9, Title: "true", Status: StatusDraft, Description: "x: y # not a comment"},
		{ID: 2, Title: `Tabs	and "quotes" and #hashes: all kept`, Priority: PriorityShould,
			Tags: []string{"a:b", "c/d", "e.f", "g_h", "ünï"},
			Tests: []Test{
				{Command: "printf 'a\\r\\nb'", Name: "crlf"},
				{Command: "line one  \nline two with trailing spaces above", TimeoutSeconds: 1},
				{Command: "echo \u0085 next line\nand a separator \u2028 here", TimeoutSeconds: 3661},
			}},
		{ID: 40, Title: "null", Status: StatusDeprecated, Description: "- looks like a list\n  indented\n\ttabbed\n~"},
		{ID: 41, Title: "123", Tests: []Test{{Command: "exit 0", TimeoutSeconds: 7200}}},
		{ID: 42, Title: "plain", Description: "\"quoted\"\n'single'\n{flow}: [x]"},
	}
	out, err := RenderSpecFile(reqs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "# What this project must keep doing") {
		t.Errorf("no header:\n%s", out)
	}
	back, err := ParseSpecFile(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	byID := map[int]Requirement{}
	for _, r := range back.Requirements {
		byID[r.ID] = r
	}
	for _, r := range reqs {
		want := r
		if err := want.Normalize(); err != nil {
			t.Fatal(err)
		}
		if got := byID[r.ID]; !SameSpec(got, want) {
			t.Errorf("%s came back\n%+v\nwant\n%+v\n%s", Key(r.ID), got, want, out)
		}
	}
	// Sorted, with the status a requirement without one has.
	if back.Requirements[0].ID != 2 || back.Requirements[0].Status != StatusApproved {
		t.Errorf("first is %+v", back.Requirements[0])
	}
	// Rendering is a function of the requirements alone.
	again, _ := RenderSpecFile([]Requirement{reqs[4], reqs[3], reqs[2], reqs[1], reqs[0]})
	if string(again) != string(out) {
		t.Errorf("rendering depends on the order given:\n%s\n---\n%s", out, again)
	}
	if _, err := RenderSpecFile([]Requirement{{ID: 1, Title: "a"}, {ID: 1, Title: "b"}}); err == nil {
		t.Error("two requirements with one id were rendered")
	}
	if _, err := RenderSpecFile([]Requirement{{ID: 0, Title: "a"}}); err == nil {
		t.Error("a requirement with no id was rendered")
	}
	if _, err := RenderSpecFile([]Requirement{{ID: 1, Title: strings.Repeat("x", MaxTitleRunes+1)}}); err == nil {
		t.Error("a requirement past the bounds was rendered")
	}
	empty, err := RenderSpecFile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := ParseSpecFile(empty); err != nil || len(f.Requirements) != 0 {
		t.Errorf("no requirements: %v %+v\n%s", err, f, empty)
	}
}

func TestSpecFilesOnDisk(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadSpecFile(dir, ""); !errors.Is(err, ErrNoSpecFile) {
		t.Fatalf("no file: %v", err)
	}
	data, err := RenderSpecFile([]Requirement{{ID: 1, Title: "t", Status: StatusApproved}})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSpecFile(dir, "", data); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, SpecFileName))
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("written: %v %v", st, err)
	}
	f, raw, err := LoadSpecFile(dir, "")
	if err != nil || len(f.Requirements) != 1 || string(raw) != string(data) {
		t.Fatalf("read back: %v %+v", err, f)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, ".cloop"))
	if len(entries) != 1 {
		t.Errorf("the write left %d files in .cloop", len(entries))
	}

	// A file that does not parse is still returned, for the hub to parse.
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, raw, err := LoadSpecFile(dir, "bad.yaml"); err == nil || string(raw) != "version: 1\n" {
		t.Errorf("an invalid file: %v %q", err, raw)
	}

	// Inside the project a link may not lead out of it.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.yaml"), []byte("version: 1\nrequirements: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.yaml"), filepath.Join(dir, "linked.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSpecFile(dir, "linked.yaml"); err == nil {
		t.Error("a link out of the project was followed")
	}
	if _, err := ReadSpecFile(dir, "../"+filepath.Base(outside)+"/secret.yaml"); err == nil {
		t.Error("a relative path out of the project was followed")
	}
	// A path a person gave outside the project is read where it is.
	if _, err := ReadSpecFile(dir, filepath.Join(outside, "secret.yaml")); err != nil {
		t.Errorf("an absolute path: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSpecFile(dir, "adir"); err == nil {
		t.Error("a directory was read as a spec file")
	}
	if err := os.WriteFile(filepath.Join(dir, "huge.yaml"), make([]byte, MaxSpecFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSpecFile(dir, "huge.yaml"); err == nil || !errors.Is(err, ErrInvalid) {
		t.Errorf("an oversized file: %v", err)
	}
}

func TestStatusesAreNormalised(t *testing.T) {
	for in, want := range map[string]string{"": "", " Approved ": StatusApproved, "DRAFT": StatusDraft, "deprecated": StatusDeprecated} {
		r := Requirement{Title: "t", Status: in}
		if err := r.Normalize(); err != nil || r.Status != want {
			t.Errorf("%q: %q %v", in, r.Status, err)
		}
	}
	r := Requirement{Title: "t", Status: "retired"}
	if err := r.Normalize(); !errors.Is(err, ErrInvalid) {
		t.Errorf("an unknown status: %v", err)
	}
	if (Requirement{}).CurrentStatus() != StatusApproved {
		t.Error("a requirement with no status is not approved")
	}
	// Status, priority and tags are not what a verdict is about.
	a := Requirement{Title: "t", Status: StatusDraft}
	b := Requirement{Title: "t", Status: StatusApproved, Priority: PriorityMust, Tags: []string{"x"}}
	if a.Fingerprint() != b.Fingerprint() || a.SyncFingerprint() == b.SyncFingerprint() {
		t.Error("the fingerprints do not separate what a verdict is about from what a spec file holds")
	}
	if (Requirement{Title: "t"}).SyncFingerprint() != (Requirement{Title: "t", Status: StatusApproved}).SyncFingerprint() {
		t.Error("no status and approved fingerprint apart")
	}
}
