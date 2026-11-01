package requirements

// fuzz_test.go fuzzes the spec file (Task 20459). ParseSpecFile is what the
// hub runs on whatever an executor sends back as a project's
// .cloop/requirements.yaml, so it must stand any input; and RenderSpecFile is
// what an export writes, so every requirement the database can hold must come
// back from the file exactly as it went in.

import (
	"errors"
	"strings"
	"testing"
)

func FuzzParseSpecFile(f *testing.F) {
	f.Add([]byte(sampleSpec))
	f.Add([]byte("version: 1\nrequirements: []\n"))
	f.Add([]byte("version: 1\nrequirements:\n  - {id: R-1, title: t, status: approved, tags: [a, b], tests: [{command: x, timeout: 1m}]}\n"))
	f.Add([]byte("version: 1\nrequirements:\n  - &a {id: R-1}\n  - *a\n"))
	f.Add([]byte("version: 1\nrequirements:\n  - id: R-1\n    title: [unclosed\n"))
	f.Add([]byte("version: 1\nrequirements:\n  - id: R-1\n    title: t\n    status: draft\n  - id: R-1\n    title: u\n    status: draft\n"))
	f.Add([]byte("version: 1\nrequirements:\n  - id: R-1\n    title: \"a\\u2028b\"\n    status: approved\n    details: |2\n        indented\n      less\n"))
	f.Add([]byte("---\nversion: 1\n...\n---\nx\n"))
	f.Add([]byte("version: 1\nrequirements:\n- {id: R-1, title: t, status: approved, <<: {priority: must}}\n"))
	f.Add([]byte("\xef\xbb\xbfversion: 1\r\nrequirements:\r\n  - id: R-2\r\n    title: crlf\r\n    status: approved\r\n"))
	if out, err := RenderSpecFile([]Requirement{{ID: 4, Title: "rendered", Description: "two\nlines",
		Tests: []Test{{Name: "n", Command: "a\nb", TimeoutSeconds: 61}}}}); err == nil {
		f.Add(out)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := ParseSpecFile(data)
		if err != nil {
			var errs SpecErrors
			if !errors.As(err, &errs) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("a parse failure that is not SpecErrors: %T %v", err, err)
			}
			if len(errs) == 0 || len(errs) > maxSpecErrors+1 {
				t.Fatalf("%d problems reported", len(errs))
			}
			for _, e := range errs {
				if e.Message == "" || e.Line < 0 || e.Column < 0 {
					t.Fatalf("a problem with no message or place: %+v", e)
				}
			}
			return
		}
		seen := map[int]bool{}
		for _, r := range file.Requirements {
			if r.ID <= 0 || seen[r.ID] {
				t.Fatalf("id %d read twice or not at all", r.ID)
			}
			seen[r.ID] = true
			if !ValidStatus(r.Status) {
				t.Fatalf("%s has status %q", Key(r.ID), r.Status)
			}
			again := r
			if err := again.Normalize(); err != nil || !SameSpec(again, r) {
				t.Fatalf("%s was read past the database's bounds: %v", Key(r.ID), err)
			}
		}
		// Whatever was read can be written, and reads back the same.
		out, err := RenderSpecFile(file.Requirements)
		if err != nil {
			t.Fatalf("a file that parsed cannot be exported: %v", err)
		}
		back, err := ParseSpecFile(out)
		if err != nil || len(back.Requirements) != len(file.Requirements) {
			t.Fatalf("the export does not read back: %v\n%s", err, out)
		}
	})
}

func FuzzSpecFileRoundTrip(f *testing.F) {
	f.Add("Config errors exit non-zero", "A malformed config.yaml\nmakes every command exit 2.", "cli",
		"malformed", "go test ./pkg/config", uint16(120), uint8(0), uint8(1))
	f.Add("true", "x: y # not a comment", "a:b", "", "printf 'a\\r\\nb'", uint16(0), uint8(1), uint8(0))
	f.Add("null", "- list\n\tindent\n~", "ünï", "two words", "line  \nnext", uint16(7200), uint8(2), uint8(2))
	f.Add("\"quoted\" 'and' #hash", "\u0085\u2028\ufeff", "x/y", "n", "a\u2029b\nc", uint16(1), uint8(3), uint8(3))
	f.Add("123", "", "", "", "echo", uint16(3661), uint8(0), uint8(0))

	priorities := append([]string{""}, Priorities...)
	statuses := append([]string{""}, Statuses...)
	f.Fuzz(func(t *testing.T, title, details, tag, name, command string, timeout uint16, prio, status uint8) {
		r := Requirement{
			ID: 1 + int(timeout%997), Title: title, Description: details,
			Priority: priorities[int(prio)%len(priorities)], Status: statuses[int(status)%len(statuses)],
		}
		if tag != "" {
			r.Tags = []string{tag, strings.ToUpper(tag) + "-2"}
		}
		if command != "" {
			r.Tests = []Test{{Name: name, Command: command, TimeoutSeconds: int(timeout)}, {Command: command + "\nexit 0"}}
		}
		if err := r.Normalize(); err != nil {
			return // the database would not hold it either
		}
		out, err := RenderSpecFile([]Requirement{r, {ID: r.ID + 1000, Title: "neighbour"}})
		if err != nil {
			t.Fatalf("a requirement the database holds cannot be exported: %v\n%+v", err, r)
		}
		back, err := ParseSpecFile(out)
		if err != nil || len(back.Requirements) != 2 {
			t.Fatalf("the export does not read back: %v\n%s", err, out)
		}
		got := back.Requirements[0]
		want := r
		want.Status = want.CurrentStatus()
		if got.ID != r.ID || !SameSpec(got, want) {
			t.Fatalf("%s came back\n%+v\nwant\n%+v\n%s", Key(r.ID), got, want, out)
		}
	})
}

// FuzzParseDraftAnswer: the model's answer to a draft is untrusted text (Task
// 20462). Whatever it is, reading it must not panic, and every requirement it
// yields is a draft that fits the bounds a person's requirement is held to —
// as is everything the hub keeps of a result an executor sends back.
func FuzzParseDraftAnswer(f *testing.F) {
	f.Add(goodAnswer)
	f.Add("```json\n" + goodAnswer + "\n```")
	f.Add(`{"requirements": [{"title": "x", "status": "approved", "test": "rm -rf /"}]}`)
	f.Add(`{"requirements": [{"title": "a b", "tags": ["A B", "c/d", "é"], "acceptance_criteria": ["", "  x  "]}]}`)
	f.Add(`{"requirements": [], "notes": "` + strings.Repeat("n", 3000) + `"}`)
	f.Add(`{"contradictions": [{"a": "R-1", "b": 2, "why": "w"}]}`)
	f.Fuzz(func(t *testing.T, out string) {
		a, err := ParseDraftAnswer(out)
		if err != nil {
			if !errors.Is(err, ErrNoDraftAnswer) {
				t.Fatalf("a failure that is not ErrNoDraftAnswer: %v", err)
			}
			a = DraftAnswer{}
		}
		res := Drafts(a, nil, 0)
		kept := CheckDraftResult(res, nil, 0)
		if len(kept.Drafts) != len(res.Drafts) {
			t.Fatalf("the hub refused %d of the executor's own drafts: %+v", len(res.Drafts)-len(kept.Drafts), kept.Refused)
		}
		for _, r := range append(res.Drafts, kept.Drafts...) {
			if r.Status != StatusDraft || r.ID != 0 {
				t.Fatalf("a proposal became %+v", r)
			}
			c := r
			if err := c.Normalize(); err != nil {
				t.Fatalf("a draft outside the bounds: %v", err)
			}
		}
		if len(res.Drafts) > MaxDrafts || len(res.Refused) > maxRefusals {
			t.Fatalf("%d drafts, %d refusals", len(res.Drafts), len(res.Refused))
		}
		known := []Requirement{{ID: 1, Title: "a"}, {ID: 2, Title: "b"}}
		if fs, err := ParseContradictions(out, known); err == nil {
			for _, f := range fs {
				if f.ID != 1 && f.ID != 2 || len(f.Others) != 1 || f.Others[0] == f.ID {
					t.Fatalf("a contradiction about what it was not shown: %+v", f)
				}
			}
		}
	})
}
