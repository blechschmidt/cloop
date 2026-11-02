package main

// requirements.go reads what `cloop requirements check --json` prints (Task
// 20466): the report of every requirement the check checked, framed between
// pkg/clijson's markers. Each requirement it found unfulfilled, or could not
// check, is a finding named by its R-<n> — what CI's requirements job fails
// on — pointing at the requirement's line in the spec file, with what its
// failing tests printed last. A frame that holds the command's own failure
// instead is a finding too: one for each problem it names by line, as an
// invalid spec file's are named, or else one for the whole failure.
//
// The report is decoded here rather than with pkg/requirements so that this
// tool keeps building from the standard library alone: it says why a job
// failed, and has to run when the module does not build.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// The frame pkg/clijson's Emit writes around a payload (its BeginMarker and
// EndMarker, which the tests hold these to). encoding/json escapes '<' and
// '>', so no payload can contain either marker.
const (
	frameBegin = "<<<cloop-json:begin>>>"
	frameEnd   = "<<<cloop-json:end>>>"
)

// DefaultSpec is where the repository keeps its requirements, relative to
// the module's root (pkg/requirements.SpecFileName).
const DefaultSpec = ".cloop/requirements.yaml"

// checkReport is the part of a check's report (pkg/requirements.Report) a
// finding states, or the failure a command printed in its place (cmd's
// helperFailure, {"error": "…"}).
type checkReport struct {
	Results []checkResult `json:"results"`
	Error   string        `json:"error"`
}

type checkResult struct {
	RequirementID *int        `json:"requirement_id"`
	Verdict       string      `json:"verdict"`
	Summary       string      `json:"summary"`
	Tests         []checkTest `json:"tests"`
}

type checkTest struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Outcome  string `json:"outcome"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
	Error    string `json:"error"`
}

// outputTail is how many of a failing test's last lines a finding quotes: the
// end of a test's output is what says why it failed, and an annotation is
// clipped at maxBodyLines.
const outputTail = 20

// maxSpecBytes bounds the spec file read for titles and lines, as a spec file
// is bounded (pkg/requirements.MaxSpecFileBytes).
const maxSpecBytes = 2 << 20

// reProblem is one problem of a spec file that does not validate, as cmd's
// specFileErrors names it: path:line:column: message.
var reProblem = regexp.MustCompile(`^\s*([^\s:][^:]*\.ya?ml):(\d+):(\d+): (.+)$`)

// requirementReports adds a finding for every requirement a framed check
// report in data found failing, and for every framed failure.
func (a *analysis) requirementReports(data []byte) {
	for _, payload := range frames(data) {
		var rep checkReport
		if json.Unmarshal(payload, &rep) != nil {
			continue
		}
		if rep.Error != "" && len(rep.Results) == 0 {
			a.framedFailure(rep.Error)
			continue
		}
		for _, r := range rep.Results {
			if r.RequirementID == nil {
				continue
			}
			switch r.Verdict {
			case "unfulfilled", "error":
				a.failedRequirement(*r.RequirementID, r)
			}
		}
	}
}

// frames are the payloads framed in data, in the order they were printed. A
// frame with no end — the command was killed while it printed — is not one.
func frames(data []byte) [][]byte {
	var out [][]byte
	for {
		i := bytes.Index(data, []byte(frameBegin))
		if i < 0 {
			return out
		}
		data = data[i+len(frameBegin):]
		j := bytes.Index(data, []byte(frameEnd))
		if j < 0 {
			return out
		}
		if p := bytes.TrimSpace(data[:j]); len(p) > 0 {
			out = append(out, p)
		}
		data = data[j+len(frameEnd):]
	}
}

// failedRequirement is the finding for one requirement: titled by its key,
// what the check found and, from the spec file, its title.
func (a *analysis) failedRequirement(id int, r checkResult) {
	key := "R-" + strconv.Itoa(id)
	what := key + " is unfulfilled"
	if r.Verdict == "error" {
		what = key + " could not be checked"
	}
	title, line := a.mod.specEntry(key)
	if title != "" {
		what += ": " + title
	}
	body := []string{oneLine(r.Summary)}
	for _, t := range r.Tests {
		if t.Outcome == "pass" {
			continue
		}
		body = append(body, "", "$ "+oneLine(t.Command))
		var status string
		switch {
		case t.Outcome == "fail":
			status = "failed with exit status " + strconv.Itoa(t.ExitCode)
		case t.Outcome == "timeout" && t.Error != "":
			status = oneLine(t.Error)
		case t.Outcome == "timeout":
			status = "timed out"
		case t.Error != "":
			status = "could not run: " + oneLine(t.Error)
		default:
			status = "could not run"
		}
		body = append(body, status)
		body = append(body, lastLines(t.Output, outputTail)...)
	}
	f := finding{kind: kindRequirement, what: what, body: body}
	if line > 0 {
		f.file, f.line = a.mod.spec, line
	}
	a.add(f)
}

// framedFailure is a command's failure, printed framed in place of its report:
// a finding for each problem it names on a line of a YAML file — an invalid
// spec file's — or one for the whole message.
func (a *analysis) framedFailure(msg string) {
	lines := strings.Split(strings.TrimRight(msg, "\n"), "\n")
	found := false
	for _, l := range lines {
		m := reProblem.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		line, _ := strconv.Atoi(m[2])
		col, _ := strconv.Atoi(m[3])
		a.add(finding{kind: kindRequirement, what: m[4], body: []string{strings.TrimSpace(l)},
			file: a.mod.rel(m[1]), line: line, col: col})
		found = true
	}
	if !found {
		a.add(finding{kind: kindRequirement, what: "cloop failed: " + oneLine(lines[0]), body: lines})
	}
}

// specEntry is the title of the requirement key in the module's spec file,
// and the line its id is on: 0 when there is no spec file, or no such
// requirement in it. It reads the file as `cloop requirements export` writes
// it — each requirement a list item opening with its id — and takes a title
// from the same item, wherever in it the key is.
func (m module) specEntry(key string) (title string, line int) {
	if m.spec == "" || m.root == "" {
		return "", 0
	}
	path := m.spec
	if !filepath.IsAbs(path) {
		path = filepath.Join(m.root, path)
	}
	data, err := readBounded(path, maxSpecBytes)
	if err != nil {
		return "", 0
	}
	lines := strings.Split(string(data), "\n")
	reID := regexp.MustCompile(`^(\s*)(-\s+)?id:\s*["']?` + regexp.QuoteMeta(key) + `["']?\s*(#.*)?$`)
	reItem := regexp.MustCompile(`^\s*-\s`)
	reTitle := regexp.MustCompile(`^\s*(?:-\s+)?title:\s*(.*?)\s*$`)
	for i, l := range lines {
		if !reID.MatchString(l) {
			continue
		}
		// The item runs from its "- " line, at or above the id, to the next.
		start := i
		for start > 0 && !reItem.MatchString(lines[start]) {
			start--
		}
		for j := start; j < len(lines); j++ {
			if j > start && reItem.MatchString(lines[j]) {
				break
			}
			if t := reTitle.FindStringSubmatch(lines[j]); t != nil {
				return unquoteYAML(t[1]), i + 1
			}
		}
		return "", i + 1
	}
	return "", 0
}

// rel names path relative to the module's root when it is under it, as an
// annotation's file must be.
func (m module) rel(path string) string {
	if m.root == "" || !filepath.IsAbs(path) {
		return filepath.ToSlash(path)
	}
	if r, err := filepath.Rel(m.root, path); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return filepath.ToSlash(path)
}

// unquoteYAML undoes the quoting of a one-line YAML scalar, as far as a title
// needs: a double-quoted one's escapes, a single-quoted one's doubled quote.
func unquoteYAML(s string) string {
	switch {
	case len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"':
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s[1 : len(s)-1]
	case len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'':
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// lastLines are the last n lines of s, with a line saying how many came
// before them.
func lastLines(s string, n int) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	ls := strings.Split(s, "\n")
	if len(ls) <= n {
		return ls
	}
	return append([]string{fmt.Sprintf("… %d earlier lines …", len(ls)-n)}, ls[len(ls)-n:]...)
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", path, limit)
	}
	return os.ReadFile(path)
}
