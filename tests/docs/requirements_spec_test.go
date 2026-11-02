package docs_test

// Every test cloop's own requirements name exists where their commands run it
// (Task 20466).
//
// .cloop/requirements.yaml is the guarantees cloop's documentation makes, each
// pointed at the test that proves it: `go test <dirs> -run '^(TestA|TestB)$'`
// or a make target, run by CI's requirements job through `make
// requirements-check`. A -run pattern that matches nothing is no failure — go
// test says "no tests to run" and exits 0 — so a requirement whose test was
// renamed or deleted would hold from then on, standing on nothing, with a
// command that still looks exactly like evidence. So each name a pattern
// gives has to be a test function declared in a directory its command tests,
// each pattern has to be anchored names (a bare `-run TestX` also runs
// TestXAndMore), each make target a rule of the Makefile, and each
// requirement that is not a draft has to be tested at all: a guarantee is a
// requirement plus a test (CONTRIBUTING.md).

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// specRunPattern is the one shape of -run pattern the spec may give: test
// names, anchored, alone or as an alternation.
var specRunPattern = regexp.MustCompile(`^\^(?:\(((?:Test|Fuzz)[A-Za-z0-9_]+(?:\|(?:Test|Fuzz)[A-Za-z0-9_]+)*)\)|((?:Test|Fuzz)[A-Za-z0-9_]+))\$$`)

// valueFlags are the go test flags that take their value as the next word
// when it is not given with "=".
var valueFlags = map[string]bool{
	"run": true, "skip": true, "timeout": true, "count": true, "cpu": true, "tags": true, "parallel": true,
	"p": true, "bench": true, "benchtime": true, "fuzz": true, "fuzztime": true, "coverprofile": true,
	"covermode": true, "o": true,
}

// shellWords splits a command as /bin/sh does for the commands the spec may
// hold: words, single- and double-quoted strings, backslash escapes. Anything
// that makes it more than one simple command — a pipe, a list, a redirection,
// a substitution, a variable — is refused rather than read wrongly.
func shellWords(cmd string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '\'':
			j := strings.IndexByte(cmd[i+1:], '\'')
			if j < 0 {
				return nil, fmt.Errorf("an unterminated single quote")
			}
			cur.WriteString(cmd[i+1 : i+1+j])
			i += j + 1
			inWord = true
		case c == '"':
			j := i + 1
			for ; j < len(cmd) && cmd[j] != '"'; j++ {
				switch cmd[j] {
				case '\\':
					j++
					if j < len(cmd) {
						cur.WriteByte(cmd[j])
					}
				case '$':
					if j+1 < len(cmd) && cmd[j+1] == '"' {
						// A dollar sign closing the string is itself.
						cur.WriteByte('$')
						continue
					}
					return nil, fmt.Errorf("a substitution in double quotes")
				case '`':
					return nil, fmt.Errorf("a substitution in double quotes")
				default:
					cur.WriteByte(cmd[j])
				}
			}
			if j >= len(cmd) {
				return nil, fmt.Errorf("an unterminated double quote")
			}
			i = j
			inWord = true
		case c == '\\' && i+1 < len(cmd):
			i++
			cur.WriteByte(cmd[i])
			inWord = true
		case c == '$' && (i+1 == len(cmd) || cmd[i+1] == ' ' || cmd[i+1] == '\t'):
			// A dollar sign ending a word is itself, as in -run=^TestX$.
			cur.WriteByte(c)
			inWord = true
		case strings.IndexByte(";&|<>()$`\n#*?[", c) >= 0:
			return nil, fmt.Errorf("%q makes it more than one simple command", string(c))
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

// specCommandProblems is what is wrong with one test command of the spec,
// read from the module at root, and the test names it resolved.
func specCommandProblems(root, cmd string, makefile []byte) (problems []string, resolved int) {
	words, err := shellWords(cmd)
	if err != nil {
		return []string{"it is not one go test or make command: " + err.Error()}, 0
	}
	switch {
	case len(words) == 2 && words[0] == "make":
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(words[1]) + `:`).Match(makefile) {
			return []string{fmt.Sprintf("the Makefile has no target %q", words[1])}, 0
		}
		return nil, 0
	case len(words) >= 2 && words[0] == "go" && words[1] == "test":
	default:
		return []string{"it is neither `go test <dirs> -run '^(TestX|TestY)$'` nor `make <target>`"}, 0
	}

	var dirs, patterns []string
	for i := 2; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "-") {
			dirs = append(dirs, w)
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(w, "-"), "=")
		if !hasValue && valueFlags[name] {
			if i+1 == len(words) {
				return []string{fmt.Sprintf("-%s has no value", name)}, 0
			}
			i++
			value = words[i]
		}
		if name == "run" {
			patterns = append(patterns, value)
		}
	}
	if len(patterns) != 1 {
		problems = append(problems, fmt.Sprintf("it gives -run %d times: give it once, naming the tests", len(patterns)))
	}
	if len(dirs) == 0 {
		problems = append(problems, "it names no package directory")
	}
	declared := map[string]bool{}
	for _, d := range dirs {
		if clean := path.Clean(d); !strings.HasPrefix(d, "./") || strings.Contains(d, "...") ||
			clean == ".." || strings.HasPrefix(clean, "../") {
			problems = append(problems, fmt.Sprintf("%q is not one package directory below the module's root, as ./pkg/x", d))
			continue
		}
		files, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(d), "*_test.go"))
		if len(files) == 0 {
			problems = append(problems, fmt.Sprintf("%s holds no test file", d))
			continue
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			for _, m := range definedTestFunc.FindAllSubmatch(data, -1) {
				declared[string(m[1])] = true
			}
		}
	}
	for _, p := range patterns {
		m := specRunPattern.FindStringSubmatch(p)
		if m == nil {
			problems = append(problems, fmt.Sprintf("-run %q is not anchored test names, as '^(TestX|TestY)$': "+
				"a pattern that matches no test passes, and an unanchored one runs tests it does not name", p))
			continue
		}
		names := m[1]
		if names == "" {
			names = m[2]
		}
		for _, n := range strings.Split(names, "|") {
			if !declared[n] {
				problems = append(problems, fmt.Sprintf("%s is not a test in %s", n, strings.Join(dirs, " ")))
				continue
			}
			resolved++
		}
	}
	return problems, resolved
}

// specProblems is what is wrong with the requirements of sf, each named by
// its key and its test.
func specProblems(root string, sf requirements.SpecFile, makefile []byte) (problems []string, resolved int) {
	for _, r := range sf.Requirements {
		if r.CurrentStatus() == requirements.StatusDraft {
			continue
		}
		if !r.Tested() {
			problems = append(problems, fmt.Sprintf("%s has no test: a guarantee is a requirement plus the test that proves it",
				requirements.Key(r.ID)))
			continue
		}
		for _, t := range r.Tests {
			ps, n := specCommandProblems(root, t.Command, makefile)
			resolved += n
			for _, p := range ps {
				problems = append(problems, fmt.Sprintf("%s, test %q: %s", requirements.Key(r.ID), t.Label(), p))
			}
		}
	}
	return problems, resolved
}

// TestRequirementsCiteOnlyRealTests is the gate.
func TestRequirementsCiteOnlyRealTests(t *testing.T) {
	root := repoRoot(t)
	sf, _, err := requirements.LoadSpecFile(root, requirements.SpecFileName)
	if err != nil {
		t.Fatal(err)
	}
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	// Without a floor the gate passes on a spec that names nothing: 19
	// requirements, 33 go test commands naming 109 tests, when this was
	// written.
	if len(sf.Requirements) < 15 {
		t.Fatalf("only %d requirements in %s; this gate is not seeing the spec it was written for",
			len(sf.Requirements), requirements.SpecFileName)
	}
	problems, resolved := specProblems(root, sf, makefile)
	for _, p := range problems {
		t.Errorf("%s: %s", requirements.SpecFileName, p)
	}
	if resolved < 80 {
		t.Errorf("only %d test names resolved; this gate is not reading the commands it was written for", resolved)
	}
}

// TestRequirementCitationGateCatchesAMissingTest is the gate's falsification
// control: each way a spec can stop pointing at a real test is reported, and
// the real shapes pass.
func TestRequirementCitationGateCatchesAMissingTest(t *testing.T) {
	root := repoRoot(t)
	makefile := []byte("build:\n\tgo build\nchangelog-check:\n\tpython3 x\n")
	cases := []struct {
		cmd  string
		want string // "" for none
	}{
		{`go test ./tests/docs -run '^(TestRequirementsCiteOnlyRealTests|TestRequirementCitationGateCatchesAMissingTest)$'`, ""},
		{`go test ./tests/docs/ -count=1 -timeout 5m -run=^TestRequirementsCiteOnlyRealTests$`, ""},
		{`go test ./tests/docs ./tests/arch -run "^(TestRequirementsCiteOnlyRealTests|TestNoOrphanedPackages)$"`, ""},
		{"make changelog-check", ""},
		{`go test ./tests/docs -run '^TestThisWasRenamed$'`, "TestThisWasRenamed is not a test in ./tests/docs"},
		{`go test ./tests/arch -run '^TestRequirementsCiteOnlyRealTests$'`, "is not a test in ./tests/arch"},
		{`go test ./tests/docs -run TestRequirementsCiteOnlyRealTests`, "is not anchored test names"},
		{`go test ./tests/docs -run '^Test.*$'`, "is not anchored test names"},
		{`go test ./tests/docs`, "it gives -run 0 times"},
		{`go test ./... -run '^TestNoOrphanedPackages$'`, "is not one package directory"},
		{`go test ./no/such/dir -run '^TestX$'`, "./no/such/dir holds no test file"},
		{`go test ./tests/docs -run '^TestX$' | tee log`, "more than one simple command"},
		{`go test ./tests/docs -run "^$(echo TestX)$"`, "a substitution in double quotes"},
		{"make no-such-target", `the Makefile has no target "no-such-target"`},
		{"make build lint", "neither"},
		{"./scripts/check.sh", "neither"},
	}
	for _, c := range cases {
		problems, _ := specCommandProblems(root, c.cmd, makefile)
		got := strings.Join(problems, "; ")
		switch {
		case c.want == "" && got != "":
			t.Errorf("%s: %s", c.cmd, got)
		case c.want != "" && !strings.Contains(got, c.want):
			t.Errorf("%s: problems %q, want one saying %q", c.cmd, got, c.want)
		}
	}

	sf, err := requirements.ParseSpecFile([]byte(`version: 1
requirements:
  - id: R-1
    title: Untested and approved
    status: approved
  - id: R-2
    title: A draft nobody has tested yet
    status: draft
  - id: R-3
    title: Tested
    status: deprecated
    tests:
      - command: go test ./tests/docs -run '^TestGone$'
`))
	if err != nil {
		t.Fatal(err)
	}
	problems, _ := specProblems(root, sf, makefile)
	want := []string{
		"R-1 has no test: a guarantee is a requirement plus the test that proves it",
		`R-3, test "go test ./tests/docs -run '^TestGone$'": TestGone is not a test in ./tests/docs`,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
}
