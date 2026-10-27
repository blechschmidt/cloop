package main

// The recordings in testdata/recorded are what go1.26.10 printed for the
// fixture packages in testdata/red, which fail every way this tool reads —
// with paths rewritten to a GitHub runner's checkout and toolchain, so that
// anchoring is shown working on output recorded on another machine:
//
//	go test -race -timeout 5s ./scripts/ci-annotate/testdata/red/...        > red.txt
//	go test -race -v -timeout 5s ./scripts/ci-annotate/testdata/red/...     > red-v.txt
//	go test -race -json -timeout 5s ./scripts/ci-annotate/testdata/red/...  > red.json
//	go vet ./scripts/ci-annotate/testdata/red/vetted/ ./scripts/ci-annotate/testdata/red/failing/ > vet.txt
//	go build ./scripts/ci-annotate/testdata/red/broken/                      > build.txt
//	go test [-v|-json] ./scripts/ci-annotate/testdata/red/passing/           > passing{.txt,-v.txt,.json}
//
// (all 2>&1). tests/ciscripts runs the fixtures with the toolchain at hand
// and checks this tool still reads them the same way.
//
// None of these tests prints a recorded line or an emitted command as it
// is: on a runner, a line that starts with "::error" — after any leading
// whitespace — becomes an annotation, so failures print them quoted.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const red = "scripts/ci-annotate/testdata/red/"

// want is what one finding must say.
type want struct {
	kind   kind
	pkg    string // the package's directory below red
	test   string
	what   string // for anything but a test
	file   string // below red; "" for no anchor
	line   int
	saying string // a line of its body contains this
}

// redWant is every finding the fixtures' output holds, in rank order but for
// the two parallel tests, whose order is the order they finished in.
var redWant = []want{
	{kindBuild, "missing", "", "setup failed", "missing/missing_test.go", 8, "no required module provides package"},
	{kindBuild, "broken", "", "build failed", "broken/broken.go", 6, "undefined: sum"},
	{kindBuild, "vetted", "", "vet failed", "vetted/vetted_test.go", 12, `fmt.Printf format %d has arg "seven" of wrong type string`},
	{kindPanic, "panicking", "TestPanics", "panic: runtime error: invalid memory address or nil pointer dereference",
		"panicking/panicking_test.go", 9, "panicking.cpuLimit"},
	{kindTimeout, "slow", "TestHangs/waiting_on_the_store", "test timed out after 5s", "slow/slow_test.go", 12,
		"TestHangs/waiting_on_the_store (5s)"},
	{kindRace, "racy", "TestRace", "data race in racy.(*counter).inc", "racy/racy_test.go", 12, "Previous write at 0x"},
	{kindTest, "failing", "TestAssertion", "", "failing/failing_test.go", 16, "2+2 = 4, want 5"},
	{kindTest, "failing", "TestFatal", "", "failing/failing_test.go", 21, "after 3 attempts"},
	{kindTest, "failing", "TestNested/fails", "", "failing/failing_test.go", 27, "the leaf failed"},
	{kindTest, "failing", "TestNested/deeper/still_deeper", "", "failing/failing_test.go", 31, "two levels down"},
	{kindTest, "failing", "TestLongLog", "", "failing/failing_test.go", 50, "the failure after eighty lines"},
	{kindTest, "failing", "TestHostileMessage", "", "failing/failing_test.go", 56, "::error file=injected.go,line=1::an injected annotation"},
	{kindTest, "failing", "TestParallelOne", "", "failing/failing_test.go", 38, "one of two parallel failures"},
	{kindTest, "failing", "TestParallelTwo", "", "failing/failing_test.go", 43, "two of two parallel failures"},
	{kindPackage, "exits", "", "failed outside any test", "", 0, "the fixture's server did not shut down"},
}

func recorded(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "recorded", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testModule(t *testing.T) module {
	t.Helper()
	m := findModule("")
	if m.root == "" || m.path == "" {
		t.Fatalf("no module above the test's directory: %+v", m)
	}
	return m
}

func (w want) String() string {
	return fmt.Sprintf("%d %s %s %q", w.kind, w.pkg, w.test, w.what)
}

// check compares findings with wants, in order, but for the order of the
// findings within each run of wants that compare equal under loose.
func check(t *testing.T, mod module, got []finding, wants []want) {
	t.Helper()
	got = rank(got)
	if len(got) != len(wants) {
		var names []string
		for _, f := range got {
			names = append(names, fmt.Sprintf("%d %s %s %q", f.kind, mod.short(f.pkg), f.test, f.what))
		}
		t.Fatalf("%d findings, want %d:\n%s", len(got), len(wants), strings.Join(names, "\n"))
	}
	var unmatched []want
	unmatched = append(unmatched, wants...)
	for i, f := range got {
		j := slices.IndexFunc(unmatched, func(w want) bool {
			return w.kind == f.kind && red+w.pkg == mod.short(f.pkg) && w.test == f.test
		})
		if j < 0 {
			t.Errorf("finding %d is not wanted: %d %s %s %q", i, f.kind, mod.short(f.pkg), f.test, f.what)
			continue
		}
		w := unmatched[j]
		unmatched = slices.Delete(unmatched, j, j+1)
		if f.kind != kindTest && f.what != w.what {
			t.Errorf("%v: what = %q", w, f.what)
		}
		wantFile := ""
		if w.file != "" {
			wantFile = red + w.file
		}
		if f.file != wantFile || f.line != w.line {
			t.Errorf("%v: points at %s:%d, want %s:%d", w, f.file, f.line, wantFile, w.line)
		}
		if !slices.ContainsFunc(f.body, func(l string) bool { return strings.Contains(l, w.saying) }) {
			t.Errorf("%v: no line of its body says %q:\n%q", w, w.saying, f.body)
		}
		if i > 0 && got[i-1].kind > f.kind {
			t.Errorf("finding %d (%v) ranks after a lesser one", i, w)
		}
	}
	for _, w := range unmatched {
		t.Errorf("missing: %v", w)
	}
}

// TestRecordedFailures: every way the fixtures fail is one finding, the same
// from go test's plain output, its -v output and its -json, each naming its
// package and test and pointing at the line that failed: a setup, build and
// vet failure; a panic, by its top frames below the runtime's; a timeout, by
// the tests still running; a data race, by both stacks and the test; each
// failing test, the leaves of nested subtests rather than their parents; and
// a package that failed when none of its tests did.
func TestRecordedFailures(t *testing.T) {
	mod := testModule(t)
	for _, name := range []string{"red.txt", "red-v.txt", "red.json"} {
		t.Run(name, func(t *testing.T) {
			check(t, mod, analyze(mod, name, 0, recorded(t, name)), redWant)
		})
	}
}

// TestRecordedVetAndBuild: go vet and go build on their own — vet prints its
// findings with no "# pkg" header, so the package is the file's directory.
func TestRecordedVetAndBuild(t *testing.T) {
	mod := testModule(t)
	vet := analyze(mod, "vet.txt", 0, recorded(t, "vet.txt"))
	if len(vet) != 1 || vet[0].what != "vet failed" || vet[0].source != red+"vetted" ||
		vet[0].file != red+"vetted/vetted_test.go" || vet[0].line != 12 || vet[0].col != 14 {
		t.Errorf("go vet: %+v", vet)
	}
	build := analyze(mod, "build.txt", 0, recorded(t, "build.txt"))
	check(t, mod, build, []want{redWant[1]})
	if build[0].col != 38 {
		t.Errorf("go build: column %d, want 38", build[0].col)
	}
}

// TestPassingOutputSaysNothing: a green step's output, in every format,
// gives no annotation and no summary — though it says FAIL, panic: and ---
// FAIL in its logs.
func TestPassingOutputSaysNothing(t *testing.T) {
	for _, name := range []string{"passing.txt", "passing-v.txt", "passing.json"} {
		t.Run(name, func(t *testing.T) {
			summary := filepath.Join(t.TempDir(), "summary.md")
			out, errOut, code := invoke(t, nil, "-summary", summary, filepath.Join("testdata", "recorded", name))
			if code != 0 || out != "" || errOut != "" {
				t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
			}
			if _, err := os.Stat(summary); !os.IsNotExist(err) {
				t.Errorf("a summary was written: %v", err)
			}
		})
	}
}

// invoke runs the command as main does, with env as its environment.
func invoke(t *testing.T, env map[string]string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut strings.Builder
	code = run(args, &out, &errOut, func(k string) string { return env[k] })
	return out.String(), errOut.String(), code
}

// command is a workflow command as GitHub's runner reads one.
type parsed struct {
	name  string
	props map[string]string
	data  string
}

// parseCommand reads a line as actions/runner's ActionCommand.TryParseV2
// does: leading whitespace trimmed, "::name props::data", the properties
// split on ',' and each on its first '=', then both unescaped.
func parseCommand(line string) (parsed, bool) {
	line = strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(line, "::") {
		return parsed{}, false
	}
	end := strings.Index(line[2:], "::")
	if end < 0 {
		return parsed{}, false
	}
	info, data := line[2:2+end], line[2+end+2:]
	name, props, _ := strings.Cut(info, " ")
	p := parsed{name: name, props: map[string]string{}, data: unescapeData(data)}
	for _, kv := range strings.Split(props, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && k != "" && v != "" {
			p.props[k] = unescapeProperty(v)
		}
	}
	return p, true
}

func unescapeData(s string) string {
	return strings.NewReplacer("%0D", "\r", "%0A", "\n", "%25", "%").Replace(s)
}

func unescapeProperty(s string) string {
	return strings.NewReplacer("%0D", "\r", "%0A", "\n", "%3A", ":", "%2C", ",", "%25", "%").Replace(s)
}

// TestEscaping: what an annotation carries comes back as it was, through the
// runner's own parsing — a percent sign, a carriage return, lines that are
// themselves workflow commands, and a title with the ':' and ',' that end a
// property — and nothing in it starts a second command.
func TestEscaping(t *testing.T) {
	for in, want := range map[string]string{
		"100%":        "100%25",
		"a\r\nb":      "a%0D%0Ab",
		"%0A":         "%250A",
		"x::error::y": "x::error::y",
	} {
		if got := escapeData(in); got != want {
			t.Errorf("escapeData(%q) = %q, want %q", in, got, want)
		}
	}
	if got := escapeProperty("a: b, 100%"); got != "a%3A b%2C 100%25" {
		t.Errorf("escapeProperty = %q", got)
	}

	title := "pkg/x: TestA, TestB: 100% red"
	body := []string{"100% sure: \r", "::error file=injected.go,line=1::an injected annotation", "::warning::with %0A in it"}
	line := command("error", finding{title: title, body: body, file: "pkg/x/x_test.go", line: 7})
	if strings.ContainsAny(line, "\r\n") {
		t.Fatalf("the command spans lines: %q", line)
	}
	p, ok := parseCommand(line)
	if !ok || p.name != "error" {
		t.Fatalf("the runner would not read %q as an error", line)
	}
	if p.props["title"] != title || p.props["file"] != "pkg/x/x_test.go" || p.props["line"] != "7" {
		t.Errorf("properties = %q", p.props)
	}
	if p.data != strings.Join(body, "\n") {
		t.Errorf("message = %q, want %q", p.data, strings.Join(body, "\n"))
	}

	// The fixture's own hostile message, through a whole run.
	mod := testModule(t)
	var hostile finding
	for _, f := range analyze(mod, "red.txt", 0, recorded(t, "red.txt")) {
		if f.test == "TestHostileMessage" {
			hostile = f
		}
	}
	p, ok = parseCommand(command("error", hostile))
	if !ok || !strings.Contains(p.data, "100% sure: \r\n    ::error file=injected.go,line=1::an injected annotation") ||
		!strings.Contains(p.data, "::warning::another, with %0A in it") {
		t.Errorf("the hostile message came back as %q", p.data)
	}
}

// TestCleaning: terminal colours and control characters do not reach an
// annotation, and invalid UTF-8 is replaced rather than passed on.
func TestCleaning(t *testing.T) {
	if got := clean("\x1b[31mred\x1b[0m \x00\x07tab\there\r \xff"); got != "red \uFFFD\uFFFDtab\there\r \uFFFD" {
		t.Errorf("clean = %q", got)
	}
}

// failingLog is plain go test output with n failing tests in one package,
// and a package after it that did not build.
func failingLog(n int) []byte {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "--- FAIL: TestNumber%02d (0.00s)\n    x_test.go:%d: number %d failed\n", i, i, i)
	}
	b.WriteString("FAIL\nFAIL\texample.com/m/many\t0.01s\n")
	b.WriteString("# example.com/m/broken\nbroken/x.go:3:9: undefined: y\nFAIL\texample.com/m/broken [build failed]\n")
	return []byte(b.String())
}

// annotations runs the command and parses what it emitted.
func annotations(t *testing.T, env map[string]string, args ...string) []parsed {
	t.Helper()
	out, errOut, code := invoke(t, env, args...)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errOut)
	}
	var ps []parsed
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if l == "" {
			continue
		}
		p, ok := parseCommand(l)
		if !ok {
			t.Fatalf("not a workflow command: %q", l)
		}
		ps = append(ps, p)
	}
	return ps
}

// TestCapsNeverHideTheFirstCause: GitHub keeps ten annotations of a level a
// step. Twenty-five failing tests and a package that did not build — printed
// after them — make nine annotations, the build failure first, and a tenth
// that names the other seventeen; one left makes one annotation that is the
// build failure and names the rest; none left makes none, and the summary
// still has all twenty-six.
func TestCapsNeverHideTheFirstCause(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "go-test.txt")
	if err := os.WriteFile(log, failingLog(25), 0o644); err != nil {
		t.Fatal(err)
	}

	ps := annotations(t, nil, "-summary", "", log)
	if len(ps) != 10 {
		t.Fatalf("%d annotations, want 10", len(ps))
	}
	if !strings.Contains(ps[0].props["title"], "example.com/m/broken: build failed") {
		t.Errorf("the first annotation is %q, not the build failure", ps[0].props["title"])
	}
	if ps[1].props["title"] != "example.com/m/many TestNumber01" {
		t.Errorf("the second annotation is %q", ps[1].props["title"])
	}
	fold := ps[9]
	if !strings.Contains(fold.props["title"], "17 more") || !strings.Contains(fold.data, "TestNumber09") ||
		!strings.Contains(fold.data, "TestNumber25") {
		t.Errorf("the last annotation does not fold the other 17: %q / %q", fold.props["title"], fold.data)
	}

	ps = annotations(t, nil, "-summary", "", "-max", "1", log)
	if len(ps) != 1 || !strings.Contains(ps[0].props["title"], "build failed") ||
		!strings.Contains(ps[0].data, "undefined: y") || !strings.Contains(ps[0].data, "25 more:") {
		t.Errorf("with room for one: %q", ps)
	}

	summary := filepath.Join(dir, "summary.md")
	ps = annotations(t, nil, "-summary", summary, "-max", "0", log)
	if len(ps) != 0 {
		t.Errorf("with no room left: %d annotations", len(ps))
	}
	md, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(md), "<details>"); n != 26 {
		t.Errorf("the summary has %d findings, want all 26", n)
	}
}

// TestInStepBudget: a step that annotates its own output (CI_WHY_STEP_DIR
// set by scripts/ci-step.sh) leaves GitHub's cap what the step has already
// used, and marks the step annotated so the job's last step leaves it be.
func TestInStepBudget(t *testing.T) {
	steps := t.TempDir()
	step := filepath.Join(steps, "003")
	if err := os.MkdirAll(step, 0o755); err != nil {
		t.Fatal(err)
	}
	// Eight errors already, one of them indented as a test would print it.
	var log strings.Builder
	for i := 0; i < 7; i++ {
		fmt.Fprintf(&log, "::error::the step's own complaint %d\n", i)
	}
	log.WriteString("        ::error file=a.go::from a test's output\n::warning::not an error\n")
	if err := os.WriteFile(filepath.Join(step, "log"), []byte(log.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(steps, "go-test.json")
	if err := os.WriteFile(input, recorded(t, "red.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	ps := annotations(t, map[string]string{"CI_WHY_STEP_DIR": step}, "-summary", "", input)
	if len(ps) != 2 || !strings.Contains(ps[0].props["title"], "missing: setup failed") ||
		!strings.Contains(ps[1].props["title"], "14 more") {
		var titles []string
		for _, p := range ps {
			titles = append(titles, p.props["title"])
		}
		t.Errorf("with two left: %q", titles)
	}
	if b, err := os.ReadFile(filepath.Join(step, "annotated")); err != nil || strings.TrimSpace(string(b)) != "2" {
		t.Errorf("annotated marker: %q, %v", b, err)
	}
}

// writeStep records a step as scripts/ci-step.sh does. status "" is a step
// that was killed.
func writeStep(t *testing.T, dir string, n int, script, log, status string) string {
	t.Helper()
	step := filepath.Join(dir, fmt.Sprintf("%03d", n))
	if err := os.MkdirAll(step, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"script": script, "log": log}
	if status != "" {
		files["status"] = status + "\n"
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(step, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return step
}

// TestStepsAnnotatesFailedSteps: the job's last step annotates each failed
// step once, the first first — by its go output when it has any, by its last
// lines when it has not, as killed when it never finished — and leaves alone
// the steps that passed, the one that annotated itself, and itself.
func TestStepsAnnotatesFailedSteps(t *testing.T) {
	dir := t.TempDir()
	writeStep(t, dir, 1, "set -euo pipefail\ngo build ./...\n", "::warning::a warning of its own\n", "0")
	writeStep(t, dir, 2, "go vet ./...\n", string(recorded(t, "vet.txt")), "1")
	var lines strings.Builder
	for i := 1; i <= 100; i++ {
		fmt.Fprintf(&lines, "terraform line %d\n", i)
	}
	writeStep(t, dir, 3, "# Validate the modules.\nset -e\nmake terraform-test \\\n  TF=terraform\n", lines.String(), "2")
	writeStep(t, dir, 4, "sleep 1000\n", "started\n", "")
	self := writeStep(t, dir, 5, "go test ./tests/security/\n", "--- FAIL: TestX (0.00s)\nFAIL\tx\t0.1s\n", "1")
	if err := os.WriteFile(filepath.Join(self, "annotated"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current := writeStep(t, dir, 6, "bash scripts/ci-step.sh --why\n", "", "")

	summary := filepath.Join(t.TempDir(), "summary.md")
	ps := annotations(t, map[string]string{"CI_WHY_STEP_DIR": current}, "-summary", summary, "-steps", dir)
	var titles []string
	for _, p := range ps {
		titles = append(titles, p.props["title"])
	}
	want := []string{
		red + "vetted: vet failed",
		"A step exited 2: make terraform-test",
		"A step was killed before it finished (its timeout-minutes, or a cancelled run): sleep 1000",
	}
	if !slices.Equal(titles, want) {
		t.Fatalf("titles %q, want %q", titles, want)
	}
	tail := strings.Split(ps[1].data, "\n")
	if len(tail) != 40 || tail[0] != "terraform line 61" || tail[39] != "terraform line 100" {
		t.Errorf("the failed step's last 40 lines are %d lines, %q … %q", len(tail), tail[0], tail[len(tail)-1])
	}
	md, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"| 2 | 1 | `go vet ./...` |", "| 3 | 2 | `make terraform-test` |", "| 4 | killed | `sleep 1000` |",
		"| 5 | 1 | `go test ./tests/security/` (it annotated its own failure) |"} {
		if !strings.Contains(string(md), s) {
			t.Errorf("the summary does not list %q:\n%s", s, md)
		}
	}
}

// TestStepsKeepWithinTheJobCap: GitHub keeps fifty annotations a job. What
// the job's steps emitted themselves — at most ten of each level a step — and
// the line GitHub adds for each failed step are spent before this runs.
func TestStepsKeepWithinTheJobCap(t *testing.T) {
	dir := t.TempDir()
	noisy := strings.Repeat("::warning::pull attempt failed\n", 12) + strings.Repeat("::notice::fine\n", 3)
	for n := 1; n <= 4; n++ {
		writeStep(t, dir, n, "echo\n", noisy, "0") // 13 each: 10 warnings kept, 3 notices
	}
	writeStep(t, dir, 5, "go test ./...\n", string(failingLog(25)), "1")
	// 50 - 1 (set-up) - 4×13 would be negative; three steps leave 50-1-39-1 = 9.
	if err := os.RemoveAll(filepath.Join(dir, "004")); err != nil {
		t.Fatal(err)
	}
	ps := annotations(t, nil, "-summary", "", "-steps", dir)
	if len(ps) != 9 || !strings.Contains(ps[8].props["title"], "18 more") {
		t.Errorf("%d annotations, the last %q; want 9, folding 18", len(ps), ps[len(ps)-1].props["title"])
	}
}

// TestSummaryFences: an excerpt holding a code fence of its own cannot close
// the summary's, and a title cannot open HTML.
func TestSummaryFences(t *testing.T) {
	summary := filepath.Join(t.TempDir(), "summary.md")
	r := &reporter{opts: options{level: "error", stepMax: 10, jobMax: 50, summary: summary}, out: &strings.Builder{}, log: &strings.Builder{}}
	r.findings = []finding{{kind: kindTest, test: "TestMarkdown", pkg: "example.com/m/p",
		body: []string{"```", "<script>", "````go"}}}
	r.emit(10)
	md, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "`````text\n```\n<script>\n````go\n`````") {
		t.Errorf("the excerpt's fence:\n%s", md)
	}
	if got := fenceFor("no ticks"); got != "```" {
		t.Errorf("fenceFor = %q", got)
	}
	if got := code("a|b`c"); got != "``a\\|b`c``" {
		t.Errorf("code = %q", got)
	}
}

// TestFirstCommand names a step by its script's first line that does
// something.
func TestFirstCommand(t *testing.T) {
	dir := t.TempDir()
	for script, want := range map[string]string{
		"# why\n\nset -euo pipefail\nshopt -s nullglob\n  go test ./... \\\n -v\n": "go test ./...",
		"":                       "(an empty script)",
		strings.Repeat("x", 100): strings.Repeat("x", 79) + "…",
		"setup-thing --flag\n":   "setup-thing --flag",
	} {
		p := filepath.Join(dir, "script")
		if err := os.WriteFile(p, []byte(script), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := firstCommand(p); got != want {
			t.Errorf("firstCommand(%q) = %q, want %q", script, got, want)
		}
	}
	if got := firstCommand(filepath.Join(dir, "absent")); got != "(the script was not recorded)" {
		t.Errorf("an absent script: %q", got)
	}
}

// TestNeverDecidesAVerdict: an input that cannot be read is reported and
// skipped, with exit status 0; only a command line it cannot use exits 2.
func TestNeverDecidesAVerdict(t *testing.T) {
	if _, errOut, code := invoke(t, nil, "-summary", "", filepath.Join(t.TempDir(), "absent.log")); code != 0 ||
		!strings.Contains(errOut, "absent.log") {
		t.Errorf("an absent input: exit %d, %q", code, errOut)
	}
	for _, args := range [][]string{{}, {"-level", "fatal", "x"}, {"-steps", "d", "x"}} {
		if _, _, code := invoke(t, nil, args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
}

// TestModuleFile: a frame recorded on another machine points into this
// checkout by the longest tail of its path that names a file here.
func TestModuleFile(t *testing.T) {
	mod := testModule(t)
	for in, want := range map[string]string{
		"/home/runner/work/cloop/cloop/scripts/ci-annotate/main.go":  "scripts/ci-annotate/main.go",
		filepath.Join(mod.root, "go.mod"):                            "go.mod",
		"scripts/ci-annotate/./main.go":                              "scripts/ci-annotate/main.go",
		"/opt/hostedtoolcache/go/1.26.10/x64/src/testing/testing.go": "",
		"../outside.go":      "",
		"/elsewhere/main.go": "",
	} {
		got, ok := mod.file(in)
		if got != want || ok != (want != "") {
			t.Errorf("file(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if got := mod.short(mod.path + "/pkg/ui"); got != "pkg/ui" {
		t.Errorf("short = %q", got)
	}
	if got := mod.short("example.com/other"); got != "example.com/other" {
		t.Errorf("short(outside) = %q", got)
	}
}

// TestRaceOutsideATest: a race in a log that is not go test's — a hub
// member's, under -race — is reported by the input's name.
func TestRaceOutsideATest(t *testing.T) {
	mod := testModule(t)
	data := recorded(t, "red.txt")
	start := strings.Index(string(data), raceRule+"\nWARNING: DATA RACE")
	end := strings.Index(string(data[start+1:]), raceRule+"\n--- FAIL") + start + 1 + len(raceRule)
	member := "hub listening on :8080\n" + string(data[start:end]) + "\nhub stopped\n"
	fs := analyze(mod, "member-2.log", 0, []byte(member))
	if len(fs) != 1 || fs[0].kind != kindRace || fs[0].pkg != "" || fs[0].test != "TestRace" {
		t.Fatalf("findings: %+v", fs)
	}
	r := &reporter{mod: mod}
	if got := r.entitle(fs[0]); got != "member-2.log TestRace: data race in racy.(*counter).inc" {
		t.Errorf("title = %q", got)
	}
}

// TestSyntheticShapes covers shapes the fixtures do not print: a parent
// test with a complaint of its own beside its failing subtest, a package
// that failed to build for want of another, a fatal error, a test binary the
// go command killed, and test2json splitting a long line.
func TestSyntheticShapes(t *testing.T) {
	mod := testModule(t)
	cases := []struct {
		name  string
		input string
		want  []string // "kind test what"
	}{{
		"a parent's own complaint",
		"--- FAIL: TestParent (0.00s)\n    x_test.go:20: the parent's own\n    --- FAIL: TestParent/child (0.00s)\n" +
			"        x_test.go:10: the child's\nFAIL\nFAIL\texample.com/m/p\t0.01s\n",
		[]string{"4 TestParent ", "4 TestParent/child "},
	}, {
		"dependents of a broken package",
		"# example.com/m/a\na/a.go:1:1: undefined: z\nFAIL\texample.com/m/a [build failed]\nFAIL\texample.com/m/b [build failed]\n",
		[]string{"0  build failed"},
	}, {
		"a fatal error",
		"fatal error: concurrent map writes\n\ngoroutine 9 [running]:\nruntime.throw({0x1, 0x2})\n\t/go/src/runtime/panic.go:1 +0x1\n" +
			"example.com/m/p.TestMaps.func1()\n\t/w/p/p_test.go:9 +0x1\nFAIL\texample.com/m/p\t0.1s\n",
		[]string{"1 TestMaps fatal error: concurrent map writes"},
	}, {
		"a panic in a goroutine, after another test failed",
		"--- FAIL: TestEarlier (0.00s)\n    x_test.go:5: an earlier failure\npanic: from a goroutine\n\ngoroutine 12 [running]:\n" +
			"example.com/m/p.TestLater.func1()\n\t/w/p/p_test.go:20 +0x1\ncreated by example.com/m/p.TestLater in goroutine 7\n" +
			"\t/w/p/p_test.go:18 +0x1\nFAIL\texample.com/m/p\t0.1s\n",
		[]string{"1 TestLater panic: from a goroutine", "4 TestEarlier "},
	}, {
		"a binary the go command killed",
		"=== RUN   TestSlow\n*** Test killed with quit: ran too long (11m0s).\nFAIL\texample.com/m/p\t660.0s\n",
		[]string{"2  *** Test killed with quit: ran too long (11m0s)."},
	}, {
		"a long line split by test2json",
		`{"Action":"output","Package":"example.com/m/p","Test":"TestLong","Output":"--- FAIL: TestLong (0.00s)\n"}` + "\n" +
			`{"Action":"output","Package":"example.com/m/p","Test":"TestLong","Output":"    x_test.go:3: aaaa"}` + "\n" +
			`{"Action":"output","Package":"example.com/m/p","Test":"TestLong","Output":"bbbb\n"}` + "\n" +
			`{"Action":"fail","Package":"example.com/m/p","Test":"TestLong"}` + "\n" +
			`{"Action":"output","Package":"example.com/m/p","Output":"FAIL\texample.com/m/p\t0.1s\n"}` + "\n",
		[]string{"4 TestLong "},
	}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, f := range rank(analyze(mod, "input", 0, []byte(c.input))) {
				got = append(got, strconv.Itoa(int(f.kind))+" "+f.test+" "+f.what)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
	// The dependents are named under the failure that explains them, and the
	// split line comes back whole.
	fs := analyze(mod, "input", 0, []byte(cases[1].input))
	if !slices.Contains(fs[0].body, "  example.com/m/b") {
		t.Errorf("the dependent is not named: %q", fs[0].body)
	}
	fs = analyze(mod, "input", 0, []byte(cases[5].input))
	if !slices.Contains(fs[0].body, "x_test.go:3: aaaabbbb") {
		t.Errorf("the split line: %q", fs[0].body)
	}
}
