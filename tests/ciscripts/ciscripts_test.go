// Package ciscripts_test tests the scripts CI's test jobs are made of (Task
// 20414): pkg/ui's split into shard jobs and the gate that puts every test in
// exactly one of them, the time budget every package is held to, the merge
// that puts the shards' coverage back together, and the race step's
// --without.
//
// The scripts run as CI runs them, as processes, against a fixture package in
// testdata. Where a guarantee rests on a gate failing, the gate is shown
// failing: test-shards.py's check is run with its regex builder broken two
// ways, and has to refuse both.
package ciscripts_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// fixture is the package the shard tests split, as the scripts take it.
const fixture = "./tests/ciscripts/testdata/shardfixture/"

func TestMain(m *testing.M) {
	// Read before Isolate moves HOME: Go's build and module caches default to
	// directories under it, and the scripts' go commands would otherwise
	// start from empty ones.
	goEnv = captureGoEnv()
	os.Exit(hometest.Isolate(m))
}

var goEnv []string

func captureGoEnv() []string {
	names := []string{"GOCACHE", "GOMODCACHE", "GOPATH"}
	out, err := exec.Command("go", append([]string{"env"}, names...)...).Output()
	if err != nil {
		return nil
	}
	var env []string
	for i, v := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if i < len(names) && v != "" {
			env = append(env, names[i]+"="+v)
		}
	}
	return env
}

// repoRoot is the module root, where the scripts expect to be run from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}

// run runs a command from the repository root and returns its stdout, its
// stderr and its exit code. A command that could not start fails the test.
func run(t *testing.T, name string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), goEnv...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return out.String(), errb.String(), code
}

func python(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	return p
}

// writeTable writes a duration table and returns its path.
func writeTable(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "durations.txt")
	body := "# a table for " + fixture + "\n" + strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// fixtureTable hands the most time to TestSlowA, B and C, so that longest
// first gives one to each of three shards; then TestStop to the third shard
// and TestStopAll to the second, which puts the prefix pair in different
// shards. TestGone is not a test the fixture has.
func fixtureTable(t *testing.T) string {
	return writeTable(t,
		"100 TestSlowA", "90 TestSlowB", "80 TestSlowC",
		"75 TestStop", "74 TestStopAll", "1.5 TestSignPositive",
		"0.2 FuzzDouble", "0.1 ExampleDouble", "50 TestGone")
}

// listed is what `go test -list pattern` names in the fixture.
func listed(t *testing.T, pattern string) []string {
	t.Helper()
	out, errOut, code := run(t, "go", "test", "-list", pattern, fixture)
	if code != 0 {
		t.Fatalf("go test -list: exit %d\n%s%s", code, out, errOut)
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if regexp.MustCompile(`^(Test|Fuzz|Example|Benchmark)\w*$`).MatchString(line) {
			names = append(names, line)
		}
	}
	return names
}

// shardRegex is test-shards.py's -run regex for one of three shards.
func shardRegex(t *testing.T, table string, shards, shard int) string {
	t.Helper()
	out, errOut, code := run(t, python(t), "scripts/test-shards.py", fixture,
		"--shards", fmt.Sprint(shards), "--table", table, "regex", fmt.Sprint(shard))
	if code != 0 {
		t.Fatalf("test-shards.py regex %d: exit %d\n%s%s", shard, code, out, errOut)
	}
	return strings.TrimSpace(out)
}

// hashShard is the shard, from 1, test-shards.py places a test the table
// does not name in: the first eight bytes of its name's SHA-256, big-endian,
// modulo the shard count. Pinned here because every shard job computes the
// plan on its own, so the hash has to be the same everywhere.
func hashShard(name string, shards int) int {
	sum := sha256.Sum256([]byte(name))
	return int(binary.BigEndian.Uint64(sum[:8])%uint64(shards)) + 1
}

func TestShardsSplitTheFixtureLongestFirst(t *testing.T) {
	table := fixtureTable(t)
	out, errOut, code := run(t, python(t), "scripts/test-shards.py", fixture, "--shards", "3", "--table", table, "check")
	if code != 0 {
		t.Fatalf("check: exit %d\n%s%s", code, out, errOut)
	}
	all := listed(t, ".")
	runnable := slices.DeleteFunc(slices.Clone(all), func(n string) bool { return strings.HasPrefix(n, "Benchmark") })
	if !strings.Contains(out, fmt.Sprintf("ok: each of %s's %d tests is selected by exactly one of 3 shards", fixture, len(runnable))) {
		t.Errorf("check passed without saying what it checked:\n%s", out)
	}
	if !strings.Contains(out, "::notice title=Stale duration table::") || !strings.Contains(out, "TestGone") {
		t.Errorf("check did not report the table's entry for a test the package no longer has:\n%s", out)
	}

	owner := map[string][]int{}
	for shard := 1; shard <= 3; shard++ {
		re := shardRegex(t, table, 3, shard)
		if !strings.HasPrefix(re, "^(") || !strings.HasSuffix(re, ")$") {
			t.Errorf("shard %d's regex is not anchored at both ends: %s", shard, re)
		}
		for _, name := range listed(t, re) {
			owner[name] = append(owner[name], shard)
		}
	}
	for _, name := range runnable {
		if len(owner[name]) != 1 {
			t.Errorf("%s is selected by shards %v, want exactly one", name, owner[name])
		}
	}
	if s := owner["BenchmarkDouble"]; len(s) != 0 {
		t.Errorf("BenchmarkDouble is claimed by shards %v; a benchmark does not run without -bench", s)
	}
	for name, want := range map[string]int{"TestSlowA": 1, "TestSlowB": 2, "TestSlowC": 3, "TestStop": 3, "TestStopAll": 2} {
		if got := owner[name]; len(got) != 1 || got[0] != want {
			t.Errorf("%s is in shard %v, want %d — the longest first, each to the shard with the least so far", name, got, want)
		}
	}
	for _, name := range []string{"TestNewOne", "TestNewTwo", "TestNewThree", "TestNewFour", "TestNewFive", "TestNewSix"} {
		if got, want := owner[name], hashShard(name, 3); len(got) != 1 || got[0] != want {
			t.Errorf("%s, which the table does not name, is in shard %v, want %d by its hash", name, got, want)
		}
	}

	// A test the table does not name is placed by its name alone: emptying
	// the table moves the tests it named, and none of the others.
	empty := writeTable(t)
	for shard := 1; shard <= 3; shard++ {
		for _, name := range listed(t, shardRegex(t, empty, 3, shard)) {
			if strings.HasPrefix(name, "TestNew") && hashShard(name, 3) != shard {
				t.Errorf("with an empty table %s moved to shard %d", name, shard)
			}
		}
	}
}

// TestShardGateRefusesARegexThatLosesOrDoublesATest breaks the regex builder
// the two ways that matter and runs the gate against each: a regex without
// anchors, which makes TestStop's shard run TestStopAll as well, and one that
// drops a test, which no shard then runs. Both have to fail the check — it is
// the only thing between them and a test CI silently never runs.
func TestShardGateRefusesARegexThatLosesOrDoublesATest(t *testing.T) {
	py := python(t)
	table := fixtureTable(t)
	for _, tc := range []struct {
		name, patch, want string
	}{
		{"unanchored", `lambda names: "|".join(names) if names else "^$"`, "::error title=Tests two shards run::"},
		{"one lost per shard", `lambda names: orig(names[1:])`, "::error title=Tests no shard runs::"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := fmt.Sprintf(`
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shards", "scripts/test-shards.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
orig = mod.regex_for
mod.regex_for = %s
sys.exit(mod.main([%q, "--shards", "3", "--table", %q, "check"]))
`, tc.patch, fixture, table)
			// -B: importing the script would otherwise leave its bytecode
			// in scripts/__pycache__, inside the working tree.
			out, errOut, code := run(t, py, "-B", "-c", script)
			if code != 1 {
				t.Fatalf("check with a %s regex: exit %d, want 1\n%s%s", tc.name, code, out, errOut)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("check with a %s regex did not say %q:\n%s", tc.name, tc.want, out)
			}
		})
	}
}

// TestDurationsAreATable runs test-durations.py on the fixture and hands
// its output to test-shards.py as the table: what one writes, the other reads.
func TestDurationsAreATable(t *testing.T) {
	py := python(t)
	out, errOut, code := run(t, py, "scripts/test-durations.py", fixture)
	if code != 0 {
		t.Fatalf("test-durations.py: exit %d\n%s%s", code, out, errOut)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("line %q is not \"<seconds> <test>\"", line)
		}
		names = append(names, f[1])
	}
	want := slices.DeleteFunc(listed(t, "."), func(n string) bool { return strings.HasPrefix(n, "Benchmark") })
	sort.Strings(names)
	sort.Strings(want)
	if !slices.Equal(names, want) {
		t.Errorf("test-durations.py timed %v, want every runnable test: %v", names, want)
	}
	table := filepath.Join(t.TempDir(), "table.txt")
	if err := os.WriteFile(table, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, errOut, code := run(t, py, "scripts/test-shards.py", fixture, "--shards", "2", "--table", table, "check"); code != 0 {
		t.Errorf("test-shards.py refused test-durations.py's output as a table: exit %d\n%s%s", code, out, errOut)
	}
}

func TestBudgetNamesThePackageItsTimeAndTheCommand(t *testing.T) {
	py := python(t)
	write := func(lines ...string) string {
		p := filepath.Join(t.TempDir(), "test.log")
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const mod = "github.com/blechschmidt/cloop/"
	log := write(
		"ok  \t"+mod+"pkg/fast\t12.345s\tcoverage: 80.0% of statements",
		"ok  \t"+mod+"pkg/slow\t1100.000s\tcoverage: 70.0% of statements",
		"FAIL\t"+mod+"pkg/broken [build failed]",
		"ok  \t"+mod+"pkg/cached\t(cached)",
		"--- FAIL: TestX (1200.00s)",
	)

	out, errOut, code := run(t, py, "scripts/test-budget.py", "--timeout", "30m", log)
	if code != 1 {
		t.Fatalf("1,100 s of a 30m timeout: exit %d, want 1\n%s%s", code, out, errOut)
	}
	// An annotation's message escapes "%" as the runner expects; read it as
	// the runner shows it.
	out = strings.ReplaceAll(out, "%25", "%")
	for _, want := range []string{
		"::error title=Test time budget%3A ./pkg/slow/::",
		"./pkg/slow/ took 1100.0 s, 61% of its 30m -timeout",
		"the budget is 60% (1080 s)",
		"scripts/test-durations.py ./pkg/slow/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the failure does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "::error title=Test time budget%3A ./pkg/fast/") {
		t.Errorf("a package at 0.7%% of its timeout was failed:\n%s", out)
	}

	if out, _, code := run(t, py, "scripts/test-budget.py", "--timeout", "30m", "--budget", "70", log); code != 0 {
		t.Errorf("61%% under a 70%% budget: exit %d, want 0\n%s", code, out)
	}
	timedOut := write("FAIL\t" + mod + "pkg/ui\t1803.836s")
	if out, _, code := run(t, py, "scripts/test-budget.py", "--timeout", "30m", timedOut); code != 1 || !strings.Contains(out, "./pkg/ui/ took 1803.8 s, 100%25") {
		t.Errorf("a package that timed out: exit %d, want 1 naming it\n%s", code, out)
	}
	if out, _, code := run(t, py, "scripts/test-budget.py", "--timeout", "30m", write("PASS")); code != 1 || !strings.Contains(out, "nothing to check") {
		t.Errorf("a log with no package results: exit %d, want 1 saying so\n%s", code, out)
	}
	if _, _, code := run(t, py, "scripts/test-budget.py", "--timeout", "30x", log); code != 2 {
		t.Errorf("--timeout 30x: exit %d, want 2", code)
	}
}

// TestMergedShardCoverageIsOneRunsCoverage runs the fixture whole and in three
// shards, and merges the shards' profiles: the result is the whole run's
// profile, block for block and count for count.
func TestMergedShardCoverageIsOneRunsCoverage(t *testing.T) {
	table := fixtureTable(t)
	dir := t.TempDir()
	cover := func(name, pattern string) string {
		p := filepath.Join(dir, name)
		out, errOut, code := run(t, "go", "test", "-count=1", "-cover", "-covermode=atomic", "-coverprofile="+p, "-run", pattern, fixture)
		if code != 0 {
			t.Fatalf("go test -coverprofile %s: exit %d\n%s%s", name, code, out, errOut)
		}
		return p
	}
	whole := cover("whole.out", ".")
	var parts []string
	for shard := 1; shard <= 3; shard++ {
		parts = append(parts, cover(fmt.Sprintf("shard%d.out", shard), shardRegex(t, table, 3, shard)))
	}
	merged, errOut, code := run(t, "bash", append([]string{"scripts/merge-coverage.sh"}, parts...)...)
	if code != 0 {
		t.Fatalf("merge-coverage.sh: exit %d\n%s", code, errOut)
	}
	lines := func(s string) []string {
		l := strings.Split(strings.TrimSpace(s), "\n")
		sort.Strings(l)
		return l
	}
	wholeBody, err := os.ReadFile(whole)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := lines(merged), lines(string(wholeBody)); !slices.Equal(got, want) {
		t.Errorf("the merged shards are not the whole run:\nmerged:\n%s\nwhole:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Its total is go tool cover's.
	funcOut, errOut2, code := run(t, "go", "tool", "cover", "-func="+whole)
	if code != 0 {
		t.Fatalf("go tool cover -func: exit %d\n%s", code, errOut2)
	}
	total := regexp.MustCompile(`total:\s+\(statements\)\s+([0-9.]+)%`).FindStringSubmatch(funcOut)
	if total == nil {
		t.Fatalf("go tool cover -func printed no total:\n%s", funcOut)
	}
	if !strings.Contains(errOut, total[1]+"% of") {
		t.Errorf("merge-coverage.sh reported %q; go tool cover says %s%%", strings.TrimSpace(errOut), total[1])
	}

	setMode := filepath.Join(dir, "set.out")
	if err := os.WriteFile(setMode, []byte("mode: set\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(t, "bash", "scripts/merge-coverage.sh", parts[0], setMode); code != 2 || !strings.Contains(errOut, "mode set") {
		t.Errorf("merging an atomic and a set profile: exit %d, want 2 naming the mode\n%s", code, errOut)
	}
}

func TestRacePackagesWithoutLeavesOutOnlyThatPackage(t *testing.T) {
	everything, errOut, code := run(t, "bash", "scripts/race-packages.sh")
	if code != 0 {
		t.Fatalf("race-packages.sh: exit %d\n%s", code, errOut)
	}
	without, errOut, code := run(t, "bash", "scripts/race-packages.sh", "--without", "pkg/ui")
	if code != 0 {
		t.Fatalf("race-packages.sh --without pkg/ui: exit %d\n%s", code, errOut)
	}
	all, rest := strings.Fields(everything), strings.Fields(without)
	const ui = "github.com/blechschmidt/cloop/pkg/ui"
	if all[0] != ui {
		t.Errorf("race-packages.sh names %s first, want %s, its longest", all[0], ui)
	}
	if want := slices.DeleteFunc(slices.Clone(all), func(p string) bool { return p == ui }); !slices.Equal(rest, want) {
		t.Errorf("--without pkg/ui changed more than pkg/ui:\nwithout: %v\nwant:    %v", rest, want)
	}
	if _, errOut, code := run(t, "bash", "scripts/race-packages.sh", "--without", "pkg/no-such-package"); code != 1 || !strings.Contains(errOut, "is not a package") {
		t.Errorf("--without a package that does not exist: exit %d, want 1 naming it\n%s", code, errOut)
	}
}

// TestWorkflowShardsWhatTheRaceStepLeavesOut reads ci.yml: every package the
// race step leaves out with --without must be what a shard job's test-shards.py
// splits, and the other way round. Leaving one out without a shard job to run
// it would drop its tests from CI with every check still green.
func TestWorkflowShardsWhatTheRaceStepLeavesOut(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(body)
	norm := func(p string) string { return strings.Trim(strings.TrimPrefix(p, "./"), "/") }
	set := func(re string) []string {
		var out []string
		for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(wf, -1) {
			if p := norm(m[1]); !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return out
	}
	var left []string
	for _, line := range strings.Split(wf, "\n") {
		if !strings.Contains(line, "race-packages.sh") {
			continue
		}
		for _, m := range regexp.MustCompile(`--without ([\w./-]+)`).FindAllStringSubmatch(line, -1) {
			if p := norm(m[1]); !slices.Contains(left, p) {
				left = append(left, p)
			}
		}
	}
	sort.Strings(left)
	sharded := set(`test-shards\.py ([\w./-]+)`)
	if len(left) == 0 {
		t.Fatal("ci.yml no longer runs race-packages.sh --without; if the race step changed, this gate is vacuous and must be updated")
	}
	if !slices.Equal(left, sharded) {
		t.Errorf("the race step leaves out %v, and the shard jobs split %v: a package left out and not sharded is not tested at all", left, sharded)
	}
	for _, pkg := range sharded {
		if !regexp.MustCompile(`go test \$[A-Z]+_GO_FLAGS -timeout "\$RACE_TIMEOUT" -coverprofile=\S+ -run "\$run" \./` + regexp.QuoteMeta(pkg) + `/`).MatchString(wf) {
			t.Errorf("no shard step runs %s with its shard's -run regex under the race step's timeout", pkg)
		}
	}
	if n := strings.Count(wf, `test-budget.py --timeout "$RACE_TIMEOUT"`); n < 1+len(sharded) {
		t.Errorf("the time budget is checked %d times, want the race step and each sharded package's shards", n)
	}
	timeouts := set(`RACE_TIMEOUT: (\S+)`)
	if len(timeouts) != 1 {
		t.Errorf("RACE_TIMEOUT is set to %v; the race step and the shards share one", timeouts)
	}
}
