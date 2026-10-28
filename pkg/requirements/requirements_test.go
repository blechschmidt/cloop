package requirements

import (
	"context"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact/redacttest"
)

func TestNormalizeBoundsEveryField(t *testing.T) {
	ok := Requirement{Title: "  Config errors exit non-zero ", Priority: " MUST ", Tags: []string{"Core", "core", " cli "},
		Tests: []Test{{Name: " unit ", Command: "  go test ./pkg/config  "}}}
	if err := ok.Normalize(); err != nil {
		t.Fatal(err)
	}
	if ok.Title != "Config errors exit non-zero" || ok.Priority != PriorityMust || strings.Join(ok.Tags, ",") != "core,cli" ||
		ok.Tests[0].Command != "go test ./pkg/config" || ok.Tests[0].Name != "unit" {
		t.Errorf("normalised to %+v", ok)
	}

	bad := map[string]Requirement{
		"no title":        {Title: "  "},
		"two-line title":  {Title: "a\nb"},
		"long title":      {Title: strings.Repeat("x", MaxTitleRunes+1)},
		"long details":    {Title: "t", Description: strings.Repeat("x", MaxDescriptionRunes+1)},
		"priority":        {Title: "t", Priority: "won't"},
		"tag shape":       {Title: "t", Tags: []string{"a b"}},
		"too many tags":   {Title: "t", Tags: manyTags(MaxTags + 1)},
		"empty command":   {Title: "t", Tests: []Test{{Command: " "}}},
		"long command":    {Title: "t", Tests: []Test{{Command: strings.Repeat("x", MaxCommandBytes+1)}}},
		"NUL in command":  {Title: "t", Tests: []Test{{Command: "true\x00"}}},
		"negative time":   {Title: "t", Tests: []Test{{Command: "true", TimeoutSeconds: -1}}},
		"too long a test": {Title: "t", Tests: []Test{{Command: "true", TimeoutSeconds: int(MaxTestTimeout/time.Second) + 1}}},
		"too many tests":  {Title: "t", Tests: make([]Test, MaxTests+1)},
	}
	for name, r := range bad {
		if err := r.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Normalize = %v, want ErrInvalid", name, err)
		}
	}
}

func manyTags(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "t" + strconv.Itoa(i)
	}
	return out
}

func TestFingerprintFollowsWhatTheVerdictIsAbout(t *testing.T) {
	base := Requirement{ID: 1, Title: "t", Description: "d", Tests: []Test{{Command: "true"}}}
	same := base
	same.Priority, same.Tags, same.UpdatedBy = PriorityCould, []string{"x"}, "someone"
	if base.Fingerprint() != same.Fingerprint() {
		t.Error("priority and tags changed the fingerprint; they say how much it matters, not what it is")
	}
	for name, mut := range map[string]func(*Requirement){
		"title":   func(r *Requirement) { r.Title = "t2" },
		"details": func(r *Requirement) { r.Description = "d2" },
		"command": func(r *Requirement) { r.Tests = []Test{{Command: "false"}} },
		"timeout": func(r *Requirement) { r.Tests = []Test{{Command: "true", TimeoutSeconds: 9}} },
		"no test": func(r *Requirement) { r.Tests = nil },
	} {
		r := base
		mut(&r)
		if r.Fingerprint() == base.Fingerprint() {
			t.Errorf("changing the %s left the fingerprint as it was", name)
		}
	}
}

func TestTestsVerdict(t *testing.T) {
	pass := TestResult{Command: "a", Outcome: OutcomePass}
	fail := TestResult{Command: "b", Outcome: OutcomeFail, ExitCode: 2}
	slow := TestResult{Command: "c", Outcome: OutcomeTimeout, Error: "timed out after 1s"}
	for _, c := range []struct {
		in      []TestResult
		verdict string
		says    string
	}{
		{[]TestResult{pass}, VerdictFulfilled, "1 test passed"},
		{[]TestResult{pass, pass}, VerdictFulfilled, "2 tests passed"},
		{[]TestResult{fail}, VerdictUnfulfilled, `test "b" failed (exit 2)`},
		{[]TestResult{pass, fail, slow}, VerdictUnfulfilled, `1 of 3 tests failed: "b"`},
		{[]TestResult{pass, slow}, VerdictError, `test "c" timed out after 1s`},
		{nil, VerdictUnverified, "no tests"},
	} {
		v, s := TestsVerdict(c.in)
		if v != c.verdict || !strings.Contains(s, c.says) {
			t.Errorf("TestsVerdict(%v) = %s %q, want %s containing %q", c.in, v, s, c.verdict, c.says)
		}
	}
}

// TestSanitizeDecidesWhatIsRecorded: an executor's report is read for what the
// hub asked, in the hub's words — whatever the cloop that sent it claims.
func TestSanitizeDecidesWhatIsRecorded(t *testing.T) {
	asked := []Requirement{
		{ID: 1, Title: "tested", Tests: []Test{{Name: "unit", Command: "go test ./a"}, {Command: "go vet ./a"}}},
		{ID: 2, Title: "untested"},
		{ID: 3, Title: "forgotten", Tests: []Test{{Command: "true"}}},
		{ID: 4, Title: "short", Tests: []Test{{Command: "true"}, {Command: "true"}}},
	}
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	rep := Report{Commit: "NOT-A-SHA; rm -rf /", Results: []Result{
		// Claims fulfilled with a failing test, and rewrites the commands.
		{RequirementID: 1, Fingerprint: "forged", Method: MethodAI, Verdict: VerdictFulfilled, Tests: []TestResult{
			{Command: "echo pwned", Outcome: OutcomePass, Output: "ghp_" + strings.Repeat("a", 36)},
			{Command: "echo pwned", Outcome: OutcomeFail, ExitCode: 0, Output: strings.Repeat("y", MaxOutputBytes+100)},
		}},
		{RequirementID: 1, Verdict: VerdictUnfulfilled}, // a duplicate: the first one is read
		{RequirementID: 2, Method: MethodAI, Verdict: "certainly", Summary: "line one\nline two",
			Evidence: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}},
		{RequirementID: 4, Method: MethodTests, Verdict: VerdictFulfilled, Tests: []TestResult{{Outcome: OutcomePass}}},
		{RequirementID: 99, Verdict: VerdictFulfilled}, // never asked about
	}}
	scrubbed := 0
	scrub := func(s string) string {
		if strings.Contains(s, "ghp_") {
			scrubbed++
			return "[redacted]"
		}
		return s
	}
	got := Sanitize(rep, asked, true, scrub, now)
	if got.Commit != "" {
		t.Errorf("commit %q kept: it is not a commit", got.Commit)
	}
	if len(got.Results) != len(asked) {
		t.Fatalf("%d results for %d requirements asked: %+v", len(got.Results), len(asked), got.Results)
	}
	r1 := got.Results[0]
	if r1.Fingerprint != asked[0].Fingerprint() || r1.Method != MethodTests || r1.Tests[0].Command != "go test ./a" ||
		r1.Tests[0].Name != "unit" || r1.Tests[1].Command != "go vet ./a" {
		t.Errorf("R-1 kept the executor's account of its definition: %+v", r1)
	}
	// "failed with exit 0" is not a failure this runner reports: an error.
	if r1.Verdict != VerdictError || r1.Tests[1].Outcome != OutcomeError {
		t.Errorf("R-1 verdict %s (%s), want an error: its second test cannot have failed with exit 0", r1.Verdict, r1.Tests[1].Outcome)
	}
	if r1.Tests[0].Output != "[redacted]" || scrubbed == 0 {
		t.Errorf("R-1's output was not scrubbed: %q", r1.Tests[0].Output)
	}
	if len(r1.Tests[1].Output) > MaxOutputBytes || !r1.Tests[1].Truncated {
		t.Errorf("R-1's second output is %d bytes, truncated %v", len(r1.Tests[1].Output), r1.Tests[1].Truncated)
	}
	if r2 := got.Results[1]; r2.Verdict != VerdictError || r2.Method != MethodAI || len(r2.Evidence) != MaxEvidence ||
		strings.Contains(r2.Summary, "\n") {
		t.Errorf("R-2 = %+v: an unknown verdict is an error, evidence bounded, the summary one line", r2)
	}
	if r3 := got.Results[2]; r3.Verdict != VerdictError || !strings.Contains(r3.Summary, "no result") || !r3.StartedAt.Equal(now) {
		t.Errorf("R-3, left out of the report, = %+v", r3)
	}
	if r4 := got.Results[3]; r4.Verdict != VerdictError || len(r4.Tests) != 0 {
		t.Errorf("R-4 reported one result for two tests and was read as %+v", r4)
	}
	// Not asked to assess, the hub takes no verdict on an untested
	// requirement from the executor.
	rep.Results[2] = Result{RequirementID: 2, Method: MethodAI, Verdict: VerdictFulfilled, Summary: "trust me"}
	if r2 := Sanitize(rep, asked, false, scrub, now).Results[1]; r2.Verdict != VerdictUnverified || r2.Method != MethodNone {
		t.Errorf("without assess, R-2 = %+v", r2)
	}
}

func TestParseSpec(t *testing.T) {
	sp, err := ParseSpec([]byte(`{"goal":" g ","requirements":[{"id":3,"title":" t ","tests":[{"command":" true "}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if sp.Goal != "g" || sp.Requirements[0].Title != "t" || sp.Requirements[0].Tests[0].Command != "true" {
		t.Errorf("spec read as %+v", sp)
	}
	for name, raw := range map[string]string{
		"not JSON":     `{`,
		"no id":        `{"requirements":[{"title":"t"}]}`,
		"duplicate id": `{"requirements":[{"id":1,"title":"a"},{"id":1,"title":"b"}]}`,
		"invalid":      `{"requirements":[{"id":1,"title":""}]}`,
		"too big":      `{"goal":"` + strings.Repeat("x", MaxSpecBytes) + `"}`,
	} {
		if _, err := ParseSpec([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: ParseSpec = %v, want ErrInvalid", name, err)
		}
	}
}

func TestParseAssessment(t *testing.T) {
	a, err := ParseAssessment("Let me look. An example: {\"verdict\":\"fulfilled\"}\nAnswer:\n" +
		`{"verdict":"unfulfilled","rationale":"no check {here}","evidence":["main.go:3 — x {y}"]}` + "\nDone.")
	if err != nil || a.verdict() != VerdictUnfulfilled || a.Rationale != "no check {here}" || len(a.Evidence) != 1 {
		t.Fatalf("ParseAssessment = %+v, %v; want the answer nearest the end", a, err)
	}
	if a, _ := ParseAssessment(`{"verdict":"unknown","rationale":"cannot tell"}`); a.verdict() != VerdictUnverified {
		t.Errorf("unknown read as %s, want unverified", a.verdict())
	}
	if _, err := ParseAssessment("I could not decide."); !errors.Is(err, ErrNoAssessment) {
		t.Errorf("no JSON: %v, want ErrNoAssessment", err)
	}
	// A megabyte of braces is a bounded scan, not one decode per brace.
	start := time.Now()
	if _, err := ParseAssessment(strings.Repeat("{", 1<<20)); !errors.Is(err, ErrNoAssessment) {
		t.Errorf("braces: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("a megabyte of braces took %s", d)
	}
}

func TestAssessPromptNamesTheRequirement(t *testing.T) {
	p := AssessPrompt("Ship a CLI", Requirement{ID: 7, Title: "Exits non-zero", Description: "On a malformed config."}, "func main() {}")
	for _, want := range []string{"R-7", "Exits non-zero", "On a malformed config.", "Ship a CLI", "func main() {}",
		"Do NOT modify", `"verdict"`} {
		if !strings.Contains(p, want) {
			t.Errorf("the prompt lacks %q:\n%s", want, p)
		}
	}
}

// ── the runner ──────────────────────────────────────────────────────────────

func TestCheckRunsTheTests(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("here"), 0o600); err != nil {
		t.Fatal(err)
	}
	reqs := []Requirement{
		{ID: 1, Title: "passes", Tests: []Test{{Command: "test -f marker && echo ok:$CLOOP_REQUIREMENT"}}},
		{ID: 2, Title: "fails", Tests: []Test{{Command: "echo first"}, {Name: "broken", Command: "echo boom >&2; exit 7"}}},
		{ID: 3, Title: "slow", Tests: []Test{{Command: "sleep 30", TimeoutSeconds: 1}}},
		{ID: 4, Title: "untested"},
	}
	var seen []int
	start := time.Now()
	results := Check(context.Background(), reqs, Options{Dir: dir, OnResult: func(r Result) { seen = append(seen, r.RequirementID) }})
	if time.Since(start) > 20*time.Second {
		t.Fatalf("the check took %s: the timeout did not stop the slow test", time.Since(start))
	}
	if len(results) != 4 || len(seen) != 4 {
		t.Fatalf("%d results, %d reported", len(results), len(seen))
	}
	if r := results[0]; r.Verdict != VerdictFulfilled || !strings.Contains(r.Tests[0].Output, "ok:R-1") || r.Fingerprint != reqs[0].Fingerprint() {
		t.Errorf("R-1 = %+v", r)
	}
	if r := results[1]; r.Verdict != VerdictUnfulfilled || r.Tests[1].ExitCode != 7 || r.Tests[1].Outcome != OutcomeFail ||
		!strings.Contains(r.Tests[1].Output, "boom") || r.Tests[0].Outcome != OutcomePass {
		t.Errorf("R-2 = %+v", r)
	}
	if r := results[2]; r.Verdict != VerdictError || r.Tests[0].Outcome != OutcomeTimeout || !strings.Contains(r.Summary, "timed out") {
		t.Errorf("R-3 = %+v", r)
	}
	if r := results[3]; r.Verdict != VerdictUnverified || r.Method != MethodNone {
		t.Errorf("R-4 = %+v", r)
	}
	if results[0].DurationMS < 0 || results[2].DurationMS < 900 {
		t.Errorf("durations %d, %d ms", results[0].DurationMS, results[2].DurationMS)
	}
}

// TestATestLeavesNothingRunning: what a test starts in the background goes
// when it ends, and a background child holding the output does not hold the
// check open, nor turn a pass into a failure.
func TestATestLeavesNothingRunning(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "bg.pid")
	start := time.Now()
	results := Check(context.Background(), []Requirement{{ID: 1, Title: "t", Tests: []Test{{
		Command: "sleep 300 & echo $! > " + pidFile + "; echo done",
	}}}}, Options{Dir: dir})
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("the check waited %s on its background child", took)
	}
	if r := results[0]; r.Verdict != VerdictFulfilled || !strings.Contains(r.Tests[0].Output, "done") {
		t.Errorf("result %+v", r)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
		time.Sleep(20 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Errorf("the test's background child %d outlived it", pid)
	}
}

func TestCheckStopsWhenItsContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	results := Check(ctx, []Requirement{
		{ID: 1, Title: "a", Tests: []Test{{Command: "sleep 30"}}},
		{ID: 2, Title: "b", Tests: []Test{{Command: "true"}}},
	}, Options{Dir: t.TempDir()})
	if results[0].Verdict != VerdictError || results[0].Tests[0].Outcome != OutcomeError {
		t.Errorf("the stopped test = %+v, want an error rather than a failure", results[0])
	}
	if results[1].Verdict != VerdictError || len(results[1].Tests) != 0 {
		t.Errorf("the requirement never reached = %+v", results[1])
	}
}

func TestTheOutputIsBoundedAndScrubbed(t *testing.T) {
	const leased, root = "s3cret-lease-value-123", "the-hubs-root-key-material"
	pat := redacttest.GitHubToken(rand.New(rand.NewPCG(20458, 1)), "ghp_")
	env := append(os.Environ(),
		"CLOOP_REDACT_ENV=LEASED_TOKEN", "LEASED_TOKEN="+leased, "CLOOP_SECRET_KEY="+root)
	results := Check(context.Background(), []Requirement{{ID: 1, Title: "t", Tests: []Test{{
		Command: `head -c 100000 /dev/zero | tr '\0' 'x'; echo; echo "lease=$LEASED_TOKEN key=${CLOOP_SECRET_KEY-unset}"; ` +
			`echo "pat=` + pat + `"; echo "` + root + `"`,
	}}}}, Options{Dir: t.TempDir(), Env: env})
	out := results[0].Tests[0]
	if len(out.Output) > MaxOutputBytes || !out.Truncated {
		t.Errorf("kept %d bytes, truncated %v", len(out.Output), out.Truncated)
	}
	if strings.Contains(out.Output, leased) || strings.Contains(out.Output, pat) || strings.Contains(out.Output, root) {
		t.Errorf("a credential survived in the output:\n%s", out.Output[len(out.Output)-300:])
	}
	if !strings.Contains(out.Output, "key=unset") {
		t.Errorf("the hub's root key reached the test's environment:\n%s", out.Output[len(out.Output)-300:])
	}
}

func TestTailBuffer(t *testing.T) {
	b := &tailBuffer{max: 8}
	_, _ = b.Write([]byte("abc"))
	_, _ = b.Write([]byte("defghij"))
	if s, cut := b.String(); s != "cdefghij" || !cut {
		t.Errorf("tail %q %v", s, cut)
	}
	b = &tailBuffer{max: 4}
	_, _ = b.Write([]byte("0123456789"))
	if s, _ := b.String(); s != "6789" {
		t.Errorf("tail %q", s)
	}
	// A cut through a rune drops the half rune rather than keeping garbage.
	b = &tailBuffer{max: 3}
	_, _ = b.Write([]byte("aé!"))
	_, _ = b.Write([]byte("é!"))
	if s, _ := b.String(); s != "!" && s != "é!" {
		t.Errorf("tail %q is not whole runes", s)
	}
}

func TestWorkTree(t *testing.T) {
	if commit, dirty := WorkTree(context.Background(), t.TempDir()); commit != "" || dirty {
		t.Errorf("a directory that is no checkout reported %q %v", commit, dirty)
	}
}
