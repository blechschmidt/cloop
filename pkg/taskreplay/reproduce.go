package taskreplay

// reproduce.go answers the question an enterprise reviewing AI-authored commits
// actually asks: if I run this task again, do I get the same change?
//
// # How it differs from ReplayTask
//
// ReplayTask re-sends a prompt to a provider and scores the two transcripts
// with JaccardSimilarity. That measures whether two models *said* similar
// things. It is a useful signal about models and no signal at all about code: a
// model can produce a near-identical explanation of a change it did not make,
// and two correct implementations of the same task share almost no prose.
//
// Reproduce re-executes the task in a fresh isolating sandbox and compares the
// commits. Nothing here scores text.
//
// # The verdict
//
// Three substantive outcomes, plus an explicit absence:
//
//	IDENTICAL    — same tree hash. The strongest result; needs no test run.
//	EQUIVALENT   — different bytes, same behaviour under the project's own
//	               test command, run against both trees.
//	DIVERGENT    — neither. The diff-of-diffs is attached.
//	INCONCLUSIVE — the harness could not reach a verdict.
//
// INCONCLUSIVE is not a fourth opinion about the code; it is the refusal to
// have one, and it exists to protect the value of the other three. The payoff
// this feature is built for is that a DIVERGENT verdict on a task which touched
// no external state is a precise signal of nondeterminism worth investigating.
// That signal is only worth chasing if DIVERGENT is rare and means something.
// Folding "the project has no test command", "the sandbox image moved", or "the
// executor died" into DIVERGENT would bury every real finding under noise, and
// an operator who chased three false ones would stop reading the verdict.
//
// Equivalence is gated on the project's own test command rather than on a
// second model's opinion for the same reason. An LLM judge asked whether two
// diffs are equivalent will confidently say yes; a test suite that passes on
// both trees is a fact.
//
// # What it will not do
//
// Reproduce is non-destructive by contract, and the contract is enforced in
// three separate places rather than documented in one:
//
//   - It never writes back. The spec it asks for is bundle mode, so the work
//     comes home as a file and there is no push (see WriteBackMode).
//   - It never touches the project's git refs — compare.go borrows the object
//     store read-only and does all its work in a scratch repository.
//   - It runs under its own quota, charged by the caller before Reproduce is
//     entered, so a reproduction storm cannot starve real work.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/testrun"
)

// Verdict is the outcome of a reproduction.
type Verdict string

const (
	// VerdictIdentical: the reproduction produced the same tree hash.
	VerdictIdentical Verdict = "identical"
	// VerdictEquivalent: different bytes, same behaviour under the project's
	// own test command on both trees.
	VerdictEquivalent Verdict = "equivalent"
	// VerdictDivergent: the reproduction produced a different change.
	VerdictDivergent Verdict = "divergent"
	// VerdictInconclusive: no verdict could be reached. See the file comment.
	VerdictInconclusive Verdict = "inconclusive"
)

// Valid reports whether v is a known verdict.
func (v Verdict) Valid() bool {
	switch v {
	case VerdictIdentical, VerdictEquivalent, VerdictDivergent, VerdictInconclusive:
		return true
	}
	return false
}

// Reproducible reports whether the verdict is one that supports the claim "this
// commit reproduces".
func (v Verdict) Reproducible() bool {
	return v == VerdictIdentical || v == VerdictEquivalent
}

// AllVerdicts is every verdict, for callers that enumerate them.
var AllVerdicts = []Verdict{VerdictIdentical, VerdictEquivalent, VerdictDivergent, VerdictInconclusive}

// ErrNoRunner is returned when Reproduce is called without a SandboxRunner.
//
// There is deliberately no default. A fallback that quietly ran the harness on
// the host would violate the isolation this whole subsystem exists to provide,
// and it would do so in the one command whose output is a trustworthiness
// claim.
var ErrNoRunner = errors.New("reproduce: no sandbox runner was supplied, and there is no host fallback by design")

// TestOutcome is one run of the project's own test command.
type TestOutcome struct {
	// Command is what was run, for the record.
	Command []string `json:"command,omitempty"`
	// Framework is the detected harness name ("go test", "pytest", …).
	Framework string `json:"framework,omitempty"`
	// Ran reports that the command actually executed. False means the sandbox
	// could not run it at all, which is not the same as a failing suite.
	Ran bool `json:"ran"`
	// Passed reports a zero exit status.
	Passed bool `json:"passed"`
	// ExitCode is the command's status, meaningful only when Ran.
	ExitCode int `json:"exit_code"`
	// Output is the tail of the command's output, for a reviewer.
	Output string `json:"output,omitempty"`
	// Duration is how long it took.
	Duration time.Duration `json:"duration,omitempty"`
}

// Agrees reports whether two outcomes describe the same behaviour.
//
// Both must have run and both must have passed. "Both failed" is deliberately
// not agreement: two suites can fail for unrelated reasons, and a reproduction
// harness that called that EQUIVALENT would certify a broken change as
// faithfully reproduced.
func (t *TestOutcome) Agrees(other *TestOutcome) bool {
	if t == nil || other == nil {
		return false
	}
	return t.Ran && other.Ran && t.Passed && other.Passed
}

// RunRequest is what a SandboxRunner is asked to do: re-execute one task in a
// fresh isolating sandbox and bring back the commit.
type RunRequest struct {
	// ProjectDir is the hub-side project this reproduction belongs to. It
	// supplies the executor binding and the workspace source; the runner must
	// not execute anything in it.
	ProjectDir string
	// Provenance is the reconstructed input state: prompt, model settings,
	// sandbox, and the commit to start from (Provenance.BaseSHA).
	Provenance *Provenance
	// Branch is the write-back branch the sandbox must commit to. It is
	// generated per reproduction and never collides with a real task branch.
	Branch string
	// TestCommand is the project's own test command, to run inside the sandbox
	// after the agent exits. Empty when none was detected.
	TestCommand []string
	// Timeout bounds the whole sandbox run.
	Timeout time.Duration
}

// VerifyRequest asks a runner to run only the test command, at a given commit,
// with no agent involved. It is how the original tree's behaviour is measured.
type VerifyRequest struct {
	ProjectDir  string
	Provenance  *Provenance
	CommitSHA   string
	TestCommand []string
	Timeout     time.Duration
}

// RunOutcome is what a SandboxRunner brings back.
type RunOutcome struct {
	// BundlePath is the git bundle holding the sandbox's commit. The runner
	// owns creating it; Reproduce removes it when it is done.
	BundlePath string
	// Branch is the ref inside the bundle.
	Branch string
	// ExitCode and Output are the agent harness's.
	ExitCode int
	Output   string
	// Skipped and SkipReason report a sandbox that ran and changed nothing.
	Skipped    bool
	SkipReason string
	// Where it ran, for the record and for the UI.
	ExecutorID   string
	ExecutorKind string
	Isolation    string
	PinnedImage  string
	// Test is the project's test command run on the reproduced tree, when a
	// command was supplied.
	Test *TestOutcome
}

// SandboxRunner places a reproduction on an isolating executor.
//
// It is an interface rather than a concrete implementation because the two
// callers assemble a spec from different places and neither can import the
// other: the hub (pkg/ui) has the executor registry, the secret broker, the
// egress filter and the project binding already wired up, while the CLI builds
// the same spec standalone. Reproduce owns what a reproduction *means* —
// reconstruct, compare, judge — and delegates only how a sandbox is started.
//
// An implementation MUST guarantee, and is tested on:
//   - the executor isolates (container, VM, or remote); never the host;
//   - the workspace is provisioned fresh at Provenance.BaseSHA;
//   - egress is denied except for broker-leased grants;
//   - write-back is bundle mode, so nothing is pushed anywhere.
type SandboxRunner interface {
	RunReproduction(ctx context.Context, req RunRequest) (*RunOutcome, error)
	VerifyCommit(ctx context.Context, req VerifyRequest) (*TestOutcome, error)
}

// DefaultReproduceTimeout bounds one reproduction when the caller names none.
//
// Generous, because it covers a model re-doing the task plus a full test suite
// on two trees, and a reproduction that timed out has burned the cost without
// producing the verdict that justifies it.
const DefaultReproduceTimeout = 45 * time.Minute

// ReproduceOptions controls one reproduction.
type ReproduceOptions struct {
	// Runner places the sandbox. Required — see ErrNoRunner.
	Runner SandboxRunner
	// Timeout bounds the whole reproduction. 0 means DefaultReproduceTimeout.
	Timeout time.Duration
	// TestCommand overrides the detected test command. Supply it for a project
	// whose suite is not what testrun.Detect would guess.
	TestCommand []string
	// SkipTests suppresses the behavioural gate entirely. The result is that a
	// non-identical reproduction can only ever be INCONCLUSIVE — which is the
	// honest outcome, and why this is off by default.
	SkipTests bool
	// Emit receives progress lines. May be nil.
	Emit func(string)
}

// Reproduction is the full record of one reproduction attempt.
type Reproduction struct {
	ID        int64     `json:"id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	TaskID    int       `json:"task_id"`
	TaskTitle string    `json:"task_title,omitempty"`

	Verdict Verdict `json:"verdict"`
	// Reason states, in one sentence, why this verdict and not another. It is
	// the field an operator reads first and the only one that is never empty.
	Reason string `json:"reason"`

	Provenance *Provenance `json:"provenance,omitempty"`
	Comparison *Comparison `json:"comparison,omitempty"`

	// Where the reproduction ran.
	ExecutorID   string `json:"executor_id,omitempty"`
	ExecutorKind string `json:"executor_kind,omitempty"`
	Isolation    string `json:"isolation,omitempty"`
	PinnedImage  string `json:"pinned_image,omitempty"`

	// The behavioural gate: the same command on both trees.
	OriginalTest *TestOutcome `json:"original_test,omitempty"`
	ReplayTest   *TestOutcome `json:"replay_test,omitempty"`

	// AgentExitCode and AgentOutput are the re-execution's own result.
	AgentExitCode int    `json:"agent_exit_code"`
	AgentOutput   string `json:"agent_output,omitempty"`

	Duration time.Duration `json:"duration,omitempty"`
	// Err is set when the harness failed rather than the comparison.
	Err string `json:"error,omitempty"`
}

// maxAgentOutput bounds the transcript kept on a Reproduction.
//
// The agent's output is unbounded and untrusted; the reason to keep any of it
// is to explain an INCONCLUSIVE verdict, and the explanation is at the end.
const maxAgentOutput = 64 << 10

// Reproduce re-executes taskID in a fresh isolating sandbox and returns a
// verdict on whether it produced the same change.
//
// It never mutates the project: not its refs, not its working tree, not its
// task record. The returned Reproduction is persisted by the caller via
// SaveReproduction, so a caller that only wants the answer can decline to
// store it.
func Reproduce(ctx context.Context, workDir string, taskID int, opts ReproduceOptions) (*Reproduction, error) {
	emit := opts.Emit
	if emit == nil {
		emit = func(string) {}
	}
	if opts.Runner == nil {
		return nil, ErrNoRunner
	}

	started := time.Now()
	rep := &Reproduction{CreatedAt: started, TaskID: taskID, Verdict: VerdictInconclusive}

	prov, err := ReadProvenance(workDir, taskID)
	if prov != nil {
		rep.Provenance = prov
		rep.TaskTitle = prov.TaskTitle
	}
	if err != nil {
		// ErrNoRecordedCommit is a property of the task, not a failure of the
		// harness, and it is by far the most common reason a reproduction
		// cannot run. Surface it as such so the UI can explain it.
		return nil, err
	}
	// Before anything is dispatched: the sandbox is provisioned by checking
	// out the base, so a task whose base cannot be recovered is one that must
	// fail here rather than after a model has been paid for.
	if err := ResolveBase(ctx, workDir, prov); err != nil {
		rep.Reason = "the commit this task was based on could not be determined: " + err.Error()
		rep.Err = err.Error()
		return rep, nil
	}
	emit(fmt.Sprintf("reproducing task %d at base %s (%s)\n",
		taskID, shortSHA(prov.BaseSHA), prov.BaseSource))

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultReproduceTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	testCmd := opts.TestCommand
	framework := ""
	if !opts.SkipTests && len(testCmd) == 0 {
		if fw, derr := testrun.Detect(workDir); derr == nil && fw != nil {
			testCmd, framework = fw.Command, fw.Name
		}
	}
	if opts.SkipTests {
		testCmd = nil
	}

	branch := reproduceBranch(taskID, started)
	out, runErr := opts.Runner.RunReproduction(runCtx, RunRequest{
		ProjectDir:  workDir,
		Provenance:  prov,
		Branch:      branch,
		TestCommand: testCmd,
		Timeout:     timeout,
	})
	if out != nil {
		rep.ExecutorID, rep.ExecutorKind = out.ExecutorID, out.ExecutorKind
		rep.Isolation, rep.PinnedImage = out.Isolation, out.PinnedImage
		rep.AgentExitCode = out.ExitCode
		rep.AgentOutput = tailOf(out.Output, maxAgentOutput)
		rep.ReplayTest = named(out.Test, framework)
		if out.BundlePath != "" {
			// Ours to remove: the bundle holds the agent's returned code and
			// the verdict is computed from it, not from keeping it.
			defer os.Remove(out.BundlePath)
		}
	}
	rep.Duration = time.Since(started)

	switch {
	case runErr != nil:
		rep.Err = runErr.Error()
		rep.Reason = "the reproduction could not be executed: " + runErr.Error()
		return rep, nil
	case out == nil:
		rep.Reason = "the sandbox runner returned no outcome"
		return rep, nil
	case out.Skipped || out.BundlePath == "":
		reason := strings.TrimSpace(out.SkipReason)
		if reason == "" {
			reason = "the sandbox produced no commit"
		}
		rep.Reason = "the reproduction returned no change to compare — " + reason
		return rep, nil
	}

	emit("comparing the reproduced commit against the original\n")
	cmp, cmpErr := CompareBundle(runCtx, workDir, out.BundlePath, out.Branch, prov)
	if cmpErr != nil {
		rep.Err = cmpErr.Error()
		rep.Reason = "the reproduced commit could not be compared: " + cmpErr.Error()
		return rep, nil
	}
	rep.Comparison = cmp
	rep.Duration = time.Since(started)

	// The behavioural gate runs only when it can change the answer: identical
	// trees are identical whatever the suite says, and running it anyway would
	// double the cost of the cheapest possible outcome.
	if !cmp.Identical && len(testCmd) > 0 {
		emit("running the project's tests against the original tree\n")
		orig, verr := opts.Runner.VerifyCommit(runCtx, VerifyRequest{
			ProjectDir:  workDir,
			Provenance:  prov,
			CommitSHA:   prov.OriginalCommit,
			TestCommand: testCmd,
			Timeout:     timeout,
		})
		if verr != nil {
			rep.Err = verr.Error()
		}
		rep.OriginalTest = named(orig, framework)
	}

	rep.Verdict, rep.Reason = verdictFor(cmp, rep.OriginalTest, rep.ReplayTest, len(testCmd) > 0, opts.SkipTests)
	emit(fmt.Sprintf("verdict: %s — %s\n", strings.ToUpper(string(rep.Verdict)), rep.Reason))
	return rep, nil
}

// verdictFor is the whole decision, separated from the plumbing so it can be
// tested against every combination without starting a sandbox.
func verdictFor(cmp *Comparison, original, replay *TestOutcome, haveTests, skipTests bool) (Verdict, string) {
	if cmp == nil {
		return VerdictInconclusive, "no comparison was produced"
	}

	// An unconfirmed base caps every verdict. A reproduction that started from
	// a tree already containing part of the change is not evidence about the
	// change: reaching the same tree is easy when most of it is already there,
	// and reaching a different one says nothing either.
	if !cmp.BaseConfirmed {
		return VerdictInconclusive, fmt.Sprintf(
			"the commit this task was based on is not recorded and could not be inferred reliably — "+
				"the write-back carried %d commits, so the reproduction did not start from the same tree the original did",
			cmp.OriginalCommits)
	}

	if cmp.Identical {
		return VerdictIdentical, fmt.Sprintf(
			"the reproduction produced the same tree (%s): the change is byte-for-byte reproducible",
			shortSHA(cmp.ReplayTree))
	}

	switch {
	case skipTests:
		return VerdictInconclusive, fmt.Sprintf(
			"the reproduction produced a different tree across %d file(s), and tests were skipped — "+
				"there is no evidence either way about whether the behaviour matches",
			len(cmp.FilesDiffering))
	case !haveTests:
		return VerdictInconclusive, fmt.Sprintf(
			"the reproduction produced a different tree across %d file(s), and this project has no "+
				"detectable test command to decide whether the behaviour is equivalent",
			len(cmp.FilesDiffering))
	case original == nil || replay == nil:
		return VerdictInconclusive, "the test command did not run on both trees, so equivalence could not be decided"
	case !original.Ran || !replay.Ran:
		return VerdictInconclusive, "the test command could not be executed on both trees, so equivalence could not be decided"
	case replay.Agrees(original):
		return VerdictEquivalent, fmt.Sprintf(
			"the reproduction produced different bytes across %d file(s), but %s passes on both trees",
			len(cmp.FilesDiffering), testLabel(replay))
	case original.Passed && !replay.Passed:
		return VerdictDivergent, fmt.Sprintf(
			"the reproduction produced a different change that fails %s, which the original passes",
			testLabel(replay))
	case !original.Passed && replay.Passed:
		return VerdictDivergent, fmt.Sprintf(
			"the reproduction produced a different change that passes %s, which the original fails",
			testLabel(replay))
	default:
		return VerdictDivergent, fmt.Sprintf(
			"the reproduction produced a different change across %d file(s), and %s fails on both trees",
			len(cmp.FilesDiffering), testLabel(replay))
	}
}

// testLabel names the suite in a sentence.
func testLabel(t *TestOutcome) string {
	if t != nil && strings.TrimSpace(t.Framework) != "" {
		return t.Framework
	}
	return "the project's tests"
}

// named stamps the detected framework onto an outcome the runner produced
// without one, so the record says which suite decided the verdict.
func named(t *TestOutcome, framework string) *TestOutcome {
	if t == nil {
		return nil
	}
	if strings.TrimSpace(t.Framework) == "" {
		t.Framework = framework
	}
	return t
}

// reproduceBranch names the write-back branch for one reproduction.
//
// Under the cloop/ prefix that ValidateWriteBackBranch requires and the git
// interception proxy allows (Task 20184), and stamped with the start time so
// two reproductions of the same task never collide. Nothing ever pushes it —
// the branch exists only inside the bundle — but it must still be a name the
// write-back machinery accepts.
func reproduceBranch(taskID int, at time.Time) string {
	return fmt.Sprintf("cloop/reproduce-%d-%d", taskID, at.UTC().Unix())
}

// tailOf returns at most n bytes from the end of s.
func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "[…truncated…]\n" + s[len(s)-n:]
}
