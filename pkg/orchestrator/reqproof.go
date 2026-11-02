package orchestrator

// reqproof.go: the requirements gate's red-green proofs (Task 20464).
//
// A check that passes says the task's requirements' tests pass. When the task
// added or changed those tests, it does not say they test anything: a test the
// agent wrote to pass passes. So once a gate check finds a task's work meets
// its requirements, the gate proves the tests the task touched — `cloop
// requirements prove --base=<where the task's work started> --only-changed
// --before-only` where the run runs, beside the work: the tests are run on the
// code before the task, in a throwaway checkout of the base with the task's
// test files laid over it, and the check that just passed is their run on the
// change. Each proof is recorded with the project's requirement proofs, tied
// to the task, and kept on the task's verdict (pm.RequirementVerdict.Proof).
//
// In linked+must mode a vacuous proof of a test the task added keeps the task
// from being done: back to pending with the explanation in its next prompt,
// like any requirement that fails the gate — a test that passes without the
// change does not show the requirement is met. In linked mode a proof is
// recorded and shown, and decides nothing. A proof that could not run, or
// could not settle it, never blocks.
//
// The base is captured when an attempt opens its guard: the HEAD of the tree
// it works in. An attempt the gate sent back starts from the earlier attempt's
// work, so its guard takes the base the gate recorded for the task instead
// (pm.TaskRequirementsCheck.Base) — while that commit is still an ancestor of
// its HEAD — or a proof of the second attempt's test would run it against the
// first attempt's implementation and call it vacuous.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// requirementsProveDispatch runs one `cloop requirements prove` and returns
// what it printed on stdout. A variable so a test can stand in for the
// executor's cloop; production runs this binary (runRequirementsProve).
var requirementsProveDispatch = runRequirementsProve

// proveGraceful is how long a proof is given to remove its checkout after it
// is asked to stop, before it is killed.
const proveGraceful = 30 * time.Second

// openProofBase is where the attempt's work starts, for a proof of the tests
// it adds or changes: HEAD of dir, or the base the gate recorded for the task
// when this attempt follows one the gate sent back.
func openProofBase(ctx context.Context, dir string, task *pm.Task) string {
	head := gitCommitAt(ctx, dir, "HEAD")
	if head == "" {
		return ""
	}
	prev := task.RequirementsCheck
	if prev == nil || prev.Base == "" || prev.Decision != requirementsDecisionRequeued {
		return head
	}
	if prev.Base == head || gitIsAncestor(ctx, dir, prev.Base, head) {
		return prev.Base
	}
	return head
}

// testsKey is what a requirement's tests are, for telling whether a task
// changed them.
func testsKey(r requirements.Requirement) string {
	b, _ := json.Marshal(r.Tests)
	return string(b)
}

// prove proves, after a check that met, the tests the task added or changed
// among the requirements in scope that passed, and records what it found on
// rc. It reports whether the run stopped while it worked.
func (g *requirementsGuard) prove(scope []gateScoped, results []requirements.Result, rc *pm.TaskRequirementsCheck, runID string) (interrupted bool) {
	if g.base == "" || rc == nil || !rc.Met() {
		return false
	}
	rc.Base = g.base
	var asked []requirements.Requirement
	var at []int
	var changed []string
	for i, sc := range scope {
		if !sc.req.Tested() || results[i].Verdict != requirements.VerdictFulfilled || results[i].Method != requirements.MethodTests {
			continue
		}
		asked = append(asked, sc.req)
		at = append(at, i)
		if was, ok := g.testsAtOpen[sc.req.ID]; !ok || was != testsKey(sc.req) {
			changed = append(changed, strconv.Itoa(sc.req.ID))
		}
	}
	if len(asked) == 0 {
		return false
	}
	ctx := g.stop
	cctx, cancel := context.WithTimeout(ctx, min(requirements.ProofBudget(asked, true), maxRequirementsGateTime))
	defer cancel()
	var rep requirements.ProofReport
	for _, batch := range requirements.Batches(asked) {
		if requirements.OversizedBatch(batch) || cctx.Err() != nil {
			continue
		}
		spec, err := requirements.EncodeSpec(requirements.Spec{Requirements: batch})
		if err != nil {
			continue
		}
		args := []string{"requirements", "prove", "--json", "--no-record", "--spec=" + string(spec), "--base=" + g.base,
			"--base-from=" + requirements.BaseFromTask, "--only-changed", "--before-only"}
		var mine []string
		for _, q := range batch {
			if slices.Contains(changed, strconv.Itoa(q.ID)) {
				mine = append(mine, strconv.Itoa(q.ID))
			}
		}
		if len(mine) > 0 {
			args = append(args, "--changed="+strings.Join(mine, ","))
		}
		out, runErr := requirementsProveDispatch(cctx, g.dir, g.env, args)
		if ctx.Err() != nil {
			return true
		}
		got, err := readProofReport(out, runErr)
		if err != nil {
			g.warn("prove the tests the task touched", err)
			continue
		}
		rep.Results = append(rep.Results, got.Results...)
	}
	if len(rep.Results) == 0 {
		return false
	}
	byID := map[int]requirements.Proof{}
	for _, p := range rep.Results {
		if _, dup := byID[p.RequirementID]; !dup {
			byID[p.RequirementID] = p
		}
	}
	now := time.Now().UTC()
	scrub := gateScrubber()
	var proofs []requirements.Proof
	for k, req := range asked {
		p, ok := byID[req.ID]
		if !ok {
			continue
		}
		// The change's side is the check that just passed, on this tree.
		res := results[at[k]]
		p.After = requirements.ProofSide{Commit: rc.Commit, Dirty: rc.Dirty, Verdict: res.Verdict, Summary: res.Summary,
			Tests: res.Tests}
		p = requirements.SanitizeProof(p, req, scrub, now)
		proofs = append(proofs, p)
		v := &rc.Requirements[at[k]]
		kept := p.Clone()
		requirements.BoundProof(&kept, pm.MaxTaskRequirementOutputBytes)
		v.Proof = &kept
		if g.gate.IncludesMust() && p.Outcome == requirements.ProofVacuous && p.NewTests {
			v.Blocking = true
			rc.Outcome = pm.RequirementsUnmet
		}
	}
	g.recordProofs(runID, proofs)
	return false
}

// readProofReport reads a dispatched proof's framed report.
func readProofReport(out []byte, runErr error) (requirements.ProofReport, error) {
	payload, perr := clijson.Extract(out)
	if perr == nil {
		var failed struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(payload, &failed) == nil && failed.Error != "" {
			return requirements.ProofReport{}, errors.New(failed.Error)
		}
		var rep requirements.ProofReport
		if err := json.Unmarshal(payload, &rep); err == nil && rep.Results != nil {
			return rep, nil
		}
	}
	if runErr != nil {
		return requirements.ProofReport{}, runErr
	}
	return requirements.ProofReport{}, fmt.Errorf("the proof sent back no report: %v", perr)
}

// recordProofs stores the gate's proofs with the project's requirement
// proofs, tied to the task and to the check's run. A failure is reported:
// the task's own record carries the proofs either way.
func (g *requirementsGuard) recordProofs(runID string, proofs []requirements.Proof) {
	if len(proofs) == 0 {
		return
	}
	db, err := statedb.Open(state.DBPath(g.o.config.WorkDir))
	if err != nil {
		g.warn("record the proofs", err)
		return
	}
	defer db.Close()
	db.AsProject()
	if _, err := db.RecordRequirementProofs(statedb.ProofRecord{RunID: runID, ExecutorID: g.executorID,
		ProvedBy: requirementsGateActor, TaskID: g.taskID}, proofs); err != nil {
		g.warn("record the proofs", err)
		return
	}
	run := statedb.RequirementRun{RunID: runID, State: statedb.RequirementRunDone, Source: requirementsGateSource,
		ExecutorID: g.executorID, TaskID: g.taskID, Kind: statedb.RequirementRunKindProve}
	for _, p := range proofs {
		run.RequirementIDs = append(run.RequirementIDs, p.RequirementID)
	}
	statedb.AuditRequirementProof(db, run, proofs, requirementsGateActor)
	if !g.o.log.IsJSON() {
		for _, p := range proofs {
			c := color.New(color.Faint)
			switch p.Outcome {
			case requirements.ProofProven:
				c = color.New(color.FgGreen)
			case requirements.ProofVacuous, requirements.ProofBroken:
				c = color.New(color.FgRed)
			}
			c.Printf("    %-6s proof: %s\n", requirements.Key(p.RequirementID), sanitizeLine(requirements.ProofHeadline(p)))
		}
	}
}

// runRequirementsProve is runRequirementsCheck for a proof: this binary, in
// dir, in its own process group — but asked to stop with SIGTERM, and given
// proveGraceful to remove its checkout before the group is killed.
func runRequirementsProve(ctx context.Context, dir string, env []string, args []string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot locate the cloop binary: %w", err)
	}
	if strings.HasSuffix(exe, ".test") {
		return nil, errors.New("running under go test, where there is no cloop binary to prove requirements with")
	}
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = dir
	cmd.Env = env
	stdout := &cappedBuffer{max: maxCheckStdoutBytes}
	stderr := &cappedBuffer{max: maxCheckStderrBytes, tail: true}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		// The proof's own process only: it stops its test and removes its
		// checkout, which the group's death would leave behind.
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = proveGraceful
	err = cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if stdout.over {
		return nil, fmt.Errorf("the proof printed more than %d MiB", maxCheckStdoutBytes>>20)
	}
	if err != nil {
		why := strings.Join(strings.Fields(stderr.String()), " ")
		if why != "" {
			return stdout.Bytes(), fmt.Errorf("%v: %s", err, why)
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}

// gitCommitAt is the commit rev names in dir, or "" when it names none.
func gitCommitAt(ctx context.Context, dir, rev string) string {
	out, err := gitQuiet(ctx, dir, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		return ""
	}
	return requirements.CleanCommit(strings.TrimSpace(out))
}

// gitIsAncestor reports whether a is an ancestor of b in dir.
func gitIsAncestor(ctx context.Context, dir, a, b string) bool {
	_, err := gitQuiet(ctx, dir, "merge-base", "--is-ancestor", a, b)
	return err == nil
}

// gitQuiet runs a read-only git in dir: bounded, no optional locks, no hooks,
// no prompt.
func gitQuiet(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-c", "core.hooksPath=" + os.DevNull}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

// vacuousText is what a re-queued task is told about a requirement whose new
// test passed without its change.
func vacuousText(v pm.RequirementVerdict) string {
	var b strings.Builder
	p := v.Proof
	fmt.Fprintf(&b, "%s %s — vacuous: its tests pass, and pass without this task's change too\n",
		requirements.Key(v.RequirementID), sanitizeLine(v.Title))
	base := shortCommit(p.Before.Commit)
	where := "the commit the task started from, " + base
	if p.Fallback {
		where += ", with the task's test files laid over it"
	}
	fmt.Fprintf(&b, "  A red-green proof ran them on the code before the task (%s), and they passed there.\n", where)
	for _, t := range p.Before.Tests {
		fmt.Fprintf(&b, "  $ %s — %s before the change\n", oneLineCommand(t.Command), t.Outcome)
	}
	if len(p.TestFiles) > 0 {
		names := make([]string, 0, len(p.TestFiles))
		for i, f := range p.TestFiles {
			if i == 8 {
				names = append(names, "…")
				break
			}
			names = append(names, sanitizeLine(f.Path))
		}
		fmt.Fprintf(&b, "  The task's test files: %s\n", strings.Join(names, ", "))
	}
	return b.String()
}

// anyVacuous reports whether a check kept its task back for a vacuous test.
func anyVacuous(rc *pm.TaskRequirementsCheck) bool {
	return rc != nil && slices.ContainsFunc(rc.Requirements, func(v pm.RequirementVerdict) bool { return v.Vacuous() })
}
