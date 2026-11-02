package orchestrator

// The requirements gate's red-green proofs (Task 20464), through real runs of
// the orchestrator: the agent is scripted, the gate's check is fakeCheck, and
// the proof is the real pkg/reqproof run in process against the project's
// real git repository — the base checked out, the task's test file laid over
// it, the test run there.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/reqproof"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// inProcessProve stands in for the dispatched `cloop requirements prove`:
// the same flags read, pkg/reqproof run here.
type inProcessProve struct {
	mu    sync.Mutex
	calls [][]string
}

func (p *inProcessProve) install(t *testing.T) {
	t.Helper()
	prev := requirementsProveDispatch
	requirementsProveDispatch = p.run
	t.Cleanup(func() { requirementsProveDispatch = prev })
}

func (p *inProcessProve) run(ctx context.Context, dir string, env []string, args []string) ([]byte, error) {
	p.mu.Lock()
	p.calls = append(p.calls, append([]string(nil), args...))
	p.mu.Unlock()
	opts := reqproof.Options{Dir: dir, Env: env, Changed: map[int]bool{}}
	var spec requirements.Spec
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--spec="):
			sp, err := requirements.ParseSpec([]byte(strings.TrimPrefix(a, "--spec=")))
			if err != nil {
				return nil, err
			}
			spec = sp
		case strings.HasPrefix(a, "--base="):
			opts.Base = strings.TrimPrefix(a, "--base=")
		case strings.HasPrefix(a, "--base-from="):
			opts.BaseFrom = strings.TrimPrefix(a, "--base-from=")
		case a == "--only-changed":
			opts.OnlyChanged = true
		case a == "--before-only":
			opts.BeforeOnly = true
		case strings.HasPrefix(a, "--changed="):
			for _, id := range strings.Split(strings.TrimPrefix(a, "--changed="), ",") {
				n, _ := strconv.Atoi(id)
				opts.Changed[n] = true
			}
		}
	}
	rep, _ := reqproof.Prove(ctx, spec.Requirements, opts)
	var b bytes.Buffer
	err := clijson.Emit(&b, rep)
	return b.Bytes(), err
}

func (p *inProcessProve) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

// writeAndCommit writes files (path → content) in dir and commits them.
func writeAndCommit(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "agent work"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func gitHead(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func taskProofs(t *testing.T, dir string, reqID int) []statedb.RequirementProof {
	t.Helper()
	proofs, err := openProjectDB(t, dir).RequirementProofs(reqID, 0)
	if err != nil {
		t.Fatal(err)
	}
	return proofs
}

const (
	gateOldLib     = "greet() { echo hello; }\n"
	gateNewLib     = "greet() { echo 'hello, world'; }\n"
	gateVacuous    = ". ./lib.sh\ngreet >/dev/null\n"
	gateProvenTest = ". ./lib.sh\n[ \"$(greet)\" = 'hello, world' ]\n"
)

// In linked+must mode a new test that passes without the task's change keeps
// the task back, with the reason in its next prompt; a later attempt's test
// is proved against where the task's work started — not against the first
// attempt's implementation — and once it shows the change the task is done.
func TestRequirementsGate_VacuousNewTestBlocksInLinkedMust(t *testing.T) {
	check := &fakeCheck{}
	check.install(t)
	prove := &inProcessProve{}
	prove.install(t)
	repo := gatedProject(t, &pm.RequirementsGate{Mode: pm.RequirementsGateLinkedMust},
		[]requirements.Requirement{tested("Greets the world", "sh tests/greet_test.sh", requirements.PriorityMust)},
		[][]int{{1}}, "Greet the world")
	writeAndCommit(t, repo, map[string]string{"lib.sh": gateOldLib})
	base := gitHead(t, repo)

	worker := &gateWorker{do: func(dir, prompt string, call int) string {
		switch call {
		case 0:
			writeAndCommit(t, dir, map[string]string{"lib.sh": gateNewLib, "tests/greet_test.sh": gateVacuous})
		default:
			writeAndCommit(t, dir, map[string]string{"tests/greet_test.sh": gateProvenTest})
		}
		return "done\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	calls := worker.snapshot()
	if len(calls) != 2 {
		t.Fatalf("the agent ran %d times, want the task and its retry", len(calls))
	}
	retry := calls[1].prompt
	for _, want := range []string{"## REQUIREMENTS NOT MET ON THE LAST ATTEMPT", "R-1 Greets the world — vacuous",
		"A red-green proof ran them on the code before the task", base[:12], "tests/greet_test.sh",
		"fails on the code as it", "$ sh tests/greet_test.sh — pass before the change"} {
		if !strings.Contains(retry, want) {
			t.Errorf("the retry's prompt does not say %q:\n%s", want, retry)
		}
	}
	if strings.Contains(retry, "Fix the work so these checks pass") {
		t.Error("the retry was told its checks fail, when they passed and proved nothing")
	}

	task := loadTask(t, repo, 1)
	if task.Status != pm.TaskDone {
		t.Fatalf("status = %s, want done", task.Status)
	}
	rc := task.RequirementsCheck
	if !rc.Met() || rc.Base != base || len(rc.Requirements) != 1 || rc.Requirements[0].Proof == nil ||
		rc.Requirements[0].Proof.Outcome != requirements.ProofProven {
		t.Fatalf("the task's record = %+v", rc)
	}
	if !hasAnnotation(task, "R-1 vacuous (its new test passes without the change)") {
		t.Errorf("no note of the vacuous test: %+v", task.Annotations)
	}

	proofs := taskProofs(t, repo, 1)
	if len(proofs) != 2 || proofs[1].Outcome != requirements.ProofVacuous || proofs[0].Outcome != requirements.ProofProven {
		t.Fatalf("recorded proofs = %+v", proofs)
	}
	for _, p := range proofs {
		if p.TaskID != 1 || p.Before.Commit != base || p.BaseFrom != requirements.BaseFromTask || !p.NewTests ||
			!p.Fallback || p.ProvedBy != requirementsGateActor {
			t.Errorf("recorded proof %+v", p)
		}
	}
	// The proof runs ahead of nothing else: no checkout of the base is left.
	if entries, _ := os.ReadDir(filepath.Join(repo, ".cloop", "worktrees")); len(entries) != 0 {
		t.Errorf("proof checkouts left behind: %v", entries)
	}
}

// In linked mode a vacuous proof is recorded and shown, and the task is done.
func TestRequirementsGate_VacuousProofOnlyRecordedInLinked(t *testing.T) {
	check := &fakeCheck{}
	check.install(t)
	prove := &inProcessProve{}
	prove.install(t)
	repo := gatedProject(t, &pm.RequirementsGate{Mode: pm.RequirementsGateLinked},
		[]requirements.Requirement{tested("Greets the world", "sh tests/greet_test.sh", requirements.PriorityMust)},
		[][]int{{1}}, "Greet the world")
	writeAndCommit(t, repo, map[string]string{"lib.sh": gateOldLib})
	worker := &gateWorker{do: func(dir, prompt string, call int) string {
		writeAndCommit(t, dir, map[string]string{"lib.sh": gateNewLib, "tests/greet_test.sh": gateVacuous})
		return "done\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(worker.snapshot()); n != 1 {
		t.Fatalf("the agent ran %d times, want once", n)
	}
	task := loadTask(t, repo, 1)
	rc := task.RequirementsCheck
	if task.Status != pm.TaskDone || !rc.Met() || rc.Requirements[0].Proof == nil ||
		rc.Requirements[0].Proof.Outcome != requirements.ProofVacuous || rc.Requirements[0].Blocking {
		t.Fatalf("status %s, record %+v", task.Status, rc)
	}
	if !strings.Contains(rc.Headline(), "tests proved red-green: R-1 vacuous") {
		t.Errorf("headline: %s", rc.Headline())
	}
	if p := taskProofs(t, repo, 1); len(p) != 1 || p[0].Outcome != requirements.ProofVacuous {
		t.Fatalf("recorded proofs = %+v", p)
	}
}

// A task that leaves its requirements' tests alone has nothing proved: the
// proof passes it over without running anything.
func TestRequirementsGate_NoProofWhenTheTaskLeavesTheTestsAlone(t *testing.T) {
	check := &fakeCheck{}
	check.install(t)
	prove := &inProcessProve{}
	prove.install(t)
	repo := gatedProject(t, &pm.RequirementsGate{Mode: pm.RequirementsGateLinkedMust},
		[]requirements.Requirement{tested("Greets the world", "sh tests/greet_test.sh", requirements.PriorityMust)},
		[][]int{{1}}, "Tidy the greeting")
	writeAndCommit(t, repo, map[string]string{"lib.sh": gateNewLib, "tests/greet_test.sh": gateProvenTest})
	worker := &gateWorker{do: func(dir, prompt string, call int) string {
		writeAndCommit(t, dir, map[string]string{"lib.sh": "greet() { echo 'hello, world'; } # tidied\n"})
		return "done\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	task := loadTask(t, repo, 1)
	if task.Status != pm.TaskDone || task.RequirementsCheck.Requirements[0].Proof != nil {
		t.Fatalf("status %s, record %+v", task.Status, task.RequirementsCheck)
	}
	if prove.count() != 1 {
		t.Fatalf("the proof was asked %d times, want once (to be told the tests are untouched)", prove.count())
	}
	if p := taskProofs(t, repo, 1); len(p) != 0 {
		t.Fatalf("a proof was recorded for tests the task did not touch: %+v", p)
	}
}

func TestOpenProofBaseCarriesOverAGateRetry(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initTestRepo(t)
	writeAndCommit(t, repo, map[string]string{"a": "1"})
	first := gitHead(t, repo)
	writeAndCommit(t, repo, map[string]string{"a": "2"})
	head := gitHead(t, repo)
	ctx := context.Background()
	if got := openProofBase(ctx, repo, &pm.Task{}); got != head {
		t.Fatalf("a first attempt starts at %s, want HEAD %s", got, head)
	}
	requeued := &pm.Task{RequirementsCheck: &pm.TaskRequirementsCheck{Base: first, Decision: requirementsDecisionRequeued}}
	if got := openProofBase(ctx, repo, requeued); got != first {
		t.Fatalf("an attempt the gate sent back starts at %s, want the task's base %s", got, first)
	}
	met := &pm.Task{RequirementsCheck: &pm.TaskRequirementsCheck{Base: first, Decision: requirementsDecisionMet}}
	if got := openProofBase(ctx, repo, met); got != head {
		t.Fatalf("a task the gate let through starts again at %s, want HEAD", got)
	}
	gone := &pm.Task{RequirementsCheck: &pm.TaskRequirementsCheck{Base: strings.Repeat("ab", 20), Decision: requirementsDecisionRequeued}}
	if got := openProofBase(ctx, repo, gone); got != head {
		t.Fatalf("a base no longer in the history: got %s, want HEAD", got)
	}
}
