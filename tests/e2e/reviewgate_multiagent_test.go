package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// The review gate in multi-agent mode, end to end with the real binary (Task
// 20365). Before this, `cloop run --multi-agent` built options of its own for
// its three sub-agents and none of them carried the gate's push hold: the
// coder's `git push` went straight to the remote, unreviewed, and the gate
// reviewed work that had already been published.
//
// `claude` is a stub that plays every part, told apart by what it is asked:
// the gate's reviewer when called with --tools (read-only), otherwise the
// pipeline's architect, coder or reviewer by the closing line of its prompt.
// The coder commits and pushes.
const multiAgentGateStub = `#!/bin/bash
prompt="$(cat)"
args="$*"
if [[ " $args " == *" --tools "* ]]; then
  echo "gate review" >> "$STUB_DIR/calls.log"
  git -C "$REMOTE" rev-parse refs/heads/main >> "$STUB_DIR/remote-at-review"
  if [ -n "$STUB_REJECT" ]; then
    echo '{"verdict":"request_changes","summary":"hello.txt greets nobody.","findings":[{"severity":"major","file":"hello.txt","line":1,"title":"missing name","detail":"greet the world"}]}'
  else
    echo '{"verdict":"approve","summary":"Fine."}'
  fi
  exit 0
fi
case "$prompt" in
  *"Design the technical approach for this task."*)
    echo "architect" >> "$STUB_DIR/calls.log"
    [[ "$prompt" == *"## REVIEW GATE"* ]] && echo "architect was told about the gate" >> "$STUB_DIR/calls.log"
    echo "Design: write hello.txt and push it."
    exit 0 ;;
  *"Implement the task following the architect's design above."*)
    echo "coder" >> "$STUB_DIR/calls.log"
    [[ "$prompt" == *"## REVIEW GATE"* ]] && echo "coder was told about the gate" >> "$STUB_DIR/calls.log"
    echo "hello" > hello.txt
    git add hello.txt && git commit -q -m "add hello"
    git push >> "$STUB_DIR/push.log" 2>&1
    echo "push exit $?" >> "$STUB_DIR/push.log"
    echo "Committed and pushed."
    echo "TASK_DONE"
    exit 0 ;;
  *"Review the implementation and emit your verdict."*)
    echo "pipeline reviewer" >> "$STUB_DIR/calls.log"
    echo "The implementation matches the design."
    echo "TASK_DONE"
    exit 0 ;;
esac
echo "unexpected call: $args" >> "$STUB_DIR/calls.log"
echo "TASK_DONE"
`

func setupMultiAgentGateE2E(t *testing.T) gateE2E {
	t.Helper()
	g := setupGateE2E(t)
	if err := os.WriteFile(filepath.Join(g.stubDir, "claude"), []byte(multiAgentGateStub), 0o755); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestE2EReviewGateHoldsMultiAgentPushesUntilApproval(t *testing.T) {
	g := setupMultiAgentGateE2E(t)
	mustRun(t, g.project, "review", "gate", "--enable", "--mode", "block")

	runOut, err := g.run(t, nil, "run", "--multi-agent")
	if err != nil {
		t.Fatalf("cloop run --multi-agent: %v\n%s", err, runOut)
	}

	calls := readFile(t, filepath.Join(g.stubDir, "calls.log"))
	for _, want := range []string{"architect", "coder", "pipeline reviewer", "gate review",
		"architect was told about the gate", "coder was told about the gate"} {
		if !strings.Contains(calls, want+"\n") {
			t.Fatalf("calls do not include %q:\n%s\nrun output:\n%s", want, calls, runOut)
		}
	}
	// The coder's push was held, not sent.
	pushes := readFile(t, filepath.Join(g.stubDir, "push.log"))
	if !strings.Contains(pushes, "held by cloop's review gate") || strings.Contains(pushes, "push exit 0") {
		t.Fatalf("the sub-agent's push was not held:\n%s", pushes)
	}
	// The remote had not moved when the gate reviewed.
	for _, sha := range strings.Fields(readFile(t, filepath.Join(g.stubDir, "remote-at-review"))) {
		if sha != g.initial {
			t.Fatalf("the remote moved before the gate approved: %s", sha)
		}
	}
	// After approval cloop pushed the reviewed work.
	if got := g.remoteFile(t, "hello.txt"); got != "hello" {
		t.Fatalf("remote hello.txt = %q after approval\nrun output:\n%s", got, runOut)
	}

	s, err := state.Load(g.project)
	if err != nil {
		t.Fatal(err)
	}
	task := s.Plan.TaskByID(1)
	if task == nil || task.Status != pm.TaskDone || task.Review == nil || task.Review.Verdict != pm.ReviewApproved {
		t.Fatalf("task = %+v", task)
	}
	if len(task.Review.Published) != 1 || task.Review.Published[0].Outcome != pm.PublishPushed {
		t.Fatalf("publish record = %+v", task.Review.Published)
	}
}

// The case the defect made dangerous: the gate rejects the work, and the
// sub-agent's push must not already be on the remote.
func TestE2EReviewGateRejectionKeepsMultiAgentWorkOffTheRemote(t *testing.T) {
	g := setupMultiAgentGateE2E(t)
	mustRun(t, g.project, "review", "gate", "--enable", "--mode", "block")

	runOut, _ := g.run(t, []string{"STUB_REJECT=1"}, "run", "--multi-agent")

	if got := g.remoteFile(t, "hello.txt"); got != "" {
		t.Fatalf("a rejected multi-agent task's work reached the remote: %q\n%s", got, runOut)
	}
	pushes := readFile(t, filepath.Join(g.stubDir, "push.log"))
	if !strings.Contains(pushes, "held by cloop's review gate") {
		t.Fatalf("the sub-agent's push was not held:\n%s", pushes)
	}
	s, err := state.Load(g.project)
	if err != nil {
		t.Fatal(err)
	}
	task := s.Plan.TaskByID(1)
	if task == nil || task.Status != pm.TaskFailed || task.Review == nil || !task.Review.Blocked {
		t.Fatalf("task = %+v", task)
	}
	if len(task.Review.Published) != 1 || task.Review.Published[0].Outcome != pm.PublishWithheld {
		t.Errorf("publish record = %+v", task.Review.Published)
	}
}
