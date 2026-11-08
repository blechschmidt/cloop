package cmd

// cloop task gate: human review gates in the task list (Task 20477).

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	gateAddAfter  int
	gateAddBefore int
	gateAddTitle  string
	gateAddNote   string
	gateAddJSON   bool
)

var taskGateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Add, approve or reopen human review gates in the task list",
	Long: `A human review gate is an entry in the task list that no agent runs. When a
run reaches it, which means every task ahead of it has finished, the run stops.
That gives a person the chance to look at what those tasks produced, edit the
tasks still to come, or add new ones ahead of the gate before the run goes on.

A gate keeps its place in the queue like any task: move it with
'cloop task move <id> up|down' or drag it in the dashboard. Starting a run
while a gate is closed runs whatever is ahead of it, then stops at the gate
again. Approving the gate lets the next run carry on past it.

Examples:
  cloop task gate add --after 4              # stop once task 4 is done
  cloop task gate add --before 7 --title "Check the schema" --note "Look at the migration first"
  cloop task gate add                        # stop once everything queued now is done
  cloop task gate approve 12
  cloop task gate reopen 12                  # make the run stop there again`,
}

var taskGateAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Put a human review gate into the run queue",
	Long: `Put a human review gate into the run queue. Without a position it goes to the
end, so the run stops once everything queued now has finished. --after N puts it
right after task N; if task N has already run, that is the head of the queue.
--before N puts it right before task N, which must still be queued.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if s.Plan == nil {
			s.Plan = pm.NewPlan(s.Goal)
			s.PMMode = true
		}
		gate := pm.NewHumanGate(gateAddTitle, gateAddNote)
		gate.ID = s.Plan.NextTaskID()
		if err := s.Plan.InsertInQueue(gate, gateAddAfter, gateAddBefore); err != nil {
			return err
		}
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
		state.LogEvent(workdir, state.EventRow{
			Type:      state.EventTaskAdded,
			TaskID:    gate.ID,
			TaskTitle: gate.Title,
			Step:      state.NoStep,
			Message:   fmt.Sprintf("Review gate #%d added via CLI: %s", gate.ID, gate.Title),
		})
		if gateAddJSON {
			return clijson.Emit(cmd.OutOrStdout(), gate)
		}
		color.New(color.FgGreen).Printf("Added review gate #%d: %s\n", gate.ID, gate.Title)
		held := 0
		for _, t := range s.Plan.Queue() {
			if t.IsWork() && pm.HeldBy(gate, t) {
				held++
			}
		}
		color.New(color.Faint).Printf("  The run stops here once the tasks ahead of it finish; %d queued task(s) wait behind it.\n", held)
		return nil
	},
}

var taskGateApproveCmd = &cobra.Command{
	Use:   "approve <id>",
	Short: "Approve a human review gate so the run can continue past it",
	Long: `Approve a human review gate: it is recorded as passed, and the tasks behind it
may run. If a run stopped at the gate, start it again with 'cloop run'.

An agent working on a task cannot approve a gate: the command refuses inside a
task's run, so a review cannot be signed off by the work it reviews.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return approveFromCLI(args[0], true)
	},
}

var taskGateReopenCmd = &cobra.Command{
	Use:   "reopen <id>",
	Short: "Close an approved or bypassed gate again, so the run stops there",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setTaskStatus(args[0], pm.TaskPending)
	},
}

// errApprovalInsideRun refuses an approval from inside a task's run: the
// orchestrator puts CLOOP_TASK_ID in every agent's environment, and a person
// at a terminal has none. It guards against an agent signing off its own
// review by accident — it is not a security boundary, since an agent on a
// local executor can write the project's database directly.
var errApprovalInsideRun = errors.New("refusing to approve from inside a task's run: " +
	"a review gate is a person's decision, not the agent's")

func insideTaskRun() bool {
	return strings.TrimSpace(os.Getenv(attachments.EnvTaskID)) != ""
}

// approveFromCLI approves task idStr: a human review gate is opened and
// recorded as passed; a task that requires approval is pre-approved, as
// 'cloop task approve' always did. gateOnly refuses an ordinary task.
func approveFromCLI(idStr string, gateOnly bool) error {
	if insideTaskRun() {
		return errApprovalInsideRun
	}
	workdir, _ := os.Getwd()
	s, err := state.Load(workdir)
	if err != nil {
		return err
	}
	if s.Plan == nil {
		return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid task ID %q: must be a number", idStr)
	}
	task := s.Plan.TaskByID(id)
	if task == nil {
		return fmt.Errorf("task %d not found: %w", id, statedb.ErrTaskNotFound)
	}
	if task.IsWork() {
		if gateOnly {
			return fmt.Errorf("task %d is not a review gate; 'cloop task approve %d' pre-approves a task that requires approval", id, id)
		}
		task.Approved = true
		if err := s.Save(); err != nil {
			return err
		}
		recordCLIApproval(workdir, task, false)
		color.New(color.FgGreen).Printf("Task %d pre-approved: %s\n", task.ID, task.Title)
		color.New(color.Faint).Printf("  This task will bypass the interactive approval gate on next run.\n")
		return nil
	}
	if !task.GateClosed() {
		color.New(color.Faint).Printf("Review gate #%d is already open (%s): %s\n", id, task.Status, task.Title)
		return nil
	}
	waiting := s.Status == "paused" && s.PauseReason != nil && s.PauseReason.TaskID == id
	old := task.Status
	pm.ApproveGate(task, operatorActor(), time.Now())
	if err := s.Save(); err != nil {
		return err
	}
	auditManualTaskStatus(workdir, id, old, task.Status)
	recordCLIApproval(workdir, task, waiting)
	color.New(color.FgGreen).Printf("Review gate #%d approved: %s\n", id, task.Title)
	if waiting {
		color.New(color.Faint).Printf("  The run stopped here. Start it again with 'cloop run' to continue.\n")
	} else {
		color.New(color.Faint).Printf("  Runs no longer stop at it.\n")
	}
	return nil
}

// recordCLIApproval writes an approval's audit row and journal entry.
// Best-effort: the approval is saved either way.
func recordCLIApproval(workdir string, task *pm.Task, waiting bool) {
	actor := operatorActor()
	if db, err := statedb.Open(state.DBPath(workdir)); err == nil {
		statedb.AuditTaskGateApprove(db, task, waiting, actor, "cloop task gate approve")
		db.Close()
	} else {
		fmt.Fprintf(os.Stderr, "[audit] record approval of task %d: %v\n", task.ID, err)
	}
	what := "Task"
	if !task.IsWork() {
		what = "Review gate"
	}
	state.LogEventDetails(workdir, state.EventRow{
		Type:      state.EventReviewGate,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      state.NoStep,
		Message:   fmt.Sprintf("%s #%d approved by %s: %s", what, task.ID, actor, task.Title),
	}, map[string]any{"action": "approved", "by": actor, "waiting": waiting, "kind": string(task.Kind)})
}

// gateState describes a gate for the task list.
func gateState(plan *pm.Plan, g *pm.Task) string {
	switch {
	case g.Status == pm.TaskDone:
		return "approved"
	case g.Status == pm.TaskSkipped:
		return "bypassed"
	case g.Approved:
		return "approved, the run goes past it next"
	case plan.WaitingGate() == g:
		return "waiting for review"
	case plan.GateBarrier() == g:
		return "the run stops here"
	default:
		return "closed"
	}
}

func init() {
	f := taskGateAddCmd.Flags()
	f.IntVar(&gateAddAfter, "after", 0, "Put the gate right after this task")
	f.IntVar(&gateAddBefore, "before", 0, "Put the gate right before this task, which must still be queued")
	f.StringVar(&gateAddTitle, "title", "", "What the gate is for (default \""+pm.DefaultGateTitle+"\")")
	f.StringVar(&gateAddNote, "note", "", "What the reviewer should look at")
	f.BoolVar(&gateAddJSON, "json", false, "Print the new gate as JSON")
	taskGateCmd.AddCommand(taskGateAddCmd, taskGateApproveCmd, taskGateReopenCmd)
	taskCmd.AddCommand(taskGateCmd)
}
