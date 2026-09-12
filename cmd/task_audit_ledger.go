package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/archive"
	"github.com/blechschmidt/cloop/pkg/orchestrator"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	auditLedgerReopen bool
	auditLedgerJSON   bool
)

// LedgerFinding is one task recorded as done whose stored summary is a
// provider or harness refusal rather than any work.
type LedgerFinding struct {
	TaskID   int                     `json:"task_id"`
	Title    string                  `json:"title"`
	Status   pm.TaskStatus           `json:"status"`
	Class    orchestrator.AbortClass `json:"abort_class"`
	Reason   string                  `json:"reason"`
	Evidence string                  `json:"evidence"`
	Archived bool                    `json:"archived"`
	Reopened bool                    `json:"reopened"`
}

var taskAuditLedgerCmd = &cobra.Command{
	Use:   "audit-ledger",
	Short: "Find tasks recorded as done whose summary is a provider error",
	Long: `Scan the task ledger for tasks marked done that never actually ran.

Before the aborted-outcome fix, the orchestrator inferred success from the
agent process exiting rather than from evidence of completion: any output
without a TASK_DONE signal was promoted to done. A provider usage limit, an
exhausted quota, a rejected credential or a harness that refused to start all
produced a short message, no signal, and a task closed as complete. Tasks
recorded that way are invisible to the plan — they read as shipped, so
auto-evolve builds on them and nobody retries them.

This command replays the abort classifier over every task's stored summary and
reports the ones whose "work" is a refusal. --reopen resets them to pending so
they are picked up on the next run.

Examples:
  cloop task audit-ledger
  cloop task audit-ledger --json
  cloop task audit-ledger --reopen`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolving working directory: %w", err)
		}
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading project state: %w", err)
		}
		if s.Plan == nil {
			return fmt.Errorf("no task plan found in %s", workdir)
		}

		findings := auditPlanLedger(s.Plan)

		// Archived tasks carry the same corruption and the same consequence —
		// a reader of project history sees completed work that never
		// happened — so they are reported. They are not reopened: pulling a
		// task back out of the archive is what 'cloop task archive' undoes,
		// and doing it implicitly here would be a surprise.
		archived, archErr := archive.Load(workdir)
		if archErr == nil {
			for i := range archived {
				if f, ok := classifyLedgerTask(&archived[i].Task); ok {
					f.Archived = true
					findings = append(findings, f)
				}
			}
		}

		if auditLedgerReopen {
			reopened := reopenLedgerTasks(workdir, s, findings)
			for i := range findings {
				if !findings[i].Archived && reopened[findings[i].TaskID] {
					findings[i].Reopened = true
				}
			}
		}

		if auditLedgerJSON {
			if findings == nil {
				// A clean ledger is an empty list, not null — consumers
				// should be able to range over the result unconditionally.
				findings = []LedgerFinding{}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(findings)
		}
		printLedgerFindings(findings, auditLedgerReopen)
		return nil
	},
}

// auditPlanLedger returns the corrupted entries in a plan.
func auditPlanLedger(plan *pm.Plan) []LedgerFinding {
	var out []LedgerFinding
	for _, t := range plan.Tasks {
		if f, ok := classifyLedgerTask(t); ok {
			out = append(out, f)
		}
	}
	return out
}

// classifyLedgerTask reports whether a task's recorded outcome is a refusal
// wearing a done status.
//
// Only done tasks are candidates. A failed or skipped task whose summary is a
// provider error is already visible as not-complete, which is the outcome this
// command exists to restore; rewriting those would churn history for no gain.
//
// An empty summary is deliberately not the signature. Live, an empty response
// is an abort — the orchestrator classifies it as one. Stored, it only means
// no summary was ever recorded, which is true of dozens of tasks that
// genuinely shipped (this project's own #174 and #20043 among them). Treating
// absence as evidence here would reopen real work, so the audit demands a
// recognisable refusal message and nothing less.
func classifyLedgerTask(t *pm.Task) (LedgerFinding, bool) {
	if t == nil || t.Status != pm.TaskDone || strings.TrimSpace(t.Result) == "" {
		return LedgerFinding{}, false
	}
	ab, ok := orchestrator.ClassifyAbort(t.Result)
	if !ok || ab.Class == orchestrator.AbortEmptyOutput {
		return LedgerFinding{}, false
	}
	return LedgerFinding{
		TaskID:   t.ID,
		Title:    t.Title,
		Status:   t.Status,
		Class:    ab.Class,
		Reason:   ab.Reason,
		Evidence: ab.Evidence,
	}, true
}

// reopenLedgerTasks resets the in-plan findings to pending and persists the
// change, returning the set of task IDs actually reopened.
func reopenLedgerTasks(workdir string, s *state.ProjectState, findings []LedgerFinding) map[int]bool {
	reopened := map[int]bool{}
	byID := map[int]*pm.Task{}
	for _, t := range s.Plan.Tasks {
		byID[t.ID] = t
	}
	for _, f := range findings {
		if f.Archived {
			continue
		}
		t := byID[f.TaskID]
		if t == nil {
			continue
		}
		t.Status = pm.TaskPending
		t.CompletedAt = nil
		t.ActualMinutes = 0
		pm.AddAnnotation(t, "cloop", fmt.Sprintf(
			"Reopened by 'cloop task audit-ledger': recorded done, but the stored summary is a %s (%s). The work never ran.",
			f.Class, f.Reason))
		state.LogEventDetails(workdir, state.EventRow{
			Type:      state.EventTaskAborted,
			TaskID:    t.ID,
			TaskTitle: t.Title,
			Step:      state.NoStep,
			Message:   fmt.Sprintf("Task #%d reopened by ledger audit (%s): %s", t.ID, f.Class, f.Reason),
		}, map[string]any{
			"abort_class": string(f.Class),
			"reason":      f.Reason,
			"evidence":    f.Evidence,
			"source":      "audit-ledger",
			"reopened_at": time.Now().UTC().Format(time.RFC3339),
		})
		reopened[t.ID] = true
	}
	if len(reopened) > 0 {
		if err := s.Save(); err != nil {
			color.New(color.FgRed).Fprintf(os.Stderr, "failed to persist reopened tasks: %v\n", err)
			return map[int]bool{}
		}
	}
	return reopened
}

func printLedgerFindings(findings []LedgerFinding, reopen bool) {
	if len(findings) == 0 {
		color.New(color.FgGreen).Println("✓ No tasks recorded as done on a provider or harness error.")
		return
	}

	bold := color.New(color.Bold)
	warn := color.New(color.FgYellow)
	dim := color.New(color.Faint)

	bold.Printf("\n%d task(s) recorded as done whose summary is a refusal, not work:\n\n", len(findings))
	for _, f := range findings {
		marker := "✗"
		if f.Reopened {
			marker = "↻"
		}
		warn.Printf("  %s #%-6d %s\n", marker, f.TaskID, f.Title)
		dim.Printf("      %s — %s\n", f.Class, f.Reason)
		if f.Evidence != "" {
			dim.Printf("      %q\n", f.Evidence)
		}
		switch {
		case f.Archived:
			dim.Printf("      archived — reopen it with 'cloop task unarchive %d' if you want it retried\n", f.TaskID)
		case f.Reopened:
			dim.Println("      reset to pending")
		}
	}

	fmt.Println()
	if reopen {
		n := 0
		for _, f := range findings {
			if f.Reopened {
				n++
			}
		}
		color.New(color.FgGreen).Printf("Reopened %d task(s) — they will be picked up on the next run.\n", n)
		return
	}
	dim.Println("Re-run with --reopen to reset them to pending.")
}

func init() {
	taskAuditLedgerCmd.Flags().BoolVar(&auditLedgerReopen, "reopen", false, "reset the reported tasks to pending")
	taskAuditLedgerCmd.Flags().BoolVar(&auditLedgerJSON, "json", false, "output findings as JSON")
	taskCmd.AddCommand(taskAuditLedgerCmd)
}
