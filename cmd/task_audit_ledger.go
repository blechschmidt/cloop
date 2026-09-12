package cmd

// task_audit_ledger.go reports — and lets an operator resolve — tasks recorded
// as done whose stored summary is a provider or harness refusal rather than
// work.
//
// Before the aborted-outcome fix (Task 20211) the orchestrator inferred success
// from the agent process exiting: any output without a TASK_DONE signal was
// promoted to done. A usage limit, an exhausted quota, a rejected credential or
// a harness that refused to start all produced a short message, no signal, and
// a task closed as complete.
//
// This command used to be the only place those entries were visible, and
// nothing consulted it — not the orchestrator, not the dashboard. So the plan
// counted them, declared itself complete, and auto-evolve planned new work on
// top. Task 20224 changed that: the classification now lives on the task
// (pm.Task.Abort), the orchestrator sweeps for it before a plan may finish or
// evolve, and the dashboard renders it. This command is the CLI view of the
// same record and shares the same classifier, so the two cannot drift.

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/archive"
	"github.com/blechschmidt/cloop/pkg/orchestrator"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	auditLedgerReopen bool
	auditLedgerClear  bool
	auditLedgerNote   string
	auditLedgerIDs    string
	auditLedgerAll    bool
	auditLedgerJSON   bool
)

// LedgerFinding is one task recorded as done whose stored summary is a
// provider or harness refusal rather than any work.
type LedgerFinding struct {
	TaskID      int           `json:"task_id"`
	Title       string        `json:"title"`
	Status      pm.TaskStatus `json:"status"`
	Class       string        `json:"abort_class"`
	Reason      string        `json:"reason"`
	Evidence    string        `json:"evidence"`
	Cleared     bool          `json:"cleared"`
	ClearedBy   string        `json:"cleared_by,omitempty"`
	ClearedNote string        `json:"cleared_note,omitempty"`
	Archived    bool          `json:"archived"`
	Reopened    bool          `json:"reopened"`
}

var taskAuditLedgerCmd = &cobra.Command{
	Use:   "audit-ledger",
	Short: "Find tasks recorded as done whose summary is a provider error",
	Long: `Scan the task ledger for tasks marked done that never actually ran.

A provider usage limit, an exhausted quota, a rejected credential or a harness
that refused to start all produce a short message and no completion signal.
Tasks recorded that way read as shipped, so the plan counts them, auto-evolve
builds on them, and nobody retries them.

This replays the abort classifier over every task's stored summary and reports
the ones whose "work" is a refusal. Findings are persisted on the task, so the
orchestrator's pre-completion sweep and the dashboard see exactly what is
listed here.

There are two ways to resolve a finding, and both are recorded:

  --reopen   the work never happened; reset the task to pending so it runs.
  --clear    the work exists anyway because a later task re-landed it. Needs
             --note saying where it landed, because a clearance without a
             reason cannot be told apart from giving up on the audit.

Restrict either to specific tasks with --ids; --reopen alone needs --all, so a
bulk reset of the ledger is never a typo.

Examples:
  cloop task audit-ledger
  cloop task audit-ledger --json
  cloop task audit-ledger --reopen --ids 194,195,196
  cloop task audit-ledger --clear --ids 193 --note "re-landed by cmd/task_tdd.go"
  cloop task audit-ledger --reopen --all`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if auditLedgerReopen && auditLedgerClear {
			return fmt.Errorf("--reopen and --clear are opposite verdicts; pick one")
		}
		if auditLedgerClear && strings.TrimSpace(auditLedgerNote) == "" {
			return fmt.Errorf("--clear needs --note: say where the work actually landed")
		}
		selected, err := parseLedgerIDs(auditLedgerIDs)
		if err != nil {
			return err
		}
		mutating := auditLedgerReopen || auditLedgerClear
		if mutating && len(selected) == 0 && !auditLedgerAll {
			return fmt.Errorf("no tasks selected: pass --ids 194,195 or --all")
		}
		if auditLedgerClear && auditLedgerAll {
			return fmt.Errorf("--clear --all would dismiss every finding at once; select with --ids")
		}

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

		// Classify and persist first, so a plain report leaves the plan in the
		// state the orchestrator will read — the report and the sweep agree by
		// construction rather than by coincidence.
		findings, dirty := auditPlanLedger(s.Plan)

		if mutating {
			changed := applyLedgerVerdicts(workdir, s, selected)
			dirty = dirty || changed > 0
			for i := range findings {
				if findings[i].Archived {
					continue
				}
				if t := s.Plan.TaskByID(findings[i].TaskID); t != nil {
					findings[i].Reopened = auditLedgerReopen && t.Status == pm.TaskPending
					if t.Abort != nil {
						findings[i].Cleared = t.Abort.Cleared
						findings[i].ClearedBy = t.Abort.ClearedBy
						findings[i].ClearedNote = t.Abort.ClearedNote
					}
					findings[i].Status = t.Status
				}
			}
		}
		if dirty {
			if err := s.Save(); err != nil {
				return fmt.Errorf("persisting ledger findings: %w", err)
			}
		}

		// Archived tasks carry the same corruption and the same consequence —
		// a reader of project history sees completed work that never
		// happened — so they are reported. They are not reopened: pulling a
		// task back out of the archive is what 'cloop task archive' undoes,
		// and doing it implicitly here would be a surprise.
		if archived, archErr := archive.Load(workdir); archErr == nil {
			for i := range archived {
				if rec := orchestrator.ClassifyStoredOutcome(&archived[i].Task); rec != nil {
					f := findingFrom(&archived[i].Task, rec)
					f.Archived = true
					findings = append(findings, f)
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
		printLedgerFindings(findings, mutating)
		return nil
	},
}

// parseLedgerIDs turns "194,195, 196" into a set.
func parseLedgerIDs(raw string) (map[int]bool, error) {
	out := map[int]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid task id %q in --ids", part)
		}
		out[n] = true
	}
	return out, nil
}

// auditPlanLedger classifies every task in the plan, attaching any finding to
// the task, and returns the findings plus whether the plan was modified.
func auditPlanLedger(plan *pm.Plan) ([]LedgerFinding, bool) {
	var out []LedgerFinding
	dirty := false
	for _, t := range plan.Tasks {
		if t == nil {
			continue
		}
		rec := orchestrator.ClassifyStoredOutcome(t)
		if rec == nil {
			if t.Status == pm.TaskDone && t.Abort != nil && !pm.AbortAppliesTo(t.Abort, t.Result) {
				t.Abort = nil
				dirty = true
			}
			continue
		}
		if t.Abort != rec {
			t.Abort = rec
			dirty = true
		}
		out = append(out, findingFrom(t, rec))
	}
	return out, dirty
}

func findingFrom(t *pm.Task, rec *pm.TaskAbort) LedgerFinding {
	return LedgerFinding{
		TaskID:      t.ID,
		Title:       t.Title,
		Status:      t.Status,
		Class:       rec.Class,
		Reason:      rec.Reason,
		Evidence:    rec.Evidence,
		Cleared:     rec.Cleared,
		ClearedBy:   rec.ClearedBy,
		ClearedNote: rec.ClearedNote,
	}
}

// applyLedgerVerdicts records the operator's decision on the selected tasks and
// returns how many it changed.
func applyLedgerVerdicts(workdir string, s *state.ProjectState, selected map[int]bool) int {
	n := 0
	for _, t := range s.Plan.Tasks {
		if t == nil || t.Abort == nil {
			continue
		}
		if len(selected) > 0 && !selected[t.ID] {
			continue
		}
		if auditLedgerClear {
			t.Abort.Clear("cli", auditLedgerNote)
			pm.AddAnnotation(t, "cloop", fmt.Sprintf(
				"Aborted-outcome finding cleared via CLI: %s", auditLedgerNote))
			state.LogEventDetails(workdir, state.EventRow{
				Type:      state.EventTaskStatusChange,
				TaskID:    t.ID,
				TaskTitle: t.Title,
				Step:      state.NoStep,
				Message: fmt.Sprintf("Task #%d aborted-outcome finding cleared: %s",
					t.ID, auditLedgerNote),
			}, map[string]any{
				"abort_class": t.Abort.Class,
				"note":        auditLedgerNote,
				"source":      "audit-ledger",
			})
			n++
			continue
		}
		// --reopen. A cleared finding is left alone unless it was named
		// explicitly: a bulk --all must not silently undo verified triage.
		if t.Abort.Cleared && len(selected) == 0 {
			continue
		}
		t.Abort.Cleared = false
		t.Abort.ClearedBy = ""
		t.Abort.ClearedNote = ""
		t.Abort.ClearedAt = nil
		t.Status = pm.TaskPending
		t.CompletedAt = nil
		t.ActualMinutes = 0
		pm.AddAnnotation(t, "cloop", fmt.Sprintf(
			"Reopened by 'cloop task audit-ledger': recorded done, but the stored summary is a %s (%s). The work never ran.",
			t.Abort.Class, t.Abort.Reason))
		state.LogEventDetails(workdir, state.EventRow{
			Type:      state.EventTaskAborted,
			TaskID:    t.ID,
			TaskTitle: t.Title,
			Step:      state.NoStep,
			Message:   fmt.Sprintf("Task #%d reopened by ledger audit (%s): %s", t.ID, t.Abort.Class, t.Abort.Reason),
		}, map[string]any{
			"abort_class": t.Abort.Class,
			"reason":      t.Abort.Reason,
			"evidence":    t.Abort.Evidence,
			"source":      "audit-ledger",
		})
		n++
	}
	return n
}

func printLedgerFindings(findings []LedgerFinding, mutated bool) {
	if len(findings) == 0 {
		color.New(color.FgGreen).Println("✓ No tasks recorded as done on a provider or harness error.")
		return
	}

	bold := color.New(color.Bold)
	warn := color.New(color.FgYellow)
	dim := color.New(color.Faint)

	open := 0
	for _, f := range findings {
		if !f.Cleared {
			open++
		}
	}

	bold.Printf("\n%d ledger entr%s recorded as done on a refusal, not work (%d still open):\n\n",
		len(findings), plural(len(findings), "y", "ies"), open)
	for _, f := range findings {
		marker, c := "✗", warn
		switch {
		case f.Reopened:
			marker = "↻"
		case f.Cleared:
			marker, c = "✓", dim
		}
		c.Printf("  %s #%-6d %s\n", marker, f.TaskID, f.Title)
		dim.Printf("      %s — %s\n", f.Class, f.Reason)
		if f.Evidence != "" {
			dim.Printf("      %q\n", f.Evidence)
		}
		switch {
		case f.Archived:
			dim.Printf("      archived — reopen it with 'cloop task unarchive %d' if you want it retried\n", f.TaskID)
		case f.Reopened:
			dim.Println("      reset to pending")
		case f.Cleared:
			dim.Printf("      checked%s: %s\n", byWhom(f.ClearedBy), f.ClearedNote)
		}
	}

	fmt.Println()
	if mutated {
		color.New(color.FgGreen).Println("Ledger updated.")
		return
	}
	if open > 0 {
		dim.Println("Resolve each with --reopen --ids <list> (the work never ran) or")
		dim.Println("--clear --ids <list> --note \"...\" (a later task re-landed it).")
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func byWhom(who string) string {
	if who == "" {
		return ""
	}
	return " by " + who
}

func init() {
	taskAuditLedgerCmd.Flags().BoolVar(&auditLedgerReopen, "reopen", false, "reset the selected tasks to pending — the work never ran")
	taskAuditLedgerCmd.Flags().BoolVar(&auditLedgerClear, "clear", false, "record that the work exists despite the refusal summary (needs --note)")
	taskAuditLedgerCmd.Flags().StringVar(&auditLedgerNote, "note", "", "evidence for --clear: where the work actually landed")
	taskAuditLedgerCmd.Flags().StringVar(&auditLedgerIDs, "ids", "", "comma-separated task IDs to act on")
	taskAuditLedgerCmd.Flags().BoolVar(&auditLedgerAll, "all", false, "with --reopen, act on every open finding")
	taskAuditLedgerCmd.Flags().BoolVar(&auditLedgerJSON, "json", false, "output findings as JSON")
	taskCmd.AddCommand(taskAuditLedgerCmd)
}
