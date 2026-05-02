package pm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// MoveResult holds the outcome of a Move operation.
type MoveResult struct {
	// Task is the task as it now exists in the destination plan (new ID).
	Task *Task
	// SrcTaskID is the original ID in the source plan.
	SrcTaskID int
	// DstTaskID is the newly assigned ID in the destination plan.
	DstTaskID int
}

// Move relocates a task from one cloop project directory to another.
//
// The source task is marked as skipped in the source plan (preserving history).
// A copy is appended to the destination plan with a new ID that does not conflict
// with any existing task IDs in that plan. Both plans are saved atomically (source
// first, then destination).
//
// When adapt is true, the AI rewrites the task title and description to suit the
// destination project's goal. p and opts must be non-nil in that case.
//
// LoadState and SaveState are callbacks so the caller (cmd layer) controls how
// state is loaded/saved — this keeps pkg/pm free of pkg/state imports.
func Move(
	ctx context.Context,
	srcPlan *Plan,
	dstPlan *Plan,
	dstGoal string,
	taskID int,
	adapt bool,
	p provider.Provider,
	opts provider.Options,
) (*MoveResult, error) {
	// Find the task in the source plan.
	var srcTask *Task
	for _, t := range srcPlan.Tasks {
		if t.ID == taskID {
			srcTask = t
			break
		}
	}
	if srcTask == nil {
		return nil, fmt.Errorf("task %d not found in source plan", taskID)
	}

	// Mark it skipped in the source (preserves history, signals it was moved).
	srcTask.Status = TaskSkipped

	// Deep-copy the task for the destination.
	tc := *srcTask
	if tc.DependsOn != nil {
		tc.DependsOn = append([]int{}, tc.DependsOn...)
	}
	if tc.Tags != nil {
		tc.Tags = append([]string{}, tc.Tags...)
	}

	// Clear execution state — it starts fresh in the destination.
	tc.Status = TaskPending
	tc.StartedAt = nil
	tc.CompletedAt = nil
	tc.Result = ""
	tc.ArtifactPath = ""
	tc.HealAttempts = 0
	tc.ActualMinutes = 0

	// Assign a new ID that doesn't conflict with anything already in the destination.
	tc.ID = nextAvailableID(dstPlan)

	// AI-driven description adaptation.
	if adapt {
		if p == nil {
			return nil, fmt.Errorf("--adapt requires a configured AI provider")
		}
		adaptContext := buildMoveAdaptContext(dstGoal, dstPlan)
		prompt := ClonePrompt(srcTask, adaptContext)
		result, err := p.Complete(ctx, prompt, opts)
		if err != nil {
			return nil, fmt.Errorf("move adapt: provider error: %w", err)
		}
		adapted, err := parseMoveAdaptResponse(result.Output)
		if err != nil {
			return nil, fmt.Errorf("move adapt: parse error: %w", err)
		}
		tc.Title = adapted.Title
		tc.Description = adapted.Description
	}

	// Remove inter-plan dependency references (they point to source task IDs).
	tc.DependsOn = nil

	dstPlan.Tasks = append(dstPlan.Tasks, &tc)

	return &MoveResult{
		Task:      &tc,
		SrcTaskID: taskID,
		DstTaskID: tc.ID,
	}, nil
}

// nextAvailableID returns max(existing IDs)+1, or 1 if the plan is empty.
func nextAvailableID(plan *Plan) int {
	max := 0
	for _, t := range plan.Tasks {
		if t.ID > max {
			max = t.ID
		}
	}
	return max + 1
}

// buildMoveAdaptContext constructs a concise adaptation context string that
// describes the destination project so the AI can rewrite the task.
func buildMoveAdaptContext(dstGoal string, dstPlan *Plan) string {
	var b strings.Builder
	b.WriteString("The task is being moved to a different project.\n\n")
	if dstGoal != "" {
		b.WriteString(fmt.Sprintf("Destination project goal: %s\n\n", dstGoal))
	}
	if len(dstPlan.Tasks) > 0 {
		b.WriteString("Existing tasks in the destination project (for context):\n")
		limit := 10
		for i, t := range dstPlan.Tasks {
			if i >= limit {
				b.WriteString(fmt.Sprintf("  ... and %d more\n", len(dstPlan.Tasks)-limit))
				break
			}
			b.WriteString(fmt.Sprintf("  - %s\n", t.Title))
		}
		b.WriteString("\n")
	}
	b.WriteString("Rewrite the task title and description so they fit naturally in the destination project. " +
		"Preserve the original intent and scope, but adjust any project-specific references.")
	return b.String()
}

// parseMoveAdaptResponse is an alias to the same JSON extraction used by clone.
func parseMoveAdaptResponse(response string) (*cloneItem, error) {
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON object found in response")
	}
	var item cloneItem
	if err := json.Unmarshal([]byte(response[start:end+1]), &item); err != nil {
		return nil, fmt.Errorf("parsing move adapt response: %w", err)
	}
	if item.Title == "" {
		return nil, fmt.Errorf("adapt produced a task with no title")
	}
	return &item, nil
}
