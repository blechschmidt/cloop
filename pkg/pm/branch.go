package pm

import "strconv"

// BranchActivation records the result of evaluating one branch entry after a task completes.
type BranchActivation struct {
	TaskID    int
	Title     string
	Activated bool   // true = task kept/reset to pending; false = task skipped
	Branch    string // "on_success" or "on_failure"
}

// ResolveBranch evaluates conditional branching after a task completes.
//
// Rules:
//   - outcome TaskDone   → activate on_success tasks, skip on_failure tasks
//   - outcome TaskFailed → activate on_failure tasks, skip on_success tasks
//   - outcome TaskSkipped or other → no branch changes
//
// "Activate" means: if the target task is pending leave it alone;
// if it was skipped (deactivated by a prior branch evaluation) reset it to pending.
// "Skip" means: if the target task is pending mark it skipped.
// Tasks that are already done/in_progress/failed are never touched.
func ResolveBranch(plan *Plan, task *Task) []BranchActivation {
	if len(task.OnSuccess) == 0 && len(task.OnFailure) == 0 {
		return nil
	}
	if task.Status != TaskDone && task.Status != TaskFailed {
		return nil
	}

	// Build ID→task map.
	byID := make(map[int]*Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		byID[t.ID] = t
	}

	var activateBranch, skipBranch []string
	var activateName, skipName string
	if task.Status == TaskDone {
		activateBranch = task.OnSuccess
		skipBranch = task.OnFailure
		activateName = "on_success"
		skipName = "on_failure"
	} else {
		activateBranch = task.OnFailure
		skipBranch = task.OnSuccess
		activateName = "on_failure"
		skipName = "on_success"
	}

	var result []BranchActivation

	for _, idStr := range activateBranch {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}
		t, ok := byID[id]
		if !ok {
			continue
		}
		// Only touch pending or previously-skipped tasks.
		if t.Status == TaskDone || t.Status == TaskInProgress || t.Status == TaskFailed || t.Status == TaskTimedOut {
			continue
		}
		if t.Status == TaskSkipped {
			t.Status = TaskPending
		}
		// Already pending — no change needed.
		result = append(result, BranchActivation{
			TaskID:    id,
			Title:     t.Title,
			Activated: true,
			Branch:    activateName,
		})
	}

	for _, idStr := range skipBranch {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}
		t, ok := byID[id]
		if !ok {
			continue
		}
		if t.Status != TaskPending {
			continue
		}
		t.Status = TaskSkipped
		result = append(result, BranchActivation{
			TaskID:    id,
			Title:     t.Title,
			Activated: false,
			Branch:    skipName,
		})
	}

	return result
}
