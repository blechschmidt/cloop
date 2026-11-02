package pm

// requirementstrace.go: the plan as the traceability matrix reads it (Task
// 20465; requirements/trace.go).

import (
	"github.com/blechschmidt/cloop/pkg/requirements"
)

// TracePlanTasks is plan's tasks as the traceability matrix reads them: each
// with the commits it records of its own work — where an isolated executor
// left it, and the HEAD the requirements gate checked it at when that had
// moved past where the task's work started. The gate's commit at the base is
// no commit of the task's: the work was not committed, and the gate says so
// with Dirty.
func TracePlanTasks(plan *Plan) []requirements.TracePlanTask {
	if plan == nil {
		return nil
	}
	views := TaskViews(plan)
	out := make([]requirements.TracePlanTask, 0, len(views))
	i := 0
	for _, t := range plan.Tasks {
		if t == nil {
			continue
		}
		pt := requirements.TracePlanTask{TaskView: views[i], Title: t.Title}
		i++
		if c := requirements.CleanCommit(t.WriteBackCommit); c != "" {
			pt.Commits = append(pt.Commits, requirements.TraceCommit{Hash: c, TaskID: t.ID,
				Source: requirements.CommitFromWriteBack})
		}
		if rc := t.RequirementsCheck; rc != nil {
			head, base := requirements.CleanCommit(rc.Commit), requirements.CleanCommit(rc.Base)
			if head != "" && head != base {
				pt.Commits = append(pt.Commits, requirements.TraceCommit{Hash: head, TaskID: t.ID,
					Source: requirements.CommitFromGate})
			}
		}
		out = append(out, pt)
	}
	return out
}
