package ui

// task_requirements_api.go: the requirements a task implements (Task 20460),
// as the task API takes them and as a requirement's details show them.
//
// POST /api/task/add, POST /api/tasks, POST /api/task/edit and PUT/PATCH
// /api/tasks/{id} accept `requirements`: a list of requirement ids, 3 or
// "R-3". On an edit it replaces the task's list, [] clears it, and leaving it
// out leaves the list alone.
//
// A link is checked against the requirements of the task's own project — the
// one the request is scoped to, which the route's authorization already
// decided the caller may write. Ids are each project's own, so there is no way
// to name another project's requirement: an id that exists only there names
// nothing here, and is refused like any unknown id.

import (
	"net/http"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
)

// checkTaskRequirements checks ids as the requirements a task of workDir's
// project implements, given those it implements now, and returns the list to
// store — or writes the refusal and returns false: 400 for an id the project
// has no requirement for, or a new link to a deprecated one.
func checkTaskRequirements(w http.ResponseWriter, workDir string, ids, already []int) ([]int, bool) {
	if len(ids) == 0 {
		return nil, true
	}
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return nil, false
	}
	defer db.Close()
	reqs, err := db.Requirements()
	if err != nil {
		requirementErr(w, err)
		return nil, false
	}
	out, err := requirements.CheckLinks(ids, reqs, already)
	if err != nil {
		requirementErr(w, err)
		return nil, false
	}
	return out, true
}

// implementingTask is a task as a requirement's details list it.
type implementingTask struct {
	ID     int           `json:"id"`
	Title  string        `json:"title"`
	Status pm.TaskStatus `json:"status"`
}

// tasksImplementing maps each requirement to the tasks of plan that implement
// it, in task order.
func tasksImplementing(plan *pm.Plan) map[int][]implementingTask {
	out := map[int][]implementingTask{}
	if plan == nil {
		return out
	}
	for _, t := range plan.Tasks {
		if t == nil {
			continue
		}
		for _, id := range t.Requirements {
			out[id] = append(out[id], implementingTask{ID: t.ID, Title: t.Title, Status: t.Status})
		}
	}
	return out
}

// planOf reads workDir's plan for the requirements views, or nil: a list of
// requirements without the tasks that implement them is still the list.
func planOf(workDir string) *pm.Plan {
	ps, err := state.LoadLite(workDir)
	if err != nil {
		return nil
	}
	return ps.Plan
}
