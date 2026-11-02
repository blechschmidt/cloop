package orchestrator

// requirements.go gives the agent working on a task the requirements the task
// implements, as its acceptance contract (Task 20460). See
// requirements.ContractSection for what the agent is told.
//
// The requirements are read from the project's database when the prompt is
// built, not carried on the task: a requirement edited while the task waited is
// the one the task is held to. On an executor that does not share the hub's
// database the seed filled that database's requirements table with the ones
// the plan links (projectseed.BuildWith), so the run there reads the same.

import (
	"strings"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// requirementContract is the contract section of task's prompt: empty for a
// task that implements no requirement. A database that cannot be read leaves
// the links named, so the agent is told its contract exists and could not be
// shown rather than told nothing.
func (o *Orchestrator) requirementContract(task *pm.Task) string {
	if task == nil || len(task.Requirements) == 0 {
		return ""
	}
	all, err := o.projectRequirements()
	if err != nil {
		color.New(color.Faint).Printf("  requirements of task %d unavailable: %v\n", task.ID, err)
	}
	return requirements.ContractSection(requirements.Resolve(task.Requirements, all))
}

// requirementStatus is where the project's approved requirements stand
// against plan (Task 20463): what an evolve round is shown, and holds what it
// proposes to. On a device the run's database is a seeded copy, and the facts
// the seed carried from the hub stand in for the checks it does not hold
// (statedb.RequirementFacts). Best effort: a database that cannot be read
// plans as a project without requirements does, and says so.
func (o *Orchestrator) requirementStatus(plan *pm.Plan) requirements.StatusSummary {
	db, err := statedb.Open(state.DBPath(o.config.WorkDir))
	if err != nil {
		color.New(color.Faint).Printf("  requirement status unavailable: %v\n", err)
		return requirements.StatusSummary{}
	}
	defer db.Close()
	facts, omitted, err := db.AsProject().RequirementFacts()
	if err != nil {
		color.New(color.Faint).Printf("  requirement status unavailable: %v\n", err)
		return requirements.StatusSummary{}
	}
	sum := requirements.Summarize(facts, pm.TaskViews(plan))
	sum.Omitted = omitted
	return sum
}

// linkedRequirements names the requirements t implements, for a line that
// lists it: " (R-3, R-5)", or nothing.
func linkedRequirements(t *pm.Task) string {
	if len(t.Requirements) == 0 {
		return ""
	}
	keys := make([]string, len(t.Requirements))
	for i, id := range t.Requirements {
		keys[i] = requirements.Key(id)
	}
	return " (" + strings.Join(keys, ", ") + ")"
}

// projectRequirements reads the project's requirements.
func (o *Orchestrator) projectRequirements() ([]requirements.Requirement, error) {
	db, err := statedb.Open(state.DBPath(o.config.WorkDir))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return db.AsProject().Requirements()
}
