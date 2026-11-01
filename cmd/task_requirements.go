package cmd

// task_requirements.go: `--requirement` on `cloop task add` and `cloop task
// edit` (Task 20460) — the requirements a task implements. Each one's details
// and tests become the task's acceptance contract when it runs (see
// requirements.ContractSection).

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const requirementFlagUsage = "A requirement this task implements, R-3 or 3 (repeatable, or comma-separated): " +
	"its details and tests become the task's acceptance contract"

// taskRequirementLinks checks refs as the requirements a task of the project
// in workDir implements, given the ones it implements now, and returns the
// list to store. "none" alone clears it. An id the project has no requirement
// for, or a new link to a deprecated one, is refused.
func taskRequirementLinks(workDir string, refs []string, already []int) ([]int, error) {
	if len(refs) == 1 && strings.EqualFold(strings.TrimSpace(refs[0]), "none") {
		return nil, nil
	}
	ids, err := requirements.ParseRefs(refs)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	reqs, err := db.AsProject().Requirements()
	if err != nil {
		return nil, err
	}
	return requirements.CheckLinks(ids, reqs, already)
}

// taskKeys names task ids as people read them: task #4, tasks #4, #9.
func taskKeys(ids []int) string {
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = fmt.Sprintf("#%d", id)
	}
	if len(keys) == 1 {
		return "task " + keys[0]
	}
	return "tasks " + strings.Join(keys, ", ")
}

// requirementKeys names ids as people read them: R-3, R-5.
func requirementKeys(ids []int) string {
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = requirements.Key(id)
	}
	return strings.Join(keys, ", ")
}
