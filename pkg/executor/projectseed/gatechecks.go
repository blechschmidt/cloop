package projectseed

// gatechecks.go records, on the hub, the requirements gate verdicts a run on a
// device reached (Task 20461).
//
// The run checked its tasks' requirements where it ran and recorded each
// check in its own copy of the project, which never comes back. What comes
// back is the task, carrying the gate's record of its last check
// (pm.Task.RequirementsCheck). The hub turns that record into its own
// requirement checks, tied to the task and the commit, so the Requirements tab
// shows a device run's verdicts beside a local run's — and it reads the record
// as what it is, the executor's report: through requirements.Sanitize, with
// the hub's own definitions. The commands, test names and fingerprints stored
// are the hub's; a test result the record has no place for in the hub's
// definition, or a requirement the hub has since changed or deleted, is not
// stored at all.

import (
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// gateCheckActor is who a requirements gate check is recorded as.
const gateCheckActor = "requirements-gate"

// recordGateChecks stores checks as the project's requirement checks and runs,
// and returns how many checks it stored. assess is whether the hub's gate asks
// the model about untested requirements: an AI verdict the hub did not ask
// for reads as unverified, whatever the device says.
func recordGateChecks(workDir string, assess bool, checks []gateCheck, prov Provenance, scrub func(string) string) (int, error) {
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return 0, fmt.Errorf("projectseed: open %s to record the run's requirement checks: %w", workDir, err)
	}
	defer db.Close()
	db.AsProject()
	all, err := db.Requirements()
	if err != nil {
		return 0, fmt.Errorf("projectseed: read %s's requirements: %w", workDir, err)
	}
	byID := make(map[int]requirements.Requirement, len(all))
	for _, r := range all {
		byID[r.ID] = r
	}
	now := time.Now().UTC()
	stored := 0
	var errs []error
	for _, gc := range checks {
		c := gc.check
		if c == nil || len(c.Requirements) == 0 {
			continue
		}
		rep := requirements.Report{Commit: c.Commit, Dirty: c.Dirty}
		var asked []requirements.Requirement
		for _, v := range c.Requirements {
			hub, ok := byID[v.RequirementID]
			// A definition the hub has changed since the run checked it is
			// not what the run checked.
			if !ok || hub.Fingerprint() != v.Fingerprint {
				continue
			}
			asked = append(asked, hub)
			rep.Results = append(rep.Results, v.Result)
		}
		if len(asked) == 0 {
			continue
		}
		clean := requirements.Sanitize(rep, asked, assess, scrub, now)
		got, err := db.RecordRequirementChecks(statedb.CheckRecord{
			RunID: c.RunID, Commit: clean.Commit, Dirty: clean.Dirty, ExecutorID: prov.ExecutorID,
			CheckedBy: gateCheckActor, TaskID: gc.taskID,
		}, clean.Results)
		if err != nil {
			errs = append(errs, fmt.Errorf("projectseed: record task #%d's requirement checks: %w", gc.taskID, err))
			continue
		}
		stored += len(got)
		run := statedb.RequirementRun{
			RunID: c.RunID, State: statedb.RequirementRunDone, Source: "gate", StartedBy: gateCheckActor,
			StartedAt: c.CheckedAt, FinishedAt: c.CheckedAt, ExecutorID: prov.ExecutorID, Assess: assess,
			Counts: requirements.Tally(clean.Results), TaskID: gc.taskID,
		}
		if run.StartedAt.IsZero() || run.StartedAt.After(now.Add(time.Hour)) {
			run.StartedAt, run.FinishedAt = now, now
		}
		for _, r := range clean.Results {
			run.RequirementIDs = append(run.RequirementIDs, r.RequirementID)
		}
		if err := db.RecordFinishedRequirementRun(run); err != nil {
			errs = append(errs, fmt.Errorf("projectseed: record task #%d's requirement check run: %w", gc.taskID, err))
			continue
		}
		statedb.AuditRequirementCheck(db, run, clean.Commit, clean.Dirty, gateCheckActor)
		if err := recordGateProofs(db, c, byID, gc.taskID, prov, scrub, now); err != nil {
			errs = append(errs, fmt.Errorf("projectseed: record task #%d's requirement proofs: %w", gc.taskID, err))
		}
	}
	return stored, errors.Join(errs...)
}

// recordGateProofs stores the red-green proofs a device's gate made of the
// tests a task added or changed (Task 20464), read like its checks: through
// requirements.SanitizeProof with the hub's own definitions, and only for a
// requirement whose definition is still the one proved.
func recordGateProofs(db *statedb.DB, c *pm.TaskRequirementsCheck, byID map[int]requirements.Requirement, taskID int,
	prov Provenance, scrub func(string) string, now time.Time) error {
	var proofs []requirements.Proof
	for _, v := range c.Requirements {
		if v.Proof == nil {
			continue
		}
		hub, ok := byID[v.RequirementID]
		if !ok || hub.Fingerprint() != v.Fingerprint || v.Proof.RequirementID != v.RequirementID {
			continue
		}
		proofs = append(proofs, requirements.SanitizeProof(*v.Proof, hub, scrub, now))
	}
	if len(proofs) == 0 {
		return nil
	}
	if _, err := db.RecordRequirementProofs(statedb.ProofRecord{RunID: c.RunID, ExecutorID: prov.ExecutorID,
		ProvedBy: gateCheckActor, TaskID: taskID}, proofs); err != nil {
		return err
	}
	run := statedb.RequirementRun{RunID: c.RunID, State: statedb.RequirementRunDone, Source: "gate",
		ExecutorID: prov.ExecutorID, TaskID: taskID, Kind: statedb.RequirementRunKindProve}
	for _, p := range proofs {
		run.RequirementIDs = append(run.RequirementIDs, p.RequirementID)
	}
	statedb.AuditRequirementProof(db, run, proofs, gateCheckActor)
	return nil
}
