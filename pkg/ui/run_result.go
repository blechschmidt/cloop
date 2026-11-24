package ui

// run_result.go brings a run on an isolating executor home (Task 20339).
//
// A project bound to an executor that cannot read this hub's filesystem is
// carried out as a seed (workspace.go), and the run on the far side records its
// outcomes in its own copy. The dashboard renders *this* hub's copy. Until this
// file nothing connected the two, and the operator saw exactly what the task
// that motivated it reported: start the run, watch a transcript end with "All
// tasks complete", and find the task still pending — the run "completed
// immediately although there is one remaining task". Starting it again ran the
// task again.
//
// Now the executor reads back what the run changed and sends it before the
// run's final status (see pkg/executor/agent/projectresult.go), and runEnded —
// the one place every dispatch path settles a finished run — merges it into the
// hub's copy before anything else looks at the plan. Dead-run recovery runs
// after the merge, so a task the run left in progress is recovered from the
// run's own account of it rather than from a plan that never heard it started.
//
// Every outcome is written to the project's journal, including the ones where
// nothing could be merged: "this executor is too old to report back" and "the
// run ended without reporting" are the two cases in which the dashboard is
// stale, and a journal row naming why is the difference between an explained
// stale task and the bug this file fixes.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// seededDispatch is what the hub knew about a dispatch that carried its project
// out: the provenance a merge stamps, which the device does not get a say in.
type seededDispatch struct {
	prov projectseed.Provenance
	// feature is set for a feature's run on an isolating executor: what its
	// returned work is landed against (Task 20367).
	feature *featureReturn
}

// maxSeededDispatches bounds the registry. An entry lives from dispatch to
// runEnded; the few paths that start a run and then lose sight of it (a stream
// that cannot be opened) would otherwise leak one entry each for the life of
// the process. Far above any real number of concurrent runs.
const maxSeededDispatches = 1024

var (
	seededMu    sync.Mutex
	seeded      = map[string]seededDispatch{}
	seededOrder []string
)

func seededKey(executorID, handleID string) string { return executorID + "\x00" + handleID }

// rememberSeededDispatch records that handleID on ex was sent the project.
func rememberSeededDispatch(ex executor.Executor, handleID string, prov projectseed.Provenance) {
	key := seededKey(ex.ID(), handleID)
	seededMu.Lock()
	defer seededMu.Unlock()
	if _, ok := seeded[key]; !ok {
		seededOrder = append(seededOrder, key)
	}
	seeded[key] = seededDispatch{prov: prov}
	for len(seededOrder) > maxSeededDispatches {
		delete(seeded, seededOrder[0])
		seededOrder = seededOrder[1:]
	}
}

// peekSeededDispatch returns the record for handleID on ex without forgetting
// it, so the run's owner row can carry the provenance to a member that adopts
// the run (Task 20354).
func peekSeededDispatch(ex executor.Executor, handleID string) (seededDispatch, bool) {
	if ex == nil || handleID == "" {
		return seededDispatch{}, false
	}
	seededMu.Lock()
	defer seededMu.Unlock()
	d, ok := seeded[seededKey(ex.ID(), handleID)]
	return d, ok
}

// isSeededDispatch reports whether handleID on ex was sent the project and has
// not been settled yet, without forgetting it.
func isSeededDispatch(ex executor.Executor, handleID string) bool {
	if ex == nil || handleID == "" {
		return false
	}
	seededMu.Lock()
	defer seededMu.Unlock()
	_, ok := seeded[seededKey(ex.ID(), handleID)]
	return ok
}

// overlaySeededRun is this hub's view of a seeded run in flight, over the
// project state about to be served: the run's status (Task 20349) and the plan
// it is working through (Task 50). Every reader of /api/state and of the state
// broadcasts goes through it, so the dashboard shows one answer.
func (s *Server) overlaySeededRun(workDir string, ps *state.ProjectState) {
	s.overlaySeededRunStatus(workDir, ps)
	s.overlaySeededRunPlan(workDir, ps)
}

// overlaySeededRunStatus reports a seeded run that is in flight as running
// (Task 20349).
//
// A run on an executor that does not share this filesystem works on a copy of
// the project and brings its state back only when it ends (collectRunResult).
// Until then the hub's state.db still holds the previous run's status, so every
// reader of /api/state and of the state broadcasts saw a finished project while
// a device was working through it. The live flag and the tracked handle are the
// hub's own knowledge that the run is under way, and the wire state says so.
//
// Only a seeded run: a run on this filesystem writes its own status, and
// overriding it would misreport one that is already pausing or finishing.
func (s *Server) overlaySeededRunStatus(workDir string, ps *state.ProjectState) {
	if ps == nil || workDir == "" || ps.Status == "running" || ps.Status == "evolving" {
		return
	}
	if _, live := s.seededRunLive(workDir); !live {
		return
	}
	ps.Status = "running"
	ps.PauseReason = nil
}

// seededRunLive reports whether a run carried out as a seed is in flight for
// workDir, by whichever hub member follows it, and whether that member is this
// one (self) — the member the device's reports reach. It is the one test of
// the overlays on /api/state and on the projects list (Task 20514), so the
// project's Overview and its card cannot disagree about whether it runs.
func (s *Server) seededRunLive(workDir string) (self, live bool) {
	if workDir == "" {
		return false, false
	}
	// Another hub member may be the one streaming it (Task 20354): its owner
	// row says so, and says whether it was carried out as a seed. Judged as
	// peerRunExecuting judges it, on the row already read.
	if o, meta, found := s.clusterRunOwner(workDir); found && !o.Self {
		return false, meta.Seeded && hubcluster.RunClaimLive(o, time.Now(), orphanRunGrace)
	}
	// The tracked handle, not the live-log flag: see seededRunInFlight, which
	// is where the difference is explained.
	return true, s.seededRunInFlight(workDir)
}

// seededRunInFlight reports whether this member is following a run for workDir
// that was carried out as a seed — a run whose plan and outcomes live on
// another machine until it reports them.
//
// The tracked handle is the test, not the live-log flag. Only the Overview's
// Run button raises that flag; the project grid's Run button and
// POST /api/projects/{idx}/run do not, and a run this hub adopted after a
// restart never did — so a seeded run started any of those ways reported
// neither its status (Task 20349) nor, once there was one, its plan. Every
// dispatch path tracks its handle, and every settling path forgets it, which
// is exactly the window in which a report describes something.
func (s *Server) seededRunInFlight(workDir string) bool {
	_, ok := s.seededRunHandle(workDir)
	return ok
}

// seededRunHandle is seededRunInFlight with the run it found.
func (s *Server) seededRunHandle(workDir string) (dispatchedRun, bool) {
	if workDir == "" {
		return dispatchedRun{}, false
	}
	run, ok := s.trackedRun(workDir)
	if !ok || run.lost || run.handedOver || run.ex == nil {
		return dispatchedRun{}, false
	}
	if !isSeededDispatch(run.ex, run.handleID) {
		return dispatchedRun{}, false
	}
	return run, true
}

// seededFeatureRun reports whether handleID on ex is a feature's run — one
// whose returned work is landed against a feature branch when it settles.
func seededFeatureRun(ex executor.Executor, handleID string) bool {
	d, ok := peekSeededDispatch(ex, handleID)
	return ok && d.feature != nil
}

// takeSeededDispatch returns and forgets the record for handleID on ex.
func takeSeededDispatch(ex executor.Executor, handleID string) (seededDispatch, bool) {
	// Whatever the run reported while it ran has been superseded by this
	// settlement, one way or another (Task 50).
	forgetInterimPlan(ex.ID(), handleID)
	key := seededKey(ex.ID(), handleID)
	seededMu.Lock()
	defer seededMu.Unlock()
	d, ok := seeded[key]
	if !ok {
		return seededDispatch{}, false
	}
	delete(seeded, key)
	for i, k := range seededOrder {
		if k == key {
			seededOrder = append(seededOrder[:i], seededOrder[i+1:]...)
			break
		}
	}
	return d, true
}

// collectRunResult merges what ex brought back of the run behind handleID into
// the hub's copy of workDir, and journals what happened. A run that was not
// sent the project — every run on an executor that shares this filesystem —
// has nothing to bring back and returns at once.
//
// stopped says the hub was asked to stop the run: one that finished before the
// stop reached it is not followed by another (Task 20516).
//
// It returns what the merge did, and whether the run was carried out as a
// seed: for such a run the report, not the project's stored status, says
// whether the hub follows it with another (MergeReport.ResumesAtOnce). The
// stored status is the previous run's until a merge replaces it, so a run that
// brought nothing back would otherwise be followed by another, and that one by
// another.
func (s *Server) collectRunResult(workDir string, ex executor.Executor, handleID string, stopped bool) (rep projectseed.MergeReport, seeded bool) {
	defer recoverGoroutine("collect run result: " + workDir)
	if workDir == "" || ex == nil || handleID == "" {
		return rep, false
	}
	d, ok := takeSeededDispatch(ex, handleID)
	if !ok {
		return rep, false
	}
	seeded = true
	// A feature's commits come back beside its project state, and are landed
	// whatever became of the state — deferred so every early return below
	// still reaches it, and after the state merge so the journal reads in the
	// order things happened.
	if d.feature != nil {
		defer s.landFeatureWork(workDir, ex, handleID, d)
	}

	journal := func(msg string, details map[string]any) {
		if details == nil {
			details = map[string]any{}
		}
		details["executor_id"] = ex.ID()
		if d.prov.RunID != "" {
			details["run_id"] = d.prov.RunID
		}
		state.LogEventDetails(workDir, state.EventRow{
			Type:    state.EventProjectResult,
			Step:    state.NoStep,
			Message: msg,
		}, details)
	}

	// The set the run's output is scrubbed with, for the files the run sent
	// while it ran that the hub holds for it (Task 20513): read before the
	// result is taken, while the handle is certainly still here.
	var redaction []projectseed.ApplyOption
	heldScrub := func(v string) string { return v }
	if hr, ok := ex.(executor.HandleRedaction); ok {
		if set, known := hr.HandleRedaction(handleID); known {
			redaction = append(redaction, projectseed.WithRedaction(set))
			heldScrub = set.String
		}
	}
	// Whatever becomes of the result below, the files the run sent while it
	// ran are not lost with it: a run whose result never comes, is refused,
	// or could not be merged still has them attached to the tasks they were
	// sent for. A merge that ran took them all, so anything still held means
	// none did.
	defer func() {
		if held, _ := attachments.Held(state.DBPath(workDir), d.prov.RunID); len(held) > 0 {
			s.claimHeldResults(workDir, d.prov, journal, heldScrub, redaction)
		}
	}()

	fetcher, canFetch := ex.(executor.ProjectResultFetcher)
	if !canFetch || !ex.Capabilities().ReturnsProjectState {
		journal(fmt.Sprintf("Executor %q ran this project from a copy of its plan and cannot send the "+
			"outcome back, so tasks it ran still show their earlier status here — and will run again "+
			"if the project is started again. %s", ex.ID(), projectResultRemedy(ex)), nil)
		return
	}

	res, err := fetcher.ProjectResult(handleID)
	if err != nil {
		if errors.Is(err, executor.ErrProjectResultUnavailable) {
			journal(missingProjectResultMessage(ex, err), map[string]any{"reason": err.Error()})
		} else {
			journal(fmt.Sprintf("The run's results could not be collected from executor %q: %v", ex.ID(), err), nil)
		}
		return
	}
	if res.Err != "" {
		journal(fmt.Sprintf("Executor %q could not read the run's results back: %s. Tasks it ran still "+
			"show their earlier status here.", ex.ID(), res.Redact(res.Err)), nil)
		return
	}

	result, err := projectseed.DecodeResult(res.Data)
	if err != nil {
		journal(fmt.Sprintf("Executor %q sent back a report of the run that could not be read (%v); "+
			"nothing from it was merged.", ex.ID(), err), nil)
		return
	}

	rep, err = projectseed.Apply(workDir, result, d.prov, res.Redact,
		append(redaction, projectseed.WithStopRequested(stopped))...)
	details := map[string]any{
		"updated": rep.Updated, "added": rep.Added, "kept": len(rep.Kept),
		"steps": rep.Steps, "events": rep.Events, "costs": rep.Costs,
	}
	if len(rep.Renumbered) > 0 {
		details["renumbered"] = rep.Renumbered
	}
	msg := rep.Summary()
	if result.Interim {
		// All that came home is what the run reported while it was running
		// (Task 50): it ended without an outcome — typically its executor
		// stopped answering — so the plan is the plan as of its last report,
		// and its journal, steps and spend stayed on the device. Said here
		// rather than in Summary, which describes a merge without knowing why
		// this one had only a progress report to work from.
		details["interim"] = true
		msg += fmt.Sprintf(" The run on executor %q ended without reporting its outcome, so this is "+
			"its last report instead: its journal, steps and spend stayed on the executor, and a task "+
			"it was working on is as that report left it.", ex.ID())
	}
	switch {
	case err != nil && !rep.Changed():
		msg = fmt.Sprintf("The run's results came back from executor %q but could not be merged: %v. "+
			"Tasks it ran still show their earlier status here.", ex.ID(), err)
	case err != nil:
		msg += fmt.Sprintf(" Recording it failed part-way: %v", err)
	}
	if err != nil {
		details["error"] = err.Error()
		s.log().Warn(logger.EventCheckpoint, 0, "remote run result: merge failed",
			map[string]interface{}{"project": workDir, "executor": ex.ID(), "error": err.Error()})
	}
	journal(msg, details)

	if rep.Changed() {
		if st, loadErr := state.LoadLite(workDir); loadErr == nil {
			s.broadcastStateDiff(workDir, st)
		} else {
			fmt.Fprintf(os.Stderr, "ui: reload %s after merging a run: %v\n", workDir, loadErr)
		}
		s.refreshProjectStatuses()
		s.broadcastProjectsUpdate()
	}
	return rep, seeded
}

// claimHeldResults attaches the files a seeded run sent while it ran to the
// tasks they were sent for when its result could not be merged (Task 20513),
// journals what became of them, and lets go of the rest.
func (s *Server) claimHeldResults(workDir string, prov projectseed.Provenance,
	journal func(string, map[string]any), scrub func(string) string, opts []projectseed.ApplyOption) {
	defer recoverGoroutine("claim held results: " + workDir)
	rep, err := projectseed.ClaimHeld(workDir, prov, scrub, opts...)
	if err != nil {
		journal(fmt.Sprintf("The files the run sent while it ran could not be attached: %v", err), nil)
		return
	}
	if rep.Attached == 0 && rep.Delivered == 0 && len(rep.LeftBehind) == 0 && len(rep.NotRecorded) == 0 {
		return
	}
	msg := fmt.Sprintf("Of the files the run sent while it ran, %s attached to the tasks they were sent for",
		pluralCount(rep.Attached, "file was", "files were"))
	if len(rep.LeftBehind) > 0 {
		msg += "; recorded without their file: " + strings.Join(rep.LeftBehind, "; ")
	}
	if len(rep.NotRecorded) > 0 {
		msg += "; not recorded: " + strings.Join(rep.NotRecorded, "; ")
	}
	journal(msg+".", map[string]any{"attached": rep.Attached})
	if rep.Attached > 0 {
		if st, err := state.LoadLite(workDir); err == nil {
			s.broadcastStateDiff(workDir, st)
		}
	}
}

// pluralCount is "1 file was" or "3 files were".
func pluralCount(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// projectResultRemedy says how ex comes to send a seeded run's outcome back, in
// the terms of ex's own kind. Only a device's answer is an agent upgrade.
func projectResultRemedy(ex executor.Executor) string {
	switch ex.Kind() {
	case executor.KindRemoteAgent, executor.KindVirtual:
		return executor.NeedsProtocol("Its agent", sessionProtocolOf(ex), remote.MinProjectResultVersion,
			"to have a seeded run's outcome sent back", "")
	case executor.KindKubernetes:
		// Unreachable from this hub's own driver, which reads the outcome back
		// out of the Pod's log; said plainly for whatever reports the kind
		// without the capability.
		return "A Kubernetes executor of this hub's build reads the outcome back out of the Pod's log, " +
			"so this one is not running this hub's driver."
	}
	return "Bind the project to an executor that shares the control plane's filesystem, or to one that " +
		"returns a run's project state."
}

// missingProjectResultMessage is the journal row for a seeded run whose executor
// can return its outcome and did not, naming what is most likely for ex's kind
// and the driver's own account of what it saw.
func missingProjectResultMessage(ex executor.Executor, err error) string {
	why := strings.TrimSpace(strings.TrimPrefix(err.Error(), executor.ErrProjectResultUnavailable.Error()))
	why = strings.TrimSpace(strings.TrimPrefix(why, ":"))
	var likely string
	switch ex.Kind() {
	case executor.KindKubernetes:
		// The Pod's log is the only way home (pkg/executor/kubernetes/
		// projectresult.go), so what can go wrong is what can go wrong with
		// that log.
		likely = "The Pod's log ended without a complete project result in it: the harness image's " +
			"cloop may predate `cloop workspace writeback --project-result-frame`, the Pod may have been " +
			"evicted or stopped before its wrapper finished, or the workload printed a result frame of " +
			"its own, which makes the real one a duplicate and neither is believed"
	case executor.KindRemoteAgent, executor.KindVirtual:
		likely = "Typically the connection dropped before the run finished"
	default:
		likely = "The executor reported no result for the run"
	}
	msg := fmt.Sprintf("The run on executor %q ended without sending its results back, so tasks it ran "+
		"still show their earlier status here. %s.", ex.ID(), likely)
	if why != "" {
		msg += " What the executor saw: " + why + "."
	}
	return msg + " Check the run's log for how far it got."
}

// ── a seeded run's plan while it runs ───────────────────────────────────────

// interimPlans caches the decoded progress report behind each live seeded run,
// so rendering the project does not inflate and parse the same document on
// every request. Keyed by executor and handle, with the digest of the bytes it
// was decoded from: a newer report has different bytes and is decoded once.
var interimPlans = struct {
	sync.Mutex
	docs  map[string]*interimPlan
	order []string
}{docs: map[string]*interimPlan{}}

// maxInterimPlans bounds the cache: one entry per seeded run whose project
// somebody has open, and each is dropped when its run settles. Kept small
// because a decoded document is held in full and the ceiling on one is
// generous (projectseed.MaxResultInflatedBytes); evicting one costs a decode,
// never a wrong answer.
const maxInterimPlans = 32

type interimPlan struct {
	sum [sha256.Size]byte
	doc *projectseed.Result
}

// forgetInterimPlan drops the cached report for a run that has settled.
func forgetInterimPlan(executorID, handleID string) {
	key := seededKey(executorID, handleID)
	interimPlans.Lock()
	defer interimPlans.Unlock()
	if _, ok := interimPlans.docs[key]; !ok {
		return
	}
	delete(interimPlans.docs, key)
	for i, k := range interimPlans.order {
		if k == key {
			interimPlans.order = append(interimPlans.order[:i], interimPlans.order[i+1:]...)
			break
		}
	}
}

// decodeInterim decodes data, reusing the last decoding of the same bytes.
func decodeInterim(key string, data []byte) (*projectseed.Result, error) {
	sum := sha256.Sum256(data)
	interimPlans.Lock()
	defer interimPlans.Unlock()
	if c, ok := interimPlans.docs[key]; ok && c.sum == sum {
		return c.doc, nil
	}
	doc, err := projectseed.DecodeResult(data)
	if err != nil {
		return nil, err
	}
	if _, ok := interimPlans.docs[key]; !ok {
		interimPlans.order = append(interimPlans.order, key)
	}
	interimPlans.docs[key] = &interimPlan{sum: sum, doc: doc}
	for len(interimPlans.order) > maxInterimPlans {
		delete(interimPlans.docs, interimPlans.order[0])
		interimPlans.order = interimPlans.order[1:]
	}
	return doc, nil
}

// overlaySeededRunPlan shows the plan a seeded run in flight is working
// through (Task 50).
//
// A run on an executor that cannot read this filesystem plans in its own copy
// of the project and reports its outcome only when it ends, so the plan it
// *made* reached the hub only then — and the dashboard, which renders this
// hub's copy, showed an empty project for the whole run. For a project whose
// tasks the run plans itself (pm mode, auto-evolve) that is every task it has:
// the operator pressed Run, watched a transcript describe twelve tasks, and
// saw none of them.
//
// The device now reports the plan as it goes (pkg/executor/agent's progress
// reports), and this folds the newest report into the state about to be
// served. On the hub's copy of the plan, never the project's own record: the
// run's account of a plan it is still changing is a view, and the merge that
// writes it down happens once, when the run ends.
//
// Nothing is overlaid for a run on this filesystem (it writes the hub's own
// database), for a run whose device is too old to report (its plan appears
// when it settles, as before), or while another hub member streams the run
// (the report is held by the member the device is connected to).
func (s *Server) overlaySeededRunPlan(workDir string, ps *state.ProjectState) {
	if ps == nil {
		return
	}
	run, ok := s.seededRunHandle(workDir)
	if !ok {
		return
	}
	d, ok := peekSeededDispatch(run.ex, run.handleID)
	if !ok {
		return
	}
	fetcher, canFetch := run.ex.(executor.InterimProjectResultFetcher)
	if !canFetch {
		return
	}
	res, err := fetcher.InterimProjectResult(run.handleID)
	if err != nil || len(res.Data) == 0 {
		return
	}
	doc, err := decodeInterim(seededKey(run.ex.ID(), run.handleID), res.Data)
	if err != nil {
		// Said once per document, not once per render: the digest cache keeps
		// a document that cannot be decoded from being decoded again.
		s.log().Warn(logger.EventCheckpoint, 0, "a device's report of its run could not be read",
			map[string]interface{}{"project": workDir, "executor": run.ex.ID(), "error": err.Error()})
		return
	}
	// The hub's own plan is left exactly as it was: the merge writes to tasks
	// and appends to the plan, and callers hand in state they may go on to
	// save — or, on the broadcast path, state they share with the caller
	// above them.
	ps.Plan = clonePlanForOverlay(ps.Plan)
	redact := res.Redact
	if redact == nil {
		redact = func(s string) string { return s }
	}
	projectseed.Merge(ps, doc, d.prov, redact, time.Now().UTC())
}

// clonePlanForOverlay copies a plan deeply enough that merging a run's report
// into the copy cannot be seen through the original: every task is a copy, and
// so is every slice the merge appends to.
func clonePlanForOverlay(p *pm.Plan) *pm.Plan {
	if p == nil {
		return nil
	}
	c := *p
	c.Tasks = make([]*pm.Task, 0, len(p.Tasks))
	for _, t := range p.Tasks {
		if t == nil {
			c.Tasks = append(c.Tasks, nil)
			continue
		}
		ct := *t
		ct.Annotations = append([]pm.Annotation(nil), t.Annotations...)
		c.Tasks = append(c.Tasks, &ct)
	}
	return &c
}
