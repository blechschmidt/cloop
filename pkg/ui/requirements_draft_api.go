package ui

// requirements_draft_api.go: the Requirements tab's Draft dialog (Task 20462).
//
//	POST /api/requirements/draft     the model drafts requirements from the goal or a pasted specification
//	POST /api/requirements/approve   approve drafts, one or all at once
//	GET  /api/requirements/lint      what the rules say about the requirements as written
//	POST /api/requirements/lint      the same, and what the model says of duplicates and contradictions
//
// # Where the model runs
//
// Never here. A draft is `cloop requirements draft --json --dry-run` and the
// model's lint `cloop requirements lint --json --ai`, dispatched through
// runCloopSubcommandFor to the project's executor with the caller's Claude
// account — or their Copilot sign-in — exactly like the Split preview and the
// other dashboard model calls (model_calls.go). The hub sends what the
// executor needs as arguments: the text, the goal and the existing
// requirements' titles for a draft, a lint spec for a lint. The rules' lint
// (requirements.Lint) reads words and runs nothing, so it runs here.
//
// # What comes back is untrusted
//
// The model's answer was read strictly on the executor, by a cloop the hub
// cannot vouch for, so the hub reads the result again through its own copy of
// the rules: requirements.CheckDraftResult keeps only drafts — a proposal that
// claims any other status is refused — within a requirement's bounds, and
// requirements.CheckModelFindings keeps of a finding only the requirements it
// names and its reason, writing its message itself. The dashboard escapes all
// of it (the XSS crawl seeds hostile drafts).
//
// # A draft counts for nothing until a person approves it
//
// Drafts are stored with the status draft, and nothing checks one: not a
// check of every requirement, not a check that names it, not the requirements
// gate, and an agent's contract names it without its text. Approving —
// one, all, or after an edit — needs task.mutate, records the approver on the
// requirement and is audited as requirement.approve.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// draftCallTimeout is the model's time on a draft — it may read the
	// repository for test commands; draftDispatchTimeout adds the workload's
	// start where the project runs.
	draftCallTimeout     = 6 * time.Minute
	draftDispatchTimeout = draftCallTimeout + time.Minute
	// lintCallTimeout bounds each of the model's two lint questions;
	// lintDispatchTimeout both, and the workload's start.
	lintCallTimeout     = 3 * time.Minute
	lintDispatchTimeout = 2*lintCallTimeout + time.Minute
	// maxLintNotes and maxLintNoteRunes bound what a lint from an executor
	// may say it did not do.
	maxLintNotes     = 5
	maxLintNoteRunes = 300
)

// projectGoal is the goal of the project at workDir, as its plan states it.
func projectGoal(ps *state.ProjectState) string {
	if ps.Plan != nil && strings.TrimSpace(ps.Plan.Goal) != "" {
		return ps.Plan.Goal
	}
	return ps.Goal
}

// handleRequirementsDraft answers POST /api/requirements/draft {source, text,
// max}: source "goal" drafts from the project's goal, "text" from text. The
// model runs on the project's executor; the drafts it proposes are stored as
// drafts, and the answer carries them with their ids, the proposals refused
// and why, and what the rules' lint says of them.
func (s *Server) handleRequirementsDraft(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	// Dispatched like a run, so it goes where a run would: the member
	// holding an edge agent's connection.
	if s.routeDispatch(w, r, workDir) {
		return
	}
	var in struct {
		Source string `json:"source"`
		Text   string `json:"text"`
		Max    int    `json:"max"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	limit := in.Max
	if limit == 0 {
		limit = requirements.DefaultDrafts
	}
	if limit < 1 || limit > requirements.MaxDrafts {
		jsonErr(w, fmt.Sprintf("max is between 1 and %d", requirements.MaxDrafts), http.StatusBadRequest)
		return
	}
	ps, err := state.LoadLite(workDir)
	if err != nil {
		jsonErr(w, "no project found — run cloop init first", http.StatusNotFound)
		return
	}
	goal := projectGoal(ps)
	var text string
	switch in.Source {
	case "goal":
		if text = goal; strings.TrimSpace(text) == "" {
			jsonErr(w, "the project has no goal to draft from: paste a specification instead", http.StatusBadRequest)
			return
		}
	case "text", "":
		in.Source, text = "text", in.Text
	default:
		jsonErr(w, `source is "goal" or "text"`, http.StatusBadRequest)
		return
	}
	if text, err = requirements.CheckDraftSource(text); err != nil {
		requirementErr(w, err)
		return
	}

	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	defer db.Close()
	all, err := db.Requirements()
	if err != nil {
		requirementErr(w, err)
		return
	}
	room := requirements.MaxRequirements - len(all)
	if room <= 0 {
		jsonErr(w, fmt.Sprintf("the project holds %d requirements, as many as a project may: delete some before drafting more",
			len(all)), http.StatusBadRequest)
		return
	}
	limit = min(limit, room)
	existing, _, err := requirements.EncodeExisting(all)
	if err != nil {
		requirementErr(w, err)
		return
	}

	// The model call spends the caller's account where the project runs: a
	// sandbox with no credential of theirs is refused now, with the 409 the
	// dialog opens the credential dialog on.
	clear := s.harnessClearanceFor(r, workDir)
	if s.refuseWithoutHarnessCredential(w, clear) {
		return
	}
	executorID := ""
	registerBuiltinExecutors()
	if ex, err := executor.Resolve(workDir); err == nil && ex != nil {
		executorID = ex.ID()
	}
	args := []string{"requirements", "draft", "--json", "--dry-run", "--max", strconv.Itoa(limit),
		"--timeout", draftCallTimeout.String(), "--existing=" + string(existing),
		// Joined to its flag: a text that starts with "-" is not a flag.
		"--text=" + text}
	if in.Source == "goal" {
		args = append(args, "--text-is-goal")
	} else {
		args = append(args, "--goal="+truncateRunes(goal, maxSpecGoalRunes))
	}
	out, err := runCloopSubcommandFor(r.Context(), s.selfExe(), workDir, draftDispatchTimeout,
		s.claudeEnvResolver(r), clear, args...)
	var res requirements.DraftResult
	if !readModelCall(w, out, err, "Drafting failed: ", &res) {
		return
	}

	checked := requirements.CheckDraftResult(res, all, limit)
	sum := sha256.Sum256([]byte(text))
	stored, err := db.AddDraftRequirements(checked.Drafts, s.auditActor(r), statedb.DraftOrigin{
		Source: in.Source, SHA256: hex.EncodeToString(sum[:]), Bytes: len(text), ExecutorID: executorID,
		Via: "dashboard", Refused: len(checked.Refused),
	})
	if err != nil {
		requirementErr(w, err)
		return
	}
	s.requirementsChanged(workDir, "", "")
	s.broadcastAuditAppend(string(auditaction.ActionRequirementDraft))

	ids := make([]int, len(stored))
	for i, q := range stored {
		ids[i] = q.ID
	}
	refused := checked.Refused
	if refused == nil {
		refused = []requirements.Refusal{}
	}
	jsonOK(w, map[string]any{
		"ok": true, "drafts": stored, "refused": refused, "notes": checked.Notes,
		"lint": requirements.Lint(append(all, stored...), ids),
	})
}

// handleRequirementsApprove answers POST /api/requirements/approve {ids}: the
// drafts named become approved — a check runs their tests from now on, and
// the requirements gate holds tasks to them — with the caller recorded as
// each one's approver and a requirement.approve row each. One already
// approved stays as it was, and is named in already.
func (s *Server) handleRequirementsApprove(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs requirements.Refs `json:"ids"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.IDs) == 0 {
		jsonErr(w, "name the drafts to approve", http.StatusBadRequest)
		return
	}
	workDir := s.resolveWorkDir(r)
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	approved, already, err := db.ApproveRequirements(in.IDs, s.auditActor(r))
	db.Close()
	if err != nil {
		requirementErr(w, err)
		return
	}
	s.requirementsChanged(workDir, "", "")
	if len(approved) > 0 {
		s.broadcastAuditAppend(string(auditaction.ActionRequirementApprove))
	}
	if approved == nil {
		approved = []requirements.Requirement{}
	}
	if already == nil {
		already = []int{}
	}
	jsonOK(w, map[string]any{"ok": true, "approved": approved, "already": already})
}

// lintSubjects reads the requirements a lint is about from a client's ids,
// which must name requirements of the project; none is every requirement but
// the deprecated ones.
func lintSubjects(all []requirements.Requirement, ids []int) ([]int, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	picked, err := pickRequirements(all, ids)
	if err != nil {
		return nil, err
	}
	out := make([]int, len(picked))
	for i, q := range picked {
		out[i] = q.ID
	}
	return out, nil
}

// handleRequirementsLint answers GET /api/requirements/lint[?ids=R-1,2]: what
// the rules find in the requirements as written. It reads words and runs
// nothing, so it is answered here, for anyone who may read the project.
func (s *Server) handleRequirementsLint(w http.ResponseWriter, r *http.Request) {
	var ids []int
	if raw := strings.TrimSpace(r.URL.Query().Get("ids")); raw != "" {
		var err error
		if ids, err = requirements.ParseRefs([]string{raw}); err != nil {
			requirementErr(w, err)
			return
		}
	}
	db, ok := openRequirementsDB(w, s.resolveWorkDir(r))
	if !ok {
		return
	}
	all, err := db.Requirements()
	db.Close()
	if err != nil {
		requirementErr(w, err)
		return
	}
	subjects, err := lintSubjects(all, ids)
	if err != nil {
		requirementErr(w, err)
		return
	}
	jsonOK(w, map[string]any{"ok": true, "findings": requirements.Lint(all, subjects), "checked": lintCount(all, subjects),
		"notes": []string{}})
}

// lintCount is how many requirements a lint of subjects is about.
func lintCount(all []requirements.Requirement, subjects []int) int {
	if subjects != nil {
		return len(subjects)
	}
	n := 0
	for _, q := range all {
		if q.CurrentStatus() != requirements.StatusDeprecated {
			n++
		}
	}
	return n
}

// lintRelevant is how many requirements a model lint of subjects would show
// the model, all fitting: the subjects and every one not deprecated.
func lintRelevant(all []requirements.Requirement, subjects []int) int {
	named := map[int]bool{}
	for _, id := range subjects {
		named[id] = true
	}
	n := 0
	for _, q := range all {
		if named[q.ID] || q.CurrentStatus() != requirements.StatusDeprecated {
			n++
		}
	}
	return n
}

// handleRequirementsLintModel answers POST /api/requirements/lint {ids}: the
// rules' findings and the model's — duplicates in other words, through the
// semantic dedup auto-evolve uses, and contradictions — asked on the
// project's executor with the caller's account.
func (s *Server) handleRequirementsLintModel(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	if s.routeDispatch(w, r, workDir) {
		return
	}
	var in struct {
		IDs requirements.Refs `json:"ids"`
	}
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	ps, err := state.LoadLite(workDir)
	if err != nil {
		jsonErr(w, "no project found — run cloop init first", http.StatusNotFound)
		return
	}
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	all, err := db.Requirements()
	db.Close()
	if err != nil {
		requirementErr(w, err)
		return
	}
	subjects, err := lintSubjects(all, in.IDs)
	if err != nil {
		requirementErr(w, err)
		return
	}
	rules := requirements.Lint(all, subjects)
	sent := subjects
	if sent == nil {
		for _, q := range all {
			if q.CurrentStatus() != requirements.StatusDeprecated {
				sent = append(sent, q.ID)
			}
		}
	}
	if len(sent) == 0 {
		jsonErr(w, "the project has no requirements to lint", http.StatusBadRequest)
		return
	}
	raw, n, err := requirements.LintSpec(truncateRunes(projectGoal(ps), maxSpecGoalRunes), all, sent)
	if err != nil {
		requirementErr(w, err)
		return
	}

	clear := s.harnessClearanceFor(r, workDir)
	if s.refuseWithoutHarnessCredential(w, clear) {
		return
	}
	args := []string{"requirements", "lint", "--json", "--ai", "--timeout", lintCallTimeout.String(), "--spec=" + string(raw)}
	for _, id := range subjects {
		args = append(args, strconv.Itoa(id))
	}
	out, err := runCloopSubcommandFor(r.Context(), s.selfExe(), workDir, lintDispatchTimeout,
		s.claudeEnvResolver(r), clear, args...)
	var rep requirements.LintReport
	if !readModelCall(w, out, err, "The model's lint failed: ", &rep) {
		return
	}
	notes := []string{}
	for _, note := range rep.Notes {
		if note = truncateRunes(strings.Join(strings.Fields(note), " "), maxLintNoteRunes); note != "" && len(notes) < maxLintNotes {
			notes = append(notes, note)
		}
	}
	if relevant := lintRelevant(all, sent); n < relevant && len(notes) < maxLintNotes {
		notes = append(notes, fmt.Sprintf("the model was shown %d of the %d requirements: the rest did not fit one request", n, relevant))
	}
	jsonOK(w, map[string]any{
		"ok": true, "findings": requirements.MergeFindings(rules, requirements.CheckModelFindings(rep.Findings, all)),
		"checked": lintCount(all, subjects), "notes": notes,
	})
}

// plural is one when n is 1, else many.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
