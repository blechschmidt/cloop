package ui

// AI feature suggestions on the Tasks tab: brainstorming ideas, and planning a
// request (Task 20342).
//
// Both run `cloop suggest --json` on the project's executor and hold what it
// proposes here for review; /api/suggest/add turns the proposals the user
// accepts into tasks, one at a time or all at once. With no input the command
// brainstorms loose ideas, and the count is how many. With an input it breaks
// that request into the tasks of a plan instead — ordered, each naming the
// earlier tasks it needs — and the count becomes the plan's length, or is
// left to the request when unset. suggest.Ledger keeps an accepted plan's
// dependencies intact however its tasks are picked.
//
// A job is per project. It used to be one hub-wide slot: a second project's
// brainstorm was refused while the first ran, and /api/suggest/status
// answered every project with whichever one had run last — text generated
// from one tenant's code, served to another.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/suggest"
)

// suggestJob is one project's latest brainstorm or plan.
type suggestJob struct {
	// gen numbers generations hub-wide. The dashboard echoes the one it is
	// showing when it accepts a proposal, so an accept aimed at a generation
	// that has since been replaced is refused instead of landing on whatever
	// now has the same ID.
	gen     int
	count   int    // ideas or plan tasks asked for; 0 lets a plan size itself
	request string // what is being planned; empty for a brainstorm
	running bool
	done    bool
	err     string
	result  *suggest.Result
	ledger  *suggest.Ledger

	// addMu serializes accepts, so each loads the plan the previous one saved
	// and the ledger never disagrees with it.
	addMu sync.Mutex
}

// status is the job as clients see it. Called with s.suggestMu held.
func (j *suggestJob) status() map[string]interface{} {
	st := map[string]interface{}{
		"gen":         j.gen,
		"running":     j.running,
		"done":        j.done,
		"error":       j.err,
		"request":     j.request,
		"summary":     "",
		"suggestions": []*suggest.Suggestion{},
	}
	if j.result != nil {
		st["summary"] = j.result.Summary
		st["suggestions"] = j.ledger.Pending(j.result.Suggestions)
	}
	return st
}

// suggestStatusJSON renders workDir's job for the wire. ok is false when the
// project has none, in which case raw is the idle status.
func (s *Server) suggestStatusJSON(workDir string) (raw []byte, ok bool) {
	s.suggestMu.Lock()
	defer s.suggestMu.Unlock()
	j := s.suggestJobs[workDir]
	if j == nil {
		raw, _ = json.Marshal((&suggestJob{}).status())
		return raw, false
	}
	raw, _ = json.Marshal(j.status())
	return raw, true
}

// broadcastSuggestStatus pushes workDir's job status to that project's
// WebSocket and SSE clients, which is how the panel learns a job finished
// without polling /api/suggest/status.
func (s *Server) broadcastSuggestStatus(workDir string) {
	if workDir == "" {
		return
	}
	raw, _ := s.suggestStatusJSON(workDir)
	msg := wsMessage{Type: "suggest_status", Data: raw}
	s.deliverToProject(workDir, msg)

	// Mirror to this project's SSE clients (fallback path). The payload
	// carries generated text about one project, so it is scoped the same way
	// as the WebSocket line above (Task 20189).
	s.deliverSSE(workDir, sseEvent{Event: "suggest_status", Data: string(raw)})
	// The job lives on this hub member; dashboards on the others learn of it
	// through the bus, SSE mirror included (Task 20354).
	s.publishWS(workDir, msg, "suggest_status")
}

// suggestCount resolves the count a client asked for: how many ideas to
// brainstorm (suggest.DefaultCount when unset), or how many tasks to plan (0
// when unset, which leaves the length to the request). Never above
// suggest.MaxCount.
func suggestCount(n int, plan bool) int {
	switch {
	case n > suggest.MaxCount:
		return suggest.MaxCount
	case n > 0:
		return n
	case plan:
		return 0
	default:
		return suggest.DefaultCount
	}
}

// handleSuggestGenerate starts a brainstorm, or with an input a plan, for the
// project in the background (POST /api/suggest/generate {count, input}). The
// result reaches clients as a suggest_status event.
func (s *Server) handleSuggestGenerate(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	// A job lives in the memory of the hub member that ran it, and status and
	// add must reach the same member (Task 20354).
	if s.routeProjectAffinity(w, r, ownerSuggest, s.resolveWorkDir(r)) {
		return
	}
	var req struct {
		Count int    `json:"count"`
		Input string `json:"input"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	// An empty body is the defaults — a brainstorm of five — as it always was.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		respondToBodyError(w, err)
		return
	}
	request, err := suggest.CleanRequest(req.Input)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	count := suggestCount(req.Count, request != "")
	workDir := s.resolveWorkDir(r)

	// A brainstorm and a plan both call the provider inside the project's
	// executor, so a sandbox with no Claude login is refused here, with the
	// 409 the dialog opens on, rather than minutes later as a job that failed
	// (Task 20379). Before the job is announced.
	suggestClear := s.harnessClearanceFor(r, workDir)
	if s.refuseWithoutHarnessCredential(w, suggestClear) {
		return
	}

	s.suggestMu.Lock()
	if j := s.suggestJobs[workDir]; j != nil && j.running {
		s.suggestMu.Unlock()
		jsonErr(w, "suggest already running", http.StatusConflict)
		return
	}
	if s.suggestJobs == nil {
		s.suggestJobs = make(map[string]*suggestJob)
	}
	s.suggestGen++
	job := &suggestJob{gen: s.suggestGen, count: count, request: request, running: true}
	s.suggestJobs[workDir] = job
	s.suggestMu.Unlock()
	s.broadcastSuggestStatus(workDir)

	args := []string{"suggest", "--json"}
	if request != "" {
		// Joined to its flag: a request that starts with "-" must not be
		// parsed as a flag of its own.
		args = append(args, "--input="+request)
	}
	if count > 0 {
		args = append(args, "--count", strconv.Itoa(count))
	}
	exe := s.selfExe()
	// Resolved here rather than inside the goroutine: planning spends the
	// caller's Claude tokens, and r must not outlive this handler.
	claudeEnv := s.claudeEnvResolver(r)

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				fmt.Fprintf(os.Stderr, "ui: suggest goroutine panic recovered: %v\n", rec)
				// Release the job so the user can retry.
				s.finishSuggest(workDir, job, nil, fmt.Sprintf("internal panic: %v", rec))
			}
		}()
		// Hard timeout: nothing else cancels this goroutine, and a hung
		// sub-binary would otherwise leave the job running forever — every
		// later generate for this project refused with 409.
		out, runErr := runCloopSubcommandFor(context.Background(), exe, workDir, suggestSubprocessTimeout, claudeEnv, suggestClear, args...)
		if runErr != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = runErr.Error()
			}
			s.finishSuggest(workDir, job, nil, msg)
			return
		}
		// Not json.Unmarshal(out): out is stdout and stderr merged by the
		// executor, so the payload has to be located in it rather than
		// assumed to be all of it. See pkg/clijson (Task 20325).
		var result suggest.Result
		if err := clijson.Unmarshal(out, &result); err != nil {
			s.finishSuggest(workDir, job, nil, "could not parse suggestions: "+err.Error())
			return
		}
		s.finishSuggest(workDir, job, &result, "")
	}()

	jsonOK(w, map[string]interface{}{"ok": true, "count": count, "gen": job.gen})
}

// finishSuggest records how job ended and tells its project's clients.
func (s *Server) finishSuggest(workDir string, job *suggestJob, result *suggest.Result, errMsg string) {
	if result != nil {
		// Checked here rather than trusted: on a device, the result came from
		// whatever cloop that device runs. What the hub asked for decides
		// whether it is a plan, not what came back.
		if job.request != "" {
			suggest.NormalizePlan(result, job.count)
		} else {
			suggest.NormalizeIdeas(result, job.count)
		}
		result.Request = job.request
	}
	s.suggestMu.Lock()
	job.running, job.done, job.err = false, true, errMsg
	if result != nil {
		job.result, job.ledger = result, suggest.NewLedger(result)
	}
	s.suggestMu.Unlock()
	s.broadcastSuggestStatus(workDir)
}

// handleSuggestStatus returns the project's job status and the proposals
// still awaiting review (GET /api/suggest/status).
func (s *Server) handleSuggestStatus(w http.ResponseWriter, r *http.Request) {
	if s.routeToOwner(w, r, ownerSuggest, s.resolveWorkDir(r)) {
		return
	}
	raw, _ := s.suggestStatusJSON(s.resolveWorkDir(r))
	jsonOK(w, json.RawMessage(raw))
}

// handleSuggestAdd turns reviewed proposals into tasks
// (POST /api/suggest/add {gen, ids}). ids name proposals of generation gen;
// a plan's tasks keep their dependencies on each other (see suggest.Ledger)
// and join the end of the run queue in plan order. Accepting a proposal that
// is already a task is a no-op.
//
// The older form, {suggestions: [...]} carrying the proposals themselves, is
// still served: one that matches the current generation is accepted like its
// ID, and any other is added as an independent idea, as it always was.
func (s *Server) handleSuggestAdd(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if s.routeToOwner(w, r, ownerSuggest, s.resolveWorkDir(r)) {
		return
	}
	var req struct {
		Gen         int                   `json:"gen"`
		IDs         []int                 `json:"ids"`
		Suggestions []*suggest.Suggestion `json:"suggestions"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	workDir := s.resolveWorkDir(r)

	s.suggestMu.Lock()
	job := s.suggestJobs[workDir]
	if job != nil && job.result == nil {
		job = nil // still generating: nothing of it can be accepted yet
	}
	s.suggestMu.Unlock()
	if req.Gen != 0 && (job == nil || job.gen != req.Gen) {
		jsonErr(w, "these suggestions have been replaced by a newer generation — review the current ones", http.StatusConflict)
		return
	}

	var ledger *suggest.Ledger
	var picked, loose []*suggest.Suggestion
	if job != nil {
		job.addMu.Lock()
		defer job.addMu.Unlock()
		s.suggestMu.Lock()
		ledger = job.ledger.Clone()
		all := job.result.Suggestions
		s.suggestMu.Unlock()

		byID := make(map[int]*suggest.Suggestion, len(all))
		for _, sg := range all {
			byID[sg.ID] = sg
		}
		for _, id := range req.IDs {
			if sg, ok := byID[id]; ok {
				picked = append(picked, sg)
			}
		}
		for _, sg := range req.Suggestions {
			if sg == nil {
				continue
			}
			if p, ok := byID[sg.ID]; ok && p.Title == sg.Title {
				picked = append(picked, p)
			} else {
				loose = append(loose, sg)
			}
		}
	} else {
		loose = req.Suggestions
	}
	if len(picked) == 0 && len(loose) == 0 {
		jsonErr(w, "no suggestions to add", http.StatusBadRequest)
		return
	}

	// LoadLite: only the plan is needed, and SaveDirect writes back without
	// touching step rows (see handleTaskAdd).
	ps, err := state.LoadLite(workDir)
	if err != nil {
		jsonErr(w, "no project found — run cloop init first", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		ps.Plan = pm.NewPlan(ps.Goal)
	}
	ps.PMMode = true

	var fromJob, fromLoose []*pm.Task
	if ledger != nil {
		fromJob = ledger.Apply(ps.Plan, picked)
	}
	if len(loose) > 0 {
		extra := &suggest.Result{Suggestions: loose}
		suggest.NormalizeIdeas(extra, 0)
		fromLoose = suggest.NewLedger(extra).Apply(ps.Plan, extra.Suggestions)
	}
	added := append(fromJob, fromLoose...)

	if len(added) > 0 {
		if err := ps.SaveDirect(); err != nil {
			jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
			return
		}
	}
	if job != nil {
		s.suggestMu.Lock()
		if s.suggestJobs[workDir] == job {
			job.ledger = ledger
		}
		s.suggestMu.Unlock()
	}

	origin := "an AI suggestion"
	if job != nil && job.request != "" {
		req := truncateRunes(job.request, 80)
		if req != job.request {
			req += "…"
		}
		origin = fmt.Sprintf("the plan for %q", req)
	}
	for i, t := range added {
		from := origin
		if i >= len(fromJob) {
			from = "an AI suggestion"
		}
		state.LogEvent(workDir, state.EventRow{
			Type:      state.EventTaskAdded,
			TaskID:    t.ID,
			TaskTitle: t.Title,
			Step:      state.NoStep,
			Message:   fmt.Sprintf("Task #%d added via UI from %s: %s", t.ID, from, t.Title),
		})
	}
	s.broadcastStateDiff(workDir, ps)
	if job != nil {
		// Other tabs drop the cards this one just accepted.
		s.broadcastSuggestStatus(workDir)
	}

	ids := make([]int, len(added))
	for i, t := range added {
		ids[i] = t.ID
	}
	jsonOK(w, map[string]interface{}{"ok": true, "added": ids, "tasks": added})
}
