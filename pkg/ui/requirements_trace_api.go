package ui

// requirements_trace_api.go: the traceability matrix and the spec coverage
// (Task 20465; pkg/requirements/trace.go).
//
//	GET /api/requirements/trace   a page of the matrix: ?priority=&tag=&gap=&after=&limit=
//
// One row per approved requirement: the tasks that implement it and their
// states, the commits they produced, its latest verdict with its age and
// staleness, its latest proof, and how it is verified. Reading is
// project.read, scoped to the project, like every requirements view.
//
// # Pages
//
// A page is a SQL keyset page (statedb/requirements_trace.go): `after` is the
// last id of the page before, `limit` how many rows (50 unless asked; at most
// 200; 0 for none). The first page — no `after` — also carries the coverage of
// every approved requirement, how many rows the filter matches, and a digest
// of the whole matrix; `?limit=0` asks for those alone, which is what the
// Overview's card reads.
//
// # Pushes
//
// A dashboard never polls the matrix. Where the hub notices a project's state
// change — its watcher, on any write to the project's database by a run, the
// CLI or this hub — pushCoverage works the coverage out again for a project
// somebody has open, and pushes requirements_coverage when the digest moved:
// the coverage, which the Overview's card draws as it comes, and the digest,
// which tells the Traceability view to read its rows again. Each hub member
// pushes to its own clients from the shared database, so nothing is relayed.
//
// # The commits
//
// A row's commits are its tasks' (requirements/trace.go): what each task
// records of its own work, and the commit-to-task trace `cloop trace` keeps in
// .cloop/trace.json — read here through trace.Peek, which changes nothing,
// reads a bounded amount, and follows no link out of .cloop. Its subjects are
// a repository's words, and the dashboard escapes them as it escapes
// everything else.

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/trace"
)

// traceAnswer is GET /api/requirements/trace's answer: a page of the matrix,
// and the filter as the hub read it.
type traceAnswer struct {
	OK bool `json:"ok"`
	requirements.TracePage
	Filter      requirements.TraceFilter `json:"filter"`
	GeneratedAt time.Time                `json:"generated_at"`
}

// traceIntParam reads a non-negative integer parameter, def when absent.
func traceIntParam(w http.ResponseWriter, r *http.Request, name string, def, ceiling int) (int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		jsonErr(w, name+" must be a whole number, 0 or more", http.StatusBadRequest)
		return 0, false
	}
	return min(n, ceiling), true
}

// handleRequirementsTrace answers GET /api/requirements/trace.
func (s *Server) handleRequirementsTrace(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	q := r.URL.Query()
	filter, err := requirements.ParseTraceFilter(q.Get("priority"), q.Get("tag"), q.Get("gap"))
	if err != nil {
		requirementErr(w, err)
		return
	}
	after, ok := traceIntParam(w, r, "after", 0, 1<<31-1)
	if !ok {
		return
	}
	limit, ok := traceIntParam(w, r, "limit", requirements.DefaultTracePage, requirements.MaxTracePage)
	if !ok {
		return
	}
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	defer db.Close()
	now := time.Now().UTC()
	page, err := requirements.Trace(db, trace.MatrixPlan(workDir, planOf(workDir)), requirements.TraceRequest{
		Filter: filter, After: after, Limit: limit, Coverage: after == 0}, now)
	if err != nil {
		requirementErr(w, err)
		return
	}
	jsonOK(w, traceAnswer{OK: true, TracePage: page, Filter: filter, GeneratedAt: now})
}

// coverageFeed is what pushCoverage last told each project's dashboards: the
// digest of the matrix they were told of.
type coverageFeed struct {
	mu   sync.Mutex
	sent map[string]string
}

// coveragePush is a requirements_coverage message.
type coveragePush struct {
	Coverage *requirements.Coverage `json:"coverage"`
	Digest   string                 `json:"digest"`
}

// pushCoverage tells workDir's open dashboards its spec coverage when the
// matrix changed since they were last told (see the file comment). plan is the
// project's plan when the caller has it loaded already; nil reads it. Nobody
// watching costs nothing, and forgets what was sent.
func (s *Server) pushCoverage(workDir string, plan *pm.Plan) {
	if workDir == "" {
		return
	}
	if !s.hasStreamClients(workDir) {
		s.covFeed.mu.Lock()
		delete(s.covFeed.sent, workDir)
		s.covFeed.mu.Unlock()
		return
	}
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return
	}
	defer db.Close()
	if plan == nil {
		plan = planOf(workDir)
	}
	page, err := requirements.Trace(db.AsProject(), trace.MatrixPlan(workDir, plan), requirements.TraceRequest{Coverage: true},
		time.Now().UTC())
	if err != nil || page.Coverage == nil {
		return
	}
	s.covFeed.mu.Lock()
	if s.covFeed.sent == nil {
		s.covFeed.sent = map[string]string{}
	}
	// Not a secret — every reader of the matrix is sent it — but compared as
	// every digest-shaped value in the hub is (tests/security).
	same := subtle.ConstantTimeCompare([]byte(s.covFeed.sent[workDir]), []byte(page.Digest)) == 1
	s.covFeed.sent[workDir] = page.Digest
	s.covFeed.mu.Unlock()
	if same {
		return
	}
	raw, err := json.Marshal(coveragePush{Coverage: page.Coverage, Digest: page.Digest})
	if err != nil {
		return
	}
	s.deliverToProject(workDir, wsMessage{Type: "requirements_coverage", Data: raw})
	s.deliverSSE(workDir, sseEvent{Event: "requirements_coverage", Data: string(raw)})
}
