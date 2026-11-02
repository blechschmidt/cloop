package requirements

// trace.go: the traceability matrix, and the spec coverage it adds up to
// (Task 20465).
//
// One row per approved requirement: its priority and tags; the tasks that
// implement it and the state each is in; the commits those tasks produced; its
// latest verdict, how old that is and whether it is stale; its latest red-green
// proof; and how it is verified at all — by tests, by the model's reading, by a
// person's word, or not. The coverage is what the rows add up to: how many
// musts are tested, proven, passing and linked to a task.
//
// # Where the pieces come from
//
// Everything a row says is recorded somewhere already, and the matrix reads it
// rather than working anything out anew: the requirement, its checks and its
// proofs from the project's database (a TraceSource, a page at a time), the
// tasks from the plan, and the commits from two places — what a task records of
// its own work (where an isolated executor left it, the commit the requirements
// gate checked it at) and the commit-to-task trace `cloop trace` keeps in
// .cloop/trace.json.
//
// A requirement's commits are its linked tasks' commits and no others. A check
// names the task it was made for, but in linked+must mode the requirements
// gate checks every must requirement at every task, so that task says nothing
// about which requirement it implements: its commits are not the requirement's.
//
// # Deleted tasks
//
// A check or a proof keeps naming the task it was made for after the task is
// deleted. Such a task is shown as deleted — never dropped, never given a state
// it no longer has. A deleted task's own links went with it, so it implements
// nothing and brings no commits.
//
// # Pages
//
// Rows come a page at a time, in id order, from the database's keyset: the
// TraceSource answers the part of a filter SQL can — priority and tag — and the
// gap, which needs the plan, is applied here, reading on until the page is full
// or the requirements run out. The coverage is over every approved requirement,
// whatever the filter, and is worked out only when asked for.

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"
)

// Verification classes: how an approved requirement is verified at all.
const (
	// VerificationTests: it has tests, which every check runs.
	VerificationTests = "tested"
	// VerificationModel: it has no tests, and its latest verdict is the
	// model's reading of the code.
	VerificationModel = "model-assessed"
	// VerificationPerson: it has no tests, and its latest verdict is one a
	// person recorded.
	VerificationPerson = "person-assessed"
	// VerificationNone: it has no tests, and nothing has reached a verdict
	// about it — it was never checked, or the model could not tell.
	VerificationNone = "unverified"
)

// Verifications lists the classes, strongest first.
var Verifications = []string{VerificationTests, VerificationModel, VerificationPerson, VerificationNone}

// Why a verdict is stale: the words the Requirements tab's list uses too.
const (
	// StaleChanged: the requirement's definition changed after it.
	StaleChanged = "changed"
	// StaleTasks: tasks finished after it, which may have changed what it
	// looked at.
	StaleTasks = "tasks"
)

// Where a commit in the matrix comes from.
const (
	// CommitFromTrace: the commit-to-task trace, .cloop/trace.json (`cloop
	// trace`).
	CommitFromTrace = "trace"
	// CommitFromWriteBack: where an isolated executor left the task's work.
	CommitFromWriteBack = "write-back"
	// CommitFromGate: the HEAD the requirements gate checked the task at,
	// when that moved past where the task started.
	CommitFromGate = "gate"
)

// FilterNone is the value of a priority or gap filter that selects the
// requirements with none.
const FilterNone = "none"

// Bounds on the matrix.
const (
	// DefaultTracePage and MaxTracePage are how many rows a page holds when
	// it is not told, and at most.
	DefaultTracePage = 50
	MaxTracePage     = 200
	// MaxTraceTasks bounds the tasks a row names, MaxTraceCommits its
	// commits; past them a row counts what it left out.
	MaxTraceTasks   = 50
	MaxTraceCommits = 30
	// MaxTraceTags bounds the tags the coverage lists for a filter.
	MaxTraceTags = 200
	// maxTraceSubjectRunes bounds a commit's subject as a row carries it, and
	// a task's title: a page holds 200 rows of up to 50 tasks each.
	maxTraceSubjectRunes = 200
	// minHashPrefix is how short a commit hash may be and still be matched to
	// a longer one naming the same commit: git's own shortest abbreviation.
	minHashPrefix = 7
)

// TraceCheckFact is a requirement's latest check, as the matrix reads it.
type TraceCheckFact struct {
	Verdict     string
	Method      string
	Summary     string
	Fingerprint string
	Commit      string
	Dirty       bool
	CheckedAt   time.Time
	// TaskID is the task whose completion the check gated, or 0.
	TaskID     int
	Regression bool
}

// TraceProofFact is a requirement's latest red-green proof, as the matrix
// reads it.
type TraceProofFact struct {
	Outcome     string
	Summary     string
	Fingerprint string
	ProvedAt    time.Time
	// TaskID is the task whose tests it proved, or 0.
	TaskID int
}

// TraceFacts is what the project's database records of one approved
// requirement: what a row is made from.
type TraceFacts struct {
	Requirement Requirement
	// Check is its latest check, nil when nothing has checked it.
	Check *TraceCheckFact
	// HeldAt is when a check of its current definition last found it
	// fulfilled; zero when none has.
	HeldAt time.Time
	// Proof is its latest proof, nil when none was made.
	Proof *TraceProofFact
}

// TracePlanTask is one task of the plan as the matrix reads it.
type TracePlanTask struct {
	TaskView
	Title string
	// Commits are what the task records of its own work: CommitFromWriteBack
	// and CommitFromGate.
	Commits []TraceCommit
}

// TracePlan is the plan as the matrix reads it: its tasks, and the commits the
// commit-to-task trace links to each, by task id.
type TracePlan struct {
	Tasks  []TracePlanTask
	Traced map[int][]TraceCommit
}

// TraceTask is a task a row names.
type TraceTask struct {
	ID    int    `json:"id"`
	Title string `json:"title,omitempty"`
	// Status is the task's state; empty for a deleted task.
	Status string `json:"status,omitempty"`
	// Deleted reports a task the plan no longer holds.
	Deleted bool `json:"deleted,omitempty"`
}

// TraceCommit is a commit a linked task produced.
type TraceCommit struct {
	Hash    string `json:"hash"`
	Subject string `json:"subject,omitempty"`
	TaskID  int    `json:"task_id"`
	// Source is CommitFromTrace, CommitFromWriteBack or CommitFromGate.
	Source string `json:"source"`
	// Confidence is how sure the commit-to-task trace was of the link, for a
	// commit it found.
	Confidence string `json:"confidence,omitempty"`
}

// TraceVerdict is a requirement's latest verdict, as a row shows it.
type TraceVerdict struct {
	Verdict   string    `json:"verdict"`
	Method    string    `json:"method,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	// AgeSeconds is how long ago it was reached.
	AgeSeconds int64 `json:"age_seconds"`
	// Stale says why it may no longer hold: StaleChanged or StaleTasks.
	Stale string `json:"stale,omitempty"`
	// TasksDoneSince counts the plan's tasks finished after it.
	TasksDoneSince int    `json:"tasks_done_since,omitempty"`
	Commit         string `json:"commit,omitempty"`
	Dirty          bool   `json:"dirty,omitempty"`
	// Task is the task whose completion the check gated, when one did.
	Task       *TraceTask `json:"task,omitempty"`
	Regression bool       `json:"regression,omitempty"`
}

// TraceProof is a requirement's latest red-green proof, as a row shows it.
type TraceProof struct {
	Outcome  string    `json:"outcome"`
	Summary  string    `json:"summary,omitempty"`
	ProvedAt time.Time `json:"proved_at"`
	// Stale reports a proof of tests the requirement no longer has.
	Stale bool       `json:"stale,omitempty"`
	Task  *TraceTask `json:"task,omitempty"`
}

// TraceRow is one approved requirement in the matrix.
type TraceRow struct {
	ID       int      `json:"id"`
	Title    string   `json:"title"`
	Priority string   `json:"priority,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	// Tests counts its tests.
	Tests int `json:"tests"`
	// Verification is one of Verifications.
	Verification string `json:"verification"`
	// Tasks are the tasks that implement it, in id order.
	Tasks        []TraceTask `json:"tasks"`
	TasksOmitted int         `json:"tasks_omitted,omitempty"`
	// Commits are the commits its tasks produced.
	Commits        []TraceCommit `json:"commits"`
	CommitsOmitted int           `json:"commits_omitted,omitempty"`
	Verdict        *TraceVerdict `json:"verdict,omitempty"`
	Proof          *TraceProof   `json:"proof,omitempty"`
	// Gaps and Action are what is open about it and what closes it, as
	// Assess says.
	Gaps   []string `json:"gaps,omitempty"`
	Action string   `json:"action,omitempty"`
	// Passing, Proven and Linked are what the coverage counts: its latest
	// check of its current definition found it fulfilled; its latest proof,
	// of its current tests, is proven; a task implements it.
	Passing bool `json:"passing"`
	Proven  bool `json:"proven"`
	Linked  bool `json:"linked"`
}

// Key is how the row's requirement is named to people.
func (r TraceRow) Key() string { return Key(r.ID) }

// traceIndex is a plan read once for every row made against it.
type traceIndex struct {
	tasks  map[int]*TracePlanTask
	linked map[int][]int
	views  []TaskView
	// done are the completion times of the plan's done tasks, in order.
	done   []time.Time
	traced map[int][]TraceCommit
}

func (p TracePlan) index() traceIndex {
	ix := traceIndex{tasks: make(map[int]*TracePlanTask, len(p.Tasks)), linked: map[int][]int{}, traced: p.Traced}
	for i := range p.Tasks {
		t := &p.Tasks[i]
		if t.ID <= 0 {
			continue
		}
		if _, dup := ix.tasks[t.ID]; dup {
			continue
		}
		ix.tasks[t.ID] = t
		ix.views = append(ix.views, t.TaskView)
		if t.Status == taskDone && !t.CompletedAt.IsZero() {
			ix.done = append(ix.done, t.CompletedAt)
		}
		seen := map[int]bool{}
		for _, id := range t.Requirements {
			if id > 0 && !seen[id] {
				seen[id] = true
				ix.linked[id] = append(ix.linked[id], t.ID)
			}
		}
	}
	for id := range ix.linked {
		slices.Sort(ix.linked[id])
	}
	slices.SortFunc(ix.done, func(a, b time.Time) int { return a.Compare(b) })
	return ix
}

// doneAfter counts the plan's tasks finished after t.
func (ix traceIndex) doneAfter(t time.Time) int {
	i := sort.Search(len(ix.done), func(i int) bool { return ix.done[i].After(t) })
	return len(ix.done) - i
}

// task names task id as a row shows it: deleted when the plan no longer holds
// it.
func (ix traceIndex) task(id int) *TraceTask {
	if id <= 0 {
		return nil
	}
	t, ok := ix.tasks[id]
	if !ok {
		return &TraceTask{ID: id, Deleted: true}
	}
	return &TraceTask{ID: id, Title: truncateRunes(oneLine(t.Title), maxTraceSubjectRunes), Status: t.Status}
}

// TraceRows makes a row of each approved requirement facts holds, against
// plan, at now, in the order facts gives them.
func TraceRows(facts []TraceFacts, plan TracePlan, now time.Time) []TraceRow {
	return traceRows(facts, plan.index(), now)
}

func traceRows(facts []TraceFacts, ix traceIndex, now time.Time) []TraceRow {
	reqs := make([]Requirement, 0, len(facts))
	last := make(map[int]LastCheck, len(facts))
	for _, f := range facts {
		r := f.Requirement
		if r.CurrentStatus() != StatusApproved || r.ID <= 0 {
			continue
		}
		reqs = append(reqs, r)
		if c := f.Check; c != nil {
			last[r.ID] = LastCheck{Verdict: c.Verdict, Summary: c.Summary, Fingerprint: c.Fingerprint,
				CheckedAt: c.CheckedAt, HeldAt: f.HeldAt}
		}
	}
	// What is open about each, and what closes it, exactly as the planners
	// and the Requirements tab's list read it.
	standing := map[int]Standing{}
	for _, st := range Assess(Standings(reqs, last), ix.views) {
		standing[st.ID] = st
	}
	out := make([]TraceRow, 0, len(reqs))
	for _, f := range facts {
		r := f.Requirement
		st, ok := standing[r.ID]
		if !ok {
			continue
		}
		// Once each, whatever the source repeats.
		delete(standing, r.ID)
		fp := r.Fingerprint()
		row := TraceRow{ID: r.ID, Title: r.Title, Priority: r.Priority, Tags: slices.Clone(r.Tags), Tests: len(r.Tests),
			Verification: verification(r, f.Check), Gaps: st.Gaps, Action: st.Action,
			Tasks: []TraceTask{}, Commits: []TraceCommit{}}
		ids := ix.linked[r.ID]
		row.Linked = len(ids) > 0
		for i, id := range ids {
			if i == MaxTraceTasks {
				row.TasksOmitted = len(ids) - i
				break
			}
			row.Tasks = append(row.Tasks, *ix.task(id))
		}
		row.Commits, row.CommitsOmitted = ix.commits(ids)
		if c := f.Check; c != nil && ValidVerdict(c.Verdict) {
			v := &TraceVerdict{Verdict: c.Verdict, Method: c.Method, Summary: truncateRunes(oneLine(c.Summary), MaxSummaryRunes),
				CheckedAt: c.CheckedAt.UTC(), Commit: CleanCommit(c.Commit), Dirty: c.Dirty, Task: ix.task(c.TaskID),
				Regression: c.Regression, TasksDoneSince: ix.doneAfter(c.CheckedAt)}
			if !c.CheckedAt.IsZero() && now.After(c.CheckedAt) {
				v.AgeSeconds = int64(now.Sub(c.CheckedAt) / time.Second)
			}
			switch {
			case st.Earlier:
				v.Stale = StaleChanged
			case v.TasksDoneSince > 0 && c.Verdict != VerdictUnverified:
				v.Stale = StaleTasks
			}
			row.Verdict = v
			row.Passing = c.Verdict == VerdictFulfilled && !st.Earlier
		}
		if p := f.Proof; p != nil && ValidProofOutcome(p.Outcome) {
			row.Proof = &TraceProof{Outcome: p.Outcome, Summary: truncateRunes(oneLine(p.Summary), MaxSummaryRunes),
				ProvedAt: p.ProvedAt.UTC(), Stale: p.Fingerprint != fp, Task: ix.task(p.TaskID)}
			row.Proven = p.Outcome == ProofProven && !row.Proof.Stale
		}
		out = append(out, row)
	}
	return out
}

// verification classifies how r is verified, given its latest check.
func verification(r Requirement, c *TraceCheckFact) string {
	if r.Tested() {
		return VerificationTests
	}
	// Only a decision counts: unverified says nobody could tell, and error
	// that the check itself did not work.
	if c != nil && (c.Verdict == VerdictFulfilled || c.Verdict == VerdictUnfulfilled) {
		switch c.Method {
		case MethodAI:
			return VerificationModel
		case MethodManual:
			return VerificationPerson
		}
	}
	return VerificationNone
}

// commits gathers the commits the tasks ids name produced, each once: what a
// task records of its own work first, then what the commit-to-task trace
// found, in the trace's order — newest first, as `git log` lists them.
func (ix traceIndex) commits(ids []int) ([]TraceCommit, int) {
	out := []TraceCommit{}
	omitted := 0
	for _, id := range ids {
		var all []TraceCommit
		if t := ix.tasks[id]; t != nil {
			all = append(all, t.Commits...)
		}
		all = append(all, ix.traced[id]...)
		for _, c := range all {
			c.Hash = CleanCommit(c.Hash)
			if c.Hash == "" || len(c.Hash) < minHashPrefix {
				continue
			}
			if i := slices.IndexFunc(out, func(o TraceCommit) bool { return sameCommit(o.Hash, c.Hash) }); i >= 0 {
				// The same commit, from another source or another task: keep
				// the longest hash, so a short one does not hide the full.
				if len(c.Hash) > len(out[i].Hash) {
					out[i].Hash = c.Hash
				}
				if out[i].Subject == "" {
					out[i].Subject = c.Subject
				}
				continue
			}
			if len(out) == MaxTraceCommits {
				omitted++
				continue
			}
			c.TaskID = id
			c.Subject = truncateRunes(oneLine(c.Subject), maxTraceSubjectRunes)
			out = append(out, c)
		}
	}
	return out, omitted
}

// sameCommit reports whether two hashes name one commit: one is a prefix of
// the other, as an abbreviation is of the full hash.
func sameCommit(a, b string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	return len(a) >= minHashPrefix && strings.HasPrefix(b, a)
}

// ── filters ─────────────────────────────────────────────────────────────────

// TraceFilter narrows the matrix. Each field empty selects every row.
type TraceFilter struct {
	// Priority is must, should, could, or FilterNone for the requirements
	// with no priority.
	Priority string `json:"priority,omitempty"`
	// Tag selects the requirements carrying it.
	Tag string `json:"tag,omitempty"`
	// Gap is one of Gaps, or FilterNone for the requirements with no gap.
	Gap string `json:"gap,omitempty"`
}

// ParseTraceFilter reads a filter a person or a client gave, refusing what
// no requirement could match.
func ParseTraceFilter(priority, tag, gap string) (TraceFilter, error) {
	f := TraceFilter{Priority: strings.ToLower(strings.TrimSpace(priority)), Gap: strings.ToLower(strings.TrimSpace(gap))}
	if f.Priority != "" && f.Priority != FilterNone && !validPriority(f.Priority) {
		return TraceFilter{}, invalid("priority %q is not must, should, could or none", truncateRunes(priority, 32))
	}
	if f.Gap != "" && f.Gap != FilterNone && !slices.Contains(Gaps, f.Gap) {
		return TraceFilter{}, invalid("gap %q is not one of %s or none", truncateRunes(gap, 32), strings.Join(Gaps, ", "))
	}
	if strings.TrimSpace(tag) != "" {
		tags, err := normalizeTags([]string{tag})
		if err != nil {
			return TraceFilter{}, err
		}
		f.Tag = tags[0]
	}
	return f, nil
}

// Match reports whether r passes f.
func (f TraceFilter) Match(r TraceRow) bool {
	switch {
	case f.Priority == FilterNone && r.Priority != "",
		f.Priority != "" && f.Priority != FilterNone && r.Priority != f.Priority,
		f.Tag != "" && !slices.Contains(r.Tags, f.Tag),
		f.Gap == FilterNone && len(r.Gaps) > 0,
		f.Gap != "" && f.Gap != FilterNone && !slices.Contains(r.Gaps, f.Gap):
		return false
	}
	return true
}

// ── coverage ────────────────────────────────────────────────────────────────

// CoverageCounts counts requirements, and how many of them are tested, proven,
// passing and linked — each also as a whole percentage, rounded down, so that
// 100 means every one.
type CoverageCounts struct {
	Total      int `json:"total"`
	Tested     int `json:"tested"`
	Proven     int `json:"proven"`
	Passing    int `json:"passing"`
	Linked     int `json:"linked"`
	TestedPct  int `json:"tested_pct"`
	ProvenPct  int `json:"proven_pct"`
	PassingPct int `json:"passing_pct"`
	LinkedPct  int `json:"linked_pct"`
}

func (c *CoverageCounts) add(r TraceRow) {
	c.Total++
	if r.Tests > 0 {
		c.Tested++
	}
	if r.Proven {
		c.Proven++
	}
	if r.Passing {
		c.Passing++
	}
	if r.Linked {
		c.Linked++
	}
}

func (c *CoverageCounts) percentages() {
	pct := func(n int) int {
		if c.Total == 0 {
			return 0
		}
		return n * 100 / c.Total
	}
	c.TestedPct, c.ProvenPct, c.PassingPct, c.LinkedPct = pct(c.Tested), pct(c.Proven), pct(c.Passing), pct(c.Linked)
}

// Coverage is the spec coverage of a project's approved requirements.
type Coverage struct {
	// Approved counts the approved requirements.
	Approved int `json:"approved"`
	// Musts counts the must requirements among them, All every one.
	Musts CoverageCounts `json:"musts"`
	All   CoverageCounts `json:"all"`
	// Stale counts the ones whose latest verdict is stale.
	Stale int `json:"stale"`
	// Gaps counts them by each kind of gap they have, Verification by how
	// they are verified.
	Gaps         map[string]int `json:"gaps"`
	Verification map[string]int `json:"verification"`
	// Tags are the tags they carry, in order: what a filter can choose from.
	Tags []string `json:"tags,omitempty"`
}

// CoverageOf adds rows up.
func CoverageOf(rows []TraceRow) Coverage {
	c := Coverage{Gaps: map[string]int{}, Verification: map[string]int{}}
	tags := map[string]bool{}
	for _, r := range rows {
		c.Approved++
		c.All.add(r)
		if r.Priority == PriorityMust {
			c.Musts.add(r)
		}
		if r.Verdict != nil && r.Verdict.Stale != "" {
			c.Stale++
		}
		for _, g := range r.Gaps {
			c.Gaps[g]++
		}
		c.Verification[r.Verification]++
		for _, t := range r.Tags {
			tags[t] = true
		}
	}
	c.All.percentages()
	c.Musts.percentages()
	for t := range tags {
		c.Tags = append(c.Tags, t)
	}
	sort.Strings(c.Tags)
	if len(c.Tags) > MaxTraceTags {
		c.Tags = c.Tags[:MaxTraceTags]
	}
	return c
}

// Lines says what c amounts to, a line at a time, for a terminal or a report.
func (c Coverage) Lines() []string {
	if c.Approved == 0 {
		return []string{"No approved requirements."}
	}
	counts := func(k CoverageCounts) string {
		return fmt.Sprintf("%d tested (%d%%), %d proven (%d%%), %d passing (%d%%), %d linked to a task (%d%%)",
			k.Tested, k.TestedPct, k.Proven, k.ProvenPct, k.Passing, k.PassingPct, k.Linked, k.LinkedPct)
	}
	var out []string
	if c.Musts.Total > 0 {
		out = append(out, fmt.Sprintf("Musts: %d — %s", c.Musts.Total, counts(c.Musts)))
	} else {
		out = append(out, "Musts: none")
	}
	out = append(out, fmt.Sprintf("All approved: %d — %s", c.All.Total, counts(c.All)))
	var gaps []string
	for _, g := range Gaps {
		if n := c.Gaps[g]; n > 0 {
			gaps = append(gaps, fmt.Sprintf("%d %s", n, g))
		}
	}
	if len(gaps) > 0 {
		out = append(out, "Open gaps: "+strings.Join(gaps, ", "))
	} else {
		out = append(out, "Open gaps: none")
	}
	var how []string
	for _, v := range Verifications {
		if n := c.Verification[v]; n > 0 {
			how = append(how, fmt.Sprintf("%d %s", n, v))
		}
	}
	out = append(out, "Verified: "+strings.Join(how, ", "))
	return out
}

// ── pages ───────────────────────────────────────────────────────────────────

// TraceQuery is what a TraceSource is asked for: the approved requirements of
// a priority (FilterNone: none) and carrying a tag, each when not empty, with
// an id above After, in id order, at most Limit of them.
type TraceQuery struct {
	Priority string
	Tag      string
	After    int
	Limit    int
}

// TraceSource reads the facts of the approved requirements a query selects:
// the project's database (statedb), a keyset page at a time.
type TraceSource interface {
	TraceFacts(q TraceQuery) ([]TraceFacts, error)
}

// TraceRequest asks for a page of the matrix.
type TraceRequest struct {
	Filter TraceFilter
	// After is the last row of the previous page: its Next.
	After int
	// Limit is how many rows the page holds; 0 asks for none.
	Limit int
	// Coverage asks for the coverage, how many rows the filter matches, and
	// the digest — what reading every approved requirement takes.
	Coverage bool
}

// TracePage is one page of the matrix.
type TracePage struct {
	Rows []TraceRow `json:"rows"`
	// Next is the After of the page that follows, 0 when none does.
	Next     int       `json:"next,omitempty"`
	Coverage *Coverage `json:"coverage,omitempty"`
	// Matched counts the rows the filter matches, of every page.
	Matched *int `json:"matched,omitempty"`
	// Digest names what the whole matrix says (TraceDigest).
	Digest string `json:"digest,omitempty"`
}

// gapChunk is how many requirements a page filtered by gap reads at a time:
// most may not have the gap, and a chunk the size of the page would read the
// table a page at a time.
const gapChunk = 100

// Trace reads one page of the matrix from src, against plan, at now.
func Trace(src TraceSource, plan TracePlan, req TraceRequest, now time.Time) (TracePage, error) {
	ix := plan.index()
	page := TracePage{Rows: []TraceRow{}}
	if req.Coverage {
		facts, err := src.TraceFacts(TraceQuery{Limit: MaxRequirements})
		if err != nil {
			return TracePage{}, err
		}
		rows := traceRows(facts, ix, now)
		cov := CoverageOf(rows)
		matched := 0
		for _, r := range rows {
			if req.Filter.Match(r) {
				matched++
			}
		}
		page.Coverage, page.Matched, page.Digest = &cov, &matched, TraceDigest(rows)
	}
	limit := min(max(req.Limit, 0), MaxTracePage)
	if limit == 0 {
		return page, nil
	}
	// One more than the page, to know whether another follows.
	chunk := limit + 1
	if req.Filter.Gap != "" {
		chunk = max(chunk, gapChunk)
	}
	after := max(req.After, 0)
	var rows []TraceRow
	// Every pass moves after up, and there are at most MaxRequirements to
	// read: the bound is a guard against a source that does not.
	for pass := 0; pass <= MaxRequirements/chunk+1 && len(rows) <= limit; pass++ {
		facts, err := src.TraceFacts(TraceQuery{Priority: req.Filter.Priority, Tag: req.Filter.Tag, After: after, Limit: chunk})
		if err != nil {
			return TracePage{}, err
		}
		for _, r := range traceRows(facts, ix, now) {
			if req.Filter.Match(r) {
				if rows = append(rows, r); len(rows) > limit {
					break
				}
			}
		}
		if len(facts) < chunk {
			break
		}
		next := facts[len(facts)-1].Requirement.ID
		if next <= after {
			break
		}
		after = next
	}
	if len(rows) > limit {
		rows = rows[:limit]
		page.Next = rows[limit-1].ID
	}
	if rows != nil {
		page.Rows = rows
	}
	return page, nil
}

// TraceDigest names what rows say, apart from how old their verdicts are: two
// digests differ exactly when a row would read differently. A dashboard keeps
// the digest of the matrix it drew, and reads it again when a pushed one
// differs.
func TraceDigest(rows []TraceRow) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, r := range rows {
		if r.Verdict != nil {
			v := *r.Verdict
			v.AgeSeconds = 0
			r.Verdict = &v
		}
		_ = enc.Encode(r)
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// ── rendering ───────────────────────────────────────────────────────────────

// Age says how long ago d seconds is, roughly, as a person reads it.
func Age(d int64) string {
	switch {
	case d < 60:
		return "just now"
	case d < 3600:
		return fmt.Sprintf("%dm ago", d/60)
	case d < 86400:
		return fmt.Sprintf("%dh ago", d/3600)
	}
	return fmt.Sprintf("%dd ago", d/86400)
}

// Label names t on one line: "#12 done", "#7 deleted".
func (t TraceTask) Label() string {
	if t.Deleted {
		return fmt.Sprintf("#%d deleted", t.ID)
	}
	return strings.TrimSpace(fmt.Sprintf("#%d %s", t.ID, t.Status))
}

// VerdictLabel says what r's latest verdict is, how old, and why it is stale.
func (r TraceRow) VerdictLabel() string {
	v := r.Verdict
	if v == nil {
		return "never checked"
	}
	s := v.Verdict
	if v.Method != "" {
		s += " (" + v.Method + ")"
	}
	s += ", " + Age(v.AgeSeconds)
	switch v.Stale {
	case StaleChanged:
		s += ", stale: changed since"
	case StaleTasks:
		s += fmt.Sprintf(", stale: %d task(s) done since", v.TasksDoneSince)
	}
	if v.Regression {
		s += ", regression"
	}
	return s
}

// ProofLabel says what r's latest proof found.
func (r TraceRow) ProofLabel() string {
	p := r.Proof
	if p == nil {
		if r.Tests == 0 {
			return "—"
		}
		return "unproven"
	}
	if p.Stale {
		return p.Outcome + " (stale)"
	}
	return p.Outcome
}

func (r TraceRow) tasksLabel() string {
	var parts []string
	for _, t := range r.Tasks {
		parts = append(parts, t.Label())
	}
	if r.TasksOmitted > 0 {
		parts = append(parts, fmt.Sprintf("+%d more", r.TasksOmitted))
	}
	return strings.Join(parts, "; ")
}

func (r TraceRow) commitsLabel(short bool) string {
	var parts []string
	for _, c := range r.Commits {
		h := c.Hash
		if short && len(h) > 10 {
			h = h[:10]
		}
		parts = append(parts, fmt.Sprintf("%s #%d", h, c.TaskID))
	}
	if r.CommitsOmitted > 0 {
		parts = append(parts, fmt.Sprintf("+%d more", r.CommitsOmitted))
	}
	return strings.Join(parts, "; ")
}

// csvCell keeps a cell from being read as a formula by a spreadsheet: titles
// are anyone's words and commit subjects anyone's commits.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// TraceCSVHeader is the first line WriteTraceCSV writes.
var TraceCSVHeader = []string{"requirement", "title", "priority", "tags", "verification", "tests", "tasks", "commits",
	"verdict", "method", "checked_at", "stale", "checked_for_task", "proof", "proof_stale", "gaps", "passing", "proven", "linked"}

// WriteTraceCSV writes rows as CSV, a header first.
func WriteTraceCSV(w io.Writer, rows []TraceRow) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(TraceCSVHeader); err != nil {
		return err
	}
	for _, r := range rows {
		var verdict, method, at, stale, forTask, proof string
		proofStale := ""
		if v := r.Verdict; v != nil {
			verdict, method, at, stale = v.Verdict, v.Method, v.CheckedAt.UTC().Format(time.RFC3339), v.Stale
			if v.Task != nil {
				forTask = v.Task.Label()
			}
		}
		if p := r.Proof; p != nil {
			proof, proofStale = p.Outcome, fmt.Sprint(p.Stale)
		}
		rec := []string{r.Key(), r.Title, r.Priority, strings.Join(r.Tags, " "), r.Verification, fmt.Sprint(r.Tests),
			r.tasksLabel(), r.commitsLabel(false), verdict, method, at, stale, forTask, proof, proofStale,
			strings.Join(r.Gaps, " "), fmt.Sprint(r.Passing), fmt.Sprint(r.Proven), fmt.Sprint(r.Linked)}
		for i := range rec {
			rec[i] = csvCell(rec[i])
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// mdCell makes s one Markdown table cell: on one line, its pipes escaped, and
// no raw HTML for a renderer to run.
func mdCell(s string) string {
	s = oneLine(s)
	s = strings.NewReplacer(`\`, `\\`, "|", `\|`, "&", "&amp;", "<", "&lt;", ">", "&gt;", "`", "\\`").Replace(s)
	if s == "" {
		return "—"
	}
	return s
}

// WriteTraceMarkdown writes the coverage, when there is one, and rows as a
// Markdown table.
func WriteTraceMarkdown(w io.Writer, rows []TraceRow, cov *Coverage) error {
	var b strings.Builder
	if cov != nil {
		b.WriteString("## Spec coverage\n\n")
		for _, l := range cov.Lines() {
			b.WriteString("- " + mdCell(l) + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("## Traceability\n\n")
	if len(rows) == 0 {
		b.WriteString("No approved requirement matches.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	b.WriteString("| Requirement | Priority | Verified | Tasks | Commits | Latest verdict | Proof | Gaps |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		cells := []string{r.Key() + " " + r.Title, r.Priority, r.Verification, r.tasksLabel(), r.commitsLabel(true),
			r.VerdictLabel(), r.ProofLabel(), strings.Join(r.Gaps, ", ")}
		for i := range cells {
			cells[i] = mdCell(cells[i])
		}
		b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
