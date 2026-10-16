package ui

// denials_api.go is the dashboard's view of what runs' firewalls refused
// (Task 20437): a task's Network section, and the project firewall card's
// recently blocked list.
//
//	GET /api/tasks/{id}/network          what the task's runs were refused
//	GET /api/firewall/blocked?project_idx=N  the project's recently blocked
//
// Both say, where nothing can be recorded, why — "denials are not observable
// on this executor" for a Kubernetes executor, the upgrade for a device whose
// agent predates protocol v24 — instead of an empty list that would read as
// "nothing was blocked".

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/denylog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// recentlyBlockedWindow is how far back the firewall card looks.
const recentlyBlockedWindow = 7 * 24 * time.Hour

// denialObservability says whether refusals of runs on ex are recorded, and
// if not, the sentence shown instead of a list. ok with an empty note is the
// normal case; not ok with an empty note is an executor with no sandbox
// firewall at all — the hub's host processes — where there is nothing to
// observe and nothing to say.
func denialObservability(ex executor.Executor) (ok bool, note string) {
	if ex == nil {
		return false, "no executor resolves for this project, so what its runs' firewalls refuse is not known"
	}
	switch ex.Kind() {
	case executor.KindKubernetes:
		return false, "Denials are not observable on this executor: a Kubernetes NetworkPolicy has no portable " +
			"log of what it refused, so a blocked connection shows only as the workload's own error."
	case executor.KindLocalProcess:
		return false, ""
	case executor.KindContainer:
		// The hub's own: its packet log is read in this process, bound on
		// first use, so asking is what starts it.
		if _, err := denylog.Shared(); err != nil {
			return false, "Denials are not observable on this executor: the hub cannot read the packet log its " +
				"sandboxes' firewalls write: " + err.Error()
		}
		if ok, why := container.DenialsObservable(); !ok {
			return false, "Denials are not observable on this executor: " + why
		}
		return true, ""
	}
	if r, ok := ex.(interface{ DenialLogStatus() (bool, string) }); ok {
		if fine, why := r.DenialLogStatus(); !fine {
			return false, "Denials are not observable on this executor: " + why
		}
		return true, ""
	}
	return false, "Denials are not observable on this executor (" + ex.Kind() + ")."
}

// denialView is one refusal as the dashboard shows it.
type denialView struct {
	Dst       string    `json:"dst"`
	Port      int       `json:"port,omitempty"`
	Proto     string    `json:"proto"`
	Rule      string    `json:"rule"`
	Kind      string    `json:"kind"`
	Why       string    `json:"why,omitempty"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Runs      int       `json:"runs,omitempty"`
	RunID     string    `json:"run_id,omitempty"`
	Executor  string    `json:"executor_id,omitempty"`
	// Proposable says an allow rule could let it through: the default deny
	// and the hard-block set, never a deny list, a metadata service or a
	// translation prefix, which an allow does not open.
	Proposable bool `json:"proposable,omitempty"`
}

func proposable(rule string) bool {
	switch denylog.RuleKind(rule) {
	case "default", "block":
		return true
	}
	return false
}

func viewOfRow(r statedb.DenialRow) denialView {
	return denialView{
		Dst: r.Dst, Port: r.Port, Proto: r.Proto, Rule: r.Rule, Kind: denylog.RuleKind(r.Rule), Why: r.Why,
		Count: r.Count, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, RunID: r.RunID, Executor: r.ExecutorID,
		Proposable: proposable(r.Rule) && r.Proto == "tcp",
	}
}

// egressView is one egress proxy refusal.
type egressView struct {
	At     time.Time `json:"at"`
	Host   string    `json:"host"`
	Port   int       `json:"port,omitempty"`
	Reason string    `json:"reason,omitempty"`
	RunID  string    `json:"run_id,omitempty"`
}

// taskNetwork is a task's Network section.
type taskNetwork struct {
	Observable bool         `json:"observable"`
	Note       string       `json:"note,omitempty"`
	Denials    []denialView `json:"denials"`
	Unitemised int64        `json:"unitemised,omitempty"`
	Egress     []egressView `json:"egress"`
}

// taskWindow is when a task ran, for matching refusals no task was named for.
func taskWindow(t *pm.Task) (from, to time.Time) {
	if t.StartedAt != nil {
		from = *t.StartedAt
	}
	if t.CompletedAt != nil {
		to = *t.CompletedAt
	}
	return from, to
}

// networkFor reads a task's refusals and its runs' egress refusals.
func (s *Server) networkFor(workDir string, t *pm.Task) taskNetwork {
	out := taskNetwork{Denials: []denialView{}, Egress: []egressView{}}
	ex := executorOfTask(t, workDir)
	out.Observable, out.Note = denialObservability(ex)
	var runs []string
	if t.RunID != "" {
		runs = []string{t.RunID}
	}
	if db, err := openProjectDB(workDir); err == nil {
		from, to := taskWindow(t)
		rows, err := db.TaskDenials(t.ID, runs, from, to)
		db.Close()
		if err == nil {
			for _, r := range rows {
				if r.Rule == statedb.DenialUnitemised {
					out.Unitemised += r.Count
					continue
				}
				out.Denials = append(out.Denials, viewOfRow(r))
			}
		}
	}
	if len(out.Denials) > 0 || out.Unitemised > 0 {
		// What was recorded was observed, whatever the executor can do now.
		out.Observable, out.Note = true, ""
	}
	if len(runs) > 0 {
		if db, err := s.controlPlaneDB(); err == nil {
			refusals, err := db.EgressRefusals(runs, 50)
			db.Close()
			if err == nil {
				for _, e := range refusals {
					out.Egress = append(out.Egress, egressView{At: e.At, Host: e.Host, Port: e.Port,
						Reason: e.Reason, RunID: e.RunID})
				}
			}
		}
	}
	return out
}

// executorOfTask is the executor a task last ran on, or the project's now.
func executorOfTask(t *pm.Task, workDir string) executor.Executor {
	if t != nil && t.ExecutorID != "" {
		if ex, err := executor.Get(t.ExecutorID); err == nil {
			return ex
		}
	}
	return projectExecutorFor(executor.PolicyProjectPath(workDir))
}

// networkSummary is what a task's details carry so the modal knows whether to
// draw the section: a count, or the reason nothing could be recorded. Nil when
// there is nothing to say — a task that never ran, or ran and was refused
// nothing on an executor that would have recorded it.
func (s *Server) networkSummary(workDir string, t *pm.Task) map[string]any {
	if t == nil || t.StartedAt == nil {
		return nil
	}
	n := s.networkFor(workDir, t)
	count := len(n.Denials) + len(n.Egress)
	if n.Unitemised > 0 {
		count++
	}
	if count == 0 && (n.Observable || n.Note == "" || t.ExecutorKind == "") {
		return nil
	}
	return map[string]any{"count": count, "note": n.Note}
}

// handleTaskNetwork serves a task's Network section.
//
// GET /api/tasks/{id}/network
func (s *Server) handleTaskNetwork(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}
	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	task, err := ps.RequireTask(id)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	jsonOK(w, s.networkFor(workDir, task))
}

// blockedView is the firewall card's recently blocked list.
type blockedView struct {
	Visible    bool         `json:"visible"`
	Observable bool         `json:"observable"`
	Note       string       `json:"note,omitempty"`
	Blocked    []denialView `json:"blocked"`
	// CanPropose says the reader may propose an allow rule from the list:
	// an admin. The proposal is a save of the project's rule set, and goes
	// through every check a save does.
	CanPropose bool `json:"can_propose"`
}

// recentlyBlocked reads the project's recent refusals.
func recentlyBlocked(workDir string, limit int) []denialView {
	out := []denialView{}
	db, err := openProjectDB(workDir)
	if err != nil {
		return out
	}
	defer db.Close()
	sums, err := db.RecentDenials(time.Now().Add(-recentlyBlockedWindow), limit)
	if err != nil {
		return out
	}
	for _, s := range sums {
		out = append(out, denialView{
			Dst: s.Dst, Port: s.Port, Proto: s.Proto, Rule: s.Rule, Kind: denylog.RuleKind(s.Rule), Why: s.Why,
			Count: s.Count, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, Runs: s.Runs, RunID: s.LastRunID,
			Executor: s.ExecutorID, Proposable: proposable(s.Rule) && s.Proto == "tcp" && proposableAddr(s.Dst),
		})
	}
	return out
}

// proposableAddr keeps a proposal to an address an allowlist may name: not a
// metadata service, which only its own entry at every level opens.
func proposableAddr(dst string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(dst))
	return err == nil && a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast()
}

// handleFirewallBlocked serves the project's recently blocked list, to those
// who may change its rules — like the card it belongs to.
//
// GET /api/firewall/blocked?project_idx=N
func (s *Server) handleFirewallBlocked(w http.ResponseWriter, r *http.Request) {
	workDir := strings.TrimSpace(s.resolveWorkDir(r))
	if workDir == "" {
		jsonErr(w, "no project selected", http.StatusBadRequest)
		return
	}
	if !s.permissionsFor(r, s.projectScope(r)).Allows(authz.PermConfigWrite) {
		jsonOK(w, blockedView{Visible: false, Blocked: []denialView{}})
		return
	}
	view := blockedView{Visible: true, Blocked: recentlyBlocked(workDir, 50)}
	view.Observable, view.Note = denialObservability(projectExecutorFor(executor.PolicyProjectPath(workDir)))
	view.CanPropose = s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermExecutorManage)
	jsonOK(w, view)
}

// blockedSummary is what the firewall card's own answer carries: enough to
// decide whether to draw the list at all.
type blockedSummary struct {
	Count int    `json:"count"`
	Note  string `json:"note,omitempty"`
}

func blockedSummaryFor(workDir string, ex executor.Executor) *blockedSummary {
	n := len(recentlyBlocked(workDir, 50))
	ok, note := denialObservability(ex)
	if ok {
		note = ""
	}
	if n == 0 && note == "" {
		return nil
	}
	return &blockedSummary{Count: n, Note: note}
}
