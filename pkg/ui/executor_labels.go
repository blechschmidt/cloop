package ui

// executor_labels.go: label grants reach the executors that carry the labels
// (Task 20432).
//
// A grant to label:region=eu,gpu=true is matched against the labels of the
// executor a lease, a proxy session or a grant query is for — and every one of
// those used to be asked as an executor ID and a project, with no labels, so
// a label grant was accepted, listed and audited and delivered nothing. They
// are asked through secretbroker.NewRequester now, with the executor as the
// hub records it (executorstore.Records): a device by its agent credential, a
// virtual executor by its device's, a configured executor by the
// configuration this process started from. Never by what a device's agent
// says about itself.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var (
	configuredLabelsMu sync.RWMutex
	// configuredLabelsValue is what the configuration this process
	// bootstrapped from gives each configured executor, by ID — the same
	// configuration its drivers were built from, so every lease this process
	// issues judges a configured executor by one set of labels. An edit to the
	// configuration applies when the hub restarts, and the leases it then
	// adopts are re-judged by the janitor (reconcileExecutorLabels).
	configuredLabelsValue map[string]map[string]string
)

// setConfiguredExecutorLabels records cfg's configured executor labels as
// this process's.
func setConfiguredExecutorLabels(cfg *config.Config) {
	var labels map[string]map[string]string
	if cfg != nil {
		labels = cfg.Executors.ConfiguredExecutorLabels()
	}
	configuredLabelsMu.Lock()
	configuredLabelsValue = labels
	configuredLabelsMu.Unlock()
}

// configuredExecutorLabels returns them, copied. Nil in a process that
// bootstrapped no control plane.
func configuredExecutorLabels() (map[string]map[string]string, error) {
	configuredLabelsMu.RLock()
	defer configuredLabelsMu.RUnlock()
	if configuredLabelsValue == nil {
		return nil, nil
	}
	out := make(map[string]map[string]string, len(configuredLabelsValue))
	for id, labels := range configuredLabelsValue {
		out[id] = executor.NormalizeLabels(labels)
	}
	return out, nil
}

// hubExecutorRecords is the hub's record of its executors over db.
func hubExecutorRecords(db *statedb.DB) secretbroker.ExecutorRecords {
	return executorstore.Records{DB: db, Configured: configuredExecutorLabels}
}

// recordedExecutor returns the hub's record of ex: its ID and the labels the
// hub recorded for it. db, when the caller holds the control plane's database
// already, saves opening it again; with none it is opened for the read. A
// process with no control plane records nothing, and gets ex's ID alone — it
// has no grants to match either.
func recordedExecutor(db *statedb.DB, ex executor.Executor) (secretbroker.RecordedExecutor, error) {
	id := ""
	if ex != nil {
		id = ex.ID()
	}
	return recordedExecutorID(db, id)
}

// recordedExecutorID is recordedExecutor for an executor known by ID.
func recordedExecutorID(db *statedb.DB, executorID string) (secretbroker.RecordedExecutor, error) {
	if db != nil {
		return secretbroker.LookupExecutor(hubExecutorRecords(db), executorID)
	}
	dir := controlPlaneDir()
	if dir == "" {
		return secretbroker.LookupExecutor(nil, executorID)
	}
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); errors.Is(err, fs.ErrNotExist) {
		// No database yet: no credential, no virtual executor, no grant.
		return secretbroker.LookupExecutor(nil, executorID)
	}
	opened, err := statedb.Open(dbPath)
	if err != nil {
		ex, _ := secretbroker.LookupExecutor(nil, executorID)
		return ex, fmt.Errorf("open the control plane's database to read executor %s's record: %w", executorID, err)
	}
	defer opened.Close()
	return secretbroker.LookupExecutor(hubExecutorRecords(opened), executorID)
}

// ── what stood on a label grant ──────────────────────────────────────────────

// labelTakeBack is one credential a change to an executor's recorded labels
// took back from a running workload.
type labelTakeBack struct {
	ExecutorID  string `json:"executor_id"`
	ProjectPath string `json:"project_path,omitempty"`
	// LeaseID is set for a secret lease's grant, SessionID for an egress
	// proxy session.
	LeaseID   string `json:"lease_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	GrantID   string `json:"grant_id"`
	// Subject is the label selector the grant was issued to.
	Subject string             `json:"subject"`
	State   remote.RevokeState `json:"state"`
	Reason  string             `json:"reason"`
}

// labelRecheck is what re-judging leases and sessions by the labels the hub
// records for their executors did.
type labelRecheck struct {
	// Leases and Sessions count the live leases and egress sessions whose
	// executor's labels had changed, and which are judged by the new ones now.
	Leases   int `json:"leases"`
	Sessions int `json:"sessions"`
	// TakenBack is every grant that stopped matching.
	TakenBack []labelTakeBack `json:"taken_back"`
	// Errors are the records that could not be read or rewritten. The
	// janitor's next pass asks again.
	Errors []string `json:"errors,omitempty"`
}

// executorRecordCache reads each executor's record once per pass.
type executorRecordCache struct {
	records secretbroker.ExecutorRecords
	seen    map[string]recordLookup
}

type recordLookup struct {
	rec secretbroker.RecordedExecutor
	err error
}

func (c *executorRecordCache) get(id string) (secretbroker.RecordedExecutor, error) {
	if l, ok := c.seen[id]; ok {
		return l.rec, l.err
	}
	rec, err := secretbroker.LookupExecutor(c.records, id)
	c.seen[id] = recordLookup{rec: rec, err: err}
	return rec, err
}

// reconcileExecutorLabels re-judges the live leases and egress proxy sessions
// this process holds on the executors in scope — every executor when scope is
// nil — by the labels the hub records for them now, and takes back every label
// grant those labels no longer match (Task 20432).
//
// A grant is taken back as a revocation of it would be (Task 20403): its
// material out of the workload on every holder, the git proxy and Kubernetes
// monitor sessions it fed closed, its App tokens destroyed, the lease going
// on with its other grants; an egress session standing on it is closed, its
// tunnels with it. The leases and sessions are relabeled in their records as
// well, so a process that adopts a run judges it as this one does.
//
// It runs when a device's labels are edited, for that device and its virtual
// executors; on every pass of the lease janitor, for everything, which is how
// an edit made on another hub member, or a configuration the hub restarted
// with, reaches the leases this member holds within a minute; and when this
// process adopts a run.
func (s *Server) reconcileExecutorLabels(ctx context.Context, scope map[string]bool, actor string) labelRecheck {
	res := labelRecheck{TakenBack: []labelTakeBack{}}
	leases := s.ownLeases()
	if svc := activeEgressProxy(); len(leases) == 0 && (svc == nil || len(svc.broker.Sessions()) == 0) {
		// Nothing held here to re-judge: an idle member's janitor opens no
		// database for this every minute.
		return res
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		res.Errors = append(res.Errors, "the hub's executor records could not be read: "+err.Error())
		return res
	}
	defer db.Close()
	cache := &executorRecordCache{records: hubExecutorRecords(db), seen: map[string]recordLookup{}}

	for _, sl := range leases {
		id := strings.TrimSpace(sl.lease.ExecutorID)
		if id == "" || (scope != nil && !scope[id]) {
			continue
		}
		rec, err := cache.get(id)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("lease %s: %v", sl.lease.ID, err))
			continue
		}
		relabeled, taken, err := s.relabelLease(ctx, sl, rec, actor)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("lease %s: %v", sl.lease.ID, err))
		}
		if relabeled {
			res.Leases++
		}
		res.TakenBack = append(res.TakenBack, taken...)
	}
	s.relabelEgressSessions(cache, scope, &res)

	if len(res.TakenBack) > 0 {
		s.broadcastSecretsUpdate("grant_revoked", "")
	}
	return res
}

// relabelLease judges sl's lease by rec's labels and takes back each label
// grant they no longer match, reporting whether the labels had changed.
func (s *Server) relabelLease(ctx context.Context, sl *secretLease, rec secretbroker.RecordedExecutor,
	actor string) (bool, []labelTakeBack, error) {
	if sl == nil || sl.lease == nil || sl.broker == nil {
		return false, nil, nil
	}
	was, held := sl.broker.HeldRequester(sl.lease.ID)
	if !held || secretbroker.SameLabels(was.Labels, rec.Labels) {
		return false, nil, nil
	}
	changed, err := sl.broker.RelabelLease(sl.lease.ID, rec.Labels)
	if !changed {
		return false, nil, err
	}
	if errors.Is(err, secretbroker.ErrLeaseMoved) {
		// Another hub process holds the lease now, with its run: what it
		// carries is that process's to judge, and its janitor does.
		return true, nil, err
	}
	var out []labelTakeBack
	for _, lw := range sl.broker.LabelWithdrawals(sl.lease.ID, was.Labels) {
		if sl.isWithdrawn(lw.GrantID) {
			continue
		}
		rv := s.revokeLeaseEverywhere(ctx, sl.lease.ID, lw.GrantID, lw.Reason, remote.RevokeScrub, actor)
		out = append(out, labelTakeBack{
			ExecutorID: rec.ID, ProjectPath: sl.lease.ProjectID, LeaseID: sl.lease.ID,
			GrantID: lw.GrantID, Subject: lw.Subject, State: rv.State, Reason: lw.Reason,
		})
	}
	return true, out, err
}

// relabelEgressSessions is reconcileExecutorLabels for the egress proxy
// sessions this process serves.
func (s *Server) relabelEgressSessions(cache *executorRecordCache, scope map[string]bool, res *labelRecheck) {
	svc := activeEgressProxy()
	if svc == nil {
		return
	}
	for _, sess := range svc.broker.Sessions() {
		if sess == nil || sess.Closed() {
			continue
		}
		id := strings.TrimSpace(sess.ExecutorID)
		if id == "" || (scope != nil && !scope[id]) {
			continue
		}
		rec, err := cache.get(id)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("egress session %s: %v", sess.ID, err))
			continue
		}
		was, live := svc.broker.SessionRequester(sess.ID)
		if !live || secretbroker.SameLabels(was.Labels, rec.Labels) {
			continue
		}
		changed, err := svc.broker.RelabelSession(sess.ID, rec.Labels)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("egress session %s: %v", sess.ID, err))
		}
		if !changed {
			continue
		}
		res.Sessions++
		now, live := svc.broker.SessionRequester(sess.ID)
		subject := sess.Grant.Subject
		if !live || !subject.LabelSubject() || subject.Matches(now) {
			continue
		}
		reason := fmt.Sprintf("egress grant %s is issued to %s and executor %s no longer carries those labels: "+
			"the hub's record of them changed from %s to %s", sess.GrantID, subject.String(), id,
			secretbroker.FormatLabels(was.Labels), secretbroker.FormatLabels(rec.Labels))
		svc.broker.CloseSession(sess.ID, reason)
		res.TakenBack = append(res.TakenBack, labelTakeBack{
			ExecutorID: id, ProjectPath: sess.ProjectID, SessionID: sess.ID, GrantID: sess.GrantID,
			Subject: subject.String(), State: remote.RevokeStateRevoked, Reason: reason,
		})
	}
}

// relabelAdoptedLease judges a lease this process just took over with its run
// by the labels the hub records for its executor now, rather than the ones the
// lease was recorded with: a device relabeled, or a hub restarted with other
// configured labels, while no process held it (Task 20432).
func (s *Server) relabelAdoptedLease(sl *secretLease) {
	if sl == nil || sl.lease == nil || sl.broker == nil || sl.auditDB == nil {
		return
	}
	rec, err := secretbroker.LookupExecutor(hubExecutorRecords(sl.auditDB), sl.lease.ExecutorID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: adopted lease %s: %v; the lease janitor asks again\n", sl.lease.ID, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
	defer cancel()
	_, taken, err := s.relabelLease(ctx, sl, rec, "janitor")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: relabel adopted lease %s: %v\n", sl.lease.ID, err)
	}
	if len(taken) > 0 {
		s.broadcastSecretsUpdate("grant_revoked", sl.lease.ID)
	}
}

// ── editing a device's labels ────────────────────────────────────────────────

// executorLabelsRequest is the PUT /api/executors/{id}/labels body: the
// device's labels, whole.
type executorLabelsRequest struct {
	Labels map[string]string `json:"labels"`
}

// executorLabelsView is the route's answer: the labels the hub records for the
// executor, where they come from, whether this route can change them, and —
// after an edit — what re-judging the device's leases and sessions did.
type executorLabelsView struct {
	ExecutorID string            `json:"executor_id"`
	Labels     map[string]string `json:"labels"`
	// Source is the record the labels are read from: "agent credential",
	// "configuration", "the agent credential of device …", or "" for none.
	Source string `json:"source,omitempty"`
	// Editable is true for an enrolled device, whose labels this route sets.
	// Why says where the labels of any other executor are set instead.
	Editable bool          `json:"editable"`
	Why      string        `json:"why,omitempty"`
	Recheck  *labelRecheck `json:"recheck,omitempty"`
}

// handleExecutorLabels serves GET and PUT /api/executors/{id}/labels (Task
// 20432): the labels a label grant reaching the executor is matched against.
//
// Only an enrolled device's labels are set here. A configured executor's are
// the hub's configuration, and a virtual executor carries its device's. An
// edit is audited (executor.labels, with the labels before and after), and the
// device's live leases and egress sessions, and its virtual executors', are
// re-judged at once: a label grant the new labels no longer match is taken
// back from the workloads holding it. The permission is the one enrolling a
// device takes, which could put any label on a new device anyway.
func (s *Server) handleExecutorLabels(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "executor id is required", http.StatusBadRequest)
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	view, cred, err := s.executorLabelsViewFor(db, id)
	if err != nil {
		if errors.Is(err, statedb.ErrExecutorNotFound) {
			jsonErr(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, view)
		return
	case http.MethodPut:
	default:
		w.Header().Set("Allow", "GET, PUT")
		jsonErr(w, "method not allowed: use GET to read, PUT to replace", http.StatusMethodNotAllowed)
		return
	}

	var req executorLabelsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !view.Editable {
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error":       "the labels of executor " + id + " are not set here: " + view.Why,
			"code":        "executor_labels_not_editable",
			"executor_id": id,
		})
		return
	}
	labels := executor.NormalizeLabels(req.Labels)
	if err := executor.ValidateLabels(labels); err != nil {
		jsonErr(w, "labels: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := db.SetAgentCredentialLabels(id, labels); err != nil {
		if errors.Is(err, statedb.ErrDBLocked) {
			jsonErr(w, "the control plane is busy; retry: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		jsonErr(w, "set labels: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// The device and every virtual executor on it: their leases are judged by
	// its labels.
	scope := map[string]bool{id: true}
	if vs, verr := db.ListVirtualExecutors(); verr == nil {
		for _, v := range vs {
			if v.ParentID == id {
				scope[v.ID] = true
			}
		}
	}
	// Detached from the browser, as a revocation's cascade is, and bounded:
	// the labels are saved, and a closed tab must not leave the take-back half
	// done.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), revokeFanoutTimeout)
	defer cancel()
	recheck := s.reconcileExecutorLabels(ctx, scope, s.auditActor(r))

	s.auditExecutorAction(r, "labels", id, map[string]any{
		"from":       labelsOrEmpty(cred.Labels),
		"to":         labelsOrEmpty(labels),
		"leases":     recheck.Leases,
		"sessions":   recheck.Sessions,
		"taken_back": len(recheck.TakenBack),
	})
	s.broadcastExecutorUpdate("labels", id)

	after, _, err := s.executorLabelsViewFor(db, id)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	after.Recheck = &recheck
	jsonOK(w, after)
}

// executorLabelsViewFor describes executor id's labels, and returns its agent
// credential when it is an enrolled device.
func (s *Server) executorLabelsViewFor(db *statedb.DB, id string) (executorLabelsView, statedb.AgentCredentialRow, error) {
	view := executorLabelsView{ExecutorID: id, Labels: map[string]string{}}
	rec, err := secretbroker.LookupExecutor(hubExecutorRecords(db), id)
	if err != nil {
		return view, statedb.AgentCredentialRow{}, err
	}
	view.Labels, view.Source = labelsOrEmpty(rec.Labels), rec.Source

	if v, ok, err := db.VirtualExecutor(id); err != nil {
		return view, statedb.AgentCredentialRow{}, err
	} else if ok {
		view.Why = "a virtual executor carries the labels of its device, " + v.ParentID + "; edit those"
		return view, statedb.AgentCredentialRow{}, nil
	}
	cred, err := db.GetAgentCredential(id)
	switch {
	case err == nil && !cred.RevokedAt.IsZero():
		view.Why = "the device's credential is revoked"
		return view, cred, nil
	case err == nil:
		view.Editable = true
		return view, cred, nil
	case !errors.Is(err, statedb.ErrAgentCredentialNotFound):
		return view, statedb.AgentCredentialRow{}, err
	}
	configured, _ := configuredExecutorLabels()
	if _, ok := configured[id]; ok {
		view.Why = "a configured executor's labels are its executors.container.labels or " +
			"executors.kubernetes.labels in the hub's configuration, read when the hub starts"
		return view, statedb.AgentCredentialRow{}, nil
	}
	if _, err := db.GetExecutor(id); err == nil {
		view.Why = "this executor carries no labels; only an enrolled device's are set here"
		return view, statedb.AgentCredentialRow{}, nil
	}
	if _, err := executor.Get(id); err == nil {
		view.Why = "this executor carries no labels; only an enrolled device's are set here"
		return view, statedb.AgentCredentialRow{}, nil
	}
	return view, statedb.AgentCredentialRow{}, fmt.Errorf("%w: %q", statedb.ErrExecutorNotFound, id)
}

// labelsOrEmpty is labels, or an empty map for none, so a JSON answer and an
// audit payload say {} rather than null.
func labelsOrEmpty(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return map[string]string{}
	}
	return labels
}

// ── which executors a label subject reaches ──────────────────────────────────

// labelMatchView is which executors a label grant reaches now (Task 20432):
// each executor whose recorded labels carry every pair its selector names.
// Executors is empty — "none" — when no executor carries them yet: the state a
// grant to a mistyped selector is in, and the reason it delivers nothing.
type labelMatchView struct {
	Executors []labelMatchExecutor `json:"executors"`
	// Unknown says why the match could not be computed, when it could not.
	Unknown string `json:"unknown,omitempty"`
}

// labelMatchExecutor is one executor a label subject reaches.
type labelMatchExecutor struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
	// Device is set for a virtual executor: the device whose labels it
	// carries.
	Device string `json:"device,omitempty"`
}

// labelFleet is every executor the hub knows, each with its record, for
// matching label subjects against.
type labelFleet struct {
	members []executorstore.FleetMember
	err     error
}

// loadLabelFleet reads the fleet: every executor with a registry row, and any
// this process registered that has none yet.
func loadLabelFleet(db *statedb.DB) labelFleet {
	var live []executorstore.FleetMember
	for _, ex := range executor.List() {
		live = append(live, executorstore.FleetMember{ID: ex.ID(), Name: ex.ID(), Kind: ex.Kind()})
	}
	members, err := executorstore.Fleet(db, hubExecutorRecords(db), live)
	return labelFleet{members: members, err: err}
}

// matches is which executors sub reaches, or nil for a subject that is no
// label selector — a project, an executor and "any" say who they reach.
func (f labelFleet) matches(sub secretbroker.Subject) *labelMatchView {
	if !sub.LabelSubject() {
		return nil
	}
	view := &labelMatchView{Executors: []labelMatchExecutor{}}
	if f.err != nil {
		view.Unknown = "the hub's executor records could not be read: " + f.err.Error()
		return view
	}
	for _, m := range executorstore.Reaches(f.members, sub) {
		view.Executors = append(view.Executors, labelMatchExecutor{ID: m.ID, Name: m.Name, Kind: m.Kind, Device: m.Device})
	}
	return view
}

// labelMatchesUnreadable is the answer for a caller who may not list the
// executor fleet: a label subject's matches are executors, and naming them is
// the executor list.
func labelMatchesUnreadable() *labelMatchView {
	return &labelMatchView{Executors: []labelMatchExecutor{},
		Unknown: "listing the executors a selector matches needs the executor.read permission"}
}

// annotateLabelMatches sets, on every grant row with a label subject, the
// executors it reaches now.
func (s *Server) annotateLabelMatches(r *http.Request, db *statedb.DB, grants []grantView) {
	var fleet *labelFleet
	canRead := s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermExecutorRead)
	for i := range grants {
		sub, err := secretbroker.ParseSubject(grants[i].Subject)
		if err != nil || !sub.LabelSubject() {
			continue
		}
		if !canRead {
			grants[i].LabelMatches = labelMatchesUnreadable()
			continue
		}
		if fleet == nil {
			f := loadLabelFleet(db)
			fleet = &f
		}
		grants[i].LabelMatches = fleet.matches(sub)
	}
}

// grantSubjectMatchesView answers GET /api/grants/matches.
type grantSubjectMatchesView struct {
	// Subject is the subject as a grant would store it.
	Subject string `json:"subject"`
	Type    string `json:"type"`
	// Matches is set for a label selector.
	Matches *labelMatchView `json:"matches,omitempty"`
}

// handleGrantSubjectMatches serves GET /api/grants/matches?subject=…: whether a
// subject parses, as what, and — for a label selector — which executors it
// reaches now, for the grant dialog to say as the subject is typed (Task
// 20432). A subject that does not parse is a 400 carrying the reason, the one
// creating the grant would meet.
func (s *Server) handleGrantSubjectMatches(w http.ResponseWriter, r *http.Request) {
	sub, err := secretbroker.ParseSubject(r.URL.Query().Get("subject"))
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	view := grantSubjectMatchesView{Subject: sub.String(), Type: string(sub.Type)}
	if sub.LabelSubject() {
		if !s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermExecutorRead) {
			view.Matches = labelMatchesUnreadable()
		} else if db, derr := s.controlPlaneDB(); derr != nil {
			view.Matches = &labelMatchView{Executors: []labelMatchExecutor{},
				Unknown: "the hub's executor records could not be read: " + derr.Error()}
		} else {
			defer db.Close()
			view.Matches = loadLabelFleet(db).matches(sub)
		}
	}
	jsonOK(w, view)
}
