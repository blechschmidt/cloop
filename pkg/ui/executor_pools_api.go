package ui

// executor_pools_api.go: administering executor pools (Task 20482).
//
// Every route here is executor.manage — an administrator's — and asks a
// session for a recent sign-in on its writes (sudo.go): a pool decides which
// machines run which projects, and its credential mints runner tokens. They go
// through the hub's Origin and JSON-only guards like every dashboard write.
//
//	GET    /api/executor-pools                          every pool, with its demand and health
//	POST   /api/executor-pools                          create (executor_pools_dashboard.go: with its
//	                                                    access list and a credential, in one step)
//	GET    /api/executor-pools/{id}                     one pool: demand, runners, queue, credentials, access list
//	PUT    /api/executor-pools/{id}                     change its definition
//	POST   /api/executor-pools/{id}/revoke              revoke it and everything it holds
//	POST   /api/executor-pools/{id}/credentials         mint a controller credential (shown once)
//	DELETE /api/executor-pools/{id}/credentials/{cid}   revoke one
//	GET|POST|DELETE /api/executor-pools/{id}/audience   who may run work on its runners
//
// A project is bound to a pool through the ordinary binding route,
// POST /api/projects/{idx}/executor with executor_id "pool:<id>".

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/kubecontroller"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// poolView is a pool as the API shows it.
type poolView struct {
	executorpool.Pool
	Binding  string                 `json:"binding"`
	Snapshot *executorpool.Snapshot `json:"snapshot,omitempty"`
	// Cordoned says an administrator holds the pool (Task 20486).
	Cordoned bool `json:"cordoned"`
	// Health is what the hub knows of the pool's controllers and makes of it
	// (Task 20486); absent for a revoked pool and where it cannot be read.
	Health *poolHealthView `json:"health,omitempty"`
}

// poolDetail is one pool with everything an administrator looks at.
type poolDetail struct {
	poolView
	Credentials []executorpool.Credential       `json:"credentials"`
	Audience    []statedb.ExecutorAudienceEntry `json:"audience"`
	Runners     []poolRunnerView                `json:"runners"`
	Queue       []poolQueueView                 `json:"queue"`
	// ControllerReports are what each of the pool's controllers last said
	// keeps it from starting runners, if anything (Task 20484).
	ControllerReports []poolControllerReportView `json:"controller_reports"`
}

// poolControllerReportView is a controller's last health report.
type poolControllerReportView struct {
	CredentialID string    `json:"credential_id"`
	Healthy      bool      `json:"healthy"`
	Reason       string    `json:"reason,omitempty"`
	Message      string    `json:"message,omitempty"`
	ReportedAt   time.Time `json:"reported_at"`
	// Storage is the controller's count of its runners' volumes (Task 20486).
	Storage *executorpool.StorageUsage `json:"storage,omitempty"`
}

// poolRunnerView is a runner as the API shows it.
type poolRunnerView struct {
	EnrollmentID string    `json:"enrollment_id"`
	Name         string    `json:"name"`
	ExecutorID   string    `json:"executor_id,omitempty"`
	State        string    `json:"state"`
	Member       string    `json:"member,omitempty"`
	QueueID      string    `json:"queue_id,omitempty"`
	MintedAt     time.Time `json:"minted_at"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	EnrolledAt   time.Time `json:"enrolled_at,omitempty"`
	RetiredAt    time.Time `json:"retired_at,omitempty"`
	RetireReason string    `json:"retire_reason,omitempty"`
	// Holds is the tenant whose data the runner's storage holds; Project the
	// tenant of the run it was handed (Task 20484).
	Holds   string `json:"holds,omitempty"`
	Project string `json:"project,omitempty"`
	// CredentialID is the controller credential that minted the runner,
	// which revoking takes the runner with it (Task 20486).
	CredentialID string `json:"credential_id,omitempty"`
}

// poolQueueView is a queued run as the API shows it.
type poolQueueView struct {
	ID          string    `json:"id"`
	ProjectPath string    `json:"project_path"`
	Starter     string    `json:"starter,omitempty"`
	State       string    `json:"state"`
	Reason      string    `json:"reason,omitempty"`
	ExecutorID  string    `json:"executor_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// poolStoreFor opens the pool store for a request, writing a 503 when it
// cannot.
func (s *Server) poolStoreFor(w http.ResponseWriter) (*executorpool.Store, bool) {
	store, err := s.poolStore()
	if err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"error": "executor pools are unavailable: " + err.Error(), "code": "executor_pool_unavailable"})
		return nil, false
	}
	return store, true
}

// writePoolErr renders a pool store error.
func writePoolErr(w http.ResponseWriter, err error) {
	var capErr *statedb.PoolAtCapacityError
	switch {
	case errors.Is(err, executorpool.ErrInvalidSpec):
		jsonErr(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, executorpool.ErrNotFound), errors.Is(err, statedb.ErrPoolCredentialNotFound):
		jsonErr(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, statedb.ErrExecutorPoolNameTaken), errors.Is(err, executorpool.ErrRevoked),
		errors.Is(err, executorpool.ErrCordoned):
		jsonErr(w, err.Error(), http.StatusConflict)
	case errors.As(err, &capErr):
		jsonErr(w, err.Error(), http.StatusConflict)
	default:
		jsonErr(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleExecutorPoolsList serves GET /api/executor-pools.
func (s *Server) handleExecutorPoolsList(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	store, ok := s.poolStoreFor(w)
	if !ok {
		return
	}
	pools, err := store.List()
	if err != nil {
		writePoolErr(w, err)
		return
	}
	access := s.poolAccessFor(store)
	out := make([]poolView, 0, len(pools))
	for _, p := range pools {
		v := s.newPoolView(store, p, true)
		if snap, _, err := store.Snapshot(p, access); err == nil {
			v.Snapshot = &snap
		}
		out = append(out, v)
	}
	// What an upgrade of a controller behind this hub installs (Task 20486).
	tag, _ := kubecontroller.ControllerImageTag(hubVersion())
	jsonOK(w, map[string]any{"pools": out, "hub_protocol": executorpool.ControllerProtocol,
		"chart": s.externalBaseURL(r) + kubecontroller.ChartArchivePath, "image_tag": tag})
}

// poolFromPath resolves the {id} wildcard, writing the error itself.
func (s *Server) poolFromPath(w http.ResponseWriter, r *http.Request) (*executorpool.Store, executorpool.Pool, bool) {
	if !s.requireExecutorAdmin(w, r) {
		return nil, executorpool.Pool{}, false
	}
	store, ok := s.poolStoreFor(w)
	if !ok {
		return nil, executorpool.Pool{}, false
	}
	p, err := store.Get(r.PathValue("id"))
	if err != nil {
		writePoolErr(w, err)
		return nil, executorpool.Pool{}, false
	}
	return store, p, true
}

// handleExecutorPoolDetail serves GET /api/executor-pools/{id}.
func (s *Server) handleExecutorPoolDetail(w http.ResponseWriter, r *http.Request) {
	store, p, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	d := poolDetail{poolView: s.newPoolView(store, p, true), Runners: []poolRunnerView{}, Queue: []poolQueueView{}}
	if snap, _, err := store.Snapshot(p, s.poolAccessFor(store)); err == nil {
		d.Snapshot = &snap
	}
	var err error
	if d.Credentials, err = store.Credentials(p.ID); err != nil {
		writePoolErr(w, err)
		return
	}
	if d.Audience, err = store.Audience(p.ID); err != nil {
		writePoolErr(w, err)
		return
	}
	if d.Audience == nil {
		d.Audience = []statedb.ExecutorAudienceEntry{}
	}
	runners, err := store.DB().ListExecutorPoolRunners(p.ID)
	if err != nil {
		writePoolErr(w, err)
		return
	}
	for _, rr := range runners {
		d.Runners = append(d.Runners, poolRunnerView{EnrollmentID: rr.EnrollmentID, Name: rr.Name, ExecutorID: rr.ExecutorID,
			State: rr.State, Member: rr.Member, QueueID: rr.QueueID, MintedAt: rr.MintedAt, ExpiresAt: rr.ExpiresAt,
			EnrolledAt: rr.EnrolledAt, RetiredAt: rr.RetiredAt, RetireReason: rr.RetireReason, Holds: rr.Holds,
			Project: rr.Project, CredentialID: rr.CredentialID})
	}
	d.ControllerReports = []poolControllerReportView{}
	reports, err := store.DB().PoolControllerStatuses(p.ID)
	if err != nil {
		writePoolErr(w, err)
		return
	}
	for _, cr := range reports {
		d.ControllerReports = append(d.ControllerReports, poolControllerReportView{CredentialID: cr.CredentialID,
			Healthy: cr.Healthy, Reason: cr.Reason, Message: cr.Message, ReportedAt: cr.ReportedAt,
			Storage: executorpool.DecodeStorage(cr.Storage)})
	}
	queue, err := store.DB().ListPoolQueue(p.ID)
	if err != nil {
		writePoolErr(w, err)
		return
	}
	for _, q := range queue {
		d.Queue = append(d.Queue, poolQueueView{ID: q.ID, ProjectPath: q.ProjectPath, Starter: q.Starter, State: q.State,
			Reason: q.Reason, ExecutorID: q.ExecutorID, CreatedAt: q.CreatedAt, UpdatedAt: q.UpdatedAt})
	}
	if d.Credentials == nil {
		d.Credentials = []executorpool.Credential{}
	}
	jsonOK(w, d)
}

// handleExecutorPoolUpdate serves PUT /api/executor-pools/{id}.
func (s *Server) handleExecutorPoolUpdate(w http.ResponseWriter, r *http.Request) {
	store, p, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	var spec executorpool.Spec
	if !decodeJSON(w, r, &spec) {
		return
	}
	next, err := store.Update(p.ID, spec, s.auditActor(r))
	if err != nil {
		writePoolErr(w, err)
		return
	}
	s.broadcastAuditAppend("executor_pool.update")
	s.poolChanged(p.ID)
	jsonOK(w, map[string]any{"ok": true, "pool": s.newPoolView(store, next, false)})
}

// handleExecutorPoolRevoke serves POST /api/executor-pools/{id}/revoke.
func (s *Server) handleExecutorPoolRevoke(w http.ResponseWriter, r *http.Request) {
	store, p, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	actor := s.auditActor(r)
	rev, err := store.Revoke(p.ID, actor)
	if err != nil {
		writePoolErr(w, err)
		return
	}
	s.finishPoolRevocation(rev, actor)
	s.broadcastAuditAppend("executor_pool.revoke")
	runners := make([]string, 0, len(rev.Runners))
	for _, rr := range rev.Runners {
		runners = append(runners, rr.ExecutorID)
	}
	jsonOK(w, map[string]any{"ok": true, "pool_id": p.ID, "credentials": rev.Credentials, "tokens": len(rev.Tokens),
		"runners": runners, "cancelled_runs": len(rev.Cancelled)})
}

// handleExecutorPoolCredentialMint serves POST /api/executor-pools/{id}/credentials.
func (s *Server) handleExecutorPoolCredentialMint(w http.ResponseWriter, r *http.Request) {
	store, p, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	token, cred, err := store.MintCredential(p.ID, s.auditActor(r))
	if err != nil {
		writePoolErr(w, err)
		return
	}
	s.broadcastAuditAppend("executor_pool.credential_mint")
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"ok": true, "credential": cred, "token": token,
		"feed_url":    s.poolControllerURL(r, poolFeedPath),
		"runners_url": s.poolControllerURL(r, poolRunnersPath),
		"server":      s.agentConnectURL(r),
		"pin":         s.transportPin(),
		"notice": "This credential is shown once and cannot be recovered — only its hash is stored. It lets a " +
			"controller start this pool's runners until it or the pool is revoked; keep it in the controller's " +
			"secret store.",
	})
}

// handleExecutorPoolCredentialRevoke serves
// DELETE /api/executor-pools/{id}/credentials/{cid}.
func (s *Server) handleExecutorPoolCredentialRevoke(w http.ResponseWriter, r *http.Request) {
	store, p, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	cid := strings.TrimSpace(r.PathValue("cid"))
	rev, err := store.RevokeCredential(p.ID, cid, s.auditActor(r))
	if err != nil {
		writePoolErr(w, err)
		return
	}
	// What the credential minted goes with it: a leaked credential must not
	// leave behind the runners it started.
	s.takeBackRunners(p.ID, rev.Runners, "the controller credential that minted it was revoked")
	s.broadcastAuditAppend("executor_pool.credential_revoke")
	s.poolChanged(p.ID)
	runners := make([]string, 0, len(rev.Runners))
	for _, rr := range rev.Runners {
		runners = append(runners, rr.ExecutorID)
	}
	jsonOK(w, map[string]any{"ok": true, "pool_id": p.ID, "credential_id": cid, "tokens": len(rev.Tokens), "runners": runners})
}

// poolAudienceRequest names one principal.
type poolAudienceRequest struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// handleExecutorPoolAudience serves /api/executor-pools/{id}/audience.
func (s *Server) handleExecutorPoolAudience(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodDelete:
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	store, p, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		var req poolAudienceRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		var err error
		if r.Method == http.MethodPost {
			err = store.Admit(p.ID, req.Kind, req.Value, s.auditActor(r))
		} else {
			err = store.Withdraw(p.ID, req.Kind, req.Value, s.auditActor(r))
		}
		if err != nil {
			if strings.Contains(err.Error(), "principal kind") || strings.Contains(err.Error(), "needs a pool") {
				jsonErr(w, err.Error(), http.StatusBadRequest)
				return
			}
			writePoolErr(w, err)
			return
		}
		s.broadcastAuditAppend("executor_pool.audience")
		// A changed list takes the runs queued under the old one out of
		// the pool's sight (demand.go).
		s.poolChanged(p.ID)
	}
	entries, err := store.Audience(p.ID)
	if err != nil {
		writePoolErr(w, err)
		return
	}
	if entries == nil {
		entries = []statedb.ExecutorAudienceEntry{}
	}
	jsonOK(w, map[string]any{"pool_id": p.ID, "audience": entries, "restricted": len(entries) > 0})
}

// bindProjectToPool binds a project to an executor pool, for
// handleProjectExecutorBind.
func (s *Server) bindProjectToPool(w http.ResponseWriter, r *http.Request, db *statedb.DB, entry projectEntry, poolID string) {
	store, ok := s.poolStoreFor(w)
	if !ok {
		return
	}
	pool, err := store.Get(poolID)
	if err != nil {
		writePoolErr(w, err)
		return
	}
	if pool.Revoked() {
		jsonErr(w, fmt.Sprintf("executor pool %s was revoked", pool.Name), http.StatusConflict)
		return
	}
	// An owned pool's runners are its owner's machines: they run only what
	// the owner may read (demand.go).
	if pool.Owner != "" {
		if ok, err := s.identityMayReadProject(pool.Owner, entry.Path); err != nil || !ok {
			writeExecutorBlocked(w, "executor_pool_owner_denied",
				fmt.Sprintf("executor pool %s belongs to someone who may not read this project", pool.Name),
				"share the project with the pool's owner, or bind it to another pool")
			return
		}
	}
	// A pool whose runners could never run this project is refused now, not
	// at its first run.
	if req, err := poolRunRequirements(entry.Path); err == nil {
		if rej, rejected := pool.Admits(req); rejected {
			jsonWorkloadErr(w, &executor.PlacementError{Constraint: rej.Constraint,
				Rejections: []executor.Rejection{rej}, Considered: 1})
			return
		}
	}
	// The binder must be on the pool's access list, as for an executor's:
	// the refusal arrives when the choice is made. The run's own check, when
	// it is queued, is the load-bearing one.
	if entries, err := store.Audience(pool.ID); err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"error": "cannot determine who may use executor pool " + pool.Name, "code": "executor_pool_audience_unavailable"})
		return
	} else if members := audienceMembers(entries); len(members) > 0 && !authz.Admits(members, s.callerSubject(r)) {
		writeJSONStatus(w, http.StatusForbidden, map[string]any{
			"error": fmt.Sprintf("executor pool %s is restricted and your account is not on its access list", pool.Name),
			"code":  "executor_pool_audience_denied", "pool_id": pool.ID})
		return
	}

	if err := db.BindProjectPool(entry.Path, pool.ID, s.sessionIdentity(r).OwnerKey()); err != nil {
		writePoolErr(w, err)
		return
	}
	binding := pool.Binding()
	if err := executor.Bind(entry.Path, binding); err != nil {
		fmt.Fprintf(os.Stderr, "ui: in-memory bind of %s to %s: %v\n", entry.Path, binding, err)
	}
	s.publishBindingChange(entry.Path)
	statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
		Action:     "bind",
		ExecutorID: binding,
		Actor:      s.auditActor(r),
		Detail: map[string]any{
			"project": entry.Name, "project_path": entry.Path, "kind": "executor_pool", "pool": pool.Name,
		},
	})
	s.broadcastAuditAppend("bind")
	s.broadcastExecutorUpdate("bound", binding)
	jsonOK(w, map[string]any{"ok": true, "project": entry.Name, "executor_id": binding, "pool": pool.Name})
}
