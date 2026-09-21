package ui

// REST surface for rolling executors forward (Task 20331).
//
// Until now the Executors panel could *see* that a device was behind the
// control plane — annotateInventory has computed a version skew since the fleet
// inventory landed — and the only thing it could do about it was print a
// sentence telling the operator to go and SSH into the machine. On a fleet of
// edge devices sitting behind NAT in other people's buildings, that sentence is
// not a remedy.
//
// Two routes close that loop. One asks a single device to upgrade now; the
// other holds the standing policy that does it without being asked. They are
// separated because they answer to different people: the button is an
// operator's decision about one machine, and the policy is an administrator's
// decision about the fleet.
//
// The audit trail matters more here than on the panel's other actions. Cordon
// takes a device out of service; this one tells it to download and execute a
// new binary as root. That is the most consequential thing the hub can ask a
// device to do, so every request is recorded with who asked, which device, and
// which version — and the deny-by-default RBAC gate in front of it is the same
// PermExecutorManage that guards enrolment and revocation.

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/autoupdate"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// upgradeRequestTimeout bounds the wait for a device to answer that it has
// accepted. It is short on purpose: the reply is sent before the download
// starts (see pkg/executor/agent/upgrade.go), so a device that has not answered
// within this window is not busy working, it is unreachable.
const upgradeRequestTimeout = 30 * time.Second

// executorUpgradeRoutes returns this feature's routes, for splicing into the
// table. Kept here rather than written into routeTable() so the whole surface —
// routes, handlers and their permissions — is readable in one file, the way
// iconRoutes does it.
func (s *Server) executorUpgradeRoutes() []routeSpec {
	return []routeSpec{
		{
			Pattern: "POST /api/executors/{id}/upgrade",
			Handler: s.handleExecutorUpgrade,
			Perm:    authz.PermExecutorManage,
			Scope:   scopeExecutor,
		},
		// Deliberately not under /api/executors/. A fleet-wide policy is not an
		// executor, and parking it at /api/executors/autoupdate would put a
		// literal segment in permanent competition with the {id} wildcard next
		// to it — a collision http.ServeMux resolves correctly today and that
		// no reader should have to know the precedence rules to be sure of.
		{
			Pattern: "GET /api/fleet/autoupdate",
			Handler: s.handleFleetAutoUpdateGet,
			Perm:    authz.PermExecutorRead,
			Scope:   scopeGlobal,
		},
		{
			Pattern: "PUT /api/fleet/autoupdate",
			Handler: s.handleFleetAutoUpdateSave,
			Perm:    authz.PermExecutorManage,
			Scope:   scopeGlobal,
		},
	}
}

type executorUpgradeRequest struct {
	// TargetVersion is a release tag, or "latest"/"" for the newest.
	TargetVersion string `json:"target_version"`
	// Force reinstalls an identical build and permits a downgrade.
	Force bool `json:"force"`
}

type executorUpgradeResponse struct {
	Accepted       bool   `json:"accepted"`
	AlreadyCurrent bool   `json:"already_current,omitempty"`
	Reason         string `json:"reason,omitempty"`
	FromVersion    string `json:"from_version,omitempty"`
	TargetVersion  string `json:"target_version,omitempty"`
	// Message is the sentence the panel shows. Rendered server-side so the
	// CLI and the dashboard cannot describe the same outcome differently —
	// in particular the distinction between "accepted" and "upgraded", which
	// is the one thing about this feature that is easy to report wrongly.
	Message string `json:"message"`
}

// handleExecutorUpgrade serves POST /api/executors/{id}/upgrade.
func (s *Server) handleExecutorUpgrade(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "executor id is required", http.StatusBadRequest)
		return
	}
	var req executorUpgradeRequest
	if !decodeExecutorBody(w, r, &req) {
		return
	}

	ex, err := executor.DefaultRegistry.Get(id)
	if err != nil {
		jsonErr(w, "no executor with id "+id+" is registered", http.StatusNotFound)
		return
	}
	remoteEx, ok := ex.(*remote.Executor)
	if !ok {
		// Container and Kubernetes executors run the control plane's own
		// binary, so "upgrade the executor" is not a thing that can be asked of
		// them separately — upgrading the hub is what moves them. Saying which
		// executors this does apply to is what stops the message reading like a
		// defect.
		jsonErr(w, "the "+string(ex.Kind())+" executor runs this control plane's own binary, so "+
			"it moves forward when the hub does. Only enrolled remote devices are upgraded "+
			"individually.", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), upgradeRequestTimeout)
	defer cancel()

	outcome, err := remoteEx.RequestUpgrade(ctx, remote.UpgradeRequest{
		TargetVersion: req.TargetVersion,
		Force:         req.Force,
		Reason:        "requested from the dashboard by " + s.auditActor(r),
	})
	if err != nil {
		// Recorded even though nothing happened on the device. An upgrade that
		// was asked for and refused is exactly as interesting to an auditor as
		// one that succeeded — more so, if somebody is probing what they can
		// reach.
		s.auditExecutorUpgrade(r, id, req, executorUpgradeResponse{Reason: err.Error()})
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	name := remoteEx.Name()
	if strings.TrimSpace(name) == "" {
		name = id
	}
	resp := executorUpgradeResponse{
		Accepted:       outcome.Accepted,
		AlreadyCurrent: outcome.AlreadyCurrent,
		Reason:         outcome.Reason,
		FromVersion:    outcome.FromVersion,
		TargetVersion:  outcome.TargetVersion,
		Message:        outcome.Summary(name),
	}
	s.auditExecutorUpgrade(r, id, req, resp)
	if resp.Accepted {
		s.broadcastExecutorUpdate("upgrading", id)
	}
	jsonOK(w, resp)
}

// auditExecutorUpgrade records an upgrade request and what came of it.
func (s *Server) auditExecutorUpgrade(
	r *http.Request, id string, req executorUpgradeRequest, resp executorUpgradeResponse,
) {
	detail := map[string]any{
		"requested_version": strings.TrimSpace(req.TargetVersion),
		"force":             req.Force,
		"accepted":          resp.Accepted,
	}
	if resp.FromVersion != "" {
		detail["from_version"] = resp.FromVersion
	}
	if resp.TargetVersion != "" {
		detail["target_version"] = resp.TargetVersion
	}
	if resp.Reason != "" {
		detail["reason"] = resp.Reason
	}
	s.auditExecutorAction(r, "upgrade", id, detail)
}

// fleetAutoUpdateView is the policy as the dashboard sees it.
type fleetAutoUpdateView struct {
	Enabled bool `json:"enabled"`
	// TargetVersion is the stored value, which may be empty.
	TargetVersion string `json:"target_version"`
	MaxInFlight   int    `json:"max_in_flight"`
	// Effective is the policy after defaults are filled in. Sent alongside the
	// raw value so the panel can show what an empty target actually means
	// without duplicating Resolve's rules in JavaScript.
	Effective  autoupdate.Policy `json:"effective"`
	HubVersion string            `json:"hub_version,omitempty"`
	SetBy      string            `json:"set_by,omitempty"`
	SetAt      string            `json:"set_at,omitempty"`
}

func (s *Server) fleetAutoUpdateView() (fleetAutoUpdateView, error) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return fleetAutoUpdateView{}, err
	}
	defer db.Close()

	stored, err := statedb.AutoUpdatePolicyFor(db)
	if err != nil {
		return fleetAutoUpdateView{}, err
	}
	hub := hubVersion()
	view := fleetAutoUpdateView{
		Enabled:       stored.Policy.Enabled,
		TargetVersion: stored.Policy.TargetVersion,
		MaxInFlight:   stored.Policy.MaxInFlight,
		Effective:     stored.Policy.Resolve(hub),
		HubVersion:    hub,
		SetBy:         stored.SetBy,
	}
	if !stored.SetAt.IsZero() {
		view.SetAt = stored.SetAt.UTC().Format(time.RFC3339)
	}
	return view, nil
}

// handleFleetAutoUpdateGet serves GET /api/fleet/autoupdate.
func (s *Server) handleFleetAutoUpdateGet(w http.ResponseWriter, r *http.Request) {
	view, err := s.fleetAutoUpdateView()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	jsonOK(w, view)
}

// handleFleetAutoUpdateSave serves PUT /api/fleet/autoupdate.
func (s *Server) handleFleetAutoUpdateSave(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	var req autoupdate.Policy
	if !decodeExecutorBody(w, r, &req) {
		return
	}
	req.TargetVersion = strings.TrimSpace(req.TargetVersion)
	if req.MaxInFlight < 0 {
		jsonErr(w, "max_in_flight cannot be negative", http.StatusBadRequest)
		return
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	if err := statedb.SetAutoUpdatePolicy(db, req, s.auditActor(r)); err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditExecutorAction(r, "autoupdate", "", map[string]any{
		"enabled":        req.Enabled,
		"target_version": req.TargetVersion,
		"max_in_flight":  req.MaxInFlight,
	})

	view, err := s.fleetAutoUpdateView()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	jsonOK(w, view)
}
