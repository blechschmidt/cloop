// Device forwarder REST API (Task 20429): list the forwarders this hub knows,
// mint enrollment tokens, revoke, and probe a connected forwarder's device —
// and, since Task 20430, bind a forwarder to a project and list and decide its
// binding requests (forwarder_bindings.go). RBAC-gated exactly like the
// executor fleet routes — executor.read to look, executor.manage to change —
// because a forwarder is part of the same fleet-administration surface even
// though it is not an executor.

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/forwarderstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// forwarderRoutes returns this feature's routes, spliced into the table like
// executorUpgradeRoutes, so the whole surface is readable in one file.
func (s *Server) forwarderRoutes() []routeSpec {
	return []routeSpec{
		{Pattern: "GET /api/forwarders", Handler: s.handleForwardersList, Perm: authz.PermExecutorRead, Scope: scopeGlobal},
		{Pattern: "POST /api/forwarders/enroll", Handler: s.handleForwarderEnroll, Perm: authz.PermExecutorManage, Scope: scopeGlobal, Sudo: sudoWrites},
		{Pattern: "DELETE /api/forwarders/{id}", Handler: s.handleForwarderDelete, Perm: authz.PermExecutorManage, Scope: scopeGlobal, Sudo: sudoWrites},
		{Pattern: "POST /api/forwarders/{id}/expose", Handler: s.handleForwarderExpose, Perm: authz.PermExecutorManage, Scope: scopeGlobal, Sudo: sudoWrites},
		// Bindings (Task 20430): which projects' runs get a forwarder's device.
		{Pattern: "GET /api/forwarders/bindings", Handler: s.handleForwarderBindingsList, Perm: authz.PermExecutorRead, Scope: scopeGlobal},
		{Pattern: "POST /api/forwarders/{id}/bindings", Handler: s.handleForwarderBind, Perm: authz.PermExecutorManage, Scope: scopeGlobal, Sudo: sudoWrites},
		{Pattern: "DELETE /api/forwarders/bindings/{bid}", Handler: s.handleForwarderUnbind, Perm: authz.PermExecutorManage, Scope: scopeGlobal},
		{Pattern: "GET /api/forwarders/requests", Handler: s.handleForwarderRequestsList, Perm: authz.PermSecretRequest, Scope: scopeGlobal},
		{Pattern: "GET /api/projects/{idx}/forwarders", Handler: s.handleProjectForwarders, Perm: authz.PermExecutorRead, Scope: scopeProjectIdx},
	}
}

// forwarderView is one forwarder as the panel renders it.
type forwarderView struct {
	ID        string                        `json:"id"`
	Name      string                        `json:"name"`
	Kind      string                        `json:"kind"`
	Device    deviceforward.ForwardedDevice `json:"device"`
	DeviceStr string                        `json:"device_str"`
	Owner     string                        `json:"owner,omitempty"`
	Status    string                        `json:"status"`
	Connected bool                          `json:"connected"`
	// ConnectedVia names the hub member holding the forwarder's tunnel when
	// that is another member (Task 20430): connectivity is read from the
	// cluster's shared owner rows, not from this member's own sessions.
	ConnectedVia string `json:"connected_via,omitempty"`
	// Bindings counts the bindings in force.
	Bindings  int                 `json:"bindings"`
	LastSeen  string              `json:"last_seen,omitempty"`
	Revoked   bool                `json:"revoked"`
	Available bool                `json:"available"`
	Detail    string              `json:"detail,omitempty"`
	Resolved  *executor.USBDevice `json:"resolved,omitempty"`
}

func (s *Server) handleForwardersList(w http.ResponseWriter, r *http.Request) {
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	rows, err := db.ListForwarders()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hub, _ := s.forwarderHub()
	connected := map[string]bool{}
	if hub != nil {
		for _, id := range hub.Connected() {
			connected[id] = true
		}
	}
	out := make([]forwarderView, 0, len(rows))
	for _, row := range rows {
		dev := unmarshalForwarderDevice(row.DeviceJSON)
		v := forwarderView{
			ID:        row.ForwarderID,
			Name:      row.Name,
			Kind:      string(dev.Kind),
			Device:    dev,
			DeviceStr: dev.Describe(),
			Owner:     row.Owner,
			Status:    row.Status,
			Connected: connected[row.ForwarderID],
			Revoked:   !row.RevokedAt.IsZero(),
		}
		if !row.LastSeen.IsZero() {
			v.LastSeen = row.LastSeen.UTC().Format(time.RFC3339)
		}
		if v.Connected && hub != nil {
			if hp := hub.Resolved(row.ForwarderID); hp != nil {
				v.Available = hp.Available
				v.Detail = hp.Detail
				v.Resolved = hp.Resolved
			}
		} else if member, meta, held := s.forwarderPeerView(row.ForwarderID); held {
			v.Connected, v.ConnectedVia = true, member
			v.Status = "online"
			v.Available, v.Detail, v.Resolved = meta.Available, meta.Detail, meta.Resolved
		} else if !v.Connected && v.Status == "online" {
			// The row says online but no live member holds the tunnel: the
			// member that held it died without saying so.
			v.Status = "offline"
		}
		if bs, err := db.ListForwarderBindings(statedb.ForwarderBindingFilter{ForwarderID: row.ForwarderID, ActiveAt: time.Now()}); err == nil {
			v.Bindings = len(bs)
		}
		out = append(out, v)
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"forwarders": out})
}

type forwarderEnrollRequest struct {
	Name       string             `json:"name"`
	Kind       string             `json:"kind"`
	USB        *executor.USBMatch `json:"usb,omitempty"`
	Interface  string             `json:"interface,omitempty"`
	Label      string             `json:"label,omitempty"`
	TTLMinutes int                `json:"ttl_minutes,omitempty"`
}

func (s *Server) handleForwarderEnroll(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req forwarderEnrollRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		jsonErr(w, "name is required", http.StatusBadRequest)
		return
	}
	dev := deviceforward.ForwardedDevice{
		Kind:      deviceforward.DeviceKind(strings.ToLower(strings.TrimSpace(req.Kind))),
		USB:       req.USB,
		Interface: req.Interface,
		Label:     req.Label,
	}
	if _, err := dev.Normalize(); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	ttl := deviceforward.DefaultEnrollTTL
	if req.TTLMinutes != 0 {
		if req.TTLMinutes < 1 || req.TTLMinutes > 1440 {
			jsonErr(w, "ttl_minutes must be between 1 and 1440", http.StatusBadRequest)
			return
		}
		ttl = time.Duration(req.TTLMinutes) * time.Minute
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	store, err := forwarderstore.New(db)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	bundle, rec, err := deviceforward.MintBundle(store, deviceforward.MintOptions{
		Name:      strings.TrimSpace(req.Name),
		Device:    dev,
		TTL:       ttl,
		Server:    s.forwarderConnectURL(r),
		Pin:       s.transportPin(),
		Owner:     s.quotaIdentity(r),
		CreatedBy: s.auditActor(r),
	})
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.auditForwarderAction(r, auditaction.ActionForwarderEnroll, rec.ID, map[string]any{
		"name": rec.Name, "device": dev.Describe(), "expires_at": rec.ExpiresAt.UTC().Format(time.RFC3339),
	})
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"id":      rec.ID,
		"name":    rec.Name,
		"device":  dev.Describe(),
		"bundle":  bundle,
		"command": "cloop forward --bundle " + bundle,
		"expires": rec.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleForwarderDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "forwarder id is required", http.StatusBadRequest)
		return
	}
	// Persist the revocation against this request's control-plane database —
	// the source of truth — rather than through the process-wide hub's own
	// store, then cut any live session this member holds. In a single hub the
	// two databases are one; keeping the write here is what makes the handler
	// correct on a member that is not the one the forwarder dialled.
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	store, err := forwarderstore.New(db)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	now := time.Now()
	kind, err := deviceforward.Revoke(store, id, now)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusNotFound)
		return
	}
	actor := s.auditActor(r)
	s.auditForwarderAction(r, auditaction.ActionForwarderRevoke, id, map[string]any{"kind": kind})
	// A revoked forwarder's bindings go with it (Task 20430), each audited, and
	// its live session and every run's device are cut on every member at once
	// — not only on this one, which may not hold the tunnel.
	fwdID := id
	if kind == "enrollment+forwarder" || kind == "enrollment" {
		if rec, gerr := store.GetEnrollment(id); gerr == nil && rec.RedeemedAgentID != "" {
			fwdID = rec.RedeemedAgentID
		}
	}
	if bids, berr := db.RevokeForwarderBindingsOf(fwdID, actor, "the forwarder was revoked", now); berr == nil {
		for _, bid := range bids {
			statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
				Action: auditaction.ActionForwarderUnbind, ForwarderID: fwdID, Actor: actor,
				Detail: map[string]any{"binding_id": bid, "reason": "the forwarder was revoked"},
			})
		}
	}
	s.announceForwarderRevocation(forwarderInvalidation{ForwarderID: fwdID, Reason: "the forwarder was revoked"})
	s.broadcastForwarderBindings(fwdID)
	writeJSONStatus(w, http.StatusOK, map[string]any{"revoked": id})
}

// handleForwarderExpose probes a forwarder's device through the hub (Task
// 20430). It opens a stream to the device — on the hub member holding the
// forwarder's tunnel, which a request reaching any other member is forwarded
// to — and, for USB, reads the device list the forwarder exports through it.
// The device is handed to nothing: an import happens only for a run whose
// project holds a binding, on the executor that runs its sandbox. (Until Task
// 20430 this opened a loopback import endpoint on the hub, which any process
// on the hub host could connect to; that endpoint is gone.)
func (s *Server) handleForwarderExpose(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "forwarder id is required", http.StatusBadRequest)
		return
	}
	if s.routeToOwner(w, r, ownerForwarder, id) {
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	row, err := db.GetForwarder(id)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusNotFound)
		return
	}
	dev := unmarshalForwarderDevice(row.DeviceJSON)
	hub, err := s.forwarderHub()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result := map[string]any{"kind": string(dev.Kind), "device": dev.Describe(), "member": s.hubInstanceID()}
	ds, err := hub.OpenDevice(ctx, id, "probe")
	if err != nil {
		result["reachable"] = false
		result["error"] = exposeErrorMessage(err)
		s.auditForwarderAction(r, auditaction.ActionForwarderExpose, id, map[string]any{
			"device": dev.Describe(), "reachable": false, "member": s.hubInstanceID(),
		})
		writeJSONStatus(w, http.StatusConflict, result)
		return
	}
	if dev.Kind == deviceforward.KindUSB {
		probe, perr := deviceforward.ProbeUSB(ctx, ds)
		if perr != nil {
			result["reachable"] = false
			result["error"] = perr.Error()
			writeJSONStatus(w, http.StatusConflict, result)
			return
		}
		result["exported"] = probe
	} else {
		_ = ds.Close()
		result["exported"] = map[string]any{"interface": ds.Exported.Interface}
	}
	result["reachable"] = true
	s.auditForwarderAction(r, auditaction.ActionForwarderExpose, id, map[string]any{
		"device": dev.Describe(), "reachable": true, "member": s.hubInstanceID(),
	})
	writeJSONStatus(w, http.StatusOK, result)
}

// forwarderConnectURL is the forwarder dial URL for this request's host.
func (s *Server) forwarderConnectURL(r *http.Request) string {
	return strings.Replace(s.agentConnectURL(r), executorConnectPath, forwarderConnectPath, 1)
}

// auditForwarderAction records a forwarder decision, best-effort.
func (s *Server) auditForwarderAction(r *http.Request, action auditaction.Action, forwarderID string, detail map[string]any) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return
	}
	defer db.Close()
	statedb.AuditForwarderLifecycle(db, statedb.ForwarderAuditInput{
		Action:      action,
		ForwarderID: forwarderID,
		Actor:       s.auditActor(r),
		Detail:      detail,
	})
	s.broadcastAuditAppend(string(action))
}

func unmarshalForwarderDevice(s string) deviceforward.ForwardedDevice {
	var d deviceforward.ForwardedDevice
	_ = json.Unmarshal([]byte(s), &d)
	return d
}

func exposeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, deviceforward.ErrForwarderOffline) {
		return "the forwarder is offline; it must be connected before its device can be reached"
	}
	return err.Error()
}
