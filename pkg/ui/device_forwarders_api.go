// Device forwarder REST API (Task 20429): list the forwarders this hub knows,
// mint enrollment tokens, revoke, and expose a connected forwarder's device
// for consumption. RBAC-gated exactly like the executor fleet routes —
// executor.read to look, executor.manage to change — because a forwarder is
// part of the same fleet-administration surface even though it is not an
// executor.

package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
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
		{Pattern: "POST /api/forwarders/enroll", Handler: s.handleForwarderEnroll, Perm: authz.PermExecutorManage, Scope: scopeGlobal},
		{Pattern: "DELETE /api/forwarders/{id}", Handler: s.handleForwarderDelete, Perm: authz.PermExecutorManage, Scope: scopeGlobal},
		{Pattern: "POST /api/forwarders/{id}/expose", Handler: s.handleForwarderExpose, Perm: authz.PermExecutorManage, Scope: scopeGlobal},
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
	LastSeen  string                        `json:"last_seen,omitempty"`
	Revoked   bool                          `json:"revoked"`
	Available bool                          `json:"available"`
	Detail    string                        `json:"detail,omitempty"`
	Resolved  *executor.USBDevice           `json:"resolved,omitempty"`
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
	hub, err := s.forwarderHub()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	closeForwarderExposure(id)
	if err := hub.Revoke(id); err != nil {
		jsonErr(w, err.Error(), http.StatusNotFound)
		return
	}
	s.auditForwarderAction(r, auditaction.ActionForwarderRevoke, id, map[string]any{"kind": "forwarder"})
	writeJSONStatus(w, http.StatusOK, map[string]any{"revoked": id})
}

// handleForwarderExpose opens a loopback consumption endpoint for a connected
// forwarder's device, so an operator — or an executor host — can attach it.
func (s *Server) handleForwarderExpose(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "forwarder id is required", http.StatusBadRequest)
		return
	}
	hub, err := s.forwarderHub()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
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

	switch dev.Kind {
	case deviceforward.KindUSB:
		ep, err := exposeForwarderUSB(hub, id)
		if err != nil {
			jsonErr(w, exposeErrorMessage(err), http.StatusConflict)
			return
		}
		busid := "<busid>"
		if hp := hub.Resolved(id); hp != nil && hp.Resolved != nil {
			busid = hp.Resolved.Port
		}
		s.auditForwarderAction(r, auditaction.ActionForwarderExpose, id, map[string]any{
			"device": dev.Describe(), "port": ep.Port(),
		})
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"kind":    "usb",
			"port":    ep.Port(),
			"busid":   busid,
			"command": fmt.Sprintf("usbip --tcp-port %d attach -r 127.0.0.1 -b %s", ep.Port(), busid),
			"note":    "Run the command on the host that should import the device; it binds loopback only.",
		})
	case deviceforward.KindL2:
		// A layer-2 forward is consumed as a TAP, which needs the host's
		// CAP_NET_ADMIN; opening one from the dashboard process is only
		// possible where the hub runs privileged. Report how it is consumed
		// rather than attempting it unconditionally.
		s.auditForwarderAction(r, auditaction.ActionForwarderExpose, id, map[string]any{"device": dev.Describe()})
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"kind": "l2",
			"note": "This interface is consumed as a TAP on the executor host; bind the project to that executor and grant the interface. A TAP cannot be opened from the dashboard process.",
		})
	default:
		jsonErr(w, "unknown device kind", http.StatusBadRequest)
	}
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

// --- exposure lifecycle ---------------------------------------------------

// forwarderExposures tracks the loopback import endpoints opened for connected
// USB forwarders, so a second expose reuses the first and a disconnect closes
// it. Package-level because the forwarder hub is a process-wide singleton.
var (
	forwarderExposuresMu sync.Mutex
	forwarderExposures   = map[string]*deviceforward.ImportEndpoint{}
)

func exposeForwarderUSB(hub *deviceforward.Hub, id string) (*deviceforward.ImportEndpoint, error) {
	forwarderExposuresMu.Lock()
	defer forwarderExposuresMu.Unlock()
	if ep, ok := forwarderExposures[id]; ok {
		return ep, nil
	}
	ep, err := hub.ListenUSB(id)
	if err != nil {
		return nil, err
	}
	forwarderExposures[id] = ep
	return ep, nil
}

func closeForwarderExposure(id string) {
	forwarderExposuresMu.Lock()
	ep := forwarderExposures[id]
	delete(forwarderExposures, id)
	forwarderExposuresMu.Unlock()
	if ep != nil {
		_ = ep.Close()
	}
}

func exposeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	if err == deviceforward.ErrForwarderOffline {
		return "the forwarder is offline; it must be connected before its device can be exposed"
	}
	return err.Error()
}
