package ui

// virtual_executors_api.go is the admin surface for virtual executors (Task
// 20345): sub-executors of an enrolled device, each with its own container
// engine and runtime, IP firewall (allowlist and denylist) and host devices.
//
//	GET  /api/executors/{id}/virtuals   a device's virtual executors, and what
//	                                    they can be built from: its USB
//	                                    inventory (?refresh=1 re-reads it from
//	                                    the device), engines, OCI runtimes and
//	                                    whether it can install a packet filter
//	POST /api/executors/{id}/virtuals   create one under that device
//	GET|PUT|DELETE /api/executors/{id}/virtual   one virtual executor
//
// Two paths rather than one because {id} names different things: the device a
// list belongs to, and the virtual executor an edit is about. The route gate
// authorizes each against the executor it names.
//
// All of it is execMgmt, reads included, for the reason the sandbox route
// gives: a device's hardware inventory and the precise reasons a firewall
// would not hold on it are reconnaissance, not status.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// virtualParentView is the GET …/virtuals response.
type virtualParentView struct {
	ExecutorID string `json:"executor_id"`
	Name       string `json:"name"`
	Connected  bool   `json:"connected"`
	// ProtocolVersion is the live session's, 0 when offline. Supported says
	// whether it can apply a firewall or devices at all.
	ProtocolVersion int  `json:"protocol_version,omitempty"`
	Supported       bool `json:"supported"`
	// Engines and OCIRuntimes are what the device reported; Networks the two
	// every engine has. Offered by the form, never enforced by it — the device
	// refuses what it cannot run, at dispatch.
	Engines     []string `json:"engines"`
	OCIRuntimes []string `json:"oci_runtimes"`
	Networks    []string `json:"networks"`
	// PacketFilter is whether the device can install a firewall, and
	// PacketFilterIssue why not.
	PacketFilter      bool   `json:"packet_filter"`
	PacketFilterIssue string `json:"packet_filter_issue,omitempty"`
	// USBDevices is the device's USB inventory. USBLive reports that it was
	// read from the device during this request; otherwise it is the snapshot
	// from its last connect, and USBError says why a requested refresh failed.
	USBDevices []executor.USBDevice `json:"usb_devices"`
	USBLive    bool                 `json:"usb_live"`
	USBError   string               `json:"usb_error,omitempty"`
	// VirtualExecutors are this device's sub-executors.
	VirtualExecutors []virtualExecutorView `json:"virtual_executors"`
}

// virtualExecutorView is one virtual executor in full.
type virtualExecutorView struct {
	ID        string               `json:"id"`
	ParentID  string               `json:"parent_id"`
	Name      string               `json:"name"`
	Spec      executor.VirtualSpec `json:"spec"`
	CreatedAt string               `json:"created_at,omitempty"`
	CreatedBy string               `json:"created_by,omitempty"`
	UpdatedAt string               `json:"updated_at,omitempty"`
	UpdatedBy string               `json:"updated_by,omitempty"`
	// Registered reports that the hub can dispatch to it; Issue why the
	// device cannot apply it, when it cannot.
	Registered bool     `json:"registered"`
	Issue      string   `json:"issue,omitempty"`
	Projects   []string `json:"projects,omitempty"`
}

// virtualExecutorRequest is the POST/PUT body.
type virtualExecutorRequest struct {
	Name string               `json:"name"`
	Spec executor.VirtualSpec `json:"spec"`
}

// handleVirtualExecutors serves GET and POST /api/executors/{id}/virtuals.
func (s *Server) handleVirtualExecutors(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	parentID := strings.TrimSpace(r.PathValue("id"))
	parent, ok := remoteParent(parentID)
	if !ok {
		jsonErr(w, fmt.Sprintf("%q is not an enrolled device; virtual executors are created under one", parentID),
			http.StatusNotFound)
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	switch r.Method {
	case http.MethodGet:
		jsonOK(w, s.virtualParent(r.Context(), db, parent, r.URL.Query().Get("refresh") == "1"))
	case http.MethodPost:
		s.createVirtualExecutor(w, r, db, parent)
	default:
		w.Header().Set("Allow", "GET, POST")
		jsonErr(w, "use GET to list a device's virtual executors or POST to create one", http.StatusMethodNotAllowed)
	}
}

// virtualParent assembles the GET …/virtuals view.
func (s *Server) virtualParent(ctx context.Context, db *statedb.DB, parent *remote.Executor, refresh bool) virtualParentView {
	view := virtualParentView{
		ExecutorID: parent.ID(),
		Name:       parent.Name(),
		Connected:  parent.Connected(),
		Networks:   executor.SandboxNetworks(),
	}
	if view.Name == "" {
		view.Name = parent.ID()
	}
	caps := parent.AgentCapabilities()
	if view.Connected {
		view.ProtocolVersion = parent.ProtocolVersion()
		view.Supported = remote.SupportsVirtualExecutor(view.ProtocolVersion)
		if refresh {
			fresh, err := parent.RefreshInventory(ctx)
			if err != nil {
				view.USBError = err.Error()
			} else {
				caps, view.USBLive = fresh, true
				persistInventory(db, parent, fresh)
			}
		}
	} else if row, err := db.GetExecutor(parent.ID()); err == nil && len(row.Capabilities) > 0 {
		// Offline: the last advertisement the device made, which is what the
		// panel can honestly show for a machine it cannot ask.
		var stored remote.AgentCapabilities
		if json.Unmarshal(row.Capabilities, &stored) == nil {
			caps = stored
			caps.USBDevices = remote.CleanUSBInventory(caps.USBDevices)
		}
		if refresh {
			view.USBError = "the device is offline; showing what it reported when it last connected"
		}
	}
	view.Engines = nonNil(caps.ContainerRuntimes)
	view.OCIRuntimes = nonNil(caps.OCIRuntimes)
	view.PacketFilter = caps.PacketFilter
	view.PacketFilterIssue = caps.PacketFilterIssue
	view.USBDevices = caps.USBDevices
	if view.USBDevices == nil {
		view.USBDevices = []executor.USBDevice{}
	}

	rows, _ := db.ListVirtualExecutors()
	bindings := projectsByExecutor(db)
	view.VirtualExecutors = []virtualExecutorView{}
	for _, v := range rows {
		if v.ParentID == parent.ID() {
			view.VirtualExecutors = append(view.VirtualExecutors, viewVirtualExecutor(v, bindings[v.ID]))
		}
	}
	return view
}

// viewVirtualExecutor renders one stored virtual executor.
func viewVirtualExecutor(v statedb.VirtualExecutor, projects []string) virtualExecutorView {
	out := virtualExecutorView{
		ID: v.ID, ParentID: v.ParentID, Name: v.Name, Spec: v.Spec,
		CreatedBy: v.CreatedBy, UpdatedBy: v.UpdatedBy, Projects: projects,
	}
	if !v.CreatedAt.IsZero() {
		out.CreatedAt = v.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !v.UpdatedAt.IsZero() {
		out.UpdatedAt = v.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if ex, err := executor.Get(v.ID); err == nil {
		if vx, ok := ex.(*remote.Virtual); ok {
			out.Registered = true
			if spec, err := v.Spec.Normalize(); err == nil {
				out.Issue = virtualIssue(vx, spec)
			} else {
				out.Issue = err.Error()
			}
		}
	}
	return out
}

// createVirtualExecutor serves POST …/virtuals.
func (s *Server) createVirtualExecutor(w http.ResponseWriter, r *http.Request, db *statedb.DB,
	parent *remote.Executor) {
	var req virtualExecutorRequest
	if !decodeExecutorBody(w, r, &req) {
		return
	}
	spec, err := req.Spec.Normalize()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := newVirtualExecutorID()
	if err != nil {
		jsonErr(w, "mint virtual executor id: "+err.Error(), http.StatusInternalServerError)
		return
	}
	row := statedb.VirtualExecutor{
		ID: id, ParentID: parent.ID(), Name: strings.TrimSpace(req.Name), Spec: spec, CreatedBy: s.auditActor(r),
	}
	if row.Name == "" {
		row.Name = id
	}
	if err := db.CreateVirtualExecutor(row); err != nil {
		writeVirtualExecutorErr(w, err)
		return
	}
	stored, _, err := db.VirtualExecutor(id)
	if err != nil {
		jsonErr(w, "read back virtual executor: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := registerVirtualExecutor(state.DBPath(s.WorkDir), stored); err != nil {
		// Stored but not dispatchable: say so rather than pretend. The row
		// stays, so the panel shows it and the next hub start retries.
		jsonErr(w, "the virtual executor was saved but could not be registered: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	s.auditExecutorAction(r, "virtual", id, map[string]any{
		"action":    "create",
		"parent_id": parent.ID(),
		"name":      stored.Name,
		"to":        stored.Spec.Describe(),
	})
	s.broadcastExecutorUpdate("virtual", id)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(viewVirtualExecutor(stored, nil))
}

// handleVirtualExecutor serves GET, PUT and DELETE /api/executors/{id}/virtual.
func (s *Server) handleVirtualExecutor(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	cur, ok, err := db.VirtualExecutor(id)
	if err != nil {
		jsonErr(w, "read virtual executor: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		jsonErr(w, fmt.Sprintf("%q is not a virtual executor", id), http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		jsonOK(w, viewVirtualExecutor(cur, projectsByExecutor(db)[id]))
	case http.MethodPut, http.MethodPost:
		var req virtualExecutorRequest
		if !decodeExecutorBody(w, r, &req) {
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = cur.Name
		}
		if err := db.UpdateVirtualExecutor(id, name, req.Spec, s.auditActor(r)); err != nil {
			writeVirtualExecutorErr(w, err)
			return
		}
		updated, _, err := db.VirtualExecutor(id)
		if err != nil {
			jsonErr(w, "read back virtual executor: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if updated.Name != cur.Name {
			if err := registerVirtualExecutor(state.DBPath(s.WorkDir), updated); err != nil {
				jsonErr(w, "saved, but re-registering under the new name failed: "+err.Error(),
					http.StatusInternalServerError)
				return
			}
		}
		s.auditExecutorAction(r, "virtual", id, map[string]any{
			"action":    "update",
			"parent_id": cur.ParentID,
			"from":      cur.Spec.Describe(),
			"to":        updated.Spec.Describe(),
		})
		s.broadcastExecutorUpdate("virtual", id)
		jsonOK(w, viewVirtualExecutor(updated, projectsByExecutor(db)[id]))
	case http.MethodDelete:
		// A running task keeps running: its handle belongs to the parent
		// device, which still addresses it. What stops is new dispatch.
		bound := projectsByExecutor(db)[id]
		if err := db.DeleteVirtualExecutor(id); err != nil {
			writeVirtualExecutorErr(w, err)
			return
		}
		if ex, err := executor.Get(id); err == nil && ex.Kind() == executor.KindVirtual {
			executor.DefaultRegistry.Unregister(id)
		}
		// The database bindings went with the row; these are their in-memory
		// mirrors, which would otherwise keep resolving to an executor that no
		// longer exists until the hub restarted.
		for _, p := range bound {
			executor.DefaultRegistry.Unbind(p)
		}
		s.auditExecutorAction(r, "virtual", id, map[string]any{
			"action":    "delete",
			"parent_id": cur.ParentID,
			"from":      cur.Spec.Describe(),
		})
		s.broadcastExecutorUpdate("virtual", id)
		jsonOK(w, map[string]any{"deleted": id})
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		jsonErr(w, "use GET, PUT or DELETE", http.StatusMethodNotAllowed)
	}
}

// writeVirtualExecutorErr maps storage errors onto status codes.
func writeVirtualExecutorErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, executor.ErrInvalidSpec):
		jsonErr(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, statedb.ErrVirtualExecutorNotFound), errors.Is(err, statedb.ErrExecutorNotFound):
		jsonErr(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, statedb.ErrVirtualExecutorExists):
		jsonErr(w, err.Error(), http.StatusConflict)
	case errors.Is(err, statedb.ErrDBLocked):
		jsonErr(w, "the control plane is busy; retry: "+err.Error(), http.StatusServiceUnavailable)
	case strings.HasPrefix(err.Error(), "statedb: virtual executor name"),
		strings.HasPrefix(err.Error(), "statedb: a virtual executor"):
		jsonErr(w, err.Error(), http.StatusBadRequest)
	default:
		jsonErr(w, err.Error(), http.StatusInternalServerError)
	}
}

// newVirtualExecutorID mints "vx-" and ten base32 characters: short enough to
// name a bridge (cloop-sbx-vx-…) inside the kernel's interface-name limits and
// an nftables table, random enough never to collide.
func newVirtualExecutorID() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return "vx-" + string(buf), nil
}

// persistInventory stores a freshly read inventory on the device's row, so the
// panel's offline view is as recent as the last refresh rather than the last
// connect.
func persistInventory(db *statedb.DB, parent *remote.Executor, caps remote.AgentCapabilities) {
	row, err := db.GetExecutor(parent.ID())
	if err != nil {
		return
	}
	if encoded, err := json.Marshal(caps); err == nil {
		row.Capabilities = encoded
	}
	row.Inventory = inventoryFromCaps(caps, parent.AgentVersion())
	_ = db.UpsertExecutor(row)
}

// projectsByExecutor maps executor IDs to the projects bound to them.
func projectsByExecutor(db *statedb.DB) map[string][]string {
	out := map[string][]string{}
	bindings, err := db.ListProjectExecutorBindings()
	if err != nil {
		return out
	}
	for _, b := range bindings {
		out[b.ExecutorID] = append(out[b.ExecutorID], b.ProjectPath)
	}
	for id := range out {
		sort.Strings(out[id])
	}
	return out
}

func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// deleteVirtualExecutorsOf removes every virtual executor of a device being
// revoked, each with its own audit row, and returns how many it removed.
//
// Deleted rather than left behind as orphans: a virtual executor dispatches
// through its parent's session and has no life of its own, and the dialog an
// admin manages them in is opened from the parent's card. An orphan would be a
// card that fails every dispatch and offers no way to remove it.
func (s *Server) deleteVirtualExecutorsOf(r *http.Request, db *statedb.DB, parentID string) int {
	rows, err := db.ListVirtualExecutors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: list virtual executors of revoked device %s: %v\n", parentID, err)
		return 0
	}
	bindings := projectsByExecutor(db)
	removed := 0
	for _, v := range rows {
		if v.ParentID != parentID {
			continue
		}
		if err := db.DeleteVirtualExecutor(v.ID); err != nil {
			fmt.Fprintf(os.Stderr, "ui: delete virtual executor %s of revoked device %s: %v\n", v.ID, parentID, err)
			continue
		}
		if ex, err := executor.Get(v.ID); err == nil && ex.Kind() == executor.KindVirtual {
			executor.DefaultRegistry.Unregister(v.ID)
		}
		for _, p := range bindings[v.ID] {
			executor.DefaultRegistry.Unbind(p)
		}
		s.auditExecutorAction(r, "virtual", v.ID, map[string]any{
			"action":    "delete",
			"parent_id": parentID,
			"name":      v.Name,
			"from":      v.Spec.Describe(),
			"reason":    "its device was revoked",
		})
		s.broadcastExecutorUpdate("virtual", v.ID)
		removed++
	}
	return removed
}
