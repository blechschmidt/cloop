package ui

// executor_sandbox_api.go is the admin's surface for one question per executor:
// do payloads run on that machine's host, or in a container on it, and under
// which engine, runtime, image and network (Task 20307, Task 20315)?
//
// # Why this could not be done through /api/config/set
//
// The Settings tab already writes configuration, and the obvious move was to add
// keys there. Two things rule it out.
//
// The first is scope. `executors.container.*` in config.yaml configures the
// *hub's own* container driver — one executor, the one running in this process.
// The setting this file exposes is per executor and there may be fifty of them,
// most on machines the hub has never had filesystem access to. There is no key
// in a single YAML file that means "edge-7 specifically".
//
// The second is that config.yaml is not where the answer can live even for one
// device. An executor's containment must be readable at dispatch, from the
// control-plane database, keyed by executor ID — see
// statedb/migrations/0044_executor_sandbox.sql for why it belongs to the hub
// rather than to the device that obeys it.
//
// # The shape of the read
//
// GET returns the configuration *and* what the device says it can support: the
// container engines it found on PATH, from the inventory it reports on every
// connect. Both, because an admin choosing "container" needs to know whether
// this device has an engine at all, and the alternative to telling them here is
// letting them save a setting whose first effect is a failed task. The panel can
// warn at the moment of the choice instead.
//
// That is advice, not enforcement. The form does not refuse an engine the device
// has not advertised, because the inventory is a snapshot from the last connect
// and an admin may legitimately be configuring a device they are about to
// install podman on. Enforcement is where it has to be — on the device, at
// dispatch, where the answer is current; see pkg/executor/agent/driver.go.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// executorSandboxView is the GET response.
type executorSandboxView struct {
	ExecutorID string                   `json:"executor_id"`
	Settings   executor.SandboxSettings `json:"settings"`
	// Configured distinguishes "an admin chose the default" from "nobody has
	// looked at this executor". The panel renders them differently, and the
	// difference is real: only one of them is a decision.
	Configured bool   `json:"configured"`
	SetAt      string `json:"set_at,omitempty"`
	SetBy      string `json:"set_by,omitempty"`

	// Modes, Engines and Networks are the selectable values, served rather than
	// hardcoded in the frontend so that the allowlist the backend enforces is
	// the same list the form offers. A frontend with its own copy would
	// eventually offer a value the API rejects, and the admin would read that
	// as a bug.
	//
	// Networks is the shortest of the three and the only one that is not an
	// allowlist: a named network an operator created on the device is accepted
	// too, because the hub cannot enumerate what exists over there. What it
	// serves is the two every engine has.
	Modes    []string `json:"modes"`
	Engines  []string `json:"engines"`
	Networks []string `json:"networks"`

	// DeviceEngines is what this device reported finding on PATH at its last
	// connect. Empty for a driver the hub runs itself — those are configured in
	// config.yaml and are not remote devices — and empty for a device that has
	// never connected.
	DeviceEngines []string `json:"device_engines,omitempty"`
	// Remote reports whether this executor is an enrolled device. The setting
	// only governs those: for a container or Kubernetes executor the hub builds
	// itself, the mode is implied by the driver and is config.yaml's business.
	Remote bool `json:"remote"`
	// AgentSupported reports whether the connected agent's protocol version can
	// honour a container mode. False strands the choice, so the panel says so
	// before the admin makes it rather than after a task fails.
	AgentSupported bool `json:"agent_supported"`
	// Warning is a human-readable caveat about this particular executor, or
	// empty. It exists so the one non-obvious failure — configuring container
	// mode on a device whose agent is too old — is stated in the panel.
	Warning string `json:"warning,omitempty"`
}

// executorSandboxRequest is the PUT body. Every field is optional; an omitted
// one is read as empty, which means "unset".
//
// Deliberately not a patch. The whole record is replaced on every write,
// because the fields interact — an engine is meaningless without container
// mode — and a partial update would let a form that has been switched to host
// mode leave a stale runtime behind in the row. Sending the whole thing makes
// the saved state exactly what the admin was looking at.
type executorSandboxRequest struct {
	Mode    string `json:"mode"`
	Engine  string `json:"engine"`
	Runtime string `json:"runtime"`
	Image   string `json:"image"`
	Network string `json:"network"`
	// Clear removes the configuration entirely, returning the executor to its
	// own default. Distinct from saving an all-empty record: that is an admin
	// asserting the default, which the panel shows as configured.
	Clear bool `json:"clear"`
}

// handleExecutorSandbox serves GET and PUT /api/executors/{id}/sandbox.
//
// One handler for both verbs rather than two routes, because the read and the
// write share the target resolution and the not-found answer, and splitting them
// would duplicate the part most worth getting right.
func (s *Server) handleExecutorSandbox(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "executor id is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.serveExecutorSandboxGet(w, id)
	case http.MethodPut, http.MethodPost:
		s.serveExecutorSandboxPut(w, r, id)
	default:
		// Named explicitly rather than left to a generic 405, because this
		// route accepts an unusual pair and an operator scripting it should be
		// told which.
		w.Header().Set("Allow", "GET, PUT")
		jsonErr(w, "method not allowed: use GET to read or PUT to set an executor's sandbox configuration",
			http.StatusMethodNotAllowed)
	}
}

// serveExecutorSandboxGet renders one executor's configuration and options.
func (s *Server) serveExecutorSandboxGet(w http.ResponseWriter, id string) {
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	s.renderExecutorSandbox(w, db, id)
}

// renderExecutorSandbox writes the view over an already-open database.
//
// Split out so the write path can answer with the stored state through the
// handle it already holds. The alternative — calling serveExecutorSandboxGet
// after a save — opens a second connection to the same file while the first is
// still in scope, and statedb.Open is not a cheap accessor: it creates and
// migrates. Two of those per write is a needless pair of WAL readers on the
// hottest file the hub has.
func (s *Server) renderExecutorSandbox(w http.ResponseWriter, db *statedb.DB, id string) {
	rec, configured, err := db.ExecutorSandboxRecord(id)
	if err != nil {
		jsonErr(w, "read sandbox configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	view := executorSandboxView{
		ExecutorID: id,
		Settings:   rec.Settings,
		Configured: configured,
		SetBy:      rec.SetBy,
		Modes:      sandboxModeNames(),
		Engines:    executor.ContainerEngines(),
		Networks:   executor.SandboxNetworks(),
	}
	if !rec.SetAt.IsZero() {
		view.SetAt = rec.SetAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	s.describeSandboxTarget(&view, id)
	jsonOK(w, view)
}

// serveExecutorSandboxPut records a configuration.
func (s *Server) serveExecutorSandboxPut(w http.ResponseWriter, r *http.Request, id string) {
	var req executorSandboxRequest
	if !decodeExecutorBody(w, r, &req) {
		return
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	// Read the outgoing value before overwriting it. A containment change is
	// only reviewable if the trail says what it changed *from*, and after the
	// write nothing knows.
	before, _, err := db.ExecutorSandboxSettings(id)
	if err != nil {
		jsonErr(w, "read current sandbox configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if req.Clear {
		if err := db.ClearExecutorSandbox(id); err != nil {
			jsonErr(w, "clear sandbox configuration: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditExecutorAction(r, "sandbox", id, map[string]any{
			"cleared": true,
			"from":    before.Describe(),
		})
		s.broadcastExecutorUpdate("sandbox", id)
		s.renderExecutorSandbox(w, db, id)
		return
	}

	want := executor.SandboxSettings{
		Mode:    executor.SandboxMode(req.Mode),
		Engine:  req.Engine,
		Runtime: req.Runtime,
		Image:   req.Image,
		Network: req.Network,
	}
	// Validated before normalizing, so an admin who typed a bad runtime and then
	// switched the mode to host is told about the runtime rather than having it
	// silently dropped. Normalize runs inside SetExecutorSandbox regardless.
	if err := want.Validate(); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := db.SetExecutorSandbox(id, want, s.auditActor(r)); err != nil {
		if errors.Is(err, statedb.ErrDBLocked) {
			jsonErr(w, "the control plane is busy; retry: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		jsonErr(w, "save sandbox configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	after := want.Normalize()
	s.auditExecutorAction(r, "sandbox", id, map[string]any{
		"from": before.Describe(),
		"to":   after.Describe(),
		"mode": string(after.Mode),
	})
	// Tell open dashboards the fleet changed, so another admin's Executors panel
	// does not go on showing the containment this one just replaced.
	s.broadcastExecutorUpdate("sandbox", id)
	s.renderExecutorSandbox(w, db, id)
}

// describeSandboxTarget fills in the parts of the view that come from the live
// fleet rather than from the configuration row: whether this executor is a
// device the setting applies to, what engines it reported, and whether its agent
// is new enough to honour a container mode.
//
// Every lookup degrades to "unknown" rather than failing the request. A panel
// that cannot render because a device is offline would be useless for the case
// it is most needed in — configuring a device before or while it is down.
func (s *Server) describeSandboxTarget(view *executorSandboxView, id string) {
	inv := s.executorInventory(id)
	view.Remote = inv.remote
	view.DeviceEngines = inv.engines
	view.AgentSupported = inv.sandboxCapable

	switch {
	case !inv.remote && inv.known:
		view.Warning = "This executor is a driver the hub runs itself, so where its payloads run is " +
			"decided by the hub's own configuration (executors.container / executors.kubernetes in " +
			"config.yaml). The setting below is applied to enrolled devices."
	case inv.remote && !inv.sandboxCapable && inv.connected:
		view.Warning = fmt.Sprintf(
			"This device's agent speaks protocol v%d, which cannot run payloads in a container — it "+
				"would ignore the instruction and use its host. Upgrade it with `cloop executor agent "+
				"install --upgrade` (needs v%d); until then a container mode is refused at dispatch "+
				"rather than silently downgraded.",
			inv.protocol, remoteSandboxMinVersion)
	// A hypervisor the machine does not have. Placed above the engine check
	// because it is the more specific answer to what this admin just
	// configured, and because unlike a missing engine it usually cannot be
	// fixed on the device at all: nested virtualization is the hosting
	// hypervisor's decision, so the useful advice is a boundary the machine
	// can actually provide.
	case inv.remote && inv.connected && view.Settings.IsVirtualized() &&
		inv.virtProbed && !inv.virtualization:
		view.Warning = fmt.Sprintf(
			"This device reports no usable /dev/kvm, so the %q runtime cannot start a VM on it and "+
				"dispatch here is refused. Enable nested virtualization on the hypervisor hosting "+
				"the device (GCP: --enable-nested-virtualization; AWS: a metal instance type) and "+
				"reconnect the agent, or choose runsc — gVisor keeps workload syscalls off the "+
				"device's kernel without needing a hypervisor.",
			view.Settings.Runtime)
	case inv.remote && len(inv.engines) == 0 && inv.connected:
		view.Warning = "This device reported no container engine on its PATH at its last connect, so a " +
			"container mode would fail at dispatch. Install docker or podman on it, or leave this " +
			"executor on host mode."
	}
}
