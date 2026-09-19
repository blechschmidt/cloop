package ui

// executor_sandbox.go connects the per-executor sandbox configuration to the two
// things that need it: the dispatch path, which must be told an executor's mode
// on every start, and the admin panel, which must describe what the device on
// the other end can actually do (Task 20307).

import (
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// remoteSandboxMinVersion is the protocol version an agent needs before it can
// honour a container mode. Re-exported under this package's name so the panel's
// warning text and the driver's refusal quote one number.
const remoteSandboxMinVersion = remote.MinSandboxModeVersion

// sandboxSettingsFactory builds the per-executor resolver the agent hub installs
// on every device executor it creates.
//
// The returned inner function is called on *every* dispatch, which is the whole
// design: an admin's change in the Executors panel governs the next task without
// the device reconnecting. That costs one indexed primary-key lookup per start,
// against a dispatch that is about to cross a network and clone a repository.
//
// It deliberately does not cache. A cache here would reintroduce exactly the
// staleness the per-dispatch read exists to remove, and the window it opened
// would be one in which the hub believed an executor was contained while the
// device was still being told otherwise.
func sandboxSettingsFactory(db *statedb.DB) func(string) func() (executor.SandboxSettings, error) {
	if db == nil {
		// No control plane means no configuration to read, which the driver
		// treats as "unset" and runs as it always did. A non-nil function
		// returning zero values would be indistinguishable in behaviour but
		// would hide the absence from anything inspecting the hub's options.
		return nil
	}
	return func(executorID string) func() (executor.SandboxSettings, error) {
		return func() (executor.SandboxSettings, error) {
			return statedb.SandboxSettingsFor(db, executorID)
		}
	}
}

// executorSandboxSummary is what a fleet card says about one executor's
// containment. A compact projection of the configuration rather than the whole
// record: the card has room for a chip, and the dialog is where the detail goes.
type executorSandboxSummary struct {
	Mode    string `json:"mode,omitempty"`
	Engine  string `json:"engine,omitempty"`
	Runtime string `json:"runtime,omitempty"`
	Image   string `json:"image,omitempty"`
	// Configured distinguishes an admin's explicit default from an executor
	// nobody has looked at.
	Configured bool `json:"configured"`
}

// applySandboxModes attaches each executor's configured sandbox mode to its card.
//
// # Why the card needs this and not just the dialog
//
// The capability chips already render `isolation: remote` for every enrolled
// device, and they render it identically whether that device runs payloads in a
// container or as a bare host process — because before this configuration
// existed, "remote" was the only thing the control plane could honestly say.
// An admin scanning the fleet for the machines that are *not* contained had
// nothing to look at.
//
// So the mode goes on the card. The runtime comes with it, because a container
// on runc and a container on kata are different boundaries and the chip that
// says "container" alone would flatten them.
//
// One query for the whole fleet, which is why statedb has ListExecutorSandboxes
// rather than only the per-executor read: a lookup per card would be N queries
// on the dashboard's most-refreshed panel.
//
// A nil database or a failed query leaves every card unannotated rather than
// failing the list. That is the safe direction here — an absent chip claims
// nothing — and it matches the handler's existing stance that a panel rendering
// the host executor beats a panel rendering an error.
func applySandboxModes(views []executorView, db *statedb.DB) []executorView {
	if db == nil || len(views) == 0 {
		return views
	}
	rows, err := db.ListExecutorSandboxes()
	if err != nil || len(rows) == 0 {
		return views
	}
	byID := make(map[string]statedb.ExecutorSandbox, len(rows))
	for _, r := range rows {
		byID[r.ExecutorID] = r
	}
	for i := range views {
		rec, ok := byID[views[i].ID]
		if !ok {
			continue
		}
		views[i].Sandbox = &executorSandboxSummary{
			Mode:       string(rec.Settings.Mode),
			Engine:     rec.Settings.Engine,
			Runtime:    rec.Settings.Runtime,
			Image:      rec.Settings.Image,
			Configured: true,
		}
	}
	return views
}

// sandboxModeNames renders the selectable modes for the API.
func sandboxModeNames() []string {
	modes := executor.SandboxModes()
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		out = append(out, string(m))
	}
	return out
}

// sandboxTargetInfo is what the live fleet can say about one executor, as far as
// the sandbox panel is concerned.
type sandboxTargetInfo struct {
	// known reports that this ID resolved to something at all. False for a typo
	// or for a device whose enrollment was revoked.
	known bool
	// remote reports that this is an enrolled device — the only kind of executor
	// whose sandbox mode this setting governs.
	remote bool
	// connected reports that a session is live. It gates the warnings: telling
	// an admin that an offline device "reported no container engine" would be
	// blaming the device for being switched off.
	connected bool
	// engines is what the device found on its PATH at its last connect.
	engines []string
	// protocol is the negotiated protocol version, or 0 when offline.
	protocol int
	// sandboxCapable reports that the agent can honour a container mode.
	sandboxCapable bool
}

// executorInventory describes one executor for the sandbox panel.
//
// Unknown is a legitimate answer and is not an error: the hub may not have been
// built yet in a test, the agent hub may be unavailable, and an ID may name an
// executor registered by config rather than by enrollment. In each case the
// panel still renders and still saves — the configuration row is keyed by ID and
// does not require the executor to exist, which is what lets an admin configure
// a device before its first connect.
func (s *Server) executorInventory(id string) sandboxTargetInfo {
	info := sandboxTargetInfo{}

	// The registry answers "is there an executor by this name, and what kind" for
	// every driver, including the ones the hub built from config.
	if ex, err := executor.DefaultRegistry.Get(id); err == nil {
		info.known = true
		info.remote = ex.Kind() == executor.KindRemoteAgent
	}

	hub, err := s.remoteHub()
	if err != nil || hub == nil {
		// Not returned to the client. The panel's job is to configure an
		// executor, and a hub that failed to build does not stop a row being
		// written — it only costs the advisory half of the view.
		return info
	}
	rex, ok := hub.Executor(id)
	if !ok {
		return info
	}
	info.known = true
	info.remote = true
	info.connected = rex.Connected()
	info.protocol = rex.ProtocolVersion()
	info.sandboxCapable = remote.SupportsSandboxMode(info.protocol)
	info.engines = rex.AgentCapabilities().ContainerRuntimes
	return info
}
