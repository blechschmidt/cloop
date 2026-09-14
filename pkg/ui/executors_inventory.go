package ui

// executors_inventory.go makes the edge fleet legible: which cloop build each
// device is running, what hardware it has, which harnesses it can actually
// invoke — and whether its build has fallen behind the control plane's.
//
// None of this was new information. The agent already sent a build version in
// its hello frame and a full capability advertisement alongside it; the hub
// decoded both and kept neither in a form anything could use. The version had
// no column, so it was dropped at the handshake. The capabilities went into an
// opaque JSON blob that the panel never rendered. So an operator running a
// fleet of edge devices could not answer the two questions that matter after a
// partial rollout — "what is each device running" and "which ones are stale" —
// from the control plane at all.
//
// Two design points worth stating because the obvious alternatives are wrong:
//
//   - Inventory is refreshed on every *connect*, not at enrollment. Enrollment
//     happens once; upgrades happen repeatedly, and they are precisely the
//     event that changes these facts. Recording at enrollment would have
//     reproduced in the database the same staleness the frozen agent version
//     produced on the wire.
//   - The live session wins over the stored row whenever there is one. A
//     stored version describes some past moment; for "what is on this device
//     right now", the connected agent is the only authority, and the row is a
//     cache of it for when the device is offline.

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/version"
)

// AgentUpgradeCommand is the procedure that actually upgrades a device.
//
// It is a constant because it used to be a lie in three places. The Executors
// panel told operators to run `cloop executor agent install --upgrade`, and
// cmd/executor_install_cmd.go defined no such flag — so the one command the UI
// offered as a remedy failed with an unknown-flag error. The flag now exists
// (see install.Upgrade), and naming it from one place means the string and the
// flag cannot drift apart again.
//
// An alias rather than a second literal: the scheduler emits the same sentence
// when it refuses a device for being below the fleet's build floor, and two
// copies of an operator instruction is how one of them goes stale.
const AgentUpgradeCommand = executor.AgentUpgradeProcedure

// upgradeHint is the sentence appended to any skew message, naming the real
// procedure. Kept separate from pkg/version's prose so the version package
// stays free of any opinion about how cloop is deployed.
var upgradeHint = "Copy the new cloop binary to the device and run `" +
	AgentUpgradeCommand + "` there."

// inventoryFromCaps projects an agent's advertisement onto the queryable
// inventory columns.
//
// Deliberately a projection and not a replacement: the full advertisement still
// goes to capabilities_json, so a field added to AgentCapabilities later is
// preserved even before it gets a column of its own.
func inventoryFromCaps(caps remote.AgentCapabilities, agentVersion string) statedb.ExecutorInventory {
	return statedb.ExecutorInventory{
		AgentVersion:      agentVersion,
		OS:                caps.OS,
		Arch:              caps.Arch,
		CPUs:              caps.CPUs,
		MemoryMB:          caps.MemoryMB,
		Harnesses:         caps.Harnesses,
		ContainerRuntimes: caps.ContainerRuntimes,
		WorkDirRoot:       caps.WorkDirRoot,
	}
}

// makeExecutorConnectRecorder refreshes a device's row every time it connects,
// so the stored build version and inventory track what is actually running
// rather than what was running the day it enrolled.
//
// Read-modify-write rather than a targeted UPDATE: UpsertExecutor's conflict
// clause overwrites name and enrolled_by from the incoming row, so building a
// partial row here would blank the enrollment provenance on every reconnect.
// Reading first also means a device whose row was deleted while its credential
// stayed valid gets a row back instead of silently having no inventory.
func makeExecutorConnectRecorder(db *statedb.DB) func(remote.AgentRecord, remote.AgentCapabilities, string) {
	return func(agent remote.AgentRecord, caps remote.AgentCapabilities, agentVersion string) {
		row, err := db.GetExecutor(agent.AgentID)
		if err != nil {
			// No row: reconstruct what the enrollment recorder would have
			// written. Not an error worth surfacing — the agent is connected
			// and working either way, and refusing to record its inventory
			// would only widen the gap this function exists to close.
			row = statedb.ExecutorRow{
				ID:         agent.AgentID,
				Name:       agent.Name,
				Kind:       executor.KindRemoteAgent,
				CreatedAt:  agent.CreatedAt,
				EnrolledBy: agent.EnrollmentID,
			}
		}
		row.Status = remote.StatusOnline
		row.Inventory = inventoryFromCaps(caps, agentVersion)
		if len(agent.Labels) > 0 {
			row.Labels = agent.Labels
		}
		// Keep the full advertisement too: the inventory columns are a subset,
		// and a capability that has no column yet must not be lost.
		if encoded, mErr := json.Marshal(caps); mErr == nil {
			row.Capabilities = encoded
		}
		if err := db.UpsertExecutor(row); err != nil {
			fmt.Fprintf(os.Stderr, "ui: record executor %s build version: %v\n", agent.AgentID, err)
		}
	}
}

// makeExecutorConnectBroadcaster wraps the connect recorder so a device that
// reconnects on a new build updates open dashboards immediately, which is the
// whole point of noticing the upgrade.
func (s *Server) makeExecutorConnectBroadcaster(
	inner func(remote.AgentRecord, remote.AgentCapabilities, string),
) func(remote.AgentRecord, remote.AgentCapabilities, string) {
	return func(agent remote.AgentRecord, caps remote.AgentCapabilities, agentVersion string) {
		if inner != nil {
			inner(agent, caps, agentVersion)
		}
		s.broadcastExecutorUpdate("connected", agent.AgentID)
	}
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

// executorInventoryView is the panel's typed view of one device's inventory.
//
// It exists because the stored capabilities were surfaced as a json.RawMessage
// the frontend never unpacked, which made every one of these fields invisible
// and unfilterable. Naming them here is what lets the panel show "4 cores /
// 7.7 GB / claude, codex" instead of nothing.
type executorInventoryView struct {
	// AgentVersion is the build the device reports. Empty for a backend that
	// is not a device.
	AgentVersion string `json:"agent_version,omitempty"`
	// AgentVersionLabel is AgentVersion rendered for display, naming the two
	// kinds of "unknown" rather than leaving a blank cell.
	AgentVersionLabel string `json:"agent_version_label,omitempty"`
	OS                string `json:"os,omitempty"`
	Arch              string `json:"arch,omitempty"`
	CPUs              int    `json:"cpus,omitempty"`
	MemoryMB          int    `json:"memory_mb,omitempty"`
	// MemoryLabel is MemoryMB in human units, computed here so every client
	// renders it identically.
	MemoryLabel       string   `json:"memory_label,omitempty"`
	Harnesses         []string `json:"harnesses,omitempty"`
	ContainerRuntimes []string `json:"container_runtimes,omitempty"`
	WorkDirRoot       string   `json:"workdir_root,omitempty"`
	// Live reports that these values came from a connected session rather than
	// from the stored row, so the panel can mark an offline device's inventory
	// as last-known rather than current.
	Live bool `json:"live"`
}

// executorSkewView is one device's build compared against the hub's.
type executorSkewView struct {
	// Skew is the classification: none|patch|behind|ahead|legacy|unknown|
	// unversioned.
	Skew string `json:"skew"`
	// Material is whether an operator should act on it now. Patch drift across
	// a fleet is normal, and flagging it would train operators to ignore the
	// warning that matters.
	Material bool `json:"material"`
	// HubVersion is what the control plane is running, so the comparison can
	// be checked rather than taken on trust.
	HubVersion string `json:"hub_version,omitempty"`
	// Note is the operator-facing sentence, including the remediation.
	Note string `json:"note,omitempty"`
}

// hubVersion is the control-plane build every device is compared against.
var hubVersion = version.String

// annotateInventory fills a view's inventory and version-skew fields.
//
// The live session is preferred over the stored row, and the row is the
// fallback for an offline device — which is the case where an operator most
// needs to know what a device *was* running, since they cannot ask it.
func annotateInventory(view *executorView, row statedb.ExecutorRow, live *remote.Executor) {
	// Only devices have a build of their own. A container or Kubernetes
	// executor runs this very binary, so reporting "version skew" against the
	// hub would be comparing the hub with itself.
	if row.Kind != executor.KindRemoteAgent {
		return
	}

	inv := row.Inventory
	fromSession := false
	if live != nil {
		if caps, ok := live.AgentInventory(); ok {
			inv = inventoryFromCaps(caps, live.AgentVersion())
			fromSession = true
		}
	}

	if inv.Known() || fromSession {
		view.Inventory = &executorInventoryView{
			AgentVersion:      inv.AgentVersion,
			AgentVersionLabel: agentVersionLabel(inv.AgentVersion),
			OS:                inv.OS,
			Arch:              inv.Arch,
			CPUs:              inv.CPUs,
			MemoryMB:          inv.MemoryMB,
			MemoryLabel:       memoryLabel(inv.MemoryMB),
			Harnesses:         inv.Harnesses,
			ContainerRuntimes: inv.ContainerRuntimes,
			WorkDirRoot:       inv.WorkDirRoot,
			Live:              fromSession,
		}
	}

	hub := hubVersion()
	skew, note := version.Classify(hub, inv.AgentVersion)
	if skew == version.SkewNone {
		// Nothing to say. Reported anyway so a client can distinguish
		// "compared, and uniform" from "never compared".
		view.VersionSkew = &executorSkewView{
			Skew:       string(skew),
			HubVersion: hub,
		}
		return
	}
	if note != "" {
		note += " " + upgradeHint
	}
	view.VersionSkew = &executorSkewView{
		Skew:       string(skew),
		Material:   skew.Material(),
		HubVersion: hub,
		Note:       note,
	}
}

// agentVersionLabel renders a reported build for display.
//
// The two kinds of unknown are kept apart because they call for different
// actions: a device that reported nothing predates version reporting, while one
// reporting the placeholder is definitely running a build older than this
// feature and is worth upgrading first.
func agentVersionLabel(v string) string {
	switch v {
	case "":
		return "unreported"
	case version.LegacyAgentVersion:
		return "legacy (pre-" + version.LegacyAgentVersion + " placeholder)"
	default:
		return v
	}
}

// memoryLabel renders megabytes in the unit an operator thinks in. Zero means
// the agent could not detect it, which is not "no memory" and so renders as
// nothing at all rather than "0 MB".
func memoryLabel(mb int) string {
	switch {
	case mb <= 0:
		return ""
	case mb < 1024:
		return fmt.Sprintf("%d MB", mb)
	default:
		return fmt.Sprintf("%.1f GB", float64(mb)/1024)
	}
}
