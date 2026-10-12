package hubdoctor

// Edge lag: how far behind this hub's own build each device on the edge
// channel is (Task 20380).
//
// A device on the edge channel follows the hub's build, and every build is
// stamped with its commit's first-parent position on main — its sequence. The
// device's root helper refuses any build earlier than the one it runs, which is
// what makes "how far behind" a number worth reading: a device twenty commits
// back is twenty commits of fixes short, and the hub cannot move it back
// either. Two situations get a warning:
//
//   - a device more than EdgeLagWarnSequences behind the hub's build, which the
//     Upgrade dialog or the auto-update policy would move forward;
//   - a device whose build carries no sequence at all — one from before builds
//     were stamped — whose helper cannot order upgrades yet, so the rollback
//     protection does not cover it until it has been upgraded once.
//
// Devices on the stable channel are not compared with the hub's build — they
// follow releases — but the second warning applies to them as much (Task
// 20421): every release before v0.0.5 carries no sequence, so a device still on
// one is named under executors.rollback_protection with the way to cover it.
//
// Read from the hub's database: the full capability advertisement every device
// sent at its last connect is stored with its row, so this works from the CLI,
// with the hub running or not, and for devices that are offline (their last
// known build).

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/version"
)

// EdgeLagWarnSequences is how many commits a device's edge build may trail
// this hub's before hub doctor warns.
const EdgeLagWarnSequences = 20

// edgeDevice is one enrolled device, as last seen.
type edgeDevice struct {
	ID, Name, Version string
	Sequence          int
	// Channel is the channel the device reported, "" for an agent too old to
	// report one; RemoteUpgrade whether it said it can carry out an upgrade
	// the hub asks for.
	Channel       string
	RemoteUpgrade bool
}

// hubSequence is this build's place on main. A variable so tests can pose as
// a stamped hub.
var hubSequence = version.BuildSequence

func checkEdgeLag(dir string, add addFn) {
	devices, err := agentDevices(dir, true)
	if err != nil {
		add(Finding{
			Check: "executors.edge_lag", Title: "Edge devices against this hub's build", Severity: SeverityWarn,
			Message:     fmt.Sprintf("the devices on the edge channel could not be read: %v", err),
			Remediation: "Check the storage findings above; the device inventory lives in .cloop/state.db",
		})
		return
	}
	if len(devices) == 0 {
		return // no device follows the hub's build; nothing to compare
	}
	hub, ok := hubSequence()
	if !ok {
		add(Finding{
			Check: "executors.edge_lag", Title: "Edge devices against this hub's build", Severity: SeverityWarn,
			Message: fmt.Sprintf("%d device(s) follow the edge channel, but this build (%s) carries no sequence, so "+
				"how far behind it they are cannot be told", len(devices), version.String()),
			Remediation: "Run hub doctor with the hub's own binary, built by scripts/build-release.sh or a deploy " +
				"that stamps github.com/blechschmidt/cloop/pkg/version.Sequence and .Commit (`cloop version` " +
				"then prints a \"sequence N on main\" line)",
			Details: map[string]any{"devices": len(devices)},
		})
		return
	}
	for _, d := range devices {
		title := "Edge build of " + d.Name
		details := map[string]any{"device": d.ID, "version": d.Version, "hub_sequence": hub}
		switch {
		case d.Sequence <= 0:
			msg, fix := executor.RollbackUnprotected(d.Name, d.Version, executor.ChannelEdge, d.RemoteUpgrade)
			add(Finding{
				Check: "executors.edge_lag", Title: title, Severity: SeverityWarn,
				Message: msg, Remediation: fix, Details: details,
			})
		case hub-d.Sequence > EdgeLagWarnSequences:
			details["sequence"] = d.Sequence
			add(Finding{
				Check: "executors.edge_lag", Title: title, Severity: SeverityWarn,
				Message: fmt.Sprintf("%s runs %s at %s, %d commits behind this hub's build at sequence %d (more "+
					"than %d)", d.Name, displayBuild(d.Version), version.SequenceLabel(d.Sequence), hub-d.Sequence,
					hub, EdgeLagWarnSequences),
				Remediation: "Press Upgrade on its row in the Executors panel, or turn on the fleet auto-update " +
					"policy; if it is not offered, the dialog says why",
				Details: details,
			})
		default:
			details["sequence"] = d.Sequence
			msg := fmt.Sprintf("%s runs %s at %s, within %d commits of this hub's build at sequence %d",
				d.Name, displayBuild(d.Version), version.SequenceLabel(d.Sequence), EdgeLagWarnSequences, hub)
			if d.Sequence > hub {
				msg = fmt.Sprintf("%s runs %s at %s, %d commits ahead of this hub's build at sequence %d",
					d.Name, displayBuild(d.Version), version.SequenceLabel(d.Sequence), d.Sequence-hub, hub)
			}
			add(Finding{Check: "executors.edge_lag", Title: title, Severity: SeverityPass, Message: msg,
				Details: details})
		}
	}
}

// checkRollbackProtection names each device on the stable channel — or too
// old to report a channel, which follows releases — whose build carries no
// sequence, so its installer cannot refuse an older one (Task 20421). Edge
// devices are checkEdgeLag's.
func checkRollbackProtection(dir string, add addFn) {
	devices, err := agentDevices(dir, false)
	if err != nil {
		add(Finding{
			Check: "executors.rollback_protection", Title: "Rollback protection of enrolled devices",
			Severity: SeverityWarn, Message: fmt.Sprintf("the enrolled devices could not be read: %v", err),
			Remediation: "Check the storage findings above; the device inventory lives in .cloop/state.db",
		})
		return
	}
	for _, d := range devices {
		title := "Rollback protection of " + d.Name
		details := map[string]any{"device": d.ID, "version": d.Version, "channel": channelLabel(d.Channel)}
		if d.Sequence <= 0 {
			msg, fix := executor.RollbackUnprotected(d.Name, d.Version, d.Channel, d.RemoteUpgrade)
			add(Finding{Check: "executors.rollback_protection", Title: title, Severity: SeverityWarn,
				Message: msg, Remediation: fix, Details: details})
			continue
		}
		details["sequence"] = d.Sequence
		add(Finding{Check: "executors.rollback_protection", Title: title, Severity: SeverityPass,
			Message: fmt.Sprintf("%s runs %s at %s; its installer refuses any build earlier than that", d.Name,
				displayBuild(d.Version), version.SequenceLabel(d.Sequence)),
			Details: details})
	}
}

// channelLabel names a reported channel, an unreported one as the stable
// channel it is.
func channelLabel(c string) string {
	if c == "" {
		return executor.ChannelStable
	}
	return c
}

// agentDevices lists the enrolled, unrevoked devices ordered by name: those
// whose last advertisement put them on the edge channel when edge is set, the
// rest otherwise.
func agentDevices(dir string, edge bool) ([]edgeDevice, error) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil // no database, no enrolled devices; storage says the rest
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	revoked := map[string]bool{}
	if store, err := executorstore.New(db); err == nil {
		if agents, err := store.ListAgents(); err == nil {
			for _, a := range agents {
				if a.Revoked() {
					revoked[a.AgentID] = true
				}
			}
		}
	}
	rows, err := db.ListExecutors()
	if err != nil {
		return nil, err
	}
	var out []edgeDevice
	for _, row := range rows {
		if row.Kind != executor.KindRemoteAgent || revoked[row.ID] {
			continue
		}
		var caps struct {
			UpdateChannel string `json:"update_channel"`
			RemoteUpgrade bool   `json:"remote_upgrade"`
		}
		if len(row.Capabilities) > 0 && json.Unmarshal(row.Capabilities, &caps) != nil {
			// An advertisement that does not parse says nothing about the
			// device, so it is left out rather than guessed at.
			continue
		}
		if (caps.UpdateChannel == executor.ChannelEdge) != edge {
			continue
		}
		if !row.Inventory.Known() && caps.UpdateChannel == "" {
			continue // enrolled, never connected: there is no build to judge
		}
		name := row.Name
		if name == "" {
			name = row.ID
		}
		// The sequence as the hub reads a disconnected device's, out-of-range
		// values included — not a second reading of the same JSON.
		out = append(out, edgeDevice{ID: row.ID, Name: name, Version: row.Inventory.AgentVersion,
			Sequence: remote.StoredBuildSequence(row.Capabilities), Channel: caps.UpdateChannel,
			RemoteUpgrade: caps.RemoteUpgrade})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// displayBuild names a reported build, or says there was none.
func displayBuild(v string) string {
	if v == "" {
		return "an unreported build"
	}
	return v
}
