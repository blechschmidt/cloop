package install

// packetfilter.go lets an upgrade grant or withdraw the packet-filter drop-in
// on a device that is already installed (Task 20352).
//
// sgx is the device that made this necessary. It was installed before the
// installer granted CAP_NET_ADMIN, so its agent could not install a sandbox's
// firewall, and the only documented fixes were re-running a full install —
// which needs the control-plane URL and pin from an enrollment bundle nobody
// keeps — or hand-writing a drop-in. An upgrade already reaches every installed
// device without the bundle, so it carries the grant too, but only when asked:
// widening or narrowing what a fleet device may do is not something to do as a
// side effect of replacing a binary.

import (
	"bytes"
	"fmt"
	"os"
	"slices"

	"github.com/blechschmidt/cloop/pkg/provenance"
)

// PacketFilterChange is what an upgrade does to the packet-filter grant.
type PacketFilterChange int

const (
	// PacketFilterKeep leaves the grant as the device has it.
	PacketFilterKeep PacketFilterChange = iota
	// PacketFilterGrant writes the drop-in, so the agent can install sandbox
	// firewalls.
	PacketFilterGrant
	// PacketFilterWithdraw removes it.
	PacketFilterWithdraw
)

// dropInChange is one pending change to the packet-filter drop-in, with what
// it replaces so a failed upgrade can put that back.
type dropInChange struct {
	// kind says which of the upgrade's unit changes this is (unitchanges.go).
	kind     string
	path     string // in the device's namespace
	next     string // the content to write; empty to remove the file
	previous []byte // what was there before
	existed  bool
	// grantedBefore and grantedAfter describe the device on either side of
	// the change.
	grantedBefore, grantedAfter bool
	// channelAfter is the channel a channel change leaves the device on.
	channelAfter provenance.Channel
}

// packetFilterState reports whether the device's unit grants the packet filter
// now, and whether it does so in the unit file itself — the form Task 20345's
// --packet-filter wrote, which only a full install can take out again.
func (in *Installer) packetFilterState(s Spec) (dropIn []byte, dropInExists, inUnit bool, err error) {
	dropIn, err = os.ReadFile(in.path(s.PacketFilterDropInPath()))
	switch {
	case err == nil:
		dropInExists = true
	case os.IsNotExist(err):
		dropIn = nil
	default:
		return nil, false, false, fmt.Errorf("install: read %s: %w", s.PacketFilterDropInPath(), err)
	}
	unit, uerr := os.ReadFile(in.path(s.UnitPath()))
	if uerr == nil {
		inUnit = slices.Contains(unitDirectives(string(unit)), "AmbientCapabilities=CAP_NET_ADMIN")
	}
	return dropIn, dropInExists, inUnit, nil
}

// planPacketFilter decides what an upgrade does to the grant. It returns nil
// when nothing needs to change, and whether the device grants the packet filter
// once the upgrade is done.
func (in *Installer) planPacketFilter(s Spec, out Output, change PacketFilterChange) (*dropInChange, bool, error) {
	if out != OutputSystemd {
		if change != PacketFilterKeep {
			return nil, false, fmt.Errorf(
				"install: --packet-filter applies to --output systemd only: it is a systemd drop-in, and "+
					"the %s output has no equivalent that keeps the capability from the agent's workloads", out)
		}
		return nil, false, nil
	}
	current, exists, inUnit, err := in.packetFilterState(s)
	if err != nil {
		return nil, false, err
	}
	granted := exists || inUnit

	switch change {
	case PacketFilterGrant:
		want := PacketFilterDropIn(s)
		if exists && slices.Equal(unitDirectives(string(current)), unitDirectives(want)) {
			return nil, true, nil // already granted by this drop-in; a prose change is not worth a restart
		}
		if inUnit && !exists {
			return nil, true, nil // granted in the unit itself; adding the same grant twice changes nothing
		}
		return &dropInChange{
			path: s.PacketFilterDropInPath(), next: want,
			previous: current, existed: exists,
			grantedBefore: granted, grantedAfter: true,
		}, true, nil
	case PacketFilterWithdraw:
		if inUnit {
			return nil, true, fmt.Errorf(
				"install: %s grants CAP_NET_ADMIN in the unit file itself (an earlier --packet-filter "+
					"rendered it there), and an upgrade does not re-render the unit. Re-run a full install "+
					"with --packet-filter=false and the device's --server to withdraw it", s.UnitPath())
		}
		if !exists {
			return nil, false, nil
		}
		return &dropInChange{
			path:     s.PacketFilterDropInPath(),
			previous: current, existed: true,
			grantedBefore: true, grantedAfter: false,
		}, false, nil
	default:
		return nil, granted, nil
	}
}

// applyDropIn makes the change. Writing goes through writeArtifact, so the file
// is replaced atomically and at the unit's mode.
func (in *Installer) applyDropIn(s Spec, c *dropInChange) error {
	if c.next == "" {
		return in.removeFile(c.path)
	}
	return in.writeArtifact(s, Artifact{Path: c.path, Mode: UnitFileMode, Content: c.next})
}

// restoreDropIn puts back what applyDropIn replaced.
func (in *Installer) restoreDropIn(s Spec, c *dropInChange) error {
	if !c.existed {
		return in.removeFile(c.path)
	}
	current, err := os.ReadFile(in.path(c.path))
	if err == nil && bytes.Equal(current, c.previous) {
		return nil
	}
	return in.writeArtifact(s, Artifact{Path: c.path, Mode: UnitFileMode, Content: string(c.previous)})
}

// describe says what the change did, or with dryRun what it would do, for the
// log and the CLI.
func (c *dropInChange) describe(dryRun bool) string {
	switch {
	case c.next == "" && dryRun:
		return "would remove " + c.path + ", taking CAP_NET_ADMIN from the agent"
	case c.next == "":
		return "removed " + c.path + ": the agent no longer holds CAP_NET_ADMIN"
	case dryRun:
		return "would write " + c.path + ", granting the agent CAP_NET_ADMIN and netlink sockets for nft(8)"
	case c.existed:
		return "rewrote " + c.path + ": the agent holds CAP_NET_ADMIN and netlink sockets, for nft(8) only"
	default:
		return "wrote " + c.path + ": the agent holds CAP_NET_ADMIN and netlink sockets, for nft(8) only"
	}
}

// PacketFilterHint is what an upgrade says about a device that cannot install
// sandbox firewalls, naming the flag that changes that.
const PacketFilterHint = "the agent holds no CAP_NET_ADMIN, so a sandbox with a firewall is refused " +
	"on this device; re-run with --packet-filter to grant it"
