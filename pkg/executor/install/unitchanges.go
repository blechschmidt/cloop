package install

// unitchanges.go is everything an upgrade may change beside the binary: the
// packet-filter grant (Task 20352), the update channel and the remote-upgrade
// helper (Task 20376). Each is a file next to the unit — never the unit
// itself, which an upgrade cannot honestly re-render (see upgrade.go) — and
// each is changed only when the operator on the device asks for it, so a plain
// --upgrade keeps all three as they are.
//
// They are planned, applied and rolled back as one set: if the agent does not
// come back after the upgrade, every file goes back to what it was, along with
// the binary.

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/blechschmidt/cloop/pkg/provenance"
)

// RemoteUpgradeChange is what an upgrade does to the remote-upgrade helper.
type RemoteUpgradeChange int

const (
	// RemoteUpgradeKeep leaves the helper as the device has it.
	RemoteUpgradeKeep RemoteUpgradeChange = iota
	// RemoteUpgradeGrant installs and arms it.
	RemoteUpgradeGrant
	// RemoteUpgradeWithdraw disarms and removes it.
	RemoteUpgradeWithdraw
)

// Kinds of file change, for the descriptions.
const (
	changePacketFilter  = "packet-filter"
	changeChannel       = "channel"
	changeHelperService = "helper-service"
	changeHelperPath    = "helper-path"
)

// unitChanges is the set an upgrade applies beside the binary.
type unitChanges struct {
	files []*dropInChange

	packetFilter        *dropInChange
	packetFilterGranted bool

	channelChanged              bool
	channelBefore, channelAfter provenance.Channel

	helperGrant, helperWithdraw bool
	helperBefore, helperAfter   bool

	applied bool
}

func (u *unitChanges) empty() bool { return u == nil || len(u.files) == 0 }

// planUnitChanges decides every change the options ask for. Nothing is
// written.
func (in *Installer) planUnitChanges(s Spec, out Output, opts UpgradeOptions) (*unitChanges, error) {
	u := &unitChanges{}
	pf, granted, err := in.planPacketFilter(s, out, opts.PacketFilter)
	if err != nil {
		return nil, err
	}
	u.packetFilterGranted = granted
	if pf != nil {
		pf.kind = changePacketFilter
		u.packetFilter = pf
		u.files = append(u.files, pf)
	}

	ch, before, after, err := in.planChannel(s, out, opts.Channel)
	if err != nil {
		return nil, err
	}
	u.channelBefore, u.channelAfter = before, after
	if ch != nil {
		u.channelChanged = true
		u.files = append(u.files, ch)
	}

	helper, hadHelper, hasHelper, err := in.planHelper(s, out, opts.RemoteUpgrade)
	if err != nil {
		return nil, err
	}
	u.helperBefore, u.helperAfter = hadHelper, hasHelper
	if len(helper) > 0 {
		u.files = append(u.files, helper...)
		u.helperGrant = opts.RemoteUpgrade == RemoteUpgradeGrant
		u.helperWithdraw = opts.RemoteUpgrade == RemoteUpgradeWithdraw
	}
	return u, nil
}

// fileState reads one file of the set.
func (in *Installer) fileState(path string) (body []byte, exists bool, err error) {
	body, err = os.ReadFile(in.path(path))
	switch {
	case err == nil:
		return body, true, nil
	case os.IsNotExist(err):
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("install: read %s: %w", path, err)
}

// planChannel decides the channel drop-in, returning the change (nil for
// none) and the channel before and after it. c empty keeps it.
func (in *Installer) planChannel(s Spec, out Output, c provenance.Channel) (
	change *dropInChange, before, after provenance.Channel, err error,
) {
	current, exists, err := in.fileState(s.ChannelDropInPath())
	if err != nil {
		return nil, "", "", err
	}
	before = provenance.ChannelStable
	if exists {
		before = provenance.ChannelEdge
		if ch, err := channelFromAssignments(envAssignments(string(current))); err == nil {
			before = ch
		}
	}
	if c == "" {
		return nil, before, before, nil
	}
	if out != OutputSystemd {
		return nil, before, before, fmt.Errorf("install: --channel applies to --output systemd only: it is "+
			"a systemd drop-in, and the %s output has no way to keep it across upgrades", out)
	}
	switch c {
	case provenance.ChannelEdge:
		want := ChannelDropIn(s, c)
		if exists && slices.Equal(unitDirectives(string(current)), unitDirectives(want)) {
			return nil, before, c, nil
		}
		return &dropInChange{kind: changeChannel, path: s.ChannelDropInPath(), next: want,
			previous: current, existed: exists, channelAfter: c}, before, c, nil
	case provenance.ChannelStable:
		if !exists {
			return nil, before, c, nil
		}
		return &dropInChange{kind: changeChannel, path: s.ChannelDropInPath(),
			previous: current, existed: true, channelAfter: c}, before, c, nil
	}
	return nil, before, before, fmt.Errorf("install: unknown channel %q", c)
}

// envAssignments returns the Environment= assignments in a unit file body.
func envAssignments(body string) []string {
	var out []string
	for _, d := range unitDirectives(body) {
		if v, ok := strings.CutPrefix(d, "Environment="); ok {
			out = append(out, strings.Fields(v)...)
		}
	}
	return out
}

// planHelper decides the remote-upgrade helper's two units, returning the
// changes and whether the device has the helper before and after them.
func (in *Installer) planHelper(s Spec, out Output, change RemoteUpgradeChange) (
	changes []*dropInChange, before, after bool, err error,
) {
	files := []struct {
		kind, path, want string
	}{
		{changeHelperService, s.UpgradeHelperServicePath(), UpgradeHelperService(s)},
		{changeHelperPath, s.UpgradeHelperPathUnitPath(), UpgradeHelperPathUnit(s)},
	}
	type state struct {
		body   []byte
		exists bool
	}
	states := make([]state, len(files))
	for i, f := range files {
		body, exists, err := in.fileState(f.path)
		if err != nil {
			return nil, false, false, err
		}
		states[i] = state{body, exists}
	}
	// The path unit is what arms the helper; it is what "installed" means.
	before = states[1].exists
	if change == RemoteUpgradeKeep {
		return nil, before, before, nil
	}
	if out != OutputSystemd {
		return nil, before, before, fmt.Errorf("install: --remote-upgrade applies to --output systemd only: the "+
			"helper is a root systemd unit, and the %s output has no equivalent", out)
	}
	for i, f := range files {
		st := states[i]
		switch change {
		case RemoteUpgradeGrant:
			if st.exists && slices.Equal(unitDirectives(string(st.body)), unitDirectives(f.want)) {
				continue
			}
			changes = append(changes, &dropInChange{kind: f.kind, path: f.path, next: f.want,
				previous: st.body, existed: st.exists})
		case RemoteUpgradeWithdraw:
			if st.exists {
				changes = append(changes, &dropInChange{kind: f.kind, path: f.path, previous: st.body, existed: true})
			}
		}
	}
	return changes, before, change == RemoteUpgradeGrant, nil
}

// applyUnitChanges writes the set. On a failure part-way, what was written is
// put back before the error is returned.
func (in *Installer) applyUnitChanges(s Spec, u *unitChanges) error {
	if u.empty() {
		return nil
	}
	if u.helperWithdraw {
		// Disarmed while its unit file still exists, so systemctl can find it.
		_ = in.run("systemctl", "disable", "--now", s.UpgradeHelperPathUnitName())
	}
	for i, c := range u.files {
		if err := in.applyDropIn(s, c); err != nil {
			for j := i - 1; j >= 0; j-- {
				_ = in.restoreDropIn(s, u.files[j])
			}
			return err
		}
	}
	u.applied = true
	if u.helperGrant {
		if err := in.run("systemctl", "daemon-reload"); err != nil {
			in.logf("note: systemctl daemon-reload failed: %v", err)
		}
		if err := in.run("systemctl", "enable", "--now", s.UpgradeHelperPathUnitName()); err != nil {
			_ = in.restoreUnitChanges(s, u)
			return fmt.Errorf("install: arm %s: %w", s.UpgradeHelperPathUnitName(), err)
		}
	}
	return nil
}

// restoreUnitChanges puts back what applyUnitChanges wrote.
func (in *Installer) restoreUnitChanges(s Spec, u *unitChanges) error {
	if u.empty() || !u.applied {
		return nil
	}
	if u.helperGrant {
		_ = in.run("systemctl", "disable", "--now", s.UpgradeHelperPathUnitName())
	}
	var failed []string
	for j := len(u.files) - 1; j >= 0; j-- {
		if err := in.restoreDropIn(s, u.files[j]); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", u.files[j].path, err))
		}
	}
	u.applied = false
	if err := in.run("systemctl", "daemon-reload"); err != nil {
		in.logf("note: systemctl daemon-reload failed: %v", err)
	}
	if u.helperWithdraw {
		_ = in.run("systemctl", "enable", "--now", s.UpgradeHelperPathUnitName())
	}
	if len(failed) > 0 {
		return fmt.Errorf("restoring %s", strings.Join(failed, "; "))
	}
	return nil
}

// describe says what the set did, or with dryRun would do, one line per
// change, for the log and the CLI.
func (u *unitChanges) describe(dryRun bool) []string {
	if u.empty() {
		return nil
	}
	var out []string
	helperSaid := false
	for _, c := range u.files {
		switch c.kind {
		case changePacketFilter:
			out = append(out, c.describe(dryRun))
		case changeChannel:
			out = append(out, c.describeChannel(dryRun))
		case changeHelperService, changeHelperPath:
			if helperSaid {
				continue
			}
			helperSaid = true
			out = append(out, u.describeHelper(dryRun))
		}
	}
	return out
}

func (c *dropInChange) describeChannel(dryRun bool) string {
	switch {
	case c.next == "" && dryRun:
		return "would remove " + c.path + ", returning the agent to the stable channel (releases only)"
	case c.next == "":
		return "removed " + c.path + ": the agent follows the stable channel (releases only)"
	case dryRun:
		return "would write " + c.path + ", putting the agent on the " + string(c.channelAfter) + " channel"
	}
	return "wrote " + c.path + ": the agent follows the " + string(c.channelAfter) +
		" channel — signed builds of main as well as releases"
}

func (u *unitChanges) describeHelper(dryRun bool) string {
	switch {
	case u.helperWithdraw && dryRun:
		return "would disarm and remove the remote-upgrade helper; the hub could no longer upgrade this device"
	case u.helperWithdraw:
		return "removed the remote-upgrade helper: the hub can no longer upgrade this device"
	case dryRun:
		return "would install and arm the remote-upgrade helper, so the hub can upgrade this device"
	}
	return "installed and armed the remote-upgrade helper: the hub can upgrade this device to a verified build"
}
