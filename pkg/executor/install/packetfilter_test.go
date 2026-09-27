package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestPacketFilterLeavesTheUnitAlone: the grant is a separate file (Task 20352),
// so the hardened unit is byte-identical with or without it, and a plan that
// withholds it removes a drop-in an earlier install or upgrade left behind.
func TestPacketFilterLeavesTheUnitAlone(t *testing.T) {
	s := baseSpec(t)
	plain, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	s.PacketFilter = true
	granted, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan(packet filter): %v", err)
	}
	if plain.Display != granted.Display {
		t.Error("--packet-filter changed the unit itself; the grant belongs in its drop-in")
	}

	dropIn := granted.Spec.PacketFilterDropInPath()
	if want := "/etc/systemd/system/cloop-executor.service.d/10-packet-filter.conf"; dropIn != want {
		t.Errorf("drop-in path = %q, want %q", dropIn, want)
	}
	found := false
	for _, a := range granted.Artifacts {
		if a.Path == dropIn {
			found = true
			if a.Mode != UnitFileMode || a.Secret {
				t.Errorf("drop-in artifact = mode %04o secret %t, want %04o and not secret", a.Mode, a.Secret, UnitFileMode)
			}
			if a.Content != PacketFilterDropIn(granted.Spec) {
				t.Error("the drop-in artifact is not PacketFilterDropIn's rendering")
			}
		}
	}
	if !found {
		t.Errorf("a plan with the packet filter does not write %s", dropIn)
	}
	if slices.Contains(granted.Remove, dropIn) {
		t.Error("a plan that grants the packet filter also removes its drop-in")
	}
	if !slices.Contains(plain.Remove, dropIn) {
		t.Errorf("a plan without the packet filter leaves an old drop-in in place: Remove = %v", plain.Remove)
	}
	for _, a := range plain.Artifacts {
		if a.Path == dropIn {
			t.Error("a plan without the packet filter writes its drop-in")
		}
	}

	// Only systemd has a drop-in to write.
	for _, out := range []Output{OutputShell, OutputDocker} {
		p, err := BuildPlan(s, out)
		if err != nil {
			t.Fatalf("BuildPlan(%s): %v", out, err)
		}
		for _, a := range p.Artifacts {
			if strings.HasSuffix(a.Path, packetFilterDropInName) {
				t.Errorf("--output %s writes a systemd drop-in", out)
			}
		}
	}
}

// TestPacketFilterDropInGrantsExactlyThreeThings: one capability, the same
// capability at exec, and one socket family — each as an addition to the unit,
// so the drop-in means the same thing over a unit from any release. A fourth
// directive would be a relaxation nobody asked for.
func TestPacketFilterDropInGrantsExactlyThreeThings(t *testing.T) {
	s, err := baseSpec(t).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	sections := parseUnitFile(t, PacketFilterDropIn(s))
	if len(sections) != 1 || sections["Service"] == nil {
		t.Fatalf("drop-in sections = %v, want only [Service]", sections)
	}
	want := map[string]string{
		"CapabilityBoundingSet":   "CAP_NET_ADMIN",
		"AmbientCapabilities":     "CAP_NET_ADMIN",
		"RestrictAddressFamilies": "AF_NETLINK",
	}
	got := map[string]string{}
	for k, v := range sections["Service"] {
		if len(v) != 1 {
			t.Errorf("%s appears %d times", k, len(v))
		}
		got[k] = v[len(v)-1]
	}
	if len(got) != len(want) {
		t.Errorf("drop-in sets %v, want exactly %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// TestPacketFilterMergesIntoWhatNftNeeds models systemd's merge of the three
// directives across a unit and its drop-ins — an empty assignment resets the
// list, anything else adds to it — and checks the result is what nft(8) needs
// and nothing more. The model is what systemd 255 does: on sgx, `systemctl
// show` gave CapabilityBoundingSet=cap_net_admin and
// RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX for this pair,
// and nft loaded a table under it.
func TestPacketFilterMergesIntoWhatNftNeeds(t *testing.T) {
	s := baseSpec(t)
	s.PacketFilter = true
	p, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatal(err)
	}
	unit := parseUnitFile(t, p.Display)["Service"]
	dropIn := parseUnitFile(t, PacketFilterDropIn(p.Spec))["Service"]

	merge := func(key string) []string {
		var set []string
		for _, v := range append(append([]string(nil), unit[key]...), dropIn[key]...) {
			if v == "" {
				set = nil
				continue
			}
			for _, item := range strings.Fields(v) {
				if !slices.Contains(set, item) {
					set = append(set, item)
				}
			}
		}
		slices.Sort(set)
		return set
	}
	for key, want := range map[string][]string{
		"CapabilityBoundingSet":   {"CAP_NET_ADMIN"},
		"AmbientCapabilities":     {"CAP_NET_ADMIN"},
		"RestrictAddressFamilies": {"AF_INET", "AF_INET6", "AF_NETLINK", "AF_UNIX"},
	} {
		if got := merge(key); !slices.Equal(got, want) {
			t.Errorf("effective %s = %v, want %v", key, got, want)
		}
	}
	// Everything else in the hardening block is untouched: the drop-in sets
	// no other directive, so NoNewPrivileges — which ambient capabilities
	// survive, and which keeps a setuid binary useless — stays on.
	if got := unit["NoNewPrivileges"]; len(got) != 1 || got[0] != "yes" {
		t.Errorf("NoNewPrivileges = %v", got)
	}
}

// TestPacketFilterDropInPassesSystemdAnalyze: systemd reads a drop-in next to
// the unit it verifies and reports a directive it cannot parse against the
// drop-in's own path. A typo there is ignored with a warning at runtime, which
// is the worst way for a grant to fail: the device looks configured and still
// cannot install a firewall.
func TestPacketFilterDropInPassesSystemdAnalyze(t *testing.T) {
	bin, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not available")
	}
	uname, gname := currentUnixNames(t)
	s := baseSpec(t)
	s.User, s.Group, s.BinaryPath, s.PacketFilter = uname, gname, "/bin/sh", true
	s.UnitDir = t.TempDir()
	plan, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	for _, a := range plan.Artifacts {
		if a.Secret {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(a.Path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(a.Path, []byte(a.Content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, runErr := exec.Command(bin, "verify", plan.Spec.UnitPath()).CombinedOutput()
	var mine []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, s.UnitDir) {
			mine = append(mine, line)
		}
	}
	if len(mine) > 0 {
		t.Errorf("systemd-analyze verify objected:\n  %s", strings.Join(mine, "\n  "))
	}
	if runErr != nil && len(mine) == 0 {
		t.Skipf("systemd-analyze could not run here (%v):\n%s", runErr, out)
	}
}

// TestInstallWithholdingThePacketFilterRemovesItsDropIn: re-installing with
// --packet-filter=false must leave a device that cannot install firewalls,
// not one still carrying the drop-in an earlier install or upgrade wrote.
func TestInstallWithholdingThePacketFilterRemovesItsDropIn(t *testing.T) {
	root := t.TempDir()
	in := &Installer{Root: root, Logf: func(string, ...any) {}}

	s := baseSpec(t)
	s.PacketFilter = true
	granted, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Apply(granted); err != nil {
		t.Fatalf("Apply(granted): %v", err)
	}
	dropIn := filepath.Join(root, granted.Spec.PacketFilterDropInPath())
	st, err := os.Stat(dropIn)
	if err != nil {
		t.Fatalf("the granted install wrote no drop-in: %v", err)
	}
	if st.Mode().Perm() != UnitFileMode {
		t.Errorf("drop-in mode = %04o, want %04o", st.Mode().Perm(), UnitFileMode)
	}

	s.PacketFilter = false
	withheld, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Apply(withheld); err != nil {
		t.Fatalf("Apply(withheld): %v", err)
	}
	if _, err := os.Stat(dropIn); !os.IsNotExist(err) {
		t.Errorf("re-installing without the packet filter left its drop-in: %v", err)
	}
	// And it is idempotent: nothing to remove is not an error.
	if err := in.Apply(withheld); err != nil {
		t.Errorf("a second Apply without the packet filter failed: %v", err)
	}
}

// ── Upgrades ────────────────────────────────────────────────────────────────

func (f *upgradeFixture) dropIn() string { return f.spec.PacketFilterDropInPath() }

func (f *upgradeFixture) hasDropIn(t *testing.T) bool {
	t.Helper()
	_, err := os.Stat(f.dropIn())
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

// TestUpgradeGrantsThePacketFilterOnACurrentBinary is sgx's case: the device
// runs the current build and was installed before the installer granted
// CAP_NET_ADMIN. `--upgrade --packet-filter` must write the grant and restart
// the agent even though there is no binary to replace — and a re-run must then
// be the no-op every other upgrade re-run is.
func TestUpgradeGrantsThePacketFilterOnACurrentBinary(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	src := f.newBinary(t, "SAME BUILD")

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, PacketFilter: PacketFilterGrant})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res.AlreadyCurrent || res.BinaryReplaced || !res.BinaryCurrent {
		t.Errorf("AlreadyCurrent=%t BinaryReplaced=%t BinaryCurrent=%t, want a grant with no binary swap",
			res.AlreadyCurrent, res.BinaryReplaced, res.BinaryCurrent)
	}
	if !res.PacketFilterChanged || !res.PacketFilterGranted || !res.Restarted {
		t.Errorf("result = %+v, want the grant written and the agent restarted", res)
	}
	body, err := os.ReadFile(f.dropIn())
	if err != nil {
		t.Fatalf("no drop-in written: %v", err)
	}
	if string(body) != PacketFilterDropIn(f.spec) {
		t.Error("the drop-in is not PacketFilterDropIn's rendering")
	}
	joined := strings.Join(*f.commands, "\n")
	if !strings.Contains(joined, "systemctl daemon-reload") || !strings.Contains(joined, "systemctl try-restart cloop-executor.service") {
		t.Errorf("the grant was not loaded and applied: commands\n%s", joined)
	}
	if got := f.installed(t); got != "SAME BUILD" {
		t.Errorf("binary changed: %q", got)
	}

	*f.commands = nil
	again, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, PacketFilter: PacketFilterGrant})
	if err != nil {
		t.Fatalf("second Upgrade: %v", err)
	}
	if !again.AlreadyCurrent || again.PacketFilterChanged || !again.PacketFilterGranted {
		t.Errorf("a repeat grant is not a no-op: %+v", again)
	}
	if len(*f.commands) != 0 {
		t.Errorf("a repeat grant ran commands: %v", *f.commands)
	}
}

// TestUpgradeKeepsThePacketFilterUnlessAsked: an ordinary upgrade neither adds
// nor removes the grant — what a fleet device may do is not something to change
// as a side effect of replacing its binary — but it does report the state.
func TestUpgradeKeepsThePacketFilterUnlessAsked(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: f.newBinary(t, "NEW BUILD")})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res.PacketFilterChanged || res.PacketFilterGranted || f.hasDropIn(t) {
		t.Errorf("a plain upgrade granted the packet filter: %+v", res)
	}
	if !strings.Contains(PacketFilterHint, "--packet-filter") {
		t.Error("the hint for a device without the grant does not say how to get it")
	}

	mustWrite(t, f.dropIn(), PacketFilterDropIn(f.spec), UnitFileMode)
	res, err = f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: f.newBinary(t, "NEWER BUILD")})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res.PacketFilterChanged || !res.PacketFilterGranted || !f.hasDropIn(t) {
		t.Errorf("a plain upgrade touched an existing grant: %+v", res)
	}
}

// TestUpgradeWithdrawsThePacketFilter: --packet-filter=false removes the
// drop-in and restarts, so the agent stops holding the capability now rather
// than at its next restart.
func TestUpgradeWithdrawsThePacketFilter(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	mustWrite(t, f.dropIn(), PacketFilterDropIn(f.spec), UnitFileMode)

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: f.newBinary(t, "SAME BUILD"), PacketFilter: PacketFilterWithdraw,
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if !res.PacketFilterChanged || res.PacketFilterGranted || f.hasDropIn(t) {
		t.Errorf("withdrawal did not remove the grant: %+v", res)
	}
	if !strings.Contains(strings.Join(*f.commands, "\n"), "try-restart") {
		t.Errorf("withdrawal did not restart the agent: %v", *f.commands)
	}

	// A unit that grants it in the file itself cannot be narrowed by a
	// drop-in, and saying so beats reporting a withdrawal that did nothing.
	inline := strings.Replace(SystemdUnit(f.spec), "AmbientCapabilities=\n", "AmbientCapabilities=CAP_NET_ADMIN\n", 1)
	mustWrite(t, f.spec.UnitPath(), inline, UnitFileMode)
	_, err = f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: f.newBinary(t, "SAME BUILD"), PacketFilter: PacketFilterWithdraw,
	})
	if err == nil || !strings.Contains(err.Error(), "--packet-filter=false") {
		t.Errorf("withdrawing a grant rendered into the unit: err = %v", err)
	}
}

// TestUpgradeGrantRollsBackWhenTheAgentDoesNotComeBack: a grant is a change to
// how the agent starts, so it gets the same guarantee as a binary swap — if
// the agent was running and does not come back, the old configuration is put
// back and the agent restarted on it.
func TestUpgradeGrantRollsBackWhenTheAgentDoesNotComeBack(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	restarted := false
	f.inst.Run = func(name string, args ...string) error {
		*f.commands = append(*f.commands, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if len(args) > 0 && args[0] == "try-restart" {
			restarted = true
		}
		if len(args) > 0 && args[0] == "is-active" && restarted && f.hasDropIn(t) {
			return errors.New("inactive")
		}
		return nil
	}

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: f.newBinary(t, "SAME BUILD"), PacketFilter: PacketFilterGrant, SettleTimeout: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Upgrade = %v, want a rollback", err)
	}
	if !res.RolledBack || res.PacketFilterChanged || res.PacketFilterGranted {
		t.Errorf("result after rollback = %+v", res)
	}
	if f.hasDropIn(t) {
		t.Error("the grant survived its own rollback")
	}
	if !strings.Contains(strings.Join(*f.commands, "\n"), "systemctl restart cloop-executor.service") {
		t.Errorf("the agent was not restarted on the restored configuration: %v", *f.commands)
	}
}

// TestUpgradeGrantWithABinarySwap: both changes in one upgrade land together.
func TestUpgradeGrantWithABinarySwap(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: f.newBinary(t, "NEW BUILD"), PacketFilter: PacketFilterGrant,
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if !res.BinaryReplaced || !res.PacketFilterChanged || !f.hasDropIn(t) || f.installed(t) != "NEW BUILD" {
		t.Errorf("result = %+v", res)
	}
}

// TestUpgradePacketFilterDryRunAndOutputs: a dry run says what it would do and
// writes nothing, and the non-systemd outputs refuse a grant they have no way
// to confine rather than pretending to make one.
func TestUpgradePacketFilterDryRunAndOutputs(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: f.newBinary(t, "SAME BUILD"), PacketFilter: PacketFilterGrant, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if f.hasDropIn(t) || res.PacketFilterChanged || len(*f.commands) != 0 {
		t.Errorf("a dry run changed the device: %+v, commands %v", res, *f.commands)
	}
	if !strings.HasPrefix(res.PacketFilterChange, "would write") {
		t.Errorf("a dry run does not say what it would do: %q", res.PacketFilterChange)
	}

	shell := newUpgradeFixture(t, OutputShell, "SAME BUILD")
	_, err = shell.inst.Upgrade(shell.spec, OutputShell, UpgradeOptions{
		Source: shell.newBinary(t, "NEW BUILD"), PacketFilter: PacketFilterGrant,
	})
	if err == nil || !strings.Contains(err.Error(), "systemd") {
		t.Errorf("a shell-output grant was accepted: %v", err)
	}
	if got := shell.installed(t); got != "SAME BUILD" {
		t.Errorf("a refused grant still replaced the binary: %q", got)
	}
}
