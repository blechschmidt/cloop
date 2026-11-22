package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// unitWithoutLandlock is the unit a release before Task 49 rendered: this one
// with the Landlock allow-list taken out. The fixtures use it to stand for a
// device installed then, which is every device the installer has produced.
func unitWithoutLandlock(s Spec) string {
	var keep []string
	for _, line := range strings.Split(SystemdUnit(s), "\n") {
		if strings.TrimSpace(line) == hostSandboxDirective {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

// TestGeneratedUnitAllowsTheLandlockCalls: the agent builds a payload's
// confinement with Landlock, and @system-service does not cover those three
// calls — so a unit that does not name them makes the agent refuse every
// payload the hub asks it to confine, on a kernel that is perfectly capable.
func TestGeneratedUnitAllowsTheLandlockCalls(t *testing.T) {
	plan, err := BuildPlan(baseSpec(t), OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	filters := parseUnitFile(t, plan.Display)["Service"]["SystemCallFilter"]
	if !slices.Contains(filters, "@system-service") {
		t.Errorf("SystemCallFilter = %v, want the standard service set among them", filters)
	}
	if !slices.Contains(filters, landlockSyscalls) {
		t.Errorf("SystemCallFilter = %v, want %q among them", filters, landlockSyscalls)
	}
	// Three names, not systemd's @sandbox set, which would also allow
	// seccomp(2) — a call the agent never makes.
	for _, call := range []string{"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"} {
		if !strings.Contains(landlockSyscalls, call) {
			t.Errorf("the grant does not name %s", call)
		}
	}
	if strings.Contains(landlockSyscalls, "seccomp") || strings.Contains(landlockSyscalls, "@") {
		t.Errorf("the grant is %q, want exactly the three Landlock calls", landlockSyscalls)
	}
	// Both lines are allow-lists, so systemd merges them into the union: the
	// grant adds to @system-service rather than replacing it. An inverted
	// list (~) would subtract instead, which is why the form is checked.
	for _, f := range filters {
		if strings.HasPrefix(f, "~") {
			t.Errorf("SystemCallFilter=%s subtracts; the grant only merges with an allow-list", f)
		}
	}
}

// TestGeneratedUnitWithLandlockPassesSystemdAnalyze: a directive systemd cannot
// parse is silently ignored, so the grant has to be checked by the real parser
// — including that it knows these syscall names.
func TestGeneratedUnitWithLandlockPassesSystemdAnalyze(t *testing.T) {
	bin, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not available")
	}
	uname, gname := currentUnixNames(t)
	s := baseSpec(t)
	s.User, s.Group = uname, gname
	s.BinaryPath = "/bin/sh"
	plan, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, plan.Spec.UnitFileName())
	if err := os.WriteFile(path, []byte(plan.Display), 0o644); err != nil {
		t.Fatalf("write unit: %v", err)
	}
	dropInDir := path + ".d"
	if err := os.MkdirAll(dropInDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dropInDir, hostSandboxDropInName),
		[]byte(HostSandboxDropIn(plan.Spec)), 0o644); err != nil {
		t.Fatalf("write drop-in: %v", err)
	}

	out, runErr := exec.Command(bin, "verify", path).CombinedOutput()
	var mine []string
	for _, line := range strings.Split(string(out), "\n") {
		// systemd names the unit by its file path and a drop-in by its own,
		// so either naming this temporary directory is a complaint about what
		// this test wrote.
		if strings.Contains(line, dir) {
			mine = append(mine, line)
		}
	}
	if len(mine) > 0 {
		t.Errorf("systemd-analyze verify rejected the unit or its drop-in:\n  %s", strings.Join(mine, "\n  "))
	}
	if runErr != nil && len(mine) == 0 {
		t.Skipf("systemd-analyze could not run here (%v):\n%s", runErr, out)
	}
}

// TestLandlockDropInGrantsExactlyOneThing: the drop-in is the unit's grant and
// nothing else, so laying it over a unit from any release cannot change what
// else that unit hardened.
func TestLandlockDropInGrantsExactlyOneThing(t *testing.T) {
	s, err := baseSpec(t).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	sections := parseUnitFile(t, HostSandboxDropIn(s))
	if len(sections) != 1 || sections["Service"] == nil {
		t.Fatalf("drop-in sections = %v, want only [Service]", sections)
	}
	svc := sections["Service"]
	if len(svc) != 1 || len(svc["SystemCallFilter"]) != 1 {
		t.Fatalf("drop-in sets %v, want one SystemCallFilter", svc)
	}
	if got := svc["SystemCallFilter"][0]; got != landlockSyscalls {
		t.Errorf("SystemCallFilter = %q, want %q", got, landlockSyscalls)
	}
	// It must not restate SystemCallErrorNumber or anything else the unit
	// already sets: a drop-in that repeated the hardening would freeze this
	// release's version of it onto a device an older one installed.
	if strings.Contains(HostSandboxDropIn(s), "SystemCallErrorNumber") {
		t.Error("the drop-in restates SystemCallErrorNumber")
	}
	if dropIn := s.HostSandboxDropInPath(); dropIn !=
		"/etc/systemd/system/cloop-executor.service.d/11-host-sandbox.conf" {
		t.Errorf("drop-in path = %q", dropIn)
	}
}

// TestFullInstallCarriesTheGrantInTheUnit: a full install needs no drop-in —
// its unit has the grant — and removes one an upgrade wrote onto the unit it
// replaces, so the device is left with one statement of the fact.
func TestFullInstallCarriesTheGrantInTheUnit(t *testing.T) {
	plan, err := BuildPlan(baseSpec(t), OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	dropIn := plan.Spec.HostSandboxDropInPath()
	for _, a := range plan.Artifacts {
		if a.Path == dropIn {
			t.Error("a full install writes the drop-in as well as the grant in its unit")
		}
	}
	if !slices.Contains(plan.Remove, dropIn) {
		t.Errorf("a full install leaves a stale drop-in behind: Remove = %v", plan.Remove)
	}
	if !unitGrantsLandlock(plan.Display) {
		t.Error("unitGrantsLandlock does not recognise the unit this release renders")
	}
	if unitGrantsLandlock(unitWithoutLandlock(plan.Spec)) {
		t.Error("unitGrantsLandlock recognises a unit that does not carry the grant")
	}
}

// TestUpgradeGrantsLandlockOnAnOlderUnit is sgx's case, and the reason the
// drop-in exists: the device runs the current build on a unit rendered before
// the grant, so no binary changes and the device still cannot confine a
// payload. An upgrade writes the grant and restarts the agent — unasked,
// because the three calls take rights away from what the agent starts rather
// than granting it any, and because every project on the device is refused
// until it has them.
func TestUpgradeGrantsLandlockOnAnOlderUnit(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	mustWrite(t, f.spec.UnitPath(), unitWithoutLandlock(f.spec), UnitFileMode)
	src := f.newBinary(t, "SAME BUILD")

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res.AlreadyCurrent || res.BinaryReplaced || !res.BinaryCurrent {
		t.Errorf("AlreadyCurrent=%t BinaryReplaced=%t BinaryCurrent=%t, want the grant with no binary swap",
			res.AlreadyCurrent, res.BinaryReplaced, res.BinaryCurrent)
	}
	if !res.Restarted {
		t.Error("the agent was not restarted, so it keeps refusing confined payloads until it is")
	}
	body, err := os.ReadFile(f.spec.HostSandboxDropInPath())
	if err != nil {
		t.Fatalf("no drop-in written: %v", err)
	}
	if string(body) != HostSandboxDropIn(f.spec) {
		t.Error("the drop-in is not HostSandboxDropIn's rendering")
	}
	said := strings.Join(res.UnitChanges, "\n")
	if !strings.Contains(said, f.spec.HostSandboxDropInPath()) || !strings.Contains(said, "Landlock") {
		t.Errorf("the upgrade did not say what it changed: %v", res.UnitChanges)
	}
	joined := strings.Join(*f.commands, "\n")
	if !strings.Contains(joined, "systemctl daemon-reload") {
		t.Errorf("the grant was not loaded: commands\n%s", joined)
	}
	// And the packet filter is untouched by it: the two grants are separate
	// files and separate decisions.
	if res.PacketFilterChanged || f.hasDropIn(t) {
		t.Error("the Landlock grant dragged the packet-filter grant along with it")
	}

	// Twice over, nothing happens: a prose change in the drop-in is not worth
	// restarting a device that is working.
	*f.commands = nil
	again, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err != nil {
		t.Fatalf("second Upgrade: %v", err)
	}
	if !again.AlreadyCurrent || len(again.UnitChanges) != 0 || len(*f.commands) != 0 {
		t.Errorf("a repeat upgrade is not a no-op: %+v, commands %v", again, *f.commands)
	}
}

// TestUpgradeWritesNoLandlockDropInOnACurrentUnit: a device installed by this
// release carries the grant in its unit, so there is nothing beside it to
// write — and an ordinary upgrade stays the no-op it has always been.
func TestUpgradeWritesNoLandlockDropInOnACurrentUnit(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: f.newBinary(t, "SAME BUILD")})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if !res.AlreadyCurrent {
		t.Errorf("an upgrade of a current device changed something: %+v", res)
	}
	if _, err := os.Stat(f.spec.HostSandboxDropInPath()); !os.IsNotExist(err) {
		t.Errorf("the drop-in was written onto a unit that already grants the calls (%v)", err)
	}
	if len(*f.commands) != 0 {
		t.Errorf("commands ran: %v", *f.commands)
	}
}

// TestUpgradeDryRunPlansTheLandlockGrantWithoutWritingIt: --dry-run is where an
// operator finds out what an upgrade would do to a device, so the grant has to
// appear there and nowhere else.
func TestUpgradeDryRunPlansTheLandlockGrantWithoutWritingIt(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	mustWrite(t, f.spec.UnitPath(), unitWithoutLandlock(f.spec), UnitFileMode)

	res, err := f.inst.Upgrade(f.spec, OutputSystemd,
		UpgradeOptions{Source: f.newBinary(t, "SAME BUILD"), DryRun: true})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	said := strings.Join(res.UnitChanges, "\n")
	if !strings.Contains(said, "would write") || !strings.Contains(said, f.spec.HostSandboxDropInPath()) {
		t.Errorf("a dry run did not plan the grant: %v", res.UnitChanges)
	}
	if _, err := os.Stat(f.spec.HostSandboxDropInPath()); !os.IsNotExist(err) {
		t.Errorf("a dry run wrote the drop-in (%v)", err)
	}
	if len(*f.commands) != 0 {
		t.Errorf("a dry run ran commands: %v", *f.commands)
	}
}

// TestUpgradeRollsBackTheLandlockGrantWhenTheAgentDoesNotComeBack: the grant is
// part of the set that goes back with the binary. A device that will not start
// under it must be left as it was, not left with a drop-in and a dead agent.
func TestUpgradeRollsBackTheLandlockGrantWhenTheAgentDoesNotComeBack(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	mustWrite(t, f.spec.UnitPath(), unitWithoutLandlock(f.spec), UnitFileMode)
	// Running before the change, and never active again after it.
	calls := 0
	f.inst.Run = func(name string, args ...string) error {
		cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
		*f.commands = append(*f.commands, cmd)
		if strings.Contains(cmd, "is-active") {
			calls++
			if calls > 1 {
				return exec.ErrNotFound
			}
		}
		return nil
	}

	_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: f.newBinary(t, "SAME BUILD"), SettleTimeout: 1,
	})
	if err == nil {
		t.Fatal("Upgrade reported success though the agent never came back")
	}
	if _, serr := os.Stat(f.spec.HostSandboxDropInPath()); !os.IsNotExist(serr) {
		t.Errorf("the drop-in survived a rollback (%v)", serr)
	}
}

// TestLandlockGrantIsSystemdOnly: the init script filters no syscalls and a
// containerised agent is held by its engine's seccomp profile, which this
// installer does not write. Either way there is no drop-in to put beside it.
func TestLandlockGrantIsSystemdOnly(t *testing.T) {
	for _, out := range []Output{OutputShell, OutputDocker} {
		s := baseSpec(t)
		p, err := BuildPlan(s, out)
		if err != nil {
			t.Fatalf("BuildPlan(%s): %v", out, err)
		}
		for _, a := range p.Artifacts {
			if strings.HasSuffix(a.Path, hostSandboxDropInName) {
				t.Errorf("--output %s writes a systemd drop-in", out)
			}
		}
		norm, err := s.Normalize()
		if err != nil {
			t.Fatal(err)
		}
		in := &Installer{Run: func(string, ...string) error { return nil }, Logf: func(string, ...any) {}}
		change, err := in.planHostSandbox(norm, out)
		if err != nil {
			t.Fatalf("planHostSandbox(%s): %v", out, err)
		}
		if change != nil {
			t.Errorf("--output %s plans a drop-in: %+v", out, change)
		}
	}
}
