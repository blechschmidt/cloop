package install

// remoteupgrade_test.go covers the device-side half of the edge channel and of
// remote upgrade (Task 20376): the channel drop-in, the root helper that
// carries out an upgrade the hub asked for, the request file between them, and
// the binding of an installed binary to the version its signature was checked
// for.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provenance"
)

func (f *upgradeFixture) exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

// TestUpgradeChannelEdgeIsADropIn: `--upgrade --channel edge`
// on a current binary writes the drop-in and restarts the agent so it starts
// with the variable; a re-run is a no-op; `--channel stable` takes it out.
func TestUpgradeChannelEdgeIsADropIn(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	src := f.newBinary(t, "SAME BUILD")

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, Channel: provenance.ChannelEdge})
	if err != nil {
		t.Fatalf("Upgrade --channel edge: %v", err)
	}
	if !res.ChannelChanged || res.Channel != provenance.ChannelEdge || !res.Restarted || res.BinaryReplaced {
		t.Errorf("result = %+v, want the channel changed and the agent restarted on the same binary", res)
	}
	body, err := os.ReadFile(f.spec.ChannelDropInPath())
	if err != nil {
		t.Fatalf("no channel drop-in: %v", err)
	}
	if !slices.Contains(unitDirectives(string(body)), "Environment="+ChannelEnv+"=edge") {
		t.Errorf("the drop-in does not set %s=edge:\n%s", ChannelEnv, body)
	}
	if filepath.Base(f.spec.ChannelDropInPath()) != "20-update-channel.conf" ||
		filepath.Dir(f.spec.ChannelDropInPath()) != f.spec.DropInDir() {
		t.Errorf("drop-in at %s", f.spec.ChannelDropInPath())
	}
	if len(res.UnitChanges) != 1 || !strings.Contains(res.UnitChanges[0], "edge channel") {
		t.Errorf("UnitChanges = %q", res.UnitChanges)
	}

	again, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, Channel: provenance.ChannelEdge})
	if err != nil || !again.AlreadyCurrent || again.ChannelChanged || again.Channel != provenance.ChannelEdge {
		t.Errorf("a second --channel edge = %+v, %v; want a no-op that still reports edge", again, err)
	}

	back, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, Channel: provenance.ChannelStable})
	if err != nil || !back.ChannelChanged || back.Channel != provenance.ChannelStable {
		t.Errorf("--channel stable = %+v, %v", back, err)
	}
	if f.exists(t, f.spec.ChannelDropInPath()) {
		t.Error("--channel stable left the drop-in behind")
	}
}

// TestPlainUpgradeKeepsEveryDropIn is the property the task names: an upgrade
// — which is what the hub's Upgrade button ends in — leaves the channel and
// the packet-filter grant exactly as the operator on the device set them.
func TestPlainUpgradeKeepsEveryDropIn(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	mustWrite(t, f.dropIn(), PacketFilterDropIn(f.spec), UnitFileMode)
	mustWrite(t, f.spec.ChannelDropInPath(), ChannelDropIn(f.spec, provenance.ChannelEdge), UnitFileMode)
	before := map[string]string{}
	for _, p := range []string{f.dropIn(), f.spec.ChannelDropInPath()} {
		b, _ := os.ReadFile(p)
		before[p] = string(b)
	}

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: f.newBinary(t, "NEW BUILD")})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if !res.BinaryReplaced || res.ChannelChanged || res.PacketFilterChanged || len(res.UnitChanges) != 0 {
		t.Errorf("result = %+v, want the binary replaced and nothing else", res)
	}
	if res.Channel != provenance.ChannelEdge || !res.PacketFilterGranted {
		t.Errorf("the result does not report the device as it is: channel %q, packet filter %t", res.Channel, res.PacketFilterGranted)
	}
	for p, want := range before {
		got, err := os.ReadFile(p)
		if err != nil || string(got) != want {
			t.Errorf("%s changed across a plain upgrade", p)
		}
	}
	if !f.exists(t, backupPath(f.spec.BinaryPath)) {
		t.Error("the replaced binary was not kept for rollback")
	}
}

// TestUpgradeRemoteUpgradeHelper: --remote-upgrade installs both units and
// arms the path unit; withdrawing disarms it before removing its files.
func TestUpgradeRemoteUpgradeHelper(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	src := f.newBinary(t, "SAME BUILD")

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, RemoteUpgrade: RemoteUpgradeGrant})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !res.RemoteUpgradeChanged || !res.RemoteUpgradeInstalled {
		t.Errorf("result = %+v", res)
	}
	for _, p := range []string{f.spec.UpgradeHelperServicePath(), f.spec.UpgradeHelperPathUnitPath()} {
		if !f.exists(t, p) {
			t.Errorf("%s was not written", p)
		}
	}
	if !slices.Contains(*f.commands, "systemctl enable --now cloop-executor-upgrade.path") {
		t.Errorf("the path unit was not armed: %v", *f.commands)
	}
	if !f.inst.HelperInstalled(f.spec) {
		t.Error("HelperInstalled is false after the grant")
	}

	*f.commands = nil
	res, err = f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, RemoteUpgrade: RemoteUpgradeWithdraw})
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if !res.RemoteUpgradeChanged || res.RemoteUpgradeInstalled || f.inst.HelperInstalled(f.spec) {
		t.Errorf("result = %+v", res)
	}
	disarm := slices.Index(*f.commands, "systemctl disable --now cloop-executor-upgrade.path")
	if disarm < 0 {
		t.Errorf("the path unit was not disarmed: %v", *f.commands)
	}
}

// TestUpgradeChannelRollsBackWithTheBinary: if the agent does not come back,
// the channel goes back along with the binary.
func TestUpgradeChannelRollsBackWithTheBinary(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	restarted := false
	f.inst.Run = func(name string, args ...string) error {
		*f.commands = append(*f.commands, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if len(args) > 0 && args[0] == "try-restart" {
			restarted = true
		}
		if len(args) > 0 && args[0] == "is-active" && restarted && f.installed(t) == "NEW BUILD" {
			return errors.New("inactive")
		}
		return nil
	}
	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: f.newBinary(t, "NEW BUILD"), Channel: provenance.ChannelEdge, SettleTimeout: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Upgrade = %v, want a rollback", err)
	}
	if !res.RolledBack || res.ChannelChanged || res.Channel != provenance.ChannelStable {
		t.Errorf("result after rollback = %+v", res)
	}
	if f.exists(t, f.spec.ChannelDropInPath()) || f.installed(t) != "OLD BUILD" {
		t.Error("the rollback left the new channel or the new binary in place")
	}
}

// TestExpectVersionBindsTheBinaryToItsSignature: an edge build's manifest
// names its version, and a binary that reports another one is refused —
// --force or not, because it is not the build that was verified.
func TestExpectVersionBindsTheBinaryToItsSignature(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, fakeCloop("dev+g1111111", "OTHER BUILD"))
	for _, force := range []bool{false, true} {
		_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
			Source: src, ProvenanceEstablished: true, ExpectVersion: "dev+ga0f3870", Force: force,
		})
		if !errors.Is(err, ErrBinaryUnusable) {
			t.Fatalf("force=%t: a binary reporting another version gave %v, want ErrBinaryUnusable", force, err)
		}
		if f.installed(t) != "OLD BUILD" {
			t.Fatal("the mismatched binary was installed")
		}
	}
	ok := f.stageBinary(t, fakeCloop("dev+ga0f3870", "EDGE BUILD"))
	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: ok, ProvenanceEstablished: true, ExpectVersion: "dev+ga0f3870", Force: true,
	}); err != nil {
		t.Fatalf("the matching binary was refused: %v", err)
	}
	if f.installed(t) != "EDGE BUILD" {
		t.Error("the matching binary was not installed")
	}
}

// TestChannelAndHelperAreSystemdOnly: like the packet filter, the shell output
// has no drop-in and no root helper to put them in.
func TestChannelAndHelperAreSystemdOnly(t *testing.T) {
	shell := newUpgradeFixture(t, OutputShell, "SAME BUILD")
	for _, opts := range []UpgradeOptions{
		{Channel: provenance.ChannelEdge},
		{RemoteUpgrade: RemoteUpgradeGrant},
	} {
		opts.Source = shell.newBinary(t, "NEW BUILD")
		if _, err := shell.inst.Upgrade(shell.spec, OutputShell, opts); err == nil || !strings.Contains(err.Error(), "systemd") {
			t.Errorf("%+v on the shell output: %v", opts, err)
		}
	}
	if shell.installed(t) != "SAME BUILD" {
		t.Error("a refused change still replaced the binary")
	}
}

// TestDeviceChannelIsWhatTheUnitSays: the helper's answer comes from the
// unit's drop-ins, an operator's later override wins, and no file at all is
// the stable channel.
func TestDeviceChannelIsWhatTheUnitSays(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	if c, err := f.inst.DeviceChannel(f.spec); err != nil || c != provenance.ChannelStable {
		t.Errorf("no drop-in: %q, %v", c, err)
	}
	mustWrite(t, f.spec.ChannelDropInPath(), ChannelDropIn(f.spec, provenance.ChannelEdge), UnitFileMode)
	if c, err := f.inst.DeviceChannel(f.spec); err != nil || c != provenance.ChannelEdge {
		t.Errorf("edge drop-in: %q, %v", c, err)
	}
	mustWrite(t, filepath.Join(f.spec.DropInDir(), "override.conf"),
		"[Service]\nEnvironment=\"CLOOP_UPDATE_CHANNEL=stable\"\n", UnitFileMode)
	if c, err := f.inst.DeviceChannel(f.spec); err != nil || c != provenance.ChannelStable {
		t.Errorf("override.conf after the drop-in: %q, %v", c, err)
	}
}

// TestUpgradeRequestRoundTrip covers the file the agent writes and the root
// helper reads.
func TestUpgradeRequestRoundTrip(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	if err := os.MkdirAll(f.spec.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	if _, err := TakeUpgradeRequest(f.spec, now); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("no request: %v", err)
	}
	if err := FileUpgradeRequest(f.spec, UpgradeRequest{
		TargetVersion: "edge:a0f387020b4df29e9f39ebe0369ec0de0ca8c674", SettleSeconds: 45,
		Reason: "requested from the dashboard\nby someone", RequestedAt: now.Add(-time.Minute).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("FileUpgradeRequest: %v", err)
	}
	req, err := TakeUpgradeRequest(f.spec, now)
	if err != nil {
		t.Fatalf("TakeUpgradeRequest: %v", err)
	}
	if req.TargetVersion != "edge:a0f387020b4df29e9f39ebe0369ec0de0ca8c674" || req.SettleSeconds != 45 {
		t.Errorf("request = %+v", req)
	}
	if strings.ContainsAny(req.Reason, "\n\r") {
		t.Errorf("a control character survived into the reason: %q", req.Reason)
	}
	if f.exists(t, f.spec.UpgradeRequestPath()) {
		t.Error("the request was not deleted once taken")
	}

	for name, setup := range map[string]func(){
		"stale": func() {
			_ = FileUpgradeRequest(f.spec, UpgradeRequest{TargetVersion: "v9.9.9",
				RequestedAt: now.Add(-RequestMaxAge - time.Minute).Format(time.RFC3339)})
		},
		"no version": func() {
			_ = FileUpgradeRequest(f.spec, UpgradeRequest{RequestedAt: now.Format(time.RFC3339)})
		},
		"not JSON": func() { mustWrite(t, f.spec.UpgradeRequestPath(), "target=v9", 0o600) },
		"too big": func() {
			mustWrite(t, f.spec.UpgradeRequestPath(), `{"target_version":"`+strings.Repeat("v", 5000)+`"}`, 0o600)
		},
		"a symlink": func() {
			target := filepath.Join(t.TempDir(), "elsewhere.json")
			mustWrite(t, target, `{"target_version":"v9.9.9","requested_at":"`+now.Format(time.RFC3339)+`"}`, 0o600)
			if err := os.Symlink(target, f.spec.UpgradeRequestPath()); err != nil {
				t.Fatal(err)
			}
		},
	} {
		setup()
		if _, err := TakeUpgradeRequest(f.spec, now); err == nil || errors.Is(err, ErrNoRequest) {
			t.Errorf("%s: a bad request was taken (%v)", name, err)
		}
		if _, err := os.Lstat(f.spec.UpgradeRequestPath()); err == nil {
			t.Errorf("%s: the bad request was left for the path unit to trigger on again", name)
		}
	}
}

// TestInstallPlanCarriesTheHelperAndTheChannel: a fresh install writes what
// it is asked for, removes what it is not, and arms the helper.
func TestInstallPlanCarriesTheHelperAndTheChannel(t *testing.T) {
	s := baseSpec(t)
	s.RemoteUpgrade, s.Channel = true, provenance.ChannelEdge
	p, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, a := range p.Artifacts {
		paths = append(paths, a.Path)
	}
	for _, want := range []string{p.Spec.ChannelDropInPath(), p.Spec.UpgradeHelperServicePath(), p.Spec.UpgradeHelperPathUnitPath()} {
		if !slices.Contains(paths, want) {
			t.Errorf("the plan does not write %s", want)
		}
	}
	if !slices.Contains(p.Next, "systemctl enable --now cloop-executor-upgrade.path") {
		t.Errorf("the plan does not arm the helper: %v", p.Next)
	}

	s.RemoteUpgrade, s.Channel = false, ""
	p, err = BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{p.Spec.ChannelDropInPath(), p.Spec.UpgradeHelperServicePath(), p.Spec.UpgradeHelperPathUnitPath()} {
		if !slices.Contains(p.Remove, gone) {
			t.Errorf("a plan without them does not remove %s", gone)
		}
	}
	if _, err := BuildPlan(Spec{Server: "wss://h/x", Channel: "nightly"}, OutputSystemd); err == nil {
		t.Error("an unknown channel was accepted")
	}
}

// TestHelperUnitsAreRootAndBounded pins what the helper runs and may write.
func TestHelperUnitsAreRootAndBounded(t *testing.T) {
	s, err := baseSpec(t).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	svc := UpgradeHelperService(s)
	d := unitDirectives(svc)
	for _, want := range []string{
		"Type=oneshot", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
		"ReadWritePaths=" + filepath.Dir(s.BinaryPath) + " " + s.StateDir,
	} {
		if !slices.Contains(d, want) {
			t.Errorf("the helper unit lacks %q", want)
		}
	}
	for _, line := range d {
		if strings.HasPrefix(line, "User=") {
			t.Errorf("the helper runs as %s; it must be root to replace a root-owned binary", line)
		}
		if strings.HasPrefix(line, "ExecStart=") && !strings.Contains(line, "--apply-request") {
			t.Errorf("the helper does not apply a request: %s", line)
		}
	}
	path := unitDirectives(UpgradeHelperPathUnit(s))
	if !slices.Contains(path, "PathExists="+s.UpgradeRequestPath()) ||
		!slices.Contains(path, "Unit="+s.UpgradeHelperName()+".service") {
		t.Errorf("the path unit does not watch the request: %v", path)
	}
}

// TestHelperUnitsPassSystemdAnalyze: a directive systemd cannot parse is
// ignored at runtime with a warning — a helper that never runs, on a device
// that looks configured.
func TestHelperUnitsPassSystemdAnalyze(t *testing.T) {
	bin, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not available")
	}
	uname, gname := currentUnixNames(t)
	s := baseSpec(t)
	s.User, s.Group, s.BinaryPath = uname, gname, "/bin/sh"
	s.RemoteUpgrade, s.Channel = true, provenance.ChannelEdge
	s.UnitDir = t.TempDir()
	plan, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatal(err)
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
	out, runErr := exec.Command(bin, "verify", plan.Spec.UnitPath(), plan.Spec.UpgradeHelperServicePath(),
		plan.Spec.UpgradeHelperPathUnitPath()).CombinedOutput()
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

// TestUninstallRemovesTheHelper: nothing of the helper outlives the agent.
func TestUninstallRemovesTheHelper(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	mustWrite(t, f.spec.UpgradeHelperServicePath(), UpgradeHelperService(f.spec), UnitFileMode)
	mustWrite(t, f.spec.UpgradeHelperPathUnitPath(), UpgradeHelperPathUnit(f.spec), UnitFileMode)
	if err := f.inst.Uninstall(f.spec, OutputSystemd, false); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if f.inst.HelperInstalled(f.spec) || f.exists(t, f.spec.UpgradeHelperServicePath()) {
		t.Error("the helper survived the uninstall")
	}
	if i := slices.Index(*f.commands, "systemctl disable --now cloop-executor-upgrade.path"); i < 0 ||
		i > slices.Index(*f.commands, "systemctl disable --now cloop-executor.service") {
		t.Errorf("the helper was not disarmed before the agent was stopped: %v", *f.commands)
	}
}
