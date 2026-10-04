package agent

// selfupgrade_test.go: what the device decides about an upgrade (Task 20376)
// — which targets it installs at all, whether it can carry one out, and that
// an unprivileged agent hands the work to the root helper rather than failing
// after it said yes.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/cosigntest"
	"github.com/blechschmidt/cloop/internal/edgetest"
	"github.com/blechschmidt/cloop/pkg/executor/install"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/provenance"
)

const commit = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"

// deviceAgent is an agent on a staged device, unprivileged, with cosign.
func deviceAgent(t *testing.T, channel provenance.Channel) (*Agent, *edgetest.Device) {
	t.Helper()
	d := edgetest.NewDevice(t, "dev+g06e06ed", 16, channel)
	withPrivilege(t, 995, nil)
	return &Agent{cfg: Config{Channel: channel, InstallTarget: d.Target, UnitActive: helperArmed, Now: func() time.Time {
		return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	}}}, d
}

// helperArmed answers UnitActive for a helper whose path unit is running, so
// no test asks the machine's systemd.
func helperArmed(string) (bool, bool) { return true, true }

// withPrivilege stubs the effective uid and cosign's presence.
func withPrivilege(t *testing.T, euid int, cosign error) {
	t.Helper()
	prevUID, prevCosign := agentEUID, cosignOnPath
	agentEUID = func() int { return euid }
	cosignOnPath = func() error { return cosign }
	t.Cleanup(func() { agentEUID, cosignOnPath = prevUID, prevCosign })
}

func TestCheckTargetIsTheDevicesDecision(t *testing.T) {
	for _, c := range []struct {
		target  string
		channel provenance.Channel
		ok      bool
		is      error
	}{
		{"v0.0.4", provenance.ChannelStable, true, nil},
		{"v0.0.4", provenance.ChannelEdge, true, nil},
		{"latest", provenance.ChannelStable, true, nil},
		{"edge:" + commit, provenance.ChannelEdge, true, nil},
		{"edge:a0f3870", provenance.ChannelEdge, true, nil},
		{"edge:" + commit, provenance.ChannelStable, false, ErrNotOnEdgeChannel},
		{"edge:" + commit, "", false, ErrNotOnEdgeChannel},
		{"edge:zzzzzzz", provenance.ChannelEdge, false, nil},
		{"dev+ga0f3870", provenance.ChannelEdge, false, ErrNotATarget},
		{"https://evil.example/cloop", provenance.ChannelEdge, false, ErrNotATarget},
		{"", provenance.ChannelEdge, false, ErrNotATarget},
	} {
		err := CheckTarget(c.target, c.channel)
		if (err == nil) != c.ok || (c.is != nil && !errors.Is(err, c.is)) {
			t.Errorf("CheckTarget(%q, %q) = %v", c.target, c.channel, err)
		}
	}
}

// TestAgentRefusesEdgeTargetsWithoutOptIn is the device's half of the opt-in:
// the hub is not trusted to have checked, the refusal reaches the hub as the
// reason, and it says the channel is changed on the device and nowhere else.
func TestAgentRefusesEdgeTargetsWithoutOptIn(t *testing.T) {
	a, d := deviceAgent(t, provenance.ChannelStable)
	reason, ok := a.upgradePreflight(remote.UpgradePayload{TargetVersion: "edge:" + commit, Force: true}, "dev+g06e06ed")
	if ok {
		t.Fatal("a device on the stable channel accepted an edge target")
	}
	for _, want := range []string{EdgeOptInCommand, "the hub cannot"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the refusal does not say %q: %s", want, reason)
		}
	}
	if _, err := os.Stat(d.Spec.UpgradeRequestPath()); err == nil {
		t.Error("a request was filed for a refused target")
	}
	// A release is still fine on the stable channel.
	if reason, ok := a.upgradePreflight(remote.UpgradePayload{TargetVersion: "v9.9.9"}, "dev+g06e06ed"); !ok {
		t.Errorf("a release was refused: %s", reason)
	}
}

// TestAgentHandsTheUpgradeToTheHelper: on the edge channel, with the helper
// installed, the agent accepts and files exactly what the frame asked for.
func TestAgentHandsTheUpgradeToTheHelper(t *testing.T) {
	a, d := deviceAgent(t, provenance.ChannelEdge)
	p := remote.UpgradePayload{TargetVersion: "edge:" + commit, SettleSeconds: 45, Reason: "dashboard"}
	if reason, ok := a.upgradePreflight(p, "dev+g06e06ed"); !ok {
		t.Fatalf("preflight refused: %s", reason)
	}
	a.runUpgrade(p, "dev+g06e06ed")

	req, err := install.TakeUpgradeRequest(d.Spec, time.Date(2026, 10, 4, 12, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("no request was filed: %v", err)
	}
	if req.TargetVersion != p.TargetVersion || req.SettleSeconds != 45 || req.Force || req.Reason != "dashboard" {
		t.Errorf("request = %+v, want the frame's fields and nothing else", req)
	}
}

// TestAgentRefusesWhatItCannotCarryOut: no helper and no root, or no cosign —
// refused before the ack, with the step that fixes it.
func TestAgentRefusesWhatItCannotCarryOut(t *testing.T) {
	a, d := deviceAgent(t, provenance.ChannelEdge)
	if err := os.Remove(d.Spec.UpgradeHelperPathUnitPath()); err != nil {
		t.Fatal(err)
	}
	reason, ok := a.upgradePreflight(remote.UpgradePayload{TargetVersion: "v9.9.9"}, "dev+g06e06ed")
	if ok || !strings.Contains(reason, RemoteUpgradeCommand) {
		t.Errorf("no helper, no root: ok=%t, %s", ok, reason)
	}
	if caps := (&Agent{cfg: Config{HostProbes: true, InstallTarget: d.Target, UnitActive: helperArmed}}).Capabilities(); caps.RemoteUpgrade ||
		!strings.Contains(caps.RemoteUpgradeIssue, RemoteUpgradeCommand) {
		t.Errorf("the hello does not carry the reason: %+v", caps)
	}

	withPrivilege(t, 0, nil)
	if _, ok := a.upgradePreflight(remote.UpgradePayload{TargetVersion: "v9.9.9"}, "dev+g06e06ed"); !ok {
		t.Error("an agent running as root was refused")
	}
	withPrivilege(t, 0, errors.New("not found"))
	reason, ok = a.upgradePreflight(remote.UpgradePayload{TargetVersion: "v9.9.9"}, "dev+g06e06ed")
	if ok || !strings.Contains(reason, "cosign is not installed") {
		t.Errorf("no cosign: ok=%t, %s", ok, reason)
	}
}

// TestAgentRefusesWithADisarmedHelper: the helper's files without its path
// unit running would take the request and never act on it; an answer that is
// not a unit state is "cannot tell", which does not refuse.
func TestAgentRefusesWithADisarmedHelper(t *testing.T) {
	a, _ := deviceAgent(t, provenance.ChannelEdge)
	var asked string
	a.cfg.UnitActive = func(unit string) (bool, bool) { asked = unit; return false, true }
	reason, ok := a.upgradePreflight(remote.UpgradePayload{TargetVersion: "v9.9.9"}, "dev+g06e06ed")
	if ok || !strings.Contains(reason, "is not active") || !strings.Contains(reason, "systemctl enable --now cloop-executor-upgrade.path") {
		t.Errorf("a disarmed helper: ok=%t, %s", ok, reason)
	}
	if asked != "cloop-executor-upgrade.path" {
		t.Errorf("asked about %q", asked)
	}
	a.cfg.UnitActive = func(string) (bool, bool) { return false, false }
	if reason, ok := a.upgradePreflight(remote.UpgradePayload{TargetVersion: "v9.9.9"}, "dev+g06e06ed"); !ok {
		t.Errorf("an unknown answer refused the upgrade: %s", reason)
	}
}

// TestAgentRefusesASettleTheHelperWouldDrop: acknowledged here and dropped
// by the helper is the outcome the ack ordering exists to prevent.
func TestAgentRefusesASettleTheHelperWouldDrop(t *testing.T) {
	a, _ := deviceAgent(t, provenance.ChannelEdge)
	reason, ok := a.upgradePreflight(remote.UpgradePayload{TargetVersion: "v9.9.9",
		SettleSeconds: install.MaxSettleSeconds + 1}, "dev+g06e06ed")
	if ok || !strings.Contains(reason, "settle time") {
		t.Errorf("ok=%t, %s", ok, reason)
	}
}

func TestAgentKnowsItAlreadyRunsTheBuild(t *testing.T) {
	a, _ := deviceAgent(t, provenance.ChannelEdge)
	reason, ok := a.upgradePreflight(remote.UpgradePayload{TargetVersion: "edge:" + commit}, "dev+ga0f3870")
	if ok || !strings.Contains(reason, "already running") {
		t.Errorf("ok=%t, %s", ok, reason)
	}
}

func TestHelloReportsTheChannel(t *testing.T) {
	for _, c := range []provenance.Channel{"", provenance.ChannelStable, provenance.ChannelEdge} {
		want := string(c)
		if want == "" {
			want = "stable"
		}
		if got := (&Agent{cfg: Config{Channel: c}}).Capabilities().UpdateChannel; got != want {
			t.Errorf("channel %q reported as %q", c, got)
		}
	}
}

// TestApplyUpgradeRequestIsTheHelpersPath: what the root helper runs. It
// installs the verified edge build over the old one, keeps the old for
// rollback and the drop-ins as they were, and restarts the agent.
func TestApplyUpgradeRequestIsTheHelpersPath(t *testing.T) {
	_, d := deviceAgent(t, provenance.ChannelEdge)
	rel := edgetest.NewRelease(t)
	rel.Publish(t, commit, cosigntest.Edge, 17, "EDGE BUILD")
	dropIns := map[string][]byte{}
	for _, p := range []string{d.Spec.PacketFilterDropInPath(), d.Spec.ChannelDropInPath()} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		dropIns[p] = b
	}
	if err := install.FileUpgradeRequest(d.Spec, install.UpgradeRequest{TargetVersion: "edge:" + commit}); err != nil {
		t.Fatal(err)
	}

	inst, cmds := edgetest.Recorder()
	req, res, staged, err := ApplyUpgradeRequest(d.Spec, install.OutputSystemd, ApplyOptions{
		Installer: inst, Fetch: rel.Options(t),
	})
	if err != nil {
		t.Fatalf("ApplyUpgradeRequest: %v", err)
	}
	if req.TargetVersion != "edge:"+commit || !staged.ProvenanceVerified || staged.Version != "dev+ga0f3870" {
		t.Errorf("req %+v, staged %+v", req, staged)
	}
	if cur, prev := d.Installed(t); cur != "EDGE BUILD" || prev != "INSTALLED" || !res.BinaryReplaced {
		t.Errorf("installed %q, kept %q, result %+v", cur, prev, res)
	}
	for p, want := range dropIns {
		if got, _ := os.ReadFile(p); string(got) != string(want) {
			t.Errorf("%s changed across the upgrade", p)
		}
	}
	if !strings.Contains(strings.Join(cmds(), "\n"), "systemctl try-restart cloop-executor.service") {
		t.Errorf("the agent was not restarted: %v", cmds())
	}
	if _, _, _, err := ApplyUpgradeRequest(d.Spec, install.OutputSystemd, ApplyOptions{Installer: inst}); !errors.Is(err, install.ErrNoRequest) {
		t.Errorf("the request was not consumed: %v", err)
	}
}

// TestApplyUpgradeRequestUsesTheDevicesChannel: a request for an edge build
// on a stable device — what a workload running as the agent's user could
// write — is refused by the helper, which reads the channel from the unit.
func TestApplyUpgradeRequestUsesTheDevicesChannel(t *testing.T) {
	_, d := deviceAgent(t, provenance.ChannelStable)
	rel := edgetest.NewRelease(t)
	rel.Publish(t, commit, cosigntest.Edge, 17, "EDGE BUILD")
	if err := install.FileUpgradeRequest(d.Spec, install.UpgradeRequest{TargetVersion: "edge:" + commit}); err != nil {
		t.Fatal(err)
	}
	inst, _ := edgetest.Recorder()
	_, _, _, err := ApplyUpgradeRequest(d.Spec, install.OutputSystemd, ApplyOptions{Installer: inst, Fetch: rel.Options(t)})
	if !errors.Is(err, ErrNotOnEdgeChannel) {
		t.Fatalf("err = %v, want ErrNotOnEdgeChannel", err)
	}
	if cur, _ := d.Installed(t); cur != "INSTALLED" {
		t.Errorf("the device changed: %q", cur)
	}
}

// TestApplyUpgradeRequestRefusesAnotherSigner: an edge build signed by
// anything but edge.yml on main is refused, and the device is unchanged.
func TestApplyUpgradeRequestRefusesAnotherSigner(t *testing.T) {
	_, d := deviceAgent(t, provenance.ChannelEdge)
	rel := edgetest.NewRelease(t)
	rel.Publish(t, commit, cosigntest.EdgeOtherBranch, 17, "BRANCH BUILD")
	if err := install.FileUpgradeRequest(d.Spec, install.UpgradeRequest{TargetVersion: "edge:" + commit}); err != nil {
		t.Fatal(err)
	}
	inst, _ := edgetest.Recorder()
	_, _, _, err := ApplyUpgradeRequest(d.Spec, install.OutputSystemd, ApplyOptions{Installer: inst, Fetch: rel.Options(t)})
	if !errors.Is(err, provenance.ErrUnverified) {
		t.Fatalf("err = %v, want ErrUnverified", err)
	}
	if cur, _ := d.Installed(t); cur != "INSTALLED" {
		t.Errorf("the device changed: %q", cur)
	}
}

func TestServiceFromCgroup(t *testing.T) {
	for in, want := range map[string]string{
		"0::/system.slice/cloop-executor.service\n":                         "cloop-executor",
		"0::/system.slice/cloop-t20376.service":                             "cloop-t20376",
		"12:pids:/x\n1:name=systemd:/system.slice/cloop-executor.service\n": "cloop-executor",
		"0::/user.slice/user-0.slice/session-4.scope":                       "",
		"0::/system.slice/getty@tty1.service":                               "",
		"0::/":                                                              "",
		"":                                                                  "",
	} {
		if got := serviceFromCgroup(in); got != want {
			t.Errorf("serviceFromCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestOwnInstallIsTheUnitThatRunsThisBinary: an agent is the install whose
// unit runs this very binary as an executor agent — a second service beside
// the default one answers for itself, and a process that only shares a
// service's cgroup is not that service's install (Task 20376).
func TestOwnInstallIsTheUnitThatRunsThisBinary(t *testing.T) {
	dir := t.TempDir()
	unitDir, initDir := filepath.Join(dir, "units"), filepath.Join(dir, "init.d")
	exe := filepath.Join(dir, "cloop-t20376")
	other := filepath.Join(dir, "cloop-latest")
	for _, p := range []string{exe, other} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	unit := func(name, execStart string) {
		t.Helper()
		body := "[Service]\nExecStart=" + execStart + "\n"
		if err := os.WriteFile(filepath.Join(unitDir, name+".service"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	unit("cloop-t20376", exe+" executor agent --server ws://127.0.0.1:18376/api/executors/connect")
	unit("cloop-ui-latest", other+" ui --port 8081")
	unit("cloop-sneaky", exe+" ui --port 1")

	spec, out, err := ownInstall("0::/system.slice/cloop-t20376.service\n", exe, "/var/lib/cloop-t20376/agent.json", unitDir, initDir)
	if err != nil || out != install.OutputSystemd {
		t.Fatalf("own unit: %v (%s)", err, out)
	}
	if spec.ServiceName != "cloop-t20376" || spec.BinaryPath != exe || spec.StateDir != "/var/lib/cloop-t20376" {
		t.Errorf("spec = %+v", spec)
	}
	if spec.UpgradeRequestPath() != "/var/lib/cloop-t20376/upgrade-request.json" {
		t.Errorf("the request would be filed at %s", spec.UpgradeRequestPath())
	}

	for name, cgroup := range map[string]string{
		"another service's cgroup":                    "0::/system.slice/cloop-ui-latest.service",
		"a unit running this binary, not as an agent": "0::/system.slice/cloop-sneaky.service",
		"a transient unit":                            "0::/system.slice/run-u42.service",
		"no service at all":                           "0::/user.slice/user-0.slice/session-4.scope",
	} {
		spec, _, err := ownInstall(cgroup, exe, "", unitDir, initDir)
		if err == nil || !strings.Contains(err.Error(), "managed service install") {
			t.Errorf("%s: err = %v, want a refusal", name, err)
		}
		if spec.ServiceName != install.DefaultServiceName {
			t.Errorf("%s: the refusal still describes %s", name, spec.ServiceName)
		}
	}

	// An init-script install that systemd's SysV generator started runs as
	// <svc>.service with no unit file of its own.
	if err := os.MkdirAll(initDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sysv := install.Spec{ServiceName: "cloop-sysv", BinaryPath: exe, Server: "wss://hub.example/api/agents/connect",
		StateDir: "/var/lib/cloop-sysv", InitDir: initDir}
	if err := os.WriteFile(filepath.Join(initDir, "cloop-sysv"), []byte(install.InitScript(sysv)), 0o755); err != nil {
		t.Fatal(err)
	}
	if spec, out, err := ownInstall("0::/system.slice/cloop-sysv.service", exe, "", unitDir, initDir); err != nil ||
		out != install.OutputShell || spec.ServiceName != "cloop-sysv" {
		t.Errorf("SysV-generated unit: %+v, %s, %v", spec, out, err)
	}
	// ...and only if the script runs this binary.
	sysv.BinaryPath = "/usr/local/bin/someone-else"
	if err := os.WriteFile(filepath.Join(initDir, "cloop-sysv"), []byte(install.InitScript(sysv)), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ownInstall("0::/system.slice/cloop-sysv.service", exe, "", unitDir, initDir); err == nil ||
		!strings.Contains(err.Error(), "does not run this binary") {
		t.Errorf("another binary's init script was taken as this agent's install: %v", err)
	}

	// An init-script install is not under systemd at all.
	if err := os.WriteFile(filepath.Join(initDir, install.DefaultServiceName), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, out, err := ownInstall("0::/", exe, "", unitDir, initDir); err != nil || out != install.OutputShell {
		t.Errorf("init script: %s, %v", out, err)
	}
}
