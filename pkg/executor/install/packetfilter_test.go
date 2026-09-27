package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPacketFilterUnitRelaxesExactlyThreeDirectives: --packet-filter hands the
// agent CAP_NET_ADMIN and netlink and nothing else. The rest of the hardening
// block must come out byte-for-byte as it does without the flag, because a
// flag that quietly loosened a fourth directive would be a hole nobody asked
// for (Task 20345).
func TestPacketFilterUnitRelaxesExactlyThreeDirectives(t *testing.T) {
	s := baseSpec(t)
	plain, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	s.PacketFilter = true
	relaxed, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan(packet filter): %v", err)
	}

	directives := func(unit string) map[string]string {
		out := map[string]string{}
		for _, line := range strings.Split(unit, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
				out[k] = v
			}
		}
		return out
	}
	a, b := directives(plain.Display), directives(relaxed.Display)
	want := map[string]string{
		"CapabilityBoundingSet":   "CAP_NET_ADMIN",
		"AmbientCapabilities":     "CAP_NET_ADMIN",
		"RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX AF_NETLINK",
	}
	for k, v := range b {
		if w, relaxedHere := want[k]; relaxedHere {
			if v != w {
				t.Errorf("%s = %q, want %q", k, v, w)
			}
			continue
		}
		if a[k] != v {
			t.Errorf("--packet-filter changed %s from %q to %q", k, a[k], v)
		}
	}
	if a["NoNewPrivileges"] != "yes" || b["NoNewPrivileges"] != "yes" {
		t.Error("NoNewPrivileges must stay on: ambient capabilities survive it")
	}
	if strings.Contains(relaxed.Display, "AF_PACKET") && !strings.Contains(relaxed.Display, "No AF_PACKET") {
		t.Error("the relaxed unit grants AF_PACKET")
	}
}

// TestPacketFilterUnitPassesSystemdAnalyze: the relaxed directives are ones
// systemd actually parses. A typo in a hardening directive is ignored with a
// warning, which is the worst way for it to fail.
func TestPacketFilterUnitPassesSystemdAnalyze(t *testing.T) {
	bin, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not available")
	}
	uname, gname := currentUnixNames(t)
	s := baseSpec(t)
	s.User, s.Group, s.BinaryPath, s.PacketFilter = uname, gname, "/bin/sh", true
	plan, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	path := filepath.Join(t.TempDir(), plan.Spec.UnitFileName())
	if err := os.WriteFile(path, []byte(plan.Display), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command(bin, "verify", path).CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, path) {
			t.Errorf("systemd-analyze verify: %s", line)
		}
	}
}
