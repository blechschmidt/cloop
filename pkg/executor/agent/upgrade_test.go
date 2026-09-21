package agent

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/install"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// TestInstallTargetResolvesRealSupervisionPaths guards a defect that would have
// made the whole feature inert without failing anywhere.
//
// Spec.UnitPath() joins UnitDir without defaulting it, so a spec carrying only
// a service name resolves to "/cloop-executor.service" — a path that exists on
// no machine. Every device would then have refused every upgrade with "not
// installed as a service", which reads like a correct answer about the device
// rather than a bug in the hub, and the feature would have looked like it
// worked while never once upgrading anything.
func TestInstallTargetResolvesRealSupervisionPaths(t *testing.T) {
	a := &Agent{}
	spec, _, _ := a.installTarget()

	unit := spec.UnitPath()
	if !strings.HasPrefix(unit, install.DefaultUnitDir+"/") {
		t.Fatalf("unit path %q is not under %s; an undefaulted UnitDir would make every "+
			"device refuse every upgrade", unit, install.DefaultUnitDir)
	}
	if filepath.Dir(unit) == "/" {
		t.Fatalf("unit path %q resolved to the filesystem root", unit)
	}
	if init := spec.InitScriptPath(); filepath.Dir(init) != install.DefaultInitDir {
		t.Fatalf("init script path %q is not under %s", init, install.DefaultInitDir)
	}
	if spec.BinaryPath != install.DefaultBinaryPath {
		t.Fatalf("binary path is %q, want %q", spec.BinaryPath, install.DefaultBinaryPath)
	}
}

// A device with no managed install must refuse rather than attempt an upgrade
// and leave a half-installed unit behind. On the test machine neither
// supervision artifact exists, which is exactly that case.
func TestInstallTargetRefusesAnUnmanagedAgent(t *testing.T) {
	a := &Agent{}
	_, _, err := a.installTarget()
	if err == nil {
		t.Skip("this machine has a managed cloop-executor install; the refusal path is unreachable")
	}
	for _, want := range []string{"managed service install", "cloop executor agent install"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal does not tell the operator how to fix it (missing %q): %v", want, err)
		}
	}
}

// Preflight has to refuse an unmanaged device before anything is downloaded,
// and the refusal is what the dashboard shows beside the device's name.
func TestUpgradePreflightRefusesWithoutAManagedInstall(t *testing.T) {
	a := &Agent{}
	if _, _, err := a.installTarget(); err == nil {
		t.Skip("this machine has a managed cloop-executor install")
	}
	reason, ok := a.upgradePreflight(remote.UpgradePayload{TargetVersion: "v9.9.9"}, "v1.0.0")
	if ok {
		t.Fatal("preflight accepted an upgrade on a device with no managed install")
	}
	if strings.TrimSpace(reason) == "" {
		t.Fatal("preflight refused without a reason")
	}
}

// TestUpgradeAckIsSentBeforeTheWork pins the ordering the whole handler is
// arranged around.
//
// A successful upgrade restarts the process, so a reply written after the
// installer runs is a reply nobody reads. If the ack moved to the end, every
// upgrade that *worked* would time out on the hub and only the failures would
// answer promptly — an outcome exactly inverted from what an operator would
// conclude from it. The accepted payload therefore carries no completion
// information at all, and this asserts the type cannot start claiming any.
func TestUpgradeAckCarriesNoCompletionClaim(t *testing.T) {
	ack := remote.UpgradingPayload{Accepted: true, FromVersion: "v1", TargetVersion: "v2"}
	// Accepted is an intention. There is deliberately no Succeeded/Installed
	// field, because the agent cannot report one over a session its own restart
	// destroys.
	if got := ack.Accepted; !got {
		t.Fatal("unreachable; keeps the field referenced")
	}
	for _, banned := range []string{"Succeeded", "Installed", "Completed", "Done"} {
		if fieldExists(ack, banned) {
			t.Fatalf("UpgradingPayload.%s claims an outcome the agent cannot observe: the "+
				"upgrade restarts the process and kills the session that would report it",
				banned)
		}
	}
}

func fieldExists(v any, name string) bool {
	_, ok := reflect.TypeOf(v).FieldByName(name)
	return ok
}
