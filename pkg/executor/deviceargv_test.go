package executor

// Tests for DeviceArgv — the translation that makes the hub's own program
// runnable on a machine that is not the hub.
//
// The bug these pin down reached a real fleet and stayed invisible until the
// control plane's binary was renamed. A hub deployed as
// /usr/local/bin/cloop-latest dispatched that path to an enrolled edge device,
// which has cloop at /usr/local/bin/cloop and nothing at all at the path it was
// sent, so the agent refused every workload with
//
//	localprocess: start "/usr/local/bin/cloop-latest": fork/exec
//	/usr/local/bin/cloop-latest: no such file or directory
//
// Every case below is chosen so that it would have failed then.

import (
	"reflect"
	"testing"
)

// isolatedExec is the fake from placement_test.go, given an isolation and —
// deliberately — SharesHostFilesystem true.
//
// That combination is the container driver's, and it is the reason this
// function does not gate on that field: a container's project directory really
// is a bind mount of a host path, and it still cannot exec a binary belonging
// to the hub. A DeviceArgv that consulted SharesHostFilesystem would leave
// every case below untranslated.
func isolatedExec(iso Isolation) Executor {
	return newCapExec("edge-"+string(iso), Capabilities{
		Isolation:            iso,
		SharesHostFilesystem: true,
	})
}

func TestDeviceArgv_HubBinaryPathBecomesABareName(t *testing.T) {
	// The three isolating shapes: a container, a Kata/VM sandbox, and an
	// enrolled remote agent. Each has a filesystem of its own.
	for _, iso := range []Isolation{IsolationContainer, IsolationVM, IsolationRemote} {
		t.Run(string(iso), func(t *testing.T) {
			// The exact argv this hub dispatched, and the exact path the agent
			// then could not find.
			spec := Spec{Argv: []string{"/usr/local/bin/cloop-latest", "run"}}
			DeviceArgv(&spec, isolatedExec(iso))

			want := []string{HarnessProgram, "run"}
			if !reflect.DeepEqual(spec.Argv, want) {
				t.Errorf("DeviceArgv produced %q, want %q — an absolute control-plane "+
					"path does not exist on an isolated executor", spec.Argv, want)
			}
		})
	}
}

func TestDeviceArgv_DoesNotCarryTheHubsSpellingAcross(t *testing.T) {
	// The obvious alternative implementation is filepath.Base, and it fails
	// exactly the case this whole file is about: the far side has never heard
	// of "cloop-latest" either. What travels is the program's identity, not
	// this host's name for it.
	spec := Spec{Argv: []string{"/opt/cloop/releases/2026-09-21/cloop-latest", "run"}}
	DeviceArgv(&spec, isolatedExec(IsolationRemote))

	if spec.Argv[0] != HarnessProgram {
		t.Errorf("DeviceArgv produced argv[0] %q; a device resolves %q on its PATH and "+
			"nothing else", spec.Argv[0], HarnessProgram)
	}
}

func TestDeviceArgv_LeavesTheArgumentsAlone(t *testing.T) {
	// Only the program is this host's; every argument after it is the
	// workload's own and means the same thing everywhere. Rewriting one would
	// be a far quieter bug than the one this function fixes.
	spec := Spec{Argv: []string{"/usr/local/bin/cloop-latest", "task", "reproduce-exec",
		"--prompt-file", "/workspace/.cloop/prompt"}}
	DeviceArgv(&spec, isolatedExec(IsolationRemote))

	want := []string{HarnessProgram, "task", "reproduce-exec", "--prompt-file", "/workspace/.cloop/prompt"}
	if !reflect.DeepEqual(spec.Argv, want) {
		t.Errorf("DeviceArgv produced %q, want %q", spec.Argv, want)
	}
}

func TestDeviceArgv_KeepsTheAbsolutePathOnTheHubItself(t *testing.T) {
	// localprocess runs in the control plane's own filesystem, where the
	// absolute path is strictly better: it pins the binary the hub is actually
	// running rather than whichever one PATH finds. This host has two.
	spec := Spec{Argv: []string{"/usr/local/bin/cloop-latest", "run"}}
	DeviceArgv(&spec, newCapExec("local", Capabilities{
		Isolation:            IsolationNone,
		SharesHostFilesystem: true,
	}))

	if got := spec.Argv[0]; got != "/usr/local/bin/cloop-latest" {
		t.Errorf("DeviceArgv rewrote argv[0] to %q on an unisolated executor; the hub's "+
			"own path is the more precise answer there", got)
	}
}

func TestDeviceArgv_IsIdempotentAndLeavesBareNamesAlone(t *testing.T) {
	// A second application must not corrupt the first, and a caller that
	// already passed a bare name — the reproduce runner's fallback does —
	// must not be disturbed.
	ex := isolatedExec(IsolationRemote)

	twice := Spec{Argv: []string{"/usr/local/bin/cloop-latest", "run"}}
	DeviceArgv(&twice, ex)
	DeviceArgv(&twice, ex)
	if want := []string{HarnessProgram, "run"}; !reflect.DeepEqual(twice.Argv, want) {
		t.Errorf("applying DeviceArgv twice produced %q, want %q", twice.Argv, want)
	}

	bare := Spec{Argv: []string{"cloop", "run"}}
	DeviceArgv(&bare, ex)
	if want := []string{"cloop", "run"}; !reflect.DeepEqual(bare.Argv, want) {
		t.Errorf("DeviceArgv disturbed an already-relative program: %q, want %q", bare.Argv, want)
	}
}

func TestDeviceArgv_DoesNotMutateTheCallersSlice(t *testing.T) {
	// Callers build argv once and keep it for their own labels and logging,
	// and a driver may retain the Spec it was handed. Writing through the
	// shared backing array would rewrite argv[0] underneath both.
	argv := []string{"/usr/local/bin/cloop-latest", "run"}
	spec := Spec{Argv: argv}
	DeviceArgv(&spec, isolatedExec(IsolationRemote))

	if argv[0] != "/usr/local/bin/cloop-latest" {
		t.Errorf("DeviceArgv mutated the caller's slice: argv[0] is now %q", argv[0])
	}
}

func TestDeviceArgv_ToleratesNothingToDo(t *testing.T) {
	// A nil spec and an empty argv both reach here from defensive call sites;
	// neither may panic, because the alternative to translating is dispatching,
	// not crashing the control plane.
	DeviceArgv(nil, isolatedExec(IsolationRemote))

	empty := Spec{}
	DeviceArgv(&empty, isolatedExec(IsolationRemote))
	if len(empty.Argv) != 0 {
		t.Errorf("DeviceArgv invented an argv: %q", empty.Argv)
	}

	// A nil executor is the fail-closed case IsolatesFromHost already defines
	// as "not isolated". Translating for one would be guessing.
	nilEx := Spec{Argv: []string{"/usr/local/bin/cloop-latest", "run"}}
	DeviceArgv(&nilEx, nil)
	if nilEx.Argv[0] != "/usr/local/bin/cloop-latest" {
		t.Errorf("DeviceArgv translated for a nil executor: %q", nilEx.Argv)
	}
}
