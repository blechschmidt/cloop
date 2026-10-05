package install

// rollback_test.go: a device refuses to be moved back on main (Task 20380).
//
// Every release and edge build is stamped with its commit's first-parent
// position on main, and the installer refuses a staged build whose sequence is
// lower than the installed binary's — read from what both binaries report when
// run, never from the request. Only AllowRollback, which only a local root
// invocation's --force sets, overrides it; Force, which a request and the hub's
// frame can carry, does not.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/version"
)

const (
	commitA = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"
	commitB = "4453c68e1c2b3a4d5e6f708192a3b4c5d6e7f809"
)

// fakeCloopAt is fakeCloop stamped with a commit and a place on main, the way
// scripts/build-release.sh stamps every build; zero and "" are left out of the
// report as a real build leaves them out.
func fakeCloopAt(version string, protocol int, commit string, sequence int, marker string) string {
	stamp := ""
	if commit != "" {
		stamp += `,"commit":"` + commit + `"`
	}
	if sequence > 0 {
		stamp += fmt.Sprintf(`,"sequence":%d`, sequence)
	}
	return "#!/bin/sh\n" +
		"# cloop-test-marker: " + marker + "\n" +
		"if [ \"$1\" = \"version\" ] && [ \"$2\" = \"--json\" ]; then\n" +
		"  printf '{\"version\":\"" + version + "\",\"protocol\":" + fmt.Sprint(protocol) +
		",\"min_protocol\":1" + stamp + "}\\n'\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = \"version\" ]; then echo \"cloop " + version + "\"; exit 0; fi\n" +
		"exit 0\n"
}

func edgeID(seq, protocol int) BinaryIdentity {
	return BinaryIdentity{Version: "dev+g" + fmt.Sprintf("%07x", seq), Protocol: protocol, MinProtocol: 1,
		Sequence: seq, Structured: true}
}

func releaseID(tag string, seq, protocol int) BinaryIdentity {
	return BinaryIdentity{Version: tag, Protocol: protocol, MinProtocol: 1, Sequence: seq, Structured: true}
}

// TestCheckUpgradeSafetyOrdersBuildsByTheirPlaceOnMain is the rule as a table:
// older edge refused, newer allowed, releases and edge builds ordered against
// each other in both directions, and what a missing sequence means on each
// side.
func TestCheckUpgradeSafetyOrdersBuildsByTheirPlaceOnMain(t *testing.T) {
	for _, c := range []struct {
		name              string
		staged, installed BinaryIdentity
		rollback          bool
	}{
		{"an older edge build at the same protocol", edgeID(4100, 18), edgeID(4150, 18), true},
		{"an older edge build one commit back", edgeID(4149, 18), edgeID(4150, 18), true},
		{"a newer edge build", edgeID(4160, 18), edgeID(4150, 18), false},
		{"the same commit (a reinstall)", edgeID(4150, 18), edgeID(4150, 18), false},
		{"edge to a later release", releaseID("v0.1.0", 4200, 18), edgeID(4150, 18), false},
		{"edge to an earlier release (versions cannot be ordered)", releaseID("v0.1.0", 4100, 18), edgeID(4150, 18), true},
		{"release to a later edge build", edgeID(4210, 18), releaseID("v0.1.0", 4200, 18), false},
		{"release to an earlier edge build", edgeID(4190, 18), releaseID("v0.1.0", 4200, 18), true},
		{"a release of the commit an edge build was made from", releaseID("v0.1.0", 4150, 18), edgeID(4150, 18), false},
		{"a later release", releaseID("v0.2.0", 4300, 18), releaseID("v0.1.0", 4200, 18), false},
		{"an older signed edge build from before sequences (schema 1)", edgeID(0, 18), edgeID(4150, 18), true},
		{"a release from before sequences (v0.0.4)", releaseID("v0.0.4", 0, 13), edgeID(4150, 18), true},
		{"a local build without a stamp over a stamped one", BinaryIdentity{Version: "dev+g1234567.dirty", Protocol: 18,
			Structured: true}, edgeID(4150, 18), true},
		{"the bootstrap: an unsequenced build installed", edgeID(4150, 18), edgeID(0, 18), false},
		{"the bootstrap: an unidentified build installed", edgeID(4150, 18), BinaryIdentity{}, false},
		{"neither carries a sequence", edgeID(0, 18), edgeID(0, 18), false},
		{"a pre-JSON build installed (text identity)", edgeID(4150, 18), BinaryIdentity{Version: "v0.0.1"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := checkUpgradeSafety(c.staged, c.installed, 1)
			if c.rollback {
				if !errors.Is(err, ErrRollback) || !errors.Is(err, ErrDowngrade) {
					t.Fatalf("err = %v, want ErrRollback (and so ErrDowngrade)", err)
				}
				for _, want := range []string{c.staged.Version, "--force", "Only root on this device"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("refusal does not mention %q: %v", want, err)
					}
				}
				return
			}
			if errors.Is(err, ErrRollback) {
				t.Fatalf("refused as a rollback: %v", err)
			}
		})
	}
}

// TestRollbackComesBeforeTheOverridableChecks: a build that is both earlier on
// main and lower in protocol is reported as the rollback, the one Force does
// not override — or a forced request would get past the protocol check and
// never meet the sequence one.
func TestRollbackComesBeforeTheOverridableChecks(t *testing.T) {
	err := checkUpgradeSafety(edgeID(4100, 17), edgeID(4150, 18), 1)
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("err = %v, want ErrRollback first", err)
	}
	// Sequenced and earlier is refused even though both are unreleased and
	// "cannot be ordered" by version, the gap the old guard left.
	if _, ok := version.Compare("dev+g0001004", "dev+g0001036"); ok {
		t.Fatal("fixture: dev builds became orderable by version")
	}
}

// TestUpgradeForceDoesNotRollBackAndAllowRollbackDoes runs the rule through
// Upgrade with real executables: Force — what a request file or the hub's
// frame carries — does not move the device back; AllowRollback, which only
// the CLI's own --force sets, does.
func TestUpgradeForceDoesNotRollBackAndAllowRollbackDoes(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "UNUSED")
	mustWrite(t, f.spec.BinaryPath, fakeCloopAt("dev+g4453c68", 18, commitB, 4150, "NEWER"), BinaryMode)
	src := f.stageBinary(t, fakeCloopAt("dev+ga0f3870", 18, commitA, 4100, "OLDER"))
	var log []string
	f.inst.Logf = func(format string, a ...any) { log = append(log, fmt.Sprintf(format, a...)) }

	for _, opts := range []UpgradeOptions{{Source: src}, {Source: src, Force: true}} {
		_, err := f.inst.Upgrade(f.spec, OutputSystemd, opts)
		if !errors.Is(err, ErrRollback) {
			t.Fatalf("force=%t: err = %v, want ErrRollback", opts.Force, err)
		}
		if got := f.installed(t); got != "NEWER" {
			t.Fatalf("force=%t moved the device back: %q", opts.Force, got)
		}
	}
	if len(*f.commands) != 0 {
		t.Errorf("a refused rollback bounced the service: %v", *f.commands)
	}
	// The journal line an operator finds when the hub's Upgrade did nothing.
	joined := strings.Join(log, "\n")
	if !strings.Contains(joined, "refused:") || !strings.Contains(joined, "sequence 4100 on main") ||
		!strings.Contains(joined, "sequence 4150 on main") || !strings.Contains(joined, "not the hub or the agent") {
		t.Errorf("no journal line names the refusal: %q", joined)
	}

	log = nil
	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, Force: true,
		AllowRollback: true}); err != nil {
		t.Fatalf("a local --force refused the rollback: %v", err)
	}
	if got := f.installed(t); got != "OLDER" {
		t.Errorf("AllowRollback did not install the older build: %q", got)
	}
	if !strings.Contains(strings.Join(log, "\n"), "rolling back from") {
		t.Errorf("the deliberate rollback was not logged: %q", log)
	}
}

// TestUpgradeLogsTheBootstrapAndTheMoveForward: an installed build without a
// sequence is replaced (the bootstrap), and the log says the device enforces
// the order from then on; a move forward names both places.
func TestUpgradeLogsTheBootstrapAndTheMoveForward(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "UNSEQUENCED")
	var log []string
	f.inst.Logf = func(format string, a ...any) { log = append(log, fmt.Sprintf(format, a...)) }
	src := f.stageBinary(t, fakeCloopAt("dev+ga0f3870", 18, commitA, 4100, "FIRST SEQUENCED"))
	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src}); err != nil {
		t.Fatalf("the bootstrap was refused: %v", err)
	}
	if !strings.Contains(strings.Join(log, "\n"), "carries no sequence, so this move cannot be ordered and is allowed") {
		t.Errorf("the bootstrap was not logged: %q", log)
	}

	log = nil
	src = f.stageBinary(t, fakeCloopAt("dev+g4453c68", 18, commitB, 4150, "LATER"))
	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src}); err != nil {
		t.Fatalf("a move forward was refused: %v", err)
	}
	if !strings.Contains(strings.Join(log, "\n"), "moving forward on main, sequence 4100 on main -> sequence 4150 on main") {
		t.Errorf("the move forward was not logged: %q", log)
	}
}

// TestManifestStampBindsTheBinaryToItsManifest: after the signature, the
// binary must report the commit and sequence its signed manifest names — a
// validly signed manifest for commit A paired with a binary of commit B is
// refused, and nothing overrides it.
func TestManifestStampBindsTheBinaryToItsManifest(t *testing.T) {
	everything := UpgradeOptions{Force: true, AllowRollback: true}
	for _, c := range []struct {
		name    string
		binary  string
		commit  string
		seq     int
		refused string
	}{
		{"the build the manifest names", fakeCloopAt("dev+ga0f3870", 18, commitA, 4100, "OK"), commitA, 4100, ""},
		{"another commit's binary, same version prefix", fakeCloopAt("dev+ga0f3870", 18, commitB, 4100, "SWAP"),
			commitA, 4100, "a manifest for one commit paired with a binary of another"},
		{"another place on main", fakeCloopAt("dev+ga0f3870", 18, commitA, 4099, "SWAP"), commitA, 4100,
			"sequence 4099 on main"},
		{"a sequenced manifest, an unstamped binary", fakeCloopAt("dev+ga0f3870", 18, "", 0, "SWAP"), commitA, 4100,
			"no sequence"},
		{"a stamped sequence but no commit", fakeCloopAt("dev+ga0f3870", 18, "", 4100, "SWAP"), commitA, 4100,
			"no commit"},
		{"a schema-1 manifest and a pre-stamp binary", fakeCloopAt("dev+ga0f3870", 18, "", 0, "OK"), commitA, 0, ""},
		{"a schema-1 manifest and a stamped binary", fakeCloopAt("dev+ga0f3870", 18, commitA, 4100, "SWAP"),
			commitA, 0, "names no sequence"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newUpgradeFixture(t, OutputSystemd, "INSTALLED")
			src := f.stageBinary(t, c.binary)
			opts := everything
			opts.Source, opts.ExpectVersion, opts.ExpectCommit, opts.ExpectSequence = src, "dev+ga0f3870", c.commit, c.seq
			_, err := f.inst.Upgrade(f.spec, OutputSystemd, opts)
			if c.refused == "" {
				if err != nil {
					t.Fatalf("refused the build its manifest describes: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrBinaryUnusable) || !strings.Contains(err.Error(), c.refused) {
				t.Fatalf("err = %v, want ErrBinaryUnusable naming %q", err, c.refused)
			}
			if got := f.installed(t); got != "INSTALLED" {
				t.Errorf("the mismatched binary was installed: %q", got)
			}
		})
	}
}

// TestInstalledIdentityFallsBackToThisProcess: the root helper is the
// installed binary. A probe of it that fails must not make the installed build
// look sequence-less — the one case the rollback rule lets through — so the
// helper answers from its own identity.
func TestInstalledIdentityFallsBackToThisProcess(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "UNUSED")
	mustWrite(t, f.spec.BinaryPath, corruptBinary, BinaryMode) // the probe of it fails
	prevRunning, prevSeq, prevCommit := runningBinaryIs, version.Sequence, version.Commit
	t.Cleanup(func() { runningBinaryIs, version.Sequence, version.Commit = prevRunning, prevSeq, prevCommit })
	version.Sequence, version.Commit = "4150", commitB
	runningBinaryIs = func(path string) bool { return path == f.spec.BinaryPath }

	src := f.stageBinary(t, fakeCloopAt("dev+ga0f3870", 18, commitA, 4100, "OLDER"))
	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, Force: true})
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("err = %v, want ErrRollback from this process's own sequence", err)
	}
	if res.InstalledBuild.Sequence != 4150 || res.InstalledBuild.Commit != commitB {
		t.Errorf("installed identity = %+v", res.InstalledBuild)
	}

	// Not the running binary: an unreadable installed build is the bootstrap
	// case, as before — an agent whose binary is broken is the one that most
	// needs replacing.
	runningBinaryIs = func(string) bool { return false }
	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src}); err != nil {
		t.Fatalf("a broken installed binary blocked the upgrade: %v", err)
	}
}

// TestParseVersionJSONReadsTheStamp: the structured identity carries the
// commit and sequence, and a malformed stamp reads as none.
func TestParseVersionJSONReadsTheStamp(t *testing.T) {
	id, ok := parseVersionJSON([]byte(`{"version":"dev+ga0f3870","protocol":18,"min_protocol":1,` +
		`"commit":"` + commitA + `","sequence":4100}`))
	if !ok || id.Commit != commitA || id.Sequence != 4100 {
		t.Fatalf("id = %+v, ok = %t", id, ok)
	}
	if !strings.Contains(id.String(), "sequence 4100 on main") {
		t.Errorf("String() = %q", id.String())
	}
	for _, raw := range []string{
		`{"version":"x","commit":"A0F387","sequence":-3}`,
		`{"version":"x","commit":"not-a-commit","sequence":2147483647}`,
	} {
		id, ok := parseVersionJSON([]byte(raw))
		if !ok || id.Commit != "" || id.Sequence != 0 {
			t.Errorf("%s: a malformed stamp was taken: %+v", raw, id)
		}
	}
}
