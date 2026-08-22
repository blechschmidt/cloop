package install

// The properties asserted here are the ones an operator cannot check by eye on
// the tenth device:
//
//   - the generated unit is something systemd will actually load (a typo in a
//     hardening directive does not fail loudly, it silently does nothing —
//     TestGeneratedUnitPassesSystemdAnalyze caught exactly that with
//     RestrictNamespaces);
//   - the enrollment token is never legible to another local user;
//   - uninstall leaves nothing behind, however many times it is run.

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// testToken is a recognisable string so an assertion that it is absent from a
// file cannot pass by accident.
const testToken = "TOKEN-CANARY-4f3a9c1e"

// testBundle builds an encoded bundle carrying testToken.
func testBundle(t *testing.T) string {
	t.Helper()
	b := remote.Bundle{
		Server:       "wss://hub.example.com/api/executors/connect",
		Token:        testToken,
		Pin:          "sha256:qUqP5cyxm6YcTAhz05Hph5gvu9M=",
		EnrollmentID: "enr_test",
		Name:         "edge-1",
		ExpiresAt:    time.Unix(1700000000, 0).UTC(),
	}
	enc, err := b.Encode()
	if err != nil {
		t.Fatalf("encode bundle: %v", err)
	}
	return enc
}

// baseSpec is a spec whose paths are all absolute and whose binary exists, so
// preflight-style checks are not what a test is measuring.
func baseSpec(t *testing.T) Spec {
	t.Helper()
	return Spec{
		Server:     "wss://hub.example.com/api/executors/connect",
		Token:      testToken,
		BinaryPath: "/usr/local/bin/cloop",
	}
}

// ── The unit is loadable ────────────────────────────────────────────────────

// TestGeneratedUnitPassesSystemdAnalyze runs the real parser where one exists.
//
// This is worth the environment dependency: `systemd-analyze verify` is the
// only thing that knows RestrictNamespaces takes "user" and not
// "CLONE_NEWUSER", and a directive systemd cannot parse is silently ignored —
// so the failure mode is a unit that looks hardened and is not.
func TestGeneratedUnitPassesSystemdAnalyze(t *testing.T) {
	bin, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not available; TestGeneratedUnitParses covers the structure")
	}

	// systemd-analyze objects to a User= that does not resolve and to the
	// "special" accounts, so borrow this process's own identity.
	uname, gname := currentUnixNames(t)

	s := baseSpec(t)
	s.User, s.Group = uname, gname
	// It also refuses an ExecStart that is not executable, which says nothing
	// about the unit's syntax.
	s.BinaryPath = "/bin/sh"

	plan, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	// Normalize has run inside BuildPlan, so take the resolved name: an
	// un-normalized spec has none, and systemd rejects a bare ".service".
	dir := t.TempDir()
	path := filepath.Join(dir, plan.Spec.UnitFileName())
	if err := os.WriteFile(path, []byte(plan.Display), 0o644); err != nil {
		t.Fatalf("write unit: %v", err)
	}

	out, runErr := exec.Command(bin, "verify", path).CombinedOutput()
	// Diagnostics about OTHER units come from systemd-analyze resolving the
	// host's dependency graph; only lines naming our file are ours.
	var mine []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, path) {
			mine = append(mine, line)
		}
	}
	if len(mine) > 0 {
		t.Errorf("systemd-analyze verify rejected the generated unit:\n  %s", strings.Join(mine, "\n  "))
	}
	if runErr != nil && len(mine) == 0 {
		// A sandbox with no /run/systemd fails before reading the file at
		// all. That is an environment limitation, not a defect in the unit.
		t.Skipf("systemd-analyze could not run here (%v):\n%s", runErr, out)
	}
}

// currentUnixNames returns names systemd will accept for User=/Group=.
func currentUnixNames(t *testing.T) (string, string) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip("cannot resolve the current user")
	}
	uname := u.Username
	gname := uname
	if g, gerr := user.LookupGroupId(u.Gid); gerr == nil {
		gname = g.Name
	}
	if validateUnixName("--user", uname) != nil || validateUnixName("--group", gname) != nil {
		t.Skipf("current identity %q/%q is not a plain unix name", uname, gname)
	}
	return uname, gname
}

// TestGeneratedUnitParses is the environment-independent half: the unit is
// well-formed INI, every directive lands in a section, and the hardening block
// is actually present rather than merely intended.
func TestGeneratedUnitParses(t *testing.T) {
	s := baseSpec(t)
	s.Labels = map[string]string{"zone": "eu", "arch": "arm64"}
	s.MaxConcurrent = 2

	unit, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	sections := parseUnitFile(t, unit.Display)

	for _, want := range []string{"Unit", "Service", "Install"} {
		if _, ok := sections[want]; !ok {
			t.Errorf("generated unit has no [%s] section", want)
		}
	}
	if got := sections["Install"]["WantedBy"]; len(got) != 1 || got[0] != "multi-user.target" {
		t.Errorf("WantedBy = %v, want [multi-user.target]", got)
	}
	if got := sections["Service"]["Restart"]; len(got) != 1 || got[0] != "always" {
		t.Errorf("Restart = %v, want [always] — an edge device must come back after a crash", got)
	}

	// Every hardening directive the package claims to emit must be in the
	// [Service] section with the value it declared.
	for _, h := range hardening {
		key, value, _ := strings.Cut(h.directive, "=")
		got, ok := sections["Service"][key]
		if !ok {
			t.Errorf("hardening directive %s is missing from [Service]", key)
			continue
		}
		if got[len(got)-1] != value {
			t.Errorf("%s = %q, want %q", key, got[len(got)-1], value)
		}
	}

	// Labels are sorted, so two renders of the same spec are byte-identical
	// and a config-management run does not restart the fleet.
	exec := sections["Service"]["ExecStart"][0]
	if i, j := strings.Index(exec, "arch=arm64"), strings.Index(exec, "zone=eu"); i < 0 || j < 0 || i > j {
		t.Errorf("labels are not emitted in sorted order: %s", exec)
	}
	again, _ := BuildPlan(s, OutputSystemd)
	if again.Display != unit.Display {
		t.Error("two renders of the same spec differ — the output is not deterministic")
	}
}

// parseUnitFile is a minimal systemd unit parser: enough to prove the file is
// structurally sound without depending on systemd being installed.
func parseUnitFile(t *testing.T, body string) map[string]map[string][]string {
	t.Helper()
	out := map[string]map[string][]string{}
	section := ""
	for i, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				t.Fatalf("line %d: malformed section header %q", i+1, line)
			}
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if section == "" {
				t.Fatalf("line %d: empty section name", i+1)
			}
			if _, dup := out[section]; dup {
				t.Fatalf("line %d: section [%s] appears twice", i+1, section)
			}
			out[section] = map[string][]string{}
			continue
		}
		if section == "" {
			t.Fatalf("line %d: directive %q before any section header", i+1, line)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("line %d: %q is not a key=value directive", i+1, line)
		}
		if strings.TrimSpace(key) != key || key == "" {
			t.Fatalf("line %d: malformed directive key %q", i+1, key)
		}
		out[section][key] = append(out[section][key], value)
	}
	return out
}

// ── The token stays private ─────────────────────────────────────────────────

// TestTokenNeverAppearsInExecStartOrWorldReadableFiles is the security
// invariant the whole package is arranged around.
//
// A unit file is world-readable, and `systemctl show` prints ExecStart to any
// local user. So the token may exist in exactly one place on the device: a
// 0600 file owned by the service account.
func TestTokenNeverAppearsInExecStartOrWorldReadableFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec func(Spec) Spec
	}{
		{"bare token", func(s Spec) Spec { return s }},
		{"bundle", func(s Spec) Spec {
			s.Token = ""
			s.Bundle = testBundle(t)
			return s
		}},
		{"custom credentials file", func(s Spec) Spec {
			s.CredentialsFile = "/etc/cloop/enrollment"
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, out := range []Output{OutputSystemd, OutputShell, OutputDocker} {
				plan, err := BuildPlan(tc.spec(baseSpec(t)), out)
				if err != nil {
					t.Fatalf("BuildPlan(%s): %v", out, err)
				}
				if strings.Contains(plan.Display, testToken) {
					t.Errorf("%s: the rendered artifact contains the enrollment token — "+
						"it would be readable by every local user", out)
				}

				root := t.TempDir()
				inst := &Installer{Root: root}
				if err := inst.Apply(plan); err != nil {
					t.Fatalf("Apply(%s): %v", out, err)
				}
				assertTokenOnlyInPrivateFile(t, root, plan)
			}
		})
	}
}

// assertTokenOnlyInPrivateFile walks the staged tree and proves the token
// appears in exactly one file, at mode 0600.
func assertTokenOnlyInPrivateFile(t *testing.T, root string, plan Plan) {
	t.Helper()

	// The needles are whichever credential forms this plan actually carries.
	// An empty string would match every file, so building the list by
	// filtering is load-bearing rather than tidiness.
	var needles []string
	for _, n := range []string{plan.Spec.Token, plan.Spec.Bundle} {
		if n != "" {
			needles = append(needles, n)
		}
	}
	if len(needles) == 0 {
		t.Fatal("the plan carries no credential material; this test would be vacuous")
	}
	holdsSecret := func(body string) bool {
		for _, n := range needles {
			if strings.Contains(body, n) {
				return true
			}
		}
		return false
	}

	credPath := filepath.Join(root, plan.Spec.CredentialsFile)
	blob, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatalf("the credentials file was not written to %s: %v", plan.Spec.CredentialsFile, err)
	}
	// Without this the "token is absent everywhere else" assertion below
	// would pass vacuously on a plan that simply never wrote it.
	if !holdsSecret(string(blob)) {
		t.Fatalf("%s holds neither the token nor the bundle; the rest of this test would be vacuous",
			plan.Spec.CredentialsFile)
	}

	found := 0
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		body, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		if !holdsSecret(string(body)) {
			return nil
		}
		found++
		info, statErr := os.Stat(p)
		if statErr != nil {
			return statErr
		}
		if perm := info.Mode().Perm(); perm != CredentialFileMode {
			t.Errorf("%s holds the enrollment token at mode %04o, want %04o",
				strings.TrimPrefix(p, root), perm, CredentialFileMode)
		}
		if rel := strings.TrimPrefix(p, root); rel != plan.Spec.CredentialsFile {
			t.Errorf("the enrollment token leaked into %s; it belongs only in %s",
				rel, plan.Spec.CredentialsFile)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk staged tree: %v", err)
	}
	if found != 1 {
		t.Errorf("the enrollment token appears in %d files, want exactly 1", found)
	}

	// And the directory holding it must not be listable by other users:
	// a 0600 file in a 0755 directory is still a file an attacker knows the
	// name of and can wait to race on a rewrite.
	dir, err := os.Stat(filepath.Dir(credPath))
	if err != nil {
		t.Fatalf("stat credentials directory: %v", err)
	}
	if perm := dir.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("the credentials directory is mode %04o, want no group or world access", perm)
	}
}

// TestExecStartCarriesAPathNotAToken pins the specific mechanism.
func TestExecStartCarriesAPathNotAToken(t *testing.T) {
	s := baseSpec(t)
	s.CredentialsFile = "/etc/cloop/enroll.tok"
	plan, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	sections := parseUnitFile(t, plan.Display)
	execStart := sections["Service"]["ExecStart"][0]

	if !strings.Contains(execStart, "--token-file /etc/cloop/enroll.tok") {
		t.Errorf("ExecStart does not read the token from a file:\n  %s", execStart)
	}
	if strings.Contains(execStart, "--token ") {
		t.Errorf("ExecStart passes --token inline; the credential would be visible in `ps`:\n  %s", execStart)
	}
}

// ── Uninstall ───────────────────────────────────────────────────────────────

// TestUninstallIsIdempotentAndComplete: an operator re-runs uninstall because
// the first run printed something they did not like. A second run that fails
// teaches them to ignore the output.
func TestUninstallIsIdempotentAndComplete(t *testing.T) {
	for _, out := range []Output{OutputSystemd, OutputShell} {
		t.Run(string(out), func(t *testing.T) {
			root := t.TempDir()
			inst := &Installer{Root: root}

			spec := baseSpec(t)
			plan, err := BuildPlan(spec, out)
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			if err := inst.Apply(plan); err != nil {
				t.Fatalf("Apply: %v", err)
			}

			// Prove there is something to remove, so the assertions below
			// are not satisfied by an install that never happened.
			for _, a := range plan.Artifacts {
				if _, err := os.Stat(filepath.Join(root, a.Path)); err != nil {
					t.Fatalf("%s was not created: %v", a.Path, err)
				}
			}

			for attempt := 1; attempt <= 3; attempt++ {
				if err := inst.Uninstall(spec, out, true); err != nil {
					t.Fatalf("Uninstall attempt %d: %v", attempt, err)
				}
				for _, a := range plan.Artifacts {
					if _, err := os.Lstat(filepath.Join(root, a.Path)); !os.IsNotExist(err) {
						t.Errorf("attempt %d: %s survived uninstall", attempt, a.Path)
					}
				}
				if _, err := os.Lstat(filepath.Join(root, plan.Spec.StateDir)); !os.IsNotExist(err) {
					t.Errorf("attempt %d: the state directory %s survived uninstall",
						attempt, plan.Spec.StateDir)
				}
			}
		})
	}
}

// TestSharedSystemDirectoriesKeepConventionalModes.
//
// The credential's directory must be 0700; the directories it happens to sit
// under must not be. A single MkdirAll(stateDir, 0700) on a device missing
// /var/lib would create /var and /var/lib at 0700 and break every other
// service that reads from them — a confinement measure with a much larger
// blast radius than the thing it protects.
func TestSharedSystemDirectoriesKeepConventionalModes(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(baseSpec(t), OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if err := (&Installer{Root: root}).Apply(plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	private := map[string]bool{
		plan.Spec.StateDir:    true,
		plan.Spec.WorkDirRoot: true,
	}
	for _, dir := range []string{"/var", "/var/lib", "/etc", "/etc/systemd", "/etc/systemd/system",
		plan.Spec.StateDir, plan.Spec.WorkDirRoot} {
		info, statErr := os.Stat(filepath.Join(root, dir))
		if statErr != nil {
			t.Fatalf("stat %s: %v", dir, statErr)
		}
		perm := info.Mode().Perm()
		if private[dir] {
			if perm&0o077 != 0 {
				t.Errorf("%s is mode %04o; it holds a credential and must not be readable by others",
					dir, perm)
			}
			continue
		}
		if perm != SystemDirMode {
			t.Errorf("%s is mode %04o, want %04o — other services traverse it",
				dir, perm, SystemDirMode)
		}
	}
}

// TestUninstallWithoutPurgeKeepsIdentity: the default must not destroy an
// agent's long-lived credential, because reinstalling over it is the common
// case and re-enrolling every device is the expensive one. The token, however,
// goes either way.
func TestUninstallWithoutPurgeKeepsIdentity(t *testing.T) {
	root := t.TempDir()
	inst := &Installer{Root: root}
	spec := baseSpec(t)

	plan, err := BuildPlan(spec, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if err := inst.Apply(plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Stand in for a credential the agent would have written after enrolling.
	identity := filepath.Join(root, plan.Spec.AgentCredential)
	if err := os.WriteFile(identity, []byte(`{"agent_id":"x"}`), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	if err := inst.Uninstall(spec, OutputSystemd, false); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(identity); err != nil {
		t.Errorf("uninstall without --purge deleted the agent's identity: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, plan.Spec.CredentialsFile)); !os.IsNotExist(err) {
		t.Error("uninstall left the enrollment token behind")
	}
	if _, err := os.Lstat(filepath.Join(root, plan.Spec.UnitPath())); !os.IsNotExist(err) {
		t.Error("uninstall left the unit file behind")
	}
}

// TestUninstallOnACleanDeviceSucceeds — the zeroth run must be as quiet as the
// second.
func TestUninstallOnACleanDeviceSucceeds(t *testing.T) {
	inst := &Installer{Root: t.TempDir()}
	for _, out := range []Output{OutputSystemd, OutputShell, OutputDocker} {
		if err := inst.Uninstall(baseSpec(t), out, true); err != nil {
			t.Errorf("Uninstall(%s) on a device that was never installed: %v", out, err)
		}
	}
}

// TestUninstallNeedsNoServerURL.
//
// Removal is not the inverse of installation in its inputs. The operator
// decommissioning a device usually no longer has the bundle — frequently
// because the hub it named is what went away — and requiring --server to
// delete a unit file would be precisely the friction this command exists to
// remove.
func TestUninstallNeedsNoServerURL(t *testing.T) {
	root := t.TempDir()
	inst := &Installer{Root: root}

	plan, err := BuildPlan(baseSpec(t), OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if err := inst.Apply(plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Everything the operator can be expected to remember: the name.
	if err := inst.Uninstall(Spec{}, OutputSystemd, true); err != nil {
		t.Fatalf("Uninstall without a server URL: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, plan.Spec.UnitPath())); !os.IsNotExist(err) {
		t.Error("the unit survived an uninstall that carried no server URL")
	}
}

// ── Generated shell is valid shell ──────────────────────────────────────────

// TestGeneratedScriptsAreValidPOSIXShell: `sh -n` is the closest thing to
// systemd-analyze for the two script outputs. A quoting bug in a generated
// script is otherwise found by the device that fails to start.
func TestGeneratedScriptsAreValidPOSIXShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	s, err := baseSpec(t).Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// Values chosen to break naive quoting: spaces, quotes, and a shell
	// metacharacter in a label.
	s.Labels = map[string]string{"site": "berlin office", "note": `a'b"c`}

	for name, body := range map[string]string{
		"init script": InitScript(s),
		"install.sh":  BootstrapScript(BootstrapParams{Server: s.Server, Pin: s.Pin}),
	} {
		path := filepath.Join(t.TempDir(), "script.sh")
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if out, err := exec.Command(sh, "-n", path).CombinedOutput(); err != nil {
			t.Errorf("%s is not valid POSIX shell: %v\n%s", name, err, out)
		}
	}
}

// TestBootstrapScriptCarriesTheDeploymentIdentity: the script's entire reason
// to exist is telling a device which control plane to trust.
func TestBootstrapScriptCarriesTheDeploymentIdentity(t *testing.T) {
	const pin = "sha256:qUqP5cyxm6YcTAhz05Hph5gvu9M="
	body := BootstrapScript(BootstrapParams{
		Server:      "wss://hub.example.com/api/executors/connect",
		Pin:         pin,
		ServiceName: "edge-agent",
	})
	for _, want := range []string{
		"wss://hub.example.com/api/executors/connect",
		pin,
		"edge-agent",
		// Nothing may execute until the whole script has arrived.
		"main \"$@\"",
		// The bundle arrives out-of-band, never as an argument by default.
		"CLOOP_ENROLL_BUNDLE",
		"--bundle-stdin",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the bootstrap script does not contain %q", want)
		}
	}
	if strings.Contains(body, "sha256:\n") {
		t.Error("an empty pin was rendered as a bare prefix")
	}
}

// ── Validation ──────────────────────────────────────────────────────────────

func TestNormalizeRejectsUnusableSpecs(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"no server", Spec{Token: "t"}, "no control-plane URL"},
		{"relative binary", Spec{Server: "wss://h/x", BinaryPath: "cloop"}, "--binary"},
		{"relative state dir", Spec{Server: "wss://h/x", StateDir: "state"}, "--state-dir"},
		{"relative workdir root", Spec{Server: "wss://h/x", WorkDirRoot: "work"}, "--workdir-root"},
		{"bad service name", Spec{Server: "wss://h/x", ServiceName: "a b"}, "--service-name"},
		{"path in service name", Spec{Server: "wss://h/x", ServiceName: "../etc/x"}, "--service-name"},
		{"bad user", Spec{Server: "wss://h/x", User: "root; rm -rf /"}, "--user"},
		{"negative concurrency", Spec{Server: "wss://h/x", MaxConcurrent: -1}, "--max-concurrent"},
		{"corrupt bundle", Spec{Bundle: "cloopenroll1.!!!!"}, "enrollment bundle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.spec.Normalize()
			if err == nil {
				t.Fatalf("Normalize accepted %+v", tc.spec)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestBundleSuppliesServerAndPin: an operator who pastes one blob must not
// also have to paste the URL and the fingerprint, and an operator who
// overrides one of them must win.
func TestBundleSuppliesServerAndPin(t *testing.T) {
	s, err := Spec{Bundle: testBundle(t)}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if s.Server != "wss://hub.example.com/api/executors/connect" {
		t.Errorf("Server = %q, want it taken from the bundle", s.Server)
	}
	if s.Pin != "sha256:qUqP5cyxm6YcTAhz05Hph5gvu9M=" {
		t.Errorf("Pin = %q, want it taken from the bundle", s.Pin)
	}

	override, err := Spec{Bundle: testBundle(t), Pin: "sha256:rotated="}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if override.Pin != "sha256:rotated=" {
		t.Errorf("Pin = %q, want the explicit flag to win over the bundle", override.Pin)
	}
}

func TestSystemdEscape(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/cloop":  "/usr/local/bin/cloop",
		"/srv/my work":          `"/srv/my work"`,
		"100%":                  "100%%",
		`/a"b`:                  `"/a\"b"`,
		"sha256:abc+/def=":      "sha256:abc+/def=",
		"":                      `""`,
		"/srv/%i and a space":   `"/srv/%%i and a space"`,
		`/tmp/x;rm -rf /`:       `"/tmp/x;rm -rf /"`,
		"wss://h/api/executors": "wss://h/api/executors",
	}
	for in, want := range cases {
		if got := systemdEscape(in); got != want {
			t.Errorf("systemdEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestStateDirOutsideVarLibIsGrantedExplicitly: ProtectSystem=strict makes the
// filesystem read-only, so a state directory that StateDirectory= cannot
// express must be granted some other way or the service cannot write at all.
func TestStateDirOutsideVarLibIsGrantedExplicitly(t *testing.T) {
	s := baseSpec(t)
	s.StateDir = "/srv/cloop-agent"
	plan, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	sections := parseUnitFile(t, plan.Display)
	rw := strings.Join(sections["Service"]["ReadWritePaths"], " ")
	if !strings.Contains(rw, "/srv/cloop-agent") {
		t.Errorf("ReadWritePaths = %q, want it to cover the state directory", rw)
	}
	if _, ok := sections["Service"]["StateDirectory"]; ok {
		t.Error("StateDirectory= was emitted for a path outside /var/lib; systemd would put the state elsewhere")
	}
}

// TestWorkDirRootOutsideStateDirIsWritable covers the scratch-disk case: an
// operator who points workloads at /mnt/fast must still be able to write there.
func TestWorkDirRootOutsideStateDirIsWritable(t *testing.T) {
	s := baseSpec(t)
	s.WorkDirRoot = "/mnt/fast/cloop"
	plan, err := BuildPlan(s, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	sections := parseUnitFile(t, plan.Display)
	if !strings.Contains(strings.Join(sections["Service"]["ReadWritePaths"], " "), "/mnt/fast/cloop") {
		t.Error("a workdir root outside the state directory was not granted write access")
	}
}

// ── Container output ────────────────────────────────────────────────────────

// TestContainerFragmentMatchesTheSystemdGuarantees: a device with podman and
// no systemd must not end up materially less confined.
func TestContainerFragmentMatchesTheSystemdGuarantees(t *testing.T) {
	plan, err := BuildPlan(baseSpec(t), OutputDocker)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	for _, want := range []string{
		"--security-opt no-new-privileges", // NoNewPrivileges=yes
		"--cap-drop ALL",                   // CapabilityBoundingSet=
		"--read-only",                      // ProtectSystem=strict
		"--tmpfs /tmp",                     // PrivateTmp=yes
		"--restart=always",                 // Restart=always
		"no-new-privileges:true",           // and the same in compose
		`cap_drop: ["ALL"]`,
		"read_only: true",
		"restart: always",
	} {
		if !strings.Contains(plan.Display, want) {
			t.Errorf("the container fragment is missing %q", want)
		}
	}
	// The credential is mounted, never handed over as an environment
	// variable: `podman inspect` prints the environment.
	if strings.Contains(plan.Display, "--env CLOOP_ENROLL") || strings.Contains(plan.Display, "--env TOKEN") {
		t.Error("the container fragment passes enrollment material through the environment")
	}
	if !strings.Contains(plan.Display, containerSecretPath+":ro") {
		t.Errorf("the credential is not mounted read-only at %s", containerSecretPath)
	}
}

// ── Reading the token back ──────────────────────────────────────────────────

// TestReadTokenFileRoundTrip closes the loop: what the installer writes is
// what `cloop executor agent --token-file` reads.
func TestReadTokenFileRoundTrip(t *testing.T) {
	root := t.TempDir()
	spec := baseSpec(t)
	spec.Token = ""
	spec.Bundle = testBundle(t)

	plan, err := BuildPlan(spec, OutputSystemd)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if err := (&Installer{Root: root}).Apply(plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, warning, err := remote.ReadTokenFile(filepath.Join(root, plan.Spec.CredentialsFile))
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if warning != "" {
		t.Errorf("a freshly installed credential produced a permissions warning: %s", warning)
	}
	if got.Token != testToken {
		t.Errorf("Token = %q, want %q", got.Token, testToken)
	}
	if got.Server != plan.Spec.Server {
		t.Errorf("Server = %q, want %q", got.Server, plan.Spec.Server)
	}
}

// TestReadTokenFileWarnsOnExposedMode: the warning is the operator's only
// signal that a provisioning script leaked the token.
func TestReadTokenFileWarnsOnExposedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment")
	if err := os.WriteFile(path, []byte(testToken+"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, warning, err := remote.ReadTokenFile(path)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if warning == "" {
		t.Error("a world-readable enrollment file produced no warning")
	}
	if got.Token != testToken {
		t.Errorf("Token = %q, want %q — the read must still succeed", got.Token, testToken)
	}
}
