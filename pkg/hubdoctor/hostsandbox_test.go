package hubdoctor

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

func hostSandboxFindings(t *testing.T, dir string, cfg *config.Config) map[string][]Finding {
	t.Helper()
	got := map[string][]Finding{}
	checkHostSandbox(dir, cfg, func(f Finding) { got[f.Check] = append(got[f.Check], f) })
	return got
}

func TestHostSandboxFindingsAcrossTheMatrix(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	prevAvail, prevABI, prevRoot := hostSandboxAvailable, hostSandboxABI, hostSandboxRoot
	t.Cleanup(func() { hostSandboxAvailable, hostSandboxABI, hostSandboxRoot = prevAvail, prevABI, prevRoot })
	hostSandboxAvailable = func() error { return nil }
	hostSandboxABI = func() (int, error) { return 6, nil }
	hostSandboxRoot = func() bool { return true }
	dir := t.TempDir()
	no := false

	sso := func(mode string, readOnly ...string) *config.Config {
		cfg := &config.Config{}
		cfg.UI.OIDC.Enabled = true
		cfg.Executors.HostSandbox = config.HostSandboxConfig{Mode: mode, ReadOnly: readOnly}
		return cfg
	}
	for name, tc := range map[string]struct {
		cfg  *config.Config
		want Severity
		says string
	}{
		"sso, auto":        {sso(""), SeverityPass, "but a hub administrator's"},
		"sso, all":         {sso("all"), SeverityPass, "administrators included"},
		"sso, off":         {sso("off"), SeverityFail, "can read every other person's projects"},
		"no sso":           {&config.Config{}, SeverityPass, "one person"},
		"bad mode":         {sso("people"), SeverityFail, "not a mode"},
		"read_only at /":   {sso("", "/"), SeverityWarn, "is left out"},
		"read_only at hub": {sso("", dir), SeverityWarn, "is left out"},
		"strict hub": {func() *config.Config {
			c := sso("off")
			c.Executors.AllowHostProcess = &no
			return c
		}(), SeverityPass, "nothing to sandbox"},
	} {
		f := only(t, hostSandboxFindings(t, dir, tc.cfg), "executors.host_sandbox")
		if f.Severity != tc.want || !strings.Contains(f.Message, tc.says) {
			t.Errorf("%s: %s %q, want %s saying %q", name, f.Severity, f.Message, tc.want, tc.says)
		}
	}

	hostSandboxABI = func() (int, error) { return 4, nil }
	f := only(t, hostSandboxFindings(t, dir, sso("")), "executors.host_sandbox")
	if f.Severity != SeverityWarn || !strings.Contains(f.Message, "abstract sockets") {
		t.Errorf("a root hub below Landlock ABI 6: %s %q", f.Severity, f.Message)
	}
	hostSandboxRoot = func() bool { return false }
	if f := only(t, hostSandboxFindings(t, dir, sso("")), "executors.host_sandbox"); f.Severity != SeverityPass {
		t.Errorf("a non-root hub below ABI 6: %s %q", f.Severity, f.Message)
	}

	hostSandboxAvailable = func() error { return errors.New("no Landlock: " + hostsandbox.ErrUnsupported.Error()) }
	f = only(t, hostSandboxFindings(t, dir, sso("")), "executors.host_sandbox")
	if f.Severity != SeverityFail || !strings.Contains(f.Message, "refuses") {
		t.Errorf("a host without the sandbox under auto: %s %q", f.Severity, f.Message)
	}
}

// TestHostSandboxFindingsOnAHostServingSeveralProjects (Task 20500): a hub
// that serves a second project keeps every run on its host to its own, with
// or without sign-in, so the sandbox is needed there and a host without it is
// a failure; and every project opted out of it is named as a warning.
func TestHostSandboxFindingsOnAHostServingSeveralProjects(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	prevAvail, prevABI, prevRoot := hostSandboxAvailable, hostSandboxABI, hostSandboxRoot
	t.Cleanup(func() { hostSandboxAvailable, hostSandboxABI, hostSandboxRoot = prevAvail, prevABI, prevRoot })
	hostSandboxAvailable = func() error { return nil }
	hostSandboxABI = func() (int, error) { return 6, nil }
	hostSandboxRoot = func() bool { return false }
	dir, web, api := t.TempDir(), t.TempDir(), t.TempDir()
	if err := multiui.AddPaths([]string{web, api}); err != nil {
		t.Fatal(err)
	}

	f := only(t, hostSandboxFindings(t, dir, &config.Config{}), "executors.host_sandbox")
	if f.Severity != SeverityPass || !strings.Contains(f.Message, "since it serves 3 projects") ||
		!strings.Contains(f.Message, "the hub's own directory, which cannot be confined, runs only once") {
		t.Errorf("a hub without sign-in serving three projects: %s %q", f.Severity, f.Message)
	}
	hubOpted := &config.Config{}
	hubOpted.Executors.HostSandbox.OptOut = []string{dir}
	if f := only(t, hostSandboxFindings(t, dir, hubOpted), "executors.host_sandbox"); strings.Contains(f.Message,
		"runs only once") {
		t.Errorf("the hint for an opted-out hub directory: %q", f.Message)
	}
	sso := &config.Config{}
	sso.UI.OIDC.Enabled = true
	if f := only(t, hostSandboxFindings(t, dir, sso), "executors.host_sandbox"); f.Severity != SeverityPass ||
		!strings.Contains(f.Message, "administrators' included") {
		t.Errorf("a hub with sign-in serving three projects: %s %q", f.Severity, f.Message)
	}
	hostSandboxAvailable = func() error { return errors.New("no Landlock") }
	if f := only(t, hostSandboxFindings(t, dir, &config.Config{}), "executors.host_sandbox"); f.Severity != SeverityFail {
		t.Errorf("a shared host without the sandbox: %s %q", f.Severity, f.Message)
	}
	hostSandboxAvailable = func() error { return nil }
	if got := hostSandboxFindings(t, dir, &config.Config{})["executors.host_sandbox.opt_out"]; len(got) != 0 {
		t.Errorf("an opt-out finding with nothing opted out: %+v", got)
	}

	opted := &config.Config{}
	opted.Executors.HostSandbox.OptOut = []string{web, "/srv/gone"}
	o := only(t, hostSandboxFindings(t, dir, opted), "executors.host_sandbox.opt_out")
	if o.Severity != SeverityWarn || !strings.Contains(o.Message, web) ||
		!strings.Contains(o.Message, "every other project") || !strings.Contains(o.Message, "/srv/gone names no project") {
		t.Errorf("the opt-outs: %s %q", o.Severity, o.Message)
	}
	opted.Executors.HostSandbox.Mode = config.HostSandboxAll
	if o := only(t, hostSandboxFindings(t, dir, opted), "executors.host_sandbox.opt_out"); !strings.Contains(o.Message, "mode all does not let") {
		t.Errorf("opt-outs under mode all: %q", o.Message)
	}

	// One project and no sign-in: nothing to keep apart, as before.
	t.Setenv("HOME", t.TempDir())
	if f := only(t, hostSandboxFindings(t, dir, &config.Config{}), "executors.host_sandbox"); f.Severity != SeverityPass ||
		!strings.Contains(f.Message, "one person") {
		t.Errorf("a single-project hub without sign-in: %s %q", f.Severity, f.Message)
	}
}
