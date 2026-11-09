package hubdoctor

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
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
