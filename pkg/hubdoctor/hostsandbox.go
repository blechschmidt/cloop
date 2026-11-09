package hubdoctor

// executors.host_sandbox: whether the people a hub with sign-in serves are
// kept out of each other's files when their runs fork on its own host
// (Task 20480).
//
// The host-process driver runs every run as the hub's own user. With sign-in
// on and the host sandbox off, one person's agent can read every other
// person's projects and Claude login, the lease files of their runs and the
// hub's database: that fails. So does a host that cannot give the sandbox,
// where the hub refuses the runs that need it. A path the operator lets every
// sandboxed run read that would hand it the hub's or another person's files
// warns — the hub leaves it out, which the operator may not expect.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

const hostSandboxTitle = "Host sandbox"

// The probes of the kernel and the process; tests replace them.
var (
	hostSandboxAvailable = hostsandbox.Available
	hostSandboxABI       = hostsandbox.ABI
	hostSandboxRoot      = hostsandbox.UsesNamespaces
)

func checkHostSandbox(dir string, cfg *config.Config, add addFn) {
	hs := cfg.Executors.HostSandbox
	mode := hs.EffectiveMode()
	finding := func(sev Severity, msg, remedy string) {
		add(Finding{Check: "executors.host_sandbox", Title: hostSandboxTitle, Severity: sev,
			Message: msg, Remediation: remedy, Details: map[string]any{"mode": mode}})
	}
	if err := hs.Validate(); err != nil {
		finding(SeverityFail, err.Error()+"; the hub refuses to start on it",
			"Set executors.host_sandbox.mode to auto, all or off")
		return
	}
	if !cfg.Executors.HostProcessAllowed() {
		finding(SeverityPass, "strict: no run forks on this host, so there is nothing to sandbox", "")
		return
	}
	people := cfg.UI.OIDC.Enabled
	if mode == config.HostSandboxOff || (mode == config.HostSandboxAuto && !people) {
		if people {
			finding(SeverityFail, "single sign-on is on and the host sandbox is off: every person's run on "+
				"this host runs as the hub's user, and its agent can read every other person's projects and "+
				"Claude login, the credential files of their runs and the hub's database",
				"Remove executors.host_sandbox.mode: off (auto sandboxes everyone but the hub's "+
					"administrators), or set executors.allow_host_process: false and run people's projects "+
					"on container executors")
			return
		}
		finding(SeverityPass, "no single sign-on: one person uses this hub, and their runs on its host are not "+
			"sandboxed", "")
		return
	}
	if err := hostSandboxAvailable(); err != nil {
		finding(SeverityFail, fmt.Sprintf("this host cannot give runs the host sandbox (%v), so the hub refuses "+
			"to run on it every run the sandbox is for", err),
			"Run the hub on Linux 6.2 or later with Landlock enabled (lsm=…,landlock), or bind people's "+
				"projects to container executors")
		return
	}
	abi, _ := hostSandboxABI()
	how := fmt.Sprintf("Landlock ABI %d", abi)
	root := hostSandboxRoot()
	if root {
		how += " with private mount, PID and IPC namespaces"
	}
	who := "every person's run on this host but a hub administrator's"
	if mode == config.HostSandboxAll {
		who = "every run on this host that acts for anyone, administrators included,"
	}
	if dropped := unsafeReadOnly(dir, hs.ReadOnly); len(dropped) > 0 {
		add(Finding{Check: "executors.host_sandbox", Title: hostSandboxTitle, Severity: SeverityWarn,
			Message: fmt.Sprintf("%s runs in the host sandbox (%s), but executors.host_sandbox.read_only "+
				"names %s, which would hand a sandboxed run the hub's files or other people's, and is "+
				"left out", who, how, strings.Join(dropped, ", ")),
			Remediation: "Name the toolchain's own directory instead of one above the hub, the identity root " +
				"or a project",
			Details: map[string]any{"mode": mode, "dropped": dropped}})
		return
	}
	if root && abi < 6 {
		finding(SeverityWarn, fmt.Sprintf("%s runs in the host sandbox (%s), but below Landlock ABI 6 a "+
			"sandboxed run on a hub running as root can still connect to the abstract sockets of the host's "+
			"daemons, some of which trust a caller for being root", who, how),
			"Run the hub as a non-root user, or on Linux 6.12 or later, whose Landlock scopes abstract sockets")
		return
	}
	finding(SeverityPass, fmt.Sprintf("%s runs in the host sandbox (%s)", who, how), "")
}

// unsafeReadOnly lists the read_only paths the hub leaves out because they are
// the filesystem's root, or contain or lie inside the control plane, the
// identity root or a registered project.
func unsafeReadOnly(dir string, paths []string) []string {
	protected := []string{}
	if abs, err := filepath.Abs(dir); err == nil {
		protected = append(protected, abs)
	}
	if root, err := claudecodeauth.HomeRootPath(); err == nil {
		protected = append(protected, filepath.Clean(root))
	}
	if entries, err := multiui.Load(); err == nil {
		for _, e := range entries {
			if abs, err := filepath.Abs(e.Path); err == nil {
				protected = append(protected, abs)
			}
		}
	}
	var out []string
	for _, p := range paths {
		p = filepath.Clean(strings.TrimSpace(p))
		bad := p == string(os.PathSeparator)
		for _, q := range protected {
			if bad || within(p, q) || within(q, p) {
				bad = true
				break
			}
		}
		if bad {
			out = append(out, p)
		}
	}
	return out
}

// within reports whether path is dir or beneath it.
func within(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}
