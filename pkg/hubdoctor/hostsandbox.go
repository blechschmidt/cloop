package hubdoctor

// executors.host_sandbox: whether the people a hub with sign-in serves are
// kept out of each other's files when their runs fork on its own host
// (Task 20480), and whether the projects a host serves are kept out of each
// other's (Task 20500).
//
// The host-process driver runs every run as the hub's own user. With sign-in
// on and the host sandbox off, one person's agent can read every other
// person's projects and Claude login, the lease files of their runs and the
// hub's database: that fails. So does a host that cannot give the sandbox,
// where the hub refuses the runs that need it. A path the operator lets every
// sandboxed run read that would hand it the hub's or another person's files
// warns — the hub leaves it out, which the operator may not expect.
//
// Under mode auto a hub that serves more than one project keeps every run on
// its host to its own project, administrators' included, so the sandbox is
// needed there with or without sign-in. A project the operator opted out of
// that (executors.host_sandbox.opt_out) runs unconfined and can read every
// other project on the host: each one is named, as a warning
// (executors.host_sandbox.opt_out), so the choice stays visible.

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
	projects := hostProjects(dir)
	shared := len(projects) > 1
	checkOptOuts(hs, mode, projects, add)
	if mode == config.HostSandboxOff || (mode == config.HostSandboxAuto && !people && !shared) {
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
	switch {
	case mode == config.HostSandboxAll:
		who = "every run on this host that acts for anyone, administrators included,"
	case shared && people:
		who = fmt.Sprintf("every run on this host, administrators' included, since it serves %d projects "+
			"(and every person's but an administrator's whatever it serves),", len(projects))
	case shared:
		who = fmt.Sprintf("every run on this host, since it serves %d projects,", len(projects))
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
	msg := fmt.Sprintf("%s runs in the host sandbox (%s)", who, how)
	if shared && mode == config.HostSandboxAuto && !optedOutHere(hs, dir) {
		// The hub's own directory cannot be confined, so on a shared host
		// its runs are refused until it is opted out: said here, before an
		// operator meets the refusal.
		msg += "; the hub's own directory, which cannot be confined, runs only once it is listed in " +
			"executors.host_sandbox.opt_out"
	}
	finding(SeverityPass, msg, "")
}

// optedOutHere reports whether opt_out lists the hub's own directory dir.
func optedOutHere(hs config.HostSandboxConfig, dir string) bool {
	own := dir
	if abs, err := filepath.Abs(dir); err == nil {
		own = abs
	}
	if r, err := filepath.EvalSymlinks(own); err == nil {
		own = r
	}
	for _, p := range hs.OptOut {
		p = filepath.Clean(strings.TrimSpace(p))
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		if p == own {
			return true
		}
	}
	return false
}

// hostProjects lists the projects the hub in dir serves — its own directory
// and every registered project, features excluded — canonical and unique.
func hostProjects(dir string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if strings.TrimSpace(p) == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return
		}
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			abs = r
		}
		if !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	add(dir)
	if entries, err := multiui.Load(); err == nil {
		for _, e := range entries {
			if !e.IsFeature() {
				add(e.Path)
			}
		}
	}
	return out
}

// checkOptOuts names, as a warning, every project opted out of being kept to
// itself on a shared host (Task 20500): its runs there can open, list and
// write every other project on the host.
func checkOptOuts(hs config.HostSandboxConfig, mode string, projects []string, add addFn) {
	if len(hs.OptOut) == 0 {
		return
	}
	known := map[string]bool{}
	for _, p := range projects {
		known[p] = true
	}
	var named, unknown []string
	for _, p := range hs.OptOut {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		abs := filepath.Clean(p)
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			abs = r
		}
		if known[abs] {
			named = append(named, p)
		} else {
			unknown = append(unknown, p)
		}
	}
	msg := fmt.Sprintf("%d project(s) opted out of executors.host_sandbox: their runs on this host are not kept "+
		"to their own project, and can open, list and write every other project here: %s",
		len(hs.OptOut), strings.Join(append(append([]string{}, named...), unknown...), ", "))
	switch mode {
	case config.HostSandboxAll:
		msg = "executors.host_sandbox.opt_out lists projects, which mode all does not let out of the sandbox: " +
			strings.Join(append(append([]string{}, named...), unknown...), ", ")
	case config.HostSandboxOff:
		msg += " (with mode off, every project's runs are unconfined anyway)"
	}
	if len(unknown) > 0 {
		msg += fmt.Sprintf("; %s names no project on this hub", strings.Join(unknown, ", "))
	}
	add(Finding{Check: "executors.host_sandbox.opt_out", Title: hostSandboxTitle, Severity: SeverityWarn,
		Message: msg,
		Remediation: "Remove a project from executors.host_sandbox.opt_out once its runs work in the host " +
			"sandbox — grant what they need with executors.host_sandbox.read_only and pass_env — or move it to " +
			"a container executor",
		Details: map[string]any{"mode": mode, "opt_out": hs.OptOut, "unknown": unknown}})
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
