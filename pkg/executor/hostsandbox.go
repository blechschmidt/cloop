package executor

import (
	"fmt"
	"path/filepath"
	"strings"
)

// HostSandbox asks a driver that forks the workload on its own host — the
// host-process driver — to confine it to the files of the person it acts for
// (Task 20480): its work directory, what this names, the system's read-only
// directories and a private temporary directory, and nothing else. See
// pkg/hostsandbox for what the kernel enforces and how.
//
// The hub decides who is sandboxed and builds this; the driver adds what only
// it knows — the lease files it was handed, its own binary, the temporary
// directory it makes — and refuses the workload rather than start it without.
//
// It carries paths, never a credential, and is json:"-" like SecretFiles for a
// narrower reason: it describes how this host's driver starts the process, so
// it means nothing on another machine and nothing after the process exists.
type HostSandbox struct {
	// Person is whom the workload acts for, for the log and the label: an
	// owner key, or "" for the hub's own login.
	Person string
	// ReadWrite are paths beyond the work directory the workload may change:
	// the person's Claude home, the home kept for them, a local repository
	// granted read-write. Each must exist.
	ReadWrite []string
	// ReadOnly are further paths it may read and execute: where the harness
	// is installed, a local repository granted read-only, the operator's
	// executors.host_sandbox.read_only.
	ReadOnly []string
	// Home is the HOME the workload gets. Empty gives it a fresh one for this
	// run alone.
	Home string
	// Path are directories put in front of the workload's PATH: where the
	// hub found the harness, which a changed HOME no longer leads to.
	Path []string
	// Env are assignments put last in the workload's environment, after the
	// sandbox's own HOME and TMPDIR: CLAUDE_CONFIG_DIR naming the hub's own
	// login for a workload that acts for no one, whose HOME no longer leads
	// to it.
	Env []string
	// PassEnv names variables of the hub's own environment the workload
	// inherits beyond the default few (executors.host_sandbox.pass_env).
	PassEnv []string
}

// LabelHostSandbox marks a workload the host sandbox confines, for the
// dispatch record. Its value is "on".
const LabelHostSandbox = "host_sandbox"

// Validate checks that every path the sandbox names is absolute.
func (h *HostSandbox) Validate() error {
	if h == nil {
		return nil
	}
	for _, list := range [][]string{h.ReadWrite, h.ReadOnly, h.Path} {
		for _, p := range list {
			if !filepath.IsAbs(p) {
				return fmt.Errorf("%w: host sandbox path %q is not absolute", ErrInvalidSpec, p)
			}
		}
	}
	if h.Home != "" && !filepath.IsAbs(h.Home) {
		return fmt.Errorf("%w: host sandbox home %q is not absolute", ErrInvalidSpec, h.Home)
	}
	for _, kv := range h.Env {
		if !strings.Contains(kv, "=") {
			return fmt.Errorf("%w: host sandbox env %q is not in K=V form", ErrInvalidSpec, kv)
		}
	}
	return nil
}
