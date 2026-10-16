package agent

// workspaceowner.go: the workspace a root agent hands a container sandbox
// (Task 20430).
//
// An agent runs as root when it has to — attaching a forwarded USB device
// writes vhci_hcd's root-only attach file, and moving a TAP into a sandbox's
// network namespace needs root in the host's — but the container driver runs a
// workload as the owner of its workspace and refuses root outright: root in a
// container defeats --cap-drop=ALL. So a root agent whose work root an operator
// gave to an unprivileged user hands each container workload's workspace to
// that user, once the agent has finished writing into it. The sandbox then runs
// as that user, the same as under an agent that never ran as root.
//
// Nothing changes for an agent that is not root, or whose work root root owns:
// the driver's refusal stands, and says what to do.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// workspaceOwner is the owner a root agent gives container workspaces to: its
// work root's, when that is not root.
func (a *Agent) workspaceOwner() (uid, gid int, ok bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	fi, err := os.Stat(a.root)
	if err != nil {
		return 0, 0, false
	}
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat || st.Uid == 0 {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// handOverWorkspace gives a container workload's workspace to the work root's
// owner, without following a symlink out of it.
func (a *Agent) handOverWorkspace(dir string) error {
	uid, gid, ok := a.workspaceOwner()
	if !ok {
		return nil
	}
	if err := containedIn(a.root, dir); err != nil {
		return err
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
	if err != nil {
		return fmt.Errorf("agent: give the workspace %s to its sandbox's user %d:%d: %w", dir, uid, gid, err)
	}
	return nil
}
