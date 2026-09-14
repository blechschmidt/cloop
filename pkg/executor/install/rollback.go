package install

// rollback.go keeps the binary an upgrade replaced, and puts it back if the
// service does not come back (Task 20252).
//
// Verification (verify.go) catches a binary that is broken in a way this machine
// can detect before it runs: truncated, wrong architecture, not cloop. It cannot
// catch a binary that runs fine and then fails in its own environment — a build
// that needs a newer libc than the device has, one whose unit file references a
// flag it no longer accepts, one with a startup panic on this device's hardware.
// Those only show up as a service that will not stay up, and by then the binary
// that worked has already been overwritten.
//
// So the upgrade keeps the old one. The cost is one binary's worth of disk on
// the device and a bounded wait after the restart; the thing bought is that a
// failed rollout on an unreachable edge device ends with the device still in the
// fleet rather than with a site visit.
//
// Three decisions are worth stating, because each has a plausible-looking
// alternative that is wrong:
//
//   - The backup is a *copy made before* the swap, not the old file renamed
//     aside. Renaming first leaves a window in which the service binary does not
//     exist at all, and a supervisor that restarts during that window fails for
//     a reason the upgrade did not cause and cannot explain.
//   - Whether the service was running is sampled *before* the restart. systemd's
//     try-restart succeeds whether or not it restarted anything, so a service an
//     operator had deliberately stopped is indistinguishable afterwards from one
//     that crashed on the new binary. Rolling back on that would undo a good
//     upgrade every time it landed on a stopped agent.
//   - A failed rollback is reported, never swallowed. If restoring the old
//     binary also fails, the device needs a human, and the message has to say so
//     plainly instead of returning the original error as though the restore had
//     worked.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// backupSuffix names the copy of the binary an upgrade replaced.
//
// A fixed, predictable name rather than a timestamped one: an operator who needs
// to roll back by hand should be able to guess the path, and a directory
// accumulating one backup per upgrade is how a device with a small root
// filesystem fills up. One generation is what rollback needs.
const backupSuffix = ".prev"

// serviceSettleTimeout bounds the wait for a restarted service to report itself
// active before the upgrade treats the new binary as bad.
//
// The agent's own startup is fast — it binds nothing and dials out — so the
// budget is dominated by systemd's own transitions and by a device slow enough
// to take seconds to page in the executable. Long enough not to roll back a
// working upgrade on a loaded Raspberry Pi; short enough that an operator
// watching the command does not conclude it has hung.
const serviceSettleTimeout = 30 * time.Second

// serviceSettleInterval is the poll period while waiting.
const serviceSettleInterval = 500 * time.Millisecond

// backupPath returns where the replaced binary is kept, in the device's
// namespace (the caller maps it through Installer.path).
func backupPath(devicePath string) string { return devicePath + backupSuffix }

// saveBackup copies the currently-installed binary aside so a failed restart can
// be undone. A missing target is not an error: there is simply nothing to keep.
func (in *Installer) saveBackup(devicePath string) (string, error) {
	target := in.path(devicePath)
	if _, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("install: stat %s: %w", devicePath, err)
	}
	backup := backupPath(devicePath)
	if err := copyFile(target, in.path(backup), BinaryMode); err != nil {
		return "", fmt.Errorf("install: keep a copy of the current %s for rollback: %w\n"+
			"Refusing to replace it without one", devicePath, err)
	}
	return backup, nil
}

// restoreBackup puts the kept binary back and asks the supervisor to start it.
//
// The restart is attempted even if the file restore failed, and its own failure
// is folded into the returned error: leaving a device with the old binary on
// disk and a stopped service is better than leaving it with no diagnosis.
func (in *Installer) restoreBackup(s Spec, out Output, backup string) error {
	if backup == "" {
		return fmt.Errorf("no backup of the previous binary was kept")
	}
	if err := os.Rename(in.path(backup), in.path(s.BinaryPath)); err != nil {
		return fmt.Errorf("restore %s from %s: %w", s.BinaryPath, backup, err)
	}
	in.logf("restored the previous %s", s.BinaryPath)
	if _, err := in.restartService(s, out); err != nil {
		return fmt.Errorf("the previous binary was restored but %s did not restart: %w",
			s.ServiceName, err)
	}
	return nil
}

// serviceActive reports whether the supervisor considers the service running,
// and whether the question could be asked at all.
//
// The second return separates "not running" from "no way to tell". They demand
// opposite responses: a service that is not running after an upgrade is grounds
// for rollback, while an output mode with no status verb (--output docker, or a
// bare binary install with no supervisor) must not be rolled back for failing to
// answer a question nobody asked it.
func (in *Installer) serviceActive(s Spec, out Output) (active, known bool) {
	if in.staged() {
		// A staged installer runs no commands, so it cannot observe anything.
		return false, false
	}
	switch out {
	case OutputSystemd:
		return in.run("systemctl", "is-active", "--quiet", s.UnitFileName()) == nil, true
	case OutputShell:
		return in.run(s.InitScriptPath(), "status") == nil, true
	default:
		return false, false
	}
}

// waitForService polls until the service reports active or the budget runs out.
//
// Returns immediately on the first success, so a healthy upgrade costs one
// status call rather than the whole timeout.
func (in *Installer) waitForService(s Spec, out Output, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for {
		if active, known := in.serviceActive(s, out); !known || active {
			// Unknown counts as satisfied: see serviceActive. Rolling back
			// because a supervisor has no status verb would make --output
			// modes without one unusable.
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(serviceSettleInterval)
	}
}

// copyFile duplicates src to dst with the given mode, flushing before it
// returns so a power loss cannot leave a backup that is itself truncated — a
// backup nobody can trust is worse than none, because the upgrade proceeds
// believing it has one.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), SystemDirMode); err != nil {
		return err
	}
	// Truncating rather than staging-and-renaming: this path is the backup
	// itself, and nothing reads it concurrently.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}
