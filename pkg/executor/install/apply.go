package install

// apply.go performs the plan and reverses it.
//
// Two properties matter more than the mechanics:
//
//   - Uninstall is idempotent. An operator re-runs it because the first run
//     printed something alarming, and a second run that fails with "no such
//     unit" trains them to ignore its output. Every step here tolerates its
//     target already being gone, and the function only fails if something is
//     still present afterwards.
//   - Nothing runs a real command when Root is set. Tests stage an install
//     into a temp directory, and a test that shelled out to the host's
//     systemctl would be a test that reconfigures the machine running it.
//
// The credential file is written before anything is started and removed before
// anything else is torn down, so a partial run never leaves a device with an
// identity it is not supervising or a supervisor with no identity.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner executes a system command. Tests substitute a recorder.
type Runner func(name string, args ...string) error

// Installer applies and reverses plans.
//
// The zero value writes to the real filesystem and runs real commands, which
// is what the CLI wants; tests set Root and Run.
type Installer struct {
	// Root prefixes every path. Empty means the real filesystem root.
	// A non-empty Root also disables command execution entirely: a staged
	// install describes a device that is not this machine, so running
	// systemctl or useradd against this one would be wrong even if it
	// happened to work.
	Root string

	// Run executes a command. Nil uses exec.Command. Ignored when Root is
	// set.
	Run Runner

	// Logf receives progress messages. Nil discards them.
	Logf func(format string, args ...any)
}

func (in *Installer) logf(format string, args ...any) {
	if in.Logf != nil {
		in.Logf(format, args...)
	}
}

// path maps a device-absolute path into the (possibly staged) filesystem.
func (in *Installer) path(p string) string {
	if in.Root == "" {
		return p
	}
	return filepath.Join(in.Root, p)
}

// staged reports whether this installer targets a directory rather than the
// live system.
func (in *Installer) staged() bool { return in.Root != "" }

// run executes a command unless the installer is staged.
func (in *Installer) run(name string, args ...string) error {
	if in.staged() {
		in.logf("would run: %s %s", name, strings.Join(args, " "))
		return nil
	}
	if in.Run != nil {
		return in.Run(name, args...)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// Apply materialises the plan.
func (in *Installer) Apply(p Plan) error {
	s := p.Spec

	// The service user first: the credential file is chowned to it, and a
	// chown to a user that does not exist yet silently leaves the file owned
	// by root, where the service cannot read it.
	if err := in.ensureUser(s); err != nil {
		return err
	}

	for _, dir := range p.Dirs {
		if err := in.ensureDir(dir); err != nil {
			return err
		}
	}
	if err := in.chownTree(s, s.StateDir); err != nil {
		return err
	}

	for _, a := range p.Artifacts {
		if err := in.writeArtifact(s, a); err != nil {
			return err
		}
	}

	switch p.Output {
	case OutputSystemd:
		if err := in.run("systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("install: reload systemd: %w", err)
		}
		if s.NoStart {
			if err := in.run("systemctl", "enable", s.UnitFileName()); err != nil {
				return fmt.Errorf("install: enable %s: %w", s.UnitFileName(), err)
			}
			in.logf("enabled %s (not started: --no-start)", s.UnitFileName())
			return nil
		}
		if err := in.run("systemctl", "enable", "--now", s.UnitFileName()); err != nil {
			return fmt.Errorf("install: enable and start %s: %w", s.UnitFileName(), err)
		}
		in.logf("enabled and started %s", s.UnitFileName())
	case OutputShell:
		if s.NoStart {
			in.logf("wrote %s (not started: --no-start)", s.InitScriptPath())
			return nil
		}
		if err := in.run(s.InitScriptPath(), "start"); err != nil {
			return fmt.Errorf("install: start %s: %w", s.ServiceName, err)
		}
		in.logf("started %s", s.ServiceName)
	case OutputDocker:
		// Deliberately nothing: the operator runs the engine. Printing the
		// command and running it are different decisions, and guessing that
		// this device's podman should own the container is not ours.
	}
	return nil
}

// ensureDir creates one directory at its declared mode.
//
// Parents are created at SystemDirMode rather than at the leaf's mode: a naive
// MkdirAll(stateDir, 0700) on a system missing /var/lib would create /var and
// /var/lib at 0700 too, and silently break every other service that reads from
// them. The leaf's mode is then re-asserted even when it already existed, so an
// operator who loosened the state directory has it tightened again on the next
// install — the same thing systemd's StateDirectoryMode does on every start.
func (in *Installer) ensureDir(d Dir) error {
	target := in.path(d.Path)
	if parent := filepath.Dir(target); parent != target {
		if err := os.MkdirAll(parent, SystemDirMode); err != nil {
			return fmt.Errorf("install: create %s: %w", filepath.Dir(d.Path), err)
		}
	}
	if err := os.Mkdir(target, d.Mode); err != nil && !os.IsExist(err) {
		return fmt.Errorf("install: create %s: %w", d.Path, err)
	}
	if d.Mode == StateDirMode {
		if err := os.Chmod(target, d.Mode); err != nil {
			return fmt.Errorf("install: set mode on %s: %w", d.Path, err)
		}
	}
	return nil
}

// writeArtifact writes one file atomically, at its declared mode.
//
// Atomicity matters for the credential in particular: a reader that catches
// the file mid-write gets a truncated token, and an agent that redeems a
// truncated token burns the enrollment.
func (in *Installer) writeArtifact(s Spec, a Artifact) error {
	target := in.path(a.Path)
	// A secret's directory must not be listable by other users; everything
	// else lives in a shared system directory.
	dirMode := SystemDirMode
	if a.Secret {
		dirMode = StateDirMode
	}
	if err := in.ensureDir(Dir{filepath.Dir(a.Path), dirMode}); err != nil {
		return err
	}
	tmp := target + ".tmp"
	// O_EXCL on the temp file, so a symlink planted at the predictable temp
	// path cannot redirect a 0600 credential write somewhere world-readable.
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, a.Mode)
	if err != nil {
		return fmt.Errorf("install: create %s: %w", a.Path, err)
	}
	if _, err := f.WriteString(a.Content); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("install: write %s: %w", a.Path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install: close %s: %w", a.Path, err)
	}
	// Chmod explicitly: OpenFile's mode is masked by the process umask, so a
	// caller running with umask 0 and one running with 0022 would otherwise
	// produce different permissions for the same credential.
	if err := os.Chmod(tmp, a.Mode); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install: set mode on %s: %w", a.Path, err)
	}
	if a.Owned {
		if err := in.chown(s, tmp); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install: install %s: %w", a.Path, err)
	}
	if a.Secret {
		in.logf("wrote %s (mode %04o, %s)", a.Path, a.Mode, s.User)
	} else {
		in.logf("wrote %s", a.Path)
	}
	return nil
}

// chown sets the service user as owner, skipping silently when the user does
// not resolve (a staged install, or a plan rendered for another machine).
func (in *Installer) chown(s Spec, path string) error {
	if in.staged() {
		return nil
	}
	uid, gid, ok := lookupServiceUser(s.User)
	if !ok {
		in.logf("note: user %s does not exist; %s is left owned by the current user", s.User, path)
		return nil
	}
	if err := os.Chown(path, uid, gid); err != nil {
		// Not fatal when unprivileged: an operator running --dry-run-adjacent
		// flows as themselves still wants the rest of the output.
		if errors.Is(err, os.ErrPermission) {
			in.logf("note: cannot chown %s to %s (not root)", path, s.User)
			return nil
		}
		return fmt.Errorf("install: chown %s to %s: %w", path, s.User, err)
	}
	return nil
}

// chownTree applies chown to a directory and everything under it.
func (in *Installer) chownTree(s Spec, dir string) error {
	if in.staged() {
		return nil
	}
	root := in.path(dir)
	if _, err := os.Stat(root); err != nil {
		return nil
	}
	return filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		return in.chown(s, p)
	})
}

// ensureUser creates the dedicated non-login service account.
//
// A dedicated account is the difference between "a compromised harness can
// read this device's state directory" and "a compromised harness runs as the
// operator". It is created with no home, no shell and no password.
func (in *Installer) ensureUser(s Spec) error {
	if in.staged() {
		in.logf("would create system user %s", s.User)
		return nil
	}
	if _, _, ok := lookupServiceUser(s.User); ok {
		return nil
	}
	if _, err := exec.LookPath("useradd"); err != nil {
		in.logf("note: useradd not found; create the %s account manually before starting the service", s.User)
		return nil
	}
	args := []string{
		"--system",
		"--no-create-home",
		"--home-dir", s.StateDir,
		"--shell", nologinShell(),
		"--user-group",
		s.User,
	}
	if err := in.run("useradd", args...); err != nil {
		return fmt.Errorf("install: create system user %s: %w", s.User, err)
	}
	in.logf("created system user %s", s.User)
	return nil
}

// nologinShell picks whichever no-login shell this distribution ships.
func nologinShell() string {
	for _, p := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "/bin/false"
}

// Uninstall reverses an install. It is idempotent: running it twice, or
// running it on a device that was never installed, succeeds quietly.
//
// The credential is removed first and the state directory last, so an
// interrupted uninstall never leaves a live token behind in a directory it
// then failed to delete.
func (in *Installer) Uninstall(spec Spec, out Output, purgeState bool) error {
	s, err := spec.NormalizeForRemoval()
	if err != nil {
		return err
	}

	switch out {
	case OutputSystemd:
		// Best-effort: a unit that is not loaded makes both of these fail,
		// and that is the expected state on a second run.
		_ = in.run("systemctl", "disable", "--now", s.UnitFileName())
	case OutputShell:
		if _, statErr := os.Stat(in.path(s.InitScriptPath())); statErr == nil {
			_ = in.run(s.InitScriptPath(), "stop")
		}
	case OutputDocker:
		_ = in.run("podman", "rm", "--force", s.ServiceName)
	}

	var problems []string
	remove := func(path string) {
		// Stat first so the log reflects what actually happened. A second
		// run reporting "removed" for files that were never there reads as a
		// tool that does not know its own state, and an operator who learns
		// to discount its output will discount the line that matters.
		_, existed := os.Lstat(in.path(path))
		if err := os.RemoveAll(in.path(path)); err != nil && !os.IsNotExist(err) {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
			return
		}
		if existed == nil {
			in.logf("removed %s", path)
		}
	}

	remove(s.CredentialsFile)

	switch out {
	case OutputSystemd:
		remove(s.UnitPath())
		// Drop-ins live in a sibling directory and would otherwise survive
		// as an orphan that confuses the next install.
		remove(s.UnitPath() + ".d")
		if err := in.run("systemctl", "daemon-reload"); err != nil {
			in.logf("note: systemctl daemon-reload failed: %v", err)
		}
	case OutputShell:
		remove(s.InitScriptPath())
		remove(filepath.Join("/run", s.ServiceName+".pid"))
	}

	if purgeState {
		remove(s.StateDir)
	} else {
		in.logf("kept %s (pass --purge to delete the agent's identity and workspaces)", s.StateDir)
	}

	// Verify rather than assume. "Leaves no unit or state directory behind"
	// is the contract, so it is checked rather than inferred from the
	// absence of an error above.
	leftovers := []string{s.CredentialsFile}
	switch out {
	case OutputSystemd:
		leftovers = append(leftovers, s.UnitPath())
	case OutputShell:
		leftovers = append(leftovers, s.InitScriptPath())
	}
	if purgeState {
		leftovers = append(leftovers, s.StateDir)
	}
	for _, p := range leftovers {
		if _, err := os.Lstat(in.path(p)); err == nil {
			problems = append(problems, p+": still present after uninstall")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("install: uninstall incomplete:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}
