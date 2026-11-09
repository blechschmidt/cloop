//go:build linux

package hostsandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// keptCaps are the capabilities a workload of a hub running as root keeps:
// the ones that decide file access, which Landlock confines anyway, and
// binding a port below 1024. Without them a project another user owns, or a
// file a tool made read-only, stops working the way it did before the
// sandbox. Everything that reaches past the filesystem — loading a module,
// BPF, raw sockets, the network's configuration, mounts, other users' ids,
// ptrace — is dropped from the bounding set, so no binary run later can have
// it back.
//
// Not CAP_DAC_READ_SEARCH, although it decides file access too: it is what
// open_by_handle_at asks for, and a file opened by its handle through a
// mount the workload may write is judged by that mount's rules, wherever the
// file is. CAP_DAC_OVERRIDE already lets root read what it may open.
var keptCaps = []uintptr{
	unix.CAP_CHOWN, unix.CAP_DAC_OVERRIDE,
	unix.CAP_FOWNER, unix.CAP_FSETID, unix.CAP_NET_BIND_SERVICE,
}

// Main is helper mode: os.Args is exactly [binary, Arg] and the policy is in
// EnvPolicy. On success it never returns — the workload has replaced it, or,
// as a namespace's init, it exits with the workload's status. It returns the
// exit code of a helper that could not set the sandbox up.
func Main() int {
	p, err := Decode(os.Getenv(EnvPolicy))
	if err != nil {
		return failed(err)
	}
	if p.Namespaces && p.Stage == 0 {
		return failed(initNamespace(p))
	}
	return failed(confineAndExec(p))
}

// failed reports a helper that could not start the workload. The message goes
// to the workload's own output, which is where whoever reads the run looks.
func failed(err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintf(os.Stderr, "cloop: host sandbox: %v\n", err)
	return ExitHelperFailed
}

// confineAndExec restricts this thread to the policy and replaces the process
// with the workload. Every step is on one locked thread, the one that execs:
// no_new_privs, the capability sets and the Landlock domain are properties of
// a thread, and execve keeps the calling thread's and discards the others.
func confineAndExec(p Policy) error {
	runtime.LockOSThread()
	program := p.Path
	if program == "" {
		var err error
		if program, err = lookPath(p.Argv[0]); err != nil {
			return err
		}
	}
	if p.Dir != "" {
		if err := os.Chdir(p.Dir); err != nil {
			return fmt.Errorf("enter %s: %w", p.Dir, err)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if err := dropCapabilities(); err != nil {
		return err
	}
	if err := restrict(p); err != nil {
		return err
	}
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, EnvPolicy+"=") {
			env = append(env, kv)
		}
	}
	if err := syscall.Exec(program, p.Argv, env); err != nil {
		return fmt.Errorf("start %s: %w", p.Argv[0], err)
	}
	return nil
}

// lookPath resolves the workload's program on its own PATH, which is this
// process's.
func lookPath(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("find %s: %w", name, err)
	}
	return path, nil
}

// dropCapabilities leaves this thread, and so the workload, with keptCaps at
// most. A process without capabilities has nothing to drop, and the ambient
// set is cleared either way.
func dropCapabilities() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil &&
		!errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("clear the ambient capabilities: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("read the capabilities: %w", err)
	}
	if data[0].Effective == 0 && data[1].Effective == 0 && data[0].Permitted == 0 && data[1].Permitted == 0 {
		return nil
	}
	keep := map[uintptr]bool{}
	for _, c := range keptCaps {
		keep[c] = true
	}
	last := lastCap()
	for c := uintptr(0); c <= last; c++ {
		if keep[c] {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop capability %d from the bounding set: %w", c, err)
		}
	}
	var mask [2]uint32
	for _, c := range keptCaps {
		mask[c/32] |= 1 << (c % 32)
	}
	for i := range data {
		data[i].Effective &= mask[i]
		data[i].Permitted &= mask[i]
		data[i].Inheritable = 0
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("drop the capabilities: %w", err)
	}
	return nil
}

// lastCap is the highest capability this kernel knows.
func lastCap() uintptr {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 && n < 64 {
			return uintptr(n)
		}
	}
	return unix.CAP_LAST_CAP
}

// initNamespace is the first helper in namespace mode: PID 1 of fresh mount,
// PID and IPC namespaces the driver created it in. It makes /tmp, /var/tmp,
// /dev/shm and /run private, mounts a /proc showing only this namespace,
// starts the second helper, and then stays as the namespace's init — passing
// signals on, reaping what is orphaned to it, and exiting with the workload's
// status. When it exits, the kernel kills everything left in the namespace.
func initNamespace(p Policy) error {
	if os.Getpid() != 1 {
		return fmt.Errorf("namespace mode needs a fresh PID namespace, and this helper is pid %d", os.Getpid())
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this binary: %w", err)
	}
	// Held open across the mounts and executed through its descriptor: a
	// binary under /tmp (a test's, or a hub run from a scratch directory) is
	// hidden once the private /tmp is in place.
	selfFD, err := unix.Open(self, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("hold this binary: %w", err)
	}
	defer unix.Close(selfFD)
	if err := privateMounts(p); err != nil {
		return err
	}
	next := p
	next.Stage = 1
	enc, err := next.Encode()
	if err != nil {
		return err
	}
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, EnvPolicy+"=") {
			env = append(env, kv)
		}
	}
	env = append(env, EnvPolicy+"="+enc)

	// Notified before the child exists, so a signal sent at once is not lost.
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
		syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH)
	child, err := syscall.ForkExec("/proc/self/fd/"+strconv.Itoa(selfFD), []string{self, Arg}, &syscall.ProcAttr{
		Dir:   p.Dir,
		Env:   env,
		Files: []uintptr{0, 1, 2},
	})
	if err != nil {
		return fmt.Errorf("start the sandboxed helper: %w", err)
	}
	go func() {
		for s := range sigs {
			_ = syscall.Kill(child, s.(syscall.Signal))
		}
	}()
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("wait for the workload: %w", err)
		}
		if pid != child {
			continue // an orphan the namespace's init reaps
		}
		switch {
		case ws.Exited():
			os.Exit(ws.ExitStatus())
		case ws.Signaled():
			// A namespace's init cannot die of a signal it sends itself, so
			// the shell's convention says which one ended the workload.
			os.Exit(128 + int(ws.Signal()))
		}
	}
}

// privateMounts builds the workload's view of the filesystem.
//
// /tmp and /var/tmp become the driver's private directory, /dev/shm and /run
// fresh tmpfs instances, and /dev/pts a terminal instance of the workload's
// own. What the policy grants beneath those — the run's lease directory, the
// resolver configuration, a project kept under /tmp, the binary that runs it —
// is bound back into the private view. Then the whole tree is made read-only,
// and only the writable grants are writable again: Landlock decides what may
// be opened, and not chmod, chown, utimes or setxattr, which the read-only
// mounts stop on everything the workload may not write.
//
// Every path is opened through openGrant, and the writable grants are put
// back by descriptor (open_tree and move_mount), never by name: a link an
// earlier run left in a directory it could write leads nowhere.
func privateMounts(p Policy) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make the mount namespace private: %w", err)
	}
	anchors := p.ReadWrite
	var fds []int
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	keepFD := func(fd int) int { fds = append(fds, fd); return fd }

	// Grants beneath the directories made private, held before anything is
	// covered: once a directory is replaced, its paths name the new one.
	type held struct {
		path     string
		fd       int
		dir      bool
		writable bool
	}
	var keep []held
	seen := map[string]bool{}
	hold := func(path string, writable, optional bool) error {
		path = filepath.Clean(path)
		if !underAny(path, privateDirs) || seen[path] {
			return nil
		}
		seen[path] = true
		fd, err := openGrant(path, anchors, 0)
		if err != nil {
			if optional && errors.Is(err, unix.ENOENT) {
				return nil
			}
			return fmt.Errorf("hold %s: %w", path, err)
		}
		keepFD(fd)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		keep = append(keep, held{path: path, fd: fd, dir: st.Mode&unix.S_IFMT == unix.S_IFDIR, writable: writable})
		return nil
	}
	for _, list := range []struct {
		paths              []string
		writable, optional bool
	}{
		{p.ReadWrite, true, false}, {[]string{p.Dir}, true, true}, {p.Devices, true, true},
		{p.ReadOnly, false, true},
	} {
		for _, path := range list.paths {
			if path == "" {
				continue
			}
			if err := hold(path, list.writable, list.optional); err != nil {
				return err
			}
		}
	}
	// Outer paths first; one beneath a path already kept comes back with it.
	sort.Slice(keep, func(i, j int) bool { return len(keep[i].path) < len(keep[j].path) })

	// The writable grants elsewhere, cloned while the tree is still writable,
	// to be put back once it is not. One beneath another comes with it.
	type clone struct{ target, tree int }
	var clones []clone
	writable := append([]string(nil), p.ReadWrite...)
	sort.Slice(writable, func(i, j int) bool { return len(writable[i]) < len(writable[j]) })
	var cloned []string
	for _, path := range writable {
		path = filepath.Clean(path)
		if underAny(path, privateDirs) || beneathAny(path, cloned) {
			continue
		}
		target, err := openGrant(path, anchors, 0)
		if err != nil {
			return fmt.Errorf("hold %s: %w", path, err)
		}
		keepFD(target)
		tree, err := unix.OpenTree(target, "", unix.OPEN_TREE_CLONE|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE|unix.O_CLOEXEC)
		if err != nil {
			return fmt.Errorf("clone %s: %w", path, err)
		}
		keepFD(tree)
		clones = append(clones, clone{target: target, tree: tree})
		cloned = append(cloned, path)
	}

	if p.Tmp != "" {
		tmp, err := unix.Open(p.Tmp, unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
		if err != nil {
			return fmt.Errorf("hold the private temporary directory %s: %w", p.Tmp, err)
		}
		keepFD(tmp)
		for _, dir := range []string{"/tmp", "/var/tmp"} {
			if !realDir(dir) {
				continue
			}
			if err := unix.Mount("/proc/self/fd/"+strconv.Itoa(tmp), dir, "", unix.MS_BIND, ""); err != nil {
				return fmt.Errorf("make %s private: %w", dir, err)
			}
		}
	}
	for _, m := range []struct{ dir, fs, opts string }{
		{"/dev/shm", "tmpfs", "mode=1777,size=256m"},
		{"/run", "tmpfs", "mode=755,size=16m"},
		{"/var/run", "tmpfs", "mode=755,size=16m"},
		{"/dev/pts", "devpts", "newinstance,ptmxmode=0666,mode=0620"},
	} {
		if !realDir(m.dir) {
			continue
		}
		if err := unix.Mount(m.fs, m.dir, m.fs, unix.MS_NOSUID|unix.MS_NOEXEC, m.opts); err != nil {
			return fmt.Errorf("make %s private: %w", m.dir, err)
		}
	}
	if fi, err := os.Lstat("/dev/ptmx"); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		if err := unix.Mount("/dev/pts/ptmx", "/dev/ptmx", "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("give the workload a terminal instance of its own: %w", err)
		}
	}
	var kept []string
	var rebind []string
	for _, k := range keep {
		if beneathAny(k.path, kept) {
			continue
		}
		if k.dir {
			if err := os.MkdirAll(k.path, 0o700); err != nil {
				return fmt.Errorf("keep %s: %w", k.path, err)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
				return fmt.Errorf("keep %s: %w", k.path, err)
			}
			if err := unix.Mknod(k.path, unix.S_IFREG|0o600, 0); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("keep %s: %w", k.path, err)
			}
		}
		if err := unix.Mount("/proc/self/fd/"+strconv.Itoa(k.fd), k.path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("keep %s: %w", k.path, err)
		}
		kept = append(kept, k.path)
		if k.writable {
			rebind = append(rebind, k.path)
		}
	}

	// Read-only, all of it; then writable where the policy says.
	if err := unix.MountSetattr(-1, "/", unix.AT_RECURSIVE, &unix.MountAttr{
		Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID,
	}); err != nil {
		return fmt.Errorf("make the filesystem read-only: %w", err)
	}
	clear := &unix.MountAttr{Attr_clr: unix.MOUNT_ATTR_RDONLY}
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/dev/pts"} {
		if !realDir(dir) {
			continue
		}
		if err := unix.MountSetattr(-1, dir, 0, clear); err != nil {
			return fmt.Errorf("make %s writable: %w", dir, err)
		}
	}
	for _, path := range rebind {
		// Opened afresh, so the descriptor is the mount just made: nothing
		// beneath a private directory has been written since.
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("reopen %s: %w", path, err)
		}
		err = unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH|unix.AT_RECURSIVE, clear)
		_ = unix.Close(fd)
		if err != nil {
			return fmt.Errorf("make %s writable: %w", path, err)
		}
	}
	for _, c := range clones {
		if err := unix.MoveMount(c.tree, "", c.target, "",
			unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
			return fmt.Errorf("put a writable grant back: %w", err)
		}
	}
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount this namespace's /proc: %w", err)
	}
	return nil
}

// beneathAny reports whether path lies beneath one of dirs (not equal to it).
func beneathAny(path string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

// realDir reports whether path is a directory and not a link to one: /var/run
// is a link to /run on most systems, and covering it would cover /run twice.
func realDir(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.IsDir()
}

// Wrap turns cmd, built to run p's program, into one that runs it in the
// sandbox: the helper (helper, this binary) started with the policy in its
// environment, in fresh namespaces when p.Namespaces says so. cmd.Env must be
// the workload's whole environment; nil is read as this process's.
func Wrap(cmd *exec.Cmd, helper string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := Available(); err != nil {
		return err
	}
	if p.Namespaces && os.Geteuid() != 0 {
		return fmt.Errorf("%w: namespace mode needs a hub running as root", ErrUnsupported)
	}
	p.Stage = 0
	enc, err := p.Encode()
	if err != nil {
		return err
	}
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(append([]string(nil), env...), EnvPolicy+"="+enc)
	cmd.Path = helper
	cmd.Args = []string{helper, Arg}
	cmd.Err = nil
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	if p.Namespaces {
		cmd.SysProcAttr.Cloneflags |= unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWIPC
	}
	return nil
}

// UsesNamespaces reports whether a workload of this process is sandboxed in
// namespace mode: when the process runs as root, the only uid for which the
// host's daemons and every file's owner bits make the filesystem rules alone
// no boundary.
func UsesNamespaces() bool { return os.Geteuid() == 0 }
