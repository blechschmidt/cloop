//go:build linux

package hostsandbox

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// abi asks the kernel which Landlock ABI it speaks: 0 with the reason when it
// speaks none (not built in, not enabled at boot, or not reachable).
func abi() (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, abiError(errno)
	}
	return int(v), nil
}

// abiError says what an errno from the version query means. Separate from the
// call so the wording of each case is a test rather than a guess about a
// kernel the test machine does not have.
func abiError(errno syscall.Errno) error {
	switch errno {
	case syscall.ENOSYS:
		return fmt.Errorf("%w: this kernel has no Landlock (Linux 5.13 or later, built with CONFIG_SECURITY_LANDLOCK)", ErrUnsupported)
	case syscall.EOPNOTSUPP:
		return fmt.Errorf("%w: Landlock is not enabled on this kernel (add landlock to the lsm= boot parameter)", ErrUnsupported)
	case syscall.EPERM:
		// Not an error the version query itself returns: asking which ABI the
		// kernel speaks takes no privilege. EPERM means something between
		// this process and the kernel refused the call — a seccomp filter, as
		// systemd installs from SystemCallFilter= with
		// SystemCallErrorNumber=EPERM. @system-service does not cover the
		// Landlock calls (they are systemd's @sandbox set), so a hardened
		// unit that does not name them leaves the process unable to confine
		// anything (Task 49). Saying so beats reporting a bare errno: the
		// kernel is usually perfectly capable, and the fix is one directive.
		return fmt.Errorf("%w: landlock_create_ruleset is blocked before it reaches the kernel (EPERM). "+
			"A seccomp filter is the usual reason: under systemd, SystemCallFilter=@system-service "+
			"does not include the Landlock calls, so the unit must also allow %q", ErrUnsupported,
			"landlock_create_ruleset landlock_add_rule landlock_restrict_self")
	default:
		return fmt.Errorf("%w: query the Landlock ABI: %v", ErrUnsupported, errno)
	}
}

// The filesystem rights of each ABI.
const (
	fsRightsV1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM

	// fileRights are the rights the kernel accepts on a rule for a file
	// rather than a directory.
	fileRights = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE |
		unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

	readRights = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR

	// writeRights is everything but making device nodes: a workload that
	// could mknod a block device in its project could read the disk under
	// every rule here.
	writeRights = readRights | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

	deviceRights = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_TRUNCATE |
		unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

// handledRights are the filesystem rights a ruleset of this ABI restricts.
// Every right the kernel knows is handled, so anything a rule does not grant
// is denied.
func handledRights(v int) uint64 {
	r := uint64(fsRightsV1)
	if v >= 2 {
		r |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if v >= 3 {
		r |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if v >= 5 {
		r |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return r
}

// scopes are the IPC scopes a ruleset of this ABI restricts: from ABI 6, a
// sandboxed process can neither signal a process outside its domain nor
// connect to an abstract socket one made.
func scopes(v int) uint64 {
	if v >= 6 {
		return unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL
	}
	return 0
}

// rule is one path and what may be done beneath it.
type rule struct {
	path     string
	rights   uint64
	required bool
}

// rules turns a policy into Landlock rules.
func rules(p Policy) []rule {
	var out []rule
	for _, path := range p.ReadWrite {
		out = append(out, rule{path: path, rights: writeRights, required: true})
	}
	if p.Tmp != "" {
		if p.Namespaces {
			for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
				out = append(out, rule{path: d, rights: writeRights})
			}
		} else {
			out = append(out, rule{path: p.Tmp, rights: writeRights, required: true})
		}
	}
	if p.Namespaces {
		// The terminal instance namespace mode mounts for this workload alone.
		for _, d := range []string{"/dev/pts", "/dev/ptmx"} {
			out = append(out, rule{path: d, rights: deviceRights})
		}
	}
	for _, path := range p.ReadOnly {
		out = append(out, rule{path: path, rights: readRights})
	}
	for _, path := range p.ListOnly {
		out = append(out, rule{path: path, rights: unix.LANDLOCK_ACCESS_FS_READ_DIR})
	}
	for _, path := range p.Devices {
		out = append(out, rule{path: path, rights: deviceRights})
	}
	return out
}

// restrict confines the calling thread to the policy's rules. The caller has
// locked itself to its thread and set no_new_privs; it execs from the same
// thread, which is what makes the restriction the workload's.
func restrict(p Policy) error {
	v, err := abi()
	if err != nil {
		return err
	}
	if v < MinABI {
		return fmt.Errorf("%w: this kernel speaks Landlock ABI %d, and the sandbox needs %d (Linux 6.2 or later)",
			ErrUnsupported, v, MinABI)
	}
	handled := handledRights(v)
	attr := unix.LandlockRulesetAttr{Access_fs: handled, Scoped: scopes(v)}
	size := unsafe.Offsetof(attr.Access_net) // Access_fs alone
	if attr.Scoped != 0 {
		size = unsafe.Sizeof(attr)
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno != 0 {
		return fmt.Errorf("hostsandbox: create the Landlock ruleset: %w", errno)
	}
	ruleset := int(fd)
	defer unix.Close(ruleset)
	for _, r := range rules(p) {
		if err := addRule(ruleset, r, handled, p.ReadWrite, p.ListOnly); err != nil {
			return err
		}
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return fmt.Errorf("hostsandbox: enter the Landlock ruleset: %w", errno)
	}
	return nil
}

// addRule grants r beneath its path. A path that does not exist is skipped
// unless the rule is required: the defaults name directories some
// distributions do not have. anchors are the writable grants, beneath which a
// path is opened without following a link out (openGrant); strict are the
// roots of other projects the workload may read, beneath which a path is
// opened following no link at all, and one that is a link is skipped.
func addRule(ruleset int, r rule, handled uint64, anchors, strict []string) error {
	fd, err := openGrantIn(r.path, anchors, strict, 0)
	if err != nil {
		if !r.required && (errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) ||
			errors.Is(err, unix.EACCES) || errors.Is(err, errLinkInReadOnly)) {
			return nil
		}
		return fmt.Errorf("hostsandbox: open %s for the sandbox: %w", r.path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("hostsandbox: stat %s: %w", r.path, err)
	}
	rights := r.rights & handled
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		rights &= fileRights
	}
	if rights == 0 {
		return nil
	}
	attr := unix.LandlockPathBeneathAttr{Allowed_access: rights, Parent_fd: int32(fd)}
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset),
		unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("hostsandbox: grant %s: %w", r.path, errno)
	}
	return nil
}

// openGrant opens path with O_PATH, for a rule or a bind. A path beneath one
// of anchors — a directory the workload may write, where an earlier run could
// have left a link — is resolved from that anchor with RESOLVE_BENEATH, so a
// link pointing out of it is refused rather than followed: a run that turned
// its home's sandbox-home into a link to / gets nothing from it next time.
// Anything else, the system's directories and the anchors themselves, is
// opened by name, links and all: nothing the workload can write leads there.
func openGrant(path string, anchors []string, flags int) (int, error) {
	return openGrantIn(path, anchors, nil, flags)
}

// errLinkInReadOnly is an entry of another project the workload may read that
// is a link (Task 20501): that project's own runs may have planted it to have
// this workload granted whatever it names, so it is not granted at all.
var errLinkInReadOnly = errors.New("a link in a project the workload may read")

// openGrantIn is openGrant with strict anchors as well: the roots of other
// projects the workload may read, whose own runs can write them. A path
// beneath one is resolved from it following no link — not even one that stays
// inside — and the root itself is opened without following a link at its last
// component, so that what is granted is what the driver listed, whatever those
// runs did since.
func openGrantIn(path string, anchors, strict []string, flags int) (int, error) {
	path = filepath.Clean(path)
	anchor, isStrict := "", false
	for _, a := range anchors {
		a = filepath.Clean(a)
		if a != path && strings.HasPrefix(path, a+"/") && len(a) > len(anchor) {
			anchor, isStrict = a, false
		}
	}
	for _, a := range strict {
		a = filepath.Clean(a)
		if a != path && strings.HasPrefix(path, a+"/") && len(a) > len(anchor) {
			anchor, isStrict = a, true
		}
	}
	if anchor == "" {
		for _, a := range strict {
			if filepath.Clean(a) == path {
				flags |= unix.O_NOFOLLOW
			}
		}
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|flags, 0)
		if err == nil && flags&unix.O_NOFOLLOW != 0 {
			var st unix.Stat_t
			if serr := unix.Fstat(fd, &st); serr != nil || st.Mode&unix.S_IFMT == unix.S_IFLNK {
				_ = unix.Close(fd)
				return -1, fmt.Errorf("%s: %w", path, errLinkInReadOnly)
			}
		}
		return fd, err
	}
	afd, err := openGrantIn(anchor, anchors, strict, unix.O_DIRECTORY)
	if err != nil {
		return -1, err
	}
	defer unix.Close(afd)
	resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS)
	if isStrict {
		resolve |= unix.RESOLVE_NO_SYMLINKS
	}
	fd, err := unix.Openat2(afd, strings.TrimPrefix(path, anchor+"/"), &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_CLOEXEC | flags),
		Resolve: resolve,
	})
	switch {
	case isStrict && (errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV)):
		return -1, fmt.Errorf("%s: %w", path, errLinkInReadOnly)
	case errors.Is(err, unix.EXDEV):
		return -1, fmt.Errorf("%s leads out of %s, which the workload can write: %w", path, anchor, err)
	}
	return fd, err
}

// ABI reports the Landlock ABI this kernel speaks, or why it speaks none.
func ABI() (int, error) { return abi() }

// Available reports whether this host can sandbox a workload, and why not.
func Available() error {
	v, err := abi()
	if err != nil {
		return err
	}
	if v < MinABI {
		return fmt.Errorf("%w: this kernel speaks Landlock ABI %d, and the sandbox needs %d (Linux 6.2 or later)",
			ErrUnsupported, v, MinABI)
	}
	return nil
}
