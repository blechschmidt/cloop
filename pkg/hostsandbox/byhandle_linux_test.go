//go:build linux

package hostsandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// openByHandle names path by its handle and opens it through mount, a
// directory on the same filesystem the workload may write, printing whether
// it could read it.
func openByHandle(path, mount string) int {
	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		fmt.Printf("byhandle:no-handle %v\n", err)
		return 0
	}
	mfd, err := unix.Open(mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Printf("byhandle:no-mount %v\n", err)
		return 0
	}
	fd, err := unix.OpenByHandleAt(mfd, h, unix.O_RDONLY)
	if err != nil {
		fmt.Printf("byhandle:denied %v\n", err)
		return 0
	}
	buf := make([]byte, 64)
	n, _ := unix.Read(fd, buf)
	fmt.Printf("byhandle:read %q\n", buf[:n])
	return 0
}

// TestAFileOutsideTheGrantsCannotBeOpenedByItsHandle: open_by_handle_at
// reaches a file through any mount of its filesystem, and Landlock judges it
// by that mount's rules — so a root workload holding CAP_DAC_READ_SEARCH could
// read and write any file on the filesystem of a directory it may write. The
// sandbox keeps the capability from it.
func TestAFileOutsideTheGrantsCannotBeOpenedByItsHandle(t *testing.T) {
	if !UsesNamespaces() {
		t.Skip("only a root workload could hold the capability")
	}
	if err := Available(); err != nil {
		t.Skipf("no host sandbox here: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil || underAny(home, privateDirs) || home == "/" {
		t.Skipf("no home outside the private directories: %q %v", home, err)
	}
	root, err := os.MkdirTemp(home, ".hostsandbox-handle-")
	if err != nil {
		t.Skipf("cannot write under %s: %v", home, err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	project, secret := filepath.Join(root, "project"), filepath.Join(root, "secret.txt")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("another person's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	self, err := HelperPath()
	if err != nil {
		t.Fatal(err)
	}
	f := sandboxFixture{root: root, project: project, home: project, other: root,
		readOnly: self, tmp: filepath.Join(root, "tmp")}
	if err := os.Mkdir(f.tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	p := f.policy(true, "")
	p.Argv = []string{self, byHandleArg, secret, project}
	p.ReadWrite = []string{project}
	out, code := f.run(t, p)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "another person's file") || !strings.Contains(out, "byhandle:denied") {
		t.Fatalf("a file outside every grant, by its handle: %s", out)
	}
}
