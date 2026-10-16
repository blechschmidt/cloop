//go:build linux

package rootkey

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// setfacl runs setfacl(1), the independent writer of the ACLs readACL reads,
// and skips when it is not installed or the filesystem keeps no ACLs.
func setfacl(t *testing.T, spec, path string) {
	t.Helper()
	bin, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl is not installed")
	}
	if out, err := exec.Command(bin, "-m", spec, path).CombinedOutput(); err != nil {
		t.Skipf("setfacl -m %s: %v: %s (no ACLs on this filesystem?)", spec, err, out)
	}
}

// readACL reads what setfacl wrote, through the open descriptor, and nil for a
// file that has no extended ACL.
func TestReadACLReadsWhatSetfaclWrote(t *testing.T) {
	path := keyFile(t, keyA)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if acl, err := readACL(f); err != nil || acl != nil {
		t.Errorf("a file with no extended ACL: %v, %v", acl, err)
	}
	f.Close()

	setfacl(t, "u:65534:r", path)
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	acl, err := readACL(f)
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, e := range acl {
		if e.tag == aclUser && e.id == 65534 && e.perm == aclRead {
			named = true
		}
	}
	if !named {
		t.Errorf("readACL = %+v, want an entry granting uid 65534 read", acl)
	}
}

// The whole path for a systemd credential (Task 20431): a root-owned file,
// 0440 by stat, which this process reads through an ACL naming its user —
// accepted — and the same file once the ACL also names another user, or with
// no ACL at all — refused. Root makes the file; the resolver is told it runs
// as another uid, which is the identity the rule judges against.
func TestARootOwnedKeyFileReadThroughAnACL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a root-owned file another uid reads")
	}
	const uid = 65534
	path := filepath.Join(t.TempDir(), "cloop-secret-key")
	if err := os.WriteFile(path, []byte(keyA), 0o400); err != nil {
		t.Fatal(err)
	}
	as := func() (Roots, error) {
		rv := self(map[string]string{EnvKeyFile: path})
		rv.euid, rv.gid, rv.groups = uid, uid, nil
		return rv.resolve()
	}

	setfacl(t, "u:"+strconv.Itoa(uid)+":r,g::-,m::r", path)
	if r, err := as(); err != nil || r.Current.Value != keyA {
		t.Fatalf("the systemd shape: %v", err)
	}

	setfacl(t, "u:1001:r", path)
	if _, err := as(); !errors.Is(err, ErrRefused) {
		t.Errorf("an ACL naming another user too: err = %v, want ErrRefused", err)
	}

	if out, err := exec.Command("setfacl", "-b", path).CombinedOutput(); err != nil {
		t.Fatalf("setfacl -b: %v: %s", err, out)
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := as(); !errors.Is(err, ErrRefused) {
		t.Errorf("root's 0440 with no ACL, through a group the process is not in: err = %v, want ErrRefused", err)
	}
}
