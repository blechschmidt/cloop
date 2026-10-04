//go:build unix

package executor

// ReplaceSecretFile's confinement (Task 20375). A container's lease directory
// belongs to the sandbox user, who can rename and replace entries in it while a
// hub running as root replaces a file there — so nothing the replacement does
// may follow a name that user could have swapped.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func leaseDirWithToken(t *testing.T) (dir, token string) {
	t.Helper()
	dir, err := os.MkdirTemp(t.TempDir(), "cloop-lease-")
	if err != nil {
		t.Fatal(err)
	}
	token = filepath.Join(dir, "github-token")
	if err := os.WriteFile(token, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, token
}

func TestReplaceSecretFileReplacesInPlace(t *testing.T) {
	dir, token := leaseDirWithToken(t)
	id, err := IdentityOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ReplaceSecretFile(token, []byte("second\n"), ReplaceOptions{Dir: &id}); err != nil {
		t.Fatalf("ReplaceSecretFile: %v", err)
	}
	got, _ := os.ReadFile(token)
	info, _ := os.Stat(token)
	if string(got) != "second\n" || info.Mode().Perm() != 0o600 {
		t.Fatalf("token = %q mode %v; want the new content at 0600", got, info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("the directory holds %d entries after a replace, want only the token", len(entries))
	}
}

// TestReplaceSecretFileRefusesALinkedDirectory: the lease directory swapped for
// a symlink to somewhere else is refused, not written through.
func TestReplaceSecretFileRefusesALinkedDirectory(t *testing.T) {
	_, token := leaseDirWithToken(t)
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "github-token"), []byte("victim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "cloop-lease-linked")
	if err := os.Symlink(elsewhere, linked); err != nil {
		t.Fatal(err)
	}
	err := ReplaceSecretFile(filepath.Join(linked, "github-token"), []byte("x"), ReplaceOptions{})
	if err == nil {
		t.Fatal("a replace through a symlinked lease directory succeeded")
	}
	if got, _ := os.ReadFile(filepath.Join(elsewhere, "github-token")); string(got) != "victim\n" {
		t.Fatal("the replace wrote through the link")
	}
	_ = token
}

// TestReplaceSecretFileRefusesASwappedDirectory: a different real directory put
// in the lease directory's place — the rename a sandbox user can make — is not
// the directory the lease created.
func TestReplaceSecretFileRefusesASwappedDirectory(t *testing.T) {
	dir, token := leaseDirWithToken(t)
	id, err := IdentityOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("planted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = ReplaceSecretFile(token, []byte("second\n"), ReplaceOptions{Dir: &id})
	if err == nil || !errors.Is(err, ErrInvalidSpec) || !strings.Contains(err.Error(), "no longer") {
		t.Fatalf("a replace into a swapped directory = %v; want a refusal", err)
	}
}

// TestReplaceSecretFileGivesTheOwnerThroughTheDescriptor: run as root, the new
// file is handed to the sandbox user. That it happens on the descriptor is what
// the symlink tests above rely on; here the result is checked.
func TestReplaceSecretFileGivesTheOwnerThroughTheDescriptor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("handing a file to another user needs root")
	}
	_, token := leaseDirWithToken(t)
	if err := ReplaceSecretFile(token, []byte("second\n"), ReplaceOptions{
		Owner: &FileOwner{UID: 65534, GID: 65534},
	}); err != nil {
		t.Fatalf("ReplaceSecretFile: %v", err)
	}
	info, _ := os.Lstat(token)
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != 65534 || st.Gid != 65534 || info.Mode().Perm() != 0o600 {
		t.Fatalf("token owned by %d:%d mode %v; want 65534:65534 at 0600", st.Uid, st.Gid, info.Mode().Perm())
	}
}

func TestReplaceSecretFileRefusesALinkAtTheName(t *testing.T) {
	dir, token := leaseDirWithToken(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(token); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, token); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceSecretFile(token, []byte("x"), ReplaceOptions{}); err == nil {
		t.Fatal("a link at the token's name was replaced")
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Fatal("the replace wrote through a link")
	}
	if err := ReplaceSecretFile(filepath.Join(dir, "never-delivered"), []byte("x"), ReplaceOptions{}); err == nil {
		t.Fatal("a file the lease never delivered was created")
	}
	if err := ReplaceSecretFile(filepath.Join(t.TempDir(), "github-token"), []byte("x"), ReplaceOptions{}); err == nil {
		t.Fatal("a file outside any lease directory was accepted")
	}
}
