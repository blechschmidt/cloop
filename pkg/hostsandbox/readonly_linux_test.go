//go:build linux

package hostsandbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAnotherProjectsEntriesAreOpenedFollowingNoLink (Task 20501): an entry
// of a project the workload may read is opened beneath that project's root
// following no link at all — one its own runs swapped for a link to anywhere,
// inside the project or out of it, is refused rather than granted — and the
// root itself is never a link.
func TestAnotherProjectsEntriesAreOpenedFollowingNoLink(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "api")
	secret := filepath.Join(base, "control-plane")
	for _, d := range []string{filepath.Join(root, "src"), filepath.Join(root, ".cloop"), secret} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"outside": secret, "inside": ".cloop"} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("api", filepath.Join(base, "api-link")); err != nil {
		t.Fatal(err)
	}
	strict := []string{root}

	fd, err := openGrantIn(filepath.Join(root, "src"), nil, strict, 0)
	if err != nil {
		t.Fatalf("a directory of the project was refused: %v", err)
	}
	_ = unix.Close(fd)
	for _, link := range []string{"outside", "inside"} {
		if fd, err := openGrantIn(filepath.Join(root, link), nil, strict, 0); !errors.Is(err, errLinkInReadOnly) {
			if err == nil {
				_ = unix.Close(fd)
			}
			t.Errorf("the link %s was opened (%v); want errLinkInReadOnly", link, err)
		}
	}
	if fd, err := openGrantIn(filepath.Join(base, "api-link"), nil, []string{filepath.Join(base, "api-link")}, 0); !errors.Is(err, errLinkInReadOnly) {
		if err == nil {
			_ = unix.Close(fd)
		}
		t.Errorf("a project root that is a link was opened (%v); want errLinkInReadOnly", err)
	}
	// A rule on a link is skipped, not failed: a project's runs planting one
	// must not stop another project's run from starting.
	if err := addRule(-1, rule{path: filepath.Join(root, "outside"), rights: readRights}, handledRights(3), nil,
		strict); err != nil {
		t.Errorf("a rule on a planted link failed the sandbox instead of being skipped: %v", err)
	}
}
