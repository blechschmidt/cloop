package gitprovision_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
)

// TestRootOwnedTrust: a Pod's /workspace is an emptyDir root owns, and git
// refuses a work tree another user owns — the first live Kubernetes run found
// every workspace fetch refused that way (Task 20385). Root is the one owner
// whose directory may be trusted, by exact path; anything this process owns
// needs nothing, and a missing directory gets nothing.
func TestRootOwnedTrust(t *testing.T) {
	own := t.TempDir()
	if got := gitprovision.RootOwnedTrust(own); got != nil {
		t.Errorf("a directory this process owns: %q, want nothing", got)
	}
	if got := gitprovision.RootOwnedTrust(filepath.Join(own, "missing")); got != nil {
		t.Errorf("a directory that does not exist: %q, want nothing", got)
	}
	if os.Geteuid() == 0 {
		// Root's own git is never refused, so there is nothing to trust.
		if got := gitprovision.RootOwnedTrust("/"); got != nil {
			t.Errorf("as root: %q, want nothing", got)
		}
		return
	}
	// "/" is owned by root on every Unix this runs on — CI's runner is not root.
	if got, want := gitprovision.RootOwnedTrust("/"), [][2]string{{"safe.directory", "/"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("a root-owned directory: %q, want %q", got, want)
	}
}
