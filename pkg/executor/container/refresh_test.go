package container

// The staged half of a token refresh, with no runtime (Task 20375): a staged
// file is rewritten in place in its host directory, and nothing that was not
// staged for the lease can be written.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestStageRefreshRewritesOnlyWhatWasStaged(t *testing.T) {
	const dir = "/run/cloop/cloop-lease-stagetest"
	spec := executor.Spec{SecretFiles: []executor.SecretFile{{
		LeaseID: "lease_s", GrantID: "g", Dir: dir, Name: "github-token", Mode: 0o600, Content: []byte("first\n"),
	}}}
	stage, err := stageSecretFiles(spec, "")
	if err != nil {
		t.Fatalf("stageSecretFiles: %v", err)
	}
	defer stage.remove()
	host := stage.files[0].host

	n, err := stage.refresh(executor.SecretRefreshRequest{LeaseID: "lease_s", Files: []executor.SecretFile{{
		LeaseID: "lease_s", Dir: dir, Name: "github-token", Mode: 0o600, Content: []byte("second\n"),
	}}})
	if err != nil || n != 1 {
		t.Fatalf("refresh = %d, %v", n, err)
	}
	if got, _ := os.ReadFile(host); string(got) != "second\n" {
		t.Fatalf("staged file = %q after the refresh", got)
	}

	n, err = stage.refresh(executor.SecretRefreshRequest{LeaseID: "lease_s", Files: []executor.SecretFile{{
		LeaseID: "lease_s", Dir: dir, Name: "planted", Mode: 0o600, Content: []byte("x"),
	}}})
	if n != 0 || err == nil || !strings.Contains(err.Error(), "was not delivered") {
		t.Fatalf("a file never staged was written: %d, %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(host), "planted")); err == nil {
		t.Fatal("the refresh created a new file in the staged directory")
	}
	n, err = stage.refresh(executor.SecretRefreshRequest{LeaseID: "lease_other", Files: []executor.SecretFile{{
		Dir: dir, Name: "github-token", Mode: 0o600, Content: []byte("x"),
	}}})
	if n != 0 || err == nil {
		t.Fatalf("another lease's refresh rewrote this lease's file: %d, %v", n, err)
	}
}
