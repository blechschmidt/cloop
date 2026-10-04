package localprocess

// A host workload's lease files rewritten in place (Task 20375).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestRefreshRewritesTheBoundLeaseFile(t *testing.T) {
	dir, err := os.MkdirTemp(t.TempDir(), "cloop-lease-")
	if err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "github-token")
	if err := os.WriteFile(token, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ex := New("refresh-host")
	h, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "sleep 30"},
		Secrets: []executor.SecretBinding{{
			LeaseID: "lease_h", GrantID: "g", Dir: dir, Files: []string{token},
		}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = ex.Signal(ctx, h.ID, executor.SignalKill)
	})

	rep := ex.RefreshSecretFiles(context.Background(), executor.SecretRefreshRequest{
		LeaseID: "lease_h",
		Files: []executor.SecretFile{
			{Dir: dir, Name: "github-token", Mode: 0o600, Content: []byte("second\n")},
			{Dir: dir, Name: "not-delivered", Mode: 0o600, Content: []byte("x")},
		},
	})
	if rep.FilesRewritten != 1 || !rep.Known || !strings.Contains(rep.Error, "was not delivered") {
		t.Fatalf("report = %+v; want the bound file rewritten and the other refused", rep)
	}
	if got, _ := os.ReadFile(token); string(got) != "second\n" {
		t.Fatalf("token = %q after the refresh", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "not-delivered")); err == nil {
		t.Fatal("the refresh planted a file the lease never delivered")
	}
	if rep := ex.RefreshSecretFiles(context.Background(), executor.SecretRefreshRequest{
		LeaseID: "lease_elsewhere", Files: []executor.SecretFile{{Dir: dir, Name: "github-token", Content: []byte("x")}},
	}); rep.Known || rep.Error != "" {
		t.Fatalf("a lease this executor does not hold = %+v", rep)
	}
}
