package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/readonlysnap"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
)

// TestWorkspaceProvisionParsesTheReadOnlyFlags is the drift gate for the flags
// pkg/executor/kubernetes renders for the projects a run may read (Task
// 20501): see buildWorkspaceInitContainer.
func TestWorkspaceProvisionParsesTheReadOnlyFlags(t *testing.T) {
	resetWorkspaceProvisionFlags(t)
	t.Cleanup(func() {
		workspaceProvisionReadOnly = nil
		workspaceProvisionReadOnlyDir = ""
		workspaceProvisionReadOnlyEnv = knowledgerun.EnvReadersToken
	})
	argv := []string{
		"--dir", "/workspace/project", "--repo", "https://github.com/acme/app.git",
		"--readonly-snapshot", "api=https://hub.example/api/run/knowledge/readonly/snapshot",
		"--readonly-snapshot", "web=https://hub.example/api/run/knowledge/readonly/snapshot",
		"--readonly-dir", "/readonly", "--readonly-token-env", "CLOOP_READERS_TOKEN",
	}
	if err := workspaceProvisionCmd.ParseFlags(argv); err != nil {
		t.Fatalf("the driver's argv must parse: %v", err)
	}
	if strings.Join(workspaceProvisionReadOnly, " ") != "api=https://hub.example/api/run/knowledge/readonly/snapshot "+
		"web=https://hub.example/api/run/knowledge/readonly/snapshot" || workspaceProvisionReadOnlyDir != "/readonly" ||
		workspaceProvisionReadOnlyEnv != "CLOOP_READERS_TOKEN" {
		t.Fatalf("parsed %v %q %q", workspaceProvisionReadOnly, workspaceProvisionReadOnlyDir, workspaceProvisionReadOnlyEnv)
	}
}

// TestPlaceReadOnlySnapshotsUnpacksWhatTheHubServes: each project the hub
// serves a snapshot of is unpacked read-only under the directory, fetched with
// the run's token; one the hub refuses is left out and said, and the run's
// workspace container does not fail for it.
func TestPlaceReadOnlySnapshotsUnpacksWhatTheHubServes(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	project := filepath.Join(t.TempDir(), "api")
	for rel, body := range map[string]string{"README.md": "api readme\n", "src/api.go": "package api\n",
		".cloop/config.yaml": "secret\n", ".env": "TOKEN=secret\n"} {
		p := filepath.Join(project, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const token = knowledgerun.TokenPrefix + "abcdefabcdefabcdefabcdef.secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req knowledgerun.SnapshotRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.Header.Get("Authorization") != "Bearer "+token || req.Slug != "api" {
			http.Error(w, `{"error":"no project this run may read is at that path"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		if _, err := readonlysnap.Build(r.Context(), project, w); err != nil {
			t.Errorf("Build: %v", err)
		}
	}))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "readonly")
	t.Cleanup(func() {
		_ = readonlysnap.Remove(filepath.Join(dir, "api"))
	})
	var out bytes.Buffer
	url := srv.URL + knowledgerun.MountPath + knowledgerun.PathReadOnlySnapshot
	if err := placeReadOnlySnapshots(context.Background(), dir, []string{"api=" + url, "gone=" + url}, token,
		&out); err != nil {
		t.Fatalf("placeReadOnlySnapshots: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "api", "src", "api.go")); err != nil || string(b) != "package api\n" {
		t.Fatalf("api/src/api.go = %q, %v (log %s)", b, err, out.String())
	}
	for _, hidden := range []string{".cloop", ".env"} {
		if _, err := os.Lstat(filepath.Join(dir, "api", hidden)); err == nil {
			t.Errorf("the snapshot placed %s", hidden)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, "api")); err != nil || fi.Mode().Perm() != 0o555 {
		t.Errorf("api is %v, %v; want a read-only directory", fi.Mode(), err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "gone")); err == nil {
		t.Error("a project the hub refused has a directory")
	}
	if !strings.Contains(out.String(), "read-only project gone: not placed") ||
		!strings.Contains(out.String(), "read-only project api: placed") {
		t.Errorf("log does not say what was placed and what was not:\n%s", out.String())
	}

	// No token, nothing fetched, and still no failure.
	out.Reset()
	dir2 := filepath.Join(t.TempDir(), "readonly")
	if err := placeReadOnlySnapshots(context.Background(), dir2, []string{"api=" + url}, "", &out); err != nil {
		t.Fatalf("placeReadOnlySnapshots with no token: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir2, "api")); err == nil || !strings.Contains(out.String(), "not placed") {
		t.Fatalf("a fetch with no token placed something: %s", out.String())
	}
	if strings.Contains(out.String(), token) {
		t.Fatal("the log carries the token")
	}
}
