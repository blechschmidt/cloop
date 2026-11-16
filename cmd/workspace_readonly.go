package cmd

// workspace_readonly.go: placing the other projects a run may read into a
// Kubernetes Pod (Task 20501). The workspace init container fetches a snapshot
// of each from the hub with the run's session token and unpacks it into the
// volume the harness mounts read-only at /readonly.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/readonlysnap"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
)

// takeReadOnlyToken reads the run's session token from the variable named,
// and removes it from this process's environment: git, which provisioning
// runs, never needs it.
func takeReadOnlyToken(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	token := strings.TrimSpace(os.Getenv(name))
	_ = os.Unsetenv(name)
	return token
}

// placeReadOnlySnapshots fetches and unpacks each SLUG=URL of specs into
// dir/SLUG. A project that cannot be placed — the hub refused it, because its
// readers list no longer names the run's project, or the fetch failed — is
// left out and said: the run is told only of the projects whose trees are
// there, and its task-boundary check asks the hub about the rest.
func placeReadOnlySnapshots(ctx context.Context, dir string, specs []string, token string, out io.Writer) error {
	if len(specs) == 0 {
		return nil
	}
	dir = strings.TrimSpace(dir)
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("--readonly-dir %q must be an absolute path", dir)
	}
	if len(specs) > executor.MaxReadOnlyProjects {
		return fmt.Errorf("%d read-only projects, at most %d are allowed", len(specs), executor.MaxReadOnlyProjects)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", dir, err)
	}
	seen := map[string]bool{}
	for _, spec := range specs {
		slug, url, ok := strings.Cut(spec, "=")
		if !ok || !executor.ValidReadOnlySlug(slug) || seen[slug] || strings.TrimSpace(url) == "" {
			return fmt.Errorf("--readonly-snapshot %q is not SLUG=URL with a valid, unique slug", spec)
		}
		seen[slug] = true
		dest := filepath.Join(dir, slug)
		snap, err := placeReadOnlySnapshot(ctx, dest, strings.TrimSpace(url), token, slug)
		if err != nil {
			_ = readonlysnap.Remove(dest)
			fmt.Fprintf(out, "read-only project %s: not placed: %v\n", slug, err)
			continue
		}
		fmt.Fprintf(out, "read-only project %s: placed %d file(s) and %d link(s), %d bytes, read-only at %s\n",
			slug, snap.Files, snap.Links, snap.Bytes, dest)
	}
	return nil
}

// placeReadOnlySnapshot fetches one snapshot and unpacks it at dest.
func placeReadOnlySnapshot(ctx context.Context, dest, url, token, slug string) (*readonlysnap.Snapshot, error) {
	if token == "" {
		return nil, errors.New("the run's session token is not in this container's environment")
	}
	if err := os.Mkdir(dest, 0o755); err != nil {
		return nil, err
	}
	body, err := knowledgerun.OpenSnapshot(ctx, url, token, slug)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return readonlysnap.Extract(body, dest)
}
