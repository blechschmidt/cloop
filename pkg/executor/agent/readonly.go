package agent

// readonly.go: placing the other projects a run may read on this device
// (Spec.ReadOnly, Task 20501).
//
// The hub gives a run another project's tree when that project's readers list
// names the run's project. A device shares no filesystem with the hub, so each
// arrives as a snapshot this agent fetches from the hub — with the run's own
// session token, from the URL the entry names, which the hub serves only while
// the list still names the run's project — and unpacks beneath its root, in a
// directory of the workload's own that only this agent writes. The payload is
// given it read-only:
//
//   - in a container (a sandbox mode of container, or a virtual executor) it is
//     bound read-only at /readonly/<slug>;
//   - as a confined host process — the hub confines a host-mode run it gives
//     another project to — the host sandbox grants it read-only where it is.
//
// The directory goes when the workload is forgotten.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/readonlysnap"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
)

// readOnlyDirName is the directory beneath the agent's root the read-only
// projects are placed in, one directory per workload. A dot-name, like the
// agent's other directories, so no project directory can be it.
const readOnlyDirName = ".cloop-readonly"

// readOnlyFetchTimeout bounds fetching every read-only project of one start.
const readOnlyFetchTimeout = 15 * time.Minute

// placeReadOnly fetches and unpacks the snapshots spec.ReadOnly names for the
// workload handleID, and rewrites spec to hand them to the payload: each placed
// project's Source is where it was unpacked, and the run's manifest names
// where the payload finds it — /readonly/<slug> in a container, the directory
// itself on the host. A project that cannot be placed is left out of both and
// logged. It returns the workload's directory, for forget to remove.
func (a *Agent) placeReadOnly(ctx context.Context, spec *executor.Spec, handleID string, hostMode bool) (string, error) {
	if len(spec.ReadOnly) == 0 {
		return "", nil
	}
	if err := executor.ValidateReadOnly(spec.ReadOnly); err != nil {
		return "", err
	}
	base := filepath.Join(a.root, readOnlyDirName, sanitizeHandle(handleID))
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", fmt.Errorf("agent: make the directory the projects this run may read are placed in: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, readOnlyFetchTimeout)
	defer cancel()
	placed := make([]executor.ReadOnlyProject, 0, len(spec.ReadOnly))
	for _, p := range spec.ReadOnly {
		dest := filepath.Join(base, p.Slug)
		snap, err := a.fetchReadOnly(ctx, spec.Env, p, dest)
		if err != nil {
			_ = readonlysnap.Remove(dest)
			a.cfg.logf("workload %s: read-only project %s not placed: %v", handleID, p.Project, err)
			continue
		}
		a.cfg.logf("workload %s: placed read-only project %s (%d files, %d bytes)", handleID, p.Project,
			snap.Files, snap.Bytes)
		p.Source = dest
		p.Snapshot = nil
		// Placed by this agent and written by nothing else: a confined host
		// payload is granted it whole.
		p.Sealed = true
		placed = append(placed, p)
	}
	spec.ReadOnly = placed
	spec.Env = executor.WithReadOnlyManifest(spec.Env, executor.ReadOnlyManifest(placed,
		func(p executor.ReadOnlyProject) string {
			if hostMode {
				return p.Source
			}
			return p.Target()
		}))
	return base, nil
}

// fetchReadOnly fetches one project's snapshot and unpacks it at dest.
func (a *Agent) fetchReadOnly(ctx context.Context, env []string, p executor.ReadOnlyProject, dest string) (*readonlysnap.Snapshot, error) {
	if p.Snapshot == nil {
		return nil, fmt.Errorf("the hub named no snapshot to fetch")
	}
	token := readOnlyEnvValue(env, p.Snapshot.TokenEnv)
	if token == "" {
		return nil, fmt.Errorf("the run's environment has no %s to fetch it with", p.Snapshot.TokenEnv)
	}
	if err := os.Mkdir(dest, 0o755); err != nil {
		return nil, err
	}
	body, err := knowledgerun.OpenSnapshot(ctx, p.Snapshot.URL, token, p.Slug)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return readonlysnap.Extract(body, dest)
}

// readOnlyEnvValue is the last value env gives name, as exec would see it.
func readOnlyEnvValue(env []string, name string) string {
	name = strings.TrimSpace(name)
	value := ""
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			value = v
		}
	}
	return strings.TrimSpace(value)
}

// removeReadOnly removes a workload's read-only projects: a directory
// placeReadOnly made, and nothing else.
func (a *Agent) removeReadOnly(dir string) {
	if dir == "" || filepath.Dir(dir) != filepath.Join(a.root, readOnlyDirName) {
		return
	}
	if err := readonlysnap.Remove(dir); err != nil {
		a.cfg.logf("warning: could not remove the read-only projects in %s: %v", dir, err)
	}
}

// clearReadOnly removes what a previous agent process placed: its workloads
// went with it.
func (a *Agent) clearReadOnly() {
	dir := filepath.Join(a.root, readOnlyDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		a.removeReadOnly(filepath.Join(dir, e.Name()))
	}
}
