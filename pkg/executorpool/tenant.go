package executorpool

// tenant.go: whose data a runner's persistent storage holds (Task 20484).
//
// A pool's controller may give each runner a volume that outlives it — the
// project's workspace, a git object cache, tool caches — so the next run of
// the same project starts from where the last one left off instead of cloning
// and building from nothing. A volume is a tenant's: what one project's run
// wrote there must never be readable by a run of another project, nor by a
// person who may not read the project it came from.
//
// The hub and the controller split that rule between them. The controller
// knows the volumes: which one a runner gets, and whether it was wiped before
// the runner started. The hub knows the runs: whose project each is and who
// started it. So:
//
//   - the controller declares, as it mints a runner, the tenant its storage
//     holds — or nothing, for storage that is fresh or was wiped before the
//     runner started (RunnerOptions.Holds, statedb's holds column);
//   - the hub hands a runner that holds a tenant only a run of that tenant,
//     which the assignment's own UPDATE checks (statedb.AssignPoolQueueEntryTo),
//     and names the run's tenant on the start (executor.LabelPoolTenant),
//     which the runner — started with --holds — checks once more itself;
//   - the hub tells the controller each runner's project as it is handed one
//     (RunnerState.Project), which the controller records on the volume, and
//     which project each queued run is (Snapshot.QueuedProjects), so it can
//     give a project back its own volume.
//
// A tenant is a digest, not a name: the pool, the project as access is
// decided — a feature's runs are its project's — and the project's owner. A
// project re-created under another owner is another tenant, and so is the same
// project served by another pool, so a volume a cluster kept from one hub
// pool is never reused unwiped for another. The digest also keeps the hub's
// project paths out of the cluster's objects; the project's name and owner
// travel separately, for the volume's record, and decide nothing.

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TenantPrefix begins every tenant.
const TenantPrefix = "prj-"

// EndpointRunnerStorage is the hub cluster endpoint a member advertises when
// its build hands a runner holding a tenant only that tenant's runs. A hub
// with a member that does not — an older build sharing the control plane —
// names no tenant on its feed and records none on a runner, so a controller
// starts every runner on a wiped volume until every member does.
const EndpointRunnerStorage = "executor-pool-runner-storage"

var tenantPattern = regexp.MustCompile(`^prj-[0-9a-f]{32}$`)

// ProjectTenant is the tenant of the project at projectPath (as access is
// decided: a feature's is its project's) owned by owner ("" when unowned),
// served by the pool poolID.
func ProjectTenant(poolID, projectPath, owner string) string {
	h := sha256.New()
	for _, part := range []string{"cloop.dev/pool-tenant/v1", strings.TrimSpace(poolID),
		filepath.Clean(strings.TrimSpace(projectPath)), strings.TrimSpace(owner)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return TenantPrefix + hex.EncodeToString(h.Sum(nil)[:16])
}

// ValidTenant reports whether s is a tenant ProjectTenant could have made.
func ValidTenant(s string) bool { return tenantPattern.MatchString(s) }

// ProjectDemand is one project's share of a pool's demand: its tenant, and
// how many of its runs wait in the queue.
type ProjectDemand struct {
	Tenant string `json:"tenant"`
	Queued int    `json:"queued"`
}

// RunMayUseHeld reports whether a queued run may be handed a runner whose
// storage holds its own project's data: whether its starter may read the
// project now, under the access policy. A run that may not is demand only a
// runner holding nothing meets — on the feed and in the dispatcher alike, or
// the controller would keep a runner on the project's volume waiting for it.
func RunMayUseHeld(q statedb.PoolQueueRow, access Access) bool {
	if access == nil {
		return false
	}
	ok, err := access.StarterMayRead(q.Starter, q.ProjectPath)
	return err == nil && ok
}

// TenantOf is the tenant of a queued run's project under access, with the
// project's name and owner for the runner's record. ok is false when access
// cannot say whose the project is; such a run is handed only to a runner
// whose storage holds nothing.
func TenantOf(poolID, projectPath string, access Access) (tenant, name, owner string, ok bool) {
	if access == nil {
		return "", "", "", false
	}
	path, owner, err := access.Project(projectPath)
	if err != nil || strings.TrimSpace(path) == "" {
		return "", "", "", false
	}
	return ProjectTenant(poolID, path, owner), filepath.Base(filepath.Clean(path)), strings.TrimSpace(owner), true
}
