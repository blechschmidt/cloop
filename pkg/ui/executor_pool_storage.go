package ui

// executor_pool_storage.go: the hub's half of persistent runner storage
// (Task 20484).
//
// A pool's controller may give its runners volumes that outlive them. The
// controller keeps the volumes; the hub keeps the rule that a volume holding
// one project's data is never handed, unwiped, to a run of another — see
// pkg/executorpool/tenant.go for the split. Here:
//
//   - poolAccess.Project names a queued run's project as access decides it,
//     which is what its tenant is made of;
//   - runProjectFor is what a runner records as it is handed a run, and what
//     its UPDATE checks against the tenant the runner holds;
//   - POST /api/pool-controller/status is a controller saying what keeps it
//     from starting runners — a volume stuck Pending, a full one — which the
//     runs waiting in its pool's queue then say too, on every member, instead
//     of a bare "waiting for pool capacity" while nothing will ever start.

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// poolStatusPath is the controller's health report.
const poolStatusPath = "/api/pool-controller/status"

// poolControllerReportTTL is how long a controller's report of trouble speaks
// for its pool: a controller reports again within minutes while the trouble
// lasts, so one older than this is from a controller that is gone.
var poolControllerReportTTL = 10 * time.Minute

// Bounds on a report, which reaches the readers of every waiting project.
const (
	maxPoolReportReason  = 64
	maxPoolReportMessage = 1024
)

// poolReportMinInterval is the least time between two reports of one
// controller: each changed report rewrites every waiting run's reason and
// its project's pause, which a controller is not let do in a loop.
var poolReportMinInterval = time.Second

// poolReportReason is what a report's reason may be: a condition reason, as
// Kubernetes writes them.
var poolReportReason = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

// Project implements executorpool.Access: the project a run's tenant is made
// of, as access is decided — a feature's runs are its project's — and its
// owner key.
func (a poolAccess) Project(projectPath string) (string, string, error) {
	p := policyProjectPath(projectPath)
	if strings.TrimSpace(p) == "" {
		return "", "", fmt.Errorf("no project path")
	}
	if !a.s.isRegisteredProject(p) {
		// A member whose registry has not caught up names no owner, and a
		// guessed one would make another project's tenant.
		return "", "", fmt.Errorf("project %s is not registered on this hub member", p)
	}
	return p, a.s.projectOwnerKey(p), nil
}

// StarterMayRead implements executorpool.Access: whether the person who
// started a run may read its project now, so may be handed a runner holding
// the project's kept data. A hub without sign-in has one operator, who may;
// a run that acts for nobody may not.
func (a poolAccess) StarterMayRead(starter, projectPath string) (bool, error) {
	if !a.s.oidcEnabled() {
		return true, nil
	}
	if strings.TrimSpace(starter) == "" {
		return false, nil
	}
	return a.s.identityMayReadProject(starter, projectPath)
}

// poolStorageSupported reports whether every live member of this hub's
// cluster hands a runner holding a project's data only that project's runs
// (executorpool.EndpointRunnerStorage). An older member sharing the control
// plane would hand it anybody's, so until every member does, the feed names
// no project and no runner is minted holding one: a controller then starts
// every runner on a wiped volume.
func (s *Server) poolStorageSupported() bool {
	node := s.clusterNode()
	if node == nil {
		return true
	}
	for _, m := range node.LiveMembers() {
		if m.Endpoint(executorpool.EndpointRunnerStorage) != "1" {
			return false
		}
	}
	return true
}

// runProjectFor is the project of the queued run q as a runner records it.
// The zero value — the hub cannot say whose the project is — goes only to a
// runner whose storage holds nothing.
func (s *Server) runProjectFor(poolID string, q statedb.PoolQueueRow, access executorpool.Access) statedb.PoolRunnerProject {
	tenant, name, owner, ok := executorpool.TenantOf(poolID, q.ProjectPath, access)
	if !ok {
		return statedb.PoolRunnerProject{}
	}
	return statedb.PoolRunnerProject{Tenant: tenant, Name: name, Owner: owner}
}

// pickPoolRunner chooses, among idle runners whose storage holds what holds
// says ("" for nothing), the one to hand a run of tenant: the first holding
// that tenant's data when the run's starter may be given it, and otherwise the
// first holding nothing. -1 when none may take it — every runner holds
// another project's data — and the run waits for a runner that may.
func pickPoolRunner(holds []string, tenant string, mayUseHeld bool) int {
	if tenant != "" && mayUseHeld {
		for i, h := range holds {
			if h == tenant {
				return i
			}
		}
	}
	for i, h := range holds {
		if h == "" {
			return i
		}
	}
	return -1
}

// poolStatusRequest is a controller's health report.
type poolStatusRequest struct {
	// Healthy says nothing keeps the controller from starting runners.
	Healthy bool `json:"healthy"`
	// Reason is the condition reason of what does: StoragePending,
	// StorageFull, …
	Reason string `json:"reason,omitempty"`
	// Message says it in a sentence.
	Message string `json:"message,omitempty"`
	// Storage is the controller's count of the pool's runner volumes (Task
	// 20486), for the dashboard; absent for a pool without them.
	Storage *executorpool.StorageUsage `json:"storage,omitempty"`
}

// handlePoolControllerStatus serves POST /api/pool-controller/status.
func (s *Server) handlePoolControllerStatus(w http.ResponseWriter, r *http.Request) {
	store, pool, cred, _, ok := s.authenticatePoolController(w, r, false)
	if !ok {
		return
	}
	var req poolStatusRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	message := cleanPoolReport(req.Message)
	switch {
	case !req.Healthy && reason == "":
		jsonErr(w, "a report of trouble needs a reason", http.StatusBadRequest)
		return
	case reason != "" && (len(reason) > maxPoolReportReason || !poolReportReason.MatchString(reason)):
		jsonErr(w, fmt.Sprintf("reason must be up to %d letters and digits, starting with a letter", maxPoolReportReason),
			http.StatusBadRequest)
		return
	}
	if req.Healthy {
		reason, message = "", ""
	}
	if req.Storage != nil && !req.Storage.Valid() {
		jsonErr(w, "storage holds counts no controller could make", http.StatusBadRequest)
		return
	}
	prev, _ := store.DB().PoolControllerStatuses(pool.ID)
	for _, p := range prev {
		if p.CredentialID == cred.ID && time.Since(p.ReportedAt) < poolReportMinInterval {
			w.Header().Set("Retry-After", "1")
			jsonErr(w, "reports come at most once a second", http.StatusTooManyRequests)
			return
		}
	}
	row := statedb.PoolControllerStatusRow{PoolID: pool.ID, CredentialID: cred.ID, Healthy: req.Healthy,
		Reason: reason, Message: message, ReportedAt: time.Now(), Storage: executorpool.EncodeStorage(req.Storage)}
	if err := store.DB().PutPoolControllerStatus(row); err != nil {
		writePoolErr(w, err)
		return
	}
	changed, storageChanged := true, true
	for _, p := range prev {
		if p.CredentialID == cred.ID {
			changed = p.Healthy != row.Healthy || p.Reason != row.Reason || p.Message != row.Message
			storageChanged = p.Storage != row.Storage
		}
	}
	if changed {
		store.AuditControllerStatus(pool.ID, cred.ID, row.Healthy, row.Reason, row.Message)
		s.refreshQueuedReasons(store, pool)
	}
	if changed || storageChanged {
		// The pool list shows both (Task 20486).
		s.notePoolDashboard(pool.ID)
	}
	jsonOK(w, map[string]any{"ok": true, "pool_id": pool.ID, "healthy": row.Healthy})
}

// cleanPoolReport makes a controller's message fit to show a project's
// readers: one line, no control characters, bounded, and with anything that
// looks like a credential scrubbed.
func cleanPoolReport(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	s = redact.Scrub(s)
	if len(s) > maxPoolReportMessage {
		s = s[:maxPoolReportMessage] + "…"
	}
	return s
}

// poolControllerTrouble is what a pool's controllers last said keeps them
// from starting runners — the newest report, when it is a report of trouble
// and recent enough to still speak for the pool.
func (s *Server) poolControllerTrouble(store *executorpool.Store, poolID string) (string, bool) {
	reports, err := store.DB().PoolControllerStatuses(poolID)
	if err != nil || len(reports) == 0 {
		return "", false
	}
	newest := reports[0]
	if newest.Healthy || time.Since(newest.ReportedAt) > poolControllerReportTTL {
		return "", false
	}
	msg := newest.Message
	if msg == "" {
		msg = newest.Reason
	}
	return msg, true
}

// queuedReasonFor is queuedReason with what the pool's controller reports.
func (s *Server) queuedReasonFor(store *executorpool.Store, pool executorpool.Pool, snap executorpool.Snapshot) string {
	reason := queuedReason(pool, snap)
	if pool.Cordoned() {
		return reason // the cordon is what keeps it waiting, whatever the controller says
	}
	if trouble, ok := s.poolControllerTrouble(store, pool.ID); ok {
		reason = fmt.Sprintf("waiting for pool capacity: executor pool %s's controller cannot start runners: %s",
			pool.Name, trouble)
	}
	return reason
}

// refreshQueuedReasons rewrites what each run waiting in pool's queue says,
// and its project's pause, after the controller's report changed.
func (s *Server) refreshQueuedReasons(store *executorpool.Store, pool executorpool.Pool) {
	snap, verdicts, err := store.Snapshot(pool, s.poolAccessFor(store))
	if err != nil {
		return
	}
	reason := s.queuedReasonFor(store, pool, snap)
	queue, err := store.DB().ListPoolQueue(pool.ID, statedb.PoolQueueWaiting)
	if err != nil {
		return
	}
	for _, q := range queue {
		if v := verdicts[q.ID]; !v.Visible || q.Reason == reason {
			continue
		}
		if err := store.DB().NotePoolQueueReason(q.ID, reason); err != nil {
			continue
		}
		if s.isRegisteredProject(q.ProjectPath) && hasProjectDB(q.ProjectPath) {
			s.setPoolCapacityPause(q.ProjectPath, reason)
		}
	}
}
