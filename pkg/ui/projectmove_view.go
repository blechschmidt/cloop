package ui

// projectmove_view.go is how a project move is followed and cleaned up after
// (Task 20496):
//
//	GET  /api/projects/{idx}/move/{id}            one move, and what cleaning up after it removes
//	POST /api/projects/{idx}/move/{id}/cleanup    clean up after it, once the caller confirms
//
// Its progress reaches whoever is watching without being asked for: every
// write the engine makes is pushed to the project's dashboards as a
// project_move message — on every hub member, since only the member driving
// the move hears the engine — and the project's entry in the projects list
// says it is moving, which the dashboard shows on its card and by holding its
// Run button, and which `cloop executor move status` finds it by.
//
// Cleanup removes what an ended move kept: its bundle and files in the hub's
// move store and the hidden refs its capture wrote. After a verified move it
// also removes the copy the source kept apart from the hub — a device's
// working copy — but only when the request says it confirms, and through a
// step on the device that removes nothing unless the copy is still the one the
// move captured (projectmove.DiscardWorkingCopy). The hub's own directory for
// a project is its home — its state, its features, the repository its runs
// are set up from — and is never removed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ─── the projects list: which projects are moving ──────────────────────────

// movingIndexTTL bounds how stale the projects list's view of open moves may
// get when nothing tells this member about a change: a move another member
// drives publishes each of its steps, so this is only the backstop.
const movingIndexTTL = 15 * time.Second

// movingIndex caches the open moves by project path.
type movingIndex struct {
	mu sync.Mutex
	at time.Time
	by map[string]multiui.MovingStatus
	// stopped: the server is shutting down, so the index opens the control
	// plane no more (stopMovingIndex).
	stopped bool
}

// movingProjects returns the open moves by the path of the project they move.
// A control plane with no database has recorded none, and is not created by
// asking.
func (s *Server) movingProjects() map[string]multiui.MovingStatus {
	s.moving.mu.Lock()
	defer s.moving.mu.Unlock()
	if s.moving.by != nil && (s.moving.stopped || time.Since(s.moving.at) < movingIndexTTL) {
		return s.moving.by
	}
	by := map[string]multiui.MovingStatus{}
	if s.moving.stopped {
		return by
	}
	if _, err := os.Stat(state.DBPath(s.WorkDir)); err == nil {
		db, err := s.controlPlaneDB()
		var moves []projectmove.Move
		if err == nil {
			moves, err = projectmove.ListMoves(db, statedb.ProjectMoveFilter{OpenOnly: true})
		}
		if err != nil {
			if db != nil {
				db.Close()
			}
			// Unreadable now: what was known stands, and the next read
			// asks again rather than reporting every project idle for a
			// whole TTL.
			if s.moving.by != nil {
				return s.moving.by
			}
			return by
		}
		for _, m := range moves {
			by[m.Project.Path] = multiui.MovingStatus{ID: m.ID, Phase: string(m.Phase), Target: m.Target,
				To: bindingName(db, m.Target)}
		}
		db.Close()
	}
	s.moving.by, s.moving.at = by, time.Now()
	return by
}

// stopMovingIndex is Shutdown's: it waits out a read of the open moves in
// flight, which holds the index's lock from opening the control plane to
// closing it, and lets none open it again. Without it a projects list sent
// while the server stood down could open the database after Run returned,
// recreating files in a directory its owner was removing.
func (s *Server) stopMovingIndex() {
	s.moving.mu.Lock()
	s.moving.stopped = true
	s.moving.mu.Unlock()
}

// dropMovingIndex forgets the cached open moves: a move started, moved on or
// ended.
func (s *Server) dropMovingIndex() {
	s.moving.mu.Lock()
	s.moving.by = nil
	s.moving.mu.Unlock()
}

// overlayMoving sets each status's Moving from the open moves: a feature's is
// its project's, since a feature moves with it.
func overlayMoving(statuses []multiui.ProjectStatus, moving map[string]multiui.MovingStatus) {
	for i := range statuses {
		statuses[i].Moving = nil
		if mv, ok := moving[policyProjectPath(statuses[i].Path)]; ok {
			statuses[i].Moving = &mv
		}
	}
}

// withMoving is statuses as a recipient is sent them, each saying whether its
// project is moving: a copy, since statuses may be the cache every reader
// holds. Read when the list is sent rather than stored with it, so a status
// refresh racing a move's step cannot leave a stale word behind, and the
// index's TTL bounds how old it can be.
func (s *Server) withMoving(statuses []multiui.ProjectStatus) []multiui.ProjectStatus {
	out := append([]multiui.ProjectStatus(nil), statuses...)
	overlayMoving(out, s.movingProjects())
	return out
}

// bindingName names a binding for a reader: the executor's or the pool's
// name, else the binding itself.
func bindingName(db *statedb.DB, binding string) string {
	switch {
	case binding == "":
		return "the hub's default executor"
	case strings.HasPrefix(binding, "pool:"):
		id := strings.TrimPrefix(binding, "pool:")
		if p, err := db.GetExecutorPool(id); err == nil && strings.TrimSpace(p.Name) != "" {
			return p.Name
		}
		return binding
	}
	if row, err := db.GetExecutor(binding); err == nil && strings.TrimSpace(row.Name) != "" {
		return row.Name
	}
	return binding
}

// ─── progress, pushed ───────────────────────────────────────────────────────

// moveChanged is what the hub does with every write a move's engine makes:
// the project's dashboards hear the move as it now stands, the projects list
// says where it is, and the other hub members do both for their own clients.
func (s *Server) moveChanged(m projectmove.Move) {
	s.pushMove(m)
	s.dropMovingIndex()
	s.broadcastProjectsUpdate()
	s.publishInvalidate(invalidateMoves, nil)
}

// pushMove sends the move, without its bulk, to the project's dashboards on
// every member.
func (s *Server) pushMove(m projectmove.Move) {
	raw, err := json.Marshal(map[string]any{"move": moveProgressOf(m)})
	if err != nil {
		return
	}
	msg := wsMessage{Type: "project_move", Data: raw}
	s.deliverToProject(m.Project.Path, msg)
	s.deliverSSE(m.Project.Path, sseEvent{Event: "project_move", Data: string(raw)})
	s.publishWS(m.Project.Path, msg, "project_move")
}

// moveProgressMismatches bounds the mismatches a push carries.
const moveProgressMismatches = 20

// moveProgressOf is a move as its progress is pushed: what the dashboard
// draws — phases, timeline, outcome, what is kept — without the capture's
// manifest and file lists, which a large repository makes large and which
// GET /api/projects/{idx}/move/{id} serves whole.
func moveProgressOf(m projectmove.Move) projectmove.Move {
	out := m
	if c := m.Detail.Capture; c != nil {
		out.Detail.Capture = &projectmove.CaptureRecord{
			Delivery: c.Delivery, Bytes: c.Bytes, Abandoned: c.Abandoned, From: c.From, WorkDir: c.WorkDir,
			Notes: c.Notes, Scan: c.Scan,
			Git: movegit.Manifest{Repository: c.Git.Repository, Head: c.Git.Head},
		}
	}
	if v := m.Detail.Verify; v != nil && len(v.Mismatches) > moveProgressMismatches {
		vv := *v
		vv.Mismatches = append(append([]string(nil), v.Mismatches[:moveProgressMismatches]...),
			fmt.Sprintf("and %d more", len(v.Mismatches)-moveProgressMismatches))
		out.Detail.Verify = &vv
	}
	return out
}

// ─── what cleanup removes ───────────────────────────────────────────────────

// moveCleanupPlan is what cleaning up after a move removes, and whether it
// may now. GET /api/projects/{idx}/move/{id} serves it beside the move, and a
// cleanup refused for want of a confirmation answers with it.
type moveCleanupPlan struct {
	// Allowed reports that cleanup may run now; Reason says why not.
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
	// CleanedAt and CleanedBy say who cleaned up after the move, and when.
	CleanedAt *time.Time `json:"cleaned_at,omitempty"`
	CleanedBy string     `json:"cleaned_by,omitempty"`
	// Verified reports that the move ended verified at its target: only then
	// does cleanup remove the source's own copy.
	Verified bool `json:"verified"`
	// Store is the move's directory in the hub's move store and what it
	// holds: the bundle and files the capture wrote.
	Store      string `json:"store,omitempty"`
	StoreBytes int64  `json:"store_bytes,omitempty"`
	// Refs are the hidden refs the capture wrote into the project's
	// repository on the hub.
	Refs []string `json:"refs,omitempty"`
	// Source is the copy of the project the source keeps apart from the hub,
	// which cleanup removes after a verified move; nil when there is none.
	Source *moveSourceCopy `json:"source,omitempty"`
	// Kept says what stays, whatever cleanup does.
	Kept []string `json:"kept,omitempty"`
	// Command is the terminal's way to the same cleanup.
	Command string `json:"command"`
}

// moveSourceCopy is a source's own copy of the project.
type moveSourceCopy struct {
	// Executor is where the copy is, and Name what it is called.
	Executor string `json:"executor"`
	Name     string `json:"name,omitempty"`
	// WorkDir is the copy's directory, as the device names it.
	WorkDir string `json:"work_dir"`
	// Removable reports that cleanup can remove it now; Reason says why not.
	Removable bool   `json:"removable"`
	Reason    string `json:"reason,omitempty"`
	// RemovedAt is when cleanup removed it.
	RemovedAt *time.Time `json:"removed_at,omitempty"`

	// snapshot, refs and files are what the device checks its copy against
	// before removing anything: the snapshot commit the capture recorded, and
	// the digests of the refs it captured and the files it delivered.
	snapshot, refs, files string
}

// moveCleanupCommand is the command that cleans up after m.
func moveCleanupCommand(m projectmove.Move) string {
	return "cloop executor move cleanup " + m.ID
}

// moveVerified reports whether m ended verified at its target.
func moveVerified(m projectmove.Move) bool {
	return m.Phase == projectmove.PhaseDone && m.Detail.Verify != nil && len(m.Detail.Verify.Mismatches) == 0
}

// moveRefs lists the hidden refs m's capture wrote: the snapshot, the linked
// worktrees', the stash entries' and the carried features'.
func moveRefs(m projectmove.Move) []string {
	c := m.Detail.Capture
	if c == nil {
		return nil
	}
	var refs []string
	if c.Git.Snapshot != nil && c.Git.Snapshot.Ref != "" {
		refs = append(refs, c.Git.Snapshot.Ref)
	}
	for _, w := range c.Git.Worktrees {
		if w.Ref != "" {
			refs = append(refs, w.Ref)
		}
	}
	for _, st := range c.Git.Stash {
		refs = append(refs, st.Name)
	}
	for _, cr := range c.Git.Carried {
		refs = append(refs, cr.Name)
	}
	return refs
}

// moveCleanupPlan works out what cleaning up after m removes now.
func (s *Server) moveCleanupPlan(ctx context.Context, m projectmove.Move) moveCleanupPlan {
	p := moveCleanupPlan{Command: moveCleanupCommand(m), Verified: moveVerified(m)}
	r := m.Detail.Retained
	if r != nil && !r.CleanedAt.IsZero() {
		at := r.CleanedAt
		p.CleanedAt, p.CleanedBy = &at, r.CleanedBy
	} else {
		p.Refs = moveRefs(m)
		if c := m.Detail.Capture; c != nil && c.Store != "" {
			if n, ok := treeBytes(c.Store); ok {
				p.Store, p.StoreBytes = c.Store, n
			}
		}
	}
	p.Source, p.Kept = s.sourceCopyOf(ctx, m, p.Verified)
	// A cleanup that kept the source's copy — its device was away — can be
	// run again for that copy alone.
	pending := p.Source != nil && p.Source.RemovedAt == nil && p.Source.Removable
	switch {
	case m.Open():
		p.Reason = "the move has not ended: cleanup is for what an ended move kept"
	case p.CleanedAt != nil && !pending:
		p.Reason = "cleaned up already"
	default:
		p.Allowed = true
	}
	return p
}

// sourceCopyOf says what of m's source cleanup removes — a device's working
// copy, after a verified move — and what it leaves where it is.
func (s *Server) sourceCopyOf(ctx context.Context, m projectmove.Move, verified bool) (*moveSourceCopy, []string) {
	c := m.Detail.Capture
	home := "the hub's directory for the project, " + m.Project.Path +
		": the project's home — its state, its features and the repository its runs are set up from — which cleanup never removes"
	switch {
	case c == nil:
		return nil, []string{"the source: the move ended before it captured anything", home}
	case c.Abandoned:
		return nil, []string{"the source: the move abandoned it, so nothing was captured from it and nothing of it is removed", home}
	case c.Delivery == projectmove.DeliverSameDevice:
		return nil, []string{"the working copy on " + nonEmpty(strings.TrimPrefix(c.From, "device "), "the device") +
			": the source and the target work in it both, so nothing of it is removed", home}
	case strings.HasPrefix(c.From, "runner "):
		return nil, []string{"the volume " + c.From + " held the project on: its pool wipes it before another project uses it", home}
	case !strings.HasPrefix(c.From, "device "):
		return nil, []string{home}
	}
	src := &moveSourceCopy{Executor: m.Source, WorkDir: c.WorkDir}
	if src.WorkDir == "" {
		src.WorkDir = executor.DeviceWorkDir(m.Project.Path)
	}
	if c.Git.Snapshot != nil {
		src.snapshot = c.Git.Snapshot.Commit
	}
	src.refs, src.files = projectmove.RefsDigest(c.Git), projectmove.FilesDigest(c.Files)
	if db, err := s.controlPlaneDB(); err == nil {
		src.Name = bindingName(db, m.Source)
		db.Close()
	}
	if !verified {
		return nil, []string{fmt.Sprintf("the working copy on %s, at %s: the move did not end verified, so the project's work is still there, and it is never removed",
			nonEmpty(src.Name, src.Executor), src.WorkDir), home}
	}
	if r := m.Detail.Retained; r != nil && !r.SourceRemovedAt.IsZero() {
		at := r.SourceRemovedAt
		src.RemovedAt = &at
		src.Reason = "removed already"
		return src, []string{home}
	}
	src.Reason = s.sourceCopyKeptBecause(ctx, m, src)
	src.Removable = src.Reason == ""
	return src, []string{home}
}

// sourceCopyKeptBecause says why a verified move's device copy cannot be
// removed now, or "" when it can.
func (s *Server) sourceCopyKeptBecause(ctx context.Context, m projectmove.Move, src *moveSourceCopy) string {
	c := m.Detail.Capture
	switch {
	case !c.Git.Repository || src.snapshot == "":
		return "it holds no repository the device could check it against before removing it; remove it on the device yourself"
	case len(c.Git.Carried) > 0:
		return "the device also keeps the working copies of the project's features beside it, which cleanup cannot check; remove them and this copy on the device yourself"
	case len(c.Git.Worktrees) > 0:
		return "it has linked worktrees, whose changes cleanup cannot check; remove the copy on the device yourself"
	case c.Delivery == projectmove.DeliverForge:
		return "the project's new executor builds its tree from the forge, and the hub cannot check that the forge still holds every commit this copy has; remove the copy on the device once you have"
	case strings.TrimSpace(m.Source) == "":
		return "the move records no executor it came from"
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		return "the hub cannot read the project's binding right now: " + err.Error()
	}
	cur, _, berr := db.ProjectExecutor(m.Project.Path)
	open, isOpen, oerr := projectmove.OpenMove(db, m.Project.Path)
	db.Close()
	switch {
	case berr != nil:
		return "the hub cannot read the project's binding right now: " + berr.Error()
	case oerr != nil:
		return "the hub cannot read the project's moves right now: " + oerr.Error()
	case isOpen:
		return fmt.Sprintf("move %s of the project is in progress", open.ID)
	case sameDeviceID(cur, m.Source):
		return fmt.Sprintf("the project is bound to %s again, so the copy there is the one it works in", nonEmpty(cur, m.Source))
	}
	// Where its next run would go — its binding, or the default it inherits.
	if ex, err := executor.ResolveBinding(m.Project.Path); err == nil && sameDeviceID(ex.ID(), m.Source) {
		return fmt.Sprintf("the project's runs go to %s again, so the copy there is the one it works in", ex.ID())
	}
	ex, err := executor.Get(m.Source)
	if err != nil {
		return fmt.Sprintf("executor %s is not registered on this hub", m.Source)
	}
	if _, held := s.agentHeldByPeer(ex); held {
		return ""
	}
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ex.HealthCheck(hctx); err != nil {
		return fmt.Sprintf("%s does not answer (%v); cleanup can remove the copy once it is back", nonEmpty(src.Name, m.Source), err)
	}
	return ""
}

// sameDeviceID reports whether two bindings run on one device: the same
// executor, or a device and its virtual executors.
func sameDeviceID(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	device := func(id string) string {
		if p := virtualParentOf(id); p != "" {
			return p
		}
		return id
	}
	return device(a) == device(b)
}

// treeBytes adds up the regular files under dir, reporting false for a dir
// that is not there.
func treeBytes(dir string) (int64, bool) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return 0, false
	}
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n, true
}

// ─── cleanup ────────────────────────────────────────────────────────────────

// discardSourceCopy removes a verified move's device copy, through a step on
// the device that removes nothing unless the copy is unchanged since the
// capture, and journals it at once: the copy is gone whatever becomes of the
// rest of the cleanup.
//
// The step runs to its end whatever becomes of the request that asked for
// it: a client giving up, or a proxy's read timeout, must not cut a removal
// off part-way (the device would finish it on the next try, but the hub
// would not know it began). It reports a copy the device kept, and why, with
// no error.
func (s *Server) discardSourceCopy(ctx context.Context, m projectmove.Move, src *moveSourceCopy, discardIgnored bool, actor string) (projectmove.Move, projectmove.WorkingCopyReport, error) {
	var report projectmove.WorkingCopyReport
	// Once more, right before the device is asked: a bind back, a new move.
	if why := s.sourceCopyKeptBecause(ctx, m, src); why != "" {
		report.Kept, report.Problems = projectmove.KeptChanged, []string{why}
		return m, report, nil
	}
	ex, err := executor.Get(src.Executor)
	if err != nil {
		return m, report, fmt.Errorf("executor %s is not registered on this hub", src.Executor)
	}
	if member, held := s.agentHeldByPeer(ex); held {
		return m, report, fmt.Errorf("%w: %s is connected to hub member %s", errMoveElsewhere, src.Executor, member)
	}
	args := []string{"--snapshot", src.snapshot, "--refs", src.refs, "--files", src.files}
	if discardIgnored {
		args = append(args, "--discard-ignored")
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), moveWorkloadTimeout)
	defer cancel()
	report, err = (&moveDriver{s: s}).runOnTarget(dctx, ex, m, "move-discard",
		executor.Workspace{Kind: executor.WorkspaceNone}, "", args...)
	if err != nil || report.Kept != "" {
		return m, report, err
	}
	if !report.Empty {
		return m, report, fmt.Errorf("`cloop workspace move-discard` on %s reported the copy at %s still there", src.Executor, src.WorkDir)
	}
	if m.Detail.Retained == nil {
		m.Detail.Retained = &projectmove.Retained{Command: moveCleanupCommand(m)}
	}
	m.Detail.Retained.SourceRemovedAt = time.Now().UTC()
	m.Detail.Retained.SourceRemoved = nonEmpty(src.Name, src.Executor) + " at " + src.WorkDir
	m.Detail.Retained.SourceKept = false
	// On the trail at once: the copy is gone whatever becomes of the rest.
	s.auditMove(auditaction.ActionProjectMoveCleanup, m, map[string]any{"actor": actor, "outcome": "source_removed",
		"source_removed": m.Detail.Retained.SourceRemoved})
	out, err := (projectmove.DBStore{Open: s.controlPlaneDB}).Advance(dctx, m, m.Phase)
	return out, report, err
}

// ─── handlers ───────────────────────────────────────────────────────────────

// projectMoveAt reads the move the request names, writing a 404 for an id
// that is not this project's.
func (s *Server) projectMoveAt(w http.ResponseWriter, r *http.Request) (projectmove.Move, bool) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return projectmove.Move{}, false
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if !movegit.ValidMoveID(id) {
		jsonErr(w, "not a move id", http.StatusBadRequest)
		return projectmove.Move{}, false
	}
	m, err := (projectmove.DBStore{Open: s.controlPlaneDB}).Get(r.Context(), id)
	if errors.Is(err, projectmove.ErrNotFound) || (err == nil && m.Project.Path != entry.Path) {
		jsonErr(w, "this project has no move "+id, http.StatusNotFound)
		return projectmove.Move{}, false
	}
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return projectmove.Move{}, false
	}
	return m, true
}

// handleProjectMove serves GET /api/projects/{idx}/move/{id}.
//
// ?progress=1 asks only how an open move is going — what the dashboard is
// pushed, and what `cloop executor move` reads each second while it follows
// one: the move without its capture's manifest and file lists, and no plan.
// An ended move is answered whole either way.
func (s *Server) handleProjectMove(w http.ResponseWriter, r *http.Request) {
	m, ok := s.projectMoveAt(w, r)
	if !ok {
		return
	}
	if m.Open() && r.URL.Query().Get("progress") == "1" {
		jsonOK(w, map[string]any{"move": moveProgressOf(m)})
		return
	}
	registerBuiltinExecutors()
	jsonOK(w, map[string]any{"move": m, "cleanup": s.moveCleanupPlan(r.Context(), m)})
}

// handleProjectMoveCleanup serves POST /api/projects/{idx}/move/{id}/cleanup.
//
// The body must say {"confirm": true}: cleanup removes things nobody can get
// back, so a request that does not say it means to is answered with what it
// would remove instead. {"keep_source": true} cleans up the hub's half and
// leaves the source's copy where it is — the way past a device that is gone.
func (s *Server) handleProjectMoveCleanup(w http.ResponseWriter, r *http.Request) {
	m, ok := s.projectMoveAt(w, r)
	if !ok {
		return
	}
	registerBuiltinExecutors()
	plan := s.moveCleanupPlan(r.Context(), m)
	// The device's step runs on the member holding its connection; the body
	// goes with the request, unread.
	if plan.Allowed && plan.Source != nil && plan.Source.Removable {
		if s.routeToOwner(w, r, ownerAgent, s.agentForExecutorID(plan.Source.Executor)) {
			return
		}
	}
	var req struct {
		Confirm        bool `json:"confirm"`
		KeepSource     bool `json:"keep_source"`
		DiscardIgnored bool `json:"discard_ignored"`
	}
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	removeSource := plan.Source != nil && plan.Source.RemovedAt == nil && !req.KeepSource
	switch {
	case m.Open():
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error": "move " + m.ID + " has not ended; clean up after it once it has", "code": "move_open", "cleanup": plan})
		return
	case plan.CleanedAt != nil && !removeSource:
		jsonOK(w, map[string]any{"move": m, "cleanup": plan})
		return
	case !req.Confirm:
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error":       "cleanup removes what move " + m.ID + " kept, which cannot be brought back: confirm it",
			"code":        "cleanup_unconfirmed",
			"remediation": `send {"confirm": true} once you have read what it removes`,
			"cleanup":     plan,
		})
		return
	}
	actor := s.auditActor(r)
	if removeSource {
		if !plan.Source.Removable {
			writeJSONStatus(w, http.StatusConflict, map[string]any{
				"error": fmt.Sprintf("the copy on %s at %s cannot be removed now: %s",
					nonEmpty(plan.Source.Name, plan.Source.Executor), plan.Source.WorkDir, plan.Source.Reason),
				"code":        "source_copy_kept",
				"remediation": `clean up with {"keep_source": true} to remove the move's bundle and refs and leave that copy where it is`,
				"cleanup":     plan,
			})
			return
		}
		// Removing it is work on that executor: only for someone who may use
		// it, as a bind or a move to it would be.
		if !s.admitExecutorAudience(w, r, plan.Source.Executor) {
			return
		}
		out, report, err := s.discardSourceCopy(r.Context(), m, plan.Source, req.DiscardIgnored, actor)
		where := nonEmpty(plan.Source.Name, plan.Source.Executor) + " at " + plan.Source.WorkDir
		switch {
		case err != nil:
			s.auditMove(auditaction.ActionProjectMoveCleanup, m, map[string]any{"actor": actor, "outcome": "refused",
				"source": plan.Source.Executor, "error": err.Error()})
			writeJSONStatus(w, http.StatusBadGateway, map[string]any{
				"error": fmt.Sprintf("the copy on %s was not removed: %v", where, err),
				"code":  "source_copy_failed", "cleanup": plan,
			})
			return
		case report.Kept != "":
			why := strings.Join(report.Problems, "; ")
			s.auditMove(auditaction.ActionProjectMoveCleanup, m, map[string]any{"actor": actor, "outcome": "refused",
				"source": plan.Source.Executor, "error": why})
			body := map[string]any{"error": fmt.Sprintf("the copy on %s was kept, and nothing else was removed: %s", where, why),
				"code": "source_copy_changed", "cleanup": plan,
				"remediation": `look at the copy on the device: if what it holds may go, remove it there yourself, or clean up with {"keep_source": true} to leave it`}
			if report.Kept == projectmove.KeptIgnored {
				body["code"], body["ignored"], body["examples"] = "source_copy_ignored", report.Ignored, report.Examples
				body["remediation"] = `no move carries files git ignores: copy any you need off the device, then clean up with {"discard_ignored": true} to remove them with the rest, or with {"keep_source": true} to leave the copy`
			}
			writeJSONStatus(w, http.StatusConflict, body)
			return
		}
		m = out
	}
	if plan.CleanedAt != nil {
		// Only the source's copy was left to remove.
		s.pushMove(m)
		jsonOK(w, map[string]any{"move": m, "cleanup": s.moveCleanupPlan(r.Context(), m)})
		return
	}
	out, err := s.cleanupMove(r.Context(), m, actor, req.KeepSource && plan.Source != nil && plan.Source.RemovedAt == nil)
	switch {
	case errors.Is(err, projectmove.ErrStillOpen):
		jsonErr(w, "move "+m.ID+" has not ended; clean up after it once it has", http.StatusConflict)
		return
	case errors.Is(err, projectmove.ErrChanged):
		jsonErr(w, "move "+m.ID+" changed while it was being cleaned up; try again", http.StatusConflict)
		return
	case err != nil:
		jsonErr(w, "clean up after move "+m.ID+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.pushMove(out)
	jsonOK(w, map[string]any{"move": out, "cleanup": s.moveCleanupPlan(r.Context(), out)})
}
