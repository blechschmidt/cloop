package ui

// Signed audit head checkpoints, written by the cluster leader (Task 20404).
//
// Every audit.checkpoints.interval the leader reads the head of every chain it
// serves — the control plane's and each registered project's — and writes one
// record per chain off the database, sealed under a key derived from
// CLOOP_SECRET_KEY. pkg/auditcheckpoint holds the record, the seal and the
// verifier; this file decides when, for which chains, and who.
//
// # One writer per window
//
// Windows are numbered from the wall clock (Unix time divided by the
// interval), so every member agrees on them, and a shared marker in the
// control plane says which window was last claimed, by whom, and whether it was
// written. A new leader resumes from the marker rather than from its own
// clock: the window its predecessor finished is not written twice, and one its
// predecessor claimed and never finished — it died between the two — is taken
// over once the claim goes stale, instead of being skipped.
//
// # What a window costs
//
// The control plane's record is written every window: it is the liveness
// signal `cloop hub doctor` reads. A project's is written when its head moved
// since this process last recorded it, and at least daily, so a hub serving a
// hundred quiet projects does not append a hundred unchanged lines every five
// minutes. The newest record for a chain is what pins its head, and an
// unchanged head is already pinned.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// auditCheckpointStale is how long another member's unfinished claim on a
// window is honoured before this member takes the window over.
const auditCheckpointStale = time.Minute

// auditCheckpointRetry is how soon a window whose records could not be written
// is tried again, within the window.
const auditCheckpointRetry = 30 * time.Second

// auditCheckpointHeartbeat bounds how long a project chain whose head has not
// moved goes without a record.
const auditCheckpointHeartbeat = 24 * time.Hour

// auditCheckpointState is the leader's memory of what it last recorded.
type auditCheckpointState struct {
	mu   sync.Mutex
	last map[string]auditHeadMark // database path -> head last recorded

	// stderr replaces os.Stderr for the records' stderr copy, now the clock
	// and member this hub's name on the window marker, so tests can read and
	// steer them.
	stderr io.Writer
	now    func() time.Time
	member string

	// failedWindow is the window whose write failure was last reported, so a
	// file that keeps failing is said once per window, not on every retry.
	failedWindow int64
	// unmarkedWindow is the last window written without the shared marker,
	// because the marker could not be written.
	unmarkedWindow int64

	// anchors remembers, per database, the newest prune anchor whose archive
	// this process has checked and what it found: an archive is read once
	// per anchor per process, not once per window.
	anchors map[string]anchorCheck
}

// anchorCheck is one anchor's archive, as this process found it.
type anchorCheck struct {
	hash     string
	verified bool
}

// checkedAnchor reports what this process found for path's anchor hash, if it
// has looked.
func (st *auditCheckpointState) checkedAnchor(path, hash string) (verified, known bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	c, ok := st.anchors[path]
	if !ok || c.hash != hash {
		return false, false
	}
	return c.verified, true
}

func (st *auditCheckpointState) rememberAnchor(path, hash string, verified bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.anchors == nil {
		st.anchors = map[string]anchorCheck{}
	}
	st.anchors[path] = anchorCheck{hash: hash, verified: verified}
}

func (st *auditCheckpointState) writtenUnmarked(window int64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.unmarkedWindow == window
}

func (st *auditCheckpointState) markWrittenUnmarked(window int64) {
	st.mu.Lock()
	st.unmarkedWindow = window
	st.mu.Unlock()
}

// firstFailureIn reports whether a write failure in window is the first one
// reported for it, and marks it reported.
func (st *auditCheckpointState) firstFailureIn(window int64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.failedWindow == window {
		return false
	}
	st.failedWindow = window
	return true
}

// auditHeadMark is one chain's head as last recorded.
type auditHeadMark struct {
	lastID   int64
	lastHash string
	anchorID int64
	at       time.Time
}

func (st *auditCheckpointState) clock() time.Time {
	st.mu.Lock()
	now := st.now
	st.mu.Unlock()
	if now != nil {
		return now()
	}
	return time.Now()
}

// auditCheckpointChain is one chain a checkpoint covers.
type auditCheckpointChain struct {
	chain string // auditcheckpoint.Chain*
	dir   string
	path  string // absolute database path
}

// watchAuditCheckpoints is the leader duty. It returns when ctx ends.
func (s *Server) watchAuditCheckpoints(ctx context.Context) {
	defer recoverGoroutine("watchAuditCheckpoints")
	for {
		wait := s.auditCheckpointTick(ctx)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// auditCheckpointSettings reads audit.checkpoints from the hub's effective
// configuration, overlay included.
func (s *Server) auditCheckpointSettings() config.AuditCheckpointsConfig {
	cfg, err := s.loadHubConfig()
	if err != nil || cfg == nil {
		return config.AuditCheckpointsConfig{}
	}
	return cfg.Audit.Checkpoints
}

// auditCheckpointTick writes the current window if it is this member's to
// write, and returns how long to wait before looking again.
func (s *Server) auditCheckpointTick(ctx context.Context) time.Duration {
	settings := s.auditCheckpointSettings()
	interval := settings.EffectiveInterval()
	now := s.auditCheckpoints.clock()
	untilNext := nextAuditWindow(now, interval).Sub(now)
	// Losses a process left behind and nobody adopted at startup — a Pod
	// replaced under a new hostname leaves a file that only goes stale after
	// the replacement started — are taken up on the leader's tick.
	if s.WorkDir != "" {
		_, _ = statedb.AdoptAuditFailureStatus(statedb.AuditFailureStatusDir(s.WorkDir))
	}
	if !settings.Enabled() || ctx.Err() != nil {
		return untilNext
	}
	window := now.Unix() / int64(interval/time.Second)
	member := s.auditCheckpointMember()

	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "audit checkpoints: open the control plane",
			map[string]interface{}{"error": err.Error()})
		return minDuration(auditCheckpointRetry, untilNext)
	}
	claim, err := db.ClaimAuditCheckpointWindow(window, interval, member, now, auditCheckpointStale)
	db.Close() //nolint:errcheck
	if err != nil {
		// The marker could not be written — most likely the control plane
		// has stopped taking writes, which is exactly when a record of its
		// heads matters most. Write the window anyway, once: without the
		// marker a leader change in this window could write it twice, and a
		// duplicate record is harmless where a missing one is not.
		if s.auditCheckpoints.firstFailureIn(window) {
			s.log().Warn(logger.EventAuthz, 0, "audit checkpoints: claim the window; writing it unmarked",
				map[string]interface{}{"error": err.Error(), "window": window})
		}
		if s.auditCheckpoints.writtenUnmarked(window) {
			return untilNext
		}
		wrote, werr := s.writeAuditCheckpoints(settings, auditcheckpoint.ReasonInterval, window, false)
		if werr != nil {
			fmt.Fprintf(os.Stderr, "[audit] could not write audit checkpoints for window %d: %v\n", window, werr)
		}
		if wrote {
			s.auditCheckpoints.markWrittenUnmarked(window)
			return untilNext
		}
		return minDuration(auditCheckpointRetry, untilNext)
	}
	if claim.FutureMarker {
		fmt.Fprintf(os.Stderr, "[audit] the checkpoint window marker claims window %d, ahead of this hub's "+
			"clock (window %d); it was replaced. A marker from the future is a skewed clock on another "+
			"member, or a database edited to stop checkpoints.\n", claim.Prior.Window, window)
	}
	if !claim.Claimed {
		if claim.HeldBy != "" && claim.RetryAt.Before(now.Add(untilNext)) {
			// Another member claimed this window and has not finished; look
			// again when its claim goes stale rather than at the next window,
			// so its death between claiming and writing costs no window.
			return maxDuration(claim.RetryAt.Sub(now), time.Second)
		}
		return untilNext
	}

	// A predecessor's window it claimed and never wrote: written now, late,
	// with the heads as they are now and the time they were read, and then
	// straight back for the current window — a leader that died between
	// claiming and writing costs no window.
	late := claim.Window < window
	wrote, err := s.writeAuditCheckpoints(settings, auditcheckpoint.ReasonInterval, claim.Window, late)
	if err != nil {
		if s.auditCheckpoints.firstFailureIn(claim.Window) {
			s.log().Warn(logger.EventAuthz, 0, "audit checkpoints: write",
				map[string]interface{}{"error": err.Error(), "window": claim.Window})
			fmt.Fprintf(os.Stderr, "[audit] could not write audit checkpoints for window %d: %v\n", claim.Window, err)
		}
		if !wrote {
			// Nowhere has this window's records: keep the claim and retry
			// within the window.
			return minDuration(auditCheckpointRetry, untilNext)
		}
		// The stderr copy went out and only the file failed. The window is
		// done — retrying would repeat every line on stderr each time — and
		// the heads are not remembered, so the next window writes them all
		// again and the file catches up once it can.
	}
	if db, err := s.controlPlaneDB(); err == nil {
		_, _ = db.CompleteAuditCheckpointWindow(claim.Window, member)
		db.Close() //nolint:errcheck
	}
	if late {
		return 0
	}
	return untilNext
}

// writeShutdownAuditCheckpoints records every chain's head one last time as a
// leading hub shuts down cleanly.
func (s *Server) writeShutdownAuditCheckpoints() {
	if !s.isLeader() {
		return
	}
	settings := s.auditCheckpointSettings()
	if !settings.Enabled() {
		return
	}
	if _, err := s.writeAuditCheckpoints(settings, auditcheckpoint.ReasonShutdown, 0, true); err != nil {
		fmt.Fprintf(os.Stderr, "[audit] could not write the shutdown audit checkpoints: %v\n", err)
	}
}

// auditCheckpointMember names this hub on the records it writes and on the
// window marker: its cluster member or lease id, or host and pid for a hub
// running without either.
func (s *Server) auditCheckpointMember() string {
	s.auditCheckpoints.mu.Lock()
	override := s.auditCheckpoints.member
	s.auditCheckpoints.mu.Unlock()
	if override != "" {
		return override
	}
	if id := s.hubInstanceID(); id != "" {
		return id
	}
	host, _ := os.Hostname()
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}

// writeAuditCheckpoints reads each chain's head and writes the records. all
// writes every chain; otherwise a project chain whose head has not moved since
// it was last recorded here, less than auditCheckpointHeartbeat ago, is left
// out. wrote reports that the records reached at least one destination, which
// with an error means stderr took them and the file did not.
func (s *Server) writeAuditCheckpoints(settings config.AuditCheckpointsConfig, reason string, window int64, all bool) (wrote bool, err error) {
	key, kerr := auditcheckpoint.KeyFromEnv()
	if kerr != nil {
		key = nil // unsigned; the doctor says so
	}
	member := s.auditCheckpointMember()
	st := &s.auditCheckpoints

	var (
		recs  []auditcheckpoint.Record
		marks = map[string]auditHeadMark{}
	)
	for _, c := range s.auditCheckpointChains() {
		head, anchors, err := readAuditHead(c.path)
		if err != nil {
			s.log().Warn(logger.EventAuthz, 0, "audit checkpoints: read a chain's head",
				map[string]interface{}{"error": err.Error(), "path": c.path})
			continue
		}
		now := st.clock().UTC()
		mark := auditHeadMark{lastID: head.LastID, lastHash: head.LastRowHash, at: now}
		if head.Anchor != nil {
			mark.anchorID = head.Anchor.ID
		}
		if head.LastID == 0 && head.Anchor == nil {
			continue // never written to: nothing to pin
		}
		if !all && c.chain == auditcheckpoint.ChainProject && st.unchanged(c.path, mark) {
			continue
		}
		rec := auditcheckpoint.HeadRecord(head, c.chain, c.path, reason, window, member, now)
		if a := head.Anchor; a != nil {
			rec.AnchorVerified = st.verifyAnchor(c.path, anchors, *a)
		}
		key.Seal(&rec)
		recs = append(recs, rec)
		marks[c.path] = mark
	}
	if len(recs) == 0 {
		return true, nil
	}

	sink := auditcheckpoint.Sink{File: settings.File}
	if settings.StderrEnabled() {
		sink.Stderr = st.stderrOut()
	}
	if err := sink.Write(recs); err != nil {
		hubmetrics.AuditCheckpoints.Add(float64(len(recs)), hubmetrics.AuditCheckpointFailed)
		return settings.StderrEnabled(), err
	}
	outcome := hubmetrics.AuditCheckpointUnsigned
	if key != nil {
		outcome = hubmetrics.AuditCheckpointSigned
	}
	hubmetrics.AuditCheckpoints.Add(float64(len(recs)), outcome)
	st.remember(marks)
	return true, nil
}

func (st *auditCheckpointState) stderrOut() io.Writer {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.stderr != nil {
		return st.stderr
	}
	return os.Stderr
}

// unchanged reports whether path's head is the one last recorded, recently.
func (st *auditCheckpointState) unchanged(path string, m auditHeadMark) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	prev, ok := st.last[path]
	return ok && prev.lastID == m.lastID && prev.lastHash == m.lastHash &&
		prev.anchorID == m.anchorID && m.at.Sub(prev.at) < auditCheckpointHeartbeat
}

func (st *auditCheckpointState) remember(marks map[string]auditHeadMark) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.last == nil {
		st.last = map[string]auditHeadMark{}
	}
	for p, m := range marks {
		st.last[p] = m
	}
}

// auditCheckpointChains lists the chains this hub serves: the control plane,
// then every registered project with a database, each file once.
func (s *Server) auditCheckpointChains() []auditCheckpointChain {
	seen := map[string]bool{}
	var out []auditCheckpointChain
	add := func(chain, dir string) {
		if dir == "" {
			return
		}
		path := state.DBPath(dir)
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if seen[path] {
			return
		}
		if _, err := os.Stat(path); err != nil {
			return // never run: no chain yet, and Open would create one
		}
		seen[path] = true
		out = append(out, auditCheckpointChain{chain: chain, dir: dir, path: path})
	}
	add(auditcheckpoint.ChainControlPlane, s.WorkDir)
	for _, e := range s.allProjectEntries() {
		add(auditcheckpoint.ChainProject, e.Path)
	}
	return out
}

// readAuditHead opens path just long enough to read its chain's head, and
// its prune anchors when it has any.
func readAuditHead(path string) (statedb.AuditHead, []statedb.AuditAnchor, error) {
	db, err := statedb.Open(path)
	if err != nil {
		return statedb.AuditHead{}, nil, err
	}
	defer db.Close()
	head, err := db.AuditHead()
	if err != nil || head.Anchor == nil {
		return head, nil, err
	}
	anchors, err := db.ListAuditAnchors()
	return head, anchors, err
}

// verifyAnchor reports whether the archive of path's newest anchor is the
// intact chain the anchor ends in, reading it the first time this process
// sees the anchor. The answer goes into the record under the seal: it is what
// lets a later verifier accept the prune once the archive has moved to cold
// storage, and what keeps an anchor written over deleted rows from being
// accepted at all. A failure is said loudly, once — at the time it happens is
// the only time anybody can still ask why.
func (st *auditCheckpointState) verifyAnchor(path string, anchors []statedb.AuditAnchor, a statedb.AuditAnchor) bool {
	if verified, known := st.checkedAnchor(path, a.AnchorHash); known {
		return verified
	}
	err := auditcheckpoint.VerifyAnchor(anchors, a)
	st.rememberAnchor(path, a.AnchorHash, err == nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[audit] prune anchor #%d of %s does not verify: %v — the checkpoints record it "+
			"unverified, and `cloop hub audit verify --checkpoints` will not accept the prune until its "+
			"archive is checked\n", a.ID, path, err)
	}
	return err == nil
}

// nextAuditWindow is when the window after now's begins.
func nextAuditWindow(now time.Time, interval time.Duration) time.Time {
	secs := int64(interval / time.Second)
	if secs <= 0 {
		secs = int64(config.AuditCheckpointIntervalDefault / time.Second)
	}
	return time.Unix((now.Unix()/secs+1)*secs, 0)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// StartAuditFailureStatus points this process's audit failure accounting at
// workDir's status directory, and records, as gap rows in their chains, the
// losses processes that died there left behind. Called by `cloop ui`, not by
// Run: the accounting is per process, and a test that builds a Server must
// not repoint it.
func StartAuditFailureStatus(workDir string) (adopted int64) {
	if workDir == "" {
		return 0
	}
	dir := statedb.AuditFailureStatusDir(workDir)
	statedb.SetAuditFailureStatusDir(dir)
	n, err := statedb.AdoptAuditFailureStatus(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[audit] could not read %s for losses an exited process left: %v\n", dir, err)
		return 0
	}
	return n
}

// shutdownAuditTrail settles the audit trail as the hub stops: what is owed
// is recorded while the databases are still open, and a leading hub writes
// every chain's head one last time.
func (s *Server) shutdownAuditTrail() {
	statedb.FlushAuditGaps(statedb.GapRecordedAtShutdown)
	s.writeShutdownAuditCheckpoints()
}
