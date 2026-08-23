package ui

// Per-project live harness output (Task 20189).
//
// Live output is the most sensitive stream the dashboard carries: it is the
// raw stdout/stderr of an AI harness working inside somebody's repository —
// file paths, source excerpts, occasionally a token the workload echoed back
// (a residual risk the threat model already names). It must never cross a
// project boundary, and on a multi-tenant hub a project boundary is also an
// identity boundary.
//
// Before this file, the buffer was three fields on Server — one `[]string`,
// one `bool`, one mutex — shared by every project the daemon had ever run.
// The replay sites could not have been correct: there was nothing to be
// correct about, because there was only ever one buffer to hand back.
//
// The fix is structural rather than a patch at each read site. The buffer is
// a map keyed by resolved workDir, reachable only through the accessors
// below, every one of which takes the workDir as its first parameter. A
// handler that has not resolved a project cannot name a room, so it cannot
// read one; `TestLiveLogBufferIsUnreachableWithoutAWorkDir` holds that
// property against future edits.

import "time"

// liveLogMaxLines caps one project's replay buffer. Reached by dropping the
// oldest lines, so replay always shows the most recent output.
const liveLogMaxLines = 500

// liveLogMaxRooms caps how many projects may hold a replay buffer at once.
//
// Rooms are created on first output and are otherwise only dropped when the
// project is deleted, so on a long-lived hub the map would grow with the
// number of projects that have *ever* run — liveLogMaxRooms × 500 lines is
// the bound that stops that being unbounded. Eviction prefers idle rooms
// (see evictLiveLogRoomLocked).
const liveLogMaxRooms = 64

// liveLogRoom is one project's slice of live output.
//
// lastUsed is touched by every accessor, not just writes: a project whose
// dashboard is open and replaying is in use even when its run is quiet, and
// evicting it would blank a screen somebody is watching.
type liveLogRoom struct {
	lines    []string
	running  bool
	lastUsed time.Time
}

// liveLogRoomFor returns workDir's room, creating it when create is set.
// Returns nil for an unknown project when create is false, and for an empty
// workDir always — an unresolved project must not silently share a room with
// another tenant, so the accessors fail closed rather than fall back.
//
// Callers hold liveLogMu.
func (s *Server) liveLogRoomFor(workDir string, create bool) *liveLogRoom {
	if workDir == "" {
		return nil
	}
	room := s.liveLogRooms[workDir]
	if room == nil {
		if !create {
			return nil
		}
		if s.liveLogRooms == nil {
			s.liveLogRooms = make(map[string]*liveLogRoom)
		}
		s.evictLiveLogRoomLocked()
		room = &liveLogRoom{}
		s.liveLogRooms[workDir] = room
	}
	room.lastUsed = time.Now()
	return room
}

// evictLiveLogRoomLocked makes space for one new room when the map is at
// capacity. It drops the least-recently-used room that is not currently
// running; a live run is spending memory for a reason and its dashboard is
// the one most likely to be open. Only if every room is running does it fall
// back to the global LRU, because refusing to allocate would silently drop
// the new project's output instead — a bounded map is the requirement, but
// losing the newest tenant's stream is the wrong way to meet it.
//
// Callers hold liveLogMu.
func (s *Server) evictLiveLogRoomLocked() {
	if len(s.liveLogRooms) < liveLogMaxRooms {
		return
	}
	var victim string
	var victimAt time.Time
	var victimRunning bool
	for dir, room := range s.liveLogRooms {
		better := victim == "" ||
			(victimRunning && !room.running) ||
			(victimRunning == room.running && room.lastUsed.Before(victimAt))
		if better {
			victim, victimAt, victimRunning = dir, room.lastUsed, room.running
		}
	}
	if victim != "" {
		delete(s.liveLogRooms, victim)
	}
}

// liveLogAppend records a chunk of workDir's output in its replay buffer.
func (s *Server) liveLogAppend(workDir, chunk string) {
	if workDir == "" {
		return
	}
	s.liveLogMu.Lock()
	defer s.liveLogMu.Unlock()
	room := s.liveLogRoomFor(workDir, true)
	if room == nil {
		return
	}
	for _, line := range splitAfterNewline(chunk) {
		room.lines = append(room.lines, line)
	}
	if len(room.lines) > liveLogMaxLines {
		// Re-slice into a fresh backing array rather than reusing the tail
		// of the old one: `lines[n:]` keeps the whole array alive, so a
		// long-running project would hold every line it ever emitted.
		trimmed := make([]string, liveLogMaxLines)
		copy(trimmed, room.lines[len(room.lines)-liveLogMaxLines:])
		room.lines = trimmed
	}
}

// liveLogReplay returns a copy of workDir's buffered lines. Unknown projects
// replay nothing — a client connecting to a project that has produced no
// output gets an empty replay, never another project's backlog.
func (s *Server) liveLogReplay(workDir string) []string {
	s.liveLogMu.Lock()
	defer s.liveLogMu.Unlock()
	room := s.liveLogRoomFor(workDir, false)
	if room == nil || len(room.lines) == 0 {
		return nil
	}
	out := make([]string, len(room.lines))
	copy(out, room.lines)
	return out
}

// liveLogStartRun clears workDir's buffer and marks it running. Called when
// this server dispatches a run, so replay never mixes two runs together.
func (s *Server) liveLogStartRun(workDir string) {
	if workDir == "" {
		return
	}
	s.liveLogMu.Lock()
	defer s.liveLogMu.Unlock()
	room := s.liveLogRoomFor(workDir, true)
	if room == nil {
		return
	}
	room.lines = nil
	room.running = true
}

// liveLogSetRunning updates workDir's in-memory run flag.
func (s *Server) liveLogSetRunning(workDir string, running bool) {
	if workDir == "" {
		return
	}
	s.liveLogMu.Lock()
	defer s.liveLogMu.Unlock()
	// Don't allocate a room just to record "not running" — that is the
	// default answer for a project with no room at all.
	room := s.liveLogRoomFor(workDir, running)
	if room == nil {
		return
	}
	room.running = running
}

// liveLogRunningFor reports whether this server is streaming a run for
// workDir. False for projects it has never run, including runs started
// outside the daemon — callers pair it with a /proc probe.
func (s *Server) liveLogRunningFor(workDir string) bool {
	s.liveLogMu.Lock()
	defer s.liveLogMu.Unlock()
	room := s.liveLogRoomFor(workDir, false)
	return room != nil && room.running
}

// liveLogEvict drops workDir's buffer outright. Called when a project is
// removed from the registry so a deleted project's output cannot be replayed
// to whoever registers that path next.
func (s *Server) liveLogEvict(workDir string) {
	if workDir == "" {
		return
	}
	s.liveLogMu.Lock()
	defer s.liveLogMu.Unlock()
	delete(s.liveLogRooms, workDir)
}

// splitAfterNewline splits a chunk into lines, keeping the terminator so
// re-joining the buffer reproduces the original bytes. Empty segments (from
// a trailing newline) are dropped.
func splitAfterNewline(chunk string) []string {
	var out []string
	start := 0
	for i := 0; i < len(chunk); i++ {
		if chunk[i] == '\n' {
			out = append(out, chunk[start:i+1])
			start = i + 1
		}
	}
	if start < len(chunk) {
		out = append(out, chunk[start:])
	}
	return out
}
