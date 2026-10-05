package ui

// The Event History panel's feed (Task 20384).
//
// The panel used to stay current by refetching: every task_update, state_diff,
// task_added, task_deleted, task_mutation and run_state message scheduled a
// GET /api/event-history, whatever tab was open, and once the history had been
// scrolled each refetch asked for every row already loaded. Each of those
// loaded the whole project — every step's output — and every event, sorted
// them in memory and returned fifty rows. :8888's telemetry had it at half of
// all dashboard fetches, every 1–5 s per open dashboard during a run.
//
// Now a page is a pair of LIMIT queries (statedb.History), and rows written
// after the page a client holds are pushed: when the watcher computes a
// project's state_diff it also reads the journal past the cursor it last
// pushed for that project and sends what it finds as one history_append to the
// project's room — the same room, gated the same way, as every other
// per-project message. A client fetches only to fill a gap it can see in the
// cursors: on connect, where the hub tells it how far the pushes it will see
// begin (a history_append with no rows), and when a push does not continue
// from where its list ends.

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	historyPageDefault = 50
	historyPageMax     = 500
	// historyValueCap is the longest step output or event details a page or
	// a push carries whole. On this hub's own journal 98% of steps fit; the
	// rest arrive in full when their row is opened (?step=N, ?event=N).
	historyValueCap = 4096
	// historyPushRows is the most rows one history_append carries. More than
	// that between two pushes is sent as a gap, which each client fills with
	// one read of its own.
	historyPushRows = 50
	// historyPushMaxBytes bounds a history_append on the wire, whatever the
	// rows hold.
	historyPushMaxBytes = 256 << 10
)

// historyCursor is a statedb.HistoryCursor on the wire: [step, event], the
// newest of each a reader has seen.
type historyCursor statedb.HistoryCursor

func (c historyCursor) MarshalJSON() ([]byte, error) {
	return []byte("[" + strconv.FormatInt(c.Step, 10) + "," + strconv.FormatInt(c.Event, 10) + "]"), nil
}

// historyPlace is a statedb.HistoryPlace on the wire: [julian day, 1 for an
// event or 0 for a step, step number or event id]. The day is the float
// SQLite computed, written in the shortest form that reads back as the same
// number — in Go and in JavaScript alike — so a page boundary sent back
// compares equal to the row it came from.
type historyPlace statedb.HistoryPlace

func (p historyPlace) MarshalJSON() ([]byte, error) {
	kind := "0"
	if p.Event {
		kind = "1"
	}
	return []byte("[" + strconv.FormatFloat(p.Day, 'g', -1, 64) + "," + kind + "," + strconv.FormatInt(p.Key, 10) + "]"), nil
}

// parseHistoryCursor reads after= as the dashboard sends it: "step,event".
func parseHistoryCursor(v string) (statedb.HistoryCursor, error) {
	f := strings.Split(v, ",")
	if len(f) == 2 {
		step, err1 := strconv.ParseInt(f[0], 10, 64)
		event, err2 := strconv.ParseInt(f[1], 10, 64)
		if err1 == nil && err2 == nil && step >= -1 && event >= 0 {
			return statedb.HistoryCursor{Step: step, Event: event}, nil
		}
	}
	return statedb.HistoryCursor{}, errors.New("must be <step>,<event> with step >= -1 and event >= 0")
}

// parseHistoryPlace reads before= as the dashboard sends it: "day,kind,key".
func parseHistoryPlace(v string) (statedb.HistoryPlace, error) {
	f := strings.Split(v, ",")
	if len(f) == 3 {
		day, err1 := strconv.ParseFloat(f[0], 64)
		key, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 == nil && err2 == nil && (f[1] == "0" || f[1] == "1") &&
			!math.IsNaN(day) && !math.IsInf(day, 0) && day >= 0 && key >= 0 {
			return statedb.HistoryPlace{Day: day, Event: f[1] == "1", Key: key}, nil
		}
	}
	return statedb.HistoryPlace{}, errors.New("must be <day>,<0|1>,<key> as a page's bottom gives it")
}

// historyEntry is one row of the panel's feed, in the shape it has read since
// Task 20118:
//
//	id          unique within the feed: step+1 for a step, -id for an event
//	kind        "step", or the event's type ("task_started", …)
//	timestamp   when the step finished or the event happened
//	task_id     0 when not task-bound
//	task_title  may be empty
//	step        the step number for a step; the event's step, -1 for none
//	message     the step's task line, or the event's summary
//	output      a step's output; exit_code and duration likewise
//	details     an event's JSON details
//	cut         the full length in bytes of output or details when the value
//	            here was shortened; the whole row is GET ?step=N / ?event=N
type historyEntry struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Timestamp time.Time `json:"timestamp"`
	TaskID    int       `json:"task_id,omitempty"`
	TaskTitle string    `json:"task_title,omitempty"`
	// Step has no omitempty: step 0 is a real step number and events set -1
	// explicitly when not step-bound — both must round-trip.
	Step int `json:"step"`
	// ExitCode has no omitempty: 0 is the success case for steps; the
	// renderer keys off Kind=="step" to know whether it is meaningful.
	ExitCode int             `json:"exit_code"`
	Message  string          `json:"message,omitempty"`
	Output   string          `json:"output,omitempty"`
	Duration string          `json:"duration,omitempty"`
	Details  json.RawMessage `json:"details,omitempty"`
	Cut      int             `json:"cut,omitempty"`
}

func historyEntryOf(r statedb.HistoryRow) historyEntry {
	if st := r.Step; st != nil {
		return historyEntry{
			ID:        int64(st.Step) + 1,
			Kind:      "step",
			Timestamp: st.Time,
			Step:      st.Step,
			Message:   st.Task,
			Output:    st.Output,
			ExitCode:  st.ExitCode,
			Duration:  st.Duration,
			Cut:       r.Cut,
		}
	}
	ev := r.Event
	e := historyEntry{
		ID:        -ev.ID,
		Kind:      string(ev.Type),
		Timestamp: ev.Timestamp,
		TaskID:    ev.TaskID,
		TaskTitle: ev.TaskTitle,
		Step:      ev.Step,
		Message:   ev.Message,
		Cut:       r.Cut,
	}
	// Passed through as written rather than decoded and encoded again; a
	// blob that is not JSON is left out, as it always was.
	if ev.Details != "" && json.Valid([]byte(ev.Details)) {
		e.Details = json.RawMessage(ev.Details)
	}
	return e
}

func historyEntries(rows []statedb.HistoryRow) []historyEntry {
	out := make([]historyEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, historyEntryOf(r))
	}
	return out
}

// historyResponse is GET /api/event-history's answer.
type historyResponse struct {
	Entries []historyEntry `json:"entries"`
	// Top is the newest step and event written when the page was read; pass
	// it back as after= to read what was written since. Absent on a before=
	// page, which says nothing about what is new.
	Top *historyCursor `json:"top,omitempty"`
	// Bottom is the place of the last entry; pass it back as before= for the
	// next page down. Null when there is no entry to page from.
	Bottom *historyPlace `json:"bottom"`
	// More reports rows below Bottom.
	More bool `json:"more"`
	// Gap is set on an after= read that found more newer rows than its limit:
	// the entries are then the newest page, not a continuation.
	Gap    bool `json:"gap,omitempty"`
	Offset int  `json:"offset"`
	Limit  int  `json:"limit"`
}

// handleEventHistory serves the project's journal — its steps and events as
// one feed, newest first (Task 20118) — a page at a time from SQL (Task 20384).
//
//	GET /api/event-history?limit=50                the newest page
//	GET /api/event-history?before=<bottom>&limit=50  the page below a bottom
//	GET /api/event-history?after=<top>&limit=500     what was written since a top
//	GET /api/event-history?offset=N&limit=50       by position, for older callers
//	GET /api/event-history?step=N | ?event=N       one row, nothing cut
//
// No total: counting the steps table reads every page of it, and the panel
// has not needed the number since it stopped paging by position.
func (s *Server) handleEventHistory(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	qv := r.URL.Query()

	for _, one := range []string{"step", "event"} {
		v := qv.Get(one)
		if v == "" {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			jsonErr(w, one+" must be a non-negative integer", http.StatusBadRequest)
			return
		}
		row, ok, err := state.EventHistoryRow(workDir, one == "step", n)
		if err != nil {
			s.historyReadFailed(w, r, workDir, err)
			return
		}
		if !ok {
			jsonErr(w, "no such "+one, http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]any{"entries": []historyEntry{historyEntryOf(row)}})
		return
	}

	q := statedb.HistoryQuery{Limit: historyPageDefault, MaxValue: historyValueCap}
	if v := qv.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			q.Limit = min(n, historyPageMax)
		}
	}
	// One direction per read; after wins.
	if v := qv.Get("after"); v != "" {
		c, err := parseHistoryCursor(v)
		if err != nil {
			jsonErr(w, "after: "+err.Error(), http.StatusBadRequest)
			return
		}
		q.After = &c
	} else if v := qv.Get("before"); v != "" {
		p, err := parseHistoryPlace(v)
		if err != nil {
			jsonErr(w, "before: "+err.Error(), http.StatusBadRequest)
			return
		}
		q.Before = &p
	} else {
		if n, err := strconv.Atoi(qv.Get("offset")); err == nil && n > 0 {
			q.Offset = n
		}
	}

	page, err := state.EventHistory(workDir, q)
	if err != nil {
		s.historyReadFailed(w, r, workDir, err)
		return
	}
	resp := historyResponse{
		Entries: historyEntries(page.Rows),
		More:    page.More,
		Gap:     page.Gap,
		Offset:  q.Offset,
		Limit:   q.Limit,
	}
	if q.Before == nil {
		top := historyCursor(page.Top)
		resp.Top = &top
	}
	if page.Bottom != nil {
		bottom := historyPlace(*page.Bottom)
		resp.Bottom = &bottom
	}
	jsonOK(w, resp)
}

func (s *Server) historyReadFailed(w http.ResponseWriter, r *http.Request, workDir string, err error) {
	if errors.Is(err, statedb.ErrProjectNotFound) {
		jsonErr(w, "no cloop project found", http.StatusNotFound)
		return
	}
	s.log().WithContext(r.Context()).Error("event_history_failed", 0, err.Error(),
		map[string]interface{}{"project": workDir})
	jsonErr(w, "event history could not be read: "+err.Error(), http.StatusInternalServerError)
}

// ── push ────────────────────────────────────────────────────────────────────

// historyAppend is the history_append message: the rows written above From,
// up to To, newest first. With no rows and From equal to To it is a sync
// point — "the pushes after this one continue from here" — which a client
// compares with the newest cursor it holds. Gap says rows above From exist
// that the message does not carry.
type historyAppend struct {
	Entries []historyEntry `json:"entries"`
	From    historyCursor  `json:"from"`
	To      historyCursor  `json:"to"`
	Gap     bool           `json:"gap,omitempty"`
}

// historyFeed is one project's push position on this hub member: the cursor
// its last history_append ended at. Each member reads the shared database
// itself, so like state_diff the message is never relayed.
type historyFeed struct {
	mu     sync.Mutex
	cursor statedb.HistoryCursor
	known  bool
}

// historyFeeds holds a feed per project somebody has open.
type historyFeeds struct {
	mu    sync.Mutex
	feeds map[string]*historyFeed
}

func (s *Server) historyFeedFor(workDir string) *historyFeed {
	s.history.mu.Lock()
	defer s.history.mu.Unlock()
	if s.history.feeds == nil {
		s.history.feeds = make(map[string]*historyFeed)
	}
	f := s.history.feeds[workDir]
	if f == nil {
		f = &historyFeed{}
		s.history.feeds[workDir] = f
	}
	return f
}

// dropHistoryFeedIfIdle forgets a project's push position once nobody on this
// member has it open. The next client to open it starts a fresh position at
// the journal's top, rather than being sent everything written while nobody
// was looking.
func (s *Server) dropHistoryFeedIfIdle(workDir string) {
	if s.hasStreamClients(workDir) {
		return
	}
	s.history.mu.Lock()
	delete(s.history.feeds, workDir)
	s.history.mu.Unlock()
}

// hasStreamClients reports whether any WebSocket or SSE client of this member
// is subscribed to workDir.
func (s *Server) hasStreamClients(workDir string) bool {
	s.hubMu.Lock()
	n := len(s.hubClients[workDir])
	s.hubMu.Unlock()
	if n > 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		if c.workDir == workDir {
			return true
		}
	}
	return false
}

// pushHistory sends the project's room the journal rows written since its
// last push. Called where the watcher computes the project's state_diff, so
// it runs on the same evidence of change — any write to the state database,
// by a run, the CLI or this hub — and never on a request's critical path.
func (s *Server) pushHistory(workDir string) {
	if workDir == "" {
		return
	}
	if !s.hasStreamClients(workDir) {
		s.dropHistoryFeedIfIdle(workDir)
		return
	}
	f := s.historyFeedFor(workDir)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.known {
		// Nothing was pushed from here yet, so nobody can be told what
		// continues from where. Announce the journal's top instead: a client
		// whose list ends below it fetches the difference itself.
		top, err := state.EventHistoryTop(workDir)
		if err != nil {
			return
		}
		f.cursor, f.known = top, true
		s.sendHistory(workDir, historyAppend{Entries: []historyEntry{}, From: historyCursor(top), To: historyCursor(top)})
		return
	}
	from := f.cursor
	page, err := state.EventHistory(workDir, statedb.HistoryQuery{
		After: &from, Limit: historyPushRows, MaxValue: historyValueCap,
	})
	if err != nil {
		return
	}
	if len(page.Rows) == 0 && !page.Gap {
		return
	}
	msg := historyAppend{
		Entries: historyEntries(page.Rows),
		From:    historyCursor(from),
		To:      historyCursor(page.Top),
		Gap:     page.Gap,
	}
	if page.Gap {
		// The page is the newest rows, not the ones above From; each client
		// reads the difference from its own position instead.
		msg.Entries = []historyEntry{}
	}
	f.cursor = page.Top
	s.sendHistory(workDir, msg)
}

// sendHistory delivers msg to workDir's WebSocket room and SSE streams.
func (s *Server) sendHistory(workDir string, msg historyAppend) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return
	}
	if len(raw) > historyPushMaxBytes {
		msg.Entries, msg.Gap = []historyEntry{}, true
		if raw, err = json.Marshal(msg); err != nil {
			return
		}
	}
	s.broadcastToProject(workDir, wsMessage{Type: "history_append", Data: raw})
	s.deliverSSE(workDir, sseEvent{Event: "history_append", Data: string(raw)})
}

// historySyncPoint is the history_append a stream opening on workDir is primed
// with: no rows, and the position the pushes it will receive continue from.
// A client whose list ends below that position — it loaded its page before
// connecting, or reconnected after missing pushes — fetches the difference.
func (s *Server) historySyncPoint(workDir string) ([]byte, bool) {
	f := s.historyFeedFor(workDir)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.known {
		top, err := state.EventHistoryTop(workDir)
		if err != nil {
			return nil, false
		}
		f.cursor, f.known = top, true
	}
	raw, err := json.Marshal(historyAppend{
		Entries: []historyEntry{}, From: historyCursor(f.cursor), To: historyCursor(f.cursor),
	})
	return raw, err == nil
}
