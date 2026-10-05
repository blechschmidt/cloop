package ui

// The hub side of the Event History feed (Task 20384): pages served from SQL,
// rows written later pushed to the project's room, and nobody outside that
// room — another tenant's project, an identity the project was never shared
// with or has been unshared from — receiving them.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"nhooyr.io/websocket"
)

// journalFixture writes steps and events into a project's database the way a
// run does, through its own handle.
type journalFixture struct {
	t    *testing.T
	dir  string
	step int
	at   time.Time
}

func newJournalFixture(t *testing.T, dir string) *journalFixture {
	return &journalFixture{t: t, dir: dir, at: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
}

func (j *journalFixture) with(fn func(*statedb.DB)) {
	j.t.Helper()
	db, err := statedb.Open(state.StateDBPath(j.dir))
	if err != nil {
		j.t.Fatalf("open %s: %v", j.dir, err)
	}
	defer db.Close()
	fn(db)
}

// tick advances the fixture's clock; every row is a second after the last.
func (j *journalFixture) tick() time.Time {
	j.at = j.at.Add(time.Second)
	return j.at
}

func (j *journalFixture) addStep(output string) int {
	j.t.Helper()
	n := j.step
	j.step++
	at := j.tick()
	j.with(func(db *statedb.DB) {
		if err := db.AppendStep(statedb.StepRow{Step: n, Task: fmt.Sprintf("Task %d: work", n), Output: output, Duration: "3s", Time: at}); err != nil {
			j.t.Fatalf("AppendStep: %v", err)
		}
	})
	return n
}

func (j *journalFixture) addEvent(message, details string) int64 {
	j.t.Helper()
	at := j.tick()
	var id int64
	j.with(func(db *statedb.DB) {
		if err := db.RecordEvent(statedb.EventRow{Timestamp: at, Type: statedb.EventTaskDone, TaskID: 7, TaskTitle: "work", Step: statedb.NoStep, Message: message, Details: details}); err != nil {
			j.t.Fatalf("RecordEvent: %v", err)
		}
		top, err := db.HistoryTop()
		if err != nil {
			j.t.Fatal(err)
		}
		id = top.Event
	})
	return id
}

// historyBody is GET /api/event-history's answer as a client reads it.
type historyBody struct {
	Entries []historyEntry `json:"entries"`
	Top     []int64        `json:"top"`
	Bottom  []float64      `json:"bottom"`
	More    bool           `json:"more"`
	Gap     bool           `json:"gap"`
}

func getHistory(t *testing.T, ts *httptest.Server, query string) (int, historyBody) {
	t.Helper()
	resp, err := http.Get(ts.URL + "/api/event-history?" + query)
	if err != nil {
		t.Fatalf("GET %s: %v", query, err)
	}
	defer resp.Body.Close()
	var b historyBody
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatalf("decode %s: %v\n%s", query, err, raw)
		}
	}
	return resp.StatusCode, b
}

// entryName names an entry by what it is, as the panel keys it.
func entryName(e historyEntry) string {
	if e.Kind == "step" {
		return fmt.Sprintf("s%d", e.Step)
	}
	return fmt.Sprintf("e%d", -e.ID)
}

func entryNames(es []historyEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = entryName(e)
	}
	return out
}

// place is a page's bottom as the dashboard sends it back: the array joined
// with commas, which is what JavaScript's Array#toString produces.
func place(b []float64) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = strings.TrimSuffix(fmt.Sprintf("%v", v), ".0")
	}
	return strings.Join(parts, ",")
}

// TestEventHistory_PagesTheJournal walks a project's journal through the HTTP
// endpoint the way the dashboard does — the newest page, then before= the
// bottom each page hands back — and by the positional offset older callers
// use, and checks both read every row once, newest first, in the shape the
// panel renders.
func TestEventHistory_PagesTheJournal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "page the journal", nil)
	j := newJournalFixture(t, dir)
	var want []string
	for i := 0; i < 7; i++ {
		want = append([]string{fmt.Sprintf("s%d", j.addStep("output "+fmt.Sprint(i)))}, want...)
		want = append([]string{fmt.Sprintf("e%d", j.addEvent(fmt.Sprintf("Task #7 done (%d)", i), `{"attempt":1}`))}, want...)
	}
	ts := newTestServer(t, dir, nil)

	code, first := getHistory(t, ts, "limit=3")
	if code != http.StatusOK {
		t.Fatalf("newest page: HTTP %d", code)
	}
	if got := entryNames(first.Entries); strings.Join(got, " ") != strings.Join(want[:3], " ") {
		t.Fatalf("newest page = %v, want %v", got, want[:3])
	}
	if len(first.Top) != 2 || first.Top[0] != 6 || first.Top[1] != 7 || !first.More || len(first.Bottom) != 3 {
		t.Fatalf("newest page: top=%v bottom=%v more=%v; want top [6 7], a bottom and more", first.Top, first.Bottom, first.More)
	}
	// The row shapes the panel renders (Task 20118), unchanged.
	ev, st := first.Entries[0], first.Entries[1]
	if ev.Kind != "task_done" || ev.ID != -7 || ev.Step != -1 || ev.TaskID != 7 || string(ev.Details) != `{"attempt":1}` {
		t.Errorf("event entry = %+v", ev)
	}
	if st.Kind != "step" || st.ID != 7 || st.Step != 6 || st.Output != "output 6" || st.Duration != "3s" || st.ExitCode != 0 {
		t.Errorf("step entry = %+v", st)
	}

	got := entryNames(first.Entries)
	page := first
	for page.More {
		code, page = getHistory(t, ts, "limit=3&before="+url.QueryEscape(place(page.Bottom)))
		if code != http.StatusOK {
			t.Fatalf("page down: HTTP %d", code)
		}
		if page.Top != nil {
			t.Errorf("a page down claims a top %v; it read nothing new", page.Top)
		}
		got = append(got, entryNames(page.Entries)...)
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("paging down read\n  %v\nwant\n  %v", got, want)
	}

	var byOffset []string
	for off := 0; ; off += 4 {
		code, p := getHistory(t, ts, fmt.Sprintf("offset=%d&limit=4", off))
		if code != http.StatusOK {
			t.Fatalf("offset %d: HTTP %d", off, code)
		}
		byOffset = append(byOffset, entryNames(p.Entries)...)
		if !p.More {
			break
		}
	}
	if strings.Join(byOffset, " ") != strings.Join(want, " ") {
		t.Fatalf("paging by offset read\n  %v\nwant\n  %v", byOffset, want)
	}
}

// TestEventHistory_ReadsWhatWasWrittenSince covers after=: the rows written
// since a top, and a gap once there are more than the limit.
func TestEventHistory_ReadsWhatWasWrittenSince(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "read what is new", nil)
	j := newJournalFixture(t, dir)
	j.addStep("first")
	ts := newTestServer(t, dir, nil)
	_, first := getHistory(t, ts, "limit=50")
	top := fmt.Sprintf("%d,%d", first.Top[0], first.Top[1])

	s := j.addStep("second")
	e := j.addEvent("Task #7 done", "")
	code, next := getHistory(t, ts, "limit=500&after="+top)
	if code != http.StatusOK || next.Gap {
		t.Fatalf("after %s: HTTP %d gap=%v", top, code, next.Gap)
	}
	if got := entryNames(next.Entries); strings.Join(got, " ") != fmt.Sprintf("e%d s%d", e, s) {
		t.Fatalf("after %s = %v, want [e%d s%d]", top, got, e, s)
	}
	if next.Top[0] != int64(s) || next.Top[1] != e {
		t.Fatalf("top after the read = %v, want [%d %d]", next.Top, s, e)
	}

	for i := 0; i < 3; i++ {
		j.addEvent("burst", "")
	}
	code, gap := getHistory(t, ts, fmt.Sprintf("limit=2&after=%d,%d", next.Top[0], next.Top[1]))
	if code != http.StatusOK || !gap.Gap || len(gap.Entries) != 2 {
		t.Fatalf("three new rows past a limit of two: HTTP %d gap=%v entries=%d, want a gap with the newest two",
			code, gap.Gap, len(gap.Entries))
	}
}

// TestEventHistory_LongValuesLoadWhole: a page carries a long output cut, says
// how long it was, and serves the row whole on its own.
func TestEventHistory_LongValuesLoadWhole(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "long outputs", nil)
	j := newJournalFixture(t, dir)
	long := strings.Repeat("0123456789", 1000)
	n := j.addStep(long)
	details := `{"files":"` + strings.Repeat("x", 5000) + `"}`
	id := j.addEvent("big details", details)
	ts := newTestServer(t, dir, nil)

	_, page := getHistory(t, ts, "limit=50")
	if len(page.Entries) != 2 {
		t.Fatalf("entries = %v", entryNames(page.Entries))
	}
	ev, st := page.Entries[0], page.Entries[1]
	if len(st.Output) != historyValueCap || st.Cut != len(long) {
		t.Errorf("long step on a page: %d bytes, cut=%d; want %d bytes and cut=%d", len(st.Output), st.Cut, historyValueCap, len(long))
	}
	if ev.Details != nil || ev.Cut != len(details) {
		t.Errorf("long details on a page: %q cut=%d; want none and cut=%d", ev.Details, ev.Cut, len(details))
	}

	_, whole := getHistory(t, ts, fmt.Sprintf("step=%d", n))
	if len(whole.Entries) != 1 || whole.Entries[0].Output != long || whole.Entries[0].Cut != 0 {
		t.Fatalf("?step=%d did not return the whole output", n)
	}
	_, wholeEv := getHistory(t, ts, fmt.Sprintf("event=%d", id))
	if len(wholeEv.Entries) != 1 || string(wholeEv.Entries[0].Details) != details {
		t.Fatalf("?event=%d did not return the whole details", id)
	}
}

// TestEventHistory_RefusesMalformedReads: positions are parsed, not trusted.
func TestEventHistory_RefusesMalformedReads(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "malformed", nil)
	newJournalFixture(t, dir).addStep("x")
	ts := newTestServer(t, dir, nil)
	for query, want := range map[string]int{
		"before=nonsense":    http.StatusBadRequest,
		"before=1,2":         http.StatusBadRequest,
		"before=NaN,0,1":     http.StatusBadRequest,
		"before=2461318,2,1": http.StatusBadRequest,
		"after=5":            http.StatusBadRequest,
		"after=-2,0":         http.StatusBadRequest,
		"step=-1":            http.StatusBadRequest,
		"step=abc":           http.StatusBadRequest,
		"step=999":           http.StatusNotFound,
		"event=999":          http.StatusNotFound,
	} {
		if code, _ := getHistory(t, ts, query); code != want {
			t.Errorf("GET ?%s: HTTP %d, want %d", query, code, want)
		}
	}
	// No database: the project is not there, which is a 404, not a 500.
	t.Setenv("HOME", t.TempDir())
	empty := t.TempDir()
	if code, _ := getHistory(t, newTestServer(t, empty, nil), "limit=5"); code != http.StatusNotFound {
		t.Errorf("a directory with no project: HTTP %d, want 404", code)
	}
}

// historyAppends returns the history_append messages queued for hc.
func historyAppends(t *testing.T, msgs []wsMessage) []historyAppendBody {
	t.Helper()
	var out []historyAppendBody
	for _, m := range msgs {
		if m.Type != "history_append" {
			continue
		}
		var b historyAppendBody
		if err := json.Unmarshal(m.Data, &b); err != nil {
			t.Fatalf("history_append is not JSON: %v\n%s", err, m.Data)
		}
		out = append(out, b)
	}
	return out
}

type historyAppendBody struct {
	Entries []historyEntry `json:"entries"`
	From    []int64        `json:"from"`
	To      []int64        `json:"to"`
	Gap     bool           `json:"gap"`
}

// TestHistoryPush_SendsTheRoomWhatWasWritten: the first push is a sync point
// (no rows; where pushes continue from), each later one exactly the rows
// written since the one before, and a push with nothing new sends nothing —
// over the WebSocket room and the SSE fallback alike.
func TestHistoryPush_SendsTheRoomWhatWasWritten(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "push", nil)
	j := newJournalFixture(t, dir)
	j.addStep("before anyone looked")
	srv := New(dir, 0, "")
	ws := subscribe(t, srv, dir, "alice@example.com")
	sse := subscribeSSE(t, srv, dir, "alice@example.com")

	srv.pushHistory(dir)
	sync := historyAppends(t, drainWSMessages(ws))
	if len(sync) != 1 || len(sync[0].Entries) != 0 || fmt.Sprint(sync[0].From) != "[0 0]" || fmt.Sprint(sync[0].To) != "[0 0]" {
		t.Fatalf("first push = %+v, want one sync point at [0 0]", sync)
	}

	s := j.addStep("new output")
	e := j.addEvent("Task #7 done", "")
	srv.pushHistory(dir)
	got := historyAppends(t, drainWSMessages(ws))
	if len(got) != 1 {
		t.Fatalf("pushes after two writes = %d, want 1", len(got))
	}
	if names := entryNames(got[0].Entries); strings.Join(names, " ") != fmt.Sprintf("e%d s%d", e, s) {
		t.Fatalf("pushed %v, want [e%d s%d]", names, e, s)
	}
	if fmt.Sprint(got[0].From) != "[0 0]" || fmt.Sprint(got[0].To) != fmt.Sprintf("[%d %d]", s, e) {
		t.Fatalf("push from %v to %v, want [0 0] to [%d %d]", got[0].From, got[0].To, s, e)
	}

	var sseAppends int
	for _, ev := range drainSSEEvents(sse) {
		if ev.Event == "history_append" && strings.Contains(ev.Data, `"Task #7 done"`) {
			sseAppends++
		}
	}
	if sseAppends != 1 {
		t.Fatalf("the SSE stream got %d history_append events carrying the rows, want 1", sseAppends)
	}

	srv.pushHistory(dir)
	if again := historyAppends(t, drainWSMessages(ws)); len(again) != 0 {
		t.Fatalf("a push with nothing new sent %+v", again)
	}
}

// TestHistoryPush_IsBounded: a burst bigger than one message is announced as
// a gap for each client to fill itself, and a long output travels cut.
func TestHistoryPush_IsBounded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "bounded", nil)
	j := newJournalFixture(t, dir)
	srv := New(dir, 0, "")
	ws := subscribe(t, srv, dir, "alice@example.com")
	srv.pushHistory(dir) // the sync point
	drainWSMessages(ws)

	j.addStep(strings.Repeat("y", 3*historyValueCap))
	srv.pushHistory(dir)
	got := historyAppends(t, drainWSMessages(ws))
	if len(got) != 1 || len(got[0].Entries) != 1 || len(got[0].Entries[0].Output) != historyValueCap || got[0].Entries[0].Cut != 3*historyValueCap {
		t.Fatalf("a long output's push = %+v, want it cut to %d bytes", got, historyValueCap)
	}

	j.with(func(db *statedb.DB) {
		for i := 0; i <= historyPushRows; i++ {
			if err := db.RecordEvent(statedb.EventRow{Type: statedb.EventTaskAdded, Step: statedb.NoStep, Message: "burst"}); err != nil {
				t.Fatal(err)
			}
		}
	})
	srv.pushHistory(dir)
	got = historyAppends(t, drainWSMessages(ws))
	if len(got) != 1 || !got[0].Gap || len(got[0].Entries) != 0 {
		t.Fatalf("a burst of %d rows pushed %+v, want one gap with no rows", historyPushRows+1, got)
	}
}

// TestHistoryPush_NeverLeavesItsProject is the Task 20189 boundary for the new
// message: rows written in alice's project are pushed to alice's room only,
// never to a client of bob's — over either transport — and bob's own pushes
// carry none of alice's rows.
func TestHistoryPush_NeverLeavesItsProject(t *testing.T) {
	dirA, dirB, srv := twoTenantHub(t)
	alice := subscribe(t, srv, dirA, "alice@example.com")
	bob := subscribe(t, srv, dirB, "bob@example.com")
	aliceSSE := subscribeSSE(t, srv, dirA, "alice@example.com")
	bobSSE := subscribeSSE(t, srv, dirB, "bob@example.com")
	srv.pushHistory(dirA)
	srv.pushHistory(dirB)
	drainWSMessages(alice)
	drainWSMessages(bob)
	drainSSEEvents(aliceSSE)
	drainSSEEvents(bobSSE)

	newJournalFixture(t, dirA).addEvent("ALICE-PRIVATE-TOKEN-abc123 deployed", "")
	newJournalFixture(t, dirB).addEvent("bob's own row", "")
	srv.pushHistory(dirA)
	srv.pushHistory(dirB)

	for _, m := range drainWSMessages(bob) {
		if strings.Contains(string(m.Data), "ALICE-PRIVATE-TOKEN") {
			t.Fatalf("project B's WebSocket received project A's journal: %s %s", m.Type, m.Data)
		}
	}
	for _, e := range drainSSEEvents(bobSSE) {
		if strings.Contains(e.Data, "ALICE-PRIVATE-TOKEN") {
			t.Fatalf("project B's SSE stream received project A's journal: %s", e.Data)
		}
	}
	// Both rooms still get their own rows, or "deliver nothing" would pass.
	var aliceGot, aliceSSEGot bool
	for _, b := range historyAppends(t, drainWSMessages(alice)) {
		for _, e := range b.Entries {
			if strings.Contains(e.Message, "ALICE-PRIVATE-TOKEN") {
				aliceGot = true
			}
		}
	}
	for _, e := range drainSSEEvents(aliceSSE) {
		aliceSSEGot = aliceSSEGot || (e.Event == "history_append" && strings.Contains(e.Data, "ALICE-PRIVATE-TOKEN"))
	}
	if !aliceGot || !aliceSSEGot {
		t.Fatalf("project A's own subscribers did not get its row: ws=%v sse=%v", aliceGot, aliceSSEGot)
	}
}

// TestHistoryPush_ReachesNobodyWithoutAccess runs the boundary through the
// real gate on a single sign-on hub whose default role is none: an identity
// the project was never shared with cannot open its stream at all, a member
// gets the project's pushes, and a member unshared mid-stream is closed and
// sent nothing written after.
func TestHistoryPush_ReachesNobodyWithoutAccess(t *testing.T) {
	f := newMemberFixture(t, true)
	j := newJournalFixture(t, f.project)
	j.addStep("alice's first step")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wsBase := "ws" + strings.TrimPrefix(f.ts.URL, "http")

	// Carol has no role and no membership: no stream on the project.
	if conn, resp, err := websocket.Dial(ctx, wsBase+"/api/ws?project_idx=0", &websocket.DialOptions{HTTPClient: f.carol}); err == nil {
		conn.CloseNow()
		t.Fatal("an identity with no access to the project opened its socket")
	} else if resp != nil && resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatalf("carol's dial was upgraded: %v", err)
	}
	if code, _ := f.call(t, f.carol, http.MethodGet, "/api/event-history?project_idx=0", nil); code == http.StatusOK {
		t.Fatal("an identity with no access read the project's event history")
	}

	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	bob, _, err := websocket.Dial(ctx, wsBase+"/api/ws?project_idx=0", &websocket.DialOptions{HTTPClient: f.bob})
	if err != nil {
		t.Fatalf("bob, a member, opens the project's socket: %v", err)
	}
	defer bob.CloseNow()
	// The connect burst's sync point, then the row written for the member.
	if !readUntil(ctx, t, bob, func(m wsMessage) bool { return m.Type == "history_append" }) {
		t.Fatal("the member's socket got no history sync point")
	}
	waitMember(t, "bob in the project's room", func() bool { return f.srv.roomSize(f.project) > 0 })
	j.addEvent("shared with bob", "")
	f.srv.pushHistory(f.project)
	if !readUntil(ctx, t, bob, func(m wsMessage) bool {
		return m.Type == "history_append" && strings.Contains(string(m.Data), "shared with bob")
	}) {
		t.Fatal("the member was not pushed the project's new row")
	}

	if code, body := f.call(t, f.alice, http.MethodDelete, members+"?identity="+url.QueryEscape(bobEmail), nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, body)
	}
	waitMember(t, "bob out of the project's room", func() bool { return f.srv.roomSize(f.project) == 0 })
	j.addEvent("AFTER-REVOCATION-SECRET", "")
	f.srv.pushHistory(f.project)

	for {
		_, raw, err := bob.Read(ctx)
		if err != nil {
			var ce websocket.CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("the revoked socket ended without a close frame: %v", err)
			}
			break
		}
		if strings.Contains(string(raw), "AFTER-REVOCATION-SECRET") {
			t.Fatalf("a member unshared from the project was pushed a row written after: %s", raw)
		}
	}
}

// TestHistorySyncPoint_PrimesProjectStreamsOnly: a stream opened on a project
// is told where its pushes begin — the journal's top — and a projects-page
// stream, which shows no project, is told nothing.
func TestHistorySyncPoint_PrimesProjectStreamsOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "sync point", nil)
	j := newJournalFixture(t, dir)
	j.addStep("a")
	e := j.addEvent("b", "")
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	wsBase := "ws" + strings.TrimPrefix(ts.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsBase+"/api/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(-1)
	var sync historyAppendBody
	if !readUntil(ctx, t, conn, func(m wsMessage) bool {
		return m.Type == "history_append" && json.Unmarshal(m.Data, &sync) == nil
	}) {
		t.Fatal("a project stream was not sent a history sync point")
	}
	if len(sync.Entries) != 0 || fmt.Sprint(sync.From) != fmt.Sprintf("[0 %d]", e) || fmt.Sprint(sync.To) != fmt.Sprint(sync.From) {
		t.Fatalf("sync point = %+v, want no rows at [0 %d]", sync, e)
	}

	landing, _, err := websocket.Dial(ctx, wsBase+"/api/ws?scope=global", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer landing.CloseNow()
	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
	defer readCancel()
	if readUntil(readCtx, t, landing, func(m wsMessage) bool { return m.Type == "history_append" }) {
		t.Fatal("a projects-page stream was sent a project's history sync point")
	}

	// The SSE fallback opens with the same sync point.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64<<10)
	var body strings.Builder
	for !strings.Contains(body.String(), "event: history_append\n") {
		n, err := resp.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			t.Fatalf("the SSE stream opened without a history sync point: %v\n%s", err, body.String())
		}
	}
}

// TestHistoryPush_FollowsTheWatcher: the push rides the watcher that computes
// the project's state_diff, so a row written by any process — here a direct
// write, as a CLI or a run would make — reaches the room without a request.
// An SSE fallback stream is pushed it too, though the sweep sends state diffs
// to WebSocket rooms only.
func TestHistoryPush_FollowsTheWatcher(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	primary := setupProjectDir(t, "primary", nil)
	viaWS := setupProjectDir(t, "watched over a websocket", nil)
	viaSSE := setupProjectDir(t, "watched over the SSE fallback", nil)
	srv := New(primary, 0, "")
	srv.Projects = []string{viaWS, viaSSE}
	ws := subscribe(t, srv, viaWS, "alice@example.com")
	sse := subscribeSSE(t, srv, viaSSE, "alice@example.com")
	wsJournal, sseJournal := newJournalFixture(t, viaWS), newJournalFixture(t, viaSSE)
	wsJournal.addStep("x")
	sseJournal.addStep("x")

	sw := newProjectSweep()
	srv.sweepProjectsTick(sw, time.Now())
	drainWSMessages(ws)
	drainSSEEvents(sse)

	wsJournal.addEvent("written by a run", "")
	sseJournal.addEvent("written by the CLI", "")
	// The sweep notices a state file's modification time; make sure these
	// writes' are not the ones it already saw.
	future := time.Now().Add(time.Minute)
	for _, dir := range []string{viaWS, viaSSE} {
		for _, f := range stateFilesFor(dir) {
			_ = os.Chtimes(f, future, future)
		}
	}
	srv.sweepProjectsTick(sw, time.Now())
	var got bool
	for _, b := range historyAppends(t, drainWSMessages(ws)) {
		for _, e := range b.Entries {
			got = got || e.Message == "written by a run"
		}
	}
	if !got {
		t.Error("a row written to a project watched over a WebSocket was not pushed by the sweep")
	}
	got = false
	for _, e := range drainSSEEvents(sse) {
		got = got || (e.Event == "history_append" && strings.Contains(e.Data, "written by the CLI"))
	}
	if !got {
		t.Error("a row written to a project watched over SSE was not pushed by the sweep")
	}
}

// TestHistoryFeed_IsForgottenWhenNobodyWatches: a project's push position is
// dropped with its last subscriber, so the next one starts at the journal's
// top instead of being sent everything written in between.
func TestHistoryFeed_IsForgottenWhenNobodyWatches(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "forget", nil)
	srv := New(dir, 0, "")
	hc := subscribe(t, srv, dir, "alice@example.com")
	srv.pushHistory(dir)
	srv.history.mu.Lock()
	_, kept := srv.history.feeds[dir]
	srv.history.mu.Unlock()
	if !kept {
		t.Fatal("a watched project has no push position")
	}
	srv.hubMu.Lock()
	delete(srv.hubClients[dir], hc)
	srv.hubMu.Unlock()
	srv.dropHistoryFeedIfIdle(dir)
	srv.history.mu.Lock()
	_, kept = srv.history.feeds[dir]
	srv.history.mu.Unlock()
	if kept {
		t.Fatal("the push position outlived the project's last subscriber")
	}
}
