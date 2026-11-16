package ui

// Readers lists pushed to open dashboards (Task 20503): each dashboard showing
// either project of a changed entry is sent that project's lists as its own
// GET would answer them — named, counted and managed per viewer — on a hub
// with single sign-on and on one without, over the WebSocket and the event
// stream, from this member and from another, and again when who may see a
// listed project changes. And the GET offers a manager exactly the projects
// the PUT would take.

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/projectreaders"
)

// readersFeed is the project_readers views one dashboard stream receives.
type readersFeed struct {
	what  string
	views chan readersResponse
	// seen is every view taken from views, in order.
	seen []readersResponse
}

// until returns the first view the stream receives that pred accepts,
// failing after five seconds. A hub pushes every open Readers section again
// whenever who may see which project changes — a share made while a test
// sets up is one — so a test waits for the view a change makes rather than
// taking the next one.
func (f *readersFeed) until(t *testing.T, what string, pred func(readersResponse) bool) readersResponse {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case v := <-f.views:
			f.seen = append(f.seen, v)
			if pred(v) {
				return v
			}
		case <-deadline:
			t.Fatalf("%s was not pushed %s; it was pushed %+v", f.what, what, f.seen)
			return readersResponse{}
		}
	}
}

// drain takes whatever views have arrived into seen.
func (f *readersFeed) drain() {
	for {
		select {
		case v := <-f.views:
			f.seen = append(f.seen, v)
		default:
			return
		}
	}
}

// waitReadersIdle waits for the hub to have delivered every readers push it
// owes.
func waitReadersIdle(t *testing.T, srv *Server) {
	t.Helper()
	waitCluster(t, "the readers pushes to be delivered", func() bool {
		srv.readersPush.mu.Lock()
		defer srv.readersPush.mu.Unlock()
		return !srv.readersPush.draining
	})
}

// quiet fails if the stream receives a view within d.
func (f *readersFeed) quiet(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case v := <-f.views:
		t.Fatalf("%s was pushed %+v, and should have been told nothing", f.what, v)
	case <-time.After(d):
	}
}

// openReadersWS dials the dashboard socket of the project at idx in c's list
// and collects the project_readers views it is sent, once the hub has put it
// in that project's room.
func openReadersWS(t *testing.T, srv *Server, base string, c *http.Client, idx int, room, what string) *readersFeed {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	before := srv.roomSize(room)
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(base, "http")+"/api/ws?project_idx="+itoa(idx),
		&websocket.DialOptions{HTTPClient: c})
	if err != nil {
		t.Fatalf("%s: dial: %v", what, err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	feed := &readersFeed{what: what, views: make(chan readersResponse, 16)}
	go func() {
		for {
			_, raw, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var msg wsMessage
			if json.Unmarshal(raw, &msg) != nil || msg.Type != "project_readers" {
				continue
			}
			var v readersResponse
			if json.Unmarshal(msg.Data, &v) == nil {
				feed.views <- v
			}
		}
	}()
	waitCluster(t, what+" to join its project's room", func() bool { return srv.roomSize(room) > before })
	return feed
}

// readerPaths is the paths a list of views names.
func readerPaths(vs []readerView) []string {
	out := []string{}
	for _, v := range vs {
		out = append(out, v.Path)
	}
	return out
}

// othersIn is c's project list without the paths in skip and without
// features: what a manager of the list may add, in the list's order.
func (f *memberFixture) othersIn(t *testing.T, c *http.Client, skip ...string) []string {
	t.Helper()
	_, paths := f.projects(t, c)
	out := []string{}
	for _, p := range paths {
		if !slices.Contains(skip, p) && !projectreaders.InsideControlDir(p) {
			out = append(out, p)
		}
	}
	return out
}

// candidatePaths is the paths a view offers to add.
func candidatePaths(cs []readerCandidate) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.Path)
	}
	return out
}

// TestReadersPush_EachDashboardIsSentItsOwnView: an entry added and removed
// through the REST handlers reaches the dashboards of both projects, each
// rendered for its viewer — the administrator is named the reader and offered
// what is left to add, a viewer who cannot see the reader is told only that
// there is one, and the reader's dashboard learns what it may read — and a
// dashboard of a project the entry does not name is told nothing.
func TestReadersPush_EachDashboardIsSentItsOwnView(t *testing.T) {
	f, reader := newReadersFixture(t)
	third := setupProjectDir(t, "a project no entry names", nil)
	registerOwned(t, third, aliceEmail)
	if code, body := f.call(t, f.alice, http.MethodPost, f.membersURL(t, f.alice),
		map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share the project with bob: %d %v", code, body)
	}

	aliceIdx, bobIdx := f.idx(t, f.alice, f.project), f.idx(t, f.bob, f.project)
	if bobIdx < 0 || f.idx(t, f.bob, reader) >= 0 {
		t.Fatalf("bob's list: the project at %d, the reader at %d — want the project alone", bobIdx, f.idx(t, f.bob, reader))
	}
	alice := openReadersWS(t, f.srv, f.ts.URL, f.alice, aliceIdx, f.project, "alice's dashboard of the project")
	bob := openReadersWS(t, f.srv, f.ts.URL, f.bob, bobIdx, f.project, "bob's dashboard of the project")
	aliceOnReader := openReadersWS(t, f.srv, f.ts.URL, f.alice, f.idx(t, f.alice, reader), reader,
		"alice's dashboard of the reader")
	unrelated := openReadersWS(t, f.srv, f.ts.URL, f.alice, f.idx(t, f.alice, third), third,
		"alice's dashboard of an unrelated project")

	list := f.readersURL(t, f.alice, f.project)
	if code, body := f.call(t, f.alice, http.MethodPut, list, map[string]any{"reader": reader}); code != http.StatusOK {
		t.Fatalf("add the reader: %d %v", code, body)
	}
	// The administrator: the reader named, with its id, and the rest of her
	// projects on offer — never the project itself or what is listed.
	got := alice.until(t, "the reader", func(v readersResponse) bool { return len(v.Readers) > 0 })
	if got.Path != f.project || !slices.Equal(readerPaths(got.Readers), []string{reader}) || !got.CanManage ||
		got.Readers[0].ID == "" || got.Readers[0].AddedBy != aliceEmail {
		t.Errorf("alice was pushed %+v, want the reader named, added by her, and the controls", got)
	}
	want := f.othersIn(t, f.alice, f.project, reader)
	if offer := candidatePaths(got.Candidates); !slices.Contains(want, third) || !slices.Equal(offer, want) {
		t.Errorf("alice is offered %v to add, want every other project she can see: %v", offer, want)
	}
	if got.Readers[0].Idx != f.idx(t, f.alice, reader) {
		t.Errorf("the reader's index in alice's view is %d, want its index in her list", got.Readers[0].Idx)
	}
	// The viewer: counted, never named, nothing to manage.
	seen := bob.until(t, "a reader counted", func(v readersResponse) bool { return v.HiddenReaders == 1 })
	if seen.Path != f.project || len(seen.Readers) != 0 || len(seen.Hidden) != 0 ||
		seen.CanManage || len(seen.Candidates) != 0 {
		t.Errorf("bob was pushed %+v, want one reader counted and nothing named or offered", seen)
	}
	// The reader's own dashboard learns what it may read.
	other := aliceOnReader.until(t, "the project it may read", func(v readersResponse) bool { return len(v.Readable) > 0 })
	if other.Path != reader || !slices.Equal(readerPaths(other.Readable), []string{f.project}) {
		t.Errorf("the reader's dashboard was pushed %+v, want the project it may now read", other)
	}

	// A GET answers what the push said.
	_, body := f.call(t, f.alice, http.MethodGet, list, nil)
	if !slices.Equal(listed(body, "readers"), []string{reader}) || !slices.Equal(listed(body, "candidates"), want) {
		t.Errorf("the GET answers readers %v, candidates %v", listed(body, "readers"), listed(body, "candidates"))
	}

	// Removed: every dashboard of both projects hears it.
	if code, body := f.call(t, f.alice, http.MethodDelete, list+"?reader="+url.QueryEscape(reader), nil); code != http.StatusOK {
		t.Fatalf("remove the reader: %d %v", code, body)
	}
	if got := alice.until(t, "the reader removed", func(v readersResponse) bool { return len(v.Readers) == 0 }); !slices.Contains(candidatePaths(got.Candidates), reader) {
		t.Errorf("after the removal alice was pushed %+v, want the reader on offer again", got)
	}
	bob.until(t, "the reader removed", func(v readersResponse) bool { return v.HiddenReaders == 0 && len(v.Readers) == 0 })
	aliceOnReader.until(t, "nothing readable", func(v readersResponse) bool { return len(v.Readable) == 0 })

	// Nothing bob was ever pushed names the reader he cannot see, and
	// nothing the unrelated project's dashboard was pushed has an entry.
	waitReadersIdle(t, f.srv)
	bob.drain()
	unrelated.drain()
	for _, v := range bob.seen {
		if strings.Contains(mustJSON(t, v), reader) {
			t.Errorf("bob was pushed the reader he cannot see: %s", mustJSON(t, v))
		}
	}
	for _, v := range unrelated.seen {
		if v.Path != third || len(v.Readers) != 0 || len(v.Readable) != 0 || v.HiddenReaders != 0 || v.HiddenReadable != 0 {
			t.Errorf("the unrelated project's dashboard was pushed %+v", v)
		}
	}
}

// TestReadersPush_AReaderIsNamedOnceItCanBeSeen: who may see a project
// changes what a list may name to whom, so sharing the reader with a viewer of
// the project pushes that viewer the reader by name — without anything on the
// list changing.
func TestReadersPush_AReaderIsNamedOnceItCanBeSeen(t *testing.T) {
	f, reader := newReadersFixture(t)
	if code, body := f.call(t, f.alice, http.MethodPost, f.membersURL(t, f.alice),
		map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share the project with bob: %d %v", code, body)
	}
	if code, body := f.call(t, f.alice, http.MethodPut, f.readersURL(t, f.alice, f.project),
		map[string]any{"reader": reader}); code != http.StatusOK {
		t.Fatalf("add the reader: %d %v", code, body)
	}
	bob := openReadersWS(t, f.srv, f.ts.URL, f.bob, f.idx(t, f.bob, f.project), f.project, "bob's dashboard of the project")

	readerMembers := "/api/projects/" + itoa(f.idx(t, f.alice, reader)) + "/members"
	if code, body := f.call(t, f.alice, http.MethodPost, readerMembers,
		map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share the reader with bob: %d %v", code, body)
	}
	got := bob.until(t, "the reader by name", func(v readersResponse) bool { return len(v.Readers) > 0 })
	if !slices.Equal(readerPaths(got.Readers), []string{reader}) || got.HiddenReaders != 0 || got.CanManage {
		t.Errorf("once he can see the reader bob was pushed %+v, want it named and still no controls", got)
	}
	if got.Readers[0].Idx != f.idx(t, f.bob, reader) {
		t.Errorf("the reader's index in bob's view is %d, want its index in his list", got.Readers[0].Idx)
	}
}

// TestReadersPush_RemovingAProjectTellsTheOtherSide: a project leaving the
// hub takes every entry naming it, and the dashboards of the projects on the
// other side of those entries are pushed their lists without it.
func TestReadersPush_RemovingAProjectTellsTheOtherSide(t *testing.T) {
	f, reader := newReadersFixture(t)
	if code, body := f.call(t, f.alice, http.MethodPut, f.readersURL(t, f.alice, f.project),
		map[string]any{"reader": reader}); code != http.StatusOK {
		t.Fatalf("add the reader: %d %v", code, body)
	}
	alice := openReadersWS(t, f.srv, f.ts.URL, f.alice, f.idx(t, f.alice, f.project), f.project,
		"alice's dashboard of the project")
	if code, body := f.call(t, f.alice, http.MethodDelete, "/api/projects/"+itoa(f.idx(t, f.alice, reader)), nil); code != http.StatusOK {
		t.Fatalf("remove the reader from the hub: %d %v", code, body)
	}
	// The last push comes once the project is off the hub, so it no longer
	// offers it to add.
	alice.until(t, "an empty list that no longer offers the removed project", func(v readersResponse) bool {
		return len(v.Readers) == 0 && v.HiddenReaders == 0 && !slices.Contains(candidatePaths(v.Candidates), reader)
	})
	waitReadersIdle(t, f.srv)
	alice.drain()
	if last := alice.seen[len(alice.seen)-1]; slices.Contains(candidatePaths(last.Candidates), reader) {
		t.Errorf("the last push alice was sent still offers the removed project: %+v", last)
	}
}

// TestReadersPush_OnAHubWithoutSignIn: the local operator's dashboards, over
// the WebSocket and over the event stream, are pushed the lists with the
// controls — on such a hub everyone may change them — and a feature's
// dashboard, which has no list, is told nothing.
func TestReadersPush_OnAHubWithoutSignIn(t *testing.T) {
	f := newFeatureFixture(t)
	addFeature(t, f.parent, "checkout", time.Now(), nil)
	// The list: the hub (0), the parent (1), its feature (2).
	entries := f.srv.allProjectEntries()
	if len(entries) != 3 || !entries[2].IsFeature() {
		t.Fatalf("the fixture's projects: %+v", entries)
	}
	hub, parent, feature := entries[0].Path, entries[1].Path, entries[2].Path
	ws := openReadersWS(t, f.srv, f.ts.URL, nil, 0, hub, "the hub project's dashboard")
	onFeature := openReadersWS(t, f.srv, f.ts.URL, nil, 2, feature, "the feature's dashboard")
	sse := openReadersSSE(t, f.srv, f.ts.URL, 1, parent, "the parent's event stream")

	if code, body := f.do(t, http.MethodPut, "/api/projects/0/readers", map[string]any{"reader_idx": 1}); code != http.StatusOK {
		t.Fatalf("list the parent on the hub project: %d %v", code, body)
	}
	got := ws.until(t, "the parent", func(v readersResponse) bool { return len(v.Readers) > 0 })
	if !slices.Equal(readerPaths(got.Readers), []string{parent}) || !got.CanManage || len(got.Candidates) != 0 {
		t.Errorf("the hub project's dashboard was pushed %+v, want the parent named, the controls, nothing "+
			"left to add (the feature never is)", got)
	}
	sse.until(t, "the hub project readable", func(v readersResponse) bool { return slices.Equal(readerPaths(v.Readable), []string{hub}) })
	onFeature.quiet(t, 300*time.Millisecond)
}

// openReadersSSE opens the event stream of the project at idx on a hub
// without sign-in and collects the project_readers views it is sent.
func openReadersSSE(t *testing.T, srv *Server, base string, idx int, room, what string) *readersFeed {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	countSSE := func() int {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		n := 0
		for c := range srv.clients {
			if c.workDir == room {
				n++
			}
		}
		return n
	}
	before := countSSE()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/events?project_idx="+itoa(idx), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d", what, resp.StatusCode)
	}
	feed := &readersFeed{what: what, views: make(chan readersResponse, 16)}
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		event := ""
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: ") && event == "project_readers":
				var v readersResponse
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &v) == nil {
					feed.views <- v
				}
			case line == "":
				event = ""
			}
		}
	}()
	waitCluster(t, what+" to subscribe", func() bool { return countSSE() > before })
	return feed
}

// TestReadersPush_ReachesAnotherMembersDashboards: an entry added through one
// hub process reaches a dashboard held by another, through the cluster bus,
// rendered by the member that holds it.
func TestReadersPush_ReachesAnotherMembersDashboards(t *testing.T) {
	dir, a, b := clusterPair(t)
	other := setupProjectDir(t, "a second project", nil)
	registerOwned(t, other, "")
	watcher := subscribe(t, b.srv, dir, "viewer@example.com")

	req, err := http.NewRequest(http.MethodPut, a.ts.URL+"/api/projects/0/readers", strings.NewReader(`{"reader_idx":1}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add the reader through A: %d", resp.StatusCode)
	}
	var got readersResponse
	for deadline := time.Now().Add(5 * time.Second); len(got.Readers) == 0; {
		if time.Now().After(deadline) {
			t.Fatalf("B's dashboard was not pushed the reader A added; the last push was %+v", got)
		}
		if err := json.Unmarshal(nextMessage(t, watcher, "project_readers").Data, &got); err != nil {
			t.Fatal(err)
		}
	}
	if got.Path != dir || !slices.Equal(readerPaths(got.Readers), []string{other}) {
		t.Errorf("B's dashboard was pushed %+v, want the reader A added", got)
	}

	// A notice naming a project B has no dashboard of is harmless, and one
	// naming nothing is ignored.
	b.srv.onBusInvalidate(hubcluster.Event{Key: invalidateReaders, Payload: json.RawMessage(`{"projects":[]}`)})
	b.srv.onBusInvalidate(hubcluster.Event{Key: invalidateReaders, Payload: json.RawMessage(`{"projects":["/nowhere"]}`)})
}

// TestReadersPush_TheLastPushIsTheLatestList: changes made at once, from
// several requests, still leave every dashboard showing the list as it stands
// after the last of them — a push rendered before a later change can never
// arrive after the later change's own.
func TestReadersPush_TheLastPushIsTheLatestList(t *testing.T) {
	f, first := newReadersFixture(t)
	readers := []string{first}
	for i := 0; i < 3; i++ {
		p := setupProjectDir(t, "reader "+itoa(i), nil)
		registerOwned(t, p, aliceEmail)
		readers = append(readers, p)
	}
	alice := openReadersWS(t, f.srv, f.ts.URL, f.alice, f.idx(t, f.alice, f.project), f.project,
		"alice's dashboard of the project")
	list := f.readersURL(t, f.alice, f.project)

	// Each reader added and removed in turn, every reader at once.
	errs := make(chan string, len(readers))
	for _, r := range readers {
		go func(r string) {
			for i := 0; i < 4; i++ {
				method, path := http.MethodPut, list
				var body io.Reader = strings.NewReader(`{"reader":` + strconvQuote(r) + `}`)
				if i%2 == 1 {
					method, path, body = http.MethodDelete, list+"?reader="+url.QueryEscape(r), http.NoBody
				}
				req, _ := http.NewRequest(method, f.ts.URL+path, body)
				req.Header.Set("Content-Type", "application/json")
				resp, err := f.alice.Do(req)
				if err != nil {
					errs <- err.Error()
					return
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					errs <- method + " " + r + ": " + resp.Status
					return
				}
			}
			errs <- ""
		}(r)
	}
	for range readers {
		if e := <-errs; e != "" {
			t.Fatal(e)
		}
	}
	// The last round ends with each reader removed; one more, added alone,
	// is what the list holds now.
	if code, body := f.call(t, f.alice, http.MethodPut, list, map[string]any{"reader": readers[2]}); code != http.StatusOK {
		t.Fatalf("add the last reader: %d %v", code, body)
	}
	// The newest view the dashboard holds comes to be that list — an
	// earlier one equal to it may have passed on the way — and nothing
	// older arrives after it.
	final := []string{readers[2]}
	newest := func() []string {
		alice.drain()
		if len(alice.seen) == 0 {
			return nil
		}
		return readerPaths(alice.seen[len(alice.seen)-1].Readers)
	}
	waitCluster(t, "the dashboard to hold the list as it stands", func() bool { return slices.Equal(newest(), final) })
	waitReadersIdle(t, f.srv)
	time.Sleep(300 * time.Millisecond)
	if got := newest(); !slices.Equal(got, final) {
		t.Errorf("after every push was delivered alice's dashboard holds %v, want the reader added last alone", got)
	}
}

// strconvQuote quotes s as a JSON string.
func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestReaders_CandidatesAreWhatThePutTakes: a manager is offered every
// project they can see that the PUT would accept — not the project itself,
// not one already listed, not a feature — and somebody who may not change
// the list is offered nothing.
func TestReaders_CandidatesAreWhatThePutTakes(t *testing.T) {
	f, reader := newReadersFixture(t)
	third := setupProjectDir(t, "a third project", nil)
	registerOwned(t, third, aliceEmail)
	featureDir := addFeature(t, f.project, "checkout", time.Now(), nil)
	if code, body := f.call(t, f.alice, http.MethodPost, f.membersURL(t, f.alice),
		map[string]any{"identity": bobEmail, "role": "maintainer"}); code != http.StatusCreated {
		t.Fatalf("share the project with bob: %d %v", code, body)
	}
	list := f.readersURL(t, f.alice, f.project)
	if code, body := f.call(t, f.alice, http.MethodPut, list, map[string]any{"reader": reader}); code != http.StatusOK {
		t.Fatalf("add the reader: %d %v", code, body)
	}
	_, body := f.call(t, f.alice, http.MethodGet, list, nil)
	offer := listed(body, "candidates")
	want := f.othersIn(t, f.alice, f.project, reader)
	if !slices.Contains(want, third) || slices.Contains(want, featureDir) || !slices.Equal(offer, want) {
		t.Fatalf("alice is offered %v, want every other project she can see and no feature: %v", offer, want)
	}
	// Each one is a project the PUT takes.
	for _, p := range offer {
		if code, body := f.call(t, f.alice, http.MethodPut, list, map[string]any{"reader": p}); code != http.StatusOK || body["added"] != true {
			t.Errorf("adding the offered %s: %d %v", p, code, body)
		}
	}
	_, body = f.call(t, f.alice, http.MethodGet, list, nil)
	if offer := listed(body, "candidates"); len(offer) != 0 {
		t.Errorf("with everything listed alice is still offered %v", offer)
	}
	// A maintainer may not change the list, so is offered nothing.
	_, body = f.call(t, f.bob, http.MethodGet, f.readersURL(t, f.bob, f.project), nil)
	if _, has := body["candidates"]; has || body["can_manage"] != false {
		t.Errorf("a maintainer's GET: %v, want no candidates and no controls", body)
	}
	// Nor is anybody on a feature, which has no list.
	_, body = f.call(t, f.alice, http.MethodGet, f.readersURL(t, f.alice, featureDir), nil)
	if _, has := body["candidates"]; has || body["feature"] != true {
		t.Errorf("a feature's GET: %v, want the feature's note and nothing to add", body)
	}
}

// TestReadersPush_SurvivesARecipientWithNoAuthority: a stream whose
// credential no longer resolves is skipped, not a reason to stop the round —
// the next dashboard is still pushed its lists.
func TestReadersPush_SurvivesARecipientWithNoAuthority(t *testing.T) {
	f, reader := newReadersFixture(t)
	// A session nobody holds any more, in the project's room.
	ghost := &hubClient{ch: make(chan wsMessage, hubClientBufferSize), resync: make(chan struct{}, 1),
		kick: make(chan streamEnd, 1), id: "ghost", cred: streamCredential{sessionHash: "no-such-session"}}
	f.srv.hubMu.Lock()
	if f.srv.hubClients[f.project] == nil {
		f.srv.hubClients[f.project] = map[*hubClient]struct{}{}
	}
	f.srv.hubClients[f.project][ghost] = struct{}{}
	f.srv.hubMu.Unlock()
	alice := openReadersWS(t, f.srv, f.ts.URL, f.alice, f.idx(t, f.alice, f.project), f.project,
		"alice's dashboard of the project")
	if code, body := f.call(t, f.alice, http.MethodPut, f.readersURL(t, f.alice, f.project),
		map[string]any{"reader": reader}); code != http.StatusOK {
		t.Fatalf("add the reader: %d %v", code, body)
	}
	alice.until(t, "the reader", func(v readersResponse) bool { return slices.Equal(readerPaths(v.Readers), []string{reader}) })
	// The round that pushed alice's dashboard passed the ghost too.
	waitReadersIdle(t, f.srv)
	for drained := false; !drained; {
		select {
		case msg := <-ghost.ch:
			if msg.Type == "project_readers" {
				t.Fatalf("a stream whose session has ended was pushed %s", msg.Data)
			}
		default:
			drained = true
		}
	}
}
