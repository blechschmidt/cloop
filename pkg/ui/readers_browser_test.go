package ui

// The Readers section in a real browser (Task 20503). readers_api_test.go and
// readers_push_test.go prove the hub's half; this proves the page's, on a hub
// with single sign-on:
//
//   - the section's script is not on first paint and arrives with the
//     Overview;
//   - the project's administrator adds a reader by picking it from the
//     projects she can see, is asked to confirm it is her because her sign-in
//     is old, and the add goes through once she has; she removes a reader she
//     can see by name and one she cannot by its entry;
//   - a viewer sees the lists and no control: the readers he cannot see are
//     counted, the projects this one may read are named, and changes made
//     elsewhere — an entry added, a reader shared with him — reach his open
//     page as pushes, with no request of its own;
//   - both views fit a phone, a tablet and a desktop: nothing wider than the
//     screen, nothing overflowing its box, every control pressable.
//
// Skips without Chrome or node, like the other browser gates here.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/projectreaders"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// readersBrowserRow is one row of a list as the page draws it.
type readersBrowserRow struct {
	Name   string `json:"name"`
	Meta   string `json:"meta"`
	Remove bool   `json:"remove"`
}

// readersBrowserView is the section as the page draws it.
type readersBrowserView struct {
	Shown         bool                `json:"shown"`
	Count         string              `json:"count"`
	Rows          []readersBrowserRow `json:"rows"`
	Notes         []string            `json:"notes"`
	Form          bool                `json:"form"`
	Options       []string            `json:"options"`
	Labels        []string            `json:"labels"`
	Note          string              `json:"note"`
	Readable      []readersBrowserRow `json:"readable"`
	ReadableNotes []string            `json:"readable_notes"`
}

func (v readersBrowserView) names() []string {
	out := []string{}
	for _, r := range v.Rows {
		out = append(out, r.Name)
	}
	return out
}

func (v readersBrowserView) removable() int {
	n := 0
	for _, r := range v.Rows {
		if r.Remove {
			n++
		}
	}
	return n
}

// readersBrowserLayout is what one screen width found wrong with the section.
type readersBrowserLayout struct {
	Width    int      `json:"width"`
	Problems []string `json:"problems"`
}

type readersBrowserResult struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	MetaNamesScript      bool                   `json:"meta_names_script"`
	LoadedBeforeOverview bool                   `json:"loaded_before_overview"`
	LoadedAfterOverview  int                    `json:"loaded_after_overview"`
	AliceInitial         readersBrowserView     `json:"alice_initial"`
	ReauthAsked          bool                   `json:"reauth_asked"`
	AfterAdd             readersBrowserView     `json:"after_add"`
	AddToast             string                 `json:"add_toast"`
	ServerAfterAdd       []string               `json:"server_after_add"`
	AfterRemove          readersBrowserView     `json:"after_remove"`
	AfterHiddenRemove    readersBrowserView     `json:"after_hidden_remove"`
	ConfirmTexts         []string               `json:"confirm_texts"`
	ServerAfterRemovals  []string               `json:"server_after_removals"`
	AliceLayout          []readersBrowserLayout `json:"alice_layout"`
	BobView              readersBrowserView     `json:"bob_view"`
	BobAfterHiddenAdd    readersBrowserView     `json:"bob_after_hidden_add"`
	BobAfterShare        readersBrowserView     `json:"bob_after_share"`
	BobPushes            int                    `json:"bob_pushes"`
	BobReadersFetches    int                    `json:"bob_readers_fetches"`
	BobLayout            []readersBrowserLayout `json:"bob_layout"`
	ErrorToasts          []string               `json:"error_toasts"`
}

func TestReadersSection_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv("HOME", t.TempDir())
	f := newMemberFixture(t, true)

	// Long, unbroken names: what real directory names are made of, and what
	// refuses to wrap.
	project := func(name, owner string) string {
		dir := namedProjectDir(t, name, "the goal of "+name)
		registerOwned(t, dir, owner)
		return dir
	}
	reader := project("payments_ledger_reconciliation_service_for_the_internal_platform_2026", aliceEmail)
	shared := project("shared_reporting_warehouse_exports_for_finance_and_operations", aliceEmail)
	library := project("common_protocol_buffers_and_generated_clients_for_every_service", aliceEmail)
	carols := project("carols_private_experiments_nobody_else_may_know_about", carolEmail)

	send := func(c *http.Client, method, path string, body any) (int, string) {
		var rdr io.Reader = http.NoBody
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, f.ts.URL+path, rdr)
		if err != nil {
			return 0, err.Error()
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	membersOf := func(c *http.Client, path string) string {
		return "/api/projects/" + itoa(f.idx(t, c, path)) + "/members"
	}
	for _, p := range []string{f.project, shared, library} {
		if code, body := send(f.alice, http.MethodPost, membersOf(f.alice, p),
			map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
			t.Fatalf("share %s with bob: %d %s", p, code, body)
		}
	}
	put := func(c *http.Client, project, reader string) {
		t.Helper()
		if code, body := send(c, http.MethodPut, f.readersURL(t, c, project),
			map[string]any{"reader": reader}); code != http.StatusOK {
			t.Fatalf("list %s on %s: %d %s", reader, project, code, body)
		}
	}
	put(f.alice, f.project, shared)  // named to alice and to bob
	put(f.root, f.project, carols)   // counted for both: only carol and the hub's admins see it
	put(f.alice, library, f.project) // the project may read the library

	// Alice's browser session signed in three hours ago, so her changes ask
	// for a recent sign-in. The provider answers as her from here on: the
	// confirmation's sign-in is hers, and the claims are not flipped again
	// while Chrome runs.
	f.idp.email, f.idp.sub, f.idp.name, f.idp.groups = aliceEmail, "sub-alice", "alice", nil
	f.idp.setSignedInAt(time.Now().Add(-3 * time.Hour))
	staleAlice := jarClient(t)
	login(t, staleAlice, f.ts)
	f.idp.setSignedInAt(time.Time{})

	// The driver's levers: what the hub holds, and the changes others make
	// while bob watches. Each answers rather than failing the test from a
	// handler goroutine.
	control := http.NewServeMux()
	control.HandleFunc("GET /readers", func(w http.ResponseWriter, r *http.Request) {
		db, err := statedb.Open(state.DBPath(f.srv.WorkDir))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer db.Close()
		res, err := projectreaders.Load(db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := []string{}
		for _, e := range res.ReadersOf(f.project) {
			out = append(out, e.ReaderPath)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	control.HandleFunc("POST /hide", func(w http.ResponseWriter, r *http.Request) {
		// The hub's administrator lists carol's project again.
		code, body := send(f.root, http.MethodPut, "/api/projects/"+itoa(f.idx(t, f.root, f.project))+"/readers",
			map[string]any{"reader": carols})
		if code != http.StatusOK {
			http.Error(w, body, http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	control.HandleFunc("POST /share", func(w http.ResponseWriter, r *http.Request) {
		// Alice shares the reader with bob: nothing on the list changes,
		// but now he may be told its name.
		code, body := send(f.alice, http.MethodPost, membersOf(f.alice, reader),
			map[string]any{"identity": bobEmail, "role": "viewer"})
		if code != http.StatusCreated {
			http.Error(w, body, http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	ctl := httptest.NewServer(control)
	defer ctl.Close()

	cfg, _ := json.Marshal(map[string]any{
		"project": f.project, "reader": reader, "shared": shared, "library": library,
		"names": map[string]string{"reader": filepath.Base(reader), "shared": filepath.Base(shared),
			"library": filepath.Base(library), "carols": filepath.Base(carols)},
		"cookies": map[string]string{"alice": sessionCookie(t, staleAlice, f.ts.URL), "bob": sessionCookie(t, f.bob, f.ts.URL)},
	})
	cmd := exec.Command(node, mustAbs(t, "testdata/readers_browser.js"), chrome, f.ts.URL, ctl.URL)
	cmd.Env = append(os.Environ(), "READERS_CONFIG="+string(cfg))
	out, err := cmd.Output()
	if os.Getenv("READERS_BROWSER_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var got readersBrowserResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("driver: %s\npartial results:\n%s", got.Error.Message, out)
	}
	name := func(p string) string { return filepath.Base(p) }

	// The script arrives with the Overview, not before.
	if !got.MetaNamesScript || got.LoadedBeforeOverview || got.LoadedAfterOverview != 1 {
		t.Errorf("the section's script: named in the page %v, loaded before the Overview %v, loaded %d time(s) after it",
			got.MetaNamesScript, got.LoadedBeforeOverview, got.LoadedAfterOverview)
	}

	// ── the administrator ──
	a := got.AliceInitial
	if !a.Shown || !slices.Equal(a.names(), []string{name(shared), "A project you can’t see"}) || a.removable() != 2 {
		t.Errorf("alice's first view lists %v (%d removable), want the shared reader and the one she cannot see, "+
			"both removable", a.names(), a.removable())
	}
	if a.Count != "2 projects" || !a.Form || a.Note != "" {
		t.Errorf("alice's first view: count %q, form %v, note %q — want two readers counted and the picker", a.Count, a.Form, a.Note)
	}
	// The picker offers the projects she can see that the hub would take:
	// never the project itself, a listed reader, or carol's.
	if !slices.Contains(a.Options, reader) || !slices.Contains(a.Options, library) ||
		slices.Contains(a.Options, f.project) || slices.Contains(a.Options, shared) || slices.Contains(a.Options, carols) {
		t.Errorf("alice is offered %v", a.Options)
	}
	if !slices.Contains(a.Labels, name(reader)) {
		t.Errorf("the picker's labels %v do not name the reader", a.Labels)
	}
	if len(a.Readable) != 1 || a.Readable[0].Name != name(library) || a.Readable[0].Remove {
		t.Errorf("alice's view of what the project may read: %+v, want the library, with no control", a.Readable)
	}
	if !got.ReauthAsked {
		t.Error("an add from a sign-in three hours old did not ask her to confirm it is her")
	}
	if !slices.Contains(got.AfterAdd.names(), name(reader)) || !strings.Contains(got.AddToast, "may now read this project") {
		t.Errorf("after the add the page lists %v and toasted %q", got.AfterAdd.names(), got.AddToast)
	}
	if !slices.Contains(got.ServerAfterAdd, reader) {
		t.Errorf("after the add the hub's list is %v", got.ServerAfterAdd)
	}
	if slices.Contains(got.AfterAdd.Options, reader) {
		t.Errorf("a listed reader is still offered: %v", got.AfterAdd.Options)
	}
	if slices.Contains(got.AfterRemove.names(), name(shared)) {
		t.Errorf("after removing the shared reader the page lists %v", got.AfterRemove.names())
	}
	if slices.Contains(got.AfterHiddenRemove.names(), "A project you can’t see") ||
		!slices.Equal(got.AfterHiddenRemove.names(), []string{name(reader)}) {
		t.Errorf("after removing the one she cannot see the page lists %v", got.AfterHiddenRemove.names())
	}
	if len(got.ConfirmTexts) != 2 || !strings.Contains(got.ConfirmTexts[0], name(shared)) ||
		!strings.Contains(got.ConfirmTexts[1], "a project you can’t see") {
		t.Errorf("each removal asked first, naming what goes: %q", got.ConfirmTexts)
	}
	if !slices.Equal(got.ServerAfterRemovals, []string{reader}) {
		t.Errorf("after the removals the hub's list is %v, want the reader alone", got.ServerAfterRemovals)
	}

	// ── the viewer ──
	b := got.BobView
	if !b.Shown || len(b.Rows) != 0 || !slices.Equal(b.Notes, []string{"1 more project you can’t see"}) {
		t.Errorf("bob's view lists %+v with notes %q, want the reader counted and not named", b.Rows, b.Notes)
	}
	if b.Form || b.removable() != 0 || !strings.Contains(b.Note, "Only this project’s administrators") {
		t.Errorf("bob's view: form %v, %d removable, note %q — want no control and the reason why", b.Form, b.removable(), b.Note)
	}
	if len(b.Readable) != 1 || b.Readable[0].Name != name(library) {
		t.Errorf("bob's view of what the project may read: %+v, want the library", b.Readable)
	}
	if !slices.Equal(got.BobAfterHiddenAdd.Notes, []string{"2 more projects you can’t see"}) {
		t.Errorf("after carol's project was listed bob's page counts %q", got.BobAfterHiddenAdd.Notes)
	}
	if !slices.Equal(got.BobAfterShare.names(), []string{name(reader)}) ||
		!slices.Equal(got.BobAfterShare.Notes, []string{"1 more project you can’t see"}) || got.BobAfterShare.removable() != 0 {
		t.Errorf("once the reader was shared with him bob's page lists %v, notes %q", got.BobAfterShare.names(), got.BobAfterShare.Notes)
	}
	if got.BobPushes < 2 || got.BobReadersFetches != 0 {
		t.Errorf("bob's page took %d pushes and made %d requests of its own for the two changes; want them pushed",
			got.BobPushes, got.BobReadersFetches)
	}

	// ── both views at a phone, a tablet and a desktop ──
	for who, layouts := range map[string][]readersBrowserLayout{"alice": got.AliceLayout, "bob": got.BobLayout} {
		if len(layouts) != 3 {
			t.Errorf("%s's view was measured at %d widths, want 3", who, len(layouts))
		}
		for _, l := range layouts {
			for _, p := range l.Problems {
				t.Errorf("%s's view at %dpx: %s", who, l.Width, p)
			}
		}
	}
	if len(got.ErrorToasts) != 0 {
		t.Errorf("the page reported errors: %q", got.ErrorToasts)
	}
}
