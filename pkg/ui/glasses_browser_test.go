package ui

// Browser gate for the display-glasses cursor (Task 20279).
//
// The shim suite in glasses_frontend_test.go drives this page by pressing keys,
// because that is what the page was built to receive. Telemetry from a real
// Ray-Ban Display session says that is the wrong model of the device, and no
// amount of pressing keys can show it: the shim delivers whatever the test asks
// for, so a page that only responds to keys passes every scenario in that file
// while doing nothing on the hardware.
//
// The trail is short and it is decisive. One session, five events. A pinch
// arrived as Enter/13 and was handled. A sideways swipe produced no key at all
// — not ArrowLeft, not the legacy Left, not an unrecognised keyCode, and the
// handler records `unmapped: <key>` for every one of those. Alongside it the
// wearer reported twice that sideways gestures moved a scrollbar and that up
// and down scrolled the page, which is touch panning in both directions.
//
// So the assertions below send no key where the device sends none. They swipe,
// with real touch events, in a real browser, against the shipped page. Chromium
// is also the only thing here with layout, a compositor, touch-action and the
// click it synthesises after a touch — and every one of those is load-bearing
// for the fix.
//
// Skips when no browser is installed, which is the normal case in CI: a gate on
// a developer box and on any runner that has Chrome, never a source of red
// builds on one that does not.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// glassesCursor is one sample of what is on screen, as testdata/glasses_browser.js
// reports it. Read from the DOM rather than from the page's own variables: the
// script is an IIFE, and `.sel` is both what the driver can see and what the
// wearer can.
type glassesCursor struct {
	Ring         int    `json:"ring"`
	At           int    `json:"at"`
	Label        string `json:"label"`
	ID           string `json:"id"`
	ActiveTag    string `json:"activeTag"`
	ActiveIsRing bool   `json:"activeIsRing"`
	ScrollY      int    `json:"scrollY"`
	Title        string `json:"title"`
}

type glassesBrowserResults struct {
	Error string `json:"error"`

	Keyboard struct {
		Before glassesCursor `json:"before"`
		Right  glassesCursor `json:"right"`
		Left   glassesCursor `json:"left"`
	} `json:"keyboard"`

	Sideways struct {
		Start glassesCursor `json:"start"`
		Next  glassesCursor `json:"next"`
		Next2 glassesCursor `json:"next2"`
		Prev  glassesCursor `json:"prev"`
	} `json:"sideways"`

	Vertical struct {
		Before glassesCursor `json:"before"`
		After  glassesCursor `json:"after"`
	} `json:"vertical"`

	Navigation struct {
		Before           glassesCursor   `json:"before"`
		Settled          glassesCursor   `json:"settled"`
		Samples          []glassesCursor `json:"samples"`
		Worst            glassesCursor   `json:"worst"`
		UnfocusedSamples int             `json:"unfocusedSamples"`
	} `json:"navigation"`

	MidFlight struct {
		During glassesCursor `json:"during"`
		After  glassesCursor `json:"after"`
	} `json:"midFlight"`
}

// telemetryBatch mirrors what the page POSTs to /api/glasses/telemetry.
type telemetryBatch struct {
	Source  string `json:"source"`
	Session string `json:"session"`
	Events  []struct {
		Kind    string `json:"kind"`
		Seq     int    `json:"seq"`
		Message string `json:"message"`
		View    string `json:"view"`
		Detail  string `json:"detail"`
	} `json:"events"`
}

// glassesBrowserRun is the whole browser session: one Chrome launch, one page
// load, every scenario. Shared because launching a browser costs seconds and
// each test below asks about a different part of the same run.
type glassesBrowserRun struct {
	res   glassesBrowserResults
	tel   []telemetryBatch
	skip  string
	fatal string
}

var glassesBrowserOnce sync.Once
var glassesBrowserCached glassesBrowserRun

func glassesBrowser(t *testing.T) glassesBrowserRun {
	t.Helper()
	glassesBrowserOnce.Do(func() { glassesBrowserCached = runGlassesBrowser() })
	r := glassesBrowserCached
	if r.skip != "" {
		t.Skip(r.skip)
	}
	if r.fatal != "" {
		t.Fatal(r.fatal)
	}
	return r
}

func runGlassesBrowser() glassesBrowserRun {
	chrome := findChrome()
	if chrome == "" {
		return glassesBrowserRun{skip: "no Chrome/Chromium installed; cannot drive real touch input"}
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return glassesBrowserRun{skip: "node not installed; cannot drive the browser"}
	}

	var mu sync.Mutex
	var batches []telemetryBatch

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	// Enough projects and tasks that the list overflows the emulated display.
	// A page that fits on screen cannot exercise the interaction between the
	// reading axis and the selection axis, which is half the report.
	projects := make([]map[string]any, 0, 12)
	for i := 0; i < 12; i++ {
		projects = append(projects, map[string]any{
			"idx": i, "name": "project-" + string(rune('a'+i)), "goal": "a goal",
			"running": false, "status": "idle", "done": i, "total": 12, "failed": 0,
		})
	}
	tasks := make([]map[string]any, 0, 12)
	for i := 0; i < 12; i++ {
		tasks = append(tasks, map[string]any{
			"id": i + 1, "title": "task number " + string(rune('a'+i)),
			"status": "pending", "priority": 1,
		})
	}

	// Not t.TempDir(): this run outlives any one test, so it owns its scratch
	// directory and removes it when the browser is done.
	work, err := os.MkdirTemp("", "cloop-glasses-browser-*")
	if err != nil {
		return glassesBrowserRun{fatal: "temp dir: " + err.Error()}
	}
	defer func() { _ = os.RemoveAll(work) }()

	s := New(work, 0, "")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/glasses/projects", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"dictation": map[string]any{"available": false, "can_add_tasks": false},
			"projects":  projects,
		})
	})
	mux.HandleFunc("/api/glasses/tasks", func(w http.ResponseWriter, r *http.Request) {
		// The delay is the point of this stub. The defect the trail shows lives
		// entirely inside the window between the view switching and the list
		// landing — 466 ms on the device — and a stub that answers instantly
		// closes the window before anything can be observed in it.
		time.Sleep(250 * time.Millisecond)
		writeJSON(w, map[string]any{
			"dictation": map[string]any{"available": false, "can_add_tasks": false},
			"tasks":     tasks, "total": len(tasks), "quick": []map[string]any{}, "status": "idle",
		})
	})
	mux.HandleFunc("/api/glasses/telemetry", func(w http.ResponseWriter, r *http.Request) {
		var b telemetryBatch
		if err := json.NewDecoder(r.Body).Decode(&b); err == nil {
			mu.Lock()
			batches = append(batches, b)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/", s.Handler())

	srv := httptest.NewServer(mux)
	defer srv.Close()

	abs, err := filepath.Abs("testdata/glasses_browser.js")
	if err != nil {
		return glassesBrowserRun{fatal: "resolving the driver: " + err.Error()}
	}
	cmd := exec.Command(node, abs, chrome, srv.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		return glassesBrowserRun{fatal: "driving the browser failed: " + err.Error() +
			"\nstdout:\n" + string(out) + "\nstderr:\n" + stderr}
	}

	var res glassesBrowserResults
	if err := json.Unmarshal(out, &res); err != nil {
		return glassesBrowserRun{fatal: "decoding driver output: " + err.Error() + "\nraw:\n" + string(out)}
	}
	if res.Error != "" {
		return glassesBrowserRun{fatal: "driver reported: " + res.Error}
	}

	mu.Lock()
	defer mu.Unlock()
	return glassesBrowserRun{res: res, tel: append([]telemetryBatch(nil), batches...)}
}

// TestGlassesSidewaysTouchWalksTheRing is the task in one assertion.
//
// No key is pressed. A finger travels sideways across the display, which is
// what the device does and what the page had no handler for, and the cursor has
// to move one stop — then another, and then back the way it came. "Selects the
// first element once and then never moves again" is precisely the failure where
// the second and third of those do not hold.
func TestGlassesSidewaysTouchWalksTheRingInBrowser(t *testing.T) {
	r := glassesBrowser(t)
	s := r.res.Sideways

	if s.Start.Ring < 4 {
		t.Fatalf("the ring is too short to walk: %+v", s.Start)
	}
	if s.Next.At == s.Start.At {
		t.Errorf("a sideways swipe did not move the cursor: stayed at %d (%q) on a ring of %d\n"+
			"this is the reported symptom: the device sends no arrow key, so a page that only "+
			"listens for keydown never sees the gesture", s.Start.At, s.Start.Label, s.Start.Ring)
	}
	if s.Next2.At == s.Next.At {
		t.Errorf("the second swipe did not move the cursor: stuck at %d (%q)\n"+
			"one swipe working and the next doing nothing is the exact shape of the report",
			s.Next.At, s.Next.Label)
	}
	// And back. The wearer's words were that they could not reach the previous
	// element, so the reverse direction is its own assertion.
	if s.Prev.At != s.Next.At {
		t.Errorf("swiping back did not return to the previous stop: went %d → %d, wanted %d",
			s.Next2.At, s.Prev.At, s.Next.At)
	}
}

// TestGlassesKeyboardStillWalksTheRing pins the channel that already worked.
//
// The pinch arrives as Enter and the shim suite covers arrows, so a touch
// recogniser that traded one channel for the other would leave both the tests
// and the hardware in a worse place than before.
func TestGlassesKeyboardStillWalksTheRing(t *testing.T) {
	r := glassesBrowser(t)
	k := r.res.Keyboard
	if k.Right.At == k.Before.At {
		t.Errorf("ArrowRight stopped moving the cursor: %d → %d", k.Before.At, k.Right.At)
	}
	if k.Left.At != k.Before.At {
		t.Errorf("ArrowLeft did not undo ArrowRight: %d → %d → %d, wanted to return to %d",
			k.Before.At, k.Right.At, k.Left.At, k.Before.At)
	}
}

// TestGlassesVerticalTouchStillScrolls holds the line the wearer drew.
//
// Their report opened by saying that swiping up and down moved the scrollbar
// and that this was good. Claiming the vertical axis for the cursor would
// "fix" the sideways gesture by breaking the one thing about this page that
// was working.
func TestGlassesVerticalTouchStillScrolls(t *testing.T) {
	r := glassesBrowser(t)
	v := r.res.Vertical
	if v.After.ScrollY <= v.Before.ScrollY {
		t.Errorf("a vertical swipe no longer scrolls: scrollY %d → %d\n"+
			"the wearer asked to keep this axis for reading", v.Before.ScrollY, v.After.ScrollY)
	}
}

// TestGlassesNavigationNeverDropsTheCursor is the defect the trail states
// outright: `go → -1` on a ring of six.
//
// Sampled across the whole in-flight window rather than once at the end,
// because the claim is that the cursor is never lost — not that it happens to
// be back by the time anyone looks.
func TestGlassesNavigationNeverDropsTheCursor(t *testing.T) {
	r := glassesBrowser(t)
	n := r.res.Navigation

	if len(n.Samples) == 0 {
		t.Fatal("no samples taken across the navigation window")
	}
	if n.Worst.At < 0 {
		t.Errorf("the cursor was lost during navigation: at=%d on a ring of %d (title %q)\n"+
			"this is the trail's `go → -1` on a ring of 6 — a screen with reachable "+
			"controls and no selection, for the whole of the fetch",
			n.Worst.At, n.Worst.Ring, n.Worst.Title)
	}
	if n.Settled.At < 0 {
		t.Errorf("the cursor was still lost after the list landed: %+v", n.Settled)
	}
	// The other half, and the reason this matters beyond a missing highlight:
	// the device aims its key events at document.activeElement. A page with
	// nothing focused is a page with nowhere to deliver them.
	if n.UnfocusedSamples > 0 {
		t.Errorf("%d of %d samples had focus outside the ring (worst: activeTag=%q)\n"+
			"on this device that is not cosmetic — an unfocused document is one the "+
			"gesture cannot be delivered to",
			n.UnfocusedSamples, len(n.Samples), n.Worst.ActiveTag)
	}
}

// TestGlassesSwipeDuringNavigationIsHeard covers the gesture made into the
// waiting window — the one a wearer on a slow tether makes constantly, and the
// point at which the real trail goes silent and never resumes.
func TestGlassesSwipeDuringNavigationIsHeard(t *testing.T) {
	r := glassesBrowser(t)
	m := r.res.MidFlight
	if m.During.At < 0 {
		t.Fatalf("precondition: the cursor was already lost before the swipe: %+v", m.During)
	}
	if m.After.At == m.During.At {
		t.Errorf("a swipe made while the view was still loading did nothing: stayed at %d of %d",
			m.During.At, m.During.Ring)
	}
}

// TestGlassesTelemetryNamesTheInputChannel is the metrics half of the task.
//
// The investigation that produced this fix was nearly blocked by the trail
// being unable to say *how* a gesture arrived — the five recorded events could
// report a key that came, but had no vocabulary for a touch that came instead.
// Now every gesture carries the channel it came in on, so the next report is a
// query rather than another round of inference.
func TestGlassesTelemetryNamesTheInputChannel(t *testing.T) {
	r := glassesBrowser(t)
	if len(r.tel) == 0 {
		t.Fatal("the page sent no telemetry at all")
	}

	var touchGestures, withActive int
	for _, b := range r.tel {
		if b.Source != "glasses" {
			t.Errorf("batch posted with source %q, want \"glasses\"", b.Source)
		}
		for _, ev := range b.Events {
			if ev.Kind != "gesture" {
				continue
			}
			if strings.Contains(ev.Detail, `"ch":"touch"`) {
				touchGestures++
			}
			if strings.Contains(ev.Detail, `"ae":`) {
				withActive++
			}
		}
	}
	if touchGestures == 0 {
		t.Errorf("no gesture on the trail names touch as its channel\n"+
			"the first real session could not distinguish \"no key arrived\" from "+
			"\"a touch arrived and was ignored\", which is what made this take four attempts\n"+
			"batches: %d", len(r.tel))
	}
	if withActive == 0 {
		t.Error("no gesture records document.activeElement; " +
			"\"the page has nothing focused to receive the next gesture\" stays invisible without it")
	}
}
