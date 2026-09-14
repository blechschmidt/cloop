package ui

// Browser gate for push-to-talk on the Dictate button (Task 20252).
//
// Every other frontend gate in this package runs the bundle under
// testdata/domshim.js, which is enough when the question is "what did the page
// ask the hub for". This one cannot use it. Push-to-talk is defined by browser
// behaviour the shim does not have:
//
//   - the `click` a browser synthesises after touchend, which the button's
//     onclick would read as a second press and use to restart the recording it
//     just ended;
//   - pointer capture, so a fingertip that drifts off the button still ends the
//     hold there rather than leaving the microphone live;
//   - touch-action, which decides whether a hold stays a hold or is taken away
//     as a scroll partway through a sentence;
//   - getUserMedia and MediaRecorder, which the empty-clip guard measures real
//     samples from.
//
// So this drives real Chromium over CDP with a fake microphone. It skips when
// no browser is installed, which is the normal case in CI — the assertions are
// a gate on a developer box and on any runner that has Chrome, never a source
// of red builds on one that does not. See testdata/ptt_browser.js.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// chromeCandidates are the install locations this project's boxes actually use,
// in preference order, plus whatever is on PATH.
var chromeCandidates = []string{
	"/opt/cft/chrome-linux64/chrome",
	"/root/.cache/puppeteer/chrome/linux-*/chrome-linux64/chrome",
	"/root/.cache/ms-playwright/chromium-*/chrome-linux64/chrome",
	"/root/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
}

func findChrome() string {
	for _, pat := range chromeCandidates {
		if !strings.Contains(pat, "*") {
			if st, err := os.Stat(pat); err == nil && !st.IsDir() {
				return pat
			}
			continue
		}
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && !st.IsDir() {
				return m
			}
		}
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// pttResult mirrors the JSON testdata/ptt_browser.js prints.
type pttResult struct {
	IdleLabel string `json:"idle_label"`

	Title          string `json:"title"`
	RecordingAfter bool   `json:"recording_after"`
	DisabledAfter  bool   `json:"disabled_after"`
	LabelAfter     string `json:"label_after"`
	Transcribes    int    `json:"transcribe_requests"`

	RecordingDuring bool   `json:"recording_during"`
	DisabledDuring  bool   `json:"disabled_during"`
	LabelDuring     string `json:"label_during"`
	TouchAction     string `json:"touch_action"`

	RecordingAfterFirst  bool `json:"recording_after_first_click"`
	RecordingAfterSecond bool `json:"recording_after_second_click"`

	LiveTracks int `json:"live_tracks"`

	Toast string `json:"toast"`
	View  string `json:"view"`
}

const pttTranscript = "add retry budgets to the executor"

// TestDictate_PushToTalkInBrowser is the whole gate; the subtests below read
// from the single browser run it performs, because launching Chrome and
// booting the dashboard costs seconds and every scenario shares that setup.
func TestDictate_PushToTalkInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot drive real touch input")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// The real dashboard — real index.html, real bundle, real app.css — with
	// only the two speech endpoints replaced. Replacing them is what makes the
	// test hermetic: /api/dictate otherwise reports the feature unavailable
	// without a Groq key, and /api/transcribe would call out to Groq.
	var transcribeCalls atomic.Int64
	s := New(t.TempDir(), 0, "")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/dictate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"available": true, "can_add_tasks": true, "backend": "groq",
		})
	})
	transcribe := func(w http.ResponseWriter, r *http.Request) {
		transcribeCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"text": pttTranscript})
	}
	mux.HandleFunc("/api/transcribe", transcribe)
	// The glasses link posts its audio to its own gated route.
	mux.HandleFunc("/api/glasses/transcribe", transcribe)
	// Enough of the wearable's two read endpoints to reach the Add screen,
	// where its dictate button lives. Stubbed rather than seeded through a real
	// project because the page's script is wrapped in an IIFE — nothing in it
	// can be reached from the driver, so the only way in is the UI itself.
	// dictation.available is the flag that reveals the button at all.
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/api/glasses/projects", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"dictation": map[string]any{"available": true, "can_add_tasks": true},
			"projects": []map[string]any{
				{"idx": 0, "name": "alpha", "goal": "a goal", "running": false, "done": 0, "total": 1, "failed": 0},
			},
		})
	})
	mux.HandleFunc("/api/glasses/tasks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"dictation": map[string]any{"available": true, "can_add_tasks": true},
			"tasks":     []map[string]any{{"id": 1, "title": "first", "status": "pending", "priority": 1}},
			"total":     1,
			"quick":     []map[string]any{},
			"status":    "idle",
		})
	})
	mux.Handle("/", s.Handler())

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cmd := exec.Command(node, mustAbs(t, "testdata/ptt_browser.js"), chrome, srv.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	if os.Getenv("PTT_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}
	var got map[string]pttResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if e, ok := got["error"]; ok || e.Title != "" {
		t.Fatalf("the driver reported an error:\n%s", out)
	}
	// A scenario the driver never reached leaves a zero value that would pass
	// several of the assertions below by accident.
	for _, name := range []string{
		"labels_say_hold_on_touch", "hold_transcribes_then_stops",
		"short_tap_sends_nothing", "mid_hold_shows_listening",
		"mouse_click_still_toggles", "consecutive_holds_both_work",
		"glasses_hold_transcribes", "glasses_tap_sends_nothing",
		"slow_microphone_recovers",
	} {
		if _, ok := got[name]; !ok {
			t.Fatalf("scenario %q did not run:\n%s", name, out)
		}
	}

	t.Run("a touch device is told to hold, not click", func(t *testing.T) {
		if l := got["labels_say_hold_on_touch"].IdleLabel; !strings.Contains(strings.ToLower(l), "hold") {
			t.Errorf("idle label on a touch-primary device = %q, want it to say the button is held —\n"+
				"nothing else on screen tells the user this is push-to-talk", l)
		}
	})

	t.Run("a hold transcribes and then stops", func(t *testing.T) {
		r := got["hold_transcribes_then_stops"]
		if r.Title != pttTranscript {
			t.Errorf("task title after a 700ms hold = %q, want %q", r.Title, pttTranscript)
		}
		if r.Transcribes != 1 {
			t.Errorf("hold produced %d transcribe requests, want exactly 1", r.Transcribes)
		}
		// The regression this whole file exists for: the click the browser
		// synthesises after touchend reaching the toggle and starting a second
		// recording, leaving the microphone live with nothing holding it.
		if r.RecordingAfter {
			t.Errorf("still recording after the finger lifted — the synthesised click " +
				"restarted dictation; the microphone stays live until something else stops it")
		}
		if r.DisabledAfter {
			t.Errorf("button left disabled after a completed hold (label %q) — unrecoverable without a reload", r.LabelAfter)
		}
	})

	t.Run("a stray tap sends nothing", func(t *testing.T) {
		r := got["short_tap_sends_nothing"]
		if r.Transcribes != 0 {
			t.Errorf("a 120ms tap produced %d transcribe requests, want 0 — "+
				"a clip that short is a fingertip brushing the button, and Whisper "+
				"answers it with a hallucinated stock phrase", r.Transcribes)
		}
		if r.Title != "" {
			t.Errorf("a stray tap wrote %q into the task title", r.Title)
		}
		if r.RecordingAfter {
			t.Errorf("a stray tap left the microphone recording")
		}
		// What the minimum-hold guard is actually for, and the assertion that
		// makes this scenario load-bearing. Three guards can end a hold without
		// uploading; matching the exact one distinguishes them. Anything about
		// checking the microphone sends the user to their OS sound settings
		// over hardware that works and was simply not held down long enough.
		if r.Toast != "Hold the button while you speak" {
			t.Errorf("a stray tap said %q, want %q", r.Toast, "Hold the button while you speak")
		}
	})

	t.Run("the button shows it is listening while held", func(t *testing.T) {
		r := got["mid_hold_shows_listening"]
		if !r.RecordingDuring {
			t.Errorf("button is not painted as recording mid-hold (label %q) — "+
				"the user has no signal that speaking now is being captured", r.LabelDuring)
		}
		if r.DisabledDuring {
			t.Errorf("button is disabled mid-hold; a disabled control receives no " +
				"pointerup, so the hold could never be released")
		}
		// Without this the browser reclaims the gesture as a scroll partway
		// through and the recording dies mid-sentence.
		if r.TouchAction != "none" {
			t.Errorf("touch-action on the dictate button = %q, want \"none\"", r.TouchAction)
		}
	})

	t.Run("a mouse still toggles", func(t *testing.T) {
		r := got["mouse_click_still_toggles"]
		if !r.RecordingAfterFirst {
			t.Errorf("first mouse click did not start recording — push-to-talk must not " +
				"be imposed on a pointer that cannot express a hold")
		}
		if r.RecordingAfterSecond {
			t.Errorf("second mouse click did not stop recording")
		}
		if r.Title != pttTranscript {
			t.Errorf("title after a click-to-start/click-to-stop cycle = %q, want %q", r.Title, pttTranscript)
		}
	})

	t.Run("consecutive holds both work", func(t *testing.T) {
		r := got["consecutive_holds_both_work"]
		if r.Transcribes != 2 {
			t.Errorf("two holds produced %d transcribe requests, want 2 — "+
				"the second hold is what fails when a release leaves pointer capture, "+
				"the click-suppression flag or the recorder in a stale state", r.Transcribes)
		}
		if r.RecordingAfter {
			t.Errorf("still recording after the second hold released")
		}
	})

	t.Run("a hold released before the microphone is live recovers", func(t *testing.T) {
		r := got["slow_microphone_recovers"]
		if r.Transcribes != 0 {
			t.Errorf("released before the recorder went live but %d transcribe requests were sent — "+
				"that hold captured no audio, so anything uploaded is silence and comes back "+
				"as a hallucinated title", r.Transcribes)
		}
		if r.Title != "" {
			t.Errorf("a hold that captured nothing wrote %q into the task title", r.Title)
		}
		if r.RecordingAfter || r.DisabledAfter {
			t.Errorf("button did not return to idle (recording=%v disabled=%v label=%q) — "+
				"this is the first hold in a browser that has not granted microphone "+
				"permission yet, so a stuck button here is the first thing a new user sees",
				r.RecordingAfter, r.DisabledAfter, r.LabelAfter)
		}
		// getUserMedia resolves after the release with a stream nobody asked
		// for any more. If it is not stopped, the browser's recording indicator
		// stays lit with nothing on the page able to turn it off.
		if r.LiveTracks != 0 {
			t.Errorf("%d microphone track(s) still live after an abandoned hold — "+
				"the recording indicator stays lit until the tab is closed", r.LiveTracks)
		}
	})

	// The glasses link ships a second, independent copy of this gesture: it is a
	// standalone document that loads no bundle, so nothing the assertions above
	// cover applies to it. Its dictate button is hidden on the wearable itself —
	// Meta grants web apps no audio capture — which means the only device that
	// ever sees it is the phone the glasses tether through, and that is exactly
	// the device this task is about.
	t.Run("the glasses link holds to talk too", func(t *testing.T) {
		hold := got["glasses_hold_transcribes"]
		if hold.Transcribes != 1 {
			t.Errorf("a hold on the glasses link produced %d transcribe requests, want 1", hold.Transcribes)
		}
		if hold.RecordingAfter {
			t.Errorf("still recording after the finger lifted — the synthesised click " +
				"restarted dictation on the glasses link")
		}
		if hold.View != "Add this task?" {
			t.Errorf("screen after a hold = %q, want the confirmation screen — the wearer "+
				"cannot edit a transcript, so confirming is the only review there is", hold.View)
		}
		if hold.Title != pttTranscript {
			t.Errorf("transcript offered for confirmation = %q, want %q", hold.Title, pttTranscript)
		}

		tap := got["glasses_tap_sends_nothing"]
		if tap.Transcribes != 0 {
			t.Errorf("a 120ms tap on the glasses link produced %d transcribe requests, want 0", tap.Transcribes)
		}
		if tap.View != "Add task" {
			t.Errorf("a stray tap moved the wearer to %q; it should leave them on the Add screen", tap.View)
		}
		if tap.Toast != "Hold the button while you speak." {
			t.Errorf("a stray tap said %q, want %q", tap.Toast, "Hold the button while you speak.")
		}
		if tap.TouchAction != "none" {
			t.Errorf("touch-action on the glasses dictate button = %q, want \"none\"", tap.TouchAction)
		}
	})

	if n := transcribeCalls.Load(); n == 0 {
		t.Errorf("the hub never received a transcribe request; the driver's own " +
			"request counts cannot mean what they claim")
	}
}

func mustAbs(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("resolve %s: %v", rel, err)
	}
	return p
}
