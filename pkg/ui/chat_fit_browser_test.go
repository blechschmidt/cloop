package ui

// Browser gate for the fit of the Chat and Assistant tabs (Task 20492). At
// every height a screen really has, the page must not scroll on either tab, the
// messages must scroll inside their list with the newest in view, and the
// input, Send and the microphone must be on screen and clickable — not under
// the fixed shortcut footer, as they were on the 1920x1200 laptop that reported
// it. See testdata/chat_fit_browser.js for what is driven; skips without Chrome
// or node, like every browser gate.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
)

// chatFitViewport is a browser window: its content area in CSS pixels, at a
// device pixel ratio that may be fractional, as a laptop scaled to 125% or 150%
// is — where a box summed from fractional heights can come out a pixel over.
type chatFitViewport struct {
	Name   string  `json:"name"`
	Width  int     `json:"width"`
	Height int     `json:"height"`
	Scale  float64 `json:"scale"`
	Mobile bool    `json:"mobile"`
}

// chatFitViewports are the content areas a maximised browser leaves on the
// screens people have. The 1920x1050 one is the 1920x1200 laptop this hub's
// telemetry has every desktop session on (Chrome on Linux), less its browser
// and desktop bars; 1536 and 1280 are a 1920x1080 laptop at 125% and 150%,
// and 1440 a MacBook's Retina screen.
var chatFitViewports = []chatFitViewport{
	{Name: "laptop-1366", Width: 1366, Height: 625, Scale: 1},
	{Name: "laptop-1280", Width: 1280, Height: 610, Scale: 1.5},
	{Name: "laptop-1440", Width: 1440, Height: 760, Scale: 2},
	{Name: "laptop-1536", Width: 1536, Height: 730, Scale: 1.25},
	{Name: "desktop-1920", Width: 1920, Height: 1050, Scale: 1},
	{Name: "tablet-768", Width: 768, Height: 1024, Scale: 2, Mobile: true},
	{Name: "phone-360", Width: 360, Height: 660, Scale: 3, Mobile: true},
}

// chatFitBusy is where the driver adds a presence bar and a banner above the
// chat, sends a message and types a long question to the Assistant.
const chatFitBusy = "desktop-1920"

// chatFitShort are windows too short for the header, the controls and the
// list's minimum: a laptop's browser window at half height, and a phone held
// sideways. There the page may scroll, but only as far as the list's minimum
// needs, and the input has to be reachable by scrolling it.
var chatFitShort = []chatFitViewport{
	{Name: "short-1280", Width: 1280, Height: 380, Scale: 1},
	{Name: "phone-landscape", Width: 740, Height: 340, Scale: 3, Mobile: true},
}

// chatFitListFloorPx is the message list's min-height in app.css: what it
// keeps in a short window instead of squeezing the input out.
const chatFitListFloorPx = 120

// chatFitMaxGapPx is how far above the footer (or the bottom of the window,
// where there is none) the chat may stop. The page's own padding is 24px; more
// than this and the chat is a box with the window's height wasted under it.
const chatFitMaxGapPx = 48

// chatFitMinMessagesPx is the least room the message list may be left: a few
// bubbles' worth, or the chat is an input with nothing to read above it.
const chatFitMinMessagesPx = 150

type chatFitBox struct {
	Top    int `json:"top"`
	Bottom int `json:"bottom"`
	Left   int `json:"left"`
	Right  int `json:"right"`
	Height int `json:"height"`
}

type chatFitMeasurement struct {
	Name          string      `json:"name"`
	Tab           string      `json:"tab"`
	InnerWidth    int         `json:"inner_width"`
	InnerHeight   int         `json:"inner_height"`
	PageOverflow  int         `json:"page_overflow"`
	PageOverflowX int         `json:"page_overflow_x"`
	ScrollY       int         `json:"scroll_y"`
	Header        *chatFitBox `json:"header"`
	Footer        *chatFitBox `json:"footer"`
	Chat          *chatFitBox `json:"chat"`
	Bar           *chatFitBox `json:"bar"`
	Input         *chatFitBox `json:"input"`
	Send          *chatFitBox `json:"send"`
	Mic           *chatFitBox `json:"mic"`
	InputHit      string      `json:"input_hit"`
	SendHit       string      `json:"send_hit"`
	MicHit        string      `json:"mic_hit"`
	InputValue    *string     `json:"input_value"`
	Rows          int         `json:"rows"`
	Last          *chatFitBox `json:"last"`
	LastText      string      `json:"last_text"`
	Messages      *struct {
		chatFitBox
		ClientHeight int `json:"client_height"`
		ScrollHeight int `json:"scroll_height"`
		ScrollTop    int `json:"scroll_top"`
	} `json:"messages"`
}

type chatFitResults struct {
	Error     string               `json:"error"`
	Viewports []chatFitMeasurement `json:"viewports"`
	Busy      *chatFitMeasurement  `json:"busy"`
	Sent      *chatFitMeasurement  `json:"sent"`
	Typing    *chatFitMeasurement  `json:"typing"`
	Overview  *struct {
		InnerHeight       int    `json:"inner_height"`
		LayoutHeight      int    `json:"layout_height"`
		ContentHeight     int    `json:"content_height"`
		PageOverflow      int    `json:"page_overflow"`
		BodyPaddingBottom string `json:"body_padding_bottom"`
		FooterPosition    string `json:"footer_position"`
	} `json:"overview"`
	Short []struct {
		Top chatFitMeasurement `json:"top"`
		End chatFitMeasurement `json:"end"`
	} `json:"short"`
}

// TestChatTab_FitsTheWindowInBrowser: the Chat and Assistant tabs over a
// history long enough to scroll, at laptop, desktop, tablet and phone sizes,
// with bars above them, while sending and typing, and in windows too short to
// fit.
func TestChatTab_FitsTheWindowInBrowser(t *testing.T) {
	chrome, node := browserTools(t)
	// One project, so boot lands on its Overview and never moves the page
	// under the driver.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "chat fit", nil)

	const lastMarker, replyMarker = "chat-fit-last-message", "chat-fit-reply"
	at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	var history []ChatMessage
	var assistant []map[string]string
	for i := 0; i < 24; i++ {
		question := fmt.Sprintf("Question %d: what is task %d waiting on?", i+1, i+3)
		answer := fmt.Sprintf("Task %d waits on task %d, which is still running. "+
			"It started a few minutes ago and has written two files so far.\nI will tell you when it finishes.", i+3, i+2)
		if i == 23 {
			answer = "The last answer in the history: " + lastMarker
		}
		history = append(history,
			ChatMessage{Role: "user", Content: question, Timestamp: at.Add(time.Duration(2*i) * time.Minute)},
			ChatMessage{Role: "assistant", Content: answer, Timestamp: at.Add(time.Duration(2*i+1) * time.Minute),
				Action: fmt.Sprintf("task show %d", i+3)})
		assistant = append(assistant, map[string]string{"role": "user", "content": question},
			map[string]string{"role": "assistant", "content": answer})
	}

	// Configured before the listener starts: requests from Chrome carry no
	// happens-before edge the race detector can see.
	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 100000, 100000
	srv.chatHistories = map[string][]ChatMessage{dir: history}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	cfg := map[string]any{
		"viewports": chatFitViewports, "busy": chatFitBusy, "short": chatFitShort,
		"last_marker": lastMarker, "assistant_history": assistant,
		"banner":  "The hub's state volume has 812 MB free, below its 1 GB floor: runs pause until space is freed.",
		"message": "what is running right now?",
		"reply":   "Task 27 is running on the container executor. " + replyMarker, "reply_marker": replyMarker,
		"long_question": "Which tasks are blocked,\nwhat are they waiting on,\nwho started them,\nwhen did each one " +
			"last make progress,\nand which of them should I look at first?\nGive me the short version.",
		"shots": os.Getenv("CHAT_FIT_SHOTS"),
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "chat-fit.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Bounded: a Chrome that stalls must fail this test, not eat the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/chat_fit_browser.js"), chrome, ts.URL, cfgPath).Output()
	var got chatFitResults
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, out, stderr)
	}
	if got.Error != "" {
		t.Fatalf("the driver reported an error: %s", got.Error)
	}
	if testing.Verbose() {
		t.Logf("measurements:\n%s", out)
	}
	if len(got.Viewports) != 2*len(chatFitViewports) || got.Busy == nil || got.Sent == nil || got.Typing == nil ||
		got.Overview == nil || len(got.Short) != len(chatFitShort) {
		t.Fatalf("the driver measured %d of %d tab views, %d of %d short windows (busy %v, sent %v, typing %v, overview %v)",
			len(got.Viewports), 2*len(chatFitViewports), len(got.Short), len(chatFitShort),
			got.Busy != nil, got.Sent != nil, got.Typing != nil, got.Overview != nil)
	}

	for _, m := range append(got.Viewports, *got.Busy, *got.Sent, *got.Typing) {
		checkChatFit(t, m)
	}

	s := got.Sent
	if s.InputValue == nil || *s.InputValue != "" {
		t.Errorf("after sending, the input still holds %v", s.InputValue)
	}
	if !strings.Contains(s.LastText, replyMarker) {
		t.Errorf("after sending, the newest message is %q, not the reply", s.LastText)
	}
	// The Assistant's box grows to its cap (120px in app.css) with six lines;
	// unless it did, the typing measurement proved nothing about a list that
	// gives up room under its reader.
	if ty := got.Typing; ty.Input == nil || ty.Input.Height < 100 {
		t.Errorf("typing six lines to the Assistant left its box %+v tall; the scenario needs it grown", ty.Input)
	}

	// Leaving the tab gives the page back: the Overview is as tall as the
	// window at least, keeps the footer's room below it, and the footer is
	// fixed over the page again.
	o := got.Overview
	if o.LayoutHeight < o.InnerHeight {
		t.Errorf("on the Overview the layout is %dpx tall in a %dpx window: the Chat tab's fixed height leaked out of it",
			o.LayoutHeight, o.InnerHeight)
	}
	if o.BodyPaddingBottom != "30px" || o.FooterPosition != "fixed" {
		t.Errorf("on the Overview the page keeps %s under its content and a %s footer, want 30px and fixed",
			o.BodyPaddingBottom, o.FooterPosition)
	}

	for _, sh := range got.Short {
		checkShortChat(t, sh.Top, sh.End)
	}
}

// chatFitPart is a control that must be reachable, where it was drawn and
// what a click at its middle landed on when not on it.
type chatFitPart struct {
	what string
	box  *chatFitBox
	hit  string
}

// chatFitParts lists the controls of a measurement that must be reachable:
// the input and Send on both tabs, and the microphone on the Chat tab.
func chatFitParts(m chatFitMeasurement) []chatFitPart {
	parts := []chatFitPart{{"the input", m.Input, m.InputHit}, {"Send", m.Send, m.SendHit}}
	if m.Tab == "chat" {
		parts = append(parts, chatFitPart{"the microphone button", m.Mic, m.MicHit})
	}
	return parts
}

// chatFitIncomplete reports a measurement that misses a part the tab draws.
func chatFitIncomplete(m chatFitMeasurement) bool {
	if m.Header == nil || m.Chat == nil || m.Bar == nil || m.Messages == nil {
		return true
	}
	for _, p := range chatFitParts(m) {
		if p.box == nil {
			return true
		}
	}
	return false
}

// checkChatFit holds one measurement of a chat-shaped tab to the window it was
// laid out in.
func checkChatFit(t *testing.T, m chatFitMeasurement) {
	t.Helper()
	at := fmt.Sprintf("%s (%dx%d)", m.Name, m.InnerWidth, m.InnerHeight)
	if chatFitIncomplete(m) {
		t.Errorf("%s: the tab is missing a part: %+v", at, m)
		return
	}
	if m.PageOverflow > 1 {
		t.Errorf("%s: the page scrolls by %dpx — the chat is taller than the window", at, m.PageOverflow)
	}
	if m.PageOverflowX > 1 {
		t.Errorf("%s: the page scrolls sideways by %dpx", at, m.PageOverflowX)
	}
	// The bottom of what may be drawn on: the footer's top edge, or the
	// window's bottom on a phone, which has no footer.
	floor := m.InnerHeight
	if m.Footer != nil {
		floor = m.Footer.Top
	}
	for _, c := range chatFitParts(m) {
		if c.hit != "" {
			t.Errorf("%s: a click on %s lands on %s", at, c.what, c.hit)
		}
		if c.box.Top < m.Header.Bottom || c.box.Bottom > floor {
			t.Errorf("%s: %s spans %d–%dpx, outside the %d–%dpx between the header and the footer",
				at, c.what, c.box.Top, c.box.Bottom, m.Header.Bottom, floor)
		}
	}
	if gap := floor - m.Bar.Bottom; gap > chatFitMaxGapPx {
		t.Errorf("%s: the chat stops %dpx above the footer — the window's height is wasted under it", at, gap)
	}
	msgs := m.Messages
	if msgs.ClientHeight < chatFitMinMessagesPx {
		t.Errorf("%s: the messages have %dpx, want at least %dpx", at, msgs.ClientHeight, chatFitMinMessagesPx)
	}
	checkNewestInView(t, at, m)
	if m.ScrollY != 0 {
		t.Errorf("%s: the page is scrolled to %dpx", at, m.ScrollY)
	}
}

// checkNewestInView: the history scrolls inside its list, and the list shows
// its newest message.
func checkNewestInView(t *testing.T, at string, m chatFitMeasurement) {
	t.Helper()
	msgs := m.Messages
	if msgs.ScrollHeight <= msgs.ClientHeight {
		t.Errorf("%s: the history is %dpx in a %dpx list and does not scroll inside it — the list grew instead",
			at, msgs.ScrollHeight, msgs.ClientHeight)
	}
	if msgs.ScrollTop+msgs.ClientHeight < msgs.ScrollHeight-2 {
		t.Errorf("%s: the list is scrolled to %d of %d: the newest message is not the one in view",
			at, msgs.ScrollTop+msgs.ClientHeight, msgs.ScrollHeight)
	}
	if m.Last == nil || m.Last.Bottom > msgs.Bottom+1 || m.Last.Bottom <= msgs.Top {
		t.Errorf("%s: the newest message (%+v) is not in view in the list (%d–%dpx)", at, m.Last, msgs.Top, msgs.Bottom)
	}
}

// checkShortChat holds the Chat tab in a window too short for it: the list
// keeps its minimum, the page scrolls no further than that needs, and scrolled
// to its end the page shows the controls whole, clear of the footer.
func checkShortChat(t *testing.T, top, end chatFitMeasurement) {
	t.Helper()
	at := fmt.Sprintf("%s (%dx%d)", top.Name, top.InnerWidth, top.InnerHeight)
	if chatFitIncomplete(top) || chatFitIncomplete(end) {
		t.Errorf("%s: the tab is missing a part: %+v / %+v", at, top, end)
		return
	}
	if got := top.Messages.ClientHeight; got < chatFitListFloorPx-1 {
		t.Errorf("%s: the list was squeezed to %dpx, below its %dpx minimum", at, got, chatFitListFloorPx)
	}
	// What a window this short lacks is at most the list's minimum: anything
	// more is height the page wastes, which the fitting windows hold to
	// chatFitMaxGapPx.
	if top.PageOverflow > chatFitListFloorPx {
		t.Errorf("%s: the page scrolls by %dpx, more than the list's %dpx minimum", at, top.PageOverflow, chatFitListFloorPx)
	}
	if top.PageOverflowX > 1 {
		t.Errorf("%s: the page scrolls sideways by %dpx", at, top.PageOverflowX)
	}
	floor := end.InnerHeight
	if end.Footer != nil {
		floor = end.Footer.Top
	}
	for _, c := range chatFitParts(end) {
		if c.hit != "" {
			t.Errorf("%s, scrolled to its end: a click on %s lands on %s", at, c.what, c.hit)
		}
		if c.box.Top < end.Header.Bottom || c.box.Bottom > floor {
			t.Errorf("%s, scrolled to its end: %s spans %d–%dpx, outside the %d–%dpx between the header and the footer",
				at, c.what, c.box.Top, c.box.Bottom, end.Header.Bottom, floor)
		}
	}
	checkNewestInView(t, at, end)
}
