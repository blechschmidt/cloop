package ui

// Browser gate for the virtual-executor dialog's network access (Task 20356).
//
// The complaint was about a form: an "IP firewall" checkbox, "Allow the public
// Internet" and the allow/deny lists sat side by side, all editable, and
// nothing said which depended on which — or that rules typed with the firewall
// off were dropped on save. The dialog now offers one choice (No network,
// Firewalled, Unfiltered) with each one's settings under it. Whether that
// holds is a question for a layout engine and a real hub, not for
// testdata/domshim.js: the shim models no display:none, and calls handlers
// directly where a user's click goes through an inline onchange that must
// reach a function exported from the bundle's IIFE.
//
// It skips when Chrome or node is missing, like every browser gate here.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

type evxBrowserSpec struct {
	Sandbox  map[string]string `json:"sandbox"`
	Firewall *struct {
		AllowPublicInternet bool     `json:"allow_public_internet"`
		AllowCIDRs          []string `json:"allow_cidrs"`
		DenyCIDRs           []string `json:"deny_cidrs"`
		Resolvers           []string `json:"resolvers"`
	} `json:"firewall"`
}

type evxBrowserResult struct {
	Settings *struct {
		NoneCheckedAtFirst       bool   `json:"none_checked_at_first"`
		RulesHiddenAtFirst       bool   `json:"rules_hidden_at_first"`
		NameHiddenAtFirst        bool   `json:"name_hidden_at_first"`
		RulesShownForFirewalled  bool   `json:"rules_shown_for_firewalled"`
		SummaryShown             bool   `json:"summary_shown"`
		SummaryDefault           string `json:"summary_default"`
		SummaryTyped             string `json:"summary_typed"`
		SummaryNothing           string `json:"summary_nothing"`
		SummaryNothingWarns      bool   `json:"summary_nothing_warns"`
		RulesHiddenForUnfiltered bool   `json:"rules_hidden_for_unfiltered"`
		NameShownForUnfiltered   bool   `json:"name_shown_for_unfiltered"`
		NameDefault              string `json:"name_default"`
		AllHiddenForNone         bool   `json:"all_hidden_for_none"`
	} `json:"settings_follow_the_choice"`
	Saved *struct {
		Firewalled           *evxBrowserSpec `json:"firewalled"`
		ReopenedRulesVisible bool            `json:"reopened_rules_visible"`
		ReopenedAllow        string          `json:"reopened_allow"`
		AfterNone            *evxBrowserSpec `json:"after_none"`
		AfterOpen            *evxBrowserSpec `json:"after_open"`
		ReopenedOpenChecked  bool            `json:"reopened_open_checked"`
		ReopenedNetworkName  string          `json:"reopened_network_name"`
		ReopenedNameVisible  bool            `json:"reopened_name_visible"`
		Executors            int             `json:"executors"`
	} `json:"saved_as_chosen"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// lateWrites applies every write to a virtual executor at once but holds its
// response for delay, the way a hub under -race on a loaded runner answers.
//
// In that window the hub already stores the change while the dialog still
// shows the form it submitted, in create mode after a first save. The first CI
// run of this test lost exactly there (2026-09-29): the driver took the stale
// form for the re-rendered one, pressed Create a second time, and waited out
// its bound for a change that had gone to a new executor. A fast machine never
// opens the window, so the test opens it on purpose.
func lateWrites(h http.Handler, delay time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || !strings.Contains(r.URL.Path, "/virtual") {
			h.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		time.Sleep(delay)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

func TestVirtualExecutorNetworkAccess_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot measure a form a user can actually see")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	dir := setupProjectDir(t, "virtual executor network access", nil)
	device := seedDevice(t, dir, "sgx-browser-1")
	// Whatever the run creates is registered process-wide; take it out again
	// so no later test in the package finds it.
	t.Cleanup(func() {
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			return
		}
		defer db.Close()
		rows, _ := db.ListVirtualExecutors()
		for _, v := range rows {
			executor.DefaultRegistry.Unregister(v.ID)
		}
	})

	// Configured before the listener starts: requests from Chrome carry no
	// happens-before edge the race detector can see.
	srv := New(dir, 0, "")
	ts := httptest.NewServer(lateWrites(srv.Handler(), time.Second))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/executor_virtual_browser.js"),
		chrome, ts.URL, device).Output()
	var got evxBrowserResult
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, out, stderr)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s", got.Error.Message)
	}
	if got.Settings == nil || got.Saved == nil {
		t.Fatalf("a scenario did not run:\n%s", out)
	}

	t.Run("each choice shows its own settings and no one else's", func(t *testing.T) {
		r := got.Settings
		if !r.NoneCheckedAtFirst {
			t.Error("a new virtual executor does not start with No network, the deny-by-default choice")
		}
		if !r.RulesHiddenAtFirst || !r.NameHiddenAtFirst {
			t.Error("firewall rules or the network name are on screen before any choice applies them — " +
				"the ambiguity this dialog was rebuilt to remove")
		}
		if !r.RulesShownForFirewalled {
			t.Fatal("choosing Firewalled did not reveal every rule field; the radio's onchange may not reach " +
				"a handler exported from the bundle")
		}
		if !r.RulesHiddenForUnfiltered || !r.NameShownForUnfiltered || r.NameDefault != "bridge" {
			t.Errorf("Unfiltered: rules hidden=%v, network name shown=%v (%q), want true, true, \"bridge\"",
				r.RulesHiddenForUnfiltered, r.NameShownForUnfiltered, r.NameDefault)
		}
		if !r.AllHiddenForNone {
			t.Error("No network left firewall rules or a network name on screen")
		}
	})

	t.Run("the rules are read back as what they let through", func(t *testing.T) {
		r := got.Settings
		if !r.SummaryShown {
			t.Fatal("the summary under the rules is not visible")
		}
		for _, c := range []struct{ name, text, want string }{
			{"defaults", r.SummaryDefault, "sandboxes can open TCP connections to the public Internet on any port, " +
				"and query DNS at 1.1.1.1. Everything else is dropped."},
			{"typed", r.SummaryTyped, "to the public Internet and 10.8.0.0/24 on any port"},
			{"typed", r.SummaryTyped, "Never reachable: 203.0.113.0/24."},
			{"nothing allowed", r.SummaryNothing, "nothing is allowed, so sandboxes get no network at all"},
		} {
			if !strings.Contains(c.text, c.want) {
				t.Errorf("%s: summary %q lacks %q — typing did not reach it through the field's oninput, or it "+
					"misreads the rules", c.name, c.text, c.want)
			}
		}
		if !r.SummaryNothingWarns {
			t.Error("a firewall that allows nothing is not flagged")
		}
	})

	t.Run("the hub stores the access chosen, and only its settings", func(t *testing.T) {
		r := got.Saved
		fw := r.Firewalled
		if fw == nil || fw.Firewall == nil {
			t.Fatalf("saving Firewalled stored no firewall: %+v", fw)
		}
		if !fw.Firewall.AllowPublicInternet || strings.Join(fw.Firewall.AllowCIDRs, ",") != "10.8.0.0/24" ||
			strings.Join(fw.Firewall.DenyCIDRs, ",") != "203.0.113.0/24" ||
			strings.Join(fw.Firewall.Resolvers, ",") != "1.1.1.1:53" || fw.Sandbox["network"] != "" {
			t.Errorf("stored firewall = %+v, network %q", *fw.Firewall, fw.Sandbox["network"])
		}
		if !r.ReopenedRulesVisible || r.ReopenedAllow != "10.8.0.0/24" {
			t.Errorf("the saved executor reopened without its rules on screen: visible=%v allow=%q",
				r.ReopenedRulesVisible, r.ReopenedAllow)
		}
		if n := r.AfterNone; n == nil || n.Firewall != nil || n.Sandbox["network"] != "none" {
			t.Errorf("switching to No network and saving stored %+v — rules left under Firewalled must not "+
				"be applied", n)
		}
		if o := r.AfterOpen; o == nil || o.Firewall != nil || o.Sandbox["network"] != "lab-net" {
			t.Errorf("Unfiltered on lab-net stored %+v", o)
		}
		if r.Executors != 1 {
			t.Errorf("three saves of one executor left %d executors — a save after the first created "+
				"another instead of editing it", r.Executors)
		}
		if !r.ReopenedOpenChecked || r.ReopenedNetworkName != "lab-net" || !r.ReopenedNameVisible {
			t.Errorf("a named network did not survive a reopen: Unfiltered=%v name=%q visible=%v — saving "+
				"again would reset it", r.ReopenedOpenChecked, r.ReopenedNetworkName, r.ReopenedNameVisible)
		}
	})
}
