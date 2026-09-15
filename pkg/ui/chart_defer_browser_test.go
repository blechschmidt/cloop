package ui

// Deferred chart library, observed in a real browser (Task 20289).
//
// TestStaticAssets_ChartLibraryIsNotEager (assetbudget_test.go) proves the
// library is absent from the page's eager references — a property of the bytes
// we serve. It cannot prove the other half: that a tab which needs the library
// still gets it, and that a user on a bad link is told so rather than left
// staring at five blank cards. Those are runtime properties of script loading,
// and testdata/domshim.js issues no requests and implements no load events, so
// only a browser can answer them.
//
// Skips when Chrome or node is unavailable, like the other browser gates here.

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

// chartsExpectedForBareProject is how many of the five Analytics canvases draw
// against a project with no tasks and no recorded provider calls: velocity,
// burn-down and cost trend. The status donut hides itself when every slice is
// zero and the latency histogram when there are no samples, so both are
// legitimately absent here — see _renderAnalytics in assets/js/19-analytics.js.
const chartsExpectedForBareProject = 3

// chartBanner mirrors the visible state of the Analytics status banner.
type chartBanner struct {
	Visible      bool   `json:"visible"`
	Text         string `json:"text"`
	RetryVisible bool   `json:"retryVisible"`
	CardsVisible bool   `json:"cardsVisible"`
}

type chartDeferResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	FirstPaint struct {
		ChartRequests int         `json:"chart_requests"`
		ChartGlobal   bool        `json:"chart_global"`
		LoaderPresent bool        `json:"loader_present"`
		MetaSrc       string      `json:"meta_src"`
		RetryExposed  bool        `json:"retry_exposed"`
		Banner        chartBanner `json:"banner"`
	} `json:"first_paint"`

	OnDemand struct {
		ChartRequests int         `json:"chart_requests"`
		ChartGlobal   bool        `json:"chart_global"`
		ChartsDrawn   int         `json:"charts_drawn"`
		Banner        chartBanner `json:"banner"`
	} `json:"on_demand"`

	SecondVisit struct {
		ChartRequests int `json:"chart_requests"`
		ChartsDrawn   int `json:"charts_drawn"`
	} `json:"second_visit"`

	Blocked struct {
		ChartRequests  int         `json:"chart_requests"`
		ChartGlobal    bool        `json:"chart_global"`
		ChartsDrawn    int         `json:"charts_drawn"`
		Banner         chartBanner `json:"banner"`
		EpicsReachable bool        `json:"epics_reachable"`
	} `json:"blocked"`

	AfterRetry struct {
		ChartRequests int         `json:"chart_requests"`
		ChartGlobal   bool        `json:"chart_global"`
		ChartsDrawn   int         `json:"charts_drawn"`
		Banner        chartBanner `json:"banner"`
	} `json:"after_retry"`
}

// TestChartLibrary_DeferredLoadInBrowser is the whole gate; the subtests read
// from one browser run, because launching Chrome and booting the dashboard
// costs seconds and every scenario shares that setup.
func TestChartLibrary_DeferredLoadInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot observe what the page fetches")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// The real dashboard, with a bare project directory: /api/analytics answers
	// 200 with an empty series for one, so the success path is reachable without
	// seeding a plan.
	s := New(t.TempDir(), 0, "")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	cmd := exec.Command(node, mustAbs(t, "testdata/chart_defer_browser.js"), chrome, srv.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if os.Getenv("CHART_DEFER_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}

	var got chartDeferResults
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s", got.Error.Message)
	}

	// Preflight: without these, every assertion below could pass on a page that
	// never loaded the loader at all.
	if !got.FirstPaint.LoaderPresent {
		t.Fatal("window.ensureChartLib is not defined on the loaded page — the " +
			"deferred loader is not in the served bundle, so nothing below is " +
			"testing what it claims")
	}
	if got.FirstPaint.MetaSrc == "" {
		t.Fatal(`the page carries no <meta name="cloop-chart-src"> content — ` +
			"the loader has no URL and the rest of this run is vacuous")
	}

	t.Run("first paint does not fetch the library", func(t *testing.T) {
		if n := got.FirstPaint.ChartRequests; n != 0 {
			t.Errorf("the page requested chart.js %d time(s) before any chart tab was "+
				"opened; the whole point of Task 20289 is that it does not. Check "+
				"whether a <script src> for it came back to index.html", n)
		}
		if got.FirstPaint.ChartGlobal {
			t.Error("window.Chart is defined at first paint — the library was " +
				"evaluated on the way to painting, which is the cost this change removed")
		}
		if !got.FirstPaint.RetryExposed {
			t.Error("window.retryAnalyticsCharts is not exposed; the banner's inline " +
				"onclick would be a silent no-op, so a failed load could never be retried")
		}
	})

	t.Run("opening Analytics fetches it and draws", func(t *testing.T) {
		if n := got.OnDemand.ChartRequests; n != 1 {
			t.Errorf("opening Analytics made %d request(s) for chart.js, want exactly 1 "+
				"(0 = never loaded, >1 = the memo in ensureChartLib is not holding)", n)
		}
		if !got.OnDemand.ChartGlobal {
			t.Fatal("window.Chart is still undefined after opening Analytics — the " +
				"deferred fetch did not arrive, so the tab is permanently blank")
		}
		// Three of the five draw for a bare project, and that is the correct
		// number rather than a tolerance: _renderAnalytics hides the status
		// donut when every slice is zero, and skips the latency histogram
		// when no provider calls have been recorded. Velocity, burn-down and
		// cost trend always render. Zero would mean the panel never ran.
		if n := got.OnDemand.ChartsDrawn; n < chartsExpectedForBareProject {
			t.Errorf("%d of the five canvases carry a Chart instance, want at least %d "+
				"(velocity, burn-down and cost trend; the donut and latency histogram "+
				"self-hide with no data) — the library loaded but the panel did not "+
				"render with it", n, chartsExpectedForBareProject)
		}
		if b := got.OnDemand.Banner; b.Visible || !b.CardsVisible {
			t.Errorf("after a successful load the banner is visible=%v and the cards "+
				"visible=%v; want the banner hidden and the cards shown (text was %q)",
				b.Visible, b.CardsVisible, b.Text)
		}
	})

	t.Run("returning to the tab does not refetch", func(t *testing.T) {
		if n := got.SecondVisit.ChartRequests; n != 0 {
			t.Errorf("a second visit to Analytics refetched chart.js %d time(s); "+
				"ensureChartLib is meant to memoise the load for the life of the page", n)
		}
		if n := got.SecondVisit.ChartsDrawn; n < chartsExpectedForBareProject {
			t.Errorf("only %d canvases are drawn after returning to the tab, want at least %d",
				n, chartsExpectedForBareProject)
		}
	})

	t.Run("a failed fetch says so and offers a retry", func(t *testing.T) {
		if got.Blocked.ChartGlobal {
			t.Fatal("window.Chart is defined even though the library URL was blocked; " +
				"the failure path never ran, so this scenario proves nothing")
		}
		b := got.Blocked.Banner
		if !b.Visible {
			t.Error("chart.js failed to load and the Analytics tab shows no banner — " +
				"the user is left with blank cards and no indication anything went wrong, " +
				"which is exactly the outcome Task 20289 was required to avoid")
		}
		if !b.RetryVisible {
			t.Error("the failure banner offers no Retry button; over a flaky link the " +
				"only recovery would be a full page reload")
		}
		if b.CardsVisible {
			t.Error("the empty chart cards are still displayed under the failure banner; " +
				"they render as five blank boxes and read as 'no data'")
		}
		if got.Blocked.ChartsDrawn != 0 {
			t.Errorf("%d charts report as drawn despite the library being blocked", got.Blocked.ChartsDrawn)
		}
	})

	t.Run("Retry recovers once the network does", func(t *testing.T) {
		if n := got.AfterRetry.ChartRequests; n < 1 {
			t.Fatalf("clicking Retry issued %d requests for chart.js; ensureChartLib is "+
				"replaying its cached rejection instead of clearing the memo and trying again", n)
		}
		if !got.AfterRetry.ChartGlobal {
			t.Fatal("window.Chart is still undefined after a successful retry")
		}
		if n := got.AfterRetry.ChartsDrawn; n < chartsExpectedForBareProject {
			t.Errorf("%d canvases drawn after Retry, want at least %d — the library "+
				"recovered but the panel did not re-render", n, chartsExpectedForBareProject)
		}
		if b := got.AfterRetry.Banner; b.Visible || !b.CardsVisible {
			t.Errorf("after a successful retry the banner is visible=%v, cards visible=%v; "+
				"want the banner gone and the charts shown (text was %q)",
				b.Visible, b.CardsVisible, b.Text)
		}
	})
}
