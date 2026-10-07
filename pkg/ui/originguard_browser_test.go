package ui

// Browser gate for the origin guards (Task 20394). See
// testdata/forgery_browser.js for what it drives and why a browser. Skips when
// Chrome or node is missing, like the others; originguard_test.go holds the
// route-table sweep that runs everywhere.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// attackerPage is what a page elsewhere does to a hub on this machine. Every
// attempt writes a task titled "pwned-…"; none may land.
const attackerPage = `<!doctype html>
<html><head><title>a page elsewhere</title></head><body>
<iframe name="sink"></iframe>
<form id="f" method="POST" enctype="text/plain" target="sink">
  <input type="hidden" name='{"title":"pwned-by-form","description":"' value='"}'>
</form>
<script>
(async () => {
  const hub = new URLSearchParams(location.search).get('hub');
  const report = {};
  try {
    // 1. The classic: a text/plain form whose one field spells JSON.
    const f = document.getElementById('f');
    f.action = hub + '/api/task/add?project_idx=0';
    const loaded = new Promise(r => document.querySelector('iframe').addEventListener('load', r, {once: true}));
    f.submit();
    await loaded;
    report.form = 'submitted';

    // 2. fetch in no-cors mode: no preflight, the body goes out as text/plain.
    const r1 = await fetch(hub + '/api/tasks?project_idx=0', {method: 'POST', mode: 'no-cors',
      body: JSON.stringify({title: 'pwned-by-fetch'})});
    report.fetch = r1.type;

    // 3. An untyped Blob: a body with no Content-Type at all.
    const r2 = await fetch(hub + '/api/task/add?project_idx=0', {method: 'POST', mode: 'no-cors',
      body: new Blob([JSON.stringify({title: 'pwned-by-blob'})])});
    report.blob = r2.type;

    // 4. A WebSocket, which the same-origin policy does not cover at all.
    report.websocket = await new Promise(res => {
      const ws = new WebSocket(hub.replace(/^http/, 'ws') + '/api/ws?project_idx=0');
      ws.onopen = () => { ws.close(); res('opened'); };
      ws.onerror = () => res('refused');
    });
  } catch (e) {
    report.error = String(e);
  }
  window.__report = report;
  window.__done = true;
})();
</script></body></html>`

type forgeryAttack struct {
	Page struct {
		Form      string `json:"form"`
		Fetch     string `json:"fetch"`
		Blob      string `json:"blob"`
		WebSocket string `json:"websocket"`
		Error     string `json:"error"`
	} `json:"page"`
	Responses []struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
		Method string `json:"method"`
	} `json:"responses"`
}

type forgeryResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	SameSite  *forgeryAttack `json:"same_site"`
	CrossSite *forgeryAttack `json:"cross_site"`
	Dashboard *struct {
		Added        bool `json:"added"`
		SettingSaved bool `json:"setting_saved"`
	} `json:"dashboard"`
	Rebound *struct {
		Text   string `json:"text"`
		Status int    `json:"status"`
	} `json:"rebound"`
}

func TestAPageElsewhereCannotDriveAnOpenHubInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot have a real page attack the hub")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "a hub a page elsewhere must not drive", nil)
	srv := New(dir, 0, "") // no sign-in: the developer's loopback hub
	srv.RPS, srv.Burst = 1e6, 1_000_000
	hub := newTestServerFor(t, srv)

	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, attackerPage)
	}))
	defer attacker.Close()
	attackerPort := attacker.URL[strings.LastIndex(attacker.URL, ":")+1:]

	metricsBefore := hubmetrics.Default.Gather()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/forgery_browser.js"), chrome, hub.URL, attackerPort)
	out, err := cmd.Output()
	var got forgeryResults
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, out, stderr)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s\nraw:\n%s", got.Error.Message, out)
	}
	if got.SameSite == nil || got.CrossSite == nil || got.Dashboard == nil || got.Rebound == nil {
		t.Fatalf("a scenario did not run:\n%s", out)
	}

	for name, a := range map[string]*forgeryAttack{"another port of the hub's host": got.SameSite, "another site": got.CrossSite} {
		t.Run("a page on "+name, func(t *testing.T) {
			if a.Page.Error != "" {
				t.Fatalf("the attacker page failed: %s", a.Page.Error)
			}
			if a.Page.Form != "submitted" || a.Page.Fetch != "opaque" || a.Page.Blob != "opaque" {
				t.Fatalf("the page did not make its attempts: %+v", a.Page)
			}
			if a.Page.WebSocket != "refused" {
				t.Errorf("the page's WebSocket was %s", a.Page.WebSocket)
			}
			posts := 0
			for _, r := range a.Responses {
				if r.Method != http.MethodPost {
					continue
				}
				posts++
				if r.Status != http.StatusForbidden {
					t.Errorf("POST %s from the page = %d, want 403", r.URL, r.Status)
				}
			}
			if posts != 3 {
				t.Errorf("the browser recorded %d POSTs to the hub, want the form and both fetches: %+v", posts, a.Responses)
			}
		})
	}

	t.Run("the dashboard itself still adds a task and saves a setting", func(t *testing.T) {
		if !got.Dashboard.Added || !got.Dashboard.SettingSaved {
			t.Errorf("dashboard = %+v", *got.Dashboard)
		}
	})

	t.Run("a name the hub does not answer to gets 421", func(t *testing.T) {
		if got.Rebound.Status != http.StatusMisdirectedRequest || !strings.Contains(got.Rebound.Text, "MISDIRECTED_REQUEST") {
			t.Errorf("rebind.test answered %d:\n%s", got.Rebound.Status, got.Rebound.Text)
		}
	})

	// The hub, not the browser, is the witness to what was written.
	t.Run("nothing the pages sent was written", func(t *testing.T) {
		ps, err := state.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		dashboardTask := false
		if ps.Plan != nil {
			for _, task := range ps.Plan.Tasks {
				if strings.HasPrefix(task.Title, "pwned") {
					t.Errorf("a forged request added %q", task.Title)
				}
				if task.Title == "Added by the dashboard itself" {
					dashboardTask = true
				}
			}
		}
		if !dashboardTask {
			t.Error("the dashboard's own task is not in the plan")
		}
	})

	t.Run("each refusal was counted and audited", func(t *testing.T) {
		after := hubmetrics.Default.Gather()
		for reason, min := range map[string]float64{"same_site": 3, "cross_site": 3, "foreign_origin": 2, "unknown_host": 1} {
			delta := counterValue(t, after, "cloop_cross_origin_refusals_total", `reason="`+reason+`"`) -
				counterValue(t, metricsBefore, "cloop_cross_origin_refusals_total", `reason="`+reason+`"`)
			if delta < min {
				t.Errorf("%s refusals rose by %v, want at least %v", reason, delta, min)
			}
		}
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionRequestOriginRefused)})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) < 8 {
			t.Errorf("%d request.origin_refused rows, want one for each of the 8 attempts", len(rows))
		}
	})
}
