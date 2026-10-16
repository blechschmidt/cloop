package ui

// The browser half of Task 20408: the dashboard, seeded with hostile strings
// everywhere a project, a workload or a peer gets to write text, driven
// through every tab and dialog the layout sweep visits with every control in
// each pressed — and nothing may run.
//
// The strings are each of the shapes a missed escape turns into code at once:
// a tag that runs script when it fails to load, an attribute break-out, the
// character reference that ended the project name's JavaScript string, a
// closing and opening script element, a javascript: URL and a line separator.
// Whatever of them ever ran would set window.__xss to the name of the field it
// was seeded in. The fields: the project's name and path, a task's title,
// description, result and captured output, tags, the device's name and labels
// and its USB inventory, a virtual executor, the features, the grant's
// subject, an access request's justification, a token's name, a quota's
// identity, the KB, the chat, the AI suggestions, the activity log, provider
// calls and a replay. Secret names and the image reference are validated by
// the hub, so they hold what it accepts.
//
// Pressing every control is the half the static gates cannot do. Under the
// hub's policy a handler that slipped back in does not run — it is a button
// that does nothing — and markup a name smuggled in does not run either; both
// leave a violation behind. So the test counts violations three ways: the
// page's own securitypolicyviolation listener, the browser's issue log, and
// the hub's report endpoint, whose counter must move by exactly the one
// violation the driver causes on purpose at the end, to prove the other zeros
// are zeros. While the crawl presses buttons the browser refuses every write
// to the hub, answering it with a hostile error message, so the page's error
// paths render one too and no press changes what the next scenario sees.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// hostile is markup, an attribute break-out, a character reference a
// JavaScript string would end at, script, a URL scheme and a line separator at
// once, labelled: if any of it ever runs it sets window.__xss to label.
func hostile(label string) string {
	set := "window.__xss='" + label + "'"
	return label + `"><img src=x onerror="` + set + `"><svg onload="` + set + `"></svg>'` +
		`>&quot;+(` + set + `)+&quot;</script><script>` + set + `</script>` +
		` javascript:` + set + " " + label
}

// hostileName is hostile for a value stored as a directory name or matched on
// screen through innerText: no '/', which a directory name cannot hold, and no
// line separator, which innerText may rewrite.
func hostileName(label string) string {
	set := "window.__xss='" + label + "'"
	return label + `"><img src=x onerror="` + set + `">&quot;+(` + set + `)+&quot;<svg onload=` + set + `>`
}

// hostileShort is hostile for a field the hub caps at 64 characters.
func hostileShort(label string) string {
	return label + `"><svg onload=window.__xss='` + label + `'>&quot;`
}

var hostileSweepStrings = sweepStrings{
	Project:       hostileName("project"),
	ProjectParent: "p</script><script>window.__xss='path'</script>/",
	HiddenProject: hostileName("hidden"),
	OtherProject:  hostileName("other"),

	TaskTitle:        hostile("title"),
	RiskTaskTitle:    hostile("risk"),
	FailedTaskTitle:  hostile("failed"),
	RunningTaskTitle: hostile("running"),
	Tag:              hostileName("tag"),
	URL:              "javascript:window.__xss='url';" + hostileName("result"),
	RepoPath:         hostile("repo"),

	Device:      hostileName("device"),
	DeviceLabel: hostile("label"),
	Virtual:     hostileShort("virtual"),
	Image:       "registry.example.com/xss/harness:1",
	Email:       hostileName("email"),
	Secret:      "xss_fixture_secret",
	TokenName:   hostileName("token"),

	ResultMarker: hostileName("result"),
	PromptMarker: hostileName("prompt"),
	ReplayOutput: hostileName("replay"),
	FeatureTitle: hostile("feature"),
	Output:       hostile("output") + "\nTASK_DONE",
	Suggestion:   hostile("suggestion"),
	UserAgent:    hostileName("agent"),
}

type xssCrawlScenario struct {
	Name     string           `json:"name"`
	Controls int              `json:"controls"`
	Pressed  int              `json:"pressed"`
	Links    int              `json:"links"`
	Reboots  int              `json:"reboots"`
	Why      []string         `json:"why"` // what each reboot waited on
	Skipped  []string         `json:"skipped"`
	CSP      []map[string]any `json:"csp"`
	Opened   []string         `json:"opened"`
	XSS      []string         `json:"xss"`
	Findings []struct {
		Kind   string `json:"kind"`
		Where  string `json:"where"`
		Detail string `json:"detail"`
	} `json:"findings"`
	Error string `json:"error"`
	MS    int    `json:"ms"`
}

type xssCrawlResults struct {
	Error     string             `json:"error"`
	Scenarios []xssCrawlScenario `json:"scenarios"`
	Openers   []string           `json:"openers"`
	Control   *xssCrawlScenario  `json:"control"`
	CSPIssues []struct {
		Scenario  string `json:"scenario"`
		Directive string `json:"directive"`
		Blocked   string `json:"blocked"`
		Type      string `json:"type"`
	} `json:"csp_issues"`
	Blocked    int `json:"blocked"`
	Exceptions []struct {
		Scenario string `json:"scenario"`
		Message  string `json:"message"`
	} `json:"exceptions"`
	ElapsedMS int `json:"elapsed_ms"`
	// AtError is what the page had recorded when the driver failed.
	AtError *struct {
		CSP []map[string]any `json:"csp"`
		XSS *string          `json:"xss"`
	} `json:"at_error"`
}

func deref(s *string) string {
	if s == nil {
		return "unset"
	}
	return *s
}

// runXSSCrawl runs the layout driver in mode "xss" against base with cfg and
// decodes what it found. A driver that fails says what the page had recorded:
// a hostile string that ran on the way in is the likeliest reason it cannot
// reach a scenario at all.
func runXSSCrawl(t *testing.T, node, chrome, base string, cfg map[string]any) xssCrawlResults {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "xss-sweep.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Bounded, so a stalled Chrome cannot hold the package to its timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/layout_sweep_browser.js"), chrome, base, cfgPath).Output()
	if os.Getenv("XSS_SWEEP_DEBUG") != "" {
		_ = os.WriteFile(filepath.Join(os.TempDir(), "xss-sweep-out.json"), out, 0o644)
	}
	var got xssCrawlResults
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%.4000s\nstderr:\n%s\n%s", err, jerr, out, stderr,
			blockedGoroutines())
	}
	if got.Error != "" {
		if a := got.AtError; a != nil && (a.XSS != nil || len(a.CSP) > 0) {
			t.Errorf("when the driver failed, window.__xss was %v and the page had recorded violations %v",
				deref(a.XSS), a.CSP)
		}
		t.Fatalf("the driver failed: %s", got.Error)
	}
	return got
}

// blockedGoroutines is the stacks of this process's goroutines in cloop code
// that have been blocked for a minute or more. The hub the crawl drives runs
// in this process, so when the crawl stalls because a request never returns,
// the breadcrumbs say where the page was and these say what the handler is
// waiting on: run 38879936287 stalled from the Secrets tab on and said no
// more.
func blockedGoroutines() string {
	buf := make([]byte, 16<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var b strings.Builder
	b.WriteString("goroutines blocked for a minute or more:\n")
	for _, g := range strings.Split(string(buf), "\n\n") {
		header, _, _ := strings.Cut(g, "\n")
		if !strings.Contains(header, " minutes]") || !strings.Contains(g, "github.com/blechschmidt/cloop/") {
			continue
		}
		if b.Len()+len(g) > 64<<10 {
			b.WriteString("… more, cut\n")
			break
		}
		b.WriteString(g)
		b.WriteString("\n\n")
	}
	return b.String()
}

// cspReported sums cloop_csp_violations_total over every label.
func cspReported() float64 {
	sum := 0.0
	for _, line := range strings.Split(hubmetrics.Default.Gather(), "\n") {
		if !strings.HasPrefix(line, "cloop_csp_violations_total{") {
			continue
		}
		var v float64
		if i := strings.LastIndexByte(line, ' '); i >= 0 {
			if err := json.Unmarshal([]byte(line[i+1:]), &v); err == nil {
				sum += v
			}
		}
	}
	return sum
}

// skipCrawlUnderRace keeps the hostile-strings crawls out of CI's race step.
// They press every control of the dashboard in Chrome, two minutes and more,
// and under the race detector on a slow runner that took pkg/ui past the
// step's 30-minute package timeout (CI run 38119330983). What they test is
// the browser's behaviour, which the detector does not see into, so CI runs
// them in a job of their own without it (.github/workflows/ci.yml, "Hostile
// strings in a real browser"). CLOOP_XSS_CRAWL=1 runs them under -race too.
func skipCrawlUnderRace(t *testing.T) {
	t.Helper()
	if raceDetector && os.Getenv("CLOOP_XSS_CRAWL") == "" {
		t.Skip("the hostile-strings crawl runs without -race, in a CI job of its own; " +
			"set CLOOP_XSS_CRAWL=1 to run it under the race detector")
	}
}

func TestHostileStrings_EveryControlInBrowser(t *testing.T) {
	skipCrawlUnderRace(t)
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot press the dashboard's controls")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	ts, _, fx := seedSweepHub(t, hostileSweepStrings)
	before := cspReported()

	var vps []layoutViewport
	for _, v := range layoutViewports {
		if v.Name == "phone-390" || v.Name == "desktop-1280" {
			vps = append(vps, v)
		}
	}
	got := runXSSCrawl(t, node, chrome, ts.URL, map[string]any{
		"mode": "xss", "viewports": vps, "tabs": layoutTabs, "allow": layoutScrollAllowlist,
		"fixture": fx, "hostile": hostile("typed"), "max_presses": 80,
	})
	pressed, controls := 0, 0
	for _, s := range got.Scenarios {
		pressed += s.Pressed
		controls += s.Controls
	}
	t.Logf("pressed %d of %d controls in %d scenarios in %.1fs; %d writes refused",
		pressed, controls, len(got.Scenarios), float64(got.ElapsedMS)/1000, got.Blocked)

	t.Run("every tab and dialog was crawled", func(t *testing.T) {
		want := map[string]bool{"header": true}
		for _, tab := range layoutTabs {
			want["tab:"+tab] = true
		}
		for _, k := range got.Openers {
			want["dialog:"+k] = true
		}
		for _, s := range got.Scenarios {
			if s.Error != "" {
				t.Errorf("%s: %s", s.Name, s.Error)
				continue
			}
			if s.Pressed == 0 && s.Controls > 0 {
				t.Errorf("%s: none of its %d controls was pressed", s.Name, s.Controls)
			}
			delete(want, s.Name)
		}
		if len(want) > 0 {
			t.Errorf("never crawled: %s", strings.Join(sortedSet(want), ", "))
		}
		// A floor, so a crawl that stopped finding controls cannot pass.
		if pressed < 400 {
			t.Errorf("pressed only %d controls; the dashboard has well over that many", pressed)
		}
	})

	t.Run("nothing ran", func(t *testing.T) {
		for _, s := range got.Scenarios {
			if len(s.XSS) > 0 {
				t.Errorf("%s: window.__xss was set by %v — the string seeded as that field ran as code", s.Name, s.XSS)
			}
			for _, u := range s.Opened {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(u)), "javascript:") {
					t.Errorf("%s: window.open(%q)", s.Name, u)
				}
			}
		}
	})

	t.Run("the policy blocked nothing", func(t *testing.T) {
		for _, s := range got.Scenarios {
			for _, v := range s.CSP {
				t.Errorf("%s: the page reported a violation: %v", s.Name, v)
			}
		}
		for _, i := range got.CSPIssues {
			if i.Scenario != "control" {
				t.Errorf("%s: the browser logged a policy violation: %s blocked %q (%s)", i.Scenario, i.Directive, i.Blocked, i.Type)
			}
		}
	})

	t.Run("no markup carries code", func(t *testing.T) {
		// A dialog's markup stays in the document once drawn, so one finding
		// recurs in every later scenario: reported once, where it was first seen.
		seen := map[string]bool{}
		for _, s := range got.Scenarios {
			for _, f := range s.Findings {
				key := f.Kind + "|" + f.Where + "|" + f.Detail
				if seen[key] {
					continue
				}
				seen[key] = true
				t.Errorf("%s: %s at %s: %s", s.Name, f.Kind, f.Where, f.Detail)
			}
		}
	})

	t.Run("no control names a missing action", func(t *testing.T) {
		for _, e := range got.Exceptions {
			if strings.Contains(e.Message, "no action is registered") {
				t.Errorf("%s: %s", e.Scenario, e.Message)
			}
		}
	})

	t.Run("the detectors see the one violation caused on purpose", func(t *testing.T) {
		c := got.Control
		if c == nil {
			t.Fatal("the driver ran no control")
		}
		if len(c.XSS) > 0 {
			t.Fatalf("the injected inline handler ran (%v): the policy did not stop it", c.XSS)
		}
		if len(c.CSP) != 1 || c.CSP[0]["directive"] != "script-src-attr" {
			t.Errorf("the page recorded %v for the injected handler, want one script-src-attr violation", c.CSP)
		}
		seen := false
		for _, i := range got.CSPIssues {
			seen = seen || i.Scenario == "control"
		}
		if !seen {
			t.Error("the browser's issue log did not record the injected handler")
		}
		// And the hub was told: the browser sends the report on its own
		// schedule, so wait for it — and then for nothing else to be there.
		deadline := time.Now().Add(15 * time.Second)
		for cspReported()-before < 1 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if d := cspReported() - before; d != 1 {
			t.Errorf("the hub counted %v violation report(s) over the run, want exactly the control's one", d)
		}
	})

	if testing.Verbose() {
		for _, e := range got.Exceptions {
			t.Logf("uncaught in %s: %s", e.Scenario, e.Message)
		}
		for _, s := range got.Scenarios {
			t.Logf("%s: pressed %d of %d in %dms, %d reboots, %d skipped %v", s.Name, s.Pressed, s.Controls,
				s.MS, s.Reboots, len(s.Skipped), s.Skipped)
			for _, why := range s.Why {
				t.Logf("%s: rebooted: %s", s.Name, why)
			}
		}
	}
}

// TestHostileMemberIdentities_InBrowser covers the strings the hub-wide crawl
// cannot reach, because they exist only with sign-on: who a project is shared
// with, why, who shared it, and the signed-in user's own display name. Each
// is chosen by an identity provider's claims or by the member who typed it.
func TestHostileMemberIdentities_InBrowser(t *testing.T) {
	skipCrawlUnderRace(t)
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot press the dashboard's controls")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv("HOME", t.TempDir())
	f := newMemberFixture(t, true)
	members := f.membersURL(t, f.alice)
	// Identities admit anything but whitespace, so the markup is written
	// without any.
	noSpace := func(label string) string {
		return `"><img/src=x/onerror=window.__xss='` + label + `'>&quot;+(window.__xss='` + label + `')+&quot;`
	}
	for _, m := range []map[string]any{
		{"identity": "sub:" + noSpace("member"), "role": "viewer", "reason": hostile("reason")},
		{"identity": "x" + noSpace("mail") + "@example.com", "role": "operator", "reason": hostile("why")},
	} {
		b, _ := json.Marshal(m)
		req, _ := http.NewRequest(http.MethodPost, f.ts.URL+members, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := f.alice.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("adding %v = %d", m["identity"], resp.StatusCode)
		}
	}
	// alice again, with a display name her identity provider chose.
	f.idp.email, f.idp.sub, f.idp.name = aliceEmail, "sub-alice", hostileName("displayname")
	viewer := jarClient(t)
	login(t, viewer, f.ts)

	cfg := map[string]any{
		"mode": "xss", "viewports": []layoutViewport{layoutViewports[len(layoutViewports)-1]},
		"fixture": layoutFixture{Project: filepath.Base(f.project)},
		"hostile": hostile("typed"), "max_presses": 80,
		"cookie": sessionCookie(t, viewer, f.ts.URL),
		"scenarios": []map[string]any{{
			"name": "members", "tab": "overview", "scope": []string{"#membersSection", "header"},
			"ready": `document.querySelectorAll('#membersList [data-member]').length >= 3 && ` +
				`(document.getElementById('userChip') || {}).textContent === ` + jsQuote(hostileName("displayname")),
		}},
	}
	got := runXSSCrawl(t, node, chrome, f.ts.URL, cfg)
	if len(got.Scenarios) != 1 || got.Scenarios[0].Error != "" || got.Scenarios[0].Pressed == 0 {
		t.Fatalf("the members crawl did not run: %+v", got.Scenarios)
	}
	s := got.Scenarios[0]
	t.Logf("pressed %d of %d controls", s.Pressed, s.Controls)
	if len(s.XSS) > 0 {
		t.Errorf("window.__xss was set by %v", s.XSS)
	}
	for _, v := range s.CSP {
		t.Errorf("the page reported a violation: %v", v)
	}
	for _, f := range s.Findings {
		t.Errorf("%s at %s: %s", f.Kind, f.Where, f.Detail)
	}
	if got.Control == nil || len(got.Control.CSP) != 1 {
		t.Errorf("the control violation was not recorded: %+v", got.Control)
	}
	// The control's report came from a signed-in browser, which sends its
	// session cookie with a same-origin report: the hub names the viewer, and
	// draws on the signed-in budget for it (csp.go). The browser sends it on
	// its own schedule, so wait for it.
	actors := func() []string {
		f.logs.mu.Lock()
		defer f.logs.mu.Unlock()
		var out []string
		for _, e := range f.logs.entries {
			if e.Event == "csp_violation" {
				out = append(out, fmt.Sprint(e.Data["actor"]))
			}
		}
		return out
	}
	deadline := time.Now().Add(15 * time.Second)
	for len(actors()) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got, want := actors(), strings.ToLower(aliceEmail); len(got) != 1 || got[0] != want {
		t.Errorf("the control's report was logged under %q, want once under the signed-in viewer %q", got, want)
	}
}

// jsQuote renders s as a JavaScript string literal.
func jsQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
