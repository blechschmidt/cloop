package ui

// Adversarial dashboard tests (Task 20188).
//
// The suites already in this package assert that each handler does its job
// when asked politely. These ask what happens when it is not: an unbounded
// date window, a mutating verb on a read-only route, a negative duration, a
// task that depends on itself, a project root pointing at /etc.
//
// Nine of these were run against the pre-fix tree (bda010f) and observed to
// fail, so each pins a defect that actually existed rather than describing
// behaviour that already held — including a 109,562,327-byte response to a
// 60-byte request and a 200 OK from DELETE /api/projects. Where a fix has a
// natural sibling in the codebase — handleMaxParallelSet's bounds check,
// handleSteps' pagination clamp — the test asserts the outlier now matches it.
//
// The three suites marked as characterization tests are the exception: they
// cover config routes that had no test at all but whose validation was
// already correct. They are here because unpinned correctness is how
// handleStepTimeoutSet drifted away from its siblings in the first place.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// rawJSON issues a request with a JSON body and returns the status and the
// decoded body without failing the test on a non-200 — these tests are about
// the rejections, so the status is the assertion.
func rawJSON(t *testing.T, ts *httptest.Server, method, path string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body for %s %s: %v", method, path, err)
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out) // error bodies may not be JSON
	return resp.StatusCode, out
}

// TestAnalyticsBoundsTheDateWindow pins the fix for an unauthenticated-read
// amplification bug: parseDay validated only that "from"/"to" were parseable
// dates, never how far apart they were. time.Parse accepts years 0000-9999,
// so ?from=0001-01-01&to=9999-12-31 drove a ~3.65M-iteration loop building a
// dateLabels slice that then sized three more allocations per provider.
//
// Measured before the fix: a 60-byte request returned a 109 MB body in ~2s,
// at the *read* permission — the lowest role on the hub. A handful of
// concurrent requests OOM the daemon.
func TestAnalyticsBoundsTheDateWindow(t *testing.T) {
	dir := setupProjectDir(t, "analytics window", nil)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Get(ts.URL + "/api/analytics?from=0001-01-01&to=9999-12-31")
	if err != nil {
		t.Fatalf("GET /api/analytics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read analytics body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/analytics returned HTTP %d, want 200", resp.StatusCode)
	}

	// The window clamp is what keeps this bounded; 1 MB is far above a
	// legitimate response (a normal month is ~1.5 KB) and far below the
	// 109 MB the unclamped loop produced.
	if len(body) > 1<<20 {
		t.Errorf("analytics response is %d bytes for an 8000-year window; "+
			"the date range must be clamped (see maxAnalyticsWindowDays)", len(body))
	}

	var out struct {
		CostTrend struct {
			Labels []string `json:"labels"`
		} `json:"cost_trend"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode analytics: %v", err)
	}
	if n := len(out.CostTrend.Labels); n > maxAnalyticsWindowDays {
		t.Errorf("cost_trend has %d day labels, want <= %d", n, maxAnalyticsWindowDays)
	}
	if len(out.CostTrend.Labels) == 0 {
		t.Error("cost_trend has no day labels; the clamp must still return a usable window")
	}
}

// TestAnalyticsAcceptsOrdinaryWindows guards the clamp against over-reach:
// a normal request must be unaffected.
func TestAnalyticsAcceptsOrdinaryWindows(t *testing.T) {
	dir := setupProjectDir(t, "analytics normal", nil)
	ts := newTestServer(t, dir, nil)

	out := apiGET(t, ts, "/api/analytics?from=2026-01-01&to=2026-01-31")
	trend, ok := out["cost_trend"].(map[string]interface{})
	if !ok {
		t.Fatalf("cost_trend missing from analytics response: %v", out)
	}
	labels, _ := trend["labels"].([]interface{})
	if len(labels) != 31 {
		t.Errorf("January 2026 produced %d day labels, want 31 — the clamp "+
			"must not shrink ordinary windows", len(labels))
	}
}

// TestIsSafeProjectRootRejectsSystemPaths covers the guard standing in front
// of os.RemoveAll in handleProjectDelete(?delete_root=true).
//
// The original guard rejected only "", relative paths, "/", "." and $HOME —
// so /etc, /usr, /var and /home all passed as "safe" targets for recursive
// deletion. Combined with POST /api/projects/new (which accepted any
// directory, and whose MkdirAll returns nil for a path that already exists),
// two project.write calls were an arbitrary-directory-deletion primitive.
//
// The predicate had no test at all before this one.
func TestIsSafeProjectRootRejectsSystemPaths(t *testing.T) {
	cases := []struct {
		path string
		want bool
		why  string
	}{
		// Pre-existing rejections — kept as regression coverage.
		{"", false, "empty"},
		{"relative/path", false, "not absolute"},
		{"/", false, "filesystem root"},

		// Critical subtrees: never a project root, at any depth.
		{"/etc", false, "system config"},
		{"/etc/cloop", false, "inside /etc"},
		{"/usr", false, "system binaries"},
		{"/usr/local/lib/x", false, "inside /usr"},
		{"/bin", false, "system binaries"},
		{"/sbin/x", false, "inside /sbin"},
		{"/boot", false, "boot partition"},
		{"/dev/shm/x", false, "device tree"},
		{"/proc/1", false, "procfs"},
		{"/sys/kernel", false, "sysfs"},
		{"/lib/x", false, "shared libraries"},

		// A bare top-level directory is never a project root either, even
		// where its children legitimately are.
		{"/var", false, "bare top-level dir"},
		{"/home", false, "bare top-level dir"},
		{"/tmp", false, "bare top-level dir"},
		{"/opt", false, "bare top-level dir"},

		// Legitimate project roots must keep working — /var/lib/cloop is
		// HOME in the packaged hub image (docker-compose.yml), and the
		// Helm chart mounts state under it.
		{"/var/lib/cloop/projects/demo", true, "packaged hub project path"},
		{"/home/alice/code/proj", true, "developer checkout"},
		{"/tmp/cloop-test-123", true, "test scratch dir"},
		{"/opt/cloop/work/proj", true, "operator-chosen root"},
		{"/srv/projects/api", true, "operator-chosen root"},
	}
	for _, c := range cases {
		t.Run(c.path+" ("+c.why+")", func(t *testing.T) {
			if got := isSafeProjectRoot(c.path); got != c.want {
				t.Errorf("isSafeProjectRoot(%q) = %v, want %v — %s", c.path, got, c.want, c.why)
			}
		})
	}
}

// TestIsSafeProjectRootRejectsHome pins the $HOME rejection against the
// running user's actual home rather than a hard-coded path.
func TestIsSafeProjectRootRejectsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	if isSafeProjectRoot(home) {
		t.Errorf("isSafeProjectRoot(%q) = true, want false — $HOME itself is never a project root", home)
	}
	// ...but a project *inside* home is fine.
	if sub := filepath.Join(home, "cloop-projects", "demo"); !isSafeProjectRoot(sub) {
		t.Errorf("isSafeProjectRoot(%q) = false, want true — projects under $HOME are legitimate", sub)
	}
}

// TestProjectCreateRejectsSystemDirectories closes the other half of the
// chain above. POST /api/projects/new ran filepath.Abs + os.MkdirAll on the
// caller's string with no confinement whatsoever, so a relative path escaped
// via the server's cwd ("../../../../tmp/x") and an absolute one landed
// wherever it pointed. Creation and deletion now share one predicate.
func TestProjectCreateRejectsSystemDirectories(t *testing.T) {
	dir := setupProjectDir(t, "project create guard", nil)
	ts := newTestServer(t, dir, nil)

	for _, target := range []string{"/etc/cloop-adversarial-probe", "/usr/cloop-probe", "/var", "/"} {
		t.Run(target, func(t *testing.T) {
			status, body := rawJSON(t, ts, http.MethodPost, "/api/projects/new", map[string]interface{}{
				"goal": "probe",
				"dir":  target,
			})
			if status != http.StatusBadRequest {
				t.Errorf("POST /api/projects/new dir=%q returned HTTP %d, want 400: %v", target, status, body)
			}
			if _, err := os.Stat("/etc/cloop-adversarial-probe"); err == nil {
				t.Errorf("handler created %q on the host filesystem", "/etc/cloop-adversarial-probe")
			}
		})
	}
}

// TestStepTimeoutRejectsOutOfRangeDurations pins the fix for the outlier
// among the three /api/options/* setters: handleMaxParallelSet and
// handleTaskTimeoutSet both range-check, while handleStepTimeoutSet checked
// only that time.ParseDuration succeeded.
//
// "-1h" parses cleanly, was persisted to config.yaml, and flowed through
// cmd/run.go into provider.Options.Timeout. The providers special-case only
// zero ("use the default"), so a negative value reached context.WithTimeout
// and produced an already-expired context: every provider call in the
// project failed instantly with "context deadline exceeded", with nothing in
// the UI explaining why.
func TestStepTimeoutRejectsOutOfRangeDurations(t *testing.T) {
	dir := setupProjectDir(t, "step timeout bounds", nil)
	ts := newTestServer(t, dir, nil)

	rejected := []struct{ value, why string }{
		{"-1h", "negative durations expire the context immediately"},
		{"-1s", "negative durations expire the context immediately"},
		{"100000h", "absurdly long timeouts defeat the watchdog"},
		{"banana", "unparseable"},
	}
	for _, c := range rejected {
		t.Run("reject "+c.value, func(t *testing.T) {
			status, body := rawJSON(t, ts, http.MethodPost, "/api/options/step-timeout",
				map[string]interface{}{"value": c.value})
			if status != http.StatusBadRequest {
				t.Errorf("step-timeout %q returned HTTP %d, want 400 (%s): %v", c.value, status, c.why, body)
			}
		})
	}

	accepted := []string{"", "0", "10m", "1h30m", "45s"}
	for _, v := range accepted {
		t.Run("accept "+v, func(t *testing.T) {
			status, body := rawJSON(t, ts, http.MethodPost, "/api/options/step-timeout",
				map[string]interface{}{"value": v})
			if status != http.StatusOK {
				t.Errorf("step-timeout %q returned HTTP %d, want 200: %v", v, status, body)
			}
		})
	}
}

// TestReadOnlyRoutesRejectMutatingMethods covers a whole class at once.
//
// Ten routes are registered without a method prefix and carry Perm: read.
// http.ServeMux therefore routes *every* verb to them, and none of the
// handlers checked r.Method — so DELETE /api/state returned 200 and the full
// state, and DELETE /api/projects returned 200 and the project list. The
// last is the sharp one: DELETE /api/projects/{idx} really does delete, so a
// client that drops the trailing index got a cheerful 200 from a listing
// instead of an error.
//
// It is also an access-control smell in its own right: a mutating verb was
// being authorized by the *read* permission. The guard now lives in gate(),
// ahead of the authz short-circuit so it applies in single-tenant mode too.
func TestReadOnlyRoutesRejectMutatingMethods(t *testing.T) {
	dir := setupProjectDir(t, "method guard", nil)
	ts := newTestServer(t, dir, nil)

	readOnly := []string{
		"/api/state",
		"/api/steps",
		"/api/event-history",
		"/api/livelog",
		"/api/timeline",
		"/api/chat/history",
		"/api/suggest/status",
		"/api/projects",
	}
	for _, path := range readOnly {
		for _, method := range []string{http.MethodDelete, http.MethodPut} {
			t.Run(method+" "+path, func(t *testing.T) {
				status, _ := rawJSON(t, ts, method, path, nil)
				if status != http.StatusMethodNotAllowed {
					t.Errorf("%s %s returned HTTP %d, want 405 — a mutating verb "+
						"must never be served by a read-only route", method, path, status)
				}
			})
		}
		t.Run("GET "+path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusMethodNotAllowed {
				t.Errorf("GET %s returned 405 — the guard must not block safe methods", path)
			}
		})
	}
}

// TestProviderCallsEchoesEffectivePagination pins a client-visible
// pagination bug. The handler parsed offset/limit with a discarded error and
// echoed the *request* values back, while pkg/statedb silently clamped the
// values it actually used. A client paginating off the echoed numbers — as
// the dashboard does — either loops forever or skips pages.
//
// handleSteps next door does this correctly (n >= 0 / n > 0, capped); this
// asserts the outlier now matches.
func TestProviderCallsEchoesEffectivePagination(t *testing.T) {
	dir := setupProjectDir(t, "provider call pagination", nil)
	ts := newTestServer(t, dir, nil)

	t.Run("negative offset", func(t *testing.T) {
		out := apiGET(t, ts, "/api/provider-calls?offset=-100")
		if got := out["offset"].(float64); got != 0 {
			t.Errorf("offset echoed as %v for ?offset=-100, want 0 (the value actually used)", got)
		}
	})
	t.Run("oversized limit", func(t *testing.T) {
		out := apiGET(t, ts, "/api/provider-calls?limit=99999999")
		got := out["limit"].(float64)
		if got > maxProviderCallsLimit {
			t.Errorf("limit echoed as %v for ?limit=99999999, want <= %d (the value actually used)",
				got, maxProviderCallsLimit)
		}
	})
	t.Run("garbage is not silently zero", func(t *testing.T) {
		out := apiGET(t, ts, "/api/provider-calls?limit=abc")
		if got := out["limit"].(float64); got <= 0 {
			t.Errorf("limit echoed as %v for ?limit=abc, want the default page size", got)
		}
	})
}

// TestQueueLimitHonoursDocumentedCap: handleQueue's doc comment promises
// "default 200, hard cap 1000" and the handler implemented neither cap. The
// only real bound was 5000, buried in pkg/taskqueue.
func TestQueueLimitHonoursDocumentedCap(t *testing.T) {
	dir := setupProjectDir(t, "queue cap", nil)
	ts := newTestServer(t, dir, nil)

	out := apiGET(t, ts, "/api/queue?limit=99999999")
	limit, ok := out["limit"].(float64)
	if !ok {
		t.Fatalf("queue response has no limit field: %v", out)
	}
	if limit > maxQueueLimit {
		t.Errorf("queue echoed limit %v, want <= %d as documented", limit, maxQueueLimit)
	}
}

// TestTaskDependsOnRejectsInvalidReferences pins a silent run-stopper.
//
// handleTaskAdd, handleTaskEdit and handlePutTask all assigned the caller's
// []int verbatim. A task depending on itself is never ready and never
// permanently blocked, so orchestrator's NextTask() returns nil, the run loop
// breaks, and the run ends early with tasks still pending and no diagnostic.
// A dangling id (9999) does the same thing.
func TestTaskDependsOnRejectsInvalidReferences(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "first", Status: pm.TaskPending},
		{ID: 2, Title: "second", Status: pm.TaskPending},
	}
	dir := setupProjectDir(t, "deps validation", tasks)
	ts := newTestServer(t, dir, nil)

	bad := []struct {
		name string
		deps []int
	}{
		{"self reference", []int{1}},
		{"dangling id", []int{9999}},
		{"negative id", []int{-3}},
		{"self among valid", []int{2, 1}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			status, body := rawJSON(t, ts, http.MethodPost, "/api/task/edit", map[string]interface{}{
				"id":         1,
				"depends_on": c.deps,
			})
			if status != http.StatusBadRequest {
				t.Errorf("edit task 1 with depends_on=%v returned HTTP %d, want 400: %v",
					c.deps, status, body)
			}
		})
	}

	t.Run("valid dependency is accepted", func(t *testing.T) {
		status, body := rawJSON(t, ts, http.MethodPost, "/api/task/edit", map[string]interface{}{
			"id":         1,
			"depends_on": []int{2},
		})
		if status != http.StatusOK {
			t.Errorf("edit task 1 with depends_on=[2] returned HTTP %d, want 200: %v", status, body)
		}
	})

	t.Run("clearing dependencies is accepted", func(t *testing.T) {
		status, body := rawJSON(t, ts, http.MethodPost, "/api/task/edit", map[string]interface{}{
			"id":         1,
			"depends_on": []int{},
		})
		if status != http.StatusOK {
			t.Errorf("clearing depends_on returned HTTP %d, want 200: %v", status, body)
		}
	})
}

// TestTaskDependsOnValidatedOnEveryWritePath makes sure the validation is not
// bolted onto one handler while the other two stay open — the shape of bug
// this codebase has repeated before (mergeExternalTasks, resolveWorkDir).
func TestTaskDependsOnValidatedOnEveryWritePath(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "first", Status: pm.TaskPending},
		{ID: 2, Title: "second", Status: pm.TaskPending},
	}
	dir := setupProjectDir(t, "deps every path", tasks)
	ts := newTestServer(t, dir, nil)

	t.Run("PUT /api/tasks/{id}", func(t *testing.T) {
		status, body := rawJSON(t, ts, http.MethodPut, "/api/tasks/1", map[string]interface{}{
			"depends_on": []int{1},
		})
		if status != http.StatusBadRequest {
			t.Errorf("PUT self-dependency returned HTTP %d, want 400: %v", status, body)
		}
	})

	t.Run("POST /api/task/add", func(t *testing.T) {
		status, body := rawJSON(t, ts, http.MethodPost, "/api/task/add", map[string]interface{}{
			"title":      "new task",
			"depends_on": []int{4242},
		})
		if status != http.StatusBadRequest {
			t.Errorf("add with dangling dependency returned HTTP %d, want 400: %v", status, body)
		}
	})
}

// TestPresenceDisplayNameIsTruncatedNotDropped covers a helper misuse.
//
// boundedQueryString returns "" for oversized input — correct for a *filter*,
// where "too long" should mean "absent" and fall through to the handler's
// zero-value path. But the presence broadcast used it on a display name,
// where "" discards the animal-name fallback assigned two lines earlier and
// broadcasts a blank label to every connected client. A display name is a
// label: it wants truncation.
func TestPresenceDisplayNameIsTruncatedNotDropped(t *testing.T) {
	long := strings.Repeat("Wolfeschlegelsteinhausenbergerdorff", 5) // 170 chars
	got := boundedDisplayName(long, maxPresenceFieldLen)
	if got == "" {
		t.Fatal("boundedDisplayName returned empty for a long name; presence would show a blank label")
	}
	if len(got) > maxPresenceFieldLen {
		t.Errorf("boundedDisplayName returned %d chars, want <= %d", len(got), maxPresenceFieldLen)
	}
	if !strings.HasPrefix(long, strings.TrimSuffix(got, "…")) {
		t.Errorf("boundedDisplayName(%q...) = %q, want a prefix of the input", long[:20], got)
	}

	t.Run("short names pass through unchanged", func(t *testing.T) {
		if got := boundedDisplayName("Aiden", maxPresenceFieldLen); got != "Aiden" {
			t.Errorf("boundedDisplayName(%q) = %q, want it unchanged", "Aiden", got)
		}
	})
	t.Run("empty stays empty so the caller's fallback wins", func(t *testing.T) {
		if got := boundedDisplayName("", maxPresenceFieldLen); got != "" {
			t.Errorf("boundedDisplayName(\"\") = %q, want \"\"", got)
		}
	})
	t.Run("multi-byte names are not cut mid-rune", func(t *testing.T) {
		got := boundedDisplayName(strings.Repeat("日本語", 40), maxPresenceFieldLen)
		if !utf8.ValidString(got) {
			t.Errorf("boundedDisplayName produced invalid UTF-8: %q", got)
		}
	})
}

// TestAnalyticsRejectsInvertedRange: "to" before "from" produced an empty
// label set that the handler then papered over with today's date. Assert the
// window is normalised rather than silently mismatching the datasets.
func TestAnalyticsRejectsInvertedRange(t *testing.T) {
	dir := setupProjectDir(t, "inverted range", nil)
	ts := newTestServer(t, dir, nil)

	out := apiGET(t, ts, "/api/analytics?from=2026-06-01&to=2026-01-01")
	trend, ok := out["cost_trend"].(map[string]interface{})
	if !ok {
		t.Fatalf("cost_trend missing: %v", out)
	}
	labels, _ := trend["labels"].([]interface{})
	if len(labels) == 0 {
		t.Error("inverted range produced no day labels")
	}
	// Every dataset must be the same width as the label axis, or the chart
	// silently misaligns costs against dates.
	datasets, _ := trend["datasets"].([]interface{})
	for i, d := range datasets {
		ds, _ := d.(map[string]interface{})
		vals, _ := ds["values"].([]interface{})
		if len(vals) != len(labels) {
			t.Errorf("dataset %d has %d values but there are %d labels", i, len(vals), len(labels))
		}
	}
}

// TestStateHandlerSurvivesHostileProjectIdx sweeps the project_idx parameter
// every handler resolves through resolveWorkDir. None of these may panic or
// serve another tenant's project.
func TestStateHandlerSurvivesHostileProjectIdx(t *testing.T) {
	primary := setupProjectDir(t, "primary", nil)
	secondary := setupProjectDir(t, "secondary", nil)
	ts := newTestServer(t, primary, []string{secondary})

	for _, idx := range []string{"-1", "999999", "abc", "", "9223372036854775808", "1e10", "0x1", "٣"} {
		t.Run("project_idx="+idx, func(t *testing.T) {
			resp, err := http.Get(ts.URL + "/api/state?project_idx=" + idx)
			if err != nil {
				t.Fatalf("GET /api/state?project_idx=%s: %v", idx, err)
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode >= 500 {
				t.Errorf("project_idx=%q returned HTTP %d — a malformed index must not 5xx",
					idx, resp.StatusCode)
			}
		})
	}
}

// The three suites below are characterization tests for config-mutation
// routes that had no coverage at all. Their validation is correct today; it
// was simply unpinned, which is how handleStepTimeoutSet drifted away from
// its two siblings in the first place. Nothing here failed pre-fix — these
// exist so the next divergence is caught by a test rather than by a run
// mysteriously failing every provider call.

func TestBudgetGlobalSaveValidatesInput(t *testing.T) {
	dir := setupProjectDir(t, "budget validation", nil)
	ts := newTestServer(t, dir, nil)

	rejected := []struct {
		name string
		body map[string]interface{}
	}{
		{"negative usd limit", map[string]interface{}{"daily_usd_limit": -1, "alert_threshold_pct": 80}},
		{"negative token limit", map[string]interface{}{"daily_token_limit": -1, "alert_threshold_pct": 80}},
		{"threshold above max", map[string]interface{}{"alert_threshold_pct": config.AlertThresholdMax + 1}},
		{"threshold below min", map[string]interface{}{"alert_threshold_pct": config.AlertThresholdMin - 1}},
	}
	for _, c := range rejected {
		t.Run(c.name, func(t *testing.T) {
			status, body := rawJSON(t, ts, http.MethodPut, "/api/budget/global", c.body)
			if status != http.StatusBadRequest {
				t.Errorf("PUT /api/budget/global %v returned HTTP %d, want 400: %v", c.body, status, body)
			}
		})
	}

	t.Run("valid budget is accepted", func(t *testing.T) {
		status, body := rawJSON(t, ts, http.MethodPut, "/api/budget/global", map[string]interface{}{
			"daily_usd_limit": 25.5, "daily_token_limit": 1000000, "alert_threshold_pct": 80,
		})
		if status != http.StatusOK {
			t.Errorf("PUT /api/budget/global returned HTTP %d, want 200: %v", status, body)
		}
	})
}

func TestClaudeCodeLimitsSaveValidatesPercentages(t *testing.T) {
	dir := setupProjectDir(t, "cc limits validation", nil)
	ts := newTestServer(t, dir, nil)

	for _, pct := range []float64{-1, 100.5, 1e9} {
		t.Run(fmt.Sprintf("reject %v", pct), func(t *testing.T) {
			status, body := rawJSON(t, ts, http.MethodPut, "/api/claudecode-limits",
				map[string]interface{}{"max_weekly_pct": pct})
			if status != http.StatusBadRequest {
				t.Errorf("max_weekly_pct=%v returned HTTP %d, want 400: %v", pct, status, body)
			}
		})
	}
	t.Run("valid percentages accepted", func(t *testing.T) {
		status, body := rawJSON(t, ts, http.MethodPut, "/api/claudecode-limits", map[string]interface{}{
			"max_weekly_pct": 80, "max_five_hour_pct": 50,
			"max_weekly_opus_pct": 25, "max_weekly_sonnet_pct": 60,
		})
		if status != http.StatusOK {
			t.Errorf("valid percentages returned HTTP %d, want 200: %v", status, body)
		}
	})
}

func TestTaskTimeoutSetValidatesRange(t *testing.T) {
	dir := setupProjectDir(t, "task timeout validation", nil)
	ts := newTestServer(t, dir, nil)

	for _, v := range []int{-1, config.OrchestratorTaskTimeoutMinutesUpper + 1} {
		t.Run(fmt.Sprintf("reject %d", v), func(t *testing.T) {
			status, body := rawJSON(t, ts, http.MethodPost, "/api/options/task-timeout",
				map[string]interface{}{"value": v})
			if status != http.StatusBadRequest {
				t.Errorf("task-timeout %d returned HTTP %d, want 400: %v", v, status, body)
			}
		})
	}
	// 0 is the documented sentinel for "use the process-wide default".
	for _, v := range []int{0, config.OrchestratorTaskTimeoutMinutesLower, 120} {
		t.Run(fmt.Sprintf("accept %d", v), func(t *testing.T) {
			status, body := rawJSON(t, ts, http.MethodPost, "/api/options/task-timeout",
				map[string]interface{}{"value": v})
			if status != http.StatusOK {
				t.Errorf("task-timeout %d returned HTTP %d, want 200: %v", v, status, body)
			}
		})
	}
}

// TestStepsPaginationIsBounded sweeps the pagination parameters that
// handleSteps slices with, asserting no combination panics or returns more
// than the documented cap. handleSteps was already correct; this pins it so
// the clamp cannot regress while its siblings are being fixed.
func TestStepsPaginationIsBounded(t *testing.T) {
	dir := setupProjectDir(t, "steps pagination", nil)
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	for i := 0; i < 20; i++ {
		ps.Steps = append(ps.Steps, state.StepResult{Step: i + 1, Output: fmt.Sprintf("step %d", i)})
	}
	if err := ps.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	ts := newTestServer(t, dir, nil)

	for _, q := range []string{
		"offset=-1", "limit=-1", "offset=-1&limit=-1",
		"offset=999999", "limit=999999", "offset=0&limit=0",
		"offset=abc&limit=abc", "limit=99999999999999999999",
	} {
		t.Run(q, func(t *testing.T) {
			out := apiGET(t, ts, "/api/steps?"+q)
			steps, _ := out["steps"].([]interface{})
			if len(steps) > 500 {
				t.Errorf("?%s returned %d steps, want <= 500", q, len(steps))
			}
		})
	}
}
