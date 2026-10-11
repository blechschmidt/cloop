package ui

// The layout sweep: every dashboard tab and every dialog, laid out by real
// Chromium at phone, tablet and desktop widths and in dark mode, against a hub
// whose content is as long as real content gets (Task 20407).
//
// "A long X overflows the UI" kept coming back from users (Tasks 20142, 20300,
// 20351) because each fix measured the surface it touched and nothing else.
// testdata/domshim.js has no box model, so every overflow is invisible to the
// node gates; only an engine laying the page out at a real width can see one.
// So this measures all of it, in one browser, and asserts:
//
//   - the document never scrolls sideways, and a phone never has to zoom the
//     page out to fit it;
//   - no element's content overflows a box that clips it or does not scroll;
//   - every button and field can be brought fully onto the screen;
//   - the only boxes that scroll sideways are layoutScrollAllowlist's, each
//     with its reason.
//
// The dialogs come from testdata/layout_sweep_browser.js's OPENERS, which
// TestLayoutSweep_EveryDialogHasAnOpener holds against every openOverlay()
// call site, and the tabs from layoutTabs, which
// TestLayoutSweep_EveryTabIsSwept holds against every switchTab() target — so
// a new dialog or tab without an entry fails the gate on any runner, browser or
// not. The browser half skips when Chrome or node is missing, like every
// browser gate here; CI's runner has both.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/kb"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/suggest"
	"github.com/blechschmidt/cloop/pkg/taskqueue"
)

// layoutViewport is one emulated screen. Mobile turns on Chrome's mobile
// emulation, which is what brings meta[viewport] into play — and with it the
// shrink-to-fit zoom an overflowing phone page gets.
type layoutViewport struct {
	Name   string `json:"name"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Scale  int    `json:"scale"`
	Mobile bool   `json:"mobile"`
}

// layoutViewports: the narrowest phone still sold and the commonest one, a
// tablet in portrait, a small laptop and a common desktop.
var layoutViewports = []layoutViewport{
	{Name: "phone-320", Width: 320, Height: 568, Scale: 2, Mobile: true},
	{Name: "phone-390", Width: 390, Height: 844, Scale: 3, Mobile: true},
	{Name: "tablet-768", Width: 768, Height: 1024, Scale: 2, Mobile: true},
	{Name: "laptop-1024", Width: 1024, Height: 768, Scale: 1, Mobile: false},
	{Name: "desktop-1280", Width: 1280, Height: 800, Scale: 1, Mobile: false},
}

// layoutDarkViewport is where the sweep repeats every tab and dialog in the
// dark theme: the phone width this hub's own telemetry sees most.
const layoutDarkViewport = "phone-390"

// layoutScrollAllowed is an element meant to scroll sideways, and why. MaxWidth
// is the widest viewport it may scroll at; above it, it has to fit like
// anything else (0: it may scroll at every width).
type layoutScrollAllowed struct {
	Selector string `json:"selector"`
	MaxWidth int    `json:"max_width"`
	Reason   string `json:"-"`
}

// layoutScrollAllowlist is every box allowed to scroll sideways. Anything else
// that does is reported: a phone user cannot see a scrollbar on a box that has
// not been scrolled yet, so sideways scrolling is a decision, not a fallback.
// An entry the sweep never finds on screen fails the gate as stale.
var layoutScrollAllowlist = []layoutScrollAllowed{
	{Selector: ".table-scroll", MaxWidth: 768, Reason: "a table has as many columns as it has facts, and a phone " +
		"has room for three: it scrolls inside its own frame so the page does not, on a phone or a tablet " +
		"in portrait. Wider than that it has to fit, which is what keeps a long name from widening a " +
		"desktop table."},
	{Selector: "#tabNav", MaxWidth: 768, Reason: "a tablet in portrait gets the tab strip rather than the " +
		"phone's menu, and the strip scrolls with its scrollbar hidden: wrapped, twenty-one tabs take " +
		"three header rows. Above 768px it wraps by group instead (Task 20351)."},
	{Selector: "#timelineChart", MaxWidth: 768, Reason: "the Gantt chart draws its time axis at a minimum " +
		"width so that a bar stays wide enough to read; on a narrow screen the chart scrolls."},
	{Selector: "#ciSnippet", MaxWidth: 768, Reason: "a workflow file to copy verbatim: wrapping its lines " +
		"would show YAML indentation that is not in the file."},
}

// layoutFixture holds the long strings the hub is seeded with; the driver
// waits for them to be on screen before it measures anything.
type layoutFixture struct {
	Project          string              `json:"project"`
	HiddenProject    string              `json:"hiddenProject"`
	Goal             string              `json:"goal"`
	Instructions     string              `json:"instructions"`
	TaskID           int                 `json:"taskID"`
	PendingTaskID    int                 `json:"pendingTaskID"`
	TaskTitle        string              `json:"taskTitle"`
	RiskTaskTitle    string              `json:"riskTaskTitle"`
	Model            string              `json:"model"`
	Secret           string              `json:"secret"`
	Email            string              `json:"email"`
	ResultMarker     string              `json:"resultMarker"`
	DeviceName       string              `json:"deviceName"`
	VirtualName      string              `json:"virtualName"`
	Image            string              `json:"image"`
	TokenName        string              `json:"tokenName"`
	Token            string              `json:"token"`
	Transcript       string              `json:"transcript"`
	TranscriptMarker string              `json:"transcriptMarker"`
	PromptMarker     string              `json:"promptMarker"`
	ReplayOutput     string              `json:"replayOutput"`
	Assistant        []map[string]string `json:"assistant"`
}

// The fixture's long content. Unbroken on purpose: CSS offers a line break at
// a space and after a hyphen, so a name with either wraps on its own and
// proves nothing. Underscores, paths and URLs are what real names are made of
// and what refuses to wrap.
const (
	layoutProject       = "internal_platform_observability_ingest_pipeline_rollout_2026"
	layoutHiddenProject = "internal_platform_observability_ingest_pipeline_archive_2019"
	layoutTaskTitle     = "Rework_the_executor_registry_reconciliation_loop_so_a_slow_device_never_blocks_dispatch"
	layoutRiskTaskTitle = "Pin_the_ingest_pipeline_harness_image_to_a_digest_before_the_rollout"
	layoutURL           = "https://github.com/blechschmidt/cloop/blob/main/pkg/executor/remote/reconcile_with_exponential_backoff_and_jitter_test.go#L1234-L1288"
	layoutRepoPath      = "/srv/build/workspaces/internal-platform/observability/ingest-pipeline/.cloop/worktrees/feature_reconcile_loop_rewrite_with_backpressure"
	layoutDevice        = "edge_gpu_runner_rack42_slot07_observability_ingest_bench"
	layoutVirtual       = "edge_gpu_runner_rack42_slot07_observability_ingest_gvisor_box"
	layoutImage         = "registry.internal.example.com/platform/observability/ingest-pipeline-harness@sha256:4f8b3c2a1d9e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a"
	layoutEmail         = "observability.ingest.pipeline.oncall.rotation@internal-platform.example.com"
	layoutSecret        = "observability_ingest_pipeline_deploy_key_for_internal_platform_monorepo"
	layoutResultMarker  = "reconcile_with_exponential_backoff_and_jitter_test.go"
	layoutPromptMarker  = "PROMPT_reconcile_loop_backpressure_marker"
	layoutReplayOutput  = "REPLAYED_reconcile_loop_backpressure_marker"
)

func layoutLong(parts ...string) string { return strings.Join(parts, " ") }

// sweepStrings is the content a sweep hub is seeded with: the layout sweep's
// long unbroken names here, or the hostile ones xss_browser_test.go drives the
// same tabs and dialogs with (Task 20408). Project names are directory names;
// Secret and Image are validated by the hub, so they hold what it accepts.
type sweepStrings struct {
	Project, HiddenProject, OtherProject string
	// ProjectParent is a path the selected project's directory sits under,
	// ending in "/", or empty.
	ProjectParent                                                 string
	TaskTitle, RiskTaskTitle, FailedTaskTitle, RunningTaskTitle   string
	Tag, URL, RepoPath                                            string
	Device, DeviceLabel, Virtual, Image, Email, Secret, TokenName string
	ResultMarker, PromptMarker, ReplayOutput                      string
	// FeatureTitle names the features; empty leaves their default titles.
	FeatureTitle string
	// Output is a task's captured output; empty writes none.
	Output string
	// Suggestion fills a finished AI brainstorm; empty seeds none.
	Suggestion string
	// UserAgent is the browser the seeded telemetry claims to come from;
	// empty sends Go's own.
	UserAgent string
}

var layoutSweepStrings = sweepStrings{
	Project: layoutProject, HiddenProject: layoutHiddenProject,
	OtherProject:     "billing_service_postgres_major_version_upgrade_dry_run",
	TaskTitle:        layoutTaskTitle,
	RiskTaskTitle:    layoutRiskTaskTitle,
	FailedTaskTitle:  "Backfill_the_audit_trail_for_grants_minted_before_the_checkpoint_rollout",
	RunningTaskTitle: "Write the operator runbook for draining a rack of edge GPU runners",
	Tag:              "observability_ingest_pipeline_backpressure",
	URL:              layoutURL, RepoPath: layoutRepoPath,
	Device: layoutDevice, Virtual: layoutVirtual, Image: layoutImage, Email: layoutEmail, Secret: layoutSecret,
	ResultMarker: layoutResultMarker, PromptMarker: layoutPromptMarker, ReplayOutput: layoutReplayOutput,
	TokenName: "ci_pipeline_for_" + layoutProject,
}

// seedHubAs is seedHub sent with the User-Agent ua, when one is given.
func seedHubAs(t *testing.T, ts *httptest.Server, ua, method, path, body string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s = %d", method, path, resp.StatusCode)
	}
}

// jsonBody marshals v for seedHub.
func jsonBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// seedLayoutHub builds the hub the sweep lays out: a fleet of projects, one
// selected with long everything, an enrolled device with a virtual executor,
// secrets, grants and a pending request, telemetry, quotas, a KB, a chat, the
// activity log, provider calls and a replay.
func seedLayoutHub(t *testing.T) (*httptest.Server, layoutFixture) {
	t.Helper()
	ts, _, fx := seedSweepHub(t, layoutSweepStrings)
	return ts, fx
}

// seedSweepHub builds that hub from s, returning the Server as well for a
// caller that seeds what only lives in process.
func seedSweepHub(t *testing.T, s sweepStrings) (*httptest.Server, *Server, layoutFixture) {
	t.Helper()
	t.Setenv(multiui.EnvRoot, t.TempDir())
	t.Setenv(secretbroker.EnvPassphraseKey, "layout-sweep-browser-passphrase")

	goal := layoutLong("Make the", s.Project, "the hub every team ships through:", s.URL,
		"and", s.RepoPath, "both stay green while the executor fleet doubles.")
	instructions := layoutLong("Always run the reconcile suite at", s.RepoPath,
		"before committing; the flaky test lives at", s.URL, "and must not be skipped.")
	now := time.Now()
	started := now.Add(-90 * time.Minute)
	done := now.Add(-30 * time.Minute)
	deadline := now.Add(48 * time.Hour)
	tasks := []*pm.Task{
		{ID: 1, Title: s.TaskTitle, Priority: 1, Status: pm.TaskDone,
			Description: layoutLong("Dispatch stalls when", s.Device, "stops answering. See", s.URL,
				"and the worktree at", s.RepoPath),
			Result: layoutLong("Committed a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 to", s.RepoPath,
				"— the regression test is", s.ResultMarker, "at", s.URL),
			Tags:      []string{s.Tag, "executor_registry"},
			StartedAt: &started, CompletedAt: &done, EstimatedMinutes: 45, ActualMinutes: 60,
			RiskScore: 8, ImpactScore: 9, Assignee: s.Email, ExternalURL: s.URL,
			Links: []pm.Link{{URL: s.URL, Label: s.TaskTitle, Kind: pm.DetectLinkKind(s.URL)}},
			Annotations: []pm.Annotation{{Timestamp: done, Author: s.Email,
				Text: layoutLong("Verified on", s.Device, "against", s.URL)}}},
		{ID: 2, Title: s.RiskTaskTitle, Priority: 2,
			Status: pm.TaskPending, DependsOn: []int{1}, Deadline: &deadline, EstimatedMinutes: 30,
			RiskScore: 4, ImpactScore: 6,
			Description: layoutLong("Use", s.Image, "everywhere", s.RepoPath, "references a tag.")},
		{ID: 3, Title: s.FailedTaskTitle, Priority: 3,
			Status: pm.TaskFailed, DependsOn: []int{1, 2}, StartedAt: &started,
			Description:      layoutLong("Replays", s.URL),
			Result:           layoutLong("error: open", s.RepoPath+"/.cloop/state.db: no such file or directory"),
			FailureDiagnosis: layoutLong("The worktree", s.RepoPath, "was pruned before the backfill ran.")},
		{ID: 4, Title: s.RunningTaskTitle, Priority: 2,
			Status: pm.TaskInProgress, StartedAt: &started, Description: layoutLong("Covers", s.Device)},
	}
	primary := namedProjectDir(t, s.ProjectParent+s.Project, goal)
	// A git checkout, which is what features need: the Overview offers them
	// only to a project at the top of a repository.
	if err := os.MkdirAll(filepath.Join(primary, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	ps, err := state.Load(primary)
	if err != nil {
		t.Fatal(err)
	}
	ps.Instructions = instructions
	ps.PMMode = true
	ps.Plan = &pm.Plan{Goal: goal, Tasks: tasks}
	if s.Output != "" {
		// What the task printed, which its details dialog shows.
		rel := filepath.Join(".cloop", "tasks", "1-output.md")
		if err := os.MkdirAll(filepath.Join(primary, ".cloop", "tasks"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(primary, rel), []byte(s.Output), 0o644); err != nil {
			t.Fatal(err)
		}
		tasks[0].ArtifactPath = rel
	}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	others := []string{
		setupProjectDir(t, "a short goal", nil),
		namedProjectDir(t, s.OtherProject, layoutLong("Upgrade without downtime:", s.URL)),
	}
	hidden := namedProjectDir(t, s.HiddenProject, "a project this viewer no longer wants to see")
	others = append(others, hidden)

	// Features, for the Overview's panel and its dialogs.
	var title func(*feature.Meta, *state.ProjectState)
	if s.FeatureTitle != "" {
		title = func(m *feature.Meta, _ *state.ProjectState) { m.Title = s.FeatureTitle }
	}
	addFeature(t, primary, "reconcile-loop-backpressure-edge-runners", now.Add(-2*time.Hour), title)
	addFeature(t, primary, "harness-image-digest-pinning", now.Add(-time.Hour), title)

	// The device, bound to the project so the Overview draws its executor and
	// Claude credential cards.
	device := seedLayoutDevice(t, primary, s)
	if err := executor.Bind(primary, device); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(primary) })

	if _, err := kb.Add(primary, s.TaskTitle, layoutLong("Runbook:", s.URL, "and", s.RepoPath),
		[]string{s.Tag}); err != nil {
		t.Fatal(err)
	}
	seedLayoutActivity(t, primary, s)

	srv := New(primary, 0, "")
	srv.Projects = others
	// The driver's readiness waits poll the hub; the default limiter would
	// answer them with 429. Set before the listener starts, which is the
	// happens-before edge the race detector needs.
	srv.RPS, srv.Burst = 100000, 100000
	srv.chatHistories = map[string][]ChatMessage{primary: {
		{Role: "user", Content: layoutLong("why did", s.TaskTitle, "fail on", s.Device+"?"), Timestamp: done},
		{Role: "assistant", Content: layoutLong("It could not open", s.RepoPath, "— see", s.URL),
			Timestamp: done, Action: "cloop task show 3 --worktree " + s.RepoPath},
	}}
	if s.Suggestion != "" {
		// A finished brainstorm, as the Tasks tab's AI suggestions show it.
		r := &suggest.Result{Summary: s.Suggestion, Suggestions: []*suggest.Suggestion{
			{ID: 1, Title: s.Suggestion, Description: s.Suggestion, Rationale: s.Suggestion,
				Category: suggest.Category(s.Suggestion), Effort: suggest.Effort(s.Suggestion)},
			{ID: 2, Title: s.TaskTitle, Description: s.URL, Rationale: s.RepoPath},
		}}
		srv.suggestJobs = map[string]*suggestJob{primary: {gen: 1, done: true, result: r, ledger: suggest.NewLedger(r)}}
	}
	installQuotas(t, srv, quota.Config{Defaults: quota.Limits{quota.ResProjects: 10}})
	withControlPlaneDir(t, primary)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	hideProjectAt(t, ts, hidden)
	seedHub(t, ts, http.MethodPut, "/api/executors/"+device+"/sandbox", jsonBody(t, map[string]any{
		"mode": "container", "engine": "docker", "runtime": "runsc", "image": s.Image, "network": "bridge"}))
	seedHub(t, ts, http.MethodPost, "/api/executors/"+device+"/virtuals", jsonBody(t, map[string]any{
		"name": s.Virtual, "spec": map[string]any{
			"sandbox": map[string]any{"mode": "container", "engine": "docker"},
			"firewall": map[string]any{"allow_public_internet": true,
				"allow_cidrs": []string{"10.20.0.0/16", "172.16.200.0/24"}, "resolvers": []string{"1.1.1.1"}}}}))
	seedHub(t, ts, http.MethodPost, "/api/secrets", jsonBody(t, map[string]any{
		"name": s.Secret, "kind": "env", "payload": `{"OBSERVABILITY_INGEST_PIPELINE_DEPLOY_KEY":"x"}`, "personal": false}))
	seedHub(t, ts, http.MethodPost, "/api/grants", jsonBody(t, map[string]any{
		"kind": "env", "secret_ref": s.Secret, "subject": "project:" + s.Project, "ttl_minutes": 1440,
		"env_keys": []string{"OBSERVABILITY_INGEST_PIPELINE_DEPLOY_KEY"}}))
	seedHub(t, ts, http.MethodPut, "/api/quotas/"+url.PathEscape(s.Email), `{"limits":{"max_projects":3}}`)
	seedHub(t, ts, http.MethodPut, "/api/config/telemetry", `{"enabled":true}`)
	seedHubAs(t, ts, s.UserAgent, http.MethodPost, "/api/telemetry", jsonBody(t, map[string]any{
		"source": "dashboard", "session": "ls0000000000000000",
		"events": []map[string]any{{"kind": "error", "seq": 1, "message": s.URL, "view": s.TaskTitle}}}))
	fileLayoutRequest(t, primary, s)

	return ts, srv, layoutFixture{
		Project: s.Project, HiddenProject: s.HiddenProject, Goal: goal, Instructions: instructions,
		TaskID: 1, PendingTaskID: 2, TaskTitle: s.TaskTitle, ResultMarker: s.ResultMarker,
		RiskTaskTitle: s.RiskTaskTitle, Model: "claude-opus-5-5", Secret: s.Secret, Email: s.Email,
		DeviceName: s.Device, VirtualName: s.Virtual, Image: s.Image,
		TokenName: s.TokenName, Token: "cloop_pat_" + strings.Repeat("a1b2c3d4", 8),
		Transcript: layoutLong("also cover the case where", s.Device, "drops off mid-dispatch, see",
			s.URL), TranscriptMarker: s.Device,
		PromptMarker: s.PromptMarker, ReplayOutput: s.ReplayOutput,
		Assistant: []map[string]string{
			{"role": "user", "content": layoutLong("what blocks", s.TaskTitle+"?")},
			{"role": "assistant", "content": layoutLong("Nothing — it finished; the test is at", s.URL)},
		},
	}
}

// seedLayoutDevice registers an enrolled remote device with a long name and a
// stored inventory, the way seedDevice does for the virtual-executor tests.
func seedLayoutDevice(t *testing.T, dir string, s sweepStrings) string {
	t.Helper()
	const id = "layout-sweep-device"
	caps := remote.AgentCapabilities{
		ContainerRuntimes: []string{"docker", "podman"}, OCIRuntimes: []string{"runc", "runsc", "kata-runtime"},
		PacketFilter: true,
		USBDevices: []executor.USBDevice{{
			Port: "1-1.4.3", Bus: 1, Dev: 7, VendorID: "1050", ProductID: "0030",
			Manufacturer: "Yubico", Product: "YubiHSM 2 hardware security module for " + s.Device,
			Serial: "0031650425", Node: "/dev/bus/usb/001/007",
		}},
	}
	dev, err := remote.NewExecutor(remote.Options{ID: id, Name: s.Device, Capabilities: caps})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if err := executor.DefaultRegistry.Register(dev); err != nil {
		t.Fatalf("Register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(id) })
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
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer db.Close()
	raw, _ := json.Marshal(caps)
	row := statedb.ExecutorRow{ID: id, Name: s.Device, Kind: executor.KindRemoteAgent, Capabilities: raw}
	if s.DeviceLabel != "" {
		row.Labels = map[string]string{"rack": s.DeviceLabel}
	}
	if err := db.UpsertExecutor(row); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
	return id
}

// seedLayoutActivity fills the project's activity log, provider-call log and
// replay history, each with the fixture's long content.
func seedLayoutActivity(t *testing.T, dir string, s sweepStrings) {
	t.Helper()
	q, err := taskqueue.Open(dir)
	if err != nil {
		t.Fatalf("taskqueue.Open: %v", err)
	}
	defer q.Close()
	for _, e := range []taskqueue.Entry{
		{Kind: taskqueue.KindTask, TaskID: 1, Title: s.TaskTitle, Status: taskqueue.StatusDone,
			Description: layoutLong("Dispatch on", s.Device), OutputSummary: layoutLong("Committed to", s.RepoPath)},
		{Kind: taskqueue.KindTask, TaskID: 3, Title: "Backfill_the_audit_trail_for_grants_minted_before_the_checkpoint_rollout",
			Status: taskqueue.StatusFailed, ErrorMessage: layoutLong("open", s.RepoPath+"/.cloop/state.db: no such file")},
	} {
		if _, err := q.Enqueue(e); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	if _, err := state.AppendProviderCall(dir, statedb.ProviderCallRow{
		Provider: "anthropic", Model: "claude-opus-5-5", TaskID: 1, TaskTitle: s.TaskTitle,
		RequestID: "req_" + strings.Repeat("0a1b2c3d", 6),
		Prompt:    layoutLong(s.PromptMarker, "Fix", s.URL, "in", s.RepoPath),
		Response:  layoutLong("Done:", s.RepoPath), Status: "ok",
		Headers:     `{"anthropic-ratelimit-requests-reset":"2026-10-11T12:00:00Z","x-request-path":"` + s.URL + `"}`,
		InputTokens: 1200, OutputTokens: 800, LatencyMs: 2345,
	}); err != nil {
		t.Fatalf("AppendProviderCall: %v", err)
	}

	conn, err := statedb.OpenConn(state.StateDBPath(state.ActiveDir(dir)), statedb.ReadWrite)
	if err != nil {
		t.Fatalf("OpenConn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`INSERT INTO replay_runs(
			created_at, task_id, task_title, original_provider, original_model, target_provider, target_model,
			prompt, original_output, replayed_output, similarity_score, equivalence_score, equivalence_rationale,
			duration_ms, input_tokens, output_tokens, error
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), 1, s.TaskTitle, "anthropic", "claude-opus-5-5",
		"openai", "gpt-5-codex-max-long-context-preview", layoutLong("Fix", s.URL),
		layoutLong("ORIGINAL", s.RepoPath), layoutLong(s.ReplayOutput, s.RepoPath),
		0.42, 3, layoutLong("Both edit", s.RepoPath), 4321, 1200, 900, ""); err != nil {
		t.Fatalf("insert replay_runs: %v", err)
	}
}

// fileLayoutRequest files an access request for the fixture secret as somebody
// else, so the Secrets tab has one for this hub's admin to decide.
func fileLayoutRequest(t *testing.T, dir string, s sweepStrings) {
	t.Helper()
	bs, err := openBrokersAt(dir)
	if err != nil {
		t.Fatalf("open brokers: %v", err)
	}
	defer bs.close()
	if bs.secret == nil {
		t.Fatalf("no secret broker: %+v", bs.status)
	}
	subject, err := secretbroker.ParseSubject("project:*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bs.secret.RequestAccess(context.Background(), secretbroker.AccessRequestInput{
		SecretRef: s.Secret, Subject: subject,
		Constraints:   secretbroker.Constraints{EnvKeys: []string{"OBSERVABILITY_INGEST_PIPELINE_DEPLOY_KEY"}},
		TTL:           time.Hour,
		Justification: layoutLong("Needed to deploy", s.Project, "from", s.RepoPath),
		Actor:         s.Email,
	}); err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
}

// layoutTabs is every switchTab target. What each looks like once its fixture
// content has rendered is TAB_READY in the driver, which fails a tab it has no
// entry for.
var layoutTabs = []string{
	"overview", "tasks", "queue", "kanban", "timeline", "kb", "deps", "risk-matrix", "analytics",
	"chat", "assistant", "replay", "provider-calls",
	"projects", "budget", "executors", "secrets", "audit", "quotas", "telemetry", "settings",
}

// ── What the driver reports ──────────────────────────────────────────────────

type layoutOffender struct {
	Kind        string `json:"kind"`
	Where       string `json:"where"`
	OverPx      int    `json:"over_px"`
	Text        string `json:"text"`
	Culprit     string `json:"culprit"`
	CulpritText string `json:"culprit_text"`
	Left        int    `json:"left"`
	Right       int    `json:"right"`
	Top         int    `json:"top"`
	Bottom      int    `json:"bottom"`
}

type layoutMeasurement struct {
	Viewport  string           `json:"viewport"`
	Theme     string           `json:"theme"`
	Page      overflowPage     `json:"page"`
	Offenders []layoutOffender `json:"offenders"`
	Allowed   []struct {
		Selector string `json:"selector"`
		Where    string `json:"where"`
		OverPx   int    `json:"over_px"`
	} `json:"allowed"`
	Elements int `json:"elements"`
	Controls int `json:"controls"`
	Roots    int `json:"roots"`
}

type layoutScenario struct {
	Name         string              `json:"name"`
	Error        string              `json:"error"`
	Measurements []layoutMeasurement `json:"measurements"`
}

type layoutResults struct {
	Error        string             `json:"error"`
	Scenarios    []layoutScenario   `json:"scenarios"`
	AllowSeen    []string           `json:"allow_seen"`
	Openers      []string           `json:"openers"`
	SelfTest     *layoutMeasurement `json:"self_test"`
	SelfTestWide *layoutMeasurement `json:"self_test_wide"`
	Exceptions   []struct {
		Scenario string `json:"scenario"`
		Message  string `json:"message"`
	} `json:"exceptions"`
	BootMS    int `json:"boot_ms"`
	ElapsedMS int `json:"elapsed_ms"`
}

// runLayoutSweep runs the driver against base and decodes what it printed.
func runLayoutSweep(t *testing.T, node, chrome, base string, fx layoutFixture, only []string) layoutResults {
	t.Helper()
	cfg := map[string]any{
		"viewports": layoutViewports, "dark_viewport": layoutDarkViewport, "tabs": layoutTabs,
		"allow": layoutScrollAllowlist, "fixture": fx, "only": only,
		"shots": os.Getenv("LAYOUT_SWEEP_SHOTS"),
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "layout-sweep.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Bounded, so a stalled Chrome cannot hold the package to its timeout
	// (Task 20340).
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/layout_sweep_browser.js"), chrome, base, cfgPath).Output()
	if os.Getenv("LAYOUT_SWEEP_DEBUG") != "" {
		_ = os.WriteFile(filepath.Join(os.TempDir(), "layout-sweep-out.json"), out, 0o644)
	}
	var got layoutResults
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, out, stderr)
	}
	return got
}

// layoutFinding is one defect, gathered across every viewport it shows at.
type layoutFinding struct {
	scenario, kind, where string
	detail                string
	at                    []string
}

// layoutFindings turns a run into its defects, merged so that one fault seen at
// five widths in two themes is one line naming them all.
func layoutFindings(scenarios []layoutScenario) []layoutFinding {
	byKey := map[string]*layoutFinding{}
	var order []string
	add := func(scenario, kind, where, detail, at string) {
		key := scenario + "|" + kind + "|" + where
		f := byKey[key]
		if f == nil {
			f = &layoutFinding{scenario: scenario, kind: kind, where: where, detail: detail}
			byKey[key] = f
			order = append(order, key)
		}
		f.at = append(f.at, at)
	}
	for _, s := range scenarios {
		for _, m := range s.Measurements {
			at := m.Viewport
			if m.Theme == "dark" {
				at += " (dark)"
			}
			p := m.Page
			if p.OverflowPx > 1 {
				add(s.Name, "page", "the document", fmt.Sprintf("scrolls %dpx sideways", p.OverflowPx), at)
			}
			if p.InnerWidth > p.ExpectedWidth+1 {
				add(s.Name, "zoom", "the document", fmt.Sprintf("the layout viewport is %dpx on a %dpx screen — "+
					"the page overflowed and the browser zoomed all of it out to fit", p.InnerWidth, p.ExpectedWidth), at)
			}
			for _, o := range m.Offenders {
				var d string
				switch o.Kind {
				case "control":
					d = fmt.Sprintf("cannot be brought fully onto the screen (left %d, right %d, top %d, bottom %d)",
						o.Left, o.Right, o.Top, o.Bottom)
				case "scroll":
					d = fmt.Sprintf("scrolls %dpx sideways and is not in layoutScrollAllowlist", o.OverPx)
				case "clip":
					d = fmt.Sprintf("hides %dpx of its content", o.OverPx)
				default:
					d = fmt.Sprintf("content runs %dpx out of its box", o.OverPx)
				}
				if o.Culprit != "" {
					d += fmt.Sprintf("; furthest right: %s %q", o.Culprit, o.CulpritText)
				} else if o.Text != "" {
					d += fmt.Sprintf("; text %q", o.Text)
				}
				add(s.Name, o.Kind, o.Where, d, at)
			}
		}
	}
	out := make([]layoutFinding, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

func (f layoutFinding) String() string {
	return fmt.Sprintf("%s: %s %s — %s [at %s]", f.scenario, f.kind, f.where, f.detail, strings.Join(f.at, ", "))
}

// TestLayoutSweep_EveryTabAndDialogFits is the sweep itself. Its subtests read
// from one browser run: booting the dashboard and opening every dialog is the
// cost, and every assertion shares it.
func TestLayoutSweep_EveryTabAndDialogFits(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot lay the dashboard out")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	ts, fx := seedLayoutHub(t)
	// LAYOUT_SWEEP_ONLY=td-overlay,tab:tasks runs just those, for working on
	// one panel; the coverage checks below are skipped with it.
	var only []string
	if o := os.Getenv("LAYOUT_SWEEP_ONLY"); o != "" {
		only = strings.Split(o, ",")
	}
	got := runLayoutSweep(t, node, chrome, ts.URL, fx, only)
	t.Logf("layout sweep: %d scenarios in %.1fs (boot %.1fs)", len(got.Scenarios),
		float64(got.ElapsedMS)/1000, float64(got.BootMS)/1000)
	if got.Error != "" {
		t.Fatalf("the driver failed: %s", got.Error)
	}

	t.Run("every tab and dialog was laid out", func(t *testing.T) {
		if len(only) > 0 {
			t.Skip("LAYOUT_SWEEP_ONLY narrows the run")
		}
		want := map[string]bool{}
		for _, tab := range layoutTabs {
			want["tab:"+tab] = true
		}
		for _, k := range got.Openers {
			want["dialog:"+k] = true
		}
		for _, s := range got.Scenarios {
			delete(want, s.Name)
		}
		if len(want) > 0 {
			t.Errorf("never measured: %s", strings.Join(sortedSet(want), ", "))
		}
	})

	t.Run("each scenario opened with its content and was measured everywhere", func(t *testing.T) {
		for _, s := range got.Scenarios {
			if s.Error != "" {
				// The opener could not reach its dialog, or the dialog never
				// showed the fixture's content: measuring it anyway would
				// measure an empty or a wrong box.
				t.Errorf("%s: %s", s.Name, s.Error)
				continue
			}
			want := len(layoutViewports) + 1 // and once more in the dark
			if strings.HasPrefix(s.Name, "dialog:mobileNavOverlay") {
				want = 3 // the phone menu exists only below the tablet breakpoint
			}
			if len(s.Measurements) != want {
				t.Errorf("%s: measured %d times, want %d", s.Name, len(s.Measurements), want)
			}
			for _, m := range s.Measurements {
				// A scope that matched nothing visible, or a tree with nothing
				// in it, passes every check below without testing anything.
				if m.Roots == 0 || m.Elements < 3 {
					t.Errorf("%s at %s: nothing on screen to measure (%d roots, %d elements)",
						s.Name, m.Viewport, m.Roots, m.Elements)
				}
			}
		}
	})

	t.Run("nothing threw", func(t *testing.T) {
		for _, e := range got.Exceptions {
			t.Errorf("%s: uncaught %s", e.Scenario, e.Message)
		}
	})

	t.Run("nothing overflows", func(t *testing.T) {
		for _, f := range layoutFindings(got.Scenarios) {
			t.Errorf("%s", f)
		}
	})

	t.Run("every allowlisted scroller is still on the page", func(t *testing.T) {
		if len(only) > 0 {
			t.Skip("LAYOUT_SWEEP_ONLY narrows the run")
		}
		seen := map[string]bool{}
		for _, s := range got.AllowSeen {
			seen[s] = true
		}
		for _, a := range layoutScrollAllowlist {
			if !seen[a.Selector] {
				t.Errorf("layoutScrollAllowlist names %q, which nothing in the sweep drew: drop the "+
					"entry, or it will excuse whatever comes to match it next", a.Selector)
			}
		}
	})

	t.Run("the gate fails on a broken page", func(t *testing.T) {
		checkLayoutSelfTest(t, got.SelfTest, got.SelfTestWide)
	})
}

// checkLayoutSelfTest holds the probe to the fixture the driver breaks on
// purpose: each defect is reported, through the same findings the sweep
// fails on, and the truncation and the allowlisted scroller are not.
func checkLayoutSelfTest(t *testing.T, plain, wide *layoutMeasurement) {
	t.Helper()
	if plain == nil || wide == nil {
		t.Fatal("the driver ran no self-test")
	}
	findings := layoutFindings([]layoutScenario{{Name: "self-test", Measurements: []layoutMeasurement{*plain}}})
	found := func(kind, id string) bool {
		for _, f := range findings {
			if f.kind == kind && strings.Contains(f.where, "#"+id) {
				return true
			}
		}
		return false
	}
	for _, c := range []struct{ kind, id, what string }{
		{"clip", "stClip", "a box that hides the end of its text"},
		{"spill", "stSpill", "text running out of a squeezed flex item"},
		{"scroll", "stScroll", "a box scrolling sideways that is not allowlisted"},
		{"control", "stButton", "a button hanging off the edge of the screen"},
	} {
		if !found(c.kind, c.id) {
			t.Errorf("the probe did not report %s (#%s as %s); the sweep cannot be trusted to "+
				"report one either. Findings: %v", c.what, c.id, c.kind, findings)
		}
	}
	for _, f := range findings {
		if strings.Contains(f.where, "#stEllipsis") || strings.Contains(f.where, "#stAllowed") {
			t.Errorf("the probe reported a deliberate truncation or an allowlisted scroller: %s", f)
		}
	}
	if len(findings) != 4 {
		t.Errorf("the self-test page has four defects and the probe reported %d: %v", len(findings), findings)
	}
	if plain.Page.OverflowPx > 1 {
		t.Errorf("the self-test page overflowed by %dpx before anything wide was added", plain.Page.OverflowPx)
	}
	wf := layoutFindings([]layoutScenario{{Name: "self-test", Measurements: []layoutMeasurement{*wide}}})
	var page, zoom bool
	for _, f := range wf {
		page = page || f.kind == "page"
		zoom = zoom || f.kind == "zoom"
	}
	if !page || !zoom {
		t.Errorf("a box %dpx wider than the screen did not report the document scrolling sideways "+
			"(%v) and the phone zooming out (%v): %v", 200, page, zoom, wf)
	}
}

// ── Static gates: no browser needed ──────────────────────────────────────────
//
// These hold the sweep's lists against the page on every runner, browser or
// not: a dialog or tab added without an entry fails here first.

var (
	openOverlayCall = regexp.MustCompile(`\bopenOverlay\(`)
	openerKey       = regexp.MustCompile(`(?m)^  '([A-Za-z0-9_-]+)(?:#[a-z-]+)?': \{`)
	quotedArg       = regexp.MustCompile(`^\s*'([^']+)'`)
	identArg        = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\s*[,)]`)
	switchTabTarget = regexp.MustCompile(`switchTab\('([a-z-]+)'\)`)
	tabPanelID      = regexp.MustCompile(`id="tab-([a-z-]+)"`)
)

// overlayCallSites returns the overlay each openOverlay() call in the front end
// opens, by id, with the call sites that open it.
func overlayCallSites(t *testing.T) map[string][]string {
	t.Helper()
	files := append([]string(nil), bundleFiles...)
	for _, d := range deferredScripts {
		files = append(files, d.path)
	}
	out := map[string][]string{}
	for _, file := range files {
		if file == "assets/js/00-overlay.js" {
			continue // the helper itself
		}
		b, err := assetFS.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		src := string(b)
		code := maskJS(src) // a call in a comment or a string is not a call
		for _, loc := range openOverlayCall.FindAllStringIndex(code, -1) {
			at := fmt.Sprintf("%s:%d", file, strings.Count(src[:loc[0]], "\n")+1)
			arg := src[loc[1]:]
			if m := quotedArg.FindStringSubmatch(arg); m != nil {
				out[m[1]] = append(out[m[1]], at)
				continue
			}
			m := identArg.FindStringSubmatch(arg)
			if m == nil {
				t.Errorf("%s: cannot tell which dialog this openOverlay() opens; pass its id, or "+
					"an element fetched by id just above the call", at)
				continue
			}
			// The element the variable holds: the nearest assignment above the
			// call that fetches one by id.
			bind := regexp.MustCompile(`\b` + regexp.QuoteMeta(m[1]) +
				`\s*=\s*(?:document\.getElementById|el)\(\s*'([^']+)'\s*\)`)
			all := bind.FindAllStringSubmatch(src[:loc[0]], -1)
			if len(all) == 0 {
				t.Errorf("%s: openOverlay(%s) — no `%s = document.getElementById('…')` above it to "+
					"say which dialog it is", at, m[1], m[1])
				continue
			}
			id := all[len(all)-1][1]
			out[id] = append(out[id], at)
		}
	}
	return out
}

// layoutOpenerKeys reads the OPENERS registry's keys out of the driver.
func layoutOpenerKeys(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "layout_sweep_browser.js"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "\nconst OPENERS = {\n")
	end := strings.Index(src[max(start, 0):], "\n};\n")
	if start < 0 || end < 0 {
		t.Fatal("testdata/layout_sweep_browser.js has no `const OPENERS = {` … `};` block")
	}
	keys := map[string]bool{}
	for _, m := range openerKey.FindAllStringSubmatch(src[start:start+end], -1) {
		keys[m[1]] = true
	}
	return keys
}

// TestLayoutSweep_EveryDialogHasAnOpener keeps the sweep's dialogs in step with
// the page's: every overlay an openOverlay() call opens needs an opener that
// reaches it with realistic content, and an opener for a dialog nothing opens
// any more is dead weight that would hide the gap.
func TestLayoutSweep_EveryDialogHasAnOpener(t *testing.T) {
	calls := overlayCallSites(t)
	openers := layoutOpenerKeys(t)
	if len(calls) < 30 || len(openers) < 30 {
		t.Fatalf("found %d dialogs opened and %d openers; the dashboard has ~37 of each, so a "+
			"pattern here has drifted and the comparison below would pass vacuously", len(calls), len(openers))
	}
	for id, at := range calls {
		if !openers[id] {
			t.Errorf("#%s is opened at %s but has no opener in testdata/layout_sweep_browser.js's "+
				"OPENERS, so the layout sweep never lays it out. Add one that opens it the way a user "+
				"does, with the fixture's long content in it.", id, strings.Join(at, ", "))
		}
	}
	for id := range openers {
		if _, ok := calls[id]; !ok {
			t.Errorf("OPENERS has an opener for #%s, which no openOverlay() call opens any more", id)
		}
	}
}

// TestLayoutSweep_EveryTabIsSwept does the same for the tabs: every switchTab
// target and every tab panel is in layoutTabs, and nothing else is.
func TestLayoutSweep_EveryTabIsSwept(t *testing.T) {
	page := loadAssets().page.contents
	targets := map[string]bool{}
	for _, m := range switchTabTarget.FindAllStringSubmatch(page, -1) {
		targets[m[1]] = true
	}
	for _, m := range tabPanelID.FindAllStringSubmatch(page, -1) {
		targets[m[1]] = true
	}
	if len(targets) < 20 {
		t.Fatalf("found %d tabs in index.html; it has 21, so the patterns here have drifted", len(targets))
	}
	swept := map[string]bool{}
	for _, tab := range layoutTabs {
		swept[tab] = true
	}
	for _, name := range sortedSet(targets) {
		if !swept[name] {
			t.Errorf("tab %q is on the page but not in layoutTabs, so the layout sweep never lays it out", name)
		}
	}
	for _, name := range sortedSet(swept) {
		if !targets[name] {
			t.Errorf("layoutTabs names %q, which is not a tab on the page", name)
		}
	}
}

// sortedSet returns m's keys in order.
func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
