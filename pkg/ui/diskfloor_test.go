package ui

// Tests for the hub's half of the free-space floor (Task 20381): the Settings
// endpoints and the overlay they write, the admin banner, the watcher's
// nudge, the floor a run of the hub's own directory is handed, the gauge, and
// the hub settling a run that died while it waited for disk space.
//
// The hub's volume is always an injected probe. Nothing here fills a disk.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
)

const mib = int64(1) << 20

// hubDiskFake stands in for the hub's view of its disks. Every path gets the
// same device and free space unless byPrefix names it otherwise.
type hubDiskFake struct {
	mu       sync.Mutex
	free     int64
	byPrefix map[string]diskusage.Volume
	calls    int
}

func (f *hubDiskFake) set(free int64) {
	f.mu.Lock()
	f.free = free
	f.mu.Unlock()
}

func (f *hubDiskFake) probe(paths ...string) ([]diskusage.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	for prefix, v := range f.byPrefix {
		if strings.HasPrefix(paths[0], prefix) {
			v.Path = paths[0]
			return []diskusage.Volume{v}, nil
		}
	}
	return []diskusage.Volume{{Mount: "/srv", Path: paths[0], Device: 1, FreeBytes: f.free}}, nil
}

func diskSettingsServer(t *testing.T, free int64) (*Server, *hubDiskFake) {
	t.Helper()
	srv := telemetrySettingsServer(t)
	fake := &hubDiskFake{free: free}
	srv.diskProbe = fake.probe
	return srv, fake
}

func putDiskFloor(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/config/disk", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.handleDiskFloorSave(rec, req)
	return rec
}

func getDiskFloor(t *testing.T, srv *Server) diskFloorSettings {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handleDiskFloorSettings(rec, httptest.NewRequest(http.MethodGet, "/api/config/disk", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/disk = %d: %s", rec.Code, rec.Body.String())
	}
	var v diskFloorSettings
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func diskFloorAuditRows(t *testing.T, dir string) []eventlog.AuditEvent {
	t.Helper()
	log, err := eventlog.Open(dir)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer log.Close()
	events, _, err := log.List(eventlog.AuditFilter{Limit: 500})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var out []eventlog.AuditEvent
	for _, e := range events {
		if e.EventType == "disk.floor.updated" {
			out = append(out, e)
		}
	}
	return out
}

// TestDiskFloorSettings_ViewAndSave: a fresh hub shows the default floor as
// unstated; a save states it in config.yaml (no overlay here), takes effect at
// once, and leaves one audit row — and a save that changes nothing, none.
func TestDiskFloorSettings_ViewAndSave(t *testing.T) {
	srv, _ := diskSettingsServer(t, 5000*mib)

	v := getDiskFloor(t, srv)
	if v.MinFreeDiskMB != config.MinFreeDiskMBDefault || v.Stated || v.Overlay {
		t.Errorf("fresh view = %+v, want the unstated default and no overlay", v)
	}
	if v.Hub.Volume != "/srv" || v.Hub.FreeBytes != 5000*mib || v.Hub.Low {
		t.Errorf("fresh hub volume = %+v", v.Hub)
	}

	rec := putDiskFloor(t, srv, `{"min_free_disk_mb": 2048}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	cfg, err := config.Load(srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Orchestrator.EffectiveMinFreeDiskMB(); got != 2048 {
		t.Errorf("config.yaml floor = %d, want 2048", got)
	}
	if v := getDiskFloor(t, srv); v.MinFreeDiskMB != 2048 || !v.Stated {
		t.Errorf("view after the save = %+v", v)
	}
	rows := diskFloorAuditRows(t, srv.WorkDir)
	if len(rows) != 1 || !strings.Contains(rows[0].Payload, `"min_free_disk_mb":2048`) ||
		!strings.Contains(rows[0].Payload, `"was_min_free_disk_mb":1024`) {
		t.Fatalf("audit rows = %+v, want one recording 1024 → 2048", rows)
	}

	if rec := putDiskFloor(t, srv, `{"min_free_disk_mb": 2048}`); rec.Code != http.StatusOK {
		t.Fatalf("second PUT = %d", rec.Code)
	}
	if n := len(diskFloorAuditRows(t, srv.WorkDir)); n != 1 {
		t.Errorf("an unchanged save wrote %d extra audit row(s)", n-1)
	}

	// 0 turns the check off, and the view says so.
	if rec := putDiskFloor(t, srv, `{"min_free_disk_mb": 0}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT 0 = %d: %s", rec.Code, rec.Body.String())
	}
	if v := getDiskFloor(t, srv); v.MinFreeDiskMB != 0 || v.Hub.Low || v.Hub.FloorBytes != 0 {
		t.Errorf("view with the check off = %+v", v)
	}
}

// TestDiskFloorSettings_RefusesWhatIsNotAFloor: refused rather than clamped,
// like every numeric writer — a typo the server repaired would leave the panel
// showing a floor nobody chose.
func TestDiskFloorSettings_RefusesWhatIsNotAFloor(t *testing.T) {
	srv, _ := diskSettingsServer(t, 5000*mib)
	for _, body := range []string{`{}`, `{"min_free_disk_mb": 10}`, `{"min_free_disk_mb": -1}`,
		`{"min_free_disk_mb": 99999999}`, `{"min_free_disk_mb": "big"}`} {
		if rec := putDiskFloor(t, srv, body); rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s = %d, want 400 (%s)", body, rec.Code, rec.Body.String())
		}
	}
	cfg, err := config.Load(srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Orchestrator.MinFreeDiskMB != nil {
		t.Errorf("a refused save stated a floor: %d", *cfg.Orchestrator.MinFreeDiskMB)
	}
}

// TestDiskFloorSettings_SaveGoesToTheHubsOverlay: with an overlay the floor is
// written there, config.yaml is left byte for byte, and the hub reads the new
// value through its merged configuration (Task 20364's save path).
func TestDiskFloorSettings_SaveGoesToTheHubsOverlay(t *testing.T) {
	shared := "provider: claudecode\norchestrator:\n  min_free_disk_mb: 2048\n"
	srv, overlay := overlayServer(t, shared, liveOverlay)
	srv.diskProbe = (&hubDiskFake{free: 5000 * mib}).probe

	if v := getDiskFloor(t, srv); v.MinFreeDiskMB != 2048 || !v.Overlay {
		t.Fatalf("view before = %+v, want config.yaml's 2048 and an overlay", v)
	}
	if rec := putDiskFloor(t, srv, `{"min_free_disk_mb": 4096}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	got, err := os.ReadFile(config.ConfigPath(srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != shared {
		t.Errorf("config.yaml was rewritten:\n%s", got)
	}
	raw, err := os.ReadFile(overlay)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "min_free_disk_mb: 4096") || !strings.Contains(string(raw), "Read by cloop ui --port 8081 only.") {
		t.Errorf("overlay after the save:\n%s", raw)
	}
	if mb, stated := srv.hubFloorMB(); mb != 4096 || !stated {
		t.Errorf("hub floor = %d (stated %v), want 4096 from the overlay", mb, stated)
	}
	rows := diskFloorAuditRows(t, srv.WorkDir)
	if len(rows) != 1 || !strings.Contains(rows[0].Payload, `"file":"config.ui-8081.yaml"`) {
		t.Errorf("audit rows = %+v, want one naming the overlay", rows)
	}
}

// TestDiskFloor_AdminBannerAndSettingsAreAdminOnly: /api/me carries the banner
// to the people who can act on it, and only while the hub's state volume is
// below the floor; the Settings endpoints are admin-only like every other
// hub-scope setting.
func TestDiskFloor_AdminBannerAndSettingsAreAdminOnly(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	resolver, err := authz.New(rbacPolicy())
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	fake := &hubDiskFake{free: 300 * mib}
	srv.diskProbe = fake.probe
	loginAs := func(groups []string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	admin := loginAs([]string{"owners"})
	operator := loginAs([]string{"engineers"})

	banner := func(c *http.Client) *hubDiskView {
		t.Helper()
		code, body := do(t, c, http.MethodGet, ts.URL+"/api/me", "")
		if code != http.StatusOK {
			t.Fatalf("GET /api/me = %d", code)
		}
		var me struct {
			HubDisk *hubDiskView `json:"hub_disk"`
		}
		if err := json.Unmarshal([]byte(body), &me); err != nil {
			t.Fatalf("decode /api/me: %v (%s)", err, body)
		}
		return me.HubDisk
	}

	if b := banner(admin); b == nil || !b.Low || b.Volume != "/srv" || b.FreeBytes != 300*mib || b.FloorBytes != 1024*mib {
		t.Errorf("admin's banner below the floor = %+v", b)
	}
	if b := banner(operator); b != nil {
		t.Errorf("an operator was shown the hub's disk: %+v", b)
	}
	fake.set(5000 * mib)
	if b := banner(admin); b != nil {
		t.Errorf("admin's banner with room = %+v, want none", b)
	}

	if code, _ := do(t, operator, http.MethodGet, ts.URL+"/api/config/disk", ""); code != http.StatusForbidden {
		t.Errorf("operator GET /api/config/disk = %d, want 403", code)
	}
	if code, _ := do(t, operator, http.MethodPut, ts.URL+"/api/config/disk", `{"min_free_disk_mb":0}`); code != http.StatusForbidden {
		t.Errorf("operator PUT /api/config/disk = %d, want 403", code)
	}
	if code, body := do(t, admin, http.MethodPut, ts.URL+"/api/config/disk", `{"min_free_disk_mb":8192}`); code != http.StatusOK {
		t.Errorf("admin PUT /api/config/disk = %d: %s", code, body)
	}
	// 5000 MB free is below the new 8 GB floor: the banner follows the save.
	if b := banner(admin); b == nil || b.FloorBytes != 8192*mib {
		t.Errorf("admin's banner after raising the floor = %+v", b)
	}
}

// TestHubDiskWatch_NudgesOnlyOnCrossing: the watcher tells open dashboards to
// re-read /api/me when the state volume crosses the floor, in either
// direction, and says nothing while it stays on one side.
func TestHubDiskWatch_NudgesOnlyOnCrossing(t *testing.T) {
	srv, fake := diskSettingsServer(t, 300*mib)
	hc := &hubClient{ch: make(chan wsMessage, 16), resync: make(chan struct{}, 1), id: "disk-watch"}
	srv.hubMu.Lock()
	srv.hubClients[srv.WorkDir] = map[*hubClient]struct{}{hc: {}}
	srv.hubMu.Unlock()
	nudges := func() int {
		n := 0
		for {
			select {
			case m := <-hc.ch:
				if m.Type == "hub_disk" {
					n++
				}
			default:
				return n
			}
		}
	}

	srv.checkHubDisk() // first reading: what /api/me already says at load
	srv.checkHubDisk()
	if n := nudges(); n != 0 {
		t.Errorf("%d nudge(s) without a crossing", n)
	}
	fake.set(5000 * mib)
	srv.checkHubDisk()
	srv.checkHubDisk()
	if n := nudges(); n != 1 {
		t.Errorf("%d nudge(s) for one crossing back above the floor, want 1", n)
	}
	fake.set(10 * mib)
	srv.checkHubDisk()
	if n := nudges(); n != 1 {
		t.Errorf("%d nudge(s) for falling below the floor, want 1", n)
	}
}

// isolatingStub is an executor that puts a boundary around its workloads.
type isolatingStub struct{ hostOnlyExecutor }

func (*isolatingStub) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer}
}

// TestHubFloorEnv: the hub hands its own floor to a run of its own directory
// on its own filesystem — where Settings may have written it to an overlay
// `cloop run` cannot read — and to nothing else.
func TestHubFloorEnv(t *testing.T) {
	dir := statedbtest.Dir(t)
	if err := os.WriteFile(config.ConfigPath(dir), []byte("provider: claudecode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := config.UIInstanceConfigPath(dir, 8081)
	if err := config.SaveUIInstanceMinFreeDisk(overlay, 3072); err != nil {
		t.Fatal(err)
	}
	controlPlaneDirMu.Lock()
	prevDir, prevPort := controlPlaneDirValue, controlPlanePortValue
	controlPlaneDirValue, controlPlanePortValue = dir, 8081
	controlPlaneDirMu.Unlock()
	t.Cleanup(func() {
		controlPlaneDirMu.Lock()
		controlPlaneDirValue, controlPlanePortValue = prevDir, prevPort
		controlPlaneDirMu.Unlock()
	})
	local := localprocess.New("disk-floor-local")
	contained := &isolatingStub{hostOnlyExecutor{id: "disk-floor-box"}}

	if got, want := hubFloorEnv(dir, local), config.EnvMinFreeDiskMB+"=3072"; got != want {
		t.Errorf("hub's own directory on the host = %q, want %q", got, want)
	}
	if got := hubFloorEnv(dir, contained); got != "" {
		t.Errorf("a sandbox was handed the hub's floor: %q", got)
	}
	if got := hubFloorEnv(t.TempDir(), local); got != "" {
		t.Errorf("another project was handed the hub's floor: %q", got)
	}

	// Nothing stated anywhere: the run's own reading reaches the same default.
	if err := os.Remove(overlay); err != nil {
		t.Fatal(err)
	}
	if got := hubFloorEnv(dir, local); got != "" {
		t.Errorf("an unstated floor was handed over: %q", got)
	}
}

// TestCollectDiskFree_ReportsEachVolumeOnce: every member reports the
// volumes it writes to — its state volume and its projects' — once each,
// labelled by mount point.
func TestCollectDiskFree_ReportsEachVolumeOnce(t *testing.T) {
	srv, _ := diskSettingsServer(t, 0)
	project := t.TempDir()
	other := t.TempDir()
	srv.Projects = []string{project, other}
	srv.diskProbe = (&hubDiskFake{byPrefix: map[string]diskusage.Volume{
		srv.WorkDir: {Mount: "/hub", Device: 1, FreeBytes: 5 << 30},
		project:     {Mount: "/data", Device: 2, FreeBytes: 700 * mib},
		other:       {Mount: "/data", Device: 2, FreeBytes: 700 * mib},
	}}).probe

	out := srv.gatherMetrics()
	want := map[string]string{
		`cloop_hub_disk_free_bytes{volume="/hub"}`:  fmt.Sprint(int64(5 << 30)),
		`cloop_hub_disk_free_bytes{volume="/data"}`: fmt.Sprint(700 * mib),
	}
	seen := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "cloop_hub_disk_free_bytes{") {
			continue
		}
		seen++
		name, value, _ := strings.Cut(line, " ")
		if want[name] != value {
			t.Errorf("sample %q, want %q for %s", line, want[name], name)
		}
	}
	if seen != 2 {
		t.Errorf("%d cloop_hub_disk_free_bytes samples, want 2 (one per volume):\n%s", seen, out)
	}
}

// TestReconcileDeadRun_SettlesADeadDiskWait: a run waiting for disk space
// claims to be live from a paused status (Task 20381). Killed while it
// waited, it left the claim behind; the hub settles it like a stale running
// status, so the dashboard stops offering Stop on a run that is gone.
func TestReconcileDeadRun_SettlesADeadDiskWait(t *testing.T) {
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	st, err := state.Init(dir, "wait for disk", 0)
	if err != nil {
		t.Fatal(err)
	}
	st.SetPaused(pausereason.New(pausereason.CodeDiskLow, "volume / has 800.0 MB free, below the 1.00 GB floor"))
	if err := st.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	srv := &Server{WorkDir: dir}

	if !srv.reconcileDeadRun(dir, runVerdict{}) {
		t.Fatal("a dead disk_low wait was not settled")
	}
	after, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !after.PausedFor(pausereason.CodeStale) {
		t.Errorf("status = %q (%+v), want paused as stale", after.Status, after.PauseReason)
	}
	rows, _, err := state.ListEvents(dir, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Type == state.EventSessionFailed && strings.Contains(r.Message, "from paused (waiting for disk space) to paused") {
			found = true
		}
	}
	if !found {
		t.Errorf("no journal row names the wait that was settled: %+v", rows)
	}

	// Any other pause is a run that already ended: nothing to settle.
	st2, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	st2.SetPaused(pausereason.New(pausereason.CodeBudget, "spent"))
	if err := st2.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	if srv.reconcileDeadRun(dir, runVerdict{}) {
		t.Error("an ordinary pause was treated as a dead run")
	}
}
