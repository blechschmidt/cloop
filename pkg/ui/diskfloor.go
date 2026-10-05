package ui

// The hub's half of the free-space floor (Task 20381).
//
// A run holds the volumes it writes to — its project's .cloop and its working
// tree — to orchestrator.min_free_disk_mb, pausing disk_low below it
// (pkg/orchestrator/diskfloor.go). The hub has a volume of its own to watch:
// the one holding its control-plane .cloop, where state.db lives. A hub whose
// database cannot take a write loses sessions, audit rows and every run's
// dispatch record, and on the host this was built on that volume was 98% full
// with a multi-gigabyte state.db on it. So the hub holds it to the same floor,
// in three places an operator looks:
//
//   - an admin-only banner across the dashboard while the volume is below the
//     floor (/api/me carries it for callers who may manage the hub; a minute
//     watcher nudges open dashboards to re-read it when the volume crosses);
//   - a `cloop hub doctor` finding, storage.free_space (pkg/hubdoctor);
//   - cloop_hub_disk_free_bytes{volume}, which every cluster member reports
//     for the volumes it writes to, its own state volume and its registered
//     projects', since each member's disk is its own.
//
// The floor itself is edited in Settings → Disk & Retention through the
// overlay-aware save path (Task 20364), and is a hub-scope setting with a
// project-scope reader: `cloop run` reads it from its project's config.yaml.
// For every project but the hub's own directory that is the file the setting
// lives in. For the hub's own directory the Settings value may sit in the
// per-instance overlay `cloop run` never reads, so the hub hands it to the
// runs it starts there as CLOOP_MIN_FREE_DISK_MB (hubFloorEnv).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/logger"
)

// hubDiskCheckInterval is how often the hub re-measures its state volume to
// decide whether the admin banner should show.
const hubDiskCheckInterval = time.Minute

// hubDiskView is the hub's account of its state volume against its floor.
type hubDiskView struct {
	// Volume is the mount point of the volume holding the hub's .cloop.
	Volume string `json:"volume"`
	// Path is the directory measured: the hub's .cloop.
	Path string `json:"path"`
	// FreeBytes is what the hub process could still write there.
	FreeBytes int64 `json:"free_bytes"`
	// FloorMB and FloorBytes are the floor in force; 0 when the check is off.
	FloorMB    int   `json:"floor_mb"`
	FloorBytes int64 `json:"floor_bytes"`
	// Low: the volume is below the floor. What the banner shows on.
	Low bool `json:"low"`
	// Warn: below twice the floor — the doctor's warning, a run or two
	// before Low.
	Warn bool `json:"warn"`
	// Error says why the volume could not be measured.
	Error string `json:"error,omitempty"`
}

// probeVolumes is diskusage.Volumes, or the probe a test installed.
func (s *Server) probeVolumes(paths ...string) ([]diskusage.Volume, error) {
	if s.diskProbe != nil {
		return s.diskProbe(paths...)
	}
	return diskusage.Volumes(paths...)
}

// hubFloorMB is the floor the hub's configuration sets, overlay included, and
// whether it states one at all. A configuration that will not load reads as
// unset — the default floor — because a parse error elsewhere in the file must
// not switch the check off.
func (s *Server) hubFloorMB() (mb int, stated bool) {
	cfg, err := s.loadHubConfig()
	if err != nil || cfg == nil {
		return config.MinFreeDiskMBDefault, false
	}
	return cfg.Orchestrator.EffectiveMinFreeDiskMB(), cfg.Orchestrator.MinFreeDiskMB != nil
}

// hubDisk measures the hub's state volume against its floor.
func (s *Server) hubDisk() hubDiskView {
	v := hubDiskView{Path: filepath.Join(s.WorkDir, ".cloop")}
	v.FloorMB, _ = s.hubFloorMB()
	v.FloorBytes = int64(v.FloorMB) << 20
	vols, err := s.probeVolumes(v.Path)
	if err != nil || len(vols) == 0 {
		if err == nil {
			err = fmt.Errorf("no volume found for %s", v.Path)
		}
		v.Error = err.Error()
		return v
	}
	v.Volume, v.FreeBytes = vols[0].Mount, vols[0].FreeBytes
	if v.FloorBytes > 0 {
		v.Low = v.FreeBytes < v.FloorBytes
		v.Warn = v.FreeBytes < 2*v.FloorBytes
	}
	return v
}

// watchHubDisk re-measures the hub's state volume every minute and tells this
// member's dashboards when it crosses the floor, so the admin banner appears
// and clears without a reload. Every member runs it: each one's disk is its
// own. Returns when ctx is cancelled.
func (s *Server) watchHubDisk(ctx context.Context) {
	defer recoverGoroutine("watchHubDisk")
	ticker := time.NewTicker(hubDiskCheckInterval)
	defer ticker.Stop()
	for {
		s.checkHubDisk()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// checkHubDisk is one watcher tick. It logs and broadcasts only on a crossing:
// a volume that stays below the floor all day is one event, not 1,440.
func (s *Server) checkHubDisk() {
	v := s.hubDisk()
	if v.Error != "" {
		return
	}
	s.diskMu.Lock()
	was, known := s.diskWasLow, s.diskChecked
	s.diskWasLow, s.diskChecked = v.Low, true
	s.diskMu.Unlock()
	if known && was == v.Low {
		return
	}
	fields := map[string]interface{}{
		"volume": v.Volume, "free_bytes": v.FreeBytes, "floor_bytes": v.FloorBytes,
	}
	switch {
	case v.Low:
		s.log().Warn(logger.EventDiskSpace, 0, "hub state volume below its free-space floor", fields)
	case known:
		s.log().Info(logger.EventDiskSpace, 0, "hub state volume back above its free-space floor", fields)
	}
	if known {
		// Carries nothing but the nudge: who may see the numbers is decided
		// where they are read, by /api/me.
		s.deliverToAll(wsMessage{Type: "hub_disk", Data: json.RawMessage(`{}`)})
	}
}

// hubDiskBanner is what /api/me adds for a caller who may manage the hub, when
// its state volume is below the floor: nil otherwise, which the dashboard reads
// as "no banner".
func (s *Server) hubDiskBanner(r *http.Request) *hubDiskView {
	if !s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermUserManage) {
		return nil
	}
	v := s.hubDisk()
	if !v.Low {
		return nil
	}
	return &v
}

// hubFloorEnv is the environment assignment that hands the hub's floor to a
// workload it starts, or "" when there is none to hand over.
//
// Only for the hub's own directory, where the Settings value may live in the
// overlay that `cloop run` cannot read; every other project's run reads the
// config.yaml its floor is set in. Only on an executor that shares this
// filesystem: the hub's floor describes the hub's disk, and a sandbox or a
// device measures its own against the project's own setting. And only when
// the hub's configuration states a floor — with none, the run's own reading
// arrives at the same default.
func hubFloorEnv(workDir string, ex executor.Executor) string {
	if ex == nil || executor.IsolatesFromHost(ex) {
		return ""
	}
	dir, port := controlPlaneSource()
	if !isSameConfigDir(workDir, dir) {
		return ""
	}
	cfg, err := loadHubConfigAt(dir, port)
	if err != nil || cfg == nil || cfg.Orchestrator.MinFreeDiskMB == nil {
		return ""
	}
	return config.EnvMinFreeDiskMB + "=" + strconv.Itoa(cfg.Orchestrator.EffectiveMinFreeDiskMB())
}

// ── Settings: GET/PUT /api/config/disk ──────────────────────────────────────

// diskFloorSettings is what the Settings panel shows and edits.
type diskFloorSettings struct {
	// MinFreeDiskMB is the floor in force; StatedMB is false when no
	// configuration file states one and the default applies.
	MinFreeDiskMB int  `json:"min_free_disk_mb"`
	Stated        bool `json:"stated"`
	DefaultMB     int  `json:"default_mb"`
	LowerMB       int  `json:"lower_mb"`
	UpperMB       int  `json:"upper_mb"`
	// Overlay reports that a save writes this hub's per-instance overlay
	// rather than config.yaml.
	Overlay bool `json:"overlay"`
	// Hub is the state volume measured against the floor.
	Hub hubDiskView `json:"hub"`
}

func (s *Server) diskFloorSettingsView() diskFloorSettings {
	mb, stated := s.hubFloorMB()
	return diskFloorSettings{
		MinFreeDiskMB: mb,
		Stated:        stated,
		DefaultMB:     config.MinFreeDiskMBDefault,
		LowerMB:       config.MinFreeDiskMBLower,
		UpperMB:       config.MinFreeDiskMBUpper,
		Overlay:       s.hubConfigOverlay() != "",
		Hub:           s.hubDisk(),
	}
}

// handleDiskFloorSettings serves GET /api/config/disk.
func (s *Server) handleDiskFloorSettings(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.diskFloorSettingsView())
}

// handleDiskFloorSave serves PUT /api/config/disk with {"min_free_disk_mb": N}:
// 0 turns the check off, anything else must lie in the configured band.
//
// Written where this hub reads (Task 20364): into its overlay once it has one,
// or config.yaml rewritten from itself. Refused rather than clamped, like
// every other numeric setting's writer: a typo the server quietly repaired
// would leave the panel showing a floor nobody chose.
func (s *Server) handleDiskFloorSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MinFreeDiskMB *int `json:"min_free_disk_mb"`
	}
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	if req.MinFreeDiskMB == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"min_free_disk_mb is required: a number of megabytes, or 0 to turn the check off"))
		return
	}
	mb := *req.MinFreeDiskMB
	if !config.ValidMinFreeDiskMB(mb) {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, config.MinFreeDiskMBError(mb).Error()))
		return
	}

	hubConfigMu.Lock()
	save, err := s.beginHubSettingsSave()
	if err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
		return
	}
	was := save.Config.Orchestrator.EffectiveMinFreeDiskMB()
	wasStated := save.Config.Orchestrator.MinFreeDiskMB != nil
	save.Config.Orchestrator.MinFreeDiskMB = &mb
	file := config.ConfigPath(s.WorkDir)
	if save.overlay != "" {
		file = save.overlay
	}
	err = save.commit(func(overlay string) error {
		return config.SaveUIInstanceMinFreeDisk(overlay, mb)
	})
	hubConfigMu.Unlock()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}

	if !wasStated || was != mb {
		s.auditDiskFloor(r, was, mb, file)
	}
	// The banner follows the new floor now, not at the next tick.
	s.checkHubDisk()
	jsonOK(w, s.diskFloorSettingsView())
}

// auditDiskFloor records a changed floor in the hub's own journal: it is a
// property of the deployment, not of a project. Best-effort, like every other
// emitter here.
func (s *Server) auditDiskFloor(r *http.Request, was, now int, file string) {
	blob, err := json.Marshal(map[string]any{
		"min_free_disk_mb":     now,
		"was_min_free_disk_mb": was,
		"file":                 filepath.Base(file),
	})
	if err != nil {
		return
	}
	actor := s.auditActor(r)
	if actor == "" {
		actor = "anonymous"
	}
	log, logErr := eventlog.Open(s.WorkDir)
	if logErr != nil {
		if logErr != eventlog.ErrNoProject {
			s.log().Warn(logger.EventAuthz, 0, "disk floor audit: open event log",
				map[string]interface{}{"error": logErr.Error()})
		}
		return
	}
	defer log.Close()
	if err := log.Append(&eventlog.AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionDiskFloorUpdated),
		EntityType: "config",
		EntityID:   "orchestrator.min_free_disk_mb",
		Payload:    string(blob),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "disk floor audit: append",
			map[string]interface{}{"error": err.Error()})
	}
}
