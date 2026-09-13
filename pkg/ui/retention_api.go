package ui

import (
	"net/http"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/janitor"
)

// diskUsageResponse is what GET /api/disk-usage returns.
//
// It pairs the measurement with the policy on purpose. "2.3 GB, 87% of it
// reclaimable" is alarming on its own and unremarkable once you know a pass is
// scheduled for tonight; an operator reading one number without the other
// draws the wrong conclusion either way.
type diskUsageResponse struct {
	*diskusage.Usage
	Policy diskUsagePolicy `json:"policy"`
	// LastRun is when the last janitor pass completed, or nil if none has.
	LastRun *time.Time `json:"last_run,omitempty"`
	// NextDue is when the next pass becomes eligible. Nil when retention is
	// disabled, since none is coming.
	NextDue *time.Time `json:"next_due,omitempty"`
	// WillVacuum reports whether the current freelist already crosses the
	// configured threshold — i.e. whether the next pass will rewrite the file.
	WillVacuum bool `json:"will_vacuum"`
}

// diskUsagePolicy is the subset of the janitor policy worth showing.
type diskUsagePolicy struct {
	Enabled           bool    `json:"enabled"`
	IntervalHours     float64 `json:"interval_hours"`
	KeepSnapshots     int     `json:"keep_snapshots"`
	ArchiveMaxBytes   int64   `json:"archive_max_bytes"`
	ArchiveMaxAgeDays int     `json:"archive_max_age_days"`
	VacuumFreeRatio   float64 `json:"vacuum_free_ratio"`
	VacuumMinFree     int64   `json:"vacuum_min_free_bytes"`
}

// handleDiskUsage serves GET /api/disk-usage for the selected project
// (Task 20229).
//
// Read-only and project-scoped: it resolves the work directory through
// resolveWorkDir so ?project_idx=N selects which project is measured, the same
// as every other per-project endpoint.
//
// The measurement walks .cloop and opens the database for two header pragmas.
// That is cheap relative to a page load and is not cached, deliberately: the
// question this answers is "what is the disk doing right now", and a stale
// answer to that is worse than no answer.
func (s *Server) handleDiskUsage(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)

	usage, err := diskusage.Measure(workDir)
	if err != nil {
		jsonErr(w, "measure disk usage: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// A project whose config will not parse still has a disk; report the
	// default policy rather than failing the whole panel.
	cfg, cfgErr := config.Load(workDir)
	if cfgErr != nil {
		cfg = nil
	}
	pol := janitor.PolicyFromConfig(cfg)

	resp := diskUsageResponse{
		Usage: usage,
		Policy: diskUsagePolicy{
			Enabled:           pol.Enabled,
			IntervalHours:     pol.Interval.Hours(),
			KeepSnapshots:     pol.KeepSnapshots,
			ArchiveMaxBytes:   pol.ArchiveMaxBytes,
			ArchiveMaxAgeDays: pol.ArchiveMaxAgeDays,
			VacuumFreeRatio:   pol.VacuumFreeRatio,
			VacuumMinFree:     pol.VacuumMinFreeBytes,
		},
		WillVacuum: pol.Enabled &&
			pol.VacuumFreeRatio < 1 &&
			usage.FreeRatio >= pol.VacuumFreeRatio &&
			usage.ReclaimableBytes >= pol.VacuumMinFreeBytes,
	}
	if last, ok := janitor.LastRun(workDir); ok {
		resp.LastRun = &last
		if pol.Enabled {
			next := last.Add(pol.Interval)
			resp.NextDue = &next
		}
	}

	jsonOK(w, resp)
}
