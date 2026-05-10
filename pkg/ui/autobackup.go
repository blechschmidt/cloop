// Auto-backup loop for the long-running cloop ui server (Task 20115).
//
// When a project's .cloop/config.yaml has `backup.auto_backup: true`, this
// loop runs a hot backup of that project's state.db on every BackupConfig
// interval (default 24h) and prunes older files to BackupConfig.KeepCount.
//
// Why scheduled here rather than via the host OS cron:
//
//   - cloop ui is the natural daemon: it already lives across project
//     lifecycles and watches every registered project, so a backup loop
//     gets the same benefit "for free" without an external cron entry.
//   - We can opt-in per project via .cloop/config.yaml, which is the same
//     place every other cloop knob lives — operators don't have to learn
//     a separate scheduling surface.
//   - The loop is conservative: it skips the run if config has been
//     toggled off since startup, and it never panics out of the watcher
//     thanks to recoverGoroutine.

package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/dbbackup"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
)

// autoBackupCheckInterval is how often the loop wakes up to evaluate
// per-project schedules. Each project decides independently whether it is
// due for a backup based on the mtime of its most recent backup file.
//
// 1 hour is a good balance: short enough to honour interval_hours: 1
// without missing the window by more than 50%, long enough to keep CPU
// idle between checks. The actual VACUUM INTO runs only when the project
// is genuinely due, so the 1h cadence does not produce 1h backup files.
const autoBackupCheckInterval = 1 * time.Hour

// watchAutoBackup runs the daily auto-backup loop for every registered
// project that has `backup.auto_backup: true`. Returns when ctx is
// cancelled. Designed to be invoked as `go s.watchAutoBackup(ctx)` from
// Run().
func (s *Server) watchAutoBackup(ctx context.Context) {
	defer recoverGoroutine("watchAutoBackup")

	// Run a first sweep shortly after startup so a cron-like miss across
	// a restart still captures the daily cadence within a reasonable
	// window. 30 seconds is enough for the server to finish initialising
	// (route registration, project scan, hub registry) without making
	// startup noticeably slower.
	startupDelay := time.NewTimer(30 * time.Second)
	defer startupDelay.Stop()

	select {
	case <-ctx.Done():
		return
	case <-startupDelay.C:
	}

	s.runAutoBackupSweep()

	ticker := time.NewTicker(autoBackupCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runAutoBackupSweep()
		}
	}
}

// runAutoBackupSweep iterates all known projects and, for each one whose
// config opts in to auto_backup and whose previous backup is older than
// the configured interval, runs a hot backup and prunes excess files.
//
// Errors from any single project are logged and skipped so a misbehaving
// project does not stall the others.
func (s *Server) runAutoBackupSweep() {
	defer recoverGoroutine("runAutoBackupSweep")

	for _, e := range s.allProjectEntries() {
		s.maybeAutoBackup(e.Path)
	}
}

// maybeAutoBackup decides whether to run an auto-backup for one project
// and, if so, runs it. Decision inputs:
//
//   - cfg.Backup.AutoBackup must be true
//   - the project must have a state.db
//   - the most recent existing backup in cfg.Backup.Dir must be older
//     than cfg.Backup.EffectiveIntervalHours()
//
// All file operations are best-effort with errors logged via the server
// logger when present.
func (s *Server) maybeAutoBackup(workDir string) {
	cfg, err := config.Load(workDir)
	if err != nil {
		s.logAutoBackup(workDir, "load config: "+err.Error())
		return
	}
	if !cfg.Backup.AutoBackup {
		return
	}

	dbPath := state.StateDBPath(workDir)
	if _, err := os.Stat(dbPath); err != nil {
		// Project may not have run yet — nothing to back up.
		return
	}

	dir := resolveBackupDir(workDir, cfg.Backup.Dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.logAutoBackup(workDir, "mkdir backup dir: "+err.Error())
		return
	}

	intervalHours := cfg.Backup.EffectiveIntervalHours()
	due, latest := isBackupDue(dir, time.Duration(intervalHours)*time.Hour)
	if !due {
		return
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	out := filepath.Join(dir, fmt.Sprintf("state-%s.db", ts))

	report, err := dbbackup.Backup(dbPath, out)
	if err != nil {
		s.logAutoBackup(workDir, "backup failed: "+err.Error())
		return
	}
	s.logAutoBackup(workDir, fmt.Sprintf(
		"auto-backup ok: %s (%d bytes, %s, prev=%s)",
		report.Output, report.SizeBytes, report.Duration.Round(time.Millisecond),
		summarisePrev(latest),
	))

	pruneOldBackups(dir, cfg.Backup.EffectiveKeepCount(), s.logAutoBackup, workDir)
}

// resolveBackupDir computes the absolute backup directory. An empty config
// value defaults to <workDir>/.cloop/backups; a relative configured value
// is interpreted as relative to workDir; an absolute value is used as-is.
func resolveBackupDir(workDir, configured string) string {
	if configured == "" {
		return filepath.Join(workDir, ".cloop", "backups")
	}
	if filepath.IsAbs(configured) {
		return configured
	}
	return filepath.Join(workDir, configured)
}

// isBackupDue scans dir for state-*.db files and returns (true, "") if no
// prior backup exists or the newest one is older than minAge. Returns the
// path of the most recent existing backup as the second value to feed the
// log line.
func isBackupDue(dir string, minAge time.Duration) (bool, string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Directory missing or unreadable → due (we'll create it).
		return true, ""
	}
	var newest os.FileInfo
	var newestPath string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), "state-") || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if newest == nil || info.ModTime().After(newest.ModTime()) {
			newest = info
			newestPath = filepath.Join(dir, e.Name())
		}
	}
	if newest == nil {
		return true, ""
	}
	if time.Since(newest.ModTime()) < minAge {
		return false, newestPath
	}
	return true, newestPath
}

// pruneOldBackups deletes oldest auto-backup files (and their .meta.json
// sidecars) so at most keep remain. keep == -1 disables pruning.
func pruneOldBackups(dir string, keep int, log func(workDir, msg string), workDir string) {
	if keep < 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type entry struct {
		path string
		mod  time.Time
	}
	var dbs []entry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), "state-") || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		dbs = append(dbs, entry{path: filepath.Join(dir, e.Name()), mod: info.ModTime()})
	}
	if len(dbs) <= keep {
		return
	}
	sort.Slice(dbs, func(i, j int) bool { return dbs[i].mod.Before(dbs[j].mod) })
	excess := len(dbs) - keep
	for i := 0; i < excess; i++ {
		_ = os.Remove(dbs[i].path)
		_ = os.Remove(dbs[i].path + dbbackup.MetadataSuffix)
		if log != nil {
			log(workDir, "pruned old backup: "+filepath.Base(dbs[i].path))
		}
	}
}

func summarisePrev(prev string) string {
	if prev == "" {
		return "<none>"
	}
	return filepath.Base(prev)
}

// logAutoBackup writes a single line through the server's structured logger
// when one is configured, falling back to stderr so messages aren't lost in
// test or no-logger setups.
func (s *Server) logAutoBackup(workDir, msg string) {
	line := fmt.Sprintf("auto-backup [%s] %s", workDir, msg)
	if s != nil && s.Log != nil {
		s.Log.Info(logger.EventStep, 0, line, map[string]interface{}{
			"work_dir":  workDir,
			"component": "autobackup",
		})
		return
	}
	fmt.Fprintln(os.Stderr, line)
}
