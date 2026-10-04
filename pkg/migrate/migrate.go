// Package migrate upgrades and repairs a project's .cloop directory.
//
// The project database belongs to pkg/statedb, which migrates it every time
// anything opens it: numbered migrations embedded in the binary, recorded in
// schema_migrations. This package used to run a second schema system beside
// that one (Task 187) — its own version number in metadata.schema_version, its
// own CREATE TABLE for a converted state.json, its own ALTER TABLE on
// plan_tasks — and the two disagreed (Task 20374):
//
//   - statedb never wrote schema_version, so every project created by a current
//     binary read as version 1 of 2, and every interactive command told its
//     user to run `cloop migrate` on a project that was up to date;
//   - the state.json conversion created three of the six tables statedb's first
//     migration does, so statedb adopted the result as version 1 and then
//     failed on the first later migration that touched a missing table — and
//     every command that opened the project failed with it;
//   - the ALTER TABLE added plan_tasks columns statedb did not know about until
//     migration 0054 had to adopt them.
//
// So this package no longer has a schema. It reports what a project's state
// storage is without writing to it (Inspect), says whether the project needs
// `cloop migrate` (NeedsUpgrade), and when it does, Run hands the work to the
// code that owns the schema: pkg/state converts a legacy state.json, through
// statedb, exactly as Load would; statedb.Open adopts a database its framework
// has never seen and applies whatever migrations are pending.
//
// Two kinds of project need it, and only these: a legacy one whose state exists
// only in state.json, and one whose state.db predates statedb's migration
// framework. Every other database is statedb's own, and is migrated whenever
// anything opens it.
package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Kind is what a project's state storage is.
type Kind string

const (
	// KindNone is a directory with no project state.
	KindNone Kind = "none"
	// KindLegacyJSON is a project whose state exists only in state.json: no
	// state.db, or one that holds no project.
	KindLegacyJSON Kind = "legacy-json"
	// KindPreStatedb is a state.db that statedb's migration framework has
	// never opened: it has no schema_migrations table.
	KindPreStatedb Kind = "pre-statedb"
	// KindStatedb is a state.db statedb owns, which is migrated whenever
	// anything opens it.
	KindStatedb Kind = "statedb"
)

// Status describes a project's state storage. Inspect produces it without
// writing anything.
type Status struct {
	Kind Kind
	// DBPath and JSONPath are where the database and the legacy file are, or
	// would be — the active session's when one is active.
	DBPath   string
	JSONPath string
	// SchemaVersion is the highest statedb migration the database records;
	// zero when it records none.
	SchemaVersion int
	// LatestVersion is the highest migration this binary carries.
	LatestVersion int
	// LegacyNewer reports a state.json beside a database it is newer than:
	// something older than this binary is still writing the legacy file, and
	// loading the project converts it again.
	LegacyNewer bool
}

// Pending is how many of this binary's migrations the database has not had.
// Zero for a database ahead of the binary; see Ahead.
func (s Status) Pending() int {
	if s.Kind == KindLegacyJSON || s.SchemaVersion >= s.LatestVersion {
		return 0
	}
	return s.LatestVersion - s.SchemaVersion
}

// Ahead reports a database migrated past this binary, which statedb refuses
// to open (see statedb's schema guard).
func (s Status) Ahead() bool { return s.SchemaVersion > s.LatestVersion }

// Describe names the storage in a phrase for reports: "statedb schema v56".
func (s Status) Describe() string {
	switch s.Kind {
	case KindNone:
		return "no project state"
	case KindLegacyJSON:
		return "legacy state.json"
	case KindPreStatedb:
		return "state.db from before statedb's migrations"
	}
	return fmt.Sprintf("statedb schema v%d", s.SchemaVersion)
}

// Inspect reports what workDir's state storage is. It never writes: the
// database is read through a read-only handle, so asking cannot migrate it,
// create it, or wait on anything but another process's lock.
func Inspect(workDir string) (Status, error) {
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		return Status{}, err
	}
	st := Status{
		Kind:          KindNone,
		DBPath:        state.DBPath(workDir),
		JSONPath:      state.LegacyPath(workDir),
		LatestVersion: latest,
	}
	jsonInfo, jsonErr := os.Stat(st.JSONPath)
	hasJSON := jsonErr == nil && !jsonInfo.IsDir()
	dbInfo, dbErr := os.Stat(st.DBPath)
	switch {
	case errors.Is(dbErr, fs.ErrNotExist):
		if hasJSON {
			st.Kind = KindLegacyJSON
		}
		return st, nil
	case dbErr != nil:
		return st, fmt.Errorf("inspect %s: %w", st.DBPath, dbErr)
	}

	schema, err := statedb.InspectSchema(st.DBPath)
	if err != nil {
		return st, err
	}
	st.SchemaVersion = schema.Version

	switch {
	case hasJSON && !schema.HoldsProject:
		// A database that exists but holds no project — something opened it
		// for an unrelated reason — while the project is still in state.json.
		st.Kind = KindLegacyJSON
	case schema.PreFramework:
		st.Kind = KindPreStatedb
	default:
		// Either statedb's own, or a file with no tables at all, which
		// statedb.Open builds from scratch like any new database.
		st.Kind = KindStatedb
		st.LegacyNewer = hasJSON && jsonInfo.ModTime().After(dbInfo.ModTime())
	}
	return st, nil
}

// NeedsUpgrade reports whether workDir holds a project that needs `cloop
// migrate`: one whose state exists only in a legacy state.json, or whose
// state.db predates statedb's migrations. A database statedb owns is migrated
// whenever anything opens it and never needs this, whatever its version. Any
// doubt — no project, an unreadable database — answers false: this decides
// whether every command prints a warning, and a wrong warning on every command
// is the defect it was rewritten for.
func NeedsUpgrade(workDir string) bool {
	if _, err := os.Stat(filepath.Join(workDir, ".cloop")); err != nil {
		return false
	}
	st, err := Inspect(workDir)
	if err != nil {
		return false
	}
	return st.Kind == KindLegacyJSON || st.Kind == KindPreStatedb
}

// Report summarises what Run did, or on a dry run would do.
type Report struct {
	DryRun bool
	// Before is the state storage Run found; After is what it left, which on
	// a dry run is Before again.
	Before Status
	After  Status
	Steps  []StepReport
	// Warnings are conditions Run did not change and the operator should
	// know about.
	Warnings []string
}

// StepReport is one thing Run did or would do.
type StepReport struct {
	Applied bool
	Note    string
}

// RepairReport describes a single repair action.
type RepairReport struct {
	Kind   string // "orphan_snapshot", "invalid_config_key"
	Detail string
	Fixed  bool
}

// Options controls Run.
type Options struct {
	WorkDir string
	DryRun  bool
}

// Run brings workDir's state storage up to date — through pkg/state and
// statedb, never through SQL of its own — and repairs what it can around it.
func Run(opts Options) (*Report, []RepairReport, error) {
	before, err := Inspect(opts.WorkDir)
	if err != nil {
		return nil, nil, err
	}
	rep := &Report{DryRun: opts.DryRun, Before: before, After: before}
	if before.Ahead() {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"the database records schema v%d, which is newer than this binary's v%d — statedb refuses to "+
				"open it; use the build that migrated it, or a newer one", before.SchemaVersion, before.LatestVersion))
	}

	if opts.DryRun {
		rep.Steps = plannedSteps(before)
	} else {
		steps, after, err := upgrade(opts.WorkDir, before)
		rep.Steps = steps
		if after.Kind != "" {
			rep.After = after
		}
		if err != nil {
			return rep, nil, err
		}
	}

	repairs, err := repairExisting(filepath.Join(opts.WorkDir, ".cloop"), opts.DryRun)
	return rep, repairs, err
}

// plannedSteps says what upgrade would do with st.
func plannedSteps(st Status) []StepReport {
	var steps []StepReport
	switch st.Kind {
	case KindLegacyJSON:
		note := "would convert state.json → state.db through statedb"
		if tasks, stepCount, err := legacyCounts(st.JSONPath); err == nil {
			note += fmt.Sprintf(" (%d tasks, %d steps)", tasks, stepCount)
		}
		steps = append(steps, StepReport{Applied: true, Note: note +
			fmt.Sprintf(", creating statedb schema v%d", st.LatestVersion)})
	case KindPreStatedb:
		steps = append(steps, StepReport{Applied: true, Note: fmt.Sprintf(
			"would adopt the database into statedb's migrations and apply v2–v%d", st.LatestVersion)})
	case KindStatedb:
		if st.LegacyNewer {
			steps = append(steps, StepReport{Applied: true,
				Note: "would convert state.json again: it is newer than state.db, so something is still writing it"})
		}
		if n := st.Pending(); n > 0 {
			steps = append(steps, StepReport{Applied: true, Note: fmt.Sprintf(
				"would apply statedb migrations v%d–v%d", st.SchemaVersion+1, st.LatestVersion)})
		}
	}
	return steps
}

// upgrade does what plannedSteps describes. The conversion is pkg/state's and
// the migration statedb's; this only decides that they run, and reports.
func upgrade(workDir string, before Status) ([]StepReport, Status, error) {
	var steps []StepReport
	if before.Kind == KindLegacyJSON || before.LegacyNewer {
		tasks, stepCount, countErr := legacyCounts(before.JSONPath)
		converted, err := state.MigrateLegacy(workDir)
		if err != nil {
			return steps, Status{}, err
		}
		if converted {
			note := "converted state.json → state.db through statedb"
			if countErr == nil {
				note += fmt.Sprintf(" (%d tasks, %d steps)", tasks, stepCount)
			}
			steps = append(steps, StepReport{Applied: true, Note: note})
		}
	}

	if _, err := os.Stat(before.DBPath); err == nil {
		db, err := statedb.Open(before.DBPath)
		if err != nil {
			return steps, Status{}, err
		}
		if err := db.Close(); err != nil {
			return steps, Status{}, err
		}
	}

	after, err := Inspect(workDir)
	if err != nil {
		return steps, Status{}, err
	}
	switch {
	case before.Kind == KindPreStatedb && after.Kind == KindStatedb:
		steps = append(steps, StepReport{Applied: true, Note: fmt.Sprintf(
			"adopted the database into statedb's migrations and applied v2–v%d", after.SchemaVersion)})
	case before.Kind == KindStatedb && after.SchemaVersion > before.SchemaVersion:
		steps = append(steps, StepReport{Applied: true, Note: fmt.Sprintf(
			"applied statedb migrations v%d–v%d", before.SchemaVersion+1, after.SchemaVersion)})
	}
	return steps, after, nil
}

// legacyCounts reads how many tasks and steps a legacy state.json holds, for
// the report. Bounded like pkg/state's own read of the file.
func legacyCounts(jsonPath string) (tasks, steps int, err error) {
	data, err := boundedread.ReadFile(jsonPath, 64<<20)
	if err != nil {
		return 0, 0, err
	}
	var legacy struct {
		Plan  *pm.Plan          `json:"plan"`
		Steps []json.RawMessage `json:"steps"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return 0, 0, err
	}
	if legacy.Plan != nil {
		tasks = len(legacy.Plan.Tasks)
	}
	return tasks, len(legacy.Steps), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Repair
// ─────────────────────────────────────────────────────────────────────────────

// repairExisting runs the repairs on the project's .cloop directory.
func repairExisting(dotcloop string, dryRun bool) ([]RepairReport, error) {
	var repairs []RepairReport

	r, err := repairOrphanSnapshots(dotcloop, dryRun)
	repairs = append(repairs, r...)
	if err != nil {
		return repairs, err
	}

	r2, err := repairConfigTypes(dotcloop, dryRun)
	repairs = append(repairs, r2...)
	return repairs, err
}

// repairOrphanSnapshots removes plan-history snapshot files whose task IDs
// no longer exist in the current plan_tasks table.
func repairOrphanSnapshots(dotcloop string, dryRun bool) ([]RepairReport, error) {
	histDir := filepath.Join(dotcloop, "plan-history")
	if _, err := os.Stat(histDir); err != nil {
		return nil, nil // no snapshots dir
	}
	dbPath := filepath.Join(dotcloop, "state.db")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil
	}

	conn, err := statedb.OpenConn(dbPath, statedb.ReadOnly)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Collect known task IDs.
	rows, err := conn.Query(`SELECT id FROM plan_tasks`)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	knownIDs := map[int]bool{}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		knownIDs[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var repairs []RepairReport
	_ = filepath.WalkDir(histDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		// Quick parse: check if file references task IDs that no longer exist.
		raw, e := os.ReadFile(path)
		if e != nil {
			return nil
		}
		var snap snapshotFile
		if e := json.Unmarshal(raw, &snap); e != nil {
			return nil
		}
		orphaned := false
		for _, t := range snap.Tasks {
			if !knownIDs[t.ID] && len(snap.Tasks) == 1 {
				orphaned = true
				break
			}
		}
		if orphaned {
			rep := RepairReport{
				Kind:   "orphan_snapshot",
				Detail: fmt.Sprintf("%s references non-existent task IDs", filepath.Base(path)),
			}
			if !dryRun {
				if e := os.Remove(path); e == nil {
					rep.Fixed = true
				}
			}
			repairs = append(repairs, rep)
		}
		return nil
	})

	return repairs, nil
}

// repairConfigTypes checks config.yaml for keys with obviously wrong types
// (e.g. numeric strings for boolean fields).
func repairConfigTypes(dotcloop string, dryRun bool) ([]RepairReport, error) {
	cfgPath := filepath.Join(dotcloop, "config.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, nil // no config; nothing to repair
	}

	var repairs []RepairReport
	lines := strings.Split(string(raw), "\n")
	boolKeys := map[string]bool{
		"auto_evolve":  true,
		"pm_mode":      true,
		"skip_clarify": true,
	}
	for i, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if !boolKeys[key] {
			continue
		}
		// Accept "true", "false", "yes", "no", "1", "0" — flag anything else.
		switch strings.ToLower(val) {
		case "true", "false", "yes", "no", "1", "0", "":
			continue
		default:
			rep := RepairReport{
				Kind:   "invalid_config_key",
				Detail: fmt.Sprintf("config.yaml line %d: key %q has unexpected value %q (expected bool)", i+1, key, val),
			}
			repairs = append(repairs, rep)
		}
	}
	return repairs, nil
}

// snapshotFile is the shape of a plan-history JSON snapshot (partial parse).
type snapshotFile struct {
	Tasks []*pm.Task `json:"tasks"`
}
