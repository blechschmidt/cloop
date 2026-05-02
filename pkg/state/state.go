package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/health"
	"github.com/blechschmidt/cloop/pkg/milestone"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	stateFile      = ".cloop/state.json" // legacy path; kept for migration detection
	stateDBFile    = ".cloop/state.db"   // current SQLite store (default session)
	activeFile     = ".cloop/active_session"
	sessionMetaFile = "session.json"     // sentinel: presence means dir is a session dir
)

// ActiveDir resolves the effective working directory for state operations.
// If a session is active (recorded in .cloop/active_session), it returns
// the session's isolated directory; otherwise it returns workDir unchanged.
func ActiveDir(workDir string) string {
	data, err := os.ReadFile(filepath.Join(workDir, activeFile))
	if err != nil {
		return workDir
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return workDir
	}
	return filepath.Join(workDir, ".cloop", "sessions", name)
}

// effectiveDBPath returns the state.db path for the given directory.
// If dir is a session directory (contains session.json), the state.db lives
// directly inside it rather than in a .cloop/ subdirectory.
func effectiveDBPath(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, sessionMetaFile)); err == nil {
		return filepath.Join(dir, "state.db")
	}
	return filepath.Join(dir, ".cloop", "state.db")
}

// effectiveLegacyPath mirrors effectiveDBPath but for the legacy state.json.
func effectiveLegacyPath(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, sessionMetaFile)); err == nil {
		return filepath.Join(dir, "state.json")
	}
	return filepath.Join(dir, ".cloop", "state.json")
}

type StepResult struct {
	Step         int       `json:"step"`
	Task         string    `json:"task"`
	Output       string    `json:"output"`
	ExitCode     int       `json:"exit_code"`
	Duration     string    `json:"duration"`
	Time         time.Time `json:"time"`
	InputTokens  int       `json:"input_tokens,omitempty"`
	OutputTokens int       `json:"output_tokens,omitempty"`
}

type ProjectState struct {
	Goal           string       `json:"goal"`
	WorkDir        string       `json:"workdir"`
	MaxSteps       int          `json:"max_steps"`
	CurrentStep    int          `json:"current_step"`
	Status         string       `json:"status"` // running, complete, failed, paused, evolving
	Steps          []StepResult `json:"steps"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	Model          string       `json:"model,omitempty"`
	Instructions   string       `json:"instructions,omitempty"`
	AutoEvolve     bool         `json:"auto_evolve"`
	EvolveStep     int          `json:"evolve_step"`

	// Provider settings
	Provider string `json:"provider,omitempty"`

	// Product manager mode
	PMMode     bool                   `json:"pm_mode,omitempty"`
	Plan       *pm.Plan               `json:"plan,omitempty"`
	Milestones []*milestone.Milestone `json:"milestones,omitempty"`

	// Cumulative token usage across all steps
	TotalInputTokens  int `json:"total_input_tokens,omitempty"`
	TotalOutputTokens int `json:"total_output_tokens,omitempty"`

	// HealthReport is the most recent plan health evaluation result.
	HealthReport *health.HealthReport `json:"health_report,omitempty"`

	// DefaultMaxMinutes is the project-level per-task execution time budget.
	DefaultMaxMinutes int `json:"default_max_minutes,omitempty"`

	// SkipClarify persists the --skip-clarify flag.
	SkipClarify bool `json:"skip_clarify,omitempty"`
}

// StatePath returns the legacy JSON state file path (used for migration detection).
func StatePath(workdir string) string {
	return filepath.Join(workdir, stateFile)
}

// StateDBPath returns the SQLite database path for the given workdir.
// It does NOT resolve the active session; use Load for that.
func StateDBPath(workdir string) string {
	return filepath.Join(workdir, stateDBFile)
}

// Load reads project state, resolving the active session first.
// Auto-migrates from state.json on first run.
func Load(workdir string) (*ProjectState, error) {
	// Resolve the active session directory.
	dir := ActiveDir(workdir)

	dbPath := effectiveDBPath(dir)
	jsonPath := effectiveLegacyPath(dir)

	// If state.db doesn't exist but state.json does, run the migration.
	// Also re-migrate when state.json is newer than state.db (e.g. cloop-stable
	// continues writing the legacy file while the UI reads via the new path).
	if dbInfo, dbErr := os.Stat(dbPath); os.IsNotExist(dbErr) {
		if _, jsonErr := os.Stat(jsonPath); jsonErr == nil {
			if migrateErr := migrateFromJSON(dir, jsonPath, dbPath); migrateErr != nil {
				return nil, fmt.Errorf("migrate state.json → state.db: %w", migrateErr)
			}
		}
	} else if dbErr == nil {
		if jsonInfo, jsonErr := os.Stat(jsonPath); jsonErr == nil {
			if jsonInfo.ModTime().After(dbInfo.ModTime()) {
				if migrateErr := migrateFromJSON(dir, jsonPath, dbPath); migrateErr != nil {
					return nil, fmt.Errorf("re-migrate state.json → state.db: %w", migrateErr)
				}
			}
		}
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		if dir != workdir {
			return nil, fmt.Errorf("active session has no state (run 'cloop init' in this session)")
		}
		return nil, fmt.Errorf("no cloop project found (run 'cloop init' first)")
	}

	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	raw, err := db.LoadState()
	if err != nil {
		return nil, err
	}
	s := fromRaw(raw)
	// Ensure WorkDir is set to the resolved session dir so Save() writes back
	// to the correct location.
	if s.WorkDir == "" {
		s.WorkDir = dir
	}
	return s, nil
}

// LoadFromDir loads state directly from a specific directory (e.g. a session
// directory) without going through the active-session resolution in Load.
// dir may be a session dir (state.db lives flat inside) or a regular workDir
// (.cloop/state.db). Returns nil, nil if no state exists.
func LoadFromDir(dir string) (*ProjectState, error) {
	dbPath := effectiveDBPath(dir)
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	raw, err := db.LoadState()
	if err != nil {
		return nil, err
	}
	s := fromRaw(raw)
	if s.WorkDir == "" {
		s.WorkDir = dir
	}
	return s, nil
}

// Save writes the project state to the SQLite store, first merging any tasks
// that were added externally while this state object was in memory. This is the
// standard save path used by the orchestrator.
// UI handlers that intentionally mutate (add/edit/delete) tasks should use
// SaveDirect to avoid the merge re-adding deleted tasks.
func (s *ProjectState) Save() error {
	s.UpdatedAt = time.Now()

	// Merge externally-added tasks before persisting.
	s.mergeExternalTasks()

	// Ensure the parent directory of state.db exists.
	dbPath := effectiveDBPath(s.WorkDir)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}

	db, err := statedb.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.SaveState(toRaw(s)); err != nil {
		return err
	}

	// Append a plan history snapshot whenever the plan changes.
	if s.PMMode && s.Plan != nil {
		_ = pm.SaveSnapshot(s.WorkDir, s.Plan)
	}
	return nil
}

// SaveDirect writes the project state to the SQLite store WITHOUT merging
// externally-added tasks. Use this for intentional UI mutations (add, edit,
// delete tasks) where the caller has already loaded the latest state and
// does not want deleted tasks re-added from disk.
func (s *ProjectState) SaveDirect() error {
	s.UpdatedAt = time.Now()

	dbPath := effectiveDBPath(s.WorkDir)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}

	db, err := statedb.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.SaveState(toRaw(s)); err != nil {
		return err
	}

	if s.PMMode && s.Plan != nil {
		_ = pm.SaveSnapshot(s.WorkDir, s.Plan)
	}
	return nil
}

// SyncFromDisk re-reads the on-disk state and merges externally-added tasks.
func (s *ProjectState) SyncFromDisk() {
	s.mergeExternalTasks()
}

// mergeExternalTasks reads the current state from disk and merges tasks added
// externally (e.g. via 'cloop task add' while running). Any task on disk whose
// ID is not present in the in-memory plan is appended, preserving its full
// content. This is an ID-set merge — it does NOT rely on maxInMemID comparisons,
// so externally-added tasks are never silently dropped due to ID ordering.
func (s *ProjectState) mergeExternalTasks() {
	disk, err := Load(s.WorkDir)
	if err != nil || disk == nil || disk.Plan == nil || len(disk.Plan.Tasks) == 0 {
		return
	}
	if s.Plan == nil {
		return
	}
	// Build set of in-memory task IDs.
	inMemIDs := make(map[int]struct{}, len(s.Plan.Tasks))
	for _, t := range s.Plan.Tasks {
		inMemIDs[t.ID] = struct{}{}
	}
	// Append every disk task whose ID is absent from memory (full content preserved).
	for _, t := range disk.Plan.Tasks {
		if _, exists := inMemIDs[t.ID]; !exists {
			s.Plan.Tasks = append(s.Plan.Tasks, t)
		}
	}
	if disk.PMMode {
		s.PMMode = true
	}
	if len(disk.Instructions) > len(s.Instructions) {
		s.Instructions = disk.Instructions
	}
}

// Init creates a new project state and persists it.
func Init(workdir, goal string, maxSteps int) (*ProjectState, error) {
	s := &ProjectState{
		Goal:      goal,
		WorkDir:   workdir,
		MaxSteps:  maxSteps,
		Status:    "initialized",
		Steps:     []StepResult{},
		CreatedAt: time.Now(),
	}
	if err := s.Save(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ProjectState) AddStep(result StepResult) {
	result.Step = s.CurrentStep
	s.Steps = append(s.Steps, result)
	s.CurrentStep++
}

func (s *ProjectState) LastNSteps(n int) []StepResult {
	if len(s.Steps) <= n {
		return s.Steps
	}
	return s.Steps[len(s.Steps)-n:]
}

// ────────────────────────────────────────────────────────────
// Conversion: ProjectState ↔ statedb.State
// ────────────────────────────────────────────────────────────

func toRaw(s *ProjectState) *statedb.State {
	r := &statedb.State{
		Goal:              s.Goal,
		WorkDir:           s.WorkDir,
		MaxSteps:          s.MaxSteps,
		CurrentStep:       s.CurrentStep,
		Status:            s.Status,
		CreatedAt:         s.CreatedAt,
		UpdatedAt:         s.UpdatedAt,
		Model:             s.Model,
		Instructions:      s.Instructions,
		AutoEvolve:        s.AutoEvolve,
		EvolveStep:        s.EvolveStep,
		Provider:          s.Provider,
		PMMode:            s.PMMode,
		Plan:              s.Plan,
		Milestones:        s.Milestones,
		TotalInputTokens:  s.TotalInputTokens,
		TotalOutputTokens: s.TotalOutputTokens,
		HealthReport:      s.HealthReport,
		DefaultMaxMinutes: s.DefaultMaxMinutes,
		SkipClarify:       s.SkipClarify,
	}
	r.Steps = make([]statedb.StepRow, len(s.Steps))
	for i, sr := range s.Steps {
		r.Steps[i] = statedb.StepRow{
			Step:         sr.Step,
			Task:         sr.Task,
			Output:       sr.Output,
			ExitCode:     sr.ExitCode,
			Duration:     sr.Duration,
			Time:         sr.Time,
			InputTokens:  sr.InputTokens,
			OutputTokens: sr.OutputTokens,
		}
	}
	return r
}

func fromRaw(r *statedb.State) *ProjectState {
	s := &ProjectState{
		Goal:              r.Goal,
		WorkDir:           r.WorkDir,
		MaxSteps:          r.MaxSteps,
		CurrentStep:       r.CurrentStep,
		Status:            r.Status,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
		Model:             r.Model,
		Instructions:      r.Instructions,
		AutoEvolve:        r.AutoEvolve,
		EvolveStep:        r.EvolveStep,
		Provider:          r.Provider,
		PMMode:            r.PMMode,
		Plan:              r.Plan,
		Milestones:        r.Milestones,
		TotalInputTokens:  r.TotalInputTokens,
		TotalOutputTokens: r.TotalOutputTokens,
		HealthReport:      r.HealthReport,
		DefaultMaxMinutes: r.DefaultMaxMinutes,
		SkipClarify:       r.SkipClarify,
	}
	s.Steps = make([]StepResult, len(r.Steps))
	for i, row := range r.Steps {
		s.Steps[i] = StepResult{
			Step:         row.Step,
			Task:         row.Task,
			Output:       row.Output,
			ExitCode:     row.ExitCode,
			Duration:     row.Duration,
			Time:         row.Time,
			InputTokens:  row.InputTokens,
			OutputTokens: row.OutputTokens,
		}
	}
	return s
}

// ────────────────────────────────────────────────────────────
// Migration: state.json → state.db
// ────────────────────────────────────────────────────────────

// legacyState mirrors ProjectState for JSON decoding (avoids the import of
// newer packages that might not exist in old JSON files).
type legacyState struct {
	Goal              string               `json:"goal"`
	WorkDir           string               `json:"workdir"`
	MaxSteps          int                  `json:"max_steps"`
	CurrentStep       int                  `json:"current_step"`
	Status            string               `json:"status"`
	Steps             []StepResult         `json:"steps"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
	Model             string               `json:"model,omitempty"`
	Instructions      string               `json:"instructions,omitempty"`
	AutoEvolve        bool                 `json:"auto_evolve"`
	EvolveStep        int                  `json:"evolve_step"`
	Provider          string               `json:"provider,omitempty"`
	PMMode            bool                 `json:"pm_mode,omitempty"`
	Plan              *pm.Plan             `json:"plan,omitempty"`
	Milestones        []*milestone.Milestone `json:"milestones,omitempty"`
	TotalInputTokens  int                  `json:"total_input_tokens,omitempty"`
	TotalOutputTokens int                  `json:"total_output_tokens,omitempty"`
	HealthReport      *health.HealthReport `json:"health_report,omitempty"`
	DefaultMaxMinutes int                  `json:"default_max_minutes,omitempty"`
	SkipClarify       bool                 `json:"skip_clarify,omitempty"`
}

func migrateFromJSON(dir, jsonPath, dbPath string) error {
	workdir := dir
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return err
	}
	var legacy legacyState
	if err := json.Unmarshal(data, &legacy); err != nil {
		return fmt.Errorf("parse state.json: %w", err)
	}

	// Ensure workdir is set (older files may omit it).
	if legacy.WorkDir == "" {
		legacy.WorkDir = workdir
	}

	s := &ProjectState{
		Goal:              legacy.Goal,
		WorkDir:           legacy.WorkDir,
		MaxSteps:          legacy.MaxSteps,
		CurrentStep:       legacy.CurrentStep,
		Status:            legacy.Status,
		Steps:             legacy.Steps,
		CreatedAt:         legacy.CreatedAt,
		UpdatedAt:         legacy.UpdatedAt,
		Model:             legacy.Model,
		Instructions:      legacy.Instructions,
		AutoEvolve:        legacy.AutoEvolve,
		EvolveStep:        legacy.EvolveStep,
		Provider:          legacy.Provider,
		PMMode:            legacy.PMMode,
		Plan:              legacy.Plan,
		Milestones:        legacy.Milestones,
		TotalInputTokens:  legacy.TotalInputTokens,
		TotalOutputTokens: legacy.TotalOutputTokens,
		HealthReport:      legacy.HealthReport,
		DefaultMaxMinutes: legacy.DefaultMaxMinutes,
		SkipClarify:       legacy.SkipClarify,
	}

	db, err := statedb.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.SaveState(toRaw(s))
}
