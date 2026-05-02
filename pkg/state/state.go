package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/health"
	"github.com/blechschmidt/cloop/pkg/milestone"
	"github.com/blechschmidt/cloop/pkg/pm"
)

const stateFile = ".cloop/state.json"

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
	PMMode     bool                    `json:"pm_mode,omitempty"`
	Plan       *pm.Plan                `json:"plan,omitempty"`
	Milestones []*milestone.Milestone  `json:"milestones,omitempty"`

	// Cumulative token usage across all steps
	TotalInputTokens  int `json:"total_input_tokens,omitempty"`
	TotalOutputTokens int `json:"total_output_tokens,omitempty"`

	// HealthReport is the most recent plan health evaluation result.
	// Populated after decomposition in PM mode (unless --skip-health-check).
	HealthReport *health.HealthReport `json:"health_report,omitempty"`

	// DefaultMaxMinutes is the project-level per-task execution time budget.
	// When a task's own MaxMinutes is 0, this value is used. 0 = no limit.
	DefaultMaxMinutes int `json:"default_max_minutes,omitempty"`
}

func StatePath(workdir string) string {
	return filepath.Join(workdir, stateFile)
}

func Load(workdir string) (*ProjectState, error) {
	data, err := os.ReadFile(StatePath(workdir))
	if err != nil {
		return nil, fmt.Errorf("no cloop project found (run 'cloop init' first): %w", err)
	}
	var s ProjectState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("corrupt state file: %w", err)
	}
	return &s, nil
}

func (s *ProjectState) Save() error {
	s.UpdatedAt = time.Now()

	// Merge externally-added tasks: re-read the plan from disk and
	// incorporate any tasks that were added while we were running.
	s.mergeExternalTasks()

	dir := filepath.Dir(StatePath(s.WorkDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(StatePath(s.WorkDir), data, 0o644); err != nil {
		return err
	}

	// Append a plan history snapshot whenever the plan changes.
	if s.PMMode && s.Plan != nil {
		// SaveSnapshot deduplicates — it's safe to call on every Save.
		_ = pm.SaveSnapshot(s.WorkDir, s.Plan)
	}
	return nil
}

// SyncFromDisk re-reads the on-disk state and merges any tasks that were
// added externally while the orchestrator was running. Call this before
// checking plan completion so that externally-added tasks are visible.
func (s *ProjectState) SyncFromDisk() {
	s.mergeExternalTasks()
}

// mergeExternalTasks reads the current state from disk and merges any tasks
// that were added externally (e.g. via 'cloop task add' while running).
// Tasks are matched by ID — new IDs on disk are appended to the in-memory plan.
func (s *ProjectState) mergeExternalTasks() {
	disk, err := Load(s.WorkDir)
	if err != nil || disk == nil || disk.Plan == nil || len(disk.Plan.Tasks) == 0 {
		return
	}
	if s.Plan == nil {
		// Caller intentionally cleared the plan (e.g., replan). Do not restore.
		return
	}
	// Determine the highest task ID currently in memory. We only merge tasks
	// from disk whose IDs are strictly greater — this ensures that:
	//   (a) externally-added tasks (always assigned maxID+1) are picked up, and
	//   (b) tasks intentionally removed from the in-memory plan are not restored
	//       (their IDs are ≤ maxInMemID and would otherwise be re-added).
	maxInMemID := 0
	for _, t := range s.Plan.Tasks {
		if t.ID > maxInMemID {
			maxInMemID = t.ID
		}
	}
	// Append any tasks from disk that were added externally (new higher IDs).
	for _, t := range disk.Plan.Tasks {
		if t.ID > maxInMemID {
			s.Plan.Tasks = append(s.Plan.Tasks, t)
		}
	}
	// If disk state has PMMode enabled, preserve it
	if disk.PMMode {
		s.PMMode = true
	}
	// Also merge instructions if disk has additions
	if len(disk.Instructions) > len(s.Instructions) {
		s.Instructions = disk.Instructions
	}
}

func Init(workdir, goal string, maxSteps int) (*ProjectState, error) {
	s := &ProjectState{
		Goal:      goal,
		WorkDir:   workdir,
		MaxSteps:  maxSteps, // 0 = unlimited
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
