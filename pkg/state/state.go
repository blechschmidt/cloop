package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	PMMode bool      `json:"pm_mode,omitempty"`
	Plan   *pm.Plan  `json:"plan,omitempty"`

	// Cumulative token usage across all steps
	TotalInputTokens  int `json:"total_input_tokens,omitempty"`
	TotalOutputTokens int `json:"total_output_tokens,omitempty"`
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
	dir := filepath.Dir(StatePath(s.WorkDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(StatePath(s.WorkDir), data, 0o644)
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
