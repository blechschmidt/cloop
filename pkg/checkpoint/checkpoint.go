// Package checkpoint provides mid-execution checkpointing for PM mode.
// Before each task starts, a checkpoint.json is written so that an interrupted
// run can resume from where it stopped rather than restarting or skipping.
package checkpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const checkpointFile = ".cloop/checkpoint.json"

// Checkpoint holds the mid-execution state for a single in-progress task.
type Checkpoint struct {
	TaskID            int       `json:"task_id"`
	TaskTitle         string    `json:"task_title"`
	StepNumber        int       `json:"step_number"`
	AccumulatedOutput string    `json:"accumulated_output,omitempty"`
	StartTimestamp    time.Time `json:"start_timestamp"`
	Provider          string    `json:"provider,omitempty"`
}

// Path returns the absolute path to the checkpoint file under workDir.
func Path(workDir string) string {
	return filepath.Join(workDir, checkpointFile)
}

// Save writes the checkpoint atomically (write to .tmp then rename).
func Save(workDir string, cp *Checkpoint) error {
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	path := Path(workDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename checkpoint: %w", err)
	}
	return nil
}

// Load reads the checkpoint file. Returns (nil, nil) if no file exists.
func Load(workDir string) (*Checkpoint, error) {
	data, err := os.ReadFile(Path(workDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parse checkpoint: %w", err)
	}
	return &cp, nil
}

// Clear removes the checkpoint file. Silently succeeds if no file exists.
func Clear(workDir string) error {
	err := os.Remove(Path(workDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear checkpoint: %w", err)
	}
	return nil
}

// Exists reports whether a checkpoint file is present.
func Exists(workDir string) bool {
	_, err := os.Stat(Path(workDir))
	return err == nil
}
