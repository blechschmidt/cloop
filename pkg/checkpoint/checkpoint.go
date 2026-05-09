// Package checkpoint provides mid-execution checkpointing for PM mode.
// Before each task starts, a checkpoint.json is written so that an interrupted
// run can resume from where it stopped rather than restarting or skipping.
package checkpoint

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/boundedread"
)

const checkpointFile = ".cloop/checkpoint.json"
const historyBaseDir = ".cloop/task-checkpoints"

// maxCheckpointBytes caps how much of a single checkpoint JSON we load into
// memory. Checkpoints persist mid-run task state including streamed
// AccumulatedOutput, so the cap is generous (8 MiB) but keeps a planted or
// runaway file from OOMing the process. Declared as var so tests can shrink
// it.
var maxCheckpointBytes int64 = 8 << 20

// Checkpoint holds the mid-execution state for a single in-progress task.
type Checkpoint struct {
	TaskID            int       `json:"task_id"`
	TaskTitle         string    `json:"task_title"`
	StepNumber        int       `json:"step_number"`
	AccumulatedOutput string    `json:"accumulated_output,omitempty"`
	StartTimestamp    time.Time `json:"start_timestamp"`
	Provider          string    `json:"provider,omitempty"`
	// Metadata for checkpoint-diff
	Event        string    `json:"event,omitempty"`         // "start", "complete", "fail", "skip"
	Status       string    `json:"status,omitempty"`        // task status at checkpoint time
	OutputHash   string    `json:"output_hash,omitempty"`   // SHA-256 hex of AccumulatedOutput
	OutputLength int       `json:"output_length,omitempty"` // len(AccumulatedOutput)
	TokenCount   int       `json:"token_count,omitempty"`   // total tokens used so far
	ElapsedSec   float64   `json:"elapsed_sec,omitempty"`   // seconds since task start
	Timestamp    time.Time `json:"timestamp,omitempty"`     // wall-clock time of this entry
}

// HashOutput returns the SHA-256 hex digest of s, or "" for empty strings.
func HashOutput(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:8]) // short 8-byte prefix is enough for display
}

// historyDir returns the directory for per-task checkpoint history.
func historyDir(workDir string, taskID int) string {
	return filepath.Join(workDir, historyBaseDir, fmt.Sprintf("task-%d", taskID))
}

// SaveHistoryEntry appends a timestamped checkpoint entry for a task.
// Files are named <unix-nano>.json inside .cloop/task-checkpoints/task-<id>/.
//
// The write is atomic — staged in a sibling .tmp file, fsynced, then renamed
// into place. Without this, a crash mid-write would leave a truncated JSON
// file that ListHistory silently skips on the next load, dropping the
// progress record permanently.
func SaveHistoryEntry(workDir string, cp *Checkpoint) error {
	dir := historyDir(workDir, cp.TaskID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create history dir: %w", err)
	}
	// Populate derived metadata fields.
	if cp.Timestamp.IsZero() {
		cp.Timestamp = time.Now()
	}
	if cp.AccumulatedOutput != "" && cp.OutputHash == "" {
		cp.OutputHash = HashOutput(cp.AccumulatedOutput)
		cp.OutputLength = len(cp.AccumulatedOutput)
	}
	id := fmt.Sprintf("%d", cp.Timestamp.UnixNano())
	path := filepath.Join(dir, id+".json")
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal history entry: %w", err)
	}
	if err := atomicfile.Write(path, data, 0o644); err != nil {
		return fmt.Errorf("write history entry: %w", err)
	}
	return nil
}

// HistoryEntry wraps a Checkpoint with its on-disk ID.
type HistoryEntry struct {
	ID         string // the unix-nano filename stem
	Checkpoint *Checkpoint
}

// ListHistory returns all checkpoint history entries for a task, sorted oldest-first.
func ListHistory(workDir string, taskID int) ([]*HistoryEntry, error) {
	dir := historyDir(workDir, taskID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read history dir: %w", err)
	}
	var result []*HistoryEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		data, err := boundedread.ReadFile(filepath.Join(dir, e.Name()), maxCheckpointBytes)
		if err != nil {
			continue
		}
		var cp Checkpoint
		if err := json.Unmarshal(data, &cp); err != nil {
			continue
		}
		result = append(result, &HistoryEntry{ID: id, Checkpoint: &cp})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result, nil
}

// LoadHistoryEntry loads a single checkpoint history entry by its ID.
func LoadHistoryEntry(workDir string, taskID int, id string) (*Checkpoint, error) {
	path := filepath.Join(historyDir(workDir, taskID), id+".json")
	data, err := boundedread.ReadFile(path, maxCheckpointBytes)
	if err != nil {
		return nil, fmt.Errorf("read history entry %s: %w", id, err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parse history entry %s: %w", id, err)
	}
	return &cp, nil
}

// Path returns the absolute path to the checkpoint file under workDir.
func Path(workDir string) string {
	return filepath.Join(workDir, checkpointFile)
}

// Save writes the checkpoint atomically (stage in a sibling .tmp file,
// fsync, then rename into place). The fsync closes a window where a power
// loss between WriteFile and Rename could leave the rename target pointing
// at zero-length data on some filesystems.
func Save(workDir string, cp *Checkpoint) error {
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	path := Path(workDir)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create checkpoint dir: %w", err)
	}
	if err := atomicfile.Write(path, data, 0o644); err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}
	return nil
}

// Load reads the checkpoint file. Returns (nil, nil) if no file exists.
//
// On parse failure (zero-byte file, schema drift from an older binary, manual
// edit gone wrong) the corrupt file is quarantined aside as
// checkpoint.json.corrupt-<unix> and (nil, nil) is returned. Losing the
// in-progress checkpoint is preferable to refusing to start a new run — and
// the user has the bytes preserved next to it for forensics.
func Load(workDir string) (*Checkpoint, error) {
	path := Path(workDir)
	data, err := boundedread.ReadFile(path, maxCheckpointBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if errors.Is(err, boundedread.ErrTooLarge) {
			qpath := atomicfile.QuarantineCorrupt(path)
			if qpath != "" {
				fmt.Fprintf(os.Stderr, "warning: checkpoint at %s exceeded size limit (%v); quarantined to %s, starting fresh\n", path, err, qpath)
			}
			return nil, nil
		}
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		qpath := atomicfile.QuarantineCorrupt(path)
		if qpath != "" {
			fmt.Fprintf(os.Stderr, "warning: checkpoint at %s was corrupt (%v); quarantined to %s, starting fresh\n", path, err, qpath)
		} else {
			fmt.Fprintf(os.Stderr, "warning: checkpoint at %s was corrupt (%v) and could not be quarantined; ignoring\n", path, err)
		}
		return nil, nil
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
