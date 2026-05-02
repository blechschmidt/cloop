package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const replayFile = ".cloop/replay.jsonl"

// Entry is one line in the replay log.
type Entry struct {
	Ts        time.Time `json:"ts"`
	TaskID    int       `json:"task_id"`
	TaskTitle string    `json:"task_title"`
	Step      int       `json:"step"`
	Content   string    `json:"content"`
}

var mu sync.Mutex

// Append writes entry as a JSON line to .cloop/replay.jsonl (append-only).
// Errors are non-fatal — the caller may ignore them.
func Append(workDir string, entry Entry) error {
	mu.Lock()
	defer mu.Unlock()

	dir := filepath.Join(workDir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("replay: mkdir: %w", err)
	}

	path := filepath.Join(workDir, replayFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("replay: open: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("replay: marshal: %w", err)
	}
	_, err = f.Write(append(line, '\n'))
	return err
}

// Load reads all entries from the replay log. If taskID > 0 only entries
// matching that task_id are returned.
func Load(workDir string, taskID int) ([]Entry, error) {
	path := filepath.Join(workDir, replayFile)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("replay: open: %w", err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	// Allow up to 10 MB per line (large task outputs)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			// Skip malformed lines silently
			continue
		}
		if taskID > 0 && e.TaskID != taskID {
			continue
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}
