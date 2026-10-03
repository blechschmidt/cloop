package donecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
)

// Bounds on a carry, which lives in a directory the agent can write to.
const (
	// maxCarryPaths bounds how many blamed paths a carry remembers.
	maxCarryPaths = 500
	// maxCarryBytes bounds the file read back.
	maxCarryBytes = 256 << 10
	// CarryMaxAge is how long a carry is honoured. A task re-run weeks later
	// starts from whatever the tree holds then.
	CarryMaxAge = 7 * 24 * time.Hour
)

// carryFormat is the version of the carry file this build writes.
const carryFormat = 1

// Carry is what an attempt that was blamed for outstanding work leaves on
// record for the next attempt at the same task: the paths it left
// uncommitted, and the HEAD the first such attempt started at. Without it the
// next attempt's baseline would find that work already in the tree, count it
// as somebody else's, and let it through.
//
// It is not a security boundary. The agent can write to the directory it
// lives in, and a forged one can only make the check stricter on the agent's
// own task: more paths it has to commit, more of its branch's commits it has
// to push.
type Carry struct {
	Format int `json:"format"`
	TaskID int `json:"task_id"`
	// Top is the repository the paths are relative to. A carry for another
	// repository is ignored.
	Top string `json:"top"`
	// Paths are the paths blamed so far, relative to Top.
	Paths []string `json:"paths,omitempty"`
	// Head is the HEAD the first blamed attempt started at.
	Head string `json:"head,omitempty"`
	// At is when it was last written.
	At time.Time `json:"at"`
}

// Next is the carry an attempt blamed with rep leaves for the next attempt at
// the task: the paths blamed now — which include those an earlier attempt was
// blamed for and that are still not committed — and the HEAD the first blamed
// attempt started at, which b already holds when it was taken from a carry.
func (b *Baseline) Next(taskID int, rep *Report) *Carry {
	c := &Carry{Format: carryFormat, TaskID: taskID, Top: b.Top, Head: b.Head, At: time.Now().UTC()}
	seen := map[string]bool{}
	for _, p := range rep.blamed {
		seen[p] = true
	}
	for _, p := range sortedPaths(seen) {
		if len(c.Paths) == maxCarryPaths {
			break
		}
		c.Paths = append(c.Paths, p)
	}
	return c
}

// ReadCarry reads the carry at path. It returns nil and no error when there is
// none, or when the one there is too old or belongs to another task; an error
// means one is there that cannot be used.
func ReadCarry(path string, taskID int) (*Carry, error) {
	f, err := openPlain(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("donecheck: %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCarryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCarryBytes {
		return nil, fmt.Errorf("donecheck: %s is larger than %d bytes", path, maxCarryBytes)
	}
	var c Carry
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("donecheck: %s: %w", path, err)
	}
	if c.Format < 1 || c.TaskID != taskID || time.Since(c.At) > CarryMaxAge || c.At.After(time.Now().Add(time.Hour)) {
		return nil, nil
	}
	if !filepath.IsAbs(c.Top) {
		return nil, fmt.Errorf("donecheck: %s names no repository", path)
	}
	if c.Head != "" && !isCommitName(c.Head) {
		return nil, fmt.Errorf("donecheck: %s: %q is not a commit name", path, c.Head)
	}
	if len(c.Paths) > maxCarryPaths {
		c.Paths = c.Paths[:maxCarryPaths]
	}
	kept := c.Paths[:0]
	for _, p := range c.Paths {
		if cleanRelPath(p) {
			kept = append(kept, p)
		}
	}
	c.Paths = kept
	return &c, nil
}

// WriteCarry writes c to path, atomically, creating its directory.
func WriteCarry(path string, c *Carry) error {
	if c == nil {
		return errors.New("donecheck: no carry to write")
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return atomicfile.Write(path, data, 0o644)
}

// ClearCarry removes the carry at path, if there is one.
func ClearCarry(path string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// carryName matches a carry file: <task id>_uncommitted.json.
var carryName = regexp.MustCompile(`^[1-9][0-9]{0,9}_uncommitted\.json$`)

// PruneCarries removes the carry files in dir last written before cutoff, and
// reports how many it removed and their size. A carry older than CarryMaxAge
// is ignored anyway; this keeps the ones a task never came back for from
// accumulating. Nothing but carry files is touched, and a symbolic link is
// never followed.
func PruneCarries(dir string, cutoff time.Time, dryRun bool) (int, int64, error) {
	if info, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return 0, 0, nil
	} else if err != nil {
		return 0, 0, err
	} else if !info.IsDir() {
		return 0, 0, fmt.Errorf("donecheck: %s is not a directory; not pruning through it", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, err
	}
	var (
		n     int
		bytes int64
		errs  []error
	)
	for _, e := range entries {
		if !carryName.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			continue
		}
		if !dryRun {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
				continue
			}
		}
		n++
		bytes += info.Size()
	}
	return n, bytes, errors.Join(errs...)
}
