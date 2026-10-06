package runbuild

// handoff.go: what one image of a run tells the next.
//
// syscall.Exec keeps the process — pid, start time, open stdout, parent — and
// discards everything in its memory. The plan is in the project database
// already (the run only adopts after persisting it); what is not is the run's
// own bookkeeping: which execution its tasks are stamped with, how many tasks
// in a row have failed, how many evolve rounds in a row found nothing, when its
// session began, why it is adopting. That goes into a handoff file in the
// project's .cloop directory, whose path the new image finds in EnvHandoff.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// EnvHandoff names the handoff file in the environment of an adopting run's
// new image. Its presence alone says "this process is continuing a run", even
// if the file turns out to be unreadable: the new image must then still skip
// everything a fresh run does at its start.
const EnvHandoff = "CLOOP_RUN_HANDOFF"

// HandoffFormat is the version of the file layout.
const HandoffFormat = 1

// MaxHandoffAge is how old a handoff may be when the new image reads it. The
// exec takes milliseconds; a file minutes old was not written for this start.
const MaxHandoffAge = 10 * time.Minute

// maxHandoffBytes bounds the read: the file is a few hundred bytes.
const maxHandoffBytes = 1 << 20

// Handoff is what an adopting run carries across its exec.
type Handoff struct {
	Format int `json:"format"`
	// Run is the process that wrote the file — and, since an exec keeps the
	// process, the one that must read it.
	Run       Ident     `json:"run"`
	WrittenAt time.Time `json:"written_at"`
	// Reason says why the run adopted: who requested it, or that the project
	// follows new builds. RequestID and RequestedBy name a request.
	Reason      string `json:"reason"`
	RequestID   string `json:"request_id,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
	// From is the image that wrote this, To what its probe reported for the
	// binary it executed, and Exe the path that binary was found at.
	From Build  `json:"from"`
	To   Build  `json:"to"`
	Exe  string `json:"exe"`
	// RunID is the execution id the run's tasks are stamped with; the new
	// image keeps it so the run's audit rows still join to its leases.
	RunID string `json:"run_id,omitempty"`
	// ProcessStart is when the process first started. The placement record
	// the hub wrote is judged stale against it, so a new image that took its
	// own start time instead would stop attributing its tasks to the executor
	// and identity the hub dispatched them under.
	ProcessStart time.Time `json:"process_start"`
	// SessionStart and SessionStartStep are where this session began, for
	// --steps and the session summary; Deadline is --timeout's.
	SessionStart     time.Time `json:"session_start"`
	SessionStartStep int       `json:"session_start_step"`
	Deadline         time.Time `json:"deadline,omitzero"`
	// The run's counters: the evolve iteration it had reached, the failures
	// and aborts in a row its stop rule counts, and the empty evolve rounds in
	// a row.
	EvolveStep              int `json:"evolve_step"`
	ConsecutiveErrors       int `json:"consecutive_errors"`
	ConsecutiveEmptyEvolves int `json:"consecutive_empty_evolves"`
	// Status and PauseReason are the run's status as it handed over.
	Status      string          `json:"status"`
	PauseReason json.RawMessage `json:"pause_reason,omitempty"`
	// Reexecs is how many adoptions preceded this one.
	Reexecs int `json:"reexecs"`
	// Parallel says which loop handed over.
	Parallel bool `json:"parallel,omitempty"`
}

// HandoffPath is where the run with process id pid writes its handoff in the
// project's .cloop directory.
func HandoffPath(cloopDir string, pid int) string {
	return filepath.Join(cloopDir, "run-handoff-"+strconv.Itoa(pid)+".json")
}

// WriteHandoff stores h at path, readable only by this user, replacing the
// file atomically so the new image can never read half of one.
func WriteHandoff(path string, h Handoff) error {
	h.Format = HandoffFormat
	if h.WrittenAt.IsZero() {
		h.WrittenAt = time.Now()
	}
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".run-handoff-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// TakeHandoff reads the handoff at path for the process self and removes the
// file, whatever it held: it is single-use, and one that cannot be used now
// never will be.
func TakeHandoff(path string, self Ident, now time.Time) (*Handoff, error) {
	if path == "" {
		return nil, errors.New("no handoff file was named")
	}
	// Only a handoff this process could have written is read — and removed:
	// the variable names a path, and removing whatever it names would make
	// it a way to delete files.
	if want := "run-handoff-" + strconv.Itoa(self.PID) + ".json"; filepath.Base(path) != want ||
		filepath.Base(filepath.Dir(path)) != ".cloop" {
		return nil, fmt.Errorf("%s is not a handoff of this process (want .cloop/%s)", path, want)
	}
	defer func() { _ = os.Remove(path) }()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxHandoffBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxHandoffBytes {
		return nil, fmt.Errorf("%s is larger than any handoff", path)
	}
	var h Handoff
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case h.Format != HandoffFormat:
		return nil, fmt.Errorf("%s is handoff format %d, this build reads %d", path, h.Format, HandoffFormat)
	case !h.Run.Same(self):
		return nil, fmt.Errorf("%s was written by pid %d, not by this process (pid %d)", path, h.Run.PID, self.PID)
	case now.Sub(h.WrittenAt) > MaxHandoffAge || h.WrittenAt.Sub(now) > time.Minute:
		return nil, fmt.Errorf("%s was written at %s, too far from now to be this start's",
			path, h.WrittenAt.UTC().Format(time.RFC3339))
	}
	return &h, nil
}
