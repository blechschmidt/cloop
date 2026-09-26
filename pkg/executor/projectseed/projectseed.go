// Package projectseed carries a cloop project into a sandbox that had to fetch
// its own source tree.
//
// # The gap this closes
//
// `cloop run` inside a sandbox reads `.cloop/` from the directory it is
// standing in. When the executor shares the hub's filesystem that directory is
// the hub's own project and everything works. When it does not — a remote
// agent, a Kubernetes Pod — the workspace is a *git clone*, and a clone of a
// source repository contains no cloop project. The run exited on its first line
// with "no cloop project found (run 'cloop init' first)" against a checkout
// that was entirely correct.
//
// # Why the legacy state.json shape
//
// This package does not invent a transport format. It writes the one cloop
// already reads: `.cloop/state.json`, the pre-SQLite layout that
// state.Load still migrates from on every open (see migrateLegacyIfNeeded).
// That choice is doing real work:
//
//   - The sandbox side needs no new code at all. The first state.Load in the
//     sandbox finds a state.json and no state.db, migrates, and returns a
//     populated project. The import path is the one every legacy project on
//     disk has exercised for a year, rather than a second deserializer written
//     for this feature and tested only by this feature.
//   - It is also the cure for a reused workspace. A workspace kept on an edge
//     device holds the *previous* dispatch's state.db, and a run that read it
//     reported "all tasks complete", or a reset task still failed, without
//     running anything. Write removes that database, so state.Load has nothing
//     to prefer over the seed; see staleDatabaseFiles for why being newer than
//     it was not enough.
//
// # What is deliberately not in a seed
//
// Steps. A long-running project's step history is the overwhelming majority of
// its state — megabytes of captured output — and the sandbox needs none of it:
// it is about to generate its own. Dropping it is what keeps a seed in the
// hundreds of kilobytes for a 482-task plan.
//
// WorkDir. The hub's absolute project path means nothing inside a sandbox, and
// leaving it set is not merely useless — ProjectState.WorkDir is what Save
// writes back through, so a seed that carried the hub's path would point the
// sandbox's writes at a directory on another machine. It is cleared here and
// re-derived on the far side by migrateFromJSON, which fills an empty WorkDir
// with the directory it is migrating in.
//
// # The way back
//
// A seed is a copy, and a run writes its outcomes into the copy. result.go and
// merge.go are the return half (Task 20339): the device reads back what the run
// changed once the workload exits, and the hub folds it into its own project.
// Without them a run could finish its task on a device while the dashboard —
// which renders the hub's database — showed it pending forever.
package projectseed

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
)

// MaxDecompressedBytes bounds a seed after inflation.
//
// A compressed cap alone is not a bound: gzip will happily expand a few
// kilobytes into gigabytes, and the receiving side of this is an edge device
// whose disk the hub does not manage. This sits well under the 64 MiB ceiling
// state.Load's own reader applies to a state.json, so a seed that passes here
// is one the far side will still agree to read.
const MaxDecompressedBytes = 32 << 20 // 32 MiB

// SeedFileName and seedDir are where a seed lands, relative to the workspace.
// The receiver owns this choice: see the note in executor/seed.go on why a
// seed names no path of its own.
const (
	seedDir      = ".cloop"
	SeedFileName = "state.json"
)

// ErrNoProject reports that the hub has no project state to seed from.
var ErrNoProject = errors.New("projectseed: no project state")

// Build serialises a project into the bytes a Spec carries.
//
// The input is the hub's own loaded state. It is copied — not mutated — before
// the fields that must not travel are cleared, because the caller's pointer is
// very often the live state a handler is still holding.
func Build(st *state.ProjectState) ([]byte, error) {
	if st == nil {
		return nil, ErrNoProject
	}

	seed := *st // shallow copy: only top-level fields are rewritten below

	// See the package comment. Steps is the size, WorkDir is the correctness.
	// StepCount and LastStepTime need no clearing — they are json:"-" and
	// cannot travel; Steps is the one that serialises.
	seed.Steps = nil
	seed.WorkDir = ""

	// Status and PauseReason describe *the hub's* run, not the one about to
	// start. Carrying "paused, subscription cap reached" into a fresh sandbox
	// would seed it with a reason to stop that belongs to another machine —
	// and the legacy decoder has no PauseReason field to receive it anyway, so
	// leaving it set would be a silent half-transfer.
	seed.Status = ""
	seed.PauseReason = nil

	// PM mode is the only mode since Task 20067, and Load forces it true on
	// arrival. Stating it here means the seed reads correctly on its own
	// rather than depending on that coercion.
	seed.PMMode = true

	raw, err := json.Marshal(&seed)
	if err != nil {
		return nil, fmt.Errorf("projectseed: marshal project state: %w", err)
	}

	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("projectseed: open compressor: %w", err)
	}
	if _, err := zw.Write(raw); err != nil {
		return nil, fmt.Errorf("projectseed: compress project state: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("projectseed: finish compressing project state: %w", err)
	}

	out := buf.Bytes()
	// Checked here rather than left to Spec.Validate so the failure names the
	// project whose plan is too large, at the moment it is read, instead of
	// surfacing as an invalid spec several layers later.
	if len(out) > executor.MaxProjectSeedBytes {
		return nil, fmt.Errorf("projectseed: seed is %d compressed bytes, over the %d-byte "+
			"ceiling (%d uncompressed); the plan is too large to ship to an isolating executor",
			len(out), executor.MaxProjectSeedBytes, len(raw))
	}
	return out, nil
}

// Write places a seed into a workspace the caller has already confined.
//
// dir must be the workload's working directory. Nothing in seed influences the
// path: the file always lands at <dir>/.cloop/state.json, which is the property
// that keeps a hostile or corrupt seed from being an arbitrary-file-write on
// whichever host materialised it.
//
// An empty seed is not an error. Most dispatches have none — every executor
// that shares the hub's filesystem — and a caller that had to test for that
// itself would eventually forget to.
func Write(dir string, seed []byte) error {
	if len(seed) == 0 {
		return nil
	}
	if err := executor.ValidateProjectSeed(seed); err != nil {
		return err
	}

	raw, err := inflate(seed)
	if err != nil {
		return err
	}

	// Parse before writing. The far side of this is state.Load, which reports
	// a malformed state.json as a project-level failure; catching it here
	// means a truncated frame is named as a truncated frame, by the machine
	// that received it, instead of as a broken project.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("projectseed: seed is not a JSON object: %w", err)
	}

	target := filepath.Join(dir, seedDir)
	if err := ensureRealDir(target); err != nil {
		return err
	}

	// The seed is the project as the hub knows it at dispatch, and it is what
	// the harness must load. A database an earlier dispatch left in a kept
	// workspace is that dispatch's copy — a task the hub has since reset still
	// failed in it, a plan the operator has since edited still unedited — and
	// it has to go rather than be left to compete. See staleDatabaseFiles.
	if err := removeStaleDatabase(target); err != nil {
		return err
	}

	// Written through a temp file in the same directory and renamed, for the
	// same reason every other state write in cloop is: the reader is
	// state.Load, and a partially written state.json is a project that fails
	// to parse rather than one that is merely out of date.
	path := filepath.Join(target, SeedFileName)
	tmp, err := os.CreateTemp(target, ".seed-*")
	if err != nil {
		return fmt.Errorf("projectseed: create temp file in %s: %w", target, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best effort: on the success path the rename has already consumed it.
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("projectseed: write %s: %w", path, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("projectseed: chmod %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("projectseed: close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("projectseed: install %s: %w", path, err)
	}
	return nil
}

// staleDatabaseFiles are what a previous dispatch's `cloop run` leaves in
// `.cloop/`: the database and SQLite's companion files.
//
// # Why they are removed rather than outdated
//
// The seed was meant to win through state.Load's own freshness rule — a
// state.json newer than state.db is re-migrated — and the package comment used
// to say it did. It did not survive contact with a real device (Task 20337):
// `cloop run` opens and writes the project database from PersistentPreRunE,
// before state.Load compares anything, so the database was always a few
// milliseconds newer than the seed written just before the harness started.
// The stale copy won every time. On the sgx edge device a task that had failed
// once stayed failed on every later dispatch — "No runnable tasks left (1
// failed)" — while the hub, having reset it, showed it pending: the operator
// could not retry it from the dashboard at all.
//
// A freshness race cannot be fixed by winning it harder. With no database
// present, state.Load migrates from the seed unconditionally: trigger 1 if
// nothing has recreated the database yet, trigger 3 ("a database with no
// project state in it") if PersistentPreRunE got there first.
//
// Nothing of value goes with them, but only because of result.go. This
// comment used to say the hub already held everything the database did — the
// plan, and every transcript as it streamed. It held the transcripts; it did
// not hold the *outcomes*, which lived only here, and deleting them at the next
// dispatch was the end of a run whose finished tasks the dashboard still showed
// pending (Task 20339). The run that wrote this database now sends what it
// changed back before its workload reports its final status, so by the time the
// next seed lands the hub has it.
var staleDatabaseFiles = []string{"state.db", "state.db-wal", "state.db-shm", "state.db-journal"}

// removeStaleDatabase deletes staleDatabaseFiles from dir, which the caller has
// already made a real directory. A symbolic link among them is removed as a
// link — os.Remove does not follow it — so nothing outside dir is touched.
func removeStaleDatabase(dir string) error {
	for _, name := range staleDatabaseFiles {
		p := filepath.Join(dir, name)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("projectseed: remove the previous dispatch's %s: %w", p, err)
		}
	}
	return nil
}

// ensureRealDir makes target a directory, replacing a symbolic link that stands
// in its place.
//
// The workspace a seed lands in may be one the previous dispatch's workload
// could write to — an executor-owned workspace is kept between dispatches, and
// a container sees it through a bind mount — and everything after this writes
// and deletes by name inside target. Left as a symlink, `.cloop` would aim
// those operations wherever the workload pointed it, on the device's own
// filesystem and outside the directory the agent confined the workload to.
// Removing the link removes only the link.
func ensureRealDir(target string) error {
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(target); err != nil {
			return fmt.Errorf("projectseed: replace the symbolic link at %s: %w", target, err)
		}
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		return fmt.Errorf("projectseed: create %s: %w", target, err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		return fmt.Errorf("projectseed: inspect %s: %w", target, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("projectseed: %s is not a directory", target)
	}
	return nil
}

// inflate decompresses a seed under a hard ceiling.
func inflate(seed []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(seed))
	if err != nil {
		return nil, fmt.Errorf("projectseed: read seed: %w", err)
	}
	defer zr.Close()

	// LimitReader at cap+1 so a payload that is exactly at the ceiling is
	// accepted and one byte more is refused, rather than silently truncated
	// into a state.json that parses to a shorter plan.
	raw, err := io.ReadAll(io.LimitReader(zr, MaxDecompressedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("projectseed: decompress seed: %w", err)
	}
	if len(raw) > MaxDecompressedBytes {
		return nil, fmt.Errorf("projectseed: seed inflates past the %d-byte ceiling",
			MaxDecompressedBytes)
	}
	return raw, nil
}
