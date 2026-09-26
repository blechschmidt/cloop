package executor

// seed.go carries the hub's *project* into a workspace the executor had to
// fetch for itself.
//
// workspace.go answers "how does the source tree get there". This file answers
// the question that was left open beside it: a cloop project is not only a
// source tree, it is also `.cloop/` — the goal, the instructions, the provider
// selection and the plan. The hub holds all of that in its own
// `.cloop/state.db`, and until this existed nothing carried any of it across a
// dispatch.
//
// The consequence was specific and, from the hub's side, invisible. A run
// placed on a remote agent or a Pod provisions a git workspace, starts
// `cloop run` inside the clone, and that process reads `.cloop/` from the tree
// it is standing in. There is none, so it exits immediately with:
//
//	Error: no cloop project found (run 'cloop init' first)
//
// The only way to make the flagship path work was to commit `.cloop/state.db`
// — a live, WAL-backed SQLite file — into the user's repository, which is what
// Task 20315 had to do to prove the circuit at all. That is not a workaround a
// product can ship: it publishes the plan to everyone who can read the repo,
// it is a binary blob the sandbox then rewrites, and it is incomplete unless
// the author remembers to checkpoint the WAL first.
//
// # Why the bytes and not a path
//
// ProjectSeed is a *payload*, not a location. Nothing in it names where it
// lands: the receiving side picks the path, always inside the workspace it has
// already confined. That is deliberate and it is the whole security argument
// for the shape of this field. A seed that carried its own destination would be
// an arbitrary-file-write primitive aimed at whichever host materialised it —
// the same reasoning that makes SecretFile.Name a bare file name, re-derived
// here rather than inherited, because this struct crosses a process boundary
// too.
//
// # Why json:"-"
//
// Same rule as Spec.SecretFiles, for a different reason. SecretFiles is
// excluded because it is plaintext credential material. This is excluded
// because it is *large* and *duplicated*: pkg/executorstore persists the
// dispatched Spec, the audit trail echoes it, and reconcile re-reads it after a
// restart. A 500 KiB plan written to three places on every dispatch would turn
// the control plane's own retention problem back on, and the seed is
// reconstructible from the project at any time — it is a copy, not a record.
// A wire format that legitimately needs the bytes opts in explicitly; see
// remote.StartPayload.ProjectSeed.

import (
	"errors"
	"fmt"
)

// MaxProjectSeedBytes bounds one seed as it travels — compressed.
//
// The largest plan on this hub is 482 tasks and about 600 KiB of text, which
// gzips to well under a tenth of this. The cap is generous against that so it
// never becomes the thing an operator has to tune, and it is still a cap: an
// unbounded field here would be an unbounded allocation on a remote frame and
// an unbounded write on an edge device's disk.
const MaxProjectSeedBytes = 4 << 20 // 4 MiB compressed

// MaxProjectResultBytes bounds what an executor sends back after a seeded run —
// compressed (Task 20339).
//
// A result is the run's changes, not the project: the tasks it touched, the
// steps, events and cost rows it recorded. One finished task is a few hundred
// bytes. The ceiling is set by the transport rather than by the content — a
// remote frame carries at most remote.MaxFrameBytes, and JSON encodes these
// bytes as base64 — so a device that produced more drops step output first,
// and says what it dropped, rather than sending a frame the hub must refuse.
const MaxProjectResultBytes = 640 << 10 // 640 KiB compressed

// ValidateProjectSeed checks what every holder of a Spec can check: that the
// payload is bounded and, if present, actually compressed.
//
// The gzip magic test is cheap and it is the difference between a corrupt seed
// failing here, naming itself, and failing inside a sandbox as a state file
// that will not parse — which surfaces as "no cloop project found", the exact
// message this whole mechanism exists to stop lying to people.
func ValidateProjectSeed(seed []byte) error {
	if len(seed) == 0 {
		return nil
	}
	if len(seed) > MaxProjectSeedBytes {
		return fmt.Errorf("%w: project seed is %d bytes, over the %d-byte ceiling",
			ErrInvalidSpec, len(seed), MaxProjectSeedBytes)
	}
	if len(seed) < 2 || seed[0] != 0x1f || seed[1] != 0x8b {
		return fmt.Errorf("%w: project seed is not gzip-compressed", ErrInvalidSpec)
	}
	return nil
}

// ProjectResult is what an executor brought back from a seeded run (Task
// 20339): the compressed document pkg/executor/projectseed decodes and merges,
// or the device's reason for having none.
type ProjectResult struct {
	// Data is the compressed result document. Empty when Err is set.
	Data []byte
	// Err is the executor's own account of why it could not read the run back
	// — the workload removed its project, the database was written by a newer
	// cloop than the device's. Operator-facing.
	Err string
	// Redact removes the credentials the hub leased to the workload from a
	// string. The hub applies it to everything it takes from Data rather than
	// trusting the device to have scrubbed: a result is written by the party a
	// redaction exists to protect against. Never nil.
	Redact func(string) string
}

// ProjectResultFetcher is implemented by drivers whose Capabilities report
// ReturnsProjectState.
type ProjectResultFetcher interface {
	// ProjectResult returns what the device sent back for handleID, once: the
	// result is released to the caller and forgotten, because merging the same
	// run twice would count its spend twice. It returns
	// ErrProjectResultUnavailable when nothing arrived.
	//
	// Call it after the handle's output stream has closed. A device sends the
	// result before the terminal status, and the terminal status is what
	// closes the stream, so by then everything that is coming has come.
	ProjectResult(handleID string) (ProjectResult, error)
}

// ErrProjectResultUnavailable reports that no result arrived for a handle.
var ErrProjectResultUnavailable = errors.New("executor: no project result was received")
