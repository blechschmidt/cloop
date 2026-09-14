package artifact

// sandbox.go records the environment a task actually executed in.
//
// The task artifact already answers "what did the agent say"; this answers
// "what was it running inside when it said it". Those are different questions,
// and the second decides whether the answer is reproducible.
//
// It matters because .cloop/sandbox.yaml is mutable and its references are
// moving targets. Six weeks on, `image: python:3.12` resolves to a different
// filesystem, and the sandbox.yaml at HEAD may not be the one that shaped the
// run. A digest plus a spec hash pins both: the digest says which bytes ran,
// the hash says which spec asked for them, and together they turn "it worked
// then and not now" into a question with an answer.
//
// # Why a file rather than a parameter
//
// The two halves of this are on opposite sides of the sandbox boundary. The
// control plane knows the pinned image — it resolved the digest and started the
// workload — but writes no task artifacts. The orchestrator writes every task
// artifact but runs *inside* the sandbox, where it can see neither the executor
// nor the reference it was launched from.
//
// The one thing they share is the project directory: bind-mounted by the
// container driver, the workspace volume under Kubernetes. So the control plane
// writes the record there before starting the workload, and WriteTaskArtifact
// picks it up from inside. No new channel, and it degrades correctly — a run
// with no record produces artifacts without the stamp rather than no artifacts.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// SandboxRunFile is where the current run's environment record lives, relative
// to the project directory.
const SandboxRunFile = ".cloop/sandbox-run.json"

// maxSandboxRunBytes bounds the read. The file is written by the control plane,
// but it lands in a directory a workload can write to, so it is parsed as
// untrusted input like anything else read back across that boundary.
const maxSandboxRunBytes = 64 << 10

// SandboxRecord is the provenance of one run's execution environment.
type SandboxRecord struct {
	// ExecutorID and ExecutorKind identify where it ran.
	ExecutorID   string `json:"executor_id,omitempty"`
	ExecutorKind string `json:"executor_kind,omitempty"`
	// Isolation is the boundary strength the executor advertised at dispatch:
	// "none" | "container" | "vm" | "remote" (executor.Capabilities.Isolation).
	//
	// Recorded here rather than looked up from the executor later because it
	// is a statement about this run: a driver reconfigured afterwards, or an
	// id re-enrolled against a different backend, would otherwise rewrite the
	// history of every task it ever ran. Empty on records written before
	// Task 20244 — readers infer it from ExecutorKind, which has always been
	// written, rather than reading the absence as "no isolation".
	Isolation string `json:"isolation,omitempty"`
	// SpecHash is the .cloop/sandbox.yaml content hash, or empty when the
	// project has no spec and ran on the executor's defaults.
	SpecHash string `json:"spec_sha256,omitempty"`
	// RequestedImage is the reference the spec asked for, before resolution.
	RequestedImage string `json:"requested_image,omitempty"`
	// PinnedImage is the reference the workload actually ran from —
	// digest-pinned where the driver could resolve one.
	PinnedImage string `json:"pinned_image,omitempty"`
	// SetupHash identifies the setup: commands baked into a derived image,
	// empty when the spec has none.
	SetupHash string `json:"setup_sha256,omitempty"`
	// Warnings are the clamps applied while parsing the spec.
	Warnings []string `json:"warnings,omitempty"`
	// StartedAt is when the workload began.
	StartedAt time.Time `json:"started_at,omitempty"`
}

// Pinned reports whether the recorded image is immutable — whether re-running
// this record would provably get the same filesystem.
//
// The test is for "@sha256:" rather than for any digest-shaped substring: a tag
// may legitimately contain hex, and calling a tag pinned is the one error here
// that would matter, because it is the claim someone relies on when they say a
// result reproduces.
func (r SandboxRecord) Pinned() bool {
	return strings.Contains(r.PinnedImage, "@sha256:")
}

// IsZero reports whether the record carries nothing worth stamping.
func (r SandboxRecord) IsZero() bool {
	return r.ExecutorID == "" && r.SpecHash == "" && r.PinnedImage == ""
}

// WriteSandboxRun persists the record for the run that is about to start.
//
// It is called by the control plane, from outside the sandbox, with the project
// directory the workload will see. Returns the path written.
func WriteSandboxRun(workDir string, rec SandboxRecord) (string, error) {
	path := filepath.Join(workDir, filepath.FromSlash(SandboxRunFile))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create .cloop dir: %w", err)
	}
	if rec.StartedAt.IsZero() {
		rec.StartedAt = time.Now()
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal sandbox record: %w", err)
	}
	if err := atomicfile.Write(path, append(data, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("write sandbox record: %w", err)
	}
	return path, nil
}

// LoadSandboxRun reads the record for the current run, if there is one.
//
// Every failure returns ok=false rather than an error. A missing, truncated or
// malformed record must never be the reason a completed task's output is not
// persisted — the stamp is provenance, and losing provenance is strictly better
// than losing the work it describes.
func LoadSandboxRun(workDir string) (SandboxRecord, bool) {
	path := filepath.Join(workDir, filepath.FromSlash(SandboxRunFile))
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > maxSandboxRunBytes {
		return SandboxRecord{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return SandboxRecord{}, false
	}
	var rec SandboxRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return SandboxRecord{}, false
	}
	if rec.IsZero() {
		return SandboxRecord{}, false
	}
	return rec, true
}

// frontmatter renders the record as YAML frontmatter lines for a task
// artifact, including the trailing newline on each. Returns "" for a record
// with nothing to say.
//
// Values are quoted with %q throughout: an image reference is repo-controlled
// via sandbox.yaml, and an unquoted one containing a colon — which every tagged
// reference does — would produce frontmatter that no YAML parser reads back as
// intended.
func (r SandboxRecord) frontmatter() string {
	if r.IsZero() {
		return ""
	}
	var b strings.Builder
	if r.ExecutorID != "" {
		fmt.Fprintf(&b, "executor_id: %q\n", r.ExecutorID)
	}
	if r.ExecutorKind != "" {
		fmt.Fprintf(&b, "executor_kind: %q\n", r.ExecutorKind)
	}
	if r.SpecHash != "" {
		fmt.Fprintf(&b, "sandbox_spec_sha256: %q\n", r.SpecHash)
	}
	if r.RequestedImage != "" {
		fmt.Fprintf(&b, "sandbox_image_requested: %q\n", r.RequestedImage)
	}
	if r.PinnedImage != "" {
		fmt.Fprintf(&b, "sandbox_image: %q\n", r.PinnedImage)
		// Only claimed when an image was recorded at all. Emitting
		// "reproducible: false" for a run that simply had no image concept
		// would read as a finding rather than as an absence.
		fmt.Fprintf(&b, "sandbox_reproducible: %t\n", r.Pinned())
	}
	if r.SetupHash != "" {
		fmt.Fprintf(&b, "sandbox_setup_sha256: %q\n", r.SetupHash)
	}
	return b.String()
}

// frontmatterKeys maps each frontmatter key back to the field it came from.
//
// It is derived from frontmatter above by reading it, and the round-trip test
// in sandbox_test.go is what keeps the two honest: a field added to the writer
// without a line here would silently stop being recoverable, and "silently" is
// the whole problem — provenance that is absent looks exactly like provenance
// for a run that had none.
var frontmatterKeys = map[string]func(*SandboxRecord, string){
	"executor_id":             func(r *SandboxRecord, v string) { r.ExecutorID = v },
	"executor_kind":           func(r *SandboxRecord, v string) { r.ExecutorKind = v },
	"sandbox_spec_sha256":     func(r *SandboxRecord, v string) { r.SpecHash = v },
	"sandbox_image_requested": func(r *SandboxRecord, v string) { r.RequestedImage = v },
	"sandbox_image":           func(r *SandboxRecord, v string) { r.PinnedImage = v },
	"sandbox_setup_sha256":    func(r *SandboxRecord, v string) { r.SetupHash = v },
}

// maxFrontmatterBytes bounds how far into an artifact the frontmatter scan
// reads. The block is a handful of short lines; anything past this is the
// agent's own transcript, which is exactly the unbounded input Task 20220 made
// every other artifact read stop trusting.
const maxFrontmatterBytes = 16 << 10

// ReadTaskSandbox recovers the sandbox a past task actually ran in.
//
// # Why this exists alongside LoadSandboxRun
//
// They read the same record from two different places, and only one of them is
// durable. LoadSandboxRun reads .cloop/sandbox-run.json, which the control
// plane overwrites before every run — it answers "what am I running in right
// now", and by the time anyone asks about task 42 it describes some later task.
// The per-task copy stamped into the artifact's frontmatter is the one that
// survives, so it is the one a reproduction has to read.
//
// Returns ok=false for a task with no artifact, no frontmatter, or no sandbox
// stamp — the ordinary case for a run that predates the stamp or executed on
// the host. A caller must treat that as "unknown", never as "unsandboxed".
func ReadTaskSandbox(workDir string, task *pm.Task) (SandboxRecord, bool) {
	if task == nil || strings.TrimSpace(task.ArtifactPath) == "" {
		return SandboxRecord{}, false
	}
	abs := resolveArtifactPath(workDir, task.ArtifactPath)
	f, err := os.Open(abs) //nolint:gosec // path is derived from the project's own state
	if err != nil {
		return SandboxRecord{}, false
	}
	defer f.Close()

	head := make([]byte, maxFrontmatterBytes)
	n, err := io.ReadFull(f, head)
	if n == 0 && err != nil {
		return SandboxRecord{}, false
	}
	return ParseSandboxFrontmatter(string(head[:n]))
}

// ParseSandboxFrontmatter extracts the sandbox stamp from a task artifact's
// leading YAML frontmatter block.
//
// It is deliberately a hand-rolled scan of `key: value` lines rather than a
// YAML decode. The block is written by frontmatter above one line at a time,
// the keys are a closed set, and a partial read that lands mid-block must yield
// the keys it did see rather than a parse error for the truncated last line —
// which is what a real YAML parser would give.
func ParseSandboxFrontmatter(s string) (SandboxRecord, bool) {
	s = strings.TrimLeft(s, "\ufeff \t\r\n")
	if !strings.HasPrefix(s, "---\n") {
		return SandboxRecord{}, false
	}
	body := s[len("---\n"):]
	if end := strings.Index(body, "\n---"); end >= 0 {
		body = body[:end]
	}

	var rec SandboxRecord
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		set, known := frontmatterKeys[strings.TrimSpace(key)]
		if !known {
			continue
		}
		value = strings.TrimSpace(value)
		// Every value the writer emits is %q-quoted. An unquoted one is a
		// truncated or hand-edited line; take it verbatim rather than drop it.
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		if value != "" {
			set(&rec, value)
		}
	}
	if rec.IsZero() {
		return SandboxRecord{}, false
	}
	return rec, true
}
