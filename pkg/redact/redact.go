// Package redact removes known secret values from text on its way somewhere
// that keeps it.
//
// # Why this exists
//
// A task that holds a leased credential can echo it. Not maliciously — a
// `set -x` in a build script, a debug flag, an HTTP library that dumps its
// request headers, a stack trace carrying an argv. The credential then lands in
// three places that outlive the lease: the task artifact under .cloop/tasks/,
// the step log in state.db, and the live-log frame broadcast to every attached
// browser. The lease expires in minutes; the transcript does not.
//
// pkg/audit already scans for this, which is the tell: the leak was expected
// and only reported afterwards. This package prevents it instead, at the point
// output is captured.
//
// # What it is not
//
// It does not hunt for secret-shaped strings. There is no entropy heuristic and
// no regex for "looks like a token", because both are on a hot streaming path
// and both mangle ordinary text — a base64 blob in a diff is not a credential.
// It matches only values the caller already knows are secret, which for cloop
// means the material a lease just injected.
//
// # The short-value guard
//
// A value shorter than MinLen is never matched. A four-character credential is
// not one, and replacing every occurrence of a short string would corrupt
// unrelated output for no security benefit. This is the same guard
// executor.RedactSecrets has always applied; it lives here now so there is one
// implementation rather than one per call site.
package redact

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Marker replaces a matched secret. It is the literal pkg/audit's scanners and
// the existing git-path redaction already use, so a transcript reads the same
// whichever layer caught the value.
const Marker = "[redacted]"

// MinLen is the shortest value worth matching; see the package doc.
const MinLen = 8

// maxHoldback bounds how many bytes a Writer will withhold while waiting to see
// whether a secret straddles two chunks.
//
// The bound exists because the alternative is unbounded latency on the live log:
// a kubeconfig is kilobytes, and holding back a kilobyte of a running task's
// output on the chance that it is the first half of one would make the panel
// lag behind the work. Values longer than this are still redacted whenever they
// arrive within a single Write — which is how a file dump actually arrives — and
// always in the whole-buffer String/Bytes pass that persistence uses.
const maxHoldback = 4096

// Set is a collection of secret values to remove. A nil *Set is valid and
// redacts nothing, so callers with no lease need no special case.
//
// Safe for concurrent use: it is immutable after New.
type Set struct {
	// values is sorted longest-first so that when one secret contains
	// another — a token file's content is the token plus a newline — the
	// longer match is consumed first and cannot leave the shorter one
	// behind as a partial.
	values [][]byte
	// first indexes the leading byte of every value, so the common case of
	// a chunk containing no secret costs one array read per position rather
	// than a comparison per value.
	first [256]bool
	// max is the longest value's length, bounding the holdback window.
	max int
}

// New returns a Set over values, ignoring those shorter than MinLen and any
// duplicates. It returns nil when nothing survives that filter, which callers
// may use to skip redaction entirely.
func New(values ...string) *Set {
	seen := make(map[string]struct{}, len(values))
	var keep []string
	for _, v := range values {
		if len(v) < MinLen || IsPlaceholder(v) {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		keep = append(keep, v)
	}
	if len(keep) == 0 {
		return nil
	}
	sort.Slice(keep, func(i, j int) bool {
		if len(keep[i]) != len(keep[j]) {
			return len(keep[i]) > len(keep[j])
		}
		return keep[i] < keep[j]
	})
	s := &Set{values: make([][]byte, 0, len(keep))}
	for _, v := range keep {
		b := []byte(v)
		s.values = append(s.values, b)
		s.first[b[0]] = true
		if len(b) > s.max {
			s.max = len(b)
		}
	}
	return s
}

// IsPlaceholder reports whether v is something a redactor already left behind
// rather than a credential.
//
// It matters because a Spec is stored with its leased variables replaced by a
// placeholder — see executorstore's redactLeasedEnv, which writes
// "<redacted:leased>" — and a spec rehydrated from that store after a hub
// restart would otherwise hand this package its own output as a secret to
// match. The result would not be a disclosure, but it would be a Set that
// exists to replace "[redacted]" with "[redacted]", doing per-chunk work on the
// streaming path for nothing and mangling a diagnostic string that is supposed
// to be legible.
//
// A credential that genuinely looked like this would be skipped. That is the
// right trade: the value is already published in the source of two packages.
func IsPlaceholder(v string) bool {
	v = strings.TrimSpace(v)
	if v == Marker {
		return true
	}
	return strings.HasPrefix(v, "<redacted") && strings.HasSuffix(v, ">")
}

// Len reports how many values the Set will match.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.values)
}

// String replaces every occurrence of every value in text with Marker.
func (s *Set) String(text string) string {
	if s == nil || text == "" {
		return text
	}
	for _, v := range s.values {
		if strings.Contains(text, string(v)) {
			text = strings.ReplaceAll(text, string(v), Marker)
		}
	}
	return text
}

// Bytes is String over a byte slice. The input is not modified; a copy is
// returned only when something matched.
func (s *Set) Bytes(b []byte) []byte {
	if s == nil || len(b) == 0 {
		return b
	}
	for _, v := range s.values {
		if bytes.Contains(b, v) {
			b = bytes.ReplaceAll(b, v, []byte(Marker))
		}
	}
	return b
}

// Contains reports whether text holds any value in the Set. It is the cheap
// question a test or an audit asks; callers scrubbing output want String.
func (s *Set) Contains(text string) bool {
	if s == nil || text == "" {
		return false
	}
	for _, v := range s.values {
		if strings.Contains(text, string(v)) {
			return true
		}
	}
	return false
}

// Holdback returns how many trailing bytes of text a streaming caller must
// withhold because they could still turn out to be the start of a secret.
//
// It is exported for callers that do their own buffering rather than writing
// through a Writer — a log bus fanning one chunk out to many subscribers cannot
// hand its bytes to an io.Writer and still number them. Zero means the whole of
// text is safe to publish now, which is the usual answer.
func (s *Set) Holdback(text string) int {
	if s == nil || text == "" {
		return 0
	}
	return s.holdback([]byte(text))
}

// holdback returns how many trailing bytes of buf must be withheld because they
// could still turn out to be the start of a secret.
//
// It is the longest k such that buf's final k bytes equal the first k bytes of
// some value longer than k. Zero when no value could be straddling the
// boundary, which is the overwhelmingly common case and costs one array read
// per candidate position.
func (s *Set) holdback(buf []byte) int {
	if s == nil || s.max <= 1 {
		return 0
	}
	w := s.max - 1
	if w > maxHoldback {
		w = maxHoldback
	}
	if w > len(buf) {
		w = len(buf)
	}
	for k := w; k > 0; k-- {
		tail := buf[len(buf)-k:]
		if !s.first[tail[0]] {
			continue
		}
		for _, v := range s.values {
			if len(v) > k && bytes.HasPrefix(v, tail) {
				return k
			}
		}
	}
	return 0
}

// Writer wraps an io.Writer so that nothing carrying a known secret reaches it.
//
// Chunk boundaries are handled: a value split across two Writes is still
// caught, because the tail that could be the start of one is withheld until the
// next Write resolves it. Flush releases any such remainder, and callers that
// own the stream's end must call it or risk losing a trailing partial line.
//
// Safe for concurrent use, because the streams it wraps — a driver's output
// pump and its reaper — race by nature.
type Writer struct {
	dst io.Writer
	set *Set

	mu      sync.Mutex
	pending []byte
}

// NewWriter returns a Writer forwarding scrubbed output to dst. A nil Set
// yields a Writer that forwards verbatim, so the caller needs no branch.
func NewWriter(dst io.Writer, set *Set) *Writer {
	return &Writer{dst: dst, set: set}
}

// Write scrubs p and forwards it. It reports len(p) consumed on success even
// when part of p is being withheld, because the io.Writer contract is about
// what the caller may consider handed over, not about what has reached dst yet.
func (w *Writer) Write(p []byte) (int, error) {
	if w.set == nil {
		return w.dst.Write(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	w.pending = append(w.pending, p...)
	w.pending = w.set.Bytes(w.pending)
	hold := w.set.holdback(w.pending)
	emit := w.pending[:len(w.pending)-hold]
	if len(emit) > 0 {
		if _, err := w.dst.Write(emit); err != nil {
			return 0, err
		}
	}
	// Copy rather than reslice: the retained tail must not alias a buffer
	// that append may grow out from under it on the next Write.
	w.pending = append([]byte(nil), w.pending[len(w.pending)-hold:]...)
	return len(p), nil
}

// Flush writes any withheld remainder. It is safe to call more than once.
func (w *Writer) Flush() error {
	if w.set == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) == 0 {
		return nil
	}
	out := w.set.Bytes(w.pending)
	w.pending = nil
	_, err := w.dst.Write(out)
	return err
}

// --- discovery ---------------------------------------------------------

// EnvKey names the environment variable through which a lease declares which
// *other* variables hold credentials.
//
// It carries names, never values — exactly like executor.SecretBinding.EnvKeys
// and for the same reason: it is inherited by every child process and would
// otherwise be one more copy of the secret. The indirection is what lets a
// workload scrub its own output without a heuristic: GITHUB_TOKEN holds a
// credential and CLOOP_GITHUB_REPO_ALLOWLIST holds a repository list, and
// nothing about the two values themselves says which is which.
const EnvKey = "CLOOP_REDACT_ENV"

// LeaseDirKey names the variable holding the lease's own credential directory.
// It is set by pkg/secretbroker; this package only reads it.
const LeaseDirKey = "CLOOP_LEASE_DIR"

// FromEnviron builds a Set from a process environment: the values of every
// variable EnvKey names, plus the contents of every file in the lease
// directory.
//
// This is how a workload redacts its *own* output. The hub knows what it
// injected and scrubs at the executor boundary, but the harness runs inside the
// sandbox and its output is captured there first — by the orchestrator, into an
// artifact — so the guarantee has to hold on both sides of that boundary.
//
// Unreadable files are skipped rather than reported. A missing lease directory
// is the ordinary case for a project with no grants, and failing to redact is
// not a reason to fail a run.
func FromEnviron(environ []string) *Set {
	lookup := make(map[string]string, len(environ))
	for _, kv := range environ {
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			lookup[kv[:eq]] = kv[eq+1:]
		}
	}
	var values []string
	for _, name := range strings.Split(lookup[EnvKey], ",") {
		if name = strings.TrimSpace(name); name != "" {
			values = append(values, lookup[name])
		}
	}
	values = append(values, leaseDirValues(lookup[LeaseDirKey])...)
	return New(values...)
}

// maxLeaseFileBytes bounds one credential file read back off disk. It matches
// executor.MaxSecretFileBytes; a larger file is not a credential this system
// delivered, and reading it would only be a way to make a Set that costs more
// to match than the output it protects.
const maxLeaseFileBytes = 256 << 10

// leaseDirValues reads the credential files in dir. Both the raw content and
// its whitespace-trimmed form are returned: a token file is written with a
// trailing newline, and `cat` of it and `$(cat)` of it must both be caught.
func leaseDirValues(dir string) []string {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if info, ierr := ent.Info(); ierr == nil && info.Size() > maxLeaseFileBytes {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, ent.Name()))
		if rerr != nil || len(b) == 0 {
			continue
		}
		out = append(out, string(b))
		if trimmed := strings.TrimSpace(string(b)); trimmed != string(b) {
			out = append(out, trimmed)
		}
	}
	return out
}

// Values returns the raw and whitespace-trimmed forms of content, which is what
// a caller holding credential bytes in memory wants to put into a Set. It is
// the in-memory counterpart of what leaseDirValues does off disk.
func Values(content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	out := []string{string(content)}
	if trimmed := strings.TrimSpace(string(content)); trimmed != string(content) && trimmed != "" {
		out = append(out, trimmed)
	}
	return out
}
