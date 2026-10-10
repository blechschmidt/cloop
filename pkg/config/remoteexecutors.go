package config

// executors.remote: what enrolled remote executors may make this hub hold
// (Task 20399).

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// RemoteExecutorsConfig bounds the memory remote executors' returned work may
// occupy on this hub while it waits to be collected: the write-back bundles a
// device is sending or has sent, and seeded runs' project-state documents.
//
// Each of those is already capped per handle — a bundle at the cap its spec
// asked for, a document at executor.MaxProjectResultBytes — but a cap per
// handle is no cap on a hub that tracks hundreds of handles per device for a
// whole fleet. These two are. Past either, the handle's write-back fails with
// the limit and what was held named in the run's journal; nothing already held
// for other handles is touched.
//
// Hub-scope: read once, when the hub starts its agent endpoint, from this
// hub's configuration with its overlay merged in. In a hub cluster each member
// applies them to the memory it holds itself.
type RemoteExecutorsConfig struct {
	// MaxPinnedWriteBackBytes is how much returned work one executor may
	// have the hub hold at once. Absent or 0 uses
	// executor.DefaultPinnedWriteBackBytes (256 MiB), which fits the largest
	// bundle a spec may ask for twice over.
	MaxPinnedWriteBackBytes int64 `yaml:"max_pinned_writeback_bytes,omitempty"`
	// MaxPinnedWriteBackTotalBytes is the ceiling for every executor
	// together, in one hub process. Absent or 0 uses
	// executor.DefaultPinnedWriteBackTotalBytes (1 GiB). It is the number
	// that keeps a hub serving every other tenant when several devices
	// misbehave at once.
	MaxPinnedWriteBackTotalBytes int64 `yaml:"max_pinned_writeback_total_bytes,omitempty"`
}

// Bounds of both executors.remote keys, in bytes.
const (
	PinnedWriteBackBytesLower = executor.MinPinnedWriteBackBytes
	PinnedWriteBackBytesUpper = executor.MaxPinnedWriteBackBytes
)

// ValidPinnedWriteBackBytes reports whether v may be stored in either key: 0
// (the default) or a value inside the band.
func ValidPinnedWriteBackBytes(v int64) bool {
	return v == 0 || (v >= PinnedWriteBackBytesLower && v <= PinnedWriteBackBytesUpper)
}

// pinnedWriteBackBandError is the refusal for a value outside the band.
func pinnedWriteBackBandError(key string, v int64) error {
	return fmt.Errorf("executors.remote.%s must be 0 (the default) or between %d (1 MiB) and %d (64 GiB) "+
		"bytes (got %d); it is a byte count, not megabytes", key, PinnedWriteBackBytesLower,
		PinnedWriteBackBytesUpper, v)
}

// ValidateRemoteExecutors checks the executors.remote section, for `cloop
// config set`, ValidateNumeric and `cloop config validate`.
func ValidateRemoteExecutors(r RemoteExecutorsConfig) error {
	if !ValidPinnedWriteBackBytes(r.MaxPinnedWriteBackBytes) {
		return pinnedWriteBackBandError("max_pinned_writeback_bytes", r.MaxPinnedWriteBackBytes)
	}
	if !ValidPinnedWriteBackBytes(r.MaxPinnedWriteBackTotalBytes) {
		return pinnedWriteBackBandError("max_pinned_writeback_total_bytes", r.MaxPinnedWriteBackTotalBytes)
	}
	// Compared as effective values, so a per-executor budget set above the
	// default ceiling is caught as well as one set above an explicit one.
	per, total := r.PinnedWriteBackLimits()
	if per > total {
		return fmt.Errorf("executors.remote.max_pinned_writeback_bytes (%d) exceeds "+
			"max_pinned_writeback_total_bytes (%d): one executor's budget cannot be larger than "+
			"every executor's together", per, total)
	}
	return nil
}

// clampRemoteExecutors repairs the section in place at Load, returning each
// repair as "field: detail". A value outside the band goes back to its
// default — never to "unbounded", which is the defect the keys exist to close
// — and a per-executor budget above the ceiling is lowered to it, which is
// what the hub would have enforced anyway.
func clampRemoteExecutors(r *RemoteExecutorsConfig) []string {
	var out []string
	if !ValidPinnedWriteBackBytes(r.MaxPinnedWriteBackBytes) {
		out = append(out, fmt.Sprintf("executors.remote.max_pinned_writeback_bytes: value %d outside "+
			"[%d, %d]; using the default %d", r.MaxPinnedWriteBackBytes, PinnedWriteBackBytesLower,
			PinnedWriteBackBytesUpper, executor.DefaultPinnedWriteBackBytes))
		r.MaxPinnedWriteBackBytes = 0
	}
	if !ValidPinnedWriteBackBytes(r.MaxPinnedWriteBackTotalBytes) {
		out = append(out, fmt.Sprintf("executors.remote.max_pinned_writeback_total_bytes: value %d "+
			"outside [%d, %d]; using the default %d", r.MaxPinnedWriteBackTotalBytes,
			PinnedWriteBackBytesLower, PinnedWriteBackBytesUpper, executor.DefaultPinnedWriteBackTotalBytes))
		r.MaxPinnedWriteBackTotalBytes = 0
	}
	if per, total := r.PinnedWriteBackLimits(); per > total {
		out = append(out, fmt.Sprintf("executors.remote.max_pinned_writeback_bytes: value %d exceeds "+
			"max_pinned_writeback_total_bytes %d; lowered to it", per, total))
		r.MaxPinnedWriteBackBytes = total
	}
	return out
}

// PinnedWriteBackLimits returns the effective per-executor budget and the
// process-wide ceiling: the configured values, or the defaults for a key that
// is unset or — defensively, since Load repairs it — out of band.
func (r RemoteExecutorsConfig) PinnedWriteBackLimits() (perExecutor, total int64) {
	perExecutor, total = executor.DefaultPinnedWriteBackBytes, executor.DefaultPinnedWriteBackTotalBytes
	if v := r.MaxPinnedWriteBackBytes; v != 0 && ValidPinnedWriteBackBytes(v) {
		perExecutor = v
	}
	if v := r.MaxPinnedWriteBackTotalBytes; v != 0 && ValidPinnedWriteBackBytes(v) {
		total = v
	}
	return perExecutor, total
}
