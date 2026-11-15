package projectmove

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// LocalTarget is the target binding that names the hub's own host: the
// built-in host driver, which runs a project's harness as a process of the hub.
// It is admitted only where the hub's executors.allow_host_process permits it.
const LocalTarget = "local"

// maxBindingLen bounds a binding string. Executor IDs are short — enrolled
// agents' are 16 characters, a pool binding is about 26 — and a binding is
// echoed into the report, so an unbounded one is refused rather than carried.
const maxBindingLen = 128

// ErrInvalidTarget is what ParseTarget's refusals match with errors.Is.
var ErrInvalidTarget = errors.New("projectmove: invalid target binding")

// Target is a validated target binding.
type Target struct {
	// Binding is the value as a project binding would store it: an executor
	// ID, or pool:<id>.
	Binding string `json:"binding"`
	// ExecutorID is the executor the binding names; empty for a pool.
	ExecutorID string `json:"executor_id,omitempty"`
	// PoolID is the pool the binding names; empty for an executor.
	PoolID string `json:"pool_id,omitempty"`
	// Local reports that the binding names the hub's own host.
	Local bool `json:"local,omitempty"`
}

// ParseTarget validates a target binding string: an executor ID, pool:<id>,
// or "local" for hub host execution.
//
// It checks the string's shape only — whether such an executor or pool
// exists, may be used by the caller and can run the project is what Preflight
// reports. The shape check comes first because the string arrives in a query
// parameter and is echoed into a report and looked up in the database: one
// that could not be a binding is refused before it reaches either.
func ParseTarget(raw string) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Target{}, fmt.Errorf("%w: a target is required: an executor ID, pool:<id>, or %s", ErrInvalidTarget, LocalTarget)
	}
	if len(s) > maxBindingLen {
		return Target{}, fmt.Errorf("%w: %d characters, at most %d", ErrInvalidTarget, len(s), maxBindingLen)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c > '~' {
			return Target{}, fmt.Errorf("%w: %q holds a character no executor ID has", ErrInvalidTarget, s)
		}
	}
	if poolID, ok := executor.PoolOf(s); ok {
		if !validID(poolID) {
			return Target{}, fmt.Errorf("%w: %q is not a pool ID", ErrInvalidTarget, poolID)
		}
		return Target{Binding: executor.PoolBinding(poolID), PoolID: poolID}, nil
	}
	if strings.HasPrefix(s, executor.PoolBindingPrefix) {
		return Target{}, fmt.Errorf("%w: %q names no pool; write pool:<id>", ErrInvalidTarget, s)
	}
	if prefix, _, found := strings.Cut(s, ":"); found {
		// executor:<id> and label:<k=v> are grant subjects, not bindings; the
		// mistake is common enough to answer precisely.
		return Target{}, fmt.Errorf("%w: %q is not a binding: name the executor by its ID (without %q), or a pool as pool:<id>",
			ErrInvalidTarget, s, prefix+":")
	}
	if !validID(s) {
		return Target{}, fmt.Errorf("%w: %q is not an executor ID", ErrInvalidTarget, s)
	}
	return Target{Binding: s, ExecutorID: s, Local: s == LocalTarget}, nil
}

// validID reports whether id has the shape of an executor or pool ID: letters,
// digits, '.', '_' and '-' (enrolled agents' IDs are base64url, which may begin
// with '-' or '_').
func validID(id string) bool {
	if id == "" || len(id) > maxBindingLen || id == "." || id == ".." {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
