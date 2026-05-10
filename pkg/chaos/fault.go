// Package chaos provides a fault-injection framework that lets cloop's
// resilience claims (retry budgets, circuit breakers, busy-timeout pragmas,
// graceful shutdown) be exercised against simulated failures rather than
// just unit-tested.
//
// Design overview
//
// The framework has four collaborating pieces:
//
//   1. A Controller that holds the currently-active faults in memory plus a
//      file-watched mirror at .cloop/chaos/active.json. The mirror lets a
//      `cloop chaos inject` invocation in one process influence a long-lived
//      `cloop ui` daemon in another, without IPC plumbing.
//   2. Middleware that wraps the provider HTTP client (see Transport) and
//      consults the controller on every request to decide whether to inject
//      a timeout, 429, 500, or network flap.
//   3. A SQLite busy holder (see SQLiteBusy) that opens a separate connection
//      to the project's state database and parks a write transaction for the
//      configured duration, forcing every other writer to time out under
//      WAL/busy_timeout — the realistic SQLITE_BUSY scenario.
//   4. A persistent journal at the chaos_runs SQLite table that records every
//      injected fault and its observed outcome, so `cloop chaos report` can
//      summarise how the system handled each fault.
//
// Fault catalogue
//
// The supported fault types are deliberately a small, fixed set that map to
// the failure modes the rest of cloop is designed to survive:
//
//   provider-timeout         — every outbound HTTP call to a provider hangs
//                              past the controller's per-fault timeout, then
//                              is cancelled with context.DeadlineExceeded.
//   provider-429             — provider responses are replaced with HTTP 429
//                              (rate limited). Exercises retry/backoff.
//   provider-500             — provider responses are replaced with HTTP 500.
//                              Exercises retry-on-5xx and circuit breaker.
//   sqlite-busy              — a sibling write transaction is held open on
//                              .cloop/state.db, forcing concurrent writers
//                              to wait out busy_timeout.
//   network-flap             — a configurable percentage of HTTP requests
//                              fail with connection-refused-like errors.
//   disk-full-simulation     — temporarily fills .cloop/chaos/ballast with a
//                              large file so writes intended for that
//                              directory fail with ENOSPC-like errors.
//   slow-disk                — wraps atomicfile writes with an artificial
//                              delay (caller-side; see SlowDisk).
//
// Faults are intentionally additive: injecting two compatible faults at once
// (e.g. provider-429 + sqlite-busy) lets you stress multiple components
// simultaneously. Each fault carries an Until time after which it is silently
// dropped, so a forgotten injection cannot poison the system permanently.
package chaos

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// FaultType identifies a kind of injected failure.
//
// New values must be added to AllFaultTypes (used by validators) and to the
// switch in Apply* helpers. Readers must treat unknown values as no-ops so
// downgrading the binary while a fault file lingers on disk does not panic.
type FaultType string

const (
	FaultProviderTimeout FaultType = "provider-timeout"
	FaultProvider429     FaultType = "provider-429"
	FaultProvider500     FaultType = "provider-500"
	FaultSQLiteBusy      FaultType = "sqlite-busy"
	FaultNetworkFlap     FaultType = "network-flap"
	FaultDiskFull        FaultType = "disk-full-simulation"
	FaultSlowDisk        FaultType = "slow-disk"
)

// AllFaultTypes lists every fault the framework knows how to inject. Used by
// CLI validation and by the `cloop chaos suite` runner.
var AllFaultTypes = []FaultType{
	FaultProviderTimeout,
	FaultProvider429,
	FaultProvider500,
	FaultSQLiteBusy,
	FaultNetworkFlap,
	FaultDiskFull,
	FaultSlowDisk,
}

// ParseFaultType validates s and returns the corresponding FaultType, or an
// error listing the valid values. Whitespace and case are normalised.
func ParseFaultType(s string) (FaultType, error) {
	norm := strings.ToLower(strings.TrimSpace(s))
	if norm == "" {
		return "", errors.New("chaos: empty fault type")
	}
	for _, f := range AllFaultTypes {
		if string(f) == norm {
			return f, nil
		}
	}
	names := make([]string, 0, len(AllFaultTypes))
	for _, f := range AllFaultTypes {
		names = append(names, string(f))
	}
	return "", fmt.Errorf("chaos: unknown fault type %q (valid: %s)", s, strings.Join(names, ", "))
}

// Fault describes a single active fault injection.
//
// All times are wall-clock UTC. Until == zero means "no expiry", but every
// public injection path requires a positive Duration so this is a defensive
// guard rather than a documented mode.
type Fault struct {
	// ID is the chaos_runs row primary key. Zero before persistence; set by
	// (*Store).Insert and copied back into the file mirror so the daemon-side
	// controller knows which row to stamp with the observed outcome.
	ID int64 `json:"id,omitempty"`

	// Type is the fault category. Unknown types are tolerated by readers.
	Type FaultType `json:"type"`

	// StartedAt is when the fault was injected. Mostly diagnostic — the active
	// window is governed by Until.
	StartedAt time.Time `json:"started_at"`

	// Until is the wall-clock time at which the fault stops applying. The
	// controller skips faults with Until.Before(time.Now()) without removing
	// them from disk; the next persistence cycle prunes them.
	Until time.Time `json:"until"`

	// Probability (0..1) of injecting the fault on each candidate event. Most
	// faults default to 1.0 (always inject) but network-flap and provider-429
	// are typically partial so retry paths actually exercise their happy path.
	Probability float64 `json:"probability,omitempty"`

	// Note is free-form text shown in `cloop chaos report` and useful when
	// running scripted chaos campaigns.
	Note string `json:"note,omitempty"`
}

// Active reports whether the fault is currently within its [StartedAt, Until)
// window. The clock-source is wall-clock by design: faults are configured by
// humans in calendar terms and survive process restarts via the JSON mirror.
func (f Fault) Active(now time.Time) bool {
	if f.Type == "" {
		return false
	}
	if f.Until.IsZero() {
		// Defensive: an open-ended fault is treated as a 1-minute window so a
		// crashed CLI cannot leave a long-running daemon stuck in a fault state.
		return !now.After(f.StartedAt.Add(time.Minute))
	}
	return !now.Before(f.StartedAt) && now.Before(f.Until)
}

// Duration returns the configured fault window length.
func (f Fault) Duration() time.Duration {
	if f.Until.IsZero() || f.StartedAt.IsZero() {
		return 0
	}
	return f.Until.Sub(f.StartedAt)
}

// Outcome captures how the system reacted to a fault. Recorded back to
// chaos_runs at the end of an injection window. Values are deliberately
// coarse-grained — fine analysis comes from the steps/events tables.
type Outcome string

const (
	OutcomeRecovered Outcome = "recovered" // system continued operating
	OutcomeDegraded  Outcome = "degraded"  // continued but with errors/retries
	OutcomeCrashed   Outcome = "crashed"   // a process exited or panicked
	OutcomeUnknown   Outcome = "unknown"   // no observation collected
)
