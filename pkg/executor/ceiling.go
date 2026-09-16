// ceiling.go is about the difference between what a run asks for and what it is
// allowed to have.
//
// Until this file existed cloop had only the first vocabulary. ResourceLimits
// is a *request*, and the drivers resolve it against the operator's config with
// one rule, stated in pkg/executor/container/container.go:
//
//	// Spec limits override the executor's configured defaults: the per-run
//	// request is more specific than the per-executor policy.
//
// That is the right rule when the request comes from the operator, and the
// wrong one when it does not. A project's resource request is read from
// .cloop/sandbox.yaml — a file committed to the repository — so "the per-run
// request" is authored by whoever can push to that repo. Under the override
// rule such a file could name `memory: 900g` and receive it: the only thing in
// its way was config.ContainerMemoryMBUpper, a 1 TiB constant sized to catch a
// typo rather than a tenant. `executors.container.memory: 2g` did not bound it,
// because that setting was never a bound. It was a default.
//
// So an operator had no way to write down the sentence this file exists to
// make expressible: *no workload on this executor gets more than this, whatever
// it asks for.*
//
// # Ceilings compose by getting tighter
//
// There are two of them, and they answer different questions:
//
//   - the fleet ceiling (config `executors.limits`) — what any workload on
//     this hub may have;
//   - the project ceiling (control-plane, operator-set) — what this one
//     project may have, which is how a single noisy project gets held below
//     the fleet's allowance without holding everything else down with it.
//
// Neither is a request, so neither can raise anything. Apply them in sequence
// and the result is the minimum of the request and every ceiling that spoke,
// with each reduction attributed to the ceiling that caused it — which is the
// only way the developer reading "your task was given 2 GB" can find out who to
// ask for more.
package executor

import (
	"fmt"
	"sort"
	"strings"
)

// Ceiling source names. They appear in Clamp.Source, in the warnings surfaced
// on a run, and in the audit trail, so they are constants rather than literals
// scattered across the call sites that produce them.
const (
	// CeilingSourceFleet is the hub-wide cap from config `executors.limits`.
	CeilingSourceFleet = "fleet"
	// CeilingSourceProject is the per-project cap an operator set on the hub.
	CeilingSourceProject = "project"
)

// ResourceCeiling bounds what a workload may be given. Zero on any field means
// "this ceiling says nothing about that resource" — not "zero of it" — which
// is what lets a ceiling constrain memory alone and leave CPU to whatever the
// executor would otherwise have done.
//
// It mirrors ResourceLimits field for field on purpose. The two are separate
// types precisely because they are not interchangeable: assigning one to the
// other is the bug this file was written to remove, and the compiler now
// refuses it.
type ResourceCeiling struct {
	// CPUMillis caps the CPU allowance in thousandths of a core.
	CPUMillis int `json:"cpu_millis,omitempty"`
	// MemoryMB caps resident memory in megabytes.
	MemoryMB int `json:"memory_mb,omitempty"`
	// DiskMB caps the writable-layer / scratch ceiling in megabytes.
	DiskMB int `json:"disk_mb,omitempty"`
	// PIDs caps the number of processes/threads.
	PIDs int `json:"pids,omitempty"`
}

// IsZero reports whether the ceiling constrains nothing.
func (c ResourceCeiling) IsZero() bool {
	return c.CPUMillis == 0 && c.MemoryMB == 0 && c.DiskMB == 0 && c.PIDs == 0
}

// Validate rejects negative caps. Zero (unset) is always valid.
//
// Negative is rejected rather than normalised because in ResourceLimits a
// negative PIDs value is the runtimes' "unlimited" sentinel, and a *ceiling*
// that means unlimited is a ceiling that should not have been written. Silently
// reading it as zero would turn a cap an operator believed they had set into no
// cap at all, which is the one failure mode this type may not have.
func (c ResourceCeiling) Validate() error {
	switch {
	case c.CPUMillis < 0:
		return fmt.Errorf("%w: ceiling cpu_millis must be >= 0, got %d", ErrInvalidSpec, c.CPUMillis)
	case c.MemoryMB < 0:
		return fmt.Errorf("%w: ceiling memory_mb must be >= 0, got %d", ErrInvalidSpec, c.MemoryMB)
	case c.DiskMB < 0:
		return fmt.Errorf("%w: ceiling disk_mb must be >= 0, got %d", ErrInvalidSpec, c.DiskMB)
	case c.PIDs < 0:
		return fmt.Errorf("%w: ceiling pids must be >= 0, got %d", ErrInvalidSpec, c.PIDs)
	}
	return nil
}

// Tighten returns the stricter of two ceilings, resource by resource.
//
// "Stricter" is the smaller *non-zero* value, because zero is silence rather
// than a bound of nothing: a ceiling naming only memory must not erase a CPU
// cap the other one set.
//
// This is the operation the fleet ceiling is accumulated with, and it is
// one-directional for the same reason executor.ApplyMinAgentBuild is. A hub
// reads many projects' config.yaml; combining them symmetrically would let one
// tenant's file raise a fleet-wide cap for every other tenant in the process.
// Loosening a fleet ceiling is deliberate and explicit — restart with the
// looser config, the ceremony every other security-relevant setting asks for.
func (c ResourceCeiling) Tighten(other ResourceCeiling) ResourceCeiling {
	return ResourceCeiling{
		CPUMillis: tighter(c.CPUMillis, other.CPUMillis),
		MemoryMB:  tighter(c.MemoryMB, other.MemoryMB),
		DiskMB:    tighter(c.DiskMB, other.DiskMB),
		PIDs:      tighter(c.PIDs, other.PIDs),
	}
}

// tighter picks the smaller of two caps, treating 0 as "no opinion".
func tighter(a, b int) int {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case b < a:
		return b
	}
	return a
}

// Clamp records one reduction a ceiling made, so it can be explained.
type Clamp struct {
	// Resource is the human name of the field: "cpu", "memory", "disk", "pids".
	Resource string `json:"resource"`
	// Requested is what the run asked for; 0 means it asked for no limit.
	Requested int `json:"requested"`
	// Effective is what it was given.
	Effective int `json:"effective"`
	// Source names the ceiling that bound it — one of the CeilingSource
	// constants.
	Source string `json:"source"`
}

// String renders the clamp the way an operator should read it.
//
// The unstated case gets its own wording. "requested 0" would be a lie about
// what the project asked for — it asked for nothing, which meant everything —
// and a developer told their 0 became 2048 has been given a puzzle rather than
// an explanation.
func (c Clamp) String() string {
	unit := resourceUnit(c.Resource)
	if c.Requested <= 0 {
		return fmt.Sprintf("%s was unbounded and the %s ceiling set it to %d%s",
			c.Resource, c.Source, c.Effective, unit)
	}
	return fmt.Sprintf("%s %d%s exceeds the %s ceiling and was lowered to %d%s",
		c.Resource, c.Requested, unit, c.Source, c.Effective, unit)
}

// resourceUnit is the suffix that makes a bare number legible.
func resourceUnit(resource string) string {
	switch resource {
	case "memory", "disk":
		return " MB"
	case "cpu":
		return "m" // milli-cores, matching Kubernetes' own rendering
	}
	return ""
}

// applyStated lowers the limits rl actually states, leaving the ones it does not
// state alone, and records each reduction against source.
//
// The asymmetry is deliberate and is explained at length on BoundSpec: writing a
// ceiling into a limit the project left unset turns "stated nothing" into
// "explicitly requested the ceiling", and the drivers treat a stated request as
// more specific than their own configured default — so it could *raise* a
// limit. An unstated request is bounded one layer down, by the driver, through
// BoundLimit.
//
// Applying two ceilings in sequence yields the minimum of the request and both,
// each reduction carrying the name of the ceiling that made it — so the order of
// application does not change the result, only which source gets the credit when
// two would have clamped to the same number. Ties go to the one applied first,
// which is why callers apply the fleet ceiling before the project's: "your hub
// caps this" is the more useful of two true answers.
func (c ResourceCeiling) applyStated(rl ResourceLimits, source string) (ResourceLimits, []Clamp) {
	if c.IsZero() {
		return rl, nil
	}
	var clamps []Clamp
	bound := func(resource string, cap int, field *int) {
		// Unstated stays unstated; only a request above the cap is lowered.
		if cap <= 0 || *field <= 0 || *field <= cap {
			return
		}
		clamps = append(clamps, Clamp{
			Resource:  resource,
			Requested: *field,
			Effective: cap,
			Source:    source,
		})
		*field = cap
	}
	bound("cpu", c.CPUMillis, &rl.CPUMillis)
	bound("memory", c.MemoryMB, &rl.MemoryMB)
	bound("disk", c.DiskMB, &rl.DiskMB)
	bound("pids", c.PIDs, &rl.PIDs)
	return rl, clamps
}

// Describe renders the ceiling for a UI or a log line, tightest fields first in
// a stable order. An empty ceiling renders as "unlimited" rather than as the
// empty string, because a blank field where a policy was expected reads as a
// rendering bug.
func (c ResourceCeiling) Describe() string {
	var parts []string
	if c.CPUMillis > 0 {
		parts = append(parts, fmt.Sprintf("cpu %s", FormatCPUMillis(c.CPUMillis)))
	}
	if c.MemoryMB > 0 {
		parts = append(parts, fmt.Sprintf("memory %s", FormatMB(c.MemoryMB)))
	}
	if c.DiskMB > 0 {
		parts = append(parts, fmt.Sprintf("disk %s", FormatMB(c.DiskMB)))
	}
	if c.PIDs > 0 {
		parts = append(parts, fmt.Sprintf("pids %d", c.PIDs))
	}
	if len(parts) == 0 {
		return "unlimited"
	}
	return strings.Join(parts, ", ")
}

// FormatMB renders a megabyte count the way an operator wrote it, so a value
// that came from "8g" reads back as "8 GB" rather than "8192 MB".
func FormatMB(mb int) string {
	switch {
	case mb <= 0:
		return "unlimited"
	case mb%1024 == 0:
		return fmt.Sprintf("%d GB", mb/1024)
	}
	return fmt.Sprintf("%d MB", mb)
}

// FormatCPUMillis renders a milli-core count as cores when it divides evenly,
// which is how nearly every real setting is written.
func FormatCPUMillis(millis int) string {
	switch {
	case millis <= 0:
		return "unlimited"
	case millis%1000 == 0:
		return fmt.Sprintf("%d", millis/1000)
	}
	return fmt.Sprintf("%.2f", float64(millis)/1000.0)
}

// ClampWarnings renders clamps as operator-facing lines, deduplicated and
// ordered so the same set always reads the same way.
//
// Deduplication matters because the fleet and project ceilings can both clamp
// the same resource to the same number, and telling someone twice that their
// memory was capped to 2 GB reads as two separate events.
func ClampWarnings(clamps []Clamp) []string {
	if len(clamps) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(clamps))
	out := make([]string, 0, len(clamps))
	for _, c := range clamps {
		line := c.String()
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}
