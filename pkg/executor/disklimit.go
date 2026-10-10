package executor

// disklimit.go is the vocabulary for a workload's disk limit (Task 20405):
// how a driver says it holds one, what it reports when a workload outgrew it,
// and the refusal a workload gets when its tree is over the limit before it has
// started.
//
// ResourceLimits.DiskMB had been a field every layer carried and only the
// Kubernetes driver honoured. The container driver refused it outright, so a
// project whose .cloop/sandbox.yaml set resources.disk could not run there at
// all, and it ignored the operator's disk ceiling, so an executor capped at
// 20 GB was capped at nothing. The container driver now holds the workspace to
// the limit by measuring it — see pkg/executor/internal/diskwatch — and this
// file is the part of that every other layer needs to name.

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// DiskEnforcement says how a driver holds a workload to
// ResourceLimits.DiskMB. The empty value means it does not, and the limit is
// not applied — placement refuses a spec that states one (RequireDiskLimit),
// and a disk ceiling on such an executor is reported as unenforced.
type DiskEnforcement string

const (
	// DiskEnforcementNone: the driver does not bound disk use.
	DiskEnforcementNone DiskEnforcement = ""
	// DiskEnforcementSampled: the driver measures the workspace while the
	// workload runs and stops it once it is over the limit. It is enforcement
	// by measurement, not a quota: a burst can overshoot by the write rate
	// times the sampling interval before the next sample sees it.
	DiskEnforcementSampled DiskEnforcement = "sampled"
	// DiskEnforcementEviction: the cluster holds the limit — the kubelet
	// evicts a Pod whose ephemeral storage or emptyDir outgrows it.
	DiskEnforcementEviction DiskEnforcement = "eviction"
)

// Enforced reports whether the mode bounds disk use at all.
func (d DiskEnforcement) Enforced() bool { return d != DiskEnforcementNone }

// Describe renders the mode the way the executor card shows it.
func (d DiskEnforcement) Describe() string {
	if !d.Enforced() {
		return "not supported"
	}
	return "enforced (" + string(d) + ")"
}

// Outcome classifies how a workload ended, when a driver knows more than its
// State says. Empty for every ending a State and an exit code describe.
type Outcome string

// OutcomeDiskLimit: the driver stopped the workload because its workspace grew
// past its disk limit. Status.DiskLimit carries the measurement.
const OutcomeDiskLimit Outcome = "disk_limit"

// Disk limit sources: where the limit a workload was held to came from, so the
// message that stops it can say whom to ask for more.
const (
	// DiskLimitFromSpec: the project's own request, .cloop/sandbox.yaml
	// resources.disk, within every ceiling.
	DiskLimitFromSpec = "spec"
	// DiskLimitFromCeiling: an operator's ceiling — the fleet's, the
	// executor's or the project's — lowered or filled in the request.
	DiskLimitFromCeiling = "ceiling"
)

// DiskLimitBreach is the measurement that put a workload over its disk limit.
type DiskLimitBreach struct {
	// UsedBytes is the workspace's allocated size when it was measured: the
	// blocks its files occupy, hard links counted once, .cloop/ excluded.
	UsedBytes int64 `json:"used_bytes"`
	// LimitMB is the limit it was held to, in MiB.
	LimitMB int `json:"limit_mb"`
	// Source is DiskLimitFromSpec or DiskLimitFromCeiling.
	Source string `json:"source,omitempty"`
	// Path is the tree that was measured, on the executor's own host.
	Path string `json:"path,omitempty"`
	// MeasuredAt is when the measurement finished.
	MeasuredAt time.Time `json:"measured_at"`
}

// UsedMB is UsedBytes in MiB, rounded up: a tree one byte over a 64 MB limit
// must not read back as "64 MB, over its limit of 64 MB".
func (b DiskLimitBreach) UsedMB() int64 {
	if b.UsedBytes <= 0 {
		return 0
	}
	mb := b.UsedBytes >> 20
	if b.UsedBytes&(1<<20-1) != 0 {
		mb++
	}
	return mb
}

// LimitBytes is the limit in bytes.
func (b DiskLimitBreach) LimitBytes() int64 { return int64(b.LimitMB) << 20 }

// Over reports whether the measurement exceeds the limit.
func (b DiskLimitBreach) Over() bool { return b.LimitMB > 0 && b.UsedBytes > b.LimitBytes() }

// Describe is the sentence fragment the journal, the task and the pause give:
// "the workspace grew to 70 MB, over its disk limit of 64 MB (from
// .cloop/sandbox.yaml resources.disk)".
func (b DiskLimitBreach) Describe() string {
	return fmt.Sprintf("the workspace grew to %s, over its disk limit of %s (%s)",
		formatUsedMB(b.UsedMB()), FormatMB(b.LimitMB), b.sourcePhrase())
}

// Remedy names what to do about it.
func (b DiskLimitBreach) Remedy() string {
	return DiskLimitAdvice(b.Source)
}

// sourcePhrase names where the limit came from.
func (b DiskLimitBreach) sourcePhrase() string { return DiskLimitSourcePhrase(b.Source) }

// DiskLimitSourcePhrase names where a disk limit from source came from, in
// the parenthesis a message gives it.
func DiskLimitSourcePhrase(source string) string {
	if source == DiskLimitFromCeiling {
		return "an operator's disk ceiling"
	}
	return "from .cloop/sandbox.yaml resources.disk"
}

// FormatUsedMB renders a measured size in MiB, never rounded to whole
// gigabytes; see formatUsedMB.
func FormatUsedMB(mb int64) string { return formatUsedMB(mb) }

// DiskLimitAdvice names how to get a workload back under a disk limit that
// came from source, or how to raise it.
func DiskLimitAdvice(source string) string {
	if source == DiskLimitFromCeiling {
		return "free space in the workspace, or ask an admin to raise the disk ceiling " +
			"(the executor's Limits in the Executors panel, the project's limits, or " +
			"executors.limits.max_disk)"
	}
	return "free space in the workspace, or raise resources.disk in .cloop/sandbox.yaml " +
		"(an operator's disk ceiling still caps it)"
}

// formatUsedMB renders a measured size, always in whole MiB. Unlike FormatMB it
// never rounds to gigabytes, even with a decimal: "20.0 GB, over its disk limit
// of 20 GB" would hide the very overshoot being reported.
func formatUsedMB(mb int64) string {
	return fmt.Sprintf("%d MB", mb)
}

// ErrDiskLimit marks a workload refused because its workspace was already
// over its disk limit when it was asked to start.
var ErrDiskLimit = errors.New("workspace over its disk limit")

// DiskLimitError is the refusal Start returns for a tree that is already over
// the limit — the meaning the provisioner's post-fetch check gives a fetched
// tree, applied to a tree that was already there. It names both sizes and how
// to raise the limit, because the run never started and this message is all
// its author gets.
type DiskLimitError struct {
	Breach DiskLimitBreach
	// Executor is the executor that refused.
	Executor string
}

// Error implements error.
func (e *DiskLimitError) Error() string {
	var b strings.Builder
	b.WriteString("executor")
	if e.Executor != "" {
		b.WriteString(" " + e.Executor)
	}
	fmt.Fprintf(&b, ": refusing to start: the workspace")
	if e.Breach.Path != "" {
		b.WriteString(" " + e.Breach.Path)
	}
	fmt.Fprintf(&b, " already holds %s, over this workload's disk limit of %s (%s); %s",
		formatUsedMB(e.Breach.UsedMB()), FormatMB(e.Breach.LimitMB), e.Breach.sourcePhrase(),
		e.Breach.Remedy())
	return b.String()
}

// Unwrap lets errors.Is(err, ErrDiskLimit) match.
func (e *DiskLimitError) Unwrap() error { return ErrDiskLimit }

// DiskLimitExplainer is implemented by a driver that can say why it cannot
// hold a workload to a disk limit right now — a remote agent knows whether its
// device runs payloads in a container and which protocol its agent speaks, and
// those have different remedies. A method rather than a field, for the reason
// EgressScopeExplainer gives.
type DiskLimitExplainer interface {
	// ExplainDiskLimitRefusal returns a sentence completing "this executor
	// cannot hold a workload to a disk limit; ...", or "" when the driver has
	// nothing more specific than the generic remedy.
	ExplainDiskLimitRefusal() string
}

// DiskEnforcementRemedy asks the driver why it cannot hold a workload to a
// disk limit, falling back to the generic advice: where to run instead.
func DiskEnforcementRemedy(ex Executor) string {
	if e, ok := ex.(DiskLimitExplainer); ok {
		if s := strings.TrimSpace(e.ExplainDiskLimitRefusal()); s != "" {
			return strings.TrimSuffix(s, ".")
		}
	}
	return "bind the project to a container or Kubernetes executor, which enforce one, or drop " +
		"resources.disk and rely on the executor's free-space floor"
}

// LabelDiskLimitSource is the Spec label set when an operator's ceiling,
// rather than the project's own request, decided the disk limit a spec
// carries. A driver that cannot read the ceilings itself — a remote agent's —
// still names the right remedy when it stops or refuses the workload.
const LabelDiskLimitSource = "disk_limit_source"

// MarkDiskLimitFromCeiling labels spec's disk limit as the ceiling's. The
// labels map is copied rather than written through, because the caller's may
// be shared with a Spec that is persisted or reused.
func MarkDiskLimitFromCeiling(spec *Spec) {
	if spec == nil {
		return
	}
	labels := make(map[string]string, len(spec.Labels)+1)
	for k, v := range spec.Labels {
		labels[k] = v
	}
	labels[LabelDiskLimitSource] = DiskLimitFromCeiling
	spec.Labels = labels
}

// DiskLimitSourceOf reads where spec's disk limit came from, given the
// ceiling the reader can see (zero when it can see none).
func DiskLimitSourceOf(spec Spec, resolvedMB int, ceiling ResourceCeiling) string {
	if resolvedMB <= 0 {
		return ""
	}
	if spec.Labels[LabelDiskLimitSource] == DiskLimitFromCeiling ||
		(ceiling.DiskMB > 0 && resolvedMB == ceiling.DiskMB) {
		return DiskLimitFromCeiling
	}
	return DiskLimitFromSpec
}

// Bounds on a breach that has crossed from a device: it is the device's word,
// and it is written into the project's journal and its pause.
const (
	maxBreachPath = 512
	// maxDiskLimitMB mirrors config.ContainerDiskMBUpper (1 TiB), the largest
	// disk limit the hub ever sends; this package cannot import config.
	maxDiskLimitMB = 1 << 20
	// maxBreachBytes is a petabyte: past any workspace, and far from where
	// the arithmetic on it overflows.
	maxBreachBytes = int64(1) << 50
)

// SanitizeDiskOutcome bounds a status's disk-limit account where the hub did
// not produce it — a remote agent's status frame. An outcome the hub does not
// know, a limit it could never have sent, or a breach that does not describe a
// tree over its limit is dropped, and the run is then judged by its State and
// exit code like any other. What is kept has a known source, a measurement of
// bounded size, and a path of bounded length with no control or bidirectional
// formatting characters to rewrite the line it is printed on.
func SanitizeDiskOutcome(o Outcome, b *DiskLimitBreach) (Outcome, *DiskLimitBreach) {
	if o != OutcomeDiskLimit || b == nil || b.LimitMB <= 0 || b.LimitMB > maxDiskLimitMB {
		return "", nil
	}
	s := *b
	if s.UsedBytes > maxBreachBytes {
		s.UsedBytes = maxBreachBytes
	}
	if !s.Over() {
		return "", nil
	}
	switch s.Source {
	case DiskLimitFromSpec, DiskLimitFromCeiling:
	default:
		s.Source = ""
	}
	s.Path = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s.Path)
	if len(s.Path) > maxBreachPath {
		s.Path = strings.ToValidUTF8(s.Path[:maxBreachPath], "")
	}
	return OutcomeDiskLimit, &s
}
