package projectmove

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Severity is how a finding bears on a move.
type Severity string

const (
	// SeverityBlocker: the move must not happen until this is resolved — it
	// would lose work, interrupt a run, or leave the project on a target that
	// cannot run it. Remedy says how to resolve it.
	SeverityBlocker Severity = "blocker"
	// SeverityWillCarry: something the source holds that the move takes with
	// it, or that stays valid where the project goes. Listed so a reader knows
	// what moves; nothing needs doing.
	SeverityWillCarry Severity = "will-carry"
	// SeverityWarning: the move can go ahead, and this is lost, changed, or
	// could not be checked. Remedy says what to do about it, before or after.
	SeverityWarning Severity = "warning"
)

// rank orders severities, worst first.
func (s Severity) rank() int {
	switch s {
	case SeverityBlocker:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

// Symbol is what the text rendering prefixes a finding with.
func (s Severity) Symbol() string {
	switch s {
	case SeverityBlocker:
		return "✗"
	case SeverityWarning:
		return "!"
	default:
		return "→"
	}
}

// Kind identifies what a finding is about. Values are stable wire strings: a
// client may switch on them.
type Kind string

const (
	// KindRun: a run that is active (executing, or queued for a pool's
	// runner), paused, or held at a human review gate. (a)
	KindRun Kind = "run"
	// KindWorkingTree: uncommitted changes or untracked files in the
	// source's working trees, the project's features' included. (b)
	KindWorkingTree Kind = "working_tree"
	// KindLocalCommits: commits on local branches — or on a detached HEAD,
	// or in the stash — that no remote holds. (c)
	KindLocalCommits Kind = "local_commits"
	// KindProjectFiles: files under the project's .cloop directory that no
	// database holds. (d)
	KindProjectFiles Kind = "project_files"
	// KindSourceUnreachable: the source cannot be reached, so what it holds
	// cannot be captured. (e)
	KindSourceUnreachable Kind = "source_unreachable"
	// KindSourceUnseen: the source can be reached but what its working copy
	// holds cannot be read from the hub. (b)–(d)
	KindSourceUnseen Kind = "source_unseen"
	// KindAbandoned: what a move that abandons its source loses. (e)
	KindAbandoned Kind = "abandoned"
	// KindTarget: the target binding itself — unknown, the binding the
	// project already has, a pool's runner, refused by host policy or the
	// agent build floor, offline, or a pool that cannot take the project. (f)
	KindTarget Kind = "target"
	// KindAudience: whether the caller is on the target executor's access
	// list. (f)
	KindAudience Kind = "audience"
	// KindHarnessCredential: whether a run on the target would receive a
	// Claude (or Copilot) credential. (f)
	KindHarnessCredential Kind = "harness_credential"
	// KindSecretGrants: the project's secret grants, and whether each one
	// reaches the target. (f)
	KindSecretGrants Kind = "secret_grants"
	// KindFirewall: the project's firewall rules against the target's. (f)
	KindFirewall Kind = "firewall"
	// KindDeviceFeatures: the devices, interfaces and forwarded hardware the
	// project uses, against what the target can expose. (f)
	KindDeviceFeatures Kind = "device_features"
	// KindIsolation: the isolation the project's sandbox spec demands,
	// against the target's claims and the evidence for them. (f)
	KindIsolation Kind = "isolation"
	// KindPathBindings: knowledge and policy bindings keyed by the project's
	// path. Requirements are not among them: they live in the project's own
	// database and name no path. (g)
	KindPathBindings Kind = "path_bindings"
)

// Finding is one thing a move could lose or break, or takes with it.
type Finding struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	// Side is which end of the move the finding is about: "source",
	// "target" or "project" (the hub's own records of it).
	Side  string `json:"side"`
	Title string `json:"title"`
	// Message says what was observed; Remedy what to do about it. Remedy is
	// set on every blocker and warning.
	Message string `json:"message"`
	Remedy  string `json:"remedy,omitempty"`
	// Items are the finding's particulars: per branch, per worktree, per
	// file category, per grant, per rule.
	Items []Item `json:"items,omitempty"`
}

// Item is one particular of a finding.
type Item struct {
	// Name identifies the particular: a branch, a worktree, a file category,
	// a grant, a rule, a store.
	Name string `json:"name"`
	// Path is a path the item lives at, when it has one.
	Path string `json:"path,omitempty"`
	// Count and Bytes are how much of it there is, when that is countable.
	Count int   `json:"count,omitempty"`
	Bytes int64 `json:"bytes,omitempty"`
	// Detail is anything else worth saying about it.
	Detail string `json:"detail,omitempty"`
	// Examples are the first few of what Count counts (paths, task titles).
	Examples []string `json:"examples,omitempty"`
}

// Side constants for Finding.Side.
const (
	SideSource  = "source"
	SideTarget  = "target"
	SideProject = "project"
)

// Endpoint describes one end of a move.
type Endpoint struct {
	// Binding is the binding value: an executor ID, pool:<id>, or "" for a
	// source that has none and runs on the hub's default executor.
	Binding string `json:"binding"`
	// ExecutorID, Kind and Name describe the executor the binding resolves
	// to; for a pool, PoolID and Name describe the pool and Kind is "pool".
	ExecutorID string `json:"executor_id,omitempty"`
	PoolID     string `json:"pool_id,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
	// Parent is the device a virtual executor belongs to.
	Parent string `json:"parent,omitempty"`
	// Workspace is where a project's work lives on this end; see the
	// Workspace* constants.
	Workspace string `json:"workspace,omitempty"`
	// WorkDir is the directory that work lives in, as that end names it.
	WorkDir string `json:"work_dir,omitempty"`
	// Reachable reports whether this end answered when the preflight asked;
	// nil when it was not asked.
	Reachable *bool `json:"reachable,omitempty"`
}

// Where a project's work lives on an executor.
const (
	// WorkspaceHubTree: the hub's own directory for the project — the host
	// driver, and a container that bind-mounts it.
	WorkspaceHubTree = "hub_tree"
	// WorkspaceDevice: a working copy the device keeps between runs, beneath
	// its agent's working-directory root.
	WorkspaceDevice = "device_working_copy"
	// WorkspacePool: a pool runner's volume, kept between runners.
	WorkspacePool = "pool_volume"
	// WorkspaceEphemeral: a tree made for each run and gone with it — a
	// Kubernetes Pod's.
	WorkspaceEphemeral = "ephemeral"
)

// Report is a preflight's answer.
type Report struct {
	// Project is the project the move is for.
	Project Project `json:"project"`
	// Source and Target are the two ends.
	Source Endpoint `json:"source"`
	Target Endpoint `json:"target"`
	// AbandonSource reports that the preflight was asked what a move that
	// does not capture its source would lose.
	AbandonSource bool `json:"abandon_source,omitempty"`
	// CheckedAt is when the preflight ran.
	CheckedAt time.Time `json:"checked_at"`
	// Blocked reports that at least one finding is a blocker.
	Blocked bool `json:"blocked"`
	// Counts tallies the findings by severity.
	Counts Counts `json:"counts"`
	// Findings are ordered blockers first, then warnings, then what is
	// carried, each group in the order the checks ran.
	Findings []Finding `json:"findings"`
}

// Counts tallies findings by severity.
type Counts struct {
	Blockers  int `json:"blockers"`
	Warnings  int `json:"warnings"`
	WillCarry int `json:"will_carry"`
}

// finish orders the findings and fills in the tallies.
func (r *Report) finish() {
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Severity.rank() < r.Findings[j].Severity.rank()
	})
	r.Counts = Counts{}
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityBlocker:
			r.Counts.Blockers++
		case SeverityWarning:
			r.Counts.Warnings++
		default:
			r.Counts.WillCarry++
		}
	}
	r.Blocked = r.Counts.Blockers > 0
}

// Of returns the findings of one kind.
func (r *Report) Of(k Kind) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Kind == k {
			out = append(out, f)
		}
	}
	return out
}

// WriteText renders the report for a terminal. Its JSON form — json.Marshal
// of the Report — is the machine-readable one a --json flag prints.
func (r *Report) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Move preflight for %s (%s)\n", r.Project.Name, r.Project.Path)
	fmt.Fprintf(&b, "  from %s\n  to   %s\n", describeEndpoint(r.Source), describeEndpoint(r.Target))
	if r.AbandonSource {
		b.WriteString("  abandoning the source: nothing is captured from it\n")
	}
	switch {
	case r.Blocked:
		fmt.Fprintf(&b, "\nBlocked: %d blocker(s), %d warning(s), %d carried.\n", r.Counts.Blockers, r.Counts.Warnings, r.Counts.WillCarry)
	default:
		fmt.Fprintf(&b, "\nNothing blocks the move: %d warning(s), %d carried.\n", r.Counts.Warnings, r.Counts.WillCarry)
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n%s [%s] %s\n", f.Severity.Symbol(), f.Severity, f.Title)
		writeIndented(&b, "    ", f.Message)
		for _, it := range f.Items {
			b.WriteString("      - " + describeItem(it) + "\n")
		}
		if f.Remedy != "" {
			writeIndented(&b, "    → ", f.Remedy)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func describeEndpoint(e Endpoint) string {
	var parts []string
	switch {
	case e.PoolID != "":
		parts = append(parts, "pool "+e.PoolID)
	case e.ExecutorID != "":
		parts = append(parts, "executor "+e.ExecutorID)
	case e.Binding != "":
		parts = append(parts, e.Binding)
	default:
		parts = append(parts, "the hub's default executor")
	}
	if e.Kind != "" {
		parts = append(parts, "("+e.Kind+")")
	}
	if e.Workspace != "" {
		where := e.Workspace
		if e.WorkDir != "" {
			where += " " + e.WorkDir
		}
		parts = append(parts, "— "+where)
	}
	return strings.Join(parts, " ")
}

func describeItem(it Item) string {
	s := it.Name
	if it.Path != "" && it.Path != it.Name {
		s += " (" + it.Path + ")"
	}
	var nums []string
	if it.Count > 0 {
		nums = append(nums, fmt.Sprintf("%d", it.Count))
	}
	if it.Bytes > 0 {
		nums = append(nums, humanBytes(it.Bytes))
	}
	if len(nums) > 0 {
		s += ": " + strings.Join(nums, ", ")
	}
	if it.Detail != "" {
		s += " — " + it.Detail
	}
	if len(it.Examples) > 0 {
		s += " [" + strings.Join(it.Examples, ", ") + "]"
	}
	return s
}

func writeIndented(b *strings.Builder, prefix, text string) {
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		b.WriteString(prefix + line + "\n")
	}
}

// humanBytes renders n bytes for a reader.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
