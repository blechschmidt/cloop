package secretbroker

// requester.go: the one constructor of a Requester (Task 20432).
//
// A grant's subject names a project, an executor, or a set of labels, and the
// last only ever matched in a test. Operators chose labels when they minted an
// enrollment token, the hub recorded them on the device's credential, the
// guide documented label:region=eu,gpu=true as reaching every executor
// carrying both, and the CLI, the dashboard and the threat model all offered
// it — but no dispatch path ever set Requester.Labels. Each of a dozen call
// sites assembled its own Requester from an executor ID and a project, so a
// label grant was accepted, listed and audited, and silently delivered
// nothing.
//
// So a Requester is built in one place, NewRequester, from a RecordedExecutor:
// the hub's own record of who the executor is. Every RecordedExecutor a
// dispatch uses comes from ExecutorRecords, whose one production
// implementation (pkg/executorstore.Records) reads the hub's tables and its
// configuration — never anything an agent reported about itself, which is
// exactly what a label selector must not be decided by. tests/arch/requester_test.go
// fails on a Requester literal anywhere else in non-test code, and on a
// RecordedExecutor literal outside the few functions allowed to assemble one.

import (
	"fmt"
	"maps"
	"sort"
	"strings"
)

// RecordedExecutor is the hub's own record of an executor, as far as a grant
// is concerned: its ID and the labels the hub recorded for it.
//
// Which record that is depends on the executor (see ExecutorRecords): the
// agent credential for an enrolled device, the device's credential for a
// virtual executor, the configuration for a configured container or
// Kubernetes executor. Never the labels a device's agent advertises when it
// connects — an agent saying it is region=eu is the spoof a label selector has
// to be immune to.
type RecordedExecutor struct {
	// ID is the executor's registry ID. Empty for a question no executor
	// asks — "which grants reach this project at all".
	ID string
	// Labels are the labels the hub recorded for the executor. Nil when it
	// records none, which no label grant matches.
	Labels map[string]string
	// Source says which record Labels came from, for the messages that explain
	// a match or a take-back: "agent credential", "configuration", "the agent
	// credential of device edge-01". Empty when there was no record.
	Source string
}

// HasLabels reports whether the record carries any label.
func (e RecordedExecutor) HasLabels() bool { return len(e.Labels) > 0 }

// LabelString renders the labels as a selector would be written,
// "k1=v1,k2=v2" in key order, or "none".
func (e RecordedExecutor) LabelString() string {
	return FormatLabels(e.Labels)
}

// FormatLabels renders labels as "k1=v1,k2=v2" in key order, or "none".
func FormatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}

// SameLabels reports whether a and b carry the same labels. Nil and empty are
// the same: neither matches any label grant.
func SameLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// ExecutorRecords is the hub's own record of its executors.
//
// The rules, one per kind of executor:
//
//   - An enrolled device carries the labels on its agent credential, which the
//     operator chose when minting its enrollment token and may change on the
//     hub (an audited edit). The labels its agent advertises at hello — from
//     `cloop executor agent --label` on the device — never count: whoever
//     controls the device chooses those.
//   - A virtual executor carries its device's labels and no others. Its own
//     registry row holds only the hub's bookkeeping label parent=<device>,
//     which is not an operator's statement about the machine and does not
//     count: a selector names a property of the hardware the work runs on, and
//     a virtual executor runs on its device's.
//   - A configured container or Kubernetes executor carries the labels its
//     configuration names (executors.container.labels,
//     executors.kubernetes.labels), read when asked, so an edit applies to the
//     next lease without a restart.
//   - The host-process executor, and any executor the hub has no record of,
//     carry none: no label grant reaches them.
//
// A record that cannot be read is an error, never "no labels": a caller that
// dispatched without the label grants an executor holds would be the silent
// non-delivery this type exists to end.
type ExecutorRecords interface {
	RecordedExecutor(executorID string) (RecordedExecutor, error)
}

// LookupExecutor returns records' record of executorID, its ID trimmed.
//
// With no records — a process that keeps none, such as a test or a CLI that
// opened no control plane — or no executor, it returns the ID alone, which no
// label grant matches.
func LookupExecutor(records ExecutorRecords, executorID string) (RecordedExecutor, error) {
	id := strings.TrimSpace(executorID)
	if records == nil || id == "" {
		return RecordedExecutor{ID: id}, nil
	}
	rec, err := records.RecordedExecutor(id)
	if err != nil {
		return RecordedExecutor{ID: id}, fmt.Errorf("secretbroker: read the hub's record of executor %s: %w", id, err)
	}
	rec.ID = id
	return rec, nil
}

// RequestScope is everything about a request that is not the identity of the
// executor making it. See Requester for each field.
type RequestScope struct {
	ProjectID     string
	RunID         string
	GitHubProxied bool
	KubeInProcess bool
	Withhold      map[string]string
}

// NewRequester builds the identity a lease, a proxy session or a grant query is
// judged as: ex's ID and recorded labels, for scope's project.
//
// It is the only place a Requester is assembled (tests/arch/requester_test.go),
// so every grant is matched against the hub's record of the executor and no
// call site can forget the labels, or supply its own.
func NewRequester(ex RecordedExecutor, scope RequestScope) Requester {
	var labels map[string]string
	if len(ex.Labels) > 0 {
		labels = maps.Clone(ex.Labels)
	}
	return Requester{
		ExecutorID:    strings.TrimSpace(ex.ID),
		ProjectID:     scope.ProjectID,
		Labels:        labels,
		RunID:         scope.RunID,
		GitHubProxied: scope.GitHubProxied,
		KubeInProcess: scope.KubeInProcess,
		Withhold:      scope.Withhold,
	}
}

// RequesterFor looks executorID up in records and builds its Requester for
// scope: LookupExecutor, then NewRequester.
func RequesterFor(records ExecutorRecords, executorID string, scope RequestScope) (r Requester, err error) {
	ex, err := LookupExecutor(records, executorID)
	if err != nil {
		return r, err
	}
	return NewRequester(ex, scope), nil
}

// Executor returns the executor identity r was built with: its ID and the
// labels recorded for it. For rebuilding r under another scope — a proxy
// session keeps the identity and not the lease's other facts.
func (r Requester) Executor() RecordedExecutor {
	return RecordedExecutor{ID: r.ExecutorID, Labels: maps.Clone(r.Labels)}
}

// Scope returns everything about r that is not its executor's identity.
func (r Requester) Scope() RequestScope {
	return RequestScope{
		ProjectID:     r.ProjectID,
		RunID:         r.RunID,
		GitHubProxied: r.GitHubProxied,
		KubeInProcess: r.KubeInProcess,
		Withhold:      r.Withhold,
	}
}

// Relabeled returns r judged as an executor carrying labels instead: what a
// lease or a proxy session becomes when the hub's record of its executor
// changes under it (Task 20432).
func (r Requester) Relabeled(labels map[string]string) Requester {
	ex := r.Executor()
	ex.Labels = labels
	return NewRequester(ex, r.Scope())
}

// LabelSubject reports whether s selects on labels, so that whether it matches
// a requester can change while a lease stands on it.
func (s Subject) LabelSubject() bool { return s.Type == SubjectLabel }
