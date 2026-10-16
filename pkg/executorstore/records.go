package executorstore

// records.go: the hub's own record of its executors, as a grant sees them
// (Task 20432).
//
// A label grant — label:region=eu,gpu=true — is matched against the labels of
// the executor a lease is for, and which labels those are is a security
// decision: whoever chooses them chooses which credentials reach the machine.
// So they come from what the hub recorded, per kind of executor, and never
// from what a device's agent advertises about itself:
//
//   - an enrolled device: its agent credential, whose labels the operator set
//     when minting the enrollment token, or changed since with an audited edit;
//   - a virtual executor: its device's credential — the labels describe the
//     machine, and a virtual executor runs on its device's;
//   - a configured container or Kubernetes executor: the hub's configuration;
//   - anything else — the host-process executor, an executor the hub has no
//     record of: no labels, which no label grant matches.
//
// secretbroker.ExecutorRecords documents the same rules for callers; this is
// their one implementation, and tests/arch/requester_test.go allows a
// secretbroker.RecordedExecutor to be assembled here and in no other place a
// dispatch reaches.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Record sources, for the messages that explain a match or a take-back.
const (
	SourceAgentCredential = "agent credential"
	SourceConfiguration   = "configuration"
	// sourceDeviceOf is formatted with a virtual executor's device.
	sourceDeviceOf = "the agent credential of device %s"
)

// Records implements secretbroker.ExecutorRecords over the control plane's
// database and the hub's configuration.
type Records struct {
	// DB holds the agent credentials and the virtual executors.
	DB *statedb.DB
	// Configured returns the labels the hub's configuration gives each
	// configured executor it enables, by ID (config.ExecutorsConfig.
	// ConfiguredExecutorLabels). Asked on every lookup, so an edit to the
	// configuration applies to the next lease. Nil for a process that
	// configures no executor.
	Configured func() (map[string]map[string]string, error)
}

// Compile-time proof that Records is what the broker's callers are written
// against.
var _ secretbroker.ExecutorRecords = Records{}

// RecordedExecutor implements secretbroker.ExecutorRecords.
//
// A table or a configuration that cannot be read is an error. Answering "no
// labels" instead would dispatch the run without the label grants its
// executor holds — the silent non-delivery Task 20432 exists to end — and say
// nothing about why.
func (r Records) RecordedExecutor(executorID string) (secretbroker.RecordedExecutor, error) {
	id := strings.TrimSpace(executorID)
	if id == "" {
		return secretbroker.RecordedExecutor{}, nil
	}
	if r.DB == nil {
		return secretbroker.RecordedExecutor{}, errors.New("executorstore: no control-plane database to read executor records from")
	}

	// A virtual executor first: its ID is in no credential row, and its own
	// registry row's only label — parent=<device> — is the hub's bookkeeping,
	// not a statement about the machine.
	v, isVirtual, err := r.DB.VirtualExecutor(id)
	if err != nil {
		return secretbroker.RecordedExecutor{}, fmt.Errorf("read virtual executor %s: %w", id, err)
	}
	if isVirtual {
		labels, _, err := r.deviceLabels(v.ParentID)
		if err != nil {
			return secretbroker.RecordedExecutor{}, err
		}
		if labels == nil {
			return secretbroker.RecordedExecutor{ID: id}, nil
		}
		return secretbroker.RecordedExecutor{ID: id, Labels: labels,
			Source: fmt.Sprintf(sourceDeviceOf, v.ParentID)}, nil
	}

	// A device is judged by its credential alone, labelled or not: a
	// configured executor that happened to share its ID must not label it.
	labels, isDevice, err := r.deviceLabels(id)
	switch {
	case err != nil:
		return secretbroker.RecordedExecutor{}, err
	case isDevice && labels == nil:
		return secretbroker.RecordedExecutor{ID: id}, nil
	case isDevice:
		return secretbroker.RecordedExecutor{ID: id, Labels: labels, Source: SourceAgentCredential}, nil
	}

	if r.Configured != nil {
		configured, err := r.Configured()
		if err != nil {
			return secretbroker.RecordedExecutor{}, fmt.Errorf("read the hub's configuration: %w", err)
		}
		if labels, ok := configured[id]; ok && len(labels) > 0 {
			return secretbroker.RecordedExecutor{ID: id, Labels: copyLabels(labels), Source: SourceConfiguration}, nil
		}
	}
	return secretbroker.RecordedExecutor{ID: id}, nil
}

// deviceLabels returns the labels on agentID's credential, and whether there
// is a credential at all. The labels are nil for a credential that carries
// none, or is revoked: a device whose credential is revoked runs nothing, and
// carries no label a grant could be matched against.
func (r Records) deviceLabels(agentID string) (labels map[string]string, isDevice bool, err error) {
	cred, err := r.DB.GetAgentCredential(strings.TrimSpace(agentID))
	switch {
	case errors.Is(err, statedb.ErrAgentCredentialNotFound):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("read the credential of device %s: %w", agentID, err)
	case !cred.RevokedAt.IsZero():
		return nil, true, nil
	}
	return copyLabels(cred.Labels), true, nil
}

func copyLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// FleetMember is one executor the hub knows, with its record, for asking
// which executors a label selector reaches (Task 20432).
type FleetMember struct {
	ID   string
	Name string
	Kind string
	// Device is set for a virtual executor: the device whose labels it
	// carries.
	Device string
	Record secretbroker.RecordedExecutor
}

// Fleet lists every executor with a registry row — the devices, their virtual
// executors, the configured drivers — and every one in extra that has none,
// each with records' record of it, sorted by ID.
func Fleet(db *statedb.DB, records secretbroker.ExecutorRecords, extra []FleetMember) ([]FleetMember, error) {
	if db == nil {
		return nil, errors.New("executorstore: no control-plane database to list executors from")
	}
	rows, err := db.ListExecutors()
	if err != nil {
		return nil, err
	}
	devices := map[string]string{}
	if vs, err := db.ListVirtualExecutors(); err == nil {
		for _, v := range vs {
			devices[v.ID] = v.ParentID
		}
	} else {
		return nil, err
	}
	members := make([]FleetMember, 0, len(rows)+len(extra))
	seen := map[string]bool{}
	add := func(m FleetMember) error {
		rec, err := secretbroker.LookupExecutor(records, m.ID)
		if err != nil {
			return err
		}
		m.Record, m.Device, seen[m.ID] = rec, devices[m.ID], true
		members = append(members, m)
		return nil
	}
	for _, row := range rows {
		if err := add(FleetMember{ID: row.ID, Name: row.Name, Kind: row.Kind}); err != nil {
			return nil, err
		}
	}
	for _, m := range extra {
		if seen[m.ID] {
			continue
		}
		if err := add(m); err != nil {
			return nil, err
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	return members, nil
}

// Reaches returns the members a grant to sub would be delivered to now: for a
// label selector, those whose recorded labels carry every pair it names. A
// project subject's reach is not a set of executors, nor "any"'s; both give
// nil.
func Reaches(members []FleetMember, sub secretbroker.Subject) []FleetMember {
	if !sub.LabelSubject() {
		return nil
	}
	out := []FleetMember{}
	for _, m := range members {
		if sub.Matches(secretbroker.NewRequester(m.Record, secretbroker.RequestScope{})) {
			out = append(out, m)
		}
	}
	return out
}
