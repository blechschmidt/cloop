package runbuild

// owner.go: the run-owner record, and what a reader makes of it.

import (
	"os"
	"strings"
	"time"
)

// Owner is the run-owner record: which process is running a project's plan,
// and on which build. The run writes it when it starts and again each time it
// adopts a newer build; it is stored with the project (the run_owner metadata
// key) and nothing but the run writes it, so a dashboard save or an older
// binary's save never touches it.
type Owner struct {
	Ident
	// Host is the machine the process runs on. Its identity can only be
	// checked from the same machine.
	Host string `json:"host,omitempty"`
	// Exe is the path the run was started from: what a deploy replaces and
	// what adoption validates (see StartPath).
	Exe string `json:"exe,omitempty"`
	// Executor is the kind of executor the run was placed on, as the
	// placement record says ("localprocess" for a run on this host).
	Executor string `json:"executor,omitempty"`
	// Adoptable says the run can adopt a newer build at a task boundary: a
	// host-process run of a build that knows how. Device and container runs
	// keep their own upgrade paths.
	Adoptable bool `json:"adoptable,omitempty"`
	// RunID is the execution id the run's tasks are stamped with.
	RunID string `json:"run_id,omitempty"`
	// StartedAt is when the process started. It survives adoptions, as the
	// pid does.
	StartedAt time.Time `json:"started_at"`
	// Build is the build the process runs now, and BuildSince when that image
	// took over: StartedAt for the first, the adoption for later ones.
	Build      Build     `json:"build"`
	BuildSince time.Time `json:"build_since"`
	// Reexecs counts the adoptions, and Previous is the build the last one
	// replaced.
	Reexecs  int    `json:"reexecs,omitempty"`
	Previous *Build `json:"previous,omitempty"`
}

// Clone returns a copy that shares nothing with o.
func (o *Owner) Clone() *Owner {
	if o == nil {
		return nil
	}
	c := *o
	if o.Previous != nil {
		p := *o.Previous
		c.Previous = &p
	}
	return &c
}

// Hostname is this machine's name as records store it.
func Hostname() string {
	h, _ := os.Hostname()
	return strings.TrimSpace(h)
}

// Live reports whether the recorded process is still running, and whether
// that could be told from here: a record from another machine, or a host
// without procfs, cannot be checked.
func (o *Owner) Live() (live, known bool) {
	if o == nil || o.PID <= 0 {
		return false, true
	}
	if o.Host != "" && o.Host != Hostname() {
		return false, false
	}
	return Running(o.Ident)
}

// Status is a run-owner record as a reader sees it: compared with the reader's
// own build — the hub's on the dashboard, the CLI's in `cloop status` — and
// checked for liveness.
type Status struct {
	Build Build `json:"build"`
	// Reference is the build the record is compared with: the reading
	// process's own.
	Reference Build `json:"reference"`
	// Behind is how many builds the run trails Reference; Comparable says
	// whether that could be told (see Behind).
	Behind     int  `json:"behind"`
	Comparable bool `json:"comparable"`
	// Live says the recorded process is still running; LiveKnown is false
	// when that could not be checked from here.
	Live      bool `json:"live"`
	LiveKnown bool `json:"live_known"`
	PID       int  `json:"pid,omitempty"`
	// Since is when the running image took over (BuildSince).
	Since     time.Time `json:"since,omitzero"`
	StartedAt time.Time `json:"started_at,omitzero"`
	Reexecs   int       `json:"reexecs,omitempty"`
	Previous  *Build    `json:"previous,omitempty"`
	Executor  string    `json:"executor,omitempty"`
	Adoptable bool      `json:"adoptable"`
}

// Assess compares o with ref. Nil when there is no record.
func Assess(o *Owner, ref Build) *Status {
	if o == nil {
		return nil
	}
	n, ok := Behind(o.Build, ref)
	live, known := o.Live()
	st := &Status{
		Build: o.Build, Reference: ref, Behind: n, Comparable: ok,
		Live: live, LiveKnown: known, PID: o.PID, Since: o.BuildSince, StartedAt: o.StartedAt,
		Reexecs: o.Reexecs, Executor: o.Executor, Adoptable: o.Adoptable,
	}
	if o.Previous != nil {
		p := *o.Previous
		st.Previous = &p
	}
	return st
}

// Request is a one-shot "adopt the hub's build at the next task boundary",
// stored with the project (the run_adopt_request metadata key) for the run to
// find at its next boundary.
//
// It names the process it is for. A request is about one run: one left behind
// by a run that has since ended must not make the next run in the project
// replace its image the moment it reaches a boundary.
type Request struct {
	ID          string    `json:"id"`
	RequestedAt time.Time `json:"requested_at"`
	// RequestedBy is the identity that asked, as the hub's audit trail names it.
	RequestedBy string `json:"requested_by,omitempty"`
	// Run is the process the request is for.
	Run Ident `json:"run"`
	// Hub is the build of the hub that asked: what the requester expected
	// the run to move to.
	Hub Build `json:"hub"`
}

// For reports whether r is addressed to the process id names.
func (r *Request) For(id Ident) bool { return r != nil && r.Run.Same(id) }

// Clone returns a copy of r.
func (r *Request) Clone() *Request {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}
