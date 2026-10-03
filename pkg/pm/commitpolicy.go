package pm

import (
	"fmt"
	"strings"
)

// This file carries the "done means committed" setting (Task 20370): an
// opt-in, per-project post-condition under which a task whose agent says it is
// done is accepted only once the changes it made are committed — and, with
// Pushed, on its branch's upstream.
//
// Like the review gate, the setting lives in project state rather than in
// config.yaml, because it has to travel with the project: a run on an
// isolating executor is seeded with the project state and never sees the
// hub's config.yaml, and the check runs inside that run, beside the work.

// CommitPolicy is what "done" requires of a task's git work. The zero value is
// off.
type CommitPolicy struct {
	// Enabled turns the check on. Pushed is kept while it is off, so switching
	// it off and on again does not lose the choice.
	Enabled bool `json:"enabled"`
	// Pushed also requires the commits a task made to be on the upstream of
	// the branch they are on.
	Pushed bool `json:"pushed,omitempty"`
}

// The values `cloop run --require-committed=<value>` and `cloop
// require-committed <value>` accept.
const (
	CommitRequireCommitted = "committed"
	CommitRequirePushed    = "pushed"
	CommitRequireOff       = "off"
)

// CommitRequirements lists the accepted values, in the order help text shows
// them.
var CommitRequirements = []string{CommitRequireCommitted, CommitRequirePushed, CommitRequireOff}

// ParseCommitRequirement turns a command-line value into a policy. The empty
// string means "committed", which is what the bare flag asks for.
func ParseCommitRequirement(v string) (*CommitPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", CommitRequireCommitted:
		return &CommitPolicy{Enabled: true}, nil
	case CommitRequirePushed:
		return &CommitPolicy{Enabled: true, Pushed: true}, nil
	case CommitRequireOff:
		return &CommitPolicy{}, nil
	}
	return nil, fmt.Errorf("%q is not one of %s", v, strings.Join(CommitRequirements, ", "))
}

// Active reports whether p requires anything. A nil policy is off.
func (p *CommitPolicy) Active() bool { return p != nil && p.Enabled }

// RequiresPush reports whether p requires the task's commits to be pushed.
func (p *CommitPolicy) RequiresPush() bool { return p.Active() && p.Pushed }

// Clone returns an independent copy (nil for nil).
func (p *CommitPolicy) Clone() *CommitPolicy {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

// Requirement is the command-line value that selects p: "committed",
// "pushed" or "off".
func (p *CommitPolicy) Requirement() string {
	switch {
	case p.RequiresPush():
		return CommitRequirePushed
	case p.Active():
		return CommitRequireCommitted
	}
	return CommitRequireOff
}

// Describe says in a few words what "done" requires under p.
func (p *CommitPolicy) Describe() string {
	switch {
	case p.RequiresPush():
		return "committed and pushed"
	case p.Active():
		return "committed"
	}
	return "off"
}
