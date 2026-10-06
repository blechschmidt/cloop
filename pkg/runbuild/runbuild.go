// Package runbuild is what a long-lived `cloop run` knows about its own build,
// and what lets it move to a newer one without ending (Task 20389).
//
// A deploy replaces the hub's binary, and a hub restart deliberately keeps runs
// alive (KillMode=process plus adoption). So a run in auto-evolve never ends
// and never upgrades: on 2026-10-06 this repository's own run was 132 commits
// behind the deployed hub, executing an orchestrator that predated "done means
// committed" and the disk floor, against a database six migrations ahead of
// what it knew. Nothing showed it, and only a manual restart fixed it.
//
// Two halves live here:
//
//   - Visibility. A run records its build — version, commit, sequence on main,
//     and the schema it embeds — in its project's run-owner record (Owner)
//     when it starts. Anything that reads the project can then compare it with
//     its own build (Assess): the hub's Overview, `cloop status`, hub doctor.
//
//   - Adoption. At a task boundary a host-process run may replace its own
//     image with the binary at the path it was started from, keeping its pid,
//     its process start time, its stdout pipe and everything the hub and the
//     local driver identify it by. Candidate holds that binary open so the file
//     that is validated is the file that is executed; Judge decides whether it
//     may be adopted; Handoff carries what the new image needs to continue the
//     same run rather than start a new one.
//
// Everything here is the standard library and pkg/version, so pkg/state can
// carry the record without dragging the orchestrator in.
package runbuild

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/version"
)

// Build is one cloop build, in the terms adoption compares them by.
type Build struct {
	// Version is version.String(): "v0.0.4", "dev+g4e35bf6".
	Version string `json:"version"`
	// Commit is the full commit the build was made from, when it knows it.
	Commit string `json:"commit,omitempty"`
	// Sequence is the commit's first-parent position on main (Task 20380),
	// zero for a build that was not stamped with one. It is the only ordering
	// two builds of main have: two "dev+g<sha>" versions do not compare.
	Sequence int `json:"sequence,omitempty"`
	// Schema is the newest database migration the build embeds, zero when the
	// build did not say (`cloop version --json` reports it since Task 20389).
	Schema int `json:"schema,omitempty"`
}

// Self is this binary's build. schema is the newest migration it embeds,
// which pkg/statedb knows and this package cannot import.
func Self(schema int) Build {
	b := version.Build()
	return Build{Version: b.Version, Commit: b.Revision, Sequence: b.Sequence, Schema: schema}
}

// IsZero reports whether b says nothing at all.
func (b Build) IsZero() bool {
	return b.Version == "" && b.Commit == "" && b.Sequence == 0 && b.Schema == 0
}

// Short names the build the way an operator reads it: the version, which for
// a build of main already carries the commit.
func (b Build) Short() string {
	v := strings.TrimSpace(b.Version)
	if v == "" {
		if c := strings.TrimSpace(b.Commit); len(c) >= 7 {
			return "dev+g" + c[:7]
		}
		return "an unidentified build"
	}
	return v
}

// Label is Short with the build's place on main, when it has one:
// "dev+g4e35bf6 (sequence 831 on main)".
func (b Build) Label() string {
	if b.Sequence <= 0 {
		return b.Short()
	}
	return fmt.Sprintf("%s (%s)", b.Short(), version.SequenceLabel(b.Sequence))
}

// Behind reports how many builds run trails ref along main, and whether that
// could be told at all.
//
// The count is the difference of their sequences, so it is exact for any two
// stamped builds of main and zero (not negative) when run is level or ahead.
// Without both sequences only identity can be told: the same commit is level,
// anything else is not comparable — a "dev+g<sha>" pair has no order, and
// guessing one would put a wrong number on an operator's screen.
func Behind(run, ref Build) (n int, ok bool) {
	if run.Sequence > 0 && ref.Sequence > 0 {
		if d := ref.Sequence - run.Sequence; d > 0 {
			return d, true
		}
		return 0, true
	}
	if c := strings.ToLower(strings.TrimSpace(run.Commit)); c != "" &&
		c == strings.ToLower(strings.TrimSpace(ref.Commit)) {
		return 0, true
	}
	if run.Version != "" && run.Version == ref.Version && !strings.HasPrefix(run.Version, version.DevVersion) {
		// Two stamped releases with the same name are the same release.
		return 0, true
	}
	return 0, false
}

// BehindPhrase renders Behind for a sentence: "132 builds behind this hub",
// "level with this hub", or "not comparable with this hub". what names the
// reference ("this hub", "this cloop").
func BehindPhrase(run, ref Build, what string) string {
	n, ok := Behind(run, ref)
	switch {
	case !ok:
		return "not comparable with " + what + " (" + ref.Short() + ")"
	case n == 1:
		return "1 build behind " + what
	case n > 1:
		return fmt.Sprintf("%d builds behind %s", n, what)
	case run.Sequence > ref.Sequence && ref.Sequence > 0:
		return fmt.Sprintf("%d builds ahead of %s", run.Sequence-ref.Sequence, what)
	default:
		return "level with " + what
	}
}
