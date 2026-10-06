package hubdoctor

// Run builds: which build each `cloop run` on this host executes, against this
// hub's (Task 20389).
//
// A deploy replaces the hub's binary and leaves the runs it started alone, and
// a run in auto-evolve never ends on its own. So a long-lived run keeps
// executing whatever it started with — on 2026-10-06 this repository's own run
// was 132 builds behind the hub that served it, without any of the
// orchestrator fixes of those weeks. Each run records its process and build in
// its project (the run-owner record); this reads that record for every run on
// the host, through a read-only handle, and warns about the ones that lag:
//
//   - a run behind this hub's build, which a host-process run can adopt at its
//     next task boundary (the Overview's "Adopt at next task boundary", or the
//     project's Follow New Builds option);
//   - a run that recorded no build at all, which started on a cloop from
//     before runs reported one and cannot adopt a newer build until it has
//     been restarted once.

import (
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/runbuild"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// hostRun is one `cloop run` process on this host.
type hostRun struct {
	runbuild.Ident
	Dir string
}

// hostRuns lists the `cloop run` processes on this host that share its view
// of the filesystem. A run in a container also shows in /proc, with a working
// directory from its own mount namespace (/workspace); reading that path here
// would read some other directory, or nothing. A variable so tests can stand
// in for /proc.
var hostRuns = func() []hostRun {
	self, _ := os.Readlink("/proc/self/ns/mnt")
	var out []hostRun
	for _, pid := range multiui.AllCloopRunPIDs() {
		p := "/proc/" + strconv.Itoa(pid)
		if ns, err := os.Readlink(p + "/ns/mnt"); err != nil || ns != self {
			continue
		}
		cwd, err := os.Readlink(p + "/cwd")
		if err != nil {
			continue
		}
		id, alive, err := runbuild.IdentOf(pid)
		if err != nil || !alive {
			continue
		}
		out = append(out, hostRun{Ident: id, Dir: cwd})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out
}

// selfRunBuild is the build runs are compared with. A variable so tests can
// pose as a stamped hub.
var selfRunBuild = state.SelfBuild

func checkRunBuilds(add addFn) {
	runs := hostRuns()
	if len(runs) == 0 {
		return
	}
	hub := selfRunBuild()
	for _, r := range runs {
		title := "Build of the run in " + r.Dir
		details := map[string]any{"project": r.Dir, "pid": r.PID, "hub_build": hub}
		owner, err := statedb.PeekRunOwner(state.DBPath(r.Dir))
		if err != nil {
			add(Finding{
				Check: "runs.build_lag", Title: title, Severity: SeverityWarn,
				Message:     fmt.Sprintf("the run (pid %d) could not be compared with this hub: %v", r.PID, err),
				Remediation: "Check that the project's .cloop/state.db is readable",
				Details:     details,
			})
			continue
		}
		// The record must name this very process — pid, start time and
		// boot — not merely a pid that has since been reused.
		if owner == nil || !owner.Ident.Same(r.Ident) {
			add(Finding{
				Check: "runs.build_lag", Title: title, Severity: SeverityWarn,
				Message: fmt.Sprintf("the run (pid %d) has not reported its build: it started on a cloop from "+
					"before runs recorded one, so it cannot be compared with this hub (%s) and cannot adopt a "+
					"newer build", r.PID, hub.Label()),
				Remediation: "Restart the run once (Stop, then Start); from then on it reports its build and can " +
					"adopt newer ones at a task boundary",
				Details: details,
			})
			continue
		}
		details["build"] = owner.Build
		details["executor"] = owner.Executor
		n, ok := runbuild.Behind(owner.Build, hub)
		switch {
		case !ok:
			add(Finding{
				Check: "runs.build_lag", Title: title, Severity: SeverityWarn,
				Message: fmt.Sprintf("the run (pid %d) executes %s, which cannot be ordered against this hub's %s",
					r.PID, owner.Build.Label(), hub.Label()),
				Remediation: "Run hub doctor with the hub's own binary; builds made by scripts/build-release.sh or the " +
					"deploy carry the sequence that orders them",
				Details: details,
			})
		case n > 0:
			details["behind"] = n
			fix := "Press \"Adopt at next task boundary\" on the project's Overview, or switch on Follow New Builds " +
				"there (`cloop run --follow-builds`); the run moves between tasks and keeps its process"
			if !owner.Adoptable {
				fix = fmt.Sprintf("The run is on a %s executor, which keeps its own upgrade path: upgrade the device "+
					"or rebuild the image, then restart the run", owner.Executor)
			}
			add(Finding{
				Check: "runs.build_lag", Title: title, Severity: SeverityWarn,
				Message: fmt.Sprintf("the run (pid %d) executes %s, %s (%s)", r.PID, owner.Build.Label(),
					runbuild.BehindPhrase(owner.Build, hub, "this hub"), hub.Label()),
				Remediation: fix,
				Details:     details,
			})
		default:
			add(Finding{
				Check: "runs.build_lag", Title: title, Severity: SeverityPass,
				Message: fmt.Sprintf("the run (pid %d) executes %s, %s", r.PID, owner.Build.Label(),
					runbuild.BehindPhrase(owner.Build, hub, "this hub")),
				Details: details,
			})
		}
	}
}
