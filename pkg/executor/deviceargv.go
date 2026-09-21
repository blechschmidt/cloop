package executor

// deviceargv.go translates a workload's *program* for an executor that does
// not resolve the control plane's filesystem paths.
//
// It is the argv half of the problem DeviceWorkDir solves for the working
// directory, and it went unnoticed for the same reason: on a hub installed as
// /usr/local/bin/cloop every path the control plane names happens to be a path
// the far side also has, so shipping argv[0] verbatim works by coincidence.
// Rename the hub's binary — a blue/green deploy to /usr/local/bin/cloop-latest
// is enough — and every dispatch to a container, a Pod or an edge device fails
// at exec with
//
//	localprocess: start "/usr/local/bin/cloop-latest": fork/exec
//	/usr/local/bin/cloop-latest: no such file or directory
//
// which names a file the operator never asked anyone to run, on a machine they
// were not thinking about.
//
// # Why a bare name
//
// The control plane cannot know where cloop lives on the far side, and it must
// not guess: an edge device installs from the release tarball into
// /usr/local/bin, a sandbox image puts it wherever its Dockerfile did, and a
// Pod runs whatever image the project configured. All three already resolve a
// bare program name against their own PATH — the kubernetes driver says so
// explicitly at cloopCommand, which exists for precisely this reason and
// describes what it does as "exactly what happens to the harness container
// when a Spec's argv[0] is bare". Nothing ever made one bare, so that branch
// was dead.
//
// A basename would be the obvious alternative and is wrong: the whole failure
// above is a hub whose binary is called something the far side has never heard
// of, and filepath.Base would faithfully carry that name across. What travels
// has to be the *identity* of the program, not its local spelling, and by
// construction argv[0] here is the control plane's own cloop binary — every
// dispatch builds it from the hub's os.Executable (pkg/ui selfExe,
// pkg/apiserver startRun).

import (
	"path/filepath"
	"strings"
)

// HarnessProgram is the name cloop is installed under everywhere the control
// plane cannot see. The release tarball, the published sandbox image and the
// agent installer all put it on PATH under this name.
const HarnessProgram = "cloop"

// DeviceArgv rewrites spec.Argv so its program can be found on ex.
//
// # Why IsolatesFromHost decides it
//
// It is the same question pkg/ui already asks two lines from the call site,
// to decide whether a workload may inherit the hub's own process environment:
// a hub path is meaningful to a workload exactly when that workload runs on
// the hub, and an environment full of them is no more portable than an argv
// full of them.
//
// The neighbouring SharesHostFilesystem would be the wrong gate, by exactly
// one driver. It answers "can host-side tooling read what the workload wrote",
// which the container driver answers yes to because the project directory
// really is a bind mount of a host path — and that same driver still cannot
// exec a binary belonging to the hub, because everything outside the mounts it
// was given is the image's filesystem. Gating on it would leave containers
// broken, which is where this defect was first measured: AuditRunArgv put the
// hub's own binary path after the image name.
//
// A no-op on an unisolated executor, where the absolute path is the better
// answer: it pins the exact binary the hub is running rather than whichever
// one PATH happens to find, which matters on a host carrying more than one
// version — the same host, note, that produced this bug by carrying two.
//
// Idempotent, and a no-op on an argv that is already relative: a caller that
// applies it twice, or that passed a bare name to begin with, gets the same
// spec back.
func DeviceArgv(spec *Spec, ex Executor) {
	if spec == nil || len(spec.Argv) == 0 || !IsolatesFromHost(ex) {
		return
	}
	if prog := strings.TrimSpace(spec.Argv[0]); prog == "" || !filepath.IsAbs(prog) {
		return
	}
	// Copied rather than assigned through: callers build argv once and keep
	// the slice for their own logging and labels, and a driver is entitled to
	// retain the Spec it was handed. Mutating the shared backing array would
	// rewrite argv[0] underneath both.
	argv := append([]string(nil), spec.Argv...)
	argv[0] = HarnessProgram
	spec.Argv = argv
}
