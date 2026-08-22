package container

// image.go owns the sandbox image contract and the preflight that tells an
// operator, in one command, why a container executor will not work yet.
//
// Preflight exists because every failure mode here is environmental and
// opaque at run time. "exec: podman: not found", "No such image", and a
// permission-denied on a bind mount all surface as a container that dies
// instantly with no output, and an operator staring at an empty log panel has
// no way to tell them apart. Preflight names the cause and the fix.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// DefaultImage is the reference used when executors.container.image is unset.
//
// The image is a contract, not just a base OS. A sandbox image must provide:
//
//   - the cloop binary at /usr/local/bin/cloop (the harness re-invokes cloop
//     subcommands from inside the sandbox);
//   - whichever agent harness the project's provider needs (for the default
//     claudecode provider, the `claude` CLI on PATH);
//   - git, plus a CA bundle, since almost every task shells out to one or
//     the other;
//   - a non-root user, because the driver runs as the project directory's
//     owner UID and that UID must be able to resolve inside the container.
//
// It deliberately does *not* bake in credentials: provider API keys and
// scoped secrets are injected as environment at start (see buildRunArgs), so
// the same image is safe to share across tenants and to publish.
//
// Until a published image exists this reference will not resolve, which is
// the correct failure: Preflight reports "image not present" with the pull
// command rather than silently falling back to something unaudited. Operators
// running an image of their own set executors.container.image.
const DefaultImage = "ghcr.io/blechschmidt/cloop-harness:latest"

// ContainerCloopPath is where the cloop binary is expected inside the
// sandbox, and where the smoke test bind-mounts the control plane's own
// binary so `cloop executor test` works against any base image.
const ContainerCloopPath = "/usr/local/bin/cloop"

// Preflight check levels.
const (
	// LevelOK: the check passed.
	LevelOK = "ok"
	// LevelWarn: usable, but with a caveat the operator should know about.
	LevelWarn = "warn"
	// LevelFail: workloads will not run until this is fixed.
	LevelFail = "fail"
)

// Finding is one preflight observation.
type Finding struct {
	// Name identifies the check, e.g. "runtime", "image", "workdir".
	Name string `json:"name"`
	// Level is one of LevelOK, LevelWarn, LevelFail.
	Level string `json:"level"`
	// Message states what was observed.
	Message string `json:"message"`
	// Fix is the concrete remedy, empty when Level is LevelOK.
	Fix string `json:"fix,omitempty"`
}

// PreflightReport is the result of checking an executor's environment.
type PreflightReport struct {
	ExecutorID string    `json:"executor_id"`
	Runtime    string    `json:"runtime"`
	Image      string    `json:"image"`
	WorkDir    string    `json:"work_dir,omitempty"`
	Findings   []Finding `json:"findings"`
}

// OK reports whether nothing fatal was found.
func (r PreflightReport) OK() bool {
	for _, f := range r.Findings {
		if f.Level == LevelFail {
			return false
		}
	}
	return true
}

// Err returns an error summarising the fatal findings, or nil when none.
func (r PreflightReport) Err() error {
	var msgs []string
	for _, f := range r.Findings {
		if f.Level != LevelFail {
			continue
		}
		m := f.Name + ": " + f.Message
		if f.Fix != "" {
			m += " (fix: " + f.Fix + ")"
		}
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 {
		return nil
	}
	return fmt.Errorf("container preflight failed — %s", strings.Join(msgs, "; "))
}

// preflightCmdTimeout bounds each runtime CLI probe. A wedged docker daemon
// makes `docker info` hang indefinitely; preflight must still return.
const preflightCmdTimeout = 20 * time.Second

// Preflight verifies that this executor can actually run a workload in
// workDir. Passing an empty workDir skips the filesystem checks and reports
// only on the runtime and image.
//
// It never returns an error for a *failed check* — those are findings.
// Callers use report.Err() when they want a single error, and the findings
// themselves when they want to show a checklist.
func (e *Executor) Preflight(ctx context.Context, workDir string) PreflightReport {
	if ctx == nil {
		ctx = context.Background()
	}
	report := PreflightReport{
		ExecutorID: e.id,
		Runtime:    e.rt.String(),
		Image:      e.opts.Image,
		WorkDir:    workDir,
	}
	add := func(name, level, msg, fix string) {
		report.Findings = append(report.Findings, Finding{Name: name, Level: level, Message: msg, Fix: fix})
	}

	// --- 1. runtime binary --------------------------------------------
	verRes, err := runCLITimeout(ctx, e.rt, preflightCmdTimeout, "version", "--format", "{{.Client.Version}}")
	switch {
	case err != nil:
		add("runtime", LevelFail,
			fmt.Sprintf("cannot execute %s (%v)", e.rt.Path, err),
			"install podman (preferred) or docker, or set executors.container.runtime")
		// Everything downstream needs a working binary; stop here.
		return report
	case verRes.ExitCode != 0:
		add("runtime", LevelFail,
			fmt.Sprintf("%s version failed: %s", e.rt.Name, firstLine(verRes.Stderr)),
			"verify the runtime installation")
		return report
	default:
		add("runtime", LevelOK,
			fmt.Sprintf("%s %s at %s", e.rt.Name, strings.TrimSpace(verRes.Stdout), e.rt.Path), "")
	}

	// --- 2. runtime is actually usable --------------------------------
	// Docker's client works fine with a dead daemon; only `info` round-trips
	// to it. Podman has no daemon but `info` still surfaces a broken storage
	// or cgroup configuration.
	//
	// Deliberately unformatted: the two runtimes expose completely different
	// info schemas ({{.Host.Arch}} on podman, {{.Architecture}} on docker),
	// so any --format string fails on one of them — and a template error
	// reads exactly like an unreachable daemon. Only the exit status is
	// needed here, and that is portable.
	infoRes, err := runCLITimeout(ctx, e.rt, preflightCmdTimeout, "info")
	switch {
	case err != nil:
		add("daemon", LevelFail,
			fmt.Sprintf("%s info did not complete: %v", e.rt.Name, err),
			daemonFix(e.rt))
	case infoRes.ExitCode != 0:
		add("daemon", LevelFail,
			fmt.Sprintf("%s info failed: %s", e.rt.Name, firstLine(infoRes.Stderr)),
			daemonFix(e.rt))
	default:
		add("daemon", LevelOK, fmt.Sprintf("%s is responding", e.rt.Name), "")
	}

	// --- 3. rootless posture -------------------------------------------
	if e.rt.Rootless {
		add("rootless", LevelOK, "rootless podman: workloads run in a user namespace owned by an unprivileged host user", "")
	} else if os.Geteuid() == 0 {
		add("rootless", LevelWarn,
			"the control plane runs as root, so containers are created by a root-owned runtime",
			"run the control plane as an unprivileged user with podman for a second isolation layer")
	}

	// --- 3b. OCI runtime ------------------------------------------------
	// Only when one is configured: a deployment on the CLI's default runtime
	// has nothing here to get wrong, and adding an always-OK finding to every
	// report would bury the ones that matter.
	if e.opts.OCIRuntime != "" {
		e.preflightOCIRuntime(ctx, add)
	}

	// --- 4. image ------------------------------------------------------
	imgRes, err := runCLITimeout(ctx, e.rt, preflightCmdTimeout, "image", "inspect", e.opts.Image)
	switch {
	case err != nil:
		add("image", LevelFail,
			fmt.Sprintf("could not inspect image %s: %v", e.opts.Image, err),
			fmt.Sprintf("%s pull %s", e.rt.Name, e.opts.Image))
	case imgRes.ExitCode != 0:
		add("image", LevelFail,
			fmt.Sprintf("image %s is not present locally", e.opts.Image),
			fmt.Sprintf("%s pull %s  (the driver never pulls implicitly, so a cold start cannot hang)",
				e.rt.Name, e.opts.Image))
	default:
		add("image", LevelOK, fmt.Sprintf("image %s is present", e.opts.Image), "")
	}

	// --- 5. SELinux ----------------------------------------------------
	if selinuxEnforcing() {
		if e.opts.SELinuxLabel == "" {
			add("selinux", LevelFail,
				"SELinux is enforcing and no relabel option is configured, so the bind-mounted "+
					"project directory will be unreadable inside the container",
				"set executors.container.selinux_label: z  (shared relabel; use Z for an exclusive one)")
		} else {
			add("selinux", LevelOK,
				fmt.Sprintf("SELinux is enforcing; mounts are relabelled with :%s", e.opts.SELinuxLabel), "")
		}
	} else if e.opts.SELinuxLabel != "" {
		add("selinux", LevelWarn,
			fmt.Sprintf("selinux_label %q is set but SELinux is not enforcing on this host", e.opts.SELinuxLabel),
			"remove executors.container.selinux_label unless this config is shared with an SELinux host")
	}

	// --- 6. network posture --------------------------------------------
	if e.opts.Network == NetworkNone {
		add("network", LevelOK, "network is disabled (--network=none)", "")
	} else {
		add("network", LevelWarn,
			fmt.Sprintf("network %q gives the workload outbound access; cloop does not filter egress itself", e.opts.Network),
			"attach an operator-managed network with an egress policy, or set executors.container.network: none")
	}

	// --- 7. workspace ---------------------------------------------------
	if workDir != "" {
		e.preflightWorkDir(workDir, add)
	}

	return report
}

// preflightOCIRuntime checks the two things a Kata sandbox needs that a runc
// one does not: the runtime has to be registered with the CLI that resolves
// `--runtime`, and the host has to be able to start a VM.
//
// Both fail late and obscurely otherwise. An unregistered name surfaces as
// docker's "unknown or invalid runtime name" on the operator's first task; a
// missing /dev/kvm surfaces as a qemu error in the container's stderr, minutes
// into a run, with nothing pointing at nested virtualization. Preflight is
// where an operator is already looking, so both are answered there.
func (e *Executor) preflightOCIRuntime(ctx context.Context, add func(name, level, msg, fix string)) {
	name := e.opts.OCIRuntime

	// Registration. registeredOCIRuntimes reports ok=false when the CLI
	// cannot be enumerated (podman), and an unenumerable runtime must not be
	// called absent — that would fail a working deployment at startup.
	if registered, ok := registeredOCIRuntimes(ctx, e.rt); ok {
		if registered[name] {
			add("oci-runtime", LevelOK,
				fmt.Sprintf("%s is registered with %s", name, e.rt.Name), "")
		} else {
			known := make([]string, 0, len(registered))
			for r := range registered {
				known = append(known, r)
			}
			sort.Strings(known)
			add("oci-runtime", LevelFail,
				fmt.Sprintf("%s does not know a runtime named %q (it has: %s)",
					e.rt.Name, name, strings.Join(known, ", ")),
				ociRuntimeFix(e.rt, name))
		}
	} else {
		add("oci-runtime", LevelWarn,
			fmt.Sprintf("cannot enumerate %s's runtimes, so %q is unverified until the first run",
				e.rt.Name, name),
			ociRuntimeFix(e.rt, name))
	}

	// Virtualization. Only asked of a runtime that needs it: crun and runsc
	// have no use for /dev/kvm and reporting on it would be noise.
	if !IsVirtualizedOCIRuntime(name) {
		return
	}
	switch st := checkKVM(); {
	case st.Usable:
		add("kvm", LevelOK,
			fmt.Sprintf("%s is usable; %s workloads run in a VM with their own kernel", KVMDevice, name), "")
	default:
		add("kvm", LevelFail,
			fmt.Sprintf("%s is not usable (%v), so %s cannot start a VM", KVMDevice, st.Err, name),
			kvmFix(st))
	}
}

// preflightWorkDir checks that the project directory can be bind-mounted and
// written to by the UID the workload will run as.
func (e *Executor) preflightWorkDir(workDir string, add func(name, level, msg, fix string)) {
	abs, err := filepath.Abs(workDir)
	if err != nil {
		add("workdir", LevelFail, fmt.Sprintf("cannot resolve %q: %v", workDir, err), "use an absolute project path")
		return
	}
	info, err := os.Stat(abs)
	if err != nil {
		add("workdir", LevelFail, fmt.Sprintf("cannot stat %s: %v", abs, err),
			"create the project directory before binding it to a container executor")
		return
	}
	if !info.IsDir() {
		add("workdir", LevelFail, fmt.Sprintf("%s is not a directory", abs), "")
		return
	}

	owner, ok := fileOwner(info)
	if !ok {
		add("workdir", LevelWarn,
			fmt.Sprintf("cannot determine the owner of %s on this platform", abs),
			"the container will run as the runtime's default user")
		return
	}

	switch {
	case e.rt.Rootless:
		// keep-id maps the invoking user to the same UID inside the
		// container, so the only thing that matters is that the invoking
		// user owns the tree.
		if owner.uid != os.Geteuid() {
			add("workdir", LevelWarn,
				fmt.Sprintf("%s is owned by uid %d but the control plane runs as uid %d; "+
					"rootless podman maps only the invoking user, so writes may fail",
					abs, owner.uid, os.Geteuid()),
				fmt.Sprintf("chown -R %d %s, or run the control plane as uid %d", os.Geteuid(), abs, owner.uid))
		} else {
			add("workdir", LevelOK,
				fmt.Sprintf("%s is owned by the invoking user (uid %d) and maps in via --userns=keep-id", abs, owner.uid), "")
		}
	case owner.uid == 0:
		// The whole point of the driver is that the workload is not root.
		// A root-owned project forces the choice between running as root
		// inside the sandbox or being unable to write; say so plainly.
		add("workdir", LevelWarn,
			fmt.Sprintf("%s is owned by root, so the workload runs as uid 0 inside the sandbox "+
				"(still with no capabilities, no new privileges, and no network by default)", abs),
			fmt.Sprintf("chown -R <unprivileged-uid> %s so the sandbox can drop to a non-root UID", abs))
	default:
		add("workdir", LevelOK,
			fmt.Sprintf("%s is owned by uid %d:%d; the workload runs as that non-root user", abs, owner.uid, owner.gid), "")
	}

	// A directory the target UID cannot write to produces a workload that
	// starts and then fails on its first file write, which reads as a
	// harness bug rather than a mount problem.
	if err := checkWritable(abs); err != nil {
		add("workdir-write", LevelWarn,
			fmt.Sprintf("the control plane cannot write to %s: %v", abs, err),
			"ensure the project directory is writable by the user the sandbox runs as")
	}
}

// daemonFix returns the runtime-appropriate remedy for an unresponsive
// runtime.
func daemonFix(rt Runtime) string {
	if rt.Name == RuntimeDocker {
		return "start the Docker daemon, or add the control-plane user to the docker group"
	}
	return "check `podman info` output; rootless podman needs a configured subuid/subgid range"
}

// ownerIDs is a file's numeric owner.
type ownerIDs struct{ uid, gid int }

// fileOwner extracts the numeric owner from a FileInfo. The second return is
// false on platforms that do not expose it.
func fileOwner(info os.FileInfo) (ownerIDs, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return ownerIDs{}, false
	}
	return ownerIDs{uid: int(st.Uid), gid: int(st.Gid)}, true
}

// checkWritable verifies the directory accepts a new file, by creating and
// removing one. Checking mode bits is not equivalent: read-only mounts, full
// filesystems, and immutable attributes all present as writable modes.
func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".cloop-preflight-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// selinuxEnforcing reports whether the host has SELinux in enforcing mode,
// where an unlabelled bind mount is invisible inside the container.
func selinuxEnforcing() bool {
	data, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}
