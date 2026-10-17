package container

// isolationprobe.go runs pkg/isolationprobe's probe under this executor's OCI
// runtime, so the isolation its name claims is checked against what the kernel
// serving the sandbox says about itself (Task 20439).
//
// The probe binary is the running process's own — the hub's for a container
// executor on the hub, the agent's on a device — bound into the sandbox
// read-only at a path no image has. An image supplies the root filesystem the
// sandbox starts in and nothing else: the probe opens none of its files, so an
// image cannot ship a probe that answers what it likes. A dynamically linked
// binary (a hub built with cgo, as a development build is) brings the host's
// own loader and libraries with it the same way, so the probe runs in an image
// with no C library at all.
//
// The run is a workload like any other — the same argv builder, the same
// confinement, the runtime under test — with no network, no environment and a
// throwaway working directory, as SmokeTest's is.

import (
	"context"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// probeDir is where the probe's files appear inside the sandbox.
const probeDir = "/.cloop-isolation-probe"

// isolationProbeTimeout bounds one probe: a Kata VM's boot, a gVisor
// sandbox's start and the probe itself, with room for a slow host.
const isolationProbeTimeout = 2 * time.Minute

// libraryDirs are where a dynamically linked binary's libraries are looked
// for, in the order the common loaders search them.
var libraryDirs = []string{
	"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
	"/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
	"/lib64", "/usr/lib64", "/lib", "/usr/lib",
}

// ProbeOptions shapes one isolation probe.
type ProbeOptions struct {
	// Source names who reads the host's own kernel for the comparison: the
	// hub, for its container executor, or a device's agent.
	Source isolationprobe.ReferenceSource
	// StageDir is where the throwaway working directory is made. It must be
	// visible to the engine at the same path — a device's agent runs with a
	// private /tmp. Empty uses the executor's own StageDir, then the system's
	// temporary directory.
	StageDir string
}

// IsolationRuntime implements executor.IsolationClaimer: the OCI runtime this
// executor hands its containers to, empty for the engine's default.
func (e *Executor) IsolationRuntime() (string, bool) { return e.opts.OCIRuntime, true }

// ProbeIsolation implements executor.IsolationProber for a container executor
// on the hub, whose host kernel is the hub's own.
func (e *Executor) ProbeIsolation(ctx context.Context) (executor.IsolationProbe, error) {
	return e.RunIsolationProbe(ctx, ProbeOptions{Source: isolationprobe.SourceHub})
}

// RunIsolationProbe runs `cloop isolation-probe` once in a sandbox under this
// executor's runtime and returns what it saw, with the host's own kernel and
// the kernel the engine reports for itself to compare it with.
func (e *Executor) RunIsolationProbe(ctx context.Context, po ProbeOptions) (executor.IsolationProbe, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, isolationProbeTimeout)
	defer cancel()

	out := executor.IsolationProbe{Runtime: e.opts.OCIRuntime, Image: e.opts.Image, Engine: e.rt.Name}

	base := strings.TrimSpace(po.StageDir)
	if base == "" {
		base = strings.TrimSpace(e.opts.StageDir)
	}
	workDir, cleanup, err := throwawayWorkDir(base, "cloop-isolation-probe-*")
	if err != nil {
		return out, err
	}
	defer cleanup()

	self, err := selfBinaryPath()
	if err != nil {
		return out, fmt.Errorf("container: find this process's own binary to bind into the probe's "+
			"sandbox: %w", err)
	}
	mounts, argv := probeLaunch(self)

	spec := executor.Spec{
		WorkDir: workDir,
		Argv:    argv,
		Labels:  map[string]string{"component": "isolation-probe"},
		// No environment, no network — the probe reads kernel interfaces and
		// needs neither — stated as an empty rule set for the reason SmokeTest
		// gives: it fits inside any firewall an admin set for this executor.
		DisableNetwork: true,
		EgressRules:    &executor.FirewallRules{},
	}
	res, err := e.runOnce(ctx, spec, mounts)
	if err != nil {
		return out, fmt.Errorf("container: start the isolation probe under %s: %w", runtimeName(e.opts.OCIRuntime), err)
	}
	switch {
	case res.TimedOut:
		return out, fmt.Errorf("container: the isolation probe under %s did not finish within %s",
			runtimeName(e.opts.OCIRuntime), isolationProbeTimeout)
	case res.StatusErr != nil:
		return out, fmt.Errorf("container: read the isolation probe's status: %w", res.StatusErr)
	}
	ev, decodeErr := isolationprobe.Decode([]byte(res.Output))
	if decodeErr != nil {
		return out, fmt.Errorf("container: the isolation probe under %s (state %s, exit %d) returned no "+
			"evidence: %w", runtimeName(e.opts.OCIRuntime), res.Status.State, res.Status.ExitCode, decodeErr)
	}

	host := isolationprobe.Collect()
	out.Evidence = ev
	out.Reference = isolationprobe.Reference{
		Kernel:       &host,
		Source:       po.Source,
		EngineKernel: e.engineKernel(ctx),
	}
	return out, nil
}

// runtimeName names an OCI runtime for a message.
func runtimeName(oci string) string {
	if strings.TrimSpace(oci) == "" {
		return "the engine's default runtime"
	}
	return fmt.Sprintf("runtime %q", oci)
}

// probeLaunch returns the mounts that put the binary at self into the sandbox
// and the argv that runs it in probe mode.
//
// A static binary is bound alone. A dynamically linked one is run through the
// host's own loader with the host's own libraries, bound beside it, because
// the image's — if it has any — need not be the ones the binary was linked
// against, and the probe must not depend on what the image ships.
func probeLaunch(self string) ([]mount, []string) {
	bin := probeDir + "/cloop"
	mounts := []mount{{HostPath: self, TargetPath: bin, ReadOnly: true}}
	direct := []string{bin, isolationprobe.Arg}

	interp, libs, err := dynamicDeps(self)
	if err != nil || interp == "" {
		return mounts, direct
	}
	loader := probeDir + "/ld.so"
	extra := []mount{{HostPath: interp, TargetPath: loader, ReadOnly: true}}
	for _, lib := range libs {
		path := findLibrary(lib)
		if path == "" {
			// A library the host cannot name: leave the binary to the image's
			// own loader, which is the best that is left.
			return mounts, direct
		}
		extra = append(extra, mount{HostPath: path, TargetPath: probeDir + "/lib/" + lib, ReadOnly: true})
	}
	return append(mounts, extra...), []string{loader, "--library-path", probeDir + "/lib", bin, isolationprobe.Arg}
}

// dynamicDeps returns an ELF binary's interpreter, resolved, and the
// libraries it needs. A static binary has neither.
func dynamicDeps(path string) (interp string, libs []string, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		b := make([]byte, p.Filesz)
		if _, err := p.ReadAt(b, 0); err != nil {
			return "", nil, fmt.Errorf("read the interpreter of %s: %w", path, err)
		}
		interp = strings.TrimRight(string(b), "\x00")
	}
	if interp == "" {
		return "", nil, nil
	}
	if resolved, err := filepath.EvalSymlinks(interp); err == nil {
		interp = resolved
	}
	libs, err = f.ImportedLibraries()
	if err != nil {
		return "", nil, fmt.Errorf("read the libraries %s needs: %w", path, err)
	}
	for _, l := range libs {
		// A name that is not a plain file name cannot be a mount target here.
		if l == "" || strings.ContainsAny(l, "/:,") {
			return "", nil, fmt.Errorf("unexpected library name %q in %s", l, path)
		}
	}
	return interp, libs, nil
}

// findLibrary returns the resolved path of a library the host's loader would
// find under one of libraryDirs, or "".
func findLibrary(name string) string {
	for _, dir := range libraryDirs {
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return resolved
		}
		return p
	}
	return ""
}

// engineKernel asks the engine which kernel release its own machine runs, so
// Classify can tell a local engine from one on another machine. Empty when the
// engine will not say.
func (e *Executor) engineKernel(ctx context.Context) string {
	format := "{{.KernelVersion}}"
	if e.rt.Name == RuntimePodman {
		format = "{{.Host.Kernel}}"
	}
	res, err := runCLITimeout(ctx, e.rt, preflightCmdTimeout, "info", "--format", format)
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	return strings.TrimSpace(firstLine(res.Stdout))
}

// onceResult is how a workload run to completion ended.
type onceResult struct {
	HandleID  string
	Output    string
	Status    executor.Status
	StatusErr error
	TimedOut  bool
	Duration  time.Duration
}

// runOnce starts spec with the extra mounts, collects its output until it
// exits or ctx ends, and reads its final status. A workload still running when
// ctx ends is killed.
func (e *Executor) runOnce(ctx context.Context, spec executor.Spec, extra []mount) (onceResult, error) {
	started := time.Now()
	handle, err := e.start(ctx, spec, extra)
	if err != nil {
		return onceResult{}, err
	}
	res := onceResult{HandleID: handle.ID}

	lines, err := e.Stream(ctx, handle.ID)
	if err != nil {
		_ = e.Signal(context.WithoutCancel(ctx), handle.ID, executor.SignalKill)
		return res, fmt.Errorf("stream output: %w", err)
	}
	var sb strings.Builder
collect:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break collect
			}
			sb.WriteString(line.Text)
		case <-ctx.Done():
			res.TimedOut = true
			_ = e.Signal(context.WithoutCancel(ctx), handle.ID, executor.SignalKill)
			break collect
		}
	}
	res.Output = strings.TrimSpace(sb.String())
	res.Duration = time.Since(started)

	statusCtx, statusCancel := context.WithTimeout(context.WithoutCancel(ctx), shortCmdTimeout)
	defer statusCancel()
	res.Status, res.StatusErr = e.Status(statusCtx, handle.ID)
	return res, nil
}

// throwawayWorkDir makes a directory under base (the system's temporary
// directory when empty) that a sandbox can be started in and nothing is kept
// in, and the function that removes it.
//
// The sandbox runs as a non-root UID: the directory is widened for it, and
// handed to an unprivileged owner when the caller is root, because a rootful
// run takes its sandbox UID from the directory's owner and the driver refuses
// uid 0 (Executor.sandboxUser).
func throwawayWorkDir(base, pattern string) (string, func(), error) {
	if base != "" {
		if err := os.MkdirAll(base, 0o755); err != nil {
			return "", nil, fmt.Errorf("container: create %s: %w", base, err)
		}
	}
	dir, err := os.MkdirTemp(base, pattern)
	if err != nil {
		return "", nil, fmt.Errorf("container: create a throwaway workdir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o777); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("container: prepare a throwaway workdir: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, smokeTestUID, smokeTestGID); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("container: hand the throwaway workdir to uid %d: %w", smokeTestUID, err)
		}
	}
	return dir, cleanup, nil
}
