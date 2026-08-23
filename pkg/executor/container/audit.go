package container

// Audit seam for the security conformance suite (tests/security).
//
// The confinement flags this driver emits — --cap-drop=ALL, --read-only, a
// non-root --user, no host networking, no docker.sock — are the entire
// difference between "sandbox" and "a second way to run as the control
// plane". They are produced deep inside Start, behind runtime detection that
// needs Docker or Podman actually installed, which is exactly the kind of
// precondition that makes a security property go untested on CI and stay
// untested until it regresses.
//
// AuditRunArgv exposes the real argv construction with the runtime dependency
// removed. It is deliberately not a reimplementation: it calls the same
// buildRequest and buildRunArgs that Start calls, so a flag that stops being
// emitted in production stops being emitted here too. A test-only copy of the
// argv logic would pass forever while production drifted.

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// AuditRuntime describes the runtime to build argv for, without probing the
// host. Rootless selects podman's keep-id UID mapping; rootful takes the
// explicit --user path.
type AuditRuntime struct {
	Name     string
	Rootless bool
}

// AuditRunArgv returns the exact command line the container executor would
// hand to the runtime for spec in workDir.
//
// workDir must exist: the driver stats it to derive the UID mapping, and a
// fabricated path would silently take a different branch than production.
func AuditRunArgv(opts Options, rt AuditRuntime, workDir string, spec executor.Spec) ([]string, error) {
	norm, err := opts.Normalize()
	if err != nil {
		return nil, fmt.Errorf("normalize options: %w", err)
	}
	name := rt.Name
	if name == "" {
		name = RuntimeDocker
	}
	e := &Executor{
		id:      norm.ID,
		opts:    norm,
		rt:      Runtime{Name: name, Path: "/usr/bin/" + name, Rootless: rt.Rootless},
		handles: map[string]*record{},
	}
	resolved, err := e.resolveWorkDir(workDir)
	if err != nil {
		return nil, err
	}
	req, err := e.buildRequest(spec, resolved, nil)
	if err != nil {
		return nil, err
	}
	built, err := buildRunArgs(req)
	if err != nil {
		return nil, err
	}
	return built.Args, nil
}

// AuditSecretStaging stages spec.SecretFiles the way Start does and returns
// the resulting command line together with the host directories the credentials
// were written into.
//
// It exists because the property worth asserting is not "the driver has a
// function that writes files" but "the bytes a lease produced end up somewhere
// the sandbox can read and nowhere else" — the mode they are created with, the
// directory's mode, and the :ro on the bind that carries them. All three are
// decided inside Start, past a runtime the conformance suite cannot assume is
// installed, so without this seam the delivery that Task 20192 exists to build
// would be exactly as untested as the drop it replaced.
//
// The caller must invoke cleanup, which wipes the staged credentials. A test
// that skips it leaves plaintext in /dev/shm.
func AuditSecretStaging(opts Options, rt AuditRuntime, workDir string, spec executor.Spec) (argv []string, dirs []string, cleanup func(), err error) {
	norm, oerr := opts.Normalize()
	if oerr != nil {
		return nil, nil, func() {}, fmt.Errorf("normalize options: %w", oerr)
	}
	name := rt.Name
	if name == "" {
		name = RuntimeDocker
	}
	e := &Executor{
		id:      norm.ID,
		opts:    norm,
		rt:      Runtime{Name: name, Path: "/usr/bin/" + name, Rootless: rt.Rootless},
		handles: map[string]*record{},
	}
	resolved, rerr := e.resolveWorkDir(workDir)
	if rerr != nil {
		return nil, nil, func() {}, rerr
	}
	// The same two calls Start makes, in the same order and with the same
	// sandbox user — a staging that chose a different UID here would prove
	// nothing about the one production creates.
	stage, serr := stageSecretFiles(spec, e.sandboxUser(resolved))
	if serr != nil {
		return nil, nil, func() {}, serr
	}
	cleanup = stage.remove
	req, berr := e.buildRequest(spec, resolved, stage.mountList())
	if berr != nil {
		cleanup()
		return nil, nil, func() {}, berr
	}
	built, aerr := buildRunArgs(req)
	if aerr != nil {
		cleanup()
		return nil, nil, func() {}, aerr
	}
	if stage != nil {
		dirs = append(dirs, stage.dirs...)
	}
	return built.Args, dirs, cleanup, nil
}

// AuditBuildNetwork returns the network a derived-image build would run with
// for spec.
//
// It is exposed for the same reason AuditRunArgv is. `setup:` executes
// repo-authored commands, so the build's network posture is a security
// boundary — a build with unconditional egress would let a pull request reach
// the Internet from a deployment configured to forbid it. That posture is
// decided inside ensureDerivedImage, behind a real image store and a real
// builder, and a property only reachable on a machine with podman installed is
// a property CI does not check.
func AuditBuildNetwork(opts Options, spec executor.Spec) (string, error) {
	norm, err := opts.Normalize()
	if err != nil {
		return "", fmt.Errorf("normalize options: %w", err)
	}
	e := &Executor{id: norm.ID, opts: norm, handles: map[string]*record{}}
	return e.buildNetwork(spec), nil
}
