// Package install turns an enrollment bundle into a running, restart-on-boot,
// hardened cloop executor agent on an edge device.
//
// Enrollment (Task 20158) ends where the real work begins. It hands the
// operator a `cloop executor agent --server … --token …` string and stops
// there, so every device costs the same manual sequence: get the binary onto
// the box, decide which user runs it, keep the token out of the shell history
// and out of `ps`, arrange for a restart after a power cut, and put the logs
// somewhere. Done by hand on the tenth device, at least one of those steps is
// done differently — and the one that gets skipped is usually the credential's
// file mode.
//
// So this package makes the whole shape a single artifact. The important
// properties are structural rather than clever:
//
//   - The enrollment token never appears in ExecStart. It is written to a
//     0600 file that only the service user can read, and the command line
//     carries a path. Anyone on the device can read a unit file, and
//     `systemctl show` and `ps` will both print an argv; neither may be a
//     place where a credential is legible. See credentialsArtifact.
//   - The service runs as a dedicated non-login user with an empty capability
//     bounding set, a read-only filesystem, and no ability to gain privilege.
//     A harness that a compromised control plane persuades to run `sudo` finds
//     nothing there to escalate into.
//   - The SPKI pin from Task 20166 is baked into the unit, so a device that
//     reboots keeps verifying the hub's identity rather than falling back to
//     whatever DNS says on the day.
//
// Rendering is separated from applying on purpose: BuildPlan is pure, so
// --dry-run is the same code path as a real install minus the writes, and the
// generated unit can be tested without a systemd on the machine running the
// tests.
package install

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// Output selects which supervision system the plan targets.
type Output string

const (
	// OutputSystemd emits a hardened .service unit. The default, because it
	// is what an edge device running a mainstream Linux already has.
	OutputSystemd Output = "systemd"
	// OutputDocker emits a `podman run` command and an equivalent compose
	// fragment, for a device whose only supervision is a container engine.
	OutputDocker Output = "docker"
	// OutputShell emits a POSIX init script, for BusyBox/OpenRC devices and
	// anything else without systemd.
	OutputShell Output = "shell"
)

// ParseOutput validates an --output value.
func ParseOutput(s string) (Output, error) {
	switch Output(strings.ToLower(strings.TrimSpace(s))) {
	case "", OutputSystemd:
		return OutputSystemd, nil
	case OutputDocker:
		return OutputDocker, nil
	case OutputShell:
		return OutputShell, nil
	}
	return "", fmt.Errorf("install: unknown --output %q (want systemd, docker or shell)", s)
}

// Defaults for an install that the operator did not otherwise specify. They
// are deliberately conventional: an operator debugging a device at 3am should
// find the unit and the state where the FHS says they will be.
const (
	DefaultServiceName = "cloop-executor"
	DefaultUser        = "cloop-executor"
	DefaultBinaryPath  = "/usr/local/bin/cloop"
	DefaultStateRoot   = "/var/lib"
	DefaultUnitDir     = "/etc/systemd/system"
	DefaultInitDir     = "/etc/init.d"
	DefaultImage       = "ghcr.io/blechschmidt/cloop:latest"

	// CredentialFileMode is the mode of the file holding enrollment
	// material. It is the single most important number in this package:
	// everything else is defence in depth around the fact that this file is
	// a bearer credential.
	CredentialFileMode os.FileMode = 0o600

	// StateDirMode keeps the credential's directory unreadable to other
	// local users, so a 0600 file cannot be reached by a directory listing
	// plus a race on a later re-write.
	StateDirMode os.FileMode = 0o700

	// SystemDirMode is for shared system directories (/etc/systemd/system,
	// /etc/init.d). They hold no secret and every other service on the box
	// traverses them, so creating one at StateDirMode would break far more
	// than it protected.
	SystemDirMode os.FileMode = 0o755

	// UnitFileMode is world-readable on purpose: systemd reads it as root,
	// operators read it to debug, and it contains no secrets — which is the
	// invariant credentialsArtifact exists to preserve.
	UnitFileMode os.FileMode = 0o644

	// ScriptFileMode is for the generated init script, which must be
	// executable by root and readable for debugging.
	ScriptFileMode os.FileMode = 0o755
)

// Spec describes the installation to materialise.
//
// Every field has a usable default; Normalize fills them and rejects the
// combinations that cannot produce a working service.
type Spec struct {
	// ServiceName names the unit, the container, the init script, the
	// system user's home and the state directory. One name so an operator
	// greps for one string.
	ServiceName string

	// User and Group own the credential file and run the process. Empty
	// defaults to ServiceName.
	User  string
	Group string

	// BinaryPath is the cloop binary on the device.
	BinaryPath string

	// StateDir holds the credential file, the agent's long-lived identity,
	// and (by default) the workload root. Empty defaults to
	// /var/lib/<ServiceName>.
	StateDir string

	// UnitDir is where the systemd unit is written. Empty defaults to
	// /etc/systemd/system.
	UnitDir string

	// CredentialsFile is the 0600 file the enrollment material is written
	// to. Empty defaults to <StateDir>/enrollment.
	//
	// There is deliberately no way to put the token on the command line
	// instead: a flag that inlines a credential into ExecStart is a flag
	// that will be used, and the resulting unit is world-readable.
	CredentialsFile string

	// AgentCredential is where the agent persists the long-lived identity
	// it receives in exchange for the enrollment token. Empty defaults to
	// <StateDir>/agent.json.
	AgentCredential string

	// WorkDirRoot confines every workload on the device. Empty defaults to
	// <StateDir>/work.
	WorkDirRoot string

	// Server is the control-plane WebSocket URL the agent dials.
	Server string

	// Pin is the hub's SPKI fingerprint ("sha256:<base64>", comma-separated
	// to stage a key rotation). Empty means ordinary PKI verification, which
	// is a real downgrade — see remote.Bundle.
	Pin string

	// Bundle is the encoded enrollment bundle (server + token + pin in one
	// blob). Either this or Token must be set for a first install; both are
	// empty when re-installing over an agent that already holds a
	// credential.
	Bundle string

	// Token is a bare enrollment token, for an operator who has one without
	// a bundle.
	Token string

	// RootCAFile is a PEM bundle to trust in addition to the system store,
	// for a hub behind a private CA.
	RootCAFile string

	// MaxConcurrent bounds simultaneous workloads. Zero lets the agent
	// choose (number of CPUs).
	MaxConcurrent int

	// Labels are scheduler selectors baked into the unit.
	Labels map[string]string

	// Image is the container image for OutputDocker.
	Image string

	// NoStart installs the unit without enabling or starting it, for
	// golden-image builds where the device must not enroll until first boot.
	NoStart bool
}

// hasCredentialMaterial reports whether this install carries something to
// redeem. A re-install over a device that already holds an agent credential
// legitimately has neither.
func (s Spec) hasCredentialMaterial() bool {
	return strings.TrimSpace(s.Bundle) != "" || strings.TrimSpace(s.Token) != ""
}

// credentialContent is what gets written to CredentialsFile.
//
// A bundle is preferred over a bare token because it carries the server URL
// and the pin with it, so the three cannot drift apart on the device.
func (s Spec) credentialContent() string {
	if b := strings.TrimSpace(s.Bundle); b != "" {
		return b + "\n"
	}
	return strings.TrimSpace(s.Token) + "\n"
}

// Normalize fills defaults and rejects a spec that cannot yield a working
// service. It returns a copy: callers keep their input intact so an error
// message can quote what was actually asked for.
func (s Spec) Normalize() (Spec, error) { return s.normalize(true) }

// NormalizeForRemoval fills the same defaults but does not insist on a
// control-plane URL.
//
// Uninstalling is not the inverse of installing in its inputs: it needs only
// the paths, and an operator removing a device does not necessarily still have
// the bundle it was enrolled with — often the reason they are removing it is
// that the hub is gone. Demanding --server to delete a file would be exactly
// the friction this command exists to remove.
func (s Spec) NormalizeForRemoval() (Spec, error) { return s.normalize(false) }

func (s Spec) normalize(requireServer bool) (Spec, error) {
	out := s

	out.ServiceName = strings.TrimSpace(out.ServiceName)
	if out.ServiceName == "" {
		out.ServiceName = DefaultServiceName
	}
	if err := validateServiceName(out.ServiceName); err != nil {
		return Spec{}, err
	}

	if strings.TrimSpace(out.User) == "" {
		out.User = out.ServiceName
	}
	if strings.TrimSpace(out.Group) == "" {
		out.Group = out.User
	}
	if err := validateUnixName("--user", out.User); err != nil {
		return Spec{}, err
	}
	if err := validateUnixName("--group", out.Group); err != nil {
		return Spec{}, err
	}

	if strings.TrimSpace(out.BinaryPath) == "" {
		out.BinaryPath = DefaultBinaryPath
	}
	if strings.TrimSpace(out.StateDir) == "" {
		out.StateDir = filepath.Join(DefaultStateRoot, out.ServiceName)
	}
	if strings.TrimSpace(out.UnitDir) == "" {
		out.UnitDir = DefaultUnitDir
	}
	if strings.TrimSpace(out.CredentialsFile) == "" {
		out.CredentialsFile = filepath.Join(out.StateDir, "enrollment")
	}
	if strings.TrimSpace(out.AgentCredential) == "" {
		out.AgentCredential = filepath.Join(out.StateDir, "agent.json")
	}
	if strings.TrimSpace(out.WorkDirRoot) == "" {
		out.WorkDirRoot = filepath.Join(out.StateDir, "work")
	}
	if strings.TrimSpace(out.Image) == "" {
		out.Image = DefaultImage
	}

	// Absolute paths only. A relative path in a unit file resolves against
	// systemd's working directory, not the operator's, so it would silently
	// point somewhere other than where it was typed.
	for _, p := range []struct{ flag, val string }{
		{"--binary", out.BinaryPath},
		{"--state-dir", out.StateDir},
		{"--unit-dir", out.UnitDir},
		{"--credentials-file", out.CredentialsFile},
		{"--workdir-root", out.WorkDirRoot},
	} {
		if !filepath.IsAbs(p.val) {
			return Spec{}, fmt.Errorf("install: %s must be an absolute path on the device, got %q", p.flag, p.val)
		}
	}
	if ca := strings.TrimSpace(out.RootCAFile); ca != "" && !filepath.IsAbs(ca) {
		return Spec{}, fmt.Errorf("install: --ca-file must be an absolute path on the device, got %q", ca)
	}

	// A bundle carries the server and the pin, so unpack it before deciding
	// whether either is missing. Explicit flags win: an operator staging a
	// key rotation overrides the pin without re-minting the bundle.
	if b := strings.TrimSpace(out.Bundle); b != "" {
		decoded, err := remote.DecodeBundle(b)
		if err != nil {
			return Spec{}, fmt.Errorf("install: %w", err)
		}
		if strings.TrimSpace(out.Server) == "" {
			out.Server = decoded.Server
		}
		if strings.TrimSpace(out.Pin) == "" {
			out.Pin = decoded.Pin
		}
	}
	out.Server = strings.TrimSpace(out.Server)
	out.Pin = strings.TrimSpace(out.Pin)
	out.Token = strings.TrimSpace(out.Token)
	out.Bundle = strings.TrimSpace(out.Bundle)

	if requireServer && out.Server == "" {
		return Spec{}, fmt.Errorf(
			"install: no control-plane URL — pass --bundle from `cloop executor enroll`, or --server explicitly")
	}
	if out.MaxConcurrent < 0 {
		return Spec{}, fmt.Errorf("install: --max-concurrent must not be negative, got %d", out.MaxConcurrent)
	}
	for k := range out.Labels {
		if strings.TrimSpace(k) == "" {
			return Spec{}, fmt.Errorf("install: a label key may not be empty")
		}
	}
	return out, nil
}

// UnitFileName is the systemd unit's basename.
func (s Spec) UnitFileName() string { return s.ServiceName + ".service" }

// UnitPath is the absolute path the unit is written to.
func (s Spec) UnitPath() string { return filepath.Join(s.UnitDir, s.UnitFileName()) }

// InitScriptPath is where OutputShell writes its script.
func (s Spec) InitScriptPath() string { return filepath.Join(DefaultInitDir, s.ServiceName) }

// agentArgs builds the agent's argv, minus the binary itself.
//
// The credential is present only as a path. That is the invariant the whole
// package is arranged around, and it is asserted directly by
// TestSystemdUnitNeverCarriesTheTokenInExecStart.
func (s Spec) agentArgs() []string {
	args := []string{"executor", "agent",
		"--server", s.Server,
		"--credential", s.AgentCredential,
		"--workdir-root", s.WorkDirRoot,
	}
	if s.hasCredentialMaterial() {
		args = append(args, "--token-file", s.CredentialsFile)
	}
	if s.Pin != "" {
		args = append(args, "--pin", s.Pin)
	}
	if ca := strings.TrimSpace(s.RootCAFile); ca != "" {
		args = append(args, "--ca-file", ca)
	}
	if s.MaxConcurrent > 0 {
		args = append(args, "--max-concurrent", strconv.Itoa(s.MaxConcurrent))
	}
	for _, k := range sortedKeys(s.Labels) {
		args = append(args, "--label", k+"="+s.Labels[k])
	}
	return args
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Artifact is one file the installer writes.
type Artifact struct {
	// Path is absolute on the device (before any Installer.Root prefix).
	Path string
	// Mode is the file's permission bits.
	Mode os.FileMode
	// Content is the file body.
	Content string
	// Secret marks content that must never be logged, printed by --dry-run,
	// or written world-readable.
	Secret bool
	// Owned marks a file that should be chowned to the service user.
	Owned bool
}

// Dir is a directory the install must exist, with the mode it must carry.
//
// The mode is per-directory rather than one constant because these fall into
// two classes with opposite requirements: a state directory holding a
// credential must be 0700, while /etc/systemd/system must stay traversable by
// everything on the box. Creating the latter at 0700 — which a single
// MkdirAll(…, 0700) over a missing path would do — breaks unrelated services.
type Dir struct {
	Path string
	Mode os.FileMode
}

// Plan is everything an install would do, computed without touching anything.
type Plan struct {
	Output Output
	Spec   Spec

	// Dirs are created before Artifacts are written.
	Dirs []Dir

	// Artifacts are the files to write.
	Artifacts []Artifact

	// Display is the operator-facing rendering for --dry-run. It never
	// contains credential material.
	Display string

	// Next lists the follow-up steps Apply performs (or that the operator
	// must perform when the plan targets a system this machine is not).
	Next []string
}

// BuildPlan renders everything an install needs, without writing anything.
func BuildPlan(spec Spec, out Output) (Plan, error) {
	s, err := spec.Normalize()
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Output: out, Spec: s}

	// The credential file comes first in every output: it must exist before
	// the service that reads it is started, and writing it first means a
	// failure part-way through leaves a device that is not running rather
	// than one running without an identity.
	if s.hasCredentialMaterial() {
		p.Dirs = append(p.Dirs, Dir{filepath.Dir(s.CredentialsFile), StateDirMode})
		p.Artifacts = append(p.Artifacts, credentialsArtifact(s))
	}

	switch out {
	case OutputSystemd:
		unit := SystemdUnit(s)
		p.Dirs = append(p.Dirs,
			Dir{s.StateDir, StateDirMode},
			Dir{s.WorkDirRoot, StateDirMode},
			Dir{s.UnitDir, SystemDirMode})
		p.Artifacts = append(p.Artifacts, Artifact{
			Path: s.UnitPath(), Mode: UnitFileMode, Content: unit,
		})
		p.Display = unit
		p.Next = []string{
			"systemctl daemon-reload",
		}
		if !s.NoStart {
			p.Next = append(p.Next, "systemctl enable --now "+s.UnitFileName())
		} else {
			p.Next = append(p.Next, "systemctl enable "+s.UnitFileName()+"  (not started: --no-start)")
		}
	case OutputShell:
		script := InitScript(s)
		p.Dirs = append(p.Dirs,
			Dir{s.StateDir, StateDirMode},
			Dir{s.WorkDirRoot, StateDirMode},
			Dir{DefaultInitDir, SystemDirMode})
		p.Artifacts = append(p.Artifacts, Artifact{
			Path: s.InitScriptPath(), Mode: ScriptFileMode, Content: script,
		})
		p.Display = script
		if !s.NoStart {
			p.Next = []string{s.InitScriptPath() + " start"}
		}
	case OutputDocker:
		// The container case writes only the credential file: the operator
		// runs the engine, and materialising a compose file into an
		// arbitrary directory would be guessing where their stack lives.
		p.Dirs = append(p.Dirs, Dir{filepath.Dir(s.CredentialsFile), StateDirMode})
		p.Display = ContainerFragment(s)
		p.Next = []string{"run the printed `podman run` command, or add the compose fragment to your stack"}
	default:
		return Plan{}, fmt.Errorf("install: unknown output %q", out)
	}
	return p, nil
}

// credentialsArtifact is the only file in any plan that holds a credential.
func credentialsArtifact(s Spec) Artifact {
	return Artifact{
		Path:    s.CredentialsFile,
		Mode:    CredentialFileMode,
		Content: s.credentialContent(),
		Secret:  true,
		Owned:   true,
	}
}

// validateServiceName rejects anything that would not round-trip through a
// unit name, a container name and a path component.
func validateServiceName(name string) error {
	if len(name) > 64 {
		return fmt.Errorf("install: --service-name %q is too long (max 64)", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf(
				"install: --service-name %q may contain only letters, digits, '-', '_' and '.'", name)
		}
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("install: --service-name %q may not start with '.'", name)
	}
	return nil
}

// validateUnixName rejects a user or group name that could inject a directive
// into the generated unit or an argument into the generated shell script.
func validateUnixName(flag, name string) error {
	if len(name) > 32 {
		return fmt.Errorf("install: %s %q is too long (max 32)", flag, name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return fmt.Errorf(
				"install: %s %q may contain only lowercase letters, digits, '-' and '_'", flag, name)
		}
	}
	return nil
}

// lookupServiceUser resolves the numeric ids the credential file must be
// owned by. It returns ok=false when the user does not exist yet, which is
// the normal state before Apply creates it.
func lookupServiceUser(name string) (uid, gid int, ok bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, false
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, false
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, false
	}
	return uid, gid, true
}
