package executor

// sandboxmode.go is the answer to a question an operator could not previously
// ask: *on this executor, does a payload run on the host, or in a container on
// that host?*
//
// # Why the question had no answer
//
// Every other driver settles it at construction. localprocess is a host
// process by definition; container.New resolves a runtime binary and fails if
// there is none; the Kubernetes driver only ever makes pods. For those, "which
// mode" is the same question as "which driver", and the driver is chosen from
// the hub's own config.yaml before anything runs.
//
// A remote agent is the one executor where that reasoning does not hold. The
// hub does not choose the driver on an edge device — the device does, and until
// this file existed it chose localprocess unconditionally
// (pkg/executor/agent/agent.go). The consequence was not a missing feature but
// a false claim: the agent detects docker/podman/nerdctl on PATH and reports
// them in AgentCapabilities.ContainerRuntimes, the fleet view renders them as
// chips, and the executor advertises IsolationRemote — while the payload ran
// as a plain host process with the agent's own privileges. An operator reading
// that card had every reason to believe in a boundary that was not there.
//
// So the mode has to be configuration rather than inference, it has to live in
// the control plane where an admin can set it, and — this is the part that
// makes it a security control rather than a preference — an executor that
// cannot honour the configured mode must refuse the work instead of quietly
// falling back to the host. The container driver already states that rule for
// its own construction:
//
//	// A missing runtime is reported as an error rather than swallowed: an
//	// operator who configured a container executor and silently got host
//	// execution would believe they had an isolation boundary they do not have.
//
// This file extends the same rule across the wire.
//
// # Why settings travel per dispatch rather than per connection
//
// The agent holds no copy of this configuration and gets no vote on it. Each
// start frame carries the settings the hub read a moment earlier, so an admin
// who switches an executor from host to container in the UI changes the next
// task — with no agent restart, no reconnect, and no window in which the
// device's idea of its own containment differs from the control plane's.

import (
	"fmt"
	"sort"
	"strings"
)

// SandboxMode says where a payload runs on a given executor.
type SandboxMode string

const (
	// SandboxModeDefault is the zero value: the executor keeps whatever it
	// would have done without this configuration. It exists so that adding
	// the field changed no deployment's behaviour, and so that "unset" is
	// distinguishable from "host" — an admin who never opened the panel has
	// not thereby asserted that host execution is acceptable.
	SandboxModeDefault SandboxMode = ""
	// SandboxModeHost runs the payload directly on the executor's host, with
	// the executor's own privileges and filesystem.
	SandboxModeHost SandboxMode = "host"
	// SandboxModeContainer runs the payload in a container on the executor's
	// host, with the workspace bind-mounted in.
	SandboxModeContainer SandboxMode = "container"
)

// SandboxModes lists the modes an admin may select, in UI order. The default
// is omitted: it is what a record's absence already means, so offering it as a
// choice would be offering "leave this alone" as an action.
func SandboxModes() []SandboxMode {
	return []SandboxMode{SandboxModeHost, SandboxModeContainer}
}

// Valid reports whether m is a mode this build understands.
func (m SandboxMode) Valid() bool {
	switch m {
	case SandboxModeDefault, SandboxModeHost, SandboxModeContainer:
		return true
	}
	return false
}

// Isolates reports whether m puts a boundary between the payload and the
// executor's host.
//
// Note that SandboxModeDefault answers false. That is deliberate and is the
// conservative direction: an unset mode means the executor does whatever it
// did before, which for the one driver that reads this field was host
// execution. A caller asking "is this contained" must not be told yes by a
// value that means "nobody has said".
func (m SandboxMode) Isolates() bool { return m == SandboxModeContainer }

// containerEngines are the container CLIs an executor may be told to drive.
//
// An allowlist for the same reason container.DetectRuntime has one: this value
// arrives from an HTTP request and ends up as the program an executor executes.
// A free-form string here would be a remote-code-execution primitive dressed
// as a configuration field.
//
// nerdctl is listed because the agent's own capability detection looks for it,
// and an engine the fleet view advertises but the settings refuse would be the
// same species of inconsistency this file exists to remove.
var containerEngines = []string{"docker", "podman", "nerdctl"}

// ContainerEngines lists the selectable container engines.
func ContainerEngines() []string {
	out := make([]string, len(containerEngines))
	copy(out, containerEngines)
	return out
}

// ValidContainerEngine reports whether name is a known container engine.
// Empty is valid and means "let the executor detect one".
func ValidContainerEngine(name string) bool {
	if strings.TrimSpace(name) == "" {
		return true
	}
	for _, e := range containerEngines {
		if e == name {
			return true
		}
	}
	return false
}

// MaxRuntimeNameLen bounds an OCI runtime name. Real names are well under 20
// characters; the limit exists so a pathological value cannot produce an
// unreadable error or a surprising argv.
//
// Exported so the container driver's own bound can be defined as this one
// rather than as a second 64 that happens to agree with it today.
const MaxRuntimeNameLen = 64

// ValidateRuntimeName checks that name is a plausible OCI runtime *name*.
//
// Empty is valid and means "the engine's own default" — no --runtime flag is
// emitted at all, which is what every existing deployment gets.
//
// The shape check is permissive on purpose. The set of legitimate names is
// open: an operator may register Kata under any name they like, and clusters
// do (kata, kata-qemu, kata-clh). What the check forbids is the shape that
// would stop the value being a name at all — a leading dash, which the engine
// would parse as another flag, and a path separator, which would turn config
// that names a runtime into config that names an arbitrary binary the engine
// runs as root. A bare name cannot do that: docker resolves it only against
// /etc/docker/daemon.json and podman only against containers.conf, both
// root-owned files an operator already controls, so the name is an indirection
// through a trusted table rather than a target.
//
// This is the canonical definition; container.ValidateOCIRuntime and the
// per-executor settings below both defer to it, so the rule cannot drift
// between the hub's config file and its API.
func ValidateRuntimeName(name string) error {
	n := strings.TrimSpace(name)
	if n == "" {
		return nil
	}
	if len(n) > MaxRuntimeNameLen {
		return fmt.Errorf("runtime name %q is too long (max %d characters)", n, MaxRuntimeNameLen)
	}
	if strings.HasPrefix(n, "-") {
		return fmt.Errorf("runtime name %q may not start with a dash", n)
	}
	if strings.ContainsAny(n, `/\`) {
		return fmt.Errorf(
			"runtime must be a registered runtime name, not a path (got %q) — register the binary "+
				"in /etc/docker/daemon.json (docker) or containers.conf [engine.runtimes] (podman) "+
				"and name it here", n)
	}
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf(
				"runtime name %q contains %q — names may use letters, digits, dot, underscore and dash",
				n, string(r))
		}
	}
	return nil
}

// SandboxSettings is the per-executor sandbox configuration an admin sets.
//
// Every field's zero value means "unset", and an unset field is never an
// assertion — it defers to whatever the executor would otherwise have done.
// That is what lets an admin pin the OCI runtime of one executor without
// thereby choosing an image for it.
type SandboxSettings struct {
	// Mode is where payloads run: on the executor's host, or in a container
	// on it.
	Mode SandboxMode `json:"mode,omitempty"`
	// Engine is the container CLI to drive ("docker", "podman", "nerdctl").
	// Empty lets the executor detect one. Ignored unless Mode is container.
	Engine string `json:"engine,omitempty"`
	// Runtime is the OCI runtime the engine hands each container to — the
	// `--runtime` value. Empty means the engine's default, which is runc or
	// crun. This is the field that decides whether the payload sits behind a
	// hypervisor (kata) or a userspace kernel (runsc); see IsVirtualized.
	Runtime string `json:"runtime,omitempty"`
	// Image is the container image payloads run in. Empty means the
	// executor's own configured default. Ignored unless Mode is container.
	Image string `json:"image,omitempty"`
}

// Provenance — who configured this and when — is deliberately not a field
// above. These settings are marshalled into every start frame, and an edge
// device has no use for the name of the admin who chose its containment. The
// attribution the fleet view shows lives beside the row in the control plane;
// see statedb.ExecutorSandbox.

// IsZero reports whether the settings configure nothing, which is what an
// executor with no record has.
func (s SandboxSettings) IsZero() bool {
	return s.Mode == SandboxModeDefault &&
		strings.TrimSpace(s.Engine) == "" &&
		strings.TrimSpace(s.Runtime) == "" &&
		strings.TrimSpace(s.Image) == ""
}

// Normalize trims whitespace and drops fields that the selected mode makes
// meaningless, so a record cannot claim an engine for host execution.
//
// Dropping rather than rejecting is the right behaviour for a UI that keeps a
// form's fields visible when the mode selector changes: an admin who picks
// container, types a runtime, then switches back to host has not made an
// error, they have changed their mind. What must not happen is the settings
// *retaining* the runtime, because then a later switch back to container would
// silently resurrect a value nobody re-confirmed.
func (s SandboxSettings) Normalize() SandboxSettings {
	out := SandboxSettings{
		Mode:    SandboxMode(strings.TrimSpace(string(s.Mode))),
		Engine:  strings.TrimSpace(s.Engine),
		Runtime: strings.TrimSpace(s.Runtime),
		Image:   strings.TrimSpace(s.Image),
	}
	if out.Mode != SandboxModeContainer {
		out.Engine = ""
		out.Runtime = ""
		out.Image = ""
	}
	return out
}

// Validate reports whether the settings are admissible.
func (s SandboxSettings) Validate() error {
	if !s.Mode.Valid() {
		return fmt.Errorf("sandbox mode %q is not one of %s", s.Mode, joinModes())
	}
	// Checked before the mode gate rather than after, so an admin who filled
	// in a bad engine and then left the mode on host is told their engine is
	// wrong instead of having it silently discarded by Normalize.
	if !ValidContainerEngine(s.Engine) {
		return fmt.Errorf("container engine %q is not one of %s",
			s.Engine, strings.Join(ContainerEngines(), ", "))
	}
	if err := ValidateRuntimeName(s.Runtime); err != nil {
		return err
	}
	if img := strings.TrimSpace(s.Image); img != "" {
		if err := validateImageRef(img); err != nil {
			return err
		}
	}
	return nil
}

// joinModes renders the selectable modes for an error message.
func joinModes() string {
	names := make([]string, 0, len(SandboxModes()))
	for _, m := range SandboxModes() {
		names = append(names, string(m))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// maxImageRefLen bounds an image reference. Real references, digest included,
// fit comfortably; this stops a multi-kilobyte value reaching an argv.
const maxImageRefLen = 512

// validateImageRef checks the shape of an image reference.
//
// Deliberately only the shape. Whether the image is *allowed* is a different
// question with a different answer per hub, and it already has an owner:
// pkg/imagepolicy, which the container driver consults at dispatch with the
// operator's registry allowlist, digest-pinning rule and signature
// requirements. Duplicating a weaker version of that here would create a
// second, more permissive gate on the same decision — and the weaker one
// would be the one an admin's request passed through.
//
// What this does own is the shape that stops a reference being a reference:
// whitespace, which would split into extra argv words, and a leading dash,
// which the engine would read as a flag.
func validateImageRef(ref string) error {
	if len(ref) > maxImageRefLen {
		return fmt.Errorf("image reference is too long (max %d characters)", maxImageRefLen)
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("image reference %q may not start with a dash", ref)
	}
	if strings.ContainsAny(ref, " \t\n\r") {
		return fmt.Errorf("image reference %q may not contain whitespace", ref)
	}
	return nil
}

// IsVirtualized reports whether these settings put payloads behind a
// hypervisor. It is false unless the mode is container: a runtime name is not
// a boundary on its own, and host execution with `runtime: kata` recorded
// against it is contained by nothing.
func (s SandboxSettings) IsVirtualized() bool {
	return s.Mode == SandboxModeContainer && IsVirtualizedRuntime(s.Runtime)
}

// IsKernelIsolated reports whether these settings keep the payload's syscalls
// off the host kernel — Kata's guest kernel or gVisor's userspace one.
func (s SandboxSettings) IsKernelIsolated() bool {
	return s.Mode == SandboxModeContainer && IsKernelIsolatedRuntime(s.Runtime)
}

// Describe renders the settings for a log line or a diagnostic. It names the
// mode even when nothing else is set, because "which mode" is the question
// this type exists to answer and "default" is a real answer to it.
func (s SandboxSettings) Describe() string {
	mode := string(s.Mode)
	if mode == "" {
		mode = "default"
	}
	if s.Mode != SandboxModeContainer {
		return mode
	}
	parts := []string{mode}
	if s.Engine != "" {
		parts = append(parts, "engine="+s.Engine)
	}
	if s.Runtime != "" {
		parts = append(parts, "runtime="+s.Runtime)
	}
	if s.Image != "" {
		parts = append(parts, "image="+s.Image)
	}
	return strings.Join(parts, " ")
}
