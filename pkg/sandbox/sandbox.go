// Package sandbox parses and validates .cloop/sandbox.yaml, a repo-committed
// description of the environment one project's tasks should execute in.
//
// # Why this file exists
//
// executors.container.image is a single hub-wide reference. On a laptop that is
// exactly right; on a hub hosting several teams it means every project shares
// one toolchain, and a repo that needs a different runtime cannot be executed in
// isolation at all without an operator editing the hub's own config. That makes
// the hub a bottleneck for a decision that belongs to the repo, and it is a hard
// blocker for multi-tenant hosting.
//
// So the spec lives in the repo, next to the code whose toolchain it describes,
// and the operator keeps control of the envelope rather than the contents.
//
// # Trust
//
// This file is untrusted input. It arrives via `git pull`; anyone who can open a
// pull request can propose one, and on a hub the person who merges it is not the
// person whose infrastructure runs it. Every rule here follows from that:
//
//   - the schema is closed (yaml.KnownFields) — an unknown key is a typo or a
//     probe for a field a future version might honour, and both deserve an error
//     rather than silence;
//   - every numeric field is clamped through the same bounds pkg/config applies
//     to the hub's own executor config, so a repo cannot request 4096 cores;
//   - env carries *names*, never values — a spec can ask for a secret the
//     project was already granted, and cannot smuggle one in;
//   - mounts are workspace-relative with no ".." (see executor.SpecMount);
//   - capabilities can only ever *narrow* what the executor already permits.
//     There is no field that turns the network on. `network:` names an egress
//     grant that must already exist for the project, and its absence turns the
//     network off. A spec that asks for more than the deployment offers is
//     refused at placement time, never quietly granted.
//
// The last point is the one worth restating: this package can make a run more
// confined than the operator's default, and can never make it less.
package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
)

// FileName is the spec's path relative to a project directory.
const FileName = ".cloop/sandbox.yaml"

// maxFileBytes bounds how much of the file is read. A sandbox spec is a few
// dozen lines; anything approaching this is not one, and an unbounded read of a
// repo-supplied file is a memory-exhaustion primitive.
const maxFileBytes = 64 << 10

// Bounds on the collection fields. They exist for the same reason as
// executor.MaxSpecMounts: past these sizes the file has stopped describing an
// environment, and each extra entry is another line of a generated Dockerfile
// or another variable forwarded into a sandbox.
const (
	MaxSetupCommands = 32
	MaxSetupCmdLen   = 4096
	MaxEnvNames      = 64
)

// ErrNotFound is returned by Load when the project has no sandbox spec. It is a
// sentinel rather than a nil-spec-and-nil-error because "this project has no
// spec" and "this project has an empty spec" mean different things: the first
// uses the hub's image, the second is a spec that failed to say anything.
var ErrNotFound = errors.New("sandbox: no .cloop/sandbox.yaml")

// ErrInvalidSpec wraps every parse and validation failure, so a caller can tell
// "the repo's file is wrong" (the author fixes it, HTTP 400) from "the file is
// fine but this deployment cannot honour it" (an operator fixes it, HTTP 409)
// without matching on message text.
var ErrInvalidSpec = errors.New("sandbox: invalid spec")

// Spec is the parsed sandbox description.
//
// Field names match the YAML keys exactly. The struct is the schema: with
// KnownFields set on the decoder there is nowhere else a valid key can be
// declared, so reading this type is reading the file format.
type Spec struct {
	// Image is the container image the project's tasks run in. Empty means
	// the executor's configured image.
	Image string `yaml:"image"`
	// Setup are shell commands baked into a derived image once per unique
	// (image, setup) pair — not re-run per task. Requires an executor that
	// can build (see executor.Capabilities.SupportsSandboxBuild).
	Setup []string `yaml:"setup"`
	// Env is an allowlist of environment variable *names* to forward into the
	// sandbox. Values are never written here; they come from the project's
	// existing secret grants, and a name the project was not granted forwards
	// nothing.
	Env []string `yaml:"env"`
	// Resources bounds one task's share of the executor.
	Resources Resources `yaml:"resources"`
	// Capabilities are the confinement waivers the project asks for.
	Capabilities Capabilities `yaml:"capabilities"`
	// Mounts re-expose sub-paths of the workspace elsewhere in the sandbox.
	Mounts []Mount `yaml:"mounts"`
}

// Resources is the per-task resource request.
type Resources struct {
	// CPU is a core allowance (1.5 = one and a half cores); 0 = executor default.
	CPU float64 `yaml:"cpu"`
	// Memory is a size string ("512m", "2g"); empty = executor default.
	Memory string `yaml:"memory"`
	// PIDs caps processes/threads; 0 = executor default.
	PIDs int `yaml:"pids"`
	// Disk is a size string bounding the workspace and scratch space; empty =
	// executor default.
	//
	// It is the one resource key that also bounds something the project does
	// not control: the size of the tree an executor fetches for it. A git
	// workspace is provisioned from a remote repository whose contents the
	// executor learns only by downloading them, so the limit reaches both the
	// volume's own sizeLimit and the provisioner's post-fetch check — see
	// Resolved.ApplyTo.
	Disk string `yaml:"disk"`
}

// Capabilities are the confinement waivers a project may request.
//
// Every field is a request that placement must be able to satisfy honestly,
// which is why `network` is a grant name rather than a bool: a bool would mean
// "please turn the network on", and there is no answer to that a repo-committed
// file is entitled to receive.
type Capabilities struct {
	// Git asserts the sandbox needs a working git. It becomes a placement
	// requirement, so a node that advertises its tooling and does not list git
	// is not chosen.
	Git bool `yaml:"git"`
	// Network names an egress grant (pkg/egressbroker) that must already exist
	// for this project and be active. Empty forces the workload off the network
	// entirely, whatever the executor's default is.
	Network string `yaml:"network"`
}

// Mount is the YAML shape of executor.SpecMount.
type Mount struct {
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"read_only"`
}

// Load reads and validates the spec for a project.
//
// It returns ErrNotFound when the project has none, which every caller treats
// as "use the executor's defaults" rather than as a failure. Any other error
// means a spec exists and is wrong, and that must not degrade to defaults: a
// project that asked for a rust toolchain and got the hub's generic image would
// fail in a way that looks like its own bug.
func Load(projectDir string) (*Spec, []string, error) {
	path := filepath.Join(projectDir, filepath.FromSlash(FileName))
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil, ErrNotFound
	case err != nil:
		return nil, nil, fmt.Errorf("sandbox: stat %s: %w", path, err)
	case info.IsDir():
		return nil, nil, fmt.Errorf("sandbox: %s is a directory", path)
	case info.Size() > maxFileBytes:
		return nil, nil, fmt.Errorf("sandbox: %s is %d bytes, at most %d are read",
			path, info.Size(), maxFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("sandbox: read %s: %w", path, err)
	}
	spec, warnings, err := Parse(data)
	if err != nil {
		return nil, warnings, fmt.Errorf("%s: %w", FileName, err)
	}
	return spec, warnings, nil
}

// Parse decodes and validates a spec from YAML.
//
// The returned warnings describe values that were clamped rather than rejected.
// Clamping is the right answer for a number that is merely out of range (the
// author wanted "lots of memory"; giving them the ceiling honours that) and the
// wrong answer for a value that is malformed or dangerous, which is an error.
// Callers surface warnings; they never have to act on them.
func Parse(data []byte) (*Spec, []string, error) {
	spec, warnings, err := parse(data)
	if err != nil {
		// Wrapped once, here, rather than at each of the two dozen returns
		// below. One boundary means a new validation rule cannot forget to
		// carry the sentinel and end up rendered as a 500.
		return nil, warnings, fmt.Errorf("%w: %w", ErrInvalidSpec, err)
	}
	return spec, warnings, nil
}

func parse(data []byte) (*Spec, []string, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	// A closed schema. Without this, `resource:` (singular) silently parses as
	// nothing and the project runs unbounded while its author believes it is
	// capped.
	dec.KnownFields(true)

	var spec Spec
	if err := dec.Decode(&spec); err != nil {
		// io.EOF is an empty document. Treat it as an empty spec rather than a
		// parse failure: a file containing only comments is a legitimate
		// placeholder, and it asks for nothing.
		if errors.Is(err, io.EOF) {
			return &Spec{}, nil, nil
		}
		return nil, nil, fmt.Errorf("parse: %w", err)
	}
	// A second document would be silently ignored by the single Decode above,
	// and "the part after --- did nothing" is a confusing way to learn that.
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, nil, errors.New("parse: the file contains more than one YAML document")
	}

	warnings, err := spec.normalize()
	if err != nil {
		return nil, warnings, err
	}
	return &spec, warnings, nil
}

// normalize trims, validates and clamps in place, returning clamp warnings.
func (s *Spec) normalize() ([]string, error) {
	var warnings []string

	// --- image ----------------------------------------------------------
	s.Image = strings.TrimSpace(s.Image)
	if s.Image != "" {
		// The container driver's validator is the authority on what a runtime
		// will accept — it is what guards the argv this reference is rendered
		// into. Reusing it means the file cannot describe an image that passes
		// here and is rejected two layers down with a worse message.
		if err := container.ValidateImageRef(s.Image); err != nil {
			return warnings, fmt.Errorf("image: %w", err)
		}
	}

	// --- setup ----------------------------------------------------------
	if len(s.Setup) > MaxSetupCommands {
		return warnings, fmt.Errorf("setup: %d commands, at most %d are allowed",
			len(s.Setup), MaxSetupCommands)
	}
	setup := make([]string, 0, len(s.Setup))
	for i, cmd := range s.Setup {
		cmd = strings.TrimSpace(cmd)
		switch {
		case cmd == "":
			return warnings, fmt.Errorf("setup[%d]: command is blank", i)
		case len(cmd) > MaxSetupCmdLen:
			return warnings, fmt.Errorf("setup[%d]: command is %d bytes, at most %d are allowed",
				i, len(cmd), MaxSetupCmdLen)
		case strings.ContainsAny(cmd, "\n\r"):
			// Each command becomes one RUN line in a generated Dockerfile. An
			// embedded newline would end that instruction and begin one the
			// operator never reviewed.
			return warnings, fmt.Errorf("setup[%d]: command spans multiple lines; "+
				"join it with && or move it into a script in the repo", i)
		case strings.ContainsRune(cmd, 0):
			return warnings, fmt.Errorf("setup[%d]: command contains a NUL byte", i)
		}
		setup = append(setup, cmd)
	}
	s.Setup = setup

	// --- env ------------------------------------------------------------
	if len(s.Env) > MaxEnvNames {
		return warnings, fmt.Errorf("env: %d names, at most %d are allowed", len(s.Env), MaxEnvNames)
	}
	seenEnv := make(map[string]struct{}, len(s.Env))
	names := make([]string, 0, len(s.Env))
	for i, name := range s.Env {
		name = strings.TrimSpace(name)
		if err := validateEnvName(name); err != nil {
			return warnings, fmt.Errorf("env[%d]: %w", i, err)
		}
		if _, dup := seenEnv[name]; dup {
			continue
		}
		seenEnv[name] = struct{}{}
		names = append(names, name)
	}
	s.Env = names

	// --- resources ------------------------------------------------------
	resWarnings, err := s.Resources.normalize()
	if err != nil {
		return warnings, err
	}
	warnings = append(warnings, resWarnings...)

	// --- capabilities ---------------------------------------------------
	s.Capabilities.Network = strings.TrimSpace(s.Capabilities.Network)
	if n := s.Capabilities.Network; n != "" {
		if err := validateGrantName(n); err != nil {
			return warnings, fmt.Errorf("capabilities.network: %w", err)
		}
	}

	// --- mounts ---------------------------------------------------------
	for i := range s.Mounts {
		s.Mounts[i].Source = strings.TrimSpace(s.Mounts[i].Source)
		s.Mounts[i].Target = strings.TrimSpace(s.Mounts[i].Target)
	}
	if err := executor.ValidateSpecMounts(s.SpecMounts()); err != nil {
		return warnings, fmt.Errorf("mounts: %w", err)
	}
	return warnings, nil
}

// normalize clamps the resource request to the bounds pkg/config already
// enforces on the hub's own executor config.
//
// Reusing those constants rather than picking new ones is deliberate: the
// ceiling on what a project may ask for and the ceiling on what an operator may
// configure are the same physical limit, and two copies of it would drift into
// a repo being able to request more than the hub can be configured to give.
func (r *Resources) normalize() ([]string, error) {
	var warnings []string

	switch {
	case r.CPU < 0:
		return warnings, fmt.Errorf("resources.cpu must be >= 0, got %v", r.CPU)
	case r.CPU > config.ContainerCPUsUpper:
		warnings = append(warnings, fmt.Sprintf(
			"resources.cpu %v exceeds the maximum of %v and was clamped", r.CPU, config.ContainerCPUsUpper))
		r.CPU = config.ContainerCPUsUpper
	}

	r.Memory = strings.TrimSpace(r.Memory)
	if r.Memory != "" {
		mb, clamped, err := config.ClampMemoryMB(r.Memory)
		if err != nil {
			return warnings, fmt.Errorf("resources.memory: %w", err)
		}
		if clamped {
			warnings = append(warnings, fmt.Sprintf(
				"resources.memory %q exceeds the maximum of %d MB and was clamped",
				r.Memory, config.ContainerMemoryMBUpper))
			// Rewritten to the clamped value so the spec that is hashed,
			// applied and recorded is the one that actually ran. Leaving the
			// original would make the artifact claim a limit the sandbox never
			// had.
			r.Memory = fmt.Sprintf("%dm", mb)
		}
		if mb > 0 && mb < config.ContainerMemoryMBLower {
			// Below the floor is not a preference, it is a sandbox that OOMs
			// before the harness finishes starting. Clamping *up* would give
			// the project more than it asked for, which is the direction this
			// package never moves in, so it is an error.
			return warnings, fmt.Errorf("resources.memory %q is below the minimum of %d MB",
				r.Memory, config.ContainerMemoryMBLower)
		}
	}

	r.Disk = strings.TrimSpace(r.Disk)
	if r.Disk != "" {
		mb, clamped, err := config.ClampDiskMB(r.Disk)
		if err != nil {
			return warnings, fmt.Errorf("resources.disk: %w", err)
		}
		if clamped {
			warnings = append(warnings, fmt.Sprintf(
				"resources.disk %q exceeds the maximum of %d MB and was clamped",
				r.Disk, config.ContainerDiskMBUpper))
			// Rewritten to the clamped value for the same reason memory is: the
			// spec that is hashed, applied and recorded has to be the one that
			// actually ran, or the artifact claims a limit the sandbox never had.
			r.Disk = fmt.Sprintf("%dm", mb)
		}
		if mb > 0 && mb < config.ContainerDiskMBLower {
			// An error rather than a clamp, because clamping *up* would hand the
			// project more than it asked for — the direction this package never
			// moves in. Below the floor there is no room for a checkout plus the
			// harness's own scratch, so the run would fail on the fetch with a
			// message about the repository rather than about the limit.
			return warnings, fmt.Errorf("resources.disk %q is below the minimum of %d MB",
				r.Disk, config.ContainerDiskMBLower)
		}
	}

	switch {
	case r.PIDs < 0:
		// -1 means "unlimited" in the runtimes, and a repo-committed file is
		// not where that decision belongs. The executor's own config still can.
		return warnings, fmt.Errorf("resources.pids must be >= 0, got %d "+
			"(a project spec cannot waive the process cap)", r.PIDs)
	case r.PIDs > 0 && r.PIDs < config.ContainerPIDsLower:
		r.PIDs = config.ContainerPIDsLower
	case r.PIDs > config.ContainerPIDsUpper:
		warnings = append(warnings, fmt.Sprintf(
			"resources.pids %d exceeds the maximum of %d and was clamped", r.PIDs, config.ContainerPIDsUpper))
		r.PIDs = config.ContainerPIDsUpper
	}
	return warnings, nil
}

// SpecMounts converts the YAML mounts to the executor's mount type.
func (s *Spec) SpecMounts() []executor.SpecMount {
	if s == nil || len(s.Mounts) == 0 {
		return nil
	}
	out := make([]executor.SpecMount, 0, len(s.Mounts))
	for _, m := range s.Mounts {
		out = append(out, executor.SpecMount{Source: m.Source, Target: m.Target, ReadOnly: m.ReadOnly})
	}
	return out
}

// IsZero reports whether the spec asks for nothing at all, in which case
// applying it is a no-op and the executor's defaults stand.
func (s *Spec) IsZero() bool {
	if s == nil {
		return true
	}
	return s.Image == "" && len(s.Setup) == 0 && len(s.Env) == 0 &&
		len(s.Mounts) == 0 && s.Resources == (Resources{}) && s.Capabilities == (Capabilities{})
}

// validateEnvName enforces the POSIX-ish shape both container runtimes and the
// kubelet accept. A name that fails here would be dropped or mangled somewhere
// downstream, and a silently-dropped secret name is an authentication failure
// inside the sandbox that looks nothing like its cause.
func validateEnvName(name string) error {
	if name == "" {
		return errors.New("environment variable name is empty")
	}
	if len(name) > 256 {
		return fmt.Errorf("environment variable name is %d bytes, at most 256 are allowed", len(name))
	}
	for i, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return fmt.Errorf("environment variable name %q is not [A-Za-z_][A-Za-z0-9_]*", name)
		}
	}
	return nil
}

// validateGrantName bounds the egress grant reference. It is looked up, not
// executed, but it also lands in log lines and audit records, so control
// characters and unbounded length are refused here rather than downstream.
func validateGrantName(name string) error {
	if len(name) > 128 {
		return fmt.Errorf("grant name is %d bytes, at most 128 are allowed", len(name))
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return fmt.Errorf("grant name %q contains %q; use [A-Za-z0-9-_.:]", name, r)
		}
	}
	return nil
}
