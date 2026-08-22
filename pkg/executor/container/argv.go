package container

// argv.go builds the container runtime command line. It is the security
// boundary of this driver: everything that confines a workload — the user it
// runs as, what it can see of the host filesystem, whether it has a network,
// what capabilities it keeps — is expressed as flags here. A missing flag is
// not a cosmetic bug, it is a hole. That is why this file is pure (no I/O, no
// globals, no clock) and why argv_test.go enumerates its output exhaustively:
// a security property you cannot unit-test is a security property you are
// merely hoping for.
//
// Two rules shape the design:
//
//   - Secret values never enter argv. Environment is forwarded with the bare
//     `--env NAME` form, which makes the runtime CLI read the value from its
//     own environment. Anyone reading /proc/<pid>/cmdline on the host sees
//     the variable's name and nothing else.
//
//   - Operator-supplied extra arguments are validated against a denylist of
//     flags that would dismantle the sandbox, and are constrained to the
//     `--flag=value` form so they cannot introduce a positional argument
//     (which the runtime would read as the image, shifting the real image
//     into the command position).

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ContainerWorkspace is the fixed in-container path the project directory is
// bind-mounted at. Fixed rather than mirroring the host path so that nothing
// inside the sandbox learns the host's directory layout, and so a workload's
// behaviour does not change when the same project is checked out elsewhere.
const ContainerWorkspace = "/workspace"

// Labels applied to every container this driver starts. They are what make
// orphan reaping possible: a control plane that was killed mid-run finds its
// leftovers by label, not by remembering them.
const (
	// LabelManaged marks a container as created by cloop.
	LabelManaged = "cloop.managed"
	// LabelExecutor records which executor instance started it.
	LabelExecutor = "cloop.executor"
	// LabelHandle records the executor handle ID.
	LabelHandle = "cloop.handle"
	// LabelProject records the host project directory.
	LabelProject = "cloop.project"
)

// Network modes.
const (
	// tmpfsScratchMB sizes the writable /tmp handed back to a workload whose
	// rootfs is read-only. It is RAM, so it is capped: an unbounded tmpfs is
	// a memory-exhaustion vector dressed up as a filesystem.
	tmpfsScratchMB = 512

	// NetworkNone fully isolates the workload: no interfaces but loopback.
	NetworkNone = "none"
	// NetworkBridge attaches the runtime's default bridge, giving the
	// workload unrestricted outbound access.
	NetworkBridge = "bridge"
)

// maxExtraArgs bounds operator-supplied runtime flags. A config file is not a
// scripting language; anything approaching this many flags is a mistake or an
// attack, and an unbounded list would let a single config key blow past the
// kernel's argv limit and produce an unreadable failure.
const maxExtraArgs = 32

// mount is one bind mount into the sandbox.
type mount struct {
	// HostPath is the source path on the control-plane host.
	HostPath string
	// TargetPath is where it appears inside the container.
	TargetPath string
	// ReadOnly maps the source read-only.
	ReadOnly bool
	// SELinuxLabel is "", "z" (shared) or "Z" (private). Only meaningful on
	// SELinux hosts, where an unlabelled bind mount is unreadable inside the
	// container.
	SELinuxLabel string
}

// String renders the mount as the runtime's -v argument.
func (m mount) String() string {
	opts := make([]string, 0, 2)
	if m.ReadOnly {
		opts = append(opts, "ro")
	}
	if m.SELinuxLabel != "" {
		opts = append(opts, m.SELinuxLabel)
	}
	s := m.HostPath + ":" + m.TargetPath
	if len(opts) > 0 {
		s += ":" + strings.Join(opts, ",")
	}
	return s
}

// runRequest is the fully-resolved description of one container run. Every
// field is already defaulted and validated by the caller; buildRunArgs only
// renders and re-checks the invariants it can see.
type runRequest struct {
	Runtime Runtime
	Image   string
	Name    string

	// Workspace is the project bind mount. Its TargetPath is always
	// ContainerWorkspace.
	Workspace mount
	// ExtraMounts are additional binds (the smoke test mounts the cloop
	// binary read-only). Never a channel for the project's own data.
	ExtraMounts []mount

	// User is the "uid:gid" the workload runs as, or "" to leave the
	// decision to the runtime (correct only under a user namespace that
	// already maps the host user, i.e. rootless podman with KeepID).
	User string
	// KeepID requests --userns=keep-id, which maps the invoking host user to
	// the same UID inside the container so bind-mounted files keep their
	// ownership. Rootless podman only.
	KeepID bool
	// AllowRoot waives the non-root user check. See Options.AllowRootUser —
	// it exists so a root sandbox is a decision, never a default.
	AllowRoot bool

	// Network is "none", "bridge", or an operator-defined network name.
	Network string
	// AddHosts pins name→address resolution as "host:ip" entries.
	AddHosts []string

	// CPUs is the core allowance (1.5 = one and a half cores); 0 = unset.
	CPUs float64
	// MemoryMB is the RSS ceiling; 0 = unset.
	MemoryMB int
	// PIDsLimit caps processes/threads; 0 = unset, -1 = explicitly unlimited.
	PIDsLimit int

	// EnvNames are the variables to forward by name. Their values must be
	// present in Env and are never rendered into argv.
	EnvNames []string
	// Env is the environment handed to the runtime CLI process itself.
	Env []string

	// Labels are attached to the container for reaping and observability.
	Labels map[string]string

	// ExtraArgs are operator-supplied runtime flags, already validated.
	ExtraArgs []string

	// Argv is the workload command, appended after the image.
	Argv []string

	// Detach runs the container in the background (`run -d`), which is how
	// Start returns a handle without waiting for the workload.
	Detach bool
}

// builtCommand is the rendered command line plus the environment the runtime
// CLI must be given for the `--env NAME` passthrough to resolve.
type builtCommand struct {
	// Args are the runtime CLI arguments, excluding argv[0].
	Args []string
	// Env is the child environment. Never nil when EnvNames is non-empty.
	Env []string
}

// buildRunArgs renders req into a runtime command line.
//
// The ordering is deliberate and load-bearing: every flag precedes the `--`
// separator, the image is the first positional argument, and the workload's
// own argv follows. The separator means an image reference beginning with a
// dash can never be re-interpreted as a flag.
func buildRunArgs(req runRequest) (builtCommand, error) {
	if err := ValidateImageRef(req.Image); err != nil {
		return builtCommand{}, err
	}
	if err := validateContainerName(req.Name); err != nil {
		return builtCommand{}, err
	}
	if len(req.Argv) == 0 {
		return builtCommand{}, fmt.Errorf("container: argv is empty")
	}
	if req.Workspace.HostPath == "" {
		return builtCommand{}, fmt.Errorf("container: workspace host path is empty")
	}
	if req.Workspace.TargetPath != ContainerWorkspace {
		return builtCommand{}, fmt.Errorf("container: workspace must be mounted at %s, got %q",
			ContainerWorkspace, req.Workspace.TargetPath)
	}
	if req.User != "" && req.KeepID {
		// keep-id already selects the UID; combining the two produces a
		// container user with no mapping, and every file operation fails
		// with a confusing EPERM.
		return builtCommand{}, fmt.Errorf("container: --user and --userns=keep-id are mutually exclusive")
	}
	// keep-id maps the invoking (unprivileged) user, so it is non-root by
	// construction. Every other path must name a non-root UID explicitly,
	// unless the operator has deliberately opted into a root sandbox.
	if !req.KeepID && !req.AllowRoot {
		if err := validateNonRootUser(req.User); err != nil {
			return builtCommand{}, err
		}
	}

	args := []string{"run"}
	if req.Detach {
		args = append(args, "--detach")
	}

	// Never pull implicitly. An image fetch can take minutes on a cold cache
	// and would turn Start — which callers expect to be prompt — into an
	// unbounded wait. Preflight checks image presence and tells the operator
	// to pull; here a missing image fails immediately and legibly.
	args = append(args, "--pull=never")

	args = append(args, "--name", req.Name)

	// --- Isolation ---------------------------------------------------
	// Capabilities: drop everything. A harness compiles code and runs
	// tests; it never needs CAP_NET_RAW or CAP_SYS_ADMIN, and keeping the
	// default set is what turns a container escape from hard into routine.
	args = append(args, "--cap-drop=ALL")
	// no-new-privileges makes setuid binaries inside the image unable to
	// elevate, so a stray setuid root helper cannot undo --user.
	args = append(args, "--security-opt=no-new-privileges")

	// Read-only root filesystem. The workspace bind mount and the scratch
	// tmpfs below stay writable; everything the image ships — /usr, /etc,
	// the interpreter on the next run's PATH — becomes immutable. Without
	// this, a workload that is compromised once can persist by rewriting a
	// binary in the image's writable layer, and every later run on the same
	// container starts already owned.
	args = append(args, "--read-only")
	// A read-only rootfs with no scratch space breaks essentially every
	// toolchain: compilers, test binaries and package managers all write to
	// /tmp. Handing it back as a tmpfs keeps those writes in RAM, bounded,
	// and discarded with the container. nosuid and nodev block the standard
	// escalation tricks; exec has to stay, because `go test` writes its test
	// binaries into TMPDIR and then runs them.
	args = append(args, "--tmpfs", fmt.Sprintf("/tmp:rw,nosuid,nodev,exec,size=%dm", tmpfsScratchMB))

	if req.KeepID {
		args = append(args, "--userns=keep-id")
	}
	if req.User != "" {
		args = append(args, "--user", req.User)
	}

	network := strings.TrimSpace(req.Network)
	if network == "" {
		network = NetworkNone
	}
	if err := ValidateNetwork(network); err != nil {
		return builtCommand{}, err
	}
	args = append(args, "--network="+network)

	for _, h := range req.AddHosts {
		if err := validateAddHost(h); err != nil {
			return builtCommand{}, err
		}
		args = append(args, "--add-host", h)
	}

	// --- Resource limits ---------------------------------------------
	if req.CPUs > 0 {
		args = append(args, "--cpus", formatCPUs(req.CPUs))
	}
	if req.MemoryMB > 0 {
		mem := strconv.Itoa(req.MemoryMB) + "m"
		args = append(args, "--memory", mem)
		// Pinning swap to the same value denies swap entirely. Without it a
		// workload simply pages out past its RSS cap and the "limit" bounds
		// nothing that matters.
		args = append(args, "--memory-swap", mem)
	}
	switch {
	case req.PIDsLimit > 0:
		args = append(args, "--pids-limit", strconv.Itoa(req.PIDsLimit))
	case req.PIDsLimit < 0:
		// Explicit opt-out, rendered as the runtimes' "unlimited" sentinel.
		args = append(args, "--pids-limit", "-1")
	}

	// --- Filesystem ---------------------------------------------------
	args = append(args, "--workdir", ContainerWorkspace)
	args = append(args, "--volume", req.Workspace.String())
	for _, m := range req.ExtraMounts {
		if m.HostPath == "" || m.TargetPath == "" {
			return builtCommand{}, fmt.Errorf("container: extra mount %+v has an empty path", m)
		}
		if m.TargetPath == ContainerWorkspace {
			return builtCommand{}, fmt.Errorf("container: extra mount may not shadow %s", ContainerWorkspace)
		}
		args = append(args, "--volume", m.String())
	}

	// --- Labels --------------------------------------------------------
	// Sorted so the command line is deterministic and therefore testable.
	labelKeys := make([]string, 0, len(req.Labels))
	for k := range req.Labels {
		labelKeys = append(labelKeys, k)
	}
	sort.Strings(labelKeys)
	for _, k := range labelKeys {
		if err := validateLabelKey(k); err != nil {
			return builtCommand{}, err
		}
		args = append(args, "--label", k+"="+sanitizeLabelValue(req.Labels[k]))
	}

	// --- Environment ---------------------------------------------------
	// Bare `--env NAME`: the runtime reads the value from its own
	// environment. Values therefore never reach the host process table.
	envIndex := make(map[string]struct{}, len(req.Env))
	for _, kv := range req.Env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			envIndex[kv[:i]] = struct{}{}
		}
	}
	seenEnv := make(map[string]struct{}, len(req.EnvNames))
	for _, name := range req.EnvNames {
		if err := validateEnvName(name); err != nil {
			return builtCommand{}, err
		}
		if _, dup := seenEnv[name]; dup {
			continue
		}
		seenEnv[name] = struct{}{}
		if _, ok := envIndex[name]; !ok {
			// Both runtimes silently omit an unset variable. Silently
			// omitting an API key produces an authentication failure inside
			// the sandbox that looks nothing like its cause, so refuse.
			return builtCommand{}, fmt.Errorf(
				"container: environment variable %q is forwarded but has no value — "+
					"the secret would be silently dropped inside the sandbox", name)
		}
		args = append(args, "--env", name)
	}

	// --- Operator escape hatch ----------------------------------------
	if err := ValidateExtraArgs(req.ExtraArgs); err != nil {
		return builtCommand{}, err
	}
	args = append(args, req.ExtraArgs...)

	// --- Image and workload -------------------------------------------
	args = append(args, "--", req.Image)
	args = append(args, req.Argv...)

	return builtCommand{Args: args, Env: req.Env}, nil
}

// formatCPUs renders a core allowance without trailing zeros, so 1.0 becomes
// "1" and 0.5 stays "0.5". Both runtimes accept either, but a stable
// rendering keeps the command line diffable in logs and tests.
func formatCPUs(c float64) string {
	s := strconv.FormatFloat(c, 'f', 3, 64)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// deniedExtraArgs maps a flag an operator must not set to the reason. Every
// entry either dismantles an isolation guarantee this driver advertises, or
// collides with a flag the driver owns (in which case the runtime's
// last-wins parsing would let config quietly override the sandbox).
var deniedExtraArgs = map[string]string{
	"--privileged":    "grants the workload full host capabilities and device access",
	"--cap-add":       "re-adds capabilities this driver deliberately drops",
	"--security-opt":  "can disable seccomp/apparmor or undo no-new-privileges",
	"--device":        "exposes host devices to the workload",
	"--userns":        "the driver selects the user namespace strategy",
	"--user":          "the driver derives the UID from the project directory owner",
	"-u":              "the driver derives the UID from the project directory owner",
	"--network":       "network policy is set by executors.container.network",
	"--net":           "network policy is set by executors.container.network",
	"--volume":        "additional host mounts bypass the workspace-only boundary",
	"-v":              "additional host mounts bypass the workspace-only boundary",
	"--mount":         "additional host mounts bypass the workspace-only boundary",
	"--tmpfs":         "use the workspace mount; ad-hoc tmpfs escapes the memory cap",
	"--pid":           "sharing the host PID namespace exposes every host process",
	"--ipc":           "sharing the host IPC namespace exposes host shared memory",
	"--uts":           "sharing the host UTS namespace lets the workload rename the host",
	"--cgroupns":      "the host cgroup namespace leaks host resource topology",
	"--cgroup-parent": "reparenting the cgroup can escape the configured limits",
	"--entrypoint":    "overriding the entrypoint changes what argv actually runs",
	"--env":           "secrets are injected by the driver, never by static config",
	"-e":              "secrets are injected by the driver, never by static config",
	"--env-file":      "secrets are injected by the driver, never by static config",
	"--name":          "container names are derived so orphans stay reapable",
	"--detach":        "the driver controls detachment",
	"-d":              "the driver controls detachment",
	"--rm":            "auto-removal would delete the container before its exit code is read",
	"--workdir":       "the workload always runs in " + ContainerWorkspace,
	"-w":              "the workload always runs in " + ContainerWorkspace,
	"--pull":          "the driver never pulls implicitly; pre-pull the image instead",
	"--restart":       "restart policies would resurrect a workload the control plane killed",
	"--init":          "conflicts with the driver's signal and exit-code handling",
}

// ValidateExtraArgs checks operator-supplied runtime flags.
//
// Two rules, both necessary:
//
//   - Every argument must begin with "-". Without this a stray positional
//     would be consumed as the image reference, silently promoting the real
//     image to the command position and running an operator-chosen image.
//
//   - Flags taking a value must use --flag=value. The alternative (--flag
//     value) is indistinguishable from a positional here, because arity is a
//     property of the runtime's own flag table that we do not have.
//
// Exported so `cloop config set` and the config validator can reject a bad
// value at the point the operator types it, rather than at the next run.
func ValidateExtraArgs(extra []string) error {
	if len(extra) > maxExtraArgs {
		return fmt.Errorf("container: too many extra_args (%d, max %d)", len(extra), maxExtraArgs)
	}
	for i, raw := range extra {
		arg := strings.TrimSpace(raw)
		if arg == "" {
			return fmt.Errorf("container: extra_args[%d] is empty", i)
		}
		if arg == "-" || arg == "--" {
			return fmt.Errorf("container: extra_args[%d] %q is not a flag", i, raw)
		}
		if !strings.HasPrefix(arg, "-") {
			return fmt.Errorf(
				"container: extra_args[%d] %q must be a flag starting with '-' — "+
					"a bare value would be read as the image reference; use --flag=value", i, raw)
		}
		flag := arg
		if eq := strings.IndexByte(arg, '='); eq >= 0 {
			flag = arg[:eq]
		}
		if reason := deniedExtraArgs[flag]; reason != "" {
			return fmt.Errorf("container: extra_args[%d] %q is not allowed: %s", i, flag, reason)
		}
		if strings.ContainsAny(arg, "\n\r\x00") {
			return fmt.Errorf("container: extra_args[%d] contains a control character", i)
		}
	}
	return nil
}

// ValidateImageRef rejects references that could be re-read as flags or that
// smuggle shell metacharacters. It is deliberately not a full grammar for
// OCI references: the goal is to keep the *argv* unambiguous, and the
// runtime does the authoritative parsing.
func ValidateImageRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("container: image reference is empty — set executors.container.image")
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("container: image reference %q may not begin with '-'", ref)
	}
	if len(ref) > 512 {
		return fmt.Errorf("container: image reference is too long (%d bytes)", len(ref))
	}
	for _, r := range ref {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("._-/:@", r):
		default:
			return fmt.Errorf("container: image reference %q contains an invalid character %q", ref, r)
		}
	}
	return nil
}

// validateContainerName enforces the runtimes' shared name grammar,
// [a-zA-Z0-9][a-zA-Z0-9_.-]*, so a derived name can never be rejected at run
// time or, worse, be parsed as a flag.
func validateContainerName(name string) error {
	if name == "" {
		return fmt.Errorf("container: container name is empty")
	}
	if len(name) > 128 {
		return fmt.Errorf("container: container name %q is too long (%d > 128)", name, len(name))
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '_' || r == '.' || r == '-'):
		default:
			return fmt.Errorf("container: container name %q contains an invalid character %q at %d", name, r, i)
		}
	}
	return nil
}

// ValidateNonRootUser rejects a --user value that would run the workload as
// UID 0 inside the container, or leave the user unset.
//
// Root in a container is not the same as root on the host, but it is one
// kernel bug or one careless bind mount away from being exactly that, and it
// makes --cap-drop=ALL far less valuable than it looks. An unset user is worse
// than an explicit root: most base images default to root, so "no --user
// flag" is root without saying so.
//
// The refusal is deliberate rather than a silent downgrade to a fixed UID like
// nobody. The workspace is a bind mount from the host, so a UID the operator
// did not choose produces a container that cannot write to its own project
// directory — a confusing mid-run permission failure instead of an immediate,
// actionable one.
func ValidateNonRootUser(user string) error { return validateNonRootUser(user) }

func validateNonRootUser(user string) error {
	u := strings.TrimSpace(user)
	if u == "" {
		return fmt.Errorf("container: refusing to start without an explicit --user: " +
			"the image's default user is root in almost every base image. " +
			"Run the control plane as a non-root user, or chown the project " +
			"directory to the unprivileged UID the workload should use")
	}
	uidField := u
	if i := strings.IndexByte(u, ':'); i >= 0 {
		uidField = u[:i]
	}
	uid, err := strconv.Atoi(strings.TrimSpace(uidField))
	if err != nil {
		// A username can only be resolved against the image's /etc/passwd,
		// which is not readable from here. Requiring a numeric UID keeps the
		// check honest rather than approving "app" and hoping.
		return fmt.Errorf("container: --user %q must be a numeric uid[:gid]; "+
			"a username cannot be checked for root-ness without reading the image", user)
	}
	if uid == 0 {
		return fmt.Errorf("container: refusing to run the workload as uid 0 (--user %q). "+
			"Root in a container defeats --cap-drop=ALL and turns any runtime escape "+
			"into host root. Chown the project directory to an unprivileged user, or "+
			"run the control plane rootless so podman's keep-id mapping applies", user)
	}
	return nil
}

// ValidateNetwork allows the two well-known modes plus operator-defined
// network names. It rejects host networking outright: --network=host removes
// the network namespace entirely, so the workload can reach every service
// bound to the host's loopback — including the control plane's own API and
// any unauthenticated metadata endpoint.
func ValidateNetwork(name string) error {
	if name == "host" {
		return fmt.Errorf(
			"container: network \"host\" is not permitted — it removes network isolation and " +
				"exposes services bound to the host loopback; use \"none\", \"bridge\", or a named network")
	}
	if strings.HasPrefix(name, "container:") {
		return fmt.Errorf("container: joining another container's network namespace is not permitted")
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("container: network name %q may not begin with '-'", name)
	}
	if len(name) > 128 {
		return fmt.Errorf("container: network name is too long (%d bytes)", len(name))
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return fmt.Errorf("container: network name %q contains an invalid character %q", name, r)
		}
	}
	return nil
}

// validateAddHost checks a "name:address" resolution pin.
func validateAddHost(h string) error {
	parts := strings.Split(h, ":")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("container: add-host %q must be in host:address form", h)
	}
	if strings.HasPrefix(h, "-") {
		return fmt.Errorf("container: add-host %q may not begin with '-'", h)
	}
	if strings.ContainsAny(h, " \t\n\r\x00") {
		return fmt.Errorf("container: add-host %q contains whitespace", h)
	}
	return nil
}

// validateEnvName enforces the POSIX-ish variable-name grammar. A name
// containing '=' would let one entry inject a second, arbitrary variable.
func validateEnvName(name string) error {
	if name == "" {
		return fmt.Errorf("container: environment variable name is empty")
	}
	if len(name) > 256 {
		return fmt.Errorf("container: environment variable name is too long (%d bytes)", len(name))
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return fmt.Errorf("container: environment variable name %q contains an invalid character %q", name, r)
		}
	}
	return nil
}

// validateLabelKey keeps label keys to the dotted-identifier shape the driver
// generates, so a caller-supplied key cannot inject a second flag.
func validateLabelKey(k string) error {
	if k == "" {
		return fmt.Errorf("container: label key is empty")
	}
	if len(k) > 128 {
		return fmt.Errorf("container: label key %q is too long", k)
	}
	if strings.HasPrefix(k, "-") {
		return fmt.Errorf("container: label key %q may not begin with '-'", k)
	}
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '/':
		default:
			return fmt.Errorf("container: label key %q contains an invalid character %q", k, r)
		}
	}
	return nil
}

// sanitizeLabelValue strips characters that would break the runtime's
// key=value label parsing or corrupt a log line. Labels are observability
// metadata, so silently cleaning them beats failing a run over a project
// directory with a newline in its name.
func sanitizeLabelValue(v string) string {
	if len(v) > 256 {
		v = v[:256]
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', 0:
			return '_'
		}
		return r
	}, v)
}
