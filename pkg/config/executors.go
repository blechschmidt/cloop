package config

// executors.go holds validation for the execution-backend section of the
// config. It lives apart from config.go because these values are not just
// tuning knobs: they define an isolation boundary, and a value that fails to
// parse must never degrade into "no limit".
//
// The split of responsibilities matches the rest of the package:
//
//   - ValidateContainerExecutor is the strict path. `cloop config set` and
//     the config validator use it to reject a bad value where the operator
//     typed it.
//   - clampContainerExecutor is the defensive path, run on every Load. A
//     hand-edited YAML that asks for a nonsensical limit is repaired to the
//     driver's conservative default and warned about, rather than being
//     honoured or crashing a long-running server.
//
// Flag-level validation of extra_args is delegated to the driver
// (container.ValidateExtraArgs) on purpose: the denylist of runtime flags
// that would dismantle the sandbox must have exactly one definition, and it
// belongs next to the argv builder it protects.

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// ParseMemoryMB converts a size string to megabytes.
//
// Accepted forms mirror what the container runtimes accept — "512m", "2g",
// "1048576k", "536870912b" — plus a bare integer, which is read as megabytes.
// (The runtimes read a bare integer as *bytes*; that reading turns "512" into
// half a kilobyte and an instantly-OOMing sandbox, so cloop takes the
// interpretation an operator obviously meant.)
//
// An empty string yields 0, meaning "no limit requested".
func ParseMemoryMB(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	unit := s[len(s)-1]
	digits := s
	multiplierKB := 1024 // default for a bare number: megabytes

	switch unit {
	case 'b', 'B':
		digits = s[:len(s)-1]
		multiplierKB = 0 // bytes; handled below
	case 'k', 'K':
		digits = s[:len(s)-1]
		multiplierKB = 1
	case 'm', 'M':
		digits = s[:len(s)-1]
		multiplierKB = 1024
	case 'g', 'G':
		digits = s[:len(s)-1]
		multiplierKB = 1024 * 1024
	case 't', 'T':
		digits = s[:len(s)-1]
		multiplierKB = 1024 * 1024 * 1024
	}

	digits = strings.TrimSpace(digits)
	if digits == "" {
		return 0, fmt.Errorf("memory %q has a unit but no value", s)
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("memory %q is not a size (expected forms: 512m, 2g, 1024k)", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("memory %q must not be negative", s)
	}

	var kb int64
	if multiplierKB == 0 {
		// Bytes: round up so a sub-kilobyte request does not become zero,
		// which would read as "no limit".
		kb = (n + 1023) / 1024
	} else {
		kb = n * int64(multiplierKB)
	}
	mb := (kb + 1023) / 1024
	if mb > int64(ContainerMemoryMBUpper) {
		return 0, fmt.Errorf("memory %q exceeds the maximum of %d MB", s, ContainerMemoryMBUpper)
	}
	if n > 0 && mb == 0 {
		mb = 1
	}
	return int(mb), nil
}

// ValidateExecutors checks the whole executors section.
//
// Strict no-host-execution mode with nothing else configured is deliberately
// NOT an error. It is a legitimate and even expected intermediate state: an
// operator hardens the control plane first, then enrolls edge devices, and
// remote executors arrive at runtime over an outbound connection rather than
// through this file. Making it fatal would mean a hardened control plane
// refuses to boot until a device happens to be online — precisely backwards
// for a security control. ExecutorWarnings surfaces it as advice instead, and
// the Executors tab shows it as a banner.
func ValidateExecutors(e ExecutorsConfig) error {
	if err := ValidateContainerExecutor(e.Container); err != nil {
		return err
	}
	if err := ValidateKubernetesExecutor(e.Kubernetes); err != nil {
		return err
	}
	return ValidateEgressConfig(e.Egress)
}

// ExecutorWarnings returns advisory messages about a valid-but-questionable
// executors section: configurations that will load and run, but that an
// operator probably did not intend.
func ExecutorWarnings(e ExecutorsConfig) []string {
	var out []string
	isolated := e.Container.Enabled || e.Kubernetes.Enabled
	if !e.HostProcessAllowed() && !isolated {
		out = append(out, "executors.allow_host_process is false and no isolated executor is "+
			"enabled — no executor is configured in this file. Projects will only run once a "+
			"remote agent enrolls (`cloop executor enroll`); until then every run is refused.")
	}
	if e.HostProcessAllowed() && !e.HostProcessExplicit() && isolated {
		out = append(out, "an isolated executor is enabled but executors.allow_host_process is "+
			"unset, so it still defaults to true and unbound projects run on the host. Set it "+
			"to false to enforce sandboxed execution.")
	}
	if e.Kubernetes.Enabled {
		// Warn about the image that will actually run, not the one that was
		// typed: an empty value means the driver's placeholder default, and
		// staying quiet about that is how an operator discovers the image
		// does not contain cloop at the first task instead of at config time.
		image := strings.TrimSpace(e.Kubernetes.Image)
		if image == "" {
			image = kubernetes.DefaultImage
		}
		for _, w := range kubernetes.ImageWarnings(image) {
			out = append(out, "executors.kubernetes."+w)
		}
		if strings.TrimSpace(e.Kubernetes.Namespace) == "" {
			out = append(out, "executors.kubernetes.namespace is unset, so Pods land in the "+
				"namespace the brokered kubeconfig happens to name (or \"cloop\"). Set it "+
				"explicitly — the namespace is the blast radius.")
		}
		if e.Kubernetes.MemoryLimit == "" && e.Kubernetes.CPULimit == "" {
			out = append(out, "executors.kubernetes sets no cpu_limit or memory_limit, so a "+
				"workload is bounded only by the namespace's LimitRange (if one exists).")
		}
	}
	if e.Egress.Enabled {
		// A loopback bind is the default and is right for host-process and
		// host-network executors; it is silently wrong for a bridged
		// container, which cannot route to the host's 127.0.0.1 and will
		// simply time out on every request. Saying so at config time is much
		// cheaper than discovering it as "the sandbox has no network".
		addr := strings.TrimSpace(e.Egress.ListenAddr)
		if (addr == "" || strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "localhost")) &&
			strings.TrimSpace(e.Egress.AdvertiseAddr) == "" && e.Container.Enabled {
			out = append(out, "executors.egress binds loopback but the container executor is "+
				"enabled — a bridged sandbox cannot reach the host's 127.0.0.1. Set "+
				"executors.egress.advertise_addr (host.containers.internal / "+
				"host.docker.internal) or bind an address the sandbox can route to.")
		}
		if e.Egress.DefaultMaxBytesUp == "" && e.Egress.DefaultMaxBytesDown == "" {
			out = append(out, "executors.egress sets no default transfer quota, so a grant "+
				"created without --max-up/--max-down can move unlimited data. Set "+
				"default_max_bytes_up/down to bound it.")
		}
	} else if e.Container.Enabled && strings.TrimSpace(e.Container.Network) == container.NetworkNone {
		out = append(out, "the container executor runs with network \"none\" and "+
			"executors.egress is disabled, so sandboxed workloads have no route out at all. "+
			"Enable executors.egress and grant hosts with `cloop egress grant` if they need one.")
	}
	return out
}

// ValidateEgressConfig returns a non-nil error describing the first problem
// found in e. It does not mutate.
//
// Like the other executor validators it runs even when the section is
// disabled, so a broken value is reported when it is written rather than
// discovered at the moment someone flips enabled to true.
func ValidateEgressConfig(e EgressConfig) error {
	if e.MaxSessionMinutes < 0 || e.MaxSessionMinutes > EgressMaxSessionMinutesUpper {
		return fmt.Errorf("executors.egress.max_session_minutes must be between 0 and %d (got %d)",
			EgressMaxSessionMinutesUpper, e.MaxSessionMinutes)
	}
	if e.DialTimeoutSeconds < 0 || e.DialTimeoutSeconds > EgressDialTimeoutSecondsUpper {
		return fmt.Errorf("executors.egress.dial_timeout_seconds must be between 0 and %d (got %d)",
			EgressDialTimeoutSecondsUpper, e.DialTimeoutSeconds)
	}
	if err := validateEgressAddr("listen_addr", e.ListenAddr, true); err != nil {
		return err
	}
	if err := validateEgressAddr("advertise_addr", e.AdvertiseAddr, false); err != nil {
		return err
	}
	for field, v := range map[string]string{
		"default_max_bytes_up":   e.DefaultMaxBytesUp,
		"default_max_bytes_down": e.DefaultMaxBytesDown,
	} {
		if _, err := egressbroker.ParseBytes(v); err != nil {
			return fmt.Errorf("executors.egress.%s: %w", field, err)
		}
	}
	return nil
}

// validateEgressAddr checks a host:port. requirePort distinguishes the bind
// address, where net.Listen needs one, from the advertised address, where a
// bare host is legitimate (the port is appended from the listener).
func validateEgressAddr(field, addr string, requirePort bool) error {
	a := strings.TrimSpace(addr)
	if a == "" {
		return nil
	}
	if strings.Contains(a, "://") || strings.ContainsAny(a, "/?#@ \t") {
		return fmt.Errorf("executors.egress.%s must be host:port, not a URL (got %q)", field, a)
	}
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		if requirePort {
			return fmt.Errorf("executors.egress.%s must be host:port (got %q)", field, a)
		}
		return nil
	}
	_ = host
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("executors.egress.%s port must be between 0 and 65535 (got %q)", field, port)
	}
	return nil
}

// clampEgressConfig repairs out-of-range values in place and reports what it
// changed, so Load can warn once per field.
//
// Every repair resets to the zero value, which the broker reads as "use my
// default", and every broker default is the tighter one: a shorter session, a
// shorter dial, a loopback bind. The one field that is *disabled* rather than
// reset is Enabled itself, for a listen address so broken that starting the
// proxy would mean binding somewhere nobody chose — the analogue of
// clampKubernetesExecutor refusing to register an unusable cluster backend.
func clampEgressConfig(e *EgressConfig) []string {
	var changed []string

	if e.MaxSessionMinutes < 0 || e.MaxSessionMinutes > EgressMaxSessionMinutesUpper {
		changed = append(changed, fmt.Sprintf("executors.egress.max_session_minutes: value %d outside [0, %d]",
			e.MaxSessionMinutes, EgressMaxSessionMinutesUpper))
		e.MaxSessionMinutes = 0
	}
	if e.DialTimeoutSeconds < 0 || e.DialTimeoutSeconds > EgressDialTimeoutSecondsUpper {
		changed = append(changed, fmt.Sprintf("executors.egress.dial_timeout_seconds: value %d outside [0, %d]",
			e.DialTimeoutSeconds, EgressDialTimeoutSecondsUpper))
		e.DialTimeoutSeconds = 0
	}
	for field, v := range map[string]*string{
		"default_max_bytes_up":   &e.DefaultMaxBytesUp,
		"default_max_bytes_down": &e.DefaultMaxBytesDown,
	} {
		if _, err := egressbroker.ParseBytes(*v); err != nil {
			changed = append(changed, fmt.Sprintf("executors.egress.%s: %v", field, err))
			*v = ""
		}
	}
	if err := validateEgressAddr("advertise_addr", e.AdvertiseAddr, false); err != nil {
		changed = append(changed, fmt.Sprintf("executors.egress.advertise_addr: %v", err))
		e.AdvertiseAddr = ""
	}
	if err := validateEgressAddr("listen_addr", e.ListenAddr, true); err != nil {
		// Resetting to "" would bind an ephemeral loopback port, which is
		// safe but silently not what the operator asked for. Disabling the
		// proxy instead makes the misconfiguration visible as "egress is
		// off" rather than as "egress is on but nothing can reach it".
		changed = append(changed, fmt.Sprintf(
			"executors.egress: disabled because listen_addr is unusable: %v", err))
		e.ListenAddr = ""
		e.Enabled = false
	}
	return changed
}

// ValidateContainerExecutor returns a non-nil error describing the first
// problem found in c. It does not mutate.
//
// It runs even when the executor is disabled: a disabled-but-broken config
// should be reported when it is written, not discovered months later at the
// moment someone flips enabled to true.
func ValidateContainerExecutor(c ContainerExecutorConfig) error {
	if rt := strings.TrimSpace(c.Runtime); rt != "" {
		switch rt {
		case container.RuntimePodman, container.RuntimeDocker:
		default:
			return fmt.Errorf("executors.container.runtime must be %q or %q (got %q)",
				container.RuntimePodman, container.RuntimeDocker, rt)
		}
	}

	if c.CPUs < 0 {
		return fmt.Errorf("executors.container.cpus must be >= 0 (got %v)", c.CPUs)
	}
	if c.CPUs > ContainerCPUsUpper {
		return fmt.Errorf("executors.container.cpus must be <= %.0f (got %v)", ContainerCPUsUpper, c.CPUs)
	}

	mb, err := ParseMemoryMB(c.Memory)
	if err != nil {
		return fmt.Errorf("executors.container.%w", err)
	}
	if mb != 0 && mb < ContainerMemoryMBLower {
		return fmt.Errorf("executors.container.memory must be at least %dMB (got %q) — "+
			"a smaller ceiling kills the workload before it starts",
			ContainerMemoryMBLower, c.Memory)
	}

	if c.PIDsLimit < -1 {
		return fmt.Errorf("executors.container.pids_limit must be -1 (unlimited), 0 (default), or a positive count (got %d)", c.PIDsLimit)
	}
	if c.PIDsLimit > 0 && (c.PIDsLimit < ContainerPIDsLower || c.PIDsLimit > ContainerPIDsUpper) {
		return fmt.Errorf("executors.container.pids_limit must be between %d and %d (got %d)",
			ContainerPIDsLower, ContainerPIDsUpper, c.PIDsLimit)
	}

	switch c.SELinuxLabel {
	case "", "z", "Z":
	default:
		return fmt.Errorf("executors.container.selinux_label must be empty, \"z\", or \"Z\" (got %q)", c.SELinuxLabel)
	}

	// Delegated to the driver so the sandbox-critical checks (network name,
	// image reference, denied flags) have a single definition.
	if _, err := c.DriverOptions(); err != nil {
		return fmt.Errorf("executors.container: %w", err)
	}
	return nil
}

// DriverOptions converts the config section into driver options, applying the
// driver's own normalisation and validation.
//
// It is the single conversion point: the CLI, the UI, and the config
// validator all go through it, so none of them can construct an executor
// whose confinement differs from what the config describes.
func (c ContainerExecutorConfig) DriverOptions() (container.Options, error) {
	mb, err := ParseMemoryMB(c.Memory)
	if err != nil {
		return container.Options{}, err
	}
	opts := container.Options{
		ID:           strings.TrimSpace(c.ID),
		Runtime:      strings.TrimSpace(c.Runtime),
		Image:        strings.TrimSpace(c.Image),
		CPUs:         c.CPUs,
		MemoryMB:     mb,
		PIDsLimit:    c.PIDsLimit,
		Network:      strings.TrimSpace(c.Network),
		AllowHosts:   c.AllowHosts,
		ExtraArgs:    c.ExtraArgs,
		SELinuxLabel: c.SELinuxLabel,
	}
	return opts.Normalize()
}

// ValidateKubernetesExecutor returns a non-nil error describing the first
// problem found in k. It does not mutate.
//
// Like the container validator it runs even when the executor is disabled, so
// a broken section is reported when it is written rather than at the moment
// someone flips enabled to true.
//
// Note what is *not* validated here: there is no kubeconfig path to check,
// because this executor has no such setting. Credentials are leased from the
// secret broker at run time, so the only thing config can say about them is
// which secret to prefer.
func ValidateKubernetesExecutor(k KubernetesExecutorConfig) error {
	for field, v := range map[string]int64{
		"active_deadline_seconds":          k.ActiveDeadlineSeconds,
		"termination_grace_period_seconds": k.TerminationGracePeriodSeconds,
		"kill_grace_period_seconds":        k.KillGracePeriodSeconds,
		"orphan_grace_period_seconds":      k.OrphanGracePeriodSeconds,
	} {
		if v < 0 {
			return fmt.Errorf("executors.kubernetes.%s must be >= 0 (got %d)", field, v)
		}
		if v > KubernetesSecondsUpper {
			return fmt.Errorf("executors.kubernetes.%s must be <= %d (got %d)",
				field, KubernetesSecondsUpper, v)
		}
	}
	if k.MaxConcurrent < 0 || k.MaxConcurrent > KubernetesMaxConcurrentUpper {
		return fmt.Errorf("executors.kubernetes.max_concurrent must be between 0 and %d (got %d)",
			KubernetesMaxConcurrentUpper, k.MaxConcurrent)
	}
	// UID 0 is the one value this executor can never honour: it always sets
	// runAsNonRoot, and the kubelet resolves the contradiction by refusing to
	// start the Pod with an error that reads like an image problem.
	if k.RunAsUser < 0 || k.RunAsGroup < 0 {
		return fmt.Errorf("executors.kubernetes.run_as_user and run_as_group must be >= 0")
	}

	// Delegated to the driver so the Pod-critical checks (namespace, image
	// reference, quantities, tolerations) have a single definition.
	if _, err := k.DriverOptions(); err != nil {
		return fmt.Errorf("executors.kubernetes: %w", err)
	}
	return nil
}

// DriverOptions converts the config section into driver options, applying the
// driver's own normalisation and validation.
//
// Credentials is deliberately left nil: only a caller holding a secret broker
// can fill it in, and that is the wiring in cmd/executor_cmd.go. A config
// validator asking "is this section well-formed" must not need a decryption
// key to answer.
func (k KubernetesExecutorConfig) DriverOptions() (kubernetes.Options, error) {
	opts := kubernetes.Options{
		ID:                    strings.TrimSpace(k.ID),
		Namespace:             strings.TrimSpace(k.Namespace),
		Image:                 strings.TrimSpace(k.Image),
		ImagePullPolicy:       strings.TrimSpace(k.ImagePullPolicy),
		ImagePullSecrets:      k.ImagePullSecrets,
		ServiceAccountName:    strings.TrimSpace(k.ServiceAccount),
		CPURequest:            strings.TrimSpace(k.CPURequest),
		CPULimit:              strings.TrimSpace(k.CPULimit),
		MemoryRequest:         strings.TrimSpace(k.MemoryRequest),
		MemoryLimit:           strings.TrimSpace(k.MemoryLimit),
		EphemeralStorageLimit: strings.TrimSpace(k.EphemeralStorageLimit),
		WorkspaceSizeLimit:    strings.TrimSpace(k.WorkspaceSizeLimit),
		NodeSelector:          k.NodeSelector,
		Tolerations:           k.Tolerations,
		ActiveDeadlineSeconds: k.ActiveDeadlineSeconds,
		RunAsUser:             k.RunAsUser,
		RunAsGroup:            k.RunAsGroup,
		KeepCompletedPods:     k.KeepCompletedPods,
		MaxConcurrent:         k.MaxConcurrent,
	}
	if k.TerminationGracePeriodSeconds > 0 {
		opts.TerminationGracePeriod = time.Duration(k.TerminationGracePeriodSeconds) * time.Second
	}
	if k.KillGracePeriodSeconds > 0 {
		opts.KillGracePeriod = time.Duration(k.KillGracePeriodSeconds) * time.Second
	}
	if k.OrphanGracePeriodSeconds > 0 {
		opts.OrphanGracePeriod = time.Duration(k.OrphanGracePeriodSeconds) * time.Second
	}
	return opts.Normalize()
}

// clampKubernetesExecutor repairs out-of-range values in place and reports
// what it changed, so Load can warn once per field.
//
// Every repair resets to the zero value, which the driver reads as "use my
// default", and every driver default is the confining one — the built-in
// non-root UID, a 30-second grace period, the reserved-namespace check. A
// clamp can therefore only tighten, never loosen. The one field that is
// *disabled* rather than reset is Enabled itself, for the case where the
// section is broken badly enough that registering it would produce a
// half-configured cluster backend.
func clampKubernetesExecutor(k *KubernetesExecutorConfig) []string {
	var changed []string

	clampSeconds := func(name string, v *int64) {
		if *v < 0 || *v > KubernetesSecondsUpper {
			changed = append(changed, fmt.Sprintf("executors.kubernetes.%s: value %d outside [0, %d]",
				name, *v, KubernetesSecondsUpper))
			*v = 0
		}
	}
	clampSeconds("active_deadline_seconds", &k.ActiveDeadlineSeconds)
	clampSeconds("termination_grace_period_seconds", &k.TerminationGracePeriodSeconds)
	clampSeconds("kill_grace_period_seconds", &k.KillGracePeriodSeconds)
	clampSeconds("orphan_grace_period_seconds", &k.OrphanGracePeriodSeconds)

	if k.MaxConcurrent < 0 || k.MaxConcurrent > KubernetesMaxConcurrentUpper {
		changed = append(changed, fmt.Sprintf("executors.kubernetes.max_concurrent: value %d outside [0, %d]",
			k.MaxConcurrent, KubernetesMaxConcurrentUpper))
		k.MaxConcurrent = 0
	}
	if k.RunAsUser < 0 {
		changed = append(changed, fmt.Sprintf("executors.kubernetes.run_as_user: %d is negative", k.RunAsUser))
		k.RunAsUser = 0
	}
	if k.RunAsGroup < 0 {
		changed = append(changed, fmt.Sprintf("executors.kubernetes.run_as_group: %d is negative", k.RunAsGroup))
		k.RunAsGroup = 0
	}
	if k.Namespace != "" {
		if err := kubernetes.ValidateNamespace(k.Namespace); err != nil {
			changed = append(changed, fmt.Sprintf("executors.kubernetes.namespace: %v", err))
			k.Namespace = ""
		}
	}
	if k.Image != "" {
		if err := kubernetes.ValidateImageRef(k.Image); err != nil {
			changed = append(changed, fmt.Sprintf("executors.kubernetes.image: %v", err))
			k.Image = ""
		}
	}
	switch k.ImagePullPolicy {
	case "", "Always", "IfNotPresent", "Never":
	default:
		changed = append(changed, fmt.Sprintf("executors.kubernetes.image_pull_policy: %q is not a pull policy",
			k.ImagePullPolicy))
		k.ImagePullPolicy = ""
	}
	for name, q := range map[string]*string{
		"cpu_request":             &k.CPURequest,
		"cpu_limit":               &k.CPULimit,
		"memory_request":          &k.MemoryRequest,
		"memory_limit":            &k.MemoryLimit,
		"ephemeral_storage_limit": &k.EphemeralStorageLimit,
		"workspace_size_limit":    &k.WorkspaceSizeLimit,
	} {
		if err := kubernetes.ValidateQuantity(*q); err != nil {
			changed = append(changed, fmt.Sprintf("executors.kubernetes.%s: %v", name, err))
			*q = ""
		}
	}
	for i, t := range k.Tolerations {
		if err := t.Validate(); err != nil {
			// Dropping the whole list rather than the offending entry: a
			// partial toleration set schedules Pods onto a node pool the
			// operator did not choose, which is worse than not scheduling.
			changed = append(changed, fmt.Sprintf("executors.kubernetes.tolerations[%d]: %v", i, err))
			k.Tolerations = nil
			break
		}
	}
	// A section that still cannot produce driver options is not salvageable
	// field-by-field; refuse to register it rather than register something
	// whose confinement nobody chose.
	if k.Enabled {
		if _, err := k.DriverOptions(); err != nil {
			changed = append(changed, fmt.Sprintf(
				"executors.kubernetes: disabled because the section is unusable: %v", err))
			k.Enabled = false
		}
	}
	return changed
}

// clampContainerExecutor repairs out-of-range values in place and reports
// what it changed, so Load can warn once per field.
//
// Each repair resets to the zero value, which every consumer reads as "use
// the driver default". The driver's defaults are the conservative ones — no
// network, a process cap, all capabilities dropped — so a clamp can only ever
// tighten confinement, never loosen it.
func clampContainerExecutor(c *ContainerExecutorConfig) []string {
	var changed []string

	if rt := strings.TrimSpace(c.Runtime); rt != "" &&
		rt != container.RuntimePodman && rt != container.RuntimeDocker {
		changed = append(changed, fmt.Sprintf("executors.container.runtime: %q is not a supported runtime", rt))
		c.Runtime = ""
	}
	if c.CPUs < 0 || c.CPUs > ContainerCPUsUpper {
		changed = append(changed, fmt.Sprintf("executors.container.cpus: value %v outside [0, %.0f]", c.CPUs, ContainerCPUsUpper))
		c.CPUs = 0
	}
	if mb, err := ParseMemoryMB(c.Memory); err != nil {
		changed = append(changed, fmt.Sprintf("executors.container.memory: %v", err))
		c.Memory = ""
	} else if mb != 0 && mb < ContainerMemoryMBLower {
		changed = append(changed, fmt.Sprintf("executors.container.memory: %q is below the %dMB minimum", c.Memory, ContainerMemoryMBLower))
		c.Memory = ""
	}
	if c.PIDsLimit < -1 || (c.PIDsLimit > 0 && (c.PIDsLimit < ContainerPIDsLower || c.PIDsLimit > ContainerPIDsUpper)) {
		changed = append(changed, fmt.Sprintf("executors.container.pids_limit: value %d outside [%d, %d]",
			c.PIDsLimit, ContainerPIDsLower, ContainerPIDsUpper))
		c.PIDsLimit = 0
	}
	switch c.SELinuxLabel {
	case "", "z", "Z":
	default:
		changed = append(changed, fmt.Sprintf("executors.container.selinux_label: %q is not \"z\" or \"Z\"", c.SELinuxLabel))
		c.SELinuxLabel = ""
	}
	if err := container.ValidateExtraArgs(c.ExtraArgs); err != nil {
		// Dropping the whole list rather than the offending entry is
		// deliberate: extra_args is frequently a flag plus its value in
		// separate entries, and removing one half leaves a command line
		// whose meaning nobody intended.
		changed = append(changed, fmt.Sprintf("executors.container.extra_args: %v", err))
		c.ExtraArgs = nil
	}
	if err := container.ValidateNetwork(c.Network); err != nil {
		changed = append(changed, fmt.Sprintf("executors.container.network: %v", err))
		c.Network = ""
	}
	if strings.TrimSpace(c.Network) == "" || strings.TrimSpace(c.Network) == container.NetworkNone {
		if len(c.AllowHosts) > 0 {
			changed = append(changed, "executors.container.allow_hosts: ignored because the sandbox has no network")
			c.AllowHosts = nil
		}
	}
	if c.Image != "" {
		if err := container.ValidateImageRef(c.Image); err != nil {
			changed = append(changed, fmt.Sprintf("executors.container.image: %v", err))
			c.Image = ""
		}
	}
	return changed
}
