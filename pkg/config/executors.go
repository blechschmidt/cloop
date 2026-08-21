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
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor/container"
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
