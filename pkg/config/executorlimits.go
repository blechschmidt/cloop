// executorlimits.go is the operator's side of the resource ceiling: the
// `executors.limits` section of config.yaml.
//
// It exists because every resource knob cloop had before it was a *default*.
// `executors.container.memory: 2g` is what a workload gets when it asks for
// nothing, and the container driver hands the decision to the workload the
// moment it does ask — "spec limits override the executor's configured
// defaults". For a request written by the operator that is right. For one read
// out of .cloop/sandbox.yaml, a file committed to the repository, it means the
// project sets its own limits and the operator's number was advice.
//
// These keys are not advice. See pkg/executor/ceiling.go for the semantics;
// this file is only the parsing, the validation and the units.
package config

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ExecutorLimitsConfig is the hub-wide ceiling on what any single workload may
// be given, whichever executor runs it.
//
// The fields are strings and a float for the same reason the rest of the
// executor config is: an operator writes "8g", not 8192, and a config file that
// demands megabytes invites the off-by-1024 error that makes a sandbox OOM on
// startup. Parsing happens here, once, with the same grammar every other size
// in this file uses.
//
// Absent or zero on any field means that resource is uncapped — the behaviour
// every deployment had before this section existed, which is what keeps adding
// it a no-op upgrade rather than a surprise outage.
type ExecutorLimitsConfig struct {
	// MaxCPU caps the core allowance of one workload (2 = two cores).
	MaxCPU float64 `yaml:"max_cpu,omitempty"`
	// MaxMemory caps resident memory, as a size string ("2g", "512m").
	MaxMemory string `yaml:"max_memory,omitempty"`
	// MaxDisk caps the workspace and scratch space, as a size string.
	MaxDisk string `yaml:"max_disk,omitempty"`
	// MaxPIDs caps processes/threads in one workload.
	MaxPIDs int `yaml:"max_pids,omitempty"`
}

// IsZero reports whether the section caps nothing.
func (l ExecutorLimitsConfig) IsZero() bool {
	return l.MaxCPU == 0 && strings.TrimSpace(l.MaxMemory) == "" &&
		strings.TrimSpace(l.MaxDisk) == "" && l.MaxPIDs == 0
}

// Ceiling converts the configured section to the executor package's ceiling
// type, returning the first parse error.
//
// Errors rather than clamps, unlike most of this file. Load() clamps an
// out-of-range value and warns, which is right when the setting is a
// preference: the hub boots, slightly different from what was asked for. A
// ceiling that silently became a different number is a policy the operator
// believes they have and does not, so the malformed case is surfaced instead —
// through ValidateExecutors at `config set`, and through ExecutorLimitWarnings
// for a hand-edited file, which is the same two-path treatment
// executors.min_agent_build gets and for the same reason.
func (l ExecutorLimitsConfig) Ceiling() (executor.ResourceCeiling, error) {
	var c executor.ResourceCeiling

	if l.MaxCPU < 0 {
		return c, fmt.Errorf("executors.limits.max_cpu must be >= 0, got %v", l.MaxCPU)
	}
	if l.MaxCPU > ContainerCPUsUpper {
		return c, fmt.Errorf("executors.limits.max_cpu %v exceeds the maximum of %v",
			l.MaxCPU, ContainerCPUsUpper)
	}
	c.CPUMillis = int(l.MaxCPU * 1000)

	if s := strings.TrimSpace(l.MaxMemory); s != "" {
		mb, err := ParseMemoryMB(s)
		if err != nil {
			return executor.ResourceCeiling{}, fmt.Errorf("executors.limits.max_memory: %w", err)
		}
		// The floor is a real constraint, not a style rule: below it the
		// harness OOMs before it finishes starting, so a ceiling set there
		// would refuse every workload on the hub while looking like a limit.
		if mb > 0 && mb < ContainerMemoryMBLower {
			return executor.ResourceCeiling{}, fmt.Errorf(
				"executors.limits.max_memory %q is below the minimum of %d MB; a ceiling that "+
					"low fails every workload on this hub", s, ContainerMemoryMBLower)
		}
		c.MemoryMB = mb
	}

	if s := strings.TrimSpace(l.MaxDisk); s != "" {
		mb, err := ParseDiskMB(s)
		if err != nil {
			return executor.ResourceCeiling{}, fmt.Errorf("executors.limits.max_disk: %w", err)
		}
		if mb > 0 && mb < ContainerDiskMBLower {
			return executor.ResourceCeiling{}, fmt.Errorf(
				"executors.limits.max_disk %q is below the minimum of %d MB; there is no room "+
					"for a checkout plus the harness's own scratch", s, ContainerDiskMBLower)
		}
		c.DiskMB = mb
	}

	switch {
	case l.MaxPIDs < 0:
		// Negative is the runtimes' "unlimited" sentinel. A ceiling meaning
		// unlimited is a ceiling that should not have been written, and reading
		// it as one silently would remove a cap the operator believes is set.
		return executor.ResourceCeiling{}, fmt.Errorf(
			"executors.limits.max_pids must be >= 0, got %d (a ceiling cannot waive the "+
				"process cap; remove the key to leave it uncapped)", l.MaxPIDs)
	case l.MaxPIDs > ContainerPIDsUpper:
		return executor.ResourceCeiling{}, fmt.Errorf(
			"executors.limits.max_pids %d exceeds the maximum of %d", l.MaxPIDs, ContainerPIDsUpper)
	default:
		c.PIDs = l.MaxPIDs
	}

	return c, nil
}

// ValidateExecutorLimits rejects a malformed ceiling at the door, for
// `cloop config set` and `cloop config validate`.
func ValidateExecutorLimits(l ExecutorLimitsConfig) error {
	_, err := l.Ceiling()
	return err
}

// ExecutorLimitWarnings surfaces a hand-edited ceiling that cannot be parsed.
//
// Refusing to boot would be a denial of service over a typo — the treatment
// Load gives every other malformed value here. But an unparseable ceiling is
// silently no ceiling, and "the deployment believes it is capped and is not" is
// exactly the state min_agent_build's banner exists to prevent. So it loads,
// and it says so loudly.
func ExecutorLimitWarnings(l ExecutorLimitsConfig) []string {
	if l.IsZero() {
		return nil
	}
	if _, err := l.Ceiling(); err != nil {
		return []string{fmt.Sprintf("executors.limits could not be parsed (%v), so no "+
			"fleet-wide resource ceiling is being enforced and a project's .cloop/sandbox.yaml "+
			"can request any amount up to the built-in maximum. Fix the key or remove the "+
			"section.", err)}
	}
	return nil
}
