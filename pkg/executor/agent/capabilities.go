package agent

// capabilities.go answers "what is this device, and what can it run?"
//
// The control plane needs this to schedule: sending a task that shells out to
// `claude` to a device without the CLI installed produces a confusing
// exit-127 failure minutes later, when it could have been an immediate,
// legible "no enrolled agent has the claude harness". Advertising capabilities
// up front turns a runtime failure into a scheduling decision.
//
// Everything here degrades to zero or empty rather than failing. A device
// whose memory cannot be read is still a perfectly good executor; refusing to
// enroll it because /proc/meminfo had an unexpected format would be absurd.

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// knownContainerRuntimes are the runtimes the container executor can drive.
// Detected so the control plane can avoid routing container-isolated work to a
// device that would have to run it on bare metal.
var knownContainerRuntimes = []string{"docker", "podman", "nerdctl"}

// knownHarnesses are the agent CLIs a cloop workload might invoke. This list
// mirrors the providers cloop supports; a device missing all of them can still
// run shell workloads, so an empty result is informative, not fatal.
var knownHarnesses = []string{"claude", "codex", "gemini", "cloop"}

// DetectOptions tunes capability detection.
type DetectOptions struct {
	// WorkDirRoot is the confinement root to advertise.
	WorkDirRoot string
	// MaxConcurrent is the agent's workload ceiling.
	MaxConcurrent int
	// Labels are operator-supplied scheduler selectors.
	Labels map[string]string
	// LookPath overrides exec.LookPath for tests.
	LookPath func(string) (string, error)
	// MemoryMB overrides memory detection for tests; -1 forces "unknown".
	MemoryMB int
}

// Detect gathers this device's capabilities.
func Detect(opts DetectOptions) remote.AgentCapabilities {
	lookPath := opts.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}

	caps := remote.AgentCapabilities{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		CPUs:          runtime.NumCPU(),
		WorkDirRoot:   opts.WorkDirRoot,
		MaxConcurrent: opts.MaxConcurrent,
		Labels:        opts.Labels,
	}

	// Workspace provisioning is git and nothing else, so the capability is
	// exactly "is git on this PATH". Advertising it is what lets the control
	// plane refuse to place a private-repository run on a device that would
	// otherwise accept the start and run the harness against an empty tree —
	// the failure this whole mechanism exists to turn into a scheduling
	// decision rather than a confusing transcript.
	if _, err := lookPath("git"); err == nil {
		caps.WorkspaceProvisioning = true
	}

	switch {
	case opts.MemoryMB > 0:
		caps.MemoryMB = opts.MemoryMB
	case opts.MemoryMB == 0:
		caps.MemoryMB = detectMemoryMB()
	}

	for _, rt := range knownContainerRuntimes {
		if _, err := lookPath(rt); err == nil {
			caps.ContainerRuntimes = append(caps.ContainerRuntimes, rt)
		}
	}
	for _, h := range knownHarnesses {
		if _, err := lookPath(h); err == nil {
			caps.Harnesses = append(caps.Harnesses, h)
		}
	}
	return caps
}

// detectMemoryMB reads total system memory, returning 0 when it cannot.
//
// Only Linux is implemented, via /proc/meminfo. That is not an oversight: the
// edge devices this feature targets are overwhelmingly Linux, and the field is
// advisory scheduling metadata. A macOS agent reports 0 and is scheduled on
// its other attributes rather than being excluded.
func detectMemoryMB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return int(kb / 1024)
	}
	return 0
}

// HasHarness reports whether caps advertises a given harness, for schedulers
// matching a project's provider against a device.
func HasHarness(caps remote.AgentCapabilities, name string) bool {
	for _, h := range caps.Harnesses {
		if h == name {
			return true
		}
	}
	return false
}

// HasContainerRuntime reports whether caps advertises any container runtime.
func HasContainerRuntime(caps remote.AgentCapabilities) bool {
	return len(caps.ContainerRuntimes) > 0
}
