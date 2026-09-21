// harness.go answers one question about a dispatch: once `cloop run` is going
// on the far side, will the binary it execs be there.
//
// # Why this is not the same question as the three refusals beside it
//
// Start already refuses a workspace the agent cannot fetch, a sandbox mode it
// is too old to honour, and a hypervisor the machine does not have. All three
// are about the *boundary* the payload runs inside. None of them is about the
// payload, and the payload is what was broken: a device advertising
// `harnesses: ["cloop"]` — no `claude` — was sent a claudecode project on
// every dispatch, and failed each time with
//
//	✗ Provider error: claude CLI start error: exec: "claude":
//	  executable file not found in $PATH
//
// That line arrives after the hub has leased a GitHub credential, written the
// broker's audit row, shipped the material to the device's tmpfs and
// provisioned a workspace directory — roughly half a second of work whose only
// product is an error naming neither the executor, nor the provider that
// needed the binary, nor the fact that the hub knew both.
//
// It did know both. AgentCapabilities.Harnesses has carried the device's
// inventory since the protocol had a hello frame, and its own doc comment says
// "a device without the harness a project needs should not be sent its work".
// executor.Requirements has carried a Harnesses field with a ConstraintHarness
// refusal ready to fire. The two were never connected: nothing in the tree ever
// populated Requirements.Harnesses except a sandbox.yaml asking for `git`, so
// the constraint was unreachable for the provider's own CLI.
//
// # The gate is the sandbox mode, and it is the whole subtlety
//
// AgentCapabilities describes the device's host — what the agent found on its
// own PATH at hello. That is the right inventory to check exactly when the
// payload will run on that host, and the wrong one as soon as it will not: in
// container mode the harness comes out of the image, which is precisely the
// configuration that *fixes* a device with no `claude` on it. Checking the
// device's PATH there would refuse the remedy along with the fault, and an
// operator following the message below would find it stopped working the
// moment they complied with it.
//
// So: host mode asks the device, container mode asks nothing. The image is not
// interrogated because nothing in the protocol can interrogate it — the agent
// reports its own PATH, not the PATH of an image it may not even have pulled
// yet — and inventing a "probably fine" for that case is how the pre-v9
// virtualization check got its own "unknown is not no" rule.
package remote

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// HarnessImageHint is the published sandbox image named when a device has no
// harness of its own. It carries `claude`, `cloop` and `git`, which is exactly
// the set a refused dispatch is missing.
//
// A constant rather than a literal in the message because docs/ and the Fleet
// panel name the same image, and a hint that drifts from what the image
// actually is would send an operator to pull something that does not fix their
// problem.
const HarnessImageHint = "ghcr.io/blechschmidt/cloop-harness:latest"

// checkHarness refuses a dispatch whose harness the device cannot provide.
//
// Silent in three cases, each of which is an absence of evidence rather than
// evidence of absence:
//
//   - the spec names no harness, because a caller with no basis for the claim
//     (`cloop executor test`, hub doctor's smoke run) must not have one forced
//     on it;
//   - the payload runs in a container, where the image supplies the binary;
//   - the device advertised no inventory at all, matching hasHarness in
//     pkg/executor/placement — an agent that said nothing has not said no.
func (e *Executor) checkHarness(spec executor.Spec, sandbox executor.SandboxSettings) error {
	want := strings.TrimSpace(spec.Harness)
	if want == "" || sandbox.Mode == executor.SandboxModeContainer {
		return nil
	}
	caps := e.AgentCapabilities()
	if harnessAdvertised(caps.Harnesses, want) {
		return nil
	}
	return fmt.Errorf(
		"%w: agent %s (%s) runs payloads on the device's own host and reports no %q there "+
			"(it has: %s), so `cloop run` would fail with \"executable file not found in $PATH\" "+
			"as soon as it started; install %s on the device, or switch this executor to a container "+
			"sandbox whose image carries it (Fleet → this executor → Sandbox, mode container, image "+
			"%s), or bind this project to an executor that has it",
		ErrHarnessUnavailable, e.id, e.name, want, describeHarnesses(caps.Harnesses), want, HarnessImageHint)
}

// harnessAdvertised reports whether want is in the device's inventory.
//
// Deliberately identical to hasHarness in pkg/executor/placement, including the
// "empty means yes" rule: the two decide the same thing for the same executor
// on two different paths — this one for a pinned project, that one for
// failover's candidate list — and a placement engine that would schedule work a
// dispatch then refuses is worse than either answer taken alone.
func harnessAdvertised(advertised []string, want string) bool {
	if len(advertised) == 0 {
		return true
	}
	for _, h := range advertised {
		if strings.EqualFold(strings.TrimSpace(h), want) {
			return true
		}
	}
	return false
}

// describeHarnesses renders the device's inventory for an operator.
//
// The empty case cannot be reached from checkHarness, which has already
// returned for it, but is spelled anyway: this also feeds Preflight, where an
// inventory-less device is a thing worth naming rather than an empty phrase in
// the middle of a sentence.
func describeHarnesses(h []string) string {
	trimmed := make([]string, 0, len(h))
	for _, s := range h {
		if s = strings.TrimSpace(s); s != "" {
			trimmed = append(trimmed, s)
		}
	}
	if len(trimmed) == 0 {
		return "none"
	}
	return strings.Join(trimmed, ", ")
}
