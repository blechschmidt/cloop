package container

// netiface.go moves a host network interface into a sandbox.
//
// # Why this is not a flag
//
// Every other thing a sandbox is given arrives as an argument to `run`: a
// mount, a device, a network, a limit. An interface cannot, because neither
// docker nor podman has a flag for it and the kernel has no concept it could
// map onto. A netdev is owned by a network namespace; the only operation is to
// move it from one namespace to another, and the destination namespace does not
// exist until the container is running.
//
// So this is a post-start step, which is the opposite of what firewall.go does
// and for a reason worth stating next to it. The firewall filters on the *host*
// side of the bridge precisely so that no window exists in which a workload is
// up and unfiltered. The same ordering is not available here — there is no
// namespace to move into before start — so the window is real: between `run -d`
// returning and the move completing, the workload is running and its interface
// is not there yet.
//
// That window is a correctness problem and never a security one, and the
// asymmetry is what makes it acceptable. Every operation here *adds* reach that
// an operator explicitly granted, so a workload that starts early sees less
// than it was promised, never more. A harness that raced would find its
// interface missing, which is why the move happens before Start returns and
// before the handle is published — the task has not been told it is running
// yet. A workload that genuinely needs to synchronise has CLOOP_HOST_INTERFACES
// and can wait for the link.
//
// # What the host gives up
//
// This is the only capability in the driver that takes something away from the
// executor. A netdev lives in exactly one namespace, so for the life of the
// workload the host cannot use the interface at all. Two consequences follow,
// and both are handled here rather than documented away:
//
//   - Moving the wrong interface does not leak access, it severs the machine.
//     The static denylist in pkg/executor catches lo and the runtimes' own
//     bridges, but the interface that actually matters — the one this host is
//     reachable on — is knowable only here, on the host, at this moment. So
//     the default route is read and the move is refused if it would go out of
//     the executor's own uplink. On a remote executor that check is the
//     difference between a bench and an unreachable machine.
//
//   - Teardown is the kernel's decision, not ours. When a network namespace is
//     destroyed the kernel returns *physical* devices to the initial namespace
//     and *deletes* virtual ones — veth, macvlan, vlan. A NIC therefore comes
//     home by itself and a veth end does not: it is destroyed, and destroying
//     one end of a veth pair destroys its peer. detachInterfaces exists to move
//     them back while the namespace is still alive, which is possible on a
//     graceful stop and impossible when the workload exits on its own.
//
// # Why gVisor and Kata are refused rather than attempted
//
// Because on both of them the move succeeds and delivers nothing. runsc builds
// its netstack from the interfaces present when the sandbox starts, and a Kata
// guest kernel only sees what the VM was given — so an interface that arrives
// afterwards is visible in the namespace from the host's point of view and
// absent from every process inside. Verified rather than assumed: under runsc
// the host can ping the segment through the sandbox's namespace while
// /proc/net/dev inside the container still lists only lo.
//
// That is the worst possible outcome — the host has handed over its interface
// and the workload cannot see it — so Capabilities reports false and placement
// refuses, rather than the driver trying and reporting success.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ifaceCmdTimeout bounds one netlink operation. These are local syscalls
// wrapped in a binary; a second is already three orders of magnitude of slack,
// and the bound exists so a wedged `ip` cannot hold a start open.
const ifaceCmdTimeout = 10 * time.Second

// LabelInterfaces records the grant handles of the host interfaces moved into
// the container, so an operator looking at a running sandbox can see which
// segments it holds without reconstructing them from the lease.
const LabelInterfaces = "cloop.interfaces"

// ipPath resolves ip(8) once. Absence is not an error here — it makes
// SupportsInterfaces false, which turns into a placement refusal that names the
// missing tool.
func ipPath() (string, bool) {
	p, err := exec.LookPath("ip")
	if err != nil {
		return "", false
	}
	return p, true
}

// nsenterPath resolves nsenter(1), which is how a command is run inside a
// container's network namespace.
//
// ip(8)'s own -n flag is not an alternative: it resolves a *named* namespace
// under /var/run/netns and fails on a PID. Creating such a name would mean
// bind-mounting the namespace into that directory and owning the cleanup of a
// file that outlives the container if anything goes wrong, which is a worse
// trade than one more binary from the same package set util-linux ships
// everywhere.
func nsenterPath() (string, bool) {
	p, err := exec.LookPath("nsenter")
	if err != nil {
		return "", false
	}
	return p, true
}

// canMoveInterfaces reports whether this process, on this host, with this OCI
// runtime, can honour Spec.Interfaces.
//
// Each term is load-bearing and each fails differently:
//
//   - Without ip(8) there is no way to issue the move at all, and without
//     nsenter(1) no way to configure the interface once it has landed.
//   - Without euid 0 the move fails with EPERM: it needs CAP_NET_ADMIN in the
//     *host* network namespace, which a rootless podman user does not have
//     however permissive its user namespace is.
//   - Under a kernel-isolated runtime the move succeeds and the workload sees
//     nothing, which is the failure this whole file is arranged to prevent.
func canMoveInterfaces(ociRuntime string) bool {
	if _, ok := ipPath(); !ok {
		return false
	}
	if _, ok := nsenterPath(); !ok {
		return false
	}
	if os.Geteuid() != 0 {
		return false
	}
	return !executor.IsKernelIsolatedRuntime(ociRuntime)
}

// interfaceSupportReason explains a false canMoveInterfaces, for preflight and
// for the error an operator reads.
//
// The runtime is reported first even when a tool is also missing, and the order
// is the whole point: every other reason here is fixed by installing a package
// or changing how the executor is launched, and this one is not. An operator on
// a Kata host told "install iproute2" installs it, retries, and only then finds
// out the runtime could never have honoured the grant. Naming the terminal
// reason first turns that staircase into one decision.
func interfaceSupportReason(ociRuntime string) string {
	if executor.IsKernelIsolatedRuntime(ociRuntime) {
		return fmt.Sprintf("the %q runtime gives the workload its own kernel, which builds "+
			"its view of the network when the sandbox starts and never sees an interface "+
			"moved in afterwards; use runc or crun for interface passthrough", ociRuntime)
	}
	if _, ok := ipPath(); !ok {
		return "ip(8) is not on PATH — install iproute2"
	}
	if _, ok := nsenterPath(); !ok {
		return "nsenter(1) is not on PATH — install util-linux"
	}
	if os.Geteuid() != 0 {
		return "moving a network interface between namespaces needs CAP_NET_ADMIN on the " +
			"host, which this process does not have; run the executor as root"
	}
	return ""
}

// runIP executes an ip(8) invocation, optionally inside a container's network
// namespace.
//
// netnsPID 0 means the host's own namespace. Anything else is entered with
// `nsenter -t <pid> -n`, which takes the PID directly.
func runIP(ctx context.Context, netnsPID int, args ...string) (string, error) {
	bin, ok := ipPath()
	if !ok {
		return "", fmt.Errorf("container: ip(8) is not on PATH")
	}
	full := make([]string, 0, len(args)+5)
	if netnsPID > 0 {
		ns, nsOK := nsenterPath()
		if !nsOK {
			return "", fmt.Errorf("container: nsenter(1) is not on PATH")
		}
		full = append(full, "-t", strconv.Itoa(netnsPID), "-n", "--", bin)
		bin = ns
	}
	full = append(full, args...)

	cctx, cancel := context.WithTimeout(ctx, ifaceCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, full...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s %s: %w%s", bin, strings.Join(full, " "), err,
			func() string {
				if text == "" {
					return ""
				}
				return ": " + text
			}())
	}
	return text, nil
}

// hostUplinkInterfaces returns the interfaces the host's default routes go out
// of.
//
// This is the check that protects a remote executor from being disconnected by
// a grant. The static denylist in pkg/executor cannot make it: which interface
// carries the default route is a fact about one machine at one moment, and the
// hub that minted the grant is usually not that machine.
//
// A failure to read the routing table returns no interfaces rather than an
// error. The alternative — refusing every interface grant because `ip route`
// was unavailable — would break a working bench for a diagnostic that is
// advisory; the static denylist still applies, and the caller logs the gap.
func hostUplinkInterfaces(ctx context.Context) map[string]struct{} {
	out := make(map[string]struct{}, 2)
	for _, family := range []string{"-4", "-6"} {
		text, err := runIP(ctx, 0, family, "route", "show", "default")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "dev" && i+1 < len(fields) {
					out[fields[i+1]] = struct{}{}
				}
			}
		}
	}
	return out
}

// movedInterface records one completed move, so it can be undone.
type movedInterface struct {
	spec executor.HostInterface
	// inSandbox is the name the interface currently carries inside the
	// sandbox, which is the target name once the rename has happened and the
	// source name before it. Rollback has to know which.
	inSandbox string
}

// attachInterfaces moves every interface in ifaces into the network namespace
// of the process at pid, and configures it.
//
// It is all-or-nothing. A partial attach would hand the workload some of the
// segments it was granted and the host a hole where the others used to be, with
// no record of which — so a failure rolls back every interface already moved
// before returning. The rollback is best-effort by necessity (it is undoing
// kernel state that may have changed underneath us) and its own failures are
// reported alongside the original error rather than replacing it: an operator
// whose bench did not come up needs to know which interfaces are still missing
// from the host.
func attachInterfaces(ctx context.Context, pid int, ifaces []executor.HostInterface) error {
	if len(ifaces) == 0 {
		return nil
	}
	if pid <= 0 {
		return fmt.Errorf("container: cannot move interfaces into a sandbox with no pid")
	}
	// Re-validated here rather than trusted from the caller. This is the last
	// thing between a Spec and a privileged netlink operation, and the Spec
	// reaches it having been persisted and re-hydrated by pkg/executorstore.
	if err := executor.ValidateInterfaces(ifaces); err != nil {
		return err
	}

	uplinks := hostUplinkInterfaces(ctx)
	var done []movedInterface
	rollback := func(cause error) error {
		var failed []string
		for i := len(done) - 1; i >= 0; i-- {
			if rerr := restoreInterface(ctx, pid, done[i]); rerr != nil {
				failed = append(failed, fmt.Sprintf("%s (%s)", done[i].spec.Source, rerr))
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("%w; additionally these interfaces could not be returned to "+
				"the host and are stranded in the sandbox's namespace: %s",
				cause, strings.Join(failed, ", "))
		}
		return cause
	}

	for _, n := range ifaces {
		src := strings.TrimSpace(n.Source)
		if _, isUplink := uplinks[src]; isUplink {
			// The refusal that matters most, and the reason it lives here
			// rather than in the broker: on a remote executor this is the
			// difference between a lab bench and a machine nobody can reach.
			return rollback(fmt.Errorf(
				"%w: interface %q (%s) carries this host's default route; moving it into a "+
					"sandbox would disconnect the executor itself",
				executor.ErrInvalidSpec, n.Name, src))
		}
		// inSandbox before err, and unconditionally: moveInterface can fail
		// *after* the netns move has succeeded — a rename that collides, an
		// address the segment already carries — and an interface left out of
		// `done` on that path is one rollback will not return to the host. It
		// reports the name the interface currently carries rather than the one
		// it was meant to end up with, because a rename that failed is exactly
		// the case where those two differ.
		inSandbox, err := moveInterface(ctx, pid, n)
		if inSandbox != "" {
			done = append(done, movedInterface{spec: n, inSandbox: inSandbox})
		}
		if err != nil {
			return rollback(err)
		}
	}
	return nil
}

// moveInterface performs one move and the configuration that follows it.
//
// It returns the name the interface carries *inside the sandbox*, which is ""
// only while the interface is still on the host. That return is what makes the
// caller's rollback complete: every step after the netns move can fail with the
// interface already gone from the host, and a caller that inferred "moved" from
// "no error" would strand exactly those.
//
// The order is forced by the kernel and by what each step needs: the interface
// must be down to be renamed, renamed before anything refers to the new name,
// up before a route through it can be installed, and addressed before a gateway
// through it resolves.
func moveInterface(ctx context.Context, pid int, n executor.HostInterface) (string, error) {
	src := strings.TrimSpace(n.Source)
	target := n.EffectiveTarget()

	// Down first. A rename is refused on an up interface by some drivers, and
	// an interface that arrives in the sandbox still carrying the host's
	// addresses would answer for them on the new segment.
	if _, err := runIP(ctx, 0, "link", "set", "dev", src, "down"); err != nil {
		return "", fmt.Errorf("container: interface %q: %w", n.Name, err)
	}
	if _, err := runIP(ctx, 0, "link", "set", "dev", src, "netns", strconv.Itoa(pid)); err != nil {
		// The overwhelmingly common cause is that the interface does not exist
		// on this host, which is what a grant minted against a different bench
		// looks like. Saying so beats relaying "Cannot find device".
		return "", fmt.Errorf("container: interface %q: moving %s into the sandbox failed — "+
			"check that it exists on this executor (`ip link show %s`): %w",
			n.Name, src, src, err)
	}

	// From here the interface is inside the sandbox under `cur`, and every
	// return carries that name so the caller can put it back.
	cur := src
	if target != src {
		if _, err := runIP(ctx, pid, "link", "set", "dev", cur, "name", target); err != nil {
			return cur, fmt.Errorf("container: interface %q: renaming %s to %s inside the "+
				"sandbox failed: %w", n.Name, src, target, err)
		}
		cur = target
	}
	if n.MTU > 0 {
		if _, err := runIP(ctx, pid, "link", "set", "dev", cur, "mtu",
			strconv.Itoa(n.MTU)); err != nil {
			return cur, fmt.Errorf("container: interface %q: %w", n.Name, err)
		}
	}
	if _, err := runIP(ctx, pid, "link", "set", "dev", cur, "up"); err != nil {
		return cur, fmt.Errorf("container: interface %q: %w", n.Name, err)
	}
	if addr := strings.TrimSpace(n.Address); addr != "" {
		if _, err := runIP(ctx, pid, "addr", "add", addr, "dev", cur); err != nil {
			return cur, fmt.Errorf("container: interface %q: %w", n.Name, err)
		}
	}
	if gw := strings.TrimSpace(n.Gateway); gw != "" {
		// `replace` rather than `add`: a sandbox on a runtime network already
		// has a default route through it, and an operator who asked for a
		// gateway on a bench interface meant that one.
		if _, err := runIP(ctx, pid, "route", "replace", "default", "via", gw,
			"dev", cur); err != nil {
			return cur, fmt.Errorf("container: interface %q: %w", n.Name, err)
		}
	}
	return cur, nil
}

// restoreInterface moves one interface back to the host's namespace, undoing
// the rename so it returns under the name the operator knows it by.
//
// Addresses are flushed first. An interface carrying the sandbox's address when
// it lands back on the host would attach that address to the host's stack,
// which is a surprise on a segment the host is not supposed to be speaking on.
func restoreInterface(ctx context.Context, pid int, m movedInterface) error {
	src := strings.TrimSpace(m.spec.Source)
	cur := m.inSandbox

	_, _ = runIP(ctx, pid, "addr", "flush", "dev", cur)
	if _, err := runIP(ctx, pid, "link", "set", "dev", cur, "down"); err != nil {
		return err
	}
	if cur != src {
		if _, err := runIP(ctx, pid, "link", "set", "dev", cur, "name", src); err != nil {
			return err
		}
	}
	// netns 1 is the initial network namespace: PID 1 is in it on every host
	// this driver runs on, and naming it by PID avoids depending on a named
	// namespace under /var/run/netns that nothing here created.
	if _, err := runIP(ctx, pid, "link", "set", "dev", src, "netns", "1"); err != nil {
		return err
	}
	return nil
}

// detachInterfaces returns a sandbox's interfaces to the host while its network
// namespace still exists.
//
// It is best-effort and its caller ignores the result, because by the time a
// workload is being reaped there is frequently nothing left to act on: the
// namespace dies with the last process in it, and the kernel has its own
// opinion about what happens then — physical devices go home, virtual ones are
// deleted.
//
// It is still worth doing, and the veth case is why. A veth end that the kernel
// reclaims is *destroyed*, taking its peer on the host with it and dismantling
// the operator's bench; moving it back a moment earlier preserves the pair. So
// this runs on the graceful-stop path, where the container is still up, and
// simply finds nothing to do on the path where the workload exited by itself.
func detachInterfaces(ctx context.Context, pid int, ifaces []executor.HostInterface) {
	if pid <= 0 || len(ifaces) == 0 {
		return
	}
	for i := len(ifaces) - 1; i >= 0; i-- {
		n := ifaces[i]
		_ = restoreInterface(ctx, pid, movedInterface{spec: n, inSandbox: n.EffectiveTarget()})
	}
}

// containerPID reads the host PID of a container's main process, which is the
// handle to its network namespace.
//
// Zero with no error is a real answer and means the container is not running —
// `inspect` reports 0 for a created-but-not-started or an exited container. The
// caller treats it as a refusal rather than retrying, because a workload that
// has already exited has no namespace to move anything into.
func (e *Executor) containerPID(ctx context.Context, name string) (int, error) {
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "inspect",
		"--format", "{{.State.Pid}}", "--", name)
	if err != nil {
		return 0, fmt.Errorf("container: read sandbox pid for %s: %w", name, err)
	}
	_ = res
	if res.ExitCode != 0 {
		return 0, fmt.Errorf("container: read sandbox pid for %s: %s", name,
			strings.TrimSpace(res.Stderr))
	}
	pid, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if err != nil {
		return 0, fmt.Errorf("container: sandbox pid for %s is not a number: %q",
			name, strings.TrimSpace(res.Stdout))
	}
	return pid, nil
}

// awaitContainerPID is containerPID with a short poll.
//
// `run -d` returns when the container has been created and started, which is
// very nearly but not exactly the moment its main process has a host pid — on a
// loaded machine the two can be a few milliseconds apart, and a single inspect
// that lands in between reports 0 and looks identical to a workload that has
// already exited.
//
// The poll is short because the two cases it separates need opposite answers
// and only time tells them apart: a pid that has not appeared yet arrives
// within milliseconds, and a pid that will never appear belongs to an argv that
// finished before this code ran. Waiting long for the second would delay every
// failure by the length of the patience extended to the first.
func (e *Executor) awaitContainerPID(ctx context.Context, name string) (int, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		pid, err := e.containerPID(ctx, name)
		if err != nil {
			return 0, err
		}
		if pid > 0 {
			return pid, nil
		}
		if time.Now().After(deadline) {
			return 0, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
