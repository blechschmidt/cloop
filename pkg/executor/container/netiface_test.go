package container

// Real-runtime tests for Spec.Interfaces (Task 20329): L2 passthrough of a host
// network interface into a sandbox.
//
// These run against a real kernel, a real bridge and a real container, because
// nothing smaller can answer the question that matters. The argv is not the
// guarantee — there is no argv, the runtimes have no flag for this — and
// neither is the netlink call succeeding. The guarantee is that a process
// *inside* the sandbox sees the link and can speak Ethernet on the segment it
// is attached to, and the difference between that and "the move returned 0" is
// exactly the gVisor case this feature had to refuse: under runsc the host can
// ping the segment through the sandbox's namespace while /proc/net/dev inside
// the container still lists only lo.
//
// The fixture is the one an operator actually builds, which is why the test
// builds it rather than mocking it:
//
//	docker network cloop-iftest   (its own bridge, its own subnet)
//	  ├── a peer container        — stands in for the board under test
//	  └── br-<id>
//	        └── cloop-ifp<pid>    — one end of a veth pair, on the bridge
//	              ↕
//	            cloop-ift<pid>    — the other end, granted to the sandbox
//
// Pinging the peer from inside the sandbox then proves the whole path: the
// interface moved, it came up, it was addressed, and frames reach a host that
// is only reachable at layer 2.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ifTestSubnet and friends live in 172.31.x to stay clear of docker's own
// default pools (172.17-172.20) on a developer machine that already has
// networks.
//
// The third octet is derived from the pid for the reason the names are: two
// concurrent runs asking docker for the same subnet collide in its address
// pool, and the loser skips with a message about the subnet being in use.
func ifTestSubnet() (cidr, peerIP, sandboxCIDR string) {
	// 1..250, so the octet is always a legal, non-reserved value.
	o := os.Getpid()%250 + 1
	return fmt.Sprintf("172.31.%d.0/24", o),
		fmt.Sprintf("172.31.%d.2", o),
		fmt.Sprintf("172.31.%d.200/24", o)
}

// requireDockerRuntime resolves docker specifically.
//
// The scenario is stated in terms of a docker network and the fixture derives
// the bridge from docker's br-<id> convention, so taking whatever DetectRuntime
// prefers would silently skip on every host that also has podman — which is
// every host this suite runs on.
func requireDockerRuntime(t *testing.T) Runtime {
	t.Helper()
	rt, err := DetectRuntime(RuntimeDocker)
	if err != nil {
		t.Skipf("docker is not available (%v); the L2 fixture needs its bridge naming", err)
	}
	return rt
}

// requireInterfaceMove skips unless this host can actually move a netdev. The
// three reasons are the three terms of canMoveInterfaces, and each of them is a
// legitimate developer machine rather than a broken one.
func requireInterfaceMove(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("moves a network interface and runs a container; skipped under -short")
	}
	if os.Geteuid() != 0 {
		t.Skip("moving an interface between namespaces needs CAP_NET_ADMIN on the host")
	}
	if _, ok := ipPath(); !ok {
		t.Skip("ip(8) is not on PATH")
	}
}

// ifTestNames derives per-process names for everything the fixture creates, so
// two test binaries running concurrently on one machine cannot collide.
//
// Every name, not just the netdevs: a fixed network name looks safe because
// each run creates and destroys its own, and is not — the second run's
// teardown removes the first run's network out from under it, and the failure
// surfaces minutes later as a peer container that cannot be started. IFNAMSIZ
// caps the interface names at 15 characters, which is why those stems are this
// short.
func ifTestNames() (sandboxEnd, bridgeEnd, network, peer string) {
	pid := os.Getpid() % 100000
	return fmt.Sprintf("clt%d", pid), fmt.Sprintf("clp%d", pid),
		fmt.Sprintf("cloop-iftest-%d", pid), fmt.Sprintf("cloop-iftest-peer-%d", pid)
}

// hostIP runs an ip(8) command on the host and fails the test on error.
func hostIP(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runIP(context.Background(), 0, args...)
	if err != nil {
		t.Fatalf("ip %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// l2Fixture is the bench: a bridge network, a peer on it, and a veth pair with
// one end plugged into the bridge and the other waiting to be granted.
type l2Fixture struct {
	network    string
	bridge     string
	peer       string
	sandboxEnd string
	bridgeEnd  string
	// peerIP is the address of the board-under-test stand-in, and sandboxCIDR
	// the address the grant configures on the far end. Both are per-process
	// for the reason the names are.
	peerIP      string
	sandboxCIDR string
}

// newL2Fixture builds the bench and registers its teardown.
//
// rt must be docker (see requireDockerRuntime): the bridge name is derived from
// docker's br-<id> convention, and podman keeps its equivalent under a
// different key in a differently shaped inspect output. Guessing at a name
// would create a veth attached to nothing, which fails as a missing peer rather
// than as a missing bridge.
func newL2Fixture(t *testing.T, rt Runtime) *l2Fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	f := &l2Fixture{}
	f.sandboxEnd, f.bridgeEnd, f.network, f.peer = ifTestNames()
	subnet, peerIP, sandboxCIDR := ifTestSubnet()
	f.peerIP, f.sandboxCIDR = peerIP, sandboxCIDR

	// Leftovers from an interrupted run would make every assertion below fail
	// for the wrong reason.
	f.destroy()
	t.Cleanup(f.destroy)

	res, err := runCLI(ctx, rt, nil, "network", "create", "--driver", "bridge",
		"--subnet", subnet, f.network)
	if err != nil || res.ExitCode != 0 {
		t.Skipf("could not create the test network (%v %s); the subnet may be in use",
			err, strings.TrimSpace(res.Stderr))
	}
	idRes, err := runCLI(ctx, rt, nil, "network", "inspect", "-f", "{{.Id}}", f.network)
	if err != nil || idRes.ExitCode != 0 {
		t.Fatalf("inspect network: %v %s", err, idRes.Stderr)
	}
	id := strings.TrimSpace(idRes.Stdout)
	if len(id) < 12 {
		t.Fatalf("network id %q is too short to derive a bridge name from", id)
	}
	f.bridge = "br-" + id[:12]
	if _, err := runIP(ctx, 0, "link", "show", f.bridge); err != nil {
		t.Skipf("bridge %s is not present (%v); this docker may not use the br-<id> convention",
			f.bridge, err)
	}

	// The peer holds the far end of the segment. `sleep` rather than a server
	// because the assertion is reachability at L2, and ICMP needs nothing
	// listening.
	peerRes, err := runCLI(ctx, rt, nil, "run", "-d", "--name", f.peer,
		"--network", f.network, "--ip", f.peerIP, ifTestImage(), "sleep", "600")
	if err != nil || peerRes.ExitCode != 0 {
		t.Skipf("could not start the peer container: %v %s", err, strings.TrimSpace(peerRes.Stderr))
	}

	// The veth pair. One end joins the bridge — which is what puts the sandbox
	// on the same L2 segment as the peer — and the other is what the grant
	// hands over.
	hostIP(t, "link", "add", f.sandboxEnd, "type", "veth", "peer", "name", f.bridgeEnd)
	hostIP(t, "link", "set", f.bridgeEnd, "master", f.bridge)
	hostIP(t, "link", "set", f.bridgeEnd, "up")
	hostIP(t, "link", "set", f.sandboxEnd, "up")
	return f
}

func (f *l2Fixture) destroy() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rt, err := DetectRuntime(RuntimeDocker)
	if err == nil {
		_, _ = runCLI(ctx, rt, nil, "rm", "-f", f.peer)
	}
	// Deleting either end takes the pair with it, and the end that matters may
	// be in a namespace that is already gone — so both are attempted and
	// neither failure is interesting.
	_, _ = runIP(ctx, 0, "link", "del", f.sandboxEnd)
	_, _ = runIP(ctx, 0, "link", "del", f.bridgeEnd)
	if err == nil {
		_, _ = runCLI(ctx, rt, nil, "network", "rm", f.network)
	}
}

// ifTestImage is the sandbox image. It needs busybox's ip and ping, which is
// what makes the assertion about what the *workload* sees rather than what the
// namespace holds.
func ifTestImage() string {
	if v := strings.TrimSpace(os.Getenv(testImageEnv)); v != "" {
		return v
	}
	return "alpine:3.20"
}

// TestInterfaceReachesTheSandboxAtLayer2 is the end-to-end proof: a veth end on
// the host becomes a working link inside an isolated container, on the same L2
// segment as a peer the sandbox has no route to.
func TestInterfaceReachesTheSandboxAtLayer2(t *testing.T) {
	requireInterfaceMove(t)
	rt := requireDockerRuntime(t)
	image := requireImage(t, rt, ifTestImage())
	f := newL2Fixture(t, rt)
	ex := newTestExecutor(t, image, func(o *Options) { o.Runtime = RuntimeDocker })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, err := executor.Run(ctx, ex, executor.Spec{
		WorkDir: t.TempDir(),
		// The wait is the contract, not a workaround for a flaky test. The
		// move happens after `run -d` returns — there is no namespace to move
		// into before that — so a workload granted an interface waits for the
		// link named by $CLOOP_HOST_INTERFACES to appear. Three seconds is a
		// tight enough bound that a regression which never attaches still
		// fails here rather than hanging.
		//
		// Then three assertions in one line, so a failure says which part of
		// the path broke: the link is present under the *granted* name, it
		// carries the granted address, and a frame reaches the peer.
		Argv: []string{"/bin/sh", "-c",
			"i=0; while [ ! -e /sys/class/net/eth1 ] && [ $i -lt 60 ]; do i=$((i+1)); sleep 0.05; done; " +
				// `ip addr show`, not `ip -br addr show`: busybox's ip is a
				// reduced applet with no -br, and the sandbox image is
				// whatever the bench runs rather than a full iproute2.
				"echo waited=$i; ip addr show eth1 && ping -c 2 -W 3 " + f.peerIP +
				" && echo L2_OK"},
		Interfaces: []executor.HostInterface{{
			Name:    "dut",
			Source:  f.sandboxEnd,
			Target:  "eth1",
			Address: f.sandboxCIDR,
		}},
	})
	out := string(res.Output)
	if err != nil {
		t.Fatalf("running with a granted interface: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "L2_OK") {
		t.Fatalf("the sandbox could not reach %s over the granted interface; output:\n%s",
			f.peerIP, out)
	}
	// The rename is part of the contract: a project told it has eth1 must find
	// it there, whatever the bench calls the netdev.
	if !strings.Contains(out, "eth1") {
		t.Errorf("output does not show the interface under its granted name eth1:\n%s", out)
	}
	if addr, _, _ := strings.Cut(f.sandboxCIDR, "/"); !strings.Contains(out, addr) {
		t.Errorf("output does not show the granted address %s on the interface:\n%s", addr, out)
	}
	// The link must be there essentially at once. Without this the test would
	// also pass against a driver that attached seconds late, which for a bench
	// is the difference between a working tool and a flaky one.
	if strings.Contains(out, "waited=60") {
		t.Errorf("the interface took the whole 3s budget to appear:\n%s", out)
	}
}

// TestInterfaceAbsentWithoutAGrant is the control. Without it every assertion
// above could be satisfied by a sandbox that happened to have a second link,
// and the test would prove nothing about the grant.
func TestInterfaceAbsentWithoutAGrant(t *testing.T) {
	requireInterfaceMove(t)
	rt := requireDockerRuntime(t)
	image := requireImage(t, rt, ifTestImage())
	f := newL2Fixture(t, rt)
	ex := newTestExecutor(t, image, func(o *Options) { o.Runtime = RuntimeDocker })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, _ := executor.Run(ctx, ex, executor.Spec{
		WorkDir: t.TempDir(),
		Argv: []string{"/bin/sh", "-c",
			"ip link show eth1 2>&1 || true; ping -c 1 -W 2 " + f.peerIP + " 2>&1 || true"},
	})
	out := string(res.Output)
	if strings.Contains(out, "L2_OK") {
		t.Fatal("the control sandbox reported success, which means the assertion is not " +
			"about the grant")
	}
	if strings.Contains(out, "2 packets received") || strings.Contains(out, "1 packets received") {
		t.Fatalf("a sandbox with no interface grant reached the L2 peer, so the segment is "+
			"routable and the positive test proves nothing:\n%s", out)
	}
}

// TestInterfaceMoveRefusesTheHostUplink is the check that protects the machine.
//
// Every other refusal in this feature prevents a sandbox from getting something
// it should not have. This one prevents the executor from losing something it
// needs: moving the interface the default route goes out of would disconnect
// the host, and on a remote bench that means losing the machine entirely.
func TestInterfaceMoveRefusesTheHostUplink(t *testing.T) {
	requireInterfaceMove(t)
	uplinks := hostUplinkInterfaces(context.Background())
	if len(uplinks) == 0 {
		t.Skip("this host has no default route, so there is no uplink to protect")
	}
	var uplink string
	for name := range uplinks {
		uplink = name
		break
	}

	// Deliberately not routed through Start: the point is the guard, and
	// standing up a container to reach it would risk the very move the guard
	// exists to prevent if the guard were broken. attachInterfaces refuses
	// before it touches netlink.
	err := attachInterfaces(context.Background(), os.Getpid(), []executor.HostInterface{{
		Name:   "uplink",
		Source: uplink,
		Target: "eth9",
	}})
	if err == nil {
		t.Fatalf("moving the host's uplink %s was permitted; this host may now be "+
			"disconnected", uplink)
	}
	if !strings.Contains(err.Error(), "default route") {
		t.Errorf("refusal %q does not explain that %s carries the default route", err, uplink)
	}
	// And the interface is still here, which is the assertion that actually
	// matters: a guard that refused after moving would have failed this.
	if _, lerr := runIP(context.Background(), 0, "link", "show", uplink); lerr != nil {
		t.Fatalf("the host's uplink %s is gone after a refused move: %v", uplink, lerr)
	}
}

// TestInterfaceReturnsToTheHostOnStop covers the teardown asymmetry that makes
// a veth bench fragile.
//
// The kernel returns a *physical* device to the initial namespace when a
// namespace dies and *deletes* a virtual one — so a veth end reclaimed by the
// kernel is destroyed, taking its peer on the host with it and dismantling the
// operator's bridge wiring. Signal moves interfaces back while the container is
// still up, which is the only moment at which that is possible.
func TestInterfaceReturnsToTheHostOnStop(t *testing.T) {
	requireInterfaceMove(t)
	rt := requireDockerRuntime(t)
	image := requireImage(t, rt, ifTestImage())
	f := newL2Fixture(t, rt)
	ex := newTestExecutor(t, image, func(o *Options) { o.Runtime = RuntimeDocker })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	h, err := ex.Start(ctx, executor.Spec{
		WorkDir:    t.TempDir(),
		Argv:       []string{"sleep", "120"},
		Interfaces: []executor.HostInterface{{Name: "dut", Source: f.sandboxEnd, Target: "eth1"}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// While it runs, the host must NOT have the interface: that is what "moved"
	// means, and a test that skipped this could pass against a driver that
	// copied nothing.
	if _, lerr := runIP(ctx, 0, "link", "show", f.sandboxEnd); lerr == nil {
		t.Errorf("%s is still in the host's namespace while the sandbox holds it, so it "+
			"was never moved", f.sandboxEnd)
	}

	if serr := ex.Signal(ctx, h.ID, executor.SignalTerminate); serr != nil {
		t.Fatalf("Signal: %v", serr)
	}

	// And now it must be back, under its original name.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, lerr := runIP(ctx, 0, "link", "show", f.sandboxEnd); lerr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not return to the host after a graceful stop; a veth bench "+
				"would have to be rebuilt after every task", f.sandboxEnd)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// The peer end surviving is the point: deleting one end of a veth pair
	// deletes both, so this is what proves the operator's bridge wiring is
	// intact rather than merely that a name reappeared.
	if _, lerr := runIP(ctx, 0, "link", "show", f.bridgeEnd); lerr != nil {
		t.Errorf("the bridge-side end %s was destroyed with the sandbox, so the pair is "+
			"gone: %v", f.bridgeEnd, lerr)
	}
}

// TestCanMoveInterfacesRefusesKernelIsolatedRuntimes pins the refusal the
// gVisor finding produced. It needs no container: the question is about the
// runtime's kernel, and answering it by running one would mean shipping a
// sandbox with no wire in it to find out.
func TestCanMoveInterfacesRefusesKernelIsolatedRuntimes(t *testing.T) {
	for _, rt := range []string{"runsc", "gvisor", "runsc-kvm", "kata", "kata-qemu"} {
		if canMoveInterfaces(rt) {
			t.Errorf("canMoveInterfaces(%q) = true; on that runtime the move succeeds and "+
				"the workload still sees no link", rt)
		}
		if reason := interfaceSupportReason(rt); !strings.Contains(reason, "own kernel") {
			t.Errorf("interfaceSupportReason(%q) = %q, want an explanation naming the "+
				"runtime's kernel", rt, reason)
		}
	}
}

// TestInterfaceSupportIsAdvertisedHonestly keeps Capabilities and the attach
// path from disagreeing. A driver that advertised the capability and then
// refused at attach would place tasks it cannot run.
func TestInterfaceSupportIsAdvertisedHonestly(t *testing.T) {
	rt := requireRuntime(t)
	ex := newTestExecutor(t, requireImage(t, rt, ifTestImage()), nil)
	want := canMoveInterfaces("")
	if got := ex.Capabilities().SupportsInterfaces; got != want {
		t.Fatalf("Capabilities().SupportsInterfaces = %v, want %v", got, want)
	}
	if !want && interfaceSupportReason("") == "" {
		t.Error("the capability is false but no reason is given, so an operator reading a " +
			"placement refusal would learn nothing")
	}
	if _, err := exec.LookPath("ip"); err == nil && os.Geteuid() == 0 && !want {
		t.Error("ip(8) is present and this process is root under a host-kernel runtime, " +
			"yet the capability is false")
	}
}

// TestInterfaceRollbackReturnsAPartiallyConfiguredInterface covers the failure
// that is invisible until it strands hardware.
//
// Every step after the netns move can fail with the interface already gone from
// the host: a rename that collides with a link the sandbox already has, an
// address the segment will not take. A rollback that inferred "was moved" from
// "returned no error" would leave exactly those on the far side of a namespace
// that is about to be destroyed, and the host would simply be missing an
// interface with nothing to say why.
//
// The forced failure is a rename onto "lo", which exists in every namespace and
// so is guaranteed to collide — after the move has already happened.
func TestInterfaceRollbackReturnsAPartiallyConfiguredInterface(t *testing.T) {
	requireInterfaceMove(t)
	rt := requireDockerRuntime(t)
	image := requireImage(t, rt, ifTestImage())
	f := newL2Fixture(t, rt)
	ex := newTestExecutor(t, image, func(o *Options) { o.Runtime = RuntimeDocker })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Started by hand rather than through Start, because Start would refuse the
	// spec at validation: ValidateHostInterface rejects a target of "lo", which
	// is the point — this exercises the driver's own recovery, below the layer
	// that would normally have caught it.
	h, err := ex.Start(ctx, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"sleep", "60"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(context.Background(), h.ID, executor.SignalKill) })

	pid, err := ex.awaitContainerPID(ctx, ex.handles[h.ID].name)
	if err != nil || pid <= 0 {
		t.Fatalf("sandbox pid: %v (%d)", err, pid)
	}

	aerr := attachInterfaces(ctx, pid, []executor.HostInterface{
		{Name: "dut", Source: f.sandboxEnd, Target: "lo"},
	})
	if aerr == nil {
		t.Fatal("renaming a moved interface onto the sandbox's loopback was reported as " +
			"success")
	}
	if strings.Contains(aerr.Error(), "stranded") {
		t.Errorf("rollback could not return the interface: %v", aerr)
	}

	// The assertion that matters: the host has it back, so the bench is intact.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, lerr := runIP(ctx, 0, "link", "show", f.sandboxEnd); lerr == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not returned to the host after a failed attach; it is stranded "+
				"in the sandbox's namespace and will be destroyed with it", f.sandboxEnd)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
