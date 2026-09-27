// Package caps keeps a cloop process's Linux capabilities where they belong:
// with the process itself, and with the one program it starts that needs one.
//
// The executor agent is installed holding CAP_NET_ADMIN (Task 20352), because
// installing a sandbox's firewall means loading an nftables ruleset and nft(8)
// cannot do that without it. systemd can only hand a capability to a service
// that runs as an ordinary user through the *ambient* set, and the ambient set
// is inherited: left alone, every program the agent starts would hold the
// capability too — the harness, its shell, git and the hooks git runs from a
// workload's own repository. A host-mode workload could then rewrite the host's
// packet filter, including the rules that confine its neighbours' sandboxes.
//
// So the capability stops at the agent. Confine clears the ambient and
// inheritable sets on every thread before the process starts anything, which
// leaves the agent holding CAP_NET_ADMIN (permitted and effective) and every
// child holding nothing. Grant then hands it back to exactly one kind of child:
// the nft(8) invocations in pkg/netfilter.
//
// Clearing has to reach every thread, because Linux keeps capabilities per
// thread and Go forks from whichever thread a goroutine happens to be on. A
// build without cgo does it with syscall.AllThreadsSyscall. A build with cgo
// cannot — the runtime refuses, since it cannot see threads C code started — so
// there a C constructor clears both sets before the Go runtime has started its
// first thread, and every thread inherits the result. Both paths are exercised
// by caps_linux_test.go against a process started with a real ambient set.
package caps

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Cap is a Linux capability number, as capabilities(7) numbers them.
type Cap uint

// NetAdmin is CAP_NET_ADMIN: what nft(8) needs to read or load a ruleset.
const NetAdmin Cap = 12

// String names the capability the way systemd and capabilities(7) do.
func (c Cap) String() string {
	if c == NetAdmin {
		return "CAP_NET_ADMIN"
	}
	return "capability " + strconv.FormatUint(uint64(c), 10)
}

// Confine stops this process's capabilities from flowing to the programs it
// starts. It clears the ambient and inheritable sets on every thread and
// leaves the permitted and effective sets alone, so the process keeps whatever
// it holds and can still Grant a capability to a particular child.
//
// It is a no-op for a process that holds nothing to pass on, which is every
// ordinary invocation of cloop, and it is safe to call more than once. It
// returns an error only when the process does hold something inheritable and
// could not clear it — which means its children would inherit it.
func Confine() error { return confine() }

// Holds reports whether this process holds c in its permitted set and may
// therefore hand it to a child. Root is not special-cased: a root process that
// has dropped c does not hold it.
func Holds(c Cap) bool { return holds(c) }

// Grant arranges for cmd, once started, to hold c — when this process holds c
// and is not root. A root child needs no grant: it gets every capability in its
// bounding set at exec anyway. Grant reports whether it asked for one.
//
// It must be called before cmd starts. A child whose exec cannot honour the
// grant fails to start rather than running without the capability, so a caller
// sees the failure at the point it matters.
func Grant(cmd *exec.Cmd, c Cap) bool { return grant(cmd, c) }

// Sets is one thread's capability sets, as /proc reports them.
type Sets struct {
	Inheritable, Permitted, Effective, Bounding, Ambient uint64
}

// Has reports whether c is in set.
func Has(set uint64, c Cap) bool { return c < 64 && set&(1<<uint(c)) != 0 }

// ParseStatus reads the Cap* lines of a /proc/<pid>/status file.
func ParseStatus(status string) (Sets, error) {
	var s Sets
	seen := 0
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		var dst *uint64
		switch key {
		case "CapInh":
			dst = &s.Inheritable
		case "CapPrm":
			dst = &s.Permitted
		case "CapEff":
			dst = &s.Effective
		case "CapBnd":
			dst = &s.Bounding
		case "CapAmb":
			dst = &s.Ambient
		default:
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return Sets{}, fmt.Errorf("caps: %s %q is not a capability mask: %w", key, strings.TrimSpace(value), err)
		}
		*dst = n
		seen++
	}
	// CapAmb arrived in Linux 4.3; a kernel without it has no ambient set to
	// clear, so four lines are a complete answer and fewer are not.
	if seen < 4 {
		return Sets{}, fmt.Errorf("caps: no capability sets in the status file")
	}
	return s, nil
}
