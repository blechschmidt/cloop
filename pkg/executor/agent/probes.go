package agent

// probes.go holds the capability probes that have to run a program: whether
// nft(8) can install a filter, and which OCI runtimes the container engine has
// registered (Task 20345). They live apart from Detect so that only the agent
// runs them — every test that builds capabilities would otherwise shell out to
// nft and docker on whatever machine it happens to run on.

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// probeTimeout bounds each probe. Both are a local syscall or a local API call
// on a healthy machine; a hello must not wait on one that is not.
const probeTimeout = 5 * time.Second

// probePacketFilter reports whether this process can install a host-side
// nftables ruleset, and the reason when it cannot.
//
// The reason is the point. The two failures an operator meets have different
// fixes — nftables not installed, or the agent's service unit withholding
// CAP_NET_ADMIN and AF_NETLINK, which the hardened default does — and the
// dashboard shows this string beside the firewall it cannot apply.
func probePacketFilter() (bool, string) {
	applier, err := netfilter.NewApplier()
	if err != nil {
		return false, err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	if err := applier.Available(ctx); err != nil {
		return false, err.Error() + " — install the agent with --packet-filter, or add a drop-in granting " +
			"AmbientCapabilities=CAP_NET_ADMIN and AF_NETLINK in RestrictAddressFamilies"
	}
	return true, ""
}

// probeOCIRuntimes lists the runtimes an engine can hand a container to.
//
// docker reports its registered table exactly. podman and nerdctl do not have
// one cheap answer, so for them this reports the runtime binaries on PATH that
// an engine would find by name — a hint for the form, never a gate: the
// runtime field stays free text, and the device refuses a name it cannot run.
func probeOCIRuntimes(engine string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	var out []string
	if engine == "docker" {
		raw, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .Runtimes}}").Output()
		if err == nil {
			var table map[string]json.RawMessage
			if json.Unmarshal(raw, &table) == nil {
				for name := range table {
					if executor.ValidateRuntimeName(name) == nil {
						out = append(out, name)
					}
				}
			}
		}
	}
	if len(out) == 0 {
		for _, name := range []string{"runc", "crun", "runsc", "kata-runtime", "youki"} {
			if _, err := exec.LookPath(name); err == nil {
				out = append(out, strings.TrimSuffix(name, "-runtime"))
			}
		}
	}
	sort.Strings(out)
	return out
}
