// Package soak drives a multi-tenant hub under sustained concurrent load and
// fails on the three defects that only appear there: cross-tenant bleed,
// leaked resources, and unbounded growth.
//
// # Why a separate suite
//
// tests/flagship proves one task completes one circuit. tests/security
// machine-checks the guarantees statically. Neither runs anything twice at
// once, and every isolation defect this project has actually shipped was a
// concurrency defect: the cross-tenant live log leak of Task 20189 came from
// the broadcast path walking every connected client, and the pkg/ui WebSocket
// tests are known to flake under load precisely because the concurrent paths
// are the ones nothing exercises on purpose.
//
// A single-task test cannot see any of that. Bleed needs a second tenant
// producing output at the same moment. A leak needs enough repetitions that
// one-per-task growth is distinguishable from a fixed cost. Superlinear growth
// needs at least two measurement intervals. So this suite exists to supply the
// one thing the others structurally cannot: simultaneity.
//
// # What it actually runs
//
// A real hub, in-process, bound to the real container executor, with real
// project-scoped API tokens as the tenant boundary. Every task is a real
// container dispatched through POST /api/run, streamed back through the real
// broadcast path, and observed by real WebSocket subscribers. The only
// stand-in is the workload itself: instead of an agent harness it runs a
// script that echoes the canary planted in its own project directory. That
// substitution is deliberate and is the point — the suite is testing the hub's
// isolation of concurrent workloads, not an agent's behaviour, and an
// unpredictable workload would make bleed undetectable.
//
// # Running it
//
//	CLOOP_SOAK=1 go test -race -timeout 30m ./tests/soak/
//
// It is opt-in because it drives the container runtime and takes minutes. CI
// runs it as its own job (see .github/workflows/ci.yml), the way the eval
// stack job landed in Task 20259.
package soak

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// enableEnv opts the suite in. Unset means skip: this drives the container
// runtime, writes to machine-global paths, and takes minutes, none of which
// belongs in the default `go test ./...` a developer runs on every save.
const enableEnv = "CLOOP_SOAK"

// keepEnv leaves the soak root and any surviving containers in place for
// post-mortem. Set it when a failure names something you want to go look at.
const keepEnv = "CLOOP_SOAK_KEEP"

// imageEnv overrides the sandbox image. The default is built by the suite
// itself (see ensureImage), because the workload has to cooperate — it must
// read the canary out of its own workspace — and no published image does.
const imageEnv = "CLOOP_SOAK_IMAGE"

// runtimeEnv pins the container runtime, matching the executor's own
// "docker" | "podman" vocabulary. Empty auto-detects.
const runtimeEnv = "CLOOP_SOAK_RUNTIME"

var (
	// flagTasks is the total number of container dispatches the soak drives.
	// The default is the task's ~20: enough repetitions that a one-per-task
	// leak is unambiguous against the fixed cost of booting a hub, and few
	// enough that the suite finishes in a CI job rather than a lunch break.
	flagTasks = flag.Int("soak.tasks", envInt("CLOOP_SOAK_TASKS", 20),
		"total container dispatches to drive through the hub")

	// flagTenants is how many distinct identities compete. Three is the
	// smallest number that distinguishes "A leaked to B" from "everyone sees
	// everything": with two tenants a broadcast bug and a routing bug look
	// identical.
	flagTenants = flag.Int("soak.tenants", envInt("CLOOP_SOAK_TENANTS", 3),
		"distinct tenant identities, each owning its own projects")

	// flagProjectsPerTenant sets how many projects each tenant owns. It is
	// what actually sets the concurrency ceiling: the hub refuses a second
	// simultaneous run on one project (409, by design), so the number of
	// projects is the number of containers that can be in flight at once.
	// Two per tenant also proves a tenant's own projects stay distinct from
	// each other, not just from other tenants'.
	flagProjectsPerTenant = flag.Int("soak.projects-per-tenant", envInt("CLOOP_SOAK_PROJECTS_PER_TENANT", 2),
		"projects each tenant owns; tenants*projects is the concurrency ceiling")
)

func envInt(key string, def int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// TestMain isolates $HOME before anything runs.
//
// Required, not optional: the hub reads the project registry from
// ~/.cloop/projects.json on every allProjectEntries() rebuild, which is the
// index space ?project_idx= maps through. Without isolation this suite would
// both read the developer's real projects into its tenant index — silently
// changing which project a tenant's index 0 resolves to — and write its own
// throwaway ones back out. tests/hermetic enforces this.
func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }

// gate skips unless the suite is opted in and the machine can actually run it.
//
// Each condition is reported separately. "soak skipped" with no reason is a
// suite that silently stopped covering anything, which is the failure mode
// this whole file exists to avoid.
func gate(t *testing.T) {
	t.Helper()
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this drives the container runtime and takes minutes", enableEnv)
	}
	if *flagTenants < 2 {
		t.Fatalf("-soak.tenants=%d cannot detect cross-tenant bleed; need at least 2", *flagTenants)
	}
	if *flagProjectsPerTenant < 1 {
		t.Fatalf("-soak.projects-per-tenant=%d leaves tenants with nothing to run", *flagProjectsPerTenant)
	}
	if want := *flagTenants * *flagProjectsPerTenant; *flagTasks < want {
		t.Fatalf("-soak.tasks=%d is below the %d projects, so some project never runs "+
			"and its subscriber proves nothing", *flagTasks, want)
	}
}

// detectRuntime returns the container CLI to drive, honouring runtimeEnv.
//
// It asks the binary whether its daemon answers rather than only whether it is
// on PATH: a docker client with no reachable daemon is the common broken state
// on a CI runner, and it fails at the first dispatch — minutes in, as an
// unexplained executor error — instead of here, as a skip that names the cause.
func detectRuntime(t *testing.T) string {
	t.Helper()
	candidates := []string{"podman", "docker"}
	if pinned := os.Getenv(runtimeEnv); pinned != "" {
		candidates = []string{pinned}
	}
	var why string
	for _, name := range candidates {
		bin, err := exec.LookPath(name)
		if err != nil {
			why += fmt.Sprintf("%s: not on PATH; ", name)
			continue
		}
		out, err := exec.Command(bin, "info", "--format", "{{.ServerVersion}}").CombinedOutput()
		if err != nil {
			why += fmt.Sprintf("%s: daemon unreachable (%v); ", name, err)
			continue
		}
		t.Logf("container runtime: %s %s", name, firstLine(string(out)))
		return name
	}
	t.Skipf("no usable container runtime: %s", why)
	return ""
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
