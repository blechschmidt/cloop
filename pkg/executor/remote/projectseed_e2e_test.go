package remote_test

// Loopback coverage for the project seed (Task 20316).
//
// The unit tests in pkg/executor/projectseed prove that a seed built from a
// project round-trips into a loadable one. What they cannot prove is that the
// bytes survive the part of the journey that only exists at the seam: a
// json:"-" field on the Spec, a sibling field on the start frame, base64 on the
// wire, a version gate at each end, and an agent that has to write the file
// into a directory it confines itself.
//
// That seam is exactly where this feature was broken before it existed — the
// hub had the project, the device had the tree, and nothing carried one to the
// other — so it is the part worth testing against a real WebSocket.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// seedFor builds a seed the way the hub does.
func seedFor(t *testing.T, goal string) []byte {
	t.Helper()
	seed, err := projectseed.Build(&state.ProjectState{
		Goal:         goal,
		WorkDir:      "/hub/only",
		Instructions: "seeded instructions",
		Provider:     "claudecode",
		Plan: &pm.Plan{
			Goal:  goal,
			Tasks: []*pm.Task{{ID: 1, Title: "seeded task", Status: pm.TaskPending}},
		},
	})
	if err != nil {
		t.Fatalf("build seed: %v", err)
	}
	return seed
}

// TestLoopbackProjectSeedReachesTheWorkload is the end-to-end claim: a seed
// attached to a Spec on the hub is readable by the process the device starts.
//
// The workload cats the file rather than the test stat-ing it, because the
// question this feature answers is "can `cloop run` on the device read a
// project", and only the workload's own view of its working directory can
// answer that.
func TestLoopbackProjectSeedReachesTheWorkload(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	res, err := executor.Run(context.Background(), ex, executor.Spec{
		WorkDir:     "seeded-project",
		Argv:        []string{"/bin/sh", "-c", "cat .cloop/state.json"},
		ProjectSeed: seedFor(t, "the seeded goal"),
	})
	if err != nil {
		t.Fatalf("Run: %v (output=%q)", err, res.Output)
	}

	out := string(res.Output)
	if !strings.Contains(out, "the seeded goal") {
		t.Fatalf("the workload could not read the seeded project; got %q", out)
	}

	// It is a real state.json, not just bytes that happen to contain the goal.
	var decoded struct {
		Goal         string   `json:"goal"`
		WorkDir      string   `json:"workdir"`
		Instructions string   `json:"instructions"`
		Plan         *pm.Plan `json:"plan"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("seed on the device is not valid JSON: %v", err)
	}
	if decoded.Instructions != "seeded instructions" {
		t.Errorf("instructions = %q", decoded.Instructions)
	}
	if decoded.Plan == nil || len(decoded.Plan.Tasks) != 1 {
		t.Errorf("plan did not survive the wire: %+v", decoded.Plan)
	}
	// The hub's own path must not have travelled: it is what Save writes back
	// through, and on the device it names a directory on another machine.
	if decoded.WorkDir != "" {
		t.Errorf("workdir = %q, want empty", decoded.WorkDir)
	}

	// And it landed inside the directory the agent confined, not beside it.
	onDevice := filepath.Join(lb.root, "seeded-project", ".cloop", "state.json")
	if _, err := os.Stat(onDevice); err != nil {
		t.Errorf("seed should be under the agent's root at %s: %v", onDevice, err)
	}
}

// TestLoopbackWithoutASeedLeavesNoProject is the control. Without it the test
// above would still pass on a device that had somehow acquired a .cloop/ of its
// own, and it pins the pre-existing behaviour an un-seeded dispatch keeps.
func TestLoopbackWithoutASeedLeavesNoProject(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	res, _ := executor.Run(context.Background(), ex, executor.Spec{
		WorkDir: "unseeded-project",
		Argv:    []string{"/bin/sh", "-c", "ls -a .cloop 2>&1 || true"},
	})
	if strings.Contains(string(res.Output), "state.json") {
		t.Errorf("an unseeded workload found a project: %q", res.Output)
	}
	if _, err := os.Stat(filepath.Join(lb.root, "unseeded-project", ".cloop")); !os.IsNotExist(err) {
		t.Errorf("an unseeded dispatch created .cloop/ on the device: %v", err)
	}
}

// TestLoopbackAgentAdvertisesProjectSeed: placement reads this capability to
// decide whether to attach a seed at all, so an agent that can place one has
// to say so over a live session.
func TestLoopbackAgentAdvertisesProjectSeed(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	if !ex.Capabilities().SupportsProjectSeed {
		t.Error("a connected current-build agent must advertise SupportsProjectSeed")
	}
}

// TestProjectSeedVersionGate pins the protocol floor. The hub must not send a
// seed to an agent that would ignore it, and must keep sending everything else
// to one — stranding a fleet mid-upgrade is the failure this floor is
// deliberately narrow to avoid.
func TestProjectSeedVersionGate(t *testing.T) {
	if remote.SupportsProjectSeed(remote.MinProjectSeedVersion - 1) {
		t.Errorf("v%d must not be treated as seed-capable", remote.MinProjectSeedVersion-1)
	}
	if !remote.SupportsProjectSeed(remote.MinProjectSeedVersion) {
		t.Errorf("v%d must be seed-capable", remote.MinProjectSeedVersion)
	}
	if !remote.SupportsProjectSeed(remote.ProtocolVersion) {
		t.Error("this build must be able to send a seed to itself")
	}
	// The floor is pinned to the version that introduced the seed. That was the
	// newest version when this was written and is not any more — v11 added the
	// upgrade frame (Task 20331) — so comparing it against ProtocolVersion has
	// stopped being the same assertion. As a literal it still catches the drift
	// it was written for: a floor that creeps upward with every protocol bump
	// would refuse to seed agents that honour the field perfectly well.
	const introducedIn = 10
	if remote.MinProjectSeedVersion != introducedIn {
		t.Errorf("MinProjectSeedVersion = %d, want %d; raising the floor strands agents that "+
			"already honour the seed", remote.MinProjectSeedVersion, introducedIn)
	}
	if remote.MinProjectSeedVersion > remote.ProtocolVersion {
		t.Errorf("MinProjectSeedVersion = %d is above ProtocolVersion = %d, so no agent this "+
			"build can talk to could ever be seeded",
			remote.MinProjectSeedVersion, remote.ProtocolVersion)
	}
}

// TestStartPayloadCarriesTheSeedOverJSON: Spec.ProjectSeed is json:"-", so the
// bytes reach the device only because StartPayload carries them itself. A
// refactor that "tidied up" the duplicate field would compile, pass every unit
// test, and silently stop seeding every remote run.
func TestStartPayloadCarriesTheSeedOverJSON(t *testing.T) {
	seed := seedFor(t, "wire check")

	payload := remote.StartPayload{
		Spec:        executor.Spec{WorkDir: "p", Argv: []string{"true"}, ProjectSeed: seed},
		HandleID:    "h1",
		ProjectSeed: seed,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded remote.StartPayload
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.Spec.ProjectSeed) != 0 {
		t.Error("Spec.ProjectSeed must not travel inside the Spec: it would be persisted by " +
			"executorstore and echoed into the audit trail on every dispatch")
	}
	if string(decoded.ProjectSeed) != string(seed) {
		t.Fatalf("StartPayload.ProjectSeed did not survive JSON: %d bytes in, %d out",
			len(seed), len(decoded.ProjectSeed))
	}
}
