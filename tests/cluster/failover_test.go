package cluster_test

// A run whose device dies, on real processes (Task 20396): two `cloop ui`
// members serving one control plane, two enrolled edge agents — one connected
// to each member — and the stub harness. The run starts on the first agent,
// through the member holding its socket; that agent is killed mid-task. The
// supervisor declares it lost, and the run starts again on the second agent,
// which only the other member can reach: that member follows it as the
// project's run, its output reaches a dashboard attached to the first member,
// the project it sends back is merged, and the project ends complete. Then the
// second agent is killed too, with nothing left to fail over to: the project
// leaves "running" paused with an executor_lost reason naming it.
//
// Opt in as for TestHubClusterEndToEnd (CLOOP_CLUSTER_E2E=1). The supervisor
// probes on its production timing — a lost agent is noticed within about a
// minute — so this takes a few minutes.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// failoverAgent is one enrolled edge agent this test can kill.
type failoverAgent struct {
	id   string
	name string
	cmd  *exec.Cmd
	work string
	log  string
}

func TestFailedOverRunOnAHubCluster(t *testing.T) {
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this builds cloop and runs hub processes and agents", enableEnv)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for the stub harness")
	}
	w := newWorld(t)
	w.initProjects()
	a := w.startHub()
	b := w.startHub()
	w.startLoadBalancer()
	st := w.waitCluster("two live members and a leader", func(s clusterStatus) bool {
		return s.live() == 2 && s.Leader != ""
	})
	a.id, b.id = w.memberFor(st, a.port), w.memberFor(st, b.port)

	// One agent on each member.
	dev1 := w.enrollAgentVia(a, "edge-one")
	dev2 := w.enrollAgentVia(b, "edge-two")
	w.waitCluster("each agent's socket to be held by its own member", func(s clusterStatus) bool {
		return s.owner("agent", dev1.id) == a.id && s.owner("agent", dev2.id) == b.id
	})
	idx := w.projectIndex()
	// Bound through A, so A mirrors the binding in memory.
	w.bindProjectVia(a, idx, dev1.id)

	// ── The run starts on the first agent, through member A ───────────────
	if r := w.post(b, fmt.Sprintf("/api/run?project_idx=%d", idx)); r.status != http.StatusOK || r.servedBy != a.id {
		t.Fatalf("POST /api/run = %d (served by %s): %s; want it dispatched by A, which holds edge-one", r.status, short(r.servedBy), r.body)
	}
	w.waitStubStarts(1)
	ws := w.openStream(a, idx)
	ws.waitFor(t, 0, "the run's banner", func(typ, data string) bool {
		return typ == "step_output" && strings.Contains(data, "Write hello.txt")
	})

	// ── The first agent's device dies mid-task ─────────────────────────────
	mark := ws.mark()
	w.killAgent(dev1)
	t.Logf("killed %s at %s; waiting for the supervisor to declare it lost", dev1.id, time.Now().Format(time.TimeOnly))

	// The replacement is started on the second agent by B — the only member
	// that can reach it — which follows it as the project's run.
	st = w.waitStatusLong("the run to fail over to edge-two and be followed by B", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) == b.id
	})
	w.waitStubStarts(2)
	ws.waitFor(t, mark, "the failover notice in the live log on A's dashboard", func(typ, data string) bool {
		return typ == "step_output" && strings.Contains(data, "failed over to "+dev2.id)
	})
	if got, err := w.queryProject(`SELECT COUNT(*) FROM events WHERE type = 'failover' AND message LIKE 'Run failed over from executor ' || ? || ' to ' || ? || '%'`,
		dev1.id, dev2.id); err != nil || got != "1" {
		t.Fatalf("the event history has %s 'failed over' rows (%v), want 1", got, err)
	}
	if got, err := w.queryProject(`SELECT fail_count FROM plan_tasks WHERE id = 1`); err != nil || got != "1" {
		t.Fatalf("task 1's fail count is %s (%v), want 1 for the attempt lost with edge-one", got, err)
	}

	// It finishes on the second agent; B merges the result and settles it.
	if err := os.WriteFile(w.release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w.waitTaskStatus(1, "done")
	w.waitProjectStatus("complete")
	w.waitCluster("the replacement's owner row to be released", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) == ""
	})
	ws.waitFor(t, mark, "the replacement's end, relayed to A", func(typ, data string) bool {
		return typ == "run_state" && strings.Contains(data, `"running":false`)
	})
	if n := w.stubStarts(); n != 2 {
		t.Fatalf("the harness was started %d times; want the first run and its one replacement", n)
	}
	// Attributed to where it actually ran (Task 20244): the device it failed
	// over to, under the replacement's own run id.
	if got, err := w.queryProject(`SELECT executor_id FROM plan_tasks WHERE id = 1`); err != nil || got != dev2.id {
		t.Fatalf("task 1 is attributed to %q (%v), want the replacement's device %s", got, err, dev2.id)
	}
	ws.close()

	// ── The second agent dies too, with nothing left to take the run ───────
	if err := os.Remove(w.release); err != nil {
		t.Fatal(err)
	}
	w.addTask("Write world.txt")
	// Rebound through B, and run through A: A must not dispatch to the
	// binding it mirrored, the lost edge-one. A hears of the change on the
	// bus, within a poll.
	w.bindProjectVia(b, idx, dev2.id)
	w.waitEffectiveExecutor(a, idx, dev2.id)
	if r := w.post(a, fmt.Sprintf("/api/run?project_idx=%d", idx)); r.status != http.StatusOK {
		t.Fatalf("second run = %d: %s", r.status, r.body)
	}
	// A run on a device leaves the hub's own status alone until its result
	// comes back; the harness starting is what says it is under way.
	w.waitStubStarts(3)
	w.killAgent(dev2)
	t.Logf("killed %s at %s; nothing is left to fail over to", dev2.id, time.Now().Format(time.TimeOnly))

	w.eventually("the project to leave running, paused executor_lost naming edge-two", 3*time.Minute, func() bool {
		status, err := w.queryProject(`SELECT value FROM metadata WHERE key = 'status'`)
		if err != nil || status != "paused" {
			return false
		}
		raw, err := w.queryProject(`SELECT value FROM metadata WHERE key = 'pause_reason'`)
		if err != nil {
			return false
		}
		var pr struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		return json.Unmarshal([]byte(raw), &pr) == nil && pr.Code == "executor_lost" && strings.Contains(pr.Detail, dev2.id)
	})
	w.waitCluster("the lost run's owner row to be released", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) == ""
	})
	if got, err := w.queryProject(`SELECT COUNT(*) FROM events WHERE type = 'failover' AND message LIKE 'Executor ' || ? || ' was lost%'`,
		dev2.id); err != nil || got == "0" {
		t.Fatalf("the event history does not say edge-two was lost (%s, %v)", got, err)
	}
	if got, err := w.queryProject(`SELECT status FROM plan_tasks WHERE id = 2`); err != nil || got != "pending" {
		t.Fatalf("task 2 is %s (%v) after its device was lost, want pending for the next run", got, err)
	}
	if n := w.stubStarts(); n != 3 {
		t.Fatalf("the harness was started %d times; nothing should have replaced the last run", n)
	}
}

// enrollAgentVia enrolls an agent named name and connects it straight to h,
// rather than through the load balancer, so the test knows which member holds
// its socket.
func (w *world) enrollAgentVia(h *hub, name string) *failoverAgent {
	w.t.Helper()
	bundle := filepath.Join(w.root, "bundle-"+name)
	server := fmt.Sprintf("ws://127.0.0.1:%d/api/executors/connect", h.port)
	w.run(w.hubDir, "executor", "enroll", "--name", name, "--server", server, "--bundle-file", bundle)
	home := filepath.Join(w.root, "agenthome-"+name)
	work := filepath.Join(w.root, "agentwork-"+name)
	for _, d := range []string{home, work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			w.t.Fatal(err)
		}
	}
	env := []string{
		"HOME=" + home,
		"PATH=" + w.binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NO_COLOR=1",
	}
	ag := &failoverAgent{name: name, work: work, log: filepath.Join(w.root, "agent-"+name+".log")}
	ag.cmd, _ = w.spawn(w.root, ag.log, env,
		"executor", "agent", "--token-file", bundle,
		"--credential", filepath.Join(home, "agent.json"), "--workdir-root", work)
	w.eventually("agent "+name+" to enroll", 30*time.Second, func() bool {
		data, _ := os.ReadFile(ag.log)
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.Index(line, "enrolled as "); i >= 0 {
				rest := line[i+len("enrolled as "):]
				if j := strings.IndexAny(rest, "; "); j > 0 {
					ag.id = rest[:j]
					return true
				}
			}
		}
		return false
	})
	return ag
}

// bindProjectVia binds the project through one member, which mirrors the
// binding in its own memory.
func (w *world) bindProjectVia(h *hub, idx int, executorID string) {
	w.t.Helper()
	body, _ := json.Marshal(map[string]string{"executor_id": executorID})
	r := w.do(http.MethodPost, h.url(), fmt.Sprintf("/api/projects/%d/executor", idx), body)
	if r.status != http.StatusOK {
		w.t.Fatalf("bind the project through hub %d: %d %s", h.port, r.status, r.body)
	}
}

// waitEffectiveExecutor waits until h would run the project's next workload
// on executorID.
func (w *world) waitEffectiveExecutor(h *hub, idx int, executorID string) {
	w.t.Helper()
	w.eventually(fmt.Sprintf("hub %d to resolve the project to %s", h.port, executorID), 15*time.Second, func() bool {
		r := w.do(http.MethodGet, h.url(), fmt.Sprintf("/api/executors?project_idx=%d", idx), nil)
		if r.status != http.StatusOK {
			return false
		}
		var out struct {
			Project *struct {
				EffectiveID string `json:"effective_id"`
			} `json:"project"`
		}
		return json.Unmarshal([]byte(r.body), &out) == nil && out.Project != nil && out.Project.EffectiveID == executorID
	})
}

// killAgent takes an agent's device down: the agent and every process working
// in its directory — the run and its harness — die at once, as on a power cut.
func (w *world) killAgent(ag *failoverAgent) {
	w.t.Helper()
	if ag.cmd != nil && ag.cmd.Process != nil {
		_ = syscall.Kill(-ag.cmd.Process.Pid, syscall.SIGKILL)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	prefix := ag.work + string(os.PathSeparator)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cwd, err := os.Readlink(filepath.Join("/proc", e.Name(), "cwd"))
		if err != nil {
			continue
		}
		if cwd == ag.work || strings.HasPrefix(cwd, prefix) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// waitStatusLong is waitCluster with room for the supervisor's production
// timing: a lost agent is declared unreachable after three failed probes,
// the first up to a probe interval (30 s ±20 %) after it went, then backing
// off 5 s and 10 s.
func (w *world) waitStatusLong(what string, cond func(clusterStatus) bool) clusterStatus {
	w.t.Helper()
	var last clusterStatus
	w.eventually(what, 3*time.Minute, func() bool {
		st, ok := w.status(w.lb.url())
		if !ok {
			return false
		}
		last = st
		return cond(st)
	})
	return last
}
