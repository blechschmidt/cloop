package projectseed

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestASeededRunsDispatchesAreRecordedOnTheHub (Task 20457): a run carried out
// as a seed — on a Kubernetes Pod, on a device — writes its task.dispatch rows
// into its own copy of the project, which never comes back. So the merge writes
// them on the hub, one per task the run started, from the hub's own dispatch
// record: where the run went and the image it ran, the digest named on its own.
// A task the run did not start gets none.
func TestASeededRunsDispatchesAreRecordedOnTheHub(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{
		Goal: "g", Status: "initialized",
		Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
			{ID: 1, Title: "Build it", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Left alone", Priority: 2, Status: pm.TaskPending},
		}},
	})
	seed := seedFromHub(t, hub)
	started, finished := time.Now().Add(-time.Minute).UTC(), time.Now().UTC()
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		t1 := st.Plan.TaskByID(1)
		t1.Status, t1.StartedAt, t1.CompletedAt = pm.TaskDone, &started, &finished
		st.Plan.Tasks = append(st.Plan.Tasks, &pm.Task{ID: 3, Title: "Created and run", Priority: 3,
			Status: pm.TaskFailed, StartedAt: &started, CompletedAt: &finished})
		if err := st.Save(); err != nil {
			t.Fatal(err)
		}
	})
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}

	const digest = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	prov := Provenance{ExecutorID: "kubernetes", ExecutorKind: "kubernetes", Isolation: "container",
		RunID: "run_hub", Identity: "alice@example.com",
		RequestedImage: "registry.example/acme/rust:1.79", PinnedImage: "registry.example/acme/rust@" + digest,
		SpecHash: "spec-hash", LeaseIDs: []string{"lease-1"}}
	rep, err := Apply(hub, res, prov, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sort.Ints(rep.Dispatched)
	if len(rep.Dispatched) != 2 || rep.Dispatched[0] != 1 || rep.Dispatched[1] != 3 {
		t.Fatalf("Dispatched = %v, want the started task and the created one", rep.Dispatched)
	}

	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "task.dispatch"})
	if err != nil {
		t.Fatal(err)
	}
	byTask := map[string]map[string]any{}
	for _, r := range rows {
		var p map[string]any
		if err := json.Unmarshal([]byte(r.Payload), &p); err != nil {
			t.Fatalf("payload %s: %v", r.Payload, err)
		}
		byTask[r.EntityID] = p
		if r.Actor != "alice@example.com" {
			t.Errorf("task %s dispatched by %q, want who the run was for", r.EntityID, r.Actor)
		}
	}
	if len(byTask) != 2 || byTask["2"] != nil {
		t.Fatalf("dispatch rows for tasks %v, want 1 and 3 only", keys(byTask))
	}
	for id, title := range map[string]string{"1": "Build it", "3": "Created and run"} {
		p := byTask[id]
		for k, want := range map[string]string{
			"title": title, "run_id": "run_hub", "executor_id": "kubernetes", "executor_kind": "kubernetes",
			"requested_image": prov.RequestedImage, "pinned_image": prov.PinnedImage, "image_digest": digest,
			"spec_sha256": "spec-hash", "recorded_by": "hub",
		} {
			if p[k] != want {
				t.Errorf("task %s: %s = %v, want %q", id, k, p[k], want)
			}
		}
	}
}

func keys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
