package kubecontroller

// Task 20484: runner volumes, against the fake API server and the fake hub —
// slot assignment, the compare-and-swap that keeps two reconcilers off one
// volume, a project given its own volume back, the wipe before another
// project's runner uses it, a volume stuck Pending or full, and both reclaim
// policies.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executorpool"
)

// persistentSpec is the rig's spec with runner volumes.
func (r *rig) persistentSpec(mutate ...func(*Persistence)) ExecutorPoolSpec {
	s := r.spec()
	s.MaxRunners = 3
	p := &Persistence{Enabled: true, Size: "10Gi"}
	for _, m := range mutate {
		m(p)
	}
	s.Persistence = p
	return s
}

// claims lists the claims in the namespace.
func (r *rig) claims() []string { return r.k8s.names("persistentvolumeclaims", testNS) }

// claim reads a claim.
func (r *rig) claim(name string) PersistentVolumeClaim {
	var c PersistentVolumeClaim
	r.k8s.decode("persistentvolumeclaims", testNS, name, &c)
	return c
}

// pod reads a Pod.
func (r *rig) pod(name string) Pod {
	var p Pod
	r.k8s.decode("pods", testNS, name, &p)
	return p
}

// podClaim is the claim a runner Pod mounts, "" for none.
func podClaim(p Pod) string {
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			return v.PersistentVolumeClaim.ClaimName
		}
	}
	return ""
}

// startedRunners waits for n runner Pods with their Secrets and returns them
// with their enrollment IDs.
func (r *rig) startedRunners(n int) map[string]string {
	r.t.Helper()
	r.eventually(fmt.Sprintf("%d runners with their Secrets", n), func() bool {
		ps := r.pods()
		if len(ps) != n {
			return false
		}
		for _, p := range ps {
			if r.enrollmentOf(p) == "" {
				return false
			}
		}
		return true
	})
	out := map[string]string{}
	for _, p := range r.pods() {
		out[p] = r.enrollmentOf(p)
	}
	return out
}

// finishPod ends a runner Pod the way a runner does — its retirement report on
// its termination log — and settles its run on the hub.
func (r *rig) finishPod(pod, enrollment string, used, capacity int64) {
	r.t.Helper()
	msg := fmt.Sprintf(`{"retired":true,"by":"self","reason":"done","runs":1,"wiped":true,"storage":{"path":"/x","capacity_bytes":%d,"free_bytes":%d,"used_bytes":%d}}`,
		capacity, capacity-used, used)
	r.k8s.setPodPhase(testNS, pod, PodSucceeded, 0, msg)
	r.hub.finish(enrollment)
}

func argsOf(c Container) string { return strings.Join(c.Args, " ") }

// TestPersistentRunnersEachGetAVolumeOfTheirOwn is slot assignment: each
// runner Pod mounts its own claim, <pool>-storage-<n>, claimed for it by name
// before the Pod existed; a fresh volume is wiped by the init container
// anyway; the runner's credentials live on a memory-backed emptyDir, never on
// the volume.
func TestPersistentRunnersEachGetAVolumeOfTheirOwn(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(2)
	r.pool("build", r.persistentSpec())
	r.start()
	runners := r.startedRunners(2)

	seen := map[string]string{}
	for name := range runners {
		pod := r.pod(name)
		claim := podClaim(pod)
		if claim == "" {
			t.Fatalf("runner Pod %s mounts no claim", name)
		}
		if other, dup := seen[claim]; dup {
			t.Fatalf("runner Pods %s and %s mount one claim %s", name, other, claim)
		}
		seen[claim] = name
		cl := r.claim(claim)
		a := cl.Metadata.Annotations
		if a[AnnotationClaimedBy] != name || a[AnnotationHolds] != holdsUnknown || a[AnnotationHubPool] != r.hub.poolID ||
			a[AnnotationStoragePool] != "build" {
			t.Fatalf("claim %s annotations %v", claim, a)
		}
		if controllerOf(cl.Metadata) == "" {
			t.Errorf("claim %s is not owned by its pool under reclaimPolicy Delete", claim)
		}
		if cl.Spec.Resources.Requests["storage"] != "10Gi" || len(cl.Spec.AccessModes) != 1 ||
			cl.Spec.AccessModes[0] != AccessReadWriteOnce {
			t.Errorf("claim %s spec %+v", claim, cl.Spec)
		}
		if pod.Metadata.Annotations[AnnotationPodWipe] != "true" || pod.Metadata.Annotations[AnnotationPodHolds] != "" ||
			pod.Metadata.Annotations[AnnotationPodClaim] != claim {
			t.Errorf("Pod %s annotations %v", name, pod.Metadata.Annotations)
		}
		assertStoragePod(t, pod, true)
	}
	if got := r.claims(); !slices.Equal(got, []string{"build-storage-0", "build-storage-1"}) {
		t.Fatalf("claims %v", got)
	}
	for _, h := range r.hub.lastMintHolds() {
		if h != "" {
			t.Fatalf("a runner on a fresh volume was minted holding %q", h)
		}
	}
	r.eventually("the status counts the volumes", func() bool {
		s := r.status("build").Storage
		return s != nil && s.Claims == 2 && s.InUse == 2 && s.Bound == 2
	})
}

// assertStoragePod checks the security properties of a runner Pod with a
// volume: credentials and homes on memory, the volume only where trees and
// caches go, and the init container as confined as the runner.
func assertStoragePod(t *testing.T, pod Pod, wipe bool) {
	t.Helper()
	if len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Name != storageInitContainer {
		t.Fatalf("init containers %+v", pod.Spec.InitContainers)
	}
	init := pod.Spec.InitContainers[0]
	if got := strings.Contains(argsOf(init), "--wipe"); got != wipe {
		t.Errorf("init container args %q, want --wipe %v", argsOf(init), wipe)
	}
	if !strings.HasPrefix(argsOf(init), "executor runner-storage --root "+storageDir) {
		t.Errorf("init container args %q", argsOf(init))
	}
	sc := init.SecurityContext
	if sc == nil || !*sc.RunAsNonRoot || *sc.AllowPrivilegeEscalation || !*sc.ReadOnlyRootFilesystem ||
		len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("init container security context %+v", sc)
	}
	if len(init.VolumeMounts) != 1 || init.VolumeMounts[0].Name != storageVolume {
		t.Errorf("the init container mounts %+v; it needs the volume and nothing else", init.VolumeMounts)
	}
	runner := pod.Spec.Containers[0]
	args := argsOf(runner)
	for _, want := range []string{"--workspace-root " + storageDir + "/workspace", "--git-cache-dir " + storageDir + "/git",
		"--cache-dir " + storageDir + "/tools", "--home-root " + privateDir + "/homes", "--secret-dir " + privateDir + "/secrets"} {
		if !strings.Contains(args, want) {
			t.Errorf("runner args %q lack %q", args, want)
		}
	}
	// The runner holds the hub to what its volume holds: --holds names the
	// tenant the Pod was minted holding, and is absent on a volume that holds
	// nothing — fresh, or wiped before the runner starts.
	if holds := pod.Metadata.Annotations[AnnotationPodHolds]; holds != "" {
		if wipe || !strings.Contains(args, "--holds "+holds) {
			t.Errorf("runner args %q, wipe %v: want --holds %s and no wipe", args, wipe, holds)
		}
	} else if strings.Contains(args, "--holds") {
		t.Errorf("runner args %q name what a volume holding nothing holds", args)
	}
	for _, e := range runner.Env {
		if e.Name == "HOME" && e.Value != privateDir {
			t.Errorf("the runner's HOME is %s, not the memory-backed %s", e.Value, privateDir)
		}
	}
	var private *Volume
	for i, v := range pod.Spec.Volumes {
		if v.Name == privateVolume {
			private = &pod.Spec.Volumes[i]
		}
	}
	if private == nil || private.EmptyDir == nil || private.EmptyDir.Medium != "Memory" || private.EmptyDir.SizeLimit == "" {
		t.Errorf("the private volume is %+v, not a bounded memory-backed emptyDir", private)
	}
	for _, m := range runner.VolumeMounts {
		if m.Name == storageVolume && (strings.HasPrefix(privateDir, m.MountPath) || strings.HasPrefix(configDir, m.MountPath)) {
			t.Errorf("the volume is mounted at %s, above where credentials live", m.MountPath)
		}
	}
}

// TestAVolumeIsReleasedOnlyOnceItsRunnerHasTerminated: the hub tells the
// controller the runner's project as it is handed its run, which the volume
// records; the claim holds while the Pod runs and is released, with what the
// runner measured, only once it has terminated.
func TestAVolumeIsReleasedOnlyOnceItsRunnerHasTerminated(t *testing.T) {
	r := newRig(t)
	web := executorpool.ProjectTenant(r.hub.poolID, "/srv/web", "alice@example.com")
	r.hub.queue(web, 1)
	r.pool("build", r.persistentSpec())
	r.start()
	runners := r.startedRunners(1)
	var pod, id string
	for p, e := range runners {
		pod, id = p, e
	}
	claim := podClaim(r.pod(pod))
	r.hub.enroll(id, time.Now())
	if !r.hub.assignProject(id, web, "web", "alice@example.com") {
		t.Fatal("the hub could not hand the runner its run")
	}
	r.eventually("the volume records the project", func() bool {
		cl := r.claim(claim)
		a := cl.Metadata.Annotations
		return a[AnnotationHolds] == web && a[AnnotationProjectName] == "web" &&
			a[AnnotationProjectOwner] == "alice@example.com" && cl.Metadata.Labels[LabelProject] == web
	})
	r.k8s.setPodPhase(testNS, pod, PodRunning, 0, "")
	r.never("the claim of a running runner was released", 800*time.Millisecond, func() bool {
		return r.claim(claim).Metadata.Annotations[AnnotationClaimedBy] != pod
	})
	r.finishPod(pod, id, 2<<30, 10<<30)
	r.eventually("the claim released, with its measurement", func() bool {
		a := r.claim(claim).Metadata.Annotations
		return a[AnnotationClaimedBy] == "" && a[AnnotationUsedBytes] == fmt.Sprint(2<<30) &&
			a[AnnotationCapacityBytes] == fmt.Sprint(10<<30) && a[AnnotationHolds] == web && a[AnnotationReleasedAt] != ""
	})
	r.eventually("the status sums the bytes", func() bool {
		s := r.status("build").Storage
		return s != nil && s.BytesUsed == 2<<30 && s.BytesCapacity == 10<<30 && s.InUse == 0
	})
}

// TestTwoReconcilersRaceForOneVolume is the compare-and-swap: two claims of one
// free volume made against the same version — two reconcilers that both saw
// it free — and the API server lets exactly one through.
func TestTwoReconcilersRaceForOneVolume(t *testing.T) {
	r := newRig(t)
	spec := r.persistentSpec()
	r.pool("build", spec)
	poolObj := r.k8s.apply("pools", testNS, ExecutorPool{APIVersion: APIVersion, Kind: Kind,
		Metadata: ObjectMeta{Name: "build"}, Spec: spec})
	var pool ExecutorPool
	b, _ := json.Marshal(poolObj)
	_ = json.Unmarshal(b, &pool)
	p := pool.Spec.Normalize().Persistence
	r.k8s.apply("persistentvolumeclaims", testNS, buildClaim(&pool, p, claimName(&pool, 0), 0))
	var cl PersistentVolumeClaim
	r.k8s.decode("persistentvolumeclaims", testNS, claimName(&pool, 0), &cl)
	view := viewOfClaim(&cl, 0)

	c1, err := New(r.options())
	if err != nil {
		t.Fatal(err)
	}
	c2, err := New(r.options())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, c := range []*Controller{c1, c2} {
		wg.Add(1)
		go func(i int, c *Controller) {
			defer wg.Done()
			_, errs[i] = c.claimFor(context.Background(), &pool, p, volumePlan{vol: view, wipe: true},
				fmt.Sprintf("build-racer%d", i), r.hub.poolID)
		}(i, c)
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !kubernetes.IsConflict(err):
			t.Fatalf("a losing claim failed with %v, not a conflict", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d claims of one volume went through: %v", won, errs)
	}
	holder := r.claim(claimName(&pool, 0)).Metadata.Annotations[AnnotationClaimedBy]
	if holder != "build-racer0" && holder != "build-racer1" {
		t.Fatalf("the volume is claimed by %q", holder)
	}
}

// TestTwoControllersNeverMountOneVolumeTwice runs two controllers that both
// believe they lead — the failure leader election exists to prevent — against
// one pool, and watches every runner Pod as they start: no claim is ever
// mounted by two runner Pods that have not terminated.
func TestTwoControllersNeverMountOneVolumeTwice(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(3)
	r.pool("build", r.persistentSpec())
	stop := make(chan struct{})
	violations := make(chan string, 1)
	var watch sync.WaitGroup
	watch.Add(1)
	go func() {
		defer watch.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			holders := map[string]string{}
			for _, name := range r.pods() {
				p := r.pod(name)
				if p.Status.Phase == PodSucceeded || p.Status.Phase == PodFailed {
					continue
				}
				c := podClaim(p)
				if c == "" {
					continue
				}
				if other, dup := holders[c]; dup {
					select {
					case violations <- fmt.Sprintf("claim %s is mounted by %s and %s", c, other, name):
					default:
					}
					return
				}
				holders[c] = name
				if got := r.claim(c).Metadata.Annotations[AnnotationClaimedBy]; got != "" && got != name {
					select {
					case violations <- fmt.Sprintf("Pod %s mounts claim %s, which names %s", name, c, got):
					default:
					}
					return
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	r.start()
	r.start()
	r.eventually("three runners on volumes", func() bool {
		n := 0
		for _, name := range r.pods() {
			if podClaim(r.pod(name)) != "" && r.enrollmentOf(name) != "" {
				n++
			}
		}
		return n >= 3
	})
	time.Sleep(500 * time.Millisecond)
	close(stop)
	watch.Wait()
	select {
	case v := <-violations:
		t.Fatal(v)
	default:
	}
	if n := len(r.claims()); n > 3 {
		t.Fatalf("%d claims for a pool of at most 3", n)
	}
}

// runOnce starts a runner for one queued run of tenant, has the hub hand it
// the run, and finishes it, returning the claim it used.
func (r *rig) runOnce(tenant, name string) (pod, claim string) {
	r.t.Helper()
	before := map[string]bool{}
	for _, p := range r.pods() {
		before[p] = true
	}
	r.hub.queue(tenant, 1)
	var id string
	r.eventually("a new runner with its Secret", func() bool {
		for _, p := range r.pods() {
			if !before[p] && r.enrollmentOf(p) != "" {
				pod, id = p, r.enrollmentOf(p)
				return true
			}
		}
		return false
	})
	claim = podClaim(r.pod(pod))
	r.hub.enroll(id, time.Now())
	if !r.hub.assignProject(id, tenant, name, "") {
		r.t.Fatalf("the hub would not hand runner %s (%s) a run of %s", pod, id, name)
	}
	r.eventually("the volume records "+name, func() bool {
		return r.claim(claim).Metadata.Annotations[AnnotationHolds] == tenant
	})
	r.finishPod(pod, id, 1<<30, 10<<30)
	r.eventually("the runner collected and its claim released", func() bool {
		return !slices.Contains(r.pods(), pod) && r.claim(claim).Metadata.Annotations[AnnotationClaimedBy] == ""
	})
	return pod, claim
}

// TestAProjectGetsItsOwnVolumeBack is the affinity choice: the next run of a
// project goes to a runner on the volume that holds its workspace, unwiped,
// minted as holding it, so the hub hands that runner nobody else's run.
func TestAProjectGetsItsOwnVolumeBack(t *testing.T) {
	r := newRig(t)
	web := executorpool.ProjectTenant(r.hub.poolID, "/srv/web", "")
	r.pool("build", r.persistentSpec())
	r.start()
	_, first := r.runOnce(web, "web")

	r.hub.queue(web, 1)
	var pod string
	r.eventually("a runner on web's volume", func() bool {
		for _, p := range r.pods() {
			if r.enrollmentOf(p) != "" {
				pod = p
				return true
			}
		}
		return false
	})
	got := r.pod(pod)
	if podClaim(got) != first {
		t.Fatalf("web's second run is on %s, not its own %s", podClaim(got), first)
	}
	if got.Metadata.Annotations[AnnotationPodWipe] != "false" || got.Metadata.Annotations[AnnotationPodHolds] != web {
		t.Fatalf("Pod annotations %v", got.Metadata.Annotations)
	}
	assertStoragePod(t, got, false)
	if h := r.hub.lastMintHolds(); len(h) != 1 || h[0] != web {
		t.Fatalf("minted holding %v", h)
	}
	rs, _ := r.hub.runner(r.enrollmentOf(pod))
	if rs.Holds != web {
		t.Fatalf("the hub records the runner holding %q", rs.Holds)
	}
	if a := r.claim(first).Metadata.Annotations; a[AnnotationHolds] != web || a[AnnotationClaimedBy] != pod {
		t.Fatalf("claim annotations %v", a)
	}
	// Another project's run is never handed this runner.
	api := executorpool.ProjectTenant(r.hub.poolID, "/srv/api", "")
	r.hub.enroll(r.enrollmentOf(pod), time.Now())
	if r.hub.assignProject(r.enrollmentOf(pod), api, "api", "") {
		t.Fatal("a runner holding web's data was handed api's run")
	}
	if n := len(r.claims()); n != 1 {
		t.Fatalf("%d claims for one project's runs", n)
	}
}

// TestAVolumeIsWipedBeforeAnotherProjectUsesIt is the isolation rule: a run of
// another project gets a fresh volume while the pool has room for one, and
// otherwise the old project's volume — wiped by the runner's init container
// before the runner starts, and recorded as holding "unknown" from the moment
// it is claimed.
func TestAVolumeIsWipedBeforeAnotherProjectUsesIt(t *testing.T) {
	r := newRig(t)
	web := executorpool.ProjectTenant(r.hub.poolID, "/srv/web", "")
	api := executorpool.ProjectTenant(r.hub.poolID, "/srv/api", "")
	spec := r.persistentSpec()
	spec.MaxRunners = 1
	r.pool("build", spec)
	r.start()
	_, webClaim := r.runOnce(web, "web")

	// One volume and no room for another: api's run gets web's, wiped.
	r.hub.queue(api, 1)
	var pod string
	r.eventually("a runner for api", func() bool {
		for _, p := range r.pods() {
			if r.enrollmentOf(p) != "" {
				pod = p
				return true
			}
		}
		return false
	})
	got := r.pod(pod)
	if podClaim(got) != webClaim {
		t.Fatalf("api's runner is on %s", podClaim(got))
	}
	if got.Metadata.Annotations[AnnotationPodWipe] != "true" || got.Metadata.Annotations[AnnotationPodHolds] != "" {
		t.Fatalf("api's runner on web's volume: %v", got.Metadata.Annotations)
	}
	assertStoragePod(t, got, true)
	cl := r.claim(webClaim)
	a := cl.Metadata.Annotations
	if a[AnnotationHolds] != holdsUnknown || a[AnnotationProjectName] != "" || a[AnnotationClaimedBy] != pod ||
		cl.Metadata.Labels[LabelProject] != "" {
		t.Fatalf("the claimed volume records %v, labels %v", a, cl.Metadata.Labels)
	}
	for _, h := range r.hub.lastMintHolds() {
		if h != "" {
			t.Fatalf("a runner on a wiped volume was minted holding %q", h)
		}
	}
}

// TestAFreshVolumeIsPreferredToWipingAnotherProjects: with room for another
// volume, a project with no volume of its own gets a new one, and the other
// project's workspace is kept.
func TestAFreshVolumeIsPreferredToWipingAnotherProjects(t *testing.T) {
	r := newRig(t)
	web := executorpool.ProjectTenant(r.hub.poolID, "/srv/web", "")
	api := executorpool.ProjectTenant(r.hub.poolID, "/srv/api", "")
	r.pool("build", r.persistentSpec())
	r.start()
	_, webClaim := r.runOnce(web, "web")
	_, apiClaim := r.runOnce(api, "api")
	if apiClaim == webClaim {
		t.Fatalf("api's run wiped web's volume %s while the pool had room for another", webClaim)
	}
	if a := r.claim(webClaim).Metadata.Annotations; a[AnnotationHolds] != web {
		t.Fatalf("web's volume records %v", a)
	}
}

// TestARunnerStuckOnAPendingVolumeIsReportedNotLooped: a claim that cannot
// bind — no such StorageClass — leaves its runner Pod unschedulable. After
// storagePendingTimeout the runner goes, its place on the hub is given back,
// the pool is Degraded, the hub's queue says why, and no runner and no new
// volume are tried until the volume's retry is due.
func TestARunnerStuckOnAPendingVolumeIsReportedNotLooped(t *testing.T) {
	r := newRig(t)
	r.k8s.claimPhase = func(class string) string {
		if class == "missing" {
			return ClaimPending
		}
		return ClaimBound
	}
	r.hub.setDemand(1)
	r.pool("build", r.persistentSpec(func(p *Persistence) { p.StorageClassName = "missing" }))
	r.start()
	// The scheduler says it is the volume — a claim of a class that binds at
	// once and cannot — which is what makes a waiting runner stuck on it.
	var pod string
	r.eventually("a runner Pod", func() bool {
		ps := r.pods()
		if len(ps) == 0 {
			return false
		}
		pod = ps[0]
		return true
	})
	r.k8s.setPodStatus(testNS, pod, func(st map[string]any) {
		st["conditions"] = []any{map[string]any{"type": "PodScheduled", "status": "False", "reason": "Unschedulable",
			"message": "0/3 nodes are available: pod has unbound immediate PersistentVolumeClaims"}}
	})
	claim := "build-storage-0"
	r.eventually("the volume marked", func() bool {
		a := r.claim(claim).Metadata.Annotations
		return a[AnnotationProblem] != "" && strings.Contains(a[AnnotationProblemReason], "Pending")
	})
	r.eventually("the stuck runner deleted and its place on the hub given back", func() bool {
		return len(r.pods()) == 0 && r.hub.mintedCount() == 1 && len(r.hub.retiredIDs()) == 1
	})
	r.eventually("Degraded StoragePending", func() bool {
		c := r.condition("build", ConditionDegraded)
		return c.Status == ConditionTrue && c.Reason == ReasonStoragePending && strings.Contains(c.Message, "Pending")
	})
	r.eventually("the hub told", func() bool {
		for _, rep := range r.hub.storageReports() {
			if rep["healthy"] == false && rep["reason"] == ReasonStoragePending {
				return true
			}
		}
		return false
	})
	r.never("a runner or a volume was tried again within the retry window", time.Second, func() bool {
		return len(r.pods()) > 0 || len(r.claims()) > 1 || r.hub.mintedCount() > 1
	})
}

// TestStuckOnVolume is when a runner Pod counts as stuck on its volume: one
// that never started, older than storagePendingTimeout, whose claim is
// Pending or which the scheduler cannot place.
func TestStuckOnVolume(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * storagePendingTimeout).UTC().Format(time.RFC3339)
	young := now.UTC().Format(time.RFC3339)
	pod := func(created, phase string, sched bool, running bool) *Pod {
		p := &Pod{Metadata: ObjectMeta{Name: "r", CreationTimestamp: created}, Status: PodStatus{Phase: phase}}
		if sched {
			p.Status.Conditions = []PodCondition{{Type: "PodScheduled", Status: ConditionFalse, Reason: "Unschedulable",
				Message: "1 node(s) had volume node affinity conflict"}}
		}
		if running {
			p.Status.ContainerStatuses = []ContainerStatus{{Name: runnerContainer, State: ContainerState{}}}
		}
		return p
	}
	pending := &volumeView{claim: &PersistentVolumeClaim{Metadata: ObjectMeta{Name: "v"}, Status: ClaimState{Phase: ClaimPending}}}
	bound := &volumeView{claim: &PersistentVolumeClaim{Metadata: ObjectMeta{Name: "v"}, Status: ClaimState{Phase: ClaimBound}}}
	cpu := pod(old, PodPending, false, false)
	cpu.Status.Conditions = []PodCondition{{Type: "PodScheduled", Status: ConditionFalse, Reason: "Unschedulable",
		Message: "0/3 nodes are available: 3 Insufficient cpu."}}
	for _, c := range []struct {
		name string
		p    *Pod
		v    *volumeView
		want bool
	}{
		{"a Pending claim the scheduler blames", pod(old, PodPending, true, false), pending, true},
		{"an unschedulable Pod on a bound claim", pod(old, PodPending, true, false), bound, true},
		{"a claim waiting for its first consumer, no node with the CPU", cpu, pending, false},
		{"a Pending claim and no word from the scheduler", pod(old, PodPending, false, false), pending, false},
		{"a Pod that has not waited long", pod(young, PodPending, true, false), pending, false},
		{"a bound claim and a schedulable Pod", pod(old, PodPending, false, false), bound, false},
		{"a Pod that started", pod(old, PodRunning, true, true), pending, false},
	} {
		why, got := stuckOnVolume(c.p, c.v, now)
		if got != c.want {
			t.Errorf("%s: stuck %v (%q), want %v", c.name, got, why, c.want)
		}
	}
}

// failFull ends a runner Pod the way its init container does on a volume
// under minFree even empty.
func (r *rig) failFull(pod string) {
	r.t.Helper()
	report := PrepareReport{Wiped: true, WipeReason: "full", Full: true, CapacityBytes: 2 << 30, FreeBytes: 512 << 20,
		UsedBytes: 1536 << 20, Error: "the volume has 512.0 MiB free of 2.0 GiB with nothing on it"}
	b, _ := json.Marshal(report)
	r.k8s.setPodStatus(testNS, pod, func(st map[string]any) {
		st["phase"] = PodFailed
		st["initContainerStatuses"] = []any{map[string]any{"name": storageInitContainer, "state": map[string]any{
			"terminated": map[string]any{"exitCode": 1, "reason": "Error", "message": string(b)}}}}
	})
}

// TestAFullVolumeIsReportedAndLeftAlone: a volume its init container found
// under minFree even empty fails its runner; the controller records it full,
// is Degraded, and — this being the pool's only volume — no runner can start,
// which the hub's queue says, until the volume is retried.
func TestAFullVolumeIsReportedAndLeftAlone(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	spec := r.persistentSpec()
	spec.MaxRunners = 1
	r.pool("build", spec)
	r.start()
	runners := r.startedRunners(1)
	var pod, id string
	for p, e := range runners {
		pod, id = p, e
	}
	claim := podClaim(r.pod(pod))
	r.failFull(pod)
	r.hub.finish(id)
	r.eventually("the volume recorded full and released", func() bool {
		a := r.claim(claim).Metadata.Annotations
		return a[AnnotationFull] != "" && a[AnnotationClaimedBy] == "" && a[AnnotationUsedBytes] == fmt.Sprint(1536<<20)
	})
	r.eventually("Degraded StorageFull, and the hub told", func() bool {
		c := r.condition("build", ConditionDegraded)
		s := r.status("build").Storage
		told := false
		for _, rep := range r.hub.storageReports() {
			told = told || rep["reason"] == ReasonStorageFull
		}
		return c.Status == ConditionTrue && c.Reason == ReasonStorageFull && s != nil && s.Full == 1 && told
	})
	r.never("a runner was started on the full volume", 800*time.Millisecond, func() bool {
		for _, p := range r.pods() {
			if p != pod && podClaim(r.pod(p)) == claim {
				return true
			}
		}
		return false
	})
}

// TestAFreshVolumeTakesAFullOnesPlace: with room for another volume, the
// next runner starts on a fresh one, and the hub is not told the pool cannot
// start runners — it can.
func TestAFreshVolumeTakesAFullOnesPlace(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	r.pool("build", r.persistentSpec())
	r.start()
	runners := r.startedRunners(1)
	var pod, id string
	for p, e := range runners {
		pod, id = p, e
	}
	claim := podClaim(r.pod(pod))
	r.failFull(pod)
	r.hub.finish(id)
	r.eventually("the next runner on a fresh volume", func() bool {
		for _, p := range r.pods() {
			if c := podClaim(r.pod(p)); c != "" && c != claim && r.enrollmentOf(p) != "" {
				return true
			}
		}
		return false
	})
	for _, rep := range r.hub.storageReports() {
		if rep["healthy"] == false {
			t.Fatalf("the hub was told the pool cannot start runners: %v", rep)
		}
	}
}

// TestReclaimPolicyDelete: volumes past maxClaims are deleted once free, and
// the rest go with the pool, whose they are.
func TestReclaimPolicyDelete(t *testing.T) {
	r := newRig(t)
	spec := r.persistentSpec()
	spec.MaxRunners = 2
	r.hub.setDemand(2)
	r.pool("build", spec)
	r.start()
	runners := r.startedRunners(2)
	r.hub.setDemand(0)
	for p, id := range runners {
		r.finishPod(p, id, 1<<30, 10<<30)
	}
	r.eventually("both released", func() bool {
		for _, c := range r.claims() {
			if r.claim(c).Metadata.Annotations[AnnotationClaimedBy] != "" {
				return false
			}
		}
		return len(r.claims()) == 2 && len(r.pods()) == 0
	})
	spec.MaxRunners = 1
	r.pool("build", spec)
	r.eventually("the volume past maxClaims deleted", func() bool {
		return slices.Equal(r.claims(), []string{"build-storage-0"})
	})
	r.k8s.removeObject("pools", testNS, "build")
	r.eventually("the pool's volumes went with it", func() bool { return len(r.claims()) == 0 })
}

// TestReclaimPolicyRetain: volumes past maxClaims are kept, unowned and with
// the record of whose data they hold; they outlive the pool; a pool of the
// same name and hub pool takes them up again, and gives a project back its
// own.
func TestReclaimPolicyRetain(t *testing.T) {
	r := newRig(t)
	web := executorpool.ProjectTenant(r.hub.poolID, "/srv/web", "")
	spec := r.persistentSpec(func(p *Persistence) { p.ReclaimPolicy = ReclaimRetain })
	spec.MaxRunners = 1
	r.pool("build", spec)
	rc := r.start()
	_, webClaim := r.runOnce(web, "web")
	if refs := r.claim(webClaim).Metadata.OwnerReferences; len(refs) != 0 {
		t.Fatalf("a retained pool's volume is owned: %+v", refs)
	}

	// Persistence off: the volume is past every slot, and kept.
	spec.Persistence.Enabled = false
	r.pool("build", spec)
	r.eventually("the volume counted as retained", func() bool {
		s := r.status("build").Storage
		return s != nil && s.Retained == 1 && s.Claims == 1
	})
	r.k8s.removeObject("pools", testNS, "build")
	time.Sleep(300 * time.Millisecond)
	if cl := r.claim(webClaim); !slices.Contains(r.claims(), webClaim) || cl.Metadata.Annotations[AnnotationHolds] != web ||
		cl.Metadata.Labels[LabelProject] != web {
		t.Fatalf("the retained volume after the pool's deletion: %+v (claims %v)", cl.Metadata, r.claims())
	}
	rc.stop(t)

	// The pool again, as it was: web's next run is on web's volume, unwiped.
	spec.Persistence.Enabled = true
	r.pool("build", spec)
	r.start()
	r.hub.queue(web, 1)
	r.eventually("web's run on its retained volume", func() bool {
		for _, p := range r.pods() {
			got := r.pod(p)
			if podClaim(got) == webClaim && got.Metadata.Annotations[AnnotationPodWipe] == "false" && r.enrollmentOf(p) != "" {
				return true
			}
		}
		return false
	})
}

// TestAHubOlderThanRunnerStorageGetsOnlyWipedRunners: a hub that does not
// record what a runner's volume holds would hand a runner on web's volume
// anybody's run, so every runner starts on a wiped volume.
func TestAHubOlderThanRunnerStorageGetsOnlyWipedRunners(t *testing.T) {
	r := newRig(t)
	web := executorpool.ProjectTenant(r.hub.poolID, "/srv/web", "")
	r.pool("build", r.persistentSpec())
	r.start()
	_, webClaim := r.runOnce(web, "web")

	r.hub.set(func(h *fakeHub) { h.noStorage = true })
	r.hub.queue(web, 1)
	var pod string
	r.eventually("a runner", func() bool {
		for _, p := range r.pods() {
			if r.enrollmentOf(p) != "" {
				pod = p
				return true
			}
		}
		return false
	})
	got := r.pod(pod)
	if got.Metadata.Annotations[AnnotationPodWipe] != "true" || got.Metadata.Annotations[AnnotationPodHolds] != "" {
		t.Fatalf("with an old hub: %v (claim %s, web's %s)", got.Metadata.Annotations, podClaim(got), webClaim)
	}
	r.eventually("the warning", func() bool { return slices.Contains(r.k8s.eventReasons(testNS), ReasonStorageUnsupported) })
}

// TestARunnerWhoseHoldsTheHubDidNotConfirmNeverStarts: the hub's echo is the
// proof it recorded what the runner holds; without it the runner's Pod is
// deleted before its Secret exists — it never starts — and its place given
// back.
func TestARunnerWhoseHoldsTheHubDidNotConfirmNeverStarts(t *testing.T) {
	r := newRig(t)
	web := executorpool.ProjectTenant(r.hub.poolID, "/srv/web", "")
	r.pool("build", r.persistentSpec())
	r.start()
	_, webClaim := r.runOnce(web, "web")

	r.hub.set(func(h *fakeHub) { h.noEcho = true })
	before := len(r.hub.retiredIDs())
	r.hub.queue(web, 1)
	r.eventually("the unconfirmed runner given back", func() bool { return len(r.hub.retiredIDs()) > before })
	for _, p := range r.pods() {
		if podClaim(r.pod(p)) == webClaim && r.enrollmentOf(p) != "" {
			t.Fatalf("runner Pod %s on web's unwiped volume got its Secret", p)
		}
	}
	r.eventually("the warning", func() bool { return slices.Contains(r.k8s.eventReasons(testNS), ReasonStorageUnsupported) })
}

// TestAKeptVolumeIsWipedAfterARunThatNeverStartedOnIt: a run can leave its
// own tree unusable, and the next runner of the project would get it back
// as it is; a runner that reports its run never started gets the volume
// marked, and the next runner wipes it.
func TestAKeptVolumeIsWipedAfterARunThatNeverStartedOnIt(t *testing.T) {
	r := newRig(t)
	web := executorpool.ProjectTenant(r.hub.poolID, "/srv/web", "")
	r.pool("build", r.persistentSpec())
	r.start()
	_, claim := r.runOnce(web, "web")

	r.hub.queue(web, 1)
	var pod, id string
	r.eventually("a runner on web's volume", func() bool {
		for _, p := range r.pods() {
			if r.enrollmentOf(p) != "" {
				pod, id = p, r.enrollmentOf(p)
				return true
			}
		}
		return false
	})
	if got := r.pod(pod); podClaim(got) != claim || got.Metadata.Annotations[AnnotationPodWipe] != "false" {
		t.Fatalf("web's second runner: %v on %s", got.Metadata.Annotations, podClaim(got))
	}
	r.hub.enroll(id, time.Now())
	r.hub.assignProject(id, web, "web", "")
	r.k8s.setPodPhase(testNS, pod, PodSucceeded, 0,
		`{"retired":true,"by":"hub","reason":"retired","runs":1,"wiped":true,"start_failed":"its run did not start"}`)
	r.hub.finish(id)
	r.eventually("the volume marked unknown", func() bool {
		a := r.claim(claim).Metadata.Annotations
		return a[AnnotationClaimedBy] == "" && a[AnnotationHolds] == holdsUnknown
	})
	r.hub.queue(web, 1)
	r.eventually("the next runner wipes it", func() bool {
		for _, p := range r.pods() {
			got := r.pod(p)
			if podClaim(got) == claim && got.Metadata.Annotations[AnnotationPodWipe] == "true" {
				return true
			}
		}
		return false
	})
}

// TestARefusedRunnersClaimIsGivenBackThoughTheClaimChanged: a claim the
// binder updated between the controller claiming it and admission refusing
// the runner Pod is still released at once — a provisioner touches a new claim
// within milliseconds — instead of being held for claimGrace while every
// refusal takes another ordinal.
func TestARefusedRunnersClaimIsGivenBackThoughTheClaimChanged(t *testing.T) {
	r := newRig(t)
	saved := claimGrace
	claimGrace = time.Minute // so only unclaim, never the grace, can release it
	t.Cleanup(func() { claimGrace = saved })
	var refused atomic.Int32
	r.k8s.onCreatePod = func(map[string]any) int {
		// Called holding the fake's lock: the binder's update lands first.
		for _, o := range r.k8s.objs {
			if o.kind == "persistentvolumeclaims" {
				o.meta()["labels"].(map[string]any)["binder-touched"] = fmt.Sprint(refused.Load())
				r.k8s.putLocked(o, "MODIFIED")
			}
		}
		refused.Add(1)
		return 403
	}
	r.hub.setDemand(1)
	r.pool("build", r.persistentSpec())
	r.start()
	r.eventually("a runner Pod refused", func() bool { return refused.Load() >= 1 })
	r.eventually("its claim released", func() bool {
		cs := r.claims()
		if len(cs) == 0 {
			return false
		}
		for _, c := range cs {
			if r.claim(c).Metadata.Annotations[AnnotationClaimedBy] != "" {
				return false
			}
		}
		return true
	})
	r.k8s.mu.Lock()
	conflicts := r.k8s.conflicts
	r.k8s.mu.Unlock()
	if conflicts == 0 {
		t.Fatal("the release met no conflict; the test proves nothing")
	}
	if n := len(r.claims()); n != 1 {
		t.Fatalf("%d claims after refused runners, want the one given back and reused", n)
	}
}

// TestACleanRunClearsAVolumesEarlierFailures: a volume runners failed on
// before, whose init container then prepared it and whose runner ran on it,
// has its failures forgotten — transient trouble over a volume's life never
// adds up to giving it up.
func TestACleanRunClearsAVolumesEarlierFailures(t *testing.T) {
	r := newRig(t)
	web := executorpool.ProjectTenant(r.hub.poolID, "/srv/web", "")
	r.pool("build", r.persistentSpec())
	r.start()
	_, claim := r.runOnce(web, "web")
	r.k8s.mu.Lock()
	o := r.k8s.objs[objKey("persistentvolumeclaims", testNS, claim)]
	o.meta()["annotations"].(map[string]any)[AnnotationFailures] = "2"
	r.k8s.putLocked(o, "MODIFIED")
	r.k8s.mu.Unlock()
	if _, again := r.runOnce(web, "web"); again != claim {
		t.Fatalf("web's second run is on %s, not its own %s", again, claim)
	}
	r.eventually("the failures forgotten", func() bool {
		a := r.claim(claim).Metadata.Annotations
		return a[AnnotationClaimedBy] == "" && a[AnnotationFailures] == ""
	})
}
