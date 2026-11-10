package kubecontroller

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The hub's demand starts runners: one Pod per queued run, each with a Secret
// it owns holding the configuration the hub minted for it — and no credential
// anywhere in the Pod.
func TestDemandStartsRunnersWithTheirConfigurationInAnOwnedSecret(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(2)
	r.pool("build", r.spec())
	r.start()

	r.eventually("two runner Pods and their Secrets", func() bool {
		return len(r.pods()) == 2 && len(r.runnerSecrets()) == 2
	})
	if n := r.hub.mintedCount(); n != 2 {
		t.Fatalf("the hub minted %d runners, want 2", n)
	}
	for _, name := range r.pods() {
		var pod Pod
		r.k8s.decode("pods", testNS, name, &pod)
		raw, _ := r.k8s.object("pods", testNS, name)
		if tok := r.hub.leaksToken(mustJSON(raw)); tok != "" {
			t.Fatalf("Pod %s carries a credential in its spec: %s", name, tok)
		}
		var secret Secret
		if !r.k8s.decode("secrets", testNS, name, &secret) {
			t.Fatalf("no Secret for Pod %s", name)
		}
		if len(secret.Metadata.OwnerReferences) != 1 || secret.Metadata.OwnerReferences[0].UID != pod.Metadata.UID ||
			secret.Metadata.OwnerReferences[0].Kind != "Pod" {
			t.Fatalf("Secret %s is not owned by its Pod: %+v", name, secret.Metadata.OwnerReferences)
		}
		b, err := remote.DecodeBundle(strings.TrimSpace(string(secret.Data[bundleKey])))
		if err != nil {
			t.Fatalf("Secret %s's bundle: %v", name, err)
		}
		if !remote.IsRunnerToken(b.Token) || b.EnrollmentID != secret.Metadata.Annotations[AnnotationEnrollmentID] {
			t.Fatalf("Secret %s carries %+v", name, b)
		}
		if got := pod.Spec.Containers[0].Image; got != defaultRunnerRepo()+"@"+fakeDigest {
			t.Fatalf("Pod %s runs %q, want the default image by digest", name, got)
		}
	}
	r.eventually("a Ready condition", func() bool {
		st := r.status("build")
		return r.condition("build", ConditionReady).Status == ConditionTrue && st.Runners == 2 && st.PendingRunners == 2 &&
			st.DesiredRunners == 2 && st.QueuedRuns == 2 && st.PoolID == r.hub.poolID
	})
	if got := r.k8s.eventReasons(testNS); !contains(got, ReasonScaledUp) {
		t.Fatalf("events %v, want a ScaledUp", got)
	}
}

// A runner the hub says is busy is never retired and its Pod never deleted on
// scale-down; idle ones that idled for the delay are, through the hub.
func TestScaleDownRetiresIdleRunnersThroughTheHubAndNeverABusyOne(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(3)
	r.pool("build", r.spec())
	r.start()
	r.eventually("three runners", func() bool { return len(r.pods()) == 3 && len(r.runnerSecrets()) == 3 })

	pods := r.pods()
	busy := r.enrollmentOf(pods[0])
	for _, p := range pods {
		r.hub.enroll(r.enrollmentOf(p), time.Now().Add(-time.Hour))
	}
	r.hub.assign(busy)
	r.hub.setDemand(0)

	// desired = min(0) + busy(1) + queued(0) = 1: the two idle runners go.
	r.eventually("the idle runners retired", func() bool { return len(r.hub.retiredIDs()) == 2 })
	for _, req := range r.hub.retireRequests() {
		for _, id := range req {
			if id == busy {
				t.Fatalf("the controller asked the hub to retire the busy runner %s", busy)
			}
		}
	}
	if st := r.hub.states(); st[busy] != statedb.PoolRunnerBusy {
		t.Fatalf("the busy runner is %q on the hub", st[busy])
	}
	// The retired runners' agents exit; the controller collects their Pods.
	for _, p := range pods[1:] {
		r.k8s.setPodPhase(testNS, p, PodSucceeded, 0, `{"retired":true,"by":"hub","reason":"retired"}`)
	}
	r.eventually("only the busy runner's Pod left", func() bool {
		ps := r.pods()
		return len(ps) == 1 && ps[0] == pods[0] && len(r.runnerSecrets()) == 1
	})
	r.never("the busy runner's Pod deleted", 500*time.Millisecond, func() bool { return !contains(r.pods(), pods[0]) })
}

// An idle runner is not retired before it has idled for scaleDownDelay.
func TestScaleDownWaitsForTheDelay(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	spec := r.spec()
	spec.ScaleDownDelay = "1s"
	r.pool("build", spec)
	r.start()
	r.eventually("a runner", func() bool { return len(r.runnerSecrets()) == 1 })
	id := r.enrollmentOf(r.pods()[0])
	r.hub.enroll(id, time.Now())
	r.hub.setDemand(0)
	r.never("retired before the delay", 600*time.Millisecond, func() bool { return len(r.hub.retiredIDs()) > 0 })
	r.eventually("retired after the delay", func() bool { return len(r.hub.retiredIDs()) == 1 })
}

// minRunners is the idle target: kept with no demand, and kept idle on top
// of the busy ones when a run arrives.
func TestMinRunnersIsAnIdleTargetOnTopOfTheBusyOnes(t *testing.T) {
	r := newRig(t)
	spec := r.spec()
	spec.MinRunners = 2
	r.pool("warm", spec)
	r.start()
	r.eventually("two warm runners", func() bool { return len(r.runnerSecrets()) == 2 })
	for _, p := range r.pods() {
		r.hub.enroll(r.enrollmentOf(p), time.Now().Add(-time.Hour))
	}
	// A run arrives and is handed to one of them.
	r.hub.setDemand(1)
	r.hub.assign(r.enrollmentOf(r.pods()[0]))
	r.eventually("a third runner, so two stay idle", func() bool { return len(r.runnerSecrets()) == 3 })
	r.eventually("desired = 2 + 1 busy", func() bool { return r.status("warm").DesiredRunners == 3 })
	r.never("a warm runner retired", 500*time.Millisecond, func() bool { return len(r.hub.retiredIDs()) > 0 })
}

// maxRunners bounds the runners, and so does the hub pool's max_runners.
func TestDesiredIsClampedByBothMaxRunners(t *testing.T) {
	r := newRig(t)
	r.hub.set(func(h *fakeHub) { h.maxRunners = 3 })
	r.hub.setDemand(20)
	spec := r.spec()
	spec.MaxRunners = 4
	r.pool("build", spec)
	r.start()
	r.eventually("three runners, the hub's max", func() bool { return len(r.runnerSecrets()) == 3 })
	r.never("a fourth runner", 500*time.Millisecond, func() bool { return len(r.pods()) > 3 })
	if got := r.status("build").DesiredRunners; got != 3 {
		t.Fatalf("desired %d, want 3", got)
	}
}

// A finished runner's Pod and Secret are deleted; a failed one's report is an
// Event.
func TestFinishedRunnersAreCollectedAndAFailureIsReported(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(2)
	r.pool("build", r.spec())
	r.start()
	r.eventually("two runners", func() bool { return len(r.runnerSecrets()) == 2 })
	pods := r.pods()
	r.hub.setDemand(0)
	r.hub.finish(r.enrollmentOf(pods[0]))
	r.hub.finish(r.enrollmentOf(pods[1]))
	r.k8s.setPodPhase(testNS, pods[0], PodSucceeded, 0, `{"retired":true,"by":"hub","reason":"its run settled"}`)
	r.k8s.setPodPhase(testNS, pods[1], PodFailed, 1,
		`{"retired":false,"by":"refused","reason":"control plane rejected the handshake: token expired (unauthorized)"}`)
	r.eventually("both collected", func() bool { return len(r.pods()) == 0 && len(r.runnerSecrets()) == 0 })
	msgs := r.k8s.eventMessages(testNS, ReasonRunnerFailed)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "token expired") {
		t.Fatalf("RunnerFailed events %v, want the refused runner's reason", msgs)
	}
}

// A runner Pod whose Secret never came — the controller stopped between the
// two creates — is collected after a grace.
func TestARunnerPodWithoutItsSecretIsCollected(t *testing.T) {
	r := newRig(t)
	created := r.pool("build", r.spec())
	uid := created["metadata"].(map[string]any)["uid"].(string)
	ctrl := true
	r.k8s.apply("pods", testNS, Pod{Metadata: ObjectMeta{Name: "build-orphan", Labels: map[string]string{
		LabelManagedBy: ManagedBy}, OwnerReferences: []OwnerReference{{APIVersion: APIVersion, Kind: Kind,
		Name: "build", UID: uid, Controller: &ctrl}}}, Spec: PodSpec{Containers: []Container{{Name: "runner", Image: "x"}}}})
	r.start()
	r.eventually("the orphan Pod deleted", func() bool { return !contains(r.pods(), "build-orphan") })
}

// A Secret whose Pod is gone is swept.
func TestASecretWithoutItsPodIsSwept(t *testing.T) {
	r := newRig(t)
	r.pool("build", r.spec())
	ctrl := true
	r.k8s.apply("secrets", testNS, Secret{Metadata: ObjectMeta{Name: "build-gone", Labels: map[string]string{
		LabelManagedBy: ManagedBy}, CreationTimestamp: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		OwnerReferences: []OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "build-gone", UID: "uid-of-a-gone-pod",
			Controller: &ctrl}}}})
	r.start()
	r.eventually("the orphan Secret deleted", func() bool { return !contains(r.runnerSecrets(), "build-gone") })
}

// A runner the hub minted for this pool with this controller's credential and
// no Secret carries — minted by a controller that died before it started it —
// is given back to the hub; one another controller's credential minted is
// that controller's.
func TestARunnerTheHubMintedAndNoPodCarriesIsRetired(t *testing.T) {
	r := newRig(t)
	r.hub.set(func(h *fakeHub) {
		for _, g := range []struct{ id, cred, state string }{
			{"ghost", fakeCredentialID, statedb.PoolRunnerPending},
			{"idle-ghost", fakeCredentialID, statedb.PoolRunnerIdle},
			{"busy-ghost", fakeCredentialID, statedb.PoolRunnerBusy},
			{"theirs", "OTHERCREDENTIAL1", statedb.PoolRunnerPending},
		} {
			h.runners[g.id] = &executorpool.RunnerState{EnrollmentID: g.id, Name: "k8s-" + g.id,
				State: g.state, MintedAt: time.Now().Add(-time.Hour), EnrolledAt: time.Now().Add(-time.Hour),
				ExpiresAt: time.Now().Add(time.Minute), CredentialID: g.cred}
			h.order = append(h.order, g.id)
		}
	})
	r.pool("build", r.spec())
	r.start()
	r.eventually("the ghost runners retired", func() bool {
		return contains(r.hub.retiredIDs(), "ghost") && contains(r.hub.retiredIDs(), "idle-ghost")
	})
	r.never("a busy runner or another controller's runner retired", 500*time.Millisecond, func() bool {
		return contains(r.hub.retiredIDs(), "theirs") || contains(r.hub.retiredIDs(), "busy-ghost")
	})
	for _, req := range r.hub.retireRequests() {
		if contains(req, "busy-ghost") {
			t.Fatalf("the controller asked the hub to retire a busy runner: %v", req)
		}
	}
}

// A runner whose Secret vanished after it started — deleted by hand, or not
// yet in a cache that fell behind — may be busy, and its Pod is left alone.
func TestAStartedRunnerIsNeverCollectedForAMissingSecret(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	r.pool("build", r.spec())
	r.start()
	r.eventually("a runner", func() bool { return len(r.runnerSecrets()) == 1 })
	pod := r.pods()[0]
	id := r.enrollmentOf(pod)
	r.hub.enroll(id, time.Now())
	r.hub.assign(id)
	r.k8s.setPodPhase(testNS, pod, PodRunning, 0, "")
	r.k8s.removeObject("secrets", testNS, pod)
	r.never("the busy runner's Pod deleted", 2*time.Second, func() bool { return !contains(r.pods(), pod) })
}

// A hub older than per-runner states cannot say who is busy: the pool is
// Degraded, and nothing is started, retired or collected on its word.
func TestAHubWithoutRunnerStatesDecidesNothing(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	r.pool("build", r.spec())
	rc := r.start()
	r.eventually("a runner", func() bool { return len(r.runnerSecrets()) == 1 })
	rc.stop(t)
	r.hub.set(func(h *fakeHub) { h.legacy = true; h.demand = 3 })
	minted := r.hub.mintedCount()
	r.start()
	r.eventually("Degraded HubTooOld", func() bool {
		return r.condition("build", ConditionDegraded).Reason == ReasonHubTooOld
	})
	r.never("a runner started or stopped on an old hub's word", time.Second, func() bool {
		return r.hub.mintedCount() != minted || len(r.pods()) != 1 || len(r.hub.retiredIDs()) > 0
	})
}

// The pool's runners are rebuilt from the API server and the hub on restart:
// a new controller starts none of what already runs.
func TestARestartedControllerRebuildsItsViewAndStartsNothingTwice(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(3)
	r.pool("build", r.spec())
	first := r.start()
	r.eventually("three runners", func() bool { return len(r.runnerSecrets()) == 3 })
	first.stop(t)
	minted := r.hub.mintedCount()

	r.start()
	r.never("a runner started twice", time.Second, func() bool { return len(r.pods()) != 3 || r.hub.mintedCount() != minted })
}

// The demand feed reconnects with backoff when the hub is unreachable, the
// pool says Degraded with the hub's own words meanwhile, and nothing is
// started or retired on a stale view.
func TestAnUnreachableHubDegradesThePoolAndDecidesNothing(t *testing.T) {
	r := newRig(t)
	r.hub.set(func(h *fakeHub) { h.down = true })
	r.hub.setDemand(2)
	r.pool("build", r.spec())
	r.start()
	r.eventually("Degraded with the hub's error", func() bool {
		c := r.condition("build", ConditionDegraded)
		return c.Status == ConditionTrue && strings.Contains(c.Message, "the hub is restarting")
	})
	if len(r.pods()) != 0 {
		t.Fatalf("runners started without the hub: %v", r.pods())
	}
	if !contains(r.k8s.eventReasons(testNS), ReasonHubUnavailable) {
		t.Fatalf("events %v, want HubUnavailable", r.k8s.eventReasons(testNS))
	}
	r.hub.set(func(h *fakeHub) { h.down = false })
	r.eventually("recovered and scaled", func() bool {
		return len(r.runnerSecrets()) == 2 && r.condition("build", ConditionDegraded).Status == ConditionFalse
	})
}

// A refused credential is Degraded with the hub's refusal, and an Event.
func TestARefusedCredentialIsReported(t *testing.T) {
	r := newRig(t)
	r.hub.set(func(h *fakeHub) { h.refuse = true })
	r.pool("build", r.spec())
	r.start()
	r.eventually("Degraded HubRefused", func() bool {
		c := r.condition("build", ConditionDegraded)
		return c.Status == ConditionTrue && c.Reason == ReasonHubRefused && strings.Contains(c.Message, "pool_credential_invalid")
	})
	for _, line := range strings.Split(r.logs.all(), "\n") {
		if strings.Contains(line, fakeCredential) {
			t.Fatalf("the credential reached the log: %s", line)
		}
	}
}

// An invalid spec shows the Invalid condition naming every problem, and
// starts nothing.
func TestAnInvalidSpecShowsInvalidAndStartsNothing(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	spec := r.spec()
	spec.MinRunners = 9
	spec.HubURL = "http://plaintext.example"
	r.pool("bad", spec)
	r.start()
	r.eventually("Invalid=True", func() bool {
		c := r.condition("bad", ConditionInvalid)
		return c.Status == ConditionTrue && strings.Contains(c.Message, "https") && strings.Contains(c.Message, "maxRunners")
	})
	if c := r.condition("bad", ConditionReady); c.Status != ConditionFalse {
		t.Fatalf("Ready is %+v on an invalid spec", c)
	}
	if st := r.status("bad"); st.ObservedGeneration != 1 {
		t.Fatalf("observedGeneration %d, want 1", st.ObservedGeneration)
	}
	r.never("a runner for an invalid spec", 500*time.Millisecond, func() bool { return len(r.pods()) > 0 })
	if !contains(r.k8s.eventReasons(testNS), ReasonInvalidSpec) {
		t.Fatalf("events %v, want InvalidSpec", r.k8s.eventReasons(testNS))
	}

	// Fixed, it serves, and observedGeneration follows.
	r.pool("bad", r.spec())
	r.eventually("valid and serving", func() bool {
		st := r.status("bad")
		return r.condition("bad", ConditionInvalid).Status == ConditionFalse && st.ObservedGeneration == 2 &&
			len(r.runnerSecrets()) == 1
	})
}

// A Pod the API server refuses — PodSecurity admission, say — is an Event and
// a Degraded condition, and no runner is minted for it.
func TestARefusedPodIsReportedAndNothingIsMinted(t *testing.T) {
	r := newRig(t)
	r.k8s.onCreatePod = func(map[string]any) int { return 403 }
	r.hub.setDemand(1)
	r.pool("build", r.spec())
	r.start()
	r.eventually("Degraded PodRefused", func() bool {
		c := r.condition("build", ConditionDegraded)
		return c.Status == ConditionTrue && c.Reason == ReasonPodRefused && strings.Contains(c.Message, "PodSecurity")
	})
	if n := r.hub.mintedCount(); n != 0 {
		t.Fatalf("the hub minted %d runners for Pods that were refused", n)
	}
}

// A runner whose Secret could not be created has its Pod deleted and its
// configuration given back to the hub, so it holds no place under
// max_runners.
func TestARunnerWhoseSecretFailsIsGivenBack(t *testing.T) {
	r := newRig(t)
	r.k8s.fail("POST /secrets", 500)
	r.hub.setDemand(1)
	r.pool("build", r.spec())
	r.start()
	r.eventually("the minted runner given back", func() bool { return len(r.hub.retiredIDs()) >= 1 })
	r.eventually("its Pod deleted", func() bool { return len(r.pods()) == 0 })
	r.k8s.fail("POST /secrets", 0)
	r.eventually("a runner once Secrets can be created", func() bool { return len(r.runnerSecrets()) == 1 })
}

// An image that does not resolve to a digest starts no runner.
func TestAnUnresolvableDefaultImageStartsNoRunner(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	r.pool("build", r.spec())
	r.start(func(o *Options) { o.ImageResolver = fakeResolver{err: errRegistryDown} })
	r.eventually("Degraded ImageUnresolved", func() bool {
		return r.condition("build", ConditionDegraded).Reason == ReasonImageUnresolved
	})
	r.never("a runner from a tag", 500*time.Millisecond, func() bool { return len(r.pods()) > 0 })
}

// Two replicas with leader election: only the leader starts runners, and the
// other takes over when it stops.
func TestOnlyTheLeaderScalesAndAFollowerTakesOver(t *testing.T) {
	r := newRig(t)
	le := func(id string) func(*Options) {
		return func(o *Options) {
			o.LeaderElection = &LeaderElection{Namespace: testNS, Name: "cloop-executor-controller", Identity: id,
				LeaseDuration: 1500 * time.Millisecond, RenewDeadline: time.Second, RetryPeriod: 200 * time.Millisecond}
		}
	}
	a := r.start(le("a"))
	b := r.start(le("b"))
	r.eventually("one leader", func() bool { return a.c.Leading() != b.c.Leading() })
	leader, follower := a, b
	if b.c.Leading() {
		leader, follower = b, a
	}
	r.hub.setDemand(1)
	r.pool("build", r.spec())
	r.eventually("a runner", func() bool { return len(r.runnerSecrets()) == 1 })
	r.never("both leading", 500*time.Millisecond, func() bool { return a.c.Leading() && b.c.Leading() })

	leader.stop(t)
	r.eventually("the follower leads", func() bool { return follower.c.Leading() })
	r.hub.setDemand(2)
	r.eventually("the new leader scales", func() bool { return len(r.runnerSecrets()) == 2 })
	var lease Lease
	r.k8s.decode("leases", testNS, "cloop-executor-controller", &lease)
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		t.Fatalf("the Lease has no holder: %+v", lease.Spec)
	}
}

// A watch whose resourceVersion fell out of the server's history is answered
// with a relist, not a stuck informer.
func TestAnExpiredWatchRelists(t *testing.T) {
	r := newRig(t)
	r.start()
	time.Sleep(300 * time.Millisecond)
	r.k8s.compact()
	r.hub.setDemand(1)
	r.pool("build", r.spec())
	r.eventually("the pool seen after the 410", func() bool { return len(r.runnerSecrets()) == 1 })
}

// A panic in a reconcile is recovered: the pool is retried and scales once
// whatever panicked stops.
func TestAPanicInReconcileIsRecovered(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	var panicking atomicBool
	panicking.set(true)
	hook := func(*ExecutorPool) {
		if panicking.get() {
			panic("a pool the controller cannot handle")
		}
	}
	testHookReconcile.Store(&hook)
	t.Cleanup(func() { testHookReconcile.Store(nil) })
	rc := r.start()
	r.pool("build", r.spec())
	r.eventually("a recorded panic", func() bool { return rc.c.panics.Load() > 0 })
	panicking.set(false)
	r.eventually("the pool scaled after the panic", func() bool { return len(r.runnerSecrets()) == 1 })
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) set(v bool) { b.mu.Lock(); b.v = v; b.mu.Unlock() }
func (b *atomicBool) get() bool  { b.mu.Lock(); defer b.mu.Unlock(); return b.v }

var errRegistryDown = fmt.Errorf("%w: ghcr.io did not answer", imagepolicy.ErrRegistry)

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
