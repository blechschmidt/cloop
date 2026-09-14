package kubernetes

// netpolprobe_test.go drives the enforcement experiment against the fake API
// server, once per kind of cluster an operator can actually have.
//
// The three that matter are named in the task this file was written for:
//
//   - enforced: the policed connection dies, and the probe says so.
//   - CNI-hostile: the policy is accepted and ignored, the policed connection
//     survives, and the probe must REFUSE the capability rather than record a
//     success because it created the object successfully.
//   - unverified: the probe could not establish its control, so it must return
//     ErrProbeInconclusive and no verdict at all — not a guess in either
//     direction.
//
// Every case also asserts cleanup, because the object this probe creates is a
// default-deny NetworkPolicy in a shared namespace. One left behind is an
// outage for whatever is scheduled there next.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeCluster drives probe Pods through their lifecycle the way a kubelet and
// a CNI would, so a test can say "this is a cluster that enforces policies"
// rather than reaching into the probe's internals.
//
// It polls for new Pods and reacts by suffix, which is what lets one helper
// model all three cluster kinds: the only thing that differs between them is
// the exit code the policed client gets.
type fakeCluster struct {
	api *fakeAPI
	// targetIP is the address handed to the target Pod. The clients connect to
	// it by literal address, so nothing here needs DNS.
	targetIP string
	// targetFails makes the HTTP server exit instead of serving, modelling a
	// probe image with no httpd.
	targetFails bool
	// controlExit is what the unpoliced client exits with. Non-zero models a
	// namespace where pod-to-pod traffic is already blocked — the case that
	// must be reported as inconclusive rather than as enforcement.
	controlExit int
	// policedExit is the measurement. Non-zero means the policy bit.
	policedExit int

	stop chan struct{}
	done chan struct{}
	seen map[string]bool
	// started records whether the reacting goroutine was ever launched. close
	// waits on done, and done is only closed by that goroutine — so a case that
	// deliberately never starts the cluster (to model a Pod that never becomes
	// ready) would otherwise deadlock in t.Cleanup rather than failing.
	started bool
}

func newFakeCluster(t *testing.T, api *fakeAPI) *fakeCluster {
	t.Helper()
	c := &fakeCluster{
		api:         api,
		targetIP:    "10.42.0.7",
		controlExit: 0,
		policedExit: 1,
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		seen:        map[string]bool{},
	}
	t.Cleanup(c.close)
	return c
}

// start begins reacting to Pods. Called after the per-case fields are set, so
// a test reads as a description of a cluster.
func (c *fakeCluster) start() {
	c.started = true
	go func() {
		defer close(c.done)
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-tick.C:
				c.step()
			}
		}
	}()
}

func (c *fakeCluster) close() {
	if !c.started {
		return
	}
	select {
	case <-c.stop:
	default:
		close(c.stop)
		<-c.done
	}
}

// step transitions any Pod it has not already handled.
func (c *fakeCluster) step() {
	for _, name := range c.api.podNames() {
		if c.seen[name] {
			continue
		}
		c.seen[name] = true
		switch {
		case strings.HasSuffix(name, "-target"):
			if c.targetFails {
				c.api.terminate(name, 127, "Error")
				continue
			}
			c.api.setPhase(name, func(p *pod) {
				p.Status.Phase = phaseRunning
				p.Status.PodIP = c.targetIP
				p.Status.ContainerStatuses = []containerStatus{{
					Name: ContainerName, Ready: true,
					State: containerState{Running: &stateRunning{
						StartedAt: time.Now().UTC().Format(time.RFC3339),
					}},
				}}
			})
		case strings.HasSuffix(name, "-control"):
			c.api.terminate(name, c.controlExit, "Completed")
		case strings.HasSuffix(name, "-policed"):
			c.api.terminate(name, c.policedExit, "Completed")
		}
	}
}

// probeExecutor builds an executor whose probe polls fast enough for a test.
//
// The interval is restored on cleanup rather than left shortened, so a test
// that runs after these does not silently inherit a different timing regime
// from the one it was written against.
func probeExecutor(t *testing.T) (*Executor, *fakeAPI, *fakeCluster) {
	t.Helper()
	prev := probePollInterval
	probePollInterval = 2 * time.Millisecond
	t.Cleanup(func() { probePollInterval = prev })

	ex, api, _ := newTestExecutor(t, nil)
	cluster := newFakeCluster(t, api)
	return ex, api, cluster
}

// runProbe runs the experiment with a test-sized budget.
func runProbe(t *testing.T, ex *Executor) (ProbeVerdict, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ex.ProbeNetworkPolicyEnforcement(ctx, ProbeOptions{Timeout: 20 * time.Second})
}

// assertProbeCleanedUp is the assertion every case shares.
//
// A leftover Pod idles; a leftover default-deny NetworkPolicy denies egress for
// whatever matches it next. Both are cloop's mess, and the janitor exists so
// neither outlives the probe on any exit path.
func assertProbeCleanedUp(t *testing.T, api *fakeAPI) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(api.policyNames()) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if left := api.policyNames(); len(left) != 0 {
		t.Errorf("the probe left NetworkPolicies behind: %v — a default-deny policy in a shared "+
			"namespace denies egress for whatever is scheduled there next", left)
	}
	deleted := api.deleteRecords()
	var deletedPods int
	for _, d := range deleted {
		if strings.Contains(d.Name, probeNamePrefix) {
			deletedPods++
		}
	}
	if deletedPods == 0 {
		t.Error("the probe deleted none of its Pods")
	}
}

// TestProbe_EnforcedCluster: the connection worked, then stopped working. That
// is the only shape of evidence that earns the capability.
func TestProbe_EnforcedCluster(t *testing.T) {
	ex, api, cluster := probeExecutor(t)
	cluster.policedExit = 1 // wget could not connect: the policy bit
	cluster.start()

	verdict, err := runProbe(t, ex)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !verdict.Enforced {
		t.Fatalf("verdict.Enforced = false on a cluster that blocked the policed connection: %+v", verdict)
	}
	if !verdict.Recorded() {
		t.Error("verdict has no observation time, so nothing downstream will treat it as evidence")
	}
	if verdict.ExecutorID != ex.ID() {
		t.Errorf("verdict.ExecutorID = %q, want %q — a verdict that does not name its executor is "+
			"replayable against a different cluster", verdict.ExecutorID, ex.ID())
	}
	if verdict.ProbeVersion != CurrentProbeVersion {
		t.Errorf("verdict.ProbeVersion = %d, want %d", verdict.ProbeVersion, CurrentProbeVersion)
	}
	if verdict.Namespace == "" {
		t.Error("verdict names no namespace, but a NetworkPolicy is namespaced")
	}
	assertProbeCleanedUp(t, api)

	// And the capability follows from it, which is the point of the whole file.
	ex.RecordNetworkPolicyVerdict(verdict)
	if !ex.Capabilities().SupportsEgressScope {
		t.Error("a proven cluster still refuses per-project egress scopes")
	}
}

// TestProbe_CNIHostileCluster is the case the capability comment has always
// named: the API server accepts the policy, returns 201, and nothing applies it.
//
// The probe must notice. Recording enforcement here — because the object was
// created without error — is exactly the silent over-permission the whole
// mechanism exists to prevent.
func TestProbe_CNIHostileCluster(t *testing.T) {
	ex, api, cluster := probeExecutor(t)
	cluster.policedExit = 0 // the policy was stored and ignored
	cluster.start()

	verdict, err := runProbe(t, ex)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if verdict.Enforced {
		t.Fatal("the probe reported enforcement on a cluster where the policed connection succeeded")
	}
	if !strings.Contains(strings.ToLower(verdict.Detail), "flannel") {
		t.Errorf("the refutation does not name the well-known cause an operator would recognise: %q",
			verdict.Detail)
	}
	// The policy really was created — this is not a case where the probe failed
	// to apply one and mistook that for non-enforcement.
	if api.policyCreateCount() == 0 {
		t.Error("no NetworkPolicy was ever created, so the experiment did not run")
	}
	assertProbeCleanedUp(t, api)

	ex.RecordNetworkPolicyVerdict(verdict)
	if ex.Capabilities().SupportsEgressScope {
		t.Error("a refuted cluster still advertises per-project egress scopes")
	}
	if status := ex.EnforcementStatus(); status != EnforcementRefuted {
		t.Errorf("status = %q, want %q", status, EnforcementRefuted)
	}
}

// TestProbe_InconclusiveWhenControlFails is the assertion that makes this a
// proof rather than a coincidence.
//
// A namespace that already denies pod-to-pod traffic would make the policed
// client fail for a reason that has nothing to do with the policy under test.
// Reporting enforcement there would be a verdict the experiment did not earn.
func TestProbe_InconclusiveWhenControlFails(t *testing.T) {
	ex, api, cluster := probeExecutor(t)
	cluster.controlExit = 1 // nothing can reach anything here
	cluster.policedExit = 1
	cluster.start()

	verdict, err := runProbe(t, ex)
	if !errors.Is(err, ErrProbeInconclusive) {
		t.Fatalf("err = %v, want ErrProbeInconclusive — a probe whose control failed proved nothing", err)
	}
	if verdict.Recorded() {
		t.Errorf("an inconclusive probe returned a recorded verdict: %+v", verdict)
	}
	if !strings.Contains(err.Error(), "control") {
		t.Errorf("the error does not say which half of the experiment failed: %v", err)
	}
	assertProbeCleanedUp(t, api)
}

// TestProbe_InconclusiveWhenTargetNeverServes covers the other way the
// experiment can fail to start: a probe image with no HTTP server in it.
//
// It matters because the symptom is identical to enforcement from the client's
// point of view — nothing answers — and the probe must not read its own broken
// setup as a finding about the cluster.
func TestProbe_InconclusiveWhenTargetNeverServes(t *testing.T) {
	ex, api, cluster := probeExecutor(t)
	cluster.targetFails = true
	cluster.start()

	verdict, err := runProbe(t, ex)
	if !errors.Is(err, ErrProbeInconclusive) {
		t.Fatalf("err = %v, want ErrProbeInconclusive", err)
	}
	if verdict.Recorded() {
		t.Errorf("a probe whose target never served returned a verdict: %+v", verdict)
	}
	assertProbeCleanedUp(t, api)
}

// TestProbe_CleansUpWhenTheContextIsCancelled.
//
// The janitor runs on a context detached from the caller's precisely because
// the usual reason cleanup runs is that the caller's context is already done.
// Inheriting it would make the probe leak exactly when it most needs not to.
func TestProbe_CleansUpWhenTheContextIsCancelled(t *testing.T) {
	ex, api, cluster := probeExecutor(t)
	// Never transition anything: the probe will sit waiting for the target.
	_ = cluster

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = ex.ProbeNetworkPolicyEnforcement(ctx, ProbeOptions{Timeout: 20 * time.Second})
	}()

	// Wait until the target Pod exists, then pull the rug out.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(api.podNames()) == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if len(api.podNames()) == 0 {
		cancel()
		<-done
		t.Fatal("the probe created no Pod")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the probe did not return after its context was cancelled")
	}
	assertProbeCleanedUp(t, api)
}

// TestProbe_ForbiddenRBACIsInconclusiveAndNamesTheRule.
//
// An operator who cannot create NetworkPolicies has learned something useful —
// the egress filter would not have worked either — and the remedy is a Role
// they can paste rather than a 403 they have to interpret.
func TestProbe_ForbiddenRBACIsInconclusive(t *testing.T) {
	ex, api, cluster := probeExecutor(t)
	cluster.start()
	api.failAlways("POST /networkpolicies", apiFailure{
		Code: 403, Reason: "Forbidden",
		Message: `networkpolicies.networking.k8s.io is forbidden: User "system:serviceaccount:cloop:runner" cannot create resource "networkpolicies"`,
	})

	verdict, err := runProbe(t, ex)
	if !errors.Is(err, ErrProbeInconclusive) {
		t.Fatalf("err = %v, want ErrProbeInconclusive", err)
	}
	if verdict.Recorded() {
		t.Errorf("a probe that could not apply its policy returned a verdict: %+v", verdict)
	}
	if !strings.Contains(err.Error(), "networkpolicies") {
		t.Errorf("the error does not name the RBAC rule that is missing: %v", err)
	}
	assertProbeCleanedUp(t, api)
}

// TestBuildProbeDenyPolicy_SelectsOnlyItsOwnClient is the same assertion the
// per-run policy has to satisfy, and for a sharper reason: this policy denies
// *everything*. A selector that matched more than the one throwaway Pod would
// cut the network out from under a tenant who merely happened to be scheduled
// in the namespace while an operator ran a diagnostic.
func TestBuildProbeDenyPolicy_SelectsOnlyItsOwnClient(t *testing.T) {
	np, err := buildProbeDenyPolicy("cloop-netpol-probe-abc", "cloop", "k8s-test", "cloop-netpol-probe-abc")
	if err != nil {
		t.Fatalf("buildProbeDenyPolicy: %v", err)
	}
	sel := np.Spec.PodSelector.MatchLabels
	if len(sel) != 1 {
		t.Fatalf("podSelector has %d labels, want exactly the probe role: %v", len(sel), sel)
	}
	if got := sel[labelProbeRole]; got != probeRoleValue("cloop-netpol-probe-abc") {
		t.Errorf("podSelector[%s] = %q, want the run-scoped role value", labelProbeRole, got)
	}
	for _, shared := range []string{LabelManaged, LabelExecutorID, LabelHandleID, labelProbe} {
		if _, ok := sel[shared]; ok {
			t.Errorf("the deny-all policy selects the shared label %q — it would deny egress for "+
				"every Pod carrying it", shared)
		}
	}
	// Two concurrent probes must not police each other.
	if probeRoleValue("run-a") == probeRoleValue("run-b") {
		t.Error("two probe runs produce the same role value")
	}
	// No egress rules at all, and no DNS hole: the client dials a literal
	// address, and leaving DNS open would test a policy nobody runs.
	if len(np.Spec.Egress) != 0 {
		t.Errorf("the deny-all policy has %d egress rule(s), want none: %+v", len(np.Spec.Egress), np.Spec.Egress)
	}
	// And the sweep can find it, so a SIGKILLed probe's policy is collected.
	if !matchesSelector(np.Metadata.Labels, executorLabelSelector("k8s-test")) {
		t.Errorf("labels %v do not match the sweep selector, so an abandoned probe policy would "+
			"never be reaped", np.Metadata.Labels)
	}
}

// TestBuildProbePods_AreConfinedLikeAHarness.
//
// The probe runs a third-party image on an operator's cluster on their behalf.
// It gets no more privilege than the workloads it is clearing the way for, and
// it carries a deadline so that a probe killed with SIGKILL — the one exit path
// the janitor cannot cover — still has its Pods removed by the cluster.
func TestBuildProbePods_AreConfinedLikeAHarness(t *testing.T) {
	opts := Options{ID: "k8s-test", Namespace: "cloop"}
	pods := map[string]*pod{
		"target": buildProbeTargetPod("cloop-netpol-probe-a-target", "cloop", "k8s-test", probeImage, opts),
		"client": buildProbeClientPod("cloop-netpol-probe-a-control", "cloop", "k8s-test", probeImage, "10.42.0.7", false, opts),
	}
	for kind, p := range pods {
		t.Run(kind, func(t *testing.T) {
			if p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
				t.Error("a ServiceAccount token is mounted into a throwaway diagnostic Pod")
			}
			if p.Spec.ActiveDeadlineSeconds == nil || *p.Spec.ActiveDeadlineSeconds <= 0 {
				t.Error("no activeDeadlineSeconds, so a SIGKILLed probe leaves this Pod running forever")
			}
			if p.Spec.RestartPolicy != "Never" {
				t.Errorf("restartPolicy = %q, want Never", p.Spec.RestartPolicy)
			}
			sc := p.Spec.Containers[0].SecurityContext
			if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				t.Error("the root filesystem is writable")
			}
			if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				t.Error("privilege escalation is allowed")
			}
			if sc == nil || sc.Capabilities == nil || len(sc.Capabilities.Drop) == 0 {
				t.Error("capabilities are not dropped")
			}
			if p.Spec.SecurityContext == nil || p.Spec.SecurityContext.RunAsNonRoot == nil ||
				!*p.Spec.SecurityContext.RunAsNonRoot {
				t.Error("the Pod may run as root")
			}
		})
	}

	// The client aims at a literal address, so the experiment does not depend
	// on DNS — which a default-deny policy would also have taken away.
	cmd := strings.Join(pods["client"].Spec.Containers[0].Command, " ")
	if !strings.Contains(cmd, "10.42.0.7") {
		t.Errorf("the client does not dial the target's address: %q", cmd)
	}

	// Only the policed client carries the label the deny-all policy selects.
	// Getting this wrong is the probe's worst failure mode and its quietest: a
	// policed client with no role label is governed by nothing, connects exactly
	// as the control did, and is recorded as a *refutation* — cloop reporting
	// that the cluster ignores NetworkPolicy when it never asked it to apply one.
	if _, ok := pods["client"].Metadata.Labels[labelProbeRole]; ok {
		t.Error("the control client carries the policed role label, so the deny-all policy " +
			"would govern the baseline too and the experiment would prove nothing")
	}
	policed := buildProbeClientPod("cloop-netpol-probe-a-policed", "cloop", "k8s-test",
		probeImage, "10.42.0.7", true, opts)
	if got := policed.Metadata.Labels[labelProbeRole]; got != probeRoleValue("cloop-netpol-probe-a") {
		t.Errorf("policed client's %s = %q, want %q — the deny-all policy would select no Pod, "+
			"and an unpoliced connection would be recorded as the cluster ignoring the policy",
			labelProbeRole, got, probeRoleValue("cloop-netpol-probe-a"))
	}
}

// TestJoinHostPort_BracketsIPv6: a dual-stack cluster hands back an IPv6 pod
// address, and an unbracketed one produces a URL wget rejects — which would
// look exactly like a blocked connection.
func TestJoinHostPort_BracketsIPv6(t *testing.T) {
	if got := joinHostPort("fd00::1", 18080); got != "[fd00::1]:18080" {
		t.Errorf("joinHostPort(IPv6) = %q, want a bracketed literal", got)
	}
	if got := joinHostPort("10.42.0.7", 18080); got != "10.42.0.7:18080" {
		t.Errorf("joinHostPort(IPv4) = %q", got)
	}
}
