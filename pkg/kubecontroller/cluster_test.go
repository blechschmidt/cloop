package kubecontroller

// cluster_test.go runs the controller against a real API server — what the
// fake cannot vouch for: that the API server accepts the CRD (its structural
// schema, and CEL rules that only compile there), that it refuses the specs
// the rules refuse, that a runner Pod is admitted in a namespace that enforces
// the restricted Pod Security Standard, that the status subresource, Lease
// and Event the controller writes are ones it accepts, and that its garbage
// collector takes the runner Pods and their Secrets with their pool.
//
// Opt-in: CLOOP_KUBECONTROLLER_E2E=1 and KUBECONFIG naming a cluster where the
// caller may install a CRD and create a namespace. The hub stays the fake one,
// on this host: the runner Pods never reach it, which is not what is checked.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

func clusterKubeconfig(t *testing.T) (string, *kubernetes.RESTConfig) {
	t.Helper()
	if os.Getenv("CLOOP_KUBECONTROLLER_E2E") == "" {
		t.Skip("set CLOOP_KUBECONTROLLER_E2E=1 and KUBECONFIG to run the controller against a real cluster")
	}
	path := os.Getenv("KUBECONFIG")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("KUBECONFIG: %v", err)
	}
	rc, err := kubernetes.ParseKubeconfig(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	return path, rc
}

func kubectlIn(t *testing.T, kubeconfig string, stdin []byte, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestAgainstARealAPIServer(t *testing.T) {
	kubeconfig, rc := clusterKubeconfig(t)
	fastTimings(t)

	// The CRD is accepted, and established.
	if out, err := kubectlIn(t, kubeconfig, CRD(), "apply", "-f", "-"); err != nil {
		t.Fatalf("the API server refused the CRD: %v\n%s", err, out)
	}
	if out, err := kubectlIn(t, kubeconfig, nil, "wait", "--for=condition=Established", "--timeout=60s",
		"crd/"+CRDName); err != nil {
		t.Fatalf("the CRD was not established: %v\n%s", err, out)
	}

	ns := fmt.Sprintf("cloop-xpool-%d", time.Now().UnixNano()%1e8)
	nsYAML := "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: " + ns + "\n  labels:\n" +
		"    pod-security.kubernetes.io/enforce: restricted\n    pod-security.kubernetes.io/enforce-version: latest\n"
	if out, err := kubectlIn(t, kubeconfig, []byte(nsYAML), "apply", "-f", "-"); err != nil {
		t.Fatalf("namespace: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = kubectlIn(t, kubeconfig, nil, "delete", "namespace", ns, "--wait=false") })
	// A Pod is refused until the namespace's default ServiceAccount exists.
	for i := 0; ; i++ {
		if _, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "serviceaccount", "default"); err == nil {
			break
		}
		if i > 100 {
			t.Fatal("the namespace's default ServiceAccount never appeared")
		}
		time.Sleep(200 * time.Millisecond)
	}

	poolYAML := func(name string, spec map[string]any) []byte {
		b, _ := json.Marshal(map[string]any{"apiVersion": APIVersion, "kind": Kind,
			"metadata": map[string]any{"name": name, "namespace": ns}, "spec": spec})
		return b
	}
	base := func() map[string]any {
		return map[string]any{"hubURL": "https://cloop.example.com", "maxRunners": 3,
			"poolCredentialSecretRef": map[string]any{"name": "pool-cred"}}
	}

	// The CRD's rules refuse what Validate refuses.
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"min-over-max", func(s map[string]any) { s["minRunners"] = 5 }, "minRunners must not exceed maxRunners"},
		{"plaintext", func(s map[string]any) { s["hubURL"] = "http://cloop.example.com" }, "https"},
		{"long-delay", func(s map[string]any) { s["scaleDownDelay"] = "25h" }, "scaleDownDelay"},
		{"bad-delay", func(s map[string]any) { s["scaleDownDelay"] = "soon" }, "scaleDownDelay"},
		{"reserved-label", func(s map[string]any) { s["runnerLabels"] = map[string]any{"cloop.dev/x": "y"} }, "controller's"},
		{"reserved-env", func(s map[string]any) {
			s["template"] = map[string]any{"env": []any{map[string]any{"name": "CLOOP_X",
				"secretKeyRef": map[string]any{"name": "s", "key": "k"}}}}
		}, "CLOOP_"},
		{"exists-with-value", func(s map[string]any) {
			s["template"] = map[string]any{"tolerations": []any{map[string]any{"key": "k", "operator": "Exists", "value": "v"}}}
		}, "takes no value"},
		{"bad-resource", func(s map[string]any) {
			s["template"] = map[string]any{"resources": map[string]any{"limits": map[string]any{"gpu": "1"}}}
		}, "cpu, memory and ephemeral-storage"},
		{"no-max", func(s map[string]any) { delete(s, "maxRunners") }, "maxRunners"},
		{"credential-env", func(s map[string]any) {
			s["template"] = map[string]any{"env": []any{map[string]any{"name": "X",
				"secretKeyRef": map[string]any{"name": "pool-cred", "key": "credential"}}}}
		}, "never given the Secret"},
		// Runner volumes (Task 20484).
		{"persistence-no-size", func(s map[string]any) { s["persistence"] = map[string]any{"enabled": true} },
			"persistence.size is required"},
		{"persistence-rwop-mixed", func(s map[string]any) {
			s["persistence"] = map[string]any{"enabled": true, "size": "1Gi",
				"accessModes": []any{"ReadWriteOncePod", "ReadWriteOnce"}}
		}, "ReadWriteOncePod cannot be combined"},
		{"persistence-few-claims", func(s map[string]any) {
			s["persistence"] = map[string]any{"enabled": true, "size": "1Gi", "maxClaims": 1}
		}, "maxClaims must not be fewer than maxRunners"},
		{"persistence-milli-size", func(s map[string]any) {
			s["persistence"] = map[string]any{"enabled": true, "size": "10m"}
		}, "persistence.size"},
		{"persistence-bad-mount", func(s map[string]any) {
			s["persistence"] = map[string]any{"enabled": true, "size": "1Gi", "mounts": []any{"home"}}
		}, "mounts"},
	} {
		spec := base()
		tc.mutate(spec)
		out, err := kubectlIn(t, kubeconfig, poolYAML("bad-"+tc.name, spec), "apply", "-f", "-")
		if err == nil {
			t.Errorf("%s: the API server accepted a spec Validate refuses", tc.name)
			continue
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s: refused with %q, want it to name %q", tc.name, out, tc.want)
		}
		var s ExecutorPoolSpec
		b, _ := json.Marshal(spec)
		_ = json.Unmarshal(b, &s)
		if len(s.Normalize().Validate()) == 0 {
			t.Errorf("%s: the API server refuses it and Validate does not", tc.name)
		}
	}

	// A runner Pod is admitted under the restricted profile.
	api := &kubeAPI{c: mustRealClient(t, rc)}
	pool := &ExecutorPool{Metadata: ObjectMeta{Name: "probe", Namespace: ns, UID: "00000000-0000-0000-0000-000000000000"},
		Spec: validSpec()}
	pod := buildRunnerPod(pool, "probe-admitted", "registry.k8s.io/pause:3.9", nil)
	pod.Metadata.OwnerReferences = nil
	admitted, err := api.createPod(context.Background(), pod)
	if err != nil {
		t.Fatalf("a runner Pod was refused in a namespace enforcing the restricted profile: %v", err)
	}
	if err := api.deletePod(context.Background(), ns, admitted.Metadata.Name, admitted.Metadata.UID); err != nil {
		t.Fatalf("delete the admitted Pod: %v", err)
	}

	// Runner volumes (Task 20484): a persistent pool is accepted; a claim's
	// metadata patch carrying a resourceVersion is a compare-and-swap that
	// keeps the protection finalizer and every other annotation; and a runner
	// Pod with its volume, init container and memory-backed emptyDir is
	// admitted under the restricted profile.
	persistent := base()
	persistent["persistence"] = map[string]any{"enabled": true, "size": "1Gi", "reclaimPolicy": "Retain",
		"mounts": []any{"workspace", "toolCache"}}
	if out, err := kubectlIn(t, kubeconfig, poolYAML("persistent", persistent), "apply", "-f", "-"); err != nil {
		t.Fatalf("a valid persistent pool: %v\n%s", err, out)
	}
	p := (&Persistence{Enabled: true, Size: "1Gi"}).normalized(3)
	probeClaim := buildClaim(pool, p, claimName(pool, 0), 0)
	// The probe pool exists nowhere: the garbage collector would take a claim
	// it owned.
	probeClaim.Metadata.OwnerReferences = nil
	claim, err := api.createClaim(context.Background(), probeClaim)
	if err != nil {
		t.Fatalf("create a runner volume: %v", err)
	}
	claimed, err := api.patchClaimMeta(context.Background(), ns, claim.Metadata.Name, claim.Metadata.ResourceVersion,
		map[string]*string{AnnotationClaimedBy: ptr("probe-a"), AnnotationHolds: ptr(holdsUnknown)}, nil, nil)
	if err != nil {
		t.Fatalf("claim the volume: %v", err)
	}
	if _, err := api.patchClaimMeta(context.Background(), ns, claim.Metadata.Name, claim.Metadata.ResourceVersion,
		map[string]*string{AnnotationClaimedBy: ptr("probe-b")}, nil, nil); !kubernetes.IsConflict(err) {
		t.Fatalf("a claim against a stale resourceVersion: %v, want a 409 Conflict", err)
	}
	got, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "pvc", claim.Metadata.Name, "-o",
		`jsonpath={.metadata.annotations.cloop\.dev/claimed-by} {.metadata.annotations.cloop\.dev/executor-pool} {.metadata.finalizers}`)
	if err != nil || !strings.Contains(got, "probe-a probe") || !strings.Contains(got, "kubernetes.io/pvc-protection") {
		t.Fatalf("the claimed volume reads %q (%v)", got, err)
	}
	released, err := api.patchClaimMeta(context.Background(), ns, claim.Metadata.Name, claimed.Metadata.ResourceVersion,
		map[string]*string{AnnotationClaimedBy: nil}, nil, &[]OwnerReference{})
	if err != nil || released.Metadata.Annotations[AnnotationClaimedBy] != "" ||
		released.Metadata.Annotations[AnnotationHolds] != holdsUnknown {
		t.Fatalf("release: %v %v", err, released)
	}
	storagePod := buildRunnerPod(pool, "probe-storage", "registry.k8s.io/pause:3.9",
		&runnerStorage{claim: claim.Metadata.Name, wipe: true, p: p})
	storagePod.Metadata.OwnerReferences = nil
	admittedStorage, err := api.createPod(context.Background(), storagePod)
	if err != nil {
		t.Fatalf("a runner Pod with a volume was refused under the restricted profile: %v", err)
	}
	if err := api.deletePod(context.Background(), ns, admittedStorage.Metadata.Name, admittedStorage.Metadata.UID); err != nil {
		t.Fatalf("delete the admitted Pod: %v", err)
	}
	if err := api.deleteClaim(context.Background(), ns, claim.Metadata.Name, claim.Metadata.UID); err != nil {
		t.Fatalf("delete the volume: %v", err)
	}

	// The controller, end to end against the real API server.
	h := newFakeHub(t)
	h.setDemand(1)
	secretYAML := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: pool-cred\n  namespace: " + ns +
		"\nstringData:\n  credential: " + fakeCredential + "\n"
	if out, err := kubectlIn(t, kubeconfig, []byte(secretYAML), "apply", "-f", "-"); err != nil {
		t.Fatalf("credential Secret: %v\n%s", err, out)
	}
	spec := base()
	spec["hubURL"] = h.url()
	spec["template"] = map[string]any{"image": "registry.k8s.io/pause:3.9"}
	if out, err := kubectlIn(t, kubeconfig, poolYAML("build", spec), "apply", "-f", "-"); err != nil {
		t.Fatalf("a valid pool: %v\n%s", err, out)
	}
	logs := &logBuf{}
	c, err := New(Options{REST: rc, Namespace: ns, Resync: 5 * time.Second, Logf: logs.logf,
		HubTransport: h.srv.Client().Transport, ImageResolver: fakeResolver{},
		ImageVerifier: fakeVerifier{status: imagepolicy.ProvenanceVerified},
		LeaderElection: &LeaderElection{Namespace: ns, Name: "cloop-executor-controller", Identity: "e2e",
			LeaseDuration: 3 * time.Second, RenewDeadline: 2 * time.Second, RetryPeriod: 500 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s\n%s", what, logs.all())
	}
	var runnerPod string
	waitFor("a runner Pod and its Secret", func() bool {
		out, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "secrets", "-l", LabelManagedBy+"="+ManagedBy,
			"-o", "jsonpath={.items[*].metadata.name}")
		if err != nil || strings.TrimSpace(out) == "" {
			return false
		}
		runnerPod = strings.Fields(out)[0]
		return true
	})
	out, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "secret", runnerPod, "-o",
		"jsonpath={.metadata.ownerReferences[0].kind}/{.metadata.ownerReferences[0].name}")
	if err != nil || strings.TrimSpace(out) != "Pod/"+runnerPod {
		t.Fatalf("the runner Secret's owner: %q %v", out, err)
	}
	waitFor("Ready=True with observedGeneration", func() bool {
		out, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", Plural+"/build", "-o",
			`jsonpath={.status.conditions[?(@.type=="Ready")].status} {.status.observedGeneration} {.status.poolID}`)
		return err == nil && strings.TrimSpace(out) == "True 1 "+h.poolID
	})
	if out, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "lease", "cloop-executor-controller", "-o",
		"jsonpath={.spec.holderIdentity}"); err != nil || strings.TrimSpace(out) != "e2e" {
		t.Fatalf("the Lease: %q %v", out, err)
	}
	waitFor("a ScaledUp Event", func() bool {
		out, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "events", "--field-selector",
			"involvedObject.name=build,reason="+ReasonScaledUp, "-o", "name")
		return err == nil && strings.TrimSpace(out) != ""
	})

	// Deleting the pool takes its runner Pods, and their Secrets with them.
	cancel()
	<-done
	if out, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "delete", Plural+"/build", "--wait=true"); err != nil {
		t.Fatalf("delete the pool: %v\n%s", err, out)
	}
	waitFor("the runner Pod and Secret collected with their pool", func() bool {
		pods, _ := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "pods", "-l", LabelManagedBy+"="+ManagedBy, "-o", "name")
		secrets, _ := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "secrets", "-l", LabelManagedBy+"="+ManagedBy, "-o", "name")
		return strings.TrimSpace(pods) == "" && strings.TrimSpace(secrets) == ""
	})
}

func mustRealClient(t *testing.T, rc *kubernetes.RESTConfig) *kubernetes.APIClient {
	t.Helper()
	c, err := kubernetes.NewAPIClient(rc, kubernetes.APIClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestRunnerVolumesOnARealCluster runs a persistent pool's runner on a real
// volume (Task 20484): the controller creates the claim and the Pod, the init
// container — `cloop executor runner-storage`, as the runner's own user under
// the restricted profile — prepares the volume and reports on its
// termination log, the agent accepts the layout and stays up, and once the
// runner is gone its claim is released. Needs, besides the cluster, an image
// with this build's cloop loaded into it:
// CLOOP_KUBECONTROLLER_E2E_IMAGE (pulled with policy Never).
func TestRunnerVolumesOnARealCluster(t *testing.T) {
	kubeconfig, rc := clusterKubeconfig(t)
	image := os.Getenv("CLOOP_KUBECONTROLLER_E2E_IMAGE")
	if image == "" {
		t.Skip("set CLOOP_KUBECONTROLLER_E2E_IMAGE to an image with this build's cloop, loaded into the cluster")
	}
	fastTimings(t)
	if out, err := kubectlIn(t, kubeconfig, CRD(), "apply", "-f", "-"); err != nil {
		t.Fatalf("the CRD: %v\n%s", err, out)
	}
	ns := fmt.Sprintf("cloop-xvol-%d", time.Now().UnixNano()%1e8)
	nsYAML := "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: " + ns + "\n  labels:\n" +
		"    pod-security.kubernetes.io/enforce: restricted\n    pod-security.kubernetes.io/enforce-version: latest\n"
	if out, err := kubectlIn(t, kubeconfig, []byte(nsYAML), "apply", "-f", "-"); err != nil {
		t.Fatalf("namespace: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = kubectlIn(t, kubeconfig, nil, "delete", "namespace", ns, "--wait=false") })
	for i := 0; ; i++ {
		if _, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "serviceaccount", "default"); err == nil {
			break
		}
		if i > 100 {
			t.Fatal("the namespace's default ServiceAccount never appeared")
		}
		time.Sleep(200 * time.Millisecond)
	}
	h := newFakeHub(t)
	h.setDemand(1)
	secretYAML := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: pool-cred\n  namespace: " + ns +
		"\nstringData:\n  credential: " + fakeCredential + "\n"
	if out, err := kubectlIn(t, kubeconfig, []byte(secretYAML), "apply", "-f", "-"); err != nil {
		t.Fatalf("credential Secret: %v\n%s", err, out)
	}
	pool, _ := json.Marshal(map[string]any{"apiVersion": APIVersion, "kind": Kind,
		"metadata": map[string]any{"name": "vol", "namespace": ns},
		"spec": map[string]any{"hubURL": h.url(), "maxRunners": 1,
			"poolCredentialSecretRef": map[string]any{"name": "pool-cred"},
			"template":                map[string]any{"image": image, "imagePullPolicy": "Never"},
			"persistence":             map[string]any{"enabled": true, "size": "64Mi", "minFree": "1Mi"}}})
	if out, err := kubectlIn(t, kubeconfig, pool, "apply", "-f", "-"); err != nil {
		t.Fatalf("the pool: %v\n%s", err, out)
	}
	logs := &logBuf{}
	c, err := New(Options{REST: rc, Namespace: ns, Resync: 5 * time.Second, Logf: logs.logf,
		HubTransport: h.srv.Client().Transport, ImageResolver: fakeResolver{},
		ImageVerifier: fakeVerifier{status: imagepolicy.ProvenanceVerified}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(150 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		pods, _ := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "pods,pvc", "-o", "wide")
		t.Fatalf("timed out waiting for %s\n%s\ncontroller log:\n%s", what, pods, logs.all())
	}
	jp := func(kind, name, path string) string {
		out, _ := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", kind, name, "-o", "jsonpath="+path)
		return strings.TrimSpace(out)
	}
	var pod string
	waitFor("the init container to finish", func() bool {
		out, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "pods", "-l", LabelManagedBy+"="+ManagedBy,
			"-o", "jsonpath={.items[*].metadata.name}")
		if err != nil || strings.TrimSpace(out) == "" {
			return false
		}
		pod = strings.Fields(out)[0]
		return jp("pod", pod, "{.status.initContainerStatuses[0].state.terminated.exitCode}") != ""
	})
	if code := jp("pod", pod, "{.status.initContainerStatuses[0].state.terminated.exitCode}"); code != "0" {
		t.Fatalf("the init container exited %s: %s", code,
			jp("pod", pod, "{.status.initContainerStatuses[0].state.terminated.message}"))
	}
	var rep PrepareReport
	msg := jp("pod", pod, "{.status.initContainerStatuses[0].state.terminated.message}")
	if err := json.Unmarshal([]byte(msg), &rep); err != nil || !rep.Wiped || rep.CapacityBytes <= 0 {
		t.Fatalf("the init container reported %q (%v)", msg, err)
	}
	claim := claimName(&ExecutorPool{Metadata: ObjectMeta{Name: "vol"}}, 0)
	if phase := jp("pvc", claim, "{.status.phase}"); phase != ClaimBound {
		t.Fatalf("the runner's claim is %s", phase)
	}
	if by := jp("pvc", claim, `{.metadata.annotations.cloop\.dev/claimed-by}`); by != pod {
		t.Fatalf("the claim names %q, not its runner %s", by, pod)
	}
	// The agent took the layout — trees on the volume, homes and leased
	// files in memory — and is trying to reach the hub, not refusing it.
	waitFor("the runner container running", func() bool {
		return jp("pod", pod, "{.status.containerStatuses[0].state.running.startedAt}") != ""
	})
	time.Sleep(3 * time.Second)
	if term := jp("pod", pod, "{.status.containerStatuses[0].state.terminated.message}"); term != "" {
		t.Fatalf("the runner exited: %s", term)
	}
	// The hub hands the runner a run of web, which the volume records.
	web := executorpool.ProjectTenant(h.poolID, "/srv/web", "")
	var id string
	for e := range h.states() {
		id = e
	}
	h.enroll(id, time.Now())
	if !h.assignProject(id, web, "web", "") {
		t.Fatalf("the hub would not hand runner %s a run of web", id)
	}
	waitFor("the volume recording web", func() bool {
		return jp("pvc", claim, `{.metadata.annotations.cloop\.dev/holds}`) == web
	})
	// Once the runner is gone, its claim is released.
	h.setDemand(0)
	if out, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "delete", "pod", pod, "--wait=true"); err != nil {
		t.Fatalf("delete the runner: %v\n%s", err, out)
	}
	h.finish(id)
	waitFor("the claim released", func() bool {
		return jp("pvc", claim, `{.metadata.annotations.cloop\.dev/claimed-by}`) == "" &&
			jp("pvc", claim, `{.metadata.annotations.cloop\.dev/released-at}`) != ""
	})

	// web's next run gets the volume back unwiped, on a runner started
	// holding web, which the agent in a restricted Pod accepts.
	h.queue(web, 1)
	var next string
	waitFor("web's next runner prepared", func() bool {
		out, err := kubectlIn(t, kubeconfig, nil, "-n", ns, "get", "pods", "-l", LabelManagedBy+"="+ManagedBy,
			"-o", "jsonpath={.items[*].metadata.name}")
		if err != nil {
			return false
		}
		for _, p := range strings.Fields(out) {
			if p != pod {
				next = p
			}
		}
		return next != "" && jp("pod", next, "{.status.initContainerStatuses[0].state.terminated.exitCode}") != ""
	})
	if code := jp("pod", next, "{.status.initContainerStatuses[0].state.terminated.exitCode}"); code != "0" {
		t.Fatalf("the init container exited %s: %s", code,
			jp("pod", next, "{.status.initContainerStatuses[0].state.terminated.message}"))
	}
	rep = PrepareReport{}
	msg = jp("pod", next, "{.status.initContainerStatuses[0].state.terminated.message}")
	if err := json.Unmarshal([]byte(msg), &rep); err != nil || rep.Wiped {
		t.Fatalf("web's own volume was prepared as %q (%v); want it kept", msg, err)
	}
	if got := jp("pod", next, "{.spec.volumes[?(@.name==\""+storageVolume+"\")].persistentVolumeClaim.claimName}"); got != claim {
		t.Fatalf("web's next runner mounts %q, not its volume %s", got, claim)
	}
	if args := jp("pod", next, "{.spec.containers[0].args}"); !strings.Contains(args, `"--holds","`+web+`"`) {
		t.Fatalf("web's next runner was started with %s, not --holds %s", args, web)
	}
	waitFor("web's runner container running", func() bool {
		return jp("pod", next, "{.status.containerStatuses[0].state.running.startedAt}") != ""
	})
	time.Sleep(3 * time.Second)
	if term := jp("pod", next, "{.status.containerStatuses[0].state.terminated.message}"); term != "" {
		t.Fatalf("the runner holding web exited: %s", term)
	}
}
