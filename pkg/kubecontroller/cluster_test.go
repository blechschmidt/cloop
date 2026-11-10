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
	pod := buildRunnerPod(pool, "probe-admitted", "registry.k8s.io/pause:3.9")
	pod.Metadata.OwnerReferences = nil
	admitted, err := api.createPod(context.Background(), pod)
	if err != nil {
		t.Fatalf("a runner Pod was refused in a namespace enforcing the restricted profile: %v", err)
	}
	if err := api.deletePod(context.Background(), ns, admitted.Metadata.Name, admitted.Metadata.UID); err != nil {
		t.Fatalf("delete the admitted Pod: %v", err)
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
