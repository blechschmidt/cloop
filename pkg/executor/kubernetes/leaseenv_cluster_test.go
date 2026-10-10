package kubernetes

// leaseenv_cluster_test.go proves on a real kubelet what leaseenv_test.go and
// configerror_test.go can only model against the fake API server:
//
//   - that the Pod buildPod renders, with its environment as secretKeyRefs into
//     the Secret leaseSecretData renders, starts a container that sees every
//     value — and that the Pod object the API server stores holds none of them;
//   - that a missing Secret, and a missing key, hold the container in
//     CreateContainerConfigError with a message secretNamedIn can read. That
//     wording is the kubelet's, not ours, and configerror.go's explanation
//     depends on it; a kubelet that changed it would turn a named failure into
//     a generic one, and only a real one can say so.
//
// Opt-in, with the same switch as ownerref_cluster_test.go:
//
//	kind create cluster --name cloop-gc
//	kind load docker-image alpine:3.21 --name cloop-gc
//	CLOOP_K8S_GC_E2E=1 go test ./pkg/executor/kubernetes/ -run RealCluster -v
//
// CLOOP_K8S_ENV_E2E_IMAGE overrides the image; it needs /bin/sh and sha256sum.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const defaultEnvE2EImage = "alpine:3.21"

// TestLeaseEnv_RealClusterResolvesTheEnvironmentFromTheSecret is the happy
// path on a real node.
func TestLeaseEnv_RealClusterResolvesTheEnvironmentFromTheSecret(t *testing.T) {
	ctxName := requireCluster(t)
	ns := envE2ENamespace(t, ctxName)

	const key = "sk-ant-api03-REAL-CLUSTER-ENV-E2E-0123456789"
	handle := "k-e2e-env-ok"
	req := envE2ERequest(ns, handle, []string{
		"ANTHROPIC_API_KEY=" + key,
		"HTTPS_PROXY=http://session:REAL-CLUSTER-PROXY-TOKEN@hub:3128",
		"CLOOP_REDACT_ENV=ANTHROPIC_API_KEY,HTTPS_PROXY",
	}, `printf 'KEYSHA=%s\n' "$(printf %s "$ANTHROPIC_API_KEY" | sha256sum | cut -d' ' -f1)"; `+
		`printf 'PROXY=%s\n' "${HTTPS_PROXY:+set}"; printf 'REDACT=%s\n' "$CLOOP_REDACT_ENV"`)

	podName := createE2EPod(t, ctxName, req)
	createE2ELeaseSecret(t, ctxName, req, podName, nil)

	waitE2E(t, "the Pod to succeed", 3*time.Minute, func() (bool, string) {
		phase, _ := kubectl(t, ctxName, nil, "get", "pod", podName, "-n", ns, "-o", "jsonpath={.status.phase}")
		return strings.TrimSpace(phase) == phaseSucceeded, phase
	})
	logs, err := kubectl(t, ctxName, nil, "logs", podName, "-n", ns, "-c", ContainerName)
	if err != nil {
		t.Fatalf("logs: %v\n%s", err, logs)
	}
	sum := sha256.Sum256([]byte(key))
	for _, want := range []string{"KEYSHA=" + hex.EncodeToString(sum[:]), "PROXY=set",
		"REDACT=ANTHROPIC_API_KEY,HTTPS_PROXY"} {
		if !strings.Contains(logs, want) {
			t.Errorf("the container did not see %q in its environment; it printed:\n%s", want, logs)
		}
	}

	stored, err := kubectl(t, ctxName, nil, "get", "pod", podName, "-n", ns, "-o", "json")
	if err != nil {
		t.Fatalf("get pod: %v\n%s", err, stored)
	}
	for _, v := range []string{key, "REAL-CLUSTER-PROXY-TOKEN"} {
		if strings.Contains(stored, v) {
			t.Errorf("the Pod object the API server stores contains %q", v)
		}
	}
	if !strings.Contains(stored, `"key": "env.ANTHROPIC_API_KEY"`) {
		t.Errorf("the stored Pod does not reference env.ANTHROPIC_API_KEY:\n%s", stored)
	}
}

// TestLeaseEnv_RealClusterNamesTheMissingSecret pins the kubelet's wording for
// both ways a reference fails to resolve.
func TestLeaseEnv_RealClusterNamesTheMissingSecret(t *testing.T) {
	ctxName := requireCluster(t)
	ns := envE2ENamespace(t, ctxName)

	cases := []struct {
		name   string
		handle string
		// create, when non-nil, makes the Secret holding only these keys.
		keep []string
	}{
		{name: "no Secret at all", handle: "k-e2e-env-gone"},
		{name: "a Secret missing the key", handle: "k-e2e-env-nokey", keep: []string{"env.PRESENT"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := envE2ERequest(ns, tc.handle, []string{"PRESENT=1", "ABSENT=2"}, "true")
			podName := createE2EPod(t, ctxName, req)
			if tc.keep != nil {
				createE2ELeaseSecret(t, ctxName, req, podName, tc.keep)
			}

			var msg string
			waitE2E(t, "CreateContainerConfigError", 3*time.Minute, func() (bool, string) {
				raw, _ := kubectl(t, ctxName, nil, "get", "pod", podName, "-n", ns, "-o", "json")
				var p pod
				if json.Unmarshal([]byte(raw), &p) != nil {
					return false, "undecodable pod"
				}
				_, w := stuckContainer(&p)
				if w == nil {
					return false, fmt.Sprintf("phase %s, statuses %+v", p.Status.Phase, p.Status.ContainerStatuses)
				}
				msg = w.Message
				return true, ""
			})
			if got := secretNamedIn(msg); got != leaseSecretName(tc.handle) {
				t.Errorf("secretNamedIn(%q) = %q, want %q — the kubelet's wording changed and the "+
					"driver's failure no longer names the Secret", msg, got, leaseSecretName(tc.handle))
			}
			t.Logf("kubelet: %s", msg)
		})
	}
}

// --- helpers ----------------------------------------------------------

func envE2ENamespace(t *testing.T, ctxName string) string {
	t.Helper()
	ns := fmt.Sprintf("cloop-env-%d-%d", os.Getpid(), time.Now().UnixNano()%1e6)
	if out, err := kubectl(t, ctxName, nil, "create", "namespace", ns); err != nil {
		t.Fatalf("create namespace: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_, _ = kubectl(t, ctxName, nil, "delete", "namespace", ns, "--wait=false", "--ignore-not-found")
	})
	return ns
}

func envE2ERequest(ns, handle string, env []string, script string) podRequest {
	image := strings.TrimSpace(os.Getenv("CLOOP_K8S_ENV_E2E_IMAGE"))
	if image == "" {
		image = defaultEnvE2EImage
	}
	return podRequest{
		ExecutorID:      "e2e",
		HandleID:        handle,
		Namespace:       ns,
		Image:           image,
		ImagePullPolicy: "IfNotPresent",
		Argv:            []string{"/bin/sh", "-c", script},
		Env:             env,
		LeaseSecretName: leaseSecretName(handle),
		Labels:          map[string]string{"project": "/srv/e2e", "task_id": "1"},
	}
}

// createE2EPod creates the Pod buildPod renders and returns its name.
func createE2EPod(t *testing.T, ctxName string, req podRequest) string {
	t.Helper()
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	body, _ := json.Marshal(p)
	out, err := kubectl(t, ctxName, body, "create", "-f", "-", "-o", "jsonpath={.metadata.name}")
	if err != nil {
		t.Fatalf("create pod: %v\n%s", err, out)
	}
	return strings.TrimSpace(out)
}

// createE2ELeaseSecret creates the lease Secret the way Start does — after the
// Pod, owned by it — optionally keeping only some keys.
func createE2ELeaseSecret(t *testing.T, ctxName string, req podRequest, podName string, keep []string) {
	t.Helper()
	data, err := leaseSecretData(req.SecretFiles, req.Env, nil)
	if err != nil {
		t.Fatalf("leaseSecretData: %v", err)
	}
	if keep != nil {
		kept := map[string][]byte{}
		for _, k := range keep {
			kept[k] = data[k]
		}
		data = kept
	}
	raw, err := kubectl(t, ctxName, nil, "get", "pod", podName, "-n", req.Namespace, "-o", "json")
	if err != nil {
		t.Fatalf("get pod: %v\n%s", err, raw)
	}
	var owner pod
	if err := json.Unmarshal([]byte(raw), &owner); err != nil {
		t.Fatal(err)
	}
	ref, ok := podOwnerReference(&owner)
	if !ok {
		t.Fatalf("no owner reference from %+v", owner.Metadata)
	}
	obj := &secret{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: objectMeta{
			Name:            req.LeaseSecretName,
			Namespace:       req.Namespace,
			OwnerReferences: []ownerReference{ref},
		},
		Type: "Opaque",
		Data: data,
	}
	body, _ := json.Marshal(obj)
	if out, err := kubectl(t, ctxName, body, "create", "-f", "-"); err != nil {
		t.Fatalf("create secret: %v\n%s", err, out)
	}
}

func waitE2E(t *testing.T, what string, d time.Duration, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(d)
	last := ""
	for time.Now().Before(deadline) {
		ok, detail := cond()
		if ok {
			return
		}
		last = detail
		time.Sleep(time.Second)
	}
	t.Fatalf("timed out after %s waiting for %s (last: %s)", d, what, last)
}

// TestStart_RealClusterDeliversTheEnvironmentAndFailsAStrandedHarness drives
// the real Executor — Start, the pump, finish — against a real API server and
// kubelet, both ways.
//
// The stranded half needs the Secret gone before the kubelet creates the
// harness, which on an idle node is about a second after Start returns. A
// nodeSelector no node satisfies holds the Pod unscheduled for as long as the
// test needs; deleting the Secret and then labelling the node reproduces
// exactly what a hub that cleaned up mid-fetch used to do.
func TestStart_RealClusterDeliversTheEnvironmentAndFailsAStrandedHarness(t *testing.T) {
	ctxName := requireCluster(t)
	ns := envE2ENamespace(t, ctxName)
	args := []string{"config", "view", "--raw", "--minify", "--flatten"}
	raw, err := kubectl(t, ctxName, nil, args...)
	if err != nil {
		t.Fatalf("kubectl config view: %v\n%s", err, raw)
	}
	rest, err := ParseKubeconfig([]byte(raw), "")
	if err != nil {
		t.Fatalf("ParseKubeconfig: %v", err)
	}
	image := strings.TrimSpace(os.Getenv("CLOOP_K8S_ENV_E2E_IMAGE"))
	if image == "" {
		image = defaultEnvE2EImage
	}
	gate := fmt.Sprintf("held-%d", time.Now().UnixNano()%1e9)
	newEx := func(selector map[string]string) *Executor {
		ex, err := New(Options{
			ID:                       "e2e-real",
			Namespace:                ns,
			Image:                    image,
			ImagePullPolicy:          "IfNotPresent",
			NodeSelector:             selector,
			Credentials:              newFakeSource(rest),
			configErrorGraceOverride: 2 * time.Second,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(ex.Close)
		return ex
	}
	const key = "sk-ant-api03-REAL-DRIVER-E2E-9876543210"
	sum := sha256.Sum256([]byte(key))
	spec := executor.Spec{
		Argv: []string{"/bin/sh", "-c",
			`printf 'KEYSHA=%s\n' "$(printf %s "$ANTHROPIC_API_KEY" | sha256sum | cut -d' ' -f1)"`},
		Env:    []string{"ANTHROPIC_API_KEY=" + key, "CLOOP_REDACT_ENV=ANTHROPIC_API_KEY"},
		Labels: map[string]string{"project": "/srv/e2e", "task_id": "7"},
	}

	t.Run("delivered", func(t *testing.T) {
		ex := newEx(nil)
		h, err := ex.Start(context.Background(), spec)
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		lines, err := ex.Stream(context.Background(), h.ID)
		if err != nil {
			t.Fatal(err)
		}
		podJSON, _ := kubectl(t, ctxName, nil, "get", "pods", "-n", ns, "-l", LabelHandleID+"="+h.ID, "-o", "json")
		if strings.Contains(podJSON, key) {
			t.Error("the Pod object the API server stores contains the key")
		}
		var out strings.Builder
		for l := range lines {
			out.WriteString(l.Text)
		}
		st, _ := ex.Status(context.Background(), h.ID)
		if st.State != executor.StateExited || st.ExitCode != 0 {
			t.Fatalf("state = %q exit %d (%s), want a clean exit; output:\n%s", st.State, st.ExitCode, st.Error, out.String())
		}
		if !strings.Contains(out.String(), "KEYSHA="+hex.EncodeToString(sum[:])) {
			t.Errorf("the harness did not see the key in its environment; output:\n%s", out.String())
		}
	})

	t.Run("stranded", func(t *testing.T) {
		ex := newEx(map[string]string{"cloop.dev/e2e-gate": gate})
		h, err := ex.Start(context.Background(), spec)
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		lease := leaseSecretName(h.ID)
		if out, err := kubectl(t, ctxName, nil, "delete", "secret", lease, "-n", ns); err != nil {
			t.Fatalf("delete the lease Secret: %v\n%s", err, out)
		}
		node, err := kubectl(t, ctxName, nil, "get", "nodes", "-o", "jsonpath={.items[0].metadata.name}")
		if err != nil {
			t.Fatalf("get node: %v\n%s", err, node)
		}
		node = strings.TrimSpace(node)
		t.Cleanup(func() { _, _ = kubectl(t, ctxName, nil, "label", "node", node, "cloop.dev/e2e-gate-") })
		if out, err := kubectl(t, ctxName, nil, "label", "node", node, "cloop.dev/e2e-gate="+gate, "--overwrite"); err != nil {
			t.Fatalf("label node: %v\n%s", err, out)
		}

		var st executor.Status
		waitE2E(t, "the stranded run to fail", 3*time.Minute, func() (bool, string) {
			st, _ = ex.Status(context.Background(), h.ID)
			return st.State.Terminal(), string(st.State)
		})
		if st.State != executor.StateFailed || !strings.Contains(st.Error, lease) {
			t.Fatalf("state = %q (%s), want failed naming %s", st.State, st.Error, lease)
		}
		t.Logf("failed: %s", st.Error)
		waitE2E(t, "the stranded Pod to be deleted", time.Minute, func() (bool, string) {
			out, _ := kubectl(t, ctxName, nil, "get", "pods", "-n", ns, "-l", LabelHandleID+"="+h.ID, "-o", "name")
			return strings.TrimSpace(out) == "", out
		})
	})
}
