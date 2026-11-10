package kubecontroller

// runner_test.go asserts the runner Pod's confinement exhaustively, on the
// marshalled JSON the API server would receive: the restricted Pod Security
// Standard and the controller's additions, whatever the template asks for.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func templatePool(t *testing.T) *ExecutorPool {
	t.Helper()
	spec := validSpec()
	spec.HubCAPin = "sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	spec.HubCABundle = testCAPEM(t)
	spec.RunnerLabels = map[string]string{"team": "platform"}
	spec.Template = RunnerTemplate{
		ServiceAccountName: "workload-identity", RuntimeClassName: "gvisor",
		Resources:    ResourceRequirements{Limits: map[string]Quantity{"memory": "4Gi"}},
		NodeSelector: map[string]string{"pool": "runners"},
		Tolerations:  []Toleration{{Key: "dedicated", Operator: "Exists", Effect: "NoSchedule"}},
		Affinity:     json.RawMessage(`{"podAntiAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[]}}`),
		Env: []SecretEnvVar{{Name: "ANTHROPIC_API_KEY", SecretKeyRef: SecretKeyRef{Name: "model", Key: "key"}},
			{Name: "HTTPS_PROXY", SecretKeyRef: SecretKeyRef{Name: "proxy", Key: "url"}}},
	}
	return &ExecutorPool{Metadata: ObjectMeta{Name: "build", Namespace: "runners", UID: "pool-uid"}, Spec: spec}
}

func TestARunnerPodMeetsTheRestrictedProfileWhateverItsTemplate(t *testing.T) {
	pod := buildRunnerPod(templatePool(t), "build-abc123", "ghcr.io/blechschmidt/cloop-harness@"+fakeDigest)
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	spec := doc["spec"].(map[string]any)

	if spec["restartPolicy"] != "Never" {
		t.Errorf("restartPolicy %v", spec["restartPolicy"])
	}
	if spec["automountServiceAccountToken"] != false {
		t.Error("the ServiceAccount token is mounted into a runner")
	}
	if spec["enableServiceLinks"] != false {
		t.Error("service links are on")
	}
	for _, k := range []string{"hostNetwork", "hostPID", "hostIPC", "nodeName"} {
		if v, ok := spec[k]; ok && v != false {
			t.Errorf("%s is %v", k, v)
		}
	}
	psc := spec["securityContext"].(map[string]any)
	if psc["runAsNonRoot"] != true || psc["runAsUser"] != float64(runnerUID) ||
		psc["seccompProfile"].(map[string]any)["type"] != "RuntimeDefault" {
		t.Errorf("Pod securityContext %v", psc)
	}
	containers := spec["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("%d containers", len(containers))
	}
	c := containers[0].(map[string]any)
	sc := c["securityContext"].(map[string]any)
	for k, want := range map[string]any{"runAsNonRoot": true, "allowPrivilegeEscalation": false,
		"readOnlyRootFilesystem": true, "privileged": false} {
		if sc[k] != want {
			t.Errorf("container securityContext.%s = %v, want %v", k, sc[k], want)
		}
	}
	caps := sc["capabilities"].(map[string]any)
	if drop := caps["drop"].([]any); len(drop) != 1 || drop[0] != "ALL" {
		t.Errorf("capabilities.drop %v", drop)
	}
	if _, ok := caps["add"]; ok {
		t.Errorf("capabilities.add %v", caps["add"])
	}
	if sc["seccompProfile"].(map[string]any)["type"] != "RuntimeDefault" {
		t.Error("the container's seccomp profile is not RuntimeDefault")
	}
	// Only the restricted profile's volume types, and the Secret read-only.
	for _, v := range spec["volumes"].([]any) {
		vm := v.(map[string]any)
		for k := range vm {
			if k != "name" && k != "emptyDir" && k != "secret" {
				t.Errorf("volume %v is a %s", vm["name"], k)
			}
		}
	}
	for _, m := range c["volumeMounts"].([]any) {
		mm := m.(map[string]any)
		if mm["name"] == configVolume && mm["readOnly"] != true {
			t.Error("the runner's configuration is mounted writable")
		}
	}
	// The template's choices reach the Pod.
	if spec["serviceAccountName"] != "workload-identity" || spec["runtimeClassName"] != "gvisor" ||
		spec["nodeSelector"].(map[string]any)["pool"] != "runners" || spec["affinity"] == nil ||
		len(spec["tolerations"].([]any)) != 1 {
		t.Errorf("the template's placement did not reach the Pod: %v", spec)
	}
	if c["resources"].(map[string]any)["limits"].(map[string]any)["memory"] != "4Gi" {
		t.Errorf("resources %v", c["resources"])
	}
	// The extra variables are references, never values.
	for _, e := range c["env"].([]any) {
		em := e.(map[string]any)
		if em["name"] == "HOME" {
			continue
		}
		if _, hasValue := em["value"]; hasValue {
			t.Errorf("variable %v carries a value in the Pod", em["name"])
		}
		if em["valueFrom"].(map[string]any)["secretKeyRef"] == nil {
			t.Errorf("variable %v is not a secretKeyRef", em["name"])
		}
	}
	args := strings.Join(toStrings(c["args"].([]any)), " ")
	if !strings.Contains(args, "executor agent --ephemeral --token-file "+configDir+"/"+bundleKey) ||
		!strings.Contains(args, "--ca-file") {
		t.Errorf("args %q", args)
	}
	// Owned by its pool, labelled for the controller's watch.
	meta := doc["metadata"].(map[string]any)
	refs := meta["ownerReferences"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["uid"] != "pool-uid" || refs[0].(map[string]any)["controller"] != true {
		t.Errorf("ownerReferences %v", refs)
	}
	labels := meta["labels"].(map[string]any)
	if labels[LabelManagedBy] != ManagedBy || labels["team"] != "platform" || labels[LabelPool] != "build" {
		t.Errorf("labels %v", labels)
	}
}

func toStrings(xs []any) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i], _ = x.(string)
	}
	return out
}

// The runner's configuration is the hub's bundle, its pin filled from the
// pool's when the hub sent none, in a Secret owned by the Pod.
func TestTheRunnerSecretCarriesTheBundleAndIsOwnedByThePod(t *testing.T) {
	pool := templatePool(t)
	exp := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	bundle, _ := remote.Bundle{Server: "wss://hub/api/executors/connect", Token: "clrt1.id.secret.mac",
		EnrollmentID: "id", Name: "k8s-x", ExpiresAt: exp}.Encode()
	pod := &Pod{Metadata: ObjectMeta{Name: "build-abc123", Namespace: "runners", UID: "pod-uid"}}
	s, err := buildRunnerSecret(pool, pod, RunnerConfig{EnrollmentID: "id", Name: "k8s-x", Bundle: bundle, ExpiresAt: exp},
		pool.Spec.HubCAPin)
	if err != nil {
		t.Fatal(err)
	}
	b, err := remote.DecodeBundle(strings.TrimSpace(string(s.Data[bundleKey])))
	if err != nil {
		t.Fatal(err)
	}
	if b.Pin != pool.Spec.HubCAPin || b.Token != "clrt1.id.secret.mac" {
		t.Fatalf("bundle %+v", b)
	}
	if !strings.Contains(string(s.Data[caKey]), "BEGIN CERTIFICATE") {
		t.Fatal("the CA bundle is not in the Secret")
	}
	if len(s.Metadata.OwnerReferences) != 1 || s.Metadata.OwnerReferences[0].UID != "pod-uid" {
		t.Fatalf("owner %+v", s.Metadata.OwnerReferences)
	}
	if s.Immutable == nil || !*s.Immutable {
		t.Fatal("the runner Secret is mutable")
	}
	if s.Metadata.Annotations[AnnotationEnrollmentID] != "id" || s.Metadata.Annotations[AnnotationExpiresAt] == "" {
		t.Fatalf("annotations %v", s.Metadata.Annotations)
	}
	raw, _ := json.Marshal(s.Metadata)
	if strings.Contains(string(raw), "secret.mac") {
		t.Fatal("the token is in the Secret's metadata")
	}
}

// A long pool name still gives Pod names a label can hold.
func TestRunnerPodNamesFitALabel(t *testing.T) {
	p := &ExecutorPool{Metadata: ObjectMeta{Name: strings.Repeat("a", 200)}}
	name, err := runnerPodName(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(name) > 63 || !labelValue.MatchString(name) || !dnsSubdomain.MatchString(name) {
		t.Fatalf("Pod name %q", name)
	}
}
