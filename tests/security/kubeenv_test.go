package security

// kubeenv_test.go — Kubernetes: no environment value in the Pod object.
//
// Threat model, boundary ④, "Env visible to others in the namespace". A Pod
// object is readable by every identity with `get pods` in the namespace,
// printed by every `kubectl describe` and written to the API server's audit
// log, and Spec.Env is where a lease puts the credentials it delivers as
// environment — the harness login among them, which is the only way a Pod gets
// one. Since Task 20401 every value travels in the run's lease Secret and the
// harness reads each through a secretKeyRef.
//
// This drives the real Pod builder through the driver's audit seam, the way
// TestWorkspaceTokenIsNotInThePodSpec does for the workspace token: an in-package
// test would be checking the same file a refactor would edit to break it.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// TestKubernetesPodCarriesNoEnvironmentValue.
func TestKubernetesPodCarriesNoEnvironmentValue(t *testing.T) {
	secrets := map[string]string{
		"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-CONFORMANCE-OAUTH-0123456789",
		"ANTHROPIC_API_KEY":       "sk-ant-api03-CONFORMANCE-APIKEY-0123456789",
		"GITHUB_TOKEN":            "ghs_CONFORMANCEGITHUBTOKEN0123456789abcd",
		"HTTPS_PROXY":             "http://session-1:CONFORMANCE-EGRESS-TOKEN@hub.cloop.svc:3128",
	}
	spec := executor.Spec{
		Argv:    []string{"/usr/local/bin/cloop", "run"},
		WorkDir: "/workspace",
		Labels:  map[string]string{"project": "/srv/app", "task_id": "1"},
	}
	for k, v := range secrets {
		spec.Env = append(spec.Env, k+"="+v)
	}
	spec.Env = append(spec.Env, "CLOOP_REDACT_ENV=CLAUDE_CODE_OAUTH_TOKEN,ANTHROPIC_API_KEY,GITHUB_TOKEN,HTTPS_PROXY")

	body, err := kubernetes.AuditPodJSON(context.Background(),
		kubernetes.Options{Image: "ghcr.io/acme/hub@" + allowedDigest}, spec, "")
	if err != nil {
		t.Fatalf("build pod: %v", err)
	}
	for name, v := range secrets {
		if strings.Contains(string(body), v) {
			t.Errorf("the Pod object contains %s's value; anyone with `get pods` in the namespace can read it", name)
		}
		if strings.Contains(string(body), base64.StdEncoding.EncodeToString([]byte(v))) {
			t.Errorf("the Pod object contains %s's value base64-encoded", name)
		}
	}

	// Absence alone is also what a Pod that dropped the variables would show:
	// each must be present, by reference, to its own key.
	var obj struct {
		Spec struct {
			Containers []struct {
				Name string `json:"name"`
				Env  []struct {
					Name      string `json:"name"`
					Value     string `json:"value"`
					ValueFrom *struct {
						SecretKeyRef *struct {
							Name string `json:"name"`
							Key  string `json:"key"`
						} `json:"secretKeyRef"`
					} `json:"valueFrom"`
				} `json:"env"`
			} `json:"containers"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("decode pod: %v", err)
	}
	if len(obj.Spec.Containers) == 0 {
		t.Fatal("the Pod has no containers")
	}
	refs := map[string]string{}
	for _, e := range obj.Spec.Containers[0].Env {
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			refs[e.Name] = e.ValueFrom.SecretKeyRef.Name + "/" + e.ValueFrom.SecretKeyRef.Key
		}
	}
	for name := range secrets {
		ref, ok := refs[name]
		if !ok {
			t.Errorf("the harness does not read %s by reference; it would run without it", name)
			continue
		}
		if !strings.HasPrefix(ref, "cloop-lease-") || !strings.HasSuffix(ref, "/env."+name) {
			t.Errorf("%s is read from %s, want the run's cloop-lease-<handle> Secret, key env.%s", name, ref, name)
		}
	}
	if strings.Contains(string(body), `"envFrom"`) {
		t.Error("the Pod imports a Secret wholesale with envFrom; the lease Secret also holds credential " +
			"files, which would land in the environment of every process the harness starts")
	}
}
