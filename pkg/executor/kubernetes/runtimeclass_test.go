package kubernetes

// runtimeclass_test.go covers the remote half of Kata support: a RuntimeClass
// on every Pod, and the capability claim that follows from it.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestValidateRuntimeClass(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr string // substring; "" means accepted
	}{
		{"empty means cluster default", "", ""},
		{"whitespace is empty", "   ", ""},
		{"kata", "kata", ""},
		{"kata-qemu", "kata-qemu", ""},
		{"kata-clh", "kata-clh", ""},
		{"dotted", "kata.example.com", ""},
		{"digits", "kata2", ""},

		// A RuntimeClass name is an RFC 1123 subdomain. Rejecting these here
		// turns a per-run 422 from the API server into a startup error against
		// the config line that caused it.
		{"uppercase", "Kata", "lowercase"},
		{"underscore", "kata_qemu", "lowercase"},
		{"leading dash", "-kata", "begin and end"},
		{"trailing dot", "kata.", "begin and end"},
		{"space", "kata qemu", "lowercase"},
		{"slash", "kata/qemu", "lowercase"},
		{"too long", strings.Repeat("k", 254), "exceeds"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRuntimeClass(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateRuntimeClass(%q) = %v, want nil", tc.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateRuntimeClass(%q) = nil, want an error containing %q", tc.in, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ValidateRuntimeClass(%q) = %q, want it to mention %q", tc.in, err, tc.wantErr)
			}
			// The field name must appear so the operator knows which key to edit.
			if !strings.Contains(err.Error(), "runtime_class") {
				t.Errorf("error %q does not name the config key", err)
			}
		})
	}
}

// TestBuildPod_RuntimeClassOmittedByDefault is the compatibility guarantee. An
// empty runtimeClassName must not be serialised at all: sending
// `"runtimeClassName": ""` is not the same as omitting it, and a cluster with
// an admission webhook on the field would reject a Pod that previously passed.
func TestBuildPod_RuntimeClassOmittedByDefault(t *testing.T) {
	p, err := buildPod(baseRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if p.Spec.RuntimeClassName != "" {
		t.Errorf("runtimeClassName = %q, want empty when unconfigured", p.Spec.RuntimeClassName)
	}

	raw, err := json.Marshal(p.Spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "runtimeClassName") {
		t.Errorf("runtimeClassName appears in the serialised Pod spec when unset; "+
			"it must be omitempty so the cluster default stays in effect:\n%s", raw)
	}
}

// TestBuildPod_RuntimeClassRendered checks the field reaches the API server
// under the name Kubernetes expects.
func TestBuildPod_RuntimeClassRendered(t *testing.T) {
	req := baseRequest()
	req.RuntimeClass = "kata-qemu"
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if p.Spec.RuntimeClassName != "kata-qemu" {
		t.Fatalf("runtimeClassName = %q, want kata-qemu", p.Spec.RuntimeClassName)
	}

	var decoded map[string]any
	raw, err := json.Marshal(p.Spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := decoded["runtimeClassName"]; got != "kata-qemu" {
		t.Errorf("serialised runtimeClassName = %v, want kata-qemu — the JSON key is what "+
			"the API server reads, not the Go field name", got)
	}
}

// TestBuildPod_RuntimeClassKeepsConfinement guards against Kata being wired in
// by relaxing the Pod's other hardening. A VM boundary is additional to the
// container one, not a replacement for it.
func TestBuildPod_RuntimeClassKeepsConfinement(t *testing.T) {
	req := baseRequest()
	req.RuntimeClass = "kata"
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
		t.Error("automountServiceAccountToken must stay false under a kata RuntimeClass")
	}
	if p.Spec.HostNetwork == nil || *p.Spec.HostNetwork {
		t.Error("hostNetwork must stay false under a kata RuntimeClass")
	}
	if psc := p.Spec.SecurityContext; psc == nil || psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot {
		t.Error("runAsNonRoot must stay true under a kata RuntimeClass")
	}
}

// TestOptionsNormalizeRuntimeClass checks the option is trimmed and validated
// where every caller goes through it.
func TestOptionsNormalizeRuntimeClass(t *testing.T) {
	t.Run("trims", func(t *testing.T) {
		got, err := Options{Namespace: "cloop", RuntimeClass: "  kata-qemu  "}.Normalize()
		if err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		if got.RuntimeClass != "kata-qemu" {
			t.Errorf("RuntimeClass = %q, want the trimmed name", got.RuntimeClass)
		}
	})

	t.Run("rejects an invalid name", func(t *testing.T) {
		if _, err := (Options{Namespace: "cloop", RuntimeClass: "Kata Qemu"}).Normalize(); err == nil {
			t.Error("Normalize accepted a RuntimeClass that the API server would reject")
		}
	})

	t.Run("empty stays empty", func(t *testing.T) {
		got, err := Options{Namespace: "cloop"}.Normalize()
		if err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		if got.RuntimeClass != "" {
			t.Errorf("RuntimeClass = %q, want empty", got.RuntimeClass)
		}
	})
}

// TestCapabilitiesVirtualizedFollowsRuntimeClass is the claim placement acts
// on. Isolation must stay "remote" — the Pod is still on someone else's
// machine — while Virtualized carries the kernel fact. Collapsing the two is
// exactly what the separate field exists to prevent.
func TestCapabilitiesVirtualizedFollowsRuntimeClass(t *testing.T) {
	cases := []struct {
		class       string
		virtualized bool
	}{
		{"", false},
		{"runc", false},
		{"gvisor", false},
		{"kata", true},
		{"kata-qemu", true},
		{"kata-clh", true},
	}

	for _, tc := range cases {
		t.Run("class="+tc.class, func(t *testing.T) {
			e := &Executor{id: "k8s", opts: Options{Namespace: "cloop", RuntimeClass: tc.class}}

			caps := e.Capabilities()
			if caps.Virtualized != tc.virtualized {
				t.Errorf("Virtualized = %v, want %v", caps.Virtualized, tc.virtualized)
			}
			if caps.Isolation != executor.IsolationRemote {
				t.Errorf("Isolation = %q, want %q — a kata Pod is still remote, and that fact "+
					"must not be lost to the virtualization one",
					caps.Isolation, executor.IsolationRemote)
			}
			if e.Virtualized() != tc.virtualized {
				t.Errorf("Virtualized() = %v, want %v", e.Virtualized(), tc.virtualized)
			}
			if e.RuntimeClass() != tc.class {
				t.Errorf("RuntimeClass() = %q, want %q", e.RuntimeClass(), tc.class)
			}
		})
	}
}
