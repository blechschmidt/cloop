package kubernetes

// sandbox_test.go covers how a per-project .cloop/sandbox.yaml reaches a Pod:
// the image override, subPath mounts on the workspace volume, the egress label,
// and the refusal to pretend it can build an image.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// hubDefaultImage stands in for whatever the operator configured hub-wide. The
// tests below are about whether a project's spec displaces it.
const hubDefaultImage = "ghcr.io/acme/hub-default:v1"

// sandboxExecutor reuses the package's fake-API harness so these pod-shape
// tests exercise the same construction path as the rest of the suite.
func sandboxExecutor(t *testing.T) *Executor {
	t.Helper()
	ex, _, _ := newTestExecutor(t, func(o *Options) { o.Image = hubDefaultImage })
	return ex
}

func TestBuildPodFor_ImageOverride(t *testing.T) {
	ex := sandboxExecutor(t)

	t.Run("spec image wins", func(t *testing.T) {
		p, err := ex.buildPodFor(context.Background(), executor.Spec{
			Argv:  []string{"cloop", "run"},
			Image: "ghcr.io/acme/rust:1.79",
		}, "h1", "cloop", "")
		if err != nil {
			t.Fatalf("buildPodFor: %v", err)
		}
		if got := p.Spec.Containers[0].Image; got != "ghcr.io/acme/rust:1.79" {
			t.Fatalf("image = %q, want the project's override", got)
		}
	})

	t.Run("absent spec image keeps the operator's", func(t *testing.T) {
		p, err := ex.buildPodFor(context.Background(), executor.Spec{Argv: []string{"cloop"}}, "h2", "cloop", "")
		if err != nil {
			t.Fatalf("buildPodFor: %v", err)
		}
		if got := p.Spec.Containers[0].Image; got != hubDefaultImage {
			t.Fatalf("image = %q, want the executor default", got)
		}
	})

	t.Run("a dangerous override is refused", func(t *testing.T) {
		_, err := ex.buildPodFor(context.Background(), executor.Spec{
			Argv:  []string{"cloop"},
			Image: "--privileged",
		}, "h3", "cloop", "")
		if !errors.Is(err, executor.ErrInvalidSpec) {
			t.Fatalf("buildPodFor = %v, want ErrInvalidSpec", err)
		}
	})
}

// TestBuildPodFor_RefusesSetup: there is no builder in a cluster. Running the
// commands as a Pod prelude would look equivalent and would not be — they would
// re-run per task and their result would die with the Pod.
func TestBuildPodFor_RefusesSetup(t *testing.T) {
	ex := sandboxExecutor(t)
	_, err := ex.buildPodFor(context.Background(), executor.Spec{
		Argv:          []string{"cloop"},
		SetupCommands: []string{"pip install -r requirements.txt"},
	}, "h", "cloop", "")
	if !errors.Is(err, executor.ErrUnsupported) {
		t.Fatalf("buildPodFor = %v, want ErrUnsupported", err)
	}
	// The refusal must name the alternative, or it is a dead end for whoever
	// wrote the YAML.
	if !strings.Contains(err.Error(), "image:") {
		t.Fatalf("error does not say what to do instead: %v", err)
	}
}

func TestBuildPodFor_SandboxMounts(t *testing.T) {
	ex := sandboxExecutor(t)
	p, err := ex.buildPodFor(context.Background(), executor.Spec{
		Argv: []string{"cloop"},
		Mounts: []executor.SpecMount{
			{Source: ".cache/pip", Target: "/home/agent/.cache/pip"},
			{Source: "vendor", Target: "/opt/vendor", ReadOnly: true},
		},
	}, "h", "cloop", "")
	if err != nil {
		t.Fatalf("buildPodFor: %v", err)
	}

	mounts := p.Spec.Containers[0].VolumeMounts
	found := map[string]volumeMount{}
	for _, m := range mounts {
		found[m.MountPath] = m
	}

	pip, ok := found["/home/agent/.cache/pip"]
	if !ok {
		t.Fatalf("the cache mount is missing: %+v", mounts)
	}
	// subPath on the workspace volume is the containment: the kubelet resolves
	// it inside the volume, so a source that somehow escaped validation still
	// cannot name anything outside it.
	if pip.Name != workspaceVolume || pip.SubPath != ".cache/pip" {
		t.Fatalf("cache mount = %+v, want a subPath on %s", pip, workspaceVolume)
	}

	vendor, ok := found["/opt/vendor"]
	if !ok || !vendor.ReadOnly {
		t.Fatalf("vendor mount = %+v, want read-only", vendor)
	}

	// The workspace and /tmp must survive alongside them, or a
	// readOnlyRootFilesystem container cannot write where it runs.
	if _, ok := found[PodWorkspace]; !ok {
		t.Fatal("the workspace mount was displaced by the sandbox mounts")
	}
	if _, ok := found["/tmp"]; !ok {
		t.Fatal("the /tmp mount was displaced by the sandbox mounts")
	}
}

func TestBuildPodFor_RejectsShadowingMounts(t *testing.T) {
	ex := sandboxExecutor(t)
	for name, target := range map[string]string{
		"workspace": PodWorkspace,
		"tmp":       "/tmp",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ex.buildPodFor(context.Background(), executor.Spec{
				Argv:   []string{"cloop"},
				Mounts: []executor.SpecMount{{Source: "a", Target: target}},
			}, "h", "cloop", "")
			if err == nil {
				t.Fatalf("a mount over %s was accepted", target)
			}
		})
	}
}

func TestBuildPodFor_RejectsEscapingMounts(t *testing.T) {
	ex := sandboxExecutor(t)
	for name, m := range map[string]executor.SpecMount{
		"dotdot":   {Source: "../etc", Target: "/x"},
		"absolute": {Source: "/etc", Target: "/x"},
		"unclean":  {Source: "a//b", Target: "/x"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ex.buildPodFor(context.Background(), executor.Spec{
				Argv: []string{"cloop"}, Mounts: []executor.SpecMount{m},
			}, "h", "cloop", ""); err == nil {
				t.Fatalf("buildPodFor accepted %+v", m)
			}
		})
	}
}

// TestBuildPodFor_EgressLabel: a Pod spec cannot turn egress off, so the driver
// states the intent where a NetworkPolicy can select on it. The label is the
// contract; see LabelEgress for what it does and does not guarantee.
func TestBuildPodFor_EgressLabel(t *testing.T) {
	ex := sandboxExecutor(t)
	cases := map[bool]string{true: "deny", false: "allow"}
	for disable, want := range cases {
		p, err := ex.buildPodFor(context.Background(), executor.Spec{
			Argv:           []string{"cloop"},
			DisableNetwork: disable,
		}, "h", "cloop", "")
		if err != nil {
			t.Fatalf("buildPodFor: %v", err)
		}
		if got := p.Metadata.Labels[LabelEgress]; got != want {
			t.Fatalf("DisableNetwork=%t produced %s=%q, want %q", disable, LabelEgress, got, want)
		}
	}
}

func TestBuildPodFor_SandboxHashAnnotation(t *testing.T) {
	ex := sandboxExecutor(t)
	p, err := ex.buildPodFor(context.Background(), executor.Spec{
		Argv:        []string{"cloop"},
		SandboxHash: "9f2c8a",
	}, "h", "cloop", "")
	if err != nil {
		t.Fatalf("buildPodFor: %v", err)
	}
	if got := p.Metadata.Annotations[AnnotationSandboxHash]; got != "9f2c8a" {
		t.Fatalf("%s = %q, want the spec hash", AnnotationSandboxHash, got)
	}
}

func TestCapabilities_SandboxSupportIsHonest(t *testing.T) {
	caps := sandboxExecutor(t).Capabilities()
	if !caps.SupportsImageOverride {
		t.Error("the driver sets the Pod's image but does not advertise it")
	}
	if !caps.SupportsSandboxMounts {
		t.Error("the driver emits subPath mounts but does not advertise it")
	}
	if caps.SupportsSandboxBuild {
		t.Error("the driver advertises a builder it does not have; a spec with " +
			"setup: would be accepted and silently dropped")
	}
}
