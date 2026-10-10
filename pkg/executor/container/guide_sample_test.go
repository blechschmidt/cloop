package container_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/sandbox"
)

// enterpriseGuide is the guide whose sample sandbox.yaml this file holds to
// what it promises.
const enterpriseGuide = "../../../docs/guides/enterprise-hosts.md"

// yamlBlockContaining returns the first fenced yaml block in doc containing
// needle.
func yamlBlockContaining(t *testing.T, doc, needle string) string {
	t.Helper()
	for _, part := range strings.Split(doc, "```yaml\n")[1:] {
		block, _, ok := strings.Cut(part, "```")
		if ok && strings.Contains(block, needle) {
			return block
		}
	}
	t.Fatalf("%s has no yaml block containing %q", enterpriseGuide, needle)
	return ""
}

// TestTheEnterpriseGuidesSandboxSampleDispatchesOnTheContainerDriver: the
// guide tells an operator of a critical host to give a project this
// sandbox.yaml, with resources.disk set, on the container executor it
// describes. Before Task 20405 the driver refused every disk limit, so the
// sample could not run there at all — placement accepted it and the dispatch
// was refused. The sample is read from the guide itself, so the two cannot
// drift apart again.
func TestTheEnterpriseGuidesSandboxSampleDispatchesOnTheContainerDriver(t *testing.T) {
	// TestIntegration_SmokeTest runs this package's own test binary inside a
	// sandbox, where the source tree is not mounted. That is the one place the
	// guide may be missing; anywhere the package's sources are, it must exist.
	if _, err := os.Stat("container.go"); err != nil {
		t.Skip("not running in the source tree (the smoke test runs this binary inside a sandbox)")
	}
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	raw, err := os.ReadFile(enterpriseGuide)
	if err != nil {
		t.Fatalf("read the guide: %v", err)
	}
	sample := yamlBlockContaining(t, string(raw), "disk: 20g")

	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, sandbox.FileName), []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := sandbox.Resolve(project)
	if err != nil {
		t.Fatalf("the guide's sample does not resolve: %v", err)
	}
	if !resolved.Present() {
		t.Fatal("the sample was not found where it was written")
	}

	// The executor the guide configures for it: gVisor for kernel_isolated, a
	// network for egress: public.
	ex, err := container.NewForDiskTest(container.Options{
		ID: "critical-host", OCIRuntime: "runsc", Network: container.NetworkBridge, AllowRootUser: true,
	})
	if err != nil {
		t.Fatalf("the guide's executor: %v", err)
	}
	if err := executor.CheckSandboxSupport(ex, resolved.Requirements(), project); err != nil {
		t.Fatalf("placement refuses the guide's sample on its own executor: %v", err)
	}

	spec := executor.Spec{WorkDir: project, Argv: []string{"cloop", "run"}}
	if err := resolved.ApplyTo(&spec, project, nil); err != nil {
		t.Fatalf("apply the sample: %v", err)
	}
	if err := executor.CheckSandboxSupport(ex, spec.SandboxRequirements(), project); err != nil {
		t.Fatalf("the applied spec is refused: %v", err)
	}
	mb, err := ex.ResolvedDiskMB(spec)
	if err != nil {
		t.Fatalf("the container driver refuses the guide's sample: %v", err)
	}
	if mb != 20*1024 {
		t.Fatalf("disk limit = %d MB, want the sample's 20g", mb)
	}
}
