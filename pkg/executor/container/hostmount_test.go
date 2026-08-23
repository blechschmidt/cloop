package container

// Real-runtime tests for Spec.HostMounts (Task 20187): the binds that carry a
// developer's local git repositories into a sandbox.
//
// These run an actual container rather than asserting on argv, because argv is
// not the guarantee. The guarantee is that the repository is readable at
// /repos/<name> and that a read-only grant cannot be written to, and both of
// those are properties of the runtime honouring the flag — which a test that
// only inspects the command line would happily pass while the mount silently
// did nothing.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// hostRepo creates a directory holding one identifiable file.
func hostRepo(t *testing.T, name, contents string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "MARKER"), []byte(contents), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	return dir
}

// TestHostMountDeliversTheRepositoryIntoTheSandbox is the end-to-end proof of
// the scenario: a repository that exists only on the hub is readable inside an
// isolated container at the documented path.
func TestHostMountDeliversTheRepositoryIntoTheSandbox(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container; skipped under -short")
	}
	ex := newTestExecutor(t, "alpine:3.20", nil)
	requireImage(t, ex.rt, "alpine:3.20")

	src := hostRepo(t, "api", "granted-by-cloop")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, err := executor.Run(ctx, ex, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/cat", "/repos/api/MARKER"},
		HostMounts: []executor.HostMount{
			{Name: "api", Source: src, Target: "/repos/api", ReadOnly: true},
		},
	})
	if err != nil {
		t.Fatalf("running with a host mount: %v (output %q)", err, res.Output)
	}
	if !strings.Contains(string(res.Output), "granted-by-cloop") {
		t.Fatalf("output %q does not contain the granted repository's marker; the bind "+
			"did not reach the sandbox and a harness would report on an empty directory",
			res.Output)
	}
}

// TestHostMountReadOnlyGrantCannotBeWritten is the property that makes
// read-only the safe default rather than a decorative one. A sandbox rewriting
// the history of a checkout that exists nowhere else is a data-loss incident,
// so the flag has to be enforced by the runtime, not by convention.
func TestHostMountReadOnlyGrantCannotBeWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container; skipped under -short")
	}
	ex := newTestExecutor(t, "alpine:3.20", nil)
	requireImage(t, ex.rt, "alpine:3.20")

	src := hostRepo(t, "api", "original")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Exit status is deliberately not the assertion: what matters is that the
	// file on the host is unchanged afterwards.
	_, _ = executor.Run(ctx, ex, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "echo tampered > /repos/api/MARKER"},
		HostMounts: []executor.HostMount{
			{Name: "api", Source: src, Target: "/repos/api", ReadOnly: true},
		},
	})

	got, err := os.ReadFile(filepath.Join(src, "MARKER"))
	if err != nil {
		t.Fatalf("read back the host file: %v", err)
	}
	if strings.TrimSpace(string(got)) != "original" {
		t.Fatalf("the sandbox wrote through a read-only grant: MARKER is now %q", got)
	}
}

// TestHostMountWritableGrantReachesTheHost is the converse. A grant that asked
// for write access must actually get it, or the option is a lie and a project
// that needs to commit would fail in a way nobody could diagnose from the
// grant.
func TestHostMountWritableGrantReachesTheHost(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container; skipped under -short")
	}
	ex := newTestExecutor(t, "alpine:3.20", nil)
	requireImage(t, ex.rt, "alpine:3.20")

	src := hostRepo(t, "api", "original")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, err := executor.Run(ctx, ex, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "echo written-by-sandbox > /repos/api/MARKER"},
		HostMounts: []executor.HostMount{
			{Name: "api", Source: src, Target: "/repos/api"}, // ReadOnly false
		},
	})
	if err != nil {
		t.Fatalf("running with a writable host mount: %v (output %q)", err, res.Output)
	}
	got, err := os.ReadFile(filepath.Join(src, "MARKER"))
	if err != nil {
		t.Fatalf("read back the host file: %v", err)
	}
	if strings.TrimSpace(string(got)) != "written-by-sandbox" {
		t.Fatalf("a writable grant did not reach the host: MARKER is %q", got)
	}
}

// TestHostMountRefusesAMissingSource guards the case where a repository was
// moved or deleted after the grant was written. Both runtimes will happily
// create a missing bind source as an empty root-owned directory, which produces
// a sandbox whose /repos/api exists and is empty — the exact "looks like it
// worked" failure this subsystem exists to remove.
func TestHostMountRefusesAMissingSource(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)

	_, err := ex.buildRequest(executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/true"},
		HostMounts: []executor.HostMount{
			{Name: "api", Source: filepath.Join(t.TempDir(), "was-moved"), Target: "/repos/api"},
		},
	}, t.TempDir(), nil)
	if err == nil {
		t.Fatal("accepted a host mount whose source does not exist; the runtime would " +
			"create it empty and the harness would find no code")
	}
	if !strings.Contains(err.Error(), "was-moved") {
		t.Errorf("error %q does not name the missing path", err)
	}
}

// TestHostMountRejectsDuplicateTargetsBeforeStart keeps two grants that both
// open a repository called "api" from shadowing each other in an order nobody
// chose.
func TestHostMountRejectsDuplicateTargetsBeforeStart(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)
	a, b := hostRepo(t, "a", "a"), hostRepo(t, "b", "b")

	_, err := ex.buildRequest(executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/true"},
		HostMounts: []executor.HostMount{
			{Name: "api", Source: a, Target: "/repos/api"},
			{Name: "api", Source: b, Target: "/repos/api"},
		},
	}, t.TempDir(), nil)
	if err == nil {
		t.Fatal("accepted two host mounts claiming /repos/api")
	}
}

// TestHostMountCannotShadowTheWorkspace protects the project's own tree. A
// grant whose target is /workspace would replace the code the task is about
// with something else entirely.
func TestHostMountCannotShadowTheWorkspace(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)
	src := hostRepo(t, "api", "x")

	_, err := ex.buildRequest(executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/true"},
		HostMounts: []executor.HostMount{
			{Name: "api", Source: src, Target: ContainerWorkspace},
		},
	}, t.TempDir(), nil)
	if err == nil {
		t.Fatalf("accepted a host mount targeting %s, which would replace the project's "+
			"own source tree", ContainerWorkspace)
	}
}

func TestHostMountCapabilityIsAdvertised(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)
	if !ex.Capabilities().SupportsHostMounts {
		t.Error("the container driver does not advertise SupportsHostMounts, so placement " +
			"would refuse the executor a developer with local repositories most needs")
	}

}
