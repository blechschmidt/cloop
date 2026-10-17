package container

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// probeTestImage is a small image with no C library at all: the probe must run
// in it whether this test binary is static or dynamically linked, because
// nothing the probe needs comes from the image.
const probeTestImage = "alpine:3.20"

// aliasedEngine writes a `docker` that stands in for a daemon.json alias: it
// hands every container asked to run under runtime "kata" to runc instead,
// which is what an entry named kata whose path is runc does. It records what
// it rewrote, and passes everything else to the real engine.
//
// This is the seam the task asks for, and the only one it allows: the host's
// docker daemon is never reconfigured to stage the alias.
func aliasedEngine(t *testing.T) (Runtime, string) {
	t.Helper()
	real, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker is not installed; the alias is staged in front of it")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "rewrites")
	script := `#!/bin/sh
prev=""
for a do
  shift
  if [ "$prev" = "--runtime" ] && [ "$a" = "kata" ]; then
    echo "--runtime kata -> --runtime runc" >> "` + log + `"
    a=runc
  fi
  set -- "$@" "$a"
  prev="$a"
done
exec "` + real + `" "$@"
`
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return Runtime{Name: RuntimeDocker, Path: path}, log
}

// TestRuncRegisteredAsKataIsCaughtByTheProbe runs the whole chain on a real
// engine. An executor whose OCI runtime is named kata claims a VM — and the
// probe, run through an engine where that name is runc, reads the host's own
// kernel. Recorded as evidence, that refuses a project requiring a hypervisor,
// naming what the probe saw.
func TestRuncRegisteredAsKataIsCaughtByTheProbe(t *testing.T) {
	requireRuntime(t)
	rt, log := aliasedEngine(t)
	image := requireImage(t, rt, probeTestImage)

	ex, err := New(Options{ID: "kata-alias", Runtime: rt.Path, OCIRuntime: "kata", Image: image})
	if err != nil {
		t.Fatal(err)
	}
	caps := ex.Capabilities()
	if !caps.Virtualized || !caps.KernelIsolated {
		t.Fatal("an executor whose runtime is named kata no longer claims a VM; this test is about that claim")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	probe, err := ex.ProbeIsolation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(log); !strings.Contains(string(b), "--runtime kata -> --runtime runc") {
		t.Fatal("the probe's sandbox never asked the engine for runtime kata")
	}
	v := probe.Verdict()
	if v.Kind != isolationprobe.KindHostKernel {
		t.Fatalf("verdict = %s (%s), want host-kernel", v.Kind, v.Detail)
	}
	if probe.Reference.Source != isolationprobe.SourceHub || probe.Reference.EngineKernel == "" {
		t.Errorf("reference = %+v, want the hub's own kernel and the engine's", probe.Reference)
	}

	rec := executor.IsolationRecord{ExecutorID: ex.ID(), Runtime: "kata", Claim: executor.IsolationClaim("kata"),
		Verdict: v.Kind, Detail: v.Detail, ProbedAt: time.Now()}
	prev := executor.SetIsolationEvidenceSource(func(id, runtime string) (executor.IsolationRecord, bool) {
		return rec, id == rec.ExecutorID && runtime == rec.Runtime
	})
	t.Cleanup(func() { executor.SetIsolationEvidenceSource(prev) })

	_, err = executor.Select([]executor.Candidate{{Executor: ex, Health: executor.Health{State: executor.NodeReady}}},
		executor.Requirements{RequireVirtualization: true})
	if err == nil {
		t.Fatal("a runc sandbox named kata was placed for a workload requiring a hypervisor")
	}
	if !strings.Contains(err.Error(), "isolation_evidence") || !strings.Contains(err.Error(), "host's boot ID") {
		t.Errorf("refusal %q should name the constraint and the evidence", err)
	}
}

// TestIsolationProbeUnderTheDefaultRuntime: a plain container is found to run
// on the host kernel, by boot ID — a claim of nothing, verified.
func TestIsolationProbeUnderTheDefaultRuntime(t *testing.T) {
	rt := requireRuntime(t)
	image := requireImage(t, rt, probeTestImage)
	ex, err := New(Options{ID: "plain", Runtime: rt.Path, Image: image})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	probe, err := ex.ProbeIsolation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := probe.Verdict(); v.Kind != isolationprobe.KindHostKernel || !strings.Contains(v.Detail, "boot ID") {
		t.Fatalf("verdict = %s (%s)", v.Kind, v.Detail)
	}
	// Nothing of the probe's outlives it.
	names, _ := ex.listExited(ctx, "label=component=isolation-probe")
	if len(names) != 0 {
		t.Errorf("probe containers left behind: %v", names)
	}
}

// TestProbeLaunchBindsTheLoaderForADynamicBinary: a dynamically linked binary
// runs through the host's own loader, bound beside it with its libraries, so
// the probe never depends on the image's C library.
func TestProbeLaunchBindsTheLoaderForADynamicBinary(t *testing.T) {
	self, err := selfBinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	mounts, argv := probeLaunch(self)
	if mounts[0].TargetPath != probeDir+"/cloop" || !mounts[0].ReadOnly || mounts[0].HostPath != self {
		t.Fatalf("binary mount = %+v", mounts[0])
	}
	for _, m := range mounts {
		if !m.ReadOnly || !strings.HasPrefix(m.TargetPath, probeDir+"/") {
			t.Errorf("mount %+v must be read-only and under %s", m, probeDir)
		}
	}
	interp, _, _ := dynamicDeps(self)
	switch {
	case interp == "":
		if len(mounts) != 1 || strings.Join(argv, " ") != probeDir+"/cloop isolation-probe" {
			t.Errorf("a static binary: mounts %+v argv %q", mounts, argv)
		}
	default:
		if argv[0] != probeDir+"/ld.so" || argv[len(argv)-1] != isolationprobe.Arg || len(mounts) < 3 {
			t.Errorf("a dynamic binary: mounts %+v argv %q", mounts, argv)
		}
	}
}
