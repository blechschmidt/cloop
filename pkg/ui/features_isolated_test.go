package ui

// A feature on an executor that isolates from the hub (Task 20367): what the
// hub builds to send it, and what it refuses. The runs themselves are driven
// end to end in tests/e2e/features_isolated_test.go.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/featurehub"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/featureops"
)

// capableStub is an isolating executor that says it can carry a feature.
type capableStub struct {
	readyzStubExecutor
	shares bool
}

func (s *capableStub) Capabilities() executor.Capabilities {
	return executor.Capabilities{
		Isolation:            executor.IsolationRemote,
		SharesHostFilesystem: s.shares,
		SupportsBranchBundle: true, SupportsWriteBack: true,
		SupportsProjectSeed: true, ReturnsProjectState: true,
	}
}

// hubFeature makes a real feature of the fixture's parent, on the hub.
func hubFeature(t *testing.T, f *featureFixture) string {
	t.Helper()
	realRepo(t, f.parent)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	info, err := featurehub.Create(ctx, featureops.CreateOptions{
		ProjectDir: f.parent, Name: "Widget", Tasks: []string{"Write the widget"},
	})
	if err != nil {
		t.Fatalf("featurehub.Create: %v", err)
	}
	return info.Path
}

func TestApplyWorkspaceShipsAFeaturesBranch(t *testing.T) {
	f := newFeatureFixture(t)
	dir := hubFeature(t, f)

	for _, tc := range []struct {
		name    string
		shares  bool
		workDir string
	}{
		{"a device", false, executor.DeviceWorkDir(dir)},
		{"a container on the hub", true, dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := &capableStub{readyzStubExecutor: readyzStubExecutor{id: "cap"}, shares: tc.shares}
			spec := uiSpec(dir, []string{"cloop", "run"}, nil)
			spec, err := applyWorkspaceFor(spec, ex, dir, true)
			if err != nil {
				t.Fatalf("applyWorkspaceFor: %v", err)
			}
			defer os.Remove(spec.BranchBundleFile)
			b := spec.Workspace.Branch
			if spec.Workspace.Kind != executor.WorkspaceBundle || b == nil || b.Branch != feature.BranchName("widget") {
				t.Fatalf("workspace = %+v", spec.Workspace)
			}
			if err := b.VerifyFile(spec.BranchBundleFile); err != nil {
				t.Errorf("the bundle file is not what the workspace describes: %v", err)
			}
			if len(spec.ProjectSeed) == 0 {
				t.Error("the feature's state does not travel with it")
			}
			if spec.WriteBack.Mode != executor.WriteBackBundle || spec.WriteBack.Branch != b.Branch ||
				spec.WriteBack.MaxBundleBytes != featureBundleLimit() {
				t.Errorf("write-back = %+v", spec.WriteBack)
			}
			if spec.WorkDir != tc.workDir {
				t.Errorf("WorkDir = %s, want %s", spec.WorkDir, tc.workDir)
			}
			if fr := featureReturnFor(spec); fr == nil || fr.Head != b.Head || fr.Branch != b.Branch {
				t.Errorf("featureReturnFor = %+v", fr)
			}
			if err := spec.Validate(); err != nil {
				t.Errorf("the spec does not validate: %v", err)
			}
		})
	}

	// A helper subcommand gets the tree and the state, but returns nothing.
	ex := &capableStub{readyzStubExecutor: readyzStubExecutor{id: "cap"}}
	spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "suggest"}, nil), ex, dir)
	if err != nil {
		t.Fatalf("applyWorkspace: %v", err)
	}
	defer os.Remove(spec.BranchBundleFile)
	if spec.WriteBack.Enabled() || featureReturnFor(spec) != nil {
		t.Errorf("a helper's dispatch asks for a write-back: %+v", spec.WriteBack)
	}
}

func TestApplyWorkspaceRefusesAnExecutorThatCannotCarryAFeature(t *testing.T) {
	f := newFeatureFixture(t)
	dir := hubFeature(t, f)
	ex := &readyzStubExecutor{id: "plain"}
	_, err := applyWorkspaceFor(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir, true)
	if err == nil || !strings.Contains(err.Error(), "cannot receive the feature's branch") {
		t.Fatalf("applyWorkspaceFor on an executor with no branch support = %v", err)
	}
	var fe *featureExecutorError
	if !errors.As(err, &fe) || !errors.Is(err, errFeatureExecutor) {
		t.Fatalf("the refusal is not a typed featureExecutorError: %T %v", err, err)
	}
	if !strings.Contains(fe.Remediation(), "container executor") || !strings.Contains(fe.Remediation(), "Kubernetes") {
		t.Errorf("the remediation does not say which executors can run a feature: %s", fe.Remediation())
	}
}

func TestFeatures_AProjectWithNoRepositoryOnTheHubIsRefusedWithTheReason(t *testing.T) {
	f := newFeatureFixture(t)
	registerBuiltinExecutors()
	iso := &readyzStubExecutor{id: "feature-norepo-iso"}
	if err := executor.DefaultRegistry.Register(iso); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(iso.id) })
	if err := executor.Bind(f.parent, iso.id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(f.parent) })
	// The project's working directory lives on its executor: on the hub there
	// is only its .cloop/.
	if err := os.RemoveAll(filepath.Join(f.parent, ".git")); err != nil {
		t.Fatal(err)
	}
	code, body := f.do(t, "POST", "/api/projects/1/features", map[string]any{"name": "x", "description": "y"})
	msg, _ := body["error"].(string)
	if code != http.StatusConflict || !strings.Contains(msg, "no git repository of its own on the hub") {
		t.Fatalf("create on a project with no repository = %d %v", code, body)
	}
	if _, err := os.Stat(feature.Dir(f.parent)); err == nil {
		t.Error("something was created for a feature that was refused")
	}
}

// releasingStub is an executor keeping a feature run's output for the hub:
// it reports a write-back and notes whether the feature already showed its
// outcome when the hub let go of that output.
type releasingStub struct {
	capableStub
	featureDir    string
	released      bool
	recordedFirst bool
}

func (s *releasingStub) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{State: executor.StateExited, WriteBack: &executor.WriteBackResult{
		Mode: executor.WriteBackBundle, Branch: feature.BranchName("widget"),
		Skipped: true, SkipReason: "the harness changed no files",
	}}, nil
}

func (s *releasingStub) ReleaseResults(string) {
	s.released = true
	if m, err := feature.LoadMeta(s.featureDir); err == nil && m.Return != nil {
		s.recordedFirst = true
	}
}

// TestLandingReleasesTheRunsOutputBeforeShowingItsOutcome: once a feature
// shows how its run came back, nothing of that run is left on the executor's
// host — the order a reader of the outcome (CI's e2e among them) relies on.
func TestLandingReleasesTheRunsOutputBeforeShowingItsOutcome(t *testing.T) {
	f := newFeatureFixture(t)
	dir := hubFeature(t, f)
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	head := strings.TrimSpace(string(out))
	ex := &releasingStub{capableStub: capableStub{readyzStubExecutor: readyzStubExecutor{id: "keeper"}}, featureDir: dir}
	f.srv.landFeatureWork(dir, ex, "h1", seededDispatch{feature: &featureReturn{
		Branch: feature.BranchName("widget"), Head: head, MaxBytes: 1 << 20,
	}})
	if !ex.released {
		t.Fatal("the executor was never told the hub was done with the run's output")
	}
	if ex.recordedFirst {
		t.Error("the feature showed its outcome while the run's output was still kept")
	}
	m, err := feature.LoadMeta(dir)
	if err != nil || m.Return == nil || m.Return.Outcome != string(featurehub.LandNothing) {
		t.Errorf("recorded return = %+v, %v", m.Return, err)
	}
}
