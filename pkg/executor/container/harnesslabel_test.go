package container

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// labelledRuntime is a runtime CLI whose `image inspect` answers for an image
// with the given configuration JSON, as `{{json .Config}}` renders it, and
// which logs every call.
func labelledRuntime(t *testing.T, configJSON string) (Runtime, string) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh for the fake runtime")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$@\" >> " + calls + "\n" +
		"if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n" +
		"  printf 'example.com/harness@sha256:" + strings.Repeat("ab", 32) + "\\037sha256:" + strings.Repeat("cd", 32) +
		"\\037%s\\n' '" + configJSON + "'\n  exit 0\nfi\nexit 0\n"
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return Runtime{Name: RuntimeDocker, Path: path}, calls
}

// TestInspectImageReadsTheImagesLabels: the one inspect the driver already
// runs carries the labels too, beside the digest and the ID it always read.
func TestInspectImageReadsTheImagesLabels(t *testing.T) {
	rt, _ := labelledRuntime(t, `{"User":"65532","Labels":{"org.cloop.harnesses":"claude,cloop,git","other":"x"}}`)
	id, err := InspectImage(context.Background(), rt, "example.com/harness:1")
	if err != nil {
		t.Fatalf("InspectImage: %v", err)
	}
	if id.Labels[imagepolicy.HarnessesLabel] != "claude,cloop,git" || id.Labels["other"] != "x" {
		t.Errorf("Labels = %v", id.Labels)
	}
	if !strings.HasPrefix(id.RepoDigest, "example.com/harness@sha256:") || !strings.HasPrefix(id.ID, "sha256:") {
		t.Errorf("the digest and the ID are no longer read alongside: %+v", id)
	}

	// An image with no labels has no Labels key at all — alpine:3.20, say —
	// and must read as present and unlabelled, never as absent.
	for _, cfg := range []string{`{"Env":["PATH=/bin"],"Cmd":["/bin/sh"]}`, `null`} {
		rt, _ = labelledRuntime(t, cfg)
		if id, err = InspectImage(context.Background(), rt, "example.com/harness:1"); err != nil || id.Labels != nil {
			t.Errorf("an image whose configuration is %s = %+v, %v; want no labels and no error", cfg, id, err)
		}
	}
}

// TestAnImageWhoseLabelLacksTheHarnessIsRefusedBeforeItRuns is the refusal
// itself (Task 20450): a copilot project and an image that says it carries
// claude, cloop and git. The driver refuses at the inspect, before a container
// exists, naming the image as configured and a published one that carries
// copilot.
func TestAnImageWhoseLabelLacksTheHarnessIsRefusedBeforeItRuns(t *testing.T) {
	rt, calls := labelledRuntime(t, `{"Labels":{"org.cloop.harnesses":"claude,cloop,git"}}`)
	ex := fakeExecutor(t, Options{Image: "example.com/harness:1"})
	ex.rt = rt

	_, err := ex.sandboxImage(context.Background(), executor.Spec{Harness: "copilot"})
	if !errors.Is(err, imagepolicy.ErrHarnessNotCarried) {
		t.Fatalf("sandboxImage = %v, want ErrHarnessNotCarried", err)
	}
	for _, want := range []string{"example.com/harness:1", "copilot", "claude, cloop, git",
		executor.HarnessImageFor("copilot")} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q: %v", want, err)
		}
	}
	if log, _ := os.ReadFile(calls); strings.Contains(string(log), "run") || strings.Contains(string(log), "build") {
		t.Errorf("the runtime was asked to do more than inspect the image:\n%s", log)
	}

	// The same image for the harness it lists, and for a workload that names
	// none, is not refused.
	for _, harness := range []string{"claude", ""} {
		if _, err := ex.sandboxImage(context.Background(), executor.Spec{Harness: harness}); err != nil {
			t.Errorf("harness %q in an image that lists it = %v, want no refusal", harness, err)
		}
	}
}

// TestAnUnlabelledImageIsNeverRefusedForItsHarness: unknown is not no. Every
// image built before the label existed — the published one's earlier releases
// among them — still runs whatever it is asked to.
func TestAnUnlabelledImageIsNeverRefusedForItsHarness(t *testing.T) {
	rt, _ := labelledRuntime(t, `{"Labels":{"org.opencontainers.image.title":"something"}}`)
	ex := fakeExecutor(t, Options{Image: "example.com/harness:1"})
	ex.rt = rt
	if _, err := ex.sandboxImage(context.Background(), executor.Spec{Harness: "copilot"}); err != nil {
		t.Errorf("an image with no %s label was refused: %v", imagepolicy.HarnessesLabel, err)
	}
}
