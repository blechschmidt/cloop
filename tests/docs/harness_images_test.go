package docs_test

// harness_images_test.go holds three statements of what the published sandbox
// images carry equal to one another (Task 20450): the org.cloop.harnesses
// label each image's Dockerfile stage sets, executor.HarnessImages — which the
// hub's refusals name an image from — and the publish workflow's matrix, which
// decides that the image exists at all.
//
// They drift in the way that hurts most. A list in Go that says the default
// image carries copilot sends every copilot project's operator to pull an
// image that fails the same way; a label that lists a program the image does
// not have lets a project past the hub's check into a sandbox where its
// harness is missing; a variant the hub names but the workflow never builds
// is an ImagePullBackOff with a helpful-looking remedy in front of it.

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// dockerStage is one stage of the Dockerfile: what it is built FROM and the
// labels its own LABEL instructions set.
type dockerStage struct {
	from   string
	labels map[string]string
}

var (
	stageLine  = regexp.MustCompile(`(?i)^FROM\s+(?:--\S+\s+)*(\S+)\s+AS\s+(\S+)`)
	labelPairs = regexp.MustCompile(`([A-Za-z0-9._-]+)="([^"]*)"`)
)

// dockerStages parses the Dockerfile's named stages, joining continued lines
// and skipping comments, as the builder reads them.
func dockerStages(t *testing.T, root string) map[string]*dockerStage {
	t.Helper()
	stages := map[string]*dockerStage{}
	var cur *dockerStage
	var inst strings.Builder
	flush := func() {
		line := strings.TrimSpace(inst.String())
		inst.Reset()
		if m := stageLine.FindStringSubmatch(line); m != nil {
			cur = &dockerStage{from: strings.ToLower(m[1]), labels: map[string]string{}}
			stages[strings.ToLower(m[2])] = cur
			return
		}
		if cur != nil && strings.HasPrefix(strings.ToUpper(line), "LABEL ") {
			for _, kv := range labelPairs.FindAllStringSubmatch(line, -1) {
				cur.labels[kv[1]] = kv[2]
			}
		}
	}
	for _, raw := range strings.Split(readFile(t, filepath.Join(root, "Dockerfile")), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") || (line == "" && inst.Len() == 0) {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			inst.WriteString(strings.TrimSuffix(line, "\\") + " ")
			continue
		}
		inst.WriteString(line)
		flush()
	}
	flush()
	return stages
}

// stageLabel is a label as a stage has it, its own or inherited from the
// stage it is built FROM.
func stageLabel(stages map[string]*dockerStage, stage, key string) (string, bool) {
	for seen := 0; seen < len(stages); seen++ {
		s, ok := stages[stage]
		if !ok {
			return "", false
		}
		if v, ok := s.labels[key]; ok {
			return v, true
		}
		stage = s.from
	}
	return "", false
}

// publishedTargets pairs the publish matrix's images with their build targets.
func publishedTargets(t *testing.T, root string) map[string]string {
	t.Helper()
	wf := readFile(t, filepath.Join(root, publishWorkflow))
	images := matrixImagePattern.FindAllStringSubmatch(wf, -1)
	targets := workflowTargetPattern.FindAllStringSubmatch(wf, -1)
	if len(images) == 0 || len(images) != len(targets) {
		t.Fatalf("%s: %d matrix images and %d targets; each image entry must name its target",
			publishWorkflow, len(images), len(targets))
	}
	out := map[string]string{}
	for i := range images {
		out[images[i][1]] = strings.ToLower(targets[i][1])
	}
	return out
}

// TestHarnessImagesCarryWhatTheirLabelsSay is the gate.
func TestHarnessImagesCarryWhatTheirLabelsSay(t *testing.T) {
	root := repoRoot(t)
	stages := dockerStages(t, root)
	targets := publishedTargets(t, root)
	if len(executor.HarnessImages) == 0 {
		t.Fatal("executor.HarnessImages is empty — the check is disabled, not passing")
	}

	prefix := "ghcr.io/" + firstPartyOwner + "/"
	listed := map[string]bool{}
	for _, img := range executor.HarnessImages {
		name, tag, ok := strings.Cut(strings.TrimPrefix(img.Ref, prefix), ":")
		if !strings.HasPrefix(img.Ref, prefix) || !ok || tag != "latest" {
			t.Errorf("%s: a published harness image is named ghcr.io/%s/<name>:latest", img.Ref, firstPartyOwner)
			continue
		}
		listed[name] = true
		target, ok := targets[name]
		if !ok {
			t.Errorf("%s is in executor.HarnessImages but %s publishes no %s", img.Ref, publishWorkflow, name)
			continue
		}
		label, ok := stageLabel(stages, target, imagepolicy.HarnessesLabel)
		if !ok {
			t.Errorf("the Dockerfile stage %s, which %s is built from, sets no %s label",
				target, name, imagepolicy.HarnessesLabel)
			continue
		}
		carries, _ := imagepolicy.ImageHarnesses(map[string]string{imagepolicy.HarnessesLabel: label})
		if !slices.Equal(carries, img.Carries) {
			t.Errorf("%s: the Dockerfile's %s stage labels it %q, executor.HarnessImages says %q",
				img.Ref, target, carries, img.Carries)
		}
	}

	// Every harness image the workflow publishes is one the hub knows the
	// contents of, so a new variant cannot ship unnamed in a refusal.
	for name, target := range targets {
		if strings.HasPrefix(target, "harness") && !listed[name] {
			t.Errorf("%s publishes %s (target %s), which executor.HarnessImages does not list",
				publishWorkflow, name, target)
		}
	}

	// The default every driver falls back to is the first, claude-carrying
	// entry: the image a refusal names for claude is the image that runs.
	def := executor.HarnessImages[0].Ref
	for what, ref := range map[string]string{
		"container.DefaultImage":  container.DefaultImage,
		"kubernetes.DefaultImage": kubernetes.DefaultImage,
		"remote.HarnessImageHint": remote.HarnessImageHint,
	} {
		if ref != def {
			t.Errorf("%s = %q, want the default harness image %q", what, ref, def)
		}
	}
	if executor.HarnessImageFor("claude") != def {
		t.Errorf("a claude project would be sent to %q, not the default image", executor.HarnessImageFor("claude"))
	}
}

// TestCopilotCLIIsPinnedByIntegrity holds the Dockerfile to what its comment
// promises: a version that is a version, an sha512 integrity for each tarball
// the install unpacks, a check at build, and the updater off.
func TestCopilotCLIIsPinnedByIntegrity(t *testing.T) {
	root := repoRoot(t)
	df := readFile(t, filepath.Join(root, "Dockerfile"))
	args := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^ARG (COPILOT_CLI_[A-Z0-9_]+)=(\S+)$`).FindAllStringSubmatch(df, -1) {
		args[m[1]] = m[2]
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(args["COPILOT_CLI_VERSION"]) {
		t.Errorf("COPILOT_CLI_VERSION = %q, want an exact version", args["COPILOT_CLI_VERSION"])
	}
	sri := regexp.MustCompile(`^sha512-[A-Za-z0-9+/]{86}==$`)
	for _, name := range []string{"COPILOT_CLI_INTEGRITY", "COPILOT_CLI_LINUX_X64_INTEGRITY",
		"COPILOT_CLI_LINUX_ARM64_INTEGRITY", "COPILOT_CLI_DETECT_LIBC_INTEGRITY"} {
		if !sri.MatchString(args[name]) {
			t.Errorf("%s = %q, want an sha512 integrity as npm prints it", name, args[name])
		}
		if !strings.Contains(df, "$"+name) {
			t.Errorf("%s is pinned and never checked", name)
		}
	}
	for _, want := range []string{
		"npm install -g --offline", // only what was checked can be unpacked
		"copilot --version",        // the build runs it
		"COPILOT_AUTO_UPDATE=false",
		"COPILOT_PKG_CACHE_HOME=",
		"COPILOT_HOME=/tmp/.copilot",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("the Dockerfile does not contain %q", want)
		}
	}
}
