// images_test.go gates the repository's first-party container image references
// against the images it actually publishes.
//
// This exists because of a specific failure. pkg/executor/container.DefaultImage
// and its Kubernetes twin both defaulted to ghcr.io/blechschmidt/cloop-harness:latest,
// the Helm chart defaulted image.repository to ghcr.io/blechschmidt/cloop, and
// the documentation instructed operators to pull both — while no workflow built
// or pushed either one. Nothing failed: the constants compiled, the chart
// linted, the docs rendered, and the defect surfaced only as ImagePullBackOff
// on someone else's cluster.
//
// A reference to an image nobody publishes is indistinguishable from a working
// default until it is pulled, so the only place to catch it is here: read the
// names the repository tells people to use, read the names the publish workflow
// produces, and require the first set to be a subset of the second.
package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// firstPartyOwner is the ghcr.io namespace this repository publishes into.
//
// Scoping by owner is what keeps the third-party and illustrative references
// out: docs/guides/enterprise-hosts.md deliberately shows an operator's own
// ghcr.io/acme/cloop-harness:2024-11, which this repository neither builds nor
// should be expected to.
const firstPartyOwner = "blechschmidt"

// publishWorkflow builds and pushes the images. Its matrix is the source of
// truth for "what do we publish".
const publishWorkflow = ".github/workflows/publish-images.yml"

// imageRefPattern matches a first-party image reference and captures its name.
// The name stops at the tag, digest, or any surrounding punctuation.
var imageRefPattern = regexp.MustCompile(`ghcr\.io/` + firstPartyOwner + `/([a-z0-9][a-z0-9._-]*)`)

// matrixImagePattern matches the `- image: <name>` entries of the publish
// workflow's matrix, and workflowTargetPattern the `target:` beside them.
var (
	matrixImagePattern     = regexp.MustCompile(`(?m)^\s*-?\s*image:\s*([a-z0-9][a-z0-9._-]*)\s*$`)
	workflowTargetPattern  = regexp.MustCompile(`(?m)^\s*target:\s*([a-z0-9][a-z0-9._-]*)\s*$`)
	dockerfileStagePattern = regexp.MustCompile(`(?mi)^FROM\s+\S+(?:\s+--\S+)*\s+AS\s+([a-z0-9][a-z0-9._-]*)`)
)

// searchRoots are the trees whose first-party image references must resolve.
// Deliberately broad: a default buried in a Go constant misleads exactly as
// effectively as one printed in a guide.
var searchRoots = []string{"docs", "pkg", "cmd", "deploy", "internal"}

// searchFiles are individual files outside those trees that carry image
// references a reader will act on.
var searchFiles = []string{"README.md", "docker-compose.yml", "Makefile"}

// TestEveryFirstPartyImageIsPublished is the gate proper.
func TestEveryFirstPartyImageIsPublished(t *testing.T) {
	root := repoRoot(t)

	published := publishedImages(t, root)
	if len(published) == 0 {
		// Either the workflow moved or its matrix shape changed. Both silently
		// disable the check, so neither may pass quietly.
		t.Fatalf("found no image names in %s — the check is disabled, not passing", publishWorkflow)
	}
	t.Logf("publish workflow produces: %s", strings.Join(sortedKeys(published), ", "))

	// name -> the places that reference it, for an actionable failure.
	refs := map[string][]string{}
	for _, rel := range searchRoots {
		collectImageRefs(t, root, filepath.Join(root, rel), refs)
	}
	for _, rel := range searchFiles {
		collectImageRefsFromFile(t, root, filepath.Join(root, rel), refs)
	}
	if len(refs) == 0 {
		t.Fatal("found no ghcr.io/" + firstPartyOwner + " references anywhere — the check is disabled, not passing")
	}

	for _, name := range sortedKeys(refs) {
		if published[name] {
			continue
		}
		sites := refs[name]
		sort.Strings(sites)
		t.Errorf("ghcr.io/%s/%s is referenced but never published.\n"+
			"  referenced from:\n    %s\n"+
			"  fix: add it to the matrix in %s (with a Dockerfile stage to build it),\n"+
			"       or change the reference to an image that is published.",
			firstPartyOwner, name, strings.Join(sites, "\n    "), publishWorkflow)
	}
}

// TestPublishWorkflowTargetsExist checks the other end of the same wire.
//
// The workflow builds each image from a named Dockerfile stage. A renamed or
// deleted stage turns a published image into a build failure at release time —
// the worst moment to discover it — so the pairing is asserted statically.
func TestPublishWorkflowTargetsExist(t *testing.T) {
	root := repoRoot(t)

	wf := readFile(t, filepath.Join(root, publishWorkflow))
	stages := map[string]bool{}
	for _, m := range dockerfileStagePattern.FindAllStringSubmatch(readFile(t, filepath.Join(root, "Dockerfile")), -1) {
		stages[strings.ToLower(m[1])] = true
	}
	if len(stages) == 0 {
		t.Fatal("found no named stages in Dockerfile — the check is disabled, not passing")
	}

	targets := workflowTargetPattern.FindAllStringSubmatch(wf, -1)
	if len(targets) == 0 {
		t.Fatalf("found no build targets in %s — the check is disabled, not passing", publishWorkflow)
	}
	for _, m := range targets {
		if !stages[strings.ToLower(m[1])] {
			t.Errorf("%s builds --target %q, but the Dockerfile has no such stage.\n"+
				"  Dockerfile stages: %s", publishWorkflow, m[1], strings.Join(sortedKeys(stages), ", "))
		}
	}
}

// publishedImages reads the image names out of the publish workflow's matrix.
func publishedImages(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, m := range matrixImagePattern.FindAllStringSubmatch(readFile(t, filepath.Join(root, publishWorkflow)), -1) {
		out[m[1]] = true
	}
	return out
}

// collectImageRefs walks a tree and records every first-party image reference.
func collectImageRefs(t *testing.T, root, dir string, into map[string][]string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// A tree that is not present is not a failure: searchRoots is a
			// superset so it keeps working as the layout moves.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".md", ".go", ".yaml", ".yml", ".tpl", ".sh", ".json":
		default:
			return nil
		}
		collectImageRefsFromFile(t, root, path, into)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

// collectImageRefsFromFile records the first-party image references in one
// file, tagged with the file and line so a failure points at something
// editable.
func collectImageRefsFromFile(t *testing.T, root, path string, into map[string][]string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read %s: %v", path, err)
	}
	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		rel = path
	}
	for i, line := range strings.Split(string(data), "\n") {
		for _, m := range imageRefPattern.FindAllStringSubmatch(line, -1) {
			name := m[1]
			site := rel + ":" + itoa(i+1)
			if !contains(into[name], site) {
				into[name] = append(into[name], site)
			}
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// itoa avoids pulling strconv in for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
