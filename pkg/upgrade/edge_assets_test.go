package upgrade

// edge_assets_test.go holds the two edge scripts to pkg/upgrade (Task 20376).
//
// scripts/build-edge.sh names the assets edge.yml publishes and StageEdge
// computes the names it downloads; they meet only at a URL, where a mismatch
// is a 404 that reads as "CI has not published this commit". And
// scripts/edge-prune.py decides which builds survive, which is the difference
// between "the edge release keeps the newest 30 commits" being true and being
// a sentence in the docs.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestEdgeScriptNamesWhatStageEdgeFetches(t *testing.T) {
	script, err := filepath.Abs("../../scripts/build-edge.sh")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("bash", script, "--list", commitA).Output()
	if err != nil {
		t.Fatalf("build-edge.sh --list: %v", err)
	}
	names := strings.Fields(string(out))

	var want []string
	for _, platform := range listReleasePlatforms(t) {
		goos, goarch, _ := strings.Cut(platform, "/")
		want = append(want, EdgeArchiveName(commitA, goos, goarch))
	}
	want = append(want, EdgeManifestV2Name(commitA), EdgeManifestName(commitA))
	if !slices.Equal(names, want) {
		t.Errorf("build-edge.sh publishes\n  %v\nbut pkg/upgrade fetches\n  %v", names, want)
	}
	// The platform a test runs on is a release platform, so StageEdge on it
	// would find its archive.
	if !slices.Contains(names, EdgeArchiveName(commitA, runtime.GOOS, runtime.GOARCH)) &&
		(runtime.GOOS == "linux" || runtime.GOOS == "darwin") {
		t.Errorf("no edge archive for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	if err := exec.Command("bash", script, "--list", "a0f3870").Run(); err == nil {
		t.Error("build-edge.sh accepted a short commit; assets must carry the full id")
	}
}

// listReleasePlatforms runs the release script's --platforms mode.
func listReleasePlatforms(t *testing.T) []string {
	t.Helper()
	path, err := filepath.Abs(releaseScript)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("bash", path, "--platforms").Output()
	if err != nil {
		t.Fatalf("%s --platforms: %v", releaseScript, err)
	}
	return strings.Fields(string(out))
}

// TestEdgePruneKeepsTheNewestCommitsOnMain runs the prune script on a release
// holding builds of 35 commits on main, one commit that is not on main, and an
// asset this script did not make.
func TestEdgePruneKeepsTheNewestCommitsOnMain(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	dir := t.TempDir()
	commit := func(i int) string { return strings.Repeat("0", 40-len(strconv.Itoa(i))) + strconv.Itoa(i) }

	// History newest first: commit 35 is the newest.
	var history []string
	for i := 35; i >= 1; i-- {
		history = append(history, commit(i))
	}
	var assets []string
	id := 0
	add := func(name string) {
		id++
		assets = append(assets, strconv.Itoa(id)+" "+name)
	}
	// Uploaded oldest first, except commit 2, re-run last: upload order must
	// not decide what survives.
	for i := 1; i <= 35; i++ {
		if i == 2 {
			continue
		}
		add(EdgeArchiveName(commit(i), "linux", "amd64"))
		add(EdgeManifestName(commit(i)))
	}
	add(EdgeArchiveName(commit(2), "linux", "amd64"))
	stranger := strings.Repeat("f", 40)
	add(EdgeManifestName(stranger))
	add("README.txt")

	write := func(name string, lines []string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cmd := exec.Command(python, "../../scripts/edge-prune.py", "--keep", "30",
		"--assets", write("assets.txt", assets), "--history", write("history.txt", history))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("edge-prune.py: %v\n%s", err, out)
	}

	doomed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if _, name, ok := strings.Cut(line, " "); ok {
			doomed[name] = true
		}
	}
	for i := 1; i <= 35; i++ {
		archive := EdgeArchiveName(commit(i), "linux", "amd64")
		if want := i <= 5; doomed[archive] != want {
			t.Errorf("commit %d (of 35): pruned=%t, want %t — the newest 30 on main are kept", i, doomed[archive], want)
		}
	}
	if !doomed[EdgeManifestName(stranger)] {
		t.Error("a build of a commit that is not on main survived the prune")
	}
	if doomed["README.txt"] {
		t.Error("the prune deleted an asset it cannot account for")
	}
}

// TestEdgeScriptWritesTheManifestSchemaThisBuildReads: the schema build-edge.sh
// writes is the one StageEdge reads (Task 20380). A script that moved ahead
// would publish manifests every device refuses; one left behind would publish
// builds with no sequence, which every device running a sequenced build
// refuses as older.
func TestEdgeScriptWritesTheManifestSchemaThisBuildReads(t *testing.T) {
	b, err := os.ReadFile("../../scripts/build-edge.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`"schema":\s*([0-9]+),`).FindSubmatch(b)
	if m == nil {
		t.Fatal(`build-edge.sh no longer writes "schema": N`)
	}
	if got, _ := strconv.Atoi(string(m[1])); got != EdgeManifestSchema {
		t.Errorf("build-edge.sh writes schema %d, this build reads up to %d", got, EdgeManifestSchema)
	}
	// And the schema-1 manifest beside it, under the old name, for devices
	// whose cloop reads nothing else.
	for _, want := range []string{`legacy["schema"] = 1`, `_manifest.v2.json`, `_manifest.json`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("build-edge.sh no longer contains %q", want)
		}
	}
}
