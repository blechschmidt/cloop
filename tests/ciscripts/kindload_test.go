package ciscripts_test

// kindload_test.go tests scripts/kind-load-image.sh, the way CI puts an image
// the runner's Docker holds on a kind cluster's nodes (Task 20510), against
// stand-ins for docker and kind that record what they are asked: each image
// is saved for the daemon's own platform alone and handed to
// `kind load image-archive`, one at a time, and a save that fails loads
// nothing after it. Then a gate: nothing CI runs may load an image with
// `kind load docker-image`, which under Docker's containerd image store hands
// the node a pulled image's whole multi-platform index with one platform's
// content, and which turned the Deployment artifacts job red on every push
// once GitHub's runners moved to a Docker that uses that store.

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// dockerStandIn answers `docker version` with $FAKE_PLATFORM and writes, for
// `docker save --platform P -o FILE IMAGE`, a FILE naming the image and the
// platform it was saved for — refusing the image $FAKE_SAVE_FAILS names the
// way a daemon refuses a platform it holds no content for.
const dockerStandIn = `#!/bin/sh
printf 'docker %s\n' "$*" >> "$CALLS"
case $1 in
version) echo "${FAKE_PLATFORM:-linux/amd64}"; exit 0 ;;
save) shift ;;
*) echo "docker stand-in: unexpected command $1" >&2; exit 3 ;;
esac
platform= out= image=
while [ $# -gt 0 ]; do
	case $1 in
	--platform) platform=$2; shift 2 ;;
	-o) out=$2; shift 2 ;;
	-*) echo "docker stand-in: unexpected flag $1" >&2; exit 3 ;;
	*) image=$1; shift ;;
	esac
done
if [ -n "${FAKE_SAVE_FAILS:-}" ] && [ "$image" = "$FAKE_SAVE_FAILS" ]; then
	echo "Error response from daemon: no suitable export target found for platform $platform" >&2
	exit 1
fi
printf '%s for %s\n' "$image" "$platform" > "$out"
`

// kindStandIn records its arguments and what the archive it was given holds.
const kindStandIn = `#!/bin/sh
printf 'kind %s | archive: %s\n' "$*" "$(cat "$3" 2>/dev/null || echo missing)" >> "$CALLS"
`

// kindLoad runs scripts/kind-load-image.sh with the stand-ins first on PATH
// and returns its streams, its exit code and the calls the stand-ins recorded.
func kindLoad(t *testing.T, env []string, args ...string) (stdout, stderr string, code int, calls []string) {
	t.Helper()
	bin := t.TempDir()
	for name, body := range map[string]string{"docker": dockerStandIn, "kind": kindStandIn} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	record := filepath.Join(t.TempDir(), "calls")
	env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "CALLS=" + record}, env...)
	script := filepath.Join(repoRoot(t), "scripts", "kind-load-image.sh")
	stdout, stderr, code = runIn(t, t.TempDir(), env, "bash", append([]string{script}, args...)...)
	b, err := os.ReadFile(record)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			calls = append(calls, l)
		}
	}
	return stdout, stderr, code, calls
}

// archivePath is the -o argument of a recorded `docker save`.
var archivePath = regexp.MustCompile(` -o (\S+) `)

func TestKindLoadImageSavesTheDaemonsPlatformAndLoadsTheArchive(t *testing.T) {
	stdout, stderr, code, calls := kindLoad(t, []string{"FAKE_PLATFORM=linux/arm64"},
		"cloop-ci", "cloop-hub:ci", "cloop-e2e-shell:local")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s\ncalls:\n%s", code, stdout, stderr, strings.Join(calls, "\n"))
	}
	// The archive's path is the script's own temporary file: read it from the
	// save, then expect the load to be handed that same file.
	var want []string
	want = append(want, "docker version --format {{.Server.Os}}/{{.Server.Arch}}")
	var archives []string
	for i, image := range []string{"cloop-hub:ci", "cloop-e2e-shell:local"} {
		if 1+2*i >= len(calls) {
			t.Fatalf("too few calls:\n%s", strings.Join(calls, "\n"))
		}
		m := archivePath.FindStringSubmatch(calls[1+2*i])
		if m == nil {
			t.Fatalf("call %d is not a docker save -o: %s", 1+2*i, calls[1+2*i])
		}
		archives = append(archives, m[1])
		want = append(want,
			"docker save --platform linux/arm64 -o "+m[1]+" "+image,
			"kind load image-archive "+m[1]+" --name cloop-ci | archive: "+image+" for linux/arm64")
		if !strings.Contains(stdout, image+" (linux/arm64) is on every node of cloop-ci") {
			t.Errorf("stdout does not say %s was loaded:\n%s", image, stdout)
		}
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
	for _, a := range archives {
		if _, err := os.Stat(filepath.Dir(a)); !os.IsNotExist(err) {
			t.Errorf("the archive's directory %s outlived the script (stat: %v)", filepath.Dir(a), err)
		}
	}
}

func TestKindLoadImageLoadsNothingAfterASaveFails(t *testing.T) {
	_, stderr, code, calls := kindLoad(t, []string{"FAKE_SAVE_FAILS=gone:1"}, "cloop-ci", "first:1", "gone:1", "never:1")
	if code == 0 {
		t.Fatalf("exit 0 though the second image could not be saved; calls:\n%s", strings.Join(calls, "\n"))
	}
	if !strings.Contains(stderr, "no suitable export target found for platform linux/amd64") {
		t.Errorf("stderr does not carry the daemon's refusal:\n%s", stderr)
	}
	var loaded []string
	for _, c := range calls {
		if strings.HasPrefix(c, "kind ") {
			loaded = append(loaded, c[strings.LastIndex(c, "archive: ")+len("archive: "):])
		}
		if strings.Contains(c, "never:1") {
			t.Errorf("the script went on past the failed save: %s", c)
		}
	}
	if strings.Join(loaded, ",") != "first:1 for linux/amd64" {
		t.Errorf("loaded %q, want only first:1", loaded)
	}
}

func TestKindLoadImageNeedsAClusterAndAnImage(t *testing.T) {
	for _, args := range [][]string{nil, {"cloop-ci"}} {
		_, stderr, code, calls := kindLoad(t, nil, args...)
		if code != 2 || !strings.Contains(stderr, "usage: kind-load-image.sh CLUSTER IMAGE...") {
			t.Errorf("args %q: exit %d, stderr %q; want 2 and the usage", args, code, stderr)
		}
		if len(calls) != 0 {
			t.Errorf("args %q: called %q before refusing", args, calls)
		}
	}
}

// loadsAnImageWhole is a `kind load docker-image` in a command line or in the
// arguments of a Go exec call.
var loadsAnImageWhole = regexp.MustCompile(`load["'\s,]+docker-image`)

// TestNothingCIRunsLoadsAnImageIntoKindWhole fails a `kind load docker-image`
// in the workflows, the scripts, the Makefile or any Go code — CI runs all of
// them. Use scripts/kind-load-image.sh, or save the daemon's own platform and
// `kind load image-archive` it, as tests/kube's toNodes does. Comments are
// left out: they say why.
func TestNothingCIRunsLoadsAnImageIntoKindWhole(t *testing.T) {
	root := repoRoot(t)
	self := filepath.Join(root, "tests", "ciscripts", "kindload_test.go")
	var found []string
	scan := func(path string) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.IndexByte(b, 0) >= 0 {
			return // a binary
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "#") || strings.HasPrefix(code, "//") {
				continue
			}
			if loadsAnImageWhole.MatchString(code) {
				rel, _ := filepath.Rel(root, path)
				found = append(found, rel+":"+strconv.Itoa(i+1)+": "+code)
			}
		}
	}
	scan(filepath.Join(root, "Makefile"))
	scanned := 0
	for _, dir := range []string{".github", "scripts", "tests", "pkg", "cmd", "internal", "deploy"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", ".cloop", "__pycache__":
					return filepath.SkipDir
				}
				return nil
			}
			// Prose says what not to run; it is not run.
			if !d.Type().IsRegular() || path == self || strings.EqualFold(filepath.Ext(path), ".md") {
				return nil
			}
			scanned++
			scan(path)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// The walk must have reached what it guards.
	if scanned < 1000 {
		t.Fatalf("scanned %d files; the walk is broken", scanned)
	}
	for _, f := range found {
		t.Errorf("loads an image into kind with `kind load docker-image`, which fails for a pulled "+
			"image under Docker's containerd image store; use scripts/kind-load-image.sh: %s", f)
	}
}
