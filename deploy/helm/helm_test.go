package helm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTheArchiveIsTheChartInTheRepository: every file of
// deploy/helm/cloop-executor-controller, byte for byte, the templates whose
// names start with an underscore included, and nothing else.
func TestTheArchiveIsTheChartInTheRepository(t *testing.T) {
	archive, sum, err := ExecutorControllerChart()
	if err != nil {
		t.Fatal(err)
	}
	again, sum2, _ := ExecutorControllerChart()
	if sum == "" || sum != sum2 || !bytes.Equal(archive, again) {
		t.Fatal("the archive is not the same bytes on every call")
	}
	if fresh, err := pack(executorController, ExecutorControllerChartName); err != nil || !bytes.Equal(fresh, archive) {
		t.Fatalf("packing the chart twice made different archives: %v", err)
	}

	onDisk := map[string][]byte{}
	if err := filepath.WalkDir(ExecutorControllerChartName, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		onDisk[filepath.ToSlash(p)] = b
		return err
	}); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	seen := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		want, ok := onDisk[h.Name]
		switch {
		case !ok:
			t.Errorf("the archive holds %s, which is not in the chart", h.Name)
		case !bytes.Equal(body, want):
			t.Errorf("%s in the archive differs from the chart's", h.Name)
		case h.Mode != 0o644 || !h.ModTime.Equal(epoch):
			t.Errorf("%s has mode %o and time %s, not the fixed ones", h.Name, h.Mode, h.ModTime)
		}
		seen++
	}
	if seen != len(onDisk) {
		t.Fatalf("the archive holds %d files and the chart %d", seen, len(onDisk))
	}
	for _, must := range []string{"Chart.yaml", "values.yaml", "templates/_helpers.tpl", "templates/_validate.tpl",
		"crds/cloop.dev_executorpools.yaml"} {
		if _, ok := onDisk[ExecutorControllerChartName+"/"+must]; !ok {
			t.Errorf("the chart has no %s", must)
		}
	}
}

// TestHelmReadsTheArchive: helm takes the archive as the chart, the way
// `helm install <URL>` would after fetching it.
func TestHelmReadsTheArchive(t *testing.T) {
	helmBin, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("CLOOP_REQUIRE_HELM") != "" {
			t.Fatalf("CLOOP_REQUIRE_HELM is set but helm is not on PATH: %v", err)
		}
		t.Skip("helm is not on PATH")
	}
	archive, _, err := ExecutorControllerChart()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ExecutorControllerChartName+".tgz")
	if err := os.WriteFile(path, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, helmBin, "template", "ctl", path, "--namespace", "cloop-runners")
	cmd.Env = append(os.Environ(), "HELM_CACHE_HOME="+filepath.Join(dir, "cache"),
		"HELM_CONFIG_HOME="+filepath.Join(dir, "config"), "HELM_DATA_HOME="+filepath.Join(dir, "data"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template of the archive: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "kind: Deployment") {
		t.Fatalf("the archive rendered no controller:\n%s", out)
	}
}
