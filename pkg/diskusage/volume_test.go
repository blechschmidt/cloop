package diskusage

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/diskreserve"
)

// TestVolumesDedupesByDevice: a project's .cloop and its working tree are
// normally one filesystem, and must be measured — and warned about — once.
func TestVolumesDedupesByDevice(t *testing.T) {
	work := t.TempDir()
	cloop := filepath.Join(work, ".cloop")
	if err := os.MkdirAll(cloop, 0o755); err != nil {
		t.Fatal(err)
	}
	vols, err := Volumes(cloop, work, "")
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}
	if len(vols) != 1 {
		t.Fatalf("Volumes = %+v, want one volume for two paths on one filesystem", vols)
	}
	v := vols[0]
	if v.Path != cloop {
		t.Errorf("Path = %q, want the first path given (%q)", v.Path, cloop)
	}
	if v.FreeBytes <= 0 {
		t.Errorf("FreeBytes = %d on the volume running this test", v.FreeBytes)
	}
	real, err := filepath.EvalSymlinks(work)
	if err != nil {
		t.Fatal(err)
	}
	if v.Mount != real && !strings.HasPrefix(real, strings.TrimSuffix(v.Mount, string(filepath.Separator))+string(filepath.Separator)) {
		t.Errorf("Mount = %q is not an ancestor of %q", v.Mount, real)
	}
}

// TestVolumesMeasuresAMissingPathWhereItWouldBeCreated: a project whose .cloop
// does not exist yet is still on the volume its parent is.
func TestVolumesMeasuresAMissingPathWhereItWouldBeCreated(t *testing.T) {
	work := t.TempDir()
	vols, err := Volumes(filepath.Join(work, "not", "yet", ".cloop"))
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}
	have, err := Volumes(work)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 1 || vols[0].Device != have[0].Device {
		t.Errorf("a missing path resolved to %+v, want the device of its parent %+v", vols, have)
	}
}

// TestVolumesSeparatesDevicesAndFollowsSymlinks: a .cloop that is a symlink
// onto another filesystem is measured where its data lands.
func TestVolumesSeparatesDevicesAndFollowsSymlinks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses /proc as a second filesystem")
	}
	work := t.TempDir()
	if err := os.Symlink("/proc", filepath.Join(work, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	base, err := Volumes(work)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := Volumes("/proc")
	if err != nil {
		t.Fatal(err)
	}
	if base[0].Device == proc[0].Device {
		t.Skip("/proc shares the test directory's device here")
	}
	vols, err := Volumes(work, filepath.Join(work, "elsewhere"))
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}
	if len(vols) != 2 {
		t.Fatalf("Volumes = %+v, want two volumes", vols)
	}
	if vols[1].Device != proc[0].Device || vols[1].Mount != "/proc" {
		t.Errorf("the symlinked path was measured as %+v, want /proc's volume", vols[1])
	}
}

// TestMeasureFilesSkipsTheReserve: the free-space reserve is a placeholder the
// run deletes when the disk fills (Task 20381), not something .cloop costs.
func TestMeasureFilesSkipsTheReserve(t *testing.T) {
	work := t.TempDir()
	cloop := filepath.Join(work, ".cloop")
	if err := os.MkdirAll(cloop, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(diskreserve.Path(work), make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cloop, "config.yaml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	u, err := MeasureFiles(work)
	if err != nil {
		t.Fatal(err)
	}
	if u.TotalBytes != 1 {
		t.Errorf("TotalBytes = %d, want 1 — the reserve was counted", u.TotalBytes)
	}
	if _, ok := u.Entry(diskreserve.Name); ok {
		t.Error("the reserve is listed as a .cloop entry")
	}
}
