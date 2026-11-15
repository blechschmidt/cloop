package gitproxy

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

const bundleSecret = "corp-internal-api-key-7f3a9c2e1b"

func scanFor() PushScan {
	return PushScan{Mode: ScanValues, Secrets: []ScanSecret{{Value: bundleSecret, Grant: "g_1", Secret: "internal-api", Field: "env API_KEY"}}}
}

// objects runs an ObjectScan over objects, stopping where it decides.
func objects(t *testing.T, scan PushScan, objs ...[3]string) (ContentScan, error) {
	t.Helper()
	o := NewObjectScan(scan)
	for _, ob := range objs {
		if err := o.Object(ob[0], ob[1], int64(len(ob[2])), strings.NewReader(ob[2])); err != nil {
			if !o.Stopped(err) {
				t.Fatalf("object %s: %v", ob[1], err)
			}
			return o.Result(), err
		}
	}
	return o.Result(), nil
}

func TestObjectScanFindsAValueInAWholeObject(t *testing.T) {
	id := strings.Repeat("ab", 20)
	got, _ := objects(t, scanFor(),
		[3]string{"blob", strings.Repeat("cd", 20), "nothing here\n"},
		[3]string{"blob", id, "KEY = '" + bundleSecret + "'\n"})
	if got.Result != ScanResultSecret || !got.Refused() || got.Objects != 2 {
		t.Fatalf("result = %+v", got)
	}
	f := got.Findings[0]
	if f.Object != id || f.Type != "blob" || f.Grant != "g_1" || f.Secret != "internal-api" || f.Field != "env API_KEY" {
		t.Errorf("finding = %+v", f)
	}
	if strings.Contains(got.Summary(), bundleSecret) {
		t.Error("the summary names the value")
	}
	// In a form a file would hold it in, and in a tree's entry name.
	enc := base64.StdEncoding.EncodeToString([]byte("token=" + bundleSecret))
	if got, _ := objects(t, scanFor(), [3]string{"blob", id, enc}); got.Result != ScanResultSecret {
		t.Errorf("a base64 form: %+v", got)
	}
	tree := "100644 " + bundleSecret + ".txt\x00" + strings.Repeat("\x01", 20)
	if got, _ := objects(t, scanFor(), [3]string{"tree", id, tree}); got.Result != ScanResultSecret {
		t.Errorf("an entry named after the value: %+v", got)
	}
}

func TestObjectScanClean(t *testing.T) {
	got, err := objects(t, scanFor(), [3]string{"blob", strings.Repeat("ab", 20), "nothing secret\n"})
	if err != nil || got.Result != ScanResultClean || got.Refused() || got.Objects != 1 || got.Inflated == 0 {
		t.Errorf("result = %+v, %v", got, err)
	}
	// No values at all: still read whole.
	if got, err := objects(t, PushScan{}, [3]string{"blob", strings.Repeat("ab", 20), "x"}); err != nil || got.Result != ScanResultClean {
		t.Errorf("no values: %+v, %v", got, err)
	}
}

func TestObjectScanStopsAtItsLimits(t *testing.T) {
	scan := scanFor()
	scan.Limits = ScanLimits{MaxObjectBytes: 8, MaxPushBytes: 1 << 20}
	got, err := objects(t, scan, [3]string{"blob", strings.Repeat("ab", 20), "more than eight bytes"})
	if err == nil || got.Result != ScanResultLimit || !got.Refused() || got.Reason == "" {
		t.Errorf("an object over the bound: %+v, %v", got, err)
	}
	scan.Limits = ScanLimits{MaxObjectBytes: 1 << 20, MaxPushBytes: 10}
	got, err = objects(t, scan,
		[3]string{"blob", strings.Repeat("ab", 20), "eight by"},
		[3]string{"blob", strings.Repeat("cd", 20), "eight by"})
	if err == nil || got.Result != ScanResultLimit {
		t.Errorf("objects over the total: %+v, %v", got, err)
	}
	// Once decided, nothing more is read.
	o := NewObjectScan(scan)
	_ = o.Object("blob", "x", 100, strings.NewReader(strings.Repeat("a", 100)))
	if err := o.Object("blob", "y", 1, strings.NewReader("a")); !o.Stopped(err) {
		t.Errorf("an object after the scan decided: %v", err)
	}
}

func tarOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScanFilesFindsAValueInAFile(t *testing.T) {
	data := tarOf(t, map[string]string{
		"artifacts/1_output.txt": "the run printed " + bundleSecret + " to its log\n",
		"tasks/1-first.md":       "# first\n",
	})
	got := ScanFiles(bytes.NewReader(data), scanFor())
	if got.Result != ScanResultSecret || len(got.Findings) != 1 || got.Findings[0].Path != ".cloop/artifacts/1_output.txt" {
		t.Fatalf("result = %+v", got)
	}
	clean := tarOf(t, map[string]string{"artifacts/1_output.txt": "nothing\n"})
	if got := ScanFiles(bytes.NewReader(clean), scanFor()); got.Result != ScanResultClean {
		t.Errorf("clean files: %+v", got)
	}
	if got := ScanFiles(bytes.NewReader([]byte("not a tar at all, and long enough to be read as a header")), scanFor()); got.Result == ScanResultClean {
		t.Errorf("a broken tar scanned clean")
	}
}

func TestScanStringsNamesIndexesNotValues(t *testing.T) {
	texts := []string{"https://git.example.com/acme/app.git", "https://git.example.com/" + bundleSecret + "/app.git", ".cloop/features/x"}
	if got := ScanStrings(texts, scanFor()); len(got) != 1 || got[0] != 1 {
		t.Errorf("ScanStrings = %v, want [1]", got)
	}
	if got := ScanStrings(texts, PushScan{}); len(got) != 0 {
		t.Errorf("no values: %v", got)
	}
}
