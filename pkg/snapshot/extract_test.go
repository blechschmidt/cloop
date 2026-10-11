package snapshot

// extractArchive is the restore path: an archive is read back into the live
// .cloop directory, so what it accepts is what a restore can write.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// legacyTypeflag is the typeflag byte pre-POSIX archivers wrote for a regular
// file: a NUL, which archive/tar names TypeRegA and deprecates, since its
// reader turns it into TypeReg. The fixture needs the byte itself.
const legacyTypeflag byte = '\x00'

// legacyArchive writes a gzip-compressed tar whose entries carry TypeRegA, the
// pre-POSIX flag (a NUL byte) for a regular file, and returns its path.
// tar.Writer never emits that flag — it promotes it to TypeReg — so the header
// is written as TypeReg and the flag and checksum patched afterwards, as an old
// archiver would have left them.
func legacyArchive(t *testing.T, entries map[string]string) string {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	type patch struct {
		off   int
		slash int // index of a trailing slash to restore in the name, or -1
	}
	var patches []patch
	for name, body := range entries {
		// tar.Writer also refuses a regular file whose name ends in a slash,
		// which a legacy directory entry is: write it with a placeholder in
		// the slash's place and put the slash back with the flag.
		p := patch{off: raw.Len(), slash: -1}
		if strings.HasSuffix(name, "/") {
			p.slash = len(name) - 1
			name = name[:p.slash] + "_"
		}
		patches = append(patches, p)
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := tw.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b := raw.Bytes()
	for _, p := range patches {
		h := b[p.off : p.off+512]
		h[156] = legacyTypeflag
		if p.slash >= 0 {
			h[p.slash] = '/'
		}
		copy(h[148:156], "        ")
		sum := 0
		for _, c := range h {
			sum += int(c)
		}
		copy(h[148:156], fmt.Sprintf("%06o\x00 ", sum))
	}

	path := filepath.Join(t.TempDir(), "legacy.tar.gz")
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, gzBuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestExtractArchiveRestoresLegacyTypeflags: a regular file flagged the
// pre-POSIX way is restored as one, and a legacy entry whose name ends in a
// slash as a directory. extractArchive used to list TypeRegA beside TypeReg;
// staticcheck's SA1019 flagged it, and Task 20411 dropped it because
// tar.Reader already reports the legacy flag as TypeReg or TypeDir. This pins
// that a restore of such an archive did not change with it.
func TestExtractArchiveRestoresLegacyTypeflags(t *testing.T) {
	archive := legacyArchive(t, map[string]string{
		".cloop/notes/legacy.txt": "written by an old archiver\n",
		".cloop/legacy-dir/":      "",
	})
	// The fixture must really carry the legacy flag, or this proves nothing.
	flags := typeflags(t, gunzip(t, archive))
	if len(flags) != 2 || flags[0] != legacyTypeflag || flags[1] != legacyTypeflag {
		t.Fatalf("the fixture's headers carry typeflags %q, want two legacy NUL flags", flags)
	}

	dest := t.TempDir()
	if err := extractArchive(archive, dest); err != nil {
		t.Fatalf("extractArchive: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, ".cloop", "notes", "legacy.txt"))
	if err != nil {
		t.Fatalf("the legacy regular file was not restored: %v", err)
	}
	if string(got) != "written by an old archiver\n" {
		t.Errorf("restored %q", got)
	}
	if fi, err := os.Stat(filepath.Join(dest, ".cloop", "legacy-dir")); err != nil || !fi.IsDir() {
		t.Errorf("the legacy directory entry was not restored as a directory (err %v)", err)
	}
}

// TestExtractArchiveRefusesAnEscape keeps the guard in front of every write:
// an entry that climbs out of the destination is refused, legacy flag or not,
// and nothing is written outside it.
func TestExtractArchiveRefusesAnEscape(t *testing.T) {
	archive := legacyArchive(t, map[string]string{"../escaped.txt": "out\n"})
	parent := t.TempDir()
	dest := filepath.Join(parent, "dest")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	err := extractArchive(archive, dest)
	if err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("extractArchive = %v, want an unsafe-path refusal", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "escaped.txt")); !os.IsNotExist(err) {
		t.Errorf("an entry was written outside the destination: %v", err)
	}
}

func gunzip(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := out.ReadFrom(gz); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// typeflags walks a raw tar's headers and returns each one's typeflag byte, so
// a fixture can be checked for what it is meant to contain.
func typeflags(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out []byte
	for off := 0; off+512 <= len(raw); {
		h := raw[off : off+512]
		if bytes.Equal(h, make([]byte, 512)) {
			break // the end-of-archive marker
		}
		size, err := strconv.ParseInt(strings.TrimRight(strings.TrimSpace(string(h[124:136])), "\x00"), 8, 64)
		if err != nil {
			t.Fatalf("header at %d: size field %q: %v", off, h[124:136], err)
		}
		out = append(out, h[156])
		off += 512 + int((size+511)/512*512)
	}
	return out
}
