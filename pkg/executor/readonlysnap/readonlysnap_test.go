package readonlysnap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

func writeFile(t *testing.T, dir, rel, body string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// projectTree is a project with source, ignored files, hidden entries at the
// top and further down, links, and one file too large to carry.
func projectTree(t *testing.T, repo bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "b")
	writeFile(t, dir, "README.md", "hello\n", 0o644)
	writeFile(t, dir, "src/main.go", "package main\n", 0o644)
	writeFile(t, dir, "bin/run.sh", "#!/bin/sh\n", 0o755)
	writeFile(t, dir, "services/api/.env", "TOKEN=nested-secret\n", 0o600)
	writeFile(t, dir, "services/api/handler.go", "package api\n", 0o644)
	writeFile(t, dir, ".cloop/config.yaml", "key: control-secret\n", 0o600)
	writeFile(t, dir, ".env", "TOKEN=top-secret\n", 0o600)
	writeFile(t, dir, "deploy/server.key", "PRIVATE\n", 0o600)
	writeFile(t, dir, ".gitignore", "build/\n*.log\n", 0o644)
	writeFile(t, dir, "build/out.bin", "ignored\n", 0o644)
	writeFile(t, dir, "debug.log", "ignored\n", 0o644)
	if err := os.Symlink("src/main.go", filepath.Join(dir, "main-link.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "outside")); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("x"), MaxFileBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "huge.dat"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if repo {
		git(t, dir, "init", "--quiet")
		git(t, dir, "add", "README.md", "src", ".gitignore")
		// A tracked file under .cloop is still never carried.
		git(t, dir, "add", "-f", ".cloop/config.yaml")
		git(t, dir, "commit", "--quiet", "-m", "init")
		writeFile(t, dir, ".git/config-extra", "secret\n", 0o600)
	}
	return dir
}

func archiveNames(t *testing.T, data []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		switch hdr.Typeflag {
		case tar.TypeSymlink:
			out[hdr.Name] = "-> " + hdr.Linkname
		default:
			b := new(bytes.Buffer)
			_, _ = b.ReadFrom(tr)
			out[hdr.Name] = b.String()
		}
	}
	return out
}

func TestBuildCarriesTheTreeWithoutItsSecrets(t *testing.T) {
	requireGit(t)
	for _, repo := range []bool{true, false} {
		name := "plain directory"
		if repo {
			name = "git repository"
		}
		t.Run(name, func(t *testing.T) {
			dir := projectTree(t, repo)
			var buf bytes.Buffer
			snap, err := Build(context.Background(), dir, &buf)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			got := archiveNames(t, buf.Bytes())
			for _, want := range []string{"README.md", "src/main.go", "bin/run.sh", "services/api/handler.go",
				".gitignore", "main-link.go", "outside"} {
				if _, ok := got[want]; !ok {
					t.Errorf("snapshot lacks %s; it holds %v", want, keys(got))
				}
			}
			for _, never := range []string{".env", "services/api/.env", ".cloop/config.yaml", "deploy/server.key",
				"build/out.bin", "debug.log", "huge.dat", ".git/config", ".git/config-extra"} {
				if _, ok := got[never]; ok {
					t.Errorf("snapshot holds %s", never)
				}
			}
			for name, body := range got {
				for _, secret := range []string{"secret", "PRIVATE"} {
					if strings.Contains(body, secret) {
						t.Errorf("%s carries %q", name, body)
					}
				}
			}
			if len(snap.Skipped) != 1 || snap.Skipped[0] != "huge.dat" {
				t.Errorf("Skipped = %v, want [huge.dat]", snap.Skipped)
			}
			if snap.Archive != int64(buf.Len()) || snap.Files == 0 {
				t.Errorf("snapshot %+v does not describe the %d bytes written", snap, buf.Len())
			}
		})
	}
}

func TestExtractLeavesAReadOnlyTree(t *testing.T) {
	requireGit(t)
	dir := projectTree(t, true)
	var buf bytes.Buffer
	if _, err := Build(context.Background(), dir, &buf); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "b")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	snap, err := Extract(&buf, dest)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	t.Cleanup(func() { _ = Remove(dest) })
	if b, err := os.ReadFile(filepath.Join(dest, "src", "main.go")); err != nil || string(b) != "package main\n" {
		t.Fatalf("src/main.go = %q, %v", b, err)
	}
	if target, err := os.Readlink(filepath.Join(dest, "main-link.go")); err != nil || target != "src/main.go" {
		t.Errorf("main-link.go -> %q, %v", target, err)
	}
	for rel, want := range map[string]os.FileMode{
		".": 0o555, "src": 0o555, "src/main.go": 0o444, "bin/run.sh": 0o555, "services/api": 0o555,
	} {
		fi, err := os.Lstat(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s has mode %v, want %v", rel, got, want)
		}
	}
	if snap.Files == 0 || snap.Links != 2 {
		t.Errorf("Extract described %+v", snap)
	}
	if err := Remove(dest); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Remove left %s: %v", dest, err)
	}
}

// archive builds a snapshot by hand, for the entries a hub never writes.
func archive(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		body := ""
		if h.Typeflag == tar.TypeReg {
			body = "x"
			h.Size = 1
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if body != "" {
			_, _ = tw.Write([]byte(body))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestExtractRefusesWhatWouldLeaveItsDestination(t *testing.T) {
	outside := t.TempDir()
	cases := map[string][]*tar.Header{
		"climbing path": {{Typeflag: tar.TypeReg, Name: "../escaped", Mode: 0o644}},
		"absolute path": {{Typeflag: tar.TypeReg, Name: outside + "/escaped", Mode: 0o644}},
		"through a link it made": {
			{Typeflag: tar.TypeSymlink, Name: "a", Linkname: outside},
			{Typeflag: tar.TypeReg, Name: "a/escaped", Mode: 0o644},
		},
		"hard link":  {{Typeflag: tar.TypeLink, Name: "h", Linkname: "/etc/passwd"}},
		"device":     {{Typeflag: tar.TypeChar, Name: "dev", Devmajor: 1, Devminor: 3}},
		"over again": {{Typeflag: tar.TypeReg, Name: "f", Mode: 0o644}, {Typeflag: tar.TypeReg, Name: "f", Mode: 0o644}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "d")
			if err := os.Mkdir(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = Remove(dest) })
			if _, err := Extract(bytes.NewReader(archive(t, entries...)), dest); err == nil {
				t.Fatalf("Extract accepted %s", name)
			}
			if _, err := os.Lstat(filepath.Join(outside, "escaped")); err == nil {
				t.Fatalf("Extract wrote outside its destination")
			}
		})
	}
}

func TestExtractNeverWritesAHiddenEntry(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Remove(dest) })
	data := archive(t,
		&tar.Header{Typeflag: tar.TypeReg, Name: ".cloop/config.yaml", Mode: 0o644},
		&tar.Header{Typeflag: tar.TypeReg, Name: "sub/.env", Mode: 0o644},
		&tar.Header{Typeflag: tar.TypeReg, Name: "ok.txt", Mode: 0o644},
	)
	if _, err := Extract(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	var got []string
	_ = filepath.WalkDir(dest, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dest, p)
			got = append(got, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(got)
	if strings.Join(got, ",") != "ok.txt" {
		t.Fatalf("extracted %v, want only ok.txt", got)
	}
}

func TestBuildRefusesATreeOverItsBounds(t *testing.T) {
	requireGit(t)
	dir := filepath.Join(t.TempDir(), "big")
	// Nine 31 MiB files of incompressible-looking but cheap content: over
	// MaxTreeBytes, each under MaxFileBytes.
	chunk := make([]byte, 31<<20)
	for i := range chunk {
		chunk[i] = byte(i*7 + i/251)
	}
	for i := 0; i < 9; i++ {
		writeFile(t, dir, "f"+string(rune('a'+i)), string(chunk), 0o644)
	}
	_, err := Build(context.Background(), dir, &bytes.Buffer{})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Build of a %d MiB tree = %v, want ErrTooLarge", 9*31, err)
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestBuildLeavesOutWhatAHiddenLinkPointsInto: a .cloop kept as a link to a
// directory of the tree hides that directory from the snapshot too.
func TestBuildLeavesOutWhatAHiddenLinkPointsInto(t *testing.T) {
	requireGit(t)
	dir := filepath.Join(t.TempDir(), "b")
	writeFile(t, dir, "src/main.go", "package main\n", 0o644)
	writeFile(t, dir, "state/config.yaml", "key: control-secret\n", 0o600)
	if err := os.Symlink("state", filepath.Join(dir, ".cloop")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := Build(context.Background(), dir, &buf); err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := archiveNames(t, buf.Bytes())
	if _, ok := got["src/main.go"]; !ok {
		t.Fatalf("the snapshot lacks src/main.go: %v", keys(got))
	}
	for name := range got {
		if strings.HasPrefix(name, "state") || strings.HasPrefix(name, ".cloop") {
			t.Errorf("the snapshot holds %s, the control directory under another name", name)
		}
	}
}
