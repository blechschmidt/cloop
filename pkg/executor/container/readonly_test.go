package container

// Real-runtime tests for Spec.ReadOnly (Task 20501): another project bound
// read-only at /readonly/<slug>, its hidden entries covered.
//
// Like hostmount_test.go they run a container rather than read argv: the
// guarantee is the runtime's read-only flag and what the covers hide, which a
// command line can describe without either being true. Set
// CLOOP_TEST_OCI_RUNTIME (runsc, kata-runtime) to run them under another
// runtime the engine knows.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// testOCIRuntimeEnv names the low-level runtime the read-only tests use.
const testOCIRuntimeEnv = "CLOOP_TEST_OCI_RUNTIME"

// readOnlyTestExecutor is newTestExecutor under the runtime the environment
// names.
func readOnlyTestExecutor(t *testing.T) *Executor {
	t.Helper()
	return newTestExecutor(t, defaultTestImage, func(o *Options) {
		o.OCIRuntime = strings.TrimSpace(os.Getenv(testOCIRuntimeEnv))
	})
}

// readOnlyProjectTree builds a project directory holding source files, the
// entries a reader must not see, and a nested .env a top-level cover does not
// reach.
func readOnlyProjectTree(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "proj-b")
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", "hello from b\n")
	write("src/lib.go", "package lib\n")
	write(".cloop/config.yaml", "anthropic_api_key: sk-secret-of-b\n")
	write(".git/config", "[remote \"origin\"]\n\turl = https://x-access-token:ghs_secret@github.com/b/b\n")
	write(".env", "TOKEN=secret-of-b\n")
	write("server.key", "-----BEGIN PRIVATE KEY-----\n")
	return dir
}

// TestReadOnlyProjectIsBoundReadOnlyWithItsSecretsCovered: a listed project is
// at /readonly/<slug>, readable; a write anywhere under it fails with EROFS;
// its control directory, git directory and credential files read as empty.
func TestReadOnlyProjectIsBoundReadOnlyWithItsSecretsCovered(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container; skipped under -short")
	}
	ex := readOnlyTestExecutor(t)
	b := readOnlyProjectTree(t)
	before := treeFingerprint(t, b)

	script := strings.Join([]string{
		`echo "kernel $(uname -r)"`,
		`cat /readonly/b/README.md`,
		`cat /readonly/b/src/lib.go`,
		`echo "cloop=[$(ls -A /readonly/b/.cloop)] git=[$(ls -A /readonly/b/.git)]"`,
		`echo "env=[$(cat /readonly/b/.env)] key=[$(cat /readonly/b/server.key)]"`,
		`for p in /readonly/b/new /readonly/b/README.md /readonly/b/src/x /readonly/b/.cloop/x /readonly/b/.env; do ` +
			`if (echo x > "$p") 2>/tmp/err; then echo "WROTE $p"; else echo "refused $p: $(cat /tmp/err)"; fi; done`,
		`rm -f /readonly/b/README.md 2>/dev/null && echo "REMOVED README" || echo "remove refused"`,
		`test -e /readonly/c && echo "C IS THERE" || echo "c absent"`,
	}, "\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := executor.Run(ctx, ex, executor.Spec{
		WorkDir:  t.TempDir(),
		Argv:     []string{"/bin/sh", "-c", script},
		ReadOnly: []executor.ReadOnlyProject{{Slug: "b", Project: b, Name: "B", Source: b}},
	})
	out := string(res.Output)
	if err != nil {
		t.Fatalf("run with a read-only project: %v (output %q)", err, out)
	}
	t.Logf("runtime %q, sandbox said:\n%s", ex.opts.OCIRuntime, out)
	for _, want := range []string{
		"hello from b", "package lib",
		"cloop=[] git=[]", "env=[] key=[]",
		"refused /readonly/b/new", "refused /readonly/b/README.md", "refused /readonly/b/src/x",
		"refused /readonly/b/.cloop/x", "refused /readonly/b/.env",
		"remove refused", "c absent",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{"WROTE", "REMOVED", "sk-secret-of-b", "ghs_secret", "secret-of-b", "BEGIN PRIVATE"} {
		if strings.Contains(out, leak) {
			t.Errorf("output holds %q — the project was not read-only or its secrets were not covered:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "Read-only file system") {
		t.Errorf("no write was refused with EROFS:\n%s", out)
	}
	if after := treeFingerprint(t, b); after != before {
		t.Errorf("the project changed on the host:\nbefore %s\nafter  %s", before, after)
	}
}

// TestNoReadOnlyProjectNoMount: a run given no other project has no /readonly
// at all, so nothing of another project is there to find.
func TestNoReadOnlyProjectNoMount(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container; skipped under -short")
	}
	ex := readOnlyTestExecutor(t)
	res, err := runInSandbox(t, ex, t.TempDir(), []string{"/bin/sh", "-c",
		`test -e /readonly && echo "READONLY THERE" || echo "no readonly"`}, nil)
	if err != nil {
		t.Fatalf("run: %v (output %q)", err, res.Output)
	}
	if !strings.Contains(string(res.Output), "no readonly") {
		t.Fatalf("a run given no project has a /readonly: %q", res.Output)
	}
}

// TestReadOnlyCoversAreRemovedWithTheContainer: the directory staged for the
// covers goes when the workload is terminal.
func TestReadOnlyCoversAreRemovedWithTheContainer(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container; skipped under -short")
	}
	ex := readOnlyTestExecutor(t)
	stage := t.TempDir()
	ex.opts.StageDir = stage
	b := readOnlyProjectTree(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if res, err := executor.Run(ctx, ex, executor.Spec{
		WorkDir:  t.TempDir(),
		Argv:     []string{"/bin/true"},
		ReadOnly: []executor.ReadOnlyProject{{Slug: "b", Project: b, Source: b}},
	}); err != nil {
		t.Fatalf("run: %v (output %q)", err, res.Output)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		left, _ := filepath.Glob(filepath.Join(stage, readOnlyDirPrefix+"*"))
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the covers' directory outlived the container: %v", left)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// treeFingerprint lists every path under dir with its size and content.
func treeFingerprint(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b.WriteString(rel)
		if fi.Mode().IsRegular() {
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			b.WriteString("=" + string(data))
		}
		b.WriteString(";")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
