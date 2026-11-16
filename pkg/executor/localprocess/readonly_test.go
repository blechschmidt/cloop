package localprocess

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
)

// TestASandboxedRunReadsAListedProjectWhereItIsAndCannotWriteIt (Task 20501):
// a project the run was given is readable at its own path, its root listable;
// a write anywhere in it fails — EACCES under Landlock, EROFS where the run's
// namespace makes the tree read-only; its control directory, git directory and
// credential files cannot be read; and a project the run was not given stays
// out of reach entirely.
func TestASandboxedRunReadsAListedProjectWhereItIsAndCannotWriteIt(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox here: %v", err)
	}
	root := t.TempDir()
	web, api, other := filepath.Join(root, "web"), filepath.Join(root, "api"), filepath.Join(root, "other")
	for _, d := range []string{web, api, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(dir, rel, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(api, "README.md", "api-readme\n")
	write(api, "src/api.go", "package api\n")
	write(api, ".cloop/config.yaml", "api-control-secret\n")
	write(api, ".git/config", "api-git-secret\n")
	write(api, ".env", "api-env-secret\n")
	write(other, "README.md", "other-readme\n")

	probe := func(name, cmd string) string {
		return "if out=$( " + cmd + " 2>&1 ); then echo \"" + name + ":ok $out\"; else echo \"" + name +
			":denied $out\"; fi\n"
	}
	script := probe("read", "cat "+filepath.Join(api, "src", "api.go")) +
		probe("list", "ls "+api) +
		probe("write", "echo x > "+filepath.Join(api, "README.md")) +
		probe("create", "touch "+filepath.Join(api, "planted")) +
		probe("create-nested", "touch "+filepath.Join(api, "src", "planted")) +
		probe("control", "cat "+filepath.Join(api, ".cloop", "config.yaml")) +
		probe("gitdir", "cat "+filepath.Join(api, ".git", "config")) +
		probe("env", "cat "+filepath.Join(api, ".env")) +
		probe("other", "cat "+filepath.Join(other, "README.md"))
	out, st := runToEnd(t, executor.Spec{
		WorkDir:     web,
		Argv:        []string{"/bin/sh", "-c", script},
		HostSandbox: &executor.HostSandbox{Person: "alice@example.com"},
		ReadOnly:    []executor.ReadOnlyProject{{Slug: "api", Project: api, Source: api}},
	})
	if st.ExitCode != 0 {
		t.Fatalf("the sandboxed run exited %d:\n%s", st.ExitCode, out)
	}
	t.Logf("sandbox said:\n%s", out)
	for _, want := range []string{"read:ok package api", "list:ok", "write:denied", "create:denied",
		"create-nested:denied", "control:denied", "gitdir:denied", "env:denied", "other:denied"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Permission denied") && !strings.Contains(out, "Read-only file system") {
		t.Errorf("no write failed with EACCES or EROFS:\n%s", out)
	}
	for _, leak := range []string{"api-control-secret", "api-git-secret", "api-env-secret", "other-readme"} {
		if strings.Contains(out, leak) {
			t.Errorf("the run read %q:\n%s", leak, out)
		}
	}
	for _, p := range []string{filepath.Join(api, "planted"), filepath.Join(api, "src", "planted")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("the run wrote %s", p)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(api, "README.md")); string(b) != "api-readme\n" {
		t.Errorf("the run changed the project it reads: README.md = %q", b)
	}
}

// TestASandboxedRunGivenNoProjectReachesNone: without Spec.ReadOnly the same
// project is out of reach, which is the default this feature only ever widens
// by a readers list.
func TestASandboxedRunGivenNoProjectReachesNone(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox here: %v", err)
	}
	root := t.TempDir()
	web, api := filepath.Join(root, "web"), filepath.Join(root, "api")
	for _, d := range []string{web, api} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(api, "README.md"), []byte("api-readme\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, st := runToEnd(t, executor.Spec{
		WorkDir: web,
		Argv: []string{"/bin/sh", "-c", "cat " + filepath.Join(api, "README.md") +
			" 2>/dev/null || echo api-denied"},
		HostSandbox: &executor.HostSandbox{Person: "alice@example.com"},
	})
	if st.ExitCode != 0 || !strings.Contains(out, "api-denied") || strings.Contains(out, "api-readme") {
		t.Fatalf("a run given no project read one (exit %d):\n%s", st.ExitCode, out)
	}
}
