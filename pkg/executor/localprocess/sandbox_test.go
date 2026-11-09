package localprocess

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
)

// runToEnd starts spec on a fresh executor and returns its output and final
// status.
func runToEnd(t *testing.T, spec executor.Spec) (string, executor.Status) {
	t.Helper()
	ex := New("sandbox-test")
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	out := drainOutput(t, ex, h.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		st, err := ex.Status(ctx, h.ID)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if st.State.Terminal() {
			return out, st
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the workload never finished: %+v", st)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestTheHubsCredentialsNeverReachAHostWorkload(t *testing.T) {
	t.Setenv("CLOOP_SECRET_KEY", "inherited-root-key")
	t.Setenv("CLOOP_NOTIFY_SLACK", "https://hooks.example/inherited")
	dir := t.TempDir()

	// Inherited, as a workload with no environment of its own is.
	out, st := runToEnd(t, executor.Spec{WorkDir: dir, Argv: []string{"/usr/bin/env"}})
	if st.ExitCode != 0 {
		t.Fatalf("env exited %d: %s", st.ExitCode, out)
	}
	for _, leaked := range []string{"inherited-root-key", "hooks.example"} {
		if strings.Contains(out, leaked) {
			t.Errorf("an inherited environment carried %q into the workload:\n%s", leaked, out)
		}
	}

	// Explicit, as the hub builds it from its own environment plus a lease —
	// which may deliver a variable of the same name, and that one is the
	// workload's.
	out, _ = runToEnd(t, executor.Spec{
		WorkDir: dir,
		Argv:    []string{"/usr/bin/env"},
		Env: append(os.Environ(),
			"CLOOP_SECRET_KEY_PREVIOUS=explicit-old-root",
			"CLOOP_UI_TOKEN=delivered-by-a-lease"),
		Secrets: []executor.SecretBinding{{LeaseID: "lease_1", EnvKeys: []string{"CLOOP_UI_TOKEN"}}},
	})
	if strings.Contains(out, "inherited-root-key") || strings.Contains(out, "explicit-old-root") {
		t.Errorf("an explicit environment carried the hub's root key into the workload:\n%s", out)
	}
	if !strings.Contains(out, "CLOOP_UI_TOKEN=delivered-by-a-lease") {
		t.Errorf("a variable a lease delivered was scrubbed:\n%s", out)
	}
}

func TestASandboxedWorkloadReachesItsProjectAndNotAnothers(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox here: %v", err)
	}
	root := t.TempDir()
	project := filepath.Join(root, "alice-app")
	other := filepath.Join(root, "bob-app")
	for _, d := range []string{project, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "README"), []byte("alice-readme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "README"), []byte("bob-readme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `cat README; cat ` + filepath.Join(other, "README") + ` 2>/dev/null || echo bob-denied
echo tmp=$TMPDIR home=$HOME
echo scratch > $TMPDIR/x && echo tmp-writable
echo built > out.txt && echo project-writable`
	out, st := runToEnd(t, executor.Spec{
		WorkDir:     project,
		Argv:        []string{"/bin/sh", "-c", script},
		HostSandbox: &executor.HostSandbox{Person: "alice@example.com"},
	})
	if st.ExitCode != 0 {
		t.Fatalf("the sandboxed workload exited %d:\n%s", st.ExitCode, out)
	}
	for _, want := range []string{"alice-readme", "bob-denied", "tmp-writable", "project-writable"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "bob-readme") {
		t.Errorf("a sandboxed workload read another project:\n%s", out)
	}
	// Its private directory went with it.
	leftovers, _ := filepath.Glob(filepath.Join(os.TempDir(), sandboxDirPrefix+"*"))
	for _, d := range leftovers {
		if strings.Contains(out, d) {
			t.Errorf("the sandbox's private directory %s outlived the workload", d)
		}
	}
}

func TestASandboxTheDriverCannotHonourIsRefusedOrFailsBeforeTheWorkloadRuns(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox here: %v", err)
	}
	ex := New("sandbox-test")
	if _, err := ex.Start(context.Background(), executor.Spec{
		Argv:        []string{"/bin/true"},
		HostSandbox: &executor.HostSandbox{},
	}); err == nil {
		t.Fatal("a sandboxed workload with no work directory was started")
	}
	if _, err := ex.Start(context.Background(), executor.Spec{
		WorkDir:     t.TempDir(),
		Argv:        []string{"/bin/true"},
		HostSandbox: &executor.HostSandbox{ReadOnly: []string{"relative/path"}},
	}); err == nil {
		t.Fatal("a sandbox naming a relative path was started")
	}
	out, st := runToEnd(t, executor.Spec{
		WorkDir:     t.TempDir(),
		Argv:        []string{"/bin/sh", "-c", "echo the-workload-ran"},
		HostSandbox: &executor.HostSandbox{ReadWrite: []string{filepath.Join(t.TempDir(), "gone")}},
	})
	if st.ExitCode != hostsandbox.ExitHelperFailed || strings.Contains(out, "the-workload-ran") {
		t.Fatalf("exit %d with output:\n%s", st.ExitCode, out)
	}
}

// A sandboxed workload does not inherit the hub operator's credentials from
// the hub's environment, whatever they are called, while a workload outside
// the sandbox keeps the ones a single-user hub runs on. A credential the hub
// set for the run, or a lease delivered, is the workload's either way.
func TestASandboxedWorkloadInheritsNoCredentialOfTheHubs(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox here: %v", err)
	}
	t.Setenv("OPENAI_API_KEY", "hub-operators-openai-key")
	t.Setenv("GROQ_API_KEY", "hub-dictation-key")
	t.Setenv("CLOOP_OIDC_CLIENT_SECRET", "hub-oidc-client-secret")
	t.Setenv("GITHUB_TOKEN", "hub-service-token")
	t.Setenv("SLACK_WEBHOOK_URL", "https://hooks.example/hub-channel")
	t.Setenv("DATABASE_URL", "postgres://hub:hub-db-password@db/hub")
	t.Setenv("SHARED_REGISTRY_MIRROR", "https://mirror.example")
	t.Setenv("LANG", "C.UTF-8")
	env := append(os.Environ(), "GITHUB_TOKEN=delivered-by-a-lease", "CLOOP_KNOWLEDGE_TOKEN=set-for-this-run")
	spec := executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/usr/bin/env"},
		Env:     env,
		Secrets: []executor.SecretBinding{{LeaseID: "lease_1", EnvKeys: []string{"GITHUB_TOKEN"}}},
	}

	out, _ := runToEnd(t, spec)
	for _, want := range []string{"hub-operators-openai-key", "hub-dictation-key", "delivered-by-a-lease"} {
		if !strings.Contains(out, want) {
			t.Errorf("a workload outside the sandbox lost %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hub-oidc-client-secret") {
		t.Errorf("the hub's OIDC client secret reached a workload:\n%s", out)
	}

	spec.HostSandbox = &executor.HostSandbox{Person: "alice@example.com", PassEnv: []string{"SHARED_REGISTRY_MIRROR"}}
	out, st := runToEnd(t, spec)
	if st.ExitCode != 0 {
		t.Fatalf("exit %d:\n%s", st.ExitCode, out)
	}
	for _, leaked := range []string{"hub-operators-openai-key", "hub-dictation-key", "hub-oidc-client-secret",
		"hub-service-token", "hooks.example", "hub-db-password"} {
		if strings.Contains(out, leaked) {
			t.Errorf("the sandboxed workload inherited %q:\n%s", leaked, out)
		}
	}
	for _, want := range []string{"GITHUB_TOKEN=delivered-by-a-lease", "CLOOP_KNOWLEDGE_TOKEN=set-for-this-run",
		"LANG=C.UTF-8", "SHARED_REGISTRY_MIRROR=https://mirror.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("the sandboxed workload lost %q:\n%s", want, out)
		}
	}
}
