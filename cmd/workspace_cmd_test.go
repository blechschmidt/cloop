package cmd

// Tests for `cloop workspace provision`.
//
// Three properties are worth a test here, and they are the three that would be
// invisible if broken:
//
//   - the flags parse the argv the Kubernetes driver actually emits. This is a
//     wire format between two files that never call each other, so nothing but
//     a test connects them;
//   - the credential is gone from the process environment by the time anything
//     is spawned. A leftover variable is inherited silently and forever;
//   - nothing this command emits can carry the token. git quotes URLs and
//     headers back in its error messages, and the output is streamed to a run
//     panel and persisted as an artifact.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// resetWorkspaceProvisionFlags restores the package-level flag variables, which
// cobra binds by pointer, so one test's parse cannot leak into the next.
func resetWorkspaceProvisionFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		workspaceProvisionDir = ""
		workspaceProvisionRepo = ""
		workspaceProvisionRef = ""
		workspaceProvisionDepth = 0
		workspaceProvisionSizeLimitMB = 0
	})
}

// TestWorkspaceProvisionParsesTheKubernetesInitContainerArgv is the drift gate
// between this command and pkg/executor/kubernetes/pod.go.
//
// The argv below is exactly what buildWorkspaceInitContainer renders (minus
// argv[0], which the kubelet resolves). If a flag here is renamed or given a
// different type, the init container starts failing in a cluster with a cobra
// usage error nobody is watching — this is the only place the two halves meet.
func TestWorkspaceProvisionParsesTheKubernetesInitContainerArgv(t *testing.T) {
	resetWorkspaceProvisionFlags(t)

	argv := []string{
		"--dir", "/workspace/project",
		"--repo", "https://github.com/acme/app.git",
		"--ref", "main",
		"--depth", "1",
		"--size-limit-mb", "512",
	}
	if err := workspaceProvisionCmd.ParseFlags(argv); err != nil {
		t.Fatalf("the driver's argv must parse: %v", err)
	}

	got := workspaceProvisionOptions{
		Dir:         workspaceProvisionDir,
		Repo:        workspaceProvisionRepo,
		Ref:         workspaceProvisionRef,
		Depth:       workspaceProvisionDepth,
		SizeLimitMB: workspaceProvisionSizeLimitMB,
	}
	want := workspaceProvisionOptions{
		Dir:         "/workspace/project",
		Repo:        "https://github.com/acme/app.git",
		Ref:         "main",
		Depth:       1,
		SizeLimitMB: 512,
	}
	if got != want {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}

	w, err := got.workspace()
	if err != nil {
		t.Fatalf("the driver's argv must produce a valid workspace: %v", err)
	}
	if w.Kind != executor.WorkspaceGit {
		t.Errorf("Kind = %q, want git — this command provisions nothing else", w.Kind)
	}
	if w.SizeLimitMB != 512 {
		t.Errorf("SizeLimitMB = %d, want 512; the emptyDir sizeLimit and this check must agree",
			w.SizeLimitMB)
	}
}

// TestWorkspaceProvisionOmittedOptionalFlags: the driver leaves --ref, --depth
// and --size-limit-mb off when the spec does not set them, and the absence has
// to mean "the remote's default branch, full history, no limit" rather than an
// error.
func TestWorkspaceProvisionOmittedOptionalFlags(t *testing.T) {
	resetWorkspaceProvisionFlags(t)

	if err := workspaceProvisionCmd.ParseFlags([]string{
		"--dir", "/workspace/project",
		"--repo", "https://github.com/acme/app.git",
	}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	w, err := workspaceProvisionOptions{
		Dir:  workspaceProvisionDir,
		Repo: workspaceProvisionRepo,
	}.workspace()
	if err != nil {
		t.Fatalf("a minimal argv must be accepted: %v", err)
	}
	if w.Ref != "" || w.Depth != 0 || w.SizeLimitMB != 0 {
		t.Errorf("absent flags must stay zero, got %+v", w)
	}
}

// TestWorkspaceProvisionRejectsBadFlags. Each case is something a driver could
// only produce by being wrong, or a person could produce by hand; both deserve
// a message naming what is unacceptable rather than a git failure three steps
// later.
func TestWorkspaceProvisionRejectsBadFlags(t *testing.T) {
	cases := map[string]struct {
		opts workspaceProvisionOptions
		want string
	}{
		"no dir": {
			workspaceProvisionOptions{Repo: "https://example.com/a/b.git"},
			"--dir is required",
		},
		"relative dir": {
			workspaceProvisionOptions{Dir: "project", Repo: "https://example.com/a/b.git"},
			"must be an absolute path",
		},
		"dot dir": {
			workspaceProvisionOptions{Dir: "./project", Repo: "https://example.com/a/b.git"},
			"must be an absolute path",
		},
		"no repo": {
			workspaceProvisionOptions{Dir: "/workspace/p"},
			"--repo is required",
		},
		"cleartext repo": {
			// A brokered token over http is a published token.
			workspaceProvisionOptions{Dir: "/workspace/p", Repo: "http://example.com/a/b.git"},
			"must be an https:// URL",
		},
		"credential in the url": {
			workspaceProvisionOptions{Dir: "/workspace/p", Repo: "https://u:p@example.com/a/b.git"},
			"must not embed credentials",
		},
		"ref that git would read as a flag": {
			workspaceProvisionOptions{Dir: "/workspace/p", Repo: "https://example.com/a/b.git", Ref: "--upload-pack=sh"},
			"starts with a dash",
		},
		"negative depth": {
			workspaceProvisionOptions{Dir: "/workspace/p", Repo: "https://example.com/a/b.git", Depth: -1},
			"depth must be >= 0",
		},
		"negative size limit": {
			workspaceProvisionOptions{Dir: "/workspace/p", Repo: "https://example.com/a/b.git", SizeLimitMB: -1},
			"size_limit_mb must be >= 0",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tc.opts.workspace()
			if err == nil {
				t.Fatalf("%+v was accepted, want an error", tc.opts)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestTakeWorkspaceCredentialClearsTheEnvironment is the assertion that the
// unset actually happens. Provisioning spawns git, git spawns whatever a hook
// or a helper decides to, and a variable left in os.Environ() is inherited by
// every one of them.
func TestTakeWorkspaceCredentialClearsTheEnvironment(t *testing.T) {
	const token = "ghp_test_0123456789abcdefghijklmnop"
	t.Setenv(kubernetes.EnvWorkspaceToken, token)
	t.Setenv(kubernetes.EnvWorkspaceUser, "custom-user")

	cred := takeWorkspaceCredential()

	if cred.Password != token {
		t.Errorf("Password = %q, want the token from the environment", cred.Password)
	}
	if cred.Username != "custom-user" {
		t.Errorf("Username = %q, want the value from the environment", cred.Username)
	}
	for _, name := range []string{kubernetes.EnvWorkspaceToken, kubernetes.EnvWorkspaceUser} {
		if v, ok := os.LookupEnv(name); ok {
			t.Errorf("%s is still set to %q after being read; every child process would inherit it",
				name, v)
		}
	}
	// And it really is gone from the whole environment, not merely from a
	// lookup by that name.
	for _, kv := range os.Environ() {
		if strings.Contains(kv, token) {
			name, _, _ := strings.Cut(kv, "=")
			t.Errorf("the token survives in the environment as %s", name)
		}
	}
}

// TestTakeWorkspaceCredentialDefaultsTheUsername: the driver sets the username
// variable, but a hand-run command and a future driver may not, and the default
// has to be the literal the broker pairs with a GitHub PAT.
func TestTakeWorkspaceCredentialDefaultsTheUsername(t *testing.T) {
	t.Setenv(kubernetes.EnvWorkspaceToken, "ghp_test_0123456789abcdefghijklmnop")
	os.Unsetenv(kubernetes.EnvWorkspaceUser)

	if got := takeWorkspaceCredential().Username; got != secretbroker.GitHubUsername {
		t.Errorf("Username = %q, want the broker's default %q", got, secretbroker.GitHubUsername)
	}
}

// TestTakeWorkspaceCredentialWithoutAToken: no token is a public repository,
// not a misconfiguration. The Kubernetes driver sets no token variable at all
// when no grant was leased.
func TestTakeWorkspaceCredentialWithoutAToken(t *testing.T) {
	for name, value := range map[string]string{"absent": "", "blank": "   "} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(kubernetes.EnvWorkspaceToken, value)
			cred := takeWorkspaceCredential()
			if !cred.Empty() {
				t.Fatalf("credential = %+v, want the zero value for an unauthenticated fetch", cred)
			}
			if len(cred.Secrets()) != 0 {
				t.Errorf("an empty credential has nothing to redact, got %v", cred.Secrets())
			}
		})
	}
}

// TestWorkspaceProvisionRedactsItsFailure is the security assertion.
//
// The token is *embedded in the repository path* so that the failure is
// guaranteed to quote it: every diagnostic on this path names the clone URL,
// whether it comes from git ("unable to access ..."), from the missing-git
// branch, or from this command's own wrapper. That makes the test hermetic —
// it needs no git server and no reachable network — while still exercising the
// real seam, which is that git happily echoes back strings that contain the
// credential.
func TestWorkspaceProvisionRedactsItsFailure(t *testing.T) {
	const token = "deadbeefcafebabe0123456789"
	// Port 1 is not listening anywhere, so a machine with git refuses in
	// milliseconds instead of waiting on a name that might resolve.
	repo := "https://127.0.0.1:1/acme/" + token + ".git"
	cred := executor.GitCredential{Username: secretbroker.GitHubUsername, Password: token}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var out bytes.Buffer
	err := runWorkspaceProvision(ctx, workspaceProvisionOptions{
		Dir:  t.TempDir(),
		Repo: repo,
	}, cred, &out)
	if err == nil {
		t.Fatal("provisioning an unreachable repository must fail, not produce an empty tree")
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error should wrap ErrWorkspaceUnavailable so callers can branch on it, got %v", err)
	}

	for _, secret := range cred.Secrets() {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error leaks the credential: %v", err)
		}
		if strings.Contains(out.String(), secret) {
			t.Errorf("the streamed output leaks the credential:\n%s", out.String())
		}
	}
	// The redaction is not passing by virtue of the message being empty: the
	// marker proves the substitution ran on text that held the secret.
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("the failure should show where the credential was removed; got %v", err)
	}
	// And the operator can still tell which repository and which directory,
	// which is the whole question after a failed init container.
	if !strings.Contains(err.Error(), "127.0.0.1:1/acme/") {
		t.Errorf("the failure should name the repository; got %v", err)
	}
	if !strings.Contains(err.Error(), "cannot provision") {
		t.Errorf("the failure should read as a provisioning refusal; got %v", err)
	}
}

// TestWorkspaceProvisionCreatesTheTargetDirectory: the Kubernetes driver mounts
// an emptyDir and points this command at a sub-path of it, so on the first run
// the target does not exist. A command that required it would fail every Pod
// whose Spec puts the harness below the volume root.
func TestWorkspaceProvisionCreatesTheTargetDirectory(t *testing.T) {
	dir := t.TempDir() + "/nested/project"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The fetch fails — nothing is listening — but the directory must exist by
	// the time it does.
	_ = runWorkspaceProvision(ctx, workspaceProvisionOptions{
		Dir:  dir,
		Repo: "https://127.0.0.1:1/acme/app.git",
	}, executor.GitCredential{}, &bytes.Buffer{})

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("the target directory should have been created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
}
