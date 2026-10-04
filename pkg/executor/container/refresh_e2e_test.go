package container

// A GitHub App token refreshed in a container sandbox with no git proxy (Task
// 20375): the hub stages the lease's files in a host directory the container
// has bind-mounted, the workload's git reads the token through the lease's
// credential helper on every call, and the hub rewrites the file in place with
// a re-minted token before GitHub's hour ends. The workload then fetches and
// pushes past that hour.
//
// The bind mount is of the directory, not the file, and that is what this test
// is really about: a file renamed into a bind-mounted *directory* is what the
// container reads next, where a single-file bind would pin the old inode.
//
// Opt-in, because it builds an image: CLOOP_REFRESH_CONTAINER_E2E=1. The image
// is the pinned Alpine base the feature e2e (tests/e2e) and CI's container
// step already use, plus git — the layer CI builds and caches before running it.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// refreshImageBase is tests/e2e's featureImageBase: one pinned base, pulled
// once by CI for both.
const refreshImageBase = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

const containerRefreshScript = `set -u
cd /tmp
git clone -q https://github.com/acme/tool repo && echo CLONED
first=$(cat "$CLOOP_LEASE_DIR/github-token")
echo WAITING
i=0
while [ "$(cat "$CLOOP_LEASE_DIR/github-token")" = "$first" ]; do
  i=$((i+1)); [ "$i" -gt 900 ] && { echo NEVER_REFRESHED; exit 3; }
  sleep 0.1
done
echo REFRESHED
echo "NEWTOKEN:$(cat "$CLOOP_LEASE_DIR/github-token")"
i=0
while [ ! -e /workspace/go ]; do
  i=$((i+1)); [ "$i" -gt 900 ] && { echo NEVER_TOLD_TO_GO; exit 4; }
  sleep 0.1
done
cd repo
git fetch -q origin && echo FETCHED
echo late > late.txt && git add late.txt && git -c user.email=a@b.invalid -c user.name=t commit -qm late
git push -q origin HEAD:refs/heads/cloop/late && echo PUSHED
`

func TestContainerSandboxRefreshesItsAppTokenPastTheHour(t *testing.T) {
	if os.Getenv("CLOOP_REFRESH_CONTAINER_E2E") != "1" {
		t.Skip("set CLOOP_REFRESH_CONTAINER_E2E=1 to run the container token-refresh e2e (it builds an image)")
	}
	// Docker specifically, and asked directly: the e2e reaches the host
	// through docker's default bridge, and requireRuntime would ask whichever
	// engine DetectRuntime prefers — podman, on a machine with both.
	docker, err := DetectRuntime("docker")
	if err != nil {
		t.Skipf("docker is unavailable: %v", err)
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		res, ierr := runCLI(ctx, docker, nil, "info")
		cancel()
		if ierr != nil || res.ExitCode != 0 {
			t.Skip("docker is installed but not responding")
		}
	}
	gateway := dockerBridgeGateway(t)
	image := buildRefreshImage(t)

	clock := secretbrokertest.NewClock(time.Now())
	gh := secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: "acme/tool"})
	gh.Clock = clock.Now
	forge := secretbrokertest.NewForge(t, gh, "acme/tool")
	proxy := secretbrokertest.NewConnectProxy(t, gateway+":0", forge.Addr)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(3 * (i + 1))
	}
	cipher, err := secretbroker.NewCipherWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(secretbrokertest.NewStore(), secretbroker.WithCipher(cipher),
		secretbroker.WithClock(clock.Now), secretbroker.WithGitHubApp(gh))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sec, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "container-app", Kind: secretbroker.KindGitHubApp, Payload: secretbrokertest.AppPayload(8, 9), Actor: "e2e",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "test-container"},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/tool"}, Permissions: []string{"contents:write"}},
		TTL:         24 * time.Hour, Actor: "e2e",
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := b.LeaseFor(ctx, secretbroker.Requester{ExecutorID: "test-container", ProjectID: "/srv/c"}, "e2e")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	dir := secretbroker.SandboxLeaseDir(lease.ID)
	delivery, err := lease.Deliver(dir)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer delivery.Close()

	// Built here rather than through newTestExecutor, whose image check asks
	// the runtime DetectRuntime prefers — podman, where both are installed —
	// about an image docker built.
	ex, err := New(Options{
		ID: "test-container", Image: image, Runtime: "docker", Network: NetworkBridge, AllowRootUser: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for _, id := range ex.Handles() {
			_ = ex.Signal(cctx, id, executor.SignalKill)
		}
		_, _ = ex.ReapOrphans(cctx)
	})
	workDir := t.TempDir()
	spec := executor.Spec{
		WorkDir: workDir,
		Argv:    []string{"/bin/sh", "-c", containerRefreshScript},
		Env: append([]string{
			"HOME=/tmp", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
			"GIT_SSL_NO_VERIFY=true", "HTTPS_PROXY=http://" + proxy.Addr, "NO_PROXY=",
		}, delivery.Env()...),
		Secrets:     secretbroker.ExecutorBindings(lease.ID, lease.ExpiresAt, delivery.Bindings()),
		SecretFiles: secretbroker.ExecutorSecretFiles(lease.ID, delivery.Files()),
	}
	h, err := ex.Start(ctx, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lines, err := ex.Stream(ctx, h.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var out strings.Builder
	waitLine := func(want string) {
		t.Helper()
		deadline := time.After(2 * time.Minute)
		for !strings.Contains(out.String(), want) {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("the sandbox ended before %q:\n%s", want, out.String())
				}
				out.WriteString(l.Text)
			case <-deadline:
				t.Fatalf("timed out waiting for %q:\n%s", want, out.String())
			}
		}
	}
	waitLine("WAITING")
	first := gh.Scoped()[0].Token

	clock.Advance(52 * time.Minute)
	fr, err := b.RefreshLeaseFiles(ctx, lease)
	if err != nil || fr == nil || len(fr.Files) != 1 {
		t.Fatalf("RefreshLeaseFiles = %+v, %v", fr, err)
	}
	defer fr.Close()
	req := executor.SecretRefreshRequest{LeaseID: lease.ID}
	for _, f := range fr.Files {
		req.Files = append(req.Files, executor.SecretFile{
			LeaseID: lease.ID, GrantID: f.GrantID, Dir: dir, Name: f.Name, Mode: f.Mode, Content: f.Content,
		})
	}
	rep := ex.RefreshSecretFiles(ctx, req)
	if !rep.Delivered() || rep.FilesRewritten != 1 {
		t.Fatalf("container refresh = %+v; want one file rewritten in the staged directory", rep)
	}
	fr.Delivered(false)
	second := strings.TrimSpace(string(fr.Files[0].Content))
	waitLine("REFRESHED")

	clock.Advance(3 * time.Minute)
	b.RetireSuperseded(ctx, lease.ID)
	if tok, _ := gh.Token(first); !tok.Revoked {
		t.Error("the superseded token was not destroyed after its grace")
	}
	clock.Advance(6 * time.Minute)
	if gh.Valid(first) {
		t.Fatal("the first token outlived its hour; the test would prove nothing")
	}
	if err := os.WriteFile(filepath.Join(workDir, "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	waitLine("PUSHED")
	got := out.String()
	if !strings.Contains(got, "FETCHED") {
		t.Fatalf("the late fetch failed:\n%s", got)
	}
	if forge.Ref(t, "acme/tool", "refs/heads/cloop/late") == "" {
		t.Fatal("the push after the hour did not reach the forge")
	}
	if strings.Contains(got, second) || strings.Contains(got, first) {
		t.Fatal("a token reached the sandbox's captured output")
	}
	if !strings.Contains(got, "NEWTOKEN:"+redact.Marker) {
		t.Fatalf("the refreshed token was not redacted:\n%s", got)
	}
}

// dockerBridgeGateway is the host's address on docker's default bridge, where
// a container on that network reaches the host.
func dockerBridgeGateway(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "network", "inspect", "bridge",
		"--format", "{{(index .IPAM.Config 0).Gateway}}").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Skipf("docker's default bridge has no gateway to reach the host through: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// buildRefreshImage builds the pinned base plus git.
func buildRefreshImage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"),
		[]byte("FROM "+refreshImageBase+"\nRUN apk add --no-cache git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const tag = "cloop-refresh-e2e:git"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	return tag
}
