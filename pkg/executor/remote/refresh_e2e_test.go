package remote_test

// A GitHub App token refreshed on a device (Task 20375, protocol v17): a real
// hub, a real agent, and a workload whose own git fetches and pushes an hour
// after dispatch because the hub sent it the token's replacement.
//
// GitHub is secretbrokertest's fake on a clock the test drives, and the forge
// honours only what that fake would honour now, so the late fetch succeeds
// only with the re-minted token. The workload reaches the forge as github.com
// through a CONNECT proxy, which is what lets the lease's credential helper —
// it answers for github.com only — answer at all.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// refreshScript clones, waits for its token file to change, prints the new
// token (which the hub must scrub), waits to be told to go, then fetches and
// pushes. It prints only markers otherwise.
const refreshScript = `set -u
gofile="$PWD/go"
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
while [ ! -e "$gofile" ]; do
  i=$((i+1)); [ "$i" -gt 900 ] && { echo NEVER_TOLD_TO_GO; exit 4; }
  sleep 0.1
done
cd repo
git fetch -q origin && echo FETCHED
echo late > late.txt && git add late.txt && git -c user.email=a@b.invalid -c user.name=t commit -qm late
git push -q origin HEAD:refs/heads/cloop/late && echo PUSHED
`

func TestLoopbackDeviceRefreshesItsAppTokenPastTheHour(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the loopback test runs POSIX shell commands")
	}
	gitBin, _ := secretbrokertest.GitTools(t)
	clock := secretbrokertest.NewClock(time.Now())
	gh := secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: "acme/tool"})
	gh.Clock = clock.Now
	forge := secretbrokertest.NewForge(t, gh, "acme/tool")
	proxy := secretbrokertest.NewConnectProxy(t, "127.0.0.1:0", forge.Addr)

	lb := newLoopback(t)
	ex := lb.executor(t)
	if !ex.SupportsSecretRefresh() {
		t.Fatal("a current agent must negotiate a protocol that carries the refresh frame")
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(7 * (i + 1))
	}
	cipher, err := secretbroker.NewCipherWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	audit := &secretbrokertest.Recorder{}
	b, err := secretbroker.New(secretbrokertest.NewStore(), secretbroker.WithCipher(cipher),
		secretbroker.WithClock(clock.Now), secretbroker.WithGitHubApp(gh), secretbroker.WithAuditor(audit))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sec, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "device-app", Kind: secretbroker.KindGitHubApp, Payload: secretbrokertest.AppPayload(5, 6), Actor: "e2e",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: ex.ID()},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/tool"}, Permissions: []string{"contents:write"}},
		TTL:         24 * time.Hour, Actor: "e2e",
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := b.LeaseFor(ctx, secretbroker.Requester{ExecutorID: ex.ID(), ProjectID: "/srv/device-refresh"}, "e2e")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	delivery, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer delivery.Close()

	env := append([]string{
		"PATH=" + filepath.Dir(gitBin) + ":/usr/bin:/bin", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0", "GIT_SSL_NO_VERIFY=true", "HTTPS_PROXY=http://" + proxy.Addr, "NO_PROXY=",
	}, delivery.Env()...)
	spec := executor.Spec{
		WorkDir:     "refresh-project",
		Argv:        []string{"/bin/sh", "-c", refreshScript},
		Env:         env,
		Labels:      map[string]string{"project": "/srv/device-refresh"},
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
		deadline := time.After(90 * time.Second)
		for !strings.Contains(out.String(), want) {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("the workload ended before %q:\n%s", want, out.String())
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
		t.Fatalf("RefreshLeaseFiles = %+v, %v; want one token file", fr, err)
	}
	defer fr.Close()
	req := executor.SecretRefreshRequest{LeaseID: lease.ID, Reason: "e2e"}
	for _, f := range fr.Files {
		req.Files = append(req.Files, executor.SecretFile{
			LeaseID: lease.ID, GrantID: f.GrantID, Dir: secretbroker.SandboxLeaseDir(lease.ID),
			Name: f.Name, Mode: f.Mode, Content: f.Content,
		})
	}
	results := lb.hub.RefreshLease(ctx, req)
	if len(results) != 1 || !results[0].Report.Delivered() || results[0].Report.FilesRewritten != 1 {
		t.Fatalf("hub refresh = %+v; want the device to rewrite one file", results)
	}
	fr.Delivered(false)
	second := strings.TrimSpace(string(fr.Files[0].Content))
	waitLine("REFRESHED")
	waitLine("NEWTOKEN:")
	waitLine("\n")

	// The superseded token goes after its grace, while it would still work.
	clock.Advance(3 * time.Minute)
	b.RetireSuperseded(ctx, lease.ID)
	if tok, _ := gh.Token(first); !tok.Revoked {
		t.Error("the superseded token was not destroyed after its grace")
	}

	clock.Advance(6 * time.Minute)
	if gh.Valid(first) {
		t.Fatal("the first token outlived its hour; the test would prove nothing")
	}
	if err := os.WriteFile(filepath.Join(lb.root, "refresh-project", "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitLine("PUSHED")
	if !strings.Contains(out.String(), "FETCHED") {
		t.Fatalf("the late fetch failed:\n%s", out.String())
	}
	if forge.Ref(t, "acme/tool", "refs/heads/cloop/late") == "" {
		t.Fatal("the push after the hour did not reach the forge")
	}
	// The hub scrubs the new token from what the device sends back, as it
	// scrubbed the first: a refresh must not open a hole in the redaction.
	got := out.String()
	if strings.Contains(got, second) || strings.Contains(got, first) {
		t.Fatal("a token came back from the device verbatim")
	}
	if !strings.Contains(got, "NEWTOKEN:"+redact.Marker) {
		t.Fatalf("the refreshed token was not redacted in the device's output:\n%s", got)
	}
}
