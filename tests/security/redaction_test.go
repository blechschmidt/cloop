package security

// Guarantee 7: a leased credential does not survive in the run's own record.
//
// The threat is not an attacker — it is the harness itself. An agent given a
// GitHub PAT, a kubeconfig or an egress credential has every ordinary reason to
// print it: a `set -x` in a build script, a debug flag, an HTTP client dumping
// its request headers, a panic whose stack carries an argv. Nothing about that
// is a compromise, and it happens on a working system.
//
// What makes it a finding is where the value lands. A lease lives for minutes;
// the places its plaintext would come to rest do not:
//
//   - .cloop/tasks/<id>-<slug>.md, the task artifact, which is permanent
//   - the step log in state.db, which the dashboard renders on demand
//   - the live-log frames, broadcast to every browser attached to the project
//
// So the credential outlives its own revocation, in a file nobody thinks of as
// a secret store, readable by anyone with the project. pkg/audit scans for
// exactly this after the fact — which proves the leak was expected and only
// reported, never prevented.
//
// These tests assert it is prevented, on both sides of the sandbox boundary,
// because output is captured on both and neither half covers the other:
//
//	inside  the sandbox: provider.Build's decorator, before the orchestrator
//	                     writes the artifact, the step log and the replay log
//	outside the sandbox: the executor driver's emit path, before the hub
//	                     broadcasts a frame or persists RunResult.Output
//
// The marker is asserted positively as well as the value negatively. A test
// that only checks the token is absent would pass just as happily against a
// harness that produced no output at all, which is the failure mode that makes
// a security test worthless.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
)

// leasedPAT is the value under test. It is long enough to clear
// redact.MinLen — a shorter one would be skipped by design, and a test built on
// one would be asserting nothing.
const leasedPAT = "ghp_S3cr3tLeasedTokenValue0123456789abcd"

// echoingProvider is a harness that prints its credential. It streams the token
// one fragment at a time *and* returns it in the final output, because those are
// two different sinks — the live artifact and everything persisted — and a fix
// that covered only one would otherwise look complete.
type echoingProvider struct {
	// chunks are delivered through OnToken, deliberately splitting the token
	// across callbacks. A per-chunk redactor passes both halves through.
	chunks []string
}

func (p *echoingProvider) Name() string         { return "echoing" }
func (p *echoingProvider) DefaultModel() string { return "test" }

func (p *echoingProvider) Complete(_ context.Context, _ string, opts provider.Options) (*provider.Result, error) {
	var full strings.Builder
	for _, c := range p.chunks {
		full.WriteString(c)
		if opts.OnToken != nil {
			opts.OnToken(c)
		}
	}
	return &provider.Result{Output: full.String()}, nil
}

// leaseEnviron is what a workload's environment looks like once a github_pat
// grant has been materialised into it: the credential, the constraint echo
// beside it, and the declaration of which of the two is which.
func leaseEnviron(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	// The token file a repo-scoped grant delivers, newline and all.
	if err := os.WriteFile(filepath.Join(dir, "github-token"), []byte(leasedPAT+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{
		redact.EnvKey + "=GITHUB_TOKEN",
		"GITHUB_TOKEN=" + leasedPAT,
		"CLOOP_GITHUB_REPO_ALLOWLIST=blechschmidt/cloop",
		redact.LeaseDirKey + "=" + dir,
	}
}

// --- inside the sandbox: artifact, step log, live artifact --------------

// TestLeakedCredentialNeverReachesTheRunRecord is the headline assertion: a
// task that echoes its leased credential produces an artifact, a step log and a
// streamed live artifact that all carry the marker and none the value.
//
// It drives the real writers — artifact.WriteTaskArtifact, state.AddStep — from
// the real decorator, rather than asserting on the decorator alone. The whole
// question is whether the scrubbed string is the one that reaches disk.
func TestLeakedCredentialNeverReachesTheRunRecord(t *testing.T) {
	set := redact.FromEnviron(leaseEnviron(t))
	if set.Len() == 0 {
		t.Fatal("the lease environment yielded no values to redact; the rest of this test would be vacuous")
	}

	// Split mid-token, which is what a token-by-token stream does.
	harness := &echoingProvider{chunks: []string{
		"cloning blechschmidt/cloop\n+ export GITHUB_TOKEN=",
		leasedPAT[:12], leasedPAT[12:28], leasedPAT[28:],
		"\nTASK_DONE\n",
	}}
	p := provider.WithRedaction(harness, set)

	var streamed strings.Builder
	res, err := p.Complete(context.Background(), "prompt", provider.Options{
		OnToken: func(tok string) { streamed.WriteString(tok) },
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Sink 1: the live artifact, written from OnToken as the harness streams.
	assertScrubbed(t, "the streamed live artifact", streamed.String())
	// Sink 2: the result every persistent writer is fed from.
	assertScrubbed(t, "the provider result", res.Output)

	// Sink 3: the task artifact, through its real writer.
	workDir := t.TempDir()
	task := &pm.Task{ID: 42, Title: "leak the token", Status: pm.TaskDone}
	// The writer returns a workDir-relative path, which is what lands in
	// task.ArtifactPath.
	rel, err := artifact.WriteTaskArtifact(workDir, task, res.Output)
	if err != nil {
		t.Fatalf("WriteTaskArtifact: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(workDir, rel))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	assertScrubbed(t, "the task artifact at "+rel, string(onDisk))

	// Sink 4: the step log, through the real state writer, read back off disk
	// rather than out of memory — persistence is the property at issue.
	if err := os.MkdirAll(filepath.Join(workDir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	ps, err := state.Init(workDir, "goal", 10)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	ps.AddStep(state.StepResult{Task: "Task 42: leak the token", Output: res.Output, Time: time.Now()})
	if err := ps.Save(); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	reloaded, err := state.Load(workDir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if len(reloaded.Steps) == 0 {
		t.Fatal("no step was persisted; the step-log assertion would be vacuous")
	}
	assertScrubbed(t, "the persisted step log", reloaded.Steps[len(reloaded.Steps)-1].Output)
}

// TestRedactionLeavesTheConstraintEchoAlone is the counterweight. A lease
// delivers the credential *and* the repository allowlist it was narrowed to; if
// scrubbing replaced the second, every mention of the repository in a
// transcript would become a marker. Operators would learn to distrust the
// marker, and then the guarantee above is worth nothing in practice.
func TestRedactionLeavesTheConstraintEchoAlone(t *testing.T) {
	set := redact.FromEnviron(leaseEnviron(t))
	p := provider.WithRedaction(&echoingProvider{chunks: []string{
		"pushing to blechschmidt/cloop as " + leasedPAT + "\n",
	}}, set)

	res, err := p.Complete(context.Background(), "prompt", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.Contains(res.Output, "blechschmidt/cloop") {
		t.Errorf("the repository allowlist was redacted as though it were a credential: %q", res.Output)
	}
	assertScrubbed(t, "the provider result", res.Output)
}

// TestBrokerDeclaresWhichLeaseVariablesAreCredentials closes the loop between
// the two halves. The scrubbing above only works because the broker names the
// credential-bearing variables when it mints the lease; if that declaration
// stopped being emitted, every test here would still pass while a real run
// leaked, because these tests write the environment themselves.
func TestBrokerDeclaresWhichLeaseVariablesAreCredentials(t *testing.T) {
	mat := secretbroker.Material{
		GrantID: "grant_redaction", SecretName: "gh", Kind: secretbroker.KindGitHubPAT,
		Env:          map[string]string{"GITHUB_TOKEN": leasedPAT, "CLOOP_GITHUB_REPO_ALLOWLIST": "org/*"},
		SensitiveEnv: []string{"GITHUB_TOKEN"},
	}
	lease := &secretbroker.Lease{ID: "lease_redaction", Materials: []secretbroker.Material{mat}}

	delivery, err := lease.Deliver("/run/cloop/cloop-lease-redactiontest")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer delivery.Close()

	env := delivery.Env()
	var declared string
	for _, kv := range env {
		if name, value, ok := strings.Cut(kv, "="); ok && name == redact.EnvKey {
			declared = value
		}
	}
	if declared == "" {
		t.Fatalf("the lease environment carries no %s, so a workload cannot tell its "+
			"credentials from its constraints: %v", redact.EnvKey, env)
	}
	if !strings.Contains(declared, "GITHUB_TOKEN") {
		t.Errorf("%s = %q, missing the credential variable", redact.EnvKey, declared)
	}
	if strings.Contains(declared, "CLOOP_GITHUB_REPO_ALLOWLIST") {
		t.Errorf("%s = %q names the constraint echo, which would mangle every mention "+
			"of the repository in a transcript", redact.EnvKey, declared)
	}
	// The declaration must carry names only. A value here would be one more
	// durable copy of the secret, in the variable meant to protect it.
	if strings.Contains(declared, leasedPAT) {
		t.Errorf("%s carries the credential value itself: %q", redact.EnvKey, declared)
	}

	// And it must actually drive redaction when a workload reads it back.
	if !redact.FromEnviron(env).Contains(leasedPAT) {
		t.Error("a workload reading this environment would not redact its own token")
	}
}

// --- outside the sandbox: live-log frames and RunResult -----------------

// TestExecutorScrubsTheFramesItBroadcasts covers the hub's side. LogLine.Text
// is forwarded verbatim to the live-log room by pkg/ui's broadcastLog, and
// accumulated into RunResult.Output by executor.Run, so a value present here is
// a value on every attached browser.
//
// The workload is a real child process echoing a variable out of its own
// environment — the `set -x` case, not a simulation of it.
func TestExecutorScrubsTheFramesItBroadcasts(t *testing.T) {
	ex := localprocess.New("redaction-test")
	spec := executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", `echo "token=$GITHUB_TOKEN"; echo "repo=$CLOOP_GITHUB_REPO_ALLOWLIST"`},
		Env:     leaseEnviron(t),
	}
	// The guarantee rests on the driver deriving its scrub set from the spec.
	if len(spec.SecretValues()) == 0 {
		t.Fatal("the spec yielded no secret values; the driver would have nothing to redact")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := executor.Run(ctx, ex, spec)
	if err != nil {
		t.Fatalf("Run: %v (output=%q)", err, res.Output)
	}

	// RunResult.Output is assembled from the same frames the live-log room
	// receives, so asserting on it asserts on both.
	assertScrubbed(t, "RunResult.Output", string(res.Output))
	if !strings.Contains(string(res.Output), "repo=blechschmidt/cloop") {
		t.Errorf("the constraint echo was mangled or the workload did not run: %q", res.Output)
	}
}

// assertScrubbed holds one sink to both halves of the guarantee: the credential
// is gone, and something was actually there to remove.
func assertScrubbed(t *testing.T, what, got string) {
	t.Helper()
	if strings.Contains(got, leasedPAT) {
		t.Errorf("%s carries the leased credential verbatim:\n%s", what, got)
	}
	// A recognisable fragment is a leak too — half a token still identifies
	// the account, and a redactor that only breaks the value up rather than
	// removing it would pass the check above.
	if frag := leasedPAT[:20]; strings.Contains(got, frag) {
		t.Errorf("%s carries a %d-character fragment of the credential:\n%s", what, len(frag), got)
	}
	if !strings.Contains(got, redact.Marker) {
		t.Errorf("%s carries no %s marker, so nothing proves the credential was there to be "+
			"removed rather than the harness having produced nothing:\n%s", what, redact.Marker, got)
	}
}
