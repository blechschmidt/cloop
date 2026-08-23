package remote_test

// Control-plane-side workspace tests, driven with a scripted peer.
//
// The device's half — a real clone, a real Authorization header, a real
// redaction — lives in pkg/executor/agent's workspace_test.go, against a real
// git server. What only the hub can get wrong is here: the version rule that
// keeps a private-repository run off an agent that would silently ignore the
// credential, the lease's lifetime, and above all the placement of the
// credential *beside* the Spec rather than inside it. That last one is not a
// style preference: pkg/executorstore persists the dispatched Spec, so a token
// that reached a Spec field would become durable.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

const workspaceTestToken = "ghp_hub_0123456789abcdefghijklmnopqrstuvwxyz"

// gitSpec is a workload whose source tree must be cloned by the device.
func gitSpec(grant string) executor.Spec {
	return executor.Spec{
		WorkDir: "cloned-project",
		Argv:    []string{"/bin/sh", "-c", "true"},
		Labels:  map[string]string{"project": "/srv/projects/demo"},
		Workspace: executor.Workspace{
			Kind:            executor.WorkspaceGit,
			Repo:            "https://github.com/acme/widget.git",
			Ref:             "main",
			Depth:           1,
			CredentialGrant: grant,
		},
	}
}

// fakeSource is a WorkspaceCredentialSource with no broker behind it.
type fakeSource struct {
	cred executor.GitCredential
	// repo, when set, is the routed URL the source redirects the workspace to,
	// as a git proxy would.
	repo string
	err  error

	mu        sync.Mutex
	calls     int
	released  int
	projectID string
}

func (f *fakeSource) ForWorkspace(_ context.Context, projectID string, _ executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	f.mu.Lock()
	f.calls++
	f.projectID = projectID
	f.mu.Unlock()
	release := func() {
		f.mu.Lock()
		f.released++
		f.mu.Unlock()
	}
	if f.err != nil {
		return executor.WorkspaceAccess{}, func() {}, f.err
	}
	return executor.WorkspaceAccess{Credential: f.cred, Repo: f.repo}, release, nil
}

func (f *fakeSource) counts() (calls, released int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.released
}

// newWorkspaceExecutor builds an executor with a credential source attached.
func newWorkspaceExecutor(t *testing.T, src executor.WorkspaceCredentialSource) *remote.Executor {
	t.Helper()
	ex, err := remote.NewExecutor(remote.Options{ID: "agent-1", Name: "edge-1", Workspace: src})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	return ex
}

// captureStart answers the next start frame and hands the payload back.
func captureStart(t *testing.T, p *peer) chan remote.StartPayload {
	t.Helper()
	got := make(chan remote.StartPayload, 1)
	go func() {
		f := p.readUntil(remote.TypeStart)
		payload, err := remote.DecodeStart(f)
		if err != nil {
			t.Errorf("DecodeStart: %v", err)
			close(got)
			return
		}
		got <- payload
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID: f.Handle, PID: 321, StartedAt: time.Now(),
		})
		if err != nil {
			t.Errorf("build started: %v", err)
			return
		}
		p.write(reply)
	}()
	return got
}

// TestOldAgentIsRefusedGitWorkspace is the version rule.
//
// It is stricter than the revocation one for a reason worth stating: a v2 agent
// does not reject the credential field, it ignores it — answers the start,
// launches the harness in the empty directory it just made, and streams back a
// transcript that looks like a working run against no code. Refusing to
// dispatch is the only place that failure can be caught.
func TestOldAgentIsRefusedGitWorkspace(t *testing.T) {
	src := &fakeSource{cred: executor.GitCredential{Username: "x-access-token", Password: workspaceTestToken}}
	ex := newWorkspaceExecutor(t, src)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.MinWorkspaceVersion-1), nil)
	defer sess.Close()

	_, err := ex.Start(context.Background(), gitSpec("github-ci"))
	if !errors.Is(err, remote.ErrWorkspaceUnsupported) {
		t.Fatalf("Start error = %v, want ErrWorkspaceUnsupported", err)
	}
	// The diagnostic is what an operator reads, so it names the device, the
	// repository, the version, and the command that fixes it.
	for _, want := range []string{"edge-1", "acme/widget", "v2", "install --upgrade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q; got %q", want, err)
		}
	}
	// No lease may be taken for a workload that was never dispatched.
	if calls, _ := src.counts(); calls != 0 {
		t.Errorf("the credential source was consulted %d times for a refused start", calls)
	}
	// The same device still runs ordinary work: this is a workload rule, not a
	// connectivity rule.
	got := captureStart(t, p)
	if _, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(), Argv: []string{"sleep", "60"},
	}); err != nil {
		t.Fatalf("an older agent must still accept work with no workspace: %v", err)
	}
	<-got
}

// TestWorkspaceCapabilityFollowsProtocolVersion: a device that advertises it
// can clone is still not usable for a clone over a session that cannot deliver
// the credential, and placement must see that.
func TestWorkspaceCapabilityFollowsProtocolVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		want    bool
	}{
		{"current", remote.ProtocolVersion, true},
		{"too old", remote.MinWorkspaceVersion - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := newWorkspaceExecutor(t, nil)
			hello := helloAt(tc.version)
			hello.Capabilities.WorkspaceProvisioning = true
			_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, hello, nil)
			defer sess.Close()

			if got := ex.Capabilities().SupportsWorkspaceProvisioning; got != tc.want {
				t.Errorf("SupportsWorkspaceProvisioning = %v, want %v (session speaks v%d)",
					got, tc.want, sess.Version())
			}
			if got := ex.SupportsWorkspaceProvisioning(); got != tc.want {
				t.Errorf("Executor.SupportsWorkspaceProvisioning() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWorkspaceCredentialTravelsOutsideTheSpec is the central assertion of the
// hub's half.
//
// A Spec is persisted by pkg/executorstore, echoed into audit rows, and re-read
// after a control-plane restart. The credential must therefore be reachable by
// the agent and absent from the Spec, and the only way to be sure is to
// marshal the Spec exactly as the store would and look.
func TestWorkspaceCredentialTravelsOutsideTheSpec(t *testing.T) {
	src := &fakeSource{cred: executor.GitCredential{
		Username:   "x-access-token",
		Password:   workspaceTestToken,
		LeaseID:    "lease_1",
		GrantID:    "grant_1",
		SecretName: "github-ci",
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}}
	ex := newWorkspaceExecutor(t, src)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	got := captureStart(t, p)
	if _, err := ex.Start(context.Background(), gitSpec("github-ci")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	payload := <-got

	if payload.WorkspaceCredential == nil {
		t.Fatal("the start payload must carry the leased credential; the device cannot fetch without it")
	}
	if payload.WorkspaceCredential.Password != workspaceTestToken {
		t.Errorf("credential password = %q, want the leased token", payload.WorkspaceCredential.Password)
	}
	if payload.GitCredential().AuthorizationHeader() == "" {
		t.Error("the payload should convert into a usable executor.GitCredential")
	}

	// The Spec, marshalled the way the store persists it, must not contain the
	// token in any field, under any name.
	raw, err := json.Marshal(payload.Spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	if strings.Contains(string(raw), workspaceTestToken) {
		t.Fatalf("the credential leaked into the persisted Spec: %s", raw)
	}
	// The grant *name* is in the spec, which is the whole design: the spec says
	// which authority to use, never the material.
	if payload.Spec.Workspace.CredentialGrant != "github-ci" {
		t.Errorf("the spec should still name the grant, got %q", payload.Spec.Workspace.CredentialGrant)
	}

	// The lease is given back once the agent has the material: holding it open
	// would leave the broker believing a credential is still in flight.
	calls, released := src.counts()
	if calls != 1 {
		t.Errorf("the source was consulted %d times, want once per start", calls)
	}
	if released != 1 {
		t.Errorf("the lease was released %d times, want exactly once after the start was confirmed", released)
	}
	if src.projectID != "/srv/projects/demo" {
		t.Errorf("the lease was requested for project %q, want the spec's project label", src.projectID)
	}

	// And a %v on the credential — the shape a future log line would take —
	// prints nothing usable.
	if s := payload.WorkspaceCredential.String(); strings.Contains(s, workspaceTestToken) {
		t.Errorf("WorkspaceCredential.String() leaks the token: %s", s)
	}
}

// TestWorkspaceLeaseIsReleasedWhenTheStartFails: a lease held for a workload
// that never ran is a credential the broker believes is out in the world.
func TestWorkspaceLeaseIsReleasedWhenTheStartFails(t *testing.T) {
	src := &fakeSource{cred: executor.GitCredential{Username: "x-access-token", Password: workspaceTestToken}}
	ex := newWorkspaceExecutor(t, src)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	// The device refuses: no git, a size limit, a mismatched remote — the hub
	// sees only the reason.
	go func() {
		f := p.readUntil(remote.TypeStart)
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID: f.Handle,
			Error:    "executor: workspace could not be provisioned: this device (edge-1) has no git on its PATH",
		})
		if err != nil {
			return
		}
		p.write(reply)
	}()

	_, err := ex.Start(context.Background(), gitSpec("github-ci"))
	if err == nil {
		t.Fatal("a device that could not provision must fail the start")
	}
	// The device's reason is surfaced verbatim, alongside the workspace, so the
	// operator is not left looking at the harness.
	if !strings.Contains(err.Error(), "no git on its PATH") {
		t.Errorf("the device's reason should be surfaced; got %v", err)
	}
	if !strings.Contains(err.Error(), "acme/widget") {
		t.Errorf("the refusal should name the workspace; got %v", err)
	}
	if _, released := src.counts(); released != 1 {
		t.Errorf("the lease was released %d times, want once even though the start failed", released)
	}
}

// TestWorkspaceGrantErrorPropagatesUnchanged: the typed error names the grant,
// the repository and the command that creates it. Callers match it with
// errors.As several layers up, and wrapping it would bury the remediation.
func TestWorkspaceGrantErrorPropagatesUnchanged(t *testing.T) {
	want := &executor.WorkspaceGrantError{
		Repo:        "https://github.com/acme/widget.git",
		RepoPath:    "acme/widget",
		Grant:       "github-ci",
		ExecutorID:  "agent-1",
		ProjectPath: "/srv/projects/demo",
		Reason:      "grant github-ci does not include repository acme/widget in its allowlist",
	}
	ex := newWorkspaceExecutor(t, &fakeSource{err: want})
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	_, err := ex.Start(context.Background(), gitSpec("github-ci"))
	if err == nil {
		t.Fatal("a workspace with no usable grant must not start")
	}
	var grantErr *executor.WorkspaceGrantError
	if !errors.As(err, &grantErr) {
		t.Fatalf("errors.As must still find the *WorkspaceGrantError; got %#v", err)
	}
	if grantErr != want {
		t.Errorf("the error should propagate unchanged, got a copy or a rebuild: %#v", grantErr)
	}
	if !errors.Is(err, executor.ErrWorkspaceGrantMissing) {
		t.Errorf("the sentinel should still match; got %v", err)
	}
	if !strings.Contains(err.Error(), "cloop secret grant") {
		t.Errorf("the remediation should survive; got %v", err)
	}
}

// TestWorkspaceWithoutABrokerIsRefused: a hub with no credential source must
// not dispatch a private-repository fetch and hope it is public.
func TestWorkspaceWithoutABrokerIsRefused(t *testing.T) {
	ex := newWorkspaceExecutor(t, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	_, err := ex.Start(context.Background(), gitSpec("github-ci"))
	if !errors.Is(err, executor.ErrWorkspaceGrantMissing) {
		t.Fatalf("Start error = %v, want ErrWorkspaceGrantMissing", err)
	}
	if !strings.Contains(err.Error(), "no secret broker") {
		t.Errorf("the refusal should say what is missing; got %v", err)
	}
}

// TestPublicWorkspaceNeedsNoLease: an unauthenticated fetch is legitimate for a
// public repository, and minting a lease for one would put a token on the wire
// that the fetch will not present.
func TestPublicWorkspaceNeedsNoLease(t *testing.T) {
	src := &fakeSource{cred: executor.GitCredential{Username: "x-access-token", Password: workspaceTestToken}}
	ex := newWorkspaceExecutor(t, src)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	got := captureStart(t, p)
	if _, err := ex.Start(context.Background(), gitSpec("")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	payload := <-got

	if payload.WorkspaceCredential != nil {
		t.Error("a workspace naming no grant must not carry a credential")
	}
	if calls, _ := src.counts(); calls != 0 {
		t.Errorf("the source was consulted %d times for a public repository", calls)
	}
}

// TestWorkspaceProvisioningIsAudited: provisioning is the moment a brokered
// credential is used against an external service, and the run's own record
// cannot answer "which grant fetched what onto which device" — the run looks
// identical whether the tree arrived or not.
func TestWorkspaceProvisioningIsAudited(t *testing.T) {
	var (
		mu     sync.Mutex
		events []executor.WorkspaceEvent
	)
	executor.SetWorkspaceAuditor(func(ev executor.WorkspaceEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	t.Cleanup(func() { executor.SetWorkspaceAuditor(nil) })

	src := &fakeSource{cred: executor.GitCredential{
		Username: "x-access-token", Password: workspaceTestToken,
		LeaseID: "lease_1", GrantID: "grant_1",
	}}
	ex := newWorkspaceExecutor(t, src)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	got := captureStart(t, p)
	if _, err := ex.Start(context.Background(), gitSpec("github-ci")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-got

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("got %d workspace audit events, want a start and an end: %+v", len(events), events)
	}
	if events[0].Phase != executor.WorkspaceProvisionStart || events[1].Phase != executor.WorkspaceProvisionEnd {
		t.Errorf("phases = %q/%q, want start then end", events[0].Phase, events[1].Phase)
	}
	for i, ev := range events {
		if ev.ExecutorKind != executor.KindRemoteAgent {
			t.Errorf("event %d kind = %q, want %q", i, ev.ExecutorKind, executor.KindRemoteAgent)
		}
		if ev.ExecutorID != "agent-1" || ev.HandleID == "" {
			t.Errorf("event %d should identify the executor and the handle: %+v", i, ev)
		}
		if ev.GrantID != "grant_1" || ev.LeaseID != "lease_1" {
			t.Errorf("event %d should carry the lease identifiers: %+v", i, ev)
		}
		if ev.ProjectPath != "/srv/projects/demo" {
			t.Errorf("event %d project = %q, want the spec's project label", i, ev.ProjectPath)
		}
		// The audit trail is durable, so it must never carry material.
		if strings.Contains(ev.Err, workspaceTestToken) {
			t.Errorf("event %d leaks the credential: %+v", i, ev)
		}
	}
	if events[1].Err != "" {
		t.Errorf("a successful dispatch should record no error, got %q", events[1].Err)
	}
}

// TestNonGitWorkspaceIsNotAudited keeps the trail meaningful: rows for
// workloads that provisioned nothing would drown the ones that did.
func TestNonGitWorkspaceIsNotAudited(t *testing.T) {
	var (
		mu     sync.Mutex
		events int
	)
	executor.SetWorkspaceAuditor(func(executor.WorkspaceEvent) {
		mu.Lock()
		events++
		mu.Unlock()
	})
	t.Cleanup(func() { executor.SetWorkspaceAuditor(nil) })

	ex := newWorkspaceExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()

	got := captureStart(t, p)
	if _, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(), Argv: []string{"sleep", "60"},
	}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-got

	mu.Lock()
	defer mu.Unlock()
	if events != 0 {
		t.Errorf("a workload with no workspace produced %d provisioning audit rows", events)
	}
}

// TestFrameStringOmitsPayload guards the property that makes a start frame safe
// to mention in a log line at all.
func TestFrameStringOmitsPayload(t *testing.T) {
	frame, err := remote.NewFrame(remote.TypeStart, "req-1", "h1", remote.StartPayload{
		Spec:                executor.Spec{WorkDir: "p", Argv: []string{"true"}},
		HandleID:            "h1",
		WorkspaceCredential: &remote.WorkspaceCredential{Password: workspaceTestToken},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	rendered := frame.String()
	if strings.Contains(rendered, workspaceTestToken) {
		t.Fatalf("Frame.String() prints the payload, credential and all: %s", rendered)
	}
	for _, want := range []string{"start", "req-1", "h1"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("Frame.String() should still identify the frame (%q); got %s", want, rendered)
		}
	}
}

// TestProtocolVersionsStayCompatible is the fleet-compatibility guard, extended
// to the workspace version: bumping the protocol must not strand deployed
// devices, and the two capability floors must stay inside the supported range.
func TestProtocolVersionsStayCompatible(t *testing.T) {
	if remote.MinProtocolVersion != 1 {
		t.Fatalf("MinProtocolVersion = %d; raising it strands every deployed v1 device",
			remote.MinProtocolVersion)
	}
	if remote.ProtocolVersion < remote.MinWorkspaceVersion {
		t.Fatalf("ProtocolVersion (%d) must be at least MinWorkspaceVersion (%d)",
			remote.ProtocolVersion, remote.MinWorkspaceVersion)
	}
	if remote.MinWorkspaceVersion <= remote.MinRevocationVersion {
		t.Fatalf("MinWorkspaceVersion (%d) should be newer than MinRevocationVersion (%d)",
			remote.MinWorkspaceVersion, remote.MinRevocationVersion)
	}
	for v := remote.MinProtocolVersion; v <= remote.ProtocolVersion; v++ {
		if remote.SupportsWorkspaceProvisioning(v) != (v >= remote.MinWorkspaceVersion) {
			t.Errorf("SupportsWorkspaceProvisioning(%d) disagrees with MinWorkspaceVersion", v)
		}
	}
}
