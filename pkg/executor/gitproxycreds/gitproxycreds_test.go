package gitproxycreds

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// forgePAT stands in for the credential the hub holds and the sandbox must
// never see. Every test that mints a session asserts this string is absent from
// what comes back.
const forgePAT = "ghp_a_real_looking_forge_token_0123456789"

const proxyBase = "https://hub.internal:8443"

// fakeInner is the credential source the decorator wraps. It records what it
// was asked for and how often its release was called, so a test can assert both
// the pass-through and the fail-closed paths.
type fakeInner struct {
	access executor.WorkspaceAccess
	err    error
	// nilRelease makes the fake return a nil release func, which the decorator
	// must substitute for a no-op rather than hand back to a caller's defer.
	nilRelease bool

	calls     int
	releases  int
	lastProj  string
	lastSpace executor.Workspace
}

func (f *fakeInner) ForWorkspace(_ context.Context, projectID string, w executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	f.calls++
	f.lastProj = projectID
	f.lastSpace = w
	if f.nilRelease {
		return f.access, nil, f.err
	}
	return f.access, func() { f.releases++ }, f.err
}

var _ executor.WorkspaceCredentialSource = (*fakeInner)(nil)

// patAccess is the access an undecorated source returns for a private repo.
func patAccess() executor.WorkspaceAccess {
	return executor.WorkspaceAccess{
		Credential: executor.GitCredential{
			Username:   "x-access-token",
			Password:   forgePAT,
			LeaseID:    "lease-77",
			GrantID:    "grant-42",
			SecretName: "github-pat",
			ExpiresAt:  time.Date(2026, 8, 23, 18, 0, 0, 0, time.UTC),
		},
	}
}

// gitWorkspace is the workspace under test: a private repo on a forge.
func gitWorkspace() executor.Workspace {
	return executor.Workspace{
		Kind:            executor.WorkspaceGit,
		Repo:            "https://github.com/acme/tool.git",
		Ref:             "main",
		CredentialGrant: "github-pat",
	}
}

func newRegistry(t *testing.T, now time.Time) *gitproxy.Registry {
	t.Helper()
	reg, err := gitproxy.NewRegistry(proxyBase)
	if err != nil {
		t.Fatalf("NewRegistry(%q) = %v", proxyBase, err)
	}
	if !now.IsZero() {
		reg.Now = func() time.Time { return now }
	}
	return reg
}

// newSource builds the decorator under test with the default policy and TTL.
func newSource(t *testing.T, inner executor.WorkspaceCredentialSource, reg *gitproxy.Registry, ttl time.Duration) *Source {
	t.Helper()
	s, err := New(inner, reg, gitproxy.Policy{}, ttl, "exec-1", "alice")
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	return s
}

// --- the credential the sandbox gets ----------------------------------------

func TestForWorkspaceKeepsTheForgePATOnTheHub(t *testing.T) {
	inner := &fakeInner{access: patAccess()}
	reg := newRegistry(t, time.Time{})
	src := newSource(t, inner, reg, 0)

	access, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	if err != nil {
		t.Fatalf("ForWorkspace = %v", err)
	}
	if release == nil {
		t.Fatal("ForWorkspace returned a nil release")
	}
	defer release()

	// The whole point: what reaches the sandbox is not the forge credential.
	if access.Credential.Password == forgePAT {
		t.Fatal("ForWorkspace handed the sandbox the forge PAT")
	}
	if access.Credential.Empty() {
		t.Fatal("ForWorkspace returned an empty credential for a private repo")
	}

	sessions := reg.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("registry holds %d sessions, want 1", len(sessions))
	}
	sess := sessions[0]

	// The password is the session token, which is only meaningful against this
	// proxy: Authenticate is the one thing it can do.
	if access.Credential.Username != sess.ID {
		t.Fatalf("credential username = %q, want the session ID %q", access.Credential.Username, sess.ID)
	}
	got, err := reg.Authenticate(access.Credential.Username, access.Credential.Password)
	if err != nil {
		t.Fatalf("the delivered credential does not authenticate against the registry: %v", err)
	}
	if got != sess {
		t.Fatalf("the credential authenticated as session %q, want %q", got.ID, sess.ID)
	}

	// And nothing else in the returned value carries the PAT either.
	assertNoPAT(t, access)
}

func TestForWorkspaceRedirectsTheRepoAtTheProxy(t *testing.T) {
	inner := &fakeInner{access: patAccess()}
	reg := newRegistry(t, time.Time{})
	src := newSource(t, inner, reg, 0)

	w := gitWorkspace()
	access, release, err := src.ForWorkspace(context.Background(), "proj-1", w)
	if err != nil {
		t.Fatalf("ForWorkspace = %v", err)
	}
	defer release()

	if want := proxyBase + "/acme/tool"; access.Repo != want {
		t.Fatalf("access.Repo = %q, want %q", access.Repo, want)
	}
	if strings.Contains(access.Repo, "github.com") {
		t.Fatalf("access.Repo = %q still points at the forge", access.Repo)
	}

	routed := access.Apply(w)
	if routed.Repo != access.Repo {
		t.Fatalf("Apply left Repo = %q, want %q", routed.Repo, access.Repo)
	}
	// Everything else about the workspace survives the swap.
	if routed.Ref != w.Ref || routed.Kind != w.Kind || routed.CredentialGrant != w.CredentialGrant {
		t.Fatalf("Apply changed more than the repo: %+v, want %+v except Repo", routed, w)
	}
	// The inner source still saw the real forge URL — the redirection happens
	// after the grant has been matched, not before.
	if inner.lastSpace.Repo != w.Repo {
		t.Fatalf("inner source saw repo %q, want the forge URL %q", inner.lastSpace.Repo, w.Repo)
	}
	if inner.lastProj != "proj-1" {
		t.Fatalf("inner source saw project %q, want proj-1", inner.lastProj)
	}
}

func TestWorkspaceAccessApplyWithNoRepoLeavesTheWorkspaceAlone(t *testing.T) {
	// The undecorated path returns an empty Repo, meaning "no redirection".
	w := gitWorkspace()
	got := executor.WorkspaceAccess{Credential: patAccess().Credential}.Apply(w)
	if got != w {
		t.Fatalf("Apply with an empty Repo changed the workspace: %+v, want %+v", got, w)
	}
	if got := (executor.WorkspaceAccess{Repo: "   "}).Apply(w); got != w {
		t.Fatalf("Apply with a whitespace Repo changed the workspace: %+v", got)
	}
}

func TestProxyRepoURLPreservesTheOwnerNamePath(t *testing.T) {
	// Workspace.RepoPath is what matches a GitHub grant's repository
	// allowlist. A proxy URL that did not preserve owner/name would break grant
	// matching for every workspace routed through the proxy.
	inner := &fakeInner{access: patAccess()}
	reg := newRegistry(t, time.Time{})
	src := newSource(t, inner, reg, 0)

	for _, upstream := range []string{
		"https://github.com/acme/tool",
		"https://github.com/acme/tool.git",
	} {
		w := gitWorkspace()
		w.Repo = upstream

		access, release, err := src.ForWorkspace(context.Background(), "proj-1", w)
		if err != nil {
			t.Fatalf("ForWorkspace(%q) = %v", upstream, err)
		}
		release()

		routed := access.Apply(w)
		path, ok := routed.RepoPath()
		if !ok {
			t.Fatalf("the proxied repo %q has no owner/name shape", routed.Repo)
		}
		if path != "acme/tool" {
			t.Fatalf("RepoPath() through the proxy = %q, want acme/tool", path)
		}
		// The routed workspace must still validate, or the driver would refuse
		// to provision it.
		if err := routed.Validate(); err != nil {
			t.Fatalf("the proxied workspace does not validate: %v", err)
		}
	}
}

func TestCredentialExpiryIsTheSessionsNotTheLeases(t *testing.T) {
	// Before interception the sandbox held the PAT and its access ended never,
	// whatever the lease said. The session's expiry is the deadline that now
	// actually bounds it.
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	inner := &fakeInner{access: patAccess()} // lease expires at 18:00
	reg := newRegistry(t, now)
	src := newSource(t, inner, reg, 30*time.Minute)

	access, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	if err != nil {
		t.Fatalf("ForWorkspace = %v", err)
	}
	defer release()

	sess := reg.Sessions()[0]
	if !access.Credential.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("credential ExpiresAt = %s, want the session's %s",
			access.Credential.ExpiresAt, sess.ExpiresAt)
	}
	if want := now.Add(30 * time.Minute); !access.Credential.ExpiresAt.Equal(want) {
		t.Fatalf("credential ExpiresAt = %s, want %s", access.Credential.ExpiresAt, want)
	}
	if access.Credential.ExpiresAt.Equal(patAccess().Credential.ExpiresAt) {
		t.Fatal("credential ExpiresAt is the inner lease's deadline, not the session's")
	}
}

func TestForWorkspaceCarriesTheAuditIdentifiersThrough(t *testing.T) {
	// The grant, lease and secret names are not secret, and the proxy's own
	// events use the same values. Carrying them through unchanged is what lets
	// the provisioning trail and the proxy trail be joined.
	inner := &fakeInner{access: patAccess()}
	reg := newRegistry(t, time.Time{})
	var events []gitproxy.Event
	reg.OnEvent = func(e gitproxy.Event) { events = append(events, e) }
	src := newSource(t, inner, reg, 0)

	access, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	if err != nil {
		t.Fatalf("ForWorkspace = %v", err)
	}
	defer release()

	in := patAccess().Credential
	switch {
	case access.Credential.LeaseID != in.LeaseID:
		t.Fatalf("LeaseID = %q, want %q", access.Credential.LeaseID, in.LeaseID)
	case access.Credential.GrantID != in.GrantID:
		t.Fatalf("GrantID = %q, want %q", access.Credential.GrantID, in.GrantID)
	case access.Credential.SecretName != in.SecretName:
		t.Fatalf("SecretName = %q, want %q", access.Credential.SecretName, in.SecretName)
	}

	sess := reg.Sessions()[0]
	if sess.ProjectID != "proj-1" || sess.ExecutorID != "exec-1" || sess.Actor != "alice" {
		t.Fatalf("session audit labels = %+v, want project proj-1, executor exec-1, actor alice", sess)
	}
	// ForWorkspace is never told a task ID, so the field stays empty rather
	// than being filled with the nearest available string. Labelling every
	// proxy event "task=github-pat" would break the joins against run and task
	// records that Event.TaskID exists to support, which is worse than a blank
	// column an operator can see is blank.
	if sess.TaskID != "" {
		t.Fatalf("session TaskID = %q, want empty: the decorator has no task ID in "+
			"scope and must not substitute another identifier", sess.TaskID)
	}

	if len(events) != 1 || events[0].Kind != gitproxy.EventSessionMinted {
		t.Fatalf("events = %+v, want one session_minted", events)
	}
	if strings.Contains(events[0].String(), forgePAT) {
		t.Fatal("the mint event carries the forge PAT")
	}
	if events[0].RepoPath != "acme/tool" {
		t.Fatalf("mint event repo = %q, want acme/tool", events[0].RepoPath)
	}
}

// --- fail-closed -------------------------------------------------------------

func TestForWorkspaceFailsClosedWhenTheSessionCannotBeMinted(t *testing.T) {
	// Falling back to the direct credential would hand the sandbox the PAT
	// precisely when the boundary is broken, which is the one moment it must
	// not.
	inner := &fakeInner{access: patAccess()}
	reg := newRegistry(t, time.Time{})
	src := newSource(t, inner, reg, 0)

	w := gitWorkspace()
	w.Repo = "https://github.com/acme" // not owner/name, so UpstreamRepoPath refuses it

	access, release, err := src.ForWorkspace(context.Background(), "proj-1", w)
	if err == nil {
		t.Fatalf("ForWorkspace succeeded with an unmintable upstream: %+v", access)
	}
	if access != (executor.WorkspaceAccess{}) {
		t.Fatalf("ForWorkspace returned %+v alongside an error, want the zero access", access)
	}
	assertNoPAT(t, access)
	if strings.Contains(err.Error(), forgePAT) {
		t.Fatal("the mint failure message quotes the forge PAT")
	}
	if !strings.Contains(err.Error(), w.Repo) {
		t.Fatalf("error = %q, want it to name the repository it could not mint for", err)
	}
	if len(reg.Sessions()) != 0 {
		t.Fatalf("a failed mint left %d sessions in the registry", len(reg.Sessions()))
	}

	// The inner lease is given back on the way out, exactly once, and the
	// release handed to the caller is safe to defer.
	if inner.releases != 1 {
		t.Fatalf("inner release called %d times on the mint-failure path, want 1", inner.releases)
	}
	if release == nil {
		t.Fatal("ForWorkspace returned a nil release on the mint-failure path")
	}
	release()
	if inner.releases != 1 {
		t.Fatalf("the returned release re-released the inner lease; count = %d", inner.releases)
	}
}

func TestForWorkspaceFailsClosedOnAnUnmintablePolicyOrTTL(t *testing.T) {
	// Same fail-closed shape, reached through the registry rather than the URL:
	// a TTL past the maximum is refused by Mint, and there is no path from
	// there that hands over the PAT.
	inner := &fakeInner{access: patAccess()}
	reg := newRegistry(t, time.Time{})
	src := newSource(t, inner, reg, gitproxy.MaxSessionTTL)
	// Push the source past what Mint will accept without going through New,
	// which would have refused it.
	src.TTL = gitproxy.MaxSessionTTL + time.Hour

	access, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	if err == nil {
		t.Fatalf("ForWorkspace succeeded with an over-long TTL: %+v", access)
	}
	if access != (executor.WorkspaceAccess{}) {
		t.Fatalf("ForWorkspace returned %+v alongside an error", access)
	}
	assertNoPAT(t, access)
	if release == nil {
		t.Fatal("ForWorkspace returned a nil release")
	}
	release()
	if inner.releases != 1 {
		t.Fatalf("inner release called %d times, want 1", inner.releases)
	}
}

func TestForWorkspaceReturnsAnUnconfiguredSourceAsAnError(t *testing.T) {
	cases := map[string]*Source{
		"nil source":   nil,
		"nil inner":    {Registry: newRegistry(t, time.Time{})},
		"nil registry": {Inner: &fakeInner{}},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			access, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
			if err == nil {
				t.Fatal("ForWorkspace succeeded on an unconfigured source")
			}
			if access != (executor.WorkspaceAccess{}) {
				t.Fatalf("ForWorkspace returned %+v alongside an error", access)
			}
			if release == nil {
				t.Fatal("ForWorkspace returned a nil release")
			}
			release() // must be safe to defer unconditionally
		})
	}
}

// --- pass-through ------------------------------------------------------------

func TestInnerErrorIsReturnedUnchanged(t *testing.T) {
	// A *executor.WorkspaceGrantError must still reach the UI with its
	// remediation intact: wrapping it here would bury the fix behind a prefix
	// about a proxy the operator has no reason to think about.
	grantErr := &executor.WorkspaceGrantError{
		Repo:        "https://github.com/acme/tool",
		RepoPath:    "acme/tool",
		Grant:       "github-pat",
		ExecutorID:  "exec-1",
		ProjectPath: "/srv/proj",
		Reason:      "grant github-pat does not list acme/tool",
	}
	inner := &fakeInner{err: grantErr}
	reg := newRegistry(t, time.Time{})
	src := newSource(t, inner, reg, 0)

	access, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	if err == nil {
		t.Fatal("ForWorkspace swallowed the inner error")
	}
	if err != error(grantErr) {
		t.Fatalf("ForWorkspace wrapped the inner error: %v", err)
	}
	var got *executor.WorkspaceGrantError
	if !errors.As(err, &got) {
		t.Fatalf("errors.As no longer finds a *WorkspaceGrantError in %v", err)
	}
	if got.Remediation() == "" {
		t.Fatal("the remediation was lost")
	}
	if !errors.Is(err, executor.ErrWorkspaceGrantMissing) {
		t.Fatalf("errors.Is(err, ErrWorkspaceGrantMissing) = false for %v", err)
	}
	if access != (executor.WorkspaceAccess{}) {
		t.Fatalf("ForWorkspace returned %+v alongside an error", access)
	}
	if len(reg.Sessions()) != 0 {
		t.Fatalf("a failed inner lease minted %d sessions", len(reg.Sessions()))
	}
	if release == nil {
		t.Fatal("ForWorkspace returned a nil release on the inner-error path")
	}
	release()
	if inner.releases != 1 {
		t.Fatalf("the inner release was called %d times, want 1", inner.releases)
	}
}

func TestNilInnerReleaseIsSubstituted(t *testing.T) {
	// Callers defer the release unconditionally, so a nil one from an inner
	// source must not become a nil-pointer panic in a driver's defer.
	for _, tc := range []struct {
		name  string
		inner *fakeInner
	}{
		{"on the error path", &fakeInner{nilRelease: true, err: errors.New("boom")}},
		{"on the success path", &fakeInner{nilRelease: true, access: patAccess()}},
		{"on the public-repo path", &fakeInner{nilRelease: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := newSource(t, tc.inner, newRegistry(t, time.Time{}), 0)
			_, release, _ := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
			if release == nil {
				t.Fatal("ForWorkspace returned a nil release")
			}
			release()
		})
	}
}

func TestPublicRepoIsPassedThroughWithoutASession(t *testing.T) {
	// There is no credential to keep off the sandbox, so there is nothing for
	// the proxy to protect and a session would only add a hop that can fail.
	inner := &fakeInner{} // zero access: no credential, no repo override
	reg := newRegistry(t, time.Time{})
	var events []gitproxy.Event
	reg.OnEvent = func(e gitproxy.Event) { events = append(events, e) }
	src := newSource(t, inner, reg, 0)

	w := gitWorkspace()
	w.CredentialGrant = ""
	access, release, err := src.ForWorkspace(context.Background(), "proj-1", w)
	if err != nil {
		t.Fatalf("ForWorkspace = %v", err)
	}
	if access != (executor.WorkspaceAccess{}) {
		t.Fatalf("ForWorkspace = %+v, want the inner access untouched", access)
	}
	if access.Repo != "" {
		t.Fatalf("a public repo was redirected to %q", access.Repo)
	}
	if got := access.Apply(w); got != w {
		t.Fatalf("Apply changed the workspace: %+v, want %+v", got, w)
	}
	if len(reg.Sessions()) != 0 {
		t.Fatalf("a public repo minted %d sessions", len(reg.Sessions()))
	}
	if len(events) != 0 {
		t.Fatalf("a public repo emitted %+v", events)
	}

	if release == nil {
		t.Fatal("ForWorkspace returned a nil release")
	}
	release()
	if inner.releases != 1 {
		t.Fatalf("the inner release was called %d times, want 1", inner.releases)
	}
}

// --- New ---------------------------------------------------------------------

func TestNewDefaultsThePolicyToWriteBackPlusFetch(t *testing.T) {
	// With a proxy interposed the clone also goes through it, which is what
	// keeps the forge credential off the sandbox for both halves of the trip.
	src, err := New(&fakeInner{}, newRegistry(t, time.Time{}), gitproxy.Policy{}, 0, "exec-1", "alice")
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	p := src.Policy
	switch {
	case !p.AllowCreate, !p.AllowUpdate, !p.AllowFetch:
		t.Fatalf("default policy = %+v, want create, update and fetch", p)
	case p.AllowDelete:
		t.Fatalf("default policy permits deletes: %+v", p)
	}
	if want := []string{"refs/heads/cloop/**"}; len(p.AllowedRefs) != 1 || p.AllowedRefs[0] != want[0] {
		t.Fatalf("default AllowedRefs = %q, want %q", p.AllowedRefs, want)
	}
	// Normalized at construction, so every mint gets the same bounds.
	if p.MaxCommands != gitproxy.DefaultMaxCommands || p.MaxPackBytes != gitproxy.DefaultMaxPackBytes {
		t.Fatalf("default bounds = (%d,%d), want (%d,%d)",
			p.MaxCommands, p.MaxPackBytes, gitproxy.DefaultMaxCommands, gitproxy.DefaultMaxPackBytes)
	}
	if src.Actor != "alice" || src.ExecutorID != "exec-1" {
		t.Fatalf("New = %+v, want actor alice and executor exec-1", src)
	}
}

func TestNewDefaultsTheActor(t *testing.T) {
	src, err := New(&fakeInner{}, newRegistry(t, time.Time{}), gitproxy.Policy{}, 0, "  exec-1  ", "   ")
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if src.Actor != "system" {
		t.Fatalf("Actor = %q, want system", src.Actor)
	}
	if src.ExecutorID != "exec-1" {
		t.Fatalf("ExecutorID = %q, want the trimmed exec-1", src.ExecutorID)
	}
}

func TestNewHonoursAnExplicitPolicy(t *testing.T) {
	src, err := New(&fakeInner{}, newRegistry(t, time.Time{}),
		gitproxy.Policy{AllowedRefs: []string{"cloop/*"}, AllowCreate: true}, 0, "exec-1", "alice")
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if want := "refs/heads/cloop/*"; len(src.Policy.AllowedRefs) != 1 || src.Policy.AllowedRefs[0] != want {
		t.Fatalf("AllowedRefs = %q, want [%q]", src.Policy.AllowedRefs, want)
	}
	if src.Policy.AllowFetch || src.Policy.AllowUpdate || src.Policy.AllowDelete {
		t.Fatalf("New widened an explicit create-only policy: %+v", src.Policy)
	}
}

func TestNewRejectsAnUnusableConfiguration(t *testing.T) {
	reg := newRegistry(t, time.Time{})
	tests := []struct {
		name    string
		inner   executor.WorkspaceCredentialSource
		reg     *gitproxy.Registry
		policy  gitproxy.Policy
		ttl     time.Duration
		wantMsg string
	}{
		{"nil inner", nil, reg, gitproxy.Policy{}, 0, "nil inner credential source"},
		{"nil registry", &fakeInner{}, nil, gitproxy.Policy{}, 0, "nil session registry"},
		{"negative ttl", &fakeInner{}, reg, gitproxy.Policy{}, -time.Second, "negative session ttl"},
		{"ttl above the maximum", &fakeInner{}, reg, gitproxy.Policy{}, gitproxy.MaxSessionTTL + time.Second, "exceeds the maximum"},
		{"policy that permits nothing", &fakeInner{}, reg,
			gitproxy.Policy{AllowedRefs: []string{"refs/heads/cloop/**"}}, 0, "permits nothing"},
		{"malformed ref pattern", &fakeInner{}, reg,
			gitproxy.Policy{AllowedRefs: []string{"refs/heads/../../x"}, AllowCreate: true}, 0, "ref pattern"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src, err := New(tc.inner, tc.reg, tc.policy, tc.ttl, "exec-1", "alice")
			if err == nil {
				t.Fatalf("New succeeded, returning %+v", src)
			}
			if src != nil {
				t.Fatalf("New returned a source alongside an error: %+v", src)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("New = %q, want it to mention %q", err, tc.wantMsg)
			}
		})
	}

	t.Run("exactly the maximum ttl is accepted", func(t *testing.T) {
		if _, err := New(&fakeInner{}, reg, gitproxy.Policy{}, gitproxy.MaxSessionTTL, "exec-1", "alice"); err != nil {
			t.Fatalf("New with the maximum TTL = %v", err)
		}
	})
}

// --- helpers -----------------------------------------------------------------

// assertNoPAT fails if the forge credential appears anywhere in what the
// decorator hands back.
func assertNoPAT(t *testing.T, access executor.WorkspaceAccess) {
	t.Helper()
	fields := map[string]string{
		"Repo":       access.Repo,
		"Username":   access.Credential.Username,
		"Password":   access.Credential.Password,
		"LeaseID":    access.Credential.LeaseID,
		"GrantID":    access.Credential.GrantID,
		"SecretName": access.Credential.SecretName,
		"header":     access.Credential.AuthorizationHeader(),
	}
	for name, v := range fields {
		if strings.Contains(v, forgePAT) {
			t.Fatalf("the forge PAT reached the sandbox through %s = %q", name, v)
		}
	}
	for _, s := range access.Credential.Secrets() {
		if strings.Contains(s, forgePAT) {
			t.Fatalf("the forge PAT reached the sandbox through Secrets() = %q", s)
		}
	}
}
