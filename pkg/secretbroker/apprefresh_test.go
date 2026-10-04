package secretbroker

// Tests for keeping a GitHub App installation token alive past GitHub's hour
// (Task 20375).
//
// GitHub's hour cannot be waited out in a test, and appTokenMinLifetime rules
// out minting tokens that expire in seconds — a fresh token shorter than five
// minutes is refused outright. So these drive time instead: the fake GitHub
// mints tokens that expire an hour after *its* clock, the broker judges
// freshness and the refresh window against the same clock, and the tests move
// that clock past the first token's expiry.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// refreshFixture is a broker with one github_app secret granted to a project,
// and the levers a refresh test pulls.
type refreshFixture struct {
	b       *Broker
	store   *memStore
	auditor *recordingAuditor
	clock   *fakeClock
	gh      *fakeGitHub
	secret  Secret
	grant   Grant
}

func newRefreshFixture(t *testing.T, repos []string, perms []string, inventory ...InstallationRepo) *refreshFixture {
	t.Helper()
	b, store, auditor, clock := newTestBroker(t)
	gh := newFakeGitHub(inventory...)
	gh.clock = clock.Now
	b.appMinter = newGitHubAppMinter(gh, clock.Now)
	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "app", Kind: KindGitHubApp, Payload: appPayloadJSON(t), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	g, err := b.Grant(context.Background(), GrantRequest{
		SecretRef:   sec.ID,
		Subject:     Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: Constraints{Repos: repos, Permissions: perms},
		TTL:         24 * time.Hour,
		Actor:       "test",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return &refreshFixture{b: b, store: store, auditor: auditor, clock: clock, gh: gh, secret: sec, grant: g}
}

func (f *refreshFixture) lease(t *testing.T) *Lease {
	t.Helper()
	lease, err := f.b.LeaseFor(context.Background(), Requester{
		ExecutorID: "exec-1", ProjectID: "/srv/app", RunID: "run_refresh",
	}, "ui")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("lease carries %d materials, want the App grant", len(lease.Materials))
	}
	return lease
}

// scopedCreates returns the mint requests that delivered a token, leaving out
// the metadata:read discovery tokens the inventory lookup mints.
func (f *refreshFixture) scopedCreates() []InstallationTokenRequest {
	f.gh.mu.Lock()
	defer f.gh.mu.Unlock()
	var out []InstallationTokenRequest
	for _, c := range f.gh.creates {
		if len(c.Permissions) == 1 && c.Permissions["metadata"] == "read" {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (f *refreshFixture) renewRows(decision Decision) []Event {
	var out []Event
	for _, ev := range f.auditor.byAction(ActionRenew) {
		if ev.Decision == decision {
			out = append(out, ev)
		}
	}
	return out
}

func (f *refreshFixture) isLive(token string) bool {
	f.gh.mu.Lock()
	defer f.gh.mu.Unlock()
	return f.gh.live[token]
}

// TestRefreshReMintsAtTheOriginalScope is the core of the task: a token
// re-minted before its hour ends, asking GitHub for exactly what the first mint
// asked for — even after the installation gained a repository the grant's glob
// would now match — and the superseded token destroyed once the new one has
// reached the workload and its grace has passed.
func TestRefreshReMintsAtTheOriginalScope(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/*"}, []string{"contents:write"},
		InstallationRepo{ID: 1, FullName: "org/tool"},
		InstallationRepo{ID: 2, FullName: "org/service"},
		InstallationRepo{ID: 3, FullName: "other/private"},
	)
	ctx := context.Background()
	lease := f.lease(t)
	first := tokenFrom(t, lease)
	firstReq := f.gh.deliveredCreate(t)

	if f.b.AppTokensDue(lease.ID) {
		t.Fatal("a fresh token is reported due for a refresh")
	}
	if fr, err := f.b.RefreshLeaseFiles(ctx, lease); err != nil || fr != nil {
		t.Fatalf("RefreshLeaseFiles on a fresh token = %v, %v; want nothing to do", fr, err)
	}

	// The installation gains a repository the grant's glob matches. A refresh
	// that re-resolved the allowlist would widen the token to it.
	f.gh.mu.Lock()
	f.gh.repos = append(f.gh.repos, InstallationRepo{ID: 4, FullName: "org/new"})
	f.gh.mu.Unlock()

	f.clock.advance(51 * time.Minute)
	if !f.b.AppTokensDue(lease.ID) {
		t.Fatal("a token nine minutes from expiry is not reported due")
	}
	fr, err := f.b.RefreshLeaseFiles(ctx, lease)
	if err != nil {
		t.Fatalf("RefreshLeaseFiles: %v", err)
	}
	if fr == nil || len(fr.Files) != 1 {
		t.Fatalf("refresh = %+v; want one token file", fr)
	}
	defer fr.Close()
	file := fr.Files[0]
	if file.Name != tokenFileName || file.GrantID != f.grant.ID || file.Mode != 0o600 {
		t.Errorf("refreshed file = %s grant %s mode %v; want %s for %s at 0600",
			file.Name, file.GrantID, file.Mode, tokenFileName, f.grant.ID)
	}
	second := strings.TrimSpace(string(file.Content))
	if second == "" || second == first {
		t.Fatalf("refresh delivered %q, want a new token", second)
	}

	creates := f.scopedCreates()
	last := creates[len(creates)-1]
	if !reflect.DeepEqual(last.RepositoryIDs, firstReq.RepositoryIDs) {
		t.Errorf("refresh asked for repositories %v, the first mint for %v — a refresh must replay the scope, "+
			"not re-resolve the glob", last.RepositoryIDs, firstReq.RepositoryIDs)
	}
	if !reflect.DeepEqual(last.Permissions, firstReq.Permissions) {
		t.Errorf("refresh asked for permissions %v, the first mint for %v", last.Permissions, firstReq.Permissions)
	}
	if last.InstallationID != firstReq.InstallationID {
		t.Errorf("refresh minted for installation %d, the first for %d", last.InstallationID, firstReq.InstallationID)
	}

	rows := f.renewRows(DecisionAllow)
	if len(rows) != 1 {
		t.Fatalf("got %d allowed secret.renew rows, want one for the refresh: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.LeaseID != lease.ID || row.GrantID != f.grant.ID || row.SecretID != f.secret.ID ||
		row.Kind != KindGitHubApp || row.RunID != "run_refresh" || row.ExpiresAt.IsZero() {
		t.Errorf("renew row = %+v; it should name the lease, grant, secret, run and the new expiry", row)
	}
	if !strings.Contains(row.Reason, "original scope") {
		t.Errorf("renew row reason %q does not say the token kept its scope", row.Reason)
	}
	for _, ev := range f.auditor.all() {
		if strings.Contains(ev.Reason, first) || strings.Contains(ev.Reason, second) {
			t.Fatalf("an audit row carries a token: %+v", ev)
		}
	}

	// Not yet delivered: the workload still holds the first token, which
	// must stay alive however long delivery takes.
	f.clock.advance(5 * time.Minute)
	f.b.RetireSuperseded(ctx, lease.ID)
	if !f.isLive(first) {
		t.Fatal("the superseded token was destroyed before its replacement reached the workload")
	}
	if !f.b.AppTokensDue(lease.ID) {
		t.Error("an undelivered refresh is not reported due, so nothing would retry its delivery")
	}

	fr.Delivered(false)
	f.clock.advance(time.Minute)
	f.b.RetireSuperseded(ctx, lease.ID)
	if !f.isLive(first) {
		t.Fatal("the superseded token was destroyed inside its grace period")
	}
	f.clock.advance(appTokenRetireGrace)
	f.b.RetireSuperseded(ctx, lease.ID)
	if f.isLive(first) {
		t.Fatal("the superseded token outlived its grace period")
	}
	if !f.isLive(second) {
		t.Fatal("retiring the old token destroyed the new one")
	}

	f.b.Release(lease.ID)
	if f.isLive(second) {
		t.Fatal("releasing the lease left the refreshed token alive at GitHub")
	}
}

// TestRefreshAfterTheHourStillMints: the mint is signed by the App's key, not
// by the expired token, so a run that touched no git for over an hour still
// gets one.
func TestRefreshAfterTheHourStillMints(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	first := tokenFrom(t, lease)
	f.clock.advance(61 * time.Minute)
	fr, err := f.b.RefreshLeaseFiles(context.Background(), lease)
	if err != nil || fr == nil || len(fr.Files) != 1 {
		t.Fatalf("refresh after expiry = %+v, %v; want a new token file", fr, err)
	}
	defer fr.Close()
	if got := strings.TrimSpace(string(fr.Files[0].Content)); got == first || !f.isLive(got) {
		t.Fatalf("refresh after expiry delivered %q; want a new live token", got)
	}
}

// TestRefreshStopsOnARevokedGrant is the property the short lease exists for:
// a grant revoked since dispatch — here through the store, as another broker
// instance over the same database revokes it — is never renewed, and the token
// it stood behind is destroyed at GitHub then and there.
func TestRefreshStopsOnARevokedGrant(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	first := tokenFrom(t, lease)
	mintsBefore := len(f.scopedCreates())

	if err := f.store.RevokeGrant(f.grant.ID, f.clock.Now()); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	f.clock.advance(51 * time.Minute)

	_, err := f.b.RefreshAppToken(context.Background(), lease.ID, f.grant.ID, first)
	if !errors.Is(err, ErrRefreshRefused) || !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("refresh of a revoked grant = %v; want ErrRefreshRefused wrapping ErrGrantRevoked", err)
	}
	if n := len(f.scopedCreates()); n != mintsBefore {
		t.Errorf("a refresh of a revoked grant minted %d token(s)", n-mintsBefore)
	}
	if f.isLive(first) {
		t.Error("the revoked grant's token is still live at GitHub; a refused refresh must end access")
	}
	deny := f.renewRows(DecisionDeny)
	if len(deny) == 0 || !strings.Contains(deny[len(deny)-1].Reason, "revoked") {
		t.Errorf("no denied secret.renew row names the revocation: %+v", deny)
	}
	if f.b.AppTokensDue(lease.ID) || f.b.HoldsFileAppTokens(lease.ID) {
		t.Error("a slot whose refresh was refused is still refreshable")
	}
	fr, err := f.b.RefreshLeaseFiles(context.Background(), lease)
	if err != nil || fr != nil {
		t.Errorf("RefreshLeaseFiles after a refusal = %+v, %v; want nothing to do", fr, err)
	}
}

// TestRefreshThroughTheLeaseReportsARefusal: the keepalive's path names a
// refused grant, so the hub can journal it.
func TestRefreshThroughTheLeaseReportsARefusal(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	first := tokenFrom(t, lease)
	f.gh.mu.Lock()
	f.gh.createErr = fmt.Errorf("%w: %w: github returned 403 Forbidden: This installation has been suspended",
		ErrGitHubAppMint, ErrGitHubAppRefused)
	f.gh.mu.Unlock()
	f.clock.advance(52 * time.Minute)

	fr, err := f.b.RefreshLeaseFiles(context.Background(), lease)
	if err != nil {
		t.Fatalf("RefreshLeaseFiles: %v", err)
	}
	if fr == nil || len(fr.Refused) != 1 || len(fr.Files) != 0 {
		t.Fatalf("refresh = %+v; want the grant reported refused and no file", fr)
	}
	if fr.Refused[0].GrantID != f.grant.ID || !strings.Contains(fr.Refused[0].Reason, "suspended") {
		t.Errorf("refusal = %+v; want it to name the grant and GitHub's reason", fr.Refused[0])
	}
	if f.isLive(first) {
		t.Error("GitHub refused the refresh and the old token was left alive")
	}
}

// TestRefreshRetriesAFailureThatMayPass: GitHub unreachable is not a refusal.
// The token held keeps working, the slot stays refreshable, and the next
// attempt succeeds.
func TestRefreshRetriesAFailureThatMayPass(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	first := tokenFrom(t, lease)
	f.gh.mu.Lock()
	f.gh.createErr = wrapf(ErrGitHubAppMint, "create installation token: dial tcp: i/o timeout")
	f.gh.mu.Unlock()
	f.clock.advance(51 * time.Minute)

	fr, err := f.b.RefreshLeaseFiles(context.Background(), lease)
	if err != nil {
		t.Fatalf("RefreshLeaseFiles: %v", err)
	}
	if fr == nil || len(fr.Pending) != 1 || len(fr.Refused) != 0 || len(fr.Files) != 0 {
		t.Fatalf("refresh = %+v; want the grant pending, not refused", fr)
	}
	if !f.isLive(first) {
		t.Fatal("a refresh that may yet succeed destroyed the token the workload holds")
	}
	if len(f.renewRows(DecisionDeny)) == 0 {
		t.Error("the failed attempt left no denied secret.renew row")
	}

	f.gh.mu.Lock()
	f.gh.createErr = nil
	f.gh.mu.Unlock()
	f.clock.advance(time.Minute)
	fr, err = f.b.RefreshLeaseFiles(context.Background(), lease)
	if err != nil || fr == nil || len(fr.Files) != 1 {
		t.Fatalf("retry = %+v, %v; want a new token file", fr, err)
	}
	fr.Close()
}

// TestRefreshSurvivesABusyStore: a store that could not answer says nothing
// about the grant, so the token held keeps working and the next attempt
// succeeds.
func TestRefreshSurvivesABusyStore(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	first := tokenFrom(t, lease)
	f.clock.advance(51 * time.Minute)
	f.store.mu.Lock()
	f.store.getGrantErr = errors.New("database is locked (SQLITE_BUSY)")
	f.store.mu.Unlock()

	_, err := f.b.RefreshAppToken(context.Background(), lease.ID, f.grant.ID, first)
	if err == nil || errors.Is(err, ErrRefreshRefused) {
		t.Fatalf("refresh against a busy store = %v; want a retryable failure", err)
	}
	if !f.isLive(first) {
		t.Fatal("a busy database ended the run's GitHub access")
	}
	got, err := f.b.RefreshAppToken(context.Background(), lease.ID, f.grant.ID, first)
	if err != nil || got.Token == first {
		t.Fatalf("retry = %v, %v; want a new token", got, err)
	}
}

// TestRefreshNeverWiderThanTheFirstToken: should GitHub answer a refresh with
// more than it granted the first time, the token is destroyed rather than
// delivered, and the grant's access ends.
func TestRefreshNeverWiderThanTheFirstToken(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, []string{"contents:read"}, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	f.gh.mu.Lock()
	f.gh.answerPermissions = map[string]string{"contents": "write", "administration": "write"}
	f.gh.mu.Unlock()
	f.clock.advance(51 * time.Minute)

	_, err := f.b.RefreshAppToken(context.Background(), lease.ID, f.grant.ID, tokenFrom(t, lease))
	if !errors.Is(err, ErrRefreshRefused) || !strings.Contains(err.Error(), "administration:write") {
		t.Fatalf("a wider refresh = %v; want a refusal naming what was wider", err)
	}
	if live := f.gh.liveTokens(); len(live) != 0 {
		t.Fatalf("tokens still live after a refused, wider refresh: %d", len(live))
	}
}

// TestRefreshOfAWildcardPermissionGrantAsksForWhatWasGranted: a "*" grant's
// first mint asks for the installation's whole set. A refresh asks for what
// that mint was granted, so a permission accepted by the org since dispatch
// neither widens the token nor — refused as wider — cuts the run off.
func TestRefreshOfAWildcardPermissionGrantAsksForWhatWasGranted(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, []string{"*"}, InstallationRepo{ID: 1, FullName: "org/tool"})
	granted := map[string]string{"contents": "write", "metadata": "read"}
	f.gh.mu.Lock()
	f.gh.answerPermissions = granted
	f.gh.mu.Unlock()
	lease := f.lease(t)
	if first := f.gh.deliveredCreate(t); first.Permissions != nil {
		t.Fatalf("the first mint of a * grant asked for %v, want the installation's whole set (nil)", first.Permissions)
	}

	// The org accepts a new permission; GitHub would now grant more for nil.
	f.gh.mu.Lock()
	f.gh.answerPermissions = nil
	f.gh.mu.Unlock()
	f.clock.advance(51 * time.Minute)
	got, err := f.b.RefreshAppToken(context.Background(), lease.ID, f.grant.ID, tokenFrom(t, lease))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got.Token == "" {
		t.Fatal("no token")
	}
	if last := f.gh.deliveredCreate(t); !reflect.DeepEqual(last.Permissions, granted) {
		t.Fatalf("the refresh asked for %v; want exactly what the first token was granted, %v", last.Permissions, granted)
	}
}

// TestRefreshIsSingleFlight: callers that find the same token due wait for one
// mint and share its result.
func TestRefreshIsSingleFlight(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	held := tokenFrom(t, lease)
	f.clock.advance(51 * time.Minute)
	mintsBefore := len(f.scopedCreates())

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	f.gh.mu.Lock()
	f.gh.beforeCreate = func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	f.gh.mu.Unlock()

	const callers = 4
	results := make([]AppTokenRefresh, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = f.b.RefreshAppToken(context.Background(), lease.ID, f.grant.ID, held)
		}(i)
		if i == 0 {
			<-entered
		}
	}
	time.Sleep(50 * time.Millisecond) // let the rest queue behind the first
	close(release)
	wg.Wait()

	if n := len(f.scopedCreates()) - mintsBefore; n != 1 {
		t.Fatalf("%d concurrent refreshes minted %d tokens, want one", callers, n)
	}
	retirers := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if results[i].Token != results[0].Token {
			t.Fatalf("callers got different tokens")
		}
		if results[i].Retire != nil {
			retirers++
		}
	}
	if retirers != 1 {
		t.Errorf("%d callers were handed the superseded token's retirement, want exactly one", retirers)
	}
}

// TestReleaseDuringARefreshDestroysTheNewToken: a lease released while GitHub
// is minting its replacement token must not leave that token alive with
// nothing pointing at it.
func TestReleaseDuringARefreshDestroysTheNewToken(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	held := tokenFrom(t, lease)
	f.clock.advance(51 * time.Minute)

	entered := make(chan struct{})
	release := make(chan struct{})
	f.gh.mu.Lock()
	f.gh.beforeCreate = func() {
		close(entered)
		<-release
	}
	f.gh.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := f.b.RefreshAppToken(context.Background(), lease.ID, f.grant.ID, held)
		done <- err
	}()
	<-entered
	f.b.Release(lease.ID)
	close(release)
	if err := <-done; !errors.Is(err, ErrRefreshRefused) {
		t.Fatalf("a refresh racing a release = %v; want ErrRefreshRefused", err)
	}
	if live := f.gh.liveTokens(); len(live) != 0 {
		t.Fatalf("%d token(s) still live after the lease was released mid-refresh", len(live))
	}
}

// TestGuardIsHandedARefresherForAnAppGrant: under the git proxy the session,
// not the keepalive, refreshes the token — so the guard must be given the
// refresher and the token's expiry, and the keepalive must leave the slot be.
func TestGuardIsHandedARefresherForAnAppGrant(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, []string{"contents:write"}, InstallationRepo{ID: 1, FullName: "org/tool"})
	guard := &capturingGuard{}
	f.b.GitGuard = guard
	lease := f.lease(t)
	if guard.req.Refresh == nil || guard.req.TokenExpiresAt.IsZero() {
		t.Fatalf("guard got Refresh=%v TokenExpiresAt=%s; an App token needs both",
			guard.req.Refresh != nil, guard.req.TokenExpiresAt)
	}
	if f.b.HoldsFileAppTokens(lease.ID) {
		t.Error("a guarded token is reported as one the keepalive refreshes")
	}

	f.clock.advance(51 * time.Minute)
	if f.b.AppTokensDue(lease.ID) {
		t.Error("the keepalive would refresh a token the proxy session holds")
	}
	got, err := guard.req.Refresh(context.Background(), guard.req.Token)
	if err != nil {
		t.Fatalf("guard refresh: %v", err)
	}
	if got.Token == guard.req.Token || got.Retire == nil || !got.ExpiresAt.After(guard.req.TokenExpiresAt) {
		t.Fatalf("guard refresh = %v; want a new token, later expiry and a retirer", got)
	}
	got.Retire()
	if f.isLive(guard.req.Token) {
		t.Error("Retire left the superseded token alive")
	}
	rows := f.renewRows(DecisionAllow)
	if len(rows) == 0 || !strings.Contains(rows[len(rows)-1].Reason, "git proxy session sess-1") {
		t.Errorf("the renew row does not name the session presenting the token: %+v", rows)
	}
	f.b.Release(lease.ID)
	if f.isLive(got.Token) {
		t.Error("releasing the lease left the refreshed token alive")
	}
}

// capturingGuard records the request and mints a stand-in session.
type capturingGuard struct{ req GitGuardRequest }

func (g *capturingGuard) GuardGitHub(_ context.Context, req GitGuardRequest) (GitGuardResult, error) {
	g.req = req
	return GitGuardResult{
		BaseURL: "https://hub.internal:8443", Username: "sess-1", Password: "session-token-not-the-pat",
		ExpiresAt: time.Now().Add(time.Hour), SessionID: "sess-1", Summary: "read-write via git proxy",
	}, nil
}

// TestRefreshedFileNamesFollowTheRenderedLease: with two App grants in one
// lease the second token file is suffixed, and a refresh must rewrite each
// grant's own file.
func TestRefreshedFileNamesFollowTheRenderedLease(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil,
		InstallationRepo{ID: 1, FullName: "org/tool"}, InstallationRepo{ID: 2, FullName: "org/lib"})
	sec2, err := f.b.Mint(context.Background(), MintRequest{
		Name: "app-lib", Kind: KindGitHubApp, Payload: appPayloadJSON(t), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	g2, err := f.b.Grant(context.Background(), GrantRequest{
		SecretRef: sec2.ID, Subject: Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: Constraints{Repos: []string{"org/lib"}}, TTL: 24 * time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	lease, err := f.b.LeaseFor(context.Background(), Requester{ExecutorID: "exec-1", ProjectID: "/srv/app"}, "ui")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	delivery, err := lease.Deliver(SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	rendered := map[string]string{} // grant → token file name
	for _, file := range delivery.Files() {
		if strings.HasPrefix(file.Name, tokenFileName) {
			rendered[file.GrantID] = file.Name
		}
	}
	_ = delivery.Close()
	if len(rendered) != 2 {
		t.Fatalf("the lease rendered token files %v; want one per grant", rendered)
	}

	f.clock.advance(51 * time.Minute)
	fr, err := f.b.RefreshLeaseFiles(context.Background(), lease)
	if err != nil || fr == nil {
		t.Fatalf("RefreshLeaseFiles = %v, %v", fr, err)
	}
	defer fr.Close()
	got := map[string]string{}
	for _, file := range fr.Files {
		got[file.GrantID] = file.Name
	}
	if !reflect.DeepEqual(got, rendered) {
		t.Fatalf("refreshed files %v, rendered %v; a refresh must rewrite the files the lease delivered", got, rendered)
	}
	if got[g2.ID] == tokenFileName && got[f.grant.ID] == tokenFileName {
		t.Fatal("both grants map to one file")
	}
}

// TestWildcardGrantLeavesTheOldTokenToLapse: a "*" allowlist also exported the
// token as GITHUB_TOKEN, which no refresh reaches, so the superseded token is
// not destroyed early — the variable keeps working for the hour it always had.
func TestWildcardGrantLeavesTheOldTokenToLapse(t *testing.T) {
	f := newRefreshFixture(t, []string{"*"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	first := tokenFrom(t, lease)
	f.clock.advance(51 * time.Minute)
	fr, err := f.b.RefreshLeaseFiles(context.Background(), lease)
	if err != nil || fr == nil {
		t.Fatalf("RefreshLeaseFiles = %v, %v", fr, err)
	}
	fr.Delivered(false)
	fr.Close()
	f.clock.advance(appTokenRetireGrace + time.Minute)
	f.b.RetireSuperseded(context.Background(), lease.ID)
	if !f.isLive(first) {
		t.Fatal("the token GITHUB_TOKEN still carries was destroyed before its hour")
	}
}

// TestEventualDeliveryLeavesTheOldTokenToLapse: a Kubernetes Secret is synced
// into the Pod by the kubelet on its own schedule, so no grace this side can
// know the Pod moved to the new token.
func TestEventualDeliveryLeavesTheOldTokenToLapse(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	first := tokenFrom(t, lease)
	f.clock.advance(51 * time.Minute)
	fr, err := f.b.RefreshLeaseFiles(context.Background(), lease)
	if err != nil || fr == nil {
		t.Fatalf("RefreshLeaseFiles = %v, %v", fr, err)
	}
	fr.Delivered(true)
	fr.Close()
	f.clock.advance(appTokenRetireGrace + time.Minute)
	f.b.RetireSuperseded(context.Background(), lease.ID)
	if !f.isLive(first) {
		t.Fatal("an eventually-delivered refresh destroyed the old token before the Pod could have moved")
	}
}

// TestGitHubRefusalClassification pins which answers from GitHub end a grant's
// access and which are retried.
func TestGitHubRefusalClassification(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		header  map[string]string
		message string
		refused bool
	}{
		{"repository removed from the installation", http.StatusUnprocessableEntity, nil,
			"There is at least one repository that does not exist or is not accessible to the parent installation.", true},
		{"installation suspended", http.StatusForbidden, nil, "This installation has been suspended", true},
		{"installation gone", http.StatusNotFound, nil, "Not Found", true},
		{"app key revoked", http.StatusUnauthorized, nil, "A JSON web token could not be decoded", true},
		{"hub clock ahead", http.StatusUnauthorized, nil,
			"'Issued at' claim ('iat') must be an Integer representing a time in the past.", false},
		{"secondary rate limit, marked", http.StatusForbidden, map[string]string{"Retry-After": "60"},
			"You have exceeded a secondary rate limit", false},
		{"secondary rate limit, unmarked", http.StatusForbidden, nil,
			"You have exceeded a secondary rate limit. Please wait a few minutes before you try again.", false},
		{"primary rate limit", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"},
			"API rate limit exceeded", false},
		{"too many requests", http.StatusTooManyRequests, nil, "slow down", false},
		{"server error", http.StatusBadGateway, nil, "bad gateway", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				body, _ := json.Marshal(map[string]string{"message": tc.message})
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			api := &httpGitHubApp{client: srv.Client()}
			_, err := api.CreateInstallationToken(context.Background(), InstallationTokenRequest{
				BaseURL: srv.URL, AppJWT: "a.b.c", InstallationID: 1,
			})
			if !errors.Is(err, ErrGitHubAppMint) {
				t.Fatalf("err = %v; want ErrGitHubAppMint", err)
			}
			if got := errors.Is(err, ErrGitHubAppRefused); got != tc.refused {
				t.Fatalf("refused = %t for %d %v; want %t (%v)", got, tc.status, tc.header, tc.refused, err)
			}
		})
	}
}

// TestRefreshAuditRowsNameNoToken: across a refresh, a retirement and a
// release, no audit row carries any token GitHub minted.
func TestRefreshAuditRowsNameNoToken(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool"}, nil, InstallationRepo{ID: 1, FullName: "org/tool"})
	lease := f.lease(t)
	f.clock.advance(51 * time.Minute)
	fr, _ := f.b.RefreshLeaseFiles(context.Background(), lease)
	fr.Delivered(false)
	fr.Close()
	f.clock.advance(appTokenRetireGrace + time.Minute)
	f.b.RetireSuperseded(context.Background(), lease.ID)
	f.b.Release(lease.ID)

	f.gh.mu.Lock()
	var tokens []string
	for tok := range f.gh.live {
		tokens = append(tokens, tok)
	}
	tokens = append(tokens, f.gh.revoked...)
	f.gh.mu.Unlock()
	sort.Strings(tokens)
	for _, ev := range f.auditor.all() {
		for _, tok := range tokens {
			if strings.Contains(ev.Reason, tok) {
				t.Fatalf("audit row %s carries a token", ev.Action)
			}
		}
	}
	destroyed := 0
	for _, ev := range f.auditor.byAction(ActionAppTokenDestroy) {
		if ev.Decision == DecisionAllow {
			destroyed++
		}
	}
	if destroyed < 2 {
		t.Errorf("%d github_app.token_destroy rows; want the superseded token's and the release's", destroyed)
	}
}
