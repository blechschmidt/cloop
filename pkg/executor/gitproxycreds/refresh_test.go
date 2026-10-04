package gitproxycreds

// The workspace path's pinned session renewing a GitHub App token through the
// source that leased it (Task 20375).

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// refreshingInner is a fakeInner whose credential the hub minted and can renew.
type refreshingInner struct {
	fakeInner
	calls   int
	err     error
	retired int
}

func (r *refreshingInner) RefreshWorkspaceCredential(_ context.Context, cred executor.GitCredential, held string) (executor.GitCredential, func(), error) {
	r.calls++
	if r.err != nil {
		return executor.GitCredential{}, nil, r.err
	}
	out := cred
	out.Password = fmt.Sprintf("ghs_renewed_%d", r.calls)
	out.TokenExpiresAt = cred.TokenExpiresAt.Add(time.Hour)
	return out, func() { r.retired++ }, nil
}

func appAccess(expires time.Time) executor.WorkspaceAccess {
	a := patAccess()
	a.Credential.Password = "ghs_dispatch_token"
	a.Credential.TokenExpiresAt = expires
	return a
}

func TestPinnedSessionOfAnAppTokenIsRefreshable(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	inner := &refreshingInner{fakeInner: fakeInner{access: appAccess(now.Add(time.Hour))}}
	reg := newRegistry(t, now)
	src := newSource(t, inner, reg, 2*time.Hour)
	access, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	if err != nil {
		t.Fatalf("ForWorkspace = %v", err)
	}
	defer release()
	sess, err := reg.Session(access.Credential.Username)
	if err != nil {
		t.Fatal(err)
	}
	if !sess.Refreshable() || !sess.CredentialExpiresAt().Equal(now.Add(time.Hour)) {
		t.Fatalf("pinned session refreshable=%t expires=%s; an App token's session must renew it",
			sess.Refreshable(), sess.CredentialExpiresAt())
	}
}

func TestPinnedSessionOfAPATIsNotRefreshable(t *testing.T) {
	inner := &refreshingInner{fakeInner: fakeInner{access: patAccess()}}
	reg := newRegistry(t, time.Time{})
	src := newSource(t, inner, reg, 0)
	access, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	if err != nil {
		t.Fatalf("ForWorkspace = %v", err)
	}
	defer release()
	sess, _ := reg.Session(access.Credential.Username)
	if sess.Refreshable() {
		t.Fatal("a PAT, whose expiry the hub does not know, was given a refresher")
	}
}

func TestWorkspaceRefresherMapsAFinalRefusal(t *testing.T) {
	inner := &refreshingInner{err: fmt.Errorf("%w: grant revoked", executor.ErrCredentialRefused)}
	refresh := workspaceRefresher(inner, appAccess(time.Now()).Credential)
	if _, err := refresh(context.Background(), "ghs_dispatch_token"); !errors.Is(err, gitproxy.ErrCredentialRefused) {
		t.Fatalf("a final refusal = %v; want gitproxy.ErrCredentialRefused", err)
	}
	inner.err = errors.New("github unreachable")
	if _, err := refresh(context.Background(), "ghs_dispatch_token"); err == nil || errors.Is(err, gitproxy.ErrCredentialRefused) {
		t.Fatalf("a passing failure = %v; want a retryable error", err)
	}
	inner.err = nil
	got, err := refresh(context.Background(), "ghs_dispatch_token")
	if err != nil || got.Credential.Password != "ghs_renewed_3" || got.Retire == nil {
		t.Fatalf("renewal = %+v, %v", got, err)
	}
}
