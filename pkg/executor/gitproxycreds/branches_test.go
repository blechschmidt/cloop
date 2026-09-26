package gitproxycreds

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// heldInner is a fakeInner that can be told the credential will be held by the
// proxy, as gitcreds.BrokerSource can. It records which door it was asked
// through, because that choice is what decides whether a branch-restricted
// grant keeps its push.
type heldInner struct {
	fakeInner
	held int
}

func (h *heldInner) ForProxiedWorkspace(ctx context.Context, projectID string, w executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	h.held++
	return h.fakeInner.ForWorkspace(ctx, projectID, w)
}

var _ HeldSource = (*heldInner)(nil)

// TestTheDecoratorLeasesAsProxied: the decorator is about to keep the
// credential on the hub, so it says so to a source that can hear it. Asking
// through the ordinary door would get a branch-restricted grant's push
// withheld for a credential that is in fact held by the proxy.
func TestTheDecoratorLeasesAsProxied(t *testing.T) {
	inner := &heldInner{fakeInner: fakeInner{access: patAccess()}}
	src := newSource(t, inner, newRegistry(t, time.Time{}), 0)

	_, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	if err != nil {
		t.Fatalf("ForWorkspace = %v", err)
	}
	defer release()
	if inner.held != 1 {
		t.Errorf("ForProxiedWorkspace called %d times, want 1", inner.held)
	}
	if inner.calls != 1 {
		t.Errorf("the inner lease ran %d times, want 1", inner.calls)
	}
}

// TestTheSessionIsNarrowedToTheGrantsBranches: the grant's list rides on the
// credential the inner source returned, and the session the sandbox gets has
// to enforce it within the hub's own ceiling.
func TestTheSessionIsNarrowedToTheGrantsBranches(t *testing.T) {
	access := patAccess()
	access.Credential.Branches = []string{"cloop/feature-*"}
	inner := &fakeInner{access: access}
	reg := newRegistry(t, time.Time{})
	src := newSource(t, inner, reg, 0) // default policy: refs/heads/cloop/** plus fetch

	got, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	if err != nil {
		t.Fatalf("ForWorkspace = %v", err)
	}
	defer release()

	sessions := reg.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("%d sessions minted, want 1", len(sessions))
	}
	pol := sessions[0].Policy
	if want := []string{"refs/heads/cloop/feature-*"}; !reflect.DeepEqual(pol.RestrictRefs, want) {
		t.Errorf("session RestrictRefs = %q, want %q", pol.RestrictRefs, want)
	}
	for ref, want := range map[string]bool{
		"refs/heads/cloop/feature-login": true,
		"refs/heads/cloop/task-1":        false, // the write-back namespace, but not this grant's
		"refs/heads/main":                false,
	} {
		if pol.AllowsRef(ref) != want {
			t.Errorf("session AllowsRef(%q) = %v, want %v", ref, !want, want)
		}
	}
	if !reflect.DeepEqual(got.Credential.Branches, access.Credential.Branches) {
		t.Errorf("returned credential lost the branch list: %q", got.Credential.Branches)
	}

	// The decorator's own policy is shared by every session it mints; one
	// grant's narrowing must not stick to it.
	if len(src.Policy.RestrictRefs) != 0 {
		t.Fatalf("the decorator's policy was narrowed in place: %q", src.Policy.RestrictRefs)
	}
	inner.access = patAccess() // a grant with no list
	if _, rel, err := src.ForWorkspace(context.Background(), "proj-2", gitWorkspace()); err != nil {
		t.Fatalf("second ForWorkspace = %v", err)
	} else {
		rel()
	}
	for _, s := range reg.Sessions() {
		if s.ProjectID == "proj-2" && s.Policy.Restricted() {
			t.Errorf("a grant with no branch list got another grant's restriction: %q", s.Policy.RestrictRefs)
		}
	}
}
