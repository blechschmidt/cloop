package gitcreds_test

// A feature's workspace is leased as its parent project (Task 20371).
//
// A feature of a project bound to a remote device ships only its own commits
// when the project's https upstream holds its base: the device clones the
// upstream with the project's GitHub grant and applies the bundle on top. The
// grant is chosen against the parent before the dispatch, but the driver asked
// the broker on behalf of the feature's own path, which no grant names — so on
// the first live run against a private repository every such feature was
// refused with "no active GitHub grant named … is issued to this executor for
// this project".

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
)

// featureLayout maps "<project>/.cloop/features/<slug>" to its project, the
// way the control plane's mapper (pkg/ui.policyProjectPath) does.
func featureLayout(p string) string {
	if i := strings.Index(p, "/.cloop/features/"); i > 0 {
		return p[:i]
	}
	return p
}

func TestFeatureWorkspaceLeasesItsParentsGrant(t *testing.T) {
	const token = "ghp_featuregrant0123456789abcdefghijk"
	b := brokerWithPAT(t, token, "project:/srv/app")
	executor.SetPolicyProjectMapper(featureLayout)
	t.Cleanup(func() { executor.SetPolicyProjectMapper(nil) })

	src, err := gitcreds.New(b, "device-1", "ui")
	if err != nil {
		t.Fatalf("gitcreds.New: %v", err)
	}
	access, release, err := src.ForWorkspace(context.Background(), "/srv/app/.cloop/features/dark-mode", privateWorkspace())
	defer release()
	if err != nil {
		t.Fatalf("the parent's grant was not leased for its feature's dispatch: %v", err)
	}
	if access.Credential.Password != token {
		t.Fatal("the lease did not carry the parent project's grant")
	}
}

// TestFeatureDoesNotBorrowAnotherProjectsGrant: the mapping goes to the
// feature's own parent, never to whichever project holds a grant.
func TestFeatureDoesNotBorrowAnotherProjectsGrant(t *testing.T) {
	b := brokerWithPAT(t, "ghp_othergrant0123456789abcdefghijklm", "project:/srv/other")
	executor.SetPolicyProjectMapper(featureLayout)
	t.Cleanup(func() { executor.SetPolicyProjectMapper(nil) })

	src, err := gitcreds.New(b, "device-1", "ui")
	if err != nil {
		t.Fatalf("gitcreds.New: %v", err)
	}
	_, release, err := src.ForWorkspace(context.Background(), "/srv/app/.cloop/features/dark-mode", privateWorkspace())
	defer release()
	var grantErr *executor.WorkspaceGrantError
	if !errors.As(err, &grantErr) {
		t.Fatalf("err = %v, want a *WorkspaceGrantError: /srv/app holds no grant", err)
	}
	if grantErr.ProjectPath != "/srv/app/.cloop/features/dark-mode" {
		t.Errorf("the refusal names %q; it should name the feature the run was for", grantErr.ProjectPath)
	}
}
