package kubernetes

// A GitHub App token replaced in a running Pod's lease Secret (Task 20375).
//
// The lease's files reach the Pod through a secret volume mounted as a
// directory with no subPath — the one shape the kubelet keeps in sync with the
// object — so patching the Secret is what refreshes the file, within the
// kubelet's sync period. These tests hold the driver to patching exactly the
// key the volume projects the token from, and to saying the delivery is
// eventual.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestRefreshPatchesTheLeaseSecretsTokenKey(t *testing.T) {
	ex, api, handle, _ := startLeasedPod(t)
	name := leaseSecretName(handle.ID)
	before := api.secretObject(name)
	if before == nil {
		t.Fatal("no lease Secret was created")
	}

	const fresh = "ghs_refreshed_in_the_cluster\n"
	rep := ex.RefreshSecretFiles(context.Background(), executor.SecretRefreshRequest{
		LeaseID: revokedLeaseID,
		Files: []executor.SecretFile{{
			LeaseID: revokedLeaseID, GrantID: "grant-1", Dir: leaseDir, Name: "github-token",
			Mode: 0o600, Content: []byte(fresh),
		}},
	})
	if !rep.Delivered() || !rep.Eventual || rep.FilesRewritten != 1 || len(rep.Handles) != 1 {
		t.Fatalf("report = %+v; want one key patched, delivered eventually", rep)
	}
	after := api.secretObject(name)
	tokenKey := secretFileKey(0, "github-token")
	if got := string(after.Data[tokenKey]); got != fresh {
		t.Fatalf("Secret key %s = %q after the refresh, want the new token", tokenKey, got)
	}
	gitconfigKey := secretFileKey(0, "gitconfig")
	if string(after.Data[gitconfigKey]) != string(before.Data[gitconfigKey]) {
		t.Fatal("the refresh changed a key it was not asked to")
	}
	if len(api.secretPatches) != 1 {
		t.Fatalf("%d patches reached the API server, want one", len(api.secretPatches))
	}

	// The Pod's output is scrubbed of the new token as it was of the first.
	rec, err := ex.lookup(handle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.bus.Redactor().Contains("x " + strings.TrimSpace(fresh) + " y") {
		t.Error("the refreshed token is not in the Pod's output redaction")
	}
}

func TestRefreshRefusesAFileTheLeaseDidNotDeliver(t *testing.T) {
	ex, api, _, _ := startLeasedPod(t)
	rep := ex.RefreshSecretFiles(context.Background(), executor.SecretRefreshRequest{
		LeaseID: revokedLeaseID,
		Files: []executor.SecretFile{{
			LeaseID: revokedLeaseID, Dir: leaseDir, Name: "authorized-keys", Mode: 0o600, Content: []byte("x"),
		}},
	})
	if rep.Delivered() || !strings.Contains(rep.Error, "was not delivered") {
		t.Fatalf("report = %+v; want a refusal", rep)
	}
	if len(api.secretPatches) != 0 {
		t.Fatal("a patch reached the API server for a file the lease never delivered")
	}
}

// TestRefreshWithoutThePatchVerbIsUnsupported: a Role that refuses the patch
// will refuse every later one too, so the report says this executor cannot
// take a refresh — the hub stops minting for it — rather than a failure to
// retry.
func TestRefreshWithoutThePatchVerbIsUnsupported(t *testing.T) {
	ex, api, _, _ := startLeasedPod(t)
	api.mu.Lock()
	api.denySecretPatch = true
	api.mu.Unlock()
	rep := ex.RefreshSecretFiles(context.Background(), executor.SecretRefreshRequest{
		LeaseID: revokedLeaseID,
		Files: []executor.SecretFile{{
			LeaseID: revokedLeaseID, GrantID: "grant-1", Dir: leaseDir, Name: "github-token",
			Mode: 0o600, Content: []byte("ghs_refused_by_rbac\n"),
		}},
	})
	if rep.Delivered() || !rep.Unsupported || rep.FilesRewritten != 0 {
		t.Fatalf("report = %+v; want Unsupported with nothing rewritten", rep)
	}
	if !strings.Contains(rep.Error, `"patch"`) {
		t.Errorf("error %q does not name the missing verb", rep.Error)
	}
}

func TestRefreshNamesTheMissingPatchVerb(t *testing.T) {
	err := explainSecretFilePatchFailure("cloop", "cloop-lease-k-1",
		&APIError{Code: http.StatusForbidden, Verb: "PATCH", Path: "/api/v1/namespaces/cloop/secrets/cloop-lease-k-1"})
	for _, want := range []string{`"patch"`, "an hour after dispatch"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}
