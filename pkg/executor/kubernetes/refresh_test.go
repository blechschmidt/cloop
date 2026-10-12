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
	"time"

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

// TestRefreshReachesAnAdoptedPodsLeaseSecret (Task 20419): the row records
// which key of the lease Secret each delivered file is projected from, so a
// hub process that adopted the Pod renews a GitHub App token in it in place —
// where it used to fail, and GitHub stopped honouring the token an hour into
// the run.
func TestRefreshReachesAnAdoptedPodsLeaseSecret(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex1, api, src := newTestExecutor(t, func(o *Options) { o.HandleStore = store })
	handle, err := ex1.Start(context.Background(), leasedSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	api.run(api.onlyPodName(t))
	rows, err := store.ListHandles("k8s-test")
	if err != nil || len(rows) != 1 || rows[0].Meta[metaLeaseSecretKeys] == "" {
		t.Fatalf("the row does not record the lease Secret's keys: %+v %v", rows, err)
	}
	if strings.Contains(rows[0].Meta[metaLeaseSecretKeys], "ghs_") {
		t.Fatal("the row carries a credential, not just where it is projected from")
	}

	// Another hub process adopts the Pod from the row.
	ex2 := newRestartedExecutor(t, api, src, store)
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec, err := ex2.lookup(handle.ID)
		if err == nil && rec.client() != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the adopting executor never connected to the Pod: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	const fresh = "ghs_refreshed_after_adoption\n"
	rep := ex2.RefreshSecretFiles(context.Background(), executor.SecretRefreshRequest{
		LeaseID: revokedLeaseID,
		Files: []executor.SecretFile{{
			LeaseID: revokedLeaseID, GrantID: "grant-1", Dir: leaseDir, Name: "github-token",
			Mode: 0o600, Content: []byte(fresh),
		}},
	})
	if !rep.Delivered() || rep.FilesRewritten != 1 || rep.Error != "" {
		t.Fatalf("refresh through the adopting executor = %+v", rep)
	}
	if got := string(api.secretObject(leaseSecretName(handle.ID)).Data[secretFileKey(0, "github-token")]); got != fresh {
		t.Fatalf("the adopted Pod's lease Secret holds %q after the refresh", got)
	}
}

// TestARecordedKeyMapIsHeldToSecretKeys: the row is read back from a
// database, so a key that is not a Secret key, or a path that is not one, is
// dropped rather than patched.
func TestARecordedKeyMapIsHeldToSecretKeys(t *testing.T) {
	st := restoreLeaseSecret(map[string]string{metaLeaseSecretKeys: `{"/run/cloop/cloop-lease-x/token":"file-0-token",` +
		`"relative/path":"file-1","/run/cloop/../etc/passwd":"file-2","/run/cloop/cloop-lease-x/ok":"bad key!"}`},
		"cloop", "k-123")
	if st == nil {
		t.Fatal("a row with one usable key restored nothing")
	}
	if st.secretName != leaseSecretName("k-123") || st.namespace != "cloop" {
		t.Fatalf("restored state names %s/%s", st.namespace, st.secretName)
	}
	if k, ok := st.keyFor("/run/cloop/cloop-lease-x/token"); !ok || k != "file-0-token" {
		t.Fatalf("the usable key was not restored: %q %v", k, ok)
	}
	if len(st.keys) != 1 {
		t.Fatalf("restored keys = %v, want only the usable one", st.keys)
	}
	if restoreLeaseSecret(map[string]string{metaLeaseSecretKeys: "{not json"}, "cloop", "k-1") != nil {
		t.Error("an unreadable key map restored state")
	}
	if restoreLeaseSecret(nil, "cloop", "k-1") != nil {
		t.Error("a row with no key map restored state")
	}
}
