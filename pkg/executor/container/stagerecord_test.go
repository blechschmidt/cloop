package container

// Where a container's credential files are staged survives the hub process
// that staged them (Task 20419): the layout goes into the handle's row, and an
// adopter rebuilt from that row wipes, revokes and refreshes the files rather
// than losing them — while trusting nothing in the row the filesystem does not
// bear out.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// TestAStagedLayoutSurvivesInTheHandleRow: the row's account rebuilds the same
// stage — directories, their identities, each file's lease and grant — and the
// rebuilt stage revokes one lease's file exactly and wipes the rest on
// teardown.
func TestAStagedLayoutSurvivesInTheHandleRow(t *testing.T) {
	stage, err := stageSecretFiles(leasedFilesSpec(t), "")
	if err != nil {
		t.Fatalf("stageSecretFiles: %v", err)
	}
	defer stage.remove()
	meta := withStageMeta(map[string]string{metaRuntime: RuntimeDocker}, stage)
	if meta[metaRuntime] != RuntimeDocker || meta[metaSecretStage] == "" {
		t.Fatalf("meta = %v", meta)
	}
	if strings.Contains(meta[metaSecretStage], "ghp_canary_pat") || strings.Contains(meta[metaSecretStage], "canary_kubeconfig") {
		t.Fatal("the row carries a credential, not just where it is")
	}

	restored, problems := restoreSecretStage(meta)
	if len(problems) != 0 || restored == nil || !restored.accountsForFiles() {
		t.Fatalf("restore = %+v, problems %v", restored, problems)
	}
	if strings.Join(restored.dirs, ",") != strings.Join(stage.dirs, ",") || len(restored.files) != len(stage.files) {
		t.Fatalf("restored dirs %v files %d, staged dirs %v files %d",
			restored.dirs, len(restored.files), stage.dirs, len(stage.files))
	}
	for i, f := range stage.files {
		if restored.files[i] != f {
			t.Errorf("file %d restored as %+v, staged as %+v", i, restored.files[i], f)
		}
	}
	for _, d := range stage.dirs {
		if restored.dirIDs[d] != stage.dirIDs[d] {
			t.Errorf("directory %s restored with identity %v, staged with %v", d, restored.dirIDs[d], stage.dirIDs[d])
		}
	}

	pat := hostPathFor(t, restored, "gitcredentials")
	kube := hostPathFor(t, restored, "kubeconfig")
	removed, err := restored.revoke(executor.RevokeRequest{LeaseID: "lease_pat"})
	if err != nil || removed != 1 {
		t.Fatalf("revoke through the restored stage = %d, %v", removed, err)
	}
	if _, err := os.Stat(pat); !os.IsNotExist(err) {
		t.Fatalf("the revoked lease's file is still on the host: %v", err)
	}
	if _, err := os.Stat(kube); err != nil {
		t.Fatalf("the other lease's file went too: %v", err)
	}
	restored.remove()
	if _, err := os.Stat(filepath.Dir(kube)); !os.IsNotExist(err) {
		t.Fatalf("teardown through the restored stage left %s", filepath.Dir(kube))
	}
	if withStageMeta(nil, nil) != nil {
		t.Error("a workload with nothing staged records a stage")
	}
}

// TestARestoredStageTrustsOnlyWhatTheFilesystemBearsOut: the row is read back
// from a database. A directory outside the staging bases, one not named as
// this driver names them, and one renamed away and replaced since — which the
// sandbox user who owns it can do in a sticky /dev/shm — is not taken for the
// staged one, and marks the stage incomplete; a directory that is simply gone
// is not a problem, since what was in it is gone too.
func TestARestoredStageTrustsOnlyWhatTheFilesystemBearsOut(t *testing.T) {
	stage, err := stageSecretFiles(leasedFilesSpec(t), "")
	if err != nil {
		t.Fatalf("stageSecretFiles: %v", err)
	}
	defer stage.remove()
	meta := withStageMeta(nil, stage)

	// Replaced: the real directory renamed away, an empty one in its place.
	replaced := stage.dirs[0]
	moved := replaced + "-moved"
	if err := os.Rename(replaced, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	if err := os.Mkdir(replaced, 0o700); err != nil {
		t.Fatal(err)
	}
	// Gone: the other directory removed.
	gone := stage.dirs[1]
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}

	restored, problems := restoreSecretStage(meta)
	if restored == nil || restored.accountsForFiles() {
		t.Fatalf("a stage with a replaced directory accounts for its files: %+v", restored)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "replaced") {
		t.Fatalf("problems = %v, want the replaced directory named", problems)
	}
	if len(restored.dirs) != 0 || len(restored.files) != 0 {
		t.Fatalf("restored dirs %v files %+v: a replaced or vanished directory was trusted", restored.dirs, restored.files)
	}

	for name, value := range map[string]string{
		"outside every base": `{"dirs":[{"host":"/etc/cloop-lease-x","target":"/run/x","dev":1,"ino":2}]}`,
		"not a lease dir":    `{"dirs":[{"host":"` + filepath.Join(os.TempDir(), "elsewhere") + `","target":"/run/x","dev":1,"ino":2}]}`,
		"unclean path":       `{"dirs":[{"host":"/dev/shm/../etc/cloop-lease-x","target":"/run/x","dev":1,"ino":2}]}`,
		"unreadable":         `{not json`,
	} {
		t.Run(name, func(t *testing.T) {
			restored, problems := restoreSecretStage(map[string]string{metaSecretStage: value})
			if restored == nil || restored.accountsForFiles() || len(problems) == 0 || len(restored.dirs) != 0 {
				t.Fatalf("restore of %s = %+v, problems %v", value, restored, problems)
			}
		})
	}
	if restored, problems := restoreSecretStage(nil); restored != nil || problems != nil {
		t.Fatalf("a row with no stage restored one: %+v %v", restored, problems)
	}
}

// adoptedWithStage records a container staged for one lease file, as a hub
// process does, and adopts it in a fresh executor over the same store, as the
// member taking its run over does.
func adoptedWithStage(t *testing.T) (*Executor, executor.HandleRecord, string) {
	t.Helper()
	const dir = "/run/cloop/cloop-lease-adopted"
	stage, err := stageSecretFiles(executor.Spec{SecretFiles: []executor.SecretFile{{
		LeaseID: "lease_adopted", GrantID: "grant_deploy", Dir: dir, Name: "deploy-key", Mode: 0o600,
		Content: []byte("deploy-key-canary-0123456789\n"),
	}}}, "")
	if err != nil {
		t.Fatalf("stageSecretFiles: %v", err)
	}
	t.Cleanup(stage.remove)
	host := stage.files[0].host

	store := executor.NewMemoryHandleStore()
	rec := savedHandle("c-staged01", "test-staged", "cloop-project-staged01", time.Now())
	rec.Meta = withStageMeta(rec.Meta, stage)
	rec.SecretsRecorded = true
	rec.Secrets = []executor.SecretBinding{{
		LeaseID: "lease_adopted", GrantID: "grant_deploy", SecretName: "deploy-key", Kind: "env",
		Dir: dir, Files: []string{dir + "/deploy-key"},
	}}
	if err := store.PutHandle(rec); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}
	ex := storeExecutor(t, "test-staged", stubRuntime(t, liveContainerStub), store)
	ex.rehydrate()
	return ex, rec, host
}

// TestAnAdoptedContainerGivesFilesBackWithoutBeingRemoved is what the recorded
// layout buys a revocation: the files of the revoked lease are wiped where the
// container reads them, and the container keeps running — where an adopted
// container with no recorded stage could give them back only by being removed
// (TestRevokingAnAdoptedContainersFilesRemovesTheContainer).
func TestAnAdoptedContainerGivesFilesBackWithoutBeingRemoved(t *testing.T) {
	ex, rec, host := adoptedWithStage(t)
	out := ex.RevokeLease(context.Background(), executor.RevokeRequest{
		LeaseID: "lease_adopted", GrantID: "grant_deploy", Reason: "revoked from the Secrets panel",
	})
	if out.State != executor.RevokeStateRevoked || out.Ack == nil {
		t.Fatalf("revocation of an adopted container's files = %+v", out)
	}
	if len(out.Ack.Killed) != 0 {
		t.Fatalf("Killed = %v: the container was removed although its files could be found", out.Ack.Killed)
	}
	if out.Ack.FilesRemoved != 1 {
		t.Fatalf("FilesRemoved = %d, want the staged file", out.Ack.FilesRemoved)
	}
	if _, err := os.Stat(host); !os.IsNotExist(err) {
		t.Fatalf("the revoked file is still where the container reads it: %v", err)
	}
	if st, err := ex.Status(context.Background(), rec.HandleID); err != nil || st.State.Terminal() {
		t.Fatalf("the adopted container was stopped: %+v %v", st, err)
	}
}

// TestAnAdoptedContainersFileIsRefreshed: a GitHub App token delivered as a
// file is renewed in an adopted container as in one this process started,
// instead of failing — and GitHub access lapsing an hour into the run.
func TestAnAdoptedContainersFileIsRefreshed(t *testing.T) {
	ex, rec, host := adoptedWithStage(t)
	rep := ex.RefreshSecretFiles(context.Background(), executor.SecretRefreshRequest{
		LeaseID: "lease_adopted",
		Files: []executor.SecretFile{{
			LeaseID: "lease_adopted", Dir: "/run/cloop/cloop-lease-adopted", Name: "deploy-key", Mode: 0o600,
			Content: []byte("renewed-key-canary-9876543210\n"),
		}},
	})
	if rep.Error != "" || rep.FilesRewritten != 1 || len(rep.Handles) != 1 || rep.Handles[0] != rec.HandleID {
		t.Fatalf("refresh of an adopted container = %+v", rep)
	}
	if got, _ := os.ReadFile(host); string(got) != "renewed-key-canary-9876543210\n" {
		t.Fatalf("the adopted container reads %q after the refresh", got)
	}
	r, err := ex.lookup(rec.HandleID)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.bus.Redactor().String("key renewed-key-canary-9876543210"); strings.Contains(got, "renewed-key") {
		t.Errorf("the refreshed value is not scrubbed from the adopted container's output: %q", got)
	}
}

// TestAnAdoptedContainersStageIsWipedWhenItEnds: the files of an adopted
// container are not left on the host when it ends.
func TestAnAdoptedContainersStageIsWipedWhenItEnds(t *testing.T) {
	ex, rec, host := adoptedWithStage(t)
	r, err := ex.lookup(rec.HandleID)
	if err != nil {
		t.Fatal(err)
	}
	ex.finish(r, executor.StateExited, 0, "")
	if _, err := os.Stat(filepath.Dir(host)); !os.IsNotExist(err) {
		t.Fatalf("the adopted container's staging directory outlived it: %v", err)
	}
}

// TestAClaimedRowIsAdoptedOnce: two drivers over one shared store adopt a
// row once — the store's claim decides — so a member started after the
// workload's owner died does not put a second log follower on it.
func TestAClaimedRowIsAdoptedOnce(t *testing.T) {
	store := &claimingStore{HandleStore: executor.NewMemoryHandleStore(), claimed: map[string]bool{}}
	rec := savedHandle("c-claimed01", "test-claimed", "cloop-project-claimed01", time.Now())
	if err := store.PutHandle(rec); err != nil {
		t.Fatal(err)
	}
	first := storeExecutor(t, "test-claimed", stubRuntime(t, liveContainerStub), store)
	first.rehydrate()
	second := storeExecutor(t, "test-claimed", stubRuntime(t, liveContainerStub), store)
	second.rehydrate()
	if _, err := first.lookup(rec.HandleID); err != nil {
		t.Fatalf("the first adopter does not track the row it claimed: %v", err)
	}
	if _, err := second.lookup(rec.HandleID); err == nil {
		t.Fatal("a second process adopted a row another had claimed")
	}
}

// claimingStore is a handle store shared by several processes: the first to
// claim a row has it.
type claimingStore struct {
	executor.HandleStore
	claimed map[string]bool
}

func (c *claimingStore) ClaimHandle(rec executor.HandleRecord) (bool, error) {
	if c.claimed[rec.HandleID] {
		return false, nil
	}
	c.claimed[rec.HandleID] = true
	return true, nil
}
