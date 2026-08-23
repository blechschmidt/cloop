package kubernetes

// secretfiles_test.go covers delivery of a secret lease's credential files into
// a Pod: the Secret they travel in, the read-only projection at the directory
// the workload's environment already names, and the cleanup that keeps the
// material from outliving the run.
//
// The assertions are written against the objects the fake API server actually
// received, not against the driver's own view of what it built. The failure
// these tests exist to catch is silent — a Pod that starts, runs, and fails to
// authenticate because a file the environment points at was never projected —
// so "the bytes are in the Secret" and "the mount is at exactly this path" have
// to be checked against the wire.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// leaseDir is the shape pkg/secretbroker produces: an absolute path under
// /run/cloop carrying the lease's own random suffix. The Pod has to expose the
// files here verbatim, because GIT_CONFIG_GLOBAL and friends already point at
// it.
const leaseDir = "/run/cloop/cloop-lease-9f2c1ab4d6e8"

// fakeLeaseToken is distinctive enough that finding it anywhere it should not be
// — a Pod object, a log line — is unambiguous.
const fakeLeaseToken = "ghp-TOTALLY-FAKE-LEASE-TOKEN-9876543210"

// secretFileSpec is a run whose grant delivered files rather than a bare token,
// which is what a repository-scoped GitHub PAT does.
//
// The gitconfig content is deliberately not valid UTF-8. Nothing in
// executor.SecretFile promises text, and a delivery path that routed the bytes
// through a Go string would mangle this silently.
func secretFileSpec() executor.Spec {
	spec := testSpec()
	spec.Env = append(spec.Env, "GIT_CONFIG_GLOBAL="+leaseDir+"/gitconfig")
	spec.SecretFiles = []executor.SecretFile{
		{
			LeaseID: "lease-1",
			GrantID: "grant-1",
			Dir:     leaseDir,
			Name:    "gitconfig",
			Content: []byte("[credential]\n\thelper = \xff\xfe/cloop\n"),
		},
		{
			LeaseID: "lease-1",
			GrantID: "grant-1",
			Dir:     leaseDir,
			Name:    "github-token",
			Content: []byte(fakeLeaseToken),
		},
	}
	return spec
}

// --- buildPod ---------------------------------------------------------

// TestBuildPod_SecretFilesProjectOnlyIntoTheHarness is the containment
// assertion. The workspace provisioner has no use for a lease's credentials —
// its own fetch credential arrives separately — and a mount it does not need is
// a mount a compromised git hook can read.
func TestBuildPod_SecretFilesProjectOnlyIntoTheHarness(t *testing.T) {
	req := workspaceRequest()
	req.SecretFiles = secretFileSpec().SecretFiles
	req.SecretFilesSecretName = "cloop-lease-k-abc123"

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if len(p.Spec.InitContainers) != 1 {
		t.Fatalf("expected the workspace init container, got %d", len(p.Spec.InitContainers))
	}
	for _, m := range p.Spec.InitContainers[0].VolumeMounts {
		if m.MountPath == leaseDir || strings.HasPrefix(m.Name, secretFilesPrefix) {
			t.Errorf("the workspace provisioner mounts the lease credentials at %s; "+
				"it has no business holding them", m.MountPath)
		}
	}
	if !hasSecretFileMount(p.Spec.Containers[0], leaseDir) {
		t.Errorf("the harness container has no lease mount at %s: %+v", leaseDir, p.Spec.Containers[0].VolumeMounts)
	}
}

// TestBuildPod_SecretFilesKeepDirectoriesApart: two lease directories each
// holding a file of the same name must not collide on one Secret key, or the
// workload reads whichever was written last — for a credential helper, that is
// answering with a grant it was never given.
func TestBuildPod_SecretFilesKeepDirectoriesApart(t *testing.T) {
	second := "/run/cloop/cloop-lease-000011112222"
	req := baseRequest()
	req.SecretFilesSecretName = "cloop-lease-k-abc123"
	req.SecretFiles = []executor.SecretFile{
		{Dir: leaseDir, Name: "gitconfig", Content: []byte("first")},
		{Dir: second, Name: "gitconfig", Content: []byte("second")},
	}

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	vols := secretFileVolumesOf(p)
	if len(vols) != 2 {
		t.Fatalf("got %d lease volumes, want one per directory: %+v", len(vols), vols)
	}
	seen := map[string]string{}
	for _, v := range vols {
		if len(v.Secret.Items) != 1 {
			t.Fatalf("volume %s projects %d items, want 1", v.Name, len(v.Secret.Items))
		}
		it := v.Secret.Items[0]
		if it.Path != "gitconfig" {
			t.Errorf("volume %s writes %q, want the bare name the environment points at", v.Name, it.Path)
		}
		if prev, dup := seen[it.Key]; dup {
			t.Fatalf("volumes %s and %s both read Secret key %q; one directory's file would win",
				prev, v.Name, it.Key)
		}
		seen[it.Key] = v.Name
	}

	// The Secret's keys are derived by the same plan, so they must be exactly
	// the ones the volumes ask for. A disagreement here fails nothing at
	// runtime: the Pod starts and the file is simply absent.
	data, err := secretFileData(req.SecretFiles)
	if err != nil {
		t.Fatalf("secretFileData: %v", err)
	}
	for key := range seen {
		if _, ok := data[key]; !ok {
			t.Errorf("volumes reference Secret key %q, which the Secret does not carry: %v", key, keysOf(data))
		}
	}
}

// --- Start ------------------------------------------------------------

// TestStart_SecretFilesTravelInASecretAndAreProjected is the delivery test: the
// exact bytes reach the cluster, and the Pod reads them back at the path the
// environment already names.
func TestStart_SecretFilesTravelInASecretAndAreProjected(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	spec := secretFileSpec()

	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	wantName := secretFilesSecretName(handle.ID)
	api.mu.Lock()
	sec := api.secrets[wantName]
	requests := append([]string(nil), api.requests...)
	api.mu.Unlock()
	if sec == nil {
		t.Fatalf("no Secret named %q; got %v", wantName, api.secretNames())
	}
	if sec.Type != "Opaque" {
		t.Errorf("Secret type = %q, want Opaque", sec.Type)
	}
	// Labelled like the Pod, so one selector finds everything the run left
	// behind.
	for _, key := range []string{LabelManaged, LabelExecutorID, LabelHandleID, LabelTaskID, LabelProject} {
		if sec.Metadata.Labels[key] == "" {
			t.Errorf("Secret label %s is empty; it cannot be traced back to its run", key)
		}
	}
	// The bytes, unchanged — including the ones that are not valid UTF-8.
	for i, f := range spec.SecretFiles {
		key := secretFileKey(0, f.Name)
		got, ok := sec.Data[key]
		if !ok {
			t.Fatalf("Secret has no key %q for file %s; keys = %v", key, f.Name, keysOf(sec.Data))
		}
		if string(got) != string(f.Content) {
			t.Errorf("secret_files[%d] arrived as %q, want %q", i, got, f.Content)
		}
	}

	// Created before the Pod: a Pod whose volume names a Secret that does not
	// exist yet sits in ContainerCreating instead of starting.
	secretAt, podAt := -1, -1
	for i, req := range requests {
		switch {
		case secretAt < 0 && strings.HasPrefix(req, "POST") && strings.Contains(req, "/secrets"):
			secretAt = i
		case podAt < 0 && strings.HasPrefix(req, "POST") && strings.HasSuffix(req, "/pods"):
			podAt = i
		}
	}
	if secretAt < 0 || podAt < 0 || secretAt > podAt {
		t.Errorf("request order = %v; the Secret must be created before the Pod", requests)
	}

	// The Pod itself: one volume, projecting the Secret read-only at the
	// spec'd directory, with the keys mapped back to the bare file names.
	name := api.onlyPodName(t)
	api.mu.Lock()
	created := *api.pods[name]
	api.mu.Unlock()

	vols := secretFileVolumesOf(&created)
	if len(vols) != 1 {
		t.Fatalf("got %d lease volumes, want 1: %+v", len(vols), created.Spec.Volumes)
	}
	src := vols[0].Secret
	if src.SecretName != wantName {
		t.Errorf("volume reads Secret %q, want %q", src.SecretName, wantName)
	}
	if src.DefaultMode == nil || *src.DefaultMode != secretFileMode {
		t.Errorf("defaultMode = %v, want %#o — the Pod sets fsGroup, so this lands as 0440 and "+
			"nothing wider", src.DefaultMode, secretFileMode)
	}
	if src.Optional == nil || *src.Optional {
		t.Error("optional must be false: a Pod that starts with an empty credential directory is " +
			"the failure this delivery exists to remove")
	}
	gotItems := map[string]string{}
	for _, it := range src.Items {
		gotItems[it.Key] = it.Path
	}
	wantItems := map[string]string{
		secretFileKey(0, "gitconfig"):    "gitconfig",
		secretFileKey(0, "github-token"): "github-token",
	}
	for key, path := range wantItems {
		if gotItems[key] != path {
			t.Errorf("items[%q] = %q, want %q — the workload's environment names the bare file",
				key, gotItems[key], path)
		}
	}

	var mount *volumeMount
	for i := range created.Spec.Containers[0].VolumeMounts {
		if created.Spec.Containers[0].VolumeMounts[i].Name == vols[0].Name {
			mount = &created.Spec.Containers[0].VolumeMounts[i]
		}
	}
	if mount == nil {
		t.Fatalf("the harness does not mount %s: %+v", vols[0].Name, created.Spec.Containers[0].VolumeMounts)
	}
	if mount.MountPath != leaseDir {
		t.Errorf("mountPath = %q, want %q verbatim — the environment already points there",
			mount.MountPath, leaseDir)
	}
	if !mount.ReadOnly {
		t.Error("the lease mount is writable: a credential helper the workload can rewrite answers " +
			"for repositories the grant excluded")
	}

	// And the credential is nowhere in the Pod object, which anyone with
	// `get pods` in the namespace can read.
	raw, _ := json.Marshal(created)
	if strings.Contains(string(raw), fakeLeaseToken) {
		t.Errorf("the created Pod contains the leased credential: %s", raw)
	}
}

// TestStart_SecretFilesAreDeletedWhenTheWorkloadFinishes: the material must not
// outlive the run. Unlike the workspace credential there is no earlier moment —
// a credential helper is invoked every time git talks to a remote — so the
// terminal state is the drop point.
func TestStart_SecretFilesAreDeletedWhenTheWorkloadFinishes(t *testing.T) {
	ex, api, leases := newTestExecutor(t, nil)

	handle, err := ex.Start(context.Background(), secretFileSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	wantName := secretFilesSecretName(handle.ID)
	if got := api.secretNames(); len(got) != 1 || got[0] != wantName {
		t.Fatalf("secrets while the run is live = %v, want exactly %q", got, wantName)
	}

	name := api.onlyPodName(t)
	api.run(name)
	api.terminate(name, 0, "Completed")
	if st := waitStatus(t, ex, handle.ID, 5*time.Second); st.State != executor.StateExited {
		t.Errorf("state = %q (%s), want exited", st.State, st.Error)
	}

	api.waitSecretsEmpty(t, 3*time.Second)
	if got := api.secretDeleteNames(); len(got) != 1 || got[0] != wantName {
		t.Errorf("secret deletes = %v, want exactly %q once", got, wantName)
	}
	leases.waitOutstandingEmpty(t, 2*time.Second)
}

// TestStart_SecretFilesAreDeletedWhenThePodCreateFails: the Secret exists
// before the Pod, so every failure between the two has to unwind it — otherwise
// a refused Start leaves live credentials in etcd with nothing to ever collect
// them.
func TestStart_SecretFilesAreDeletedWhenThePodCreateFails(t *testing.T) {
	ex, api, leases := newTestExecutor(t, nil)
	api.failAlways("POST /pods", apiFailure{Code: 403, Reason: "Forbidden", Message: "pods is forbidden"})

	if _, err := ex.Start(context.Background(), secretFileSpec()); err == nil {
		t.Fatal("Start succeeded despite the Pod create being refused")
	}
	if names := api.secretNames(); len(names) != 0 {
		t.Errorf("the credential Secret outlived the failed Start: %v", names)
	}
	if got := api.secretDeleteNames(); len(got) != 1 {
		t.Errorf("secret deletes = %v, want exactly one", got)
	}
	leases.waitOutstandingEmpty(t, 2*time.Second)
}

// TestStart_SecretFileNameThatCannotBeAKeyIsRefused. The API server would
// reject the object with a message about a field path; refusing here names the
// file instead, and refuses before anything reaches the cluster.
func TestStart_SecretFileNameThatCannotBeAKeyIsRefused(t *testing.T) {
	ex, api, leases := newTestExecutor(t, nil)
	spec := secretFileSpec()
	// A bare file name — executor.ValidateSecretFiles accepts it — that is not
	// a legal Secret key.
	spec.SecretFiles[0].Name = "git config"

	_, err := ex.Start(context.Background(), spec)
	if err == nil {
		t.Fatal("Start accepted a file name that cannot be a Secret key")
	}
	if !errors.Is(err, executor.ErrInvalidSpec) {
		t.Errorf("error %v does not wrap ErrInvalidSpec, so the API renders it as a server fault", err)
	}
	if !strings.Contains(err.Error(), "git config") {
		t.Errorf("error %v does not name the offending file", err)
	}
	if names := api.podNames(); len(names) != 0 {
		t.Errorf("a Pod was created despite the refusal: %v", names)
	}
	if names := api.secretNames(); len(names) != 0 {
		t.Errorf("a Secret was created despite the refusal: %v", names)
	}
	leases.waitOutstandingEmpty(t, 2*time.Second)
}

// TestCapabilities_SecretFiles guards the pair of claims placement reads. False
// on the first refuses a lease-dependent workload here (see
// executor.Requirements.RequireSecretFiles); true on the second would make the
// hub write plaintext to its own disk for a workload that runs on a node and
// can never read it.
func TestCapabilities_SecretFiles(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	caps := ex.Capabilities()
	if !caps.SupportsSecretFiles {
		t.Error("SupportsSecretFiles is false; a repo-scoped PAT delivers its whole enforcement as " +
			"files, and placement would refuse every such run on this driver")
	}
	if caps.SecretFilesFromHostPath {
		t.Error("SecretFilesFromHostPath is true; the hub would materialise plaintext on the " +
			"control plane for a Pod on a node that has never seen that filesystem")
	}
}

// --- helpers ----------------------------------------------------------

// secretFileVolumesOf returns the lease-projection volumes of a Pod.
func secretFileVolumesOf(p *pod) []volume {
	var out []volume
	for _, v := range p.Spec.Volumes {
		if v.Secret != nil {
			out = append(out, v)
		}
	}
	return out
}

func hasSecretFileMount(c container, dir string) bool {
	for _, m := range c.VolumeMounts {
		if m.MountPath == dir {
			return true
		}
	}
	return false
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
