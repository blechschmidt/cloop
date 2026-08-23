package kubernetes

// workspace_test.go covers getting a source tree into a Pod: the init
// container buildPod renders for it, the Secret the credential travels in, and
// the refusals that keep a run from starting against an empty directory.
//
// The tests that matter most are the negative ones. A run whose workspace
// silently did not arrive looks exactly like a run whose workspace did — same
// Pod, same phase transitions, plausible output — so "no Pod was created" and
// "the token is not in the object" are the assertions that have to hold, and
// they are written against the marshalled JSON and the fake API server's
// recorded requests rather than against the driver's own opinion of what it
// did.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// fakeWorkspaceToken is distinctive enough that finding it anywhere it should not be is
// unambiguous, and long enough that executor.RedactSecrets treats it as a
// credential rather than as ordinary text.
const fakeWorkspaceToken = "ghp-TOTALLY-FAKE-WORKSPACE-TOKEN-0123456789"

func gitWorkspace() executor.Workspace {
	return executor.Workspace{
		Kind:            executor.WorkspaceGit,
		Repo:            "https://github.com/acme/widgets.git",
		Ref:             "main",
		Depth:           1,
		CredentialGrant: "acme-pat",
	}
}

// --- fake credential source -------------------------------------------

// fakeWorkspaceSource is an executor.WorkspaceCredentialSource that hands out
// a canned token, or the typed refusal a missing grant produces.
type fakeWorkspaceSource struct {
	mu   sync.Mutex
	cred executor.GitCredential
	// repo, when set, is the routed URL the source redirects the workspace to,
	// as a git proxy would.
	repo     string
	err      error
	calls    int
	released int
}

func (s *fakeWorkspaceSource) ForWorkspace(ctx context.Context, projectID string,
	w executor.Workspace) (executor.WorkspaceAccess, func(), error) {

	s.mu.Lock()
	s.calls++
	cred, err := s.cred, s.err
	s.mu.Unlock()

	release := func() {
		s.mu.Lock()
		s.released++
		s.mu.Unlock()
	}
	if err != nil {
		// The contract says the release func is non-nil even on the error
		// path, and that a source which never leased anything must not report
		// a release. Returning the counting closure here would hide a driver
		// that released a lease it was never given.
		return executor.WorkspaceAccess{}, func() {}, err
	}
	return executor.WorkspaceAccess{Credential: cred, Repo: s.repo}, release, nil
}

func (s *fakeWorkspaceSource) counts() (calls, released int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.released
}

func workingSource() *fakeWorkspaceSource {
	return &fakeWorkspaceSource{cred: executor.GitCredential{
		Username:   "x-access-token",
		Password:   fakeWorkspaceToken,
		LeaseID:    "ws-lease-1",
		GrantID:    "grant-1",
		SecretName: "acme-pat",
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}}
}

func missingGrantSource() *fakeWorkspaceSource {
	return &fakeWorkspaceSource{err: &executor.WorkspaceGrantError{
		Repo:        "https://github.com/acme/widgets.git",
		RepoPath:    "acme/widgets",
		Grant:       "acme-pat",
		ExecutorID:  "k8s-test",
		ProjectPath: "/srv/app",
		Reason:      "no active GitHub grant authorises acme/widgets",
	}}
}

// --- fake API server: secrets -----------------------------------------

// routeSecret serves the two Secret calls this driver makes. It deliberately
// serves no GET: the driver has no read access to Secrets and a fake that
// answered one would let a regression that started reading them pass.
func (f *fakeAPI) routeSecret(w http.ResponseWriter, r *http.Request) {
	name := pathAfter(r.URL.Path, "secrets")
	switch {
	case r.Method == http.MethodPost && name == "":
		var in secret
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeStatus(w, 400, "BadRequest", "undecodable body: "+err.Error())
			return
		}
		if in.Metadata.Name == "" {
			writeStatus(w, 422, "Invalid", "metadata.name is required")
			return
		}
		f.mu.Lock()
		_, exists := f.secrets[in.Metadata.Name]
		if !exists {
			stored := in
			f.secrets[in.Metadata.Name] = &stored
		}
		f.mu.Unlock()
		if exists {
			writeStatus(w, 409, "AlreadyExists", fmt.Sprintf("secrets %q already exists", in.Metadata.Name))
			return
		}
		writeJSON(w, 201, in)

	case r.Method == http.MethodDelete && name != "":
		f.mu.Lock()
		_, ok := f.secrets[name]
		delete(f.secrets, name)
		f.secretDeletes = append(f.secretDeletes, name)
		f.mu.Unlock()
		if !ok {
			writeStatus(w, 404, "NotFound", fmt.Sprintf("secrets %q not found", name))
			return
		}
		writeJSON(w, 200, map[string]string{"kind": "Status", "status": "Success"})

	default:
		writeStatus(w, 405, "MethodNotAllowed", r.Method+" "+r.URL.Path)
	}
}

// pathAfter returns the segment following kind in a namespaced resource path,
// or "" for a collection URL.
func pathAfter(p, kind string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, seg := range parts {
		if seg == kind && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func (f *fakeAPI) secretNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.secrets))
	for name := range f.secrets {
		out = append(out, name)
	}
	return out
}

func (f *fakeAPI) secretDeleteNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.secretDeletes...)
}

// waitSecretsEmpty polls until no Secret remains, since the delete happens on
// the watcher or pump goroutine.
func (f *fakeAPI) waitSecretsEmpty(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if len(f.secretNames()) == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("workspace secrets still present after %s: %v — a brokered credential is sitting in the cluster",
		d, f.secretNames())
}

// requestsMatching returns every recorded request whose line contains sub.
func (f *fakeAPI) requestsMatching(sub string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, req := range f.requests {
		if strings.Contains(req, sub) {
			out = append(out, req)
		}
	}
	return out
}

// --- buildPod ---------------------------------------------------------

func workspaceRequest() podRequest {
	req := baseRequest()
	req.Workspace = gitWorkspace()
	req.WorkspaceSecretName = "cloop-ws-k-abc123"
	return req
}

// TestBuildPod_WorkspaceInitContainer is the shape assertion: exactly one init
// container, running the right command, mounting the writable volumes, with
// the credential reachable only by reference.
func TestBuildPod_WorkspaceInitContainer(t *testing.T) {
	p, err := buildPod(workspaceRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if len(p.Spec.InitContainers) != 1 {
		t.Fatalf("got %d init containers, want exactly 1", len(p.Spec.InitContainers))
	}
	init := p.Spec.InitContainers[0]
	if init.Name != InitContainerName {
		t.Errorf("init container name = %q, want %q", init.Name, InitContainerName)
	}
	// The same image as the harness, so it goes through the same image trust
	// policy and needs no second entry in an operator's registry allowlist.
	if init.Image != p.Spec.Containers[0].Image {
		t.Errorf("init image = %q, harness image = %q; they must be the same image",
			init.Image, p.Spec.Containers[0].Image)
	}

	gotArgv := append(append([]string(nil), init.Command...), init.Args...)
	wantArgv := []string{
		"cloop", "workspace", "provision",
		"--dir", PodWorkspace,
		"--repo", "https://github.com/acme/widgets.git",
		"--ref", "main",
		"--depth", "1",
	}
	if !reflect.DeepEqual(gotArgv, wantArgv) {
		t.Errorf("init argv =\n  %v\nwant\n  %v", gotArgv, wantArgv)
	}

	mounted := map[string]bool{}
	for _, m := range init.VolumeMounts {
		mounted[m.MountPath] = true
		if m.ReadOnly {
			t.Errorf("init mount %s is read-only; the provisioner has to write the tree", m.MountPath)
		}
	}
	for _, want := range []string{PodWorkspace, "/tmp"} {
		if !mounted[want] {
			t.Errorf("init container has no writable volume at %s", want)
		}
	}

	// The credential: present, and present only as a reference.
	var token *envVar
	for i := range init.Env {
		if init.Env[i].Name == EnvWorkspaceToken {
			token = &init.Env[i]
		}
	}
	if token == nil {
		t.Fatalf("init container has no %s; env = %+v", EnvWorkspaceToken, init.Env)
	}
	if token.Value != "" {
		t.Errorf("%s carries an inline value (%q); a credential must only ever arrive by secretKeyRef",
			EnvWorkspaceToken, token.Value)
	}
	if token.ValueFrom == nil || token.ValueFrom.SecretKeyRef == nil {
		t.Fatalf("%s has no valueFrom.secretKeyRef", EnvWorkspaceToken)
	}
	ref := token.ValueFrom.SecretKeyRef
	if ref.Name != "cloop-ws-k-abc123" || ref.Key != EnvWorkspaceToken {
		t.Errorf("secretKeyRef = %+v, want name cloop-ws-k-abc123 key %s", ref, EnvWorkspaceToken)
	}
}

// TestBuildPod_WorkspaceInitConfinementMatchesHarness: the provisioner handles
// the credential, so it must be at least as confined as the code that does
// not. Comparing the two structs rather than re-listing the fields is what
// makes a future field added to one and forgotten on the other fail here.
func TestBuildPod_WorkspaceInitConfinementMatchesHarness(t *testing.T) {
	p, err := buildPod(workspaceRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	harness := p.Spec.Containers[0].SecurityContext
	init := p.Spec.InitContainers[0].SecurityContext
	if harness == nil || init == nil {
		t.Fatal("both containers must carry a securityContext")
	}
	if !reflect.DeepEqual(harness, init) {
		hb, _ := json.Marshal(harness)
		ib, _ := json.Marshal(init)
		t.Errorf("the init container's confinement differs from the harness's:\n  harness: %s\n  init:    %s", hb, ib)
	}
	// Spot-check the properties the comparison would happily agree on if both
	// were wrong.
	if init.RunAsNonRoot == nil || !*init.RunAsNonRoot {
		t.Error("init runAsNonRoot must be true")
	}
	if init.ReadOnlyRootFilesystem == nil || !*init.ReadOnlyRootFilesystem {
		t.Error("init readOnlyRootFilesystem must be true")
	}
	if init.AllowPrivilegeEscalation == nil || *init.AllowPrivilegeEscalation {
		t.Error("init allowPrivilegeEscalation must be explicitly false")
	}
	if init.Capabilities == nil || len(init.Capabilities.Drop) != 1 || init.Capabilities.Drop[0] != "ALL" {
		t.Errorf("init capabilities = %+v, want drop: [ALL]", init.Capabilities)
	}
	if init.SeccompProfile == nil || init.SeccompProfile.Type != "RuntimeDefault" {
		t.Error("init seccompProfile must be RuntimeDefault")
	}
}

// TestBuildPod_WorkspaceTokenIsNotInThePodObject is the security assertion the
// whole delivery design exists for. Anyone with `get pods` in the namespace
// reads this object; the token must not be in it in any form, including the
// base64 the Secret API would have produced.
func TestBuildPod_WorkspaceTokenIsNotInThePodObject(t *testing.T) {
	req := workspaceRequest()
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(data)
	forbidden := map[string]string{
		"the raw token":              fakeWorkspaceToken,
		"its base64 form":            base64.StdEncoding.EncodeToString([]byte(fakeWorkspaceToken)),
		"a rendered basic header":    base64.StdEncoding.EncodeToString([]byte("x-access-token:" + fakeWorkspaceToken)),
		"the URL-embedded userinfo":  "x-access-token:" + fakeWorkspaceToken,
		"an Authorization extraHead": "extraHeader",
	}
	for what, needle := range forbidden {
		if strings.Contains(body, needle) {
			t.Errorf("the Pod object contains %s (%q). Anyone with `get pods` in the namespace can read it",
				what, needle)
		}
	}
	// And the reference that replaces it is there, so the test cannot pass by
	// the credential simply not being wired at all.
	if !strings.Contains(body, `"secretKeyRef"`) {
		t.Errorf("the Pod object has no secretKeyRef; the credential is not being delivered: %s", body)
	}
}

// TestBuildPod_WorkspaceInitDoesNotInheritEnv: the harness's environment holds
// brokered provider keys. A git fetch has no use for any of them, and the
// narrower the provisioner's environment the less a hostile repository's hooks
// can reach.
func TestBuildPod_WorkspaceInitDoesNotInheritEnv(t *testing.T) {
	req := workspaceRequest()
	req.Env = []string{"ANTHROPIC_API_KEY=sk-secret-value", "PATH=/usr/bin"}
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	for _, ev := range p.Spec.InitContainers[0].Env {
		switch ev.Name {
		case EnvWorkspaceToken, EnvWorkspaceUser:
		default:
			t.Errorf("init container inherited %q from the harness environment", ev.Name)
		}
	}
	// The harness still gets it: this is about scope, not about dropping it.
	if len(p.Spec.Containers[0].Env) != 2 {
		t.Errorf("harness env = %+v, want the Spec's two variables", p.Spec.Containers[0].Env)
	}
}

// TestBuildPod_WorkspaceWithoutSecretIsUnauthenticated: a public repository
// needs no grant, and the Pod must reflect that rather than referencing a
// Secret nobody created — which the kubelet answers with
// CreateContainerConfigError and a retry loop.
func TestBuildPod_WorkspaceWithoutSecretIsUnauthenticated(t *testing.T) {
	req := workspaceRequest()
	req.WorkspaceSecretName = ""
	req.Workspace.CredentialGrant = ""
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	for _, ev := range p.Spec.InitContainers[0].Env {
		if ev.Name == EnvWorkspaceToken {
			t.Fatalf("an unauthenticated fetch must set no %s at all, got %+v", EnvWorkspaceToken, ev)
		}
	}
	data, _ := json.Marshal(p)
	if strings.Contains(string(data), "secretKeyRef") {
		t.Errorf("the Pod references a Secret that was never created: %s", data)
	}
}

// TestBuildPod_NoWorkspaceNoInitContainer: the kinds that need nothing must
// leave the Pod exactly as it was, or every existing run grows a container.
func TestBuildPod_NoWorkspaceNoInitContainer(t *testing.T) {
	for _, kind := range []executor.WorkspaceKind{executor.WorkspaceUnspecified, executor.WorkspaceNone} {
		t.Run(string("kind="+kind), func(t *testing.T) {
			req := baseRequest()
			req.Workspace = executor.Workspace{Kind: kind}
			p, err := buildPod(req)
			if err != nil {
				t.Fatalf("buildPod: %v", err)
			}
			if len(p.Spec.InitContainers) != 0 {
				t.Errorf("kind %q produced %d init containers, want none", kind, len(p.Spec.InitContainers))
			}
			data, _ := json.Marshal(p)
			if strings.Contains(string(data), "initContainers") {
				t.Errorf("an empty init container list must be omitted from the JSON: %s", data)
			}
		})
	}
}

// TestBuildPod_RejectsBindWorkspace: bind means "the tree is already here
// because we share the control plane's filesystem". A Pod does not, so
// accepting it would start the harness in an empty emptyDir — the exact bug
// Spec.Workspace exists to make impossible.
func TestBuildPod_RejectsBindWorkspace(t *testing.T) {
	req := baseRequest()
	req.Workspace = executor.Workspace{Kind: executor.WorkspaceBind}
	_, err := buildPod(req)
	if err == nil {
		t.Fatal("buildPod accepted a bind workspace; a Pod shares no filesystem with the control plane")
	}
	if !errors.Is(err, executor.ErrInvalidSpec) {
		t.Errorf("error %v does not wrap ErrInvalidSpec", err)
	}
	for _, want := range []string{"bind", "git", "none"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q, so it does not say what to do instead", err, want)
		}
	}
}

// TestBuildPod_WorkspaceSizeLimit: a project's own disk allowance is more
// specific than the executor's default, so it must win — and it must reach the
// emptyDir, which is the only thing that actually bounds the tree.
func TestBuildPod_WorkspaceSizeLimit(t *testing.T) {
	req := workspaceRequest()
	req.WorkspaceSizeLimit = "1Gi"
	req.Workspace.SizeLimitMB = 256

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	var ws *volume
	for i := range p.Spec.Volumes {
		if p.Spec.Volumes[i].Name == workspaceVolume {
			ws = &p.Spec.Volumes[i]
		}
	}
	if ws == nil || ws.EmptyDir == nil {
		t.Fatalf("no workspace emptyDir in %+v", p.Spec.Volumes)
	}
	if ws.EmptyDir.SizeLimit != "256Mi" {
		t.Errorf("workspace sizeLimit = %q, want 256Mi (the Spec's limit beats the executor default)",
			ws.EmptyDir.SizeLimit)
	}
	// The provisioner is told the same number so it can fail the fetch with an
	// explanation instead of letting the kubelet evict the Pod mid-run.
	argv := strings.Join(append(append([]string(nil), p.Spec.InitContainers[0].Command...),
		p.Spec.InitContainers[0].Args...), " ")
	if !strings.Contains(argv, "--size-limit-mb 256") {
		t.Errorf("init argv %q does not carry the size limit", argv)
	}

	// With no Spec limit the executor's configured default still applies.
	req.Workspace.SizeLimitMB = 0
	p, err = buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if got := p.Spec.Volumes[0].EmptyDir.SizeLimit; got != "1Gi" {
		t.Errorf("workspace sizeLimit = %q, want the executor default 1Gi", got)
	}
}

// TestWorkspaceCommand covers the one guess this driver makes about the image:
// where cloop lives inside it.
func TestWorkspaceCommand(t *testing.T) {
	cases := map[string]struct {
		argv []string
		want string
	}{
		"absolute cloop is believed":   {[]string{"/usr/local/bin/cloop", "run"}, "/usr/local/bin/cloop"},
		"custom absolute cloop":        {[]string{"/opt/cloop/bin/cloop"}, "/opt/cloop/bin/cloop"},
		"bare name falls back to PATH": {[]string{"cloop", "run"}, "cloop"},
		// An interpreter is not the harness binary; `/bin/sh workspace
		// provision` would fail in a way that points at the wrong subsystem.
		"interpreter is not adopted": {[]string{"/bin/sh", "-c", "cloop run"}, "cloop"},
		"empty argv":                 {nil, "cloop"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := workspaceCommand(tc.argv); got != tc.want {
				t.Errorf("workspaceCommand(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// --- Start ------------------------------------------------------------

func workspaceSpec() executor.Spec {
	spec := testSpec()
	spec.Workspace = gitWorkspace()
	return spec
}

// TestStart_WorkspaceGrantMissingCreatesNothing is the refusal that matters.
// A run whose credential could not be leased must not reach the cluster at
// all: no Pod, because a Pod would produce a transcript of work done against
// an empty directory, and no Secret, because there was nothing to put in one.
func TestStart_WorkspaceGrantMissingCreatesNothing(t *testing.T) {
	src := missingGrantSource()
	ex, api, leases := newTestExecutor(t, func(o *Options) { o.Workspace = src })

	_, err := ex.Start(context.Background(), workspaceSpec())
	if err == nil {
		t.Fatal("Start succeeded without a workspace credential; the run would have operated on an empty tree")
	}
	if !errors.Is(err, executor.ErrWorkspaceGrantMissing) {
		t.Errorf("error %v does not match ErrWorkspaceGrantMissing", err)
	}
	var grantErr *executor.WorkspaceGrantError
	if !errors.As(err, &grantErr) {
		t.Fatalf("error %v is not a *executor.WorkspaceGrantError; the UI cannot render its remediation", err)
	}
	if grantErr.RepoPath != "acme/widgets" {
		t.Errorf("grant error names repo %q, want acme/widgets", grantErr.RepoPath)
	}
	if fix := grantErr.Remediation(); !strings.Contains(fix, "cloop secret grant") {
		t.Errorf("remediation %q does not print the command that fixes it", fix)
	}

	if names := api.podNames(); len(names) != 0 {
		t.Errorf("a Pod was created despite the refusal: %v", names)
	}
	if names := api.secretNames(); len(names) != 0 {
		t.Errorf("a Secret was created despite the refusal: %v", names)
	}
	if got := api.requestsMatching("POST"); len(got) != 0 {
		t.Errorf("the driver wrote to the cluster despite refusing the run: %v", got)
	}
	// The kubeconfig lease is still released, or a refused Start leaks a
	// credential the broker believes is held.
	leases.waitOutstandingEmpty(t, 2*time.Second)
}

// TestStart_WorkspaceSecretDeliversTheCredential walks the successful path:
// the Secret exists before the Pod, carries the bare token under the env var's
// own name, and the Pod references it without containing it.
func TestStart_WorkspaceSecretDeliversTheCredential(t *testing.T) {
	src := workingSource()
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = src })

	handle, err := ex.Start(context.Background(), workspaceSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	api.mu.Lock()
	stored := make(map[string]*secret, len(api.secrets))
	for k, v := range api.secrets {
		stored[k] = v
	}
	requests := append([]string(nil), api.requests...)
	api.mu.Unlock()

	if len(stored) != 1 {
		t.Fatalf("got %d workspace secrets, want exactly 1: %v", len(stored), api.secretNames())
	}
	wantName := workspaceSecretName(handle.ID)
	sec, ok := stored[wantName]
	if !ok {
		t.Fatalf("no Secret named %q; got %v", wantName, api.secretNames())
	}
	if sec.StringData[EnvWorkspaceToken] != fakeWorkspaceToken {
		t.Errorf("Secret carries %q under %s, want the bare token",
			sec.StringData[EnvWorkspaceToken], EnvWorkspaceToken)
	}
	// Labelled like the Pod, so an operator can find both with one selector.
	for _, key := range []string{LabelManaged, LabelExecutorID, LabelHandleID, LabelTaskID} {
		if sec.Metadata.Labels[key] == "" {
			t.Errorf("Secret label %s is empty; it cannot be traced back to its run", key)
		}
	}

	// The Secret is POSTed before the Pod: an init container whose secretKeyRef
	// names an object that does not exist yet sits in CreateContainerConfigError.
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

	// The Pod object itself is clean.
	name := api.onlyPodName(t)
	api.mu.Lock()
	raw, _ := json.Marshal(api.pods[name])
	api.mu.Unlock()
	if strings.Contains(string(raw), fakeWorkspaceToken) {
		t.Errorf("the created Pod contains the token: %s", raw)
	}

	// The broker lease is released as soon as the material is in the cluster,
	// not held for the length of the run.
	calls, released := src.counts()
	if calls != 1 {
		t.Errorf("ForWorkspace called %d times, want 1", calls)
	}
	if released != 1 {
		t.Errorf("workspace lease released %d times, want 1 — the cluster holds the material now", released)
	}
}

// TestStart_WorkspaceSecretIsDeletedWhenTheInitContainerFinishes: the material
// must stop existing when its one consumer is done, not when the run is.
func TestStart_WorkspaceSecretIsDeletedWhenTheInitContainerFinishes(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })

	handle, err := ex.Start(context.Background(), workspaceSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	if len(api.secretNames()) != 1 {
		t.Fatalf("expected the credential Secret to exist while the Pod is Pending, got %v", api.secretNames())
	}

	// The Pod is still Pending — only the init container has finished.
	api.finishInitContainer(name, 0, "Completed")
	api.waitSecretsEmpty(t, 3*time.Second)
	if got := api.secretDeleteNames(); len(got) != 1 || got[0] != workspaceSecretName(handle.ID) {
		t.Errorf("secret deletes = %v, want exactly %q", got, workspaceSecretName(handle.ID))
	}

	api.run(name)
	api.terminate(name, 0, "Completed")
	if st := waitStatus(t, ex, handle.ID, 5*time.Second); st.State != executor.StateExited {
		t.Errorf("state = %q (%s), want exited", st.State, st.Error)
	}
	// And no second delete once the workload finishes: the backstop in finish()
	// must be idempotent, not a spare API call per run.
	if got := api.secretDeleteNames(); len(got) != 1 {
		t.Errorf("secret deletes = %v, want the delete to happen exactly once", got)
	}
}

// TestStart_WorkspaceSecretIsDeletedWhenTheWorkloadFinishes covers the
// backstop: a Pod that never reports an init container status — deleted before
// it scheduled, a watch that lost the transition — must still not leave a
// brokered credential behind.
func TestStart_WorkspaceSecretIsDeletedWhenTheWorkloadFinishes(t *testing.T) {
	ex, api, leases := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })

	handle, err := ex.Start(context.Background(), workspaceSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	if len(api.secretNames()) != 1 {
		t.Fatalf("expected one credential Secret, got %v", api.secretNames())
	}

	api.run(name)
	api.terminate(name, 0, "Completed")
	if st := waitStatus(t, ex, handle.ID, 5*time.Second); st.State != executor.StateExited {
		t.Errorf("state = %q (%s), want exited", st.State, st.Error)
	}
	api.waitSecretsEmpty(t, 3*time.Second)
	leases.waitOutstandingEmpty(t, 2*time.Second)
}

// TestStart_WorkspaceSecretIsDeletedWhenThePodCreateFails: the Secret exists
// before the Pod, so every failure between the two has to unwind it.
func TestStart_WorkspaceSecretIsDeletedWhenThePodCreateFails(t *testing.T) {
	ex, api, leases := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })
	api.failAlways("POST /pods", apiFailure{Code: 403, Reason: "Forbidden", Message: "pods is forbidden"})

	if _, err := ex.Start(context.Background(), workspaceSpec()); err == nil {
		t.Fatal("Start succeeded despite the Pod create being refused")
	}
	if names := api.secretNames(); len(names) != 0 {
		t.Errorf("the credential Secret outlived the failed Start: %v", names)
	}
	leases.waitOutstandingEmpty(t, 2*time.Second)
}

// TestStart_WorkspaceWithoutCredentialSource: a nil source is not an error for
// a public repository — the fetch simply runs unauthenticated — but a Spec
// that named a grant must be refused rather than started against a repository
// it cannot authenticate.
func TestStart_WorkspaceWithoutCredentialSource(t *testing.T) {
	t.Run("public repo starts", func(t *testing.T) {
		ex, api, _ := newTestExecutor(t, nil)
		spec := workspaceSpec()
		spec.Workspace.CredentialGrant = ""

		if _, err := ex.Start(context.Background(), spec); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if names := api.secretNames(); len(names) != 0 {
			t.Errorf("an unauthenticated fetch created a Secret: %v", names)
		}
		name := api.onlyPodName(t)
		api.mu.Lock()
		p := api.pods[name]
		initCount := len(p.Spec.InitContainers)
		api.mu.Unlock()
		if initCount != 1 {
			t.Errorf("got %d init containers, want 1 — the tree still has to be fetched", initCount)
		}
	})

	t.Run("private repo is refused", func(t *testing.T) {
		ex, api, leases := newTestExecutor(t, nil)
		_, err := ex.Start(context.Background(), workspaceSpec())
		if err == nil {
			t.Fatal("Start succeeded with a grant nothing could honour")
		}
		if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
			t.Errorf("error %v does not wrap ErrWorkspaceUnavailable", err)
		}
		if names := api.podNames(); len(names) != 0 {
			t.Errorf("a Pod was created anyway: %v", names)
		}
		leases.waitOutstandingEmpty(t, 2*time.Second)
	})
}

// TestStart_RejectsBindWorkspace: the refusal has to survive the whole Start
// path, not just buildPod, and must leave nothing behind.
func TestStart_RejectsBindWorkspace(t *testing.T) {
	ex, api, leases := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })
	spec := testSpec()
	spec.Workspace = executor.Workspace{Kind: executor.WorkspaceBind}

	_, err := ex.Start(context.Background(), spec)
	if err == nil {
		t.Fatal("Start accepted a bind workspace on a driver that shares no filesystem")
	}
	if !errors.Is(err, executor.ErrInvalidSpec) {
		t.Errorf("error %v does not wrap ErrInvalidSpec", err)
	}
	if names := api.podNames(); len(names) != 0 {
		t.Errorf("a Pod was created anyway: %v", names)
	}
	leases.waitOutstandingEmpty(t, 2*time.Second)
}

// TestWorkspaceAuditTrail: provisioning is the moment a brokered credential is
// used against an external service, so it gets its own rows — and they must
// name the grant without ever carrying the material.
func TestWorkspaceAuditTrail(t *testing.T) {
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

	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })
	handle, err := ex.Start(context.Background(), workspaceSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.finishInitContainer(name, 0, "Completed")
	api.waitSecretsEmpty(t, 3*time.Second)
	api.run(name)
	api.terminate(name, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)

	mu.Lock()
	defer mu.Unlock()
	var starts, ends int
	for _, ev := range events {
		switch ev.Phase {
		case executor.WorkspaceProvisionStart:
			starts++
			// The start row precedes the lease — it has to, or a lease that
			// fails would produce an end with no matching start — so it names
			// the grant the Spec *asked* for rather than a resolved ID.
			if ev.Workspace.CredentialGrant != "acme-pat" {
				t.Errorf("start row names grant %q, want acme-pat", ev.Workspace.CredentialGrant)
			}
		case executor.WorkspaceProvisionEnd:
			ends++
			// The end row names what was actually used, which is the question
			// an operator has after an incident.
			if ev.GrantID != "grant-1" || ev.LeaseID != "ws-lease-1" {
				t.Errorf("end row names grant %q lease %q, want grant-1/ws-lease-1", ev.GrantID, ev.LeaseID)
			}
			if ev.DurationMS < 0 {
				t.Errorf("end row duration = %dms", ev.DurationMS)
			}
			if ev.Err != "" {
				t.Errorf("end row reports an error for a successful fetch: %q", ev.Err)
			}
		}
		if ev.ExecutorKind != executor.KindKubernetes {
			t.Errorf("event kind = %q, want %q", ev.ExecutorKind, executor.KindKubernetes)
		}
		if ev.HandleID != handle.ID {
			t.Errorf("event handle = %q, want %q", ev.HandleID, handle.ID)
		}
		if ev.ProjectPath != "/srv/app" {
			t.Errorf("event project = %q, want /srv/app", ev.ProjectPath)
		}
		blob, _ := json.Marshal(ev)
		if strings.Contains(string(blob), fakeWorkspaceToken) {
			t.Errorf("an audit row carries the credential: %s", blob)
		}
	}
	if starts != 1 {
		t.Errorf("got %d start events, want 1", starts)
	}
	if ends != 1 {
		t.Errorf("got %d end events, want exactly 1 — a double-counted compliance trail is worse than none", ends)
	}
}

// TestClassifyPod_FailedWorkspaceInitContainer: a tree that could not be
// fetched must not be reported as a harness failure. None of the task's code
// ran, and the remedy is a grant or a ref, not anything in the repository.
func TestClassifyPod_FailedWorkspaceInitContainer(t *testing.T) {
	p := &pod{Status: podStatus{
		Phase: phaseFailed,
		InitContainerStatuses: []containerStatus{{
			Name: InitContainerName,
			State: containerState{Terminated: &stateTerminated{
				ExitCode: 3, Reason: "Error",
				Message: "fatal: could not read Username for 'https://github.com'",
			}},
		}},
		ContainerStatuses: []containerStatus{{
			Name:  ContainerName,
			State: containerState{Waiting: &stateWaiting{Reason: "PodInitializing"}},
		}},
	}}
	state, code, msg := classifyPod(p)
	if state != executor.StateFailed {
		t.Errorf("state = %q, want failed", state)
	}
	if code != 3 {
		t.Errorf("exit code = %d, want the provisioner's 3", code)
	}
	if !strings.Contains(msg, "workspace could not be provisioned") {
		t.Errorf("message %q does not name the workspace as the cause", msg)
	}
	if strings.Contains(msg, "PodInitializing") {
		t.Errorf("message %q reports the harness's placeholder state instead of the real cause", msg)
	}
}

// TestStart_FailedProvisioningIsReportedAndCleanedUp walks the whole failure:
// the init container exits non-zero, the run reports the workspace as the
// cause, and the credential is gone regardless.
func TestStart_FailedProvisioningIsReportedAndCleanedUp(t *testing.T) {
	ex, api, leases := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })

	handle, err := ex.Start(context.Background(), workspaceSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.finishInitContainer(name, 128, "Error")
	api.setPhase(name, func(p *pod) {
		p.Status.Phase = phaseFailed
		p.Status.ContainerStatuses = []containerStatus{{
			Name:  ContainerName,
			State: containerState{Waiting: &stateWaiting{Reason: "PodInitializing"}},
		}}
	})

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateFailed {
		t.Errorf("state = %q (%s), want failed", st.State, st.Error)
	}
	if !strings.Contains(st.Error, "workspace could not be provisioned") {
		t.Errorf("error %q does not name the workspace as the cause", st.Error)
	}
	api.waitSecretsEmpty(t, 3*time.Second)
	leases.waitOutstandingEmpty(t, 2*time.Second)
}

// TestCapabilities_WorkspaceProvisioning: placement refuses a git workspace on
// any executor that does not advertise this, so a false here silently makes
// every Kubernetes run with a repository unschedulable.
func TestCapabilities_WorkspaceProvisioning(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	if !ex.Capabilities().SupportsWorkspaceProvisioning {
		t.Error("SupportsWorkspaceProvisioning must be true: this driver fetches the tree with an init container")
	}
	// True even without a credential source, because a public repository needs
	// no credential and refusing it at placement would be the wrong error.
	withSource, _, _ := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })
	if !withSource.Capabilities().SupportsWorkspaceProvisioning {
		t.Error("SupportsWorkspaceProvisioning must not depend on Options.Workspace")
	}
}

// TestPreflight_WorkspaceFinding: a missing credential source is a warning an
// operator sees before a private clone fails inside a Pod.
func TestPreflight_WorkspaceFinding(t *testing.T) {
	for name, tc := range map[string]struct {
		source    executor.WorkspaceCredentialSource
		wantLevel string
	}{
		"no source warns": {nil, LevelWarn},
		"source is ok":    {workingSource(), LevelOK},
	} {
		t.Run(name, func(t *testing.T) {
			ex, _, _ := newTestExecutor(t, func(o *Options) { o.Workspace = tc.source })
			report := ex.Preflight(context.Background())
			var found *Finding
			for i := range report.Findings {
				if report.Findings[i].Name == "workspace" {
					found = &report.Findings[i]
				}
			}
			if found == nil {
				t.Fatalf("no workspace finding in %+v", report.Findings)
			}
			if found.Level != tc.wantLevel {
				t.Errorf("workspace finding level = %q, want %q (%s)", found.Level, tc.wantLevel, found.Message)
			}
			if tc.wantLevel == LevelWarn && !strings.Contains(found.Fix, "cloop secret grant") {
				t.Errorf("the warning does not say how to fix it: %+v", found)
			}
		})
	}
}

// TestExplainSecretFailure: a 403 on Secrets is the failure an operator hits
// when upgrading a hub whose Role predates workspace provisioning, and the
// message has to be the rule, not a reminder that RBAC exists.
func TestExplainSecretFailure(t *testing.T) {
	err := explainSecretFailure("cloop", "cloop-ws-k-1",
		&APIError{Code: http.StatusForbidden, Verb: "POST", Path: "/api/v1/namespaces/cloop/secrets",
			Message: "secrets is forbidden"})
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error %v does not wrap ErrWorkspaceUnavailable", err)
	}
	for _, want := range []string{`resources: ["secrets"]`, `verbs: ["create", "delete"]`, "never"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	// And it must not ask for read access, which is the objection any reviewer
	// of an RBAC change touching Secrets raises first.
	for _, forbidden := range []string{`"get"`, `"list"`, `"watch"`} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("the remediation asks for %s on Secrets; the driver never reads one back", forbidden)
		}
	}
}
