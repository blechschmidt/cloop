package kubernetes

// leaseenv_test.go covers the workload's environment reaching its Pod by
// reference (Task 20401): every value in the lease Secret, every variable in the
// harness container a secretKeyRef to it, and not one value in the Pod object.
//
// The assertions resolve the Pod's environment the way a kubelet does — each
// reference looked up in the Secret's data, a missing Secret or key a refusal —
// rather than trusting that a reference "looks right". A reference to a key the
// Secret does not carry is admitted by the API server and fails only when the
// kubelet creates the container, so the only test that catches it is one that
// does what the kubelet does.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// leasedEnv is the environment a lease hands a sandboxed run, one of each kind
// the threat model names: an env secret's keys — the harness login among them,
// which is the only way a Pod gets one — a GitHub token for a grant over every
// repository, an egress session's credentialed proxy URL in all four
// variables, the redaction declaration, and a constraint that is not secret at
// all. Every value is distinctive enough that finding it anywhere is
// unambiguous.
func leasedEnv() []string {
	proxy := "http://egress-session-7f3a:EGRESS-SESSION-TOKEN-4242@hub.cloop.svc:3128"
	return []string{
		"CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-LEASED-OAUTH-TOKEN-000111222333",
		"ANTHROPIC_API_KEY=sk-ant-api03-LEASED-API-KEY-444555666777",
		"GITHUB_TOKEN=ghs_LEASEDGITHUBTOKEN0123456789abcdefABCDEF",
		"GH_TOKEN=ghs_LEASEDGITHUBTOKEN0123456789abcdefABCDEF",
		"HTTP_PROXY=" + proxy,
		"HTTPS_PROXY=" + proxy,
		"http_proxy=" + proxy,
		"https_proxy=" + proxy,
		"NO_PROXY=hub.cloop.svc",
		"CLOOP_REDACT_ENV=CLAUDE_CODE_OAUTH_TOKEN,ANTHROPIC_API_KEY,GITHUB_TOKEN,GH_TOKEN,HTTP_PROXY,HTTPS_PROXY",
		"CLOOP_GITHUB_REPO_ALLOWLIST=*",
	}
}

// leasedEnvSecrets are the values in leasedEnv that are credentials.
func leasedEnvSecrets() []string {
	return []string{
		"sk-ant-oat01-LEASED-OAUTH-TOKEN-000111222333",
		"sk-ant-api03-LEASED-API-KEY-444555666777",
		"ghs_LEASEDGITHUBTOKEN0123456789abcdefABCDEF",
		"EGRESS-SESSION-TOKEN-4242",
	}
}

// resolveEnv resolves a container's environment the way the kubelet does:
// a plain value as written, a secretKeyRef by looking the key up in the named
// Secret. A reference to a Secret or a key that is not there fails the test,
// because on a node it holds the container in CreateContainerConfigError.
func resolveEnv(t *testing.T, c container, secrets map[string]map[string][]byte) map[string]string {
	t.Helper()
	out := make(map[string]string, len(c.Env))
	for _, e := range c.Env {
		if e.ValueFrom == nil {
			out[e.Name] = e.Value
			continue
		}
		ref := e.ValueFrom.SecretKeyRef
		if ref == nil {
			t.Fatalf("container %s: %s has a valueFrom with no secretKeyRef", c.Name, e.Name)
		}
		if e.Value != "" {
			t.Errorf("container %s: %s carries both a value and a reference", c.Name, e.Name)
		}
		data, ok := secrets[ref.Name]
		if !ok {
			t.Fatalf("container %s: %s references Secret %q, which does not exist (have %v)",
				c.Name, e.Name, ref.Name, secretMapNames(secrets))
		}
		v, ok := data[ref.Key]
		if !ok {
			t.Fatalf("container %s: %s references key %q, which Secret %q does not carry (keys %v)",
				c.Name, e.Name, ref.Key, ref.Name, keysOf(data))
		}
		out[e.Name] = string(v)
	}
	return out
}

func secretMapNames(m map[string]map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// envMap turns K=V entries into a map.
func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		out[k] = v
	}
	return out
}

// driverGitEnv is the git configuration buildPod adds on its own to a request
// with no CA bundle and no GIT_CONFIG_* entries of its own.
var driverGitEnv = map[string]string{
	"GIT_CONFIG_COUNT":   "1",
	"GIT_CONFIG_KEY_0":   "safe.directory",
	"GIT_CONFIG_VALUE_0": PodWorkspace,
}

// --- buildPod ---------------------------------------------------------

// TestBuildPod_EnvIsDeliveredByReference is the shape assertion. Every Spec
// variable is a secretKeyRef to its own env.<NAME> key in the lease Secret,
// required rather than optional; the only plain values are the driver's own git
// configuration; and resolving the references against the data the create path
// would write reproduces the Spec's environment exactly.
func TestBuildPod_EnvIsDeliveredByReference(t *testing.T) {
	req := baseRequest()
	req.Env = leasedEnv()
	req.LeaseSecretName = "cloop-lease-k-abc123"

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	harness := p.Spec.Containers[0]
	spec := envMap(req.Env)
	for _, e := range harness.Env {
		if _, fromSpec := spec[e.Name]; !fromSpec {
			if want, own := driverGitEnv[e.Name]; !own || e.Value != want {
				t.Errorf("%s=%q is neither a Spec variable nor the driver's own git configuration", e.Name, e.Value)
			}
			continue
		}
		if e.Value != "" || e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
			t.Errorf("%s is not delivered by reference: %+v", e.Name, e)
			continue
		}
		ref := e.ValueFrom.SecretKeyRef
		if ref.Name != req.LeaseSecretName || ref.Key != "env."+e.Name {
			t.Errorf("%s references %s/%s, want %s/env.%s", e.Name, ref.Name, ref.Key, req.LeaseSecretName, e.Name)
		}
		if ref.Optional == nil || *ref.Optional {
			t.Errorf("%s's reference is optional (%v); a missing key would start the harness without "+
				"the variable instead of holding it where the driver can name the cause", e.Name, ref.Optional)
		}
	}

	data, err := leaseSecretData(req.SecretFiles, req.Env)
	if err != nil {
		t.Fatalf("leaseSecretData: %v", err)
	}
	got := resolveEnv(t, harness, map[string]map[string][]byte{req.LeaseSecretName: data})
	for name, want := range spec {
		if got[name] != want {
			t.Errorf("%s resolves to %q, want %q", name, got[name], want)
		}
	}
	for name, want := range driverGitEnv {
		if got[name] != want {
			t.Errorf("%s resolves to %q, want the driver's %q", name, got[name], want)
		}
	}
	if len(got) != len(spec)+len(driverGitEnv) {
		t.Errorf("harness environment has %d variables, want the Spec's %d plus the driver's %d: %v",
			len(got), len(spec), len(driverGitEnv), got)
	}
	// And the Secret carries nothing the Pod does not read: an env key no
	// reference names is a credential parked in etcd for nobody.
	referenced := map[string]bool{}
	for _, e := range harness.Env {
		if e.ValueFrom != nil {
			referenced[e.ValueFrom.SecretKeyRef.Key] = true
		}
	}
	for key := range data {
		if !referenced[key] {
			t.Errorf("the lease Secret carries %q, which no variable references", key)
		}
	}
}

// TestBuildPod_NoLeasedEnvValueInThePodObject is the property the task exists
// for, asserted on the bytes: no value of a leased env secret — nor its base64
// form — appears anywhere in the object a `get pods` returns.
func TestBuildPod_NoLeasedEnvValueInThePodObject(t *testing.T) {
	req := workspaceRequest()
	req.Env = leasedEnv()
	req.LeaseSecretName = "cloop-lease-k-abc123"
	req.SecretFiles = secretFileSpec().SecretFiles
	req.WriteBack = executor.WriteBack{Mode: executor.WriteBackPush, Branch: "cloop/task-42"}
	req.Workspace.Ref = strings.Repeat("a", 40)

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertNoLeakedEnv(t, "the Pod object", string(raw))

	// Absence alone is also what a Pod that forgot the variables would show.
	for _, name := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "HTTPS_PROXY"} {
		if !strings.Contains(string(raw), `"name":"`+name+`"`) {
			t.Errorf("the Pod object does not set %s at all", name)
		}
	}
	if !strings.Contains(string(raw), `"key":"env.ANTHROPIC_API_KEY"`) {
		t.Error("the Pod object does not reference env.ANTHROPIC_API_KEY in the lease Secret")
	}
}

// assertNoLeakedEnv fails when any credential in leasedEnv, raw or base64'd, is
// in body.
func assertNoLeakedEnv(t *testing.T, where, body string) {
	t.Helper()
	for _, v := range leasedEnvSecrets() {
		if strings.Contains(body, v) {
			t.Errorf("%s contains the leased credential %q", where, v)
		}
		if b := base64.StdEncoding.EncodeToString([]byte(v)); strings.Contains(body, b) {
			t.Errorf("%s contains the leased credential %q base64-encoded", where, v)
		}
	}
}

// TestBuildPod_EnvWithoutALeaseSecretIsRefused: values with nowhere to be read
// from must not fall back to being written inline, which is the exposure the
// whole change removes.
func TestBuildPod_EnvWithoutALeaseSecretIsRefused(t *testing.T) {
	req := baseRequest()
	req.Env = []string{"ANTHROPIC_API_KEY=sk-ant-api03-LEASED-API-KEY-444555666777"}
	_, err := buildPod(req)
	if err == nil {
		t.Fatal("buildPod rendered an environment with no Secret to read it from")
	}
	if !errors.Is(err, executor.ErrInvalidSpec) {
		t.Errorf("error %v does not wrap ErrInvalidSpec", err)
	}
	if strings.Contains(err.Error(), "LEASED-API-KEY") {
		t.Errorf("the refusal quotes the value it refused to write: %v", err)
	}
}

// TestBuildPod_EnvRefusalsDoNotQuoteValues: an entry with no name may be a
// value that lost it, and error strings reach logs and the dashboard.
func TestBuildPod_EnvRefusalsDoNotQuoteValues(t *testing.T) {
	req := baseRequest()
	req.LeaseSecretName = "cloop-lease-k-abc123"
	req.Env = []string{"PATH=/usr/bin", "sk-ant-api03-ORPHANED-VALUE-NO-NAME"}
	_, err := buildPod(req)
	if err == nil || !strings.Contains(err.Error(), "not in K=V form") {
		t.Fatalf("buildPod = %v, want a K=V refusal", err)
	}
	if strings.Contains(err.Error(), "ORPHANED-VALUE") {
		t.Errorf("the refusal quotes the malformed entry: %v", err)
	}
	if !strings.Contains(err.Error(), "entry 2 of 2") {
		t.Errorf("the refusal does not say which entry: %v", err)
	}
}

// TestHarnessEnv_GitConfigCountIsTheDrivers: GIT_CONFIG_COUNT is the one Spec
// variable not carried in the Secret, because buildPod numbers its own entries
// after the Spec's and writes the total itself. Everything else of the block
// still comes from the Secret, and the numbering is unchanged.
func TestHarnessEnv_GitConfigCountIsTheDrivers(t *testing.T) {
	spec := []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: Bearer LEASED-HEADER-TOKEN",
	}
	env, err := harnessEnv("cloop-lease-k-1", spec, [][2]string{{"safe.directory", PodWorkspace}})
	if err != nil {
		t.Fatalf("harnessEnv: %v", err)
	}
	data, err := leaseEnvData(spec)
	if err != nil {
		t.Fatalf("leaseEnvData: %v", err)
	}
	if _, ok := data["env.GIT_CONFIG_COUNT"]; ok {
		t.Error("the Secret carries GIT_CONFIG_COUNT, which the harness never reads from it")
	}
	got := resolveEnv(t, container{Name: ContainerName, Env: env},
		map[string]map[string][]byte{"cloop-lease-k-1": data})
	want := map[string]string{
		"GIT_CONFIG_COUNT":   "2",
		"GIT_CONFIG_KEY_0":   "http.extraHeader",
		"GIT_CONFIG_VALUE_0": "Authorization: Bearer LEASED-HEADER-TOKEN",
		"GIT_CONFIG_KEY_1":   "safe.directory",
		"GIT_CONFIG_VALUE_1": PodWorkspace,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for _, e := range env {
		if strings.Contains(e.Value, "LEASED-HEADER-TOKEN") {
			t.Errorf("%s carries the credential as a plain value", e.Name)
		}
	}

	// An uncounted entry at the index the driver claims is a collision the API
	// server would reject without naming it.
	_, err = harnessEnv("cloop-lease-k-1", []string{"GIT_CONFIG_KEY_0=core.pager"},
		[][2]string{{"safe.directory", PodWorkspace}})
	if err == nil || !strings.Contains(err.Error(), "GIT_CONFIG_KEY_0") {
		t.Errorf("harnessEnv = %v, want a refusal naming the duplicated GIT_CONFIG_KEY_0", err)
	}
}

// TestLeaseSecretData_KeysCannotCollide: files and variables share one Secret,
// and their keys are disjoint by construction — "d<N>." and "env." — even for
// a file and a variable with the same name.
func TestLeaseSecretData_KeysCannotCollide(t *testing.T) {
	files := []executor.SecretFile{{Dir: leaseDir, Name: "env.TOKEN", Content: []byte("file")}}
	data, err := leaseSecretData(files, []string{"TOKEN=variable"})
	if err != nil {
		t.Fatalf("leaseSecretData: %v", err)
	}
	if string(data["d0.env.TOKEN"]) != "file" || string(data["env.TOKEN"]) != "variable" {
		t.Errorf("data = %v, want the file under d0.env.TOKEN and the variable under env.TOKEN", keysOf(data))
	}
}

// TestLeaseSecretData_RefusesWhatASecretCannotHold: the API server caps a
// Secret at 1 MiB and its refusal would name a field path, after the Pod was
// created. Refusing first names the run.
func TestLeaseSecretData_RefusesWhatASecretCannotHold(t *testing.T) {
	big := "BLOB=" + strings.Repeat("x", maxLeaseSecretBytes+1)
	if _, err := leaseSecretData(nil, []string{big}); err == nil || !errors.Is(err, executor.ErrInvalidSpec) {
		t.Errorf("leaseSecretData(%d bytes) = %v, want an ErrInvalidSpec refusal", len(big), err)
	}
	if data, err := leaseSecretData(nil, []string{"GIT_CONFIG_COUNT=0"}); err != nil || data != nil {
		t.Errorf("an environment of nothing but GIT_CONFIG_COUNT carries %v (%v); want no Secret at all", data, err)
	}
	if data, err := leaseSecretData(nil, []string{"EMPTY="}); err != nil || data["env.EMPTY"] == nil {
		t.Errorf("an empty value = %v (%v); want a present, empty key — a nil one marshals as null", data, err)
	}
}

// TestLeaseEnvVar_FormattingRedactsTheValue: a plan that reaches a %v must not
// carry the credential with it.
func TestLeaseEnvVar_FormattingRedactsTheValue(t *testing.T) {
	plan, err := planLeaseEnv([]string{"ANTHROPIC_API_KEY=sk-ant-api03-LEASED-API-KEY-444555666777"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmtV(plan.vars), fmtSharpV(plan.vars)} {
		if strings.Contains(s, "LEASED-API-KEY") {
			t.Errorf("formatting the plan prints the value: %s", s)
		}
	}
}

// --- Start ------------------------------------------------------------

// TestStart_EnvTravelsInTheLeaseSecret drives the real Start against the fake
// API server: the Secret the server received carries each value under its own
// key, the Pod the server received carries none of them, and the Pod's
// references resolve against that Secret to exactly the Spec's environment.
func TestStart_EnvTravelsInTheLeaseSecret(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })
	spec := secretFileSpec()
	spec.Workspace = gitWorkspace()
	spec.Env = append(spec.Env, leasedEnv()...)

	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.mu.Lock()
	created := *api.pods[name]
	api.mu.Unlock()
	sec := api.secretObject(leaseSecretName(handle.ID))
	if sec == nil {
		t.Fatalf("no lease Secret %s; secrets = %v", leaseSecretName(handle.ID), api.secretNames())
	}

	raw, _ := json.Marshal(created)
	assertNoLeakedEnv(t, "the Pod the API server received", string(raw))
	if strings.Contains(string(raw), fakeLeaseToken) {
		t.Error("the Pod the API server received contains the leased file content")
	}

	want := envMap(spec.Env)
	for k, v := range want {
		if got, ok := sec.Data["env."+k]; !ok || string(got) != v {
			t.Errorf("Secret key env.%s = %q (present %v), want %q", k, got, ok, v)
		}
	}
	got := resolveEnv(t, created.Spec.Containers[0], map[string]map[string][]byte{sec.Metadata.Name: sec.Data})
	for k, v := range want {
		if got[k] != v {
			t.Errorf("the harness would see %s=%q, want %q", k, got[k], v)
		}
	}
	// The provisioner still sees none of it, Secret or not.
	for _, e := range created.Spec.InitContainers[0].Env {
		if _, leased := want[e.Name]; leased {
			t.Errorf("the workspace provisioner reads %s; it has no business with the harness's environment", e.Name)
		}
	}
}

// TestStart_EnvOnlyRunCreatesTheLeaseSecret: a run that leases nothing but
// sets an environment — an env-kind grant, the harness login — still needs the
// Secret, and gets one with no file keys and no volume.
func TestStart_EnvOnlyRunCreatesTheLeaseSecret(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	spec := testSpec()
	spec.Env = []string{"ANTHROPIC_API_KEY=sk-ant-api03-LEASED-API-KEY-444555666777"}

	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	sec := api.secretObject(leaseSecretName(handle.ID))
	if sec == nil {
		t.Fatalf("no lease Secret; secrets = %v", api.secretNames())
	}
	if len(sec.Data) != 1 || string(sec.Data["env.ANTHROPIC_API_KEY"]) != "sk-ant-api03-LEASED-API-KEY-444555666777" {
		t.Errorf("Secret data keys = %v, want exactly env.ANTHROPIC_API_KEY", keysOf(sec.Data))
	}
	name := api.onlyPodName(t)
	api.mu.Lock()
	created := *api.pods[name]
	api.mu.Unlock()
	if vols := secretFileVolumesOf(&created); len(vols) != 0 {
		t.Errorf("an env-only run mounts %d Secret volume(s); there are no files to project", len(vols))
	}
}

// TestStart_NoEnvAndNoFilesCreatesNoSecret: a run with nothing to carry needs
// no Secret, and so needs no Secret RBAC — the smoke test `cloop executor test`
// runs is one of these.
func TestStart_NoEnvAndNoFilesCreatesNoSecret(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	if _, err := ex.Start(context.Background(), testSpec()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	api.onlyPodName(t)
	if n := api.secretCreateCount(); n != 0 {
		t.Errorf("secret creates = %d, want none for a run with no environment and no files", n)
	}
}

// TestStart_EnvSecretRefusedByRBACFailsTheStart: a Role without the secrets
// rule refuses the create, and the run must not start — with the values inline
// or with an environment the kubelet can never resolve.
func TestStart_EnvSecretRefusedByRBACFailsTheStart(t *testing.T) {
	ex, api, leases := newTestExecutor(t, nil)
	api.failAlways("POST /secrets", apiFailure{Code: 403, Reason: "Forbidden", Message: "secrets is forbidden"})
	spec := testSpec()
	spec.Env = []string{"ANTHROPIC_API_KEY=sk-ant-api03-LEASED-API-KEY-444555666777"}

	_, err := ex.Start(context.Background(), spec)
	if err == nil {
		t.Fatal("Start succeeded although the lease Secret could not be created")
	}
	for _, want := range []string{`resources: ["secrets"]`, `"patch"`, "environment"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	// The Pod created before the Secret is deleted again, not left parked.
	waitFor(t, 3*time.Second, func() bool { return len(api.podNames()) == 0 })
	leases.waitOutstandingEmpty(t, 2*time.Second)
}

func fmtV(v any) string      { return fmt.Sprintf("%v", v) }
func fmtSharpV(v any) string { return fmt.Sprintf("%#v", v) }

// waitFor polls cond until it holds or d passes.
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}
