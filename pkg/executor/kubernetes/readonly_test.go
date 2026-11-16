package kubernetes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const readOnlyTokenEnv = "CLOOP_READERS_TOKEN"

func readOnlyRequest() podRequest {
	req := seededRequest()
	req.ReadOnly = []executor.ReadOnlyProject{
		{Slug: "api", Project: "/srv/projects/api", Snapshot: &executor.ReadOnlySnapshotRef{
			URL: "https://hub.example/api/run/knowledge/readonly/snapshot", TokenEnv: readOnlyTokenEnv}},
		{Slug: "web", Project: "/srv/projects/web", Snapshot: &executor.ReadOnlySnapshotRef{
			URL: "https://hub.example/api/run/knowledge/readonly/snapshot", TokenEnv: readOnlyTokenEnv}},
	}
	return req
}

// TestBuildPod_ReadOnlyProjectsAreMountedReadOnlyInTheHarness: the volume the
// workspace container fills is the harness's at /readonly, read-only — the
// one thing that keeps a harness running as the uid that wrote the files from
// changing them — and writable in the workspace container alone, which is
// told where to fetch each project and given the run's token to do it with.
func TestBuildPod_ReadOnlyProjectsAreMountedReadOnlyInTheHarness(t *testing.T) {
	p, err := buildPod(readOnlyRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	harness := findContainer(p.Spec.Containers, ContainerName)
	m := mountOf(harness, readOnlyVolume)
	if m == nil || m.MountPath != executor.ReadOnlyRoot || !m.ReadOnly {
		t.Fatalf("harness mount of the read-only projects = %+v, want %s read-only", m, executor.ReadOnlyRoot)
	}
	init := findContainer(p.Spec.InitContainers, InitContainerName)
	if init == nil {
		t.Fatal("no workspace container to fetch the projects")
	}
	if im := mountOf(init, readOnlyVolume); im == nil || im.MountPath != executor.ReadOnlyRoot || im.ReadOnly {
		t.Fatalf("workspace container mount of the read-only projects = %+v, want %s writable", im, executor.ReadOnlyRoot)
	}
	args := strings.Join(init.Args, " ")
	for _, want := range []string{
		"--readonly-snapshot api=https://hub.example/api/run/knowledge/readonly/snapshot",
		"--readonly-snapshot web=https://hub.example/api/run/knowledge/readonly/snapshot",
		"--readonly-dir " + executor.ReadOnlyRoot, "--readonly-token-env " + readOnlyTokenEnv,
	} {
		if !strings.Contains(args, want) {
			t.Errorf("workspace container args lack %q: %s", want, args)
		}
	}
	var token *envVar
	for i := range init.Env {
		if init.Env[i].Name == readOnlyTokenEnv {
			token = &init.Env[i]
		}
	}
	if token == nil || token.Value != "" || token.ValueFrom == nil || token.ValueFrom.SecretKeyRef == nil ||
		token.ValueFrom.SecretKeyRef.Name != readOnlyRequest().LeaseSecretName ||
		token.ValueFrom.SecretKeyRef.Key != envSecretKeyPrefix+readOnlyTokenEnv {
		t.Fatalf("workspace container token = %+v, want a reference to the lease Secret's %s",
			token, envSecretKeyPrefix+readOnlyTokenEnv)
	}
	var vol *volume
	for i := range p.Spec.Volumes {
		if p.Spec.Volumes[i].Name == readOnlyVolume {
			vol = &p.Spec.Volumes[i]
		}
	}
	if vol == nil || vol.EmptyDir == nil || vol.EmptyDir.SizeLimit == "" {
		t.Fatalf("read-only volume = %+v, want a bounded emptyDir", vol)
	}
	// Nothing of a token's value in the Pod object.
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "cloop_know1_") {
		t.Fatalf("the Pod object carries a session token: %s", raw)
	}
}

func TestBuildPod_NoReadOnlyProjectsNoVolume(t *testing.T) {
	p, err := buildPod(seededRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	for _, v := range p.Spec.Volumes {
		if v.Name == readOnlyVolume {
			t.Fatal("a run given no project has a read-only volume")
		}
	}
	for _, c := range append(p.Spec.Containers, p.Spec.InitContainers...) {
		if mountOf(&c, readOnlyVolume) != nil || strings.Contains(strings.Join(c.Args, " "), "--readonly") {
			t.Fatalf("container %s is given a read-only project", c.Name)
		}
	}
}

func TestBuildPod_RefusesReadOnlyProjectsItCannotPlace(t *testing.T) {
	cases := map[string]func(*podRequest){
		"no workspace container": func(r *podRequest) {
			r.Workspace = executor.Workspace{}
			r.ProjectSeed = false
		},
		"no lease Secret": func(r *podRequest) { r.LeaseSecretName = "" },
		"no snapshot":     func(r *podRequest) { r.ReadOnly[0].Snapshot = nil },
		"two token names": func(r *podRequest) {
			r.ReadOnly[1].Snapshot = &executor.ReadOnlySnapshotRef{URL: "https://x/y", TokenEnv: "OTHER"}
		},
		"mount over /readonly": func(r *podRequest) {
			r.SandboxMounts = []executor.SpecMount{{Source: "cache", Target: "/readonly/api"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := readOnlyRequest()
			mutate(&req)
			if _, err := buildPod(req); err == nil {
				t.Fatalf("buildPod accepted read-only projects with %s", name)
			}
		})
	}
}

// TestStart_ReadOnlyProjectsReachThePodWithTheTokenByReference runs Start
// against the fake API server: the Pod it creates mounts the read-only
// projects read-only in the harness, its workspace container is told where to
// fetch them, and the run's token is in the lease Secret, never in the Pod.
func TestStart_ReadOnlyProjectsReachThePodWithTheTokenByReference(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	if got := ex.Capabilities().ReadOnlyProjects; got != executor.ReadOnlySnapshot {
		t.Fatalf("capabilities say %q, want snapshot", got)
	}
	const token = "cloop_know1_0123456789abcdef01234567.run-token-secret"
	spec := seededSpec(t)
	spec.Env = append(spec.Env, readOnlyTokenEnv+"="+token)
	spec.ReadOnly = []executor.ReadOnlyProject{{Slug: "api", Project: "/srv/projects/api",
		Snapshot: &executor.ReadOnlySnapshotRef{URL: "https://hub.example/api/run/knowledge/readonly/snapshot",
			TokenEnv: readOnlyTokenEnv}}}
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.mu.Lock()
	raw, _ := json.Marshal(api.pods[name])
	api.mu.Unlock()
	podJSON := string(raw)
	if strings.Contains(podJSON, token) {
		t.Fatal("the run's token is in the Pod object")
	}
	for _, want := range []string{`"--readonly-snapshot"`, `"api=https://hub.example/api/run/knowledge/readonly/snapshot"`,
		`"mountPath":"/readonly","readOnly":true`} {
		if !strings.Contains(podJSON, want) {
			t.Errorf("the Pod lacks %s: %s", want, podJSON)
		}
	}
	sec := api.secretObject(leaseSecretName(h.ID))
	if sec == nil || string(sec.Data[envSecretKeyPrefix+readOnlyTokenEnv]) != token {
		t.Fatalf("the lease Secret does not carry the token the workspace container fetches with")
	}
}
