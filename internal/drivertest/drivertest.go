// Package drivertest stands in for what the executor drivers talk to — a
// container runtime's CLI and a Kubernetes API server — so a test can drive the
// real drivers end to end (Task 20403): the container driver's staged lease
// files on disk, and the Kubernetes driver's lease Secret in the stand-in API
// server, are what a revocation has to reach.
//
// Neither runs anything. The runtime reports one image as present and every
// container as running until it is removed or killed; the API server keeps
// every Pod pending. Both are test-only: production code must not import this
// package (tests/arch enforces it).
package drivertest

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// ── a container runtime that runs nothing ───────────────────────────────────

// Image is a pinned reference the stand-in runtime reports as present.
const Image = "docker.io/library/alpine@sha256:" +
	"d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

// ContainerRuntime writes, into dir, a `docker` that answers the container
// driver as a running container would and stops it when removed or killed, and
// returns its path. Its name has to be docker: the driver accepts no other
// runtime.
func ContainerRuntime(t testing.TB, dir string) string {
	t.Helper()
	gone := filepath.Join(dir, "removed")
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in
image) printf '%%s\037%%s\n' '%[2]s' 'sha256:5f3b8f9c2b'; exit 0 ;;
run) echo "fake-container-id"; exit 0 ;;
logs) i=0; while [ ! -e '%[1]s' ] && [ "$i" -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; exit 0 ;;
wait) i=0; while [ ! -e '%[1]s' ] && [ "$i" -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; echo 137; exit 0 ;;
inspect) if [ -e '%[1]s' ]; then echo "Error: No such container" >&2; exit 1; fi
  echo '{"Status":"running","Running":true,"ExitCode":0,"StartedAt":"2026-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}'; exit 0 ;;
rm|kill|stop) : > '%[1]s'; exit 0 ;;
network) echo '{}'; exit 0 ;;
*) exit 0 ;;
esac
`, gone, Image)
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(gone, nil, 0o600) })
	return path
}

// ── a Kubernetes API server that keeps a Pod pending ────────────────────────

// KubeAPI serves the Pod and Secret calls the Kubernetes driver makes, and keeps
// every Pod pending — running, as far as a revocation is concerned — so a test
// can see what a revocation does to a live Pod's lease Secret. A test can
// report a Pod's workspace provisioner finished (FinishInitContainer), which a
// watching driver sees on its next look.
type KubeAPI struct {
	srv     *httptest.Server
	mu      sync.Mutex
	pods    map[string]map[string]any
	secrets map[string]map[string][]byte
	deleted bool
	// changed is closed, and replaced, whenever a Pod's status changes: every
	// watch open then ends, and the driver reads the Pod again.
	changed chan struct{}
	// secretDeletes names every Secret a delete removed.
	secretDeletes []string
	// finished names the Pods FinishPod ended: their log is empty and over.
	finished map[string]bool
}

// NewKubeAPI starts one, closed when the test ends.
func NewKubeAPI(t testing.TB) *KubeAPI {
	t.Helper()
	f := &KubeAPI{pods: map[string]map[string]any{}, secrets: map[string]map[string][]byte{},
		changed: make(chan struct{}), finished: map[string]bool{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.route))
	t.Cleanup(f.srv.Close)
	return f
}

// REST is the connection a driver uses to reach it.
func (f *KubeAPI) REST() *kubernetes.RESTConfig {
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return &kubernetes.RESTConfig{Server: f.srv.URL, CAData: caPEM, BearerToken: "fake", Namespace: "cloop"}
}

func kubeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func kubeStatus(w http.ResponseWriter, code int, reason string) {
	kubeJSON(w, code, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure",
		"reason": reason, "code": code, "message": reason})
}

// kubeSegment returns the path segment after kind, or "".
func kubeSegment(p, kind string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, seg := range parts {
		if seg == kind && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func (f *KubeAPI) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/version":
		kubeJSON(w, 200, map[string]string{"gitVersion": "v1.31.0", "major": "1", "minor": "31"})
	case strings.Contains(p, "/networkpolicies"):
		kubeJSON(w, 200, map[string]any{"kind": "NetworkPolicyList", "metadata": map[string]string{"resourceVersion": "1"}, "items": []any{}})
	case strings.Contains(p, "/secrets"):
		f.routeSecret(w, r, kubeSegment(p, "secrets"))
	case strings.HasSuffix(p, "/log"):
		f.mu.Lock()
		done := f.finished[kubeSegment(p, "pods")]
		f.mu.Unlock()
		if done {
			// A finished Pod's log, which says nothing and is over.
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			return
		}
		kubeStatus(w, http.StatusBadRequest, "container is waiting to start")
	case strings.Contains(p, "/pods/"):
		f.routePod(w, r, kubeSegment(p, "pods"))
	case strings.HasSuffix(p, "/pods"):
		switch {
		case r.Method == http.MethodPost:
			var in map[string]any
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				kubeStatus(w, 400, "BadRequest")
				return
			}
			meta, _ := in["metadata"].(map[string]any)
			if meta == nil {
				meta = map[string]any{}
				in["metadata"] = meta
			}
			name, _ := meta["name"].(string)
			if name == "" {
				gen, _ := meta["generateName"].(string)
				name = gen + "x1"
				meta["name"] = name
			}
			meta["uid"] = "uid-" + name
			meta["resourceVersion"] = "1"
			in["status"] = map[string]any{"phase": "Pending"}
			f.mu.Lock()
			f.pods[name] = in
			f.mu.Unlock()
			kubeJSON(w, 201, in)
		case r.URL.Query().Get("watch") == "true":
			// Held open with nothing to say until a Pod changes: the stream
			// then ends, as the API server's own timeout ends one, and the
			// driver reads the Pod again.
			f.mu.Lock()
			changed := f.changed
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			select {
			case <-r.Context().Done():
			case <-changed:
			}
		default:
			kubeJSON(w, 200, map[string]any{"kind": "PodList", "metadata": map[string]string{"resourceVersion": "1"}, "items": []any{}})
		}
	default:
		kubeStatus(w, 404, "NotFound")
	}
}

func (f *KubeAPI) routePod(w http.ResponseWriter, r *http.Request, name string) {
	f.mu.Lock()
	p, ok := f.pods[name]
	if ok && r.Method == http.MethodDelete {
		delete(f.pods, name)
		f.deleted = true
	}
	f.mu.Unlock()
	if !ok {
		kubeStatus(w, 404, "NotFound")
		return
	}
	kubeJSON(w, 200, p)
}

func (f *KubeAPI) routeSecret(w http.ResponseWriter, r *http.Request, name string) {
	switch {
	case r.Method == http.MethodPost:
		var in struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Data       map[string][]byte `json:"data"`
			StringData map[string]string `json:"stringData"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			kubeStatus(w, 400, "BadRequest")
			return
		}
		// stringData is write-only on a real API server, merged into data:
		// the workspace Secret is written that way.
		data := in.Data
		if data == nil {
			data = map[string][]byte{}
		}
		for k, v := range in.StringData {
			data[k] = []byte(v)
		}
		f.mu.Lock()
		f.secrets[in.Metadata.Name] = data
		f.mu.Unlock()
		kubeJSON(w, 201, map[string]any{"metadata": map[string]string{"name": in.Metadata.Name}})
	case r.Method == http.MethodPatch:
		var patch struct {
			Data map[string][]byte `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			kubeStatus(w, 400, "BadRequest")
			return
		}
		f.mu.Lock()
		data, ok := f.secrets[name]
		for k, v := range patch.Data {
			if ok {
				data[k] = v
			}
		}
		f.mu.Unlock()
		if !ok {
			kubeStatus(w, 404, "NotFound")
			return
		}
		kubeJSON(w, 200, map[string]any{"metadata": map[string]string{"name": name}})
	case r.Method == http.MethodDelete:
		f.mu.Lock()
		_, ok := f.secrets[name]
		delete(f.secrets, name)
		if ok {
			f.secretDeletes = append(f.secretDeletes, name)
		}
		f.mu.Unlock()
		if !ok {
			kubeStatus(w, 404, "NotFound")
			return
		}
		kubeJSON(w, 200, map[string]string{"kind": "Status", "status": "Success"})
	default:
		kubeStatus(w, 405, "MethodNotAllowed")
	}
}

// WaitSecret waits for a Secret whose name starts with prefix, and returns its
// name.
func (f *KubeAPI) WaitSecret(t testing.TB, prefix string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		for name := range f.secrets {
			if strings.HasPrefix(name, prefix) {
				f.mu.Unlock()
				return name
			}
		}
		f.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s* Secret was created", prefix)
	return ""
}

// KeyHolding returns the key of secret holding value, or "".
func (f *KubeAPI) KeyHolding(secret, value string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.secrets[secret] {
		if string(v) == value {
			return k
		}
	}
	return ""
}

// SecretData returns a copy of secret's data.
func (f *KubeAPI) SecretData(secret string) map[string][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range f.secrets[secret] {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// SecretExists reports whether the Secret called name is held.
func (f *KubeAPI) SecretExists(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.secrets[name]
	return ok
}

// SecretDeleted reports whether a delete removed the Secret called name.
func (f *KubeAPI) SecretDeleted(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.secretDeletes, name)
}

// WaitPod waits for a Pod to be created, and returns its name.
func (f *KubeAPI) WaitPod(t testing.TB) string {
	t.Helper()
	return f.WaitWorkspacePod(t, false)
}

// WaitWorkspacePod waits for a Pod to be created — one whose init container
// provisions a workspace, when workspace is set: a hub's isolation probe
// starts Pods of its own — and returns its name.
func (f *KubeAPI) WaitWorkspacePod(t testing.TB, workspace bool) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, name := range f.podNames() {
			if !workspace || f.InitContainerArg(name, "--repo") != "" {
				return name
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no Pod was created")
	return ""
}

func (f *KubeAPI) podNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.pods))
	for name := range f.pods {
		names = append(names, name)
	}
	return names
}

// InitContainerArg returns the value following flag in the Pod's workspace
// provisioner's arguments — "--repo" is the URL it fetches — or "".
func (f *KubeAPI) InitContainerArg(pod, flag string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	spec, _ := f.pods[pod]["spec"].(map[string]any)
	inits, _ := spec["initContainers"].([]any)
	for _, c := range inits {
		cm, _ := c.(map[string]any)
		args, _ := cm["args"].([]any)
		for i, a := range args {
			if a == flag && i+1 < len(args) {
				v, _ := args[i+1].(string)
				return v
			}
		}
	}
	return ""
}

// FinishInitContainer reports pod's workspace provisioner as having exited
// with code, the Pod still pending, as a kubelet does between the provisioner
// exiting and the harness starting.
func (f *KubeAPI) FinishInitContainer(pod string, code int) {
	f.setStatus(pod, func(status map[string]any) {
		status["initContainerStatuses"] = []any{terminatedStatus(kubernetes.InitContainerName, code)}
	})
}

// FinishPod ends pod: its harness exited with code, the Pod is terminal and its
// log empty and over, as a kubelet reports a Pod that ran to completion.
func (f *KubeAPI) FinishPod(pod string, code int) {
	f.mu.Lock()
	f.finished[pod] = true
	f.mu.Unlock()
	phase := "Succeeded"
	if code != 0 {
		phase = "Failed"
	}
	f.setStatus(pod, func(status map[string]any) {
		status["phase"] = phase
		if _, ok := status["initContainerStatuses"]; !ok {
			status["initContainerStatuses"] = []any{terminatedStatus(kubernetes.InitContainerName, 0)}
		}
		status["containerStatuses"] = []any{terminatedStatus(kubernetes.ContainerName, code)}
	})
}

func terminatedStatus(name string, code int) map[string]any {
	return map[string]any{
		"name": name,
		"state": map[string]any{"terminated": map[string]any{
			"exitCode": code, "reason": "Completed",
			"finishedAt": time.Now().UTC().Format(time.RFC3339),
		}},
	}
}

// setStatus changes pod's status with change and tells every open watch.
func (f *KubeAPI) setStatus(pod string, change func(status map[string]any)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pods[pod]
	if !ok {
		return
	}
	status, _ := p["status"].(map[string]any)
	if status == nil {
		status = map[string]any{"phase": "Pending"}
		p["status"] = status
	}
	change(status)
	if meta, _ := p["metadata"].(map[string]any); meta != nil {
		rv := 1
		fmt.Sscanf(fmt.Sprint(meta["resourceVersion"]), "%d", &rv)
		meta["resourceVersion"] = fmt.Sprint(rv + 1)
	}
	close(f.changed)
	f.changed = make(chan struct{})
}

// PodDeleted reports whether any Pod was deleted.
func (f *KubeAPI) PodDeleted() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleted
}

// KubeSource hands the Kubernetes driver the stand-in API server's connection.
type KubeSource struct{ Rest *kubernetes.RESTConfig }

// Acquire implements kubernetes.CredentialSource.
func (s KubeSource) Acquire(context.Context, string) (*kubernetes.Credentials, error) {
	return &kubernetes.Credentials{Rest: s.Rest, LeaseID: "kube-lease", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

// Renew implements kubernetes.CredentialSource.
func (s KubeSource) Renew(ctx context.Context, _ string) (*kubernetes.Credentials, error) {
	return s.Acquire(ctx, "")
}

// Release implements kubernetes.CredentialSource.
func (s KubeSource) Release(string) {}

// Describe implements kubernetes.CredentialSource.
func (s KubeSource) Describe() string { return "stand-in API server" }
