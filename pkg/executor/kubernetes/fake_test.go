package kubernetes

// fake_test.go stands up an httptest server that speaks enough of the
// Kubernetes Pod API for the driver to be exercised end to end: create with
// generateName, get, list by label selector, watch, follow logs, and delete.
//
// It is a fake rather than a mock on purpose. The interesting bugs in this
// driver are sequencing bugs — a watch established after the Pod already
// finished, a log follower started before the container is ready, a lease
// released before the delete that needs it — and none of them show up against
// a mock that returns canned values. They show up against something that
// holds a connection open and delivers events in an order a test chooses.

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI is a minimal Kubernetes API server.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	pods     map[string]*pod
	nextName int
	watchers map[string][]chan watchEvent
	logs     map[string]*logStream
	// secrets holds the workspace credential Secrets the driver creates, and
	// secretDeletes records every delete by name. Both live here rather than in
	// workspace_test.go because the routing that fills them is here; the
	// handlers and every assertion about them are in workspace_test.go.
	secrets       map[string]*secret
	secretDeletes []string
	// history is the per-Pod event log a watch replays from. A real API
	// server keeps one so a client that reconnects with a resourceVersion
	// does not miss what happened while it was away; without it here, every
	// test would race the driver's watch establishment and the driver would
	// look flaky when it is the fake that lost the event.
	history map[string][]versionedEvent
	// deletes records (name, gracePeriodSeconds) per delete call.
	deletes []deleteRecord
	// requests records every path the driver hit, for assertions about what
	// it did and did not call.
	requests []string
	// failures maps "VERB /path-substring" to a canned failure, so a test can
	// make one call fail without affecting the rest.
	failures map[string]apiFailure
	// unauthorized flips every call to 401, simulating a revoked credential.
	unauthorized bool
}

// versionedEvent is one watch frame plus the resourceVersion it happened at.
type versionedEvent struct {
	rv int
	ev watchEvent
}

type deleteRecord struct {
	Name  string
	Grace int64
}

// logStream models a Pod's log endpoint.
//
// The entry survives being closed rather than being deleted, because the real
// failure this reproduces is a *late* reader: the driver decides to follow
// logs when it observes Running, which can land after the container already
// terminated. A deleted map entry would hand that reader a nil channel and
// block it forever — a bug in the fake that looks exactly like a bug in the
// driver.
type logStream struct {
	ch     chan string
	closed bool
}

func newLogStream() *logStream { return &logStream{ch: make(chan string, 64)} }

func (l *logStream) close() {
	if l == nil || l.closed {
		return
	}
	l.closed = true
	close(l.ch)
}

type apiFailure struct {
	Code    int
	Reason  string
	Message string
	// Raw, when set, is written instead of a Status object — the shape an
	// ingress or a proxy returns.
	Raw string
	// Once makes the failure apply to a single call.
	Once bool
	used bool
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{
		t:        t,
		pods:     make(map[string]*pod),
		watchers: make(map[string][]chan watchEvent),
		logs:     make(map[string]*logStream),
		history:  make(map[string][]versionedEvent),
		failures: make(map[string]apiFailure),
		secrets:  make(map[string]*secret),
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.route))
	t.Cleanup(f.srv.Close)
	return f
}

// restConfig points a driver at this fake, verifying its certificate
// properly rather than skipping TLS — the verification path is part of what
// is under test.
func (f *fakeAPI) restConfig() *RESTConfig {
	cert := f.srv.Certificate()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return &RESTConfig{
		Server:      f.srv.URL,
		CAData:      caPEM,
		BearerToken: "fake-token",
		Namespace:   "cloop",
		Context:     "fake",
	}
}

// --- routing ----------------------------------------------------------

func (f *fakeAPI) route(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	unauthorized := f.unauthorized
	f.mu.Unlock()

	if unauthorized {
		writeStatus(w, 401, "Unauthorized", "the credential was rejected")
		return
	}
	if fail, ok := f.takeFailure(r); ok {
		if fail.Raw != "" {
			w.WriteHeader(fail.Code)
			_, _ = w.Write([]byte(fail.Raw))
			return
		}
		writeStatus(w, fail.Code, fail.Reason, fail.Message)
		return
	}

	switch {
	case r.URL.Path == "/version":
		writeJSON(w, 200, map[string]string{"gitVersion": "v1.31.0", "major": "1", "minor": "31"})

	case strings.Contains(r.URL.Path, "/secrets"):
		f.routeSecret(w, r)

	case strings.HasSuffix(r.URL.Path, "/log"):
		f.handleLog(w, r)

	case strings.Contains(r.URL.Path, "/pods/"):
		name := path4(r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			f.handleGet(w, name)
		case http.MethodDelete:
			f.handleDelete(w, r, name)
		default:
			writeStatus(w, 405, "MethodNotAllowed", r.Method)
		}

	case strings.HasSuffix(r.URL.Path, "/pods"):
		switch {
		case r.Method == http.MethodPost:
			f.handleCreate(w, r)
		case r.URL.Query().Get("watch") == "true":
			f.handleWatch(w, r)
		case r.Method == http.MethodGet:
			f.handleList(w, r)
		default:
			writeStatus(w, 405, "MethodNotAllowed", r.Method)
		}

	default:
		writeStatus(w, 404, "NotFound", "no route for "+r.URL.Path)
	}
}

// path4 extracts the pod name from /api/v1/namespaces/{ns}/pods/{name}[/sub].
func path4(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, seg := range parts {
		if seg == "pods" && i+1 < len(parts) {
			name, _ := url.PathUnescape(parts[i+1])
			return name
		}
	}
	return ""
}

func (f *fakeAPI) handleCreate(w http.ResponseWriter, r *http.Request) {
	var in pod
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeStatus(w, 400, "BadRequest", "undecodable body: "+err.Error())
		return
	}
	if in.Metadata.GenerateName == "" {
		writeStatus(w, 422, "Invalid", "metadata.generateName is required by this fake")
		return
	}

	f.mu.Lock()
	f.nextName++
	in.Metadata.Name = fmt.Sprintf("%s%05d", in.Metadata.GenerateName, f.nextName)
	in.Metadata.UID = "uid-" + in.Metadata.Name
	in.Metadata.ResourceVersion = "1"
	in.Metadata.CreationTimestamp = time.Now().UTC().Format(time.RFC3339)
	in.Status.Phase = phasePending
	stored := in
	f.pods[in.Metadata.Name] = &stored
	f.logs[in.Metadata.Name] = newLogStream()
	// Serialise the response from an independent copy, not from `stored`.
	// The map holds &stored, so the driver's Start can return, the test can
	// call setPhase, and the kubelet-simulating mutation lands on the very
	// bytes writeJSON is reading — a race in the fixture that reads like a
	// race in the driver.
	respond := stored
	f.mu.Unlock()

	writeJSON(w, 201, respond)
}

func (f *fakeAPI) handleGet(w http.ResponseWriter, name string) {
	f.mu.Lock()
	p, ok := f.pods[name]
	var copyOut pod
	if ok {
		copyOut = *p
	}
	f.mu.Unlock()
	if !ok {
		writeStatus(w, 404, "NotFound", fmt.Sprintf("pods %q not found", name))
		return
	}
	writeJSON(w, 200, copyOut)
}

func (f *fakeAPI) handleList(w http.ResponseWriter, r *http.Request) {
	selector := r.URL.Query().Get("labelSelector")
	f.mu.Lock()
	out := podList{}
	out.Metadata.ResourceVersion = "1"
	names := make([]string, 0, len(f.pods))
	for name := range f.pods {
		names = append(names, name)
	}
	for _, name := range names {
		p := f.pods[name]
		if matchesSelector(p.Metadata.Labels, selector) {
			out.Items = append(out.Items, *p)
		}
	}
	f.mu.Unlock()
	writeJSON(w, 200, out)
}

// matchesSelector implements the two selector forms the driver emits:
// "key=value" equality and a bare "key" existence check.
func matchesSelector(labels map[string]string, selector string) bool {
	if strings.TrimSpace(selector) == "" {
		return true
	}
	for _, term := range strings.Split(selector, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		if k, v, isEq := strings.Cut(term, "="); isEq {
			if labels[k] != v {
				return false
			}
			continue
		}
		if _, ok := labels[term]; !ok {
			return false
		}
	}
	return true
}

func (f *fakeAPI) handleDelete(w http.ResponseWriter, r *http.Request, name string) {
	var opts deleteOptions
	_ = json.NewDecoder(r.Body).Decode(&opts)
	grace := int64(-1)
	if opts.GracePeriodSeconds != nil {
		grace = *opts.GracePeriodSeconds
	}

	f.mu.Lock()
	p, ok := f.pods[name]
	if ok {
		delete(f.pods, name)
		f.deletes = append(f.deletes, deleteRecord{Name: name, Grace: grace})
	}
	f.logs[name].close()
	f.mu.Unlock()

	if !ok {
		writeStatus(w, 404, "NotFound", fmt.Sprintf("pods %q not found", name))
		return
	}
	raw, _ := json.Marshal(p)
	f.recordDeletion(name, raw)
	writeJSON(w, 200, map[string]string{"kind": "Status", "status": "Success"})
}

func (f *fakeAPI) handleWatch(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Query().Get("fieldSelector"), "metadata.name=")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeStatus(w, 500, "InternalError", "no flusher")
		return
	}

	since := 0
	if rv := r.URL.Query().Get("resourceVersion"); rv != "" {
		since, _ = strconv.Atoi(rv)
	}

	// Capture the backlog and subscribe under one lock, so an event emitted
	// concurrently is either replayed or delivered live — never both, never
	// neither.
	ch := make(chan watchEvent, 64)
	f.mu.Lock()
	var backlog []watchEvent
	for _, ve := range f.history[name] {
		if ve.rv > since {
			backlog = append(backlog, ve.ev)
		}
	}
	f.watchers[name] = append(f.watchers[name], ch)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		kept := f.watchers[name][:0]
		for _, c := range f.watchers[name] {
			if c != ch {
				kept = append(kept, c)
			}
		}
		f.watchers[name] = kept
		f.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	flusher.Flush()

	enc := json.NewEncoder(w)
	for _, ev := range backlog {
		if err := enc.Encode(ev); err != nil {
			return
		}
		flusher.Flush()
		if ev.Type == "DELETED" {
			return
		}
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if err := enc.Encode(ev); err != nil {
				return
			}
			flusher.Flush()
			if ev.Type == "DELETED" {
				return
			}
		}
	}
}

func (f *fakeAPI) handleLog(w http.ResponseWriter, r *http.Request) {
	name := path4(r.URL.Path)
	f.mu.Lock()
	p, exists := f.pods[name]
	stream := f.logs[name]
	started := false
	if exists {
		if cs := p.harnessStatus(); cs != nil {
			started = cs.State.Running != nil || cs.State.Terminated != nil
		}
	}
	f.mu.Unlock()

	if !exists {
		writeStatus(w, 404, "NotFound", fmt.Sprintf("pods %q not found", name))
		return
	}
	if !started {
		// The real API server's answer for a container that has not run:
		// while it is still being created, and permanently for one whose
		// image never pulled. The driver must retry the first case without
		// hanging on the second.
		writeStatus(w, 400, "BadRequest",
			fmt.Sprintf("container %q in pod %q is waiting to start: ContainerCreating", ContainerName, name))
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeStatus(w, 500, "InternalError", "no flusher")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)
	flusher.Flush()

	if stream == nil {
		// No stream was ever opened for this Pod; an empty 200 is what the
		// API server returns for a container that produced nothing.
		return
	}
	follow := r.URL.Query().Get("follow") == "true"
	for {
		select {
		case <-r.Context().Done():
			return
		case chunk, open := <-stream.ch:
			if !open {
				return
			}
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
			flusher.Flush()
			if !follow {
				return
			}
		}
	}
}

// --- test-side controls -----------------------------------------------

// podNames returns the stored Pod names.
func (f *fakeAPI) podNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.pods))
	for name := range f.pods {
		out = append(out, name)
	}
	return out
}

// onlyPodName waits for exactly one Pod to exist and returns its name.
func (f *fakeAPI) onlyPodName(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if names := f.podNames(); len(names) == 1 {
			return names[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected exactly one pod, got %v", f.podNames())
	return ""
}

// setPhase mutates a Pod and broadcasts a MODIFIED event, the way a real
// kubelet status update would.
func (f *fakeAPI) setPhase(name string, mutate func(*pod)) {
	f.mu.Lock()
	p, ok := f.pods[name]
	if !ok {
		f.mu.Unlock()
		return
	}
	mutate(p)
	rv, _ := strconv.Atoi(p.Metadata.ResourceVersion)
	p.Metadata.ResourceVersion = strconv.Itoa(rv + 1)
	raw, _ := json.Marshal(p)
	ev := watchEvent{Type: "MODIFIED", Object: raw}
	f.history[name] = append(f.history[name], versionedEvent{rv: rv + 1, ev: ev})
	watchers := append([]chan watchEvent(nil), f.watchers[name]...)
	f.mu.Unlock()

	for _, ch := range watchers {
		select {
		case ch <- ev:
		case <-time.After(time.Second):
		}
	}
}

// run marks a Pod Running.
func (f *fakeAPI) run(name string) {
	f.setPhase(name, func(p *pod) {
		p.Status.Phase = phaseRunning
		p.Status.ContainerStatuses = []containerStatus{{
			Name:  ContainerName,
			Ready: true,
			State: containerState{Running: &stateRunning{StartedAt: time.Now().UTC().Format(time.RFC3339)}},
		}}
	})
}

// finishInitContainer reports the workspace provisioner as terminated while
// leaving the Pod Pending, which is what a real kubelet does between an init
// container exiting and the app container starting. It is the transition the
// driver drops the credential Secret on.
func (f *fakeAPI) finishInitContainer(name string, exitCode int, reason string) {
	f.setPhase(name, func(p *pod) {
		p.Status.InitContainerStatuses = []containerStatus{{
			Name: InitContainerName,
			State: containerState{Terminated: &stateTerminated{
				ExitCode: exitCode, Reason: reason,
				FinishedAt: time.Now().UTC().Format(time.RFC3339),
			}},
		}}
	})
}

// succeed terminates a Pod with the given exit code, closing its log stream
// first so the follower sees EOF the way a real one does.
func (f *fakeAPI) terminate(name string, exitCode int, reason string) {
	f.mu.Lock()
	f.logs[name].close()
	f.mu.Unlock()

	phase := phaseSucceeded
	if exitCode != 0 {
		phase = phaseFailed
	}
	f.setPhase(name, func(p *pod) {
		p.Status.Phase = phase
		p.Status.ContainerStatuses = []containerStatus{{
			Name: ContainerName,
			State: containerState{Terminated: &stateTerminated{
				ExitCode: exitCode, Reason: reason,
				FinishedAt: time.Now().UTC().Format(time.RFC3339),
			}},
		}}
	})
}

// emitLog pushes a chunk into a Pod's log stream.
func (f *fakeAPI) emitLog(name, text string) {
	f.mu.Lock()
	stream := f.logs[name]
	f.mu.Unlock()
	if stream == nil || stream.closed {
		return
	}
	select {
	case stream.ch <- text:
	case <-time.After(time.Second):
		f.t.Errorf("emitLog(%s) blocked; nobody is following", name)
	}
}

// failNext makes the next matching call fail. key is "VERB /substring".
func (f *fakeAPI) failNext(key string, fail apiFailure) {
	fail.Once = true
	f.mu.Lock()
	f.failures[key] = fail
	f.mu.Unlock()
}

// failAlways makes every matching call fail until cleared.
func (f *fakeAPI) failAlways(key string, fail apiFailure) {
	f.mu.Lock()
	f.failures[key] = fail
	f.mu.Unlock()
}

func (f *fakeAPI) takeFailure(r *http.Request) (apiFailure, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, fail := range f.failures {
		verb, sub, _ := strings.Cut(key, " ")
		if verb != r.Method || !strings.Contains(r.URL.Path, sub) {
			continue
		}
		if fail.Once {
			if fail.used {
				continue
			}
			fail.used = true
			f.failures[key] = fail
		}
		return fail, true
	}
	return apiFailure{}, false
}

func (f *fakeAPI) deleteRecords() []deleteRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]deleteRecord(nil), f.deletes...)
}

func (f *fakeAPI) setUnauthorized(v bool) {
	f.mu.Lock()
	f.unauthorized = v
	f.mu.Unlock()
}

// handleDeleteDirect removes a Pod without an API call, simulating an
// eviction, a node drain, or someone running `kubectl delete` — the cases
// where the Pod disappears and the driver was not the one who asked.
func (f *fakeAPI) handleDeleteDirect(name string) {
	f.mu.Lock()
	p, ok := f.pods[name]
	delete(f.pods, name)
	f.logs[name].close()
	f.mu.Unlock()
	if !ok {
		return
	}
	raw, _ := json.Marshal(p)
	f.recordDeletion(name, raw)
}

// recordDeletion appends a DELETED frame to the Pod's history and broadcasts
// it to any live watcher.
func (f *fakeAPI) recordDeletion(name string, raw []byte) {
	ev := watchEvent{Type: "DELETED", Object: raw}
	f.mu.Lock()
	rv := len(f.history[name]) + 2
	f.history[name] = append(f.history[name], versionedEvent{rv: rv, ev: ev})
	watchers := append([]chan watchEvent(nil), f.watchers[name]...)
	f.mu.Unlock()
	for _, ch := range watchers {
		select {
		case ch <- ev:
		case <-time.After(time.Second):
		}
	}
}

// seedPod inserts a Pod directly, bypassing create — used to simulate the
// orphans a killed control plane leaves behind.
func (f *fakeAPI) seedPod(name string, labels map[string]string, phase string, age time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pods[name] = &pod{
		Metadata: objectMeta{
			Name:              name,
			Namespace:         "cloop",
			Labels:            labels,
			ResourceVersion:   "1",
			CreationTimestamp: time.Now().Add(-age).UTC().Format(time.RFC3339),
		},
		Status: podStatus{Phase: phase},
	}
	f.logs[name] = newLogStream()
}

// --- response helpers -------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeStatus(w http.ResponseWriter, code int, reason, message string) {
	writeJSON(w, code, status{
		Kind: "Status", Status: "Failure",
		Reason: reason, Message: message, Code: code,
	})
}

// --- fake credential source -------------------------------------------

// fakeSource is a CredentialSource that hands out the fake API's config and
// counts every acquire, renew and release, so tests can assert the lease
// accounting the driver promises.
type fakeSource struct {
	rest *RESTConfig

	mu          sync.Mutex
	nextID      int
	acquired    []string
	released    []string
	renewals    int
	acquireErr  error
	renewErr    error
	leaseWindow time.Duration
}

func newFakeSource(rest *RESTConfig) *fakeSource {
	return &fakeSource{rest: rest, leaseWindow: 15 * time.Minute}
}

func (s *fakeSource) Describe() string { return "fake credential source" }

// Acquire implements CredentialSource.
func (s *fakeSource) Acquire(ctx context.Context, _ string) (*Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acquireErr != nil {
		return nil, s.acquireErr
	}
	return s.issueLocked(), nil
}

// Renew implements CredentialSource. A renewal that fails is how a revoked
// grant reaches the driver.
func (s *fakeSource) Renew(ctx context.Context, leaseID string) (*Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewals++
	if s.renewErr != nil {
		return nil, s.renewErr
	}
	// A real renewal supersedes the old lease: the broker drops it and
	// issues a new ID, so the old one must not stay counted as outstanding.
	s.released = append(s.released, leaseID)
	return s.issueLocked(), nil
}

// issueLocked mints a lease. Caller holds s.mu.
func (s *fakeSource) issueLocked() *Credentials {
	s.nextID++
	id := fmt.Sprintf("lease-%d", s.nextID)
	s.acquired = append(s.acquired, id)
	return &Credentials{
		Rest:       s.rest,
		LeaseID:    id,
		ExpiresAt:  time.Now().Add(s.leaseWindow),
		SecretName: "fake-kubeconfig",
		Namespace:  "cloop",
	}
}

func (s *fakeSource) setAcquireErr(err error) {
	s.mu.Lock()
	s.acquireErr = err
	s.mu.Unlock()
}

func (s *fakeSource) setRenewErr(err error) {
	s.mu.Lock()
	s.renewErr = err
	s.mu.Unlock()
}

func (s *fakeSource) setLeaseWindow(d time.Duration) {
	s.mu.Lock()
	s.leaseWindow = d
	s.mu.Unlock()
}

func (s *fakeSource) Release(leaseID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if leaseID != "" {
		s.released = append(s.released, leaseID)
	}
}

func (s *fakeSource) counts() (acquired, released, renewals int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.acquired), len(s.released), s.renewals
}

// outstanding returns the lease IDs acquired but never released. A non-empty
// result after a handle finishes is a leaked credential.
func (s *fakeSource) outstanding() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	rel := make(map[string]int, len(s.released))
	for _, id := range s.released {
		rel[id]++
	}
	var out []string
	for _, id := range s.acquired {
		if rel[id] > 0 {
			rel[id]--
			continue
		}
		out = append(out, id)
	}
	return out
}

// waitOutstandingEmpty polls until every lease is released or the deadline
// passes, since release happens on the pump goroutine.
func (s *fakeSource) waitOutstandingEmpty(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if len(s.outstanding()) == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("leases still held after %s: %v", d, s.outstanding())
}
