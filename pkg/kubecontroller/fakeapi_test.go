package kubecontroller

// fakeapi_test.go stands up an httptest TLS server that speaks enough of the
// Kubernetes API for the controller to be run end to end against it: list
// and watch with resourceVersions and history, 410 for a resourceVersion it
// no longer holds, label selectors, the status subresource, create/delete
// with uid preconditions, ownerReference garbage collection, Leases with
// optimistic concurrency, and Events.
//
// A fake rather than a mock, for the reason pkg/executor/kubernetes's is one:
// the controller's interesting bugs are sequencing bugs — a watch that misses
// what happened between its list and its start, a create the cache has not
// shown yet, two replicas racing for a Lease — and they only show up against
// something that holds connections open and delivers events in order.

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// fakeObj is one stored object.
type fakeObj struct {
	kind string // "pools", "pods", "secrets", "leases", "events", "persistentvolumeclaims"
	ns   string
	name string
	body map[string]any
}

func (o *fakeObj) meta() map[string]any {
	m, _ := o.body["metadata"].(map[string]any)
	if m == nil {
		m = map[string]any{}
		o.body["metadata"] = m
	}
	return m
}

type fakeEvent struct {
	rv   int
	kind string
	ns   string
	typ  string
	obj  map[string]any
}

type fakeCall struct {
	Method, Path, Query string
}

type fakeK8s struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	rv      int
	nextUID int
	objs    map[string]*fakeObj // kind/ns/name
	history []fakeEvent
	// compactedBelow answers a watch from an older resourceVersion 410.
	compactedBelow int
	waiters        []chan struct{}
	calls          []fakeCall
	// failures maps "METHOD substring" to a status code, for every matching
	// call while set.
	failures map[string]int
	// onCreatePod, when set, may refuse a Pod create with a status code.
	onCreatePod func(pod map[string]any) int
	// watchesOpen counts watch requests in flight.
	watchesOpen int
	// claimPhase decides a new claim's phase by its storage class: Bound
	// unless it says otherwise, as a provisioner that binds at once would.
	claimPhase func(class string) string
	// onPatch, when set, runs before a PATCH is applied — a test's moment to
	// change the object under the patcher.
	onPatch func(kind, name string)
	// patches counts PATCH requests, and conflicts the 409s they got.
	patches, conflicts int
}

func newFakeK8s(t *testing.T) *fakeK8s {
	t.Helper()
	f := &fakeK8s{t: t, objs: map[string]*fakeObj{}, failures: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.route))
	t.Cleanup(func() {
		f.mu.Lock()
		for _, w := range f.waiters {
			close(w)
		}
		f.waiters = nil
		f.mu.Unlock()
		f.srv.CloseClientConnections()
		f.srv.Close()
	})
	return f
}

func (f *fakeK8s) restConfig() *kubernetes.RESTConfig {
	cert := f.srv.Certificate()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return &kubernetes.RESTConfig{Server: f.srv.URL, CAData: caPEM, BearerToken: "fake-token", Namespace: "runners"}
}

func objKey(kind, ns, name string) string { return kind + "/" + ns + "/" + name }

// ── routing ────────────────────────────────────────────────────────────────

// parsedPath is a request path, decoded.
type parsedPath struct {
	kind, ns, name, sub string
}

func parsePath(p string) (parsedPath, bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	// /api/v1/namespaces/{ns}/{res}[/{name}[/{sub}]]
	// /apis/{group}/{version}/namespaces/{ns}/{res}[/{name}[/{sub}]]
	// /api/v1/{res} or /apis/{g}/{v}/{res} (all namespaces)
	var rest []string
	switch {
	case len(parts) >= 2 && parts[0] == "api":
		rest = parts[2:]
	case len(parts) >= 3 && parts[0] == "apis":
		rest = parts[3:]
	default:
		return parsedPath{}, false
	}
	var out parsedPath
	if len(rest) >= 2 && rest[0] == "namespaces" {
		out.ns = rest[1]
		rest = rest[2:]
	}
	if len(rest) == 0 {
		return parsedPath{}, false
	}
	res := rest[0]
	switch res {
	case Plural:
		out.kind = "pools"
	case "pods", "secrets", "leases", "events", "persistentvolumeclaims":
		out.kind = res
	default:
		return parsedPath{}, false
	}
	if len(rest) >= 2 {
		out.name, _ = url.PathUnescape(rest[1])
	}
	if len(rest) >= 3 {
		out.sub = rest[2]
	}
	return out, true
}

func (f *fakeK8s) route(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery})
	for k, code := range f.failures {
		method, sub, _ := strings.Cut(k, " ")
		if method == r.Method && strings.Contains(r.URL.Path+"?"+r.URL.RawQuery, sub) {
			f.mu.Unlock()
			writeK8sStatus(w, code, "Injected", "injected failure")
			return
		}
	}
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer fake-token" {
		writeK8sStatus(w, 401, "Unauthorized", "bad token")
		return
	}
	p, ok := parsePath(r.URL.Path)
	if !ok {
		writeK8sStatus(w, 404, "NotFound", "no route for "+r.URL.Path)
		return
	}
	switch {
	case r.Method == http.MethodGet && p.name == "" && r.URL.Query().Get("watch") == "true":
		f.handleWatch(w, r, p)
	case r.Method == http.MethodGet && p.name == "":
		f.handleList(w, r, p)
	case r.Method == http.MethodGet:
		f.handleGet(w, p)
	case r.Method == http.MethodPost && p.name == "":
		f.handleCreate(w, r, p)
	case r.Method == http.MethodPut:
		f.handleUpdate(w, r, p)
	case r.Method == http.MethodPatch:
		f.handlePatch(w, r, p)
	case r.Method == http.MethodDelete:
		f.handleDelete(w, r, p)
	default:
		writeK8sStatus(w, 405, "MethodNotAllowed", r.Method+" "+r.URL.Path)
	}
}

func writeK8sStatus(w http.ResponseWriter, code int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "status": "Failure", "reason": reason,
		"message": msg, "code": code})
}

func writeK8sJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ── store ──────────────────────────────────────────────────────────────────

// putLocked stores an object and records the event. Caller holds f.mu.
func (f *fakeK8s) putLocked(o *fakeObj, typ string) {
	f.rv++
	o.meta()["resourceVersion"] = strconv.Itoa(f.rv)
	f.objs[objKey(o.kind, o.ns, o.name)] = o
	f.history = append(f.history, fakeEvent{rv: f.rv, kind: o.kind, ns: o.ns, typ: typ, obj: deepCopyMap(o.body)})
	f.wakeLocked()
}

func (f *fakeK8s) wakeLocked() {
	for _, w := range f.waiters {
		close(w)
	}
	f.waiters = nil
}

// deleteLocked removes an object, its dependents with it. Caller holds f.mu.
func (f *fakeK8s) deleteLocked(o *fakeObj) {
	delete(f.objs, objKey(o.kind, o.ns, o.name))
	f.rv++
	gone := deepCopyMap(o.body)
	gone["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.rv)
	f.history = append(f.history, fakeEvent{rv: f.rv, kind: o.kind, ns: o.ns, typ: "DELETED", obj: gone})
	uid, _ := o.meta()["uid"].(string)
	// The garbage collector: everything owned by uid goes too.
	var owned []*fakeObj
	for _, other := range f.objs {
		refs, _ := other.meta()["ownerReferences"].([]any)
		for _, r := range refs {
			if rm, _ := r.(map[string]any); rm != nil && rm["uid"] == uid {
				owned = append(owned, other)
				break
			}
		}
	}
	for _, other := range owned {
		f.deleteLocked(other)
	}
	f.wakeLocked()
}

func deepCopyMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func matchesLabels(obj map[string]any, selector string) bool {
	if strings.TrimSpace(selector) == "" {
		return true
	}
	meta, _ := obj["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	for _, term := range strings.Split(selector, ",") {
		k, v, eq := strings.Cut(strings.TrimSpace(term), "=")
		got, ok := labels[k]
		if !ok || (eq && got != v) {
			return false
		}
	}
	return true
}

// ── handlers ───────────────────────────────────────────────────────────────

func (f *fakeK8s) handleList(w http.ResponseWriter, r *http.Request, p parsedPath) {
	sel := r.URL.Query().Get("labelSelector")
	f.mu.Lock()
	var items []map[string]any
	keys := make([]string, 0, len(f.objs))
	for k := range f.objs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		o := f.objs[k]
		if o.kind == p.kind && (p.ns == "" || o.ns == p.ns) && matchesLabels(o.body, sel) {
			items = append(items, deepCopyMap(o.body))
		}
	}
	rv := strconv.Itoa(f.rv)
	f.mu.Unlock()
	if items == nil {
		items = []map[string]any{}
	}
	writeK8sJSON(w, 200, map[string]any{"metadata": map[string]any{"resourceVersion": rv}, "items": items})
}

func (f *fakeK8s) handleGet(w http.ResponseWriter, p parsedPath) {
	f.mu.Lock()
	o, ok := f.objs[objKey(p.kind, p.ns, p.name)]
	var body map[string]any
	if ok {
		body = deepCopyMap(o.body)
	}
	f.mu.Unlock()
	if !ok {
		writeK8sStatus(w, 404, "NotFound", fmt.Sprintf("%s %q not found", p.kind, p.name))
		return
	}
	writeK8sJSON(w, 200, body)
}

func (f *fakeK8s) handleCreate(w http.ResponseWriter, r *http.Request, p parsedPath) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeK8sStatus(w, 400, "BadRequest", err.Error())
		return
	}
	meta, _ := body["metadata"].(map[string]any)
	if meta == nil {
		writeK8sStatus(w, 422, "Invalid", "no metadata")
		return
	}
	name, _ := meta["name"].(string)
	f.mu.Lock()
	defer f.mu.Unlock()
	if name == "" {
		gen, _ := meta["generateName"].(string)
		if gen == "" {
			writeK8sStatus(w, 422, "Invalid", "metadata.name or metadata.generateName is required")
			return
		}
		f.nextUID++
		name = fmt.Sprintf("%s%05d", gen, f.nextUID)
		meta["name"] = name
	}
	if p.kind == "pods" && f.onCreatePod != nil {
		if code := f.onCreatePod(body); code != 0 {
			writeK8sStatus(w, code, "Forbidden", "pods \""+name+"\" is forbidden: violates PodSecurity \"restricted:latest\"")
			return
		}
	}
	if _, exists := f.objs[objKey(p.kind, p.ns, name)]; exists {
		writeK8sStatus(w, 409, "AlreadyExists", fmt.Sprintf("%s %q already exists", p.kind, name))
		return
	}
	f.nextUID++
	meta["uid"] = fmt.Sprintf("uid-%s-%d", name, f.nextUID)
	meta["namespace"] = p.ns
	meta["creationTimestamp"] = time.Now().UTC().Format(time.RFC3339)
	if p.kind == "pools" {
		meta["generation"] = 1
	}
	if p.kind == "pods" {
		body["status"] = map[string]any{"phase": PodPending}
	}
	if p.kind == "persistentvolumeclaims" {
		spec, _ := body["spec"].(map[string]any)
		class, _ := spec["storageClassName"].(string)
		phase := ClaimBound
		if f.claimPhase != nil {
			phase = f.claimPhase(class)
		}
		st := map[string]any{"phase": phase}
		if phase == ClaimBound {
			req, _ := spec["resources"].(map[string]any)["requests"].(map[string]any)
			st["capacity"] = map[string]any{"storage": req["storage"]}
		}
		body["status"] = st
		// The protection finalizer every claim gets, which a PUT of a partial
		// view would drop.
		meta["finalizers"] = []any{"kubernetes.io/pvc-protection"}
	}
	o := &fakeObj{kind: p.kind, ns: p.ns, name: name, body: body}
	f.putLocked(o, "ADDED")
	writeK8sJSON(w, 201, deepCopyMap(body))
}

func (f *fakeK8s) handleUpdate(w http.ResponseWriter, r *http.Request, p parsedPath) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeK8sStatus(w, 400, "BadRequest", err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.objs[objKey(p.kind, p.ns, p.name)]
	if !ok {
		writeK8sStatus(w, 404, "NotFound", p.name)
		return
	}
	meta, _ := body["metadata"].(map[string]any)
	if rv, _ := meta["resourceVersion"].(string); rv != "" && rv != cur.meta()["resourceVersion"] {
		writeK8sStatus(w, 409, "Conflict", "the object has been modified; please apply your changes to the latest version")
		return
	}
	next := deepCopyMap(cur.body)
	switch {
	case p.kind == "pools" && p.sub == "status":
		next["status"] = body["status"]
	case p.kind == "pools" && p.sub == "":
		next["spec"] = body["spec"]
		gen, _ := next["metadata"].(map[string]any)["generation"].(float64)
		next["metadata"].(map[string]any)["generation"] = gen + 1
	case p.kind == "leases":
		next["spec"] = body["spec"]
	default:
		writeK8sStatus(w, 405, "MethodNotAllowed", "update of "+p.kind)
		return
	}
	o := &fakeObj{kind: p.kind, ns: p.ns, name: p.name, body: next}
	f.putLocked(o, "MODIFIED")
	writeK8sJSON(w, 200, deepCopyMap(next))
}

// handlePatch applies a JSON merge patch to an object's metadata, with the
// API server's optimistic concurrency: a resourceVersion in the patch that is
// not the object's is a 409 Conflict, and nothing changes.
func (f *fakeK8s) handlePatch(w http.ResponseWriter, r *http.Request, p parsedPath) {
	if ct := r.Header.Get("Content-Type"); ct != "application/merge-patch+json" {
		writeK8sStatus(w, 415, "UnsupportedMediaType", "patch type "+ct)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeK8sStatus(w, 400, "BadRequest", err.Error())
		return
	}
	if hook := f.onPatchHook(); hook != nil {
		hook(p.kind, p.name)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.patches++
	cur, ok := f.objs[objKey(p.kind, p.ns, p.name)]
	if !ok {
		writeK8sStatus(w, 404, "NotFound", p.name)
		return
	}
	for k := range body {
		if k != "metadata" {
			writeK8sStatus(w, 422, "Invalid", "the fake applies metadata patches only, not "+k)
			return
		}
	}
	meta, _ := body["metadata"].(map[string]any)
	if rv, _ := meta["resourceVersion"].(string); rv != "" && rv != cur.meta()["resourceVersion"] {
		f.conflicts++
		writeK8sStatus(w, 409, "Conflict", "the object has been modified; please apply your changes to the latest version")
		return
	}
	next := deepCopyMap(cur.body)
	nm := next["metadata"].(map[string]any)
	for _, field := range []string{"annotations", "labels"} {
		patch, ok := meta[field].(map[string]any)
		if !ok {
			continue
		}
		have, _ := nm[field].(map[string]any)
		if have == nil {
			have = map[string]any{}
		}
		for k, v := range patch {
			if v == nil {
				delete(have, k)
			} else {
				have[k] = v
			}
		}
		nm[field] = have
	}
	if refs, ok := meta["ownerReferences"]; ok {
		nm["ownerReferences"] = refs
	}
	o := &fakeObj{kind: p.kind, ns: p.ns, name: p.name, body: next}
	f.putLocked(o, "MODIFIED")
	writeK8sJSON(w, 200, deepCopyMap(next))
}

func (f *fakeK8s) onPatchHook() func(kind, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.onPatch
}

func (f *fakeK8s) handleDelete(w http.ResponseWriter, r *http.Request, p parsedPath) {
	var opts struct {
		Preconditions *struct {
			UID string `json:"uid"`
		} `json:"preconditions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&opts)
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objs[objKey(p.kind, p.ns, p.name)]
	if !ok {
		writeK8sStatus(w, 404, "NotFound", p.name)
		return
	}
	if opts.Preconditions != nil && opts.Preconditions.UID != "" && opts.Preconditions.UID != o.meta()["uid"] {
		writeK8sStatus(w, 409, "Conflict", "Precondition failed: UID in precondition does not match")
		return
	}
	f.deleteLocked(o)
	writeK8sJSON(w, 200, map[string]any{"kind": "Status", "status": "Success"})
}

func (f *fakeK8s) handleWatch(w http.ResponseWriter, r *http.Request, p parsedPath) {
	q := r.URL.Query()
	from, _ := strconv.Atoi(q.Get("resourceVersion"))
	timeout, _ := strconv.Atoi(q.Get("timeoutSeconds"))
	if timeout <= 0 {
		timeout = 60
	}
	sel := q.Get("labelSelector")
	f.mu.Lock()
	if from < f.compactedBelow {
		f.mu.Unlock()
		writeK8sStatus(w, 410, "Expired", "too old resource version")
		return
	}
	f.watchesOpen++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.watchesOpen--
		f.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}
	enc := json.NewEncoder(w)
	deadline := time.NewTimer(time.Duration(timeout) * time.Second)
	defer deadline.Stop()
	last := from
	for {
		f.mu.Lock()
		var out []fakeEvent
		for _, ev := range f.history {
			if ev.rv > last && ev.kind == p.kind && (p.ns == "" || ev.ns == p.ns) && matchesLabels(ev.obj, sel) {
				out = append(out, ev)
			}
			if ev.rv > last {
				last = max(last, ev.rv)
			}
		}
		wake := make(chan struct{})
		f.waiters = append(f.waiters, wake)
		f.mu.Unlock()
		for _, ev := range out {
			if err := enc.Encode(map[string]any{"type": ev.typ, "object": ev.obj}); err != nil {
				return
			}
		}
		if fl != nil && len(out) > 0 {
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			return
		case <-wake:
		}
	}
}

// ── test helpers ───────────────────────────────────────────────────────────

// apply creates or replaces an object from a typed value.
func (f *fakeK8s) apply(kind, ns string, v any) map[string]any {
	f.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		f.t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		f.t.Fatal(err)
	}
	meta := body["metadata"].(map[string]any)
	name := meta["name"].(string)
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.objs[objKey(kind, ns, name)]; ok {
		next := deepCopyMap(cur.body)
		next["spec"] = body["spec"]
		if kind == "pools" {
			gen, _ := next["metadata"].(map[string]any)["generation"].(float64)
			next["metadata"].(map[string]any)["generation"] = gen + 1
		}
		if labels, ok := meta["labels"]; ok {
			next["metadata"].(map[string]any)["labels"] = labels
		}
		f.putLocked(&fakeObj{kind: kind, ns: ns, name: name, body: next}, "MODIFIED")
		return deepCopyMap(next)
	}
	f.nextUID++
	if meta["uid"] == nil {
		meta["uid"] = fmt.Sprintf("uid-%s-%d", name, f.nextUID)
	}
	meta["namespace"] = ns
	if meta["creationTimestamp"] == nil {
		meta["creationTimestamp"] = time.Now().UTC().Format(time.RFC3339)
	}
	if kind == "pools" {
		meta["generation"] = 1
	}
	f.putLocked(&fakeObj{kind: kind, ns: ns, name: name, body: body}, "ADDED")
	return deepCopyMap(body)
}

// setPodPhase moves a Pod to phase, with a terminated runner container when
// the phase is terminal.
func (f *fakeK8s) setPodPhase(ns, name, phase string, exitCode int, message string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objs[objKey("pods", ns, name)]
	if !ok {
		f.t.Fatalf("no Pod %s/%s", ns, name)
	}
	next := deepCopyMap(o.body)
	status := map[string]any{"phase": phase}
	if phase == PodSucceeded || phase == PodFailed {
		status["containerStatuses"] = []any{map[string]any{"name": runnerContainer, "state": map[string]any{
			"terminated": map[string]any{"exitCode": exitCode, "message": message}}}}
	}
	next["status"] = status
	f.putLocked(&fakeObj{kind: "pods", ns: ns, name: name, body: next}, "MODIFIED")
}

// setPodStatus replaces a Pod's status with what set makes of it.
func (f *fakeK8s) setPodStatus(ns, name string, set func(status map[string]any)) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objs[objKey("pods", ns, name)]
	if !ok {
		f.t.Fatalf("no Pod %s/%s", ns, name)
	}
	next := deepCopyMap(o.body)
	status, _ := next["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
	}
	set(status)
	next["status"] = status
	f.putLocked(&fakeObj{kind: "pods", ns: ns, name: name, body: next}, "MODIFIED")
}

// removeObject deletes an object as a user would.
func (f *fakeK8s) removeObject(kind, ns, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.objs[objKey(kind, ns, name)]; ok {
		f.deleteLocked(o)
	}
}

// names lists the stored objects of kind in ns.
func (f *fakeK8s) names(kind, ns string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, o := range f.objs {
		if o.kind == kind && o.ns == ns {
			out = append(out, o.name)
		}
	}
	sort.Strings(out)
	return out
}

// object returns a stored object's JSON.
func (f *fakeK8s) object(kind, ns, name string) (map[string]any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objs[objKey(kind, ns, name)]
	if !ok {
		return nil, false
	}
	return deepCopyMap(o.body), true
}

// decode returns a stored object decoded into v.
func (f *fakeK8s) decode(kind, ns, name string, v any) bool {
	obj, ok := f.object(kind, ns, name)
	if !ok {
		return false
	}
	b, _ := json.Marshal(obj)
	return json.Unmarshal(b, v) == nil
}

// eventsFor returns the reasons of the Events recorded in ns.
func (f *fakeK8s) eventReasons(ns string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, o := range f.objs {
		if o.kind == "events" && o.ns == ns {
			r, _ := o.body["reason"].(string)
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// eventMessages returns the messages of the Events with reason in ns.
func (f *fakeK8s) eventMessages(ns, reason string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, o := range f.objs {
		if o.kind == "events" && o.ns == ns && o.body["reason"] == reason {
			m, _ := o.body["message"].(string)
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// callLog returns the calls so far.
func (f *fakeK8s) callLog() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

// compact makes every resourceVersion up to now too old to watch from.
func (f *fakeK8s) compact() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.compactedBelow = f.rv + 1
}

// fail makes calls matching "METHOD substring" answer code; 0 clears it.
func (f *fakeK8s) fail(key string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if code == 0 {
		delete(f.failures, key)
		return
	}
	f.failures[key] = code
}
