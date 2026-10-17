package kubernetes

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// The node's kernel and a Kata guest's, as the probe reads them. The node is
// sgx's own capture (runc reads its host's boot ID); the guest is the QEMU q35
// guest captured on sgx, standing in for a Kata Pod (pkg/isolationprobe's
// testdata says how each was captured).
var (
	nodeKernel = isolationprobe.Evidence{
		Schema: 1, Release: "6.8.0-79-generic", Version: "#79-Ubuntu SMP PREEMPT_DYNAMIC Tue Aug 12 14:42:46 UTC 2025",
		Machine: "x86_64", BootID: "2d725fb0-4ac8-4443-b68c-8c50313f7439", UptimeSeconds: 14460005,
		Hypervisor: true, DMIVendor: "Alibaba Cloud", DMIProduct: "Alibaba Cloud ECS",
	}
	kataGuest = isolationprobe.Evidence{
		Schema: 1, Release: "6.6.142-0-virt", Version: "#1-Alpine SMP PREEMPT_DYNAMIC 2026-06-04 05:37:20",
		Machine: "x86_64", BootID: "37031ef6-ddd1-44bb-a61d-990106817d96", UptimeSeconds: 1.88,
		Hypervisor: true, DMIVendor: "QEMU", DMIProduct: "Standard PC (Q35 + ICH9, 2009)",
	}
)

// fakeKubelet runs probe Pods: it schedules each onto a node, writes what the
// kernel under its RuntimeClass would report, and terminates it. handlers maps
// a RuntimeClass name to the evidence a Pod under it prints — which is how a
// test says "this cluster's kata class is really runc".
type fakeKubelet struct {
	api      *fakeAPI
	node     string
	handlers map[string]isolationprobe.Evidence
	// output overrides what a Pod under the named RuntimeClass prints, and exit
	// its exit code: an image whose cloop predates the probe.
	output map[string]string
	exit   int
	// rehome moves the reference Pod to another node, which no real API server
	// does to a Pod created with spec.nodeName — the guard is tested anyway.
	rehome string

	mu      sync.Mutex
	created map[string]pod
	stop    chan struct{}
	done    chan struct{}
}

func startFakeKubelet(t *testing.T, api *fakeAPI, k *fakeKubelet) *fakeKubelet {
	t.Helper()
	prev := probePollInterval
	probePollInterval = 2 * time.Millisecond
	k.api, k.created = api, map[string]pod{}
	k.stop, k.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(k.done)
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-k.stop:
				return
			case <-tick.C:
				k.step()
			}
		}
	}()
	t.Cleanup(func() {
		close(k.stop)
		<-k.done
		probePollInterval = prev
	})
	return k
}

func (k *fakeKubelet) step() {
	for _, name := range k.api.podNames() {
		k.mu.Lock()
		_, seen := k.created[name]
		k.mu.Unlock()
		if seen {
			continue
		}
		k.api.mu.Lock()
		p := *k.api.pods[name]
		k.api.mu.Unlock()
		k.mu.Lock()
		k.created[name] = p
		k.mu.Unlock()

		node := k.node
		if p.Spec.NodeName != "" {
			node = p.Spec.NodeName
			if k.rehome != "" {
				node = k.rehome
			}
		}
		k.api.setPhase(name, func(p *pod) { p.Spec.NodeName = node })
		k.api.run(name)
		rc := p.Spec.RuntimeClassName
		out, ok := k.output[rc]
		if !ok {
			line, _ := isolationprobe.Encode(k.handlers[rc])
			out = string(line)
		}
		k.api.emitLog(name, out)
		code := 0
		if _, overridden := k.output[rc]; overridden {
			code = k.exit
		}
		k.api.terminate(name, code, "Completed")
	}
}

func (k *fakeKubelet) pods() map[string]pod {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make(map[string]pod, len(k.created))
	for n, p := range k.created {
		out[n] = p
	}
	return out
}

func probeK8s(t *testing.T, runtimeClass string) (*Executor, *fakeAPI) {
	t.Helper()
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.RuntimeClass = runtimeClass })
	return ex, api
}

func runIsolationProbe(t *testing.T, ex *Executor) (isolationprobe.Verdict, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p, err := ex.ProbeIsolation(ctx)
	if err != nil {
		return isolationprobe.Verdict{}, err
	}
	return p.Verdict(), nil
}

// TestIsolationProbe_RuntimeClassWhoseHandlerIsRunc is the RuntimeClass the
// task names: called kata, handled by runc. The probe Pod and the reference
// Pod read the same kernel instance, and the claim is contradicted.
func TestIsolationProbe_RuntimeClassWhoseHandlerIsRunc(t *testing.T) {
	ex, api := probeK8s(t, "kata")
	if !ex.Capabilities().Virtualized {
		t.Fatal("a kata RuntimeClass no longer claims virtualization; this test is about that claim")
	}
	k := startFakeKubelet(t, api, &fakeKubelet{node: "node-a", handlers: map[string]isolationprobe.Evidence{
		"kata": nodeKernel, "": nodeKernel,
	}})

	v, err := runIsolationProbe(t, ex)
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != isolationprobe.KindHostKernel {
		t.Fatalf("verdict = %s (%s), want host-kernel", v.Kind, v.Detail)
	}
	if got := isolationprobe.Judge(isolationprobe.KindVM, v.Kind); got != isolationprobe.StatusContradicted {
		t.Fatalf("Judge = %s, want contradicted", got)
	}

	// Two Pods: the probe under the claimed class, unpinned; the reference on
	// the probe's node under the default runtime.
	var probe, ref *pod
	for name, p := range k.pods() {
		p := p
		switch {
		case strings.HasSuffix(name, "-probe"):
			probe = &p
		case strings.HasSuffix(name, "-reference"):
			ref = &p
		}
	}
	if probe == nil || ref == nil {
		t.Fatalf("want a probe and a reference Pod, got %v", api.podNames())
	}
	if probe.Spec.RuntimeClassName != "kata" || probe.Spec.NodeName != "" {
		t.Errorf("probe Pod: runtimeClassName=%q nodeName=%q", probe.Spec.RuntimeClassName, probe.Spec.NodeName)
	}
	if ref.Spec.RuntimeClassName != "" || ref.Spec.NodeName != "node-a" {
		t.Errorf("reference Pod: runtimeClassName=%q nodeName=%q, want the default runtime on node-a",
			ref.Spec.RuntimeClassName, ref.Spec.NodeName)
	}
	for _, p := range []*pod{probe, ref} {
		c := p.Spec.Containers[0]
		if strings.Join(c.Command, " ") != "cloop isolation-probe" || c.Image != ex.opts.Image {
			t.Errorf("container runs %q in %s", c.Command, c.Image)
		}
		if p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
			t.Error("a probe Pod must not mount a service account token")
		}
		if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil ||
			!*c.SecurityContext.ReadOnlyRootFilesystem {
			t.Error("a probe Pod's root filesystem must be read-only")
		}
		if p.Metadata.Labels[LabelTaskID] == "" {
			t.Error("a probe Pod must be visible to the orphan sweep")
		}
	}
	assertIsolationProbeCleanedUp(t, api, 2)
}

// TestIsolationProbe_KataPod: the class really is Kata. The probe Pod's kernel
// is a guest's — its own boot ID, QEMU's firmware tables — and the claim is
// verified against the node's kernel the reference read.
func TestIsolationProbe_KataPod(t *testing.T) {
	ex, api := probeK8s(t, "kata-qemu")
	startFakeKubelet(t, api, &fakeKubelet{node: "node-a", handlers: map[string]isolationprobe.Evidence{
		"kata-qemu": kataGuest, "": nodeKernel,
	}})
	v, err := runIsolationProbe(t, ex)
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != isolationprobe.KindVM {
		t.Fatalf("verdict = %s (%s), want vm", v.Kind, v.Detail)
	}
	assertIsolationProbeCleanedUp(t, api, 2)
}

// TestIsolationProbe_StaysWithinTheExecutorRole: every request the probe makes
// is one the executor Role grants — pods create, get and delete, pods/log get
// — and nothing reads a Node, which the namespaced Role cannot grant.
func TestIsolationProbe_StaysWithinTheExecutorRole(t *testing.T) {
	ex, api := probeK8s(t, "kata")
	startFakeKubelet(t, api, &fakeKubelet{node: "node-a", handlers: map[string]isolationprobe.Evidence{
		"kata": nodeKernel, "": nodeKernel,
	}})
	if _, err := runIsolationProbe(t, ex); err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	reqs := append([]string(nil), api.requests...)
	api.mu.Unlock()
	for _, r := range reqs {
		method, path, _ := strings.Cut(r, " ")
		var verb string
		switch {
		case strings.Contains(path, "/nodes"):
			t.Fatalf("the probe read a Node: %s", r)
		case strings.HasSuffix(path, "/log") && method == "GET":
			verb = "pods/log get"
		case strings.HasSuffix(path, "/pods") && method == "POST":
			verb = "pods create"
		case strings.Contains(path, "/pods/") && method == "GET":
			verb = "pods get"
		case strings.Contains(path, "/pods/") && method == "DELETE":
			verb = "pods delete"
		default:
			t.Fatalf("request %s is not one the probe should make", r)
		}
		if !roleGrants(verb) {
			t.Errorf("%s needs %s, which the executor Role does not grant", r, verb)
		}
	}
}

// roleGrants reads the executor Role table the chart and CI are checked
// against.
func roleGrants(verb string) bool {
	resource, v, _ := strings.Cut(verb, " ")
	for _, rule := range executorRole {
		if rule.Group != "" || rule.Resource != resource {
			continue
		}
		for _, rv := range rule.Verbs {
			if rv == v {
				return true
			}
		}
	}
	return false
}

// TestIsolationProbe_AnImageWithoutTheProbe: an image whose cloop predates the
// probe answers with an unknown command, which is a failed probe naming the
// image — never a verdict.
func TestIsolationProbe_AnImageWithoutTheProbe(t *testing.T) {
	ex, api := probeK8s(t, "kata")
	startFakeKubelet(t, api, &fakeKubelet{node: "node-a",
		output: map[string]string{"kata": "Error: unknown command \"isolation-probe\" for \"cloop\"\n"}, exit: 1})
	_, err := runIsolationProbe(t, ex)
	if err == nil {
		t.Fatal("a probe that printed no evidence produced a verdict")
	}
	if !strings.Contains(err.Error(), ex.opts.Image) || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("error %q should name the image and quote its answer", err)
	}
	assertIsolationProbeCleanedUp(t, api, 1)
}

// TestIsolationProbe_RefusesAReferenceFromAnotherNode: comparing two nodes'
// kernels would read a second machine as isolation.
func TestIsolationProbe_RefusesAReferenceFromAnotherNode(t *testing.T) {
	ex, api := probeK8s(t, "kata")
	startFakeKubelet(t, api, &fakeKubelet{node: "node-a", rehome: "node-b", handlers: map[string]isolationprobe.Evidence{
		"kata": nodeKernel, "": kataGuest,
	}})
	if _, err := runIsolationProbe(t, ex); err == nil || !strings.Contains(err.Error(), "node-b") {
		t.Fatalf("err = %v, want a refusal naming the other node", err)
	}
}

func assertIsolationProbeCleanedUp(t *testing.T, api *fakeAPI, created int) {
	t.Helper()
	deleted := map[string]bool{}
	for _, d := range api.deleteRecords() {
		if strings.HasPrefix(d.Name, isolationProbeNamePrefix) {
			deleted[d.Name] = true
		}
	}
	if len(deleted) != created {
		t.Errorf("the probe deleted %d of its %d Pods (%v)", len(deleted), created, deleted)
	}
}

// TestBuildIsolationProbePod_Serialises pins the two fields the comparison
// rests on to the names the API server reads.
func TestBuildIsolationProbePod_Serialises(t *testing.T) {
	p := buildIsolationProbePod("cloop-isolation-probe-x-reference", "cloop", "k8s", "run", "", "node-a",
		Options{Image: "img", Namespace: "cloop"})
	raw, err := json.Marshal(p.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"nodeName":"node-a"`) || strings.Contains(string(raw), "runtimeClassName") {
		t.Errorf("reference Pod spec = %s", raw)
	}
	p = buildIsolationProbePod("cloop-isolation-probe-x-probe", "cloop", "k8s", "run", "kata", "",
		Options{Image: "img", Namespace: "cloop"})
	raw, _ = json.Marshal(p.Spec)
	if !strings.Contains(string(raw), `"runtimeClassName":"kata"`) || strings.Contains(string(raw), "nodeName") {
		t.Errorf("probe Pod spec = %s", raw)
	}
}
