package kubeguard

// inspect_test.go proves the writes a write grant must not be able to make
// (Task 20420): a ServiceAccount token Secret, a workload running as another
// ServiceAccount or reaching the node, RBAC, a CertificateSigningRequest — and
// that a body the monitor cannot read is refused rather than forwarded.
//
// Every refusal is checked twice, as the rest of the package's tests are:
// InspectWrite and Decide on their own, and through the proxy, where the
// stand-in API server must never see the refused request.

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// writePolicy is what a write grant's session runs under: every verb, one
// namespace.
func writePolicy() Policy {
	p := Policy{Verbs: allVerbs(), Namespaces: []string{"app"}}
	p.Normalize()
	return p
}

// inspect runs one write through Decide and, where its body decides, through
// InspectWrite, the way the proxy does.
func inspect(t *testing.T, method, target, contentType, body string) error {
	t.Helper()
	r := mustParse(t, method, target)
	if err := writePolicy().Decide(r); err != nil {
		return err
	}
	if !NeedsBody(r) {
		return nil
	}
	return InspectWrite(r, contentType, "", []byte(body))
}

func wantReason(t *testing.T, err error, want DenyReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("allowed; want a %s refusal", want)
	}
	if !errors.Is(err, ErrDenied) {
		t.Errorf("error does not wrap ErrDenied: %v", err)
	}
	if got, _ := DenyReasonOf(err); got != want {
		t.Errorf("reason = %q, want %q (%v)", got, want, err)
	}
}

func TestServiceAccountTokenSecretsAreRefused(t *testing.T) {
	const secrets = "/api/v1/namespaces/app/secrets"
	const one = secrets + "/creds"
	cases := []struct {
		name, method, target, ct, body string
	}{
		{"create", http.MethodPost, secrets, "application/json",
			`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"t","annotations":{"kubernetes.io/service-account.name":"deployer"}},"type":"kubernetes.io/service-account-token"}`},
		{"create, the type alone", http.MethodPost, secrets, "application/json",
			`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"t"},"type":"kubernetes.io/service-account-token"}`},
		{"create as YAML", http.MethodPost, secrets, "application/yaml",
			"apiVersion: v1\nkind: Secret\nmetadata:\n  name: t\ntype: kubernetes.io/service-account-token\n"},
		{"create with no Content-Type", http.MethodPost, secrets, "",
			`{"kind":"Secret","type":"kubernetes.io/service-account-token"}`},
		{"the harmless copy of a repeated key first", http.MethodPost, secrets, "application/json",
			`{"kind":"Secret","type":"Opaque","type":"kubernetes.io/service-account-token"}`},
		{"the dangerous copy of a repeated key first", http.MethodPost, secrets, "application/json",
			`{"kind":"Secret","type":"kubernetes.io/service-account-token","type":"Opaque"}`},
		{"update", http.MethodPut, one, "application/json",
			`{"kind":"Secret","metadata":{"name":"creds"},"type":"kubernetes.io/service-account-token"}`},
		{"merge patch re-pointing an existing token Secret", http.MethodPatch, one, "application/merge-patch+json",
			`{"metadata":{"annotations":{"kubernetes.io/service-account.name":"deployer","kubernetes.io/service-account.uid":"1"}}}`},
		{"JSON patch, by path", http.MethodPatch, one, "application/json-patch+json",
			`[{"op":"add","path":"/metadata/annotations/kubernetes.io~1service-account.name","value":"deployer"}]`},
		{"JSON patch, by value", http.MethodPatch, one, "application/json-patch+json",
			`[{"op":"replace","path":"/type","value":"kubernetes.io/service-account-token"}]`},
		{"server-side apply", http.MethodPatch, one, "application/apply-patch+yaml",
			"apiVersion: v1\nkind: Secret\nmetadata:\n  name: creds\ntype: kubernetes.io/service-account-token\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantReason(t, inspect(t, c.method, c.target, c.ct, c.body), DenyServiceAccountTokenSecret)
		})
	}
}

func TestOrdinarySecretsStillWrite(t *testing.T) {
	for _, c := range []struct{ method, target, ct, body string }{
		{http.MethodPost, "/api/v1/namespaces/app/secrets", "application/json",
			`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db"},"type":"Opaque","stringData":{"password":"x"}}`},
		{http.MethodPost, "/api/v1/namespaces/app/secrets", "application/json; charset=utf-8",
			`{"kind":"Secret","metadata":{"name":"tls"},"type":"kubernetes.io/tls"}`},
		{http.MethodPatch, "/api/v1/namespaces/app/secrets/db", "application/strategic-merge-patch+json",
			`{"stringData":{"password":"y"}}`},
	} {
		if err := inspect(t, c.method, c.target, c.ct, c.body); err != nil {
			t.Errorf("%s %s refused: %v", c.method, c.target, err)
		}
	}
}

// TestWorkloadsMayRunOnlyAsTheDefaultServiceAccount covers a Pod and every
// controller that stamps Pods out of a template.
func TestWorkloadsMayRunOnlyAsTheDefaultServiceAccount(t *testing.T) {
	podSpec := func(sa string) string {
		if sa == "-" {
			return `{"containers":[{"name":"c","image":"busybox"}]}`
		}
		return fmt.Sprintf(`{"serviceAccountName":%q,"containers":[{"name":"c","image":"busybox"}]}`, sa)
	}
	templated := func(kind, sa string) string {
		return fmt.Sprintf(`{"kind":%q,"spec":{"template":{"spec":%s}}}`, kind, podSpec(sa))
	}
	workloads := []struct{ path, kind string }{
		{"/apis/apps/v1/namespaces/app/deployments", "Deployment"},
		{"/apis/apps/v1/namespaces/app/replicasets", "ReplicaSet"},
		{"/apis/apps/v1/namespaces/app/statefulsets", "StatefulSet"},
		{"/apis/apps/v1/namespaces/app/daemonsets", "DaemonSet"},
		{"/apis/batch/v1/namespaces/app/jobs", "Job"},
		{"/api/v1/namespaces/app/replicationcontrollers", "ReplicationController"},
		{"/api/v1/namespaces/app/podtemplates", "PodTemplate"},
	}
	for _, w := range workloads {
		t.Run(w.kind, func(t *testing.T) {
			wantReason(t, inspect(t, http.MethodPost, w.path, "application/json", templated(w.kind, "deployer")),
				DenyWorkloadServiceAccount)
			for _, ok := range []string{"default", "", "-"} {
				if err := inspect(t, http.MethodPost, w.path, "application/json", templated(w.kind, ok)); err != nil {
					t.Errorf("serviceAccountName %q refused: %v", ok, err)
				}
			}
		})
	}
	t.Run("CronJob", func(t *testing.T) {
		body := `{"kind":"CronJob","spec":{"schedule":"* * * * *","jobTemplate":{"spec":{"template":{"spec":` +
			podSpec("deployer") + `}}}}}`
		wantReason(t, inspect(t, http.MethodPost, "/apis/batch/v1/namespaces/app/cronjobs", "application/json", body),
			DenyWorkloadServiceAccount)
	})

	pods := "/api/v1/namespaces/app/pods"
	for _, c := range []struct{ name, ct, body string }{
		{"a Pod", "application/json", `{"kind":"Pod","spec":` + podSpec("deployer") + `}`},
		{"the deprecated serviceAccount field", "application/json",
			`{"kind":"Pod","spec":{"serviceAccount":"deployer","containers":[]}}`},
		{"a repeated key, harmless first", "application/json",
			`{"kind":"Pod","spec":{"serviceAccountName":"default","serviceAccountName":"deployer"}}`},
		{"a repeated key, dangerous first", "application/json",
			`{"kind":"Pod","spec":{"serviceAccountName":"deployer","serviceAccountName":"default"}}`},
		{"another spelling", "application/json", `{"kind":"Pod","spec":{"ServiceAccountName":"deployer"}}`},
		{"not a string", "application/json", `{"kind":"Pod","spec":{"serviceAccountName":7}}`},
		{"YAML", "application/yaml", "kind: Pod\nspec:\n  serviceAccountName: deployer\n"},
		{"a YAML merge key", "application/yaml",
			"kind: Pod\nbase: &b\n  serviceAccountName: deployer\nspec:\n  <<: *b\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			wantReason(t, inspect(t, http.MethodPost, pods, c.ct, c.body), DenyWorkloadServiceAccount)
		})
	}

	deploy := "/apis/apps/v1/namespaces/app/deployments/web"
	for _, c := range []struct{ name, ct, body string }{
		{"strategic merge patch", "application/strategic-merge-patch+json",
			`{"spec":{"template":{"spec":{"serviceAccountName":"deployer"}}}}`},
		{"JSON patch to the field", "application/json-patch+json",
			`[{"op":"replace","path":"/spec/template/spec/serviceAccountName","value":"deployer"}]`},
		{"JSON patch replacing the whole spec", "application/json-patch+json",
			`[{"op":"replace","path":"/spec/template/spec","value":{"serviceAccountName":"deployer"}}]`},
		{"JSON patch copying a value in", "application/json-patch+json",
			`[{"op":"copy","from":"/metadata/name","path":"/spec/template/spec/serviceAccountName"}]`},
		{"server-side apply", "application/apply-patch+yaml",
			"apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      serviceAccountName: deployer\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			wantReason(t, inspect(t, http.MethodPatch, deploy, c.ct, c.body), DenyWorkloadServiceAccount)
		})
	}
	if err := inspect(t, http.MethodPatch, deploy, "application/json-patch+json",
		`[{"op":"remove","path":"/spec/template/spec/serviceAccountName"}]`); err != nil {
		t.Errorf("removing the field — which reverts to default — was refused: %v", err)
	}
}

// TestCustomResourcesNamingAServiceAccountAreRefused: a TaskRun, a Workflow or
// a Kustomization naming a ServiceAccount is a controller acting as it.
func TestCustomResourcesNamingAServiceAccountAreRefused(t *testing.T) {
	taskruns := "/apis/tekton.dev/v1/namespaces/app/taskruns"
	wantReason(t, inspect(t, http.MethodPost, taskruns, "application/json",
		`{"kind":"TaskRun","spec":{"serviceAccountName":"pipeline-admin"}}`), DenyWorkloadServiceAccount)
	if err := inspect(t, http.MethodPost, taskruns, "application/json", `{"kind":"TaskRun","spec":{}}`); err != nil {
		t.Errorf("a TaskRun with no ServiceAccount was refused: %v", err)
	}
	// A custom resource may claim a group under k8s.io; it is as unknown as
	// any other.
	for _, group := range []string{"pipelines.k8s.io", "gateway.networking.k8s.io"} {
		wantReason(t, inspect(t, http.MethodPost, "/apis/"+group+"/v1/namespaces/app/runs", "application/json",
			`{"kind":"Run","spec":{"serviceAccountName":"pipeline-admin"}}`), DenyWorkloadServiceAccount)
	}
	// The API server's own groups are known: an Ingress is not read.
	if err := inspect(t, http.MethodPost, "/apis/networking.k8s.io/v1/namespaces/app/ingresses",
		"application/vnd.kubernetes.protobuf", "\x6b\x38\x73\x00"); err != nil {
		t.Errorf("an Ingress was inspected: %v", err)
	}
	// A built-in kind that is not a workload is not read: a ConfigMap may
	// hold any text, including that word.
	if err := inspect(t, http.MethodPost, "/api/v1/namespaces/app/configmaps", "application/vnd.kubernetes.protobuf",
		"\x6b\x38\x73\x00 serviceAccountName: admin"); err != nil {
		t.Errorf("a ConfigMap was inspected: %v", err)
	}
	// Nor is a subresource: a Scale cannot change who a workload runs as.
	if err := inspect(t, http.MethodPatch, "/apis/apps/v1/namespaces/app/deployments/web/scale",
		"application/merge-patch+json", `{"spec":{"replicas":3}}`); err != nil {
		t.Errorf("a scale was inspected: %v", err)
	}
}

func TestWorkloadsThatReachTheNodeAreRefused(t *testing.T) {
	pods := "/api/v1/namespaces/app/pods"
	for _, c := range []struct{ name, ct, body string }{
		{"hostPath", "application/json",
			`{"kind":"Pod","spec":{"volumes":[{"name":"root","hostPath":{"path":"/"}}],"containers":[]}}`},
		{"hostPID", "application/json", `{"kind":"Pod","spec":{"hostPID":true}}`},
		{"hostIPC", "application/json", `{"kind":"Pod","spec":{"hostIPC":true}}`},
		{"hostNetwork", "application/json", `{"kind":"Pod","spec":{"hostNetwork":true}}`},
		{"privileged", "application/json",
			`{"kind":"Pod","spec":{"containers":[{"name":"c","securityContext":{"privileged":true}}]}}`},
		{"YAML 1.1's yes", "application/yaml", "kind: Pod\nspec:\n  hostPID: yes\n"},
		{"JSON patch adding a hostPath volume", "application/json-patch+json",
			`[{"op":"add","path":"/spec/volumes/-","value":{"name":"r","hostPath":{"path":"/var/lib/kubelet"}}}]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			method, target := http.MethodPost, pods
			if strings.HasSuffix(c.ct, "json-patch+json") {
				method, target = http.MethodPatch, "/apis/apps/v1/namespaces/app/daemonsets/agent"
			}
			wantReason(t, inspect(t, method, target, c.ct, c.body), DenyHostAccess)
		})
	}
	if err := inspect(t, http.MethodPost, pods, "application/json",
		`{"kind":"Pod","spec":{"hostNetwork":false,"containers":[{"name":"c","securityContext":{"privileged":false}}]}}`); err != nil {
		t.Errorf("a Pod saying false to every host access was refused: %v", err)
	}
}

func TestUnreadableWritesOfInspectedKindsAreRefused(t *testing.T) {
	pods := "/api/v1/namespaces/app/pods"
	for _, c := range []struct{ name, method, target, ct, body string }{
		{"protobuf", http.MethodPost, pods, "application/vnd.kubernetes.protobuf", "k8s\x00\n\x0f\n\x02v1\x12\x03Pod"},
		{"CBOR", http.MethodPost, pods, "application/cbor", "\xd9\xd9\xf7\xa1"},
		{"malformed JSON", http.MethodPost, pods, "application/json", `{"kind":"Pod",`},
		{"data after the object", http.MethodPost, pods, "application/json", `{"kind":"Pod"} {"spec":{}}`},
		{"no body", http.MethodPost, pods, "application/json", ``},
		{"a patch with no Content-Type", http.MethodPatch, pods + "/web", "", `{"spec":{}}`},
		{"CBOR apply", http.MethodPatch, pods + "/web", "application/apply-patch+cbor", "\xa1"},
		{"YAML repeating a key", http.MethodPost, pods, "application/yaml", "kind: Pod\nkind: Pod\n"},
		{"two YAML documents", http.MethodPost, pods, "application/yaml", "kind: Pod\n---\nkind: Pod\n"},
		{"too deep", http.MethodPost, pods, "application/json",
			strings.Repeat(`{"a":`, maxInspectDepth+5) + `1` + strings.Repeat(`}`, maxInspectDepth+5)},
		{"a protobuf Secret", http.MethodPost, "/api/v1/namespaces/app/secrets",
			"application/vnd.kubernetes.protobuf", "k8s\x00"},
	} {
		t.Run(c.name, func(t *testing.T) {
			wantReason(t, inspect(t, c.method, c.target, c.ct, c.body), DenyUnreadableBody)
		})
	}
	t.Run("compressed", func(t *testing.T) {
		r := mustParse(t, http.MethodPost, pods)
		wantReason(t, InspectWrite(r, "application/json", "gzip", []byte(`{"kind":"Pod"}`)), DenyUnreadableBody)
	})
}

// TestRBACAndCertificateWritesAreRefusedUnderEveryGrant: no body to read —
// the kind alone hands out authority.
func TestRBACAndCertificateWritesAreRefusedUnderEveryGrant(t *testing.T) {
	wideOpen := Policy{Verbs: allVerbs()}
	wideOpen.Normalize()
	cases := []struct {
		method, target string
		want           DenyReason
	}{
		{http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/namespaces/app/rolebindings", DenyRBACBinding},
		{http.MethodPut, "/apis/rbac.authorization.k8s.io/v1/namespaces/app/rolebindings/edit", DenyRBACBinding},
		{http.MethodPatch, "/apis/rbac.authorization.k8s.io/v1/namespaces/app/rolebindings/edit", DenyRBACBinding},
		{http.MethodDelete, "/apis/rbac.authorization.k8s.io/v1/namespaces/app/rolebindings/edit", DenyRBACBinding},
		{http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", DenyRBACBinding},
		{http.MethodDelete, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/cluster-admin", DenyRBACBinding},
		{http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/namespaces/app/roles", DenyRBACRole},
		{http.MethodPatch, "/apis/rbac.authorization.k8s.io/v1/clusterroles/edit", DenyRBACRole},
		{http.MethodPost, "/apis/certificates.k8s.io/v1/certificatesigningrequests", DenyCertificateSigningRequest},
		{http.MethodPut, "/apis/certificates.k8s.io/v1/certificatesigningrequests/me/approval", DenyCertificateSigningRequest},
		{http.MethodPatch, "/apis/certificates.k8s.io/v1/certificatesigningrequests/me/status", DenyCertificateSigningRequest},
	}
	for _, p := range []Policy{wideOpen, writePolicy(), ReadOnlyPolicy()} {
		for _, c := range cases {
			t.Run(c.method+" "+c.target+" "+p.Summary(), func(t *testing.T) {
				wantReason(t, p.Decide(mustParse(t, c.method, c.target)), c.want)
			})
		}
	}
	// Reading them is left to the ordinary checks.
	for _, target := range []string{
		"/apis/rbac.authorization.k8s.io/v1/namespaces/app/rolebindings",
		"/apis/certificates.k8s.io/v1/certificatesigningrequests",
	} {
		if err := wideOpen.Decide(mustParse(t, http.MethodGet, target)); err != nil {
			t.Errorf("GET %s refused: %v", target, err)
		}
	}
}

func TestEphemeralContainersAreRefusedForEveryVerb(t *testing.T) {
	wideOpen := Policy{Verbs: allVerbs()}
	wideOpen.Normalize()
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodPut} {
		wantReason(t, wideOpen.Decide(mustParse(t, method, "/api/v1/namespaces/app/pods/web-0/ephemeralcontainers")),
			DenyDangerousSubresource)
	}
}

// denialCount reads cloop_kubeguard_denials_total for one reason.
func denialCount(t *testing.T, reason DenyReason) float64 {
	t.Helper()
	re := regexp.MustCompile(`(?m)^cloop_kubeguard_denials_total\{reason="` + regexp.QuoteMeta(string(reason)) + `"\} (\S+)$`)
	m := re.FindStringSubmatch(hubmetrics.Default.Gather())
	if m == nil {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("parse %q: %v", m[1], err)
	}
	return v
}

// TestCredentialWritesNeverReachTheCluster drives each refusal through the
// proxy: a 403 the sandbox can read, an audit row and a metric label of its
// own — and nothing forwarded.
func TestCredentialWritesNeverReachTheCluster(t *testing.T) {
	h := newHarness(t, writePolicy())
	cases := []struct {
		name, method, path, ct, body string
		want                         DenyReason
	}{
		{"token Secret", http.MethodPost, "/api/v1/namespaces/app/secrets", "application/json",
			`{"kind":"Secret","metadata":{"name":"t","annotations":{"kubernetes.io/service-account.name":"default"}},"type":"kubernetes.io/service-account-token"}`,
			DenyServiceAccountTokenSecret},
		{"Pod as another ServiceAccount", http.MethodPost, "/api/v1/namespaces/app/pods", "application/json",
			`{"kind":"Pod","metadata":{"name":"p"},"spec":{"serviceAccountName":"deployer","containers":[{"name":"c","image":"busybox"}]}}`,
			DenyWorkloadServiceAccount},
		{"Job as another ServiceAccount", http.MethodPost, "/apis/batch/v1/namespaces/app/jobs", "application/json",
			`{"kind":"Job","spec":{"template":{"spec":{"serviceAccountName":"deployer","containers":[]}}}}`,
			DenyWorkloadServiceAccount},
		{"hostPath Pod", http.MethodPost, "/api/v1/namespaces/app/pods", "application/json",
			`{"kind":"Pod","spec":{"volumes":[{"name":"n","hostPath":{"path":"/"}}],"containers":[]}}`,
			DenyHostAccess},
		{"RoleBinding", http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/namespaces/app/rolebindings",
			"application/json", `{"kind":"RoleBinding"}`, DenyRBACBinding},
		{"CertificateSigningRequest", http.MethodPost, "/apis/certificates.k8s.io/v1/certificatesigningrequests",
			"application/json", `{"kind":"CertificateSigningRequest"}`, DenyCertificateSigningRequest},
		{"protobuf Pod", http.MethodPost, "/api/v1/namespaces/app/pods", "application/vnd.kubernetes.protobuf",
			"k8s\x00\n\x02v1", DenyUnreadableBody},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before, metricBefore := h.api.count(), denialCount(t, c.want)
			resp := h.do(t, c.method, c.path, strings.NewReader(c.body), "Content-Type", c.ct)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			if h.api.count() != before {
				t.Fatalf("the refused write reached the cluster")
			}
			st := decodeStatus(t, resp)
			if msg, _ := st["message"].(string); !strings.Contains(msg, "cloop Kubernetes monitor") {
				t.Errorf("the refusal does not say who refused it: %q", msg)
			}
			ev := h.lastDenial(t)
			if ev.Reason != c.want || ev.Namespace == "" && !strings.Contains(c.path, "certificatesigning") {
				t.Errorf("audit row = %+v, want reason %q", ev, c.want)
			}
			if got := denialCount(t, c.want); got != metricBefore+1 {
				t.Errorf("cloop_kubeguard_denials_total{reason=%q} went %v -> %v, want +1", c.want, metricBefore, got)
			}
		})
	}
}

// TestAnInspectedWriteIsForwardedByteForByte: what reaches the cluster is the
// body that was judged, whole.
func TestAnInspectedWriteIsForwardedByteForByte(t *testing.T) {
	h := newHarness(t, writePolicy())
	body := `{"kind":"Pod","metadata":{"name":"p"},"spec":{"serviceAccountName":"default","containers":[{"name":"c","image":"busybox"}]}}`
	resp := h.do(t, http.MethodPost, "/api/v1/namespaces/app/pods?dryRun=All", strings.NewReader(body),
		"Content-Type", "application/json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	h.api.mu.Lock()
	got := h.api.bodies[len(h.api.bodies)-1]
	h.api.mu.Unlock()
	if got != body {
		t.Errorf("the cluster received %q, want %q", got, body)
	}
	if q := h.api.last().URL.Query().Get("dryRun"); q != "All" {
		t.Errorf("dryRun = %q", q)
	}
}

// TestAPatchIsJudgedAgainstWhatItPatches: a patch keeps the fields it does not
// mention, so a new image for a Deployment running as the deployer's
// ServiceAccount is refused — after the monitor read the Deployment, and
// before the patch reached the cluster.
func TestAPatchIsJudgedAgainstWhatItPatches(t *testing.T) {
	stored := map[string]string{
		"/apis/apps/v1/namespaces/app/deployments/deployer-run": `{"kind":"Deployment","spec":{"template":{"spec":{"serviceAccountName":"deployer","containers":[{"name":"c","image":"app:1"}]}}}}`,
		"/apis/apps/v1/namespaces/app/deployments/plain":        `{"kind":"Deployment","spec":{"template":{"spec":{"serviceAccountName":"default","containers":[{"name":"c","image":"app:1"}]}}}}`,
		"/apis/apps/v1/namespaces/app/daemonsets/node-agent":    `{"kind":"DaemonSet","spec":{"template":{"spec":{"volumes":[{"name":"k","hostPath":{"path":"/var/lib/kubelet"}}],"containers":[]}}}}`,
	}
	h := newHarness(t, writePolicy())
	h.api.mu.Lock()
	h.api.answer = func(r *http.Request) (int, string) {
		if r.Method != http.MethodGet {
			return http.StatusOK, `{"kind":"Status","status":"Success"}`
		}
		if r.URL.Path == "/apis/apps/v1/namespaces/app/deployments/broken" {
			return http.StatusInternalServerError, `{"kind":"Status"}`
		}
		if obj, ok := stored[r.URL.Path]; ok {
			return http.StatusOK, obj
		}
		return http.StatusNotFound, `{"kind":"Status","reason":"NotFound"}`
	}
	h.api.mu.Unlock()
	newImage := `{"spec":{"template":{"spec":{"containers":[{"name":"c","image":"attacker:1"}]}}}}`
	patch := func(path string) *http.Response {
		return h.do(t, http.MethodPatch, path, strings.NewReader(newImage),
			"Content-Type", "application/strategic-merge-patch+json")
	}
	patchesSeen := func() int {
		h.api.mu.Lock()
		defer h.api.mu.Unlock()
		n := 0
		for _, r := range h.api.requests {
			if r.Method == http.MethodPatch {
				n++
			}
		}
		return n
	}

	if resp := patch("/apis/apps/v1/namespaces/app/deployments/deployer-run"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("patching a Deployment that runs as another ServiceAccount: status %d, want 403", resp.StatusCode)
	}
	if ev := h.lastDenial(t); ev.Reason != DenyWorkloadServiceAccount {
		t.Errorf("reason = %q, want %q", ev.Reason, DenyWorkloadServiceAccount)
	}
	if resp := patch("/apis/apps/v1/namespaces/app/daemonsets/node-agent"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("patching a DaemonSet with a hostPath volume: status %d, want 403", resp.StatusCode)
	}
	if ev := h.lastDenial(t); ev.Reason != DenyHostAccess {
		t.Errorf("reason = %q, want %q", ev.Reason, DenyHostAccess)
	}
	if n := patchesSeen(); n != 0 {
		t.Fatalf("%d refused patches reached the cluster", n)
	}
	// The monitor could not read the object: neither refused nor forwarded.
	if resp := patch("/apis/apps/v1/namespaces/app/deployments/broken"); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("patching an object the monitor cannot read: status %d, want 502", resp.StatusCode)
	}
	if n := patchesSeen(); n != 0 {
		t.Fatalf("a patch the monitor could not check reached the cluster")
	}

	if resp := patch("/apis/apps/v1/namespaces/app/deployments/plain"); resp.StatusCode != http.StatusOK {
		t.Errorf("patching a Deployment that runs as default: status %d, want 200", resp.StatusCode)
	}
	// Nothing stored: a server-side apply creating the object is judged by
	// its body alone.
	if resp := h.do(t, http.MethodPatch, "/apis/apps/v1/namespaces/app/deployments/new",
		strings.NewReader("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: new\n"),
		"Content-Type", "application/apply-patch+yaml"); resp.StatusCode != http.StatusOK {
		t.Errorf("applying a new Deployment: status %d, want 200", resp.StatusCode)
	}
	if n := patchesSeen(); n != 2 {
		t.Errorf("%d patches reached the cluster, want the 2 allowed", n)
	}
}

// TestAnOversizedInspectedBodyIsRefused: the inspected path reads the body
// whole, so the cap has to hold there too — declared and chunked.
func TestAnOversizedInspectedBodyIsRefused(t *testing.T) {
	p := writePolicy()
	p.MaxBodyBytes = 64
	h := newHarness(t, p)
	big := `{"kind":"Pod","metadata":{"name":"` + strings.Repeat("x", 200) + `"}}`
	resp := h.do(t, http.MethodPost, "/api/v1/namespaces/app/pods", strings.NewReader(big),
		"Content-Type", "application/json")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if ev := h.lastDenial(t); ev.Reason != DenyBodyTooLarge {
		t.Errorf("reason = %q, want %q", ev.Reason, DenyBodyTooLarge)
	}
	// Chunked: no declared length, so only the read can find out.
	resp = h.do(t, http.MethodPost, "/api/v1/namespaces/app/pods", struct{ *strings.Reader }{strings.NewReader(big)},
		"Content-Type", "application/json")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("chunked: status = %d, want 403", resp.StatusCode)
	}
	if ev := h.lastDenial(t); ev.Reason != DenyBodyTooLarge {
		t.Errorf("chunked: reason = %q, want %q", ev.Reason, DenyBodyTooLarge)
	}
	if h.api.count() != 0 {
		t.Errorf("an oversized write reached the cluster")
	}
}
