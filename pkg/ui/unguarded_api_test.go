package ui

// unguarded_api_test.go: the Secrets panel says what becomes of a kubeconfig
// grant on this hub, and only an administrator may acknowledge delivering one
// without the Kubernetes access monitor (Task 20420).

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// withNoKubeGuard runs a test on a hub with no Kubernetes access monitor,
// restoring whatever another test left.
func withNoKubeGuard(t *testing.T) {
	t.Helper()
	kubeGuardOnce.Do(func() {}) // see withKubeGuardRequired
	prevSvc, prevReq := kubeGuardSingleton.Load(), kubeGuardRequired.Load()
	kubeGuardSingleton.Store(nil)
	kubeGuardRequired.Store(false)
	t.Cleanup(func() {
		kubeGuardSingleton.Store(prevSvc)
		kubeGuardRequired.Store(prevReq)
	})
}

// testKubeconfigPayload is a static kubeconfig the broker accepts.
const testKubeconfigPayload = "apiVersion: v1\nkind: Config\ncurrent-context: dev\nclusters:\n- name: k\n  cluster:\n" +
	"    server: https://k8s.example.test\ncontexts:\n- name: dev\n  context:\n    cluster: k\n    user: u\n" +
	"users:\n- name: u\n  user:\n    token: not-a-real-cluster-token\n"

// grantRow is the part of a GET /api/grants row these tests read.
type grantRow struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	KubeDelivery string `json:"kube_delivery"`
	UnguardedAck *struct {
		By     string `json:"by"`
		Reason string `json:"reason"`
	} `json:"unguarded_ack"`
}

func (f *personalFixture) grantRows(t *testing.T, who string) map[string]grantRow {
	t.Helper()
	code, body := getFull(t, f.clients[who], f.base+"/api/grants")
	if code != http.StatusOK {
		t.Fatalf("%s GET /api/grants = %d\n%s", who, code, body)
	}
	var env struct {
		Grants []grantRow `json:"grants"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	out := map[string]grantRow{}
	for _, g := range env.Grants {
		out[g.ID] = g
	}
	return out
}

func (f *personalFixture) do(t *testing.T, who, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, f.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.clients[who].Do(req)
	if err != nil {
		t.Fatalf("%s %s %s: %v", who, method, path, err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		b.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, b.String()
}

// newKubeGrant stores a shared kubeconfig and grants it under constraints,
// as a maintainer would, and returns the grant's id.
func (f *personalFixture) newKubeGrant(t *testing.T, name string, constraints map[string]any) string {
	t.Helper()
	code, body := f.postJSON(t, "lead", "/api/secrets", map[string]any{
		"name": name, "kind": "kubeconfig", "payload": testKubeconfigPayload, "personal": false,
	})
	if code != http.StatusOK {
		t.Fatalf("store the kubeconfig = %d\n%s", code, body)
	}
	req := map[string]any{"source": "secret", "secret_ref": name, "subject": "project:/srv/app", "ttl_minutes": 60}
	for k, v := range constraints {
		req[k] = v
	}
	code, body = f.postJSON(t, "lead", "/api/grants", req)
	if code != http.StatusOK {
		t.Fatalf("grant = %d\n%s", code, body)
	}
	var g grantRow
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		t.Fatal(err)
	}
	return g.ID
}

// TestTheSecretsPanelSaysWhatBecomesOfAKubeconfigGrant: refused without a
// monitor, delivered on an acknowledgement, held by a running monitor.
func TestTheSecretsPanelSaysWhatBecomesOfAKubeconfigGrant(t *testing.T) {
	withNoKubeGuard(t)
	f := newPersonalFixture(t)
	readOnly := f.newKubeGrant(t, "dev-read", map[string]any{"contexts": []string{"dev"}, "namespaces": []string{"app"}})
	everything := f.newKubeGrant(t, "dev-all", map[string]any{"contexts": []string{"dev"},
		"verbs": []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}})

	rows := f.grantRows(t, "lead")
	if got := rows[readOnly].KubeDelivery; got != kubeDeliveryRefused {
		t.Errorf("a read-only, one-namespace grant on a hub with no monitor reads %q, want %q", got, kubeDeliveryRefused)
	}
	if got := rows[everything].KubeDelivery; got != kubeDeliveryUnconstrained {
		t.Errorf("a grant claiming every verb reads %q, want %q", got, kubeDeliveryUnconstrained)
	}

	// A maintainer may grant the credential but not decide it goes unenforced.
	if code, body := f.do(t, "lead", http.MethodPost, "/api/grants/"+readOnly+"/unguarded", `{"reason":"just do it"}`); code != http.StatusForbidden {
		t.Fatalf("a maintainer acknowledged an unguarded grant: %d\n%s", code, body)
	}
	// An administrator must say why.
	if code, body := f.do(t, "root", http.MethodPost, "/api/grants/"+readOnly+"/unguarded", `{"reason":"  "}`); code != http.StatusBadRequest ||
		!strings.Contains(body, "needs a reason") {
		t.Fatalf("an acknowledgement without a reason: %d\n%s", code, body)
	}
	// And cannot acknowledge what claims nothing the monitor enforces.
	if code, body := f.do(t, "root", http.MethodPost, "/api/grants/"+everything+"/unguarded", `{"reason":"x"}`); code != http.StatusBadRequest {
		t.Fatalf("acknowledging an unconstrained grant: %d\n%s", code, body)
	}

	code, body := f.do(t, "root", http.MethodPost, "/api/grants/"+readOnly+"/unguarded",
		`{"reason":"the lab cluster, until the monitor is deployed"}`)
	if code != http.StatusOK {
		t.Fatalf("an administrator's acknowledgement = %d\n%s", code, body)
	}
	row := f.grantRows(t, "lead")[readOnly]
	if row.KubeDelivery != kubeDeliveryAcknowledged || row.UnguardedAck == nil ||
		row.UnguardedAck.By == "" || !strings.Contains(row.UnguardedAck.Reason, "lab cluster") {
		t.Fatalf("after the acknowledgement the row reads %+v", row)
	}

	// The trail names it.
	code, body = getFull(t, f.clients["root"], f.base+"/api/audit?limit=200")
	if code != http.StatusOK || !strings.Contains(body, string(secretbroker.ActionUnguardedAck)) ||
		!strings.Contains(body, "lab cluster") {
		t.Errorf("no secret.unguarded_ack row in the trail: %d", code)
	}

	// With a monitor running the grant is held by it, whatever was acknowledged.
	svc := newTestKubeGuardService(t, kubeguard.Policy{})
	kubeGuardSingleton.Store(svc)
	if got := f.grantRows(t, "lead")[readOnly].KubeDelivery; got != kubeDeliveryMonitor {
		t.Errorf("with a monitor running the row reads %q, want %q", got, kubeDeliveryMonitor)
	}
	kubeGuardSingleton.Store(nil)

	if code, body := f.do(t, "root", http.MethodDelete, "/api/grants/"+readOnly+"/unguarded", ""); code != http.StatusOK {
		t.Fatalf("withdrawal = %d\n%s", code, body)
	}
	if row := f.grantRows(t, "lead")[readOnly]; row.KubeDelivery != kubeDeliveryRefused || row.UnguardedAck != nil {
		t.Errorf("after the withdrawal the row reads %+v", row)
	}
	if code, _ := f.do(t, "root", http.MethodDelete, "/api/grants/"+readOnly+"/unguarded", ""); code != http.StatusBadRequest {
		t.Errorf("withdrawing an acknowledgement that is not in force = %d, want 400", code)
	}
}

// TestKubeDeliveryAgreesWithTheBroker holds the panel's badge to the rule the
// broker applies: whatever the row says, the lease does.
func TestKubeDeliveryAgreesWithTheBroker(t *testing.T) {
	withNoKubeGuard(t)
	sec := secretbroker.Secret{Kind: secretbroker.KindKubeconfig}
	for _, tc := range []struct {
		c    secretbroker.Constraints
		ack  bool
		want string
	}{
		{secretbroker.Constraints{Contexts: []string{"dev"}}, false, kubeDeliveryRefused},
		{secretbroker.Constraints{Namespaces: []string{"app"}}, true, kubeDeliveryAcknowledged},
		{secretbroker.Constraints{Namespaces: []string{"*"},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}}, false,
			kubeDeliveryUnconstrained},
	} {
		g := secretbroker.Grant{Constraints: tc.c}
		if tc.ack {
			g.UnguardedAck = secretbroker.UnguardedAck{At: g.CreatedAt.AddDate(2026, 0, 0), By: "root", Reason: "lab"}
		}
		if got := kubeDelivery(sec, g); got != tc.want {
			t.Errorf("%+v ack=%v: kubeDelivery = %q, want %q", tc.c, tc.ack, got, tc.want)
		}
	}
	kubeGuardRequired.Store(true)
	if got := kubeDelivery(sec, secretbroker.Grant{}); got != kubeDeliveryMonitorDown {
		t.Errorf("a configured monitor that is not running reads %q", got)
	}
	kubeGuardRequired.Store(false)
	share := secretbroker.Secret{Kind: secretbroker.KindKubeconfig,
		Metadata: map[string]string{"kube.share": "3f9c2a1b", secretbroker.KubeShareMetaRenewal: secretbroker.KubeShareRenewalHub}}
	if got := kubeDelivery(share, secretbroker.Grant{}); got != kubeDeliveryMonitorRequired {
		t.Errorf("a share the hub renews reads %q, want %q", got, kubeDeliveryMonitorRequired)
	}
}
