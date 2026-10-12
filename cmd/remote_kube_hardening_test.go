package cmd

// `cloop remote kube revoke` and `renew` act on a cluster with the caller's own
// credentials, over a share whose metadata its uploader wrote (Task 20420).
// These pin the order and the checks: the hub is asked first, the context must
// reach the share's own cluster through the CA it trusts, renew mints only for
// the share's own ServiceAccount, and the token reaches the hub with the server
// that minted it.

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/kubeshare"
)

const hardenedShareID = "3f9c2a1b"

var hardenedSA = "cloop-aks-dev-" + hardenedShareID

// stubCluster is an API server that records every request and answers from a
// small object table.
type stubCluster struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []string
	// sa is the ServiceAccount's metadata, nil for none.
	sa map[string]any
}

func newStubCluster(t *testing.T) *stubCluster {
	t.Helper()
	c := &stubCluster{}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.requests = append(c.requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		saPath := "/api/v1/namespaces/cloop-shares/serviceaccounts/" + hardenedSA
		switch {
		case r.Method == http.MethodGet && r.URL.Path == saPath && c.sa != nil:
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": c.sa})
		case r.Method == http.MethodPost && r.URL.Path == saPath+"/token":
			now := time.Now()
			_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{
				"token":               shareJWT("cloop-shares", hardenedSA, now, now.Add(time.Hour)),
				"expirationTimestamp": now.Add(time.Hour).UTC().Format(time.RFC3339)}})
		case r.Method == http.MethodGet && r.URL.Query().Get("labelSelector") != "":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"kind":"Status","status":"Failure","reason":"NotFound","code":404}`)
		}
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *stubCluster) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.srv.Certificate().Raw})
}

func (c *stubCluster) calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.requests...)
}

// kubeconfigFor writes a developer kubeconfig whose one context reaches c with
// a static token, so nothing signs in through a plugin.
func (c *stubCluster) kubeconfigFor(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	doc := "apiVersion: v1\nkind: Config\ncurrent-context: dev\nclusters:\n- name: k\n  cluster:\n" +
		"    server: " + c.srv.URL + "\n    certificate-authority-data: " +
		base64.StdEncoding.EncodeToString(c.caPEM()) + "\ncontexts:\n- name: dev\n  context: {cluster: k, user: me}\n" +
		"users:\n- name: me\n  user: {token: developer-token}\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func shareJWT(ns, name string, iat, exp time.Time) string {
	payload, _ := json.Marshal(map[string]any{"sub": "system:serviceaccount:" + ns + ":" + name,
		"iat": iat.Unix(), "exp": exp.Unix()})
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".c2ln"
}

// stubHub is a hub holding one share, which may or may not authorise the
// caller, and records what it was asked.
type stubHub struct {
	srv *httptest.Server

	mu        sync.Mutex
	calls     []string
	authorize int // status GET .../authorize answers
	renewBody map[string]string
}

func newStubHub(t *testing.T, meta map[string]string) *stubHub {
	t.Helper()
	h := &stubHub{authorize: http.StatusOK}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.calls = append(h.calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets": []any{map[string]any{"id": "sec_share", "name": "aks-dev", "kind": "kubeconfig",
					"metadata": meta, "personal": false}},
				"broker": map[string]any{"secrets_available": true},
			})
		case "GET /api/secrets/sec_share/authorize":
			if h.authorize != http.StatusOK {
				w.WriteHeader(h.authorize)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
					"code": "forbidden", "message": "you may not touch this secret"}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sec_share", "action": r.URL.Query().Get("action"),
				"authorized": true})
		case "POST /api/secrets/sec_share/renew":
			_ = json.NewDecoder(r.Body).Decode(&h.renewBody)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sec_share", "name": "aks-dev",
				"expires_at": time.Now().Add(time.Hour), "verified": true})
		case "DELETE /api/secrets/sec_share":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "not_found", "message": "no route"}})
		}
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *stubHub) called(call string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.calls {
		if c == call {
			return true
		}
	}
	return false
}

// hardenedMeta is a share's metadata as a hub that records it writes it.
func hardenedMeta(server string, ca []byte) map[string]string {
	return map[string]string{
		kubeshare.MetaShare: hardenedShareID, kubeshare.MetaRenewal: "manual", kubeshare.MetaAccess: "read",
		kubeshare.MetaServiceAccount: "cloop-shares/" + hardenedSA, kubeshare.MetaNamespaces: "team-a",
		kubeshare.MetaServer: server, kubeshare.MetaCA: kubeshare.CAFingerprint(ca),
		kubeshare.MetaOwner: "alice@example.com", kubeshare.MetaContext: "dev",
		kubeshare.MetaIssuedAt:  time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		kubeshare.MetaExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
}

func TestRevokeAsksTheHubBeforeTouchingTheCluster(t *testing.T) {
	cluster := newStubCluster(t)
	hub := newStubHub(t, hardenedMeta(cluster.srv.URL, cluster.caPEM()))
	hub.authorize = http.StatusForbidden
	kubeFlags(t, hub.srv.URL, func() { kubeKubeconfig = cluster.kubeconfigFor(t) })

	_, err := runKube(t, remoteKubeRevokeCmd, "aks-dev")
	if err == nil || !strings.Contains(err.Error(), "nothing in the cluster was touched") {
		t.Fatalf("revoke the hub refuses: %v", err)
	}
	if calls := cluster.calls(); len(calls) != 0 {
		t.Fatalf("the cluster was touched before the hub said yes: %v", calls)
	}
	if hub.called("DELETE /api/secrets/sec_share") {
		t.Error("the secret was deleted")
	}
}

func TestRevokeRefusesAContextForAnotherCluster(t *testing.T) {
	cluster := newStubCluster(t)
	for name, meta := range map[string]map[string]string{
		"another server": hardenedMeta("https://prod.example.com:6443", cluster.caPEM()),
		"another CA":     hardenedMeta(cluster.srv.URL, []byte("some other CA")),
	} {
		t.Run(name, func(t *testing.T) {
			hub := newStubHub(t, meta)
			kubeFlags(t, hub.srv.URL, func() { kubeKubeconfig = cluster.kubeconfigFor(t) })
			before := len(cluster.calls())
			_, err := runKube(t, remoteKubeRevokeCmd, "aks-dev")
			if err == nil || !strings.Contains(err.Error(), "context dev") {
				t.Fatalf("revoke through a context for another cluster: %v", err)
			}
			if calls := cluster.calls(); len(calls) != before {
				t.Fatalf("the context's cluster was touched: %v", calls[before:])
			}
			if hub.called("DELETE /api/secrets/sec_share") {
				t.Error("the secret was deleted")
			}
		})
	}
}

func TestRenewMintsOnlyForTheSharesOwnServiceAccount(t *testing.T) {
	cluster := newStubCluster(t)
	hub := newStubHub(t, hardenedMeta(cluster.srv.URL, cluster.caPEM()))
	kubeFlags(t, hub.srv.URL, func() { kubeKubeconfig = cluster.kubeconfigFor(t) })

	// The ServiceAccount exists but is somebody else's: it carries the
	// share's label and another owner.
	cluster.mu.Lock()
	cluster.sa = map[string]any{"name": hardenedSA, "namespace": "cloop-shares", "uid": "u1", "resourceVersion": "1",
		"labels":      map[string]any{kubeshare.LabelShare: hardenedShareID},
		"annotations": map[string]any{kubeshare.AnnotationOwner: "mallory@example.com"}}
	cluster.mu.Unlock()
	if _, err := runKube(t, remoteKubeRenewCmd, "aks-dev"); err == nil ||
		!strings.Contains(err.Error(), "refusing to mint a token") {
		t.Fatalf("renew for another owner's ServiceAccount: %v", err)
	}
	for _, c := range cluster.calls() {
		if strings.HasSuffix(c, "/token") {
			t.Fatalf("a token was minted: %v", cluster.calls())
		}
	}

	// The share's own: minted, and handed to the hub with where it was minted.
	cluster.mu.Lock()
	cluster.sa["annotations"] = map[string]any{kubeshare.AnnotationOwner: "alice@example.com"}
	cluster.mu.Unlock()
	if out, err := runKube(t, remoteKubeRenewCmd, "aks-dev"); err != nil {
		t.Fatalf("renew: %v\n%s", err, out)
	}
	if !hub.called("GET /api/secrets/sec_share/authorize") {
		t.Error("renew did not ask the hub first")
	}
	hub.mu.Lock()
	body := hub.renewBody
	hub.mu.Unlock()
	if body["server"] != cluster.srv.URL || body["ca_sha256"] != kubeshare.CAFingerprint(cluster.caPEM()) ||
		body["token"] == "" {
		t.Errorf("the hub was sent %+v, want the token with the server and CA that minted it", map[string]string{
			"server": body["server"], "ca_sha256": body["ca_sha256"]})
	}
}
