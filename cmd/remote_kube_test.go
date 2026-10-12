package cmd

// `cloop remote kube` against a stand-in hub (Task 20416). The whole circuit —
// a real cluster, the exec plugin, renewal across a token's expiry — is
// tests/kube/share_test.go; these pin what the terminal decides on its own.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/kubeshare"
)

// kubeHub answers GET /api/secrets with secrets and whether the hub runs the
// Kubernetes monitor, and GET /api/me with an identity. Anything else is a
// test failure: these commands must not reach further than that unasked.
func kubeHub(t *testing.T, monitored bool, secrets ...map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/secrets":
			if secrets == nil {
				secrets = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets":    secrets,
				"broker":     map[string]any{"secrets_available": true},
				"kube_guard": map[string]any{"enabled": monitored, "running": monitored},
			})
		case "GET /api/me":
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "alice@example.com"})
		default:
			t.Errorf("unexpected hub call %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// kubeFlags sets the package-level flag variables for one command run and
// puts them back afterwards.
func kubeFlags(t *testing.T, hub string, set func()) {
	t.Helper()
	credentialHome(t)
	remoteHub, remoteToken = hub, "cloop_pat_test"
	set()
	t.Cleanup(func() {
		remoteHub, remoteToken = "", ""
		kubeContext, kubeKubeconfig, kubeNamespaces, kubeAccess = "", "", nil, "read"
		kubeTTL, kubeSANamespace, kubeClusterWide, kubeRenewal = kubeshare.DefaultTTL, "", false, "auto"
		kubeServer, kubeShared, kubeDryRun, kubeJSON, kubeLocal, kubeForce = "", false, false, false, false, false
	})
}

func runKube(t *testing.T, c *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	c.SetOut(&out)
	t.Cleanup(func() { c.SetOut(nil) })
	err := c.RunE(c, args)
	return out.String(), err
}

// pluginKubeconfig writes a kubeconfig whose only credential is an exec
// plugin that records that it ran.
func pluginKubeconfig(t *testing.T) (path, ranMarker string) {
	t.Helper()
	dir := t.TempDir()
	ranMarker = filepath.Join(dir, "plugin-ran")
	plugin := filepath.Join(dir, "plugin")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\ntouch '"+ranMarker+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(`apiVersion: v1
kind: Config
current-context: aks-dev
clusters:
- name: aks
  cluster: {server: "https://aks-dev.example.com:443"}
contexts:
- name: aks-dev
  context: {cluster: aks, user: entra, namespace: payments}
users:
- name: entra
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: `+plugin+`
      interactiveMode: Never
`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, ranMarker
}

// TestShareDryRunSignsInToNothing: --dry-run prints the plan for the hub it
// would store the share on, and neither runs the plugin nor touches anything.
func TestShareDryRunSignsInToNothing(t *testing.T) {
	hub := kubeHub(t, true)
	kc, ran := pluginKubeconfig(t)
	kubeFlags(t, hub.URL, func() {
		kubeKubeconfig, kubeNamespaces, kubeAccess, kubeSANamespace, kubeDryRun = kc,
			[]string{"payments,payments-staging"}, "write", "cloop-shares", true
	})
	out, err := runKube(t, remoteKubeShareCmd, "aks-dev")
	if err != nil {
		t.Fatalf("share --dry-run: %v\n%s", err, out)
	}
	for _, want := range []string{
		`Sharing context aks-dev (https://aks-dev.example.com:443) with ` + hub.URL + ` as "aks-dev"`,
		"Write access    payments, payments-staging (RoleBinding",
		"-> ClusterRole edit in each",
		"Self-renewal    Role cloop-aks-dev-",
		"--dry-run: nothing was created",
		"ServiceAccount cloop-shares/cloop-aks-dev-",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run does not say %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(ran); err == nil {
		t.Error("--dry-run ran the exec plugin")
	}
}

func TestShareRefusesBeforeSigningIn(t *testing.T) {
	kc, ran := pluginKubeconfig(t)
	for _, tc := range []struct {
		name      string
		monitored bool
		secrets   []map[string]any
		set       func()
		want      string
	}{
		{"a taken name", true, []map[string]any{{"id": "sec_1", "name": "aks-dev", "kind": "kubeconfig"}},
			func() { kubeNamespaces = []string{"payments"} }, `already holds a secret named "aks-dev"`},
		{"hub renewal without a monitor", false, nil,
			func() { kubeNamespaces, kubeRenewal = []string{"payments"}, "hub" }, "does not run the Kubernetes access monitor"},
		{"write living where it writes", true, nil,
			func() { kubeNamespaces, kubeAccess, kubeSANamespace = []string{"payments"}, "write", "payments" }, "one of the namespaces this share writes"},
		{"write with no home", true, nil,
			func() { kubeNamespaces, kubeAccess = []string{"payments"}, "write" }, "needs --sa-namespace"},
		{"a plain-http server", true, nil,
			func() { kubeNamespaces, kubeServer = []string{"payments"}, "http://10.0.0.1:6443" }, "not https://"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hub := kubeHub(t, tc.monitored, tc.secrets...)
			kubeFlags(t, hub.URL, func() {
				kubeKubeconfig = kc
				tc.set()
			})
			out, err := runKube(t, remoteKubeShareCmd, "aks-dev")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q\n%s", err, tc.want, out)
			}
			if _, err := os.Stat(ran); err == nil {
				t.Fatal("the plugin ran before the refusal")
			}
		})
	}
}

func TestChooseRenewal(t *testing.T) {
	for _, tc := range []struct {
		flag      string
		monitored bool
		want      kubeshare.Renewal
		err       bool
	}{
		{"auto", true, kubeshare.RenewalHub, false},
		{"", false, kubeshare.RenewalManual, false},
		{"hub", true, kubeshare.RenewalHub, false},
		{"hub", false, "", true},
		{"manual", true, kubeshare.RenewalManual, false},
		{"weekly", true, "", true},
	} {
		got, err := chooseRenewal(tc.flag, tc.monitored, "https://hub")
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("chooseRenewal(%q, %v) = %q, %v", tc.flag, tc.monitored, got, err)
		}
	}
}

func shareSecret(name string, meta map[string]string) map[string]any {
	return map[string]any{"id": "sec_" + name, "name": name, "kind": "kubeconfig", "metadata": meta,
		"personal": true, "mine": true, "active_grants": 2}
}

func TestListShowsExpiryAndWhoRenews(t *testing.T) {
	now := time.Now().UTC()
	hubRenewed := map[string]string{
		kubeshare.MetaShare: "3f9c2a1b", kubeshare.MetaRenewal: "hub", kubeshare.MetaAccess: "read",
		kubeshare.MetaServiceAccount: "payments/cloop-aks-dev-3f9c2a1b", kubeshare.MetaNamespaces: "payments",
		kubeshare.MetaIssuedAt:  now.Add(-time.Hour).Format(time.RFC3339),
		kubeshare.MetaExpiresAt: now.Add(23 * time.Hour).Format(time.RFC3339),
		kubeshare.MetaRenewedAt: now.Add(-time.Hour).Format(time.RFC3339), kubeshare.MetaRenewals: "3",
	}
	lapsed := map[string]string{
		kubeshare.MetaShare: "77aa00bb", kubeshare.MetaRenewal: "hub", kubeshare.MetaAccess: "write",
		kubeshare.MetaServiceAccount: "shares/cloop-eks-77aa00bb", kubeshare.MetaNamespaces: "ci",
		kubeshare.MetaExpiresAt: now.Add(-time.Hour).Format(time.RFC3339), kubeshare.MetaRenewState: "lapsed",
		kubeshare.MetaRenewError: "the share's token expired before it was renewed",
	}
	hub := kubeHub(t, true,
		shareSecret("aks-dev", hubRenewed), shareSecret("eks-ci", lapsed),
		map[string]any{"id": "sec_x", "name": "plain-kube", "kind": "kubeconfig"},
		map[string]any{"id": "sec_y", "name": "gh", "kind": "github_pat"})
	kubeFlags(t, hub.URL, func() {})
	out, err := runKube(t, remoteKubeListCmd)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"runs the Kubernetes access monitor",
		"aks-dev", "payments/cloop-aks-dev-3f9c2a1b", "hub, renewed 1h0m ago",
		"eks-ci", "lapsed: run `cloop remote kube renew eks-ci`",
		"eks-ci: the last renewal failed: the share's token expired",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list does not show %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "plain-kube") || strings.Contains(out, "gh ") {
		t.Errorf("list shows secrets that are not shares:\n%s", out)
	}

	kubeJSON = true
	out, err = runKube(t, remoteKubeListCmd)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Shares []struct {
			Name     string `json:"name"`
			Renewals int    `json:"renewals"`
			Lapsed   bool   `json:"lapsed"`
		} `json:"shares"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Shares) != 2 ||
		doc.Shares[0].Renewals != 3 || !doc.Shares[1].Lapsed {
		t.Errorf("list --json = %s (%v)", out, err)
	}
}

func TestRevokeOfAShareTheHubNoLongerHasSaysHowToFindItsObjects(t *testing.T) {
	hub := kubeHub(t, true)
	kubeFlags(t, hub.URL, func() {})
	_, err := runKube(t, remoteKubeRevokeCmd, "aks-dev")
	if err == nil {
		t.Fatal("revoke of an unknown share succeeded")
	}
	for _, want := range []string{
		`holds no secret named "aks-dev"`,
		"kubectl get serviceaccounts -A -l app.kubernetes.io/managed-by=cloop",
		"kubectl delete serviceaccount,rolebinding,role -A -l cloop.dev/kube-share=<SHARE>",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q:\n%v", want, err)
		}
	}
}
