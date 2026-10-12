package kubeexec

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testCA = "-----BEGIN CERTIFICATE-----\nMIIBdzCCAR2gAwIBAgIBADAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhrM3Mtc2Vy\n-----END CERTIFICATE-----\n"

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// TestLoadMergesFilesTheWayKubectlDoes: the first file to define a name wins,
// current-context comes from the first file that sets one, and a missing file
// in the list is skipped.
func TestLoadMergesFilesTheWayKubectlDoes(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yaml")
	second := filepath.Join(dir, "second.yaml")
	writeFile(t, first, `
apiVersion: v1
kind: Config
clusters:
- name: shared
  cluster: {server: "https://first.example.com"}
contexts:
- name: dev
  context: {cluster: shared, user: alice, namespace: team-a}
users:
- name: alice
  user: {token: first-token}
`, 0o600)
	writeFile(t, second, `
current-context: prod
clusters:
- name: shared
  cluster: {server: "https://second.example.com"}
- name: prod-cluster
  cluster: {server: "https://prod.example.com"}
contexts:
- name: prod
  context: {cluster: prod-cluster, user: alice}
users:
- name: alice
  user: {token: second-token}
`, 0o600)
	k, err := Load([]string{first, filepath.Join(dir, "missing.yaml"), second})
	if err != nil {
		t.Fatal(err)
	}
	if k.CurrentContext != "prod" {
		t.Errorf("current-context = %q, want the first one set (prod)", k.CurrentContext)
	}
	dev, err := k.Context("dev")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Server != "https://first.example.com" || dev.token != "first-token" || dev.Namespace != "team-a" {
		t.Errorf("dev resolved to %s / %q / %s; the first definition must win", dev.Server, dev.token, dev.Namespace)
	}
	cur, err := k.Context("")
	if err != nil {
		t.Fatal(err)
	}
	if cur.Name != "prod" || cur.Server != "https://prod.example.com" {
		t.Errorf("the current context resolved to %s at %s", cur.Name, cur.Server)
	}
	if _, err := k.Context("staging"); err == nil || !strings.Contains(err.Error(), "dev, prod") {
		t.Errorf("an unknown context: err = %v, want the known ones listed", err)
	}
}

// TestContextResolvesPathsAgainstTheirKubeconfig: on the developer's machine a
// path is theirs, so CA files, token files and a relative plugin command all
// resolve — against the directory of the file that named them.
func TestContextResolvesPathsAgainstTheirKubeconfig(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "kube")
	writeFile(t, filepath.Join(cfgDir, "certs", "ca.pem"), testCA, 0o644)
	writeFile(t, filepath.Join(cfgDir, "tokens", "dev"), "  file-token\n", 0o600)
	fakePlugin(t, mkdir(t, filepath.Join(cfgDir, "bin")), "login",
		printing(credentialJSON(APIVersionV1, plantedToken, testNow.Add(time.Hour))))
	cfg := filepath.Join(cfgDir, "config")
	writeFile(t, cfg, `
clusters:
- name: c
  cluster:
    server: https://k8s.example.com:6443/
    certificate-authority: certs/ca.pem
    tls-server-name: api.internal
    extensions:
    - name: client.authentication.k8s.io/exec
      extension:
        audience: 6dae42f8
        tenant: {id: 72f988bf}
contexts:
- name: file
  context: {cluster: c, user: file}
- name: plugin
  context: {cluster: c, user: plugin, namespace: apps}
users:
- name: file
  user: {tokenFile: tokens/dev}
- name: plugin
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: ./bin/login
      interactiveMode: Never
      provideClusterInfo: true
`, 0o600)
	k, err := Load([]string{cfg})
	if err != nil {
		t.Fatal(err)
	}

	file, err := k.Context("file")
	if err != nil {
		t.Fatal(err)
	}
	if string(file.CAData) != testCA {
		t.Errorf("the CA file was not read relative to the kubeconfig: %q", file.CAData)
	}
	if file.Server != "https://k8s.example.com:6443" {
		t.Errorf("server = %q (a trailing slash must be trimmed)", file.Server)
	}
	if file.Plugin() != nil {
		t.Error("a tokenFile user reported a plugin")
	}
	rc, cred, err := file.RESTConfig(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if cred != nil || rc.BearerToken != "file-token" || rc.ServerName != "api.internal" {
		t.Errorf("tokenFile context: token %q, server name %q, credential %v", rc.BearerToken, rc.ServerName, cred)
	}

	plugin, err := k.Context("plugin")
	if err != nil {
		t.Fatal(err)
	}
	if p := plugin.Plugin(); p == nil || p.Dir != cfgDir || p.Command != "./bin/login" {
		t.Fatalf("plugin = %+v", p)
	}
	if got := string(plugin.ExecExtension); !strings.Contains(got, `"audience":"6dae42f8"`) || !strings.Contains(got, `"id":"72f988bf"`) {
		t.Errorf("the exec extension was not carried as JSON: %s", got)
	}
	var stderr bytes.Buffer
	rc, cred, err = plugin.RESTConfig(context.Background(), Options{Stderr: &stderr, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("RESTConfig ran the plugin and failed: %v", err)
	}
	if rc.BearerToken != plantedToken || cred == nil || cred.ExpiresAt.IsZero() {
		t.Errorf("the plugin's credential did not reach the REST config: %q %v", rc.BearerToken, cred)
	}
	if rc.Namespace != "apps" || rc.Context != "plugin" {
		t.Errorf("rest config namespace/context = %q/%q", rc.Namespace, rc.Context)
	}
}

func mkdir(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestContextRefusesWhatItCannotUse(t *testing.T) {
	dir := t.TempDir()
	ca := base64.StdEncoding.EncodeToString([]byte(testCA))
	cfg := filepath.Join(dir, "config")
	writeFile(t, cfg, `
clusters:
- name: tls
  cluster: {server: "https://k8s.example.com", certificate-authority-data: `+ca+`}
- name: plain
  cluster: {server: "http://k8s.example.com:8080"}
contexts:
- {name: gcp, context: {cluster: tls, user: gcp}}
- {name: impersonating, context: {cluster: tls, user: impersonating}}
- {name: basic, context: {cluster: tls, user: basic}}
- {name: nothing, context: {cluster: tls, user: nothing}}
- {name: halfcert, context: {cluster: tls, user: halfcert}}
- {name: plaintext, context: {cluster: plain, user: ok}}
- {name: alpha, context: {cluster: tls, user: alpha}}
- {name: nouser, context: {cluster: tls}}
users:
- {name: gcp, user: {auth-provider: {name: gcp}}}
- {name: impersonating, user: {token: t, as: system:admin}}
- {name: basic, user: {username: u, password: p}}
- {name: nothing, user: {}}
- {name: halfcert, user: {client-certificate-data: `+ca+`}}
- {name: ok, user: {token: t}}
- {name: alpha, user: {exec: {apiVersion: client.authentication.k8s.io/v1alpha1, command: x}}}
`, 0o600)
	k, err := Load([]string{cfg})
	if err != nil {
		t.Fatal(err)
	}
	for ctx, want := range map[string]string{
		"gcp":           `auth-provider`,
		"impersonating": "impersonates",
		"basic":         "basic authentication",
		"nothing":       "no credential cloop can use",
		"halfcert":      "without its key",
		"plaintext":     "is not https://",
		"alpha":         "removed in 1.24",
		"nouser":        "names no user",
	} {
		_, err := k.Context(ctx)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("context %s: err = %v, want it to mention %q", ctx, err, want)
		}
	}
}

func TestLoadSaysWhatItTried(t *testing.T) {
	dir := t.TempDir()
	_, err := Load([]string{filepath.Join(dir, "a"), filepath.Join(dir, "b")})
	if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, "a")) {
		t.Errorf("err = %v, want the paths tried", err)
	}
	t.Setenv("KUBECONFIG", "/x/one"+string(os.PathListSeparator)+" "+string(os.PathListSeparator)+"/x/two")
	if got := DefaultPaths(); len(got) != 2 || got[0] != "/x/one" || got[1] != "/x/two" {
		t.Errorf("DefaultPaths from KUBECONFIG = %v", got)
	}
	t.Setenv("KUBECONFIG", "")
	t.Setenv("HOME", dir)
	if got := DefaultPaths(); len(got) != 1 || got[0] != filepath.Join(dir, ".kube", "config") {
		t.Errorf("DefaultPaths without KUBECONFIG = %v", got)
	}
}
