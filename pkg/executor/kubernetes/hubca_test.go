package kubernetes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// hubGitCA is the hub's own CA for its git proxy's in-cluster URL.
func hubGitCA(t *testing.T) *executor.GitCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "cloop hub CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &executor.GitCA{URLs: []string{"https://cloop-cloop-hub.cloop.svc:8443/"},
		PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// TestBuildPod_HubCAFromTheLeaseSecret: with no git_ca_bundle, the hub's own
// CA travels in the run's lease Secret and reaches both containers, scoped to
// the proxy's URL (Task 20409).
func TestBuildPod_HubCAFromTheLeaseSecret(t *testing.T) {
	req := workspaceRequest()
	req.GitCA = podGitCA(hubGitCA(t), GitCABundle{})
	req.LeaseSecretName = "cloop-lease-k-abc123"
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	var vol *volume
	for i := range p.Spec.Volumes {
		if p.Spec.Volumes[i].Name == hubCAVolume {
			vol = &p.Spec.Volumes[i]
		}
	}
	if vol == nil || vol.Secret == nil || vol.Secret.SecretName != req.LeaseSecretName {
		t.Fatalf("no lease-Secret volume %q in %+v", hubCAVolume, p.Spec.Volumes)
	}
	if len(vol.Secret.Items) != 1 || vol.Secret.Items[0].Key != hubCAKey ||
		vol.Secret.Items[0].Path != executor.SandboxGitCAFileName {
		t.Errorf("volume items = %+v, want %s as %s", vol.Secret.Items, hubCAKey, executor.SandboxGitCAFileName)
	}
	wantKey := "http.https://cloop-cloop-hub.cloop.svc:8443/.sslCAInfo"
	for _, c := range append(append([]container(nil), p.Spec.InitContainers...), p.Spec.Containers...) {
		mounted := false
		for _, m := range c.VolumeMounts {
			if m.Name == hubCAVolume {
				mounted = m.MountPath == executor.SandboxGitCADir && m.ReadOnly
			}
		}
		if !mounted {
			t.Errorf("container %s does not mount the hub CA read-only at %s", c.Name, executor.SandboxGitCADir)
		}
		env := map[string]string{}
		for _, e := range c.Env {
			if e.ValueFrom == nil {
				env[e.Name] = e.Value
			}
		}
		n, _ := strconv.Atoi(env["GIT_CONFIG_COUNT"])
		found := false
		for i := 0; i < n; i++ {
			idx := strconv.Itoa(i)
			if env["GIT_CONFIG_KEY_"+idx] == wantKey && env["GIT_CONFIG_VALUE_"+idx] == executor.SandboxGitCAFile {
				found = true
			}
		}
		if !found {
			t.Errorf("container %s does not trust the hub CA for the proxy's URL: %v", c.Name, env)
		}
		if _, ok := env["GIT_SSL_CAINFO"]; ok {
			t.Errorf("container %s sets GIT_SSL_CAINFO, which replaces git's trust store for every host", c.Name)
		}
	}
}

// TestBuildPod_GitCABundleKeepsItsURL: a URL the operator's ConfigMap already
// names keeps the operator's answer — two sslCAInfo values for one URL would
// leave git using whichever came last.
func TestBuildPod_GitCABundleKeepsItsURL(t *testing.T) {
	bundle, err := GitCABundle{ConfigMap: "proxy-ca", URLs: []string{"https://cloop-cloop-hub.cloop.svc:8443"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if ca := podGitCA(hubGitCA(t), bundle); ca != nil {
		t.Fatalf("podGitCA kept %v under a bundle that names the same URL", ca.URLs)
	}
	other, err := GitCABundle{ConfigMap: "forge-ca", URLs: []string{"https://forge.internal"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if ca := podGitCA(hubGitCA(t), other); ca == nil || len(ca.URLs) != 1 {
		t.Fatalf("a bundle for another URL dropped the hub CA: %+v", ca)
	}
}

// TestStart_LeaseSecretCarriesTheHubCA: through Start against the fake API,
// the Secret the Pod mounts carries the CA under the key the volume reads —
// and a run with nothing else to lease still gets a Secret for it.
func TestStart_LeaseSecretCarriesTheHubCA(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	ca := hubGitCA(t)
	spec := testSpec()
	spec.GitCA = ca

	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	wantName := leaseSecretName(handle.ID)
	api.mu.Lock()
	sec := api.secrets[wantName]
	api.mu.Unlock()
	if sec == nil {
		t.Fatalf("no lease Secret %q for a run whose only lease is the hub CA; got %v", wantName, api.secretNames())
	}
	if string(sec.Data[hubCAKey]) != string(ca.PEM) {
		t.Errorf("Secret key %s = %q, want the CA", hubCAKey, sec.Data[hubCAKey])
	}
	name := api.onlyPodName(t)
	api.mu.Lock()
	created := *api.pods[name]
	api.mu.Unlock()
	found := false
	for _, v := range created.Spec.Volumes {
		if v.Name == hubCAVolume && v.Secret != nil && v.Secret.SecretName == wantName {
			found = true
		}
	}
	if !found {
		t.Errorf("the Pod does not project the lease Secret's CA: %+v", created.Spec.Volumes)
	}
}

// TestBuildPod_HubCAForNodeReachesTheHarness: a harness whose model calls go
// to the hub's relay (Task 20435) is told, by a plain variable, to have Node
// trust the very file its git trusts for the proxy — and a git-only bundle
// sets no Node trust. The operator's bundle naming the proxy's URL keeps git's
// answer and leaves Node's.
func TestBuildPod_HubCAForNodeReachesTheHarness(t *testing.T) {
	for _, node := range []bool{true, false} {
		ca := hubGitCA(t)
		ca.Node = node
		req := workspaceRequest()
		req.GitCA = podGitCA(ca, GitCABundle{})
		req.LeaseSecretName = "cloop-lease-k-abc123"
		p, err := buildPod(req)
		if err != nil {
			t.Fatalf("buildPod: %v", err)
		}
		var got *envVar
		for _, c := range p.Spec.Containers {
			for i := range c.Env {
				if c.Env[i].Name == executor.NodeCAEnvKey {
					got = &c.Env[i]
				}
			}
		}
		switch {
		case node && (got == nil || got.Value != executor.SandboxGitCAFile || got.ValueFrom != nil):
			t.Errorf("the harness's Node trust = %+v, want a plain %s", got, executor.SandboxGitCAFile)
		case !node && got != nil:
			t.Errorf("a git-only bundle set %s", executor.NodeCAEnvKey)
		}
	}
	bundle, err := GitCABundle{ConfigMap: "proxy-ca", URLs: []string{"https://cloop-cloop-hub.cloop.svc:8443"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	ca := hubGitCA(t)
	ca.Node = true
	if kept := podGitCA(ca, bundle); kept == nil || !kept.Node || len(kept.URLs) != 0 {
		t.Fatalf("under a bundle naming the proxy's URL, Node's CA = %+v; want it kept for Node with no git URL", kept)
	}
}
