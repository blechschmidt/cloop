package kms_test

// The Helm chart's kms values against the code that reads them (Task 20433).
//
// The chart renders secrets.kms into the hub's config.yaml and runs the KMS v2
// plugin as a sidecar sharing a socket with the hub. Each half is a claim
// about this codebase that helm cannot check: that the rendered section is one
// config.ValidateSecrets accepts and kms.Resolve builds the intended roots
// from, and that the plugin listens where the hub dials. So the chart is
// rendered here, for each shape of the values, and its output is read the way
// the hub reads it.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/rootkey"
)

func renderHubChart(t *testing.T, set ...string) []map[string]any {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("CLOOP_REQUIRE_HELM") != "" {
			t.Fatalf("CLOOP_REQUIRE_HELM is set but helm is not on PATH: %v", err)
		}
		t.Skip("helm is not on PATH; install helm 3 to check the chart's kms values against the hub (CI requires it)")
	}
	_, file, _, _ := runtime.Caller(0)
	chart := filepath.Join(filepath.Dir(file), "..", "..", "deploy", "helm", "cloop-hub")
	args := []string{"template", "cloop", chart, "--namespace", "cloop",
		"--set", "secrets.existingSecret=external", "--set", "executor.kubernetes.enabled=true"}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(helm, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template: %v\n%s", err, stderr.String())
	}
	var docs []map[string]any
	dec := yaml.NewDecoder(&stdout)
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			break
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

func kindNamed(docs []map[string]any, kind string) map[string]any {
	for _, d := range docs {
		if d["kind"] == kind {
			return d
		}
	}
	return nil
}

// renderedConfig is the config.yaml the chart's ConfigMap carries, parsed as
// the hub parses it.
func renderedConfig(t *testing.T, docs []map[string]any) *config.Config {
	t.Helper()
	cm := kindNamed(docs, "ConfigMap")
	data, _ := cm["data"].(map[string]any)
	text, _ := data["config.yaml"].(string)
	if text == "" {
		t.Fatal("the chart rendered no config.yaml")
	}
	cfg := config.Default()
	if err := yaml.Unmarshal([]byte(text), cfg); err != nil {
		t.Fatalf("the rendered config.yaml does not parse: %v\n%s", err, text)
	}
	return cfg
}

// containers returns the Pod's containers by name, and each one's mounts by
// volume name.
func containers(t *testing.T, docs []map[string]any) map[string]map[string]string {
	t.Helper()
	dep := kindNamed(docs, "Deployment")
	spec, _ := dep["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	list, _ := pod["containers"].([]any)
	out := map[string]map[string]string{}
	for _, c := range list {
		cm, _ := c.(map[string]any)
		name, _ := cm["name"].(string)
		mounts := map[string]string{}
		ms, _ := cm["volumeMounts"].([]any)
		for _, m := range ms {
			mm, _ := m.(map[string]any)
			v, _ := mm["name"].(string)
			p, _ := mm["mountPath"].(string)
			mounts[v] = p
		}
		out[name] = mounts
	}
	return out
}

func TestHelmChartRendersAKMSTheHubAccepts(t *testing.T) {
	keys := rootkey.Roots{Current: rootkey.Root{Value: "a-root-key-for-the-render-test-0123456789",
		Source: rootkey.SourceFile}}

	t.Run("a KMS v2 plugin sidecar", func(t *testing.T) {
		docs := renderHubChart(t, "kms.enabled=true", "kms.plugin.image=example.com/kms-plugin:v1",
			"kms.plugin.args[0]=--listen-addr=unix:///var/run/kmsplugin/socket.sock", "kms.movingFromPassphrase=true")
		cfg := renderedConfig(t, docs)
		if err := config.ValidateSecrets(cfg.Secrets); err != nil {
			t.Fatalf("the hub refuses the rendered secrets section: %v", err)
		}
		roots, err := kms.Resolve(cfg.Secrets, keys)
		if err != nil {
			t.Fatal(err)
		}
		defer roots.Close()
		if !roots.Current.IsKMS() || roots.Previous.Passphrase != keys.Current.Value {
			t.Fatalf("roots = current KMS %v, previous passphrase %v", roots.Current.IsKMS(), roots.Previous.Passphrase != "")
		}
		socket, err := config.KMSv2SocketPath(cfg.Secrets.KMS.KMSv2.Endpoint)
		if err != nil {
			t.Fatal(err)
		}
		cs := containers(t, docs)
		hub, plugin := cs["hub"], cs["kms-plugin"]
		if plugin == nil {
			t.Fatal("no kms-plugin container")
		}
		if hub["kms-socket"] != filepath.Dir(socket) || plugin["kms-socket"] != filepath.Dir(socket) {
			t.Fatalf("the hub (%q) and the plugin (%q) do not share the socket's directory %s",
				hub["kms-socket"], plugin["kms-socket"], filepath.Dir(socket))
		}
	})

	t.Run("Vault Transit with the Kubernetes auth method", func(t *testing.T) {
		docs := renderHubChart(t, "kms.enabled=true", "kms.provider=transit",
			"kms.transit.address=https://vault.example.com:8200", "kms.transit.key=cloop",
			"kms.transit.kubernetes.role=cloop-hub", "kms.transit.caConfigMap.name=vault-ca")
		cfg := renderedConfig(t, docs)
		if err := config.ValidateSecrets(cfg.Secrets); err != nil {
			t.Fatalf("the hub refuses the rendered secrets section: %v", err)
		}
		tr := cfg.Secrets.KMS.Transit
		hub := containers(t, docs)["hub"]
		if hub["kms-sa-token"] == "" || !strings.HasPrefix(tr.Kubernetes.TokenFile, hub["kms-sa-token"]+"/") {
			t.Fatalf("the projected token is mounted at %q and the hub reads %q", hub["kms-sa-token"], tr.Kubernetes.TokenFile)
		}
		if !strings.HasPrefix(tr.CAFile, hub["kms-ca"]+"/") {
			t.Fatalf("the CA is mounted at %q and the hub reads %q", hub["kms-ca"], tr.CAFile)
		}
		if _, ok := containers(t, docs)["kms-plugin"]; ok {
			t.Fatal("a Transit KMS renders a plugin sidecar")
		}
	})

	t.Run("Vault Transit with a token Secret", func(t *testing.T) {
		docs := renderHubChart(t, "kms.enabled=true", "kms.provider=transit",
			"kms.transit.address=https://vault.example.com:8200", "kms.transit.key=cloop",
			"kms.transit.tokenSecret.name=vault-token")
		cfg := renderedConfig(t, docs)
		if err := config.ValidateSecrets(cfg.Secrets); err != nil {
			t.Fatalf("the hub refuses the rendered secrets section: %v", err)
		}
		hub := containers(t, docs)["hub"]
		if !strings.HasPrefix(cfg.Secrets.KMS.Transit.TokenFile, hub["kms-token"]+"/") {
			t.Fatalf("the token is mounted at %q and the hub reads %q", hub["kms-token"], cfg.Secrets.KMS.Transit.TokenFile)
		}
	})

	t.Run("off", func(t *testing.T) {
		cfg := renderedConfig(t, renderHubChart(t))
		if cfg.Secrets.UsesKMS() || cfg.Secrets.PreviousRoot != "" {
			t.Fatalf("a release without kms renders a secrets section: %+v", cfg.Secrets)
		}
	})
}
