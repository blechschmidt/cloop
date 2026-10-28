package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// refusingCluster is a cluster credential nothing can be leased from, so a
// preflight stops at the credential check — after the image checks this test
// reads.
type refusingCluster struct{}

func (refusingCluster) Describe() string { return "refusing" }
func (refusingCluster) Acquire(context.Context, string) (*kubernetes.Credentials, error) {
	return nil, errors.New("no cluster in this test")
}
func (refusingCluster) Renew(context.Context, string) (*kubernetes.Credentials, error) {
	return nil, errors.New("no cluster in this test")
}
func (refusingCluster) Release(string) {}

// loginSource is a registry secret holding a login for one registry.
type loginSource struct{}

func (loginSource) RegistryLogins(context.Context) (imagepolicy.DockerLogins, error) {
	return imagepolicy.ParseDockerConfig([]byte(`{"auths":{"registry.example":{"username":"u","password":"p"}}}`))
}
func (loginSource) Describe() string { return "registry secret ci-robot" }

// TestTheHubsKubernetesDriverResolvesTagsWithItsRegistryLogin (Task 20457):
// the driver reconciliation registers resolves every tag a Pod would carry,
// signing in with the registry login its identity source supplies — which the
// preflight reports by name.
func TestTheHubsKubernetesDriverResolvesTagsWithItsRegistryLogin(t *testing.T) {
	permissive(t)
	reg := executor.NewRegistry()
	opts := isolatedOpts(reg)
	opts.KubernetesCredentials = func(string, *config.Config, string) (Identity, func(), error) {
		return Identity{Cluster: refusingCluster{}, Registry: loginSource{}}, nil, nil
	}
	cfg := &config.Config{}
	cfg.Executors.Kubernetes.Enabled = true
	cfg.Executors.Kubernetes.ID = "k8s"
	// By digest, so the preflight resolves nothing at a real registry.
	cfg.Executors.Kubernetes.Image = "registry.example/ops/harness@sha256:" + strings.Repeat("ab", 32)

	d := diagFor(t, FromConfig(context.Background(), t.TempDir(), cfg, opts), "k8s")
	var login *Finding
	for i := range d.Findings {
		if d.Findings[i].Name == "registry-login" {
			login = &d.Findings[i]
		}
	}
	if login == nil || login.Level != "ok" || !strings.Contains(login.Message, "registry secret ci-robot") ||
		!strings.Contains(login.Message, "registry.example") {
		t.Fatalf("the registered driver does not resolve with its registry login: %+v", d.Findings)
	}
}

// TestRegistryLoginSourceNeverFallsBackToAnonymous: no registry_secret is an
// anonymous resolution; a configured one this process has no secret store to
// read is a source that says so at every dispatch — never nil, which would
// resolve anonymously beside a login the operator meant the hub to use.
func TestRegistryLoginSourceNeverFallsBackToAnonymous(t *testing.T) {
	t.Setenv("CLOOP_SECRET_KEY", "")
	t.Setenv("CLOOP_SECRET_KEY_FILE", "")
	cfg := &config.Config{}
	if src, _ := registryLoginSource(t.TempDir(), cfg, nil); src != nil {
		t.Fatalf("no registry_secret built %v, want nil", src)
	}
	cfg.Executors.Kubernetes.RegistrySecret = "ci-robot"
	src, cleanup := registryLoginSource(t.TempDir(), cfg, nil)
	if cleanup != nil {
		defer cleanup()
	}
	if src == nil {
		t.Fatal("a configured registry_secret with no secret store built no source")
	}
	if _, err := src.RegistryLogins(context.Background()); err == nil || !strings.Contains(err.Error(), "ci-robot") {
		t.Fatalf("RegistryLogins = %v, want a refusal naming the secret", err)
	}
}
