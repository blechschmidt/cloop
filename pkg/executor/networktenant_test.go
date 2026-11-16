package executor

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestNetworkTenantIsTheProjectTheHubNamed (Task 20502): the project label the
// hub stamps wins over the workload's directory — on a device the directory is
// the device's own path, the label the hub's — and two projects never share a
// tenant, while a project's own workloads always do.
func TestNetworkTenantIsTheProjectTheHubNamed(t *testing.T) {
	SetPolicyProjectMapper(nil)
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"label", Spec{WorkDir: "/var/lib/cloop-agent/trees/app-1a2b", Labels: map[string]string{"project": "/srv/app"}}, "/srv/app"},
		{"directory without a label", Spec{WorkDir: "/srv/app"}, "/srv/app"},
		{"cleaned", Spec{Labels: map[string]string{"project": "/srv/./app/"}}, "/srv/app"},
		{"blank label falls back", Spec{WorkDir: "/srv/app", Labels: map[string]string{"project": "  "}}, "/srv/app"},
		{"no project", Spec{Labels: map[string]string{"component": "web-ui"}}, ""},
	}
	for _, c := range cases {
		if got := NetworkTenant(c.spec); got != c.want {
			t.Errorf("%s: NetworkTenant = %q, want %q", c.name, got, c.want)
		}
	}
	a := NetworkTenant(Spec{Labels: map[string]string{"project": "/srv/app"}})
	b := NetworkTenant(Spec{Labels: map[string]string{"project": "/srv/app2"}})
	if a == b {
		t.Errorf("two projects share the tenant %q", a)
	}
}

// TestNetworkTenantOfAFeatureIsItsProject: where the control plane maps a
// feature's worktree onto its parent, a feature's run is its project's tenant;
// without the mapping (an edge device) it is a tenant of its own, which keeps
// it apart from every other project all the same.
func TestNetworkTenantOfAFeatureIsItsProject(t *testing.T) {
	parent := "/srv/app"
	feature := filepath.Join(parent, ".cloop", "features", "login")
	SetPolicyProjectMapper(func(p string) string {
		if i := strings.Index(p, "/.cloop/features/"); i > 0 {
			return p[:i]
		}
		return p
	})
	t.Cleanup(func() { SetPolicyProjectMapper(nil) })
	if got := NetworkTenant(Spec{Labels: map[string]string{"project": feature}}); got != parent {
		t.Errorf("a feature's tenant is %q, want its project %q", got, parent)
	}
	SetPolicyProjectMapper(nil)
	if got := NetworkTenant(Spec{Labels: map[string]string{"project": feature}}); got != feature {
		t.Errorf("without the mapping a feature's tenant is %q, want its own %q", got, feature)
	}
}
