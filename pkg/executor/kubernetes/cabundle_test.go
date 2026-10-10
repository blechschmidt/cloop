package kubernetes

import (
	"strconv"
	"strings"
	"testing"
)

// proxyBundle is the shape the Helm chart renders for a hub whose git proxy
// is served under its in-cluster Service name.
func proxyBundle() GitCABundle {
	return GitCABundle{
		ConfigMap: "cloop-cloop-hub-proxy-ca",
		URLs:      []string{"https://cloop-cloop-hub.cloop.svc:8443"},
	}
}

func TestGitCABundleNormalize(t *testing.T) {
	got, err := proxyBundle().Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got.Key != DefaultGitCABundleKey {
		t.Errorf("Key = %q, want the default %q", got.Key, DefaultGitCABundleKey)
	}
	// The trailing slash is what makes git's http.<url>.* match every
	// repository beneath the proxy and nothing on a longer host name.
	if want := []string{"https://cloop-cloop-hub.cloop.svc:8443/"}; len(got.URLs) != 1 || got.URLs[0] != want[0] {
		t.Errorf("URLs = %q, want %q", got.URLs, want)
	}

	if z, err := (GitCABundle{}).Normalize(); err != nil || z.Enabled() {
		t.Errorf("the zero bundle: %+v, %v; want disabled and valid", z, err)
	}

	refused := map[string]GitCABundle{
		"urls with no config map":    {URLs: []string{"https://hub:8443/"}},
		"a key with no config map":   {Key: "ca.crt"},
		"no urls":                    {ConfigMap: "ca"},
		"an http url":                {ConfigMap: "ca", URLs: []string{"http://hub:8080/"}},
		"a url with credentials":     {ConfigMap: "ca", URLs: []string{"https://u:p@hub:8443/"}},
		"a url with a query":         {ConfigMap: "ca", URLs: []string{"https://hub:8443/?x=1"}},
		"a url with no host":         {ConfigMap: "ca", URLs: []string{"https:///path"}},
		"a url with whitespace":      {ConfigMap: "ca", URLs: []string{"https://hub:8443/\n[core]"}},
		"a config map name in caps":  {ConfigMap: "Proxy-CA", URLs: []string{"https://hub:8443/"}},
		"a key with a slash":         {ConfigMap: "ca", Key: "../ca.crt", URLs: []string{"https://hub:8443/"}},
		"more urls than the ceiling": {ConfigMap: "ca", URLs: strings.Split(strings.Repeat("https://hub:8443/,", maxGitCABundleURLs+1), ",")[:maxGitCABundleURLs+1]},
	}
	for name, b := range refused {
		if _, err := b.Normalize(); err == nil {
			t.Errorf("%s: Normalize accepted %+v", name, b)
		}
	}
}

// TestBuildPod_GitCABundleReachesBothContainers: the provisioner fetches
// through the proxy before the harness ever runs, so a bundle only the harness
// held would fail the run at its first step.
func TestBuildPod_GitCABundleReachesBothContainers(t *testing.T) {
	bundle, err := proxyBundle().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	req := workspaceRequest()
	req.GitCABundle = bundle
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}

	var vol *volume
	for i := range p.Spec.Volumes {
		if p.Spec.Volumes[i].Name == gitCAVolume {
			vol = &p.Spec.Volumes[i]
		}
	}
	if vol == nil || vol.ConfigMap == nil {
		t.Fatalf("no ConfigMap volume %q in %+v", gitCAVolume, p.Spec.Volumes)
	}
	if vol.ConfigMap.Name != bundle.ConfigMap || len(vol.ConfigMap.Items) != 1 ||
		vol.ConfigMap.Items[0].Key != DefaultGitCABundleKey || vol.ConfigMap.Items[0].Path != "ca.crt" {
		t.Errorf("volume = %+v, want %s/%s projected as ca.crt", vol.ConfigMap, bundle.ConfigMap, DefaultGitCABundleKey)
	}
	if vol.ConfigMap.Optional == nil || *vol.ConfigMap.Optional {
		t.Error("the bundle volume must not be optional: a missing ConfigMap has to hold the Pod, " +
			"not start one whose first fetch fails on a certificate")
	}

	wantKey := "http.https://cloop-cloop-hub.cloop.svc:8443/.sslCAInfo"
	for _, c := range append(append([]container(nil), p.Spec.InitContainers...), p.Spec.Containers...) {
		// The harness's block opens with the workspace trust; the bundle follows.
		first := 0
		if c.Name == ContainerName {
			first = 1
		}
		mounted := false
		for _, m := range c.VolumeMounts {
			if m.Name == gitCAVolume {
				mounted = m.MountPath == PodGitCADir && m.ReadOnly
			}
		}
		if !mounted {
			t.Errorf("container %s does not mount the bundle read-only at %s", c.Name, PodGitCADir)
		}
		env := map[string]string{}
		for _, e := range c.Env {
			if e.ValueFrom == nil {
				env[e.Name] = e.Value
			}
		}
		idx := strconv.Itoa(first)
		if env["GIT_CONFIG_COUNT"] != strconv.Itoa(first+1) || env["GIT_CONFIG_KEY_"+idx] != wantKey ||
			env["GIT_CONFIG_VALUE_"+idx] != PodGitCAFile {
			t.Errorf("container %s git config = COUNT %q, KEY_%s %q, VALUE_%s %q; want %d, %q, %q",
				c.Name, env["GIT_CONFIG_COUNT"], idx, env["GIT_CONFIG_KEY_"+idx], idx, env["GIT_CONFIG_VALUE_"+idx],
				first+1, wantKey, PodGitCAFile)
		}
		// Never the global form: that would replace the image's trust store
		// for every host the workload reaches directly.
		if _, ok := env["GIT_SSL_CAINFO"]; ok {
			t.Errorf("container %s sets GIT_SSL_CAINFO, which replaces git's trust store for every host", c.Name)
		}
	}
}

// TestBuildPod_GitCABundleJoinsAnExistingConfigBlock: GIT_CONFIG_COUNT is one
// variable for the whole environment. A workload whose environment already
// numbers entries — the review gate's push rewrite, say — must keep them.
func TestBuildPod_GitCABundleJoinsAnExistingConfigBlock(t *testing.T) {
	bundle, err := proxyBundle().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	req := baseRequest()
	req.GitCABundle = bundle
	req.LeaseSecretName = "cloop-lease-k-abc123"
	req.Env = []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=url.cloop-review::https://.pushInsteadOf",
		"GIT_CONFIG_VALUE_0=https://",
	}
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	// The Spec's own entries arrive from the lease Secret, the driver's as
	// plain values; resolve both the way the kubelet does.
	data, err := leaseSecretData(nil, req.Env)
	if err != nil {
		t.Fatal(err)
	}
	env := resolveEnv(t, p.Spec.Containers[0], map[string]map[string][]byte{req.LeaseSecretName: data})
	if env["GIT_CONFIG_COUNT"] != "3" || env["GIT_CONFIG_KEY_0"] != "url.cloop-review::https://.pushInsteadOf" ||
		env["GIT_CONFIG_KEY_1"] != "safe.directory" ||
		env["GIT_CONFIG_KEY_2"] != "http.https://cloop-cloop-hub.cloop.svc:8443/.sslCAInfo" {
		t.Errorf("merged block = %v; want the existing entry kept at 0, the workspace trust at 1, the bundle at 2", env)
	}

	req.Env = []string{"GIT_CONFIG_COUNT=many"}
	if _, err := buildPod(req); err == nil {
		t.Error("buildPod renumbered over a GIT_CONFIG_COUNT it could not read")
	}
}

func TestBuildPod_NoGitCABundleNoVolume(t *testing.T) {
	p, err := buildPod(workspaceRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	for _, v := range p.Spec.Volumes {
		if v.ConfigMap != nil {
			t.Errorf("a Pod with no bundle configured carries ConfigMap volume %q", v.Name)
		}
	}
	for _, c := range append(p.Spec.InitContainers, p.Spec.Containers...) {
		for _, e := range c.Env {
			if strings.Contains(e.Value, "sslCAInfo") {
				t.Errorf("container %s trusts a CA with no bundle configured: %s=%s", c.Name, e.Name, e.Value)
			}
		}
	}
}

// TestBuildPod_HarnessGitTrustsTheWorkspace: /workspace is an emptyDir, which
// root owns whatever runAsUser says, and git refuses a work tree another user
// owns — so without this every git command the harness runs in its own
// workspace fails with "detected dubious ownership". The first live run on a
// cluster found exactly that (Task 20385). The trust is the one path, nothing
// wider, and the init container gets none: cloop's provisioner applies it
// itself, only to a root-owned target.
func TestBuildPod_HarnessGitTrustsTheWorkspace(t *testing.T) {
	p, err := buildPod(workspaceRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	env := map[string]string{}
	for _, e := range p.Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	if env["GIT_CONFIG_COUNT"] != "1" || env["GIT_CONFIG_KEY_0"] != "safe.directory" ||
		env["GIT_CONFIG_VALUE_0"] != PodWorkspace {
		t.Errorf("harness git config = %v; want exactly safe.directory=%s", env, PodWorkspace)
	}
	for _, e := range p.Spec.InitContainers[0].Env {
		if strings.HasPrefix(e.Name, "GIT_CONFIG_") {
			t.Errorf("the init container carries %s=%s; the provisioner trusts its target itself", e.Name, e.Value)
		}
	}
}
