package kubernetes

// cabundle.go hands a workload's git the certificate authority it needs for
// particular URLs, and for nothing else (Task 20385).
//
// The case it exists for is the hub's own git interception proxy. In a cluster
// it is served under an in-cluster name — cloop-hub.cloop.svc — which no
// public CA will certify, so its certificate is private, and a Pod's git
// refuses it. On an edge device the operator fixes that by installing the CA in
// the image or pointing GIT_SSL_CAINFO at a bundle; a Pod gives the operator
// neither, because this driver writes the Pod spec.
//
// # Why per URL, and not GIT_SSL_CAINFO
//
// GIT_SSL_CAINFO *replaces* git's trust store. A workload whose bundle held
// only the proxy's CA could no longer verify github.com, gitlab.com or any
// other forge it reaches directly — a public repository fetched without a
// grant, a dependency named by URL — and the failure would read as a network
// problem nowhere near the setting that caused it. git's http.<url>.sslCAInfo
// scopes the bundle to the URLs named and leaves every other host on the
// image's own store, so turning this on can only make a connection work.
//
// It reaches git through the GIT_CONFIG_COUNT protocol in both containers'
// environment, which outranks every config file and needs nothing written into
// the workspace. The harness's own git reads it directly; cloop's provisioning
// and write-back children run with a closed environment and import exactly
// these keys from it (gitprovision.TransportConfig).
//
// # Why a ConfigMap the operator names
//
// A CA certificate is public, so a ConfigMap is the right object, and one the
// operator (or the Helm chart, or trust-manager) maintains in the workload
// namespace keeps this driver from needing any new authority: the kubelet
// fetches a ConfigMap a Pod mounts on the Pod's behalf, so the Role gains no
// configmaps rule. A missing ConfigMap parks the Pod in ContainerCreating with
// an event naming it, which is the failure to want — a Pod that started anyway
// would fail its first fetch with a certificate error instead.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const (
	// PodGitCADir is where the bundle is mounted, read-only, in the harness and
	// the workspace provisioner.
	PodGitCADir = "/etc/cloop/git-ca"
	// PodGitCAFile is the bundle inside PodGitCADir, whatever the ConfigMap
	// key it came from.
	PodGitCAFile = PodGitCADir + "/ca.crt"

	// DefaultGitCABundleKey is the ConfigMap entry read when none is named:
	// the name cert-manager and trust-manager use.
	DefaultGitCABundleKey = "ca.crt"

	gitCAVolume = "git-ca"

	// maxGitCABundleURLs bounds the list. A hub has one git proxy; a handful
	// of private forges besides it is plausible, and dozens is a bundle that
	// should be the image's trust store instead.
	maxGitCABundleURLs = 16
)

// gitCAFileMode is world-readable: the file is a CA certificate, and a Pod's
// user differs from the kubelet's.
var gitCAFileMode int32 = 0o444

// GitCABundle names the PEM bundle a workload's git verifies certain https
// URLs against. The zero value delivers nothing.
type GitCABundle struct {
	// ConfigMap is a ConfigMap in the namespace Pods are created in.
	ConfigMap string `yaml:"config_map,omitempty"`
	// Key is the entry holding the PEM bundle. Empty means DefaultGitCABundleKey.
	Key string `yaml:"key,omitempty"`
	// URLs are the https base URLs git verifies against the bundle — a hub's
	// executors.git_proxy.advertise_url, typically. Every other host keeps the
	// image's own trust store.
	URLs []string `yaml:"urls,omitempty"`
}

// Enabled reports whether a bundle is configured.
func (b GitCABundle) Enabled() bool { return strings.TrimSpace(b.ConfigMap) != "" }

// Normalize validates b and fills defaults, returning a copy. A bundle with no
// ConfigMap must name nothing else: a key or URL list on its own is a section
// half-written, and silently ignoring it would leave the operator debugging a
// certificate error.
func (b GitCABundle) Normalize() (GitCABundle, error) {
	b.ConfigMap = strings.TrimSpace(b.ConfigMap)
	b.Key = strings.TrimSpace(b.Key)
	if b.ConfigMap == "" {
		if b.Key != "" || len(b.URLs) > 0 {
			return b, fmt.Errorf("git_ca_bundle names a key or urls but no config_map to read the bundle from")
		}
		return GitCABundle{}, nil
	}
	if err := validateDNSSubdomain(b.ConfigMap, "git_ca_bundle.config_map"); err != nil {
		return b, err
	}
	if b.Key == "" {
		b.Key = DefaultGitCABundleKey
	}
	if !validSecretKeyName(b.Key) || len(b.Key) > maxDNSSubdomain {
		// ConfigMap keys follow the same [-._a-zA-Z0-9]+ rule as Secret keys.
		return b, fmt.Errorf("git_ca_bundle.key %q is not a valid ConfigMap key ([-._a-zA-Z0-9], at most %d characters)",
			b.Key, maxDNSSubdomain)
	}
	if len(b.URLs) == 0 {
		return b, fmt.Errorf("git_ca_bundle names no urls: list the https URLs git should verify " +
			"against the bundle — on a hub running the git proxy, executors.git_proxy.advertise_url")
	}
	if len(b.URLs) > maxGitCABundleURLs {
		return b, fmt.Errorf("git_ca_bundle names %d urls; at most %d are allowed", len(b.URLs), maxGitCABundleURLs)
	}
	seen := make(map[string]bool, len(b.URLs))
	urls := make([]string, 0, len(b.URLs))
	for _, raw := range b.URLs {
		u, err := normalizeGitCAURL(raw)
		if err != nil {
			return b, err
		}
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	b.URLs = urls
	return b, nil
}

// normalizeGitCAURL checks one URL and renders it the way git matches
// http.<url>.* keys; see executor.NormalizeGitCAURL, which the hub's own CA
// (executor.GitCA) is held to as well.
func normalizeGitCAURL(raw string) (string, error) {
	u, err := executor.NormalizeGitCAURL(raw)
	if err != nil {
		return "", fmt.Errorf("git_ca_bundle: %w", err)
	}
	return u, nil
}

// gitConfigPairs is the configuration that scopes the bundle: one
// http.<url>.sslCAInfo per URL.
func (b GitCABundle) gitConfigPairs() [][2]string {
	if !b.Enabled() {
		return nil
	}
	out := make([][2]string, 0, len(b.URLs))
	for _, u := range b.URLs {
		out = append(out, [2]string{"http." + u + ".sslCAInfo", PodGitCAFile})
	}
	return out
}

// volume is the ConfigMap projected as one read-only file.
func (b GitCABundle) volume() volume {
	return volume{
		Name: gitCAVolume,
		ConfigMap: &configMapSource{
			Name:        b.ConfigMap,
			Items:       []keyToPath{{Key: b.Key, Path: "ca.crt"}},
			DefaultMode: &gitCAFileMode,
			Optional:    boolPtr(false),
		},
	}
}

func (b GitCABundle) mount() volumeMount {
	return volumeMount{Name: gitCAVolume, MountPath: PodGitCADir, ReadOnly: true}
}

// withGitConfig adds pairs to the GIT_CONFIG_COUNT block in env; see
// executor.WithGitConfig.
func withGitConfig(env []string, pairs [][2]string) ([]string, error) {
	return executor.WithGitConfig(env, pairs)
}

// The hub's own CA (Spec.GitCA, Task 20409), for a hub whose git proxy serves a
// certificate it issued itself. It travels in the run's lease Secret — public
// material, but the Secret already exists per run and is deleted with the Pod,
// where a ConfigMap would be one more object this driver needs authority over —
// and is projected read-only at executor.SandboxGitCAFile in both containers.
const (
	// hubCAKey is the lease Secret entry holding the hub's CA.
	hubCAKey = "hub-ca.crt"
	// hubCAVolume projects it.
	hubCAVolume = "hub-ca"
)

// podGitCA returns the part of the hub's CA this Pod takes from its lease
// Secret: the URLs the operator's git_ca_bundle does not already name. A URL
// the bundle covers keeps the operator's answer — two sslCAInfo values for one
// URL would leave git using whichever came last. Nil when nothing remains.
func podGitCA(ca *executor.GitCA, bundle GitCABundle) *executor.GitCA {
	if ca == nil {
		return nil
	}
	covered := map[string]bool{}
	if bundle.Enabled() {
		for _, u := range bundle.URLs {
			covered[u] = true
		}
	}
	out := &executor.GitCA{PEM: append([]byte(nil), ca.PEM...)}
	for _, u := range ca.URLs {
		if !covered[u] {
			out.URLs = append(out.URLs, u)
		}
	}
	if len(out.URLs) == 0 {
		return nil
	}
	return out
}

// hubCAVolumeFor projects the lease Secret's hubCAKey as one read-only file.
func hubCAVolumeFor(leaseSecret string) volume {
	return volume{
		Name: hubCAVolume,
		Secret: &secretSource{
			SecretName:  leaseSecret,
			Items:       []keyToPath{{Key: hubCAKey, Path: executor.SandboxGitCAFileName}},
			DefaultMode: &gitCAFileMode,
			Optional:    boolPtr(false),
		},
	}
}

func hubCAMount() volumeMount {
	return volumeMount{Name: hubCAVolume, MountPath: executor.SandboxGitCADir, ReadOnly: true}
}
