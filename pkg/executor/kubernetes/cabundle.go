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
	"net/url"
	"strconv"
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
// http.<url>.* keys: scheme, host, port, and a path ending in "/" so that
// https://hub:8443/ matches every repository beneath it and nothing at
// https://hub:8443.evil.example.
func normalizeGitCAURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("git_ca_bundle url %q contains whitespace", s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("git_ca_bundle url %q is not a URL: %v", s, err)
	}
	switch {
	case u.Scheme != "https":
		// http:// carries no certificate to verify; a bundle for it is a
		// misunderstanding of what the proxy needs.
		return "", fmt.Errorf("git_ca_bundle url %q must be https", s)
	case u.Host == "" || u.Hostname() == "":
		return "", fmt.Errorf("git_ca_bundle url %q has no host", s)
	case u.User != nil:
		return "", fmt.Errorf("git_ca_bundle url %q must not embed credentials", s)
	case u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return "", fmt.Errorf("git_ca_bundle url %q must be a base URL with no query or fragment", s)
	}
	path := u.EscapedPath()
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return "https://" + strings.ToLower(u.Host) + path, nil
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

// withGitConfig adds pairs to the GIT_CONFIG_COUNT block in env (K=V strings),
// after any entries already there, and returns the new list.
//
// The count is one variable for the whole environment, so appending a second
// block would silently replace the first — a lease's or the review gate's —
// rather than join it. A count that does not parse is refused rather than
// overwritten: whoever set it meant something by the entries it numbers.
func withGitConfig(env []string, pairs [][2]string) ([]string, error) {
	if len(pairs) == 0 {
		return env, nil
	}
	out := make([]string, 0, len(env)+1+2*len(pairs))
	n := 0
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "GIT_CONFIG_COUNT="); ok {
			c, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || c < 0 {
				return nil, fmt.Errorf("%w: GIT_CONFIG_COUNT %q in the workload's environment is not a count",
					executor.ErrInvalidSpec, v)
			}
			n = c
			continue
		}
		out = append(out, kv)
	}
	for i, kv := range pairs {
		idx := strconv.Itoa(n + i)
		out = append(out, "GIT_CONFIG_KEY_"+idx+"="+kv[0], "GIT_CONFIG_VALUE_"+idx+"="+kv[1])
	}
	return append(out, "GIT_CONFIG_COUNT="+strconv.Itoa(n+len(pairs))), nil
}
