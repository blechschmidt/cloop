package kubeguard

// kubeconfig.go renders the document delivered into the sandbox.
//
// This is the artefact the whole package is arranged around, and the property
// that matters is what it does *not* contain: no bearer token for the
// cluster, no client certificate, no client key, no CA for the cluster, not
// even the cluster's address. A sandbox holding this file cannot reach the
// API server at all except through the monitor, because it does not know
// where the API server is.
//
// kubeconfig_test.go asserts exactly that, against a kubeconfig whose
// credential is a known plaintext.

import (
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Names used inside the delivered document. Fixed rather than derived: the
// sandbox has exactly one cluster to talk to, so a name carries no
// information, and a name derived from the grant would put operator-supplied
// text into a file a harness parses.
const (
	kubeconfigClusterName = "cloop"
	kubeconfigUserName    = "cloop"
	kubeconfigContextName = "cloop"
)

// sandboxKubeconfig is the document written into the sandbox. It is a
// separate, minimal type rather than a reuse of the parser's: this side only
// ever emits the five fields below, and a struct that could express an `exec`
// block is a struct that could one day emit one.
type sandboxKubeconfig struct {
	APIVersion     string            `yaml:"apiVersion"`
	Kind           string            `yaml:"kind"`
	CurrentContext string            `yaml:"current-context"`
	Clusters       []sandboxCluster  `yaml:"clusters"`
	Contexts       []sandboxContext  `yaml:"contexts"`
	Users          []sandboxUser     `yaml:"users"`
	Preferences    map[string]string `yaml:"preferences,omitempty"`
}

type sandboxCluster struct {
	Name    string `yaml:"name"`
	Cluster struct {
		Server string `yaml:"server"`
		CAData string `yaml:"certificate-authority-data,omitempty"`
	} `yaml:"cluster"`
}

type sandboxContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster   string `yaml:"cluster"`
		User      string `yaml:"user"`
		Namespace string `yaml:"namespace,omitempty"`
	} `yaml:"context"`
}

type sandboxUser struct {
	Name string `yaml:"name"`
	User struct {
		Token string `yaml:"token"`
	} `yaml:"user"`
}

// renderKubeconfig builds the sandbox-facing document for a session.
//
// defaultNamespace is the namespace the delivered context points at. It is a
// convenience only — the monitor enforces the namespace allowlist on every
// request regardless of what the context says, which is the difference this
// package exists to make. Setting it means `kubectl get pods` works without
// -n; it means nothing about what `kubectl -n other get pods` can do.
func (r *Registry) renderKubeconfig(s *Session, token, defaultNamespace string) ([]byte, error) {
	if strings.TrimSpace(r.BaseURL) == "" {
		return nil, fmt.Errorf("kubeguard: registry has no base url to advertise")
	}

	// Prefer a namespace the policy actually permits. A context pointing at a
	// namespace every request would be refused for is a worse first
	// experience than no default at all.
	ns := strings.TrimSpace(defaultNamespace)
	if ns != "" && !s.Policy.AllowsNamespace(ns) {
		ns = ""
	}
	if ns == "" {
		ns = firstConcreteNamespace(s.Policy.Namespaces)
	}

	var doc sandboxKubeconfig
	doc.APIVersion = "v1"
	doc.Kind = "Config"
	doc.CurrentContext = kubeconfigContextName

	var cl sandboxCluster
	cl.Name = kubeconfigClusterName
	cl.Cluster.Server = r.BaseURL
	if len(r.CABundle) > 0 {
		cl.Cluster.CAData = base64.StdEncoding.EncodeToString(r.CABundle)
	}
	doc.Clusters = []sandboxCluster{cl}

	var ctx sandboxContext
	ctx.Name = kubeconfigContextName
	ctx.Context.Cluster = kubeconfigClusterName
	ctx.Context.User = kubeconfigUserName
	ctx.Context.Namespace = ns
	doc.Contexts = []sandboxContext{ctx}

	var usr sandboxUser
	usr.Name = kubeconfigUserName
	usr.User.Token = token
	doc.Users = []sandboxUser{usr}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("kubeguard: render kubeconfig: %w", err)
	}
	return out, nil
}

// firstConcreteNamespace returns the first allowlist entry that names a
// namespace rather than matching a set of them, or "".
//
// It mirrors pkg/secretbroker's function of the same name, for the same
// reason: a glob is not a namespace, and pinning a context to "app-*" would
// produce a kubeconfig that looks configured and fails on first use.
func firstConcreteNamespace(namespaces []string) string {
	for _, ns := range namespaces {
		n := strings.TrimSpace(ns)
		if n == "" || strings.ContainsAny(n, "*?[]") {
			continue
		}
		return n
	}
	return ""
}
