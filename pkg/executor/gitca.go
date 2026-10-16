package executor

// gitca.go carries a certificate authority a workload's git trusts for
// particular https URLs, and for nothing else (Task 20409).
//
// The case it exists for is the hub's own git interception proxy served under
// a certificate the hub issued itself (executors.git_proxy.tls: auto). No
// sandbox image trusts that CA, and none should have to be rebuilt to: the hub
// sends the CA with the dispatch, and each driver puts it where the workload's
// git — and cloop's own provisioning git — will read it.
//
// # Per URL, never GIT_SSL_CAINFO
//
// GIT_SSL_CAINFO *replaces* git's trust store, so a workload given the hub's
// CA that way could no longer verify github.com or any other host it reaches
// directly. Worse for the boundary, it would also trust *any* host whose
// certificate the hub's CA signed. git's http.<url>.sslCAInfo scopes the
// bundle to the URLs named: the proxy's URL verifies against the hub's CA,
// every other host against the image's own store — so another server holding a
// certificate from the same CA is still refused. It reaches git through the
// GIT_CONFIG_COUNT protocol, which outranks every config file and needs nothing
// written into the workspace.
//
// # What it carries
//
// A CA certificate — public by construction — and the URLs it is for. Never a
// private key: Validate refuses any PEM block that is not a certificate, so a
// mistake upstream cannot ship the CA's key to a sandbox inside this struct.
//
// # Node, which has no per-URL trust
//
// Since Task 20435 the same bundle may also be handed to Node.js, which is
// what Claude Code runs on, so a harness talking to the hub's model relay on
// the git proxy's listener verifies it. Node takes extra CAs from
// NODE_EXTRA_CA_CERTS, a file it reads at start, and trusts them for every TLS
// connection the process makes — there is no per-URL form. So a bundle asks
// for it explicitly (Node), only the hub sets that, only for a run whose model
// calls go to a relay this CA certifies, and the file it names holds the hub's
// CA and nothing else: Validate refuses a Node bundle of more than one
// certificate. The CA issues leaves for the proxy's advertised names alone
// (pkg/hubca), and its key never leaves the hub.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const (
	// SandboxGitCADir is where a sandbox with a filesystem of its own — a
	// container, a Pod, a container on an edge device — finds the CA,
	// mounted read-only.
	SandboxGitCADir = "/etc/cloop/hub-ca"
	// SandboxGitCAFile is the bundle inside SandboxGitCADir.
	SandboxGitCAFile = SandboxGitCADir + "/ca.crt"
	// SandboxGitCAFileName is SandboxGitCAFile's base name.
	SandboxGitCAFileName = "ca.crt"

	// MaxGitCAPEMBytes bounds the bundle. A CA certificate is a kilobyte;
	// anything near this is not one.
	MaxGitCAPEMBytes = 64 << 10
	// maxGitCAURLs bounds the URLs one bundle is trusted for.
	maxGitCAURLs = 16
)

// GitCA is a certificate authority a workload's git trusts for particular
// https URLs.
type GitCA struct {
	// URLs are https base URLs, rendered the way git matches http.<url>.*:
	// scheme, host, port and a path ending in "/".
	URLs []string `json:"urls"`
	// PEM holds one or more CA certificates. Public.
	PEM []byte `json:"pem"`
	// Node asks the driver to also name the bundle in NODE_EXTRA_CA_CERTS
	// (NodeCAEnvKey), for a harness on Node.js that talks to the hub's model
	// relay (Task 20435). Node trusts it for every host, not the URLs above;
	// see the file's comment.
	Node bool `json:"node,omitempty"`
}

// NodeCAEnvKey is the variable Node.js reads extra CA certificates from.
const NodeCAEnvKey = "NODE_EXTRA_CA_CERTS"

// NodeEnv is what a driver adds to the workload's environment for a bundle it
// placed at path: NODE_EXTRA_CA_CERTS naming it, when the bundle asks for
// that; nothing otherwise.
func (c *GitCA) NodeEnv(path string) []string {
	if c == nil || !c.Node || path == "" {
		return nil
	}
	return []string{NodeCAEnvKey + "=" + path}
}

// Validate checks the bundle as a driver is about to write it: every URL an
// https base, and the PEM nothing but parseable CA certificates.
func (c *GitCA) Validate() error {
	if c == nil {
		return nil
	}
	if len(c.URLs) == 0 {
		return fmt.Errorf("%w: git_ca names no URL to trust it for", ErrInvalidSpec)
	}
	if len(c.URLs) > maxGitCAURLs {
		return fmt.Errorf("%w: git_ca names %d URLs; at most %d", ErrInvalidSpec, len(c.URLs), maxGitCAURLs)
	}
	for _, u := range c.URLs {
		norm, err := NormalizeGitCAURL(u)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSpec, err)
		}
		if norm != u {
			return fmt.Errorf("%w: git_ca url %q is not in normal form (%q)", ErrInvalidSpec, u, norm)
		}
	}
	if len(c.PEM) == 0 || len(c.PEM) > MaxGitCAPEMBytes {
		return fmt.Errorf("%w: git_ca carries %d bytes of PEM; want 1 to %d", ErrInvalidSpec, len(c.PEM), MaxGitCAPEMBytes)
	}
	rest := c.PEM
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// The check that matters most: nothing but certificates, so a
			// private key cannot reach a sandbox through this field.
			return fmt.Errorf("%w: git_ca holds a %q block; only certificates may travel to a sandbox",
				ErrInvalidSpec, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("%w: git_ca certificate does not parse: %v", ErrInvalidSpec, err)
		}
		if !cert.IsCA {
			return fmt.Errorf("%w: git_ca certificate %q is not a CA certificate", ErrInvalidSpec, cert.Subject.CommonName)
		}
		n++
	}
	if strings.TrimSpace(string(rest)) != "" {
		return fmt.Errorf("%w: git_ca PEM has trailing data that is not a PEM block", ErrInvalidSpec)
	}
	if n == 0 {
		return fmt.Errorf("%w: git_ca PEM holds no certificate", ErrInvalidSpec)
	}
	if c.Node && n != 1 {
		// Node trusts the file for every host it reaches: it holds the hub's
		// CA and nothing else.
		return fmt.Errorf("%w: git_ca for Node holds %d certificates; it must hold exactly the hub's CA", ErrInvalidSpec, n)
	}
	return nil
}

// Clone returns a deep copy, so a driver can rewrite one Spec's without
// touching another's.
func (c *GitCA) Clone() *GitCA {
	if c == nil {
		return nil
	}
	return &GitCA{URLs: append([]string(nil), c.URLs...), PEM: append([]byte(nil), c.PEM...), Node: c.Node}
}

// ConfigPairs is the git configuration that trusts the bundle at path for
// the URLs and nothing else: one http.<url>.sslCAInfo per URL.
func (c *GitCA) ConfigPairs(path string) [][2]string {
	if c == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	out := make([][2]string, 0, len(c.URLs))
	for _, u := range c.URLs {
		out = append(out, [2]string{"http." + u + ".sslCAInfo", path})
	}
	return out
}

// Covers reports whether a request to rawURL is one git would verify against
// the bundle: the same scheme, host and port as one of the URLs, under its
// path at a "/" boundary.
func (c *GitCA) Covers(rawURL string) bool {
	if c == nil {
		return false
	}
	norm, err := NormalizeGitCAURL(rawURL)
	if err != nil {
		return false
	}
	for _, u := range c.URLs {
		if strings.HasPrefix(norm, u) {
			return true
		}
	}
	return false
}

// NormalizeGitCAURL checks one URL and renders it the way git matches
// http.<url>.* keys: scheme, host, port, and a path ending in "/" so that
// https://hub:8443/ matches every repository beneath it and nothing at
// https://hub:8443.evil.example.
func NormalizeGitCAURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("git CA url %q contains whitespace", s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("git CA url %q is not a URL: %v", s, err)
	}
	switch {
	case u.Scheme != "https":
		// http:// carries no certificate to verify.
		return "", fmt.Errorf("git CA url %q must be https", s)
	case u.Host == "" || u.Hostname() == "":
		return "", fmt.Errorf("git CA url %q has no host", s)
	case u.User != nil:
		return "", fmt.Errorf("git CA url %q must not embed credentials", s)
	case u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return "", fmt.Errorf("git CA url %q must be a base URL with no query or fragment", s)
	}
	path := u.EscapedPath()
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return "https://" + strings.ToLower(u.Host) + path, nil
}

// WithGitConfig adds pairs to the GIT_CONFIG_COUNT block in env (K=V strings),
// after any entries already there, and returns the new list.
//
// The count is one variable for the whole environment, so appending a second
// block would silently replace the first — a lease's or the review gate's —
// rather than join it. A count that does not parse is refused rather than
// overwritten: whoever set it meant something by the entries it numbers.
func WithGitConfig(env []string, pairs [][2]string) ([]string, error) {
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
					ErrInvalidSpec, v)
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

// NeedsGitCA reports whether the workload will speak to a URL the bundle
// covers: its lease rewrites GitHub to a covered proxy (CLOOP_GIT_PROXY_URL),
// its workspace is fetched from one, or its harness's model calls go to the
// hub's relay on it (Node, Task 20435). A driver that cannot deliver the
// bundle refuses exactly the workloads for which this is true.
func (s Spec) NeedsGitCA(workspaceRepo string) bool {
	if s.GitCA == nil {
		return false
	}
	if s.GitCA.Node {
		return true
	}
	if workspaceRepo != "" && s.GitCA.Covers(workspaceRepo) {
		return true
	}
	if s.Workspace.Kind == WorkspaceGit && s.GitCA.Covers(s.Workspace.Repo) {
		return true
	}
	for _, kv := range s.Env {
		if v, ok := strings.CutPrefix(kv, "CLOOP_GIT_PROXY_URL="); ok && s.GitCA.Covers(v) {
			return true
		}
	}
	return false
}
