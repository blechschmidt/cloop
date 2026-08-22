package kubernetes

// kubeconfig.go turns a kubeconfig document into a RESTConfig, in memory.
//
// It is deliberately not a general kubeconfig loader. client-go's loader
// exists to make a *workstation* work: it merges files, resolves relative
// paths, runs exec credential plugins, and consults auth-provider blocks. On
// a multi-tenant control plane every one of those is a liability, because the
// document being parsed arrives from the secret broker and may have been
// supplied by a tenant:
//
//   - an `exec` block names a binary and arguments that client-go would run
//     *on the control-plane host*, as the control-plane user. That is remote
//     code execution handed over by a config file, and it is precisely the
//     thing pkg/executor exists to prevent. Rejected.
//   - `auth-provider` is the deprecated ancestor of the same idea (the gcp
//     provider shelled out to gcloud). Rejected.
//   - a file path — certificate-authority, client-certificate, client-key —
//     would make the credential depend on a file on the control-plane host.
//     A tenant could point it at a path they do not own and have the control
//     plane read it for them. Rejected: the broker delivers bytes, so
//     only the *-data forms are honoured.
//
// What survives is the small, inert subset: a server URL, a CA, and either a
// bearer token or a client certificate. Everything else is an error naming
// the offending field, so an operator learns why their kubeconfig was refused
// instead of watching it silently not work.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// RESTConfig is everything needed to talk to one API server. It holds
// credentials in memory and is never serialised to disk.
type RESTConfig struct {
	// Server is the API server base URL ("https://10.0.0.1:6443").
	Server string
	// Namespace is the context's default namespace, if it named one. The
	// executor's configured namespace takes precedence over it.
	Namespace string
	// Context is the surviving kubeconfig context name, for diagnostics.
	Context string

	// CAData is the PEM bundle that signs the API server's certificate.
	CAData []byte
	// ServerName overrides the SNI/verification hostname (tls-server-name).
	ServerName string
	// Insecure disables server certificate verification. Honoured because
	// kind/minikube clusters legitimately need it, but surfaced in
	// Describe() so it can never be an invisible downgrade.
	Insecure bool

	// BearerToken authenticates with Authorization: Bearer.
	BearerToken string
	// ClientCertData/ClientKeyData authenticate with mTLS.
	ClientCertData []byte
	ClientKeyData  []byte

	// ProxyURL routes requests through an HTTP proxy (proxy-url).
	ProxyURL string
}

// Describe returns an audit-safe one-line summary: endpoint, context,
// namespace and auth *method*, never the credential itself.
func (rc *RESTConfig) Describe() string {
	if rc == nil {
		return "(none)"
	}
	auth := "anonymous"
	switch {
	case rc.BearerToken != "":
		auth = "bearer-token"
	case len(rc.ClientCertData) > 0:
		auth = "client-cert"
	}
	s := fmt.Sprintf("server=%s context=%s namespace=%s auth=%s",
		rc.Server, orNone(rc.Context), orNone(rc.Namespace), auth)
	if rc.Insecure {
		s += " tls=INSECURE"
	}
	return s
}

// tlsConfig builds the transport TLS settings for this config.
func (rc *RESTConfig) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if rc.Insecure {
		// Explicitly requested by the kubeconfig; Describe() reports it.
		cfg.InsecureSkipVerify = true
	} else if len(rc.CAData) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(rc.CAData) {
			return nil, fmt.Errorf("kubernetes: certificate-authority-data is not a PEM certificate bundle")
		}
		cfg.RootCAs = pool
	}
	if rc.ServerName != "" {
		cfg.ServerName = rc.ServerName
	}
	if len(rc.ClientCertData) > 0 || len(rc.ClientKeyData) > 0 {
		if len(rc.ClientCertData) == 0 || len(rc.ClientKeyData) == 0 {
			return nil, fmt.Errorf("kubernetes: client-certificate-data and client-key-data must both be present")
		}
		pair, err := tls.X509KeyPair(rc.ClientCertData, rc.ClientKeyData)
		if err != nil {
			return nil, fmt.Errorf("kubernetes: client certificate is unusable: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// rawKubeconfig mirrors the subset of the kubeconfig schema this driver
// accepts. Unknown top-level keys are ignored by the YAML decoder, which is
// the desired behaviour: an extension block cannot change how we authenticate
// because nothing reads it.
type rawKubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			TLSServerName            string `yaml:"tls-server-name"`
			ProxyURL                 string `yaml:"proxy-url"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string    `yaml:"token"`
			TokenFile             string    `yaml:"tokenFile"`
			ClientCertificateData string    `yaml:"client-certificate-data"`
			ClientKeyData         string    `yaml:"client-key-data"`
			ClientCertificate     string    `yaml:"client-certificate"`
			ClientKey             string    `yaml:"client-key"`
			Exec                  yaml.Node `yaml:"exec"`
			AuthProvider          yaml.Node `yaml:"auth-provider"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// ParseKubeconfig builds a RESTConfig from a kubeconfig document.
//
// contextName selects a context; empty uses current-context, and a document
// with exactly one context is accepted without either. The broker's
// MinimizeKubeconfig has usually already reduced the document to the contexts
// a grant permits, so in practice this picks from a very short list.
func ParseKubeconfig(raw []byte, contextName string) (*RESTConfig, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("kubernetes: kubeconfig is empty")
	}
	var kc rawKubeconfig
	if err := yaml.Unmarshal(raw, &kc); err != nil {
		return nil, fmt.Errorf("kubernetes: kubeconfig is not valid YAML: %w", err)
	}
	if len(kc.Contexts) == 0 {
		return nil, fmt.Errorf("kubernetes: kubeconfig declares no contexts")
	}

	want := strings.TrimSpace(contextName)
	if want == "" {
		want = strings.TrimSpace(kc.CurrentContext)
	}
	if want == "" && len(kc.Contexts) == 1 {
		want = kc.Contexts[0].Name
	}
	if want == "" {
		return nil, fmt.Errorf("kubernetes: kubeconfig has %d contexts and no current-context; "+
			"set executors.kubernetes.context to choose one", len(kc.Contexts))
	}

	idx := -1
	for i, c := range kc.Contexts {
		if c.Name == want {
			idx = i
			break
		}
	}
	if idx < 0 {
		names := make([]string, 0, len(kc.Contexts))
		for _, c := range kc.Contexts {
			names = append(names, c.Name)
		}
		return nil, fmt.Errorf("kubernetes: kubeconfig has no context %q (available: %s)",
			want, strings.Join(names, ", "))
	}
	kctx := kc.Contexts[idx].Context

	out := &RESTConfig{
		Context:   want,
		Namespace: strings.TrimSpace(kctx.Namespace),
	}

	// --- cluster ---------------------------------------------------------
	found := false
	for _, cl := range kc.Clusters {
		if cl.Name != kctx.Cluster {
			continue
		}
		found = true
		if strings.TrimSpace(cl.Cluster.CertificateAuthority) != "" {
			return nil, fmt.Errorf("kubernetes: cluster %q uses certificate-authority (a file path on the "+
				"control-plane host); use certificate-authority-data so the CA travels with the brokered secret",
				cl.Name)
		}
		out.Server = strings.TrimRight(strings.TrimSpace(cl.Cluster.Server), "/")
		out.Insecure = cl.Cluster.InsecureSkipTLSVerify
		out.ServerName = strings.TrimSpace(cl.Cluster.TLSServerName)
		out.ProxyURL = strings.TrimSpace(cl.Cluster.ProxyURL)
		if data := strings.TrimSpace(cl.Cluster.CertificateAuthorityData); data != "" {
			decoded, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return nil, fmt.Errorf("kubernetes: cluster %q certificate-authority-data is not base64: %w", cl.Name, err)
			}
			out.CAData = decoded
		}
		break
	}
	if !found {
		return nil, fmt.Errorf("kubernetes: context %q references cluster %q which the kubeconfig does not define",
			want, kctx.Cluster)
	}
	if out.Server == "" {
		return nil, fmt.Errorf("kubernetes: cluster %q has no server URL", kctx.Cluster)
	}
	if err := validateServerURL(out.Server); err != nil {
		return nil, err
	}
	if out.ProxyURL != "" {
		if _, err := url.Parse(out.ProxyURL); err != nil {
			return nil, fmt.Errorf("kubernetes: cluster %q proxy-url is not a URL: %w", kctx.Cluster, err)
		}
	}

	// --- user ------------------------------------------------------------
	// A context with no user is anonymous, which some clusters genuinely
	// allow; it is not an error here, it just fails at the API with 401.
	for _, u := range kc.Users {
		if u.Name != kctx.User {
			continue
		}
		if !u.User.Exec.IsZero() {
			return nil, fmt.Errorf("kubernetes: user %q uses an exec credential plugin. cloop refuses it: "+
				"running that binary would execute tenant-controlled code on the control-plane host, which is "+
				"exactly what isolated executors exist to prevent. Mint a ServiceAccount token instead "+
				"(kubectl create token <sa> --duration=...)", u.Name)
		}
		if !u.User.AuthProvider.IsZero() {
			return nil, fmt.Errorf("kubernetes: user %q uses an auth-provider block, which shells out on the "+
				"control-plane host. Mint a ServiceAccount token instead", u.Name)
		}
		if strings.TrimSpace(u.User.TokenFile) != "" {
			return nil, fmt.Errorf("kubernetes: user %q uses tokenFile (a path on the control-plane host); "+
				"inline the token so it travels with the brokered secret", u.Name)
		}
		if strings.TrimSpace(u.User.ClientCertificate) != "" || strings.TrimSpace(u.User.ClientKey) != "" {
			return nil, fmt.Errorf("kubernetes: user %q uses client-certificate/client-key file paths; "+
				"use the -data forms so the credential travels with the brokered secret", u.Name)
		}
		out.BearerToken = strings.TrimSpace(u.User.Token)
		var err error
		if out.ClientCertData, err = decodeOptionalB64(u.User.ClientCertificateData,
			"user "+u.Name+" client-certificate-data"); err != nil {
			return nil, err
		}
		if out.ClientKeyData, err = decodeOptionalB64(u.User.ClientKeyData,
			"user "+u.Name+" client-key-data"); err != nil {
			return nil, err
		}
		break
	}

	// Fail here rather than at the first API call: a TLS pair that does not
	// load is a configuration error, and discovering it at Start would look
	// like a cluster outage.
	if _, err := out.tlsConfig(); err != nil {
		return nil, err
	}
	return out, nil
}

// validateServerURL rejects endpoints the driver cannot safely use. A plain
// http:// endpoint would send the bearer token in clear text, which is worth
// refusing even on a trusted network — a kubeconfig is portable and the
// operator who wrote it is rarely the one running it.
func validateServerURL(server string) error {
	u, err := url.Parse(server)
	if err != nil {
		return fmt.Errorf("kubernetes: server %q is not a URL: %w", server, err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		return fmt.Errorf("kubernetes: server %q uses http://; the bearer token would cross the network "+
			"in clear text. Use https://", server)
	default:
		return fmt.Errorf("kubernetes: server %q must be an https:// URL (got scheme %q)", server, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("kubernetes: server %q has no host", server)
	}
	return nil
}

func decodeOptionalB64(s, field string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %s is not base64: %w", field, err)
	}
	return decoded, nil
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(unset)"
	}
	return s
}
