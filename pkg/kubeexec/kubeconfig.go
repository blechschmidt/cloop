package kubeexec

// kubeconfig.go reads a workstation kubeconfig the way kubectl does — the
// mirror image of pkg/executor/kubernetes.ParseKubeconfig, which reads a
// kubeconfig the hub was handed and refuses most of what this file honours.
//
// On the hub those refusals are right: a certificate-authority path names a
// file on the control-plane host, a tokenFile reads one, and an exec block runs
// a program, all on behalf of whoever uploaded the document. On the developer's
// own machine every one of them is wrong. The paths name the developer's files,
// the plugin is one they installed, and the document is the one kubectl
// already uses for them. So here they are all honoured, and nothing this file
// produces is ever sent to the hub except the static kubeconfig
// `cloop remote kube share` builds from a freshly minted ServiceAccount token.
//
// Several files merge the way client-go merges $KUBECONFIG: the first file to
// define a cluster, user or context by a name wins, and current-context comes
// from the first file that sets one. Relative paths resolve against the
// directory of the file that named them.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// maxKubeconfigBytes bounds one kubeconfig file. A real one with a dozen
// clusters and their CAs is tens of kilobytes.
const maxKubeconfigBytes = 8 << 20

// rawConfig is the schema subset a workstation kubeconfig is read through.
type rawConfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string     `yaml:"name"`
		Cluster rawCluster `yaml:"cluster"`
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
		Name string  `yaml:"name"`
		User rawUser `yaml:"user"`
	} `yaml:"users"`
}

type rawCluster struct {
	Server                   string `yaml:"server"`
	CertificateAuthority     string `yaml:"certificate-authority"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
	TLSServerName            string `yaml:"tls-server-name"`
	ProxyURL                 string `yaml:"proxy-url"`
	DisableCompression       bool   `yaml:"disable-compression"`
	Extensions               []struct {
		Name      string    `yaml:"name"`
		Extension yaml.Node `yaml:"extension"`
	} `yaml:"extensions"`
}

type rawUser struct {
	Token                 string   `yaml:"token"`
	TokenFile             string   `yaml:"tokenFile"`
	ClientCertificate     string   `yaml:"client-certificate"`
	ClientCertificateData string   `yaml:"client-certificate-data"`
	ClientKey             string   `yaml:"client-key"`
	ClientKeyData         string   `yaml:"client-key-data"`
	Username              string   `yaml:"username"`
	Password              string   `yaml:"password"`
	As                    string   `yaml:"as"`
	AsGroups              []string `yaml:"as-groups"`
	AsUID                 string   `yaml:"as-uid"`
	AuthProvider          *struct {
		Name string `yaml:"name"`
	} `yaml:"auth-provider"`
	Exec *struct {
		APIVersion         string   `yaml:"apiVersion"`
		Command            string   `yaml:"command"`
		Args               []string `yaml:"args"`
		Env                []EnvVar `yaml:"env"`
		InstallHint        string   `yaml:"installHint"`
		ProvideClusterInfo bool     `yaml:"provideClusterInfo"`
		InteractiveMode    string   `yaml:"interactiveMode"`
	} `yaml:"exec"`
}

// sourced remembers which file an entry came from, for path resolution and for
// messages.
type sourcedCluster struct {
	rawCluster
	file string
}

type sourcedUser struct {
	rawUser
	file string
}

type sourcedContext struct {
	cluster, user, namespace string
	file                     string
}

// Kubeconfig is several workstation kubeconfig files, merged.
type Kubeconfig struct {
	// CurrentContext is the merged current-context.
	CurrentContext string
	// Files are the files read, in order.
	Files []string

	clusters map[string]sourcedCluster
	users    map[string]sourcedUser
	contexts map[string]sourcedContext
}

// DefaultPaths returns the files kubectl would read: $KUBECONFIG's list when
// it is set, otherwise ~/.kube/config.
func DefaultPaths() []string {
	if env := strings.TrimSpace(os.Getenv("KUBECONFIG")); env != "" {
		var out []string
		for _, p := range filepath.SplitList(env) {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	return []string{filepath.Join(home, ".kube", "config")}
}

// Load reads and merges paths. A file in a $KUBECONFIG list that does not
// exist is skipped, as kubectl skips it; when none exists the error says
// which were tried.
func Load(paths []string) (*Kubeconfig, error) {
	k := &Kubeconfig{
		clusters: map[string]sourcedCluster{},
		users:    map[string]sourcedUser{},
		contexts: map[string]sourcedContext{},
	}
	var missing []string
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		raw, err := readBounded(abs)
		if errors.Is(err, os.ErrNotExist) {
			missing = append(missing, abs)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read kubeconfig %s: %w", abs, err)
		}
		var rc rawConfig
		if err := yaml.Unmarshal(raw, &rc); err != nil {
			return nil, fmt.Errorf("kubeconfig %s is not valid YAML: %w", abs, err)
		}
		k.Files = append(k.Files, abs)
		if k.CurrentContext == "" {
			k.CurrentContext = strings.TrimSpace(rc.CurrentContext)
		}
		for _, c := range rc.Clusters {
			if _, seen := k.clusters[c.Name]; !seen && c.Name != "" {
				k.clusters[c.Name] = sourcedCluster{rawCluster: c.Cluster, file: abs}
			}
		}
		for _, u := range rc.Users {
			if _, seen := k.users[u.Name]; !seen && u.Name != "" {
				k.users[u.Name] = sourcedUser{rawUser: u.User, file: abs}
			}
		}
		for _, c := range rc.Contexts {
			if _, seen := k.contexts[c.Name]; !seen && c.Name != "" {
				k.contexts[c.Name] = sourcedContext{
					cluster: c.Context.Cluster, user: c.Context.User,
					namespace: c.Context.Namespace, file: abs,
				}
			}
		}
	}
	if len(k.Files) == 0 {
		if len(missing) == 0 {
			return nil, errors.New("no kubeconfig to read: set KUBECONFIG or pass --kubeconfig")
		}
		return nil, fmt.Errorf("no kubeconfig found (tried %s); pass --kubeconfig", strings.Join(missing, ", "))
	}
	return k, nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxKubeconfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxKubeconfigBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes, more than a kubeconfig plausibly is",
			path, maxKubeconfigBytes)
	}
	return raw, nil
}

// ContextNames lists the contexts, sorted.
func (k *Kubeconfig) ContextNames() []string {
	out := make([]string, 0, len(k.contexts))
	for n := range k.contexts {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Context is one resolved context: where the cluster is, how it is trusted,
// and how its user authenticates.
type Context struct {
	Name      string
	Namespace string
	Cluster   string
	User      string

	Server                string
	CAData                []byte
	TLSServerName         string
	InsecureSkipTLSVerify bool
	ProxyURL              string
	DisableCompression    bool
	// ExecExtension is the cluster's client.authentication.k8s.io/exec
	// extension as JSON, handed to a provideClusterInfo plugin.
	ExecExtension json.RawMessage

	// Exactly one of the three is set on a context with a credential.
	token          string
	clientCertData []byte
	clientKeyData  []byte
	exec           *Config
}

// Plugin reports the exec plugin the context's user runs, or nil.
func (c *Context) Plugin() *Config {
	if c == nil || c.exec == nil {
		return nil
	}
	cp := *c.exec
	return &cp
}

// Context resolves name, or the current context when name is empty.
func (k *Kubeconfig) Context(name string) (*Context, error) {
	want := strings.TrimSpace(name)
	if want == "" {
		want = k.CurrentContext
	}
	if want == "" {
		if len(k.contexts) == 1 {
			for n := range k.contexts {
				want = n
			}
		} else {
			return nil, fmt.Errorf("the kubeconfig sets no current-context; name one with --context (have: %s)",
				strings.Join(k.ContextNames(), ", "))
		}
	}
	kc, ok := k.contexts[want]
	if !ok {
		return nil, fmt.Errorf("the kubeconfig has no context %q (have: %s)", want, strings.Join(k.ContextNames(), ", "))
	}
	cl, ok := k.clusters[kc.cluster]
	if !ok {
		return nil, fmt.Errorf("context %q names cluster %q, which no kubeconfig file defines", want, kc.cluster)
	}
	out := &Context{
		Name: want, Namespace: strings.TrimSpace(kc.namespace),
		Cluster: kc.cluster, User: kc.user,
		Server:                strings.TrimRight(strings.TrimSpace(cl.Server), "/"),
		TLSServerName:         strings.TrimSpace(cl.TLSServerName),
		InsecureSkipTLSVerify: cl.InsecureSkipTLSVerify,
		ProxyURL:              strings.TrimSpace(cl.ProxyURL),
		DisableCompression:    cl.DisableCompression,
	}
	if out.Server == "" {
		return nil, fmt.Errorf("cluster %q has no server URL", kc.cluster)
	}
	u, err := url.Parse(out.Server)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("cluster %q's server %q is not a URL", kc.cluster, out.Server)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("cluster %q's server %s is not https://; the hub refuses an API server that "+
			"would receive a bearer token in clear text", kc.cluster, out.Server)
	}
	if data := strings.TrimSpace(cl.CertificateAuthorityData); data != "" {
		if out.CAData, err = decodeB64(data, "cluster "+kc.cluster+" certificate-authority-data"); err != nil {
			return nil, err
		}
	} else if path := strings.TrimSpace(cl.CertificateAuthority); path != "" {
		if out.CAData, err = readFileRelative(cl.file, path, "cluster "+kc.cluster+" certificate-authority"); err != nil {
			return nil, err
		}
	}
	for _, ext := range cl.Extensions {
		if ext.Name != ClusterExtensionName || ext.Extension.IsZero() {
			continue
		}
		var v any
		if err := ext.Extension.Decode(&v); err != nil {
			return nil, fmt.Errorf("cluster %q's %s extension: %w", kc.cluster, ClusterExtensionName, err)
		}
		if out.ExecExtension, err = json.Marshal(normalizeYAML(v)); err != nil {
			return nil, fmt.Errorf("cluster %q's %s extension is not representable as JSON: %w",
				kc.cluster, ClusterExtensionName, err)
		}
	}

	if kc.user == "" {
		return nil, fmt.Errorf("context %q names no user, so it has no credential to create anything with", want)
	}
	usr, ok := k.users[kc.user]
	if !ok {
		return nil, fmt.Errorf("context %q names user %q, which no kubeconfig file defines", want, kc.user)
	}
	if err := out.resolveUser(kc.user, usr); err != nil {
		return nil, err
	}
	return out, nil
}

// resolveUser fills the credential fields from a user entry.
func (c *Context) resolveUser(name string, u sourcedUser) error {
	switch {
	case u.AuthProvider != nil:
		return fmt.Errorf("user %q authenticates through the %q auth-provider, which kubectl itself no longer "+
			"supports; convert the kubeconfig to its exec plugin (for GKE, gke-gcloud-auth-plugin; for AKS, "+
			"`kubelogin convert-kubeconfig`) and retry", name, u.AuthProvider.Name)
	case u.As != "" || len(u.AsGroups) > 0 || u.AsUID != "":
		return fmt.Errorf("user %q impersonates another identity (as:); cloop remote kube share creates "+
			"objects as the credential itself, so use a context that authenticates as you directly", name)
	case u.Username != "" || u.Password != "":
		return fmt.Errorf("user %q uses basic authentication, which Kubernetes removed in 1.19", name)
	}
	var err error
	switch {
	case u.Exec != nil:
		dir := ""
		if u.file != "" {
			dir = filepath.Dir(u.file)
		}
		c.exec = &Config{
			APIVersion:         u.Exec.APIVersion,
			Command:            u.Exec.Command,
			Args:               append([]string(nil), u.Exec.Args...),
			Env:                append([]EnvVar(nil), u.Exec.Env...),
			InstallHint:        u.Exec.InstallHint,
			ProvideClusterInfo: u.Exec.ProvideClusterInfo,
			InteractiveMode:    InteractiveMode(u.Exec.InteractiveMode),
			Dir:                dir,
		}
		return c.exec.Validate()
	case strings.TrimSpace(u.Token) != "":
		c.token = strings.TrimSpace(u.Token)
	case strings.TrimSpace(u.TokenFile) != "":
		raw, ferr := readFileRelative(u.file, u.TokenFile, "user "+name+" tokenFile")
		if ferr != nil {
			return ferr
		}
		c.token = strings.TrimSpace(string(raw))
		if c.token == "" {
			return fmt.Errorf("user %q's tokenFile is empty", name)
		}
	}
	if u.ClientCertificateData != "" {
		if c.clientCertData, err = decodeB64(u.ClientCertificateData, "user "+name+" client-certificate-data"); err != nil {
			return err
		}
	} else if u.ClientCertificate != "" {
		if c.clientCertData, err = readFileRelative(u.file, u.ClientCertificate, "user "+name+" client-certificate"); err != nil {
			return err
		}
	}
	if u.ClientKeyData != "" {
		if c.clientKeyData, err = decodeB64(u.ClientKeyData, "user "+name+" client-key-data"); err != nil {
			return err
		}
	} else if u.ClientKey != "" {
		if c.clientKeyData, err = readFileRelative(u.file, u.ClientKey, "user "+name+" client-key"); err != nil {
			return err
		}
	}
	if (len(c.clientCertData) > 0) != (len(c.clientKeyData) > 0) {
		return fmt.Errorf("user %q has a client certificate without its key, or a key without its certificate", name)
	}
	if c.token == "" && len(c.clientCertData) == 0 {
		return fmt.Errorf("user %q has no credential cloop can use (no token, client certificate or exec plugin)", name)
	}
	return nil
}

// RESTConfig returns a config for the context with a working credential: the
// token or certificate as written, or the one its exec plugin prints when run
// now, on this machine.
func (c *Context) RESTConfig(ctx context.Context, opts Options) (*kubernetes.RESTConfig, *Credential, error) {
	rc := &kubernetes.RESTConfig{
		Server:     c.Server,
		Namespace:  c.Namespace,
		Context:    c.Name,
		CAData:     append([]byte(nil), c.CAData...),
		ServerName: c.TLSServerName,
		Insecure:   c.InsecureSkipTLSVerify,
		ProxyURL:   c.ProxyURL,
	}
	if c.exec == nil {
		rc.BearerToken = c.token
		rc.ClientCertData = append([]byte(nil), c.clientCertData...)
		rc.ClientKeyData = append([]byte(nil), c.clientKeyData...)
		return rc, nil, nil
	}
	cred, err := Run(ctx, *c.exec, &Cluster{
		Server:                   c.Server,
		TLSServerName:            c.TLSServerName,
		InsecureSkipTLSVerify:    c.InsecureSkipTLSVerify,
		CertificateAuthorityData: c.CAData,
		ProxyURL:                 c.ProxyURL,
		DisableCompression:       c.DisableCompression,
		Config:                   c.ExecExtension,
	}, opts)
	if err != nil {
		return nil, nil, err
	}
	rc.BearerToken = cred.Token
	rc.ClientCertData = cred.ClientCertificateData
	rc.ClientKeyData = cred.ClientKeyData
	return rc, cred, nil
}

// readFileRelative reads a path a kubeconfig named, relative to its file.
func readFileRelative(kubeconfigFile, path, field string) ([]byte, error) {
	p := strings.TrimSpace(path)
	if !filepath.IsAbs(p) && kubeconfigFile != "" {
		p = filepath.Join(filepath.Dir(kubeconfigFile), p)
	}
	raw, err := readBounded(p)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return raw, nil
}

// normalizeYAML turns yaml.v3's decoded maps into JSON-marshalable ones.
// yaml.v3 decodes a mapping into map[string]any already, but a mapping with a
// non-string key decodes into map[any]any, which encoding/json refuses.
func normalizeYAML(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = normalizeYAML(x)
		}
		return t
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[fmt.Sprint(k)] = normalizeYAML(x)
		}
		return out
	case []any:
		for i, x := range t {
			t[i] = normalizeYAML(x)
		}
		return t
	}
	return v
}
