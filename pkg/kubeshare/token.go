package kubeshare

// token.go is a share's credential: what a ServiceAccount token says about
// itself, and the static kubeconfig that carries it.
//
// The claims are read without verifying the token's signature, and that is
// enough for what they are used for: deciding *when* to renew and *which*
// ServiceAccount to renew for. Neither grants anything — a renewal is a
// request the API server authenticates and authorises with the token itself,
// so a forged claim can at most produce a renewal the cluster refuses. Where
// the hub must know the token is real (one a developer pushes with `cloop
// remote kube renew`), it asks the cluster (Client.WhoAmI).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Claims is what a ServiceAccount token says about itself.
type Claims struct {
	Namespace      string
	ServiceAccount string
	UID            string
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

// Subject is the username the API server authenticates the token as.
func (c Claims) Subject() string {
	return "system:serviceaccount:" + c.Namespace + ":" + c.ServiceAccount
}

// Lifetime is how long the token was issued for.
func (c Claims) Lifetime() time.Duration { return c.ExpiresAt.Sub(c.IssuedAt) }

// ErrNotServiceAccountToken is a token that is not a bounded ServiceAccount
// token: not a JWT, not for a ServiceAccount, or without an expiry.
var ErrNotServiceAccountToken = errors.New("not a bounded ServiceAccount token")

// ParseClaims reads a token's claims. It refuses anything a share could not
// have minted: a share's token is always a JWT for a ServiceAccount, with an
// issue time and an expiry.
func ParseClaims(token string) (Claims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: it is not a JWT", ErrNotServiceAccountToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return Claims{}, fmt.Errorf("%w: its payload is not base64url", ErrNotServiceAccountToken)
	}
	var raw struct {
		Sub string `json:"sub"`
		Iat *int64 `json:"iat"`
		Exp *int64 `json:"exp"`
		K8s struct {
			Namespace      string `json:"namespace"`
			ServiceAccount struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"serviceaccount"`
		} `json:"kubernetes.io"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("%w: its payload is not JSON", ErrNotServiceAccountToken)
	}
	rest, ok := strings.CutPrefix(raw.Sub, "system:serviceaccount:")
	ns, name, ok2 := strings.Cut(rest, ":")
	if !ok || !ok2 || ns == "" || name == "" {
		return Claims{}, fmt.Errorf("%w: it authenticates as %q, not as a ServiceAccount", ErrNotServiceAccountToken, raw.Sub)
	}
	if raw.K8s.Namespace != "" && (raw.K8s.Namespace != ns || raw.K8s.ServiceAccount.Name != name) {
		return Claims{}, fmt.Errorf("%w: its subject and its kubernetes.io claims disagree", ErrNotServiceAccountToken)
	}
	if raw.Exp == nil || raw.Iat == nil {
		return Claims{}, fmt.Errorf("%w: it has no expiry (a legacy token Secret's, which never expires); "+
			"a share holds only tokens minted through the TokenRequest API", ErrNotServiceAccountToken)
	}
	c := Claims{
		Namespace: ns, ServiceAccount: name, UID: raw.K8s.ServiceAccount.UID,
		IssuedAt:  time.Unix(*raw.Iat, 0).UTC(),
		ExpiresAt: time.Unix(*raw.Exp, 0).UTC(),
	}
	if !c.ExpiresAt.After(c.IssuedAt) {
		return Claims{}, fmt.Errorf("%w: it expires before it was issued", ErrNotServiceAccountToken)
	}
	return c, nil
}

// KubeconfigParams describe the static kubeconfig a share stores.
type KubeconfigParams struct {
	// Name is the context's, the cluster's and the user's name: the share's.
	Name string
	// Server, CAData, TLSServerName, Insecure and ProxyURL describe the
	// cluster exactly as the developer's kubeconfig did.
	Server        string
	CAData        []byte
	TLSServerName string
	Insecure      bool
	ProxyURL      string
	// Namespace is the context's default namespace.
	Namespace string
	// Token is the ServiceAccount token.
	Token string
}

// The static document: exactly the inert subset the hub's parser accepts —
// server, CA, a bearer token — and nothing that could name a file or a program.
type staticKubeconfig struct {
	APIVersion     string          `yaml:"apiVersion"`
	Kind           string          `yaml:"kind"`
	CurrentContext string          `yaml:"current-context"`
	Clusters       []staticCluster `yaml:"clusters"`
	Contexts       []staticContext `yaml:"contexts"`
	Users          []staticUser    `yaml:"users"`
}

type staticCluster struct {
	Name    string `yaml:"name"`
	Cluster struct {
		Server        string `yaml:"server"`
		CAData        string `yaml:"certificate-authority-data,omitempty"`
		TLSServerName string `yaml:"tls-server-name,omitempty"`
		Insecure      bool   `yaml:"insecure-skip-tls-verify,omitempty"`
		ProxyURL      string `yaml:"proxy-url,omitempty"`
	} `yaml:"cluster"`
}

type staticContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster   string `yaml:"cluster"`
		User      string `yaml:"user"`
		Namespace string `yaml:"namespace,omitempty"`
	} `yaml:"context"`
}

type staticUser struct {
	Name string `yaml:"name"`
	User struct {
		Token string `yaml:"token"`
	} `yaml:"user"`
}

// RenderKubeconfig builds the static kubeconfig a share stores on the hub.
func RenderKubeconfig(p KubeconfigParams) ([]byte, error) {
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Server) == "" || strings.TrimSpace(p.Token) == "" {
		return nil, errors.New("kubeshare: a kubeconfig needs a name, a server and a token")
	}
	var doc staticKubeconfig
	doc.APIVersion, doc.Kind, doc.CurrentContext = "v1", "Config", p.Name
	var cl staticCluster
	cl.Name = p.Name
	cl.Cluster.Server = p.Server
	if len(p.CAData) > 0 {
		cl.Cluster.CAData = base64.StdEncoding.EncodeToString(p.CAData)
	}
	cl.Cluster.TLSServerName = p.TLSServerName
	cl.Cluster.Insecure = p.Insecure
	cl.Cluster.ProxyURL = p.ProxyURL
	var ctx staticContext
	ctx.Name = p.Name
	ctx.Context.Cluster, ctx.Context.User, ctx.Context.Namespace = p.Name, p.Name, p.Namespace
	var u staticUser
	u.Name = p.Name
	u.User.Token = p.Token
	doc.Clusters, doc.Contexts, doc.Users = []staticCluster{cl}, []staticContext{ctx}, []staticUser{u}
	return yaml.Marshal(doc)
}

// ReplaceToken returns kubeconfig with the current context's user's token set
// to token, and nothing else changed — a renewal changes the credential, never
// the cluster it is for.
func ReplaceToken(kubeconfig []byte, token string) ([]byte, error) {
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("kubeshare: refusing to write an empty or malformed token")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(kubeconfig, &root); err != nil {
		return nil, fmt.Errorf("kubeshare: the stored kubeconfig is not YAML: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("kubeshare: the stored kubeconfig is not a YAML mapping")
	}
	doc := root.Content[0]
	current := scalar(mapValue(doc, "current-context"))
	contexts := mapValue(doc, "contexts")
	if contexts == nil || contexts.Kind != yaml.SequenceNode {
		return nil, errors.New("kubeshare: the stored kubeconfig has no contexts")
	}
	if current == "" && len(contexts.Content) == 1 {
		current = scalar(mapValue(contexts.Content[0], "name"))
	}
	user := ""
	for _, c := range contexts.Content {
		if scalar(mapValue(c, "name")) == current {
			user = scalar(mapValue(mapValue(c, "context"), "user"))
		}
	}
	if user == "" {
		return nil, fmt.Errorf("kubeshare: the stored kubeconfig's context %q names no user", current)
	}
	users := mapValue(doc, "users")
	if users == nil || users.Kind != yaml.SequenceNode {
		return nil, errors.New("kubeshare: the stored kubeconfig has no users")
	}
	for _, u := range users.Content {
		if scalar(mapValue(u, "name")) != user {
			continue
		}
		body := mapValue(u, "user")
		tok := mapValue(body, "token")
		if body == nil || tok == nil || tok.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("kubeshare: the stored kubeconfig's user %q has no token to replace", user)
		}
		tok.Value, tok.Tag, tok.Style = token, "!!str", 0
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(&root); err != nil {
			return nil, fmt.Errorf("kubeshare: re-encode the kubeconfig: %w", err)
		}
		if err := enc.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return nil, fmt.Errorf("kubeshare: the stored kubeconfig defines no user %q", user)
}

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(n.Value)
}
