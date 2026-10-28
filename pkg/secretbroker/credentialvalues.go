package secretbroker

// credentialvalues.go names every credential a lease delivered, value by
// value (Task 20436).
//
// The git proxy refuses a push that carries a credential the run holds, and
// it can only match what it is given. A Material's Files are whole documents —
// a kubeconfig, a docker config.json, a credential helper script, a gitconfig —
// most of whose bytes are no secret at all and turn up in every repository
// (the helper script is the same for every lease), so the documents are taken
// apart here, by the package that wrote them, into the values inside them
// that are credentials: a kubeconfig's bearer tokens and client keys, a
// registry's auth, a proxy URL's password. Env values come as the material
// declared them sensitive (SensitiveEnv), never the constraint echoes beside
// them, which name repositories and namespaces.

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// CredentialValue is one credential a lease delivered, and where it came
// from. Value is plaintext; the rest is what a report may name instead.
type CredentialValue struct {
	Value      string
	GrantID    string
	SecretName string
	Kind       Kind
	// Field says which part of the delivery Value is: "env API_KEY", "the
	// kubeconfig's token for user ci", "the registry password for ghcr.io".
	Field string
}

// CredentialValues returns every credential the lease's materials carry, each
// value once — under the first grant that delivered it.
func (l *Lease) CredentialValues() []CredentialValue {
	if l == nil {
		return nil
	}
	var out []CredentialValue
	for _, m := range l.Materials {
		out = append(out, m.credentialValues()...)
	}
	return dedupeCredentialValues(out)
}

func dedupeCredentialValues(in []CredentialValue) []CredentialValue {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, c := range in {
		if c.Value == "" || seen[c.Value] {
			continue
		}
		seen[c.Value] = true
		out = append(out, c)
	}
	return out
}

func (m Material) credentialValues() []CredentialValue {
	var out []CredentialValue
	add := func(v, field string) {
		if v = strings.TrimSpace(v); v == "" {
			return
		}
		out = append(out, CredentialValue{Value: v, GrantID: m.GrantID, SecretName: m.SecretName, Kind: m.Kind, Field: field})
	}

	keys := append([]string(nil), m.SensitiveEnv...)
	sort.Strings(keys)
	for _, k := range keys {
		v := m.Env[k]
		add(v, "env "+k)
		// A proxy URL's password, on its own: what a person copies out of it.
		if pw := urlPassword(v); pw != "" {
			add(pw, "the password in env "+k)
		}
	}

	// The GitHub credential the hub holds whether or not the sandbox got it:
	// under the git proxy it never did, and matching it anyway is defence in
	// depth.
	if t := strings.TrimSpace(m.githubToken); t != "" {
		add(t, "the GitHub token")
	}

	for _, f := range m.Files {
		switch m.Kind {
		case KindGitHubPAT, KindGitHubApp:
			switch {
			case isLeaseFile(f.Name, tokenFileName):
				add(string(f.Content), "the GitHub token")
			case isLeaseFile(f.Name, proxyCredentialName):
				for _, line := range strings.Split(string(f.Content), "\n") {
					if pw, ok := strings.CutPrefix(line, "password="); ok {
						add(pw, "the git proxy session token")
					}
				}
			}
		case KindKubeconfig:
			if isLeaseFile(f.Name, kubeconfigFileName) {
				for _, kv := range kubeconfigCredentials(f.Content) {
					add(kv.value, kv.field)
				}
			}
		case KindRegistry:
			if f.Name == "config.json" {
				for _, kv := range registryCredentials(f.Content) {
					add(kv.value, kv.field)
				}
			}
		}
	}
	// The cluster credential behind a Kubernetes monitor session, which the
	// hub presents upstream and the sandbox never got: matched anyway, for the
	// reason the GitHub token above is.
	if m.Kind == KindKubeconfig && len(m.kubeUpstream) > 0 {
		for _, kv := range kubeconfigCredentials(m.kubeUpstream) {
			add(kv.value, kv.field)
		}
	}
	return out
}

// isLeaseFile reports whether name is base, or base with the suffix a lease
// holding several grants of one kind gives each grant's copy.
func isLeaseFile(name, base string) bool {
	return name == base || strings.HasPrefix(name, base+"-")
}

// urlPassword returns the decoded password of a URL with userinfo, or "".
func urlPassword(v string) string {
	if !strings.Contains(v, "@") || !strings.Contains(v, "://") {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.User == nil {
		return ""
	}
	pw, _ := u.User.Password()
	return pw
}

type fieldValue struct {
	field string
	value string
}

// credentialEnvName says which of an exec plugin's env variables hold a
// credential rather than a region or a profile name.
var credentialEnvName = regexp.MustCompile(`(?i)token|secret|password|passwd|key|credential`)

// kubeconfigCredentials returns the credentials in a kubeconfig's users: bearer
// tokens, client keys — as written, base64, and decoded to their PEM — basic
// auth passwords, auth-provider tokens, and the credential-named env an exec
// plugin is run with. Certificates and server addresses are not credentials.
func kubeconfigCredentials(doc []byte) []fieldValue {
	var cfg kubeConfig
	if err := yaml.Unmarshal(doc, &cfg); err != nil {
		return nil
	}
	var out []fieldValue
	for _, u := range cfg.Users {
		who := "for user " + u.Name
		str := func(m map[string]any, k string) string {
			s, _ := m[k].(string)
			return s
		}
		if t := str(u.User, "token"); t != "" {
			out = append(out, fieldValue{"the kubeconfig's token " + who, t})
		}
		if k := str(u.User, "client-key-data"); k != "" {
			out = append(out, fieldValue{"the kubeconfig's client key " + who, k})
			if pem, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k)); err == nil {
				out = append(out, fieldValue{"the kubeconfig's client key " + who, string(pem)})
			}
		}
		if p := str(u.User, "password"); p != "" {
			out = append(out, fieldValue{"the kubeconfig's password " + who, p})
		}
		if ap, ok := u.User["auth-provider"].(map[string]any); ok {
			if c, ok := ap["config"].(map[string]any); ok {
				for _, k := range []string{"access-token", "id-token", "refresh-token", "client-secret"} {
					if v := str(c, k); v != "" {
						out = append(out, fieldValue{"the kubeconfig's auth-provider " + k + " " + who, v})
					}
				}
			}
		}
		if ex, ok := u.User["exec"].(map[string]any); ok {
			if env, ok := ex["env"].([]any); ok {
				for _, e := range env {
					em, ok := e.(map[string]any)
					if !ok {
						continue
					}
					name, value := str(em, "name"), str(em, "value")
					if value != "" && credentialEnvName.MatchString(name) {
						out = append(out, fieldValue{"the kubeconfig's exec env " + name + " " + who, value})
					}
				}
			}
		}
	}
	return out
}

// registryCredentials returns the credentials in a docker config.json: each
// registry's auth as written and the password inside it, its password, and its
// identity and registry tokens.
func registryCredentials(doc []byte) []fieldValue {
	var cfg struct {
		Auths map[string]map[string]any `json:"auths"`
	}
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return nil
	}
	regs := make([]string, 0, len(cfg.Auths))
	for r := range cfg.Auths {
		regs = append(regs, r)
	}
	sort.Strings(regs)
	var out []fieldValue
	for _, r := range regs {
		a := cfg.Auths[r]
		str := func(k string) string {
			s, _ := a[k].(string)
			return s
		}
		if auth := str("auth"); auth != "" {
			out = append(out, fieldValue{"the registry auth for " + r, auth})
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth)); err == nil {
				if _, pw, ok := strings.Cut(string(raw), ":"); ok {
					out = append(out, fieldValue{"the registry password for " + r, pw})
				}
			}
		}
		for _, k := range []string{"password", "identitytoken", "registrytoken"} {
			if v := str(k); v != "" {
				out = append(out, fieldValue{"the registry " + k + " for " + r, v})
			}
		}
	}
	return out
}
