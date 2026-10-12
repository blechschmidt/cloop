package kubeshare

// upload.go is what the dashboard says when someone uploads a kubeconfig the
// hub can never use (Task 20416).
//
// A kubeconfig whose user signs in through an exec credential plugin, or the
// older auth-provider block, works on the developer's machine and nowhere the
// hub could put it: the hub will not run the plugin, and a sandbox has neither
// the plugin nor a person to complete its sign-in. Stored anyway, it would be
// refused at every dispatch, by which time the person who uploaded it is no
// longer looking. So the upload is refused, and the refusal names the plugin
// and gives the one command that does work.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// PluginUse is one kubeconfig user that signs in through a credential plugin.
type PluginUse struct {
	User string
	// Contexts are the contexts that use the user, sorted.
	Contexts []string
	// Namespace is the first such context's default namespace, if it has one.
	Namespace string
	// Command and Args are the exec plugin's; AuthProvider the auth-provider's
	// name when that is what the user has instead.
	Command      string
	Args         []string
	AuthProvider string
}

// Plugin names the plugin for a person.
func (u PluginUse) Plugin() string {
	if u.AuthProvider != "" {
		return fmt.Sprintf("the %q auth-provider", u.AuthProvider)
	}
	return DescribePlugin(u.Command, u.Args)
}

// DescribePlugin names an exec plugin the way its users know it: the program,
// and the platform it signs in to when that is recognisable.
func DescribePlugin(command string, args []string) string {
	base := filepath.Base(strings.TrimSpace(command))
	switch {
	case base == "kubelogin":
		return "kubelogin (Microsoft Entra ID, as on AKS)"
	case base == "aws" && len(args) >= 2 && args[0] == "eks" && args[1] == "get-token":
		return "aws eks get-token (Amazon EKS)"
	case base == "aws-iam-authenticator":
		return "aws-iam-authenticator (Amazon EKS)"
	case base == "gke-gcloud-auth-plugin":
		return "gke-gcloud-auth-plugin (Google GKE)"
	case base == "kubectl" && len(args) > 0 && args[0] == "oidc-login":
		return "kubectl oidc-login (OpenID Connect)"
	case base == "kubectl-oidc_login":
		return "kubectl-oidc_login (OpenID Connect)"
	case base == "" || base == ".":
		return "an unnamed exec plugin"
	}
	return base
}

// PluginUses lists the users of raw that sign in through a credential plugin
// and are used by at least one context. A user no context names is not
// reported: it reaches nothing.
func PluginUses(raw []byte) ([]PluginUse, error) {
	var kc struct {
		Contexts []struct {
			Name    string `yaml:"name"`
			Context struct {
				User      string `yaml:"user"`
				Namespace string `yaml:"namespace"`
			} `yaml:"context"`
		} `yaml:"contexts"`
		Users []struct {
			Name string `yaml:"name"`
			User struct {
				Exec *struct {
					Command string   `yaml:"command"`
					Args    []string `yaml:"args"`
				} `yaml:"exec"`
				AuthProvider *struct {
					Name string `yaml:"name"`
				} `yaml:"auth-provider"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(raw, &kc); err != nil {
		return nil, err
	}
	var out []PluginUse
	for _, u := range kc.Users {
		if u.User.Exec == nil && u.User.AuthProvider == nil {
			continue
		}
		use := PluginUse{User: u.Name}
		if u.User.Exec != nil {
			use.Command, use.Args = u.User.Exec.Command, u.User.Exec.Args
		} else {
			use.AuthProvider = u.User.AuthProvider.Name
		}
		for _, c := range kc.Contexts {
			if c.Context.User != u.Name {
				continue
			}
			use.Contexts = append(use.Contexts, c.Name)
			if use.Namespace == "" {
				use.Namespace = strings.TrimSpace(c.Context.Namespace)
			}
		}
		if len(use.Contexts) == 0 {
			continue
		}
		sort.Strings(use.Contexts)
		out = append(out, use)
	}
	return out, nil
}

// ShareCommand is the command that shares context on hub as secret name.
// namespace is the context's default namespace, or empty for a placeholder.
func ShareCommand(name, context, namespace, hub string) string {
	ns := "<namespace>" // a placeholder, left unquoted so it reads as one
	if n := strings.TrimSpace(namespace); n != "" {
		ns = shellWord(n)
	}
	parts := []string{"cloop remote kube share", shellWord(name)}
	if hub = strings.TrimSpace(hub); hub != "" {
		parts = append(parts, "--hub", shellWord(hub))
	}
	parts = append(parts, "--context", shellWord(context), "--namespaces", ns)
	return strings.Join(parts, " ")
}

// UploadRefusal returns why an uploaded kubeconfig cannot be stored, or "" when
// it can. name is the secret name the uploader chose and hub the hub's URL, so
// the command in the message is the one to run.
func UploadRefusal(raw []byte, name, hub string) string {
	uses, err := PluginUses(raw)
	if err != nil || len(uses) == 0 {
		// A document that does not parse is the broker's to refuse, with its
		// own message; this one is only about plugins.
		return ""
	}
	first := uses[0]
	var who []string
	for _, u := range uses {
		who = append(who, fmt.Sprintf("user %q (context %s) signs in through %s",
			u.User, strings.Join(u.Contexts, ", "), u.Plugin()))
	}
	runs := "it runs the plugin there"
	if first.AuthProvider != "" {
		runs = "it signs you in there"
	}
	return fmt.Sprintf("This kubeconfig cannot be stored: %s. The hub never runs a credential plugin — it would "+
		"be running a program named in an uploaded file on the control-plane host — and a sandbox has neither "+
		"the plugin nor you to complete its sign-in. Share the cluster from your own terminal instead: %s, "+
		"creates a ServiceAccount with only the access you choose, and stores its token here — personal to you "+
		"on a hub with single sign-on:\n\n    %s\n\n(Sign the terminal in first with `cloop login`. Add "+
		"--access write for write access; see `cloop remote kube share --help`.)",
		strings.Join(who, "; "), runs, ShareCommand(name, first.Contexts[0], first.Namespace, hub))
}

// shellWord quotes s for a POSIX shell when it needs it.
func shellWord(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
