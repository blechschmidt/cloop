package secretbroker

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// threeContextKubeconfig gives every context its own cluster and its own
// user. That separation is what makes the pruning assertions meaningful: if
// dropping the "staging" context leaves staging-cluster or staging-user in
// the document, the executor still holds a credential for a cluster the grant
// never authorised.
//
// It also carries two top-level keys the typed round-trip does not model
// (preferences, injected-field), so the "unknown keys are stripped" property
// has something to strip.
const threeContextKubeconfig = `
apiVersion: v1
kind: Config
current-context: prod
preferences: {}
injected-field: danger
clusters:
  - name: prod-cluster
    cluster:
      server: https://prod.example.test
      certificate-authority-data: cHJvZC1jYQ==
  - name: staging-cluster
    cluster:
      server: https://staging.example.test
      certificate-authority-data: c3RhZ2luZy1jYQ==
  - name: dev-cluster
    cluster:
      server: https://dev.example.test
contexts:
  - name: prod
    context:
      cluster: prod-cluster
      user: prod-user
      namespace: default
  - name: staging
    context:
      cluster: staging-cluster
      user: staging-user
      namespace: staging-ns
  - name: dev
    context:
      cluster: dev-cluster
      user: dev-user
      namespace: dev-ns
users:
  - name: prod-user
    user:
      token: prod-secret-token
  - name: staging-user
    user:
      token: staging-secret-token
  - name: dev-user
    user:
      token: dev-secret-token
`

// twoNamespaceKubeconfig has one context already inside a "team-*" allowlist
// and one that is not, so a glob-only allowlist can be seen to keep the first
// and drop the second.
const twoNamespaceKubeconfig = `
apiVersion: v1
kind: Config
current-context: inside
clusters:
  - name: c-inside
    cluster:
      server: https://inside.example.test
  - name: c-outside
    cluster:
      server: https://outside.example.test
contexts:
  - name: inside
    context:
      cluster: c-inside
      user: u-inside
      namespace: team-a
  - name: outside
    context:
      cluster: c-outside
      user: u-outside
      namespace: default
users:
  - name: u-inside
    user:
      token: inside-secret-token
  - name: u-outside
    user:
      token: outside-secret-token
`

// singleDefaultKubeconfig is the minimal shape: one context sitting in
// "default". It also omits apiVersion/kind so the defaulting is exercised.
const singleDefaultKubeconfig = `
current-context: only
clusters:
  - name: c1
    cluster:
      server: https://c1.example.test
contexts:
  - name: only
    context:
      cluster: c1
      user: u1
      namespace: default
users:
  - name: u1
    user:
      token: only-secret-token
`

func parseKube(t *testing.T, data []byte) kubeConfig {
	t.Helper()
	var cfg kubeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("minimized kubeconfig is not valid YAML: %v\n%s", err, data)
	}
	return cfg
}

func parseKubeMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatalf("minimized kubeconfig is not valid YAML: %v\n%s", err, data)
	}
	return m
}

func kubeContextNames(cfg kubeConfig) []string {
	out := make([]string, 0, len(cfg.Contexts))
	for _, c := range cfg.Contexts {
		out = append(out, c.Name)
	}
	return out
}

func kubeClusterNames(cfg kubeConfig) []string {
	out := make([]string, 0, len(cfg.Clusters))
	for _, c := range cfg.Clusters {
		out = append(out, c.Name)
	}
	return out
}

func kubeUserNames(cfg kubeConfig) []string {
	out := make([]string, 0, len(cfg.Users))
	for _, u := range cfg.Users {
		out = append(out, u.Name)
	}
	return out
}

func kubeNamespaceOf(t *testing.T, cfg kubeConfig, ctxName string) string {
	t.Helper()
	for _, c := range cfg.Contexts {
		if c.Name == ctxName {
			return c.Context.Namespace
		}
	}
	t.Fatalf("context %q is not present in %v", ctxName, kubeContextNames(cfg))
	return ""
}

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

// TestMinimizeKubeconfigContextAllowlist: only the allowlisted context
// survives.
func TestMinimizeKubeconfigContextAllowlist(t *testing.T) {
	out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), Constraints{
		Contexts:   []string{"prod"},
		Namespaces: []string{"team-a"},
	})
	if err != nil {
		t.Fatalf("MinimizeKubeconfig: %v", err)
	}
	cfg := parseKube(t, out)
	if got := kubeContextNames(cfg); len(got) != 1 || got[0] != "prod" {
		t.Fatalf("contexts = %v, want exactly [prod]", got)
	}
	if cfg.APIVersion != "v1" || cfg.Kind != "Config" {
		t.Errorf("envelope = %q/%q, want v1/Config", cfg.APIVersion, cfg.Kind)
	}
}

// TestMinimizeKubeconfigPrunesUnreferencedCredentials is the core security
// property of this file. Minimization is subtractive: the delivered document
// must not merely fail to *mention* the staging cluster, it must not contain
// staging's certificate or token at all. A workload that never receives a
// credential cannot use it, whatever it intends; a workload handed the full
// kubeconfig plus a policy note is only asked not to.
func TestMinimizeKubeconfigPrunesUnreferencedCredentials(t *testing.T) {
	out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), Constraints{
		Contexts:   []string{"prod"},
		Namespaces: []string{"team-a"},
	})
	if err != nil {
		t.Fatalf("MinimizeKubeconfig: %v", err)
	}
	cfg := parseKube(t, out)

	if got := kubeClusterNames(cfg); len(got) != 1 || got[0] != "prod-cluster" {
		t.Errorf("clusters = %v, want exactly [prod-cluster]", got)
	}
	if got := kubeUserNames(cfg); len(got) != 1 || got[0] != "prod-user" {
		t.Errorf("users = %v, want exactly [prod-user]", got)
	}

	// The material itself, not just the names: a token that survives inside
	// some field we did not think to inspect is still a live credential.
	for _, secret := range []string{
		"staging-secret-token",
		"dev-secret-token",
		"c3RhZ2luZy1jYQ==",             // staging CA data
		"https://staging.example.test", // staging endpoint
		"https://dev.example.test",
	} {
		if bytes.Contains(out, []byte(secret)) {
			t.Errorf("minimized kubeconfig still contains dropped material %q:\n%s", secret, out)
		}
	}

	// The surviving context's own material must of course still be there,
	// otherwise "minimized" would just mean "broken".
	if !bytes.Contains(out, []byte("prod-secret-token")) {
		t.Errorf("minimized kubeconfig lost the surviving user's token:\n%s", out)
	}
}

// TestMinimizeKubeconfigStripsUnknownTopLevelKeys: the typed round-trip is
// what discards kubeconfig keys we do not model, so nothing an operator (or a
// tampered store) added at the top level rides along into a delivered
// credential.
func TestMinimizeKubeconfigStripsUnknownTopLevelKeys(t *testing.T) {
	out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), Constraints{
		Contexts:   []string{"prod"},
		Namespaces: []string{"team-a"},
	})
	if err != nil {
		t.Fatalf("MinimizeKubeconfig: %v", err)
	}
	m := parseKubeMap(t, out)
	for _, key := range []string{"injected-field", "preferences"} {
		if _, ok := m[key]; ok {
			t.Errorf("top-level key %q survived minimization: %v", key, m)
		}
	}
	if bytes.Contains(out, []byte("danger")) {
		t.Errorf("injected value survived minimization:\n%s", out)
	}
	// Only the keys the type models may appear.
	for key := range m {
		switch key {
		case "apiVersion", "kind", "current-context", "clusters", "contexts", "users":
		default:
			t.Errorf("unexpected top-level key %q in minimized kubeconfig", key)
		}
	}
}

// TestMinimizeKubeconfigDefaultsEnvelope: a payload missing apiVersion/kind
// still has to come back as a document kubectl will load, otherwise the
// minimization would hand back something that reads as a broken credential
// rather than a narrowed one.
func TestMinimizeKubeconfigDefaultsEnvelope(t *testing.T) {
	out, err := MinimizeKubeconfig([]byte(singleDefaultKubeconfig), Constraints{
		Namespaces: []string{"default"},
	})
	if err != nil {
		t.Fatalf("MinimizeKubeconfig: %v", err)
	}
	cfg := parseKube(t, out)
	if cfg.APIVersion != "v1" {
		t.Errorf("apiVersion = %q, want v1", cfg.APIVersion)
	}
	if cfg.Kind != "Config" {
		t.Errorf("kind = %q, want Config", cfg.Kind)
	}
	if cfg.CurrentContext != "only" {
		t.Errorf("current-context = %q, want only", cfg.CurrentContext)
	}
}

// TestMinimizeKubeconfigNamespacePinning covers the three namespace outcomes:
// pin, leave alone, and drop.
func TestMinimizeKubeconfigNamespacePinning(t *testing.T) {
	t.Run("pins a disallowed namespace to the first concrete allowed one", func(t *testing.T) {
		out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), Constraints{
			Contexts:   []string{"prod"},
			Namespaces: []string{"team-a"},
		})
		if err != nil {
			t.Fatalf("MinimizeKubeconfig: %v", err)
		}
		cfg := parseKube(t, out)
		if ns := kubeNamespaceOf(t, cfg, "prod"); ns != "team-a" {
			t.Errorf("namespace = %q, want team-a (pinned away from default)", ns)
		}
	})

	t.Run("leaves an already-allowed namespace alone", func(t *testing.T) {
		// team-b is listed first deliberately: if the code pinned
		// unconditionally the result would be team-b, so seeing team-a proves
		// the "already inside the allowlist" branch ran.
		out, err := MinimizeKubeconfig([]byte(twoNamespaceKubeconfig), Constraints{
			Contexts:   []string{"inside"},
			Namespaces: []string{"team-b", "team-a"},
		})
		if err != nil {
			t.Fatalf("MinimizeKubeconfig: %v", err)
		}
		cfg := parseKube(t, out)
		if ns := kubeNamespaceOf(t, cfg, "inside"); ns != "team-a" {
			t.Errorf("namespace = %q, want team-a left untouched", ns)
		}
	})

	t.Run("glob-only allowlist drops a non-matching context", func(t *testing.T) {
		// There is no concrete namespace to substitute, and guessing which of
		// the team-* namespaces the operator meant would be inventing
		// authority. Dropping is the only defensible outcome.
		out, err := MinimizeKubeconfig([]byte(twoNamespaceKubeconfig), Constraints{
			Namespaces: []string{"team-*"},
		})
		if err != nil {
			t.Fatalf("MinimizeKubeconfig: %v", err)
		}
		cfg := parseKube(t, out)
		if got := kubeContextNames(cfg); len(got) != 1 || got[0] != "inside" {
			t.Fatalf("contexts = %v, want exactly [inside]", got)
		}
		if ns := kubeNamespaceOf(t, cfg, "inside"); ns != "team-a" {
			t.Errorf("namespace = %q, want team-a", ns)
		}
		if bytes.Contains(out, []byte("outside-secret-token")) {
			t.Errorf("dropped context's credential survived:\n%s", out)
		}
	})

	t.Run("glob-only allowlist with no match at all is a denial", func(t *testing.T) {
		_, err := MinimizeKubeconfig([]byte(singleDefaultKubeconfig), Constraints{
			Namespaces: []string{"team-*"},
		})
		if !errors.Is(err, ErrMinimizedEmpty) {
			t.Fatalf("err = %v, want ErrMinimizedEmpty", err)
		}
	})

	t.Run("no namespace allowlist leaves namespaces untouched", func(t *testing.T) {
		out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), Constraints{
			Contexts: []string{"prod"},
		})
		if err != nil {
			t.Fatalf("MinimizeKubeconfig: %v", err)
		}
		cfg := parseKube(t, out)
		if ns := kubeNamespaceOf(t, cfg, "prod"); ns != "default" {
			t.Errorf("namespace = %q, want default (unchanged)", ns)
		}
	})
}

// TestMinimizeKubeconfigCurrentContext: a current-context naming a dropped
// context would make kubectl fail confusingly, so it is repointed — but never
// away from a context that is still valid.
func TestMinimizeKubeconfigCurrentContext(t *testing.T) {
	t.Run("repointed when the original was dropped", func(t *testing.T) {
		out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), Constraints{
			Contexts: []string{"staging", "dev"},
		})
		if err != nil {
			t.Fatalf("MinimizeKubeconfig: %v", err)
		}
		cfg := parseKube(t, out)
		names := kubeContextNames(cfg)
		if cfg.CurrentContext == "prod" {
			t.Fatalf("current-context still names the dropped context %q", cfg.CurrentContext)
		}
		if !containsString(names, cfg.CurrentContext) {
			t.Errorf("current-context = %q, want one of the surviving contexts %v",
				cfg.CurrentContext, names)
		}
	})

	t.Run("preserved when the original survived", func(t *testing.T) {
		out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), Constraints{
			Contexts: []string{"prod", "staging"},
		})
		if err != nil {
			t.Fatalf("MinimizeKubeconfig: %v", err)
		}
		cfg := parseKube(t, out)
		if cfg.CurrentContext != "prod" {
			t.Errorf("current-context = %q, want prod preserved", cfg.CurrentContext)
		}
	})
}

// TestMinimizeKubeconfigEmptyResultIsDenial: an empty kubeconfig would look
// like a working credential that mysteriously reaches nothing, so nothing
// surviving must be an error instead.
func TestMinimizeKubeconfigEmptyResultIsDenial(t *testing.T) {
	tests := []struct {
		name string
		c    Constraints
	}{
		{"no context matches the allowlist", Constraints{Contexts: []string{"nonexistent"}}},
		{"context allowlist matches nothing with namespaces set", Constraints{
			Contexts:   []string{"qa-*"},
			Namespaces: []string{"team-a"},
		}},
		{"empty constraints deny every context", Constraints{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), tc.c)
			if !errors.Is(err, ErrMinimizedEmpty) {
				t.Fatalf("err = %v, want ErrMinimizedEmpty", err)
			}
			if out != nil {
				t.Errorf("a denial must not also return a document, got %d bytes", len(out))
			}
		})
	}
}

// TestMinimizeKubeconfigMalformedPayload: a payload that is not a kubeconfig
// is rejected as malformed rather than silently minimized to nothing, so the
// operator learns which of the two problems they have.
func TestMinimizeKubeconfigMalformedPayload(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"unterminated flow sequence", "contexts: [ {name: x }"},
		{"tab indentation", "apiVersion: v1\n\tkind: Config\n"},
		{"not yaml at all", ":\n:"},
		{"empty payload", ""},
		{"no contexts", "apiVersion: v1\nkind: Config\nclusters: []\nusers: []\n"},
		{"contexts present but empty", "apiVersion: v1\nkind: Config\ncontexts: []\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MinimizeKubeconfig([]byte(tc.raw), Constraints{
				Contexts:   []string{"prod"},
				Namespaces: []string{"team-a"},
			})
			if !errors.Is(err, ErrMalformedPayload) {
				t.Fatalf("err = %v, want ErrMalformedPayload", err)
			}
		})
	}
}

// TestKubeconfigSummary: the audit/CLI string names contexts and namespaces
// and nothing else — never an endpoint or a token.
func TestKubeconfigSummary(t *testing.T) {
	out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), Constraints{
		Contexts:   []string{"prod"},
		Namespaces: []string{"team-a"},
	})
	if err != nil {
		t.Fatalf("MinimizeKubeconfig: %v", err)
	}
	got := KubeconfigSummary(out)
	if !strings.Contains(got, "prod/team-a") {
		t.Errorf("KubeconfigSummary() = %q, want it to contain %q", got, "prod/team-a")
	}
	for _, leak := range []string{"prod-secret-token", "https://prod.example.test"} {
		if strings.Contains(got, leak) {
			t.Errorf("KubeconfigSummary() = %q leaks %q", got, leak)
		}
	}

	t.Run("context without a namespace is named alone", func(t *testing.T) {
		out, err := MinimizeKubeconfig([]byte(threeContextKubeconfig), Constraints{
			Contexts: []string{"prod", "staging"},
		})
		if err != nil {
			t.Fatalf("MinimizeKubeconfig: %v", err)
		}
		if got := KubeconfigSummary(out); got != "prod/default,staging/staging-ns" {
			t.Errorf("KubeconfigSummary() = %q", got)
		}
	})

	t.Run("unparseable input does not panic", func(t *testing.T) {
		if got := KubeconfigSummary([]byte(":\n:")); got != "unparseable" {
			t.Errorf("KubeconfigSummary(garbage) = %q, want \"unparseable\"", got)
		}
	})
}
