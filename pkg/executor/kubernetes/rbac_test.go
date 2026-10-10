package kubernetes

// rbac_test.go pins the executor Role the Helm chart ships to the authority
// this driver actually uses (executorRole), in both directions: a verb the
// driver calls and the chart does not grant fails here instead of as a 403 on a
// customer's first run, and a verb the chart grants and the driver never calls
// fails here instead of shipping. The second direction is the one that matters
// for security — `patch` on networkpolicies is the authority to widen a running
// sandbox's firewall, and before this test nothing would have noticed it being
// added.
//
// It renders the real chart with `helm template` rather than reading the YAML
// file, because the Role is a template: what an operator installs is what helm
// renders, conditionals and all.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// requireHelmEnv turns the skip below into a failure. CI sets it on the job
// that runs this test on purpose, so the check cannot pass by not running.
const requireHelmEnv = "CLOOP_REQUIRE_HELM"

// chartValueSets are the renders checked. The Role is conditional, and the
// feature flags around it are where a future edit is likeliest to add a rule:
// the credential monitors, and a workload namespace of the operator's choosing.
var chartValueSets = []struct {
	name      string
	set       []string
	workloads string // the namespace the Role must live in; "" when there must be none
}{
	{
		name:      "in-cluster executor",
		set:       []string{"executor.kubernetes.enabled=true"},
		workloads: "cloop-workloads",
	},
	{
		name: "in-cluster executor with both monitors and its own namespace",
		set: []string{
			"executor.kubernetes.enabled=true",
			"executor.kubernetes.namespace=sandboxes",
			"executor.gitProxy.enabled=true",
			"executor.kubeGuard.enabled=true",
			"executor.monitorTLS.selfSigned=true",
		},
		workloads: "sandboxes",
	},
	{
		// Remote agents only: the chart refuses this unless told the operator
		// means it, and then must grant nothing in any namespace.
		name: "no in-cluster executor",
		set:  []string{"executor.kubernetes.enabled=false", "config.allowIsolationlessInstall=true"},
	},
}

// TestHelmChartExecutorRoleIsExactlyWhatTheDriverCalls renders the chart and
// compares its Role, verb by verb, against executorRole.
func TestHelmChartExecutorRoleIsExactlyWhatTheDriverCalls(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv(requireHelmEnv) != "" {
			t.Fatalf("%s is set but helm is not on PATH: %v", requireHelmEnv, err)
		}
		t.Skip("helm is not on PATH, so the chart's executor Role cannot be rendered and compared " +
			"with the verbs the driver calls; install helm 3 to run this check (CI requires it)")
	}
	chart := filepath.Join(moduleRoot(t), "deploy", "helm", "cloop-hub")
	want := roleVerbs(executorRole)

	for _, vs := range chartValueSets {
		t.Run(vs.name, func(t *testing.T) {
			docs := renderChart(t, helm, chart, vs.set)

			var roles, bindings []k8sObject
			for _, d := range docs {
				switch d.Kind {
				case "ClusterRole", "ClusterRoleBinding":
					// The namespace is the blast radius; a cluster-scoped grant
					// would make "where can this hub write" unanswerable.
					t.Errorf("the chart renders a %s (%s); the executor's authority must be one "+
						"namespaced Role", d.Kind, d.Metadata.Name)
				case "Role":
					roles = append(roles, d)
				case "RoleBinding":
					bindings = append(bindings, d)
				}
			}

			if vs.workloads == "" {
				if len(roles)+len(bindings) != 0 {
					t.Errorf("the chart renders %d Role(s) and %d RoleBinding(s) with the in-cluster "+
						"executor off; it must grant nothing it does not use", len(roles), len(bindings))
				}
				return
			}
			if len(roles) != 1 || len(bindings) != 1 {
				t.Fatalf("got %d Role(s) and %d RoleBinding(s), want exactly one of each", len(roles), len(bindings))
			}
			role, binding := roles[0], bindings[0]
			if role.Metadata.Namespace != vs.workloads {
				t.Errorf("the Role is in namespace %q, want the workload namespace %q — a rule in the "+
					"release namespace would reach the hub's own Secrets", role.Metadata.Namespace, vs.workloads)
			}
			if binding.Metadata.Namespace != vs.workloads || binding.RoleRef.Kind != "Role" ||
				binding.RoleRef.Name != role.Metadata.Name {
				t.Errorf("the RoleBinding (%s/%s → %s %s) does not bind the executor Role in %s",
					binding.Metadata.Namespace, binding.Metadata.Name, binding.RoleRef.Kind,
					binding.RoleRef.Name, vs.workloads)
			}

			got := map[string]map[string]bool{}
			for _, rule := range role.Rules {
				if len(rule.ResourceNames) > 0 || len(rule.NonResourceURLs) > 0 {
					t.Errorf("rule %+v is scoped by resourceNames or nonResourceURLs, which no driver "+
						"call needs", rule)
				}
				for _, g := range rule.APIGroups {
					for _, r := range rule.Resources {
						key := resourceKey(g, r)
						if got[key] == nil {
							got[key] = map[string]bool{}
						}
						for _, v := range rule.Verbs {
							got[key][v] = true
						}
					}
				}
			}

			// Both directions, reported separately so a failure says which.
			for _, key := range sortedKeys(want) {
				for _, v := range sortedSet(want[key]) {
					if !got[key][v] {
						t.Errorf("the Role does not grant %s on %s, which the driver calls — every "+
							"run that needs it would fail with a 403 on the operator's cluster", v, key)
					}
				}
			}
			for _, key := range sortedKeys(got) {
				for _, v := range sortedSet(got[key]) {
					if !want[key][v] {
						t.Errorf("the Role grants %s on %s, which the driver never calls — authority "+
							"nothing uses is authority a compromised hub gets for free", v, key)
					}
				}
			}
		})
	}
}

// TestExecutorRoleNeverReadsSecretsOrMutatesWhatItCreated is the table's own
// guard: the properties the chart's comments argue for, asserted on the source
// every remedy and the chart test now come from.
func TestExecutorRoleNeverReadsSecretsOrMutatesWhatItCreated(t *testing.T) {
	verbs := roleVerbs(executorRole)
	for _, v := range []string{"get", "list", "watch", "update"} {
		if verbs[resourceKey("", "secrets")][v] {
			t.Errorf("the executor Role grants %s on secrets; the driver never reads a Secret back", v)
		}
	}
	for _, key := range []string{resourceKey("", "pods"), resourceKey("networking.k8s.io", "networkpolicies")} {
		for _, v := range []string{"update", "patch"} {
			if verbs[key][v] {
				t.Errorf("the executor Role grants %s on %s; nothing the driver creates is mutated afterwards", v, key)
			}
		}
	}
	for key, set := range verbs {
		if set["*"] || strings.Contains(key, "*") {
			t.Errorf("the executor Role has a wildcard on %s", key)
		}
	}
	if verbs[resourceKey("", "pods/exec")] != nil {
		t.Error("the executor Role grants pods/exec; a shell into a sandbox is an operator's opt-in")
	}
	// And the remedies render from it.
	if got := secretsRuleYAML(); !strings.Contains(got, `verbs: ["create", "patch", "delete"]`) {
		t.Errorf("secretsRuleYAML() = %q", got)
	}
	if got := rbacFix("cloop", true); !strings.Contains(got, "secrets: [create patch delete]") ||
		!strings.Contains(got, "networking.k8s.io networkpolicies: [create delete list]") {
		t.Errorf("rbacFix = %q, want every rule of the table", got)
	}
	if got := rbacFix("cloop", false); strings.Contains(got, "networkpolicies") {
		t.Errorf("rbacFix without egress = %q; it must not ask for authority the executor does not use", got)
	}
}

// --- rendering --------------------------------------------------------

// k8sObject is what this test reads of a rendered manifest.
type k8sObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Rules   []policyRule `yaml:"rules"`
	RoleRef struct {
		Kind string `yaml:"kind"`
		Name string `yaml:"name"`
	} `yaml:"roleRef"`
}

type policyRule struct {
	APIGroups       []string `yaml:"apiGroups"`
	Resources       []string `yaml:"resources"`
	Verbs           []string `yaml:"verbs"`
	ResourceNames   []string `yaml:"resourceNames"`
	NonResourceURLs []string `yaml:"nonResourceURLs"`
}

// renderChart runs `helm template` and decodes every document.
//
// Helm's own state directories point into the test's temporary directory: a
// local chart needs none of them, and nothing here may write to the developer's
// home (see tests/hermetic).
func renderChart(t *testing.T, helm, chart string, set []string) []k8sObject {
	t.Helper()
	args := []string{"template", "cloop", chart, "--namespace", "cloop",
		"--set", "secrets.existingSecret=external"}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, helm, args...)
	tmp := t.TempDir()
	cmd.Env = append(os.Environ(),
		"HELM_CACHE_HOME="+filepath.Join(tmp, "cache"),
		"HELM_CONFIG_HOME="+filepath.Join(tmp, "config"),
		"HELM_DATA_HOME="+filepath.Join(tmp, "data"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helm %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}

	var docs []k8sObject
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var d k8sObject
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode the rendered chart: %v", err)
		}
		if d.Kind != "" {
			docs = append(docs, d)
		}
	}
	if len(docs) == 0 {
		t.Fatalf("helm rendered no objects:\n%s", out)
	}
	return docs
}

// moduleRoot walks up to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}

// --- comparison helpers -----------------------------------------------

func resourceKey(group, resource string) string {
	if group == "" {
		return resource
	}
	return group + "/" + resource
}

func roleVerbs(rules []roleRule) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, r := range rules {
		key := resourceKey(r.Group, r.Resource)
		if out[key] == nil {
			out[key] = map[string]bool{}
		}
		for _, v := range r.Verbs {
			out[key][v] = true
		}
	}
	return out
}

func sortedKeys(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
