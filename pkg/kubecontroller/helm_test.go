package kubecontroller

// helm_test.go holds the Helm chart in deploy/helm/cloop-executor-controller
// (Task 20485) to the controller it installs, by rendering it with
// `helm template` — what an operator installs is what helm renders,
// conditionals and all:
//
//   - its Role is exactly RequiredRules, in both directions, and grants no verb
//     beyond the ceiling the chart was specified with; nothing is cluster-wide;
//   - its CRD is the one the controller embeds;
//   - the Deployment runs two leader-electing replicas under the restricted
//     profile, probed on the controller's health endpoint;
//   - runners get an account of their own that mounts no token, and the pool
//     the chart creates is one the controller's own validation accepts;
//   - requireDigest pins every image the chart names, and the NetworkPolicy
//     leaves runners the hub and DNS;
//   - and the render refuses what it should.
//
// cmd/executor_controller_chart_test.go checks that the Deployment's flags are
// ones `cloop executor controller` accepts.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// requireHelmEnv turns a skip for a missing helm into a failure. CI sets it on
// the job that runs these tests on purpose, so they cannot pass by not running.
const requireHelmEnv = "CLOOP_REQUIRE_HELM"

const chartNamespace = "cloop-runners"

// testDigest is a well-formed digest for the pinning cases.
const testDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

// helmBinary returns helm, or skips (fails under CLOOP_REQUIRE_HELM).
func helmBinary(t *testing.T) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv(requireHelmEnv) != "" {
			t.Fatalf("%s is set but helm is not on PATH: %v", requireHelmEnv, err)
		}
		t.Skip("helm is not on PATH, so the executor controller chart cannot be rendered; " +
			"install helm 3 to run this check (CI requires it)")
	}
	return helm
}

// chartDir is the chart's directory in this module, found from this source
// file rather than the working directory, which a test may have changed.
func chartDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller found no source file")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "deploy", "helm", "cloop-executor-controller")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above " + thisFile)
		}
		dir = parent
	}
}

// helmTemplate runs `helm template` with the given --set values and returns
// its output, or its error and stderr. Helm's state directories point into a
// temporary directory: nothing here may write to the developer's home.
func helmTemplate(t *testing.T, helm string, set ...string) ([]byte, error) {
	t.Helper()
	return helmTemplateFiles(t, helm, nil, set...)
}

// helmTemplateFiles is helmTemplate with values files (-f) as well.
func helmTemplateFiles(t *testing.T, helm string, files []string, set ...string) ([]byte, error) {
	t.Helper()
	args := []string{"template", "ctl", chartDir(t), "--namespace", chartNamespace}
	for _, f := range files {
		args = append(args, "-f", f)
	}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, helm, args...)
	cmd.Dir = filepath.Dir(chartDir(t))
	tmp := t.TempDir()
	cmd.Env = append(os.Environ(),
		"HELM_CACHE_HOME="+filepath.Join(tmp, "cache"),
		"HELM_CONFIG_HOME="+filepath.Join(tmp, "config"),
		"HELM_DATA_HOME="+filepath.Join(tmp, "data"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New(strings.TrimSpace(err.Error() + "\n" + stderr.String()))
	}
	return out, nil
}

// refuses asserts that the render fails, and for the reason given: a refusal
// that fails for some other reason (a mistyped value, a broken template)
// proves nothing.
func refuses(t *testing.T, helm, what, reason string, set ...string) {
	t.Helper()
	_, err := helmTemplate(t, helm, set...)
	switch {
	case err == nil:
		t.Errorf("the chart rendered %s", what)
	case !strings.Contains(err.Error(), reason):
		t.Errorf("the chart refused %s, but not because %q:\n%v", what, reason, err)
	}
}

// chartObject is one rendered object, decoded as JSON would be.
type chartObject map[string]any

func (o chartObject) kind() string { s, _ := o["kind"].(string); return s }

func (o chartObject) name() string { return o.str("metadata", "name") }

func (o chartObject) namespace() string { return o.str("metadata", "namespace") }

// get walks keys into nested maps.
func (o chartObject) get(keys ...string) any {
	var cur any = map[string]any(o)
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func (o chartObject) str(keys ...string) string { s, _ := o.get(keys...).(string); return s }

// into decodes the object into a typed value through JSON.
func (o chartObject) into(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any(o))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %s %s: %v", o.kind(), o.name(), err)
	}
}

// renderChart renders and decodes every object, failing on a refusal.
func renderChart(t *testing.T, helm string, set ...string) []chartObject {
	t.Helper()
	return renderChartFiles(t, helm, nil, set...)
}

// renderChartFiles is renderChart with values files as well.
func renderChartFiles(t *testing.T, helm string, files []string, set ...string) []chartObject {
	t.Helper()
	out, err := helmTemplateFiles(t, helm, files, set...)
	if err != nil {
		t.Fatalf("helm template %v %v: %v", files, set, err)
	}
	var objs []chartObject
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var m map[string]any
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode the rendered chart: %v", err)
		}
		if len(m) > 0 {
			objs = append(objs, chartObject(m))
		}
	}
	if len(objs) == 0 {
		t.Fatalf("helm rendered no objects:\n%s", out)
	}
	return objs
}

func objectsOf(objs []chartObject, kind string) []chartObject {
	var out []chartObject
	for _, o := range objs {
		if o.kind() == kind {
			out = append(out, o)
		}
	}
	return out
}

// only returns the single object of a kind.
func only(t *testing.T, objs []chartObject, kind string) chartObject {
	t.Helper()
	found := objectsOf(objs, kind)
	if len(found) != 1 {
		t.Fatalf("the chart renders %d %s object(s), want exactly one", len(found), kind)
	}
	return found[0]
}

// grants is a Role's verbs per "group/resource" ("resource" in the core group).
type grants map[string]map[string]bool

func grantKey(group, resource string) string {
	if group == "" {
		return resource
	}
	return group + "/" + resource
}

func (g grants) add(group, resource string, verbs ...string) {
	k := grantKey(group, resource)
	if g[k] == nil {
		g[k] = map[string]bool{}
	}
	for _, v := range verbs {
		g[k][v] = true
	}
}

func (g grants) keys() []string {
	out := make([]string, 0, len(g))
	for k := range g {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedVerbs(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// requiredGrants is RequiredRules as grants; without leader election the
// chart leaves the Lease rule out.
func requiredGrants(leaderElection bool) grants {
	g := grants{}
	for _, r := range RequiredRules() {
		for _, grp := range r.APIGroups {
			for _, res := range r.Resources {
				if res == "leases" && !leaderElection {
					continue
				}
				g.add(grp, res, r.Verbs...)
			}
		}
	}
	return g
}

// roleGrants reads a rendered Role's rules, failing on any shape the
// controller has no use for.
func roleGrants(t *testing.T, role chartObject) grants {
	t.Helper()
	var r struct {
		Rules []struct {
			APIGroups       []string `json:"apiGroups"`
			Resources       []string `json:"resources"`
			Verbs           []string `json:"verbs"`
			ResourceNames   []string `json:"resourceNames"`
			NonResourceURLs []string `json:"nonResourceURLs"`
		} `json:"rules"`
	}
	role.into(t, &r)
	g := grants{}
	for _, rule := range r.Rules {
		if len(rule.ResourceNames) > 0 || len(rule.NonResourceURLs) > 0 {
			t.Errorf("rule %+v is scoped by resourceNames or nonResourceURLs, which no controller call needs", rule)
		}
		for _, grp := range rule.APIGroups {
			for _, res := range rule.Resources {
				if grp == "*" || res == "*" || strings.Contains(res, "*") {
					t.Errorf("the Role has a wildcard: group %q resource %q", grp, res)
				}
				for _, v := range rule.Verbs {
					if v == "*" {
						t.Errorf("the Role grants every verb on %s", grantKey(grp, res))
					}
				}
				g.add(grp, res, rule.Verbs...)
			}
		}
	}
	return g
}

// roleValueSets are the renders whose Role is checked: the defaults, one
// replica without leader election, and everything the chart can switch on.
var roleValueSets = []struct {
	name           string
	set            []string
	leaderElection bool
}{
	{name: "defaults", leaderElection: true},
	{name: "one replica without leader election",
		set: []string{"replicaCount=1", "leaderElection.enabled=false"}},
	{name: "a pool, a network policy and pinned images", leaderElection: true, set: []string{
		"pool.create=true", "pool.hubURL=https://hub.example.com", "pool.credential.value=cloop_pool1_abc.def",
		"pool.template.automountServiceAccountToken=true", "pool.persistence.enabled=true",
		"networkPolicy.enabled=true", "networkPolicy.hub.cidrs[0]=10.96.0.0/12",
		"requireDigest=true", "image.digest=" + testDigest,
	}},
}

// TestHelmChartRoleIsExactlyWhatTheControllerCalls compares the chart's Role,
// verb by verb, with RequiredRules — which rbac_test.go holds to the calls the
// controller makes — and checks the binding's shape.
func TestHelmChartRoleIsExactlyWhatTheControllerCalls(t *testing.T) {
	helm := helmBinary(t)
	for _, vs := range roleValueSets {
		t.Run(vs.name, func(t *testing.T) {
			objs := renderChart(t, helm, vs.set...)
			for _, o := range objs {
				if k := o.kind(); k == "ClusterRole" || k == "ClusterRoleBinding" {
					t.Errorf("the chart renders a %s (%s): the controller's authority, Secrets above all, must "+
						"be one namespaced Role", k, o.name())
				}
			}
			role, binding := only(t, objs, "Role"), only(t, objs, "RoleBinding")
			if role.namespace() != chartNamespace || binding.namespace() != chartNamespace {
				t.Errorf("the Role is in %q and its binding in %q, want the release namespace %q",
					role.namespace(), binding.namespace(), chartNamespace)
			}
			if binding.str("roleRef", "kind") != "Role" || binding.str("roleRef", "name") != role.name() {
				t.Errorf("the RoleBinding refers to %s %s, not the Role %s",
					binding.str("roleRef", "kind"), binding.str("roleRef", "name"), role.name())
			}
			controllerSA := only(t, objs, "Deployment").str("spec", "template", "spec", "serviceAccountName")
			subjects, _ := binding.get("subjects").([]any)
			if len(subjects) != 1 {
				t.Fatalf("the RoleBinding has %d subjects, want the controller's ServiceAccount alone", len(subjects))
			}
			s := chartObject(subjects[0].(map[string]any))
			if s.str("kind") != "ServiceAccount" || s.str("name") != controllerSA || s.str("namespace") != chartNamespace {
				t.Errorf("the RoleBinding's subject is %v, want ServiceAccount %s/%s", s, chartNamespace, controllerSA)
			}

			got, want := roleGrants(t, role), requiredGrants(vs.leaderElection)
			for _, key := range want.keys() {
				for _, v := range sortedVerbs(want[key]) {
					if !got[key][v] {
						t.Errorf("the Role does not grant %s on %s, which the controller calls — it would fail "+
							"with a 403 on the operator's cluster", v, key)
					}
				}
			}
			for _, key := range got.keys() {
				for _, v := range sortedVerbs(got[key]) {
					if !want[key][v] {
						t.Errorf("the Role grants %s on %s, which the controller never calls — authority nothing "+
							"uses is authority a compromised controller gets for free", v, key)
					}
				}
			}
		})
	}
}

// roleCeiling is the most the chart's Role may ever grant, as the chart was
// specified: pods, secrets and persistentvolumeclaims with
// create/get/list/watch/delete/patch, leases for leader election, events
// (create), and executorpools plus executorpools/status — read on the pools,
// write on their status only. It is independent of RequiredRules, so widening
// both together still fails here.
var roleCeiling = map[string][]string{
	"pods":                           {"create", "get", "list", "watch", "delete", "patch"},
	"secrets":                        {"create", "get", "list", "watch", "delete", "patch"},
	"persistentvolumeclaims":         {"create", "get", "list", "watch", "delete", "patch"},
	"events":                         {"create"},
	"coordination.k8s.io/leases":     {"get", "create", "update"},
	"cloop.dev/executorpools":        {"get", "list", "watch"},
	"cloop.dev/executorpools/status": {"get", "update", "patch"},
}

func TestHelmChartRoleGrantsNoVerbBeyondItsCeiling(t *testing.T) {
	helm := helmBinary(t)
	for _, vs := range roleValueSets {
		t.Run(vs.name, func(t *testing.T) {
			got := roleGrants(t, only(t, renderChart(t, helm, vs.set...), "Role"))
			for _, key := range got.keys() {
				allowed, ok := roleCeiling[key]
				if !ok {
					t.Errorf("the Role grants %v on %s, which is not among the resources the controller may "+
						"touch", sortedVerbs(got[key]), key)
					continue
				}
				for _, v := range sortedVerbs(got[key]) {
					found := false
					for _, a := range allowed {
						found = found || a == v
					}
					if !found {
						t.Errorf("the Role grants %s on %s, beyond its ceiling %v", v, key, allowed)
					}
				}
			}
		})
	}
	// The table itself: RequiredRules fits under the ceiling, or the ceiling
	// would fail every render rather than guard it.
	for key, verbs := range requiredGrants(true) {
		for v := range verbs {
			ok := false
			for _, a := range roleCeiling[key] {
				ok = ok || a == v
			}
			if !ok {
				t.Errorf("RequiredRules has %s on %s, beyond the chart's ceiling: the chart could not grant it", v, key)
			}
		}
	}
}

// The chart's crds/ holds the CRD the controller embeds, byte for byte: Helm
// installs the one there, and a field only the controller knows is a field the
// API server prunes from every pool.
func TestHelmChartShipsTheControllersCRD(t *testing.T) {
	path := filepath.Join(chartDir(t), "crds", "cloop.dev_executorpools.yaml")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, CRD()) {
		t.Fatalf("%s differs from pkg/kubecontroller/crds/cloop.dev_executorpools.yaml; copy it:\n"+
			"  cp pkg/kubecontroller/crds/cloop.dev_executorpools.yaml %s", path, path)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("the chart's crds/ holds %d files, want the ExecutorPool CRD alone", len(entries))
	}
}

// container returns a Pod spec's only container.
func container(t *testing.T, podSpec chartObject) chartObject {
	t.Helper()
	cs, _ := podSpec.get("containers").([]any)
	if len(cs) != 1 {
		t.Fatalf("%d containers, want 1", len(cs))
	}
	return chartObject(cs[0].(map[string]any))
}

func stringList(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, _ := it.(string)
		out = append(out, s)
	}
	return out
}

func TestHelmChartDeploymentRunsTwoRestrictedLeaderElectingReplicas(t *testing.T) {
	helm := helmBinary(t)
	objs := renderChart(t, helm)
	dep := only(t, objs, "Deployment")
	if n, _ := dep.get("spec", "replicas").(int); n != 2 {
		t.Errorf("replicas %v, want 2", dep.get("spec", "replicas"))
	}
	pod := chartObject(dep.get("spec", "template", "spec").(map[string]any))
	if pod.get("automountServiceAccountToken") != true {
		t.Error("the controller's Pods do not mount the token it talks to the API server with")
	}
	psc := chartObject(pod.get("securityContext").(map[string]any))
	if psc.get("runAsNonRoot") != true || psc.str("seccompProfile", "type") != "RuntimeDefault" {
		t.Errorf("Pod securityContext %v is not restricted", psc)
	}
	c := container(t, pod)
	sc := chartObject(c.get("securityContext").(map[string]any))
	for k, want := range map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
		"privileged": false} {
		if sc.get(k) != want {
			t.Errorf("container securityContext.%s = %v, want %v", k, sc.get(k), want)
		}
	}
	if drop := stringList(sc.get("capabilities", "drop")); len(drop) != 1 || drop[0] != "ALL" {
		t.Errorf("capabilities.drop %v, want [ALL]", drop)
	}
	if add := sc.get("capabilities", "add"); add != nil {
		t.Errorf("capabilities.add %v", add)
	}
	for _, k := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if v := pod.get(k); v != nil && v != false {
			t.Errorf("%s is %v", k, v)
		}
	}
	for _, v := range pod.get("volumes").([]any) {
		for k := range v.(map[string]any) {
			if k != "name" && k != "emptyDir" {
				t.Errorf("volume %v is a %s; the controller needs a scratch directory and nothing else", v, k)
			}
		}
	}

	args := stringList(c.get("args"))
	if len(args) < 2 || args[0] != "executor" || args[1] != "controller" {
		t.Fatalf("args %v do not run `cloop executor controller`", args)
	}
	for _, want := range []string{"--namespace=" + chartNamespace, "--leader-elect=true",
		"--leader-election-namespace=" + chartNamespace, "--leader-election-name=cloop-executor-controller",
		"--health-addr=:8081"} {
		found := false
		for _, a := range args {
			found = found || a == want
		}
		if !found {
			t.Errorf("args %v lack %s", args, want)
		}
	}

	// Both probes are the controller's own, on its health port.
	ports, _ := c.get("ports").([]any)
	if len(ports) != 1 {
		t.Fatalf("ports %v", ports)
	}
	port := chartObject(ports[0].(map[string]any))
	if port.str("name") != "health" || port.get("containerPort") != 8081 {
		t.Errorf("port %v, want health 8081", port)
	}
	for probe, path := range map[string]string{"livenessProbe": "/healthz", "readinessProbe": "/readyz"} {
		if got := c.str(probe, "httpGet", "path"); got != path {
			t.Errorf("%s path %q, want %q", probe, got, path)
		}
		if got := c.str(probe, "httpGet", "port"); got != "health" {
			t.Errorf("%s port %q, want health", probe, got)
		}
	}
	// A rollout starts the replacement first: the Lease keeps one leader.
	if dep.str("spec", "strategy", "type") != "RollingUpdate" || dep.get("spec", "strategy", "rollingUpdate", "maxUnavailable") != 0 {
		t.Errorf("strategy %v, want a rolling update that keeps both replicas", dep.get("spec", "strategy"))
	}
	// Two replicas drain one at a time.
	pdb := only(t, objs, "PodDisruptionBudget")
	if pdb.get("spec", "maxUnavailable") != 1 {
		t.Errorf("PodDisruptionBudget %v", pdb.get("spec"))
	}
	// One replica without leader election: no Lease flags, no budget, and
	// the old Pod stops before its replacement starts — two Pods without an
	// elector would both scale.
	single := renderChart(t, helm, "replicaCount=1", "leaderElection.enabled=false")
	if len(objectsOf(single, "PodDisruptionBudget")) != 0 {
		t.Error("a single replica has a PodDisruptionBudget that would block every drain")
	}
	if st := only(t, single, "Deployment").str("spec", "strategy", "type"); st != "Recreate" {
		t.Errorf("without leader election the strategy is %q; a surge Pod would scale beside the old one", st)
	}
	for _, a := range stringList(container(t, chartObject(only(t, single, "Deployment").
		get("spec", "template", "spec").(map[string]any))).get("args")) {
		if strings.HasPrefix(a, "--leader-election-") {
			t.Errorf("leader election is off but the args carry %s", a)
		}
	}
}

func TestHelmChartRunnersGetAnAccountOfTheirOwnThatMountsNoToken(t *testing.T) {
	helm := helmBinary(t)
	objs := renderChart(t, helm, "pool.create=true", "pool.hubURL=https://hub.example.com",
		"pool.credential.value=cloop_pool1_abc.def")
	controllerSA := only(t, objs, "Deployment").str("spec", "template", "spec", "serviceAccountName")
	pool := only(t, objs, "ExecutorPool")
	var ep ExecutorPool
	pool.into(t, &ep)
	runnerSA := ep.Spec.Template.ServiceAccountName
	if runnerSA == "" || runnerSA == controllerSA || runnerSA == "default" {
		t.Fatalf("the pool's runners run as %q (the controller is %q); they need an account of their own",
			runnerSA, controllerSA)
	}
	if ep.Spec.Template.AutomountServiceAccountToken {
		t.Error("the pool asks for a token by default")
	}
	accounts := map[string]chartObject{}
	for _, sa := range objectsOf(objs, "ServiceAccount") {
		accounts[sa.name()] = sa
	}
	for _, name := range []string{controllerSA, runnerSA} {
		sa, ok := accounts[name]
		if !ok {
			t.Fatalf("no ServiceAccount %s is rendered", name)
		}
		if sa.get("automountServiceAccountToken") != false {
			t.Errorf("ServiceAccount %s mounts its token by default", name)
		}
	}
	for _, b := range objectsOf(objs, "RoleBinding") {
		for _, s := range b.get("subjects").([]any) {
			if chartObject(s.(map[string]any)).str("name") == runnerSA {
				t.Errorf("RoleBinding %s grants the runners' account authority", b.name())
			}
		}
	}

	// The pool is one the controller accepts, and its credential is in the
	// Secret it names, under the key it names.
	if problems := ep.Spec.Normalize().Validate(); len(problems) != 0 {
		t.Fatalf("the chart's pool is invalid to the controller: %v", problems)
	}
	secret := only(t, objs, "Secret")
	ref := ep.Spec.PoolCredentialSecretRef
	if secret.name() != ref.Name {
		t.Fatalf("the pool reads Secret %q, the chart writes %q", ref.Name, secret.name())
	}
	enc := secret.str("data", ref.Key)
	val, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || string(val) != "cloop_pool1_abc.def" {
		t.Fatalf("Secret %s key %s holds %q (%v)", ref.Name, ref.Key, val, err)
	}

	// Asked for, the token is the runners' account's, and still valid.
	objs = renderChart(t, helm, "pool.create=true", "pool.hubURL=https://hub.example.com",
		"pool.credential.existingSecret=mine", "pool.credential.key=token",
		"pool.template.automountServiceAccountToken=true")
	only(t, objs, "ExecutorPool").into(t, &ep)
	if !ep.Spec.Template.AutomountServiceAccountToken || ep.Spec.Template.ServiceAccountName != runnerSA {
		t.Fatalf("template %+v, want the runners' account with its token", ep.Spec.Template)
	}
	if ep.Spec.PoolCredentialSecretRef != (SecretKeyRef{Name: "mine", Key: "token"}) {
		t.Fatalf("credential ref %+v, want mine/token", ep.Spec.PoolCredentialSecretRef)
	}
	if problems := ep.Spec.Normalize().Validate(); len(problems) != 0 {
		t.Fatalf("the chart's pool with a token is invalid: %v", problems)
	}
	if n := len(objectsOf(objs, "Secret")); n != 0 {
		t.Fatalf("with existingSecret the chart writes %d Secret(s)", n)
	}
}

func TestHelmChartRequireDigestPinsEveryImageItNames(t *testing.T) {
	helm := helmBinary(t)
	base := []string{"requireDigest=true", "image.digest=" + testDigest}
	objs := renderChart(t, helm, base...)
	c := container(t, chartObject(only(t, objs, "Deployment").get("spec", "template", "spec").(map[string]any)))
	if img := c.str("image"); img != "ghcr.io/blechschmidt/cloop@"+testDigest {
		t.Errorf("image %q, want the repository at the digest", img)
	}
	found := false
	for _, a := range stringList(c.get("args")) {
		found = found || a == "--require-image-digest"
	}
	if !found {
		t.Error("requireDigest does not start the controller with --require-image-digest")
	}
	// A pool's runner image: a digest, empty for the controller's verified
	// default, or one of cloop's own by tag, which the controller resolves and
	// verifies the same way — the chart's list of those is OwnRepositories.
	pool := append(append([]string{}, base...), "pool.create=true", "pool.hubURL=https://hub.example.com",
		"pool.credential.existingSecret=cred")
	renderChart(t, helm, pool...)
	renderChart(t, helm, append(pool, "pool.template.image=registry.example.com/runner@"+testDigest)...)
	renderChart(t, helm, append(pool, "pool.template.image=registry.example.com/runner@sha512:"+strings.Repeat("b", 128))...)
	for _, own := range imagepolicy.OwnRepositories {
		renderChart(t, helm, append(pool, "pool.template.image="+own+":0.0.7")...)
		if !imagepolicy.IsOwnImage(own + ":0.0.7") {
			t.Fatalf("%s is not one of cloop's own images to imagepolicy", own)
		}
	}
	var listed []string
	if err := json.Unmarshal([]byte(chartTemplateDefine(t, "cloop-executor-controller.ownRepositories")), &listed); err != nil {
		t.Fatalf("the chart's ownRepositories is not a JSON list: %v", err)
	}
	if strings.Join(listed, ",") != strings.Join(imagepolicy.OwnRepositories, ",") {
		t.Fatalf("the chart's ownRepositories %v differ from imagepolicy.OwnRepositories %v", listed, imagepolicy.OwnRepositories)
	}
	refuses(t, helm, "a lookalike of cloop's own image by tag", "is not pinned by digest",
		append(pool, "pool.template.image=registry.example.com/blechschmidt/cloop-harness:0.0.7")...)
	// Built from the list, so no unpublished first-party name is written out
	// here (tests/docs holds every one that is to the publishing workflow).
	refuses(t, helm, "a repository that merely begins like cloop's", "is not pinned by digest",
		append(pool, "pool.template.image="+imagepolicy.OwnRepositories[len(imagepolicy.OwnRepositories)-1]+"-evil:0.0.7")...)
	// Without requireDigest a tag is the image, and no flag is passed.
	c = container(t, chartObject(only(t, renderChart(t, helm, "image.tag=v1"), "Deployment").
		get("spec", "template", "spec").(map[string]any)))
	if c.str("image") != "ghcr.io/blechschmidt/cloop:v1" {
		t.Errorf("image %q", c.str("image"))
	}
	for _, a := range stringList(c.get("args")) {
		if a == "--require-image-digest" {
			t.Error("--require-image-digest without requireDigest")
		}
	}
	refuses(t, helm, "the controller by tag", "requireDigest is true but the controller's image",
		"requireDigest=true", "image.tag=v1")
	refuses(t, helm, "a pool's runners by tag", "requireDigest is true but pool.template.image",
		append(pool, "pool.template.image=registry.example.com/runner:1")...)
	refuses(t, helm, "a digest that is not one", "is not a content digest", "image.digest=sha256:abc")
	refuses(t, helm, "a digest of a family references do not use", "is not a content digest",
		"image.digest=sha384:"+strings.Repeat("a", 96))
	refuses(t, helm, "a sha512 digest of the wrong length", "is not a content digest",
		"image.digest=sha512:"+strings.Repeat("a", 64))
	renderChart(t, helm, "requireDigest=true", "image.digest=sha512:"+strings.Repeat("a", 128))
}

func TestHelmChartNetworkPolicyLeavesRunnersTheHubAndDNS(t *testing.T) {
	helm := helmBinary(t)
	if n := len(objectsOf(renderChart(t, helm), "NetworkPolicy")); n != 0 {
		t.Fatalf("the defaults render %d NetworkPolicy objects; it is opt-in", n)
	}
	objs := renderChart(t, helm, "networkPolicy.enabled=true",
		"networkPolicy.hub.namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name=cloop",
		"networkPolicy.hub.podSelector.matchLabels.app\\.kubernetes\\.io/name=cloop-hub",
		"networkPolicy.hub.cidrs[0]=203.0.113.0/24", "networkPolicy.hub.ports[0]=8080",
		"networkPolicy.hub.ports[1]=8443", "networkPolicy.hub.ports[2]=3128")
	var np struct {
		Spec struct {
			PodSelector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"podSelector"`
			PolicyTypes []string         `json:"policyTypes"`
			Ingress     []map[string]any `json:"ingress"`
			Egress      []struct {
				To    []map[string]any `json:"to"`
				Ports []struct {
					Protocol string `json:"protocol"`
					Port     int    `json:"port"`
				} `json:"ports"`
			} `json:"egress"`
		} `json:"spec"`
	}
	only(t, objs, "NetworkPolicy").into(t, &np)
	sel := np.Spec.PodSelector.MatchLabels
	if len(sel) != 2 || sel[LabelName] != RunnerName || sel[LabelManagedBy] != ManagedBy {
		t.Errorf("podSelector %v, want every runner the controller starts", sel)
	}
	if strings.Join(np.Spec.PolicyTypes, ",") != "Ingress,Egress" || len(np.Spec.Ingress) != 0 {
		t.Errorf("policyTypes %v ingress %v: no connection to a runner may be allowed", np.Spec.PolicyTypes, np.Spec.Ingress)
	}
	if len(np.Spec.Egress) != 2 {
		t.Fatalf("%d egress rules, want the hub's and DNS's", len(np.Spec.Egress))
	}
	hub, dns := np.Spec.Egress[0], np.Spec.Egress[1]
	if len(hub.To) != 2 || hub.To[0]["namespaceSelector"] == nil || hub.To[0]["podSelector"] == nil ||
		hub.To[1]["ipBlock"].(map[string]any)["cidr"] != "203.0.113.0/24" {
		t.Errorf("the hub rule reaches %v", hub.To)
	}
	var hubPorts []int
	for _, p := range hub.Ports {
		if p.Protocol != "TCP" {
			t.Errorf("hub port %+v is not TCP", p)
		}
		hubPorts = append(hubPorts, p.Port)
	}
	if len(hubPorts) != 3 || hubPorts[0] != 8080 || hubPorts[1] != 8443 || hubPorts[2] != 3128 {
		t.Errorf("hub ports %v", hubPorts)
	}
	if len(dns.To) != 1 || dns.To[0]["namespaceSelector"] == nil || len(dns.Ports) != 2 ||
		dns.Ports[0] != (struct {
			Protocol string `json:"protocol"`
			Port     int    `json:"port"`
		}{"UDP", 53}) || dns.Ports[1].Protocol != "TCP" || dns.Ports[1].Port != 53 {
		t.Errorf("the DNS rule is %+v, want UDP and TCP 53", dns)
	}
	// The DNS Pods' own port, where it is not 53 (OpenShift's 5353).
	only(t, renderChart(t, helm, "networkPolicy.enabled=true", "networkPolicy.hub.cidrs[0]=10.0.0.0/8",
		"networkPolicy.dns.ports={5353}"), "NetworkPolicy").into(t, &np)
	if p := np.Spec.Egress[1].Ports; len(p) != 2 || p[0].Port != 5353 || p[0].Protocol != "UDP" ||
		p[1].Port != 5353 || p[1].Protocol != "TCP" {
		t.Errorf("networkPolicy.dns.ports={5353} opens %+v", p)
	}
	for _, rule := range np.Spec.Egress {
		if len(rule.To) == 0 || len(rule.Ports) == 0 {
			t.Errorf("egress rule %+v is open to every destination or port", rule)
		}
	}
	refuses(t, helm, "a policy with no way to the hub", "networkPolicy.hub names no destination",
		"networkPolicy.enabled=true")
	refuses(t, helm, "a policy open to every address", "is every address",
		"networkPolicy.enabled=true", "networkPolicy.hub.cidrs[0]=0.0.0.0/0")
	refuses(t, helm, "a policy with no hub port", "networkPolicy.hub.ports is empty",
		"networkPolicy.enabled=true", "networkPolicy.hub.cidrs[0]=10.0.0.0/8", "networkPolicy.hub.ports=null")
	refuses(t, helm, "a policy with no resolver", "networkPolicy.dns names no resolver",
		"networkPolicy.enabled=true", "networkPolicy.hub.cidrs[0]=10.0.0.0/8", "networkPolicy.dns.namespaceSelector=null")
	refuses(t, helm, "a policy with no DNS port", "networkPolicy.dns.ports is empty",
		"networkPolicy.enabled=true", "networkPolicy.hub.cidrs[0]=10.0.0.0/8", "networkPolicy.dns.ports=")
}

// Values reach the objects as what they say: a number or a boolean set
// with --set becomes the string a label needs, a 0 is kept rather than
// replaced by a default, and a value holding a newline stays one value
// rather than adding keys behind the chart's checks.
func TestHelmChartRendersValuesAsTheyWereGiven(t *testing.T) {
	helm := helmBinary(t)
	values := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(values, []byte(`pool:
  template:
    runtimeClassName: "gvisor\n    serviceAccountName: ctl-cloop-executor-controller\n    automountServiceAccountToken: true"
    imagePullPolicy: "IfNotPresent\n    image: attacker.example/runner:latest"
podAnnotations:
  note: "a\nb: c"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	objs := renderChartFiles(t, helm, []string{values}, "pool.create=true", "pool.hubURL=https://hub.example.com",
		"pool.credential.existingSecret=c", "pool.runnerLabels.tier=1", "pool.template.nodeSelector.gpu=true",
		"pool.scaleDownDelay=0", "pool.persistence.enabled=true", "pool.persistence.minFree=0",
		"pool.persistence.maxClaims=9", "podLabels.release=2")
	var ep ExecutorPool
	only(t, objs, "ExecutorPool").into(t, &ep)
	tmpl := ep.Spec.Template
	if tmpl.ServiceAccountName != "ctl-cloop-executor-controller-runner" || tmpl.AutomountServiceAccountToken ||
		tmpl.Image != "" {
		t.Errorf("a value's newline added keys to the template: %+v", tmpl)
	}
	if !strings.Contains(tmpl.RuntimeClassName, "\n") || !strings.Contains(tmpl.ImagePullPolicy, "\n") {
		t.Errorf("the values with newlines were not kept as one value each: %+v", tmpl)
	}
	if ep.Spec.RunnerLabels["tier"] != "1" || tmpl.NodeSelector["gpu"] != "true" {
		t.Errorf("runnerLabels %v nodeSelector %v, want strings", ep.Spec.RunnerLabels, tmpl.NodeSelector)
	}
	if ep.Spec.ScaleDownDelay != "0s" {
		t.Errorf("scaleDownDelay 0 rendered as %q, want 0s", ep.Spec.ScaleDownDelay)
	}
	if p := ep.Spec.Persistence; p == nil || p.MinFree != "0" || p.MaxClaims != 9 {
		t.Errorf("persistence %+v, want minFree 0 and maxClaims 9 as given", p)
	}
	dep := only(t, objs, "Deployment")
	if v, ok := dep.get("spec", "template", "metadata", "labels", "release").(string); !ok || v != "2" {
		t.Errorf("podLabels.release=2 rendered as %#v", dep.get("spec", "template", "metadata", "labels", "release"))
	}
	if v := dep.str("spec", "template", "metadata", "annotations", "note"); v != "a\nb: c" {
		t.Errorf("podAnnotations.note rendered as %q", v)
	}
	// Unset, the delay is the CRD's 5m.
	only(t, renderChart(t, helm, "pool.create=true", "pool.hubURL=https://hub.example.com",
		"pool.credential.existingSecret=c"), "ExecutorPool").into(t, &ep)
	if ep.Spec.ScaleDownDelay != DefaultScaleDownDelay {
		t.Errorf("scaleDownDelay unset rendered as %q", ep.Spec.ScaleDownDelay)
	}
}

// chartTemplateDefine returns the body of a {{ define }} in _helpers.tpl.
func chartTemplateDefine(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(chartDir(t), "templates", "_helpers.tpl"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, `{{- define "`+name+`" -}}`)
	if start < 0 {
		t.Fatalf("_helpers.tpl defines no %s", name)
	}
	body := src[start+len(`{{- define "`+name+`" -}}`):]
	end := strings.Index(body, "{{- end -}}")
	if end < 0 {
		t.Fatalf("%s has no end", name)
	}
	return strings.TrimSpace(body[:end])
}

// The render refuses what would install a controller that cannot work, or
// one with more authority or less isolation than the chart promises.
func TestHelmChartRefusesWhatItShould(t *testing.T) {
	helm := helmBinary(t)
	pool := func(more ...string) []string {
		return append([]string{"pool.create=true", "pool.hubURL=https://hub.example.com"}, more...)
	}
	for _, tc := range []struct {
		what, reason string
		set          []string
	}{
		{"two replicas without leader election", "leaderElection.enabled is false",
			[]string{"leaderElection.enabled=false"}},
		{"RBAC for the namespace's default account", "serviceAccount.create is false and serviceAccount.name is empty",
			[]string{"serviceAccount.create=false"}},
		{"runners as the controller's account", "the runner ServiceAccount and the controller's are both",
			[]string{"runnerServiceAccount.create=false", "runnerServiceAccount.name=ctl-cloop-executor-controller"}},
		{"runners as the default account", "the runner ServiceAccount is the namespace's",
			[]string{"runnerServiceAccount.create=false", "runnerServiceAccount.name=default"}},
		{"runners with no account", "runnerServiceAccount.name is empty",
			[]string{"runnerServiceAccount.create=false"}},
		{"a pool with no hub", "pool.hubURL is empty",
			[]string{"pool.create=true", "pool.credential.existingSecret=c"}},
		{"a pool on a plaintext hub", "must be an https URL",
			[]string{"pool.create=true", "pool.hubURL=http://hub.example.com", "pool.credential.existingSecret=c"}},
		{"a pool whose hub URL has a user", "must be an https URL",
			[]string{"pool.create=true", "pool.hubURL=https://u@hub.example.com", "pool.credential.existingSecret=c"}},
		{"a pool with no credential", "the pool has no credential", pool()},
		{"two credential sources", "mutually exclusive",
			pool("pool.credential.existingSecret=c", "pool.credential.value=cloop_pool1_a.b")},
		{"a credential that is not one", "is not a pool controller credential",
			pool("pool.credential.value=hunter2")},
		{"min above max", "pool.minRunners 5",
			pool("pool.credential.existingSecret=c", "pool.minRunners=5", "pool.maxRunners=2")},
		{"runners handed the credential", "holds the pool's controller credential",
			pool("pool.credential.existingSecret=c", "pool.template.env[0].name=X",
				"pool.template.env[0].secretKeyRef.name=c", "pool.template.env[0].secretKeyRef.key=credential")},
		{"a CA bundle that is not PEM", "pool.hubCABundle holds no PEM",
			pool("pool.credential.existingSecret=c", "pool.hubCABundle=nope")},
		{"an unknown provenance mode", "controller.imageProvenance must be warn or required",
			[]string{"controller.imageProvenance=maybe"}},
		{"a resync that is no duration", "controller.resync",
			[]string{"controller.resync=often"}},
		{"a resync under the controller's floor", "is under 30s", []string{"controller.resync=10s"}},
		{"a resync just under the floor", "is under 30s", []string{"controller.resync=29s999ms"}},
		{"the controller as the default account", "the controller's ServiceAccount is the namespace's",
			[]string{"serviceAccount.create=false", "serviceAccount.name=default"}},
		{"a created account named default", "the controller's ServiceAccount is the namespace's",
			[]string{"serviceAccount.name=default"}},
		{"a controller account that is no name", "is not a lowercase RFC 1123 name",
			[]string{"serviceAccount.name=Controller"}},
		{"a scale-down delay that is no duration", "pool.scaleDownDelay",
			pool("pool.credential.existingSecret=c", "pool.scaleDownDelay=soon")},
		{"fewer volumes than runners", "fewer than pool.maxRunners",
			pool("pool.credential.existingSecret=c", "pool.persistence.enabled=true", "pool.persistence.maxClaims=2")},
	} {
		refuses(t, helm, tc.what, tc.reason, tc.set...)
	}
}
