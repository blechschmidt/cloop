package secretbroker_test

// Several kubeconfig grants in one lease (Task 20413). Each rendered its
// document at the same path, so a delivered lease was refused ("secret_files[N]
// repeats path …/kubeconfig") and a materialised one kept whichever grant
// wrote last. They now render one merged document; see kubemulti.go.
//
// An external test package, so the leases come from secretbrokertest.KubeLease
// — the same fixture the driver packages build theirs from.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

const (
	alphaServer = "https://alpha.example.test:6443"
	alphaToken  = "alpha-cluster-token-0123456789"
	betaServer  = "https://beta.example.test:6443"
	betaToken   = "beta-cluster-token-0123456789"
	monitorURL  = "https://monitor.example.test:8444"
)

// alpha is read-only on one namespace; beta may also create, on another. alpha
// is therefore the narrower, and its context is current-context.
func alphaBeta() []secretbrokertest.KubeGrant {
	return []secretbrokertest.KubeGrant{
		{Secret: "alpha-kube", Kubeconfig: secretbrokertest.Kubeconfig(alphaServer, alphaToken, "default"),
			Constraints: secretbroker.Constraints{Namespaces: []string{"team-a"}}},
		{Secret: "beta-kube", Kubeconfig: secretbrokertest.Kubeconfig(betaServer, betaToken, "default"),
			Constraints: secretbroker.Constraints{Namespaces: []string{"team-b"},
				Verbs: []string{"get", "list", "watch", "create"}}},
	}
}

// mergedDoc is what a test reads back out of a merged kubeconfig.
type mergedDoc struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string         `yaml:"name"`
		Cluster map[string]any `yaml:"cluster"`
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
		Name string         `yaml:"name"`
		User map[string]any `yaml:"user"`
	} `yaml:"users"`
}

func parseMerged(t *testing.T, data []byte) mergedDoc {
	t.Helper()
	var d mergedDoc
	if err := yaml.Unmarshal(data, &d); err != nil {
		t.Fatalf("the merged kubeconfig is not YAML: %v\n%s", err, data)
	}
	return d
}

// reach is where a context leads: the server its cluster names, the token its
// user presents, and its namespace. Empty fields mean the reference resolves
// to nothing.
type reach struct{ server, token, namespace string }

func (d mergedDoc) reach(t *testing.T, context string) reach {
	t.Helper()
	for _, c := range d.Contexts {
		if c.Name != context {
			continue
		}
		var r reach
		r.namespace = c.Context.Namespace
		for _, cl := range d.Clusters {
			if cl.Name == c.Context.Cluster {
				r.server, _ = cl.Cluster["server"].(string)
			}
		}
		for _, u := range d.Users {
			if u.Name == c.Context.User {
				r.token, _ = u.User["token"].(string)
			}
		}
		return r
	}
	t.Fatalf("the merged kubeconfig has no context %q: %+v", context, d.Contexts)
	return reach{}
}

func (d mergedDoc) contextNames() []string {
	var out []string
	for _, c := range d.Contexts {
		out = append(out, c.Name)
	}
	return out
}

// kubeconfigFiles returns the delivered files KUBECONFIG could name.
func kubeconfigFiles(files []secretbroker.DeliveredFile) []secretbroker.DeliveredFile {
	var out []secretbroker.DeliveredFile
	for _, f := range files {
		if f.Name == "kubeconfig" || strings.HasPrefix(f.Name, "kubeconfig") {
			out = append(out, f)
		}
	}
	return out
}

func envMap(pairs []string) map[string]string {
	out := map[string]string{}
	for _, kv := range pairs {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}

func grantOf(t *testing.T, lease *secretbroker.Lease, secret string, index int) string {
	t.Helper()
	n := 0
	for _, m := range lease.Materials {
		if m.SecretName == secret {
			if n == index {
				return m.GrantID
			}
			n++
		}
	}
	t.Fatalf("the lease has no material %d of %s", index, secret)
	return ""
}

func bindingOf(t *testing.T, bindings []secretbroker.LeaseBinding, grantID string) secretbroker.LeaseBinding {
	t.Helper()
	for _, b := range bindings {
		if b.GrantID == grantID {
			return b
		}
	}
	t.Fatalf("no binding for grant %s", grantID)
	return secretbroker.LeaseBinding{}
}

// TestTwoClustersDeliverOneKubeconfig is the reported failure: two kubeconfig
// grants must reach a driver as one document the spec accepts, each grant's
// context leading to its own cluster with its own credential.
func TestTwoClustersDeliverOneKubeconfig(t *testing.T) {
	_, lease := secretbrokertest.KubeLease(t, nil, alphaBeta()...)
	if len(lease.Materials) != 2 {
		t.Fatalf("lease carries %d materials, want both grants (refused: %+v)", len(lease.Materials), lease.Refused)
	}
	dir := secretbroker.SandboxLeaseDir(lease.ID)
	d, err := lease.Deliver(dir)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer d.Close()
	files := secretbroker.ExecutorSecretFiles(lease.ID, d.Files())
	spec := executor.Spec{
		Argv: []string{"claude"}, WorkDir: "/workspace", Env: d.Env(), SecretFiles: files,
		Secrets: secretbroker.ExecutorBindings(lease.ID, lease.ExpiresAt, d.Bindings()),
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("the delivered lease is refused, as it was before: %v", err)
	}
	kc := kubeconfigFiles(d.Files())
	if len(kc) != 1 || kc[0].Name != "kubeconfig" {
		t.Fatalf("got %d kubeconfig files (%v); KUBECONFIG names exactly one", len(kc), kc)
	}
	env := envMap(d.Env())
	if got, want := env["KUBECONFIG"], filepath.Join(dir, "kubeconfig"); got != want {
		t.Errorf("KUBECONFIG = %q, want %q", got, want)
	}

	doc := parseMerged(t, kc[0].Content)
	if got := doc.contextNames(); !slices.Equal(got, []string{"alpha-kube", "beta-kube"}) {
		t.Fatalf("contexts = %v, want each grant's, named after its secret", got)
	}
	if doc.CurrentContext != "alpha-kube" {
		t.Errorf("current-context = %q, want the narrower (read-only) grant's", doc.CurrentContext)
	}
	if got := doc.reach(t, "alpha-kube"); got != (reach{alphaServer, alphaToken, "team-a"}) {
		t.Errorf("alpha-kube leads to %+v", got)
	}
	if got := doc.reach(t, "beta-kube"); got != (reach{betaServer, betaToken, "team-b"}) {
		t.Errorf("beta-kube leads to %+v", got)
	}
	if len(doc.Clusters) != 2 || len(doc.Users) != 2 {
		t.Errorf("clusters %d, users %d: both exported kubeconfigs name theirs \"kubernetes\" and "+
			"\"kubernetes-admin\", and the merge must keep them apart", len(doc.Clusters), len(doc.Users))
	}

	// The single-grant variables describe the grant behind current-context;
	// the multi-grant ones describe both.
	for k, want := range map[string]string{
		"CLOOP_K8S_NAMESPACE":           "team-a",
		"CLOOP_K8S_ALLOWED_NAMESPACES":  "team-a",
		"CLOOP_K8S_VERBS":               "get,list,watch",
		secretbroker.KubeContextsEnvKey: "alpha-kube,beta-kube",
	} {
		if got := env[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	for _, k := range []string{secretbroker.KubeGuardSessionEnvKey, secretbroker.KubeGuardSessionsEnvKey} {
		if v, ok := env[k]; ok {
			t.Errorf("%s = %q on a lease no monitor guards", k, v)
		}
	}
	var grants []secretbroker.KubeGrantDescription
	if err := json.Unmarshal([]byte(env[secretbroker.KubeGrantsEnvKey]), &grants); err != nil {
		t.Fatalf("CLOOP_K8S_GRANTS is not JSON: %v (%q)", err, env[secretbroker.KubeGrantsEnvKey])
	}
	if len(grants) != 2 ||
		!slices.Equal(grants[0].Contexts, []string{"alpha-kube"}) || grants[0].Secret != "alpha-kube" ||
		grants[0].Namespace != "team-a" || !slices.Equal(grants[0].Verbs, []string{"get", "list", "watch"}) ||
		!slices.Equal(grants[1].Contexts, []string{"beta-kube"}) || grants[1].Namespace != "team-b" ||
		!slices.Equal(grants[1].Verbs, []string{"get", "list", "watch", "create"}) ||
		grants[0].Monitored || grants[1].Monitored {
		t.Errorf("CLOOP_K8S_GRANTS = %+v", grants)
	}

	// Nothing about the document is a variable's: the cluster tokens are in
	// the file and nowhere in the environment.
	for k, v := range env {
		if strings.Contains(v, alphaToken) || strings.Contains(v, betaToken) {
			t.Errorf("%s carries a cluster token", k)
		}
	}
}

// TestOneClusterGrantedTwice: the same kubeconfig granted twice — another
// namespace, another verb — renders two contexts that differ by a suffix, each
// pinned to its own grant's namespace.
func TestOneClusterGrantedTwice(t *testing.T) {
	kc := secretbrokertest.Kubeconfig(alphaServer, alphaToken, "default")
	_, lease := secretbrokertest.KubeLease(t, nil,
		secretbrokertest.KubeGrant{Secret: "prod.kube", Kubeconfig: kc,
			Constraints: secretbroker.Constraints{Namespaces: []string{"web", "worker"}}},
		secretbrokertest.KubeGrant{Secret: "prod.kube", Kubeconfig: kc,
			Constraints: secretbroker.Constraints{Namespaces: []string{"api"}}},
	)
	d, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer d.Close()
	if err := executor.ValidateSecretFiles(secretbroker.ExecutorSecretFiles(lease.ID, d.Files())); err != nil {
		t.Fatalf("a cluster granted twice is refused: %v", err)
	}
	doc := parseMerged(t, kubeconfigFiles(d.Files())[0].Content)
	// The one-namespace grant is the narrower, so it names first.
	if got := doc.contextNames(); !slices.Equal(got, []string{"prod-kube", "prod-kube-2"}) {
		t.Fatalf("contexts = %v, want the sanitised secret name and a suffix", got)
	}
	if doc.CurrentContext != "prod-kube" {
		t.Errorf("current-context = %q", doc.CurrentContext)
	}
	if got := doc.reach(t, "prod-kube"); got != (reach{alphaServer, alphaToken, "api"}) {
		t.Errorf("prod-kube leads to %+v", got)
	}
	if got := doc.reach(t, "prod-kube-2"); got != (reach{alphaServer, alphaToken, "web"}) {
		t.Errorf("prod-kube-2 leads to %+v", got)
	}
	env := envMap(d.Env())
	if env["CLOOP_K8S_NAMESPACE"] != "api" || env["CLOOP_K8S_ALLOWED_NAMESPACES"] != "api" {
		t.Errorf("single-grant variables %q / %q, want the current-context grant's",
			env["CLOOP_K8S_NAMESPACE"], env["CLOOP_K8S_ALLOWED_NAMESPACES"])
	}
}

// TestMonitoredAndUnmonitoredGrantsMerge: a grant the monitor holds is an entry
// pointing at the monitor with a session token, one it declined is the
// minimised document's own — and only the second's credential makes the
// document a thing withdrawing that grant must take.
func TestMonitoredAndUnmonitoredGrantsMerge(t *testing.T) {
	guard := &secretbrokertest.KubeGuard{BaseURL: monitorURL, Decline: map[string]bool{"beta-kube": true}}
	b, lease := secretbrokertest.KubeLease(t, guard, alphaBeta()...)
	sessions := guard.Sessions()
	if len(sessions) != 1 || sessions[0].Request.SecretName != "alpha-kube" {
		t.Fatalf("the monitor minted %+v, want alpha's session alone", sessions)
	}
	session := sessions[0]

	d, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer d.Close()
	kc := kubeconfigFiles(d.Files())
	if len(kc) != 1 {
		t.Fatalf("got %d kubeconfig files", len(kc))
	}
	doc := parseMerged(t, kc[0].Content)
	if got := doc.reach(t, "alpha-kube"); got != (reach{monitorURL, session.Token, "team-a"}) {
		t.Errorf("the monitored context leads to %+v, want the monitor with its session", got)
	}
	if got := doc.reach(t, "beta-kube"); got != (reach{betaServer, betaToken, "team-b"}) {
		t.Errorf("the unmonitored context leads to %+v", got)
	}
	if bytes.Contains(kc[0].Content, []byte(alphaToken)) {
		t.Error("the monitored grant's cluster credential reached the document")
	}

	env := envMap(d.Env())
	if env[secretbroker.KubeGuardSessionEnvKey] != session.ID || env[secretbroker.KubeGuardSessionsEnvKey] != session.ID {
		t.Errorf("session variables %q / %q, want %s", env[secretbroker.KubeGuardSessionEnvKey],
			env[secretbroker.KubeGuardSessionsEnvKey], session.ID)
	}
	var grants []secretbroker.KubeGrantDescription
	if err := json.Unmarshal([]byte(env[secretbroker.KubeGrantsEnvKey]), &grants); err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 || !grants[0].Monitored || grants[0].Session != session.ID || grants[1].Monitored ||
		grants[1].Session != "" {
		t.Errorf("CLOOP_K8S_GRANTS = %+v", grants)
	}

	// Attribution: the document is beta's, whose credential is in it; alpha's
	// binding names nothing — its withdrawal is the closing of its session.
	alpha, beta := grantOf(t, lease, "alpha-kube", 0), grantOf(t, lease, "beta-kube", 0)
	path := filepath.Join(d.Dir, "kubeconfig")
	if ab := bindingOf(t, d.Bindings(), alpha); len(ab.Files) != 0 || len(ab.EnvKeys) != 0 {
		t.Errorf("the monitored grant's binding names %v / %v", ab.Files, ab.EnvKeys)
	}
	if bb := bindingOf(t, d.Bindings(), beta); !slices.Equal(bb.Files, []string{path}) ||
		!slices.Equal(bb.EnvKeys, []string{"KUBECONFIG"}) {
		t.Errorf("the unmonitored grant's binding names %v / %v, want the document", bb.Files, bb.EnvKeys)
	}
	if got := secretbroker.ExecutorSecretFiles(lease.ID, d.Files()); len(got) != 1 || got[0].GrantID != beta {
		t.Errorf("the document is attributed to %+v, want beta's grant", got)
	}

	// A restore re-derives the session's cluster credential from the grant: the
	// minimised document under its own names, exactly what the monitor was
	// given — the merge renamed nothing it holds.
	upstream, err := b.KubeconfigUpstream(lease.ID, alpha)
	if err != nil {
		t.Fatalf("KubeconfigUpstream: %v", err)
	}
	if !bytes.Equal(upstream, session.Request.Kubeconfig) {
		t.Errorf("a restore would re-derive\n%s\nbut the monitor was given\n%s", upstream, session.Request.Kubeconfig)
	}
	if !bytes.Contains(upstream, []byte("kubernetes-admin@kubernetes")) {
		t.Errorf("the monitor was handed a renamed document:\n%s", upstream)
	}
}

// TestWithdrawingOneKubeconfigGrant is Task 20403's take-back on a merged
// document: a monitored grant's withdrawal leaves the document — its session
// closing is what takes its access — unless it is the grant the document
// belongs to; an unmonitored grant's takes the document, since its cluster
// credential is in it.
func TestWithdrawingOneKubeconfigGrant(t *testing.T) {
	cases := []struct {
		name    string
		decline map[string]bool
		// withdraw is the grant taken back, by secret; stays reports whether
		// the document survives it.
		withdraw string
		stays    bool
	}{
		{"monitored, not the one the document belongs to", nil, "beta-kube", true},
		{"monitored, the narrowest, which the document belongs to", nil, "alpha-kube", false},
		{"monitored beside an unmonitored grant", map[string]bool{"beta-kube": true}, "alpha-kube", true},
		{"unmonitored beside a monitored grant", map[string]bool{"beta-kube": true}, "beta-kube", false},
		{"unmonitored, not the narrowest", map[string]bool{"alpha-kube": true, "beta-kube": true}, "beta-kube", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			guard := &secretbrokertest.KubeGuard{BaseURL: monitorURL, Decline: c.decline}
			_, lease := secretbrokertest.KubeLease(t, guard, alphaBeta()...)
			grant := grantOf(t, lease, c.withdraw, 0)

			// On the hub's own filesystem.
			dir, err := secretbroker.NewLeaseDirPath(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			m, err := lease.MaterializeAt(dir)
			if err != nil {
				t.Fatalf("MaterializeAt: %v", err)
			}
			defer m.Close()
			path := envMap(m.Env())["KUBECONFIG"]
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("the merged kubeconfig was not written: %v", err)
			}
			if _, err := m.Withdraw(grant); err != nil {
				t.Fatalf("Withdraw: %v", err)
			}
			if _, err := os.Stat(path); (err == nil) != c.stays {
				t.Errorf("after withdrawing %s the document exists = %v, want %v", c.withdraw, err == nil, c.stays)
			}

			// And in what the hub holds to deliver.
			d, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.Withdraw(grant)
			if got := len(kubeconfigFiles(d.Files())) == 1; got != c.stays {
				t.Errorf("after withdrawing %s the delivery still carries the document = %v, want %v",
					c.withdraw, got, c.stays)
			}
		})
	}
}

// TestOneKubeconfigGrantRendersAsBefore: a lease with one kubeconfig grant is
// untouched — its document byte for byte, its variables and its binding as
// they were before the merge existed.
func TestOneKubeconfigGrantRendersAsBefore(t *testing.T) {
	_, lease := secretbrokertest.KubeLease(t, nil, alphaBeta()[0])
	d, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	kc := kubeconfigFiles(d.Files())
	if len(kc) != 1 || !bytes.Equal(kc[0].Content, lease.Materials[0].Files[0].Content) {
		t.Fatalf("one grant's document was rewritten:\n%s", kc[0].Content)
	}
	if !bytes.Contains(kc[0].Content, []byte("kubernetes-admin@kubernetes")) {
		t.Error("one grant's context was renamed")
	}
	env := envMap(d.Env())
	for _, k := range []string{secretbroker.KubeContextsEnvKey, secretbroker.KubeGrantsEnvKey, secretbroker.KubeGuardSessionsEnvKey} {
		if _, ok := env[k]; ok {
			t.Errorf("%s set for one grant", k)
		}
	}
	if env["CLOOP_K8S_NAMESPACE"] != "team-a" || env["CLOOP_K8S_VERBS"] != "get,list,watch" {
		t.Errorf("single-grant variables changed: %v", env)
	}
	b := bindingOf(t, d.Bindings(), lease.Materials[0].GrantID)
	want := []string{"CLOOP_K8S_ALLOWED_NAMESPACES", "CLOOP_K8S_NAMESPACE", "CLOOP_K8S_VERBS", "KUBECONFIG"}
	if !slices.Equal(b.EnvKeys, want) || len(b.Files) != 1 {
		t.Errorf("binding = %v / %v, want %v and the document", b.EnvKeys, b.Files, want)
	}
}

// TestTheMergedKubeconfigIsAFunctionOfTheGrants: the same grants render the
// same document and variables whatever order their materials arrive in — which
// is what lets the hub process that adopts a run derive the document its
// dispatcher delivered.
func TestTheMergedKubeconfigIsAFunctionOfTheGrants(t *testing.T) {
	grants := append(alphaBeta(), secretbrokertest.KubeGrant{Secret: "alpha-kube",
		Kubeconfig:  secretbrokertest.Kubeconfig(alphaServer, alphaToken, "default"),
		Constraints: secretbroker.Constraints{Namespaces: []string{"team-c"}}})
	guard := &secretbrokertest.KubeGuard{BaseURL: monitorURL, Decline: map[string]bool{"beta-kube": true}}
	_, lease := secretbrokertest.KubeLease(t, guard, grants...)
	render := func(l *secretbroker.Lease) ([]byte, []string) {
		d, err := l.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		return kubeconfigFiles(d.Files())[0].Content, d.Env()
	}
	doc, env := render(lease)
	for _, order := range [][]int{{2, 1, 0}, {1, 0, 2}, {0, 2, 1}} {
		permuted := *lease
		permuted.Materials = nil
		for _, i := range order {
			permuted.Materials = append(permuted.Materials, lease.Materials[i])
		}
		gotDoc, gotEnv := render(&permuted)
		if !bytes.Equal(gotDoc, doc) || !slices.Equal(gotEnv, env) {
			t.Fatalf("materials in order %v render\n%s\nwhere the lease renders\n%s", order, gotDoc, doc)
		}
	}
	// Three grants, two of one secret: suffixed in grant order, never by
	// arrival.
	if got := parseMerged(t, doc).contextNames(); !slices.Equal(got, []string{"alpha-kube", "alpha-kube-2", "beta-kube"}) {
		t.Errorf("contexts = %v", got)
	}
}

// TestADanglingReferenceNeverReachesAnotherGrantsCredential: a context naming a
// user its own document does not define names nothing in the merged one either —
// in particular not another grant's user that happened to share the name.
func TestADanglingReferenceNeverReachesAnotherGrantsCredential(t *testing.T) {
	dangling := []byte(`apiVersion: v1
kind: Config
current-context: kubernetes-admin@kubernetes
clusters:
- name: kubernetes
  cluster:
    server: ` + alphaServer + `
contexts:
- name: kubernetes-admin@kubernetes
  context:
    cluster: kubernetes
    user: kubernetes-admin
users: []
`)
	grants := alphaBeta()
	grants[0].Kubeconfig = dangling
	_, lease := secretbrokertest.KubeLease(t, nil, grants...)
	d, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	doc := parseMerged(t, kubeconfigFiles(d.Files())[0].Content)
	if got := doc.reach(t, "alpha-kube"); got.token != "" {
		t.Fatalf("alpha's undefined user resolves to a credential (%q)", got.token)
	}
	if got := doc.reach(t, "beta-kube"); got.token != betaToken {
		t.Errorf("beta's own user resolves to %q", got.token)
	}
}

// TestKubectlReadsTheMergedDocument runs the real kubectl against a merged
// document on disk: it is the client the document exists for, and the one
// whose rules about names, current-context and duplicate entries decide
// whether a merge works.
func TestKubectlReadsTheMergedDocument(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("kubectl is not on PATH")
	}
	guard := &secretbrokertest.KubeGuard{BaseURL: monitorURL, Decline: map[string]bool{"beta-kube": true}}
	_, lease := secretbrokertest.KubeLease(t, guard, alphaBeta()...)
	dir, err := secretbroker.NewLeaseDirPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m, err := lease.MaterializeAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	kubeconfig := envMap(m.Env())["KUBECONFIG"]
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(kubectl, append([]string{"--kubeconfig", kubeconfig}, args...)...)
		cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := run("config", "current-context"); got != "alpha-kube" {
		t.Errorf("kubectl's current-context = %q", got)
	}
	if got := run("config", "get-contexts", "-o", "name"); got != "alpha-kube\nbeta-kube" {
		t.Errorf("kubectl's contexts = %q", got)
	}
	for _, c := range []struct{ context, server, token, namespace string }{
		{"alpha-kube", monitorURL, guard.Sessions()[0].Token, "team-a"},
		{"beta-kube", betaServer, betaToken, "team-b"},
	} {
		got := run("config", "view", "--raw", "--minify", "--context", c.context, "-o",
			"jsonpath={.clusters[0].cluster.server} {.users[0].user.token} {.contexts[0].context.namespace}")
		if want := c.server + " " + c.token + " " + c.namespace; got != want {
			t.Errorf("kubectl --context %s resolves to %q, want %q", c.context, got, want)
		}
	}
}

// TestARefusedMaterialIsNamedOnTheLease is the second half of Task 20413: a
// grant whose secret stands and whose material the broker could not build — a
// monitor that refused it, a payload that does not parse, constraints nothing
// in the document satisfies — is skipped with an audit row, as it always was,
// and now also named on the lease, so the dispatcher can tell the project its
// run goes without it. The other grants are still delivered.
func TestARefusedMaterialIsNamedOnTheLease(t *testing.T) {
	guard := &secretbrokertest.KubeGuard{BaseURL: monitorURL,
		Refuse: map[string]string{"beta-kube": "the monitor cannot hold an exec credential plugin"}}
	grants := append(alphaBeta(),
		secretbrokertest.KubeGrant{Secret: "garbled-kube", Kubeconfig: []byte("{not: [yaml"),
			Constraints: secretbroker.Constraints{Namespaces: []string{"team-c"}}},
		secretbrokertest.KubeGrant{Secret: "elsewhere-kube", Kubeconfig: secretbrokertest.Kubeconfig(betaServer, betaToken, "default"),
			Constraints: secretbroker.Constraints{Contexts: []string{"no-such-context"}}},
	)
	_, lease := secretbrokertest.KubeLease(t, guard, grants...)
	if len(lease.Materials) != 1 || lease.Materials[0].SecretName != "alpha-kube" {
		t.Fatalf("the lease carries %v, want alpha's material still delivered", lease.SecretNames())
	}
	byName := map[string]secretbroker.RefusedCredential{}
	for _, r := range lease.Refused {
		byName[r.SecretName] = r
	}
	for name, want := range map[string]string{
		"beta-kube":      "exec credential plugin",
		"garbled-kube":   "not valid YAML",
		"elsewhere-kube": "no kubeconfig context satisfies",
	} {
		r, ok := byName[name]
		switch {
		case !ok:
			t.Errorf("%s is not named on the lease: %+v", name, lease.Refused)
		case !r.Delivery || r.Kind != secretbroker.KindKubeconfig || r.GrantID == "" || r.SecretID == "":
			t.Errorf("%s refused as %+v", name, r)
		case !strings.Contains(r.Reason, want):
			t.Errorf("%s refused for %q, want it to say %q", name, r.Reason, want)
		}
	}
	if r := byName["beta-kube"]; !strings.Contains(r.Reason, "credential guard unavailable") {
		t.Errorf("a monitor's refusal reads %q", r.Reason)
	}
	if len(lease.Refused) != 3 {
		t.Errorf("refused = %+v, want the three", lease.Refused)
	}
}

// TestAWithheldGrantIsNotARefusal: a grant the requester itself asked to go
// without (Requester.Withhold, Task 20379) is the dispatcher's own decision,
// and is not handed back to it as news.
func TestAWithheldGrantIsNotARefusal(t *testing.T) {
	b, lease := secretbrokertest.KubeLease(t, nil, alphaBeta()...)
	beta := grantOf(t, lease, "beta-kube", 0)
	again, err := b.LeaseFor(t.Context(), secretbroker.Requester{
		ExecutorID: secretbrokertest.KubeExecutor, ProjectID: secretbrokertest.KubeProject,
		Withhold: map[string]string{beta: "withheld by the test"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Materials) != 1 || len(again.Refused) != 0 {
		t.Fatalf("materials %v, refused %+v", again.SecretNames(), again.Refused)
	}
}

// TestTheNarrowestGrantIsCurrentContext pins the order the merge takes grants
// in, each rule on its own: the narrower grant is named "zeta", so a merge that
// fell back to ordering by name would put it last.
func TestTheNarrowestGrantIsCurrentContext(t *testing.T) {
	named := func(ns string) secretbroker.Constraints {
		return secretbroker.Constraints{Namespaces: []string{ns}}
	}
	cases := []struct {
		name          string
		narrow, broad secretbroker.Constraints
		// The kubeconfig's own namespace, which a pattern must admit.
		narrowNS, broadNS string
	}{
		{"every namespace named before a pattern",
			named("team-a"), named("team-*"), "default", "team-b"},
		{"a pattern before cluster-wide",
			named("team-*"), secretbroker.Constraints{Contexts: []string{"kubernetes-admin*"}}, "team-a", "default"},
		{"read-only before read-write",
			named("team-a"), secretbroker.Constraints{Namespaces: []string{"team-b"}, Verbs: []string{"get", "delete"}},
			"default", "default"},
		{"fewer namespaces first",
			named("team-a"), secretbroker.Constraints{Namespaces: []string{"team-b", "team-c"}}, "default", "default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, lease := secretbrokertest.KubeLease(t, nil,
				secretbrokertest.KubeGrant{Secret: "alpha-kube", Constraints: c.broad,
					Kubeconfig: secretbrokertest.Kubeconfig(alphaServer, alphaToken, c.broadNS)},
				secretbrokertest.KubeGrant{Secret: "zeta-kube", Constraints: c.narrow,
					Kubeconfig: secretbrokertest.Kubeconfig(betaServer, betaToken, c.narrowNS)},
			)
			if len(lease.Materials) != 2 {
				t.Fatalf("lease carries %v (refused %+v)", lease.SecretNames(), lease.Refused)
			}
			d, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			doc := parseMerged(t, kubeconfigFiles(d.Files())[0].Content)
			if doc.CurrentContext != "zeta-kube" {
				t.Errorf("current-context = %q, want the narrower grant's", doc.CurrentContext)
			}
			if got := envMap(d.Env())[secretbroker.KubeContextsEnvKey]; got != "zeta-kube,alpha-kube" {
				t.Errorf("CLOOP_K8S_CONTEXTS = %q, want the narrower grant first", got)
			}
		})
	}
}

// TestAHubMaterialisedMergeIsAFileTheSpecNeeds is the host delivery path: the
// lease written to the hub's own filesystem, the spec carrying only bindings
// and the environment. It validates, KUBECONFIG names the merged document on
// disk, and — with every grant monitored, so no grant's credential is in the
// document — some binding still names the file, or the spec would not say the
// workload needs one (executor.Spec.NeedsSecretFiles) and placement would not
// require an executor that can receive it.
func TestAHubMaterialisedMergeIsAFileTheSpecNeeds(t *testing.T) {
	guard := &secretbrokertest.KubeGuard{BaseURL: monitorURL}
	_, lease := secretbrokertest.KubeLease(t, guard, alphaBeta()...)
	dir, err := secretbroker.NewLeaseDirPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m, err := lease.MaterializeAt(dir)
	if err != nil {
		t.Fatalf("MaterializeAt: %v", err)
	}
	defer m.Close()
	spec := executor.Spec{Argv: []string{"cloop", "run"}, WorkDir: t.TempDir(), Env: m.Env(),
		Secrets: secretbroker.ExecutorBindings(lease.ID, lease.ExpiresAt, m.Bindings())}
	if err := spec.Validate(); err != nil {
		t.Fatalf("the hub-materialised merge is refused: %v", err)
	}
	if !spec.NeedsSecretFiles() {
		t.Error("no binding names the merged kubeconfig, so the spec does not say the workload needs a file")
	}
	raw, err := os.ReadFile(envMap(m.Env())["KUBECONFIG"])
	if err != nil {
		t.Fatalf("KUBECONFIG names nothing on the hub: %v", err)
	}
	if got := parseMerged(t, raw).contextNames(); !slices.Equal(got, []string{"alpha-kube", "beta-kube"}) {
		t.Errorf("contexts on disk = %v", got)
	}
}
