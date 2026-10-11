package ui

// Two kubeconfig grants in one run's lease (Task 20413), through the hub's own
// Kubernetes monitor: one document reaches the workload, each of its contexts
// presents its own grant's session and reaches that grant's namespace and no
// other, a hub process that adopts the run restores both sessions under the
// tokens the document holds, and taking one grant back leaves the other
// working. And the other half of the task: a kubeconfig the monitor refuses is
// named in the project's event history, on every run that went without it.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// grantKubeTwice grants the rig's kubeconfig a second time, for namespace web
// with a write: the same cluster granted twice. The rig's own grant (namespace
// app, read-only) is the narrower, so its context is current-context.
func grantKubeTwice(t *testing.T, r *restoreRig) secretbroker.Grant {
	t.Helper()
	broker, closeDB, err := openUIBroker(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	g, err := broker.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: r.kubeGrant.SecretID,
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: r.ex.ID()},
		Constraints: secretbroker.Constraints{Namespaces: []string{"web"},
			Verbs: []string{"get", "list", "watch", "create"}},
		TTL: 24 * time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return g
}

// contextTokens reads the one kubeconfig a lease delivered and returns the
// bearer token behind each context, and its current-context.
func contextTokens(t *testing.T, sl *secretLease) (map[string]string, string) {
	t.Helper()
	var docs [][]byte
	for _, f := range sl.SecretFiles() {
		if strings.HasPrefix(f.Name, "kubeconfig") {
			docs = append(docs, f.Content)
		}
	}
	if len(docs) != 1 {
		t.Fatalf("the lease delivered %d kubeconfig files, want one", len(docs))
	}
	var doc struct {
		Current  string `yaml:"current-context"`
		Contexts []struct {
			Name    string `yaml:"name"`
			Context struct {
				User string `yaml:"user"`
			} `yaml:"context"`
		} `yaml:"contexts"`
		Users []struct {
			Name string `yaml:"name"`
			User struct {
				Token string `yaml:"token"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(docs[0], &doc); err != nil {
		t.Fatalf("delivered kubeconfig: %v", err)
	}
	out := map[string]string{}
	for _, c := range doc.Contexts {
		for _, u := range doc.Users {
			if u.Name == c.Context.User {
				out[c.Name] = u.User.Token
			}
		}
	}
	return out, doc.Current
}

// reachesOnly asserts that token reaches the cluster in namespace own and is
// refused in every one of others, through the monitor.
func reachesOnly(t *testing.T, r *restoreRig, when, token, own string, others ...string) {
	t.Helper()
	d := dispatched{kubeToken: token}
	if code := r.kube(d, "/api/v1/namespaces/"+own+"/pods"); code != http.StatusOK {
		t.Errorf("%s: the session for %s answered %d in its own namespace", when, own, code)
	}
	for _, ns := range others {
		if code := r.kube(d, "/api/v1/namespaces/"+ns+"/pods"); code != http.StatusForbidden {
			t.Errorf("%s: the session for %s answered %d in %s, want 403 from the monitor", when, own, code, ns)
		}
	}
}

// TestTwoKubeconfigGrantsThroughTheMonitorSurviveAdoption is the task on the
// hub's real monitor: one document with a context per grant, each confined to
// its own grant's namespace, and both sessions restored by the process that
// adopts the run — which re-derives each from its grant under the names the
// monitor was given, not the merged document's.
func TestTwoKubeconfigGrantsThroughTheMonitorSurviveAdoption(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	r := newRestoreRig(t)
	second := grantKubeTwice(t, r)

	sl := acquireSecretLease(r.dir, r.dir, r.ex, "run_two_kube", nil)
	if sl == nil {
		t.Fatal("no lease was issued")
	}
	stopKeepaliveForTest(sl)
	sl.bindHandle(r.ex.ID(), "h-1")
	// What applyLease hands a driver, validated as every driver validates it.
	spec := executor.Spec{Argv: []string{"cloop", "run"}, WorkDir: r.dir, Env: sl.Env(),
		Secrets: sl.Bindings(), SecretFiles: sl.SecretFiles()}
	if err := spec.Validate(); err != nil {
		t.Fatalf("the merged lease is refused: %v", err)
	}
	tokens, current := contextTokens(t, sl)
	appToken, webToken := tokens["restore-kube"], tokens["restore-kube-2"]
	if appToken == "" || webToken == "" || appToken == webToken {
		t.Fatalf("contexts %v: want restore-kube and restore-kube-2, each with its own session", tokens)
	}
	if current != "restore-kube" {
		t.Errorf("current-context = %q, want the narrower grant's", current)
	}
	reachesOnly(t, r, "at dispatch", appToken, "app", "web", "kube-system")
	reachesOnly(t, r, "at dispatch", webToken, "web", "app", "kube-system")

	r.clock.Advance(2 * time.Minute)
	r.restart(dispatched{lease: sl}, "hub_new")
	taken := r.takeOver(dispatched{lease: sl})
	if taken == nil {
		t.Fatal("the restarted process does not hold the run's lease")
	}
	defer taken.Close()
	for name, tok := range tokens {
		id, _, _ := strings.Cut(tok, ".")
		if !activeKubeGuard().reg.Known(id) {
			t.Fatalf("the session behind %s was not restored", name)
		}
	}
	// The document the workload already holds keeps working, context by
	// context.
	reachesOnly(t, r, "after the adoption", appToken, "app", "web")
	reachesOnly(t, r, "after the adoption", webToken, "web", "app")

	// Taking the second grant back closes its session alone.
	if err := taken.withdrawGrant(context.Background(), second.ID, "test"); err != nil {
		t.Fatalf("withdrawGrant: %v", err)
	}
	if code := r.kube(dispatched{kubeToken: webToken}, "/api/v1/namespaces/web/pods"); code == http.StatusOK {
		t.Error("the withdrawn grant's session still reaches its namespace")
	}
	reachesOnly(t, r, "after the other grant was taken back", appToken, "app", "web")
}

// TestTakingOneKubeconfigGrantBackLeavesTheDocument: on the dispatching hub,
// withdrawing the broader of two monitored grants closes its session and keeps
// the document the other grant reads; withdrawing the grant the document
// belongs to takes the document from what the hub would deliver again.
func TestTakingOneKubeconfigGrantBackLeavesTheDocument(t *testing.T) {
	r := newRestoreRig(t)
	second := grantKubeTwice(t, r)
	sl := acquireSecretLease(r.dir, r.dir, r.ex, "run_two_kube", nil)
	if sl == nil {
		t.Fatal("no lease was issued")
	}
	stopKeepaliveForTest(sl)
	defer sl.Close()
	tokens, _ := contextTokens(t, sl)

	if err := sl.withdrawGrant(context.Background(), second.ID, "test"); err != nil {
		t.Fatalf("withdrawGrant: %v", err)
	}
	if code := r.kube(dispatched{kubeToken: tokens["restore-kube-2"]}, "/api/v1/namespaces/web/pods"); code == http.StatusOK {
		t.Error("the withdrawn grant's session still reaches its namespace")
	}
	reachesOnly(t, r, "after one grant was taken back", tokens["restore-kube"], "app", "web")
	if left, _ := contextTokens(t, sl); left["restore-kube"] != tokens["restore-kube"] {
		t.Fatal("taking the broader grant back changed the document the narrower one reads")
	}

	if err := sl.withdrawGrant(context.Background(), r.kubeGrant.ID, "test"); err != nil {
		t.Fatalf("withdrawGrant: %v", err)
	}
	for _, f := range sl.SecretFiles() {
		if strings.HasPrefix(f.Name, "kubeconfig") {
			t.Fatal("the document stayed with the hub after the grant it belongs to was taken back")
		}
	}
}

// TestARefusedKubeconfigIsInTheRunsEventHistory: the monitor refuses a
// kubeconfig whose user runs an exec credential plugin. The lease is still
// issued with the project's other grants, and every run that goes without it
// says so in the project's event history, naming the run.
func TestARefusedKubeconfigIsInTheRunsEventHistory(t *testing.T) {
	r := newRestoreRig(t)
	broker, closeDB, err := openUIBroker(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	execKube, err := broker.Mint(context.Background(), secretbroker.MintRequest{
		Name: "aks-kube", Kind: secretbroker.KindKubeconfig, Actor: "test", Payload: []byte(`apiVersion: v1
kind: Config
current-context: aks
clusters:
- name: aks
  cluster:
    server: https://aks.example.test
contexts:
- name: aks
  context:
    cluster: aks
    user: aks
    namespace: app
users:
- name: aks
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubelogin
      args: [get-token]
`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: execKube.ID, Subject: secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: r.ex.ID()},
		Constraints: secretbroker.Constraints{Namespaces: []string{"app"}}, TTL: time.Hour, Actor: "test",
	}); err != nil {
		t.Fatal(err)
	}
	closeDB()

	for _, run := range []string{"run_first", "run_second"} {
		sl := acquireSecretLease(r.dir, r.dir, r.ex, run, nil)
		if sl == nil {
			t.Fatalf("%s: no lease was issued; the refusal must not cost the project its other grants", run)
		}
		stopKeepaliveForTest(sl)
		if got := sl.lease.SecretNames(); strings.Contains(strings.Join(got, ","), "aks-kube") {
			t.Fatalf("%s: the refused kubeconfig is in the lease: %v", run, got)
		}
		sl.Close()
	}

	rows, _, err := state.ListEvents(r.dir, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	var found []statedb.EventRow
	for _, row := range rows {
		if row.Type == state.EventCredentialRefused && strings.Contains(row.Message, `"aks-kube"`) {
			found = append(found, row)
		}
	}
	if len(found) != 2 {
		t.Fatalf("got %d credential_refused rows for aks-kube, want one per run: %+v", len(found), found)
	}
	for _, row := range found {
		if !strings.Contains(row.Message, "exec credential plugin") || !strings.Contains(row.Message, "could not deliver") {
			t.Errorf("the row does not say why: %q", row.Message)
		}
		if !strings.Contains(row.Details, `"delivery":true`) || !strings.Contains(row.Details, `"run_id":"run_`) {
			t.Errorf("the row does not name its run: %s", row.Details)
		}
	}
}
