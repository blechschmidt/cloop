package cmd

// `cloop executor pool` (Task 20486) against a hub with single sign-on in this
// process: the one-step create shows its credential once, the list and show
// say what the dashboard says, cordon, rotation's two steps and revoke act —
// and a non-administrator, and an administrator's terminal session approved
// too long ago, are refused the way the dashboard refuses them.

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/hubclient"
)

// runPoolCLI runs `cloop executor pool <args>` as a terminal would: through
// the root command, its flags parsed from args and reset afterwards.
func runPoolCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetFlags(executorPoolCmd)
	t.Cleanup(func() { resetFlags(executorPoolCmd) })
	var out bytes.Buffer
	rootCmd.SetArgs(append([]string{"executor", "pool"}, args...))
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, err := rootCmd.ExecuteContextC(ctx)
	return out.String(), err
}

func TestExecutorPoolCommands(t *testing.T) {
	w := newRemoteWorld(t)
	w.as(t, rootEmail)

	out, err := runPoolCLI(t, "create", "gpu", "--max-runners", "3", "--label", "gpu=a100",
		"--audience", "group:ml-team", "--persistence", "--size", "40Gi", "--json")
	if err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	var created hubclient.CreatedPool
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("create --json is not JSON: %v\n%s", err, out)
	}
	if !strings.HasPrefix(created.Token, executorpool.CredentialPrefix) || created.Credential == nil ||
		created.Pool.Name != "gpu" || len(created.Audience) != 1 || created.Install == nil {
		t.Fatalf("the create's answer: %+v", created)
	}
	// This hub is served over plain HTTP in the test, so it says why there is
	// no install command and shows the credential all the same.
	if created.Install.Command != "" || !strings.Contains(created.Install.Unavailable, "HTTPS") {
		t.Fatalf("the install block over plaintext: %+v", created.Install)
	}

	out, err = runPoolCLI(t, "create", "cpu", "--max-runners", "2")
	if err != nil {
		t.Fatalf("create (text): %v\n%s", err, out)
	}
	for _, want := range []string{"Created executor pool cpu", "shown once", executorpool.CredentialPrefix,
		"It has no access list", "cloop executor pool show cpu"} {
		if !strings.Contains(out, want) {
			t.Errorf("create's output lacks %q:\n%s", want, out)
		}
	}
	if _, err := runPoolCLI(t, "create", "bad", "--max-runners", "1", "--audience", "planet:mars"); err == nil ||
		!strings.Contains(err.Error(), "--audience") {
		t.Fatalf("a bad --audience: %v", err)
	}

	out, err = runPoolCLI(t, "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	for _, want := range []string{"NAME", "WAITING", "CONTROLLER", "gpu", "cpu", "none yet", "never"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, created.Token) {
		t.Fatal("the list shows a credential")
	}

	out, err = runPoolCLI(t, "cordon", "gpu", "--reason", "node upgrade")
	if err != nil || !strings.Contains(out, "Cordoned executor pool gpu") {
		t.Fatalf("cordon: %v\n%s", err, out)
	}
	out, err = runPoolCLI(t, "show", "gpu")
	if err != nil {
		t.Fatalf("show: %v\n%s", err, out)
	}
	for _, want := range []string{"Executor pool gpu", "cordoned", "node upgrade", "group:ml-team", "gpu=a100",
		"Controller credentials:", created.Credential.ID} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if out, err := runPoolCLI(t, "uncordon", "gpu"); err != nil || !strings.Contains(out, "Uncordoned") {
		t.Fatalf("uncordon: %v\n%s", err, out)
	}

	// Rotation, in two steps: a new credential, then the old ones revoked —
	// but not before a controller used the new one.
	out, err = runPoolCLI(t, "rotate-credential", "gpu")
	if err != nil {
		t.Fatalf("rotate-credential: %v\n%s", err, out)
	}
	for _, want := range []string{"New controller credential", executorpool.CredentialPrefix,
		"kubectl -n cloop-gpu create secret generic gpu-pool-credential", created.Credential.ID,
		"rotate-credential gpu --finish"} {
		if !strings.Contains(out, want) {
			t.Errorf("rotate-credential lacks %q:\n%s", want, out)
		}
	}
	if _, err := runPoolCLI(t, "rotate-credential", "gpu", "--finish"); err == nil ||
		!strings.Contains(err.Error(), "has not moved to the newest credential") {
		t.Fatalf("--finish before the new credential was used: %v", err)
	}
	out, err = runPoolCLI(t, "rotate-credential", "gpu", "--finish", "--force")
	if err != nil || !strings.Contains(out, "Revoked credential "+created.Credential.ID) {
		t.Fatalf("--finish --force: %v\n%s", err, out)
	}
	c, err := hubClientFor(w.hub.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.ExecutorPool(t.Context(), created.Pool.ID)
	if err != nil {
		t.Fatal(err)
	}
	live := 0
	for _, cr := range d.Credentials {
		if !cr.Revoked() {
			live++
		}
	}
	if live != 1 || len(d.Credentials) != 2 {
		t.Fatalf("after the rotation: %d credentials, %d live; want 2 and 1", len(d.Credentials), live)
	}

	out, err = runPoolCLI(t, "update", "gpu", "--max-runners", "5")
	if err != nil || !strings.Contains(out, "may now have 5 runners at once (it was 3)") ||
		!strings.Contains(out, "--set pool.maxRunners=5") {
		t.Fatalf("update: %v\n%s", err, out)
	}
	if p, err := c.ResolveExecutorPool(t.Context(), "gpu"); err != nil || p.MaxRunners != 5 || p.Labels["gpu"] != "a100" {
		t.Fatalf("after update: %+v %v (the rest of the definition must stay)", p, err)
	}
	if _, err := runPoolCLI(t, "revoke", "gpu"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("revoke without --yes off a terminal: %v", err)
	}
	if out, err := runPoolCLI(t, "revoke", "gpu", "--yes"); err != nil || !strings.Contains(out, "Revoked executor pool gpu") {
		t.Fatalf("revoke --yes: %v\n%s", err, out)
	}
	if _, err := runPoolCLI(t, "show", "gpu"); err == nil {
		t.Fatal("a revoked pool is still found by its name")
	}
}

func TestExecutorPoolCommandsAreAnAdministrators(t *testing.T) {
	w := newRemoteWorld(t)
	w.as(t, alexEmail, ssohubtest.GroupMaintainers)
	_, err := runPoolCLI(t, "create", "mine", "--max-runners", "1")
	if err == nil {
		t.Fatal("a maintainer created an executor pool")
	}
	if ae, ok := hubclient.AsAPIError(err); !ok || ae.Status != 403 || !strings.Contains(err.Error(), "executor.manage") {
		t.Fatalf("a maintainer's refusal: %v", err)
	}
	if _, err := runPoolCLI(t, "list"); err == nil {
		t.Fatal("a maintainer listed executor pools")
	}
}

func TestExecutorPoolChangesAskAStaleTerminalToSignInAgain(t *testing.T) {
	clk := &movableClock{}
	credPath := credentialHome(t)
	hub := ssohubtest.Start(t, ssohubtest.Options{SelfExe: cliSelfExe(t), AdminEmails: []string{rootEmail}, Clock: clk.now})
	w := &remoteWorld{hub: hub, credPath: credPath}
	w.as(t, rootEmail)
	if out, err := runPoolCLI(t, "create", "late", "--max-runners", "1"); err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	clk.advance(3 * time.Hour)
	if out, err := runPoolCLI(t, "list"); err != nil {
		t.Fatalf("list on a stale session: %v\n%s (reads ask nothing)", err, out)
	}
	_, err := runPoolCLI(t, "cordon", "late")
	if err == nil || !hubclient.IsReauthRequired(err) || !strings.Contains(err.Error(), "cloop login") {
		t.Fatalf("cordon on a stale session: %v", err)
	}
}

// checkRetiring refuses a revocation that would retire a busy runner — one
// the credential started, or one the hub names no credential for.
func TestRotationRefusesToRetireBusyRunners(t *testing.T) {
	old := []hubclient.PoolCredential{{ID: "old"}}
	cases := []struct {
		name    string
		runners []hubclient.PoolRunner
		refuse  bool
	}{
		{"nothing busy", []hubclient.PoolRunner{{State: "idle", CredentialID: "old"}}, false},
		{"busy on the new credential", []hubclient.PoolRunner{{State: "busy", CredentialID: "new"}}, false},
		{"busy on the old credential", []hubclient.PoolRunner{{State: "busy", CredentialID: "old"}}, true},
		{"busy, credential unknown", []hubclient.PoolRunner{{State: "busy"}}, true},
	}
	for _, c := range cases {
		err := checkRetiring(&hubclient.PoolDetail{Runners: c.runners}, old)
		if (err != nil) != c.refuse {
			t.Errorf("%s: %v, refuse %v", c.name, err, c.refuse)
		}
	}
}
