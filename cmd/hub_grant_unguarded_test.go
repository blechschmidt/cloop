package cmd

// `cloop hub grant unguarded` and the acknowledgement in `cloop hub grant list`
// (Task 20420).

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

const unguardedTestKubeconfig = "apiVersion: v1\nkind: Config\ncurrent-context: dev\nclusters:\n- name: k\n  cluster:\n" +
	"    server: https://k8s.example.test\ncontexts:\n- name: dev\n  context:\n    cluster: k\n    user: u\n" +
	"users:\n- name: u\n  user:\n    token: not-a-real-cluster-token\n"

func runGrantUnguarded(t *testing.T, withdraw bool, args ...string) (string, error) {
	t.Helper()
	hubGrantUnguardedWithdrawFlag = withdraw
	t.Cleanup(func() { hubGrantUnguardedWithdrawFlag = false })
	return captureStdout(t, func() error {
		return runHubSub(t, hubGrantUnguardedCmd, func(c *cobra.Command) {
			c.Flags().String("workdir", "", "")
			c.Flags().Bool("json", false, "")
			c.Flags().String("reason", "", "")
			c.Flags().BoolVar(&hubGrantUnguardedWithdrawFlag, "withdraw", withdraw, "")
		}, args...)
	})
}

func runGrantList(t *testing.T, grants bool, args ...string) (string, error) {
	t.Helper()
	hubGrantGrantsFlag = grants
	t.Cleanup(func() { hubGrantGrantsFlag = false })
	return captureStdout(t, func() error {
		return runHubSub(t, hubGrantListCmd, func(c *cobra.Command) {
			c.Flags().String("workdir", "", "")
			c.Flags().Bool("json", false, "")
			c.Flags().BoolVar(&hubGrantGrantsFlag, "grants", grants, "")
		}, args...)
	})
}

func TestHubGrantUnguardedRecordsShowsAndWithdraws(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "hub-grant-unguarded-test")
	dir := hubDir(t)
	broker, closer, err := openHubBroker(dir)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := broker.Mint(context.Background(), secretbroker.MintRequest{Name: "lab-kube",
		Kind: secretbroker.KindKubeconfig, Payload: []byte(unguardedTestKubeconfig), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	g, err := broker.Grant(context.Background(), secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
		Constraints: secretbroker.Constraints{Namespaces: []string{"app"}}, Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	closer()

	// Refused, and said so, before anyone acknowledges it.
	out, err := runGrantList(t, true, "--workdir", dir)
	if err != nil {
		t.Fatalf("list --grants: %v", err)
	}
	if !strings.Contains(out, g.ID) || !strings.Contains(out, "refused: namespaces app and read-only access") {
		t.Fatalf("list --grants does not show the grant refused:\n%s", out)
	}

	if _, err := runGrantUnguarded(t, false, g.ID, "--workdir", dir); err == nil ||
		!strings.Contains(err.Error(), "--reason is required") {
		t.Fatalf("an acknowledgement without --reason: %v", err)
	}
	out, err = runGrantUnguarded(t, false, g.ID, "--workdir", dir, "--reason", "throwaway lab cluster")
	if err != nil {
		t.Fatalf("unguarded: %v\n%s", err, out)
	}
	for _, want := range []string{g.ID, "namespaces app and read-only access", "throwaway lab cluster", "by cli:"} {
		if !strings.Contains(out, want) {
			t.Errorf("unguarded output lacks %q:\n%s", want, out)
		}
	}

	out, err = runGrantList(t, false, "--workdir", dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "delivered without the Kubernetes access monitor (acknowledged)") ||
		!strings.Contains(out, g.ID) || !strings.Contains(out, "throwaway lab cluster") {
		t.Fatalf("list does not show the acknowledgement:\n%s", out)
	}

	if out, err = runGrantUnguarded(t, true, g.ID, "--workdir", dir); err != nil {
		t.Fatalf("withdraw: %v\n%s", err, out)
	}
	broker, closer, err = openHubBroker(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	grants, err := broker.ListGrants(secretbroker.GrantFilter{})
	if err != nil || len(grants) != 1 || grants[0].UnguardedAck.Recorded() {
		t.Fatalf("after --withdraw: %+v, %v", grants, err)
	}
}
